/* ============================================================
   NetProbe — Cloudflare Workers 入口（原创实现）
   - 静态资源由 Workers Assets 直接服务（wrangler.jsonc assets 配置）
   - /api/* 与未命中资源的深链接（/report/<id>、/ip/<ip> 等）进入本 Worker
   - 常规缓存为 Worker 内存（隔离实例级），不绑定 KV / R2
   - Torrent 检测的 announce 记录与全站查询计数存 Durable Object（跨隔离、跨节点一致）
   ============================================================ */
"use strict";

import { fetchJson, isV4, isV6, normalizeIp, rdapBootstrap, rdapGet, shortHash } from "./lib/util.js";
import * as caches from "./lib/caches.js";
import * as geo from "./lib/geo.js";
import { dnsblCheck, dnsblFull } from "./lib/dnsbl.js";
import * as ripe from "./lib/ripe.js";
import { ipDeepFull } from "./lib/ipdeep.js";
import { cfRisk } from "./lib/cfrisk.js";
import { cardSvg } from "./lib/card.js";
import { ipScore } from "./lib/score.js";
import { getStatusHistory } from "./lib/status.js";

const START = Date.now();

/* ---------------- 访客 IP：Cloudflare 直接提供可信头 ---------------- */
function getVisitorIp(request) {
  return (
    request.headers.get("cf-connecting-ip") ||
    request.headers.get("x-real-ip") ||
    (request.headers.get("x-forwarded-for") || "").split(",")[0].trim() ||
    "0.0.0.0"
  );
}

/* ---------------- 限流（内存级，按隔离实例计） ---------------- */
const RATE_RULES = [
  { re: /^\/api\/(ipscore|cfrisk|ipdeep|ip\/trend)/, limit: 12, name: "heavy" },
  { re: /^\/api\/card\.svg$/, limit: 20, name: "card" },
  { re: /^\/api\/(whois|geoip|iprisk|ping\/start|egress\/geo|tlsinfo|stats)/, limit: 40, name: "light" },
  { re: /^\/api\/(turnstile|recaptcha)\/verify$/, limit: 20, name: "verify" },
      { re: /^\/api\/ooni/, limit: 60, name: "ooni" },
      { re: /^\/api\/gp\/poll/, limit: 120, name: "gppoll" },
      { re: /^\/api\/gp/, limit: 20, name: "gp" },
];
const rateBuckets = new Map();
function rateLimit(ip, p) {
  for (const rule of RATE_RULES) {
    if (rule.re.test(p)) {
      const key = rule.name + "|" + ip;
      const now = Date.now();
      let b = rateBuckets.get(key);
      if (!b || now - b.t0 > 60000) { b = { t0: now, n: 0 }; rateBuckets.set(key, b); }
      b.n++;
      if (rateBuckets.size > 20000) rateBuckets.clear();
      return { ok: b.n <= rule.limit, retry: Math.max(1, Math.ceil((60000 - (now - b.t0)) / 1000)) };
    }
  }
  return { ok: true };
}

/* ---------------- JSON 输出（边缘自动压缩，无需手动 gzip） ---------------- */
function json(obj, code, extraHeaders) {
  return new Response(JSON.stringify(obj), {
    status: code,
    headers: Object.assign(
      { "Content-Type": "application/json; charset=utf-8", "Access-Control-Allow-Origin": "*" },
      extraHeaders || {}
    ),
  });
}

async function readJsonBody(request, maxLen) {
  const body = await request.text();
  if (body.length > (maxLen || 65536)) throw new Error("payload too large");
  try { return JSON.parse(body) || {}; } catch (e) { return {}; }
}

/* ---------------- Whois / TLD ---------------- */
let tldStatsCache = null;
async function tldStats() {
  if (tldStatsCache && Date.now() - tldStatsCache.t < 24 * 3600 * 1000) return tldStatsCache.d;
  const boot = await rdapBootstrap();
  const services = boot.services || [];
  let rdapCount = 0;
  services.forEach((s) => (rdapCount += s[0].length));
  const tlds = [];
  services.forEach((s) => s[0].forEach((t) => tlds.push(t)));
  tlds.sort();
  tldStatsCache = { d: { total: tlds.length, rdapCount, tlds: tlds.slice(0, 800), t: Date.now() }, t: Date.now() };
  return tldStatsCache.d;
}

async function whoisQuery(q) {
  q = String(q || "").trim();
  let target;
  if (/^as\d+$/i.test(q)) {
    target = "https://rdap.org/autnum/" + q.replace(/^as/i, "");
  } else if (isV4(q) || isV6(q)) {
    target = "https://rdap.org/ip/" + q;
  } else {
    const tld = q.split(".").pop().toLowerCase();
    const boot = await rdapBootstrap();
    const entry = (boot.services || []).find((s) => s[0].indexOf(tld) !== -1);
    target = entry ? entry[1][0] + "domain/" + q : "https://rdap.org/domain/" + q;
  }
  return rdapGet(target);
}

/* ---------------- check-host.net Ping 代理 ---------------- */
const CH = { "Accept": "application/json", "User-Agent": "NetProbe/1.0 (site tool)" };
function isPrivateTarget(t) {
  if (/^(127\.|10\.|192\.168\.|0\.|169\.254\.)/.test(t)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(t)) return true;
  if (/^::1$/.test(t) || /^f[cd][0-9a-f]{2}:/i.test(t)) return true;
  return false;
}

/* ---------------- DoH 白名单代理 ---------------- */
const DOH_ALLOW = [
  "https://dns.alidns.com/resolve?",
  "https://doh.pub/dns-query?",
  "https://dns.google/resolve?",
  "https://cloudflare-dns.com/dns-query?",
  "https://dns.quad9.net:5053/dns-query?",
  "https://dns.quad9.net/dns-query?",
  "https://dns11.quad9.net/dns-query?",
  "https://dns.adguard-dns.com/resolve?",
  "https://doh.sb/dns-query?",
  "https://dns0.eu/resolve?",
  "https://freedns.controld.com/v0/p0?",
];

/* ---------------- 检测报告（内存级，隔离实例生命周期内有效） ---------------- */
const reports = new Map();
async function createReport(body, env) {
  const d = {};
  const put = (k, v, max) => { if (v != null) d[k] = String(v).slice(0, max || 120); };
  put("ip", body.ip, 64);
  put("label", body.label, 40);
  put("score", body.score, 8);
  put("purity", body.purity, 8);
  put("asn", body.asn, 24);
  put("org", body.org);
  put("cc", body.cc, 8);
  put("city", body.city, 60);
  put("region", body.region, 60);
  put("rpki", body.rpki, 16);
  put("dnsblHit", body.dnsblHit, 8);
  if (!d.ip) throw new Error("缺少 ip");
  const id = shortHash(d.ip + Date.now() + Math.random()).slice(0, 6);
  const t = Date.now();
  let ttl = parseInt(body.ttl, 10);
  if (!isFinite(ttl)) ttl = 604800;
  ttl = ttl * 1000; // 客户端传秒，内部统一毫秒
  if (ttl < 3600000) ttl = 3600000;
  if (ttl > 30 * 86400000) ttl = 30 * 86400000;
  const rec = { id, t, exp: t + ttl, d };
  reports.set(id, rec);
  const doStub = countersStub(env);
  if (doStub) {
    try { await doStub.fetch("https://do/report", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(rec) }); } catch (e) {}
  }
  return rec;
  if (reports.size > 300) {
    const arr = [...reports.entries()].sort((a, b) => a[1].t - b[1].t);
    while (reports.size > 300) reports.delete(arr.shift()[0]);
  }
  return { id };
}

/* ---------------- Torrent 地址检测（BitTorrent HTTP Tracker） ----------------
   /torrent/ 页面为访客生成随机 info_hash（20 字节），拼成仅含本站 Tracker 的
   Magnet 链接；BT 客户端添加链接后按 BEP 3 向 /api/torrent/announce 发起 GET
   announce，这里把请求来源（Cloudflare 提供的 cf-connecting-ip，即客户端真实
   出口）记入按 info_hash 划分的 Durable Object 房间；浏览器轮询 /api/torrent/
   results 回显。房间 2 小时无活动由闹钟自动清空，peer 30 分钟无活动即剔除。 */

function rawQueryBytes(rawUrl, name) {
  const qi = rawUrl.indexOf("?");
  if (qi === -1) return null;
  for (const part of rawUrl.slice(qi + 1).split("&")) {
    const eq = part.indexOf("=");
    const k = eq === -1 ? part : part.slice(0, eq);
    if (k !== name) continue;
    const v = eq === -1 ? "" : part.slice(eq + 1);
    const out = [];
    for (let i = 0; i < v.length; i++) {
      if (v[i] === "%" && i + 2 < v.length + 1) {
        out.push(parseInt(v.substr(i + 1, 2), 16) || 0);
        i += 2;
      } else out.push(v.charCodeAt(i) & 0xff);
    }
    return out;
  }
  return null;
}

function bytesToHex(b) {
  let s = "";
  for (const x of b) s += (x < 16 ? "0" : "") + x.toString(16);
  return s;
}

const BT_CLIENTS = {
  qB: "qBittorrent", TR: "Transmission", UT: "uTorrent", UM: "uTorrent Mac",
  LT: "libtorrent", DE: "Deluge", AZ: "Vuze", BC: "BitComet", BT: "BitTorrent",
  XL: "迅雷", SD: "Thunder", TT: "TuoTu", FG: "FlashGet", MO: "MonoTorrent", A2: "aria2",
};

function clientName(peerHex, ua) {
  if (ua) {
    const m = ua.match(/^\s*([A-Za-z][A-Za-z0-9 ._+-]{0,28}?)\s*\/?\s*v?(\d[\w.]*)/);
    if (m) return (m[1].trim() + " " + m[2]).trim();
  }
  if (peerHex && peerHex.length === 40) {
    let s = "";
    for (let i = 0; i < 40; i += 2) s += String.fromCharCode(parseInt(peerHex.substr(i, 2), 16) || 63);
    const az = s.match(/^-([A-Za-z]{2})(\d{1,4})/);
    if (az) return (BT_CLIENTS[az[1]] || "客户端 " + az[1]) + "（" + az[1] + az[2] + "）";
    const ch = s[0];
    if (ch === "M") return "BitTorrent（mainline）";
    if (ch === "S") return "Shadow/xbt";
    if (ch === "T") return "BitTornado";
    if (ch === "A") return "ABC";
  }
  return "未知客户端";
}

const bstr = (s) => s.length + ":" + s;
const bTrackFail = (msg) => "d14:failure reason" + bstr(msg) + "e";
const bTrackOk = (complete, incomplete) =>
  "d8:completei" + complete + "e10:downloadedi0e10:incompletei" + incomplete +
  "e8:intervali120e12:min intervali60e5:peers0:e";
function bTrack(body) {
  return new Response(body, {
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*" },
  });
}

export class TorrentRoom {
  constructor(state, env) { this.state = state; this._room = null; }
  async loadRoom() {
    if (!this._room) this._room = (await this.state.storage.get("peers")) || { map: {}, updated: 0 };
    return this._room;
  }
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/record" && request.method === "POST") {
      const info = await request.json();
      const now = Date.now();
      const room = await this.loadRoom();
      const key = info.ip + "|" + info.port;
      const prev = room.map[key];
      room.map[key] = {
        ip: info.ip, port: info.port, peer: info.peer, client: info.client, agent: info.agent,
        event: info.event, left: info.left,
        first: prev ? prev.first : now, last: now, count: (prev ? prev.count : 0) + 1,
      };
      for (const k of Object.keys(room.map)) if (now - room.map[k].last > 1800000) delete room.map[k];
      room.updated = now;
      this._room = room;
      await this.state.storage.put("peers", room);
      await this.state.storage.setAlarm(now + 2 * 3600 * 1000);
      return Response.json(room);
    }
    if (url.pathname === "/list") return Response.json(await this.loadRoom());
    return new Response("not found", { status: 404 });
  }
  async alarm() {
    const room = await this.loadRoom();
    if (Date.now() - room.updated > 2 * 3600 * 1000) {
      this._room = { map: {}, updated: 0 };
      await this.state.storage.deleteAll();
    } else {
      await this.state.storage.setAlarm(Date.now() + 2 * 3600 * 1000);
    }
  }
}

const torrentRoomsMem = new Map();
function torrentRoomStub(env, hex) {
  return env && env.TORRENT_DO ? env.TORRENT_DO.get(env.TORRENT_DO.idFromName("bt-" + hex)) : null;
}
async function torrentRecord(env, hex, info) {
  const stub = torrentRoomStub(env, hex);
  if (stub) {
    const r = await stub.fetch("https://torrent-room/record", { method: "POST", body: JSON.stringify(info) });
    return r.json();
  }
  return memTorrentRecord(hex, info);
}
async function torrentList(env, hex) {
  const stub = torrentRoomStub(env, hex);
  if (stub) {
    const r = await stub.fetch("https://torrent-room/list");
    return r.json();
  }
  return torrentRoomsMem.get(hex) || { map: {}, updated: 0 };
}
function memTorrentRecord(hex, info) {
  let st = torrentRoomsMem.get(hex);
  if (!st) {
    st = { map: {}, updated: 0 };
    torrentRoomsMem.set(hex, st);
    if (torrentRoomsMem.size > 400) torrentRoomsMem.delete(torrentRoomsMem.keys().next().value);
  }
  const now = Date.now();
  const key = info.ip + "|" + info.port;
  const prev = st.map[key];
  st.map[key] = {
    ip: info.ip, port: info.port, peer: info.peer, client: info.client, agent: info.agent,
    event: info.event, left: info.left,
    first: prev ? prev.first : now, last: now, count: (prev ? prev.count : 0) + 1,
  };
  for (const k of Object.keys(st.map)) if (now - st.map[k].last > 1800000) delete st.map[k];
  st.updated = now;
  return st;
}

/* ---------------- 全站查询计数（Durable Object，按天分桶 + 累计） ----------------
   /api/geoip、/api/ipscore 等查询接口命中时 +1；首页横幅读今日与累计值。 */

export class Counters {
  constructor(state, env) { this.state = state; this._c = null; }
  async load() {
    if (!this._c) this._c = (await this.state.storage.get("data")) || { total: 0, days: {}, last: 0 };
    return this._c;
  }
  async fetch(request) {
    const url = new URL(request.url);
    const today = new Date().toISOString().slice(0, 10);
    if (url.pathname === "/hit" && request.method === "POST") {
      const c = await this.load();
      c.total += 1;
      c.days[today] = (c.days[today] || 0) + 1;
      const keys = Object.keys(c.days).sort();
      while (keys.length > 35) delete c.days[keys.shift()];
      c.last = Date.now();
      this._c = c;
      await this.state.storage.put("data", c);
      return Response.json({ today: c.days[today] || 0, total: c.total });
    }
    if (url.pathname === "/read") {
      const c = await this.load();
      return Response.json({ today: c.days[today] || 0, total: c.total, updated: c.last });
    }
    if (url.pathname === "/report" && request.method === "POST") {
      const body = await request.json();
      if (!body || !body.id || !body.d) return Response.json({ ok: false }, 400);
      await this.state.storage.put("report:" + body.id, { t: body.t, exp: body.exp, d: body.d });
      // 顺手清理少量过期报告（每 20 次写入做一次）
      this._wc = (this._wc || 0) + 1;
      if (this._wc % 20 === 0) {
        const entries = await this.state.storage.list({ prefix: "report:" });
        const now = Date.now();
        for (const [k, v] of entries) {
          if (v && v.exp && now > v.exp) await this.state.storage.delete(k);
        }
      }
      return Response.json({ ok: true });
    }
    if (url.pathname === "/report/read") {
      const id = url.searchParams.get("id") || "";
      if (!/^[A-Za-z0-9]{4,12}$/.test(id)) return Response.json({ ok: false }, 400);
      const v = await this.state.storage.get("report:" + id);
      if (!v || (v.exp && Date.now() > v.exp)) {
        if (v) await this.state.storage.delete("report:" + id);
        return Response.json({ ok: false }, 404);
      }
      return Response.json({ ok: true, t: v.t, d: v.d });
    }
    return new Response("not found", { status: 404 });
  }
}

const countersMem = { today: "", todayN: 0, total: 0 };
function countersStub(env) {
  return env && env.COUNTERS_DO ? env.COUNTERS_DO.get(env.COUNTERS_DO.idFromName("global")) : null;
}
async function statsRead(env) {
  const stub = countersStub(env);
  if (stub) {
    try { const r = await stub.fetch("https://counters/read"); return await r.json(); } catch (e) {}
  }
  return { today: countersMem.todayN, total: countersMem.total };
}
function statsHit(env, ctx) {
  const stub = countersStub(env);
  const mem = () => {
    const t = new Date().toISOString().slice(0, 10);
    if (countersMem.today !== t) { countersMem.today = t; countersMem.todayN = 0; }
    countersMem.todayN++; countersMem.total++;
  };
  if (!stub) { mem(); return; }
  const p = stub.fetch("https://counters/hit", { method: "POST" })
    .then((r) => r.json())
    .then((d) => { countersMem.today = new Date().toISOString().slice(0, 10); countersMem.todayN = d.today; countersMem.total = d.total; })
    .catch(() => mem());
  if (ctx && ctx.waitUntil) ctx.waitUntil(p);
}

/* ---------------- 入口 ---------------- */
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const p = url.pathname;
    const visitorIp = getVisitorIp(request);

    try {
      let m;
      if (p === "/api/session") {
        return json({ ip: visitorIp, ua: request.headers.get("user-agent") || "" });
      }
      if (p === "/api/health") {
        return json({
          ok: true,
          runtime: "cloudflare-workers",
          uptime_s: Math.floor((Date.now() - START) / 1000),
          asset_ver: "runtime",
          caches: caches.stats(),
          reports: reports.size,
          status_log: (await getStatusHistory(false)).lastRun,
          note: "Workers 版：常规缓存为隔离实例内存；Torrent 房间存 Durable Object（2 小时自动清除）",
        });
      }
      if (p === "/api/admin/purge") {
        const token = url.searchParams.get("token") || "";
        if (!env.ADMIN_TOKEN) return json({ ok: false, error: "未配置 ADMIN_TOKEN 环境变量，管理接口停用" }, 403);
        if (token !== env.ADMIN_TOKEN) return json({ ok: false, error: "token 无效" }, 403);
        const cleared = caches.clearAll();
        rateBuckets.clear();
        tldStatsCache = null;
        reports.clear();
        return json({ ok: true, cleared });
      }

      const rl = rateLimit(visitorIp, p);
      if (!rl.ok) {
        return json({ error: "请求过于频繁，请稍后再试" }, 429, { "Retry-After": String(rl.retry) });
      }

      if ((m = p.match(/^\/api\/geoip\/(.+)$/))) {
        statsHit(env, ctx);
        return json(await geo.geoLookup(decodeURIComponent(m[1])));
      }
      if ((m = p.match(/^\/api\/iprisk\/(.+)$/))) {
        statsHit(env, ctx);
        return json(geo.classifyRisk(await geo.geoLookup(decodeURIComponent(m[1]))));
      }
      if ((m = p.match(/^\/api\/ipdeep\/(.+)$/))) {
        statsHit(env, ctx);
        return json(await ipDeepFull(decodeURIComponent(m[1])));
      }
      if ((m = p.match(/^\/api\/ipscore\/(.+)$/))) {
        statsHit(env, ctx);
        return json(await ipScore(decodeURIComponent(m[1])));
      }
      /* 分流出口检测：批量补齐出口 IP 的归属地（页面前端已逐一探测目标站点） */
      if (p === "/api/egress/geo" && request.method === "POST") {
        const body = await readJsonBody(request, 4096);
        const ips = (Array.isArray(body.ips) ? body.ips : [])
          .map((x) => String(x || "").trim())
          .filter((x) => isV4(x) || isV6(x))
          .slice(0, 24);
        const out = {};
        await Promise.allSettled(ips.map(async (ip) => {
          try { out[ip] = await geo.geoLookup(ip); } catch (e) {}
        }));
        return json({ ok: true, geo: out });
      }
      /* TLS 指纹：Cloudflare 在 request.cf 上提供的 ClientHello 摘要字段（按套餐可用性返回） */
      if (p === "/api/tlsinfo") {
        const cf = request.cf || {};
        const d = {
          tlsVersion: cf.tlsVersion || null,
          tlsCipher: cf.tlsCipher || null,
          helloLength: cf.tlsClientHelloLength || null,
          extensionsSha1: cf.tlsClientExtensionsSha1 || null,
          asn: cf.asn || null,
          asOrganization: cf.asOrganization || null,
          country: cf.country || null,
        };
        d.available = !!(d.tlsVersion && d.tlsCipher);
        return json(d);
      }
      /* reCAPTCHA v3 评分（官方公开测试密钥，演示链路用） */
      if (p === "/api/recaptcha/verify" && request.method === "POST") {
        const body = await readJsonBody(request);
        const token = String(body.token || "").slice(0, 8192);
        if (!token) return json({ ok: false, reason: "缺少 token" }, 400);
        try {
          const resp = await fetch("https://www.google.com/recaptcha/api/siteverify", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              secret: "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe",
              response: token,
            }).toString(),
            signal: AbortSignal.timeout(10000),
          });
          const d = await resp.json();
          return json({ ok: !!d.success, score: typeof d.score === "number" ? d.score : null, action: d.action || "", errors: d["error-codes"] || [] });
        } catch (e) {
          return json({ ok: false, score: null, errors: ["verification_unreachable"] });
        }
      }
      /* 全站查询计数（首页横幅） */
      if (p === "/api/ooni") {
        const path = url.searchParams.get("path") || "";
        if (!/^\/api\/v1\/measurements\?/.test(path)) return json({ error: "not allowed" }, 403);
        const r = await fetch("https://api.ooni.io" + path, { headers: { "User-Agent": "NetProbe/1.0" } });
        return new Response(await r.text(), { status: r.status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
      }
      if (p === "/api/gp" && request.method === "POST") {
        const body = await request.text();
        const r = await fetch("https://api.globalping.io/v1/measurements", {
          method: "POST",
          headers: { "Content-Type": "application/json", "User-Agent": "NetProbe/1.0" },
          body,
        });
        const loc = r.headers.get("Location") || "";
        return new Response(await r.text(), { status: r.status, headers: { "Content-Type": "application/json", "X-GP-Location": loc, "Cache-Control": "no-store" } });
      }
      if (p === "/api/gp/poll") {
        const id = url.searchParams.get("id") || "";
        if (!/^[A-Za-z0-9-]{4,64}$/.test(id)) return json({ error: "bad id" }, 400);
        const r = await fetch("https://api.globalping.io/v1/measurements/" + id, { headers: { "User-Agent": "NetProbe/1.0" } });
        return new Response(await r.text(), { status: r.status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
      }
      if (p === "/api/stats") {
        return json(await statsRead(env));
      }
      if ((m = p.match(/^\/api\/ip\/trend\/(.+)$/))) {
        return json(geo.trendFor(decodeURIComponent(m[1])));
      }
      if ((m = p.match(/^\/api\/cfrisk\/(.+)$/))) {
        return json(await cfRisk(decodeURIComponent(m[1])));
      }
      if (p === "/api/card.svg") {
        const param = url.searchParams.get("ip") || "";
        const target = (isV4(param) || isV6(param)) ? param : visitorIp;
        if (!target) {
          return new Response('<svg xmlns="http://www.w3.org/2000/svg" width="480" height="227" viewBox="0 0 720 340"><rect width="720" height="340" rx="28" fill="#1e293b"/><text x="360" y="180" font-size="30" fill="#94a3b8" text-anchor="middle" font-family="sans-serif">无法识别访客 IP</text></svg>',
            { headers: { "Content-Type": "image/svg+xml; charset=utf-8", "Cache-Control": "no-store" } });
        }
        const styleKey = url.searchParams.get("style") || "midnight";
        const stickerKey = url.searchParams.get("sticker") || "none";
        let w = parseInt(url.searchParams.get("w"), 10);
        if (!w || w < 120 || w > 1440) w = 480;
        const card = await cardSvg(target, styleKey, stickerKey, w);
        return new Response(card.svg, {
          headers: { "Content-Type": card.ct, "Cache-Control": "public, max-age=300", "Access-Control-Allow-Origin": "*" },
        });
      }
      if (p === "/api/turnstile/verify" && request.method === "POST") {
        const body = await readJsonBody(request);
        const token = String(body.token || "").slice(0, 4096);
        if (!token) return json({ ok: false, reason: "缺少 token" }, 400);
        try {
          const resp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({ secret: "1x0000000000000000000000000000000AA", response: token }).toString(),
            signal: AbortSignal.timeout(10000),
          });
          const d = await resp.json();
          return json({ ok: !!d.success, errors: d["error-codes"] || [] });
        } catch (e) {
          return json({ ok: false, errors: ["verification_unreachable"] });
        }
      }
      if (p === "/api/whois") {
        return json(await whoisQuery(url.searchParams.get("q") || ""));
      }
      if (p === "/api/whois/tlds") {
        const s = await tldStats();
        return json({ total: s.total, rdapCount: s.rdapCount, tlds: s.tlds });
      }
      if (p === "/api/ping/start") {
        const host = url.searchParams.get("host") || visitorIp;
        if (isPrivateTarget(host)) throw new Error("private_target");
        const r = await fetchJson("https://check-host.net/check-ping?host=" + encodeURIComponent(host) + "&max_nodes=25", CH, 12000);
        if (r.error) throw new Error(r.error);
        return json(r);
      }
      if ((m = p.match(/^\/api\/ping\/result\/([a-z0-9]+)$/))) {
        return json(await fetchJson("https://check-host.net/check-result/" + encodeURIComponent(m[1]), CH, 12000));
      }
      if ((m = p.match(/^\/api\/dnsleak\/([a-z0-9]+)$/))) {
        return json(await fetchJson("https://ipleak.net/jsondns/" + m[1], { "User-Agent": "NetProbe/1.0" }, 10000));
      }
      if (p === "/api/doh") {
        const target = url.searchParams.get("u") || "";
        if (!DOH_ALLOW.some((pre) => target.startsWith(pre))) return json({ error: "not allowed" }, 403);
        return json(await fetchJson(target, { accept: "application/dns-json", "User-Agent": "NetProbe/1.0" }, 8000));
      }
      if (p === "/api/dns/config") {
        return json({ enabled: false, zone: "", note: "Workers 版不支持 UDP 53 自托管采集，DNS 泄露检测走 ipleak 公共接口" });
      }
      if ((m = p.match(/^\/api\/dns\/result\/([a-z0-9-]+)$/))) {
        return json({ resolvers: [] });
      }
      if (p === "/api/torrent/announce") {
        // BitTorrent HTTP Tracker：响应必须是 bencode，任何错误也不能回 JSON
        try {
          const ih = rawQueryBytes(request.url, "info_hash");
          if (!ih || ih.length !== 20) return bTrack(bTrackFail("invalid info_hash"));
          const hex = bytesToHex(ih);
          const pid = bytesToHex(rawQueryBytes(request.url, "peer_id") || []);
          const ua = request.headers.get("user-agent") || "";
          const q = url.searchParams;
          await torrentRecord(env, hex, {
            ip: visitorIp,
            port: Math.min(65535, parseInt(q.get("port") || "0", 10) || 0),
            peer: pid,
            client: clientName(pid, ua),
            agent: ua.slice(0, 100),
            event: (q.get("event") || "").slice(0, 16),
            left: parseInt(q.get("left") || "0", 10) || 0,
          });
          const room = await torrentList(env, hex);
          let complete = 0, incomplete = 0;
          Object.values(room.map || {}).forEach((x) => (x.left === 0 ? complete++ : incomplete++));
          return bTrack(bTrackOk(complete, incomplete));
        } catch (e) {
          return bTrack(bTrackFail("internal error"));
        }
      }
      if (p === "/api/torrent/results") {
        const hex = (url.searchParams.get("h") || "").toLowerCase();
        if (!/^[0-9a-f]{40}$/.test(hex)) return json({ ok: false, error: "bad hash" }, 400);
        const room = await torrentList(env, hex);
        return json({
          ok: true,
          hash: hex,
          updated: room.updated || 0,
          peers: Object.values(room.map || {}).sort((a, b) => b.last - a.last),
        });
      }
      if (p === "/api/report" && request.method === "POST") {
        const body = await readJsonBody(request, 8192);
        try {
          const r = await createReport(body, env);
          return json({ ok: true, id: r.id, url: "/report/" + r.id });
        } catch (e) {
          return json({ ok: false, error: e.message || "参数错误" }, 400);
        }
      }
      if ((m = p.match(/^\/api\/report\/([A-Za-z0-9]+)$/))) {
        let r = reports.get(m[1]);
        if (!r) {
          const doStub = countersStub(env);
          if (doStub) {
            try {
              const rr = await doStub.fetch("https://do/report/read?id=" + encodeURIComponent(m[1]));
              if (rr.ok) r = await rr.json();
            } catch (e) {}
          }
        }
        if (!r || (r.exp && Date.now() > r.exp)) {
          if (r) reports.delete(m[1]);
          return json({ ok: false, error: "报告不存在或已过期" }, 404);
        }
        return json({ ok: true, t: r.t, d: r.d });
      }
      if (p === "/api/status/history") {
        return json(await getStatusHistory(true));
      }

      /* ---- 未命中静态资源：深链接回退（/report/<id>、/ip/<ip> 等） ---- */
      if (env && env.ASSETS) {
        const sm = p.match(/^\/([a-z-]+)(\/|$)/);
        if (sm) {
          const asset = await env.ASSETS.fetch(new URL("http://local/" + sm[1] + "/index.html"));
          if (asset.status === 200) return asset;
        }
        const direct = await env.ASSETS.fetch(url);
        if (direct.status !== 404) return direct;
      }
      return new Response("Not Found", { status: 404 });
    } catch (e) {
      return json({ error: e.message || "upstream error" }, 502);
    }
  },
};
