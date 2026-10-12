/* ============================================================
   lib/transit.js — 中转站 / 路径节点探测
   数据源：
     1) Globalping（主）—— 全球多探测点实测 traceroute，给出真实跳 IP。
        选它作主源的原因：check-host.net 对 Cloudflare 出口（Workers 版运行时）
        返回 403，而 Globalping 从 Node 与 Workers 两侧都可达。
     2) check-host.net（备）—— Globalping 不可用时回退，行为与旧版一致。
     3) RIPEstat bgplay（辅）—— AS 级 BGP 观测链路，补充运营商级中转关系。
   每一跳用 ip-api 批量接口补齐 ASN / 运营商 / 城市 / 机房标志。
   采用 start / result 两段式，与站内全球 Ping 代理保持一致（避免长阻塞请求）。
   依赖：util、caches、ipapi、ripe
   ============================================================ */
"use strict";
import { fetchJson, postRaw, isV4, isBogon } from "./util.js";
import { makeCache } from "./caches.js";
import { ipApiBatch } from "./ipapi.js";
import { routeTopology } from "./ripe.js";

const CH = { "Accept": "application/json", "User-Agent": "NetProbe/1.0 (site tool)" };
const GP = { "User-Agent": "NetProbe/1.0" };
const NODE_CACHE = makeCache("ch-nodes", 24 * 3600000, 4);
const RESULT_CACHE = makeCache("transit-result", 30 * 60000, 2000);

/* Globalping 探测点分布：覆盖多洲，避免路径单一。
   实测 magic:"World" 的 6 个点会偏向同一机房（多为 Hetzner），
   因此显式指定国家列表以拿到真实跨洲路径。 */
const GP_LOCATIONS = [
  { magic: "Germany" },
  { magic: "United States" },
  { magic: "Japan" },
  { magic: "China" },
  { magic: "Netherlands" },
  { magic: "Brazil" },
  { magic: "Singapore" },
  { magic: "United Kingdom" },
];

/* 进行中的任务：id → { ip, t, maxNodes, src } */
const jobs = new Map();
const JOB_TTL = 10 * 60000;

function pruneJobs() {
  const now = Date.now();
  for (const [k, v] of jobs) if (now - v.t > JOB_TTL) jobs.delete(k);
}

/* ---------------- check-host 节点清单（备用源用；含 ASN / 城市） ---------------- */
export async function chNodes() {
  const hit = NODE_CACHE.get("hosts");
  if (hit !== undefined) return hit;
  let d = {};
  try {
    const r = await fetchJson("https://check-host.net/nodes/hosts", CH, 12000);
    d = (r && r.nodes) || {};
  } catch (e) { d = {}; }
  NODE_CACHE.set("hosts", d);
  return d;
}

/* ---------------- 发起 traceroute ---------------- */
export async function transitStart(targetIp, maxNodes) {
  pruneJobs();
  const n = Math.max(3, Math.min(20, parseInt(maxNodes, 10) || 6));

  /* 主源：Globalping */
  try {
    const gp = await gpStart(targetIp, n);
    if (gp) return gp;
  } catch (e) { /* 落到备用源 */ }

  /* 备源：check-host.net */
  const ch = await chStart(targetIp, n);
  return ch;
}

/* ---------- Globalping 发起 ---------- */
async function gpStart(targetIp, n) {
  const r = await postRaw(
    "https://api.globalping.io/v1/measurements",
    { type: "traceroute", target: targetIp, locations: GP_LOCATIONS.slice(0, n), limit: n },
    GP,
    15000
  );
  if (r.status !== 202) throw new Error("HTTP " + r.status);
  const loc = r.headers.location || "";
  const id = String(loc).split("/").pop();
  if (!/^[A-Za-z0-9-]{4,64}$/.test(id)) throw new Error("bad measurement id");
  const body = JSON.parse(r.body);
  jobs.set(id, { ip: targetIp, t: Date.now(), maxNodes: n, src: "gp", count: body.probesCount || n });
  return { request_id: id, nodes: [], probes: body.probesCount || n, permanent_link: loc, source: "globalping" };
}

/* ---------- check-host 发起（备用） ---------- */
async function chStart(targetIp, n) {
  const url = "https://check-host.net/check-traceroute?host=" + encodeURIComponent(targetIp) +
    "&max_nodes=" + n;
  const r = await fetchJson(url, CH, 12000);
  if (r.error) throw new Error(r.error);
  const id = r.request_id;
  jobs.set(id, { ip: targetIp, t: Date.now(), maxNodes: n, src: "ch" });

  const meta = await chNodes().catch(() => ({}));
  const nodes = Object.keys(r.nodes || {}).map((k) => {
    const m = meta[k] || {};
    const l = Array.isArray(m.location) ? m.location : [];
    return { node: k, cc: (l[0] || "").toLowerCase(), country: l[1] || "", city: l[2] || "", asn: String(m.asn || "").replace(/^AS/i, "") };
  });
  return { request_id: id, nodes: nodes, permanent_link: r.permanent_link || "", source: "check-host.net" };
}

/* ---------------- check-host 跳解析（备用源用） ----------------
   check-host 的每节点结构在不同响应中可能多包一层，这里按形状自适应：
     [hop1, hop2, ...]            或            [[hop1, hop2, ...]]
   其中 hop = [probe, probe, ...]，probe = { host, query_times } */
function hopsArrayOf(v) {
  if (!Array.isArray(v) || !v.length) return [];
  if (Array.isArray(v[0]) && v[0].length && Array.isArray(v[0][0])) return v[0];
  return v;
}
export function parseHops(raw) {
  const hops = [];
  const arr = hopsArrayOf(raw);
  arr.forEach((probeArr, idx) => {
    if (!Array.isArray(probeArr)) return;
    let ip = "";
    let rtt = null;
    for (const p of probeArr) {
      if (!p) continue;
      if (p.host && !ip) ip = String(p.host);
      const times = Array.isArray(p.query_times) ? p.query_times : [];
      for (const t of times) {
        const v = parseFloat(t);
        if (!isNaN(v) && (rtt === null || v < rtt)) rtt = v;
      }
    }
    hops.push({ n: idx + 1, ip: ip, rtt: rtt });
  });
  return hops;
}

/* 私有/内网/保留地址跳 */
export function isPrivateHop(ip) {
  if (!ip) return true;
  if (!isV4(ip)) return /^(fe80:|fc|fd|::1)/i.test(ip);
  return isBogon(ip) ||
    /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(ip);
}

/* ---------------- 查询结果（未完成则返回 pending） ---------------- */
export async function transitResult(id, opts) {
  const cached = RESULT_CACHE.get(id);
  if (cached !== undefined) return cached;

  const o = opts || {};
  /* Workers 各 isolate 不共享内存，start 与 result 很可能落在不同实例上，
     因此 jobs 里查不到时必须能靠调用方传来的 ip/src 继续工作（无状态回退）。 */
  const job = jobs.get(id) || {
    ip: o.ip || null,
    t: Date.now(),
    maxNodes: 0,
    src: o.src === "ch" || o.src === "check-host.net" ? "ch" : "gp",
    stateless: true,
  };
  if (!job.ip && job.src === "ch") return { error: "expired" };

  if (job.src === "gp") return gpResult(id, job);
  return chResult(id, job);
}

/* ---------- Globalping 结果 ---------- */
async function gpResult(id, job) {
  let d;
  try {
    d = await fetchJson("https://api.globalping.io/v1/measurements/" + encodeURIComponent(id), GP, 15000);
  } catch (e) {
    return { pending: true };
  }
  if (!d || (d.status !== "finished" && d.status !== "failed")) return { pending: true };

  /* 无状态回退时从测量结果自身取目标 IP（Globalping 会在 target 字段回显） */
  if (!job.ip && d.target) job.ip = String(d.target);
  if (!job.ip) return { pending: true };

  const nodes = [];
  const hopIps = new Set();
  for (const res of d.results || []) {
    const p = res.probe || {};
    const rr = res.result || {};
    const hops = (rr.hops || []).map((h, i) => {
      const ts = (h.timings || []).map((t) => t && t.rtt).filter((v) => typeof v === "number" && !isNaN(v));
      return {
        n: i + 1,
        ip: h.resolvedAddress || "",
        rtt: ts.length ? Math.round(Math.min.apply(null, ts) * 100) / 100 : null,
        host: h.resolvedHostname || "",
      };
    });
    nodes.push({
      node: [p.city, p.country].filter(Boolean).join(", ") || p.network || "probe",
      cc: String(p.country || "").toLowerCase().slice(0, 2),
      country: p.country || "",
      city: p.city || "",
      asn: String(p.asn || "").replace(/^AS/i, ""),
      ip: "",
      network: p.network || "",
      status: rr.status || "",
      hops: hops,
    });
    hops.forEach((h) => { if (h.ip && isV4(h.ip)) hopIps.add(h.ip); });
  }
  if (!nodes.length) return { pending: true };
  return buildOut(id, job, nodes, hopIps, false);
}

/* ---------- check-host 结果（备用） ---------- */
async function chResult(id, job) {
  let data;
  try {
    data = await fetchJson("https://check-host.net/check-result/" + encodeURIComponent(id), CH, 12000);
  } catch (e) {
    return { pending: true };
  }
  const keys = Object.keys(data || {});
  if (!keys.length) return { pending: true };

  /* check-host 会边探测边返回，未响应节点为 null；全部非 null 才算完成。
     超过 25 秒仍未收齐则接受当前部分结果，避免请求永久挂起。 */
  const unfinished = keys.some((k) => data[k] === null || data[k] === undefined);
  const anyHops = keys.some((k) => Array.isArray(data[k]) && data[k].length);
  const elapsed = Date.now() - job.t;
  if (unfinished && (!anyHops || elapsed < 25000)) return { pending: true };

  const meta = await chNodes().catch(() => ({}));
  const nodes = [];
  const hopIps = new Set();
  for (const nodeKey of keys) {
    const hops = parseHops(data[nodeKey]);
    if (!hops.length) continue;
    const m = meta[nodeKey] || {};
    const l = Array.isArray(m.location) ? m.location : [];
    nodes.push({
      node: nodeKey,
      cc: (l[0] || "").toLowerCase(),
      country: l[1] || "",
      city: l[2] || "",
      asn: String(m.asn || "").replace(/^AS/i, ""),
      ip: m.ip || "",
      hops: hops,
    });
    hops.forEach((h) => { if (h.ip && isV4(h.ip)) hopIps.add(h.ip); });
  }
  if (!nodes.length) return { pending: true };
  return buildOut(id, job, nodes, hopIps, unfinished);
}

/* ---------------- 公共聚合：打标 + 中转站 + ASN 分组 + BGP 链路 ---------------- */
async function buildOut(id, job, nodes, hopIps, unfinished) {
  const targetIp = job.ip;

  /* 批量富化所有跳 IP（含目标 IP） */
  hopIps.add(targetIp);
  const geo = await ipApiBatch([...hopIps]).catch(() => ({}));

  const stations = new Map();
  nodes.forEach((nd) => {
    nd.hops = nd.hops.map((h) => {
      const g = geo[h.ip] || null;
      const priv = isPrivateHop(h.ip);
      const isTarget = h.ip === targetIp;
      const item = {
        n: h.n, ip: h.ip, rtt: h.rtt,
        private: priv, isTarget: isTarget,
        asn: g ? g.asn : null,
        asname: g ? (g.asname || g.org || g.isp || "") : "",
        cc: g ? g.cc : "",
        city: g ? g.city : "",
        org: g ? (g.org || g.isp || "") : "",
        hosting: g ? g.hosting : null,
      };
      if (!priv && !isTarget && h.ip) {
        const s = stations.get(h.ip) || {
          ip: h.ip, asn: item.asn, asname: item.asname, org: item.org,
          cc: item.cc, city: item.city, hosting: item.hosting, seen: 0, rtts: [],
        };
        s.seen++;
        if (h.rtt !== null) s.rtts.push(h.rtt);
        stations.set(h.ip, s);
      }
      return item;
    });
  });

  const stArr = [...stations.values()].sort((a, b) => b.seen - a.seen).slice(0, 40).map((s) => ({
    ip: s.ip, asn: s.asn, asname: s.asname, org: s.org, cc: s.cc, city: s.city,
    hosting: s.hosting, hopsSeen: s.seen,
    rttMin: s.rtts.length ? Math.round(Math.min.apply(null, s.rtts) * 100) / 100 : null,
  }));

  /* 按 ASN 聚合中转运营商（无 ASN 归属的跳归入「未知」，不计入 ASN 统计） */
  const asnMap = new Map();
  for (const s of stArr) {
    if (!s.asn) continue;
    const k = s.asn;
    if (!asnMap.has(k)) asnMap.set(k, { asn: s.asn, name: s.asname || s.org || "", ips: [], hosting: s.hosting, hops: 0 });
    const a = asnMap.get(k);
    a.ips.push(s.ip);
    a.hops += s.hopsSeen;
  }
  const asnGroups = [...asnMap.values()].sort((a, b) => b.hops - a.hops);

  /* 补 AS 级 BGP 链路 */
  let asnChain = null;
  try {
    const targetAsn = (geo[targetIp] && geo[targetIp].asn) || null;
    if (targetAsn) asnChain = await routeTopology(targetIp, targetAsn).catch(() => null);
  } catch (e) { asnChain = null; }

  const out = {
    ip: targetIp,
    complete: !unfinished,
    nodes: nodes,
    stations: stArr,
    asnGroups: asnGroups,
    asnChain: asnChain,
    summary: {
      probes: nodes.length,
      publicHops: stArr.length,
      uniqueAsn: asnGroups.length,
      distinctIps: hopIps.size,
    },
    source: (job.src === "gp" ? "Globalping 全球探测点 traceroute" : "check-host.net traceroute") +
      " + ip-api 富化" + (asnChain ? " + RIPE RIS BGP" : ""),
    disclaimer: "中转站为全球探测节点实测 traceroute 得到的路径跳；受路由策略与探测点位置影响，同一 IP 在不同地区路径可能不同。",
  };
  if (!unfinished) RESULT_CACHE.set(id, out);
  return out;
}
