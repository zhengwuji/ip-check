/* ============================================================
   NetProbe 服务端（原创实现，零依赖）
   入口仅保留：HTTP 路由 / 静态托管 / 限流 / 压缩 / 运维接口。
   业务逻辑按模块拆分在 lib/：
     lib/util.js    通用请求、IP 工具、RDAP、原子写盘
     lib/caches.js  统一 TTL 缓存工厂（注册表 + 每小时淘汰）
     lib/geo.js     GeoIP 聚合 / 风险分类 / 趋势 / 位置历史
     lib/dnsbl.js   DNSBL 黑名单（IPv4 + IPv6）
     lib/ripe.js    RIPEstat / RDAP 数据源
     lib/ipdeep.js  PTR / 端口扫描 / 任播识别
     lib/cfrisk.js  Cloudflare 环境风险评估
     lib/card.js    IP 信息卡片 SVG

   路由一览：
     GET  /api/session            访客出口 IP 会话
     GET  /api/geoip/:ip          GeoIP 聚合
     GET  /api/iprisk/:ip         IP 风险分类
     GET  /api/ipdeep/:ip         深度信息
     GET  /api/ipscore/:ip        IP 评分全家桶（重）
     GET  /api/ip/trend/:ip       网段查询热度 + 纯净度均值
     GET  /api/cfrisk/:ip         Cloudflare 环境风险评估
     GET  /api/card.svg           IP 信息卡片（style/sticker/w）
     POST /api/turnstile/verify   Turnstile 服务端二次校验
     POST /api/recaptcha/verify   reCAPTCHA v3 评分校验（公开测试密钥）
     POST /api/egress/geo         分流出口批量归属地
     GET  /api/tlsinfo            TLS 指纹（HTTPS 部署下有效）
     GET  /api/stats              全站查询计数（今日/累计）
     GET  /api/whois?q=           RDAP 代理
     GET  /api/whois/tlds         IANA 根区统计
     GET  /api/ping/start|result  check-host.net Ping 代理
     GET  /api/doh?u=             DoH 白名单代理
     GET  /api/dns/config|result  自托管 DNS 泄露
     POST /api/report             生成检测报告分享链接
     GET  /api/report/:id         读取报告
     GET  /api/status/history     服务状态巡检历史
     GET  /api/health             健康检查（缓存/内存/数据文件）
     GET  /api/admin/purge        清空全部缓存（需 token）
   ============================================================ */
"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");
const dns = require("dns").promises;
const zlib = require("zlib");
const crypto = require("crypto");

const util = require("./lib/util");
const caches = require("./lib/caches");
const geo = require("./lib/geo");
const dnsbl = require("./lib/dnsbl");
const ripe = require("./lib/ripe");
const { ipDeep, ipDeepFull } = require("./lib/ipdeep");
const { ispCheck } = require("./lib/isp");
const { transitStart, transitResult } = require("./lib/transit");
const { cfRisk } = require("./lib/cfrisk");
const { cardSvg } = require("./lib/card");

const { fetchRaw, fetchJson, isV4, isV6, normalizeIp, isBogon, xmlEsc,
        rdapBootstrap, rdapGet, writeJsonAtomic, shortHash } = util;

const PORT = parseInt(process.env.PORT || "80", 10);
const PUBLIC_DIR = path.join(__dirname, "public");
const DATA_DIR = path.join(__dirname, "data");
const DNS_ZONE = process.env.DNS_ZONE || "";

/* 人机校验服务端密钥：默认使用 Google / Cloudflare 官方公开测试密钥（仅演示链路，始终通过）。
   生产环境请通过环境变量配置自有密钥，测试密钥不具备任何防护能力。 */
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET || "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"; // Google 公开测试密钥
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET || "1x0000000000000000000000000000000AA";        // Cloudflare 公开测试密钥

/* ---------------- 访客 IP：仅在直接连接来自本机/内网（反代）时信任转发头 ---------------- */
function getVisitorIp(req) {
  const ra = (req.socket.remoteAddress || "").replace(/^::ffff:/, "");
  const trustedProxy =
    !ra || ra === "::1" || ra === "127.0.0.1" ||
    /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/.test(ra);
  if (trustedProxy) {
    return String(
      req.headers["cf-connecting-ip"] ||
      req.headers["x-real-ip"] ||
      (req.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
      ra || ""
    ).replace(/^::ffff:/, "");
  }
  return ra; // 直连公网访问：使用 socket 真实地址，转发头不可信
}

/* ---------------- 接口限流（按访客 IP 的滑动窗口，防脚本刷重接口） ---------------- */
const RATE_RULES = [
  { re: /^\/api\/(ipscore|cfrisk|ipdeep|ip\/trend)/, limit: 12, name: "heavy" },
  { re: /^\/api\/card\.svg$/, limit: 20, name: "card" },
  { re: /^\/api\/(whois|geoip|iprisk|ping\/start|egress\/geo|tlsinfo|stats)/, limit: 40, name: "light" },
  { re: /^\/api\/(turnstile|recaptcha)\/verify$/, limit: 20, name: "verify" },
  { re: /^\/api\/ooni/, limit: 60, name: "ooni" },
  { re: /^\/api\/gp\/poll/, limit: 120, name: "gppoll" },
  { re: /^\/api\/gp/, limit: 20, name: "gp" },
  { re: /^\/api\/(transit\/start|transit\/result)/, limit: 30, name: "transit" },
  { re: /^\/api\/isp\//, limit: 40, name: "isp" },
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

/* ---------------- 响应输出（自动 gzip） ---------------- */
const COMPRESSIBLE = /json|html|text|javascript|xml|svg/i;
function sendBuf(req, res, code, headers, buf) {
  const ct = headers["Content-Type"] || "";
  if (COMPRESSIBLE.test(ct) && buf.length > 1024 && /\bgzip\b/.test(req.headers["accept-encoding"] || "")) {
    buf = zlib.gzipSync(buf);
    headers = Object.assign({}, headers, { "Content-Encoding": "gzip", Vary: "Accept-Encoding" });
  }
  headers = Object.assign({}, headers, { "Content-Length": buf.length });
  res.writeHead(code, headers);
  res.end(buf);
}
function sendJson(req, res, code, obj, extraHeaders) {
  const h = Object.assign(
    { "Content-Type": "application/json; charset=utf-8", "Access-Control-Allow-Origin": "*" },
    extraHeaders || {}
  );
  sendBuf(req, res, code, h, Buffer.from(JSON.stringify(obj)));
}
function readBody(req, maxLen) {
  return new Promise((resolve) => {
    let body = "";
    req.on("data", (c) => { body += c; if (body.length > (maxLen || 65536)) req.destroy(); });
    req.on("end", () => resolve(body));
    req.on("close", () => resolve(body));
  });
}

/* ---------------- 静态资源自动版本号（内容 hash，部署即失效） ---------------- */
function computeAssetVer() {
  let acc = "";
  const walk = (dir) => {
    let items = [];
    try { items = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return; }
    for (const it of items.sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const p = path.join(dir, it.name);
      if (it.isDirectory()) walk(p);
      else {
        try { const st = fs.statSync(p); acc += p + ":" + st.size + ":" + Math.floor(st.mtimeMs / 1000) + ";"; } catch (e) {}
      }
    }
  };
  walk(path.join(PUBLIC_DIR, "assets"));
  try { const st = fs.statSync(path.join(PUBLIC_DIR, "favicon.svg")); acc += "favicon:" + st.size + ":" + Math.floor(st.mtimeMs / 1000); } catch (e) {}
  return shortHash(acc);
}
const ASSET_VER = computeAssetVer();

/* ---------------- 静态文件 ---------------- */
const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".ico": "image/x-icon",
  ".webmanifest": "application/manifest+json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
};
function serveStatic(req, res, pathname) {
  let rel = decodeURIComponent(pathname);
  if (rel === "/" || rel === "") rel = "/index.html";
  const filePath = path.join(PUBLIC_DIR, path.normalize(rel).replace(/^(\.\.[/\\])+/, ""));
  if (!filePath.startsWith(PUBLIC_DIR)) { res.writeHead(403); return res.end("Forbidden"); }
  let target = filePath;
  fs.stat(target, (err, st) => {
    if (!err && st.isDirectory()) target = path.join(target, "index.html");
    fs.readFile(target, (err2, buf) => {
      if (err2) {
        // /xxx/... 深链接回退到对应页面的 index.html（如 /report/<id>）
        const m = rel.match(/^\/([a-z-]+)\//);
        const fallback = path.join(PUBLIC_DIR, m ? m[1] : "", "index.html");
        if (m) {
          return fs.readFile(fallback, (err3, buf3) => {
            if (err3) { res.writeHead(404); return res.end("Not Found"); }
            sendFile(req, res, buf3, fallback);
          });
        }
        res.writeHead(404); return res.end("Not Found");
      }
      sendFile(req, res, buf, target);
    });
  });
}
function sendFile(req, res, buf, target) {
  const ext = path.extname(target).toLowerCase();
  const ct = MIME[ext] || "application/octet-stream";
  const headers = { "Content-Type": ct };
  let versioned = false;
  try { versioned = new URL(req.url, "http://x").searchParams.has("v"); } catch (e) {}
  if (ct.includes("html")) {
    // HTML 注入资源版本号（?v=AUTO → 内容 hash），本身不缓存
    headers["Cache-Control"] = "no-cache";
    buf = Buffer.from(buf.toString("utf8").replaceAll("?v=AUTO", "?v=" + ASSET_VER));
  } else if (versioned) {
    // 带 ?v= 的静态资源：内容变化会改变 hash，可长缓存
    headers["Cache-Control"] = "public, max-age=2592000";
  } else {
    headers["Cache-Control"] = "no-cache";
  }
  sendBuf(req, res, 200, headers, buf);
}

/* ---------------- IP 评分全家桶（编排各 lib） ---------------- */
async function ipScore(ip) {
  const [riskData, deep] = await Promise.all([geo.geoLookup(ip).catch(() => null), ipDeep(ip)]);
  const risk = riskData ? geo.classifyRisk(riskData) : null;
  if (riskData && riskData.asn) { deep.asn = riskData.asn; deep.asname = riskData.asname || ""; deep.org = riskData.org || riskData.isp || ""; deep.bogon = isBogon(ip); }
  const asn = risk && risk.asn ? await ripe.asnInfo(risk.asn).catch(() => null) : null;
  if (asn && asn.date) deep.asnRegDate = asn.date;
  const [db, rp, sources, route, dbll, domains, sample, neighbours] = await Promise.all([
    dnsbl.dnsblCheck(ip).catch(() => null),
    ripe.rpkiCheck(ip, risk && risk.asn).catch(() => null),
    geo.geoMulti(ip).catch(() => []),
    ripe.routeTopology(ip, risk && risk.asn).catch(() => null),
    dnsbl.dnsblFull(ip).catch(() => null),
    geo.relatedDomains(ip).catch(() => null),
    geo.subnetSample(ip).catch(() => null),
    risk && risk.asn ? ripe.asnNeighbours(risk.asn).catch(() => null) : Promise.resolve(null),
  ]);
  geo.recordGeoHistory(ip, riskData);
  return { ip, risk, deep, asn, dnsbl: db, rpki: rp, sources, route, dnsblFull: dbll, domains, sample, neighbours, geoHistory: geo.geoHistoryFor(ip) };
}

/* ---------------- TLD 统计：IANA 根区可查后缀数 / RDAP 直连数 ---------------- */
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
  const d = { total: tlds.length, rdapCount, tlds: tlds.slice(0, 800), t: Date.now() };
  tldStatsCache = { d, t: Date.now() };
  return d;
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

/* ---------------- check-host.net 全球节点 Ping 代理 ---------------- */
const CH = { ua: { "Accept": "application/json", "User-Agent": "NetProbe/1.0 (site tool)" } };
function isPrivateTarget(t) {
  if (/^(127\.|10\.|192\.168\.|0\.|169\.254\.)/.test(t)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(t)) return true;
  if (/^::1$/.test(t) || /^f[cd][0-9a-f]{2}:/i.test(t)) return true;
  return false;
}
async function pingStart(host) {
  if (isPrivateTarget(host)) throw new Error("private_target");
  const r = await fetchJson("https://check-host.net/check-ping?host=" + encodeURIComponent(host) + "&max_nodes=25", CH.ua, 12000);
  if (r.error) throw new Error(r.error);
  return r;
}
async function pingResult(id) {
  return fetchJson("https://check-host.net/check-result/" + encodeURIComponent(id), CH.ua, 12000);
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

/* ---------------- 自托管 DNS 泄露检测 ---------------- */
let dnsTokens = new Map();

/* ---------------- 检测报告分享（快照存储，30 天过期） ---------------- */
const REPORT_FILE = path.join(DATA_DIR, "reports.json");
let reports = {};
try { reports = JSON.parse(fs.readFileSync(REPORT_FILE, "utf8")); } catch (e) {}
let reportSaveTimer = null;
function saveReports() {
  if (reportSaveTimer) return;
  reportSaveTimer = setTimeout(() => {
    reportSaveTimer = null;
    try { writeJsonAtomic(REPORT_FILE, JSON.stringify(reports)); } catch (e) {}
  }, 2000);
  if (reportSaveTimer.unref) reportSaveTimer.unref();
}
function pruneReports() {
  const cutoff = Date.now() - 30 * 86400000;
  for (const [id, r] of Object.entries(reports)) {
    const exp = r.exp || r.t + 30 * 86400000;
    if (exp < Date.now()) delete reports[id];
  }
}
function createReport(body) {
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
  const id = crypto.randomBytes(5).toString("base64url").replace(/[-_]/g, "a").slice(0, 6);
  let ttl = (parseInt(body.ttl, 10) || 604800) * 1000; // 客户端传秒，内部统一毫秒
  ttl = Math.min(Math.max(ttl, 3600000), 30 * 86400000);
  reports[id] = { id, t: Date.now(), exp: Date.now() + ttl, d };
  const ids = Object.keys(reports);
  if (ids.length > 500) {
    ids.sort((a, b) => reports[a].t - reports[b].t);
    while (ids.length > 500) delete reports[ids.shift()];
  }
  pruneReports();
  saveReports();
  return { id };
}

/* ---------------- 服务状态巡检（服务端定时，供状态历史与通知） ---------------- */
const STATUS_SERVICES = [
  { name: "OpenAI / ChatGPT", url: "https://status.openai.com/api/v2/summary.json" },
  { name: "Claude (Anthropic)", url: "https://status.anthropic.com/api/v2/summary.json" },
  { name: "Perplexity", url: "https://status.perplexity.com/api/v2/summary.json" },
  { name: "Cursor", url: "https://status.cursor.com/api/v2/summary.json" },
  { name: "Groq", url: "https://groqstatus.com/api/v2/summary.json" },
  { name: "ElevenLabs", url: "https://status.elevenlabs.io/api/v2/summary.json" },
  { name: "Replicate", url: "https://status.replicate.com/api/v2/summary.json" },
  { name: "Hugging Face", url: "https://status.huggingface.co/api/v2/summary.json" },
  { name: "Cloudflare", url: "https://www.cloudflarestatus.com/api/v2/summary.json" },
  { name: "Vercel", url: "https://www.vercel-status.com/api/v2/summary.json" },
  { name: "Supabase", url: "https://status.supabase.com/api/v2/summary.json" },
  { name: "Fly.io", url: "https://status.flyio.net/api/v2/summary.json" },
  { name: "DigitalOcean", url: "https://status.digitalocean.com/api/v2/summary.json" },
  { name: "Figma", url: "https://status.figma.com/api/v2/summary.json" },
  { name: "GitHub", url: "https://www.githubstatus.com/api/v2/summary.json" },
  { name: "npm", url: "https://status.npmjs.org/api/v2/summary.json" },
  { name: "Atlassian", url: "https://status.atlassian.com/api/v2/summary.json" },
  { name: "Sentry", url: "https://status.sentry.io/api/v2/summary.json" },
  { name: "Discord", url: "https://discordstatus.com/api/v2/summary.json" },
  { name: "Zoom", url: "https://status.zoom.us/api/v2/summary.json" },
];
const STATUS_LOG_FILE = path.join(DATA_DIR, "status-log.json");
let statusLog = { current: {}, changes: [], lastRun: 0 };
try { statusLog = Object.assign(statusLog, JSON.parse(fs.readFileSync(STATUS_LOG_FILE, "utf8"))); } catch (e) {}
let statusSaveTimer = null;
function saveStatusLog() {
  if (statusSaveTimer) return;
  statusSaveTimer = setTimeout(() => {
    statusSaveTimer = null;
    try { writeJsonAtomic(STATUS_LOG_FILE, JSON.stringify(statusLog)); } catch (e) {}
  }, 3000);
  if (statusSaveTimer.unref) statusSaveTimer.unref();
}
async function notifyTelegram(text) {
  if (!process.env.TG_BOT_TOKEN || !process.env.TG_CHAT_ID) return;
  try {
    await fetch("https://api.telegram.org/bot" + process.env.TG_BOT_TOKEN + "/sendMessage", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: process.env.TG_CHAT_ID, text }),
    });
  } catch (e) {}
}
let patrolling = false;
async function patrolStatuses() {
  if (patrolling) return;
  patrolling = true;
  try {
    const results = await Promise.all(STATUS_SERVICES.map(async (svc) => {
      try {
        const d = await fetchJson(svc.url, null, 9000);
        const level = (d.status && d.status.indicator) || "none";
        return { name: svc.name, level, desc: (d.status && d.status.description) || "" };
      } catch (e) {
        return { name: svc.name, level: "unknown", desc: "巡检查询失败" };
      }
    }));
    const now = new Date().toISOString();
    const fresh = [];
    for (const r of results) {
      const prev = statusLog.current[r.name];
      if (!prev || prev.level !== r.level) {
        fresh.push({ t: now, name: r.name, from: prev ? prev.level : "init", to: r.level, desc: r.desc });
      }
      statusLog.current[r.name] = { level: r.level, desc: r.desc, t: now };
    }
    if (fresh.length) {
      statusLog.changes = fresh.concat(statusLog.changes).slice(0, 200);
      notifyTelegram("NetProbe 服务状态变化：\n" + fresh.map((f) => f.name + ": " + f.from + " → " + f.to).join("\n"));
      saveStatusLog();
    }
    statusLog.lastRun = Date.now();
  } catch (e) {} finally { patrolling = false; }
}

/* ---------------- 管理员 token（首次启动自动生成） ---------------- */
const ADMIN_TOKEN_FILE = path.join(DATA_DIR, "admin-token");
let ADMIN_TOKEN = "";
try { ADMIN_TOKEN = fs.readFileSync(ADMIN_TOKEN_FILE, "utf8").trim(); } catch (e) {}
if (!ADMIN_TOKEN) {
  ADMIN_TOKEN = crypto.randomBytes(16).toString("hex");
  try { writeJsonAtomic(ADMIN_TOKEN_FILE, JSON.stringify(ADMIN_TOKEN)); } catch (e) {}
  console.log("[admin] 生成管理 token: " + ADMIN_TOKEN + "（存储于 data/admin-token）");
}

/* ---------------- 健康检查 ---------------- */
function dataFileSizes() {
  const out = {};
  try {
    for (const f of fs.readdirSync(DATA_DIR)) {
      const st = fs.statSync(path.join(DATA_DIR, f));
      if (st.isFile()) out[f] = st.size;
    }
  } catch (e) {}
  return out;
}

/* ---------------- Torrent 地址检测（内存版 BT Tracker） ----------------
   原理同 Workers 版：/torrent/ 页面为访客生成随机 info_hash 的 Magnet 链接，
   BT 客户端添加后向本站 /api/torrent/announce 发起 announce，这里记录来源 IP
   并由浏览器轮询 /api/torrent/results 回显。单进程内存存储，peer 30 分钟无
   活动剔除，房间 2 小时无活动清空。 */

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
      if (v[i] === "%" && i + 2 <= v.length) {
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
function bTrackSend(res, body) {
  res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
  res.end(body);
}

const torrentRooms = new Map();
function torrentRecordMem(hex, info) {
  let st = torrentRooms.get(hex);
  if (!st) {
    st = { map: {}, updated: 0 };
    torrentRooms.set(hex, st);
    if (torrentRooms.size > 400) torrentRooms.delete(torrentRooms.keys().next().value);
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

/* ---------------- 全站查询计数（内存级，按天分桶 + 累计） ---------------- */
const statsCounters = { today: "", todayN: 0, total: 0 };
function statsHit() {
  const t = new Date().toISOString().slice(0, 10);
  if (statsCounters.today !== t) { statsCounters.today = t; statsCounters.todayN = 0; }
  statsCounters.todayN++; statsCounters.total++;
}

/* ---------------- HTTP 服务 ---------------- */
const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, "http://" + (req.headers.host || "localhost"));
  const p = u.pathname;
  const visitorIp = getVisitorIp(req);

  try {
    let m;
    if (p === "/api/session") {
      return sendJson(req, res, 200, { ip: visitorIp, ua: req.headers["user-agent"] || "" });
    }
    if (p === "/api/health") {
      return sendJson(req, res, 200, {
        ok: true,
        uptime_s: Math.floor(process.uptime()),
        node: process.version,
        rss_mb: Math.round(process.memoryUsage().rss / 1048576),
        asset_ver: ASSET_VER,
        caches: caches.stats(),
        reports: Object.keys(reports).length,
        patrol_last_run: statusLog.lastRun,
        patrol_current_bad: Object.entries(statusLog.current).filter(([, v]) => v.level && v.level !== "none").length,
        data_files: dataFileSizes(),
      });
    }
    if (p === "/api/admin/purge") {
      if ((u.searchParams.get("token") || "") !== ADMIN_TOKEN) return sendJson(req, res, 403, { ok: false, error: "token 无效" });
      const cleared = caches.clearAll();
      rateBuckets.clear();
      tldStatsCache = null;
      return sendJson(req, res, 200, { ok: true, cleared });
    }

    // 限流（健康检查与管理接口豁免）
    const rl = rateLimit(visitorIp, p);
    if (!rl.ok) {
      return sendJson(req, res, 429, { error: "请求过于频繁，请稍后再试" }, { "Retry-After": String(rl.retry) });
    }

    if ((m = p.match(/^\/api\/geoip\/(.+)$/))) {
      statsHit();
      return sendJson(req, res, 200, await geo.geoLookup(decodeURIComponent(m[1])));
    }
    if ((m = p.match(/^\/api\/iprisk\/(.+)$/))) {
      statsHit();
      return sendJson(req, res, 200, geo.classifyRisk(await geo.geoLookup(decodeURIComponent(m[1]))));
    }
    if ((m = p.match(/^\/api\/ipdeep\/(.+)$/))) {
      statsHit();
      return sendJson(req, res, 200, await ipDeepFull(decodeURIComponent(m[1])));
    }
    if ((m = p.match(/^\/api\/ipscore\/(.+)$/))) {
      statsHit();
      return sendJson(req, res, 200, await ipScore(decodeURIComponent(m[1])));
    }
    // ISP 家宽判定（是否住宅宽带 IP）
    if ((m = p.match(/^\/api\/isp\/(.+)$/))) {
      statsHit();
      const tip = decodeURIComponent(m[1]);
      if (!isV4(tip) && !isV6(tip)) return sendJson(req, res, 400, { error: "无效的 IP 地址" });
      const rd = await geo.geoLookup(tip).catch(() => null);
      const dp = await ipDeep(tip).catch(() => null);
      return sendJson(req, res, 200, await ispCheck(tip, rd, dp));
    }
    // 中转站路径探测：发起
    if ((m = p.match(/^\/api\/transit\/start\/(.+)$/))) {
      statsHit();
      const tip = decodeURIComponent(m[1]);
      if (!isV4(tip) && !isV6(tip)) return sendJson(req, res, 400, { error: "无效的 IP 地址" });
      if (isPrivateTarget(tip) || isBogon(tip)) return sendJson(req, res, 400, { error: "private_target" });
      const mn = u.searchParams.get("nodes") || "";
      try {
        return sendJson(req, res, 200, await transitStart(tip, mn));
      } catch (e) {
        return sendJson(req, res, 502, { error: String(e.message || e) });
      }
    }
    // 中转站路径探测：取结果
    if ((m = p.match(/^\/api\/transit\/result\/([A-Za-z0-9_-]{4,64})$/))) {
      statsHit();
      const r = await transitResult(m[1]).catch(() => ({ error: "failed" }));
      if (r && r.error) return sendJson(req, res, 404, r);
      return sendJson(req, res, 200, r);
    }
    // 分流出口检测：批量补齐出口 IP 的归属地
    if (p === "/api/egress/geo" && req.method === "POST") {
      const body = await readBody(req, 4096);
      let ips = [];
      try { ips = (JSON.parse(body).ips || []).map((x) => String(x || "").trim()); } catch (e) {}
      ips = ips.filter((x) => isV4(x) || isV6(x)).slice(0, 24);
      const out = {};
      await Promise.allSettled(ips.map(async (ip) => {
        try { out[ip] = await geo.geoLookup(ip); } catch (e) {}
      }));
      return sendJson(req, res, 200, { ok: true, geo: out });
    }
    // TLS 指纹：本地 HTTPS 部署才有值（ Workers 版取 request.cf 字段）
    if (p === "/api/tlsinfo") {
      let d = { tlsVersion: null, tlsCipher: null, helloLength: null, extensionsSha1: null, asn: null, asOrganization: null, country: null };
      try {
        const sock = req.socket;
        if (typeof sock.getCipher === "function" && sock.encrypted) {
          const c = sock.getCipher();
          const cert = sock.getCertificate && sock.getCertificate();
          if (c) { d.tlsVersion = sock.getProtocol ? sock.getProtocol() : null; d.tlsCipher = c.name || null; }
          if (cert && cert.valid_from) d.certNotBefore = cert.valid_from;
        }
      } catch (e) {}
      d.available = !!(d.tlsVersion && d.tlsCipher);
      if (!d.available) d.note = "本地为 HTTP 部署，无 TLS 握手指纹；线上 Workers 版会返回 ClientHello 摘要字段";
      return sendJson(req, res, 200, d);
    }
    // reCAPTCHA v3 评分（默认使用 Google 官方公开测试密钥，演示链路用；可用环境变量覆盖为自有密钥）
    if (p === "/api/recaptcha/verify" && req.method === "POST") {
      const body = await readBody(req, 16384);
      let token = "";
      try { token = String(JSON.parse(body).token || "").slice(0, 8192); } catch (e) {}
      if (!token) return sendJson(req, res, 400, { ok: false, reason: "缺少 token" });
      try {
        const resp = await fetch("https://www.google.com/recaptcha/api/siteverify", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "NetProbe/1.0" },
          body: new URLSearchParams({ secret: RECAPTCHA_SECRET, response: token }).toString(),
          signal: AbortSignal.timeout(10000),
        });
        const d = await resp.json();
        return sendJson(req, res, 200, { ok: !!d.success, score: typeof d.score === "number" ? d.score : null, action: d.action || "", errors: d["error-codes"] || [] });
      } catch (e) {
        return sendJson(req, res, 200, { ok: false, score: null, errors: ["verification_unreachable"] });
      }
    }
    // 全站查询计数（首页横幅）
    if (p === "/api/ooni") {
      const q = u.searchParams.get("path") || "";
      if (!/^\/api\/v1\/measurements\?/.test(q)) return sendJson(req, res, 403, { error: "not allowed" });
      const d = await fetchJson("https://api.ooni.io" + q, { "User-Agent": "NetProbe/1.0" }, 20000);
      return sendJson(req, res, 200, d);
    }
    if (p === "/api/gp" && req.method === "POST") {
      const body = await readBody(req, 65536);
      const r = await fetch("https://api.globalping.io/v1/measurements", {
        method: "POST",
        headers: { "Content-Type": "application/json", "User-Agent": "NetProbe/1.0" },
        body,
      });
      res.writeHead(r.status, { "Content-Type": "application/json", "X-GP-Location": r.headers.get("Location") || "", "Cache-Control": "no-store" });
      res.end(await r.text());
      return;
    }
    if (p === "/api/gp/poll") {
      const id = u.searchParams.get("id") || "";
      if (!/^[A-Za-z0-9-]{4,64}$/.test(id)) return sendJson(req, res, 400, { error: "bad id" });
      const d = await fetchJson("https://api.globalping.io/v1/measurements/" + id, { "User-Agent": "NetProbe/1.0" }, 15000);
      return sendJson(req, res, 200, d);
    }
    if (p === "/api/stats") {
      const t = new Date().toISOString().slice(0, 10);
      return sendJson(req, res, 200, {
        today: statsCounters.today === t ? statsCounters.todayN : 0,
        total: statsCounters.total,
      });
    }
    if ((m = p.match(/^\/api\/ip\/trend\/(.+)$/))) {
      return sendJson(req, res, 200, geo.trendFor(decodeURIComponent(m[1])));
    }
    if ((m = p.match(/^\/api\/cfrisk\/(.+)$/))) {
      return sendJson(req, res, 200, await cfRisk(decodeURIComponent(m[1])));
    }
    if (p === "/api/card.svg") {
      const param = u.searchParams.get("ip") || "";
      const target = (isV4(param) || isV6(param)) ? param : visitorIp;
      if (!target || target === "::1" || target === "127.0.0.1") {
        res.writeHead(200, { "Content-Type": "image/svg+xml; charset=utf-8", "Cache-Control": "no-store" });
        return res.end('<svg xmlns="http://www.w3.org/2000/svg" width="480" height="227" viewBox="0 0 720 340"><rect width="720" height="340" rx="28" fill="#1e293b"/><text x="360" y="180" font-size="30" fill="#94a3b8" text-anchor="middle" font-family="sans-serif">无法识别访客 IP（本地访问）</text></svg>');
      }
      const styleKey = u.searchParams.get("style") || "midnight";
      const stickerKey = u.searchParams.get("sticker") || "none";
      let w = parseInt(u.searchParams.get("w"), 10);
      if (!w || w < 120 || w > 1440) w = 480;
      const card = await cardSvg(target, styleKey, stickerKey, w);
      res.writeHead(200, { "Content-Type": card.ct, "Cache-Control": "public, max-age=300", "Access-Control-Allow-Origin": "*" });
      return res.end(card.svg);
    }
    if (p === "/api/turnstile/verify" && req.method === "POST") {
      const body = await readBody(req);
      let token = "";
      try { token = String(JSON.parse(body).token || "").slice(0, 4096); } catch (e) {}
      if (!token) return sendJson(req, res, 400, { ok: false, reason: "缺少 token" });
      try {
        const resp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "NetProbe/1.0" },
          body: new URLSearchParams({ secret: TURNSTILE_SECRET, response: token }).toString(),
          signal: AbortSignal.timeout(10000),
        });
        const d = await resp.json();
        return sendJson(req, res, 200, { ok: !!d.success, errors: d["error-codes"] || [] });
      } catch (e) {
        return sendJson(req, res, 200, { ok: false, errors: ["verification_unreachable"] });
      }
    }
    if (p === "/api/whois") {
      return sendJson(req, res, 200, await whoisQuery(u.searchParams.get("q") || ""));
    }
    if (p === "/api/whois/tlds") {
      const s = await tldStats();
      return sendJson(req, res, 200, { total: s.total, rdapCount: s.rdapCount, tlds: s.tlds });
    }
    if (p === "/api/ping/start") {
      return sendJson(req, res, 200, await pingStart(u.searchParams.get("host") || visitorIp));
    }
    if ((m = p.match(/^\/api\/ping\/result\/([a-z0-9]+)$/))) {
      return sendJson(req, res, 200, await pingResult(m[1]));
    }
    if ((m = p.match(/^\/api\/dnsleak\/([a-z0-9]+)$/))) {
      const d = await fetchJson("https://ipleak.net/jsondns/" + m[1], { "User-Agent": "NetProbe/1.0" }, 10000);
      return sendJson(req, res, 200, d);
    }
    if (p === "/api/doh") {
      const target = u.searchParams.get("u") || "";
      if (!DOH_ALLOW.some((pre) => target.startsWith(pre))) {
        return sendJson(req, res, 403, { error: "not allowed" });
      }
      const d = await fetchJson(target, { accept: "application/dns-json", "User-Agent": "NetProbe/1.0" }, 8000);
      return sendJson(req, res, 200, d);
    }
    if (p === "/api/dns/config") {
      const zone = DNS_ZONE ? await dns.resolveNs(DNS_ZONE).then(() => DNS_ZONE).catch(() => "") : "";
      return sendJson(req, res, 200, { enabled: !!zone, zone });
    }
    if ((m = p.match(/^\/api\/dns\/result\/([a-z0-9-]+)$/))) {
      return sendJson(req, res, 200, { resolvers: dnsTokens.get(m[1]) || [] });
    }
    if (p === "/api/torrent/announce") {
      // BitTorrent HTTP Tracker：必须回 bencode，任何错误也不能回 JSON
      try {
        const ih = rawQueryBytes(req.url, "info_hash");
        if (!ih || ih.length !== 20) return bTrackSend(res, bTrackFail("invalid info_hash"));
        const hex = bytesToHex(ih);
        const pid = bytesToHex(rawQueryBytes(req.url, "peer_id") || []);
        const ua = req.headers["user-agent"] || "";
        const q = u.searchParams;
        torrentRecordMem(hex, {
          ip: visitorIp,
          port: Math.min(65535, parseInt(q.get("port") || "0", 10) || 0),
          peer: pid,
          client: clientName(pid, ua),
          agent: ua.slice(0, 100),
          event: (q.get("event") || "").slice(0, 16),
          left: parseInt(q.get("left") || "0", 10) || 0,
        });
        let complete = 0, incomplete = 0;
        Object.values(torrentRooms.get(hex).map).forEach((x) => (x.left === 0 ? complete++ : incomplete++));
        return bTrackSend(res, bTrackOk(complete, incomplete));
      } catch (e) {
        return bTrackSend(res, bTrackFail("internal error"));
      }
    }
    if (p === "/api/torrent/results") {
      const hex = (u.searchParams.get("h") || "").toLowerCase();
      if (!/^[0-9a-f]{40}$/.test(hex)) return sendJson(req, res, 400, { ok: false, error: "bad hash" });
      const st = torrentRooms.get(hex) || { map: {}, updated: 0 };
      return sendJson(req, res, 200, {
        ok: true,
        hash: hex,
        updated: st.updated || 0,
        peers: Object.values(st.map).sort((a, b) => b.last - a.last),
      });
    }
    if (p === "/api/report" && req.method === "POST") {
      const body = await readBody(req, 8192);
      let data = {};
      try { data = JSON.parse(body) || {}; } catch (e) {}
      try {
        const r = createReport(data);
        return sendJson(req, res, 200, { ok: true, id: r.id, url: "/report/" + r.id });
      } catch (e) {
        return sendJson(req, res, 400, { ok: false, error: e.message || "参数错误" });
      }
    }
    if ((m = p.match(/^\/api\/report\/([A-Za-z0-9]+)$/))) {
      const r = reports[m[1]];
      if (!r || (r.exp && r.exp < Date.now())) {
        if (r) delete reports[m[1]];
        return sendJson(req, res, 404, { ok: false, error: "报告不存在或已过期" });
      }
      return sendJson(req, res, 200, { ok: true, t: r.t, d: r.d });
    }
    if (p === "/api/status/history") {
      return sendJson(req, res, 200, {
        current: statusLog.current,
        changes: statusLog.changes.slice(0, 40),
        lastRun: statusLog.lastRun,
      });
    }
    return serveStatic(req, res, p);
  } catch (e) {
    sendJson(req, res, 502, { error: e.message || "upstream error" });
  }
});

/* 自托管 DNS 泄露：UDP 53 采集 */
if (DNS_ZONE) {
  const dgram = require("dgram");
  const sock = dgram.createSocket("udp4");
  sock.on("message", (msg, rinfo) => {
    try {
      let labels = [], i = 12;
      while (msg[i] !== 0 && i < msg.length) {
        const len = msg[i++];
        labels.push(msg.slice(i, i + len).toString("ascii"));
        i += len;
      }
      const qname = labels.join(".");
      const mt = qname.match(/^([a-z0-9]+(?:-[0-9]+)?)\./);
      if (mt) {
        const token = mt[1].split("-")[0];
        if (!dnsTokens.has(token)) dnsTokens.set(token, []);
        const arr = dnsTokens.get(token);
        if (!arr.some((x) => x.ip === rinfo.address)) arr.push({ ip: rinfo.address, ts: Date.now() });
        setTimeout(() => dnsTokens.delete(token), 60 * 1000);
      }
    } catch (e) {}
  });
  try {
    sock.bind(53, () => console.log("[dns] listening on :53 for *" + DNS_ZONE));
  } catch (e) {
    console.error("[dns] cannot bind :53:", e.message);
  }
}

/* 服务状态巡检：启动 10 秒后首跑，此后每 5 分钟一轮 */
setTimeout(patrolStatuses, 10000).unref();
setInterval(patrolStatuses, 5 * 60 * 1000).unref();

server.listen(PORT, () => {
  console.log("NetProbe server running at http://0.0.0.0:" + PORT + " (assets v" + ASSET_VER + ")");
  if (!DNS_ZONE) console.log("[dns] DNS_ZONE 未配置，DNS 泄露检测走 ipleak 公共接口");
});
