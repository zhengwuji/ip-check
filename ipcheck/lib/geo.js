/* ============================================================
   lib/geo.js — GeoIP 聚合 / 风险分类 / 多源定位 / 网段趋势 / 位置历史
   依赖：util（fetchJson/normalizeIp/writeJsonAtomic）、caches
   ============================================================ */
"use strict";
const fs = require("fs");
const path = require("path");
const dns = require("dns").promises;
const { fetchJson, normalizeIp, isV4, writeJsonAtomic } = require("./util");
const { makeCache } = require("./caches");

const DATA_DIR = path.join(__dirname, "..", "data");
const CACHE_FILE = path.join(DATA_DIR, "geoip-cache.json");
const GEO_TTL = 30 * 24 * 3600 * 1000;

/* ---------------- 磁盘持久化缓存（原子写盘） ---------------- */
const geoCache = makeCache("geoip", GEO_TTL, 50000);
try {
  const raw = JSON.parse(fs.readFileSync(CACHE_FILE, "utf8"));
  for (const [k, v] of Object.entries(raw)) {
    if (Date.now() - v.t < GEO_TTL) geoCache.set(k, v.d !== undefined ? v.d : v);
  }
} catch (e) { /* 首次运行无缓存 */ }

let saveTimer = null;
function scheduleSave() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    try {
      const out = {};
      for (const [k, v] of geoCache.map) out[k] = v;
      writeJsonAtomic(CACHE_FILE, JSON.stringify(out));
    } catch (e) { /* 忽略 */ }
  }, 3000);
  if (saveTimer.unref) saveTimer.unref();
}

/* ---------------- GeoIP 聚合（ip.sb → ipwho.is → ip-api） ---------------- */
async function geoLookup(ip) {
  const key = normalizeIp(ip);
  const hit = geoCache.get(key);
  if (hit) { recordTrend(ip, quickPurity(hit)); return hit; }

  let d = null;
  // 源 1：ip.sb
  try {
    const r = await fetchJson("https://api.ip.sb/geoip/" + encodeURIComponent(ip), { "User-Agent": "NetProbe/1.0" });
    if (r && r.country) {
      d = {
        ip: r.ip || ip,
        country: r.country || "",
        country_code: (r.country_code || "").toLowerCase(),
        region: r.region || "",
        city: r.city || "",
        isp: r.isp || r.organization || "",
        org: r.organization || "",
        asn: r.asn || null,
        latitude: r.latitude || null,
        longitude: r.longitude || null,
      };
    }
  } catch (e) {}
  // 源 2：ipwho.is
  if (!d) {
    try {
      const r = await fetchJson("https://ipwho.is/" + encodeURIComponent(ip));
      if (r && r.success !== false && r.country) {
        d = {
          ip: r.ip || ip,
          country: r.country || "",
          country_code: (r.country_code || "").toLowerCase(),
          region: r.region || "",
          city: r.city || "",
          isp: (r.connection && r.connection.isp) || "",
          org: (r.connection && r.connection.org) || "",
          asn: r.connection && r.connection.asn || null,
          latitude: r.latitude || null,
          longitude: r.longitude || null,
        };
      }
    } catch (e) {}
  }
  // 源 3：ip-api.com（含 proxy/hosting/reverse 增强字段）
  let extra = null;
  try {
    extra = await fetchJson(
      "http://ip-api.com/json/" + encodeURIComponent(ip) +
      "?fields=status,message,country,countryCode,regionName,city,isp,org,as,asname,reverse,proxy,hosting,mobile,lat,lon"
    );
  } catch (e) {}
  if (!d && extra && extra.status === "success") {
    const asMatch = String(extra.as || "").match(/^AS(\d+)/);
    d = {
      ip,
      country: extra.country || "",
      country_code: (extra.countryCode || "").toLowerCase(),
      region: extra.regionName || "",
      city: extra.city || "",
      isp: extra.isp || "",
      org: extra.org || "",
      asn: asMatch ? parseInt(asMatch[1], 10) : null,
      latitude: extra.lat || null,
      longitude: extra.lon || null,
    };
  }
  if (!d) throw new Error("geoip unavailable");

  if (extra && extra.status === "success") {
    d.proxy = !!extra.proxy;
    d.hosting = !!extra.hosting;
    d.mobile = !!extra.mobile;
    d.asname = extra.asname || "";
    d.reverse = extra.reverse || "";
    if (extra.country) d.country = extra.country;
    if (extra.countryCode) d.country_code = String(extra.countryCode).toLowerCase();
    if (extra.regionName) d.region = extra.regionName;
    if (extra.city) d.city = extra.city;
    if (extra.isp && !d.isp) d.isp = extra.isp;
    if (extra.org && !d.org) d.org = extra.org;
    const asMatch2 = String(extra.as || "").match(/^AS(\d+)/);
    if (!d.asn && asMatch2) d.asn = parseInt(asMatch2[1], 10);
  }

  geoCache.set(key, d);
  scheduleSave();
  recordTrend(ip, quickPurity(d));
  return d;
}

/* 供趋势记录用的快速纯净度估算（轻量，不查黑名单） */
function quickPurity(d) {
  if (!d) return null;
  let p = 100;
  if (d.hosting === true) p -= 12;
  if (d.proxy === true) p -= 30;
  return Math.max(0, p);
}

/* ---------------- IP 风险分类 ---------------- */
const DATACENTER_ASN = new Set([
  13335, 16509, 15169, 8075, 14061, 20473, 63949, 45102,
  9009, 16276, 24940, 51167, 396982, 14618, 16592, 200052, 35048, 49870,
  398101, 396356, 54113, 55286, 60781, 45899, 59318, 209605, 212238, 208276,
]);
/* 机房/云特征词。注意：不要加入 communications / networks 这类通用词——
   Comcast Cable Communications、Charter Communications 等接入型 ISP 名称里都有，
   会把家宽误判成机房（同时影响 classifyRisk 与 isp.js 的家宽判定）。 */
const DATACENTER_ORG = /amazon|aws|google|microsoft|azure|oracle|digitalocean|linode|vultr|choopa|hetzner|ovh|scaleway|contabo|m247|leaseweb|alibaba|tencent|huawei|ucloud|qiniu|bandwagon|hostwinds|kamatera|upcloud|akamai|fastly|cloudflare|datacamp|packethub|gcore|melbikomas|xhost|aeza|justhost|bluevps|hosting|\bhost\b|vps|datacenter|data center|colo\b|it7|zendata|psychz|quadranet|colocation/i;
const RESIDENTIAL_HINT = /telecom|telekom|comcast|verizon|at&t|china (telecom|unicom|mobile)|chinanet|cnnet|cmcc|t-mobile|sprint|vodafone|orange|jio|airtel|pldt|virgin|charter|cox|spectrum|kddi|softbank|ntt docomo|hinet|电信|联通|移动|广电|长城宽带|鹏博士|家庭宽带/i;
const EDUCATION_HINT = /university|edu\b|教育网|cernet|school|college/i;

function classifyRisk(d) {
  const org = d.org || d.isp || "";
  const hostingFlag = d.hosting;
  const proxyFlag = d.proxy;

  let isDatacenter;
  if (hostingFlag === true) isDatacenter = true;
  else if (hostingFlag === false) isDatacenter = DATACENTER_ASN.has(d.asn);
  else isDatacenter = DATACENTER_ASN.has(d.asn) || DATACENTER_ORG.test(org);

  let isResidential = !isDatacenter && RESIDENTIAL_HINT.test(org);
  if (!isDatacenter && !isResidential && org) isResidential = true;
  const isEducation = !isDatacenter && EDUCATION_HINT.test(org);

  // 免费风控库（ip-api）把绝大多数机房网段都标 proxy=true，
  // 无法区分"机房 IP"与"在用的 VPN/代理出口"：
  //   proxy=true 且非机房 → 视为真实匿名/代理特征
  //   proxy=true 且机房   → 仅视为机房特征（is_hosting_proxy），不按代理惩罚
  const isRealProxy = proxyFlag === true && !isDatacenter;
  const isHostingProxy = proxyFlag === true && isDatacenter;

  let label;
  if (isEducation) label = "教育网 (Education)";
  else if (isDatacenter) label = "机房IP (Hosting)";
  else if (isResidential) label = "家庭宽带 (ISP)";
  else label = "未知";

  return {
    ip: d.ip,
    country: d.country,
    country_code: d.country_code,
    region: d.region,
    city: d.city,
    isp: d.isp,
    org: d.org,
    asn: d.asn,
    asname: d.asname || "",
    reverse: d.reverse || "",
    is_datacenter: isDatacenter,
    isResidential: isResidential && !isDatacenter,
    is_proxy: isRealProxy,
    is_hosting_proxy: isHostingProxy,
    is_mobile: !!d.mobile,
    company_type: isEducation ? "education" : isDatacenter ? "hosting" : isResidential ? "isp" : "unknown",
    label,
    note: "基于 GeoIP 多源与 ASN/组织名的启发式分类，仅供参考",
  };
}

/* ---------------- 多源定位比对（三库经纬度交叉验证） ---------------- */
const geoMultiCache = makeCache("geo-multi", 24 * 3600000);
async function geoMulti(ip) {
  const key = normalizeIp(ip);
  const hit = geoMultiCache.get(key);
  if (hit) return hit;
  const jobs = [
    fetchJson("https://api.ip.sb/geoip/" + encodeURIComponent(ip), { "User-Agent": "NetProbe/1.0" }, 6000)
      .then((r) => (r && r.latitude != null ? { src: "ip.sb", lat: r.latitude, lon: r.longitude, city: r.city || "", cc: (r.country_code || "").toLowerCase() } : null))
      .catch(() => null),
    fetchJson("https://ipwho.is/" + encodeURIComponent(ip), null, 6000)
      .then((r) => (r && r.success !== false && r.latitude != null ? { src: "ipwho.is", lat: r.latitude, lon: r.longitude, city: r.city || "", cc: (r.country_code || "").toLowerCase() } : null))
      .catch(() => null),
    fetchJson("http://ip-api.com/json/" + encodeURIComponent(ip) + "?fields=status,lat,lon,city,countryCode", null, 6000)
      .then((r) => (r && r.status === "success" ? { src: "ip-api.com", lat: r.lat, lon: r.lon, city: r.city || "", cc: (r.countryCode || "").toLowerCase() } : null))
      .catch(() => null),
  ];
  const settled = await Promise.allSettled(jobs);
  const d = settled.map((s) => (s.status === "fulfilled" ? s.value : null)).filter(Boolean);
  geoMultiCache.set(key, d);
  return d;
}

/* ---------------- 网段查询热度趋势（含快速纯净度均值） ----------------
   数据结构（兼容旧版纯数字计数）：
   trendData[day][subnet] = { c: 次数, ps: 纯净度求和, n: 采样数 } 或 数字 */
const TREND_FILE = path.join(DATA_DIR, "trend.json");
let trendData = {};
try { trendData = JSON.parse(fs.readFileSync(TREND_FILE, "utf8")); } catch (e) { /* 首次运行 */ }
let trendSaveTimer = null;
const trendLastHit = new Map(); // 子网 → 上次计数时间戳（60 秒去重）

function recordTrend(ip, purity) {
  const key = normalizeIp(ip);
  if (!isV4(key)) return; // 趋势按 /24 统计，仅 IPv4
  const subnet = key.replace(/\.\d+$/, "");
  const now = Date.now();
  if (now - (trendLastHit.get(subnet) || 0) < 60 * 1000) return;
  trendLastHit.set(subnet, now);
  if (trendLastHit.size > 20000) trendLastHit.clear();
  const day = new Date().toISOString().slice(0, 10);
  if (!trendData[day]) trendData[day] = {};
  let e = trendData[day][subnet];
  if (typeof e === "number") e = { c: e, ps: 0, n: 0 };
  if (!e) e = { c: 0, ps: 0, n: 0 };
  e.c += 1;
  if (purity != null && isFinite(purity)) { e.ps += purity; e.n += 1; }
  trendData[day][subnet] = e;
  const days = Object.keys(trendData).sort();
  while (days.length > 30) delete trendData[days.shift()];
  if (!trendSaveTimer) {
    trendSaveTimer = setTimeout(() => {
      trendSaveTimer = null;
      try { writeJsonAtomic(TREND_FILE, JSON.stringify(trendData)); } catch (e2) { /* 忽略 */ }
    }, 8000);
    if (trendSaveTimer.unref) trendSaveTimer.unref();
  }
}

function trendFor(ip) {
  const key = normalizeIp(ip);
  const subnet = key.replace(/\.\d+$/, "");
  const series = [];
  for (let i = 13; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
    let e = (trendData[d] && trendData[d][subnet]) || 0;
    if (typeof e === "number") e = { c: e, ps: 0, n: 0 };
    const purity = e.n > 0 ? Math.round(e.ps / e.n) : null;
    series.push({ date: d.slice(5).replace("-", "/"), n: e.c || 0, purity });
  }
  const sum = (arr) => arr.reduce((x, y) => x + y.n, 0);
  const last7 = sum(series.slice(7));
  const prev7 = sum(series.slice(0, 7));
  const delta = prev7 > 0 ? Math.round(((last7 - prev7) / prev7) * 100) : last7 > 0 ? 100 : 0;
  const level = last7 >= 50 ? "热门" : last7 >= 10 ? "一般" : "冷门";
  const pvals = series.map((x) => x.purity).filter((x) => x != null);
  const purity = pvals.length ? Math.round(pvals.reduce((a, b) => a + b, 0) / pvals.length) : null;
  return { subnet: subnet + ".0/24", series, index: last7, delta, level, sample: last7 + prev7, purity };
}

/* ---------------- 位置历史（本站查询快照，按 /24 记录） ---------------- */
const GEO_HIST_FILE = path.join(DATA_DIR, "geo-history.json");
let geoHist = {};
try { geoHist = JSON.parse(fs.readFileSync(GEO_HIST_FILE, "utf8")); } catch (e) { /* 首次 */ }
let geoHistSaveTimer = null;
function recordGeoHistory(ip, d) {
  const key = normalizeIp(ip);
  if (!isV4(key) || !d || !d.country) return;
  const subnet = key.replace(/\.\d+$/, "");
  const loc = [d.country, d.region, d.city].filter(Boolean).join(" / ");
  const day = new Date().toISOString().slice(0, 10);
  if (!geoHist[subnet]) geoHist[subnet] = [];
  const arr = geoHist[subnet];
  if (arr.length && arr[arr.length - 1].t === day) { arr[arr.length - 1].loc = loc; return; }
  if (arr.length && arr[arr.length - 1].loc === loc) { arr[arr.length - 1].t = day; return; }
  arr.push({ t: day, loc });
  while (arr.length > 20) arr.shift();
  if (Object.keys(geoHist).length > 20000) delete geoHist[Object.keys(geoHist)[0]];
  if (!geoHistSaveTimer) {
    geoHistSaveTimer = setTimeout(() => {
      geoHistSaveTimer = null;
      try { writeJsonAtomic(GEO_HIST_FILE, JSON.stringify(geoHist)); } catch (e) { /* 忽略 */ }
    }, 8000);
    if (geoHistSaveTimer.unref) geoHistSaveTimer.unref();
  }
}
function geoHistoryFor(ip) {
  const subnet = normalizeIp(ip).replace(/\.\d+$/, "");
  return (geoHist[subnet] || []).slice(-8);
}

/* ---------------- 关联域名（PTR 根域 + 同网段 rDNS 采样） ---------------- */
const relDomCache = makeCache("related-domains", 24 * 3600000);
async function relatedDomains(ip) {
  const key = normalizeIp(ip);
  if (!isV4(key)) return null;
  const hit = relDomCache.get(key);
  if (hit) return hit;
  const base = key.replace(/\.\d+$/, "");
  const ptrOf = (x) => dns.resolvePtr(x).then((a) => a[0] || "").catch(() => "");
  const main = await ptrOf(ip);
  const samples = [1, 2, 3, 17, 33, 49, 65, 97].map((n) => base + "." + n);
  const ptrs = await Promise.all(samples.map(ptrOf));
  const rootDom = (h) => {
    const m = String(h).match(/([a-z0-9-]+\.[a-z]{2,})\.?$/i);
    return m ? m[1].toLowerCase() : "";
  };
  const domains = [];
  if (main) {
    const dm = rootDom(main);
    if (dm) domains.push({ domain: dm, via: "反向 DNS", host: main });
  }
  for (const p of ptrs) {
    if (!p) continue;
    const dm = rootDom(p);
    if (dm && !domains.some((x) => x.domain === dm)) domains.push({ domain: dm, via: "同网段 rDNS", host: p });
    if (domains.length >= 4) break;
  }
  relDomCache.set(key, domains);
  return domains;
}

/* ---------------- 同网段样本（ip-api 邻居快照） ---------------- */
const sampleCache = makeCache("subnet-sample", 24 * 3600000);
async function subnetSample(ip) {
  const key = normalizeIp(ip);
  if (!isV4(key)) return null;
  const hit = sampleCache.get(key);
  if (hit) return hit;
  const base = key.replace(/\.\d+$/, "");
  const cand = [2, 3, 17, 33, 49, 65, 81, 97, 113, 129, 145, 161]
    .map((n) => base + "." + n)
    .filter((x) => x !== key)
    .slice(0, 12);
  const got = await Promise.all(cand.map((x) =>
    fetchJson("http://ip-api.com/json/" + x + "?fields=status,city,countryCode,isp,org", null, 6000)
      .then((r) => (r && r.status === "success" ? { ip: x, city: r.city || "", cc: (r.countryCode || "").toLowerCase(), org: r.org || r.isp || "" } : null))
      .catch(() => null)
  ));
  const d = got.filter(Boolean).slice(0, 8);
  sampleCache.set(key, d);
  return d;
}

module.exports = {
  geoLookup, classifyRisk, geoMulti, subnetSample, relatedDomains,
  recordTrend, trendFor, recordGeoHistory, geoHistoryFor, quickPurity,
  RESIDENTIAL_HINT, EDUCATION_HINT, DATACENTER_ASN, DATACENTER_ORG,
};
