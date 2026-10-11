/* ============================================================
   lib/geo.js — Workers 版 GeoIP 聚合 / 风险分类 / 趋势 / 位置历史
   与服务器版的差异：
   - 无磁盘持久化：geoip 缓存与趋势/历史全部内存化（隔离实例生命周期内有效）
   - PTR 反解走 DoH
   ============================================================ */
"use strict";
import { fetchJson, normalizeIp, isV4 } from "./util.js";
import { makeCache } from "./caches.js";
import { resolvePtr } from "./doh.js";

const geoCache = makeCache("geoip", 24 * 3600 * 1000, 30000);

export async function geoLookup(ip) {
  const key = normalizeIp(ip);
  const hit = geoCache.get(key);
  if (hit) { recordTrend(ip, quickPurity(hit)); return hit; }

  let d = null;
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
  recordTrend(ip, quickPurity(d));
  return d;
}

export function quickPurity(d) {
  if (!d) return null;
  let p = 100;
  if (d.hosting === true) p -= 12;
  if (d.proxy === true) p -= 30;
  return Math.max(0, p);
}

/* ---------------- 风险分类（与服务器版一致） ---------------- */
export const DATACENTER_ASN = new Set([
  13335, 16509, 15169, 8075, 14061, 20473, 63949, 45102,
  9009, 16276, 24940, 51167, 396982, 14618, 16592, 200052, 35048, 49870,
  398101, 396356, 54113, 55286, 60781, 45899, 59318, 209605, 212238, 208276,
]);
export const DATACENTER_ORG = /amazon|aws|google|microsoft|azure|oracle|digitalocean|linode|vultr|choopa|hetzner|ovh|scaleway|contabo|m247|leaseweb|alibaba|tencent|huawei|ucloud|qiniu|bandwagon|hostwinds|kamatera|upcloud|akamai|fastly|cloudflare|datacamp|packethub|gcore|melbikomas|xhost|aeza|justhost|bluevps|hosting|host |vps|server|datacenter|data center|colo\b|networks inc|networks\b|communications|it7|zendata|psychz|quadranet|colocation/i;
export const RESIDENTIAL_HINT = /telecom|telekom|comcast|verizon|at&t|china (telecom|unicom|mobile)|chinanet|cnnet|cmcc|t-mobile|sprint|vodafone|orange|jio|airtel|pldt|virgin|charter|cox|spectrum|kddi|softbank|ntt docomo|hinet|电信|联通|移动|广电|长城宽带|鹏博士|家庭宽带/i;
export const EDUCATION_HINT = /university|edu\b|教育网|cernet|school|college/i;

export function classifyRisk(d) {
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

/* ---------------- 多源定位比对 ---------------- */
const geoMultiCache = makeCache("geo-multi", 24 * 3600000);
export async function geoMulti(ip) {
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

/* ---------------- 网段热度趋势（内存化，兼容服务器版数据形状） ---------------- */
let trendData = {};
let trendLastHit = new Map();

function trendSave() { /* 内存版无需落盘 */ }

export function recordTrend(ip, purity) {
  const key = normalizeIp(ip);
  if (!isV4(key)) return;
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
  trendSave();
}

export function trendFor(ip) {
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

/* ---------------- 位置历史（内存化） ---------------- */
let geoHist = {};
export function recordGeoHistory(ip, d) {
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
}
export function geoHistoryFor(ip) {
  const subnet = normalizeIp(ip).replace(/\.\d+$/, "");
  return (geoHist[subnet] || []).slice(-8);
}

/* ---------------- 关联域名（PTR 走 DoH，邻居采样 8→4 控制子请求数） ---------------- */
const relDomCache = makeCache("related-domains", 24 * 3600000);
export async function relatedDomains(ip) {
  const key = normalizeIp(ip);
  if (!isV4(key)) return null;
  const hit = relDomCache.get(key);
  if (hit) return hit;
  const base = key.replace(/\.\d+$/, "");
  const main = await resolvePtr(ip);
  const samples = [1, 2, 3, 17].map((n) => base + "." + n);
  const ptrs = await Promise.all(samples.map((x) => resolvePtr(x)));
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

/* ---------------- 同网段样本（ip-api，12→8 控制子请求数） ---------------- */
const sampleCache = makeCache("subnet-sample", 24 * 3600000);
export async function subnetSample(ip) {
  const key = normalizeIp(ip);
  if (!isV4(key)) return null;
  const hit = sampleCache.get(key);
  if (hit) return hit;
  const base = key.replace(/\.\d+$/, "");
  const cand = [2, 3, 17, 33, 49, 65, 81, 97]
    .map((n) => base + "." + n)
    .filter((x) => x !== key)
    .slice(0, 8);
  const got = await Promise.all(cand.map((x) =>
    fetchJson("http://ip-api.com/json/" + x + "?fields=status,city,countryCode,isp,org", null, 6000)
      .then((r) => (r && r.status === "success" ? { ip: x, city: r.city || "", cc: (r.countryCode || "").toLowerCase(), org: r.org || r.isp || "" } : null))
      .catch(() => null)
  ));
  const d = got.filter(Boolean).slice(0, 8);
  sampleCache.set(key, d);
  return d;
}
