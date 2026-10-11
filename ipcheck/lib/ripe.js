/* ============================================================
   lib/ripe.js — RIPEstat / RDAP 数据源
   ASN 注册信息、宣告规模、BGP 路由拓扑、互联邻居、RPKI 验证
   依赖：util、caches
   ============================================================ */
"use strict";
const { fetchJson, normalizeIp, isV4, rdapGet } = require("./util");
const { makeCache } = require("./caches");

/* ---------------- ASN 增强：RDAP 注册信息 + RIPEstat 宣告规模 ---------------- */
const asnInfoCache = makeCache("asn-info", 7 * 86400000);
async function asnInfo(asn) {
  if (!asn) return null;
  const hit = asnInfoCache.get(asn);
  if (hit) return hit;
  const out = { date: "", name: "", org: "", country: "", ipv4: null, prefixes: 0, bw: "", events: [] };
  const [rdap, ripe, whois] = await Promise.allSettled([
    rdapGet("https://rdap.org/autnum/" + asn),
    fetchJson("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS" + asn, null, 12000),
    fetchJson("https://stat.ripe.net/data/whois/data.json?resource=AS" + asn, null, 12000),
  ]);
  if (rdap.status === "fulfilled" && rdap.value) {
    const d = rdap.value;
    out.name = d.name || "";
    (d.events || []).forEach((ev) => {
      if (ev.eventDate && ["registration", "last changed", "last update of RDAP database"].indexOf(ev.eventAction) >= 0) {
        if (ev.eventAction !== "last update of RDAP database") out.events.push({ action: ev.eventAction, date: ev.eventDate.slice(0, 10) });
      }
    });
    const ev = (d.events || []).find((e) => e.eventAction === "registration");
    if (ev && ev.eventDate) out.date = ev.eventDate.slice(0, 10);
    for (const ent of d.entities || []) {
      if ((ent.roles || []).includes("registrant") && ent.vcardArray) {
        const fn = ent.vcardArray[1].find((x) => x[0] === "fn");
        if (fn) { out.org = fn[3]; break; }
      }
    }
  }
  if (ripe.status === "fulfilled" && ripe.value.data && Array.isArray(ripe.value.data.prefixes)) {
    let v4 = 0;
    for (const p of ripe.value.data.prefixes) {
      const m = String(p.prefix || "").match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
      if (m && parseInt(m[2], 10) <= 32) v4 += Math.pow(2, 32 - parseInt(m[2], 10));
    }
    out.ipv4 = v4;
    out.prefixes = ripe.value.data.prefixes.length;
    out.bw = v4 >= 65536 ? "100-1000 Gbps" : v4 >= 8192 ? "10-100 Gbps" : v4 >= 1024 ? "1-10 Gbps" : v4 >= 256 ? "0.1-1 Gbps" : "<0.1 Gbps";
  }
  if (whois.status === "fulfilled" && whois.value.data && Array.isArray(whois.value.data.records)) {
    for (const rec of whois.value.data.records) {
      if (!Array.isArray(rec)) continue;
      const f = rec.find((x) => /^Country$/i.test(x.key || ""));
      if (f && f.value) { out.country = String(f.value).toUpperCase(); break; }
    }
  }
  asnInfoCache.set(asn, out);
  return out;
}

/* ASN 注册日期（轻量，仅 RDAP autnum） */
const asnRegCache = makeCache("asn-reg-date", 7 * 86400000);
async function asnRegDate(asn) {
  if (!asn) return "";
  const hit = asnRegCache.get(asn);
  if (hit !== undefined) return hit;
  let date = "";
  try {
    const d = await rdapGet("https://rdap.org/autnum/" + asn);
    const ev = (d.events || []).find((e) => e.eventAction === "registration");
    if (ev && ev.eventDate) date = ev.eventDate.slice(0, 10);
  } catch (e) {}
  asnRegCache.set(asn, date);
  return date;
}

/* ---------------- AS 名称查询（RIPEstat as-overview） ---------------- */
const asNameCache = makeCache("as-name", 7 * 86400000);
async function asOverview(asn) {
  if (!asn) return "";
  const hit = asNameCache.get(asn);
  if (hit !== undefined) return hit;
  let name = "";
  try {
    const r = await fetchJson("https://stat.ripe.net/data/as-overview/data.json?resource=AS" + asn, null, 8000);
    name = (r.data && r.data.holder) || "";
  } catch (e) {}
  asNameCache.set(asn, name);
  return name;
}

/* ---------------- RPKI 路由源验证（RIPEstat） ---------------- */
const rpkiCache = makeCache("rpki", 7 * 86400000);
async function rpkiCheck(ip, asn) {
  if (!asn || !isV4(normalizeIp(ip))) return null;
  const key = normalizeIp(ip);
  const hit = rpkiCache.get(key);
  if (hit) return hit;
  let prefix = "";
  try {
    const ni = await fetchJson("https://stat.ripe.net/data/network-info/data.json?resource=" + encodeURIComponent(key), null, 10000);
    if (ni.data && ni.data.prefix) prefix = ni.data.prefix;
  } catch (e) {}
  if (!prefix) {
    rpkiCache.set(key, { prefix: "", status: "" });
    return { prefix: "", status: "" };
  }
  let status = "";
  try {
    const r = await fetchJson(
      "https://stat.ripe.net/data/rpki-validation/data.json?resource=AS" + asn + "&prefix=" + encodeURIComponent(prefix),
      null, 10000
    );
    if (r.data && r.data.status) status = r.data.status;
  } catch (e) {}
  const d = { prefix, status };
  rpkiCache.set(key, d);
  return d;
}

/* ---------------- BGP 路由拓扑（RIPE RIS 观测路径 → 上游占比） ---------------- */
const routeCache = makeCache("route-topology", 6 * 3600000);
async function routeTopology(ip, asn) {
  if (!asn || !isV4(normalizeIp(ip))) return null;
  const key = normalizeIp(ip);
  const hit = routeCache.get(key);
  if (hit !== undefined) return hit;
  let d = null;
  try {
    const r = await fetchJson("https://stat.ripe.net/data/bgplay/data.json?resource=" + encodeURIComponent(key), null, 15000);
    const dd = r.data || {};
    const paths = [];
    (dd.initial_state || []).forEach((st) => { if (st.attrs && Array.isArray(st.attrs.path)) paths.push(st.attrs.path); });
    (dd.events || []).forEach((ev) => { if (ev.attrs && Array.isArray(ev.attrs.path)) paths.push(ev.attrs.path); });
    if (!paths.length) { routeCache.set(key, null); return null; }
    const prefix = (dd.initial_state || [])[0] && dd.initial_state[0].target_prefix || "";
    const firstHop = new Map();
    const second = new Map();
    for (const p of paths) {
      const norm = [];
      for (const a of p) { if (norm[norm.length - 1] !== a) norm.push(a); }
      let i = norm.lastIndexOf(asn);
      if (i <= 0) continue;
      const up = norm[i - 1];
      firstHop.set(up, (firstHop.get(up) || 0) + 1);
      if (!second.has(up)) second.set(up, new Map());
      if (i - 2 >= 0) {
        const m = second.get(up);
        m.set(norm[i - 2], (m.get(norm[i - 2]) || 0) + 1);
      }
    }
    let total = 0;
    firstHop.forEach((c) => (total += c));
    const upsRaw = [...firstHop.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
    const ups = [];
    for (const [a, c] of upsRaw) {
      const name = await asOverview(a).catch(() => "");
      ups.push({
        asn: a,
        name,
        share: Math.round((c / total) * 1000) / 10,
        up2: [...(second.get(a) || new Map()).entries()].sort((x, y) => y[1] - x[1]).slice(0, 6).map(([a2]) => ({ asn: a2 })),
      });
    }
    const seen = new Set();
    const seconds = [];
    for (const u of ups) {
      for (const s of u.up2) {
        if (!seen.has(s.asn)) {
          seen.add(s.asn);
          seconds.push({ asn: s.asn, name: await asOverview(s.asn).catch(() => "") });
        }
      }
    }
    d = { prefix, paths: total, upstreams: ups, seconds };
  } catch (e) { d = null; }
  routeCache.set(key, d);
  return d;
}

/* ---------------- ASN 互联邻居（上游 / 客户 / 对等） ---------------- */
const IDC_HINT = /hosting|host |cloud|data ?center|colo|server|vps|networks?\b|communications|telecom|corp|inc|ltd|gmbh|llc|s\.a\.|pty/i;
const ISP_HINT = /telecom|telekom|comcast|verizon|china (telecom|unicom|mobile)|cmcc|vodafone|orange|jio|airtel|kddi|softbank|hinet|宽带|电信|联通|移动/i;
const nbCache = makeCache("asn-neighbours", 24 * 3600000);
async function asnNeighbours(asn) {
  if (!asn) return null;
  const hit = nbCache.get(asn);
  if (hit !== undefined) return hit;
  let d = null;
  try {
    const r = await fetchJson("https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS" + asn, null, 12000);
    const nb = (r.data && r.data.neighbours || []).sort((a, b) => b.power - a.power).slice(0, 18);
    const out = await Promise.all(nb.map(async (x) => {
      const name = await asOverview(x.asn);
      const kind = ISP_HINT.test(name) && !IDC_HINT.test(name) ? "ISP" : IDC_HINT.test(name) ? "IDC" : "其他";
      return { asn: x.asn, name: name || "AS" + x.asn, kind, rel: x.type === "left" ? "上游" : x.type === "right" ? "客户" : "对等" };
    }));
    d = out;
  } catch (e) { d = null; }
  nbCache.set(asn, d);
  return d;
}

module.exports = { asnInfo, asnRegDate, asOverview, rpkiCheck, routeTopology, asnNeighbours, IDC_HINT, ISP_HINT };
