/* ============================================================
   lib/cfrisk.js — Cloudflare 环境风险评估（七类高置信信号）
   等效评估：公开黑名单（代理/Tor/滥用）+ GeoIP 启发式（机房/VPN/代理类型），
   非 Cloudflare 官方机器人分数。分数越低越好，仅供环境对照。
   支持 IPv4 与 IPv6。依赖：util、caches、geo、dnsbl
   ============================================================ */
"use strict";
const { normalizeIp, isV4, isV6 } = require("./util");
const { makeCache } = require("./caches");
const { geoLookup, classifyRisk, RESIDENTIAL_HINT } = require("./geo");
const { dnsblCheck, dnsblFull } = require("./dnsbl");

const cfRiskCache = makeCache("cf-risk", 6 * 3600000);
const CF_ABUSE_LISTS = [
  "Spamhaus ZEN", "SpamCop BL", "Barracuda BRBL", "DroneBL", "Surriel PSBL",
  "Blocklist.de", "WPBL", "GBUdb Truncate", "JunkEmailFilter", "S5h All", "Manitu ixHash",
];

async function cfRisk(ip) {
  const raw = String(ip || "");
  if (!isV4(raw) && !isV6(raw)) return { ip: raw, error: "不支持的地址格式" };
  const key = normalizeIp(raw);
  const hit = cfRiskCache.get(key);
  if (hit) return hit;
  const [riskData, dbll, basic] = await Promise.all([
    geoLookup(key).catch(() => null),
    dnsblFull(key).catch(() => null),
    dnsblCheck(key).catch(() => null),
  ]);
  const risk = riskData ? classifyRisk(riskData) : null;
  const org = risk ? (risk.org || risk.isp || "") : "";
  const proxyFlag = riskData && riskData.proxy === true;
  const listed = (name) => (dbll || []).some((x) => x.name === name && x.listed);
  const residentialOrg = RESIDENTIAL_HINT.test(org);
  const signals = {
    open_proxy: listed("Tornevall"),
    residential_proxy: !!(proxyFlag && risk && !risk.is_datacenter && residentialOrg),
    corporate_proxy: !!(proxyFlag && risk && !risk.is_datacenter && org && !residentialOrg),
    vpn: !!(proxyFlag && risk && risk.is_datacenter),
    tor: !!(basic && basic.tor),
    hosting: !!(risk && risk.is_datacenter),
    abuse: CF_ABUSE_LISTS.some((n) => listed(n)),
  };
  let score = 0;
  if (signals.open_proxy) score += 30;
  if (signals.residential_proxy) score += 30;
  if (signals.corporate_proxy) score += 25;
  if (signals.vpn) score += 20;
  if (signals.tor) score += 40;
  if (signals.hosting) score += 10;
  if (signals.abuse) score += 35;
  score = Math.min(100, score);
  const band = score <= 14 ? "环境干净" : score <= 39 ? "存在风险特征" : score <= 59 ? "风险偏高" : "高风险";
  const d = {
    ip: key, score, band, signals,
    geo: risk ? {
      country: risk.country, cc: (risk.country_code || "").toLowerCase(),
      region: risk.region, city: risk.city, org, isp: risk.isp,
      asn: risk.asn, asname: risk.asname,
      is_datacenter: risk.is_datacenter,
      is_cf: risk.asn === 13335 || /cloudflare/i.test((risk.asname || "") + " " + org),
    } : null,
    note: "基于公开黑名单与 ASN/组织启发式的等效评估，非 Cloudflare 官方机器人分数",
  };
  cfRiskCache.set(key, d);
  return d;
}

module.exports = { cfRisk, CF_ABUSE_LISTS };
