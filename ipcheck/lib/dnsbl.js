/* ============================================================
   lib/dnsbl.js — DNSBL 黑名单检测（公开名单，支持 IPv4 / IPv6）
   只把 127.0.0.0/8 的应答计为命中；127.255.x 视为查询被拒（未判定）。
   IPv6 走 nibble 反解（取前 64 位 / 32 个 nibble，这是各 DNSBL 的通用约定）。
   依赖：util、caches
   ============================================================ */
"use strict";
const dns = require("dns").promises;
const { isV4, isV6, expandV6, normalizeIp } = require("./util");
const { makeCache } = require("./caches");

function reverseName(ip) {
  if (isV4(ip)) return ip.split(".").reverse().join(".");
  if (isV6(ip)) {
    // 取展开后前 4 组（64 位），nibble 倒排 + ip6.arpa
    const nib = expandV6(ip).split(":").slice(0, 4).join("").split("").reverse();
    return nib.join(".") + ".ip6.arpa";
  }
  return "";
}

const dnsblCache = makeCache("dnsbl-basic", 7 * 86400000);
async function dnsblCheck(ip) {
  const rev = reverseName(ip);
  if (!rev) return null;
  const key = normalizeIp(ip);
  const hit = dnsblCache.get(key);
  if (hit) return hit;
  // 正常 NXDOMAIN → reject → false；fake-IP 类网络返回 198.18.x.x 也会被过滤
  const listed = (zone) => dns.resolve4(rev + "." + zone)
    .then((a) => (a || []).some((x) => /^127\./.test(x)))
    .catch(() => false);
  const d = {
    spamcop: await listed("bl.spamcop.net"),
    dronebl: await listed("dnsbl.dronebl.org"),
    tor: await listed("tor.dan.me.uk"),
  };
  dnsblCache.set(key, d);
  return d;
}

/* ---------------- DNSBL 12 源（分类黑名单检测） ---------------- */
const DNSBL_LISTS = [
  { name: "Spamhaus ZEN", zone: "zen.spamhaus.org", cat: "垃圾邮件" },
  { name: "SpamCop BL", zone: "bl.spamcop.net", cat: "垃圾邮件" },
  { name: "Barracuda BRBL", zone: "b.barracudacentral.org", cat: "声誉" },
  { name: "DroneBL", zone: "dnsbl.dronebl.org", cat: "僵尸网络" },
  { name: "Surriel PSBL", zone: "psbl.surriel.com", cat: "垃圾邮件" },
  { name: "Blocklist.de", zone: "bl.blocklist.de", cat: "僵尸网络" },
  { name: "WPBL", zone: "db.wpbl.info", cat: "恶意代码" },
  { name: "GBUdb Truncate", zone: "truncate.gbudb.net", cat: "声誉" },
  { name: "Tornevall", zone: "opm.tornevall.org", cat: "代理/Tor" },
  { name: "JunkEmailFilter", zone: "hostkarma.junkemailfilter.com", cat: "声誉" },
  { name: "S5h All", zone: "all.s5h.net", cat: "垃圾邮件" },
  { name: "Manitu ixHash", zone: "ix.manitu.net", cat: "垃圾邮件" },
];

const dnsblFullCache = makeCache("dnsbl-full", 6 * 3600000);
async function dnsblFull(ip) {
  const rev = reverseName(ip);
  if (!rev) return null;
  const key = normalizeIp(ip);
  const hit = dnsblFullCache.get(key);
  if (hit) return hit;
  const out = await Promise.all(DNSBL_LISTS.map(async (L) => {
    const t0 = Date.now();
    let listed = false, refused = false;
    try {
      const a = await dns.resolve4(rev + "." + L.zone);
      const codes = (a || []).filter((x) => /^127\.0\.0\./.test(x));
      const err = (a || []).some((x) => /^127\.255\./.test(x));
      if (err) refused = true;
      else if (codes.length) {
        // hostkarma 127.0.0.4/5 是白名单码，不算命中
        listed = !(L.zone === "hostkarma.junkemailfilter.com" && codes.every((h) => h === "127.0.0.4" || h === "127.0.0.5"));
      }
    } catch (e) {
      const code = e && e.code;
      if (code !== "ENOTFOUND" && code !== "ENODATA") refused = true; // SERVFAIL/超时等视为未判定
    }
    return { name: L.name, zone: L.zone, cat: L.cat, listed, refused, ms: Date.now() - t0 };
  }));
  dnsblFullCache.set(key, out);
  return out;
}

module.exports = { dnsblCheck, dnsblFull, DNSBL_LISTS, reverseName };
