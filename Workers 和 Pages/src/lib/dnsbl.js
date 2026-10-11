/* ============================================================
   lib/dnsbl.js — Workers 版 DNSBL（UDP/53 → DoH）
   命中判定与服务器版一致：127.0.0.0/8 计为命中；127.255.x 视为查询被拒。
   ============================================================ */
"use strict";
import { isV4, isV6, expandV6, normalizeIp } from "./util.js";
import { makeCache } from "./caches.js";
import { resolveAList } from "./doh.js";

export function reverseName(ip) {
  if (isV4(ip)) return ip.split(".").reverse().join(".");
  if (isV6(ip)) {
    const nib = expandV6(ip).split(":").slice(0, 4).join("").split("").reverse();
    return nib.join(".") + ".ip6.arpa";
  }
  return "";
}

export const DNSBL_LISTS = [
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
export async function dnsblFull(ip) {
  const rev = reverseName(ip);
  if (!rev) return null;
  const key = normalizeIp(ip);
  const hit = dnsblFullCache.get(key);
  if (hit) return hit;
  const out = await Promise.all(DNSBL_LISTS.map(async (L) => {
    const t0 = Date.now();
    let listed = false, refused = false;
    const a = await resolveAList(rev + "." + L.zone);
    if (a === null) {
      refused = true; // 两个 DoH 上游都失败：未判定
    } else {
      const codes = a.filter((x) => /^127\.0\.0\./.test(x));
      const err = a.some((x) => /^127\.255\./.test(x));
      if (err) refused = true;
      else if (codes.length) {
        listed = !(L.zone === "hostkarma.junkemailfilter.com" && codes.every((h) => h === "127.0.0.4" || h === "127.0.0.5"));
      }
    }
    return { name: L.name, zone: L.zone, cat: L.cat, listed, refused, ms: Date.now() - t0 };
  }));
  dnsblFullCache.set(key, out);
  return out;
}

/* 基础三项：直接从 dnsblFull 派生（省 2 次 DoH），Tor 单独查一条 */
const dnsblBasicCache = makeCache("dnsbl-basic", 6 * 3600000);
export async function dnsblCheck(ip) {
  const rev = reverseName(ip);
  if (!rev) return null;
  const key = normalizeIp(ip);
  const hit = dnsblBasicCache.get(key);
  if (hit) return hit;
  const [full, torA] = await Promise.all([
    dnsblFull(key).catch(() => null),
    resolveAList(rev + ".tor.dan.me.uk"),
  ]);
  const listed = (name) => (full || []).some((x) => x.name === name && x.listed);
  const d = {
    spamcop: listed("SpamCop BL"),
    dronebl: listed("DroneBL"),
    tor: torA ? torA.some((x) => /^127\./.test(x)) : false,
  };
  dnsblBasicCache.set(key, d);
  return d;
}
