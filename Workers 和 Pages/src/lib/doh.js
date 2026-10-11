/* ============================================================
   lib/doh.js — DNS over HTTPS（Workers 无法直接发 UDP/53）
   用 Cloudflare / Google 的 DoH JSON 接口替代 dns.resolve4 / resolvePtr，
   并带 10 分钟内存缓存（DNSBL 重复查询命中缓存可大幅减少 subrequest）。
   ============================================================ */
"use strict";
import { makeCache } from "./caches.js";

const DOH_ENDPOINTS = [
  "https://cloudflare-dns.com/dns-query",
  "https://dns.google/resolve",
];

const dohCache = makeCache("doh", 10 * 60000, 20000);

/* 返回 Answer.data 字符串数组；查询成功但无记录返回 []；两个上游都失败返回 null */
export async function dohQuery(name, type) {
  const key = type + "|" + name.toLowerCase();
  const hit = dohCache.get(key);
  if (hit !== undefined) return hit;
  let out = null;
  for (const ep of DOH_ENDPOINTS) {
    try {
      const url = ep + "?name=" + encodeURIComponent(name) + "&type=" + type;
      const r = await fetch(url, {
        headers: { accept: "application/dns-json" },
        signal: AbortSignal.timeout(5000),
        cf: { cacheTtl: 300, cacheEverything: true },
      });
      if (!r.ok) continue;
      const d = await r.json();
      out = d.Status === 0 && Array.isArray(d.Answer) ? d.Answer.map((a) => String(a.data)) : [];
      break;
    } catch (e) { /* 试下一个上游 */ }
  }
  if (out !== null) dohCache.set(key, out);
  return out;
}

export async function resolveAList(name) {
  const ans = await dohQuery(name, "A");
  return ans ? ans.filter((x) => /^\d{1,3}(\.\d{1,3}){3}$/.test(x)) : null;
}

export async function resolvePtr(name) {
  const ans = await dohQuery(name, "PTR");
  return ans && ans.length ? ans[0] : "";
}
