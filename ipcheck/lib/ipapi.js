/* ============================================================
   lib/ipapi.js — ip-api.com 批量查询（免费接口，单批最多 100 个 IP）
   用途：为中转路径上的每一跳补齐 ASN / 运营商 / 城市 / 机房标志
   注意：免费接口仅支持 HTTP，且有 15 请求/分钟限制，故按 IP 缓存 24 小时
   依赖：util、caches
   ============================================================ */
"use strict";
const { postJson } = require("./util");
const { makeCache } = require("./caches");

const FIELDS = "status,message,country,countryCode,regionName,city,isp,org,as,asname,proxy,hosting,mobile,reverse";
const BATCH_URL = "http://ip-api.com/batch?fields=" + FIELDS;
const ipApiCache = makeCache("ipapi", 24 * 3600000, 20000);

/* 把 ip-api 原始项归一为站内统一字段 */
function normIpApi(d, ip) {
  const asRaw = String(d.as || "");
  const m = asRaw.match(/^AS(\d+)\s*(.*)$/i);
  return {
    ip: d.query || ip,
    cc: String(d.countryCode || "").toLowerCase(),
    country: d.country || "",
    region: d.regionName || "",
    city: d.city || "",
    isp: d.isp || "",
    org: d.org || "",
    asn: m ? parseInt(m[1], 10) : null,
    asname: (m && m[2]) || d.asname || "",
    proxy: d.proxy === true,
    hosting: d.hosting === true,
    mobile: d.mobile === true,
    ptr: d.reverse || "",
  };
}

/* 批量查询：入参任意 IP 数组，返回 { ip: 归一对象 }，查不到的 IP 不出现在结果里 */
async function ipApiBatch(ips) {
  const uniq = [];
  const seen = new Set();
  for (const raw of ips || []) {
    const ip = String(raw || "").trim();
    if (!ip || seen.has(ip)) continue;
    seen.add(ip);
    uniq.push(ip);
  }
  const out = {};
  const miss = [];
  for (const ip of uniq) {
    const hit = ipApiCache.get(ip);
    if (hit !== undefined) { if (hit) out[ip] = hit; } else miss.push(ip);
  }
  for (let i = 0; i < miss.length; i += 100) {
    const chunk = miss.slice(i, i + 100);
    try {
      const arr = await postJson(BATCH_URL, chunk, null, 12000);
      if (!Array.isArray(arr)) continue;
      chunk.forEach((ip, idx) => {
        const raw = arr[idx];
        const d = raw && raw.status === "success" ? normIpApi(raw, ip) : null;
        ipApiCache.set(ip, d); // 负结果也缓存，避免反复打失败 IP
        if (d) out[ip] = d;
      });
    } catch (e) {
      // 网络失败不写缓存，下次可重试
    }
  }
  return out;
}

/* 单个 IP 查询（复用批量通道） */
async function ipApiOne(ip) {
  const m = await ipApiBatch([ip]);
  return m[String(ip)] || null;
}

module.exports = { ipApiBatch, ipApiOne, normIpApi };
