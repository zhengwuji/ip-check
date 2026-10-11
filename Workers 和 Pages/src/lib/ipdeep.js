/* ============================================================
   lib/ipdeep.js — Workers 版深度信息
   差异：Workers 无法发起 TCP connect —— 端口扫描不可用，仅保留
   PTR 反解（DoH）与任播识别；接口形状与服务器版保持兼容。
   ============================================================ */
"use strict";
import { isBogon } from "./util.js";
import { geoLookup } from "./geo.js";
import { asnRegDate } from "./ripe.js";
import { resolvePtr } from "./doh.js";

export const ANYCAST_IPS = new Set([
  "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
  "208.67.222.222", "208.67.220.220", "223.5.5.5", "223.6.6.6",
  "114.114.114.114", "119.29.29.29", "180.76.76.76", "64.6.64.6",
]);
export const ANYCAST_SERVICE = {
  "8.8.8.8": { name: "GOOGLE PUBLIC DNS", operator: "Google", deploy: "全球任播部署" },
  "8.8.4.4": { name: "GOOGLE PUBLIC DNS", operator: "Google", deploy: "全球任播部署" },
  "1.1.1.1": { name: "CLOUDFLARE PUBLIC DNS", operator: "Cloudflare", deploy: "全球任播部署" },
  "1.0.0.1": { name: "CLOUDFLARE PUBLIC DNS", operator: "Cloudflare", deploy: "全球任播部署" },
  "9.9.9.9": { name: "QUAD9 PUBLIC DNS", operator: "Quad9", deploy: "全球任播部署" },
  "149.112.112.112": { name: "QUAD9 PUBLIC DNS", operator: "Quad9", deploy: "全球任播部署" },
  "208.67.222.222": { name: "OPENDNS", operator: "Cisco OpenDNS", deploy: "全球任播部署" },
  "208.67.220.220": { name: "OPENDNS", operator: "Cisco OpenDNS", deploy: "全球任播部署" },
  "223.5.5.5": { name: "ALIDNS PUBLIC DNS", operator: "阿里巴巴", deploy: "全球任播部署" },
  "223.6.6.6": { name: "ALIDNS PUBLIC DNS", operator: "阿里巴巴", deploy: "全球任播部署" },
  "114.114.114.114": { name: "114DNS", operator: "南京信风", deploy: "全球任播部署" },
  "119.29.29.29": { name: "DNSPOD PUBLIC DNS", operator: "腾讯", deploy: "全球任播部署" },
};

export async function ipDeep(ip) {
  const ptr = await resolvePtr(ip).catch(() => "");
  return {
    ip,
    ptr,
    openPorts: [],
    anycast: ANYCAST_IPS.has(ip),
    anycastService: ANYCAST_SERVICE[ip] || null,
    asnRegDate: null,
    scanned: 0,
    scanReliable: false,
    note: "Workers 版不支持端口扫描（无 TCP socket）",
  };
}

export async function ipDeepFull(ip) {
  const base = await ipDeep(ip);
  const riskData = await geoLookup(ip).catch(() => null);
  if (riskData && riskData.asn) {
    base.asnRegDate = await asnRegDate(riskData.asn).catch(() => "");
    base.asn = riskData.asn;
    base.asname = riskData.asname || "";
    base.org = riskData.org || riskData.isp || "";
    base.bogon = isBogon(ip);
  }
  return base;
}
