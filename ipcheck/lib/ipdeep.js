/* ============================================================
   lib/ipdeep.js — IP 深度信息：PTR 反解 / 常见端口扫描 / 任播识别
   依赖：util、geo、ripe
   ============================================================ */
"use strict";
const net = require("net");
const dns = require("dns").promises;
const { isV4, isBogon } = require("./util");
const { geoLookup } = require("./geo");
const { asnRegDate } = require("./ripe");

const ANYCAST_IPS = new Set([
  "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
  "208.67.222.222", "208.67.220.220", "223.5.5.5", "223.6.6.6",
  "114.114.114.114", "119.29.29.29", "180.76.76.76", "64.6.64.6",
]);
const ANYCAST_SERVICE = {
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
const SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 8888, 9090, 27017];

function probePort(ip, port, timeout) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let done = false;
    const finish = (open) => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve(open ? port : null);
    };
    sock.setTimeout(timeout);
    sock.once("connect", () => finish(true));
    sock.once("timeout", () => finish(false));
    sock.once("error", () => finish(false));
    try { sock.connect(port, ip); } catch (e) { finish(false); }
  });
}

async function ipDeep(ip) {
  const isV4Addr = isV4(ip);
  // 哨兵：探测一个几乎必然关闭的端口。若它也"通"，说明网络经透明代理，
  // 所有 TCP connect 都会成功，端口扫描结果不可信。
  const sentinel = isV4Addr ? await probePort(ip, 1, 1500) : null;
  const reliable = sentinel === null;
  const [ptr, ...ports] = await Promise.all([
    dns.resolvePtr(ip).then((a) => a[0] || "").catch(() => ""),
    ...(isV4Addr && reliable ? SCAN_PORTS.map((p) => probePort(ip, p, 900)) : [Promise.resolve(null)]),
  ]);
  return {
    ip,
    ptr,
    openPorts: ports.filter(Boolean),
    anycast: ANYCAST_IPS.has(ip),
    anycastService: ANYCAST_SERVICE[ip] || null,
    asnRegDate: null, // 由路由层填充
    scanned: isV4Addr && reliable ? SCAN_PORTS.length : 0,
    scanReliable: reliable,
  };
}

// 带 ASN 注册日期的深度查询（路由层包装）
async function ipDeepFull(ip) {
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

module.exports = { ipDeep, ipDeepFull, probePort, ANYCAST_IPS, ANYCAST_SERVICE };
