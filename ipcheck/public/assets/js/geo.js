/* ============================================================
   NetProbe — GeoIP 查询模块（原创实现）
   策略：本站后端缓存 API 优先（/24 子网归并，省配额），
         失败时回退公共 API：ip.sb → ipwho.is
   ============================================================ */
(function () {
  "use strict";

  var cache = new Map();      // 归一化 IP → 结果
  var inflight = new Map();   // 去重并发

  // IPv4 归并到 /24 网段首地址，同网段只查一次
  function normalizeIp(ip) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return ip.replace(/\.\d+$/, ".1");
    return ip;
  }

  async function fromBackend(ip) {
    const r = await fetch("/api/geoip/" + encodeURIComponent(ip), { signal: AbortSignal.timeout(5000) });
    if (!r.ok) return null;
    const d = await r.json();
    return {
      geoString: [d.country, d.region, d.city, d.isp].filter(Boolean).join(" "),
      countryCode: (d.country_code || "").toLowerCase() || null,
      country: d.country || "",
      region: d.region || "",
      city: d.city || "",
      isp: d.isp || "",
      asn: d.asn || null,
      org: d.org || "",
      raw: d,
    };
  }

  async function fromIpSB(ip) {
    const r = await fetch("https://api.ip.sb/geoip/" + encodeURIComponent(ip), { signal: AbortSignal.timeout(6000) });
    if (!r.ok) return null;
    const d = await r.json();
    if (!d.country) return null;
    return {
      geoString: [d.country, d.region, d.city, d.isp || d.organization].filter(Boolean).join(" "),
      countryCode: (d.country_code || "").toLowerCase() || null,
      country: d.country || "",
      region: d.region || "",
      city: d.city || "",
      isp: d.isp || d.organization || "",
      asn: d.asn || null,
      org: d.organization || "",
      raw: d,
    };
  }

  async function fromIpWhoIs(ip) {
    const r = await fetch("https://ipwho.is/" + encodeURIComponent(ip), { signal: AbortSignal.timeout(6000) });
    const d = await r.json();
    if (!d || d.success === false) return null;
    return {
      geoString: [d.country, d.region, d.city, d.connection && d.connection.isp].filter(Boolean).join(" "),
      countryCode: (d.country_code || "").toLowerCase() || null,
      country: d.country || "",
      region: d.region || "",
      city: d.city || "",
      isp: (d.connection && d.connection.isp) || d.connection && d.connection.org || "",
      asn: d.connection && d.connection.asn || null,
      org: (d.connection && d.connection.org) || "",
      raw: d,
    };
  }

  const PROVIDERS = [fromBackend, fromIpSB, fromIpWhoIs];

  async function lookup(ip) {
    if (!ip) return null;
    const key = normalizeIp(ip);
    if (cache.has(key)) return cache.get(key);
    if (inflight.has(key)) return inflight.get(key);

    const p = (async () => {
      for (const fn of PROVIDERS) {
        try {
          const res = await fn(ip);
          if (res) {
            cache.set(key, res);
            return res;
          }
        } catch (e) { /* 尝试下一个源 */ }
      }
      return null;
    })();

    inflight.set(key, p);
    try {
      return await p;
    } finally {
      inflight.delete(key);
    }
  }

  /* ---------- 国家代码 → 中文名（用于地区库纠偏） ---------- */
  var CC_NAME = {
    cn: "中国", hk: "中国香港", mo: "中国澳门", tw: "中国台湾",
    jp: "日本", kr: "韩国", sg: "新加坡", my: "马来西亚", th: "泰国",
    vn: "越南", id: "印度尼西亚", ph: "菲律宾", in: "印度",
    us: "美国", ca: "加拿大", mx: "墨西哥", br: "巴西", ar: "阿根廷",
    gb: "英国", fr: "法国", de: "德国", it: "意大利", es: "西班牙",
    nl: "荷兰", se: "瑞典", ch: "瑞士", pl: "波兰", ru: "俄罗斯",
    tr: "土耳其", ae: "阿联酋", sa: "沙特", au: "澳大利亚", nz: "新西兰",
    za: "南非", eg: "埃及", ng: "尼日利亚", ke: "肯尼亚",
  };

  // 用后端国家码校验中文归属地文案；不一致时用后端数据重新拼装
  function validateGeoText(geoText, cc, geoData) {
    if (!cc) return geoText || "";
    const expect = CC_NAME[cc];
    if (!expect || !geoText) return geoText || "";
    if (geoText.indexOf(expect) === 0) return geoText;
    const parts = [];
    if (geoData) {
      if (geoData.country) parts.push(geoData.country);
      if (geoData.region && geoData.region !== geoData.city) parts.push(geoData.region);
      if (geoData.city) parts.push(geoData.city);
      if (geoData.isp) parts.push(geoData.isp);
      if (parts.length) return parts.join(" ");
    }
    return expect + " " + geoText;
  }

  window.GEO = { lookup, normalizeIp, validateGeoText, CC_NAME };
})();
