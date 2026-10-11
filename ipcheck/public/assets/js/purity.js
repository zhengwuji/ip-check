/* ============================================================
   NetProbe — AI 服务 IP 纯净度检测引擎（原创实现）
   能力：
     exits()      三出口对比（国内直连出口 / Cloudflare 出口 / 服务出口）
     trace(host)  cdn-cgi/trace 解析
     apiProbe()   API 可达性（401 = 网络与边缘均正常）
     ipRisk()     后端风险分类（含 ip-api proxy/hosting 标志）
     trustScore() 0-100 信任评分
     quickUdp()   WebRTC srflx 快检
   ============================================================ */
(function () {
  "use strict";

  var UNSUPPORTED = ["CN", "RU", "BY", "KP", "IR", "SY", "CU"];

  async function trace(host) {
    var map = {};
    try {
      const r = await NP.fetchT("https://" + host + "/cdn-cgi/trace", null, 6000);
      (await r.text()).trim().split("\n").forEach(function (l) {
        var i = l.indexOf("=");
        if (i > 0) map[l.slice(0, i)] = l.slice(i + 1);
      });
      map.__ok = true;
    } catch (e) {
      map.__ok = false;
    }
    return map;
  }

  // 国内直连出口：ip138 / ip.cn 文本解析
  async function chinaExit() {
    try {
      const resp = await NP.fetchT("https://2026.ip138.com/", null, 7000);
      const html = await resp.text();
      const ipM = html.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
      const geoM = html.match(/来自：([^<\n]+)/);
      if (ipM) return { ip: ipM[1], geo: geoM ? geoM[1].trim() : "", via: "ip138" };
    } catch (e) {}
    try {
      const resp = await NP.fetchT("https://my.ip.cn/", null, 7000);
      const text = await resp.text();
      const ipM = text.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
      const geoM = text.match(/归属地[:：]\s*(.+)/);
      if (ipM) return { ip: ipM[1], geo: geoM ? geoM[1].trim() : "", via: "ip.cn" };
    } catch (e) {}
    return null;
  }

  async function apiProbe(url, method) {
    var t0 = performance.now();
    try {
      const r = await NP.fetchT(url, { method: method || "GET" }, 6000);
      return { reachable: true, status: r.status, latency: Math.round(performance.now() - t0) };
    } catch (e) {
      try {
        await NP.fetchT(url, { method: method || "GET", mode: "no-cors" }, 6000);
        return { reachable: true, status: null, latency: Math.round(performance.now() - t0) };
      } catch (e2) {
        return { reachable: false, status: null, latency: Math.round(performance.now() - t0) };
      }
    }
  }

  async function latencyMedian(url, rounds) {
    var arr = [];
    for (var i = 0; i < (rounds || 6); i++) {
      var t0 = performance.now();
      try {
        await fetch(url, { mode: "no-cors", cache: "no-store", signal: AbortSignal.timeout(4000) });
        arr.push(Math.round(performance.now() - t0));
      } catch (e) {}
    }
    return NP.median(arr);
  }

  async function ipRisk(ip) {
    try {
      const r = await fetch("/api/iprisk/" + encodeURIComponent(ip), { signal: AbortSignal.timeout(8000) });
      if (r.ok) return await r.json();
    } catch (e) {}
    return null;
  }

  // 信任评分：家宽 92；干净机房 85；未知 70；真实匿名/代理 −35；机房代理特征 −0（仅提示）；不支持地区封顶 15
  function trustScore(risk, cc) {
    var s = 50;
    if (risk) {
      if (risk.isResidential) s = 92;
      else if (risk.is_datacenter) s = 85;
      else s = 70;
      if (risk.is_proxy) s -= 35;
      if (risk.is_mobile) s += 2;
    } else {
      s = 45;
    }
    if (cc && UNSUPPORTED.indexOf(cc.toUpperCase()) !== -1) s = Math.min(s, 15);
    return Math.max(0, Math.min(100, s));
  }

  function scoreLabel(s) {
    if (s >= 80) return { text: "纯净", cls: "verdict-safe" };
    if (s >= 60) return { text: "良好", cls: "verdict-info" };
    if (s >= 40) return { text: "一般", cls: "verdict-warn" };
    return { text: "高危", cls: "verdict-bad" };
  }

  function regionVerdict(cc) {
    if (!cc) return null;
    var upper = cc.toUpperCase();
    if (UNSUPPORTED.indexOf(upper) !== -1) {
      return { ok: false, text: upper + " 不在官方支持地区列表中（参考，以官方公告为准）" };
    }
    return { ok: true, text: upper + " 属于受支持地区（参考）" };
  }

  // WebRTC 快检：是否能看到 srflx 公网地址
  function quickUdp() {
    return new Promise(function (resolve) {
      if (typeof RTCPeerConnection === "undefined") return resolve({ ok: false, addr: null, note: "浏览器不支持" });
      var pc;
      try {
        pc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.cloudflare.com:3478" }] });
      } catch (e) { return resolve({ ok: false, addr: null, note: "创建失败" }); }
      var done = false;
      var timer = setTimeout(finish, 5000);
      function finish() {
        if (done) return;
        done = true;
        try { pc.close(); } catch (e) {}
        resolve(result);
      }
      var result = { ok: false, addr: null, note: "未见 UDP 公网映射" };
      pc.createDataChannel("");
      pc.onicecandidate = function (e) {
        if (!e.candidate) return finish();
        var m = (e.candidate.candidate || "").match(/candidate:\S+ \d+ \S+ \d+ ([^\s]+) \d+ typ (\w+)/);
        if (m && m[2] === "srflx" && m[1].indexOf(".local") === -1) {
          result = { ok: true, addr: m[1], note: "UDP 可直连公网" };
          finish();
        }
      };
      pc.createOffer().then(function (o) { return pc.setLocalDescription(o); }).catch(function () { finish(); });
    });
  }

  /* ---------------- 设备信息与指纹（仅本地计算，不上传） ---------------- */
  function fnv1a(str) {
    var h = 0x811c9dc5;
    for (var i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = (h * 0x01000193) >>> 0;
    }
    return ("00000000" + h.toString(16).toUpperCase()).slice(-8);
  }

  function canvasFingerprint() {
    try {
      var c = document.createElement("canvas");
      c.width = 240; c.height = 60;
      var ctx = c.getContext("2d");
      ctx.textBaseline = "top";
      ctx.font = "16px 'Arial'";
      ctx.fillStyle = "#f60"; ctx.fillRect(2, 2, 100, 18);
      ctx.fillStyle = "#069"; ctx.fillText("NetProbe \u2022 <canvas>", 4, 14);
      ctx.fillStyle = "rgba(102,204,0,0.7)"; ctx.fillText("NetProbe \u2022 <canvas>", 6, 17);
      ctx.strokeStyle = "#f00"; ctx.beginPath(); ctx.arc(200, 30, 18, 0, Math.PI * 2); ctx.stroke();
      ctx.fillStyle = "rgba(0,0,200,0.35)"; ctx.beginPath(); ctx.arc(200, 30, 12, 0.6, 3.2); ctx.fill();
      return fnv1a(c.toDataURL());
    } catch (e) { return "不可用"; }
  }

  function webglInfo() {
    try {
      var gl = document.createElement("canvas").getContext("webgl") ||
               document.createElement("canvas").getContext("experimental-webgl");
      if (!gl) return { renderer: "不可用", fp: "不可用" };
      var dbg = gl.getExtension("WEBGL_debug_renderer_info");
      var renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
      var vendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR);
      var params = [
        gl.getParameter(gl.VERSION),
        gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        gl.getParameter(gl.MAX_TEXTURE_SIZE),
        gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
        gl.getParameter(gl.MAX_VIEWPORT_DIMS).join(","),
        (gl.getSupportedExtensions() || []).length,
      ].join("|");
      return { renderer: renderer || "未知", fp: fnv1a(String(renderer) + "|" + String(vendor) + "|" + params) };
    } catch (e) { return { renderer: "不可用", fp: "不可用" }; }
  }

  function osBrowser() {
    var ua = navigator.userAgent;
    var os = "未知";
    if (/Windows NT/.test(ua)) os = "Windows";
    else if (/Mac OS X/.test(ua)) os = "macOS";
    else if (/Android/.test(ua)) os = "Android";
    else if (/iPhone|iPad|iPod/.test(ua)) os = "iOS";
    else if (/Linux/.test(ua)) os = "Linux";
    var br = "未知";
    var m;
    if ((m = ua.match(/Edg\/([\d.]+)/))) br = "Edge " + m[1];
    else if ((m = ua.match(/OPR\/([\d.]+)/))) br = "Opera " + m[1];
    else if ((m = ua.match(/Firefox\/([\d.]+)/))) br = "Firefox " + m[1];
    else if ((m = ua.match(/Chrome\/([\d.]+)/))) br = "Chrome " + m[1];
    else if ((m = ua.match(/Version\/([\d.]+).*Safari/))) br = "Safari " + m[1];
    return os + " / " + br;
  }

  // 国家代码 → 当地惯用语言
  var CC_LANG = {
    us: ["英语", "en"], gb: ["英语", "en"], ca: ["英语/法语", "en"], au: ["英语", "en"],
    nz: ["英语", "en"], ie: ["英语", "en"], cn: ["中文（简体）", "zh"], tw: ["中文（繁体）", "zh"],
    hk: ["中文（繁体）", "zh"], mo: ["中文（繁体）", "zh"], sg: ["中文/英语", "zh"], jp: ["日语", "ja"],
    kr: ["韩语", "ko"], kp: ["韩语", "ko"], de: ["德语", "de"], at: ["德语", "de"], ch: ["德/法/意语", "de"],
    fr: ["法语", "fr"], be: ["荷/法语", "nl"], es: ["西班牙语", "es"], mx: ["西班牙语", "es"],
    ar: ["西班牙语", "es"], it: ["意大利语", "it"], nl: ["荷兰语", "nl"], pt: ["葡萄牙语", "pt"],
    br: ["葡萄牙语", "pt"], ru: ["俄语", "ru"], ua: ["乌克兰语", "uk"], pl: ["波兰语", "pl"],
    cz: ["捷克语", "cs"], se: ["瑞典语", "sv"], no: ["挪威语", "no"], dk: ["丹麦语", "da"],
    fi: ["芬兰语", "fi"], tr: ["土耳其语", "tr"], ae: ["阿拉伯语", "ar"], sa: ["阿拉伯语", "ar"],
    eg: ["阿拉伯语", "ar"], il: ["希伯来语", "he"], in: ["印地/英语", "hi"], id: ["印尼语", "id"],
    vn: ["越南语", "vi"], th: ["泰语", "th"], ph: ["菲律宾语/英语", "tl"], my: ["马来语", "ms"],
  };

  function langInfo(cc) {
    var local = (navigator.languages && navigator.languages.length ? navigator.languages.join(", ") : navigator.language) || "未知";
    var entry = CC_LANG[cc];
    if (!entry) return { local: local, native: "未知", match: null };
    var primary = (navigator.languages && navigator.languages[0]) || navigator.language || "";
    var match = primary.toLowerCase().indexOf(entry[1]) === 0;
    return { local: local, native: entry[0], match: match };
  }

  /* ---------------- 出口 IP 历史记录（仅存浏览器本地） ---------------- */
  function readHistory(key) {
    try { return JSON.parse(localStorage.getItem(key) || "[]"); } catch (e) { return []; }
  }
  function pushHistory(key, ip, city, cc) {
    if (!ip) return;
    var list = readHistory(key);
    var now = Date.now();
    var last = list[list.length - 1];
    if (last && last.ip === ip && now - last.t < 3600 * 1000) { last.t = now; last.city = city || last.city; }
    else list.push({ t: now, ip: ip, city: city || "", cc: cc || "" });
    while (list.length > 10) list.shift();
    try { localStorage.setItem(key, JSON.stringify(list)); } catch (e) {}
  }
  function clearHistory(key) {
    try { localStorage.removeItem(key); } catch (e) {}
  }

  // 城市 → IANA 时区（常见出口城市）
  var CITY_TZ = {
    "Los Angeles": "America/Los_Angeles", "San Jose": "America/Los_Angeles", "Seattle": "America/Los_Angeles",
    "Phoenix": "America/Phoenix", "New York": "America/New_York", "North Virginia": "America/New_York",
    "Ashburn": "America/New_York", "Miami": "America/New_York", "Atlanta": "America/New_York",
    "Chicago": "America/Chicago", "Dallas": "America/Chicago", "Denver": "America/Denver",
    "Toronto": "America/Toronto", "Vancouver": "America/Vancouver", "Mexico City": "America/Mexico_City",
    "Sao Paulo": "America/Sao_Paulo", "London": "Europe/London", "Frankfurt": "Europe/Berlin",
    "Berlin": "Europe/Berlin", "Nuremberg": "Europe/Berlin", "Langen": "Europe/Berlin",
    "Amsterdam": "Europe/Amsterdam", "Paris": "Europe/Paris", "Madrid": "Europe/Madrid",
    "Barcelona": "Europe/Madrid", "Milan": "Europe/Rome", "Zurich": "Europe/Zurich",
    "Stockholm": "Europe/Stockholm", "Vienna": "Europe/Vienna", "Warsaw": "Europe/Warsaw",
    "Prague": "Europe/Prague", "Sofia": "Europe/Sofia", "Bucharest": "Europe/Bucharest",
    "Budapest": "Europe/Budapest", "Meppel": "Europe/Amsterdam", "Kyiv": "Europe/Kyiv",
    "Moscow": "Europe/Moscow", "Istanbul": "Europe/Istanbul", "Dubai": "Asia/Dubai",
    "Tel Aviv": "Asia/Jerusalem", "Mumbai": "Asia/Kolkata", "Rajpura": "Asia/Kolkata",
    "Singapore": "Asia/Singapore", "Jakarta": "Asia/Jakarta", "Bangkok": "Asia/Bangkok",
    "Ho Chi Minh City": "Asia/Ho_Chi_Minh", "Hong Kong": "Asia/Hong_Kong", "Hongkong": "Asia/Hong_Kong",
    "Shanghai": "Asia/Shanghai", "Beijing": "Asia/Shanghai", "Taipei": "Asia/Taipei",
    "Seoul": "Asia/Seoul", "Tokyo": "Asia/Tokyo", "Osaka": "Asia/Tokyo",
    "Sydney": "Australia/Sydney", "Melbourne": "Australia/Melbourne", "Auckland": "Pacific/Auckland",
    "Johannesburg": "Africa/Johannesburg", "Cairo": "Africa/Cairo", "Shiraz": "Asia/Tehran",
    "Qom": "Asia/Tehran", "Tehran": "Asia/Tehran", "Almaty": "Asia/Almaty",
  };

  function tzOffsetHours(tz) {
    try {
      var parts = new Intl.DateTimeFormat("en-US", { timeZone: tz, timeZoneName: "longOffset" })
        .formatToParts(new Date());
      var v = (parts.find(function (p) { return p.type === "timeZoneName"; }) || {}).value || "";
      var m = v.match(/GMT([+-])(\d{2}):(\d{2})/);
      if (!m) return v === "GMT" ? 0 : null;
      var n = parseInt(m[2], 10) + parseInt(m[3], 10) / 60;
      return m[1] === "-" ? -n : n;
    } catch (e) { return null; }
  }
  function fmtOff(h) { return "UTC" + (h >= 0 ? "+" : "−") + Math.abs(h); }

  window.PURITY = {
    trace, chinaExit, apiProbe, latencyMedian, ipRisk,
    trustScore, scoreLabel, regionVerdict, quickUdp,
    osBrowser, canvasFingerprint, webglInfo, langInfo,
    readHistory, pushHistory, clearHistory, CITY_TZ, tzOffsetHours, fmtOff,
  };
})();
