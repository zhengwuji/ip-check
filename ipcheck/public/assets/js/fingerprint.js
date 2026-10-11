/* ============================================================
   NetProbe — 浏览器指纹检测（原创实现，全部本地计算）
   组件：Canvas / WebGL（含渲染哈希）/ 音频栈 / 已装字体 /
        数学函数精度 / 屏幕与硬件 / 存储与隐私位 / UA-CH
   合成：组件值稳定序列化后 SHA-256 → 指纹 ID
   TLS：GET /api/tlsinfo（Workers 运行时返回 ClientHello 摘要字段）
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;

  async function sha256Hex(str) {
    var buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
    var out = "";
    new Uint8Array(buf).forEach(function (b) { out += (b < 16 ? "0" : "") + b.toString(16); });
    return out;
  }

  /* ---------- Canvas ---------- */
  function canvasPrint() {
    var c = document.createElement("canvas");
    c.width = 260; c.height = 60;
    var ctx = c.getContext("2d");
    var g = ctx.createLinearGradient(0, 0, 260, 60);
    g.addColorStop(0, "#f60"); g.addColorStop(0.5, "#fa0"); g.addColorStop(1, "#06f");
    ctx.fillStyle = g; ctx.fillRect(0, 0, 260, 60);
    ctx.textBaseline = "alphabetic";
    ctx.fillStyle = "#0b0b0b"; ctx.font = "17px 'Arial'";
    ctx.fillText("NetProbe \u21e8 \u6307\u7eb9\u63a2\u6d4b \U0001f575 1234", 4, 24);
    ctx.fillStyle = "rgba(102,204,0,0.72)"; ctx.font = "15.5px 'Times New Roman'";
    ctx.fillText("NetProbe \u21e8 \u6307\u7eb9\u63a2\u6d4b \U0001f575 1234", 6, 46);
    ctx.strokeStyle = "rgba(0,80,200,0.6)"; ctx.arc(230, 30, 22, 0, Math.PI * 1.6); ctx.stroke();
    return c.toDataURL();
  }

  /* ---------- WebGL ---------- */
  function webglInfo() {
    var out = { version: null, vendor: null, renderer: null, slVersion: null, renderHash: null, extCount: 0 };
    try {
      var c = document.createElement("canvas");
      var gl = c.getContext("webgl") || c.getContext("experimental-webgl");
      if (!gl) return out;
      out.version = gl.getParameter(gl.VERSION);
      out.vendor = gl.getParameter(gl.VENDOR);
      out.renderer = gl.getParameter(gl.RENDERER);
      out.slVersion = gl.getParameter(gl.SHADING_LANGUAGE_VERSION);
      var dbg = gl.getExtension("WEBGL_debug_renderer_info");
      if (dbg) {
        out.vendor = gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL);
        out.renderer = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL);
      }
      out.extCount = (gl.getExtensions ? gl.getExtensions() : gl.getSupportedExtensions() || []).length;
      // 渲染哈希：画一个由多元素组成的场景后读像素
      var r = document.createElement("canvas");
      r.width = 220; r.height = 60;
      var g2 = r.getContext("webgl") || r.getContext("experimental-webgl");
      if (g2) {
        g2.clearColor(0.2, 0.5, 0.9, 1);
        g2.clear(g2.COLOR_BUFFER_BIT);
        var buf = g2.createBuffer();
        g2.bindBuffer(g2.ARRAY_BUFFER, buf);
        g2.bufferData(g2.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), g2.STATIC_DRAW);
        var vs = g2.createShader(g2.VERTEX_SHADER);
        g2.shaderSource(vs, "attribute vec2 p;void main(){gl_Position=vec4(p,0.0,1.0);}");
        g2.compileShader(vs);
        var fs = g2.createShader(g2.FRAGMENT_SHADER);
        g2.shaderSource(fs, "precision mediump float;void main(){gl_FragColor=vec4(0.6,0.1+gl_FragCoord.y/90.0,0.3,1.0);}");
        g2.compileShader(fs);
        var pr = g2.createProgram();
        g2.attachShader(pr, vs); g2.attachShader(pr, fs); g2.linkProgram(pr); g2.useProgram(pr);
        var loc = g2.getAttribLocation(pr, "p");
        g2.enableVertexAttribArray(loc);
        g2.vertexAttribPointer(loc, 2, g2.FLOAT, false, 0, 0);
        g2.drawArrays(g2.TRIANGLE_STRIP, 0, 4);
        var px = new Uint8Array(220 * 60 * 4);
        g2.readPixels(0, 0, 220, 60, g2.RGBA, g2.UNSIGNED_BYTE, px);
        var s = "";
        for (var i = 0; i < px.length; i += 97) s += px[i] + ",";
        out.renderHash = s;
      }
    } catch (e) {}
    return out;
  }

  /* ---------- 音频栈 ---------- */
  function audioPrint() {
    return new Promise(function (resolve) {
      try {
        var Ctx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
        if (!Ctx) return resolve(null);
        var ctx = new Ctx(1, 4096, 44100);
        var osc = ctx.createOscillator();
        osc.type = "triangle";
        osc.frequency.value = 10000;
        var comp = ctx.createDynamicsCompressor();
        comp.threshold.value = -50; comp.knee.value = 40; comp.ratio.value = 12;
        comp.attack.value = 0; comp.release.value = 0.25;
        osc.connect(comp); comp.connect(ctx.destination);
        osc.start(0);
        ctx.startRendering().then(function (buf) {
          var ch = buf.getChannelData(1) || buf.getChannelData(0);
          var sum = 0;
          for (var i = 3000; i < 4000; i++) sum += Math.abs(ch[i]);
          resolve(sum.toFixed(10));
        }).catch(function () { resolve(null); });
      } catch (e) { resolve(null); }
    });
  }

  /* ---------- 字体探测（宽度对比法） ---------- */
  var FONT_LIST = [
    "Calibri", "Cambria", "Consolas", "Constantia", "Corbel", "Candara",
    "Segoe UI", "Tahoma", "Trebuchet MS", "Verdana", "Georgia", "Impact",
    "Comic Sans MS", "Courier New", "Arial Black", "Palatino Linotype",
    "Lucida Sans Unicode", "Franklin Gothic", "Garamond",
    "Meiryo", "Malgun Gothic", "Yu Gothic", "MS PGothic",
    "SimSun", "NSimSun", "SimHei", "FangSong", "KaiTi", "DengXian",
    "Microsoft YaHei", "Microsoft YaHei UI",
    "PingFang SC", "Hiragino Sans GB", "Songti SC", "STHeiti", "STKaiti", "STFangsong",
    "HarmonyOS Sans SC", "MiSans", "Alibaba PuHuiTi",
  ];
  function fontProbe() {
    var found = [];
    try {
      var c = document.createElement("canvas");
      var ctx = c.getContext("2d");
      var test = "mmmmmmmmmmlli Ww@\u4e2d\u6587\u6d4b\u8bd5";
      var base = ["monospace", "sans-serif", "serif"];
      var baseW = {};
      base.forEach(function (b) {
        ctx.font = "72px " + b;
        baseW[b] = ctx.measureText(test).width;
      });
      FONT_LIST.forEach(function (f) {
        var hit = base.some(function (b) {
          ctx.font = "72px '" + f + "'," + b;
          return Math.abs(ctx.measureText(test).width - baseW[b]) > 0.5;
        });
        if (hit) found.push(f);
      });
    } catch (e) {}
    return found;
  }

  /* ---------- 采集全部组件 ---------- */
  async function collect() {
    var nav = navigator, scr = screen;
    var tz = "—";
    try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "—"; } catch (e) {}

    var wgl = webglInfo();
    var fonts = fontProbe();
    var audio = await audioPrint();

    var media = function (q) {
      try { return matchMedia(q).matches; } catch (e) { return null; }
    };

    var comps = {
      userAgent: nav.userAgent || "",
      platform: nav.platform || null,
      vendor: nav.vendor || null,
      languages: (nav.languages || [nav.language]).join(","),
      timezone: tz,
      timezoneOffset: new Date().getTimezoneOffset(),
      uaBrands: nav.userAgentData && Array.isArray(nav.userAgentData.brands)
        ? nav.userAgentData.brands.map(function (b) { return b.brand + "/" + b.version; }).join(",") : null,
      uaMobile: nav.userAgentData ? !!nav.userAgentData.mobile : null,
      screen: scr.width + "x" + scr.height + "@" + scr.colorDepth,
      availScreen: scr.availWidth + "x" + scr.availHeight,
      windowOuter: window.outerWidth + "x" + window.outerHeight,
      devicePixelRatio: String(window.devicePixelRatio),
      colorGamutP3: media("(color-gamut: p3)"),
      forcedColors: media("(forced-colors: active)"),
      reducedMotion: media("(prefers-reduced-motion: reduce)"),
      invertedColors: media("(inverted-colors: inverted)"),
      hardwareConcurrency: nav.hardwareConcurrency || null,
      deviceMemory: nav.deviceMemory || null,
      maxTouchPoints: nav.maxTouchPoints || 0,
      touchEvents: "ontouchstart" in window,
      cookiesEnabled: nav.cookieEnabled,
      doNotTrack: nav.doNotTrack || null,
      webdriver: !!nav.webdriver,
      pdfViewer: nav.pdfViewerEnabled != null ? nav.pdfViewerEnabled : null,
      localStorage: (function () { try { localStorage.setItem("__np", "1"); localStorage.removeItem("__np"); return true; } catch (e) { return false; } })(),
      sessionStorage: (function () { try { sessionStorage.setItem("__np", "1"); sessionStorage.removeItem("__np"); return true; } catch (e) { return false; } })(),
      indexedDB: !!window.indexedDB,
      canvas: canvasPrint(),
      webglVersion: wgl.version, webglVendor: wgl.vendor, webglRenderer: wgl.renderer,
      webglSlVersion: wgl.slVersion, webglExtCount: wgl.extCount, webglRender: wgl.renderHash,
      audio: audio,
      fonts: fonts.join(","),
      math: [
        Math.acos(0.123), Math.atan(0.5), Math.sin(-1e300), Math.cos(10.000000000123),
        Math.tan(-1e300), Math.sinh(1), Math.cosh(492), Math.asinh(1e300),
        Math.exp(1), Math.pow(Math.PI, -100), Math.log(Math.exp(10)),
      ].map(function (x) { return String(x); }).join("|"),
    };
    return comps;
  }

  /* ---------- 展示 ---------- */
  function kvRow(k, vStr, longVal) {
    var shown = String(vStr == null || vStr === "" ? "—" : vStr);
    var cell = "<span class='mono'>" + esc(shown) + "</span>";
    if (longVal && String(longVal).length > shown.length) {
      cell = "<details class='fp-expand'><summary>" + esc(shown) + " …</summary><pre class='fp-pre'>" +
        esc(String(longVal)) + "</pre></details>";
    }
    return "<tr><td><b>" + esc(k) + "</b></td><td>" + cell + "</td></tr>";
  }
  function trunc(s, n) { s = String(s == null ? "" : s); return s.length > n ? s.slice(0, n - 1) + "…" : s; }

  function renderRows(comps) {
    var rows = [];
    rows.push(kvRow("User-Agent", trunc(comps.userAgent, 72), comps.userAgent));
    rows.push(kvRow("平台 / 厂商", [comps.platform, comps.vendor].filter(Boolean).join(" / ") || "—"));
    if (comps.uaBrands) rows.push(kvRow("UA-CH 品牌", comps.uaBrands));
    if (comps.uaMobile != null) rows.push(kvRow("UA-CH 移动端", comps.uaMobile ? "是" : "否"));
    rows.push(kvRow("语言", comps.languages));
    rows.push(kvRow("时区", comps.timezone + "（UTC 偏移 " + comps.timezoneOffset + " 分钟）"));
    rows.push(kvRow("屏幕", comps.screen + " · 可用 " + comps.availScreen + " · 窗口 " + comps.windowOuter + " · 缩放 " + comps.devicePixelRatio));
    rows.push(kvRow("显示特性",
      "广色域 P3: " + comps.colorGamutP3 + " · 强制对比: " + comps.forcedColors +
      " · 减弱动效: " + comps.reducedMotion + " · 反色: " + comps.invertedColors));
    rows.push(kvRow("硬件", "核心 " + comps.hardwareConcurrency + " · 内存 " + (comps.deviceMemory || "?") + " GB · 触点 " + comps.maxTouchPoints + " · 触摸事件 " + comps.touchEvents));
    rows.push(kvRow("存储与隐私位",
      "localStorage " + comps.localStorage + " · sessionStorage " + comps.sessionStorage +
      " · indexedDB " + comps.indexedDB + " · Cookie " + comps.cookiesEnabled +
      " · DNT " + comps.doNotTrack + " · 自动化标志 " + comps.webdriver));
    rows.push(kvRow("已装字体（" + comps.fonts.split(",").filter(Boolean).length + " 个）", trunc(comps.fonts || "—", 88), comps.fonts));
    rows.push(kvRow("Canvas 渲染", trunc(comps.canvas.replace(/^data:image\/png;base64,/, ""), 64), comps.canvas));
    rows.push(kvRow("WebGL", trunc(comps.webglRenderer || "不可用", 80), [comps.webglVersion, comps.webglVendor, comps.webglRenderer, comps.webglSlVersion, "扩展数 " + comps.webglExtCount].filter(Boolean).join(" | ")));
    rows.push(kvRow("WebGL 渲染哈希", comps.webglRender ? trunc(comps.webglRender, 64) + " …" : "不可用", comps.webglRender));
    rows.push(kvRow("音频栈输出", comps.audio || "不可用"));
    rows.push(kvRow("数学函数精度", trunc(comps.math, 72), comps.math));
    document.getElementById("fpBody").innerHTML = rows.join("");
  }

  async function compute() {
    var idEl = document.getElementById("fpId");
    idEl.textContent = "计算中…";
    document.getElementById("fpBody").innerHTML = "<tr><td colspan='2' class='muted small'>计算中…</td></tr>";
    var comps = await collect();
    // 稳定序列化：按 key 排序
    var keys = Object.keys(comps).sort();
    var stable = keys.map(function (k) { return k + "=" + String(comps[k]); }).join("&");
    var hex = await sha256Hex(stable);
    idEl.textContent = hex.slice(0, 40);
    document.getElementById("fpTime").textContent =
      "SHA-256 · 完整哈希 " + hex.slice(0, 32) + "… · 计算于 " + new Date().toLocaleTimeString();
    renderRows(comps);
    return hex;
  }

  var currentHex = "";
  compute().then(function (h) { currentHex = h; });
  document.getElementById("fpRecalc").addEventListener("click", async function () {
    this.disabled = true;
    currentHex = await compute();
    this.disabled = false;
  });
  document.getElementById("fpCopy").addEventListener("click", function () {
    if (!currentHex) return;
    NP.copy(currentHex);
    NP.toast("指纹 ID 已复制");
  });

  /* ---------- TLS 指纹 ---------- */
  (async function () {
    try {
      var r = await fetch("/api/tlsinfo", { cache: "no-store", signal: AbortSignal.timeout(8000) });
      var d = await r.json();
      if (!d || (!d.available && !d.extensionsSha1)) return; // 完全没有 TLS 数据则不展示卡片
      document.getElementById("tlsCard").style.display = "";
      var rows = "";
      rows += "<div class='kv-row'><span class='k'>TLS 版本</span><span class='v'>" + (d.tlsVersion ? "<b>" + esc(d.tlsVersion) + "</b>" : "<span class='muted small'>不可用</span>") + "</span></div>";
      rows += "<div class='kv-row'><span class='k'>密码套件</span><span class='v mono'>" + esc(d.tlsCipher || "—") + "</span></div>";
      if (d.helloLength) rows += "<div class='kv-row'><span class='k'>ClientHello 长度</span><span class='v'>" + esc(String(d.helloLength)) + " 字节</span></div>";
      if (d.extensionsSha1) rows += "<div class='kv-row'><span class='k'>扩展列表摘要</span><span class='v mono'>" + esc(d.extensionsSha1) + "</span></div>";
      if (d.asn) rows += "<div class='kv-row'><span class='k'>连接来源 ASN</span><span class='v'>AS" + esc(String(d.asn)) + (d.asOrganization ? " · " + esc(d.asOrganization) : "") + "</span></div>";
      if (d.note) rows += "<div class='kv-row'><span class='k'>说明</span><span class='v muted small'>" + esc(d.note) + "</span></div>";
      document.getElementById("tlsRows").innerHTML = rows;
    } catch (e) {}
  })();
})();
