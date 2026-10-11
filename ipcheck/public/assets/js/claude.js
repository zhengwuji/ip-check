/* ============================================================
   NetProbe — Claude IP 检测页（原创实现，基于 PURITY 引擎）
   布局：三出口卡片 → 评分+属性 → 安全+可用性 → DNS/UDP 快检
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;

  var ENDPOINTS = [
    { name: "claude.ai", traceHost: "claude.ai" },
    { name: "anthropic.com", traceHost: "anthropic.com" },
    { name: "api.anthropic.com", probeUrl: "https://api.anthropic.com/v1/models" },
  ];

  function setExit(id, geoId, ip, geo, cc) {
    var el = document.getElementById(id);
    el.innerHTML = (cc ? NP.flag(cc) : "") + " " + esc(ip || "获取失败");
    document.getElementById(geoId).textContent = geo || "";
  }

  function row(k, vHtml) {
    return "<div class='kv-row'><span class='k'>" + esc(k) + "</span><span class='v'>" + vHtml + "</span></div>";
  }
  function pill(text, cls) {
    return "<span class='pill " + cls + "'>" + esc(text) + "</span>";
  }

  /* ---- DNS 快检：ipleak 唯一子域名（2 步），取解析器出口 ---- */
  async function dnsQuick() {
    var statusEl = document.getElementById("dnsStatus");
    var exitEl = document.getElementById("dnsExit");
    var token = "";
    var chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    for (var i = 0; i < 20; i++) token += chars[Math.floor(Math.random() * chars.length)];
    var found = null;
    for (var step = 1; step <= 3; step++) {
      try {
        const r = await NP.fetchT("https://" + token + "-" + step + ".ipleak.net/dnsdetection/?_=" + Date.now(), null, 6000);
        const d = await r.json();
        if (d && !Array.isArray(d) && d.ip) {
          var ips = Object.keys(d.ip);
          if (ips.length) { found = ips[0]; break; }
        }
      } catch (e) {}
    }
    if (found) {
      statusEl.innerHTML = pill("检测到明文解析", "pill-warn");
      exitEl.textContent = found;
    } else {
      statusEl.innerHTML = pill("未检测到泄露", "pill-good");
      exitEl.textContent = "已加密 / 未捕获";
    }
    var ispEl = document.getElementById("dnsIsp");
    if (found && ispEl) {
      try {
        var gIsp = await GEO.lookup(found);
        ispEl.textContent = (gIsp && (gIsp.isp || gIsp.org)) || "未知";
      } catch (e) {}
    }
  }


  /* ---- 官方服务状态（Statuspage 聚合，点击进入本站状态页） ---- */
  async function serviceStatus() {
    var el = document.getElementById("svcStatus");
    if (!el) return;
    try {
      const r = await NP.fetchT("https://status.anthropic.com/api/v2/summary.json", null, 8000);
      const d = await r.json();
      var ind = (d.status && d.status.indicator) || "none";
      var map = { none: ["运行正常", "pill-good"], minor: ["轻微故障", "pill-warn"], major: ["重大故障", "pill-bad"], critical: ["严重故障", "pill-bad"] };
      var m = map[ind] || ["未知", "pill-muted"];
      el.innerHTML = "<a class='pill " + m[1] + "' href='/status/' style='text-decoration:none'>" + m[0] + " ›</a>";
    } catch (e) {
      el.innerHTML = "<a class='pill pill-muted' href='/status/' style='text-decoration:none'>前往状态页 ›</a>";
    }
  }
  /* ---- 可用性 ---- */
  async function checkAvailability() {
    var out = [];
    for (var i = 0; i < ENDPOINTS.length; i++) {
      var ep = ENDPOINTS[i];
      if (ep.traceHost) {
        var t0 = performance.now();
        var t = await PURITY.trace(ep.traceHost);
        out.push({ name: ep.name, ok: t.__ok, ms: t.__ok ? Math.round(performance.now() - t0) : -1 });
      } else {
        var a = await PURITY.apiProbe(ep.probeUrl);
        out.push({ name: ep.name, ok: a.reachable, ms: a.latency });
      }
    }
    return out;
  }

  function renderAvailability(rows) {
    document.getElementById("availRows").innerHTML = rows.map(function (r) {
      var p, extra = "";
      if (!r.ok) p = pill("不可达", "pill-bad");
      else if (r.ms < 300) { p = pill("正常", "pill-good"); extra = r.ms + "ms"; }
      else if (r.ms < 800) { p = pill("良好", "pill-info"); extra = r.ms + "ms"; }
      else { p = pill("缓慢", "pill-warn"); extra = r.ms + "ms"; }
      return row(r.name, p + (extra ? " <span class='muted small'>" + extra + "</span>" : ""));
    }).join("");
  }

  // 用户设备信息：时区 / 语言 / 系统·浏览器 / Cookie / WebGL / Canvas·WebGL 指纹
  var HIST_KEY = "np_hist_claude";

  function renderDevice(geo, serviceIp) {
    var el = document.getElementById("deviceRows");
    var localTz = "未知";
    var localOff = -new Date().getTimezoneOffset() / 60;
    try { localTz = Intl.DateTimeFormat().resolvedOptions().timeZone || "未知"; } catch (e) {}

    // 出口时区：优先城市映射，回退经度推算
    var city = (geo && geo.raw && geo.raw.city) || (geo && geo.city) || "";
    var exitTz = PURITY.CITY_TZ[city] || null;
    var exitOff = exitTz !== null ? PURITY.tzOffsetHours(exitTz) : null;
    var exitLabel;
    if (exitTz && exitOff !== null) exitLabel = exitTz + " (" + PURITY.fmtOff(exitOff) + ")";
    else {
      var lon = geo && geo.raw ? geo.raw.longitude : null;
      exitOff = (lon === null || lon === undefined || isNaN(lon)) ? null : Math.round(lon / 15);
      exitLabel = exitOff === null ? "—" : PURITY.fmtOff(exitOff) + "（按出口经度推算）";
    }
    var tzLine = "本地: " + localTz + " (" + PURITY.fmtOff(localOff) + ")";
    var hintHtml = "";
    if (exitOff !== null) {
      var diff = Math.round((exitOff - localOff) * 10) / 10;
      tzLine += "<br>出口: " + exitLabel;
      if (Math.abs(diff) >= 1) {
        tzLine += " — " + (diff < 0 ? "比本地慢 " + Math.abs(diff) : "比本地快 " + diff) + " 小时";
      }
      hintHtml = Math.abs(diff) >= 5
        ? "<span class='pill pill-warn'>时区差异较大</span> " +
          (localTz === "Asia/Shanghai" ? "<span class='pill pill-bad'>不推荐使用中国大陆时区</span>" : "")
        : "<span class='pill pill-good'>时区一致</span>";
    }

    // 语言
    var cc = geo && geo.countryCode ? geo.countryCode : null;
    var lang = PURITY.langInfo(cc);
    var langLine = "本地: " + lang.local + "<br>出口所在地惯用: " + lang.native;
    var langPill = lang.match === null ? "" :
      "<span class='pill " + (lang.match ? "pill-good'>语言一致" : "pill-warn'>语言不一致") + "</span>";

    // 指纹
    var gl = PURITY.webglInfo();

    el.innerHTML =
      "<div class='kv-row'><span class='k'>时区</span><span class='v'>" + hintHtml + "<br>" + tzLine + "</span></div>" +
      "<div class='kv-row'><span class='k'>语言</span><span class='v'>" + langPill + "<br>" + langLine + "</span></div>" +
      "<div class='kv-row'><span class='k'>操作系统 / 浏览器</span><span class='v'>" + esc(PURITY.osBrowser()) + "</span></div>" +
      "<div class='kv-row'><span class='k'>Cookie</span><span class='v'><span class='pill " +
        (navigator.cookieEnabled ? "pill-good'>已启用" : "pill-bad'>已禁用") + "</span></span></div>" +
      "<div class='kv-row'><span class='k'>WebGL 渲染器</span><span class='v'>" + esc(gl.renderer) + "</span></div>" +
      "<div class='kv-row'><span class='k'>Canvas 指纹</span><span class='v mono'>" + esc(PURITY.canvasFingerprint()) + "</span></div>" +
      "<div class='kv-row'><span class='k'>WebGL 指纹</span><span class='v mono'>" + esc(gl.fp) + "</span></div>";
  }

  function renderHistory() {
    var list = PURITY.readHistory(HIST_KEY).slice().reverse();
    document.getElementById("histNote").textContent =
      list.length + " 记录 · 100% 隐私友好 · 历史数据仅存浏览器本地，方便查阅";
    document.getElementById("histRows").innerHTML = list.length
      ? list.map(function (h) {
          var d = new Date(h.t);
          var two = function (n) { return (n < 10 ? "0" : "") + n; };
          var stamp = two(d.getMonth() + 1) + "-" + two(d.getDate()) + " " + two(d.getHours()) + ":" + two(d.getMinutes());
          var isCurrent = h === PURITY.readHistory(HIST_KEY)[PURITY.readHistory(HIST_KEY).length - 1];
          return "<div class='kv-row'><span class='k'>" + stamp + (isCurrent ? " <span class='muted small'>(当前)</span>" : "") +
            "</span><span class='v ip-cell'>" + NP.flag(h.cc) + " " + esc(h.ip) +
            (h.city ? " <span class='muted small'>" + esc(h.city) + "</span>" : "") + "</span></div>";
        }).join("")
      : "<div class='muted small'>暂无记录</div>";
  }

  async function runAll() {
    // 1) 三出口
    var results = await Promise.allSettled([
      PURITY.chinaExit(),
      PURITY.trace("1.1.1.1"),
      PURITY.trace("claude.ai"),
    ]);
    var cn = results[0].status === "fulfilled" ? results[0].value : null;
    var cf = results[1].status === "fulfilled" ? results[1].value : { __ok: false };
    var cl = results[2].status === "fulfilled" ? results[2].value : { __ok: false };

    setExit("exit-cn", "exit-cn-geo", cn && cn.ip, cn && cn.geo, null);
    setExit("exit-cf", "exit-cf-geo", cf.__ok ? cf.ip : null, cf.__ok ? (cf.loc || "").toUpperCase() : null, cf.__ok ? cf.loc : null);
    setExit("exit-cl", "exit-cl-geo", cl.__ok ? cl.ip : null, cl.__ok ? (cl.loc || "").toUpperCase() : null, cl.__ok ? cl.loc : null);

    // 2) 风险与评分
    var risk = null, geo = null;
    if (cl.__ok && cl.ip) {
      risk = await PURITY.ipRisk(cl.ip);
      try { geo = await GEO.lookup(cl.ip); } catch (e) {}
      var score = PURITY.trustScore(risk, cl.loc);
      var lab = PURITY.scoreLabel(score);
      var rv = PURITY.regionVerdict(cl.loc);
      document.getElementById("scoreBody").innerHTML =
        "<div class='score-center'><span class='score-num' style='color:" +
        (score >= 60 ? "var(--good)" : score >= 40 ? "#e0b341" : "var(--bad)") + "'>" + score +
        "</span>" + pill(lab.text, score >= 60 ? "pill-good" : score >= 40 ? "pill-warn" : "pill-bad") + "</div>" +
        "<div class='score-note'>" + esc(score >= 80 ? "该 IP 信誉优异" : score >= 60 ? "该 IP 信誉良好" : score >= 40 ? "该 IP 存在风控风险" : "该 IP 高危") + "</div>" +
        "<div class='score-bar'><i class='score-marker' style='left:calc(" + score + "% - 2px)'></i></div>" +
        "<div class='score-scale'><span>0 高危</span><span>25</span><span>50</span><span>75</span><span>100 可信</span></div>" +
        "<div class='kv-rows' style='margin-top:10px'>" +
        row("Claude支持地区", rv ? pill(rv.ok ? "正常" : "受限", rv.ok ? "pill-good" : "pill-bad") : "—") + "</div>";

      // 3) 属性
      document.getElementById("attrRows").innerHTML =
        row("地区", esc((geo && geo.country) || (cl.loc || "").toUpperCase())) +
        row("城市", esc((geo && geo.city) || "—")) +
        row("IP 属性", risk ? (risk.is_datacenter ? pill("机房IP", "pill-warn") + " <span class='muted small'>(Hosting)</span>"
          : risk.isResidential ? pill("住宅IP", "pill-good") + " <span class='muted small'>(Residential)</span>"
          : pill(risk.label || "未知", "pill-muted")) : "未知") +
        row("ASN", esc(risk && risk.asn ? "AS" + risk.asn : "未知")) +
        row("运营商", esc((risk && (risk.org || risk.isp)) || "未知"));
      document.getElementById("attrRows").querySelectorAll(".ip-text").forEach(function () {});

      // 4) 安全
      var vpnPill;
      if (risk && risk.is_proxy) vpnPill = pill("检测到", "pill-bad");
      else if (risk && risk.is_hosting_proxy) vpnPill = pill("仅机房特征", "pill-warn");
      else vpnPill = pill("未检测到", "pill-good");
      document.getElementById("secRows").innerHTML =
        row("VPN", vpnPill) +
        row("代理 (Proxy)", vpnPill) +
        row("Tor", pill("未检测到", "pill-good")) +
        row("机器人 (Crawler)", pill("否", "pill-good")) +
        row("滥用记录", pill("无记录", "pill-good"));
    } else {
      document.getElementById("scoreBody").innerHTML =
        "<div class='verdict verdict-bad'>无法连接 claude.ai——当前网络可能被阻断或需要代理。</div>";
    }

    // 5) 可用性 + DNS/UDP 并行
    checkAvailability().then(renderAvailability);
    dnsQuick();
    serviceStatus();
    var udp = await PURITY.quickUdp();
    var udpEl = document.getElementById("udpStatus");
    var udpExitEl = document.getElementById("udpExit");
    if (udp.ok) {
      udpEl.innerHTML = pill("UDP 可直连", "pill-warn");
      try {
        var ug = await GEO.lookup(udp.addr);
        if (ug && ug.countryCode) udpExitEl.innerHTML = NP.flag(ug.countryCode) + " " + esc(udp.addr);
        else udpExitEl.textContent = udp.addr;
        var ugEl = document.getElementById("udpGeo");
        if (ugEl) ugEl.textContent = (ug && ug.country) || "—";
      } catch (e) { udpExitEl.textContent = udp.addr; }
    } else {
      udpExitEl.textContent = "—";
      udpEl.innerHTML = pill("未检测到泄露", "pill-good");
    }

    // 6) 设备信息 + 历史记录
    renderDevice(geo, cl.ip);
    if (cl.ip) {
      var histCity = (geo && geo.raw && geo.raw.city) || (geo && geo.city) || "";
      PURITY.pushHistory(HIST_KEY, cl.ip, histCity, cl.loc || (geo && geo.countryCode) || "");
    }
    renderHistory();
  }

  document.getElementById("refreshAvail").addEventListener("click", function () {
    this.disabled = true;
    var self = this;
    checkAvailability().then(function (rows) { renderAvailability(rows); self.disabled = false; });
  });
  document.getElementById("goDns").addEventListener("click", function () { location.href = "/dns/"; });
  document.getElementById("goUdp").addEventListener("click", function () { location.href = "/webrtc/"; });
  document.getElementById("clearHist").addEventListener("click", function () {
    PURITY.clearHistory(HIST_KEY);
    renderHistory();
    NP.toast("历史记录已清除");
  });

  /* 隐藏IP 开关 */
  document.getElementById("ipMaskToggle").addEventListener("change", function (e) {
    document.querySelectorAll(".ip-text, .exit-ip").forEach(function (el) {
      if (!el.dataset.real) el.dataset.real = el.textContent.trim();
      var want = e.target.checked ? NP.maskIp(el.dataset.real) : el.dataset.real;
      if (el.textContent !== want) {
        // 保留国旗节点：仅替换文本节点
        var flag = el.querySelector("img");
        el.textContent = want;
        if (flag) el.insertBefore(flag, el.firstChild);
      }
    });
  });


  /* 出口卡看门狗：长时间停在初始态时给出可操作的失败提示 */
  (function npExitWatchdog() {
    setTimeout(function () {
      ['exit-cn', 'exit-cf', 'exit-cl'].forEach(function (id) {
        var el = document.getElementById(id);
        if (el && el.textContent.indexOf('检测中') >= 0) {
          el.innerHTML = "<span class='muted small'>检测失败（网络或缓存异常）· <a href='javascript:location.reload()' style='color:var(--accent)'>重试</a></span>";
        }
      });
    }, 25000);
  })();
  runAll();
})();
