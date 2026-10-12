/* ============================================================
   NetProbe — Cloudflare 全面检测（原创实现）
   三卡横幅 + Turnstile 双模式（公开测试密钥 + 服务端二次校验）
   + 网络等级对比表 + 边缘分段测速 + 环境风险评估 + 连接详情/网络画像/历史
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;

  // Cloudflare 官方文档公开发布的 Turnstile 测试 sitekey（仅用于演示链路，非私密凭据）
  // 参考：https://developers.cloudflare.com/turnstile/troubleshooting/testing/
  var TS_KEYS = {
    ni: "1x00000000000000000000BB", // 非交互：总是通过
    mg: "3x00000000000000000000FF", // 托管：强制交互式挑战
  };
  var COLO_CITY = {
    LAX: "洛杉矶", SJC: "圣何塞", SEA: "西雅图", IAD: "华盛顿", ORD: "芝加哥",
    DFW: "达拉斯", ATL: "亚特兰大", MIA: "迈阿密", JFK: "纽约", EWR: "纽瓦克",
    YYZ: "多伦多", YVR: "温哥华", GRU: "圣保罗", SCL: "圣地亚哥",
    LHR: "伦敦", CDG: "巴黎", FRA: "法兰克福", AMS: "阿姆斯特丹", MAD: "马德里",
    MXP: "米兰", ZRH: "苏黎世", ARN: "斯德哥尔摩", CPH: "哥本哈根", WAW: "华沙",
    VIE: "维也纳", PRG: "布拉格", IST: "伊斯坦布尔", SVO: "莫斯科", DME: "莫斯科",
    NRT: "东京", KIX: "大阪", ICN: "首尔", HKG: "香港", TPE: "台北", KHH: "高雄",
    SIN: "新加坡", KUL: "吉隆坡", BKK: "曼谷", CGK: "雅加达", MNL: "马尼拉", SGN: "胡志明市",
    BOM: "孟买", DEL: "德里", MAA: "金奈", BLR: "班加罗尔", DXB: "迪拜", TLV: "特拉维夫",
    SYD: "悉尼", MEL: "墨尔本", AKL: "奥克兰", JNB: "约翰内斯堡", MFM: "澳门",
    PVG: "上海", SHA: "上海", PEK: "北京", CAN: "广州", SZX: "深圳",
  };
  var WARP_TEXT = { w: "已启用", off: "未启用", on: "启用" };
  var GATEWAY_TEXT = { on: "经过", off: "未启用" };

  function coloLabel(colo) {
    return colo + (COLO_CITY[colo] ? " " + COLO_CITY[colo] : "");
  }

  const fetchTrace = NP.fetchTrace;

  function ipLinkHtml(ip) {
    return "<a href='/ip/" + encodeURIComponent(ip) + "'>" + esc(ip) + "</a>";
  }

  /* ---------------- 隐藏IP 开关（复用公共实现） ---------------- */
  function applyMask() {
    NP.applyIpMask();
  }
  NP.bindIpMask(function () { renderHistory(); });

  const maskText = NP.maskText;

  /* ---------------- 三卡横幅 ---------------- */
  var mainTrace = null;

  async function renderBanner() {
    var trace = {};
    try { trace = await fetchTrace("www.cloudflare.com"); } catch (e) {}
    mainTrace = trace;
    var ipEl = document.getElementById("cf-ip");
    ipEl.dataset.real = trace.ip || "";
    ipEl.innerHTML = (trace.loc ? NP.flag(trace.loc) : "") + " " + (trace.ip ? ipLinkHtml(trace.ip) : "无法连接");
    document.getElementById("cf-geo").textContent = trace.loc ? trace.loc.toUpperCase() : "";

    var colo = trace.colo || "—";
    document.getElementById("cf-colo").innerHTML = NP.flag(trace.loc) + " " + esc(coloLabel(colo));
    document.getElementById("cf-colo-geo").textContent =
      (trace.loc ? trace.loc.toUpperCase() + " · " : "") + (COLO_CITY[colo] || "数据中心") + " · 代码 " + colo;

    var warp = WARP_TEXT[trace.warp] || trace.warp || "未知";
    document.getElementById("cf-warp").innerHTML =
      "<span class='pill " + (trace.warp === "w" || trace.warp === "on" || trace.warp === "plus" ? "pill-good" : "pill-muted") + "'>WARP " + esc(warp) + "</span>";
    document.getElementById("cf-proto").textContent =
      [trace.http ? trace.http.replace("http/", "HTTP/") : "", trace.tls || "", trace.sni === "plaintext" ? "明文 SNI" : "加密 SNI"].filter(Boolean).join(" · ");

    renderDetails(trace);
    pushHistory(trace);
    applyMask();
    return trace;
  }

  /* ---------------- 连接详情 / 网络画像 ---------------- */
  function row(k, vHtml) {
    return "<div class='kv-row'><span class='k'>" + k + "</span><span class='v'>" + vHtml + "</span></div>";
  }

  function fmtTraceTime(ts) {
    var n = parseInt(ts, 10);
    if (!n) return "—";
    var d = new Date(n * 1000);
    function p(x) { return (x < 10 ? "0" : "") + x; }
    return d.getFullYear() + "/" + p(d.getMonth() + 1) + "/" + p(d.getDate()) + " " + p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
  }

  function renderDetails(trace) {
    if (!trace.colo) { document.getElementById("detailRows").innerHTML = "<div class='error-text small'>无法获取 trace（Cloudflare 不可达）</div>"; return; }
    document.getElementById("detailRows").innerHTML =
      row("节点代码", "<b>" + esc(trace.colo) + "</b>") +
      row("数据中心", "<b>" + esc(COLO_CITY[trace.colo] ? COLO_CITY[trace.colo] + "（" + COLO_CITY[trace.colo] + "）" : trace.colo) + "</b>") +
      row("节点所在地", NP.flag(trace.loc) + " " + esc(trace.loc || "—")) +
      row("出口 IP 定位", NP.flag(trace.loc) + " " + esc(trace.loc || "—")) +
      row("访问协议", esc((trace.http || "?").replace("http/", "HTTP/"))) +
      row("TLS 版本", esc(trace.tls || "?")) +
      row("SNI", esc(trace.sni === "plaintext" ? "明文 SNI" : "加密 SNI")) +
      row("密钥交换", esc(trace.kex || "—")) +
      row("WARP", esc(trace.warp === "off" ? "WARP 未启用" : "WARP " + (WARP_TEXT[trace.warp] || trace.warp))) +
      row("Zero Trust 网关", esc(GATEWAY_TEXT[trace.gateway] || "未启用")) +
      row("边缘服务器时间", esc(fmtTraceTime(trace.ts)));
  }

  function detectHttp3() {
    return new Promise(function (resolve) {
      var url = "https://speed.cloudflare.com/__down?bytes=1";
      var go = function () {
        fetch(url, { cache: "no-store", signal: AbortSignal.timeout(6000) })
          .then(function (r) { return r.arrayBuffer(); })
          .then(function () {
            var ent = performance.getEntriesByType("resource").filter(function (e) { return e.name.indexOf("speed.cloudflare.com") > -1; });
            var proto = ent.length ? String(ent[ent.length - 1].nextHopProtocol || "") : "";
            resolve(proto === "h3" || proto === "http/3" || proto.indexOf("h3") === 0);
          })
          .catch(function () { resolve(null); });
      };
      // 浏览器通常需要先成功一次 HTTP/2 才会尝试 HTTP/3，连跑两次取第二次结果
      fetch(url, { cache: "no-store", signal: AbortSignal.timeout(6000) })
        .then(function (r) { return r.arrayBuffer(); })
        .then(go)
        .catch(function () { go(); });
    });
  }

  var riskData = null;

  function renderProfile(trace) {
    var el = document.getElementById("profileRows");
    if (!trace.colo) { el.innerHTML = "<div class='error-text small'>无法获取 trace</div>"; return; }
    var g = riskData && riskData.geo ? riskData.geo : null;
    var isV6 = /:/.test(trace.ip || "");
    var rows = [
      row("出口是否 Cloudflare IP", riskData
        ? "<span class='pill " + (g.is_cf ? "pill-good" : "pill-muted") + "'>" + (g.is_cf ? "是" : "否") + "</span>"
        : "<span class='pill pill-muted'>查询中</span>"),
      row("出口 ASN", g && g.asn ? "<b>AS" + esc(g.asn) + "</b> " + esc(g.asname || g.org || "") : "<span class='muted'>查询中</span>"),
    ];
    if (riskData) {
      var purity = Math.max(0, 100 - riskData.score);
      var pill = purity >= 85 ? "<span class='pill pill-good'>纯净</span>" : purity >= 60 ? "<span class='pill pill-warn'>一般</span>" : "<span class='pill pill-bad'>较差</span>";
      rows.push(row("出口 IP 纯净度", "<a href='/ip/" + encodeURIComponent(trace.ip) + "'><b>" + purity + " / 100</b> " + pill + "</a>"));
      var sameRegion = (trace.loc || "").toUpperCase() === (g.cc || "").toUpperCase();
      rows.push(row("节点与出口地区", "<span class='pill " + (sameRegion ? "pill-good" : "pill-warn") + "'>" + (sameRegion ? "就近接入" : "跨区接入") + "</span>"));
    }
    rows.push(row("HTTP/3（QUIC）", "<span id='h3Cell' class='muted'>检测中</span>"));
    rows.push(row("TLS 1.3", trace.tls === "TLSv1.3" ? "<span class='pill pill-good'>是</span>" : "<span class='pill pill-muted'>" + esc(trace.tls || "—") + "</span>"));
    rows.push(row("加密 SNI（ECH）", trace.sni === "encrypted" ? "<span class='pill pill-good'>启用</span>" : "<span class='pill pill-muted'>未启用</span>"));
    rows.push(row("IP 版本", esc(isV6 ? "IPv6" : "IPv4")));
    el.innerHTML = rows.join("");

    detectHttp3().then(function (ok) {
      var cell = document.getElementById("h3Cell");
      if (!cell) return;
      cell.outerHTML = ok === null
        ? "<span class='pill pill-muted'>无法判定</span>"
        : "<span class='pill " + (ok ? "pill-good" : "pill-muted") + "'>" + (ok ? "启用" : "未启用") + "</span>";
    });
  }

  /* ---------------- 环境风险评估 ---------------- */
  function renderRisk(ip) {
    document.getElementById("riskIp").dataset.real = ip || "";
    document.getElementById("riskIp").innerHTML = ip ? (mainTrace && mainTrace.loc ? NP.flag(mainTrace.loc) : "") + " " + ipLinkHtml(ip) : "检测中…";
    var sigEl = document.getElementById("riskSignals");
    var scoreEl = document.getElementById("riskScore");
    var geoEl = document.getElementById("riskGeo");
    sigEl.innerHTML = "<div class='muted small'>正在评估…</div>";
    NP.fetchT("/api/cfrisk/" + encodeURIComponent(ip), null, 20000)
      .then(function (r) { return r.json(); })
      .then(function (d) {
        riskData = d;
        renderProfile(mainTrace || {});
        var cls = d.score <= 14 ? "pill-good" : d.score <= 39 ? "pill-warn" : "pill-bad";
        scoreEl.innerHTML = "<span class='pill " + cls + "'>● 风险指数： <b>" + d.score + "</b> / 100 · " + esc(d.band) + "</span>";
        if (d.geo) {
          var g = d.geo;
          geoEl.innerHTML =
            "<div class='cg-main'>" + NP.flag(g.cc) + " <b>" + esc((g.cc || "").toUpperCase()) + "</b> " + esc(g.country || "") + "</div>" +
            "<div class='cg-line'>" + esc([g.region, g.city].filter(Boolean).join(" · ") || "—") + "</div>" +
            "<div class='cg-line muted'>" + esc(g.org || g.isp || "—") + (g.is_datacenter ? "（机房网络）" : "") + "</div>";
        } else {
          geoEl.innerHTML = "<span class='muted small'>定位信息不可用</span>";
        }
        var defs = [
          ["公开代理（Open Proxy）", d.signals.open_proxy],
          ["住宅代理（Residential Proxy）", d.signals.residential_proxy],
          ["企业代理（Corporate Proxy）", d.signals.corporate_proxy],
          ["VPN 出口", d.signals.vpn],
          ["Tor 出口", d.signals.tor],
          ["机房 / 云服务器 IP", d.signals.hosting],
          ["滥用记录（垃圾邮件 / 攻击）", d.signals.abuse],
        ];
        sigEl.innerHTML = defs.map(function (x) {
          return "<div class='sig-row'><span>" + esc(x[0]) + "</span>" +
            "<span class='pill " + (x[1] ? "pill-bad" : "pill-good") + "'>● " + (x[1] ? "检测到" : "未检测到") + "</span></div>";
        }).join("");
        applyMask();
      })
      .catch(function () {
        scoreEl.innerHTML = "<span class='pill pill-muted'>评估失败</span>";
        sigEl.innerHTML = "<div class='error-text small'>风险评估接口暂时不可用，请稍后点「刷新」重试</div>";
      });
  }

  function riskFlow() {
    renderBanner().then(function (trace) {
      if (trace && trace.ip) renderRisk(trace.ip);
      else {
        document.getElementById("riskIp").textContent = "无法获取出口 IP";
        document.getElementById("riskSignals").innerHTML = "<div class='error-text small'>无法连接 Cloudflare trace 接口</div>";
      }
    });
  }
  document.getElementById("riskRefresh").addEventListener("click", riskFlow);

  /* ---------------- Turnstile 双模式 ---------------- */
  var tsTimers = {};
  window.__npTurnstileReady = function () {
    ["ni", "mg"].forEach(function (mode) { renderTs(mode); });
  };

  function setServerPill(mode, ok, errors) {
    var el = document.getElementById("ts-" + mode + "-server");
    if (ok) el.innerHTML = "<span class='pill pill-good'>PASS ✔</span>";
    else el.innerHTML = "<span class='pill pill-bad'>FAIL</span>" + (errors && errors.length ? " <span class='muted small'>" + esc(errors.join(", ")) + "</span>" : "");
  }

  function serverVerify(mode, token) {
    var el = document.getElementById("ts-" + mode + "-server");
    el.innerHTML = "<span class='spin'></span>";
    fetch("/api/turnstile/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: token }),
      signal: AbortSignal.timeout(15000),
    }).then(function (r) { return r.json(); })
      .then(function (d) { setServerPill(mode, !!d.ok, d.errors); })
      .catch(function () { setServerPill(mode, false, ["unreachable"]); });
  }

  function verdictHtml(mode, kind) {
    var el = document.getElementById("ts-" + mode + "-verdict");
    if (kind === "pass") {
      el.innerHTML = "<div class='verdict verdict-safe' style='margin-bottom:0'>" +
        (mode === "ni" ? "智能无感通过！<br>无需任何用户交互，后台静默校验成功。" : "校验通过！人机验证已完成，当前环境未触发进一步风控。") + "</div>";
    } else if (kind === "interactive") {
      el.innerHTML = "<div class='verdict verdict-warn' style='margin-bottom:0'><b>需要点击确认</b><br>Turnstile 正在评估当前浏览器与网络环境，点击上方勾选框即可继续。</div>";
    } else if (kind === "fail") {
      el.innerHTML = "<div class='verdict verdict-bad' style='margin-bottom:0'>✗ Turnstile 校验出错——常见于网络无法访问 challenges.cloudflare.com。</div>";
    } else if (kind === "wait") {
      el.innerHTML = "<div class='verdict' style='margin-bottom:0;background:var(--bg-soft)'><b>校验中</b><br>Turnstile 正在评估当前浏览器与网络环境…</div>";
    }
  }

  function renderTs(mode) {
    var box = document.getElementById("ts-" + mode);
    var statusEl = document.getElementById("ts-" + mode + "-status");
    var msEl = document.getElementById("ts-" + mode + "-ms");
    var tokenEl = document.getElementById("ts-" + mode + "-token");
    if (!window.turnstile) {
      statusEl.innerHTML = "<span class='pill pill-muted'>组件加载失败</span>";
      return;
    }
    statusEl.innerHTML = "<span class='pill pill-info'>校验中</span>";
    document.getElementById("ts-" + mode + "-server").innerHTML = "<span class='pill pill-muted'>—</span>";
    msEl.textContent = "—";
    tokenEl.textContent = "尚未取得 token";
    verdictHtml(mode, "wait");
    var t0 = performance.now();
    if (tsTimers[mode]) { try { turnstile.remove(tsTimers[mode]); } catch (e) {} }
    box.innerHTML = "<div id='ts-w-" + mode + "'></div>";
    tsTimers[mode] = turnstile.render("#ts-w-" + mode, {
      sitekey: TS_KEYS[mode],
      callback: function (token) {
        var ms = Math.round(performance.now() - t0);
        statusEl.innerHTML = "<span class='pill pill-good'>校验成功</span>";
        msEl.textContent = ms + " ms";
        tokenEl.textContent = token ? token.slice(0, 600) : "（空）";
        verdictHtml(mode, "pass");
        serverVerify(mode, token);
        if (mode === "mg") statusEl.innerHTML = "<span class='pill pill-good'>校验成功</span>";
      },
      "before-interactive-callback": function () {
        statusEl.innerHTML = "<span class='pill pill-warn'>需要点击确认</span>";
        verdictHtml(mode, "interactive");
      },
      "error-callback": function () {
        statusEl.innerHTML = "<span class='pill pill-bad'>校验失败</span>";
        verdictHtml(mode, "fail");
      },
      "timeout-callback": function () {
        statusEl.innerHTML = "<span class='pill pill-warn'>校验超时</span>";
      },
    });
  }

  document.querySelectorAll(".ts-reset").forEach(function (btn) {
    btn.addEventListener("click", function () { renderTs(btn.dataset.mode); });
  });

  /* ---------------- 网络等级对比表 ---------------- */
  var GRADE_HOSTS = [
    { host: "unpkg.com", name: "unpkg.com", sub: "免费套餐站点代表", grade: "免费版", badge: "g-free" },
    { host: "cloudflare.com", name: "cloudflare.com", sub: "Cloudflare 官网", grade: "企业版", badge: "g-ent" },
    { host: "openai.com", name: "openai.com", sub: "ChatGPT 所属站点", grade: "企业版", badge: "g-ent" },
    { host: "discord.com", name: "discord.com", sub: "Discord 网关", grade: "企业版", badge: "g-ent" },
    { host: "1.1.1.1", name: "1.1.1.1", sub: "WARP 与公共 DNS 使用的网络", grade: "WARP / DNS 网络", badge: "g-warp" },
    { host: "speed.cloudflare.com", name: "speed.cloudflare.com", sub: "官方测速服务", grade: "测速网络", badge: "g-speed" },
    { host: "cdnjs.cloudflare.com", name: "cdnjs.cloudflare.com", sub: "静态资源 CDN", grade: "静态资源 CDN", badge: "g-misc" },
    { host: "workers.cloudflare.com", name: "workers.cloudflare.com", sub: "Workers 平台", grade: "Workers 平台", badge: "g-misc" },
  ];

  var gradeRunning = false;
  async function runGrade() {
    if (gradeRunning) return;
    gradeRunning = true;
    var body = document.getElementById("gradeBody");
    var conc = document.getElementById("gradeConclusion");
    conc.textContent = "";
    body.innerHTML = GRADE_HOSTS.map(function (h) {
      return "<tr><td><div class='gt-site'><span class='gt-name'>" + NP.favicon(h.host, h.name) + esc(h.name) + "</span><span class='gt-sub'>" + esc(h.sub) + "</span></div></td>" +
        "<td><span class='gt-badge " + h.badge + "'>" + esc(h.grade) + "</span></td>" +
        "<td class='muted small'>测试中…</td><td class='muted small'>—</td><td class='muted small'>—</td></tr>";
    }).join("");

    var results = await Promise.all(GRADE_HOSTS.map(async function (h, idx) {
      var t0 = performance.now();
      var t = {};
      try { t = await fetchTrace(h.host); } catch (e) {}
      var ms = t.colo ? Math.round(performance.now() - t0) : -1;
      return { idx: idx, t: t, ms: ms };
    }));

    var maxMs = Math.max.apply(null, results.map(function (r) { return r.ms > 0 ? r.ms : 0; }).concat([1]));
    body.innerHTML = results.map(function (r) {
      var h = GRADE_HOSTS[r.idx];
      var coloCell = r.t.colo
        ? "<span class='gt-colo'>" + NP.flag(r.t.loc) + " <b>" + esc(r.t.colo) + "</b> " + esc(COLO_CITY[r.t.colo] || "") + "</span>"
        : "<span class='error-text'>不可达</span>";
      var barW = r.ms > 0 ? Math.max(10, Math.round((r.ms / maxMs) * 100)) : 0;
      return "<tr><td><div class='gt-site'><span class='gt-name'>" + NP.favicon(h.host, h.name) + esc(h.name) + "</span><span class='gt-sub'>" + esc(h.sub) + "</span></div></td>" +
        "<td><span class='gt-badge " + h.badge + "'>" + esc(h.grade) + "</span></td>" +
        "<td>" + coloCell + "</td>" +
        "<td>" + (r.ms > 0 ? "<span class='gt-lat'>" + r.ms + " ms</span><span class='lat-bar'><i style='width:" + barW + "%'></i></span>" : "<span class='muted small'>—</span>") + "</td>" +
        "<td>" + (r.t.http ? esc(r.t.http.replace("http/", "HTTP/")) : "<span class='muted small'>—</span>") + "</td></tr>";
    }).join("");

    var colos = results.filter(function (r) { return r.t.colo; }).map(function (r) { return r.t.colo; });
    var uniq = Array.from(new Set(colos));
    if (!colos.length) {
      conc.textContent = "本轮所有站点均不可达，可能是当前网络无法直连 Cloudflare，稍后可点「重新测试」再试。";
    } else if (uniq.length === 1) {
      conc.innerHTML = "本条线路下所有等级的站点都命中同一个节点 <b>" + esc(coloLabel(uniq[0])) + "</b>，没有被按套餐差异化调度，属于理想状态。";
    } else {
      var free = results[0].t.colo, ent = results[1].t.colo;
      conc.innerHTML = free && ent && free !== ent
        ? "检测到差异化调度：免费套餐命中 <b>" + esc(coloLabel(free)) + "</b>，企业级网络命中 <b>" + esc(coloLabel(ent)) + "</b>——这条线路对不同套餐的 Cloudflare 流量走了不同的节点。"
        : "不同等级站点命中了不同节点（" + uniq.map(function (c) { return "<b>" + esc(coloLabel(c)) + "</b>"; }).join("、") + "），存在按网络/域名的分流调度。";
    }
    gradeRunning = false;
  }
  document.getElementById("gradeRerun").addEventListener("click", runGrade);

  /* ---------------- 边缘节点分段测速 ---------------- */
  var MB = 1024 * 1024;
  var speedRunning = false;

  async function edgeRtt() {
    var samples = [];
    for (var i = 0; i < 8; i++) {
      var t0 = performance.now();
      try {
        await fetch("https://speed.cloudflare.com/__down?bytes=0", { cache: "no-store", signal: AbortSignal.timeout(4000) });
        samples.push(Math.round(performance.now() - t0));
      } catch (e) {}
    }
    return samples;
  }

  async function segmentedDownload(onTick) {
    var chunk = 25 * MB, maxTotal = 300 * MB, maxMs = 15000;
    var got = 0, t0 = performance.now();
    while (got < maxTotal && performance.now() - t0 < maxMs) {
      const r = await fetch("https://speed.cloudflare.com/__down?bytes=" + chunk, { cache: "no-store", signal: AbortSignal.timeout(20000) });
      const buf = await r.arrayBuffer();
      got += buf.byteLength;
      onTick(got, performance.now() - t0);
    }
    return got * 8 / ((performance.now() - t0) / 1000) / 1e6;
  }

  async function segmentedUpload(onTick) {
    var chunk = 5 * MB, maxTotal = 50 * MB, maxMs = 15000;
    var sent = 0, t0 = performance.now();
    var blob = new Blob([crypto.getRandomValues(new Uint8Array(chunk))]);
    while (sent < maxTotal && performance.now() - t0 < maxMs) {
      await fetch("https://speed.cloudflare.com/__up", { method: "POST", body: blob.slice(0), signal: AbortSignal.timeout(20000) });
      sent += chunk;
      onTick(sent, performance.now() - t0);
    }
    return sent * 8 / ((performance.now() - t0) / 1000) / 1e6;
  }

  function fmtSpeed(v) {
    if (!isFinite(v) || v <= 0) return "失败";
    return v >= 100 ? Math.round(v).toString() : v.toFixed(1);
  }

  async function runSpeed() {
    if (speedRunning) return;
    speedRunning = true;
    var btn = document.getElementById("speedStart");
    btn.disabled = true; btn.textContent = "测速中…";
    var dlEl = document.getElementById("spdDl"), ulEl = document.getElementById("spdUl"), rttEl = document.getElementById("spdRtt");
    var bar = document.querySelector("#speedProgress i");
    dlEl.textContent = "—"; ulEl.textContent = "—"; rttEl.textContent = "—";
    bar.style.width = "5%";

    var samples = await edgeRtt();
    if (samples.length) {
      var med = NP.median(samples);
      rttEl.textContent = med;
      bar.style.width = "15%";
    }

    try {
      await segmentedDownload(function (got, ms) {
        dlEl.textContent = fmtSpeed(got * 8 / (ms / 1000) / 1e6);
        bar.style.width = (15 + Math.min(50, (got / (300 * MB)) * 50)) + "%";
      });
    } catch (e) { dlEl.textContent = "失败"; }
    bar.style.width = "70%";

    try {
      await segmentedUpload(function (sent, ms) {
        ulEl.textContent = fmtSpeed(sent * 8 / (ms / 1000) / 1e6);
        bar.style.width = (70 + Math.min(28, (sent / (50 * MB)) * 28)) + "%";
      });
    } catch (e) { ulEl.textContent = "失败"; }
    bar.style.width = "100%";
    btn.disabled = false; btn.textContent = "重新测速";
    speedRunning = false;
  }
  document.getElementById("speedStart").addEventListener("click", runSpeed);

  /* ---------------- 节点历史记录（localStorage） ---------------- */
  var HIST_KEY = "np_cf_history";

  function histLoad() {
    try { return JSON.parse(localStorage.getItem(HIST_KEY)) || []; } catch (e) { return []; }
  }
  function pushHistory(trace) {
    if (!trace || !trace.colo || !trace.ip) return;
    var list = histLoad();
    var d = new Date();
    function p(x) { return (x < 10 ? "0" : "") + x; }
    var stamp = p(d.getMonth() + 1) + "/" + p(d.getDate()) + " " + p(d.getHours()) + ":" + p(d.getMinutes());
    var last = list[0];
    if (last && last.ip === trace.ip && last.colo === trace.colo && last.stamp === stamp) return;
    list.unshift({ stamp: stamp, colo: trace.colo, city: COLO_CITY[trace.colo] || "", loc: trace.loc || "", ip: trace.ip });
    if (list.length > 20) list.length = 20;
    try { localStorage.setItem(HIST_KEY, JSON.stringify(list)); } catch (e) {}
    renderHistory();
  }
  function renderHistory() {
    var list = histLoad();
    var el = document.getElementById("histList");
    if (!list.length) { el.innerHTML = "<div class='muted small'>暂无记录</div>"; return; }
    el.innerHTML = list.map(function (h) {
      return "<div class='hist-item'><span class='hist-time'>" + esc(h.stamp) + "</span>" +
        "<span class='hist-main'>" + (h.loc ? NP.flag(h.loc) : "") + " <b>" + esc(h.colo + (h.city ? " " + h.city : "")) + "</b> · " +
        "<a href='/ip/" + encodeURIComponent(h.ip) + "' class='ip-text' data-real='" + esc(h.ip) + "'>" + esc(maskText(h.ip)) + "</a></span></div>";
    }).join("");
  }
  document.getElementById("histClear").addEventListener("click", function () {
    try { localStorage.removeItem(HIST_KEY); } catch (e) {}
    renderHistory();
  });

  /* ---------------- reCAPTCHA v3 补充测试（Google 官方公开测试 sitekey，演示链路，非私密凭据） ---------------- */
  var RC_SITE = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"; // Google 官方 reCAPTCHA v3 测试 sitekey
  function rcPill(text, cls) { return "<span class='pill " + cls + "'>" + esc(text) + "</span>"; }
  function rcLoad() {
    return new Promise(function (resolve, reject) {
      if (window.grecaptcha && window.grecaptcha.execute) return resolve();
      var done = false;
      var s = document.createElement("script");
      s.src = "https://www.google.com/recaptcha/api.js?render=" + RC_SITE;
      s.async = true;
      s.onload = function () { if (!done) { done = true; resolve(); } };
      s.onerror = function () { if (!done) { done = true; reject(new Error("load-failed")); } };
      document.head.appendChild(s);
      setTimeout(function () { if (!done) { done = true; reject(new Error("load-timeout")); } }, 9000);
    });
  }
  function rcStars(score) {
    var n = score >= 0.9 ? 5 : score >= 0.7 ? 4 : score >= 0.5 ? 3 : score >= 0.3 ? 2 : 1;
    var lab = score >= 0.9 ? "极佳" : score >= 0.7 ? "良好" : score >= 0.5 ? "一般" : score >= 0.3 ? "较差" : "很差";
    var cls = score >= 0.7 ? "pill-good" : score >= 0.5 ? "pill-warn" : "pill-bad";
    return { stars: "★★★★★".slice(0, n) + "☆☆☆☆☆".slice(0, 5 - n), lab: lab, cls: cls };
  }
  async function rcStart() {
    var btn = document.getElementById("rcStart");
    var statusEl = document.getElementById("rcStatus");
    var scoreEl = document.getElementById("rcScore");
    var serverEl = document.getElementById("rcServer");
    var verdictEl = document.getElementById("rcVerdict");
    btn.disabled = true;
    verdictEl.innerHTML = "";
    scoreEl.textContent = "—";
    serverEl.innerHTML = "<span class='pill pill-muted'>—</span>";
    statusEl.innerHTML = "<span class='pill pill-info'>加载风控内核…</span>";
    try {
      await rcLoad();
    } catch (e) {
      statusEl.innerHTML = rcPill("组件加载失败", "pill-bad");
      verdictEl.innerHTML = "<div class='verdict verdict-warn' style='margin-bottom:0'>Google reCAPTCHA 组件未能加载——你的网络到 Google 不可达（大陆网络常见），无法完成本项测试。</div>";
      btn.disabled = false;
      return;
    }
    statusEl.innerHTML = "<span class='pill pill-info'>校验中…</span>";
    try {
      var token = await new Promise(function (resolve, reject) {
        grecaptcha.ready(function () {
          try { grecaptcha.execute(RC_SITE, { action: "netprobe" }).then(resolve, reject); }
          catch (e) { reject(e); }
        });
      });
      statusEl.innerHTML = rcPill("已取得 token", "pill-info");
      const r = await fetch("/api/recaptcha/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: token }),
        signal: AbortSignal.timeout(15000),
      });
      const d = await r.json();
      if (!d.ok) {
        statusEl.innerHTML = rcPill("校验未通过", "pill-bad");
        serverEl.innerHTML = rcPill("FAIL", "pill-bad");
        verdictEl.innerHTML = "<div class='verdict verdict-warn' style='margin-bottom:0'>服务端 siteverify 未通过" +
          (d.errors && d.errors.length ? "（" + esc(d.errors.join("、")) + "）" : "") + "。测试密钥场景下通常为组件链路异常，可重置后重试。</div>";
      } else if (d.score == null) {
        // 公开测试密钥只验证链路，不返回真实分数
        statusEl.innerHTML = rcPill("完成", "pill-good");
        serverEl.innerHTML = rcPill("PASS", "pill-good");
        scoreEl.innerHTML = "— <span class='muted small'>测试密钥不返回真实分数</span>";
        verdictEl.innerHTML = "<div class='verdict verdict-safe' style='margin-bottom:0'>✓ 完整链路走通：浏览器取得 token → 服务端 siteverify 校验通过。当前使用官方公开测试密钥（演示模式），不返回 0.0-1.0 可信分数；站长配置自己的 reCAPTCHA v3 密钥后即可显示真实评分与星级。</div>";
      } else {
        statusEl.innerHTML = rcPill("完成", "pill-good");
        serverEl.innerHTML = rcPill("PASS", "pill-good");
        var st = rcStars(d.score);
        scoreEl.innerHTML = "<b style='font-size:1.15em'>" + d.score.toFixed(1) + "</b> / 1.0　" + st.stars + " " + rcPill(st.lab, st.cls) +
          " <span class='muted small'>action=" + esc(d.action || "netprobe") + "</span>";
        verdictEl.innerHTML = "<div class='verdict " + (d.score >= 0.7 ? "verdict-safe" : d.score >= 0.5 ? "verdict-warn" : "verdict-bad") + "' style='margin-bottom:0'>" +
          (d.score >= 0.9 ? "✓ Google 对当前浏览器与网络信誉评价极高，属于最理想的免验证环境。"
            : d.score >= 0.7 ? "✓ 环境良好，绝大多数场景可以正常通过 Google 的无感校验。"
            : d.score >= 0.5 ? "△ 存在一定风险特征，部分风控较严的网站可能要求补充验证。"
            : "✗ Google 认为当前环境可信度较低，容易在各类站点触发验证码或拦截。") +
          "（演示模式：公开测试密钥返回的分数为固定通过值，此处主要验证链路与交互是否完整。）</div>";
      }
    } catch (e) {
      statusEl.innerHTML = rcPill("校验出错", "pill-bad");
      verdictEl.innerHTML = "<div class='verdict verdict-bad' style='margin-bottom:0'>✗ reCAPTCHA 校验出错——常见于网络无法访问 Google 服务。</div>";
    }
    btn.disabled = false;
  }
  document.getElementById("rcStart").addEventListener("click", rcStart);
  document.getElementById("rcReset").addEventListener("click", function () {
    document.getElementById("rcStatus").innerHTML = "<span class='pill pill-muted'>等待触发</span>";
    document.getElementById("rcScore").textContent = "—";
    document.getElementById("rcServer").innerHTML = "<span class='pill pill-muted'>—</span>";
    document.getElementById("rcVerdict").innerHTML = "";
  });

  /* ---------------- 启动 ---------------- */
  renderHistory();
  riskFlow();
  runGrade();
})();
