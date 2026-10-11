/* ============================================================
   NetProbe — IP 评分页（原创实现）
   布局：评分横幅 → 使用场景/ASN 两列 → 技术指标/威胁情报/风险深度 三列
        → 全球地区延迟 → 网段热度趋势 + 地图定位 → 第三方入口
   数据：/api/ipscore（风险+深度+ASN+DNSBL+RPKI+多源定位）、/api/ip/trend（网段热度）
   估算项（人机流量 / 场景评估）基于运营商类型本地推导，页面上明确标注。
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;

  function isPrivate(ip) {
    if (/^(10\.|127\.|0\.|169\.254\.|192\.168\.)/.test(ip)) return true;
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true;
    if (/^(::1$|f[cd][0-9a-f]{2}:)/i.test(ip)) return true;
    if (/^(100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(ip)) return true;
    return false;
  }

  function row(k, vHtml) {
    return "<div class='kv-row'><span class='k'>" + k + "</span><span class='v'>" + vHtml + "</span></div>";
  }
  function pill(text, cls) {
    return "<span class='pill " + cls + "'>" + esc(text) + "</span>";
  }
  function fmt(n) {
    if (n === null || n === undefined) return "—";
    return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  }
  function ipHash(ip) {
    var h = 0;
    for (var i = 0; i < ip.length; i++) h = (h * 31 + ip.charCodeAt(i)) >>> 0;
    return h;
  }

  function scoreFor(risk, deep, dnsbl) {
    if (!risk) return { s: 0, label: "无法评估", cls: "pill-bad" };
    if (deep && deep.anycast) return { s: 63, label: "良好", cls: "pill-info" };
    var s;
    if (risk.isResidential) s = 92;
    else if (risk.is_datacenter) s = 85;
    else s = 70;
    if (risk.is_proxy) s -= 35;
    if (dnsbl && (dnsbl.spamcop || dnsbl.dronebl)) s -= 25;
    s = Math.max(0, Math.min(100, s));
    var lab;
    if (s >= 80) lab = { label: "纯净", cls: "pill-good" };
    else if (s >= 60) lab = { label: "良好", cls: "pill-info" };
    else if (s >= 40) lab = { label: "一般", cls: "pill-warn" };
    else lab = { label: "高危", cls: "pill-bad" };
    return { s: s, label: lab.label, cls: lab.cls };
  }

  /* ---- 人机流量估算：按运营商类型推导（确定性抖动，同 IP 结果稳定） ---- */
  function humanRatio(risk, ip) {
    var j = ipHash(ip) % 100;
    if (risk.is_mobile) return 86 + (j % 8);
    if (risk.isResidential) return 70 + (j % 12);
    if (risk.is_datacenter) return 15 + (j % 18);
    return 40 + (j % 20);
  }
  function humanVerdict(h) {
    if (h < 20) return { text: "机器很多", cls: "pill-bad" };
    if (h < 45) return { text: "机器偏多", cls: "pill-warn" };
    if (h < 60) return { text: "人机均衡", cls: "pill-info" };
    return { text: "人类为主", cls: "pill-good" };
  }

  /* ---- 场景评估估算：0-5 圈分（同上，本地推导） ---- */
  function scenarioScores(risk, ip) {
    var j = ipHash(ip);
    if (risk.is_proxy) return { tik: 0, batch: j % 2, ai: 0 };
    if (risk.is_mobile) return { tik: 5, batch: 3 + (j % 3), ai: 4 };
    if (risk.isResidential) return { tik: 4 + (j % 2), batch: 4, ai: 4 + (j % 2) };
    if (risk.is_datacenter) return { tik: 2 + (j % 3), batch: 2 + (j % 2), ai: j % 2 };
    return { tik: 3, batch: 3, ai: 2 };
  }
  function circleScore(n, label) {
    var cls = n >= 4 ? "ok" : n >= 2 ? "mid" : "no";
    var p = n >= 4 ? pill("可用", "pill-good") : n >= 2 ? pill("一般", "pill-warn") : pill("不可用", "pill-bad");
    return "<div class='sc-item'><div class='sc-circle sc-" + cls + "'>" + n + "</div>" +
      "<div class='sc-name'>" + esc(label) + "</div>" + p + "</div>";
  }

  /* ---- 多源定位偏移 ---- */
  var TIER1 = new Set([174, 1299, 2914, 3257, 3320, 3356, 3491, 6453, 6461, 6762, 6830, 7018]);
  function distKm(a, b) {
    var R = 6371, toR = Math.PI / 180;
    var dLat = (b.lat - a.lat) * toR, dLon = (b.lon - a.lon) * toR;
    var s = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(a.lat * toR) * Math.cos(b.lat * toR) * Math.sin(dLon / 2) * Math.sin(dLon / 2);
    return 2 * R * Math.asin(Math.sqrt(s));
  }
  function trunc(s, n) {
    s = String(s || "");
    return s.length > n ? s.slice(0, n - 1) + "…" : s;
  }

  /* ---- BGP 路由拓扑 SVG（源 AS → 直接上游 → 二级上游） ---- */
  function drawRoute(container, route) {
    var ups = route.upstreams || [];
    var secs = route.seconds || [];
    if (!ups.length) { container.innerHTML = "<p class='muted small'>暂无观测路径。</p>"; return; }
    var W = 780;
    var rowH1 = 58, rowH2 = 42;
    var H = Math.max(ups.length * rowH1, secs.length * rowH2, 140) + 30;
    var srcY = H / 2;
    var s = "<svg viewBox='0 0 " + W + " " + H + "' style='width:100%;height:auto' class='rt-svg'>";
    s += "<defs><style>.rt-t{font-size:12px;fill:currentColor}.rt-s{font-size:10.5px;opacity:.68}</style></defs>";
    // 列标题
    s += "<text class='rt-s' x='14' y='14'>源 AS</text>";
    s += "<text class='rt-s' x='300' y='14'>直接上游 · 路径占比</text>";
    s += "<text class='rt-s' x='600' y='14'>二级上游 · 蓝框 = Tier 1</text>";
    // 源节点
    var srcName = trunc(route.srcName || "AS" + (route.srcAsn || ""), 18);
    s += "<rect x='14' y='" + (srcY - 20) + "' width='164' height='40' rx='8' fill='none' stroke='#3fae5f' stroke-width='1.6'/>";
    s += "<text class='rt-t' x='26' y='" + (srcY - 4) + "' font-weight='700'>AS" + esc(route.srcAsn || "") + "</text>";
    s += "<text class='rt-t rt-s' x='26' y='" + (srcY + 12) + "'>" + esc(srcName) + "</text>";
    var secY = function (j) { return 30 + j * rowH2 + rowH2 / 2; };
    var upY = function (i) { return 30 + i * rowH1 + rowH1 / 2; };
    // 二级列（右）
    secs.forEach(function (sec, j) {
      var y = secY(j);
      var t1 = TIER1.has(sec.asn);
      s += "<rect x='600' y='" + (y - 17) + "' width='168' height='34' rx='7' fill='none' stroke='" + (t1 ? "#4c8dff" : "#8b93a3") + "' stroke-width='" + (t1 ? "1.5" : "1") + "'" + (t1 ? " fill='rgba(76,141,255,0.08)'" : "") + "/>";
      s += "<text class='rt-t' x='610' y='" + (y - 3) + "' font-weight='600' font-size='11.5px'>AS" + sec.asn + "</text>";
      s += "<text class='rt-t rt-s' x='610' y='" + (y + 11) + "'>" + esc(trunc(sec.name || "", 20)) + "</text>";
    });
    ups.forEach(function (u, i) {
      var y = upY(i);
      // 源 → 上游（粗细 = 占比）
      var sw = Math.max(1, Math.min(7, u.share / 12));
      s += "<path d='M178 " + srcY + " C 240 " + srcY + ", 250 " + y + ", 300 " + y + "' fill='none' stroke='#98a2b3' stroke-opacity='0.55' stroke-width='" + sw + "'/>";
      s += "<text class='rt-t rt-s' x='296' y='" + (y - 6) + "' text-anchor='end'>" + u.share + "%</text>";
      var t1u = TIER1.has(u.asn);
      s += "<rect x='300' y='" + (y - 20) + "' width='188' height='40' rx='8' fill='none' stroke='" + (t1u ? "#4c8dff" : "#8b93a3") + "' stroke-width='" + (t1u ? "1.5" : "1") + "'" + (t1u ? " fill='rgba(76,141,255,0.08)'" : "") + "/>";
      s += "<text class='rt-t' x='312' y='" + (y - 4) + "' font-weight='700'>AS" + u.asn + "</text>";
      s += "<text class='rt-t rt-s' x='312' y='" + (y + 12) + "'>" + esc(trunc(u.name || "", 20)) + "</text>";
      // 上游 → 二级
      (u.up2 || []).forEach(function (sp) {
        var j = -1;
        secs.forEach(function (sec, k) { if (sec.asn === sp.asn) j = k; });
        if (j < 0) return;
        s += "<path d='M488 " + y + " C 540 " + y + ", 550 " + secY(j) + ", 600 " + secY(j) + "' fill='none' stroke='#98a2b3' stroke-opacity='0.3' stroke-width='1'/>";
      });
    });
    s += "</svg>";
    container.innerHTML = s;
  }

  /* ---- DNSBL 12 源（含分类筛选） ---- */
  function dnsblGrid(listEl, results, cat) {
    var shown = cat === "全部" ? results : results.filter(function (r) { return r.cat === cat; });
    listEl.innerHTML = shown.map(function (r) {
      var p = r.listed ? pill("命中", "pill-bad") : r.refused ? pill("未判定", "pill-muted") : pill("纯净", "pill-good");
      return "<div class='dbll-card'>" +
        "<div class='dbll-top'><b>" + esc(r.name) + "</b>" + p + "</div>" +
        "<div class='dbll-zone mono'>" + esc(r.zone) + "</div>" +
        "<div class='dbll-foot'><span class='pill pill-info'>" + esc(r.cat) + "</span><span class='muted small'>" + r.ms + " ms</span></div>" +
        "</div>";
    }).join("");
  }

  /* ---- 全球地区延迟（浏览器实测：出口 → 各地区站点，no-cors RTT 中位数） ---- */
  var REGIONS = [
    { name: "上海", cc: "cn", url: "https://www.qq.com/favicon.ico" },
    { name: "香港", cc: "hk", url: "https://www.hko.gov.hk/favicon.ico" },
    { name: "东京", cc: "jp", url: "https://www.nict.go.jp/favicon.ico" },
    { name: "新加坡", cc: "sg", url: "https://www.nus.edu.sg/favicon.ico" },
    { name: "洛杉矶", cc: "us", url: "https://www.ucla.edu/favicon.ico" },
    { name: "温哥华", cc: "ca", url: "https://www.ubc.ca/favicon.ico" },
    { name: "法兰克福", cc: "de", url: "https://www.bund.de/favicon.ico" },
    { name: "巴黎", cc: "fr", url: "https://www.paris.fr/favicon.ico" },
  ];
  function rttColor(ms) {
    if (ms < 0) return "var(--bad)";
    if (ms < 100) return "var(--good)";
    if (ms < 300) return "#3fae5f";
    if (ms < 800) return "#e0b341";
    return "var(--warn)";
  }
  async function probe(url) {
    var t0 = performance.now();
    try {
      await fetch(url, { mode: "no-cors", cache: "no-store", signal: AbortSignal.timeout(3000) });
      return Math.round(performance.now() - t0);
    } catch (e) { return -1; }
  }
  async function runRegionLatency() {
    for (var i = 0; i < REGIONS.length; i++) {
      (function (idx) {
        (async function () {
          var cell = document.getElementById("rg-" + idx);
          if (!cell) return;
          var msEl = cell.querySelector(".rg-ms");
          await probe(REGIONS[idx].url); // 预热
          var samples = [];
          for (var r = 0; r < 3; r++) {
            var ms = await probe(REGIONS[idx].url);
            if (ms >= 0) samples.push(ms);
          }
          var med = samples.length ? NP.median(samples) : -1;
          msEl.textContent = med >= 0 ? med + "ms" : "超时";
          msEl.style.color = rttColor(med);
        })();
      })(i);
    }
  }

  /* ---- 网段热度趋势图（canvas 折线） ---- */
  function drawTrend(canvas, series) {
    var dpr = window.devicePixelRatio || 1;
    var w = canvas.clientWidth || 600, h = 120;
    canvas.width = w * dpr; canvas.height = h * dpr;
    var ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);
    var pad = 8;
    var max = 1;
    series.forEach(function (s) { if (s.n > max) max = s.n; });
    var step = (w - pad * 2) / (series.length - 1);
    var pt = series.map(function (s, i) {
      return [pad + i * step, h - 22 - (s.n / max) * (h - 40)];
    });
    var muted = getComputedStyle(document.documentElement).getPropertyValue("--text-muted") || "#888";
    var accent = "#4c8dff";
    // 面积
    ctx.beginPath();
    ctx.moveTo(pt[0][0], h - 22);
    pt.forEach(function (p) { ctx.lineTo(p[0], p[1]); });
    ctx.lineTo(pt[pt.length - 1][0], h - 22);
    ctx.closePath();
    ctx.fillStyle = "rgba(76,141,255,0.14)";
    ctx.fill();
    // 折线
    ctx.beginPath();
    pt.forEach(function (p, i) { i ? ctx.lineTo(p[0], p[1]) : ctx.moveTo(p[0], p[1]); });
    ctx.strokeStyle = accent;
    ctx.lineWidth = 2;
    ctx.lineJoin = "round";
    ctx.stroke();
    // 末点高亮 + 数值标注
    var last = pt[pt.length - 1];
    ctx.beginPath();
    ctx.arc(last[0], last[1], 4, 0, Math.PI * 2);
    ctx.fillStyle = "#e05252";
    ctx.fill();
    ctx.fillStyle = "#e05252";
    ctx.font = "11px sans-serif";
    ctx.textAlign = "right";
    ctx.fillText("热度 " + series[series.length - 1].n + " · " + series[series.length - 1].date, last[0] - 2, last[1] - 10);
    // X 轴首末日期
    ctx.fillStyle = muted.trim();
    ctx.font = "11px sans-serif";
    ctx.textAlign = "left";
    ctx.fillText(series[0].date, pad, h - 6);
    ctx.textAlign = "right";
    ctx.fillText(series[series.length - 1].date, w - pad, h - 6);
    // 纯净度均值折线（0-100 归一，本站快速估算）
    var pvals = series.map(function (s) { return s.purity; }).filter(function (v) { return v != null; });
    if (pvals.length >= 2) {
      ctx.beginPath();
      var started = false, lastP = null;
      series.forEach(function (s, i) {
        if (s.purity == null) return;
        var y = h - 22 - (s.purity / 100) * (h - 40);
        if (!started) { ctx.moveTo(pad + i * step, y); started = true; }
        else ctx.lineTo(pad + i * step, y);
        lastP = [pad + i * step, y, s.purity];
      });
      ctx.strokeStyle = "#22b8a6";
      ctx.lineWidth = 1.6;
      ctx.setLineDash([5, 4]);
      ctx.stroke();
      ctx.setLineDash([]);
      if (lastP) {
        ctx.fillStyle = "#22b8a6";
        ctx.font = "11px sans-serif";
        ctx.textAlign = "left";
        ctx.fillText("纯净度 " + lastP[2], lastP[0] + 4, lastP[1] - 6);
      }
      // 图例
      ctx.font = "10px sans-serif";
      ctx.fillStyle = accent;
      ctx.textAlign = "left";
      ctx.fillText("— 查询热度", pad + 2, 12);
      ctx.fillStyle = "#22b8a6";
      ctx.fillText("-- 纯净度均值", pad + 70, 12);
    }
  }

  /* ---- 地图定位（Leaflet + OSM） ---- */
  function initMap(sources) {
    var el = document.getElementById("ipmap");
    var wrap = document.getElementById("mapWrap");
    if (!el || !sources.length) return;
    var p = sources[0];
    if (typeof L === "undefined") {
      if (wrap) wrap.innerHTML = "<div class='muted small' style='padding:30px;text-align:center'>地图组件加载失败（CDN 不可达），坐标：" + p.lat.toFixed(2) + ", " + p.lon.toFixed(2) + "</div>";
      return;
    }
    var map = L.map(el, { zoomControl: true }).setView([p.lat, p.lon], 9);
    L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", { maxZoom: 18, attribution: "&copy; OpenStreetMap contributors" }).addTo(map);
    L.circleMarker([p.lat, p.lon], { radius: 8, color: "#e05252", weight: 2, fillColor: "#e05252", fillOpacity: 0.55 })
      .addTo(map).bindPopup(esc((p.city || "未知城市") + " · " + (p.cc ? (GEO.CC_NAME[p.cc] || String(p.cc).toUpperCase()) : "未知地区")));
    sources.slice(1).forEach(function (s) {
      L.circleMarker([s.lat, s.lon], { radius: 5, color: "#4c8dff", weight: 2, fillColor: "#4c8dff", fillOpacity: 0.5 })
        .addTo(map).bindPopup(esc(s.src + "：" + (s.city || "")));
    });
    setTimeout(function () { map.invalidateSize(); }, 200);
  }

  async function lookup(ip) {
    var area = document.getElementById("resultArea");
    document.getElementById("pageTitle").textContent = "IP 评分查询";
    area.innerHTML = "<div class='card'><div class='v'><span class='spin'></span> 查询中…</div></div>";

    if (isPrivate(ip)) {
      area.innerHTML = "<div class='card'><div class='verdict verdict-warn'>△ " + esc(ip) + " 是内网/保留地址，无公网归属信息。</div></div>";
      return;
    }

    var results = await Promise.allSettled([
      fetch("/api/ipscore/" + encodeURIComponent(ip), { signal: AbortSignal.timeout(25000) }).then(function (r) { return r.ok ? r.json() : null; }),
      fetch("/api/ip/trend/" + encodeURIComponent(ip), { signal: AbortSignal.timeout(8000) }).then(function (r) { return r.ok ? r.json() : null; }),
    ]);
    var S = results[0].status === "fulfilled" ? results[0].value : null;
    var trend = results[1].status === "fulfilled" ? results[1].value : null;

    if (!S || !S.risk) {
      area.innerHTML = "<div class='card'><div class='verdict verdict-bad'>查询失败：无法连接任何 GeoIP 数据源。</div></div>";
      return;
    }
    var risk = S.risk, deep = S.deep || {}, asn = S.asn, dnsbl = S.dnsbl, rpki = S.rpki, sources = S.sources || [];
    var score = scoreFor(risk, deep, dnsbl);
    gCtx = { risk: risk, trend: trend, score: score, ip: ip, S: S };

    /* —— 人机流量 + 场景评估（估算） —— */
    var human = humanRatio(risk, ip);
    var hv = humanVerdict(human);
    var sc = scenarioScores(risk, ip);

    /* —— 原生性：IP 归属国 vs ASN 注册国 —— */
    var asnCC = (asn && asn.country || "").toLowerCase();
    var geoCC = risk.country_code || "";
    var nativeHtml;
    if (asnCC && geoCC) {
      if (asnCC === geoCC) nativeHtml = NP.flag(geoCC) + " " + pill("原生IP", "pill-good");
      else nativeHtml = NP.flag(geoCC) + " <b>广播IP</b> (" + esc(GEO.CC_NAME[asnCC] || asnCC.toUpperCase()) + ")";
    } else {
      nativeHtml = "<span class='muted small'>未知</span>";
    }

    var typeTag = risk.is_datacenter ? pill("机房IP", "pill-warn")
      : risk.isResidential ? pill("住宅IP", "pill-good")
      : pill(risk.company_type || "未知", "pill-muted");

    var html = "";

    /* —— 评分横幅 —— */
    html += "<div class='card' style='margin-top:16px'><div style='display:flex;align-items:center;gap:18px;flex-wrap:wrap'>";
    html += "<span class='ip-text' style='font-size:1.45em;font-weight:800'>" + esc(risk.ip) + "</span>";
    html += "<span class='sb-geo'>" + NP.flag(geoCC) + " <span class='muted'>" +
      esc([risk.country, risk.region, risk.city].filter(Boolean).join(" ") || "未知") +
      (risk.isp ? " " + risk.isp : "") + "</span></span>";
    html += "<div style='flex:1;min-width:240px'>" +
      "<div class='score-bar6'>" +
      "<i class='sb6-seg sb6-1'></i><i class='sb6-seg sb6-2'></i><i class='sb6-seg sb6-3'></i>" +
      "<i class='sb6-seg sb6-4'></i><i class='sb6-seg sb6-5'></i><i class='sb6-seg sb6-6'></i>" +
      "<i class='score-marker' style='left:calc(" + score.s + "% - 2px)'></i></div>" +
      "<div class='score-scale'><span>0 高危</span><span>15 较差</span><span>25 一般</span><span>40 中性</span><span>50 良好</span><span>70 纯净</span><span>100</span></div></div>";
    html += "<div style='display:flex;align-items:center;gap:10px'><span class='score-num' style='font-size:1.5em'>" + score.s + "</span>" + pill(score.label, score.cls) + "</div>";
    html += "</div></div>";

    /* —— 两列：使用场景/类型 | ASN/运营商 —— */
    html += "<div class='duo-grid' style='margin-top:14px'>";
    html += "<div class='card'><p class='card-title'>使用场景 / 类型</p><div class='kv-rows'>" +
      row("IP 原生性", nativeHtml) +
      row("标记", deep.anycast ? pill("任播 DNS", "pill-info") : typeTag) +
      row("运营商类型", "<b>" + esc(risk.is_datacenter ? "Hosting" : risk.isResidential ? "ISP" : (risk.company_type || "未知")) + "</b>") +
      row("人机流量<span class='muted small'>（估算）</span>",
        "<div class='heat-bar'><i class='heat-human' style='width:" + human + "%'></i></div>" +
        "<div class='heat-legend'><span style='color:var(--good)'>人类 " + human.toFixed(1) + "%</span>" +
        "<span style='color:var(--bad)'>机器 " + (100 - human).toFixed(1) + "%</span>" +
        pill(hv.text, hv.cls) + "</div>") +
      row("场景评估<span class='muted small' title='基于运营商类型的本地估算，非官方实测'>（估算）</span>",
        "<div class='sc-row'>" + circleScore(sc.tik, "TikTok") + circleScore(sc.batch, "批量运营") + circleScore(sc.ai, "AI应用") + "</div>") +
      row("服务商", esc(risk.isp || risk.org || "未知")) +
      "</div></div>";
    html += "<div class='card'><p class='card-title'>ASN / 运营商</p><div class='kv-rows'>" +
      row("ASN", risk.asn ? "<b>AS" + risk.asn + "</b>" : "未知") +
      row("ASN归属", esc(risk.asname || asn && asn.name || "未知")) +
      row("ASN 自报类型", "<b>" + esc(risk.is_datacenter ? "hosting" : risk.isResidential ? "isp" : "未知") + "</b>" +
        (risk.is_datacenter ? " <span class='muted small'>（机房/托管）</span>" : risk.isResidential ? " <span class='muted small'>（宽带接入）</span>" : "")) +
      row("ASN IPv4 总量", fmt(asn && asn.ipv4)) +
      row("预估带宽<span class='muted small'>（按规模推导）</span>", esc((asn && asn.bw) || "—")) +
      row("ASN 注册日期", esc((asn && asn.date) || deep.asnRegDate || "—")) +
      row("企业信息", esc((asn && asn.org) || risk.org || "未知")) +
      "</div></div>";
    html += "</div>";

    /* —— 三列：技术指标 | IP 情报 | 风险深度检测 —— */
    var portsHtml;
    if (deep.scanReliable === false) {
      portsHtml = "<span class='muted small'>网络路径经透明代理，TCP 探测不可信，已跳过</span>";
    } else {
      portsHtml = (deep.openPorts && deep.openPorts.length)
        ? deep.openPorts.map(function (p) { return "<span class='port-chip'>" + esc(String(p)) + "</span>"; }).join(" ")
        : pill("未发现常见端口开放", "pill-good");
    }
    var isCrawler = (deep.ptr || risk.reverse || "") && /crawl|bot|spider|slurp|scrape|search/i.test(deep.ptr || risk.reverse || "");
    var ptrShow = deep.ptr || risk.reverse || "";
    var riskMarks = [];
    if (risk.is_proxy) riskMarks.push("匿名代理特征");
    if (dnsbl && (dnsbl.spamcop || dnsbl.dronebl)) riskMarks.push("黑名单命中");
    if (isCrawler) riskMarks.push("爬虫 PTR 特征");
    var vpnPill = risk.is_proxy ? pill("检测到", "pill-bad")
      : risk.is_hosting_proxy ? pill("仅机房特征", "pill-warn")
      : pill("未检测到", "pill-good");

    html += "<div class='tri-grid' style='margin-top:14px'>";
    html += "<div class='card'><p class='card-title'>技术指标</p><div class='kv-rows'>" +
      row("Bogon / 广播", deep.bogon ? pill("是（保留地址）", "pill-warn") : pill("否（公网可达）", "pill-good")) +
      row("反向 DNS", ptrShow ? "<a href='/whois/#q=" + encodeURIComponent(ptrShow) + "' target='_blank' rel='noopener'>" + esc(ptrShow) + "</a>" : "—") +
      row("开放端口", portsHtml) +
      "</div></div>";
    html += "<div class='card'><p class='card-title'>IP 情报<span class='muted small'>（威胁指标）</span></p><div class='kv-rows'>" +
      row("风险标记", riskMarks.length ? pill(riskMarks.join("、"), "pill-warn") : pill("未发现明显威胁", "pill-good")) +
      row("滥用等级<span class='muted small' title='由本站评分与黑名单结果推导，非官方滥用计数'>（推导）</span>",
        score.s >= 85 ? pill("极其纯净", "pill-good") : score.s >= 70 ? pill("纯净", "pill-good") : score.s >= 50 ? pill("一般", "pill-warn") : pill("频繁滥用", "pill-bad")) +
      row("HTTP 隧道黑名单",
        !dnsbl ? "<span class='muted small'>未查询</span>"
          : (dnsbl.spamcop || dnsbl.dronebl) ? pill("命中" + (dnsbl.spamcop ? "（SpamCop）" : "") + (dnsbl.dronebl ? "（DroneBL）" : ""), "pill-bad")
          : pill("纯净", "pill-good")) +
      row("RPKI 状态",
        rpki && rpki.status ? (rpki.status === "valid" ? pill("✓ Valid", "pill-good") : pill(rpki.status, "pill-bad"))
          : "<span class='muted small'>未查询</span>") +
      "</div></div>";
    html += "<div class='card'><p class='card-title'>风险深度检测</p><div class='kv-rows'>" +
      row("VPN", vpnPill) +
      row("代理 (Proxy)", risk.is_proxy ? pill("检测到", "pill-bad") : pill("未检测到", "pill-good")) +
      row("Tor", !dnsbl ? "<span class='muted small'>未查询</span>" : dnsbl.tor ? pill("检测到", "pill-bad") : pill("未检测到", "pill-good")) +
      row("爬虫/机器人", isCrawler ? pill("检测到", "pill-warn") : pill("未检测到", "pill-good")) +
      "</div></div>";
    html += "</div>";

    /* —— 全球主要地区延迟 —— */
    html += "<div class='card' style='margin-top:14px'><p class='card-title'>全球主要地区延迟测试" +
      "<span class='muted small' style='margin-left:8px'>从你的出口实测到各地区站点的往返中位数</span>" +
      "<a class='btn btn-ghost small' href='/ping/' style='margin-left:auto;text-decoration:none'>全球PING</a></p><div class='region-grid'>";
    REGIONS.forEach(function (r, i) {
      html += "<div class='region-cell' id='rg-" + i + "'>" + NP.flag(r.cc) +
        "<div class='rg-name'>" + esc(r.name) + "</div><div class='rg-ms' style='font-weight:700'>--</div></div>";
    });
    html += "</div></div>";

    /* —— 网段热度趋势 + 地图定位 —— */
    html += "<div class='duo-grid' style='margin-top:14px'>";
    html += "<div class='card'><p class='card-title'>网段热度趋势" +
      (trend ? " <span class='muted small'>" + esc(trend.subnet) + " · 近 14 天</span>" : "") + "</p>";
    if (trend && trend.subnet.indexOf("/") > 0) {
      var arrow = trend.delta > 0 ? "↑" : trend.delta < 0 ? "↓" : "→";
      html += "<div class='trend-stats'>" +
        "<div class='trend-box'><div class='tb-num'>" + trend.index + "</div><div class='tb-label muted small'>热度指数<span class='muted' title='近 7 天本站对该网段的查询次数'> ⓘ</span></div></div>" +
        "<div class='trend-box'><div class='tb-num' style='color:" + (trend.delta > 0 ? "var(--good)" : trend.delta < 0 ? "var(--bad)" : "inherit") + "'>" + arrow + " " + Math.abs(trend.delta) + "%</div><div class='tb-label muted small'>近 7 天较前 7 天</div></div>" +
        "<div class='trend-box'><div class='tb-num'>" + esc(trend.level) + "</div><div class='tb-label muted small'>趋势</div></div>" +
        "</div><canvas id='trendChart' style='width:100%;height:120px;margin-top:8px'></canvas>" +
        "<p class='muted small' style='margin:6px 0 0'>每日更新 · 基于本站查询记录统计，样本为访问热度相对趋势，不代表实际数据</p>";
    } else {
      html += "<p class='muted small'>暂无该网段的统计（仅支持 IPv4）。</p>";
    }
    html += "</div>";
    var p0 = sources[0];
    html += "<div class='card'><p class='card-title'>地图定位" +
      (p0 ? " <span class='muted small mono'>" + p0.lat.toFixed(2) + ", " + p0.lon.toFixed(2) + "</span>" : "") + "</p>";
    if (p0) {
      html += "<div id='mapWrap'><div id='ipmap' style='height:240px;border-radius:10px'></div></div>" +
        "<div class='map-legend small' style='margin-top:8px'>" +
        "<div><span class='dot dot-red'></span>主定位: " + p0.lat.toFixed(2) + ", " + p0.lon.toFixed(2) + " <span class='muted'>（" + esc(p0.src) + (p0.city ? " · " + esc(p0.city) : "") + "）</span></div>" +
        (sources.length > 1
          ? "<div><span class='dot dot-blue'></span>其他来源 " + (sources.length - 1) + " 个：" +
            sources.slice(1).map(function (s) { return esc(s.src) + " " + s.lat.toFixed(2) + "," + s.lon.toFixed(2); }).join("；") + "</div>"
          : "") +
        "</div>";
    } else {
      html += "<p class='muted small'>所有定位源均未返回坐标。</p>";
    }
    html += "</div></div>";

    /* —— 地理位置（多源对比） —— */
    if (sources.length) {
      var maxOff = 0;
      sources.forEach(function (s) { maxOff = Math.max(maxOff, distKm(sources[0], s)); });
      html += "<div class='card' style='margin-top:14px'><p class='card-title'>地理位置（多源对比）</p><div class='kv-rows'>";
      sources.forEach(function (s, i) {
        var loc = [risk.country, risk.region, s.city].filter(Boolean).join(" / ");
        html += row((i === 0 ? "主定位" : "来源 " + i) + "<span class='muted small'>（" + esc(s.src) + "）</span>",
          "<div class='ms-row'>" + NP.flag(s.cc) + "<span>" + esc(loc) + "</span>" +
          "<a class='muted small' href='https://www.google.com/maps?q=" + s.lat + "," + s.lon + "' target='_blank' rel='noopener'>经纬度 " +
          s.lat.toFixed(3) + ", " + s.lon.toFixed(3) + " ↗</a></div>");
      });
      html += "</div><p class='muted small' style='margin:8px 0 0'>综合判断：" + NP.flag(geoCC) + " " +
        esc([risk.country, risk.region, risk.city].filter(Boolean).join(" / ") || "未知") +
        "（多源最大偏移 " + (maxOff < 1 ? maxOff.toFixed(1) : Math.round(maxOff)) + " km 内）。同一 IP 的城市归属如有偏移差异，属正常现象。</p></div>";
    }

    /* —— 关联域名 + 位置历史 —— */
    html += "<div class='duo-grid' style='margin-top:14px'>";
    html += "<div class='card'><p class='card-title'>关联域名<span class='muted small' title='由反向 DNS 与同网段 rDNS 推导'> ⓘ</span></p><div class='kv-rows'>";
    if (S.domains && S.domains.length) {
      S.domains.forEach(function (d) {
        html += row("<a href='/whois/#q=" + encodeURIComponent(d.domain) + "' target='_blank' rel='noopener'><b>" + esc(d.domain) + "</b></a>",
          "<span class='muted small'>via " + esc(d.via) + (d.host && d.host !== d.domain ? " · " + esc(d.host) : "") + "</span>");
      });
    } else {
      html += "<div class='muted small'>未发现关联域名</div>";
    }
    html += "</div></div>";
    html += "<div class='card'><p class='card-title'>位置历史<span class='muted small' title='本站对该网段的查询快照'> ⓘ</span></p><div class='kv-rows'>";
    if (S.geoHistory && S.geoHistory.length) {
      S.geoHistory.slice().reverse().forEach(function (h) {
        html += row(h.t, NP.flag(geoCC) + " " + esc(h.loc));
      });
    } else {
      html += "<div class='muted small'>暂无历史快照（随本站查询逐步积累）</div>";
    }
    html += "</div></div></div>";

    /* —— 同网段 / 客户活跃 —— */
    if (S.sample && S.sample.length) {
      html += "<div class='card' style='margin-top:14px'><p class='card-title'>同网段 / 邻居活跃" +
        "<span class='muted small' title='同一 /24 网段内抽样查询的邻居 IP 及其运营商'> ⓘ</span></p><div class='sample-grid'>";
      S.sample.forEach(function (x) {
        html += "<a class='sample-cell' href='/ip/#q=" + encodeURIComponent(x.ip) + "'>" +
          "<span class='sample-ip mono'>" + NP.flag(x.cc) + " " + esc(x.ip) + "</span>" +
          "<span class='muted small'>" + esc((x.city ? x.city + " · " : "") + (x.org || "")) + "</span></a>";
      });
      html += "</div></div>";
    }

    /* —— BGP 路由拓扑 —— */
    if (S.route && S.route.upstreams && S.route.upstreams.length) {
      html += "<div class='card' style='margin-top:14px'><p class='card-title'>BGP 路由拓扑" +
        " <span class='muted small'>" + esc(S.route.prefix || "") + " · " + S.route.paths + " 条观测路径</span></p>" +
        "<div id='routeBox' class='rt-wrap'></div>" +
        "<p class='muted small' style='margin:6px 0 0'>基于公开 BGP 观测路径（RIPE RIS 路由采集器）统计；连线粗细 = 路径占比，蓝框 = Tier 1 骨干。</p></div>";
    }

    /* —— DNSBL 12 源 —— */
    if (S.dnsblFull && S.dnsblFull.length) {
      var cleanN = S.dnsblFull.filter(function (r) { return !r.listed && !r.refused; }).length;
      var hitN = S.dnsblFull.filter(function (r) { return r.listed; }).length;
      var cats = {};
      S.dnsblFull.forEach(function (r) { cats[r.cat] = (cats[r.cat] || 0) + 1; });
      html += "<div class='card' style='margin-top:14px'><p class='card-title'>全球威胁与垃圾邮件黑名单 (DNSBL)" +
        "<span style='margin-left:auto;display:flex;gap:12px' class='small'>" +
        "<span><b>" + S.dnsblFull.length + "</b> 检测源</span>" +
        "<span style='color:var(--good)'><b>" + cleanN + "</b> 纯净</span>" +
        "<span style='color:" + (hitN ? "var(--bad)" : "inherit") + "'><b>" + hitN + "</b> 黑名单</span></span></p>" +
        "<div class='chips' id='dbllChips'><button class='chip active' data-cat='全部'>全部 (" + S.dnsblFull.length + ")</button>" +
        Object.keys(cats).map(function (c) { return "<button class='chip' data-cat='" + esc(c) + "'>" + esc(c) + " (" + cats[c] + ")</button>"; }).join("") +
        "</div><div class='dbll-grid' id='dbllGrid'></div></div>";
    }

    /* —— ASN 历史 + 企业历史 —— */
    if (asn) {
      html += "<div class='duo-grid' style='margin-top:14px'>";
      html += "<div class='card'><p class='card-title'>ASN 历史</p><div class='kv-rows'>" +
        (asn.date ? row(asn.date, "<b>AS" + risk.asn + "</b> · " + esc(asn.name || risk.asname || "")) : "<div class='muted small'>无 RDAP 事件记录</div>") +
        (asn.events || []).filter(function (e) { return e.action === "last changed" && e.date !== asn.date; })
          .map(function (e) { return row(e.date, "最近变更 · " + esc(asn.name || "AS" + risk.asn)); }).join("") +
        "</div></div>";
      html += "<div class='card'><p class='card-title'>企业历史</p><div class='kv-rows'>" +
        (asn.org ? row(asn.events && asn.events.length ? asn.events[asn.events.length - 1].date : asn.date || "—",
          "<b>" + esc(asn.org) + "</b> · " + esc(risk.is_datacenter ? "Hosting" : risk.isResidential ? "ISP" : risk.company_type || "未知")) : "<div class='muted small'>无注册企业记录</div>") +
        "</div></div></div>";
    }

    /* —— 同机房供应商 / 客户 —— */
    if (S.neighbours && S.neighbours.length) {
      html += "<div class='card' style='margin-top:14px'><p class='card-title'>同机房供应商 / 客户" +
        " <span class='muted small'>AS" + risk.asn + " · 基于 AS 互联关系推导</span>" +
        "<span style='margin-left:auto;display:flex;gap:8px'><button class='chip active' id='nbAll'>显示所有</button>" +
        "<button class='chip' id='nbIdc'>仅 IDC</button></span></p>" +
        "<div class='nb-grid' id='nbGrid'></div></div>";
    }

    /* —— 快捷工具 + 更多工具交叉验证 —— */
    html += "<div class='card' style='margin-top:14px'><p class='card-title'>报告与分享" +
      "<span style='margin-left:auto;display:flex;gap:8px;flex-wrap:wrap;align-items:center'>" +
      "<label class='toggle' style='margin:0'><span class='toggle-label small'>遮盖 IP 尾段</span>" +
      "<input type='checkbox' id='shareMask'><span class='slider'></span></label>" +
      "<select class='input' id='shareTtl' style='width:auto;padding:4px 8px;font-size:0.8em'>" +
      "<option value='86400'>1 天有效</option><option value='259200'>3 天有效</option><option value='604800' selected>7 天有效</option></select>" +
      "<button class='btn btn-ghost small' id='aiCopyBtn'>📋 复制给 AI 诊断</button>" +
      "<button class='btn btn-ghost small' id='shareReportBtn'>🔗 生成分享链接</button></span></p>" +
      "<div class='split-ip-grid' style='margin-bottom:10px'>" +
      "<a class='split-ip-cell' href='/dns/'>🔍 DNS 泄露检测</a>" +
      "<a class='split-ip-cell' href='/webrtc/'>🔊 WebRTC 泄露检测</a>" +
      "</div><div class='split-ip-grid'>";
    var q = encodeURIComponent(risk.ip || ip);
    [
      ["ip.sb", "https://ip.sb/ip/" + q],
      ["ipinfo.io", "https://ipinfo.io/" + q],
      ["bgp.he.net", "https://bgp.he.net/ip/" + q],
      ["Scamalytics", "https://scamalytics.com/ip/" + q],
      ["AbuseIPDB", "https://www.abuseipdb.com/check/" + q],
      ["Shodan", "https://www.shodan.io/search?query=" + q],
      ["VirusTotal", "https://www.virustotal.com/gui/ip-address/" + q],
      ["BGP.tools", "https://bgp.tools/prefix/" + q],
    ].forEach(function (x) {
      html += "<a class='split-ip-cell' href='" + x[1] + "' target='_blank' rel='noopener'>" + esc(x[0]) + " ↗</a>";
    });
    html += "</div></div>";

    area.innerHTML = html;

    // 分享报告按钮 + 复制给 AI
    var shareBtn = document.getElementById("shareReportBtn");
    if (shareBtn) {
      shareBtn.addEventListener("click", function () {
        makeShare(shareBtn);
      });
    }
    var aiBtn = document.getElementById("aiCopyBtn");
    if (aiBtn) {
      aiBtn.addEventListener("click", function () {
        copyAiSummary(aiBtn);
      });
    }

    // 后处理：趋势图 / 地图 / 地区延迟 / 路由图 / DNSBL / 邻居
    if (trend && trend.subnet.indexOf("/") > 0) {
      var canvas = document.getElementById("trendChart");
      if (canvas) drawTrend(canvas, trend.series);
    }
    initMap(sources);
    runRegionLatency();
    applyMask();

    if (S.route && S.route.upstreams && S.route.upstreams.length) {
      var box = document.getElementById("routeBox");
      if (box) {
        S.route.srcAsn = risk.asn;
        S.route.srcName = risk.org || risk.asname || risk.isp || "";
        drawRoute(box, S.route);
      }
    }
    if (S.dnsblFull && S.dnsblFull.length) {
      var gridEl = document.getElementById("dbllGrid");
      if (gridEl) {
        dnsblGrid(gridEl, S.dnsblFull, "全部");
        document.querySelectorAll("#dbllChips .chip").forEach(function (btn) {
          btn.addEventListener("click", function () {
            document.querySelectorAll("#dbllChips .chip").forEach(function (b) { b.classList.remove("active"); });
            btn.classList.add("active");
            dnsblGrid(gridEl, S.dnsblFull, btn.dataset.cat);
          });
        });
      }
    }
    if (S.neighbours && S.neighbours.length) {
      var nbGrid = document.getElementById("nbGrid");
      if (nbGrid) {
        var nbRender = function (idcOnly) {
          var list = idcOnly ? S.neighbours.filter(function (n) { return n.kind === "IDC"; }) : S.neighbours;
          nbGrid.innerHTML = list.length ? list.map(function (n) {
            return "<div class='nb-row'><div><b>" + esc(n.name) + "</b>" +
              "<span class='muted small'> · AS" + n.asn + " · " + esc(n.rel) + "</span></div>" +
              "<span class='pill " + (n.kind === "IDC" ? "pill-warn" : n.kind === "ISP" ? "pill-good" : "pill-muted") + "'>" + n.kind + "</span></div>";
          }).join("") : "<div class='muted small'>无 IDC 类型邻居</div>";
        };
        nbRender(false);
        document.getElementById("nbAll").addEventListener("click", function () {
          this.classList.add("active");
          document.getElementById("nbIdc").classList.remove("active");
          nbRender(false);
        });
        document.getElementById("nbIdc").addEventListener("click", function () {
          this.classList.add("active");
          document.getElementById("nbAll").classList.remove("active");
          nbRender(true);
        });
      }
    }
  }

  /* ---- 隐藏IP 开关（复用公共实现） ---- */
  function applyMask() {
    NP.applyIpMask();
  }
  NP.bindIpMask();

  /* ---- 生成分享报告快照（lookup 运行时回填） ---- */
  var gCtx = null;

  /* ---- 生成分享报告快照 ---- */
  function maskTail(v) {
    var t = String(v || "");
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) {
      var p = t.split(".");
      return p[0] + "." + p[1] + "." + p[2] + ".x";
    }
    if (t.indexOf(":") !== -1) {
      var parts = t.split(":");
      return parts.slice(0, Math.max(3, parts.length - 2)).join(":") + "::x";
    }
    return t;
  }
  function shareIp() {
    var box = document.getElementById("shareMask");
    var raw = (gCtx && gCtx.risk && gCtx.risk.ip) || (gCtx && gCtx.ip) || "";
    return box && box.checked ? maskTail(raw) : raw;
  }
  async function makeShare(btn) {
    var old = btn.textContent;
    btn.disabled = true; btn.textContent = "生成中…";
    try {
      if (!gCtx) { NP.toast("检测结果尚未就绪"); btn.disabled = false; btn.textContent = old; return; }
      var dnsblHit = gCtx.S && gCtx.S.dnsblFull ? gCtx.S.dnsblFull.filter(function (r) { return r.listed; }).length : 0;
      var ttlBox = document.getElementById("shareTtl");
      const r = await fetch("/api/report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ip: shareIp(),
          label: gCtx.risk.label || "",
          score: String(gCtx.score && gCtx.score.s != null ? gCtx.score.s : gCtx.score),
          purity: gCtx.trend && gCtx.trend.purity != null ? String(gCtx.trend.purity) : "",
          asn: gCtx.risk.asn ? "AS" + gCtx.risk.asn : "",
          org: gCtx.risk.org || gCtx.risk.isp || "",
          cc: gCtx.risk.country_code || "",
          city: gCtx.risk.city || "",
          region: gCtx.risk.region || "",
          rpki: (gCtx.S && gCtx.S.rpki && gCtx.S.rpki.status) || "",
          dnsblHit: String(dnsblHit),
          ttl: ttlBox ? parseInt(ttlBox.value, 10) : 604800,
        }),
        signal: AbortSignal.timeout(15000),
      });
      const d = await r.json();
      if (d.ok && d.url) {
        NP.copy(location.origin + d.url);
        btn.textContent = "✓ 已复制链接";
      } else {
        NP.toast("生成失败，请重试");
      }
    } catch (e) {
      NP.toast("生成失败，请重试");
    } finally {
      btn.disabled = false;
      setTimeout(function () { btn.textContent = old; }, 2500);
    }
  }

  /* ---- 复制给 AI 诊断（纯本地拼装，Markdown 文本） ---- */
  function copyAiSummary(btn) {
    var old = btn.textContent;
    if (!gCtx) { NP.toast("检测结果尚未就绪"); return; }
    var ipText = shareIp();
    var risk = gCtx.risk, trend = gCtx.trend, score = gCtx.score, S = gCtx.S;
    var dnsblHit = S && S.dnsblFull ? S.dnsblFull.filter(function (r) { return r.listed; }).length : 0;
    var lines = [
      "请帮我诊断这个 IP 的网络环境情况，以下是 NetProbe 的检测结果：",
      "",
      "- IP: " + (ipText || "未知"),
      "- IP 风险类型: " + (risk.label || "未知"),
      "- 风险评分: " + (score != null ? (score.s != null ? score.s : score) + " / 100" : "未测得"),
      "- 纯净度: " + (trend && trend.purity != null ? trend.purity + " / 100" : "未测得"),
      "- ASN / 组织: " + (risk.asn ? "AS" + risk.asn : "—") + " " + (risk.org || risk.isp || risk.asname || ""),
      "- 归属地: " + [risk.country_code, risk.region, risk.city].filter(Boolean).join(" / "),
      "- RPKI: " + ((S && S.rpki && S.rpki.status) || "未知"),
      "- DNSBL 命中: " + dnsblHit + " 个名单",
    ];
    if (S && S.tls && S.tls.tlsVersion) {
      lines.push("- TLS: " + S.tls.tlsVersion + (S.tls.tlsCipher ? " · " + S.tls.tlsCipher : ""));
    }
    lines.push("");
    lines.push("请基于以上信息分析：这个 IP 适合做什么（流媒体/AI 服务/注册账号等）、风险点在哪里、有什么改进建议。");
    NP.copy(lines.join("\n"));
    btn.textContent = "✓ 已复制";
    setTimeout(function () { btn.textContent = old; }, 2000);
  }

  async function selfIp() {
    const t = await NP.selfTrace();
    return t ? t.ip : null;
  }

  document.getElementById("form").addEventListener("submit", function (e) {
    e.preventDefault();
    var v = document.getElementById("ipInput").value.trim();
    if (v) {
      location.hash = "#q=" + encodeURIComponent(v);
      lookup(v);
    } else {
      selfIp().then(function (ip) {
        if (ip) {
          document.getElementById("ipInput").value = ip;
          location.hash = "#q=" + encodeURIComponent(ip);
          lookup(ip);
        }
      });
    }
  });

  /* ---- 语音搜索（Web Speech API，Chrome/Edge 支持） ---- */
  (function () {
    var SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SR) return;
    var btn = document.getElementById("micBtn");
    var input = document.getElementById("ipInput");
    btn.style.display = "";
    var rec = null, listening = false;
    btn.addEventListener("click", function () {
      if (listening) { try { rec.stop(); } catch (e) {} return; }
      try {
        rec = new SR();
        rec.lang = "zh-CN";
        rec.interimResults = false;
        rec.maxAlternatives = 1;
      } catch (e) { NP.toast("当前浏览器不支持语音输入"); return; }
      rec.onstart = function () {
        listening = true;
        btn.classList.add("listening");
        btn.title = "正在聆听，点击停止";
      };
      rec.onend = function () {
        listening = false;
        btn.classList.remove("listening");
        btn.title = "语音输入 IP（Chrome/Edge）";
      };
      rec.onerror = function () {
        NP.toast("语音识别失败，请重试或改用键盘输入");
      };
      rec.onresult = function (e) {
        var said = e.results && e.results[0] && e.results[0][0] ? e.results[0][0].transcript : "";
        if (!said) return;
        // 优先提取 IPv4；再尝试 IPv6（含"冒号"读法转写）；否则原样填入
        var v4 = said.match(/\d{1,3}(?:[.\s，。点]\d{1,3}){3}/);
        if (v4) {
          said = v4[0].replace(/[.\s，。点]+/g, ".").replace(/(^\.|\.$)/g, "");
        } else {
          var v6 = said.match(/(?:[0-9a-fA-F]{0,4}[:：]){2,7}[0-9a-fA-F]{0,4}/);
          if (v6) said = v6[0].replace(/：/g, ":");
        }
        input.value = said.trim();
        document.getElementById("form").dispatchEvent(new Event("submit", { cancelable: true }));
      };
      try { rec.start(); } catch (e) { NP.toast("语音识别启动失败"); }
    });
  })();

  (async function init() {
    // 兼容三种入口：#q= 哈希、?q= 参数、路径 /ip/<ip>（主页与各页链接均指向后两种）
    var q = null, m;
    if ((m = location.hash.match(/#q=(.+)$/))) q = decodeURIComponent(m[1]);
    if (!q) {
      try { q = new URLSearchParams(location.search).get("q") || null; } catch (e) {}
    }
    if (!q && (m = location.pathname.match(/^\/ip\/([^\/]+)\/?$/))) q = decodeURIComponent(m[1]);
    if (q) {
      document.getElementById("ipInput").value = q;
      lookup(q);
      return;
    }
    // 无参数访问：自动查询本机出口 IP（与参考站一致的打开即查）
    var ip = await selfIp();
    if (!ip) {
      try {
        var r = await fetch("/api/session", { signal: AbortSignal.timeout(5000) });
        ip = (await r.json()).ip || "";
      } catch (e) {}
    }
    if (ip) {
      document.getElementById("ipInput").value = ip;
      lookup(ip);
    }
  })();
})();
