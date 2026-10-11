/* ============================================================
   NetProbe — 分流出口检测（原创实现）
   浏览器逐一 fetch 各目标站点的公开回显接口（Cloudflare 系为
   cdn-cgi/trace，开放 CORS 且返回 ip= 行），读取每个站点看到的
   出口 IP；DNS 出口用唯一子域名触发本机解析（ipleak 检测节点，
   响应体直接带解析器列表）；WebRTC 出口用 STUN srflx 候选。
   归属地经本站 /api/egress/geo 批量补齐，地图用本地 Leaflet。
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;

  var TARGETS = [
    { name: "claude.ai", tag: "AI", url: "https://claude.ai/cdn-cgi/trace" },
    { name: "chatgpt.com", tag: "AI", url: "https://chatgpt.com/cdn-cgi/trace" },
    { name: "openai.com", tag: "AI", url: "https://openai.com/cdn-cgi/trace" },
    { name: "sora.com", tag: "AI", url: "https://sora.com/cdn-cgi/trace" },
    { name: "perplexity.ai", tag: "AI", url: "https://perplexity.ai/cdn-cgi/trace" },
    { name: "www.cloudflare.com", tag: "全球", url: "https://www.cloudflare.com/cdn-cgi/trace" },
    { name: "gitlab.com", tag: "开发", url: "https://gitlab.com/cdn-cgi/trace" },
    { name: "nodejs.org", tag: "开发", url: "https://nodejs.org/cdn-cgi/trace" },
    { name: "www.coinbase.com", tag: "支付", url: "https://www.coinbase.com/cdn-cgi/trace" },
    { name: "www.okx.com", tag: "支付", url: "https://www.okx.com/cdn-cgi/trace" },
    { name: "api.ipify.org", tag: "参考", url: "https://api.ipify.org?format=json", json: true, note: "直连参考" },
  ];
  var TAG_CLS = { AI: "pill-bad", 全球: "pill-info", 开发: "pill-good", 支付: "pill-warn", 参考: "pill-muted", DNS: "pill-info", "WEBRTC": "pill-warn" };

  function setProgress(pct, text) {
    var bar = document.querySelector("#progress i");
    if (bar) bar.style.width = pct + "%";
    document.getElementById("progressText").textContent = text || "";
  }

  function isV4(s) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(s); }

  async function probeTarget(t) {
    var t0 = performance.now();
    var resp = await fetch(t.url, { cache: "no-store", signal: AbortSignal.timeout(9000) });
    var text = await resp.text();
    var ms = Math.round(performance.now() - t0);
    var ip = "";
    if (t.json) {
      try { ip = (JSON.parse(text).ip || "").trim(); } catch (e) {}
    } else {
      var m = text.match(/^ip=(.+)$/m);
      if (m) ip = m[1].trim();
    }
    if (!ip) throw new Error("no ip");
    return { ip: ip, ms: ms };
  }

  /* DNS 出口：唯一子域名触发本机解析，检测节点在响应里直接回传解析器来源 */
  async function dnsExits() {
    var chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    var token = "";
    for (var i = 0; i < 22; i++) token += chars[Math.floor(Math.random() * chars.length)];
    var found = new Map();
    for (var r = 1; r <= 2; r++) {
      try {
        var resp = await fetch("https://" + token + "-" + r + ".ipleak.net/dnsdetection/?_=" + Date.now(),
          { cache: "no-store", signal: AbortSignal.timeout(8000) });
        var data = await resp.json();
        if (data && !Array.isArray(data) && data.ip) {
          Object.keys(data.ip).forEach(function (ip) {
            if (!found.has(ip)) found.set(ip, true);
          });
        }
      } catch (e) {}
      setProgress(78 + r * 3, "DNS 解析探测（" + r + "/2）…");
    }
    return [...found.keys()];
  }

  /* WebRTC 出口：STUN srflx 公网映射地址（跳过 mDNS 混淆地址） */
  function webrtcExit() {
    return new Promise(function (resolve) {
      if (typeof RTCPeerConnection === "undefined") return resolve(null);
      var pc;
      try {
        pc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }, { urls: "stun:stun.cloudflare.com:3478" }] });
      } catch (e) { return resolve(null); }
      var done = false;
      var timer = setTimeout(function () { finish(null); }, 7000);
      function finish(v) {
        if (done) return;
        done = true;
        clearTimeout(timer);
        try { pc.close(); } catch (e) {}
        resolve(v);
      }
      pc.createDataChannel("");
      pc.onicecandidate = function (e) {
        if (!e.candidate) return finish(null);
        var c = e.candidate.candidate || "";
        var m = c.match(/candidate:\S+ \d+ \S+ \d+ ([^\s]+) \d+ typ srflx/);
        if (m && m[1].indexOf(".local") === -1) finish(m[1]);
      };
      pc.createOffer().then(function (o) { return pc.setLocalDescription(o); }).catch(function () { finish(null); });
    });
  }

  /* ---------- 渲染 ---------- */
  var ROWS = []; // {label, tag, ip, ms, done, note}

  function tagPill(tag) {
    return "<span class='pill " + (TAG_CLS[tag] || "pill-muted") + "'>" + esc(tag) + "</span>";
  }

  function renderRows() {
    document.getElementById("egBody").innerHTML = ROWS.map(function (r, i) {
      var ipCell = "<span class='muted small'>检测中…</span>";
      if (r.done && r.ip) ipCell = "<span class='ip-cell mono'>" + esc(r.ip) + "</span>";
      else if (r.done && r.error) ipCell = "<span class='error-text small'>" + esc(r.error) + "</span>";
      else if (r.done) ipCell = "<span class='muted small'>未探测到</span>";
      var geoCell = "<span class='muted small' data-geo-for='" + i + "'>—</span>";
      var msCell = r.done && r.ms != null ? r.ms + " ms" : "—";
      var nameHtml = esc(r.label) + (r.note ? " <span class='muted small'>" + esc(r.note) + "</span>" : "");
      return "<tr><td><b>" + nameHtml + "</b></td><td>" + tagPill(r.tag) + "</td>" +
        "<td>" + ipCell + "</td><td>" + geoCell + "</td><td class='muted small'>" + msCell + "</td></tr>";
    }).join("");
  }

  function fillGeo(geoMap) {
    ROWS.forEach(function (r, i) {
      if (!r.ip) return;
      var g = geoMap[r.ip];
      var el = document.querySelector("[data-geo-for='" + i + "']");
      if (el && g) {
        el.innerHTML = NP.flag(g.countryCode) + " " + esc([g.country, g.city].filter(Boolean).join(" · ") || "未知");
      } else if (el) {
        el.textContent = "未知";
      }
    });
  }

  function drawMap(points) {
    document.getElementById("mapCard").style.display = "";
    var el = document.getElementById("egMap");
    if (typeof L === "undefined" || !points.length) {
      document.getElementById("mapWrap").innerHTML =
        "<div class='muted small' style='padding:30px;text-align:center'>地图组件加载失败，共 " + points.length + " 个出口位置。</div>";
      return;
    }
    var first = points[0];
    var map = L.map(el, { zoomControl: true }).setView([first.lat, first.lon], 3);
    L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", { maxZoom: 18, attribution: "&copy; OpenStreetMap contributors" }).addTo(map);
    points.forEach(function (p) {
      var ccText = p.cc ? (GEO.CC_NAME[p.cc] || String(p.cc).toUpperCase()) : "未知地区";
      L.circleMarker([p.lat, p.lon], { radius: 8, color: "#e05252", weight: 2, fillColor: "#e05252", fillOpacity: 0.5 })
        .addTo(map)
        .bindPopup(esc((p.city || "未知城市") + " · " + ccText) +
          "<br>" + esc(p.users.join("、")));
    });
    setTimeout(function () { map.invalidateSize(); }, 200);
  }

  function verdict() {
    var siteRows = ROWS.filter(function (r) { return r.tag !== "DNS" && r.tag !== "WEBRTC" && r.done && r.ip; });
    var ips = [...new Set(siteRows.map(function (r) { return r.ip; }))];
    var el = document.getElementById("egVerdict");
    var dnsRow = ROWS.find(function (r) { return r.tag === "DNS"; });
    var html = "";
    if (ips.length <= 1) {
      html += "<div class='verdict verdict-info'>所有站点出口一致（" + esc(ips[0] || "未知") + "）：当前更像是全局代理或直连。若你配置了分流规则却没有出现不同出口，请检查客户端模式与规则顺序。</div>";
    } else {
      html += "<div class='verdict verdict-safe'>✓ 检测到 " + ips.length + " 个不同出口：分流已生效。请核对每个目标走的是不是你预期的线路。</div>";
    }
    if (dnsRow && dnsRow.done && dnsRow.ips && dnsRow.ips.length) {
      html += "<div class='verdict verdict-warn' style='margin-top:8px'>DNS 解析出口：" +
        dnsRow.ips.map(function (x) { return esc(x); }).join("、") +
        "。若该地址属于你的宽带运营商而非代理服务商，说明 DNS 在本地明文解析，建议到「DNS泄露」页面深度检测。</div>";
    } else if (dnsRow && dnsRow.done) {
      html += "<div class='verdict verdict-safe' style='margin-top:8px'>未捕获明文 DNS 解析出口——你的 DNS 很可能已加密（DoH/DoT 或 fake-IP 模式）。</div>";
    }
    el.innerHTML = html;
    document.getElementById("distinctInfo").textContent = "共 " + siteRows.length + " 个站点 · " + ips.length + " 个不同出口";
  }

  async function start() {
    var btn = document.getElementById("startBtn");
    btn.disabled = true;
    document.getElementById("resultCard").style.display = "";
    document.getElementById("mapCard").style.display = "none";
    document.getElementById("egVerdict").innerHTML = "";
    document.getElementById("distinctInfo").textContent = "";
    NP.applyIpMask && NP.applyIpMask();

    ROWS = TARGETS.map(function (t) {
      return { label: t.name, tag: t.tag, ip: "", ms: null, done: false, note: t.note || "", error: "", url: t.url, json: !!t.json };
    });
    ROWS.push({ label: "DNS 解析出口", tag: "DNS", ip: "", ms: null, done: false, note: "唯一子域名探测", error: "", ips: null });
    ROWS.push({ label: "WebRTC UDP 出口", tag: "WEBRTC", ip: "", ms: null, done: false, note: "STUN srflx", error: "" });
    renderRows();

    var finished = 0;
    var total = ROWS.length;

    /* HTTP 目标并行探测，每个完成即刷新行 */
    var probes = TARGETS.map(async function (t, idx) {
      setProgress(5 + Math.round((finished / total) * 60), "正在探测 " + t.name + " …");
      try {
        var res = await probeTarget(t);
        ROWS[idx].ip = res.ip;
        ROWS[idx].ms = res.ms;
      } catch (e) {
        ROWS[idx].done = true;
        ROWS[idx].error = "不可达或被拦截";
        finished++;
        renderRows();
        return;
      }
      ROWS[idx].done = true;
      finished++;
      renderRows();
      setProgress(5 + Math.round((finished / total) * 60), "已探测 " + finished + "/" + total);
    });

    /* DNS 出口 */
    var dnsPromise = (async function () {
      var idx = ROWS.findIndex(function (r) { return r.tag === "DNS"; });
      try {
        var ips = await dnsExits();
        ROWS[idx].done = true;
        ROWS[idx].ips = ips;
        ROWS[idx].ip = ips.length === 1 ? ips[0] : "";
      } catch (e) {
        ROWS[idx].done = true;
        ROWS[idx].error = "探测节点不可达";
      }
      finished++;
      renderRows();
      setProgress(5 + Math.round((finished / total) * 60), "DNS 探测完成");
    })();

    /* WebRTC 出口 */
    var webrtcPromise = (async function () {
      var idx = ROWS.findIndex(function (r) { return r.tag === "WEBRTC"; });
      var ip = await webrtcExit();
      ROWS[idx].done = true;
      ROWS[idx].ip = ip || "";
      if (!ip) ROWS[idx].error = "浏览器已禁用或无 srflx 候选";
      finished++;
      renderRows();
      setProgress(5 + Math.round((finished / total) * 60), "WebRTC 探测完成");
    })();

    await Promise.allSettled([Promise.allSettled(probes), dnsPromise, webrtcPromise]);
    setProgress(88, "批量查询归属地…");

    /* 批量归属地 + 地图 */
    var allIps = [...new Set(ROWS.filter(function (r) { return r.ip; }).map(function (r) { return r.ip; }))];
    var geoMap = {};
    if (allIps.length) {
      try {
        var resp = await fetch("/api/egress/geo", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ips: allIps }),
          signal: AbortSignal.timeout(30000),
        });
        var d = await resp.json();
        if (d && d.geo) geoMap = d.geo;
      } catch (e) {}
    }
    fillGeo(geoMap);
    verdict();
    NP.applyIpMask && NP.applyIpMask();

    var points = [];
    var byIp = {};
    ROWS.forEach(function (r) {
      if (!r.ip || !geoMap[r.ip]) return;
      var g = geoMap[r.ip];
      var la = g.latitude != null ? g.latitude : g.lat;
      var lo = g.longitude != null ? g.longitude : g.lon;
      if (la == null || lo == null) return;
      if (!byIp[r.ip]) byIp[r.ip] = { lat: la, lon: lo, cc: g.countryCode, city: g.city, users: [] };
      byIp[r.ip].users.push(r.label);
    });
    Object.keys(byIp).forEach(function (k) { points.push(byIp[k]); });
    if (points.length) drawMap(points);

    setProgress(100, "完成");
    btn.disabled = false;
    btn.textContent = "重新检测";
  }

  document.getElementById("startBtn").addEventListener("click", start);
  NP.bindIpMask();
})();
