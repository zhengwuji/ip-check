/* ============================================================
   NetProbe 主页逻辑（原创实现）
   1) 本机 IP 查询（国内源 + GeoIP 纠偏）  2) 连通性点阵
   3) 35+ 网站分流出口测试  4) 出口 IP 汇总  5) 隐藏IP 开关
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;

  /* ---------------- 连通性点阵 ---------------- */
  var pingTargets = [
    { name: "字节跳动", domain: "perfops.byte-test.com", url: "https://perfops.byte-test.com/500b-bench.jpg", tag: "国内" },
    { name: "淘宝", domain: "taobao.com", url: "https://www.taobao.com/favicon.ico", tag: "国内" },
    { name: "微信", domain: "qq.com", url: "https://res.wx.qq.com/a/wx_fed/assets/res/NTI4MWU5.ico", tag: "国内" },
    { name: "GitHub", domain: "github.com", url: "https://github.com/generate_204", tag: "国际" },
    { name: "Cloudflare", domain: "cloudflare.com", url: "https://1.1.1.1/cdn-cgi/trace", tag: "国际" },
    { name: "YouTube", domain: "youtube.com", url: "https://www.youtube.com/generate_204", tag: "国际" },
  ];

  function dotClass(ms) {
    if (ms < 0) return "dot-fail";
    if (ms < 100) return "dot-good";
    if (ms < 400) return "dot-warn";
    return "dot-bad";
  }

  async function probe(url) {
    var start = performance.now();
    try {
      await fetch(url, { mode: "no-cors", cache: "no-store", signal: AbortSignal.timeout(2500) });
      return Math.round(performance.now() - start);
    } catch (e) {
      return -1;
    }
  }

  function renderPingGrid() {
    var grid = document.getElementById("pingGrid");
    grid.innerHTML = pingTargets
      .map(function (t, i) {
        var dots = "";
        for (var d = 0; d < 12; d++) dots += '<div class="ping-dot dot-pending"></div>';
        return (
          '<div class="ping-card">' +
          '<div class="ping-card-top">' + NP.favicon(t.domain, t.name) +
          '<span class="ping-name">' + esc(t.name) + (t.tag === "国内" ? NP.flag("cn") : "") + "</span>" +
          '<span class="ping-ms" id="pm-' + i + '" style="color:var(--text-muted)">--</span></div>' +
          '<div class="ping-dots" id="pd-' + i + '">' + dots + "</div>" +
          "</div>"
        );
      })
      .join("");
  }

  async function runPings() {
    // 预热：建立 TCP+TLS 连接，不计入显示
    await Promise.allSettled(pingTargets.map(function (t) { return probe(t.url); }));

    var ROUNDS = 12, MIN_GAP = 80;
    var history = pingTargets.map(function () { return []; });

    await Promise.allSettled(
      pingTargets.map(async function (t, i) {
        for (var round = 0; round < ROUNDS; round++) {
          var t0 = performance.now();
          var ms = await probe(t.url);
          var dot = document.querySelector("#pd-" + i + " .ping-dot:nth-child(" + (round + 1) + ")");
          if (dot) dot.className = "ping-dot " + dotClass(ms);
          if (ms >= 0) history[i].push(ms);
          var med = NP.median(history[i]);
          var msEl = document.getElementById("pm-" + i);
          if (med >= 0) {
            msEl.textContent = Math.min(med, 999) + "ms";
            msEl.style.color = med < 100 ? "var(--good)" : med < 400 ? "#e0b341" : "var(--warn)";
          } else {
            msEl.textContent = "超时";
            msEl.style.color = "var(--bad)";
          }
          var cost = performance.now() - t0;
          if (cost < MIN_GAP && round < ROUNDS - 1) {
            await new Promise(function (r) { setTimeout(r, MIN_GAP - cost); });
          }
        }
      })
    );
  }

  /* ---------------- 本机 IP 查询 ---------------- */
  async function fetchIp138() {
    try {
      const resp = await NP.fetchT("https://2026.ip138.com/", null, 8000);
      const html = await resp.text();
      const ipM = html.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
      const geoM = html.match(/来自：([^<\n]+)/) || html.match(/本站主数据：([^<\n]+)/);
      if (ipM) return { ip: ipM[1], geo: geoM ? geoM[1].trim() : "", source: "ip138.com" };
    } catch (e) {}
    return null;
  }

  async function fetchIpCN() {
    try {
      const resp = await NP.fetchT("https://my.ip.cn/", null, 8000);
      const text = await resp.text();
      const ipM = text.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
      const geoM = text.match(/归属地[:：]\s*(.+)/);
      if (ipM) return { ip: ipM[1], geo: geoM ? geoM[1].trim() : "", source: "ip.cn" };
    } catch (e) {}
    return null;
  }

  // 用 GeoIP 国家码校验中文文案，不一致时以国家码为准重建文案
  async function pickGeo(ip, candidates) {
    var data = null;
    try { data = await GEO.lookup(ip); } catch (e) {}
    var cc = data && data.countryCode;
    var best = candidates.filter(function (c) { return c && c.geo; })
      .sort(function (a, b) { return b.geo.length - a.geo.length; })[0] || { geo: "", source: "" };
    if (!cc) return best;
    var validated = candidates.filter(function (c) {
      return c && c.geo && GEO.validateGeoText(c.geo, cc, data) === c.geo;
    });
    var pick = validated.sort(function (a, b) { return b.geo.length - a.geo.length; })[0] || best;
    if (!pick.geo && data) pick = { geo: data.geoString, source: "GeoIP" };
    return pick;
  }

  async function renderIpResult(ip, geo, source, valueEl, geoEl, sourceEl) {
    var flag = "";
    var data = null;
    try { data = await GEO.lookup(ip); } catch (e) {}
    if (data && data.countryCode) flag = NP.flag(data.countryCode);
    if (!geo && data) geo = data.geoString;
    valueEl.innerHTML = flag + ' <a href="/ip/?q=' + encodeURIComponent(ip) + '" target="_blank" rel="noopener">' + esc(ip) + "</a>";
    geoEl.textContent = geo || "";
    geoEl.title = geo || "";
    // 出口性质：依赖后端 ASN 分类
    try {
      const r = await fetch("/api/iprisk/" + encodeURIComponent(ip), { signal: AbortSignal.timeout(6000) });
      if (r.ok) {
        const d = await r.json();
        sourceEl.innerHTML = esc(d.label || "");
        sourceEl.title = d.note || "";
      }
    } catch (e) {}
  }

  function cloneIpCard(titleSuffix) {
    var card = document.createElement("div");
    card.className = "card";
    card.innerHTML =
      '<div class="kv" style="background:transparent;border:none;padding:0"><div class="k">IPv4 (' + titleSuffix + ')</div></div>' +
      '<div class="ip-value"></div><div class="ip-geo"></div><div class="ip-source"></div>';
    document.getElementById("ipCard").after(card);
    return {
      value: card.querySelector(".ip-value"),
      geo: card.querySelector(".ip-geo"),
      source: card.querySelector(".ip-source"),
    };
  }

  async function runIpQuery() {
    var results = await Promise.allSettled([fetchIp138(), fetchIpCN()]);
    var a = results[0].status === "fulfilled" ? results[0].value : null;
    var b = results[1].status === "fulfilled" ? results[1].value : null;
    var vEl = document.getElementById("ipValue");
    var gEl = document.getElementById("ipGeo");
    var sEl = document.getElementById("ipSource");

    if (!a && !b) {
      vEl.textContent = "获取失败";
      gEl.textContent = "无法连接国内 IP 查询服务";
      return;
    }
    if (!a || !b) {
      var r = a || b;
      await renderIpResult(r.ip, r.geo, r.source, vEl, gEl, sEl);
      return;
    }
    if (a.ip === b.ip) {
      var picked = await pickGeo(a.ip, [
        { geo: a.geo, source: "ip138" },
        { geo: b.geo, source: "ip.cn" },
      ]);
      var src = picked.source === "GeoIP" ? "GeoIP（地区库纠偏）" : "ip138 / ip.cn";
      await renderIpResult(a.ip, picked.geo, src, vEl, gEl, sEl);
    } else {
      var p1 = await pickGeo(a.ip, [{ geo: a.geo, source: "ip138" }]);
      await renderIpResult(a.ip, p1.geo, p1.source, vEl, gEl, sEl);
      var el2 = cloneIpCard("备用出口");
      var p2 = await pickGeo(b.ip, [{ geo: b.geo, source: "ip.cn" }]);
      await renderIpResult(b.ip, p2.geo, p2.source, el2.value, el2.geo, el2.source);
    }
  }

  /* ---------------- 网站分流测试 ---------------- */
  // method:
  //   cftrace  — 请求目标站 cdn-cgi/trace，从文本取 ip / loc
  //   netease  — HEAD 图片，读 cdn-user-ip 响应头
  //   bytedance— HEAD 图片，读 x-request-ip / x-response-cinfo 响应头
  //   alibaba  — alicdn DNS 探测 JSONP
  var tests = [
    { name: "网易", type: "domestic", method: "netease", domain: "163.com" },
    { name: "字节跳动", type: "domestic", method: "bytedance", domain: "bytedance.com", url: "https://perfops.byte-test.com/500b-bench.jpg" },
    { name: "Cloudflare中国", type: "domestic", method: "cftrace", domain: "cloudflare-cn.com", cfhost: "www.cloudflare-cn.com" },
    { name: "高通中国", type: "domestic", method: "cftrace", domain: "qualcomm.cn", cfhost: "www.qualcomm.cn" },

    { name: "Discord", type: "international", extra: ["social"], method: "cftrace", domain: "discord.com", cfhost: "gateway.discord.gg" },
    { name: "X (Twitter)", type: "international", extra: ["social"], method: "cftrace", domain: "x.com", cfhost: "api.x.com" },
    { name: "Medium", type: "international", extra: ["social"], method: "cftrace", domain: "medium.com", cfhost: "medium.com" },
    { name: "Signal", type: "international", extra: ["social"], method: "cftrace", domain: "signal.org", cfhost: "signal.org" },

    { name: "Anthropic", type: "international", extra: ["ai"], method: "cftrace", domain: "anthropic.com", cfhost: "anthropic.com" },
    { name: "Claude", type: "international", extra: ["ai"], method: "cftrace", domain: "claude.ai", cfhost: "claude.ai" },
    { name: "ChatGPT", type: "international", extra: ["ai"], method: "cftrace", domain: "chatgpt.com", cfhost: "chatgpt.com" },
    { name: "OpenAI", type: "international", extra: ["ai"], method: "cftrace", domain: "openai.com", cfhost: "openai.com" },
    { name: "Sora", type: "international", extra: ["ai"], method: "cftrace", domain: "sora.com", cfhost: "sora.com" },
    { name: "Grok", type: "international", extra: ["ai"], method: "cftrace", domain: "grok.com", cfhost: "grok.com" },
    { name: "Perplexity", type: "international", extra: ["ai"], method: "cftrace", domain: "perplexity.ai", cfhost: "www.perplexity.ai" },
    { name: "Midjourney", type: "international", extra: ["ai"], method: "cftrace", domain: "midjourney.com", cfhost: "midjourney.com" },
    { name: "Mistral AI", type: "international", extra: ["ai"], method: "cftrace", domain: "mistral.ai", cfhost: "mistral.ai" },

    { name: "Coinbase", type: "international", extra: ["crypto"], method: "cftrace", domain: "coinbase.com", cfhost: "coinbase.com" },
    { name: "OKX", type: "international", extra: ["crypto"], method: "cftrace", domain: "okx.com", cfhost: "www.okx.com" },
    { name: "Binance", type: "international", extra: ["crypto"], method: "cftrace", domain: "binance.com", cfhost: "www.binance.info" },
    { name: "Crypto.com", type: "international", extra: ["crypto"], method: "cftrace", domain: "crypto.com", cfhost: "crypto.com" },

    { name: "Zoom", type: "international", extra: ["tools"], method: "cftrace", domain: "zoom.us", cfhost: "zoom.us" },
    { name: "1Password", type: "international", extra: ["tools"], method: "cftrace", domain: "1password.com", cfhost: "1password.com" },
    { name: "Wise", type: "international", extra: ["tools"], method: "cftrace", domain: "wise.com", cfhost: "wise.com" },
    { name: "Poe", type: "international", extra: ["tools"], method: "cftrace", domain: "poe.com", cfhost: "poe.com" },
    { name: "Notion", type: "international", extra: ["tools"], method: "cftrace", domain: "notion.so", cfhost: "notion.so" },
    { name: "Shopify", type: "international", extra: ["tools"], method: "cftrace", domain: "shopify.com", cfhost: "shopify.com" },
    { name: "GoDaddy", type: "international", extra: ["tools"], method: "cftrace", domain: "godaddy.com", cfhost: "godaddy.com" },
    { name: "Product Hunt", type: "international", extra: ["tools"], method: "cftrace", domain: "producthunt.com", cfhost: "producthunt.com" },

    { name: "Cloudflare", type: "international", extra: ["speed"], method: "cftrace", domain: "cloudflare.com", cfhost: "www.cloudflare.com" },

    { name: "cdnjs", type: "international", extra: ["static"], method: "cftrace", domain: "cdnjs.cloudflare.com", cfhost: "cdnjs.cloudflare.com" },
    { name: "npm registry", type: "international", extra: ["static"], method: "cftrace", domain: "npmjs.com", cfhost: "registry.npmjs.org" },
    { name: "Kali 镜像", type: "international", extra: ["static"], method: "cftrace", domain: "kali.download", cfhost: "kali.download" },
    { name: "unpkg", type: "international", extra: ["static"], method: "cftrace", domain: "unpkg.com", cfhost: "unpkg.com" },
    { name: "Node.js", type: "international", extra: ["dev"], method: "cftrace", domain: "nodejs.org", cfhost: "nodejs.org" },
    { name: "GitLab", type: "international", extra: ["dev"], method: "cftrace", domain: "gitlab.com", cfhost: "gitlab.com" },

    { name: "Crunchyroll", type: "international", extra: ["media"], method: "cftrace", domain: "crunchyroll.com", cfhost: "crunchyroll.com" },
  ];

  var state = tests.map(function () {
    return { status: "pending", ip: null, geo: null, cc: null, error: null };
  });

  function badgeHTML(t) {
    var html = t.type === "domestic"
      ? '<span class="badge badge-domestic">国内</span>'
      : '<span class="badge badge-international">国际</span>';
    var labels = { ai: "AI", crypto: "Crypto", social: "Social", tools: "Tools", speed: "Speed", dev: "Dev", media: "Media", static: "Static" };
    (t.extra || []).forEach(function (e) {
      html += '<span class="badge badge-' + e + '">' + (labels[e] || e) + "</span>";
    });
    return html;
  }

  function cellsHTML(i) {
    var t = tests[i], s = state[i];
    var siteCell = "<td><div class='site-cell'>" + NP.favicon(t.domain, t.name) +
      "<span class='site-name'>" + esc(t.name) + "</span>" + badgeHTML(t) + "</div></td>";
    var flagCell, ipCell, geoCell;
    if (s.status === "pending") {
      flagCell = "<td></td>"; ipCell = "<td><span class='pending-text'></span></td>"; geoCell = "<td></td>";
    } else if (s.status === "loading") {
      flagCell = "<td><div class='loading-bar' style='width:22px;height:22px;border-radius:50%'></div></td>";
      ipCell = "<td><div class='loading-bar' style='width:110px'></div></td>";
      geoCell = "<td><div class='loading-bar' style='width:160px'></div></td>";
    } else if (s.status === "error") {
      flagCell = "<td class='muted' style='text-align:center'>?</td>";
      ipCell = "<td><span class='error-text'>" + esc(s.error || "获取失败") + "</span></td>";
      geoCell = "<td></td>";
    } else {
      flagCell = "<td>" + NP.flag(s.cc) + "</td>";
      ipCell = "<td class='ip-cell ip-text'>" + esc(s.ip || "未获取到 IP") + "</td>";
      geoCell = "<td class='geo-cell'>" + esc(s.geo || "") + "</td>";
    }
    return siteCell + flagCell + ipCell + geoCell;
  }

  function renderRow(i) {
    var tbody = document.getElementById("tableBody");
    var row = tbody.children[i];
    if (!row) return renderTable();
    row.innerHTML = cellsHTML(i);
    renderSummary();
  }

  function renderTable() {
    document.getElementById("tableBody").innerHTML =
      tests.map(function (_, i) { return "<tr>" + cellsHTML(i) + "</tr>"; }).join("");
  }

  /* ---------- 出口 IP 汇总 ---------- */
  function compactIp(ip) {
    if (!ip || ip.indexOf(":") === -1) return ip;
    if (ip.length <= 22) return ip;
    var p = ip.split(":");
    return p[0] + ":" + p[1] + "…" + p[p.length - 1];
  }

  function renderSummary() {
    var grid = document.getElementById("splitIpGrid");
    var seen = new Map();
    state.forEach(function (s) {
      if (!s || s.status !== "done" || !s.ip) return;
      if (!seen.has(s.ip)) seen.set(s.ip, s.cc || "");
      else if (!seen.get(s.ip) && s.cc) seen.set(s.ip, s.cc);
    });
    var cells = [];
    seen.forEach(function (cc, ip) {
      cells.push(
        '<a class="split-ip-cell" href="/ip/?q=' + encodeURIComponent(ip) + '" target="_blank" rel="noopener" title="查询 ' + esc(ip) + ' 的 IP 质量">' +
        NP.flag(cc, "split-flag") + "<span class='split-ip ip-text'>" + esc(compactIp(ip)) + "</span></a>"
      );
    });
    grid.innerHTML = cells.join("");
    applyMasks();
  }

  /* ---------- 检测方法实现 ---------- */
  async function detectCfTrace(host) {
    const resp = await NP.fetchT("https://" + host + "/cdn-cgi/trace", null, 5000);
    const text = await resp.text();
    const map = {};
    text.trim().split("\n").forEach(function (line) {
      var kv = line.split("=");
      if (kv.length >= 2) map[kv[0]] = kv.slice(1).join("=");
    });
    return { ip: map.ip || null, loc: map.loc ? map.loc.toLowerCase() : null };
  }

  function detectAlibaba() {
    return new Promise(function (resolve, reject) {
      var cb = "__npAli_" + Date.now() + "_" + Math.random().toString(36).slice(2);
      var rand = Date.now() + "-" + Math.random().toString(36).slice(2, 18);
      var url = "https://" + rand + ".dns-detect.alicdn.com/api/detect/DescribeDNSLookup?cb=" + cb;
      var timer = setTimeout(done, 5000);
      function finish(data) {
        if (data && data.content && data.content.localIp) {
          resolve({ ip: data.content.localIp, cc: data.content.ipCountry ? data.content.ipCountry.toLowerCase() : null });
        } else reject(new Error("无IP数据"));
      }
      function done() {
        clearTimeout(timer);
        delete window[cb];
        var el = document.getElementById("np-ali-script");
        if (el) el.remove();
      }
      window[cb] = function (data) { done(); finish(data); };
      var s = document.createElement("script");
      s.id = "np-ali-script";
      s.src = url;
      s.async = true;
      s.onerror = function () { done(); reject(new Error("加载失败")); };
      document.body.appendChild(s);
    });
  }

  async function detectNetease() {
    const resp = await NP.fetchT(
      "https://necaptcha.nosdn.127.net/ab7f4275c1744aa28e0a8f3a1c58c532.png",
      { method: "HEAD" }, 5000
    );
    const ip = resp.headers.get("cdn-user-ip");
    if (ip) return { ip: ip };
    throw new Error("未获取到 IP");
  }

  async function detectBytedance(url) {
    const resp = await NP.fetchT(url, { method: "HEAD" }, 5000);
    const ip = resp.headers.get("x-request-ip") || resp.headers.get("x-response-cinfo");
    if (ip) return { ip: ip };
    throw new Error("未获取到 IP");
  }

  async function runTest(i) {
    var t = tests[i];
    state[i].status = "loading";
    renderRow(i);
    try {
      var ip = null, cc = null, geo = null;
      if (t.method === "cftrace") {
        var r;
        try { r = await detectCfTrace(t.cfhost || t.domain); }
        catch (e) {
          if (t.domain !== (t.cfhost || t.domain)) r = await detectCfTrace(t.domain);
          else throw e;
        }
        ip = r.ip; cc = r.loc;
      } else if (t.method === "netease") {
        var rn = await detectNetease(); ip = rn.ip;
      } else if (t.method === "bytedance") {
        var rb = await detectBytedance(t.url); ip = rb.ip;
      } else if (t.method === "alibaba") {
        var ra = await detectAlibaba(); ip = ra.ip; cc = ra.cc;
      }

      state[i].ip = ip;
      state[i].cc = cc;
      state[i].status = ip ? "done" : "error";
      state[i].error = ip ? null : "未获取到 IP";
      if (ip) {
        renderRow(i);
        var g = await GEO.lookup(ip).catch(function () { return null; });
        if (g) {
          if (!state[i].geo) state[i].geo = g.geoString;
          if (!state[i].cc) state[i].cc = g.countryCode;
        }
      }
      renderRow(i);
    } catch (e) {
      state[i].status = "error";
      state[i].error = (e && e.message) || "获取失败";
      renderRow(i);
    }
  }

  async function runAll() {
    await NP.withLimit(tests, 12, function (_t, i) { return runTest(i); });
    for (var attempt = 1; attempt <= 2; attempt++) {
      var failed = [];
      state.forEach(function (s, i) { if (s.status === "error") failed.push(i); });
      if (!failed.length) break;
      await new Promise(function (r) { setTimeout(r, 1800 * attempt); });
      await NP.withLimit(failed, 12, function (_t, idx) { return runTest(failed[idx]); });
    }
  }

  /* ---------------- 隐藏IP 开关 ---------------- */
  window.__maskOn = false;
  function applyMasks() {
    document.querySelectorAll(".ip-text").forEach(function (el) {
      if (!el.dataset.real) el.dataset.real = el.textContent.trim();
      var want = window.__maskOn ? NP.maskIp(el.dataset.real) : el.dataset.real;
      if (el.textContent !== want) el.textContent = want;
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var tg = document.getElementById("ipMaskToggle");
    tg.addEventListener("change", function (e) {
      window.__maskOn = e.target.checked;
      document.querySelectorAll(".ip-text").forEach(function (el) {
        if (!el.dataset.real) el.dataset.real = el.textContent.trim();
      });
      applyMasks();
    });
    applyMasks();
  });

  /* ---------------- 全站查询统计条 ---------------- */
  (async function () {
    var strip = document.getElementById("statsStrip");
    if (!strip) return;
    try {
      var r = await fetch("/api/stats", { cache: "no-store", signal: AbortSignal.timeout(6000) });
      var d = await r.json();
      if (!d || typeof d.total !== "number") return;
      document.getElementById("stToday").textContent = (d.today || 0).toLocaleString();
      document.getElementById("stTotal").textContent = (d.total || 0).toLocaleString();
      strip.style.display = "";
    } catch (e) {}
  })();

  /* ---------------- 启动 ---------------- */
  renderPingGrid();
  runIpQuery();
  runPings();
  renderTable();
  runAll();
})();
