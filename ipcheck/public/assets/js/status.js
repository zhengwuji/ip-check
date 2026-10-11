/* ============================================================
   NetProbe — 服务状态监控（原创实现）
   数据源：各服务官方 Statuspage 实例的 summary.json 接口。
   布局：汇总横幅 → 当前故障卡片网格 → 运行中卡片网格。
   指示灯：none=operating / minor=major / major=重大 / maintenance=维护
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;

  var SERVICES = [
    {
      group: "AI 服务", short: "AI", badge: "badge-ai",
      items: [
        { name: "OpenAI / ChatGPT", url: "https://status.openai.com/api/v2/summary.json" },
        { name: "Claude (Anthropic)", url: "https://status.anthropic.com/api/v2/summary.json" },
        { name: "Perplexity", url: "https://status.perplexity.com/api/v2/summary.json" },
        { name: "Cursor", url: "https://status.cursor.com/api/v2/summary.json" },
        { name: "Groq", url: "https://groqstatus.com/api/v2/summary.json" },
        { name: "ElevenLabs", url: "https://status.elevenlabs.io/api/v2/summary.json" },
        { name: "Replicate", url: "https://status.replicate.com/api/v2/summary.json" },
        { name: "Hugging Face", url: "https://status.huggingface.co/api/v2/summary.json" },
      ],
    },
    {
      group: "云服务", short: "云服务", badge: "badge-speed",
      items: [
        { name: "Cloudflare", url: "https://www.cloudflarestatus.com/api/v2/summary.json" },
        { name: "Vercel", url: "https://www.vercel-status.com/api/v2/summary.json" },
        { name: "Supabase", url: "https://status.supabase.com/api/v2/summary.json" },
        { name: "Fly.io", url: "https://status.flyio.net/api/v2/summary.json" },
        { name: "DigitalOcean", url: "https://status.digitalocean.com/api/v2/summary.json" },
        { name: "Figma", url: "https://status.figma.com/api/v2/summary.json" },
        { name: "Python.org", url: "https://status.python.org/api/v2/summary.json" },
      ],
    },
    {
      group: "开发", short: "开发", badge: "badge-dev",
      items: [
        { name: "GitHub", url: "https://www.githubstatus.com/api/v2/summary.json" },
        { name: "npm", url: "https://status.npmjs.org/api/v2/summary.json" },
        { name: "Atlassian", url: "https://status.atlassian.com/api/v2/summary.json" },
        { name: "Postman", url: "https://status.postman.com/api/v2/summary.json" },
        { name: "Sentry", url: "https://status.sentry.io/api/v2/summary.json" },
        { name: "Clerk", url: "https://status.clerk.com/api/v2/summary.json" },
        { name: "Twilio", url: "https://status.twilio.com/api/v2/summary.json" },
        { name: "SendGrid", url: "https://status.sendgrid.com/api/v2/summary.json" },
        { name: "Discord", url: "https://discordstatus.com/api/v2/summary.json" },
        { name: "Twitch", url: "https://status.twitch.tv/api/v2/summary.json" },
        { name: "Zoom", url: "https://status.zoom.us/api/v2/summary.json" },
      ],
    },
  ];

  var STATE = {
    none: { level: "ok", text: "运行正常", sub: "" },
    minor: { level: "warn", text: "轻微故障", sub: "" },
    major: { level: "bad", text: "重大故障", sub: "" },
    critical: { level: "bad", text: "严重故障", sub: "" },
    maintenance: { level: "info", text: "维护中", sub: "" },
  };

  var results = []; // {name, groupShort, badge, state, desc, link, fetched}

  /* 故障历史（仅存浏览器本地）：记录每个服务最近一次非正常状态的时间 */
  var HIST_KEY = "np_status_hist";
  function histLoad() {
    try { return JSON.parse(localStorage.getItem(HIST_KEY) || "{}"); } catch (e) { return {}; }
  }
  function ago(ts) {
    var s = Math.max(1, Math.round((Date.now() - ts) / 1000));
    if (s < 3600) return Math.round(s / 60) + " 分钟前";
    if (s < 86400) return Math.round(s / 3600) + " 小时前";
    return Math.round(s / 86400) + " 天前";
  }

  function renderAll() {
    var bad = results.filter(function (r) { return r.state && r.state.level !== "ok"; });
    var ok = results.filter(function (r) { return r.state && r.state.level === "ok"; });
    var pending = results.filter(function (r) { return !r.state; });

    // 汇总横幅
    var banner = document.getElementById("summaryBanner");
    if (pending.length === results.length) {
      banner.className = "summary-banner";
      banner.innerHTML = "<div class='big'><span class='spin'></span> 正在获取各官方状态页…</div>";
    } else if (bad.length === 0) {
      banner.className = "summary-banner ok";
      banner.innerHTML = "<div class='big'>✓ 全部 " + ok.length + " 个服务运行正常</div>" +
        "<div class='meta'>数据更新于 " + new Date().toLocaleTimeString("zh-CN", { hour12: false }) + " · 自动检测中</div>";
    } else {
      var byGroup = {};
      bad.forEach(function (r) { byGroup[r.groupShort] = (byGroup[r.groupShort] || 0) + 1; });
      var catHtml = results.reduce(function (acc, r) {
        var key = r.groupShort;
        if (!acc.seen[key]) { acc.seen[key] = true; acc.list.push(key); }
        return acc;
      }, { seen: {}, list: [] }).list.map(function (g) {
        var total = results.filter(function (r) { return r.groupShort === g; }).length;
        var badN = bad.filter(function (r) { return r.groupShort === g; }).length;
        return "<span>" + g + " " + (total - badN) + "/" + total + (badN ? " <span style='color:var(--bad)'>⚠</span>" : "") + "</span>";
      }).join("");
      banner.className = "summary-banner";
      banner.innerHTML = "<div class='big'>" + bad.length + " 个服务出现故障</div>" +
        "<div class='meta'>数据更新于 " + new Date().toLocaleTimeString("zh-CN", { hour12: false }) + " · 自动检测中</div>" +
        "<div class='cats'>" + catHtml + "</div>";
    }

    // 故障区
    var badArea = document.getElementById("badArea");
    var badSec = document.getElementById("badSection");
    if (bad.length) {
      badSec.style.display = "";
      badArea.innerHTML = bad.map(function (r) {
        return "<div class='st-card " + (r.state.level === "bad" ? "st-bad" : "st-warn") + "'>" +
          "<div class='st-top'><span style='color:" + (r.state.level === "bad" ? "var(--bad)" : "#e0b341") + "'>●</span>" +
          "<span class='st-name'>" + NP.favicon(r.host, r.name) + esc(r.name) +
          "<span class='badge " + r.badge + "'>" + esc(r.groupShort) + "</span></span>" +
          "<span style='color:" + (r.state.level === "bad" ? "var(--bad)" : "#e0b341") + ";font-size:0.84em;font-weight:700'>" + esc(r.state.text) + "</span></div>" +
          "<div class='st-sub'>⚠ " + esc(r.desc || r.state.text) + (r.link ? " · <a href='" + esc(r.link) + "' target='_blank' rel='noopener'>详情 ↗</a>" : "") + "</div>" +
          "</div>";
      }).join("");
    } else {
      badSec.style.display = "none";
    }

    // 运行中
    var hist = histLoad();
    var okArea = document.getElementById("okArea");
    okArea.innerHTML = ok.map(function (r) {
      var last = hist[r.name] ? "<div class='st-sub muted small'>上次故障：" + ago(hist[r.name]) + "</div>" : "";
      return "<div class='st-card'>" +
        "<div class='st-top'><span style='color:var(--good)'>●</span>" +
        "<span class='st-name'>" + NP.favicon(r.host, r.name) + esc(r.name) +
        "<span class='badge " + r.badge + "'>" + esc(r.groupShort) + "</span></span>" +
        "<span style='color:var(--good);font-size:0.84em;font-weight:700'>正常</span></div>" + last +
        "</div>";
    }).join("");
    document.getElementById("okCount").textContent = ok.length + " 个服务";
    if (pending.length) {
      okArea.innerHTML += results.filter(function (r) { return !r.state; }).map(function (r) {
        return "<div class='st-card'><div class='st-top'><span class='spin'></span><span class='st-name'>" +
          NP.favicon(r.host, r.name) + esc(r.name) + "<span class='badge " + r.badge + "'>" + esc(r.groupShort) + "</span></span></div></div>";
      }).join("");
    }
  }

  function hostOf(url) {
    return url.replace("/api/v2/summary.json", "").replace("https://", "");
  }

  async function fetchOne(svc, groupShort) {
    var r = { name: svc.name, groupShort: groupShort, badge: "", host: hostOf(svc.url), state: null, desc: "", link: "" };
    results.push(r);
    try {
      const resp = await fetch(svc.url, { cache: "no-store", signal: AbortSignal.timeout(9000) });
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      const d = await resp.json();
      var indicator = (d.status && d.status.indicator) || "none";
      var st = STATE[indicator] || STATE.none;
      var desc = "";
      var incidents = d.incidents || [];
      var maint = d.scheduled_maintenances || [];
      if (incidents.length) {
        desc = incidents.map(function (i) { return i.name; }).join("、");
        if (indicator === "none") st = STATE.minor;
      } else if (maint.length) {
        st = STATE.maintenance;
        desc = maint.map(function (m) { return m.name; }).join("、");
      }
      r.state = st;
      r.desc = desc;
      r.link = (d.page && d.page.url) || svc.url.replace("/api/v2/summary.json", "/");
      r.fetched = Date.now();
      // 非正常状态记入本地故障历史
      if (st.level === "warn" || st.level === "bad") {
        try {
          var h = histLoad();
          h[svc.name] = Date.now();
          localStorage.setItem(HIST_KEY, JSON.stringify(h));
        } catch (e) {}
      }
    } catch (e) {
      r.state = { level: "info", text: "状态页不可达", sub: "" };
      r.desc = "查询失败";
      r.link = svc.url.replace("/api/v2/summary.json", "/");
    }
    renderAll();
  }

  async function refresh() {
    results = [];
    renderAll();
    var jobs = [];
    SERVICES.forEach(function (g) {
      g.items.forEach(function (s) {
        jobs.push(function () { return fetchOne(s, g.short); });
      });
    });
    await NP.withLimit(jobs, 6, function (fn) { return fn(); });
  }

  document.getElementById("refreshBtn").addEventListener("click", refresh);

  /* ---- 服务端巡检历史 ---- */
  var LEVEL_TEXT = { none: "正常", minor: "轻微故障", major: "重大故障", critical: "严重故障", maintenance: "维护中", unknown: "查询失败", init: "首次记录" };
  async function loadPatrol() {
    var el = document.getElementById("patrolHistory");
    if (!el) return;
    try {
      const r = await NP.fetchT("/api/status/history", null, 10000);
      const d = await r.json();
      var changes = d.changes || [];
      if (!changes.length) {
        el.innerHTML = "<div class='muted small'>暂无记录（服务端巡检启动后，状态发生变化时会出现在这里）。</div>";
        return;
      }
      var now = Date.now();
      el.innerHTML = changes.slice(0, 12).map(function (c) {
        var ago = Math.max(1, Math.round((now - new Date(c.t).getTime()) / 60000));
        var agoTxt = ago < 60 ? ago + " 分钟前" : ago < 1440 ? Math.round(ago / 60) + " 小时前" : Math.round(ago / 1440) + " 天前";
        var bad = c.to !== "none";
        return "<div class='nb-row' style='margin-bottom:6px'><div><b>" + NP.esc(c.name) + "</b>" +
          "<span class='muted small'> · " + NP.esc(LEVEL_TEXT[c.from] || c.from) + " → " + NP.esc(LEVEL_TEXT[c.to] || c.to) + "</span></div>" +
          "<span class='pill " + (bad ? "pill-warn" : "pill-good") + "'>" + agoTxt + "</span></div>";
      }).join("");
    } catch (e) {
      el.innerHTML = "<div class='muted small'>巡检历史暂不可用。</div>";
    }
  }
  loadPatrol();
  refresh();
})();
