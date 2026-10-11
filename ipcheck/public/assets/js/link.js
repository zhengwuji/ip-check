/* ============================================================
   NetProbe — 网络连通性测试（原创实现）
   按国家/地区分组，每组 4 列目标卡片（icon + 名字 + 延迟 + 点阵），
   组标题带可达统计与刷新按钮，页面顶部有延迟图例。
   探测方式：no-cors fetch（小图标或 generate_204），超时 4s。
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;

  var GROUPS = [
    {
      name: "中国", cc: "cn",
      targets: [
        { name: "DeepSeek", domain: "deepseek.com", url: "https://www.deepseek.com/favicon.ico" },
        { name: "抖音", domain: "douyin.com", url: "https://www.douyin.com/favicon.ico" },
        { name: "哔哩哔哩", domain: "bilibili.com", url: "https://www.bilibili.com/favicon.ico" },
        { name: "京东", domain: "jd.com", url: "https://www.jd.com/favicon.ico" },
        { name: "腾讯 QQ", domain: "qq.com", url: "https://www.qq.com/favicon.ico" },
        { name: "微信", domain: "qq.com", url: "https://res.wx.qq.com/a/wx_fed/assets/res/NTI4MWU5.ico" },
        { name: "小红书", domain: "xhscdn.com", url: "https://fe-static.xhscdn.com/favicon.ico" },
        { name: "新浪微博", domain: "weibo.com", url: "https://weibo.com/favicon.ico" },
        { name: "百度", domain: "baidu.com", url: "https://www.baidu.com/favicon.ico" },
        { name: "网易", domain: "163.com", url: "https://www.163.com/favicon.ico" },
        { name: "淘宝", domain: "taobao.com", url: "https://www.taobao.com/favicon.ico" },
        { name: "小米", domain: "mi.com", url: "https://www.mi.com/favicon.ico" },
      ],
    },
    {
      name: "日本", cc: "jp",
      targets: [
        { name: "Sony", domain: "sony.com", url: "https://www.sony.com/favicon.ico" },
        { name: "任天堂", domain: "nintendo.com", url: "https://www.nintendo.com/favicon.ico" },
        { name: "Yahoo! JP", domain: "yahoo.co.jp", url: "https://www.yahoo.co.jp/favicon.ico" },
        { name: "LINE", domain: "line.me", url: "https://line.me/favicon.ico" },
      ],
    },
    {
      name: "美国", cc: "us",
      targets: [
        { name: "Apple", domain: "apple.com", url: "https://www.apple.com/favicon.ico" },
        { name: "Google", domain: "google.com", url: "https://www.google.com/generate_204" },
        { name: "YouTube", domain: "youtube.com", url: "https://www.youtube.com/generate_204" },
        { name: "GitHub", domain: "github.com", url: "https://github.com/generate_204" },
        { name: "Netflix", domain: "netflix.com", url: "https://assets.nflxext.com/us/ffe/siteui/common/icons/nficon2016.ico" },
        { name: "Spotify", domain: "spotify.com", url: "https://open.spotify.com/favicon.ico" },
        { name: "X (Twitter)", domain: "x.com", url: "https://abs.twimg.com/favicons/twitter.3.ico" },
        { name: "Facebook", domain: "facebook.com", url: "https://static.xx.fbcdn.net/rsrc.php/yb/r/hLRJ1GG_y0J.ico" },
        { name: "Instagram", domain: "instagram.com", url: "https://static.cdninstagram.com/rsrc.php/yb/r/hLRJ1GG_y0J.ico" },
        { name: "LinkedIn", domain: "linkedin.com", url: "https://static.licdn.com/favicon.ico" },
        { name: "Twitch", domain: "twitch.tv", url: "https://static.twitchcdn.net/assets/favicon-32-e29e246c157142c94346.png" },
        { name: "Zoom", domain: "zoom.us", url: "https://st1.zoom.us/favicon.ico" },
        { name: "ChatGPT", domain: "chatgpt.com", url: "https://chatgpt.com/favicon.ico" },
        { name: "Claude", domain: "anthropic.com", url: "https://api.anthropic.com/favicon.ico" },
        { name: "Gemini", domain: "google.com", url: "https://generativelanguage.googleapis.com/favicon.ico" },
        { name: "Amazon", domain: "amazon.com", url: "https://www.amazon.com/favicon.ico" },
        { name: "Steam", domain: "steampowered.com", url: "https://store.steampowered.com/favicon.ico" },
        { name: "Reddit", domain: "reddit.com", url: "https://www.reddit.com/favicon.ico" },
        { name: "Wikipedia", domain: "wikipedia.org", url: "https://www.wikipedia.org/static/favicon/wikipedia.ico" },
        { name: "Bing", domain: "bing.com", url: "https://www.bing.com/favicon.ico" },
      ],
    },
    {
      name: "欧洲", cc: "eu",
      targets: [
        { name: "BBC", domain: "bbc.com", url: "https://www.bbc.com/favicon.ico" },
        { name: "Yandex", domain: "yandex.com", url: "https://yastatic.net/favicon.ico" },
        { name: "npm", domain: "npmjs.com", url: "https://registry.npmjs.org/" },
      ],
    },
    {
      name: "其他地区", cc: "",
      targets: [
        { name: "Naver", domain: "naver.com", url: "https://www.naver.com/favicon.ico" },
        { name: "TikTok", domain: "tiktok.com", url: "https://www.tiktok.com/favicon.ico" },
        { name: "Noon (中东)", domain: "noon.com", url: "https://www.noon.com/favicon.ico" },
        { name: "MercadoLibre (拉美)", domain: "mercadolibre.com", url: "https://http2.mlstatic.com/favicon.ico" },
        { name: "Takealot (非洲)", domain: "takealot.com", url: "https://static.takealot.com/favicon.ico" },
      ],
    },
  ];

  function msColor(ms) {
    if (ms < 0) return "dot-fail";
    if (ms < 150) return "dot-good";
    if (ms < 400) return "dot-good";
    if (ms < 1500) return "dot-bad";
    return "dot-fail";
  }

  /* ---------- 自定义目标（仅存本机） ---------- */
  var CUSTOM_KEY = "np_link_custom_v1";
  var CUSTOM = [];
  try {
    var savedCustom = JSON.parse(localStorage.getItem(CUSTOM_KEY) || "[]");
    if (Array.isArray(savedCustom)) {
      CUSTOM = savedCustom.filter(function (x) { return x && x.url && x.domain; });
    }
  } catch (e) {}
  function persistCustom() {
    try { localStorage.setItem(CUSTOM_KEY, JSON.stringify(CUSTOM)); } catch (e) {}
  }
  function allGroups() {
    var gs = GROUPS.slice();
    if (CUSTOM.length) gs.push({ name: "自定义目标", cc: "", custom: true, targets: CUSTOM });
    return gs;
  }
  function msTextColor(ms) {
    if (ms < 0) return "var(--text-muted)";
    if (ms < 400) return "var(--good)";
    if (ms < 1500) return "#e0b341";
    return "var(--warn)";
  }

  async function probe(url, timeout) {
    var t0 = performance.now();
    try {
      await fetch(url, { mode: "no-cors", cache: "no-store", signal: AbortSignal.timeout(timeout || 4000) });
      return Math.round(performance.now() - t0);
    } catch (e) {
      return -1;
    }
  }

  function renderGroups() {
    var gs = allGroups();
    var html = "";
    gs.forEach(function (g, gi) {
      html += "<div class='group-title' style='justify-content:space-between'>" +
        "<span>" + (g.cc ? NP.flag(g.cc, "split-flag") : "🌍") + " <span style='font-size:1.05em'>" + esc(g.name) +
        "</span> <span class='muted small' id='gs-" + gi + "'>—</span></span>" +
        "<button class='btn btn-ghost small' data-refresh='" + gi + "'>↻ 刷新</button></div>";
      html += "<div class='link-grid' id='grid-" + gi + "'>";
      g.targets.forEach(function (t, ti) {
        html += "<div class='link-card' id='lc-" + gi + "-" + ti + "'>" +
          "<div class='link-card-top'>" + NP.favicon(t.domain, t.name) +
          "<span class='site-name' style='flex:1;font-size:0.86em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>" + esc(t.name) + "</span>" +
          (g.custom ? "<button class='btn btn-ghost small' data-del='" + ti + "' title='移除该目标' style='padding:0 7px'>✕</button>" : "") +
          "<span class='link-ms' style='color:var(--text-muted)'>--</span></div>" +
          "<div class='ping-dots'>" + "<div class='ping-dot dot-pending'></div>".repeat(10) + "</div>" +
          "</div>";
      });
      html += "</div>";
    });
    document.getElementById("groups").innerHTML = html;
    document.querySelectorAll("[data-refresh]").forEach(function (btn) {
      btn.addEventListener("click", function () { runGroup(parseInt(btn.dataset.refresh, 10)); });
    });
    document.querySelectorAll("[data-del]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var ti = parseInt(btn.dataset.del, 10);
        CUSTOM.splice(ti, 1);
        persistCustom();
        renderGroups();
        var gs2 = allGroups();
        if (gs2[gs2.length - 1].custom) runGroup(gs2.length - 1);
      });
    });
  }

  function updateCard(gi, ti, ms) {
    var card = document.getElementById("lc-" + gi + "-" + ti);
    if (!card) return;
    var dots = card.querySelectorAll(".ping-dot");
    var fills = Math.max(0, Math.min(10, ms < 0 ? 10 : Math.round(Math.min(ms, 2000) / 200)));
    dots.forEach(function (d, i) {
      d.className = "ping-dot " + (i < fills ? msColor(ms) : "dot-pending");
    });
    var msEl = card.querySelector(".link-ms");
    if (ms < 0) {
      msEl.textContent = "超时";
      msEl.style.color = "var(--bad)";
    } else {
      msEl.textContent = ms + "ms";
      msEl.style.color = msTextColor(ms);
    }
  }

  function updateGroupStat(gi) {
    var g = allGroups()[gi];
    var ok = 0, total = 0, sum = 0;
    g.targets.forEach(function (_, ti) {
      var card = document.getElementById("lc-" + gi + "-" + ti);
      if (!card) return;
      var txt = card.querySelector(".link-ms").textContent;
      total++;
      if (txt.indexOf("ms") !== -1) { ok++; sum += parseInt(txt, 10); }
    });
    var el = document.getElementById("gs-" + gi);
    if (ok > 0) el.textContent = "可达 " + ok + "/" + total + " · 平均 " + Math.round(sum / ok) + "ms";
    else el.textContent = "检测中…";
  }

  async function runGroup(gi) {
    var g = allGroups()[gi];
    await Promise.allSettled(g.targets.map(async function (t, ti) {
      var ms = await probe(t.url);
      updateCard(gi, ti, ms);
      updateGroupStat(gi);
    }));
  }

  async function runAll() {
    var btn = document.getElementById("startBtn");
    btn.disabled = true;
    document.getElementById("startLabel").textContent = "测试中…";
    var gs = allGroups();
    var jobs = [];
    gs.forEach(function (_, gi) { jobs.push(function () { return runGroup(gi); }); });
    await NP.withLimit(jobs, 2, function (fn) { return fn(); });
    document.getElementById("startLabel").textContent = "重新测试";
    btn.disabled = false;
  }

  document.getElementById("startBtn").addEventListener("click", runAll);

  /* ---------- 添加自定义目标 ---------- */
  document.getElementById("cAdd").addEventListener("click", function () {
    var name = document.getElementById("cName").value.trim();
    var raw = document.getElementById("cUrl").value.trim();
    var url, domain;
    if (/^https?:\/\//i.test(raw)) {
      try {
        var u = new URL(raw);
        domain = u.hostname;
        url = u.origin + "/favicon.ico";
      } catch (e) { return; }
    } else {
      domain = raw.replace(/\/.*$/, "").replace(/:\d+$/, "");
      url = "https://" + domain + "/favicon.ico";
    }
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(domain)) return;
    if (CUSTOM.some(function (x) { return x.domain === domain; })) return;
    CUSTOM.push({ name: name || domain, url: url, domain: domain });
    persistCustom();
    document.getElementById("cName").value = "";
    document.getElementById("cUrl").value = "";
    renderGroups();
    runGroup(allGroups().length - 1);
  });

  renderGroups();
  runAll();
})();
