/* ============================================================
   NetProbe — AI 资讯（原创实现）
   数据源：Hacker News Algolia 公开检索 API（开放 CORS、无需密钥），
   按关键词限定标题检索、按时间倒序；「全部」= 多关键词并行合并去重。
   页面结构：标签筛选 → 动态卡片流 → 分页；下方保留站内指南合集。
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;

  var PAGE_SIZE = 15;        // 每页展示条数（合并后）
  var PER_FETCH = PAGE_SIZE; // 每个关键词每次取回条数（保证单标签页也能取满一页）
  var CACHE_TTL = 5 * 60 * 1000;

  var TAGS = [
    { key: "all",       label: "全部",     kws: ["openai", "anthropic", "claude", "chatgpt", "gemini", "codex", "llm"] },
    { key: "openai",    label: "OpenAI",   kws: ["openai"] },
    { key: "chatgpt",   label: "ChatGPT",  kws: ["chatgpt"] },
    { key: "claude",    label: "Claude",   kws: ["claude"] },
    { key: "anthropic", label: "Anthropic",kws: ["anthropic"] },
    { key: "gemini",    label: "Gemini",   kws: ["gemini"] },
    { key: "codex",     label: "Codex",    kws: ["codex"] },
    { key: "mcp",       label: "MCP",      kws: ["mcp"] },
    { key: "llm",       label: "LLM",      kws: ["llm"] },
  ];

  var curTag = "all", curPage = 1;

  function tagByKey(k) {
    for (var i = 0; i < TAGS.length; i++) if (TAGS[i].key === k) return TAGS[i];
    return TAGS[0];
  }

  function apiUrl(kw, page) {
    return "https://hn.algolia.com/api/v1/search_by_date?query=" + encodeURIComponent(kw) +
      "&tags=story&hitsPerPage=" + PER_FETCH + "&page=" + (page - 1) +
      "&restrictSearchableAttributes=title&typoTolerance=false";
  }

  function cacheKey(tag, page) { return "np_news_" + tag + "_" + page; }

  async function fetchFeed(tag, page) {
    var ck = cacheKey(tag, page);
    try {
      var raw = sessionStorage.getItem(ck);
      if (raw) {
        var c = JSON.parse(raw);
        if (Date.now() - c.t < CACHE_TTL) return c.d;
      }
    } catch (e) {}

    var t = tagByKey(tag);
    var rs = await Promise.allSettled(t.kws.map(function (kw) {
      return fetch(apiUrl(kw, page), { signal: AbortSignal.timeout(8000) }).then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      });
    }));
    var merged = {}, maxPages = 0, okCount = 0;
    rs.forEach(function (res) {
      if (res.status !== "fulfilled" || !res.value) return;
      okCount++;
      var d = res.value;
      if (d.nbPages > maxPages) maxPages = d.nbPages;
      (d.hits || []).forEach(function (h) {
        if (h && h.objectID && h.title && !merged[h.objectID]) merged[h.objectID] = h;
      });
    });
    if (!okCount) throw new Error("资讯源暂时不可达");
    var hits = Object.keys(merged).map(function (k) { return merged[k]; })
      .sort(function (a, b) { return (b.created_at_i || 0) - (a.created_at_i || 0); })
      .slice(0, PAGE_SIZE);
    var out = { hits: hits, pages: Math.min(maxPages || 1, 50) };
    try { sessionStorage.setItem(ck, JSON.stringify({ t: Date.now(), d: out })); } catch (e) {}
    return out;
  }

  function timeAgo(iso) {
    var ts = new Date(iso).getTime();
    if (!ts) return "";
    var s = Math.max(1, Math.floor((Date.now() - ts) / 1000));
    if (s < 60) return "刚刚";
    if (s < 3600) return Math.floor(s / 60) + " 分钟前";
    if (s < 86400) return Math.floor(s / 3600) + " 小时前";
    if (s < 86400 * 30) return Math.floor(s / 86400) + " 天前";
    return new Date(ts).toLocaleDateString("zh-CN");
  }

  function renderList(tag, page, data) {
    var area = document.getElementById("newsList");
    if (!data.hits.length) {
      area.innerHTML = "<div class='card'><div class='muted'>该标签下暂时没有新动态，稍后再来看看。</div></div>";
      return;
    }
    var t = tagByKey(tag);
    area.innerHTML = data.hits.map(function (h) {
      var link = h.url || ("https://news.ycombinator.com/item?id=" + h.objectID);
      var site = "";
      try { if (h.url) site = " · " + new URL(h.url).hostname.replace(/^www\./, ""); } catch (e) {}
      return "<div class='card news-item'><div class='news-title'>" +
        "<a href='" + esc(link) + "' target='_blank' rel='noopener'>" + esc(h.title) + "</a>" +
        (site ? "<span class='muted small'> " + esc(site) + "</span>" : "") +
        "</div><div class='news-meta muted small'>" +
        "<span class='chip chip-flat'>" + esc(t.label) + "</span>" +
        "<span>⬆ " + (h.points || 0) + "</span>" +
        "<span>💬 " + (h.num_comments || 0) + "</span>" +
        "<span>" + esc(timeAgo(h.created_at)) + "</span>" +
        "<span>" + esc(h.author || "") + "</span>" +
        "<a href='https://news.ycombinator.com/item?id=" + esc(h.objectID) + "' target='_blank' rel='noopener'>HN 讨论</a>" +
        "</div></div>";
    }).join("");
  }

  function renderPager(tag, page, pages) {
    var box = document.getElementById("newsPager");
    if (pages <= 1) { box.style.display = "none"; return; }
    box.style.display = "";
    var start = Math.max(1, Math.min(page - 4, pages - 8));
    var end = Math.min(pages, start + 8);
    var html = "";
    html += "<button class='chip" + (page <= 1 ? " disabled" : "") + "' data-p='" + (page - 1) + "'" + (page <= 1 ? " disabled" : "") + ">← 上一页</button>";
    for (var i = start; i <= end; i++) {
      html += "<button class='chip" + (i === page ? " active" : "") + "' data-p='" + i + "'>" + i + "</button>";
    }
    html += "<button class='chip" + (page >= pages ? " disabled" : "") + "' data-p='" + (page + 1) + "'" + (page >= pages ? " disabled" : "") + ">下一页 →</button>";
    html += "<span class='muted small'>第 " + page + " / " + pages + " 页</span>";
    box.innerHTML = html;
    box.querySelectorAll("button[data-p]").forEach(function (b) {
      b.addEventListener("click", function () {
        var p = parseInt(b.dataset.p, 10);
        if (p >= 1 && p <= pages && p !== page) {
          location.hash = "#" + tag + "/" + p;
        }
      });
    });
  }

  function renderChips() {
    document.getElementById("newsChips").innerHTML = TAGS.map(function (t) {
      return "<button class='chip" + (t.key === curTag ? " active" : "") + "' data-tag='" + t.key + "'>" + esc(t.label) + "</button>";
    }).join("");
    document.querySelectorAll("#newsChips .chip").forEach(function (b) {
      b.addEventListener("click", function () { location.hash = "#" + b.dataset.tag + "/1"; });
    });
  }

  var loadSeq = 0;
  async function load() {
    var seq = ++loadSeq;
    var area = document.getElementById("newsList");
    area.innerHTML = "<div class='card'><div class='v'><span class='spin'></span> 加载 AI 动态中…</div></div>";
    document.getElementById("newsPager").style.display = "none";
    try {
      var d = await fetchFeed(curTag, curPage);
      if (seq !== loadSeq) return;
      renderList(curTag, curPage, d);
      renderPager(curTag, curPage, d.pages);
    } catch (e) {
      if (seq !== loadSeq) return;
      area.innerHTML = "<div class='card'><div class='verdict verdict-bad'>资讯加载失败：" + esc(e.message || "网络异常") +
        " <button class='chip' id='newsRetry' style='margin-left:8px'>重试</button></div></div>";
      var btn = document.getElementById("newsRetry");
      if (btn) btn.addEventListener("click", function () { try { sessionStorage.removeItem(cacheKey(curTag, curPage)); } catch (x) {} load(); });
    }
  }

  function applyHash() {
    var m = location.hash.match(/^#([a-z]+)(?:\/(\d+))?$/);
    if (m && tagByKey(m[1]).key === m[1]) {
      curTag = m[1];
      curPage = Math.max(1, parseInt(m[2] || "1", 10) || 1);
    } else {
      curTag = "all"; curPage = 1;
    }
    renderChips();
    load();
  }

  window.addEventListener("hashchange", applyHash);
  applyHash();
})();
