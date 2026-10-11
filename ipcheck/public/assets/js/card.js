/* ============================================================
   NetProbe — IP 信息卡片生成器（原创实现）
   数据源：/api/card.svg 动态 SVG（服务端按访客 IP 实时渲染）
   交互：风格/贴纸/宽度选择 + 嵌入代码复制 + 风格预览墙
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;

  var STYLES = [
    ["random", "🎲 随机"], ["midnight", "暗夜"], ["minimal", "极简"], ["sunset", "落日"],
    ["ocean", "海岸"], ["aurora", "极光"], ["neon", "霓虹"], ["terminal", "终端"],
    ["coffee", "咖啡"], ["sakura", "樱粉"], ["starry", "星夜"], ["forest", "翡翠"], ["ink", "水墨"],
  ];
  var STYLE_NAME = { midnight: "暗夜", minimal: "极简", sunset: "落日", ocean: "海岸", aurora: "极光", neon: "霓虹", terminal: "终端", coffee: "咖啡", sakura: "樱粉", starry: "星夜", forest: "翡翠", ink: "水墨" };
  var STICKERS = [
    ["none", "无"], ["random", "🎲 随机"],
    ["rainbow", "🌈"], ["rocket", "🚀"], ["fire", "🔥"], ["bolt", "⚡"], ["star", "⭐"], ["moon", "🌙"],
    ["cherry", "🌸"], ["cat", "🐱"], ["dog", "🐶"], ["pizza", "🍕"], ["coffee", "☕"], ["game", "🎮"],
    ["skull", "💀"], ["crown", "👑"], ["gem", "💎"], ["clover", "🍀"], ["robot", "🤖"], ["ghost", "👻"],
    ["vip", "VIP"], ["linux", "LINUX"], ["dev", "DEV"], ["passed", "PASSED"], ["pro", "PRO"], ["n666", "666"],
  ];
  var STICKER_NAME = { rainbow: "🌈", rocket: "🚀", fire: "🔥", bolt: "⚡", star: "⭐", moon: "🌙", cherry: "🌸", cat: "🐱", dog: "🐶", pizza: "🍕", coffee: "☕", game: "🎮", skull: "💀", crown: "👑", gem: "💎", clover: "🍀", robot: "🤖", ghost: "👻", vip: "VIP", linux: "LINUX", dev: "DEV", passed: "PASSED", pro: "PRO", n666: "666" };
  var WIDTHS = [[240, "240"], [360, "360"], [480, "480（建议尺寸）"], [560, "560"], [720, "原图"]];

  var state = { style: "midnight", sticker: "none", w: 480, myIp: "" };

  function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
  function resolvedStyle() { return state.style === "random" ? pick(Object.keys(STYLE_NAME)) : state.style; }
  function resolvedSticker() {
    if (state.sticker !== "random") return state.sticker;
    var pool = STICKERS.filter(function (s) { return s[0] !== "none" && s[0] !== "random"; }).map(function (s) { return s[0]; });
    return pick(pool);
  }

  function cardUrl(styleKey, stickerKey, w, bust) {
    var p = new URLSearchParams({ style: styleKey, sticker: stickerKey, w: String(w) });
    if (bust) p.set("t", String(Date.now()));
    return "/api/card.svg?" + p.toString();
  }

  function renderChips() {
    document.getElementById("styleChips").innerHTML = STYLES.map(function (s) {
      return "<button class='chip" + (state.style === s[0] ? " active" : "") + "' data-style='" + s[0] + "'>" + esc(s[1]) + "</button>";
    }).join("");
    document.getElementById("stickerChips").innerHTML = STICKERS.map(function (s) {
      return "<button class='chip" + (state.sticker === s[0] ? " active" : "") + "' data-sticker='" + s[0] + "'>" + esc(s[1]) + "</button>";
    }).join("");
    document.getElementById("widthChips").innerHTML = WIDTHS.map(function (w) {
      return "<button class='chip" + (state.w === w[0] ? " active" : "") + "' data-w='" + w[0] + "'>" + esc(w[1]) + "</button>";
    }).join("");
  }

  function renderPreview() {
    var sk = resolvedStyle(), tk = resolvedSticker();
    var img = document.getElementById("cardImg");
    img.src = cardUrl(sk, tk, 480, true);
    img.style.maxWidth = "480px";
    var styleLabel = state.style === "random" ? "随机（本次：" + (STYLE_NAME[sk] || sk) + "）" : STYLE_NAME[state.style];
    var stLabel = state.sticker === "random" ? "随机（本次：" + (STICKER_NAME[tk] || tk) + "）" : (STICKER_NAME[state.sticker] || "无");
    document.getElementById("curLabel").textContent = "当前：" + styleLabel + " · 贴纸 " + stLabel;
    document.getElementById("cardMeta").textContent =
      "这张图由 " + cardUrl(sk, tk, 480) + " 实时渲染，刷新页面即可看到重新识别的出口 IP。";

    var base = cardUrl(sk, tk, state.w);
    var md = "[![IP 信息卡片](" + location.origin + base + ")](" + location.origin + "/ip/ \"查看 IP\")";
    document.getElementById("fmtMd").textContent = md;
    document.getElementById("fmtMd2").textContent = md;
    document.getElementById("fmtHtml").textContent =
      "<a href=\"" + location.origin + "/ip/\"><img src=\"" + location.origin + base + "\" alt=\"IP 信息卡片\" title=\"查看 IP\"></a>";
    document.getElementById("fmtBb").textContent =
      "[url=" + location.origin + "/ip/][img]" + location.origin + base + "[/img][/url]";
    document.getElementById("shareUrl").textContent = location.origin + "/card/?style=" + state.style + "&sticker=" + state.sticker;
  }

  function renderWall() {
    document.getElementById("styleWall").innerHTML = Object.keys(STYLE_NAME).map(function (k) {
      return "<div class='wall-cell" + (state.style === k ? " wall-active" : "") + "' data-wall='" + k + "'>" +
        "<img loading='lazy' src='/api/card.svg?ip=1.2.3.4&style=" + k + "&sticker=none&w=240' alt='" + esc(STYLE_NAME[k]) + " 风格预览'>" +
        "<span class='wall-name'>" + esc(STYLE_NAME[k]) + "</span></div>";
    }).join("");
  }

  function randomAll() {
    state.style = "random";
    state.sticker = "random";
    renderChips(); renderWall(); renderPreview();
  }

  document.getElementById("styleChips").addEventListener("click", function (e) {
    var b = e.target.closest("[data-style]");
    if (!b) return;
    state.style = b.dataset.style;
    renderChips(); renderWall(); renderPreview();
  });
  document.getElementById("stickerChips").addEventListener("click", function (e) {
    var b = e.target.closest("[data-sticker]");
    if (!b) return;
    state.sticker = b.dataset.sticker;
    renderChips(); renderPreview();
  });
  document.getElementById("widthChips").addEventListener("click", function (e) {
    var b = e.target.closest("[data-w]");
    if (!b) return;
    state.w = parseInt(b.dataset.w, 10);
    renderChips(); renderPreview();
  });
  document.getElementById("styleWall").addEventListener("click", function (e) {
    var c = e.target.closest("[data-wall]");
    if (!c) return;
    state.style = c.dataset.wall;
    renderChips(); renderWall(); renderPreview();
  });
  document.getElementById("btnRandom").addEventListener("click", randomAll);
  document.getElementById("btnCopyIp").addEventListener("click", function () {
    if (!state.myIp) return;
    navigator.clipboard.writeText(state.myIp).then(function () {
      var b = document.getElementById("btnCopyIp");
      b.textContent = "✓ 已复制";
      setTimeout(function () { b.textContent = "📋 复制当前 IP"; }, 1500);
    });
  });
  document.getElementById("btnRefresh").addEventListener("click", function () {
    renderPreview();
    loadIp();
  });
  document.getElementById("btnMoreFmt").addEventListener("click", function () {
    var m = document.getElementById("moreFmt");
    m.style.display = m.style.display === "none" ? "" : "none";
  });
  document.querySelectorAll(".code-box").forEach(function (pre) {
    pre.addEventListener("click", function () {
      navigator.clipboard.writeText(pre.textContent).then(function () {
        pre.classList.add("copied");
        setTimeout(function () { pre.classList.remove("copied"); }, 800);
      });
    });
  });

  async function loadIp() {
    try {
      const r = await NP.fetchT("/api/session", null, 8000);
      const d = await r.json();
      state.myIp = d.ip || "";
    } catch (e) { state.myIp = ""; }
  }

  // 入口参数预选
  var qs = new URLSearchParams(location.search);
  if (qs.get("style") && (qs.get("style") === "random" || STYLE_NAME[qs.get("style")])) state.style = qs.get("style");
  if (qs.get("sticker") && STICKERS.some(function (s) { return s[0] === qs.get("sticker"); })) state.sticker = qs.get("sticker");

  renderChips();
  renderWall();
  renderPreview();
  loadIp();
})();
