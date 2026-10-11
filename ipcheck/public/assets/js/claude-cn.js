/* ============================================================
   NetProbe — Claude 中国用户特征加权评分（原创实现，本地计算）
   六项区域指纹加权 0-100：系统时区 30 / 浏览器语言 24 /
   已装中文字体 20 / Intl 区域格式 10 / UTC+8 偏移 8 / Emoji 渲染 8。
   分档：低 0-30 · 中 31-60 · 高 61-100。
   ============================================================ */
(function () {
  "use strict";

  var CN_TZS = new Set([
    "Asia/Shanghai", "Asia/Urumqi", "Asia/Chongqing", "Asia/Chungking",
    "Asia/Harbin", "Asia/Kashgar", "PRC",
  ]);
  var PLUS8_NON_CN = new Set([
    "Asia/Singapore", "Asia/Kuala_Lumpur", "Asia/Kuching", "Asia/Manila",
    "Asia/Taipei", "Asia/Makassar", "Asia/Ujung_Pandang", "Australia/Perth",
  ]);
  var CN_FONTS = [
    "Microsoft YaHei", "Microsoft YaHei UI", "PingFang SC", "SimSun", "NSimSun",
    "SimHei", "FangSong", "KaiTi", "DengXian", "Songti SC", "STHeiti", "STKaiti",
    "Hiragino Sans GB", "HarmonyOS Sans SC", "MiSans", "Alibaba PuHuiTi",
    "Source Han Sans SC", "Noto Sans CJK SC",
  ];

  function esc(s) { return NP.esc(s); }
  function pill(text, cls) { return "<span class='pill " + cls + "'>" + esc(text) + "</span>"; }

  function fontProbe() {
    var found = [];
    try {
      var c = document.createElement("canvas");
      var ctx = c.getContext("2d");
      var test = "mmmmmmmmmmlli \u4e2d\u6587\u6d4b\u8bd5\u5b57\u4f53";
      var base = ["monospace", "sans-serif", "serif"];
      var baseW = {};
      base.forEach(function (b) { ctx.font = "72px " + b; baseW[b] = ctx.measureText(test).width; });
      CN_FONTS.forEach(function (f) {
        var hit = base.some(function (b) {
          ctx.font = "72px '" + f + "'," + b;
          return Math.abs(ctx.measureText(test).width - baseW[b]) > 0.5;
        });
        if (hit) found.push(f);
      });
    } catch (e) {}
    return found;
  }

  /* 旗帜 emoji 饱和度探测：部分国产 ROM 会把旗帜渲染成单色/缺字 */
  function emojiColorRatio() {
    try {
      var c = document.createElement("canvas");
      c.width = 84; c.height = 30;
      var ctx = c.getContext("2d");
      ctx.font = "24px sans-serif";
      ctx.textBaseline = "top";
      ctx.fillText("\uD83C\uDDE8\uD83C\uDDF3", 2, 2);  // 🇨🇳
      ctx.fillText("\uD83C\uDDFA\uD83C\uDDF8", 44, 2); // 🇺🇸
      var d = ctx.getImageData(0, 0, 84, 30).data;
      var colored = 0, total = 0;
      for (var i = 0; i < d.length; i += 4) {
        if (d[i + 3] > 60) {
          total++;
          var mx = Math.max(d[i], d[i + 1], d[i + 2]), mn = Math.min(d[i], d[i + 1], d[i + 2]);
          if (mx - mn > 28) colored++;
        }
      }
      return total ? colored / total : -1;
    } catch (e) { return -1; }
  }

  function detect() {
    var tz = "—";
    try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "—"; } catch (e) {}
    var langs = navigator.languages || (navigator.language ? [navigator.language] : []);
    var l0 = langs[0] || "";

    /* 1. 系统时区（30） */
    var s1 = 0, v1 = tz;
    if (CN_TZS.has(tz)) s1 = 30;
    else if (PLUS8_NON_CN.has(tz)) s1 = 6;

    /* 2. 浏览器语言（24） */
    var s2 = 0, v2 = langs.join(", ") || "—";
    if (/^zh(-cn|-hans|-sg)?$/i.test(l0)) s2 = 24;
    else if (/^zh/i.test(l0)) s2 = 10;
    else if (langs.some(function (x) { return /^zh/i.test(x); })) s2 = 14;

    /* 3. 中文字体（20） */
    var fonts = fontProbe();
    var s3 = 0;
    if (fonts.length >= 3) s3 = 20;
    else if (fonts.length === 2) s3 = 12;
    else if (fonts.length === 1) s3 = 6;
    var v3 = fonts.length ? fonts.slice(0, 8).join("、") + (fonts.length > 8 ? " 等 " + fonts.length + " 个" : "") : "未检出常用中文字体";

    /* 4. Intl 区域格式（10） */
    var loc = "—";
    var s4 = 0;
    try { loc = Intl.DateTimeFormat().resolvedOptions().locale || "—"; } catch (e) {}
    if (/^zh/i.test(loc)) s4 = 10;

    /* 5. 时区偏移（8） */
    var off = new Date().getTimezoneOffset();
    var s5 = off === -480 ? 8 : 0;
    var v5 = "UTC" + (off <= 0 ? "+" : "-") + Math.floor(Math.abs(off) / 60) + ":" + ("0" + (Math.abs(off) % 60)).slice(-2);

    /* 6. Emoji 渲染（8，弱信号：仅对安卓生效） */
    var ratio = emojiColorRatio();
    var isAndroid = /Android/i.test(navigator.userAgent);
    var s6 = 0;
    var v6;
    if (ratio < 0) v6 = "无法采样（Canvas 受限）";
    else if (ratio > 0.06) v6 = "彩色旗帜渲染正常";
    else if (isAndroid && ratio <= 0.02) { s6 = 8; v6 = "单色/缺字渲染（安卓合规 ROM 常见）"; }
    else if (isAndroid) { s6 = 4; v6 = "旗帜渲染色彩偏弱"; }
    else v6 = "非彩色渲染（桌面端字母替身，正常）";

    var total = Math.min(100, s1 + s2 + s3 + s4 + s5 + s6);
    return {
      total: total,
      rows: [
        { name: "系统时区", w: 30, v: v1, s: s1 },
        { name: "浏览器语言", w: 24, v: v2, s: s2 },
        { name: "已装中文字体", w: 20, v: v3, s: s3 },
        { name: "Intl 区域格式", w: 10, v: loc, s: s4 },
        { name: "时区偏移", w: 8, v: v5, s: s5 },
        { name: "Emoji 渲染", w: 8, v: v6, s: s6 },
      ],
    };
  }

  function render() {
    var r = detect();
    var band, cls;
    if (r.total <= 30) { band = "低"; cls = "pill-good"; }
    else if (r.total <= 60) { band = "中"; cls = "pill-warn"; }
    else { band = "高"; cls = "pill-bad"; }

    document.getElementById("cnScoreBody").innerHTML =
      "<div style='display:flex;align-items:center;gap:14px;flex-wrap:wrap'>" +
      "<span class='score-num' style='font-size:1.6em'>" + r.total + "</span>" +
      pill(band + "风险", cls) +
      "<div style='flex:1;min-width:200px'>" +
      "<div class='score-bar'><i class='score-marker' style='left:calc(" + r.total + "% - 2px)'></i></div>" +
      "<div class='score-scale'><span>0 低</span><span>30</span><span>60</span><span>100 高</span></div>" +
      "</div></div>";

    document.getElementById("cnSignalRows").innerHTML = r.rows.map(function (x) {
      return "<div class='kv-row'><span class='k'>" + esc(x.name) +
        " <span class='muted small'>权重 " + x.w + "</span></span><span class='v'>" +
        esc(String(x.v).slice(0, 90)) + " " + pill(x.s > 0 ? "+" + x.s : "0", x.s > 0 ? "pill-warn" : "pill-good") + "</span></div>";
    }).join("");

    var verdict;
    if (r.total <= 30) {
      verdict = "<div class='verdict verdict-safe'>✓ 当前环境的中国用户特征较弱，与官方风控视角的「正常海外环境」更接近。</div>";
    } else if (r.total <= 60) {
      verdict = "<div class='verdict verdict-warn'>△ 环境带有一定中国用户特征。若配合非中国出口 IP 使用 Claude，这类组合会被部分风控模型重点关注，建议至少把系统时区改为其他 UTC+8 时区（如 Asia/Singapore）。</div>";
    } else {
      verdict = "<div class='verdict verdict-bad'>✗ 环境高度呈现中国用户特征。即使出口 IP 在海外，客户端读取的系统时区、语言与字体仍会暴露地区属性。建议：① 系统时区改为 Asia/Singapore 等非中国大陆 UTC+8 时区；② 精简浏览器语言列表；③ 改用网络层透明代理（TUN/软路由），避免本地应用感知代理存在。</div>";
    }
    document.getElementById("cnVerdict").innerHTML = verdict;
  }

  render();
  document.getElementById("cnRecalc").addEventListener("click", render);
})();
