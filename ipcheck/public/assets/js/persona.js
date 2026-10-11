/* ============================================================
   NetProbe — 深度画像检测（原创实现，纯本地）
   五项信号加权 0-100，与目标国家逐项对照：
     系统时区 25 / 浏览器语言 25 / 区域格式 (Intl locale) 20 /
     UTC 偏移 15 / 文字系统字体 15
   COUNTRY_DATA 为精简对照表：主要时区 / 首选语言 / IANA locale / 文字系统。
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;

  var SCRIPTS = {
    han:    { label: "中文（汉字）",     test: "网络检测字体测试",       fonts: ["Microsoft YaHei", "PingFang SC", "SimSun", "Hiragino Sans GB", "Meiryo", "Malgun Gothic", "Noto Sans CJK SC", "Source Han Sans SC"] },
    kana:   { label: "日语（假名+汉字）", test: "インターネット検定テスト", fonts: ["Meiryo", "Yu Gothic", "MS Gothic", "Hiragino Kaku Gothic Pro", "Hiragino Sans", "Noto Sans CJK JP", "OSAKA"] },
    hangul: { label: "韩语（谚文）",     test: "인터넷 글꼴 시험",        fonts: ["Malgun Gothic", "Apple SD Gothic Neo", "NanumGothic", "Noto Sans CJK KR"] },
    cyrillic: { label: "西里尔字母",     test: "Проверка сетевых шрифтов", fonts: ["Segoe UI", "PT Sans", "Helvetica", "Arial", "PT Root UI", "Noto Sans"] },
    arabic: { label: "阿拉伯字母",       test: "اختبار خطوط الشبكة",      fonts: ["Segoe UI", "Tahoma", "Geeza Pro", "Dubai", "Noto Naskh Arabic", "Traditional Arabic"] },
    thai:   { label: "泰文",             test: "ทดสอบฟอนต์เครือข่าย",     fonts: ["Leelawadee UI", "Tahoma", "Sukhumvit Set", "Noto Sans Thai"] },
    latin:  { label: "拉丁字母",         test: "Network font check",      fonts: ["Segoe UI", "Helvetica Neue", "Arial", "Calibri", "Roboto", "San Francisco"] },
  };

  var COUNTRY_DATA = [
    { cc: "cn", name: "中国",     tz: ["Asia/Shanghai", "Asia/Urumqi"],              langs: ["zh-CN", "zh"],    locale: "zh-CN", script: "han" },
    { cc: "hk", name: "中国香港", tz: ["Asia/Hong_Kong"],                            langs: ["zh-HK", "zh-TW", "zh", "en-HK", "en"], locale: "zh-HK", script: "han" },
    { cc: "tw", name: "中国台湾", tz: ["Asia/Taipei"],                               langs: ["zh-TW", "zh", "en-TW", "en"], locale: "zh-TW", script: "han" },
    { cc: "jp", name: "日本",     tz: ["Asia/Tokyo"],                                langs: ["ja", "ja-JP"],    locale: "ja-JP", script: "kana" },
    { cc: "kr", name: "韩国",     tz: ["Asia/Seoul"],                                langs: ["ko", "ko-KR"],    locale: "ko-KR", script: "hangul" },
    { cc: "sg", name: "新加坡",   tz: ["Asia/Singapore"],                            langs: ["en-SG", "en", "zh-SG", "zh", "ms"], locale: "en-SG", script: "han" },
    { cc: "my", name: "马来西亚", tz: ["Asia/Kuala_Lumpur"],                         langs: ["ms-MY", "ms", "en-MY", "en"], locale: "ms-MY", script: "latin" },
    { cc: "th", name: "泰国",     tz: ["Asia/Bangkok"],                              langs: ["th-TH", "th", "en-TH", "en"], locale: "th-TH", script: "thai" },
    { cc: "vn", name: "越南",     tz: ["Asia/Ho_Chi_Minh"],                          langs: ["vi-VN", "vi", "en"], locale: "vi-VN", script: "latin" },
    { cc: "id", name: "印度尼西亚", tz: ["Asia/Jakarta"],                            langs: ["id-ID", "id", "en-ID", "en"], locale: "id-ID", script: "latin" },
    { cc: "in", name: "印度",     tz: ["Asia/Kolkata", "Asia/Calcutta"],             langs: ["hi-IN", "hi", "en-IN", "en"], locale: "hi-IN", script: "latin" },
    { cc: "us", name: "美国",     tz: ["America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles", "America/Phoenix", "America/Anchorage", "Pacific/Honolulu"], langs: ["en-US", "en"], locale: "en-US", script: "latin" },
    { cc: "ca", name: "加拿大",   tz: ["America/Toronto", "America/Vancouver", "America/Edmonton", "America/Winnipeg", "America/Halifax"], langs: ["en-CA", "en", "fr-CA", "fr"], locale: "en-CA", script: "latin" },
    { cc: "mx", name: "墨西哥",   tz: ["America/Mexico_City"],                       langs: ["es-MX", "es", "en"], locale: "es-MX", script: "latin" },
    { cc: "br", name: "巴西",     tz: ["America/Sao_Paulo"],                         langs: ["pt-BR", "pt", "en"], locale: "pt-BR", script: "latin" },
    { cc: "ar", name: "阿根廷",   tz: ["America/Argentina/Buenos_Aires"],            langs: ["es-AR", "es", "en"], locale: "es-AR", script: "latin" },
    { cc: "gb", name: "英国",     tz: ["Europe/London"],                             langs: ["en-GB", "en"],    locale: "en-GB", script: "latin" },
    { cc: "de", name: "德国",     tz: ["Europe/Berlin"],                             langs: ["de-DE", "de", "en"], locale: "de-DE", script: "latin" },
    { cc: "fr", name: "法国",     tz: ["Europe/Paris"],                              langs: ["fr-FR", "fr", "en"], locale: "fr-FR", script: "latin" },
    { cc: "it", name: "意大利",   tz: ["Europe/Rome"],                               langs: ["it-IT", "it", "en"], locale: "it-IT", script: "latin" },
    { cc: "es", name: "西班牙",   tz: ["Europe/Madrid"],                             langs: ["es-ES", "es", "en"], locale: "es-ES", script: "latin" },
    { cc: "nl", name: "荷兰",     tz: ["Europe/Amsterdam"],                          langs: ["nl-NL", "nl", "en"], locale: "nl-NL", script: "latin" },
    { cc: "se", name: "瑞典",     tz: ["Europe/Stockholm"],                          langs: ["sv-SE", "sv", "en"], locale: "sv-SE", script: "latin" },
    { cc: "ch", name: "瑞士",     tz: ["Europe/Zurich"],                             langs: ["de-CH", "de", "fr-CH", "fr", "it-CH", "it", "en"], locale: "de-CH", script: "latin" },
    { cc: "pl", name: "波兰",     tz: ["Europe/Warsaw"],                             langs: ["pl-PL", "pl", "en"], locale: "pl-PL", script: "latin" },
    { cc: "ru", name: "俄罗斯",   tz: ["Europe/Moscow", "Asia/Yekaterinburg", "Asia/Novosibirsk", "Asia/Vladivostok"], langs: ["ru-RU", "ru", "en"], locale: "ru-RU", script: "cyrillic" },
    { cc: "tr", name: "土耳其",   tz: ["Europe/Istanbul"],                           langs: ["tr-TR", "tr", "en"], locale: "tr-TR", script: "latin" },
    { cc: "ua", name: "乌克兰",   tz: ["Europe/Kyiv", "Europe/Kiev"],                langs: ["uk-UA", "uk", "ru", "en"], locale: "uk-UA", script: "cyrillic" },
    { cc: "ae", name: "阿联酋",   tz: ["Asia/Dubai"],                                langs: ["ar-AE", "ar", "en-AE", "en"], locale: "ar-AE", script: "arabic" },
    { cc: "sa", name: "沙特阿拉伯", tz: ["Asia/Riyadh"],                             langs: ["ar-SA", "ar", "en-SA", "en"], locale: "ar-SA", script: "arabic" },
    { cc: "eg", name: "埃及",     tz: ["Africa/Cairo"],                              langs: ["ar-EG", "ar", "en-EG", "en"], locale: "ar-EG", script: "arabic" },
    { cc: "au", name: "澳大利亚", tz: ["Australia/Sydney", "Australia/Melbourne", "Australia/Brisbane", "Australia/Perth"], langs: ["en-AU", "en"], locale: "en-AU", script: "latin" },
    { cc: "nz", name: "新西兰",   tz: ["Pacific/Auckland"],                          langs: ["en-NZ", "en"],    locale: "en-NZ", script: "latin" },
  ];

  /* ---------- 本机信号采集 ---------- */
  function getTz() {
    try { return Intl.DateTimeFormat().resolvedOptions().timeZone || "—"; } catch (e) { return "—"; }
  }
  function getLangs() {
    return navigator.languages || (navigator.language ? [navigator.language] : []);
  }
  function getLocale() {
    try { return Intl.DateTimeFormat().resolvedOptions().locale || "—"; } catch (e) { return "—"; }
  }
  function tzOffsetMin() {
    return -new Date().getTimezoneOffset();
  }
  function fmtOffset(min) {
    var sign = min >= 0 ? "+" : "-";
    var abs = Math.abs(min);
    return "UTC" + sign + Math.floor(abs / 60) + (abs % 60 ? ":" + String(abs % 60).padStart(2, "0") : "");
  }

  function fontProbe(script) {
    var sc = SCRIPTS[script] || SCRIPTS.latin;
    var found = [];
    try {
      var c = document.createElement("canvas");
      var ctx = c.getContext("2d");
      var test = sc.test;
      var base = ["monospace", "sans-serif", "serif"];
      var baseW = {};
      base.forEach(function (b) { ctx.font = "72px " + b; baseW[b] = ctx.measureText(test).width; });
      sc.fonts.forEach(function (f) {
        var hit = base.some(function (b) {
          ctx.font = "72px '" + f + "'," + b;
          return Math.abs(ctx.measureText(test).width - baseW[b]) > 0.5;
        });
        if (hit) found.push(f);
      });
    } catch (e) {}
    return found;
  }

  /* ---------- 打分 ---------- */
  function scoreAgainst(target) {
    var tz = getTz();
    var langs = getLangs();
    var l0 = (langs[0] || "").toLowerCase();
    var locale = getLocale();
    var off = tzOffsetMin();
    var signals = [];

    /* 1. 时区名称（25） */
    var s1, v1 = tz;
    s1 = target.tz.indexOf(tz) !== -1 ? 25 : 0;
    signals.push({ k: "系统时区", w: 25, s: s1, got: v1, want: target.tz[0] + (target.tz.length > 1 ? " 等" + target.tz.length + "个" : ""), hint: "浏览器/系统设置 → 时区。挂代理时优先让时区跟随出口国家。" });

    /* 2. 浏览器语言（25） */
    var s2 = 0;
    var hit = langs.some(function (l) { return target.langs.indexOf(l) !== -1; });
    if (hit) s2 = 25;
    else {
      var baseLang = (target.langs[0] || "").split("-")[0];
      if (baseLang && langs.some(function (l) { return l.toLowerCase().indexOf(baseLang.toLowerCase()) === 0; })) s2 = 12;
    }
    signals.push({ k: "浏览器语言", w: 25, s: s2, got: langs.join(", ") || "—", want: target.langs.join(" / "), hint: "浏览器设置 → 首选语言，把目标语言移到第一位。" });

    /* 3. 区域格式（20） */
    var s3 = 0;
    var locLower = locale.toLowerCase();
    var wantLower = target.locale.toLowerCase();
    if (locLower === wantLower) s3 = 20;
    else if (locLower.split("-")[0] === wantLower.split("-")[0]) s3 = 8;
    signals.push({ k: "区域格式 (Intl locale)", w: 20, s: s3, got: locale, want: target.locale, hint: "系统区域/格式设置跟随目标国家，或让浏览器语言驱动它。" });

    /* 4. UTC 偏移（15）：目标国任一时区当前偏移一致即满分 */
    var wantOff = null;
    try {
      var now = new Date();
      var dtf = new Intl.DateTimeFormat("en-US", { timeZone: target.tz[0], timeZoneName: "shortOffset" });
      var part = dtf.formatToParts(now).find(function (p) { return p.type === "timeZoneName"; });
      var m = part && part.value.match(/GMT([+-]\d{1,2})(?::(\d{2}))?/);
      if (m) wantOff = parseInt(m[1], 10) * 60 + (m[2] ? (m[1][0] === "-" ? -1 : 1) * parseInt(m[2], 10) : 0);
    } catch (e) {}
    var s4 = wantOff !== null && wantOff === off ? 15 : 0;
    signals.push({ k: "当前 UTC 偏移", w: 15, s: s4, got: fmtOffset(off), want: wantOff === null ? "—" : fmtOffset(wantOff), hint: "偏移由时区决定；夏令时切换季注意目标国是否处于 DST。" });

    /* 5. 文字系统字体（15） */
    var found = fontProbe(target.script);
    var s5 = found.length >= 2 ? 15 : found.length === 1 ? 8 : 0;
    signals.push({ k: SCRIPTS[target.script].label + "字体", w: 15, s: s5, got: found.length ? found.slice(0, 3).join("、") + (found.length > 3 ? " 等" + found.length + "个" : "") : "未检出", want: "目标文字系统的常见字体", hint: "安装系统语言包或目标语言字体即可补齐。" });

    var total = signals.reduce(function (a, s) { return a + s.s; }, 0);
    return { signals: signals, total: total };
  }

  /* ---------- 渲染 ---------- */
  function band(t) {
    if (t >= 80) return ["高度一致", "pill-good", "verdict-safe", "画像与目标国家的本地人高度一致，网站很难从这些信号里分辨出差异。"];
    if (t >= 55) return ["部分一致", "pill-info", "verdict-warn", "有明显的本地化特征，但仍有一到两项会暴露差异；可按下方提示继续修正。"];
    if (t >= 30) return ["差异明显", "pill-warn", "verdict-warn", "多项信号与目标国家不符，风控系统很可能将你识别为「代理或非常规访客」。"];
    return ["完全不符", "pill-bad", "verdict-bad", "几乎所有信号都指向另一个地区。若目标是伪装本地身份，当前配置基本不成立。"];
  }

  function run() {
    var cc = document.getElementById("targetCountry").value;
    var t = COUNTRY_DATA.find(function (c) { return c.cc === cc; });
    if (!t) return;
    var r = scoreAgainst(t);
    var b = band(r.total);

    var html = "<div class='card' style='margin-top:14px'><p class='card-title'>画像评分 <span class='badge'>" + NP.flag(t.cc) + " " + esc(t.name) + "</span></p>";
    html += "<div style='display:flex;align-items:baseline;gap:14px;flex-wrap:wrap'>" +
      "<div class='score-num' style='font-size:2.6em;font-weight:800'>" + r.total + "</div>" +
      "<div><span class='pill " + b[1] + "'>" + b[0] + "</span> <span class='muted small'>/ 100 · 目标 " + esc(t.name) + "</span></div></div>";
    html += "<div class='verdict " + b[2] + "' style='margin-top:8px'>" + b[3] + "</div>";
    html += "<div class='tbl-wrap' style='margin-top:10px'><table class='tbl' style='min-width:640px'>" +
      "<thead><tr><th>信号</th><th>你的浏览器</th><th>目标（" + esc(t.name) + "）</th><th style='width:90px'>得分</th></tr></thead><tbody>";
    r.signals.forEach(function (s) {
      var cls = s.s === s.w ? "pill-good" : s.s > 0 ? "pill-warn" : "pill-bad";
      html += "<tr><td><b>" + esc(s.k) + "</b><br><span class='muted small'>权重 " + s.w + "</span></td>" +
        "<td class='small' style='max-width:240px;word-break:break-all'>" + esc(s.got) + "</td>" +
        "<td class='small' style='max-width:240px;word-break:break-all'>" + esc(s.want) + "</td>" +
        "<td><span class='pill " + cls + "'>" + s.s + " / " + s.w + "</span></td></tr>";
    });
    html += "</tbody></table></div>";

    var hints = r.signals.filter(function (s) { return s.s < s.w; });
    if (hints.length) {
      html += "<div class='muted small' style='margin-top:10px'><b>修正建议：</b><ul style='margin:6px 0 0 18px'>" +
        hints.map(function (s) { return "<li><b>" + esc(s.k) + "</b>：" + esc(s.hint) + "</li>"; }).join("") + "</ul></div>";
    }
    html += "<p class='muted small' style='margin-top:10px'>注：本评分只覆盖浏览器可读信号，不包含 IP 归属地核对（请配合「IP 评分」页）与行为特征，不能保证通过任何网站的专门风控。</p></div>";
    document.getElementById("scoreArea").innerHTML = html;
    document.getElementById("detailArea").innerHTML = "";
  }

  /* ---------- 初始化 ---------- */
  var sel = document.getElementById("targetCountry");
  sel.innerHTML = COUNTRY_DATA.map(function (c) {
    return "<option value='" + c.cc + "'>" + NP.flag(c.cc) + " " + esc(c.name) + "（" + c.locale + "）</option>";
  }).join("");
  // 默认按当前语言猜一个
  var guess = (getLangs()[0] || "en").toLowerCase();
  var matched = COUNTRY_DATA.find(function (c) { return guess.indexOf(c.cc) !== -1; }) || COUNTRY_DATA.find(function (c) { return c.cc === "us"; });
  sel.value = matched.cc;
  document.getElementById("runBtn").addEventListener("click", run);
})();
