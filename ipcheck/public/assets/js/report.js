/* ============================================================
   NetProbe — 检测报告只读页（原创实现）
   路由：/report/<id>；对比分享：/report/<idB>?cmp=<idA>,<idB>
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;

  function kv(k, v) {
    return "<div class='kv-row'><span class='k'>" + esc(k) + "</span><span class='v'>" + (v == null || v === "" ? "—" : v) + "</span></div>";
  }

  function reportCard(d, title) {
    var purity = d.purity != null && d.purity !== "" ? parseInt(d.purity, 10) : null;
    var purityHtml = "—";
    if (purity != null && isFinite(purity)) {
      var cls = purity >= 85 ? "pill-good" : purity >= 60 ? "pill-warn" : "pill-bad";
      var txt = purity >= 85 ? "纯净" : purity >= 60 ? "一般" : "较差";
      purityHtml = "<b>" + purity + "</b> / 100 <span class='pill " + cls + "'>" + txt + "</span>";
    }
    var scoreHtml = "—";
    if (d.score != null && d.score !== "") scoreHtml = esc(d.score) + " / 100";
    return "<div class='card'>" +
      "<p class='card-title'>" + esc(title || "检测结果") +
      (d.cc ? " " + NP.flag(d.cc.toLowerCase()) : "") +
      " <span class='ip-text' style='font-size:1.1em;font-weight:800;margin-left:6px'>" + esc(d.ip || "") + "</span></p>" +
      "<div class='kv-rows'>" +
      kv("出口类型", d.label ? "<span class='pill pill-info'>" + esc(d.label) + "</span>" : "—") +
      kv("纯净度", purityHtml) +
      kv("风险指数", scoreHtml) +
      kv("ASN / 运营商", d.asn ? "<b>" + esc(d.asn) + "</b> " + esc(d.org || "") : esc(d.org || "—")) +
      kv("归属地", esc([d.cc && d.cc.toUpperCase(), d.region, d.city].filter(Boolean).join(" · ") || "—")) +
      kv("RPKI 路由验证", d.rpki ? esc(d.rpki) : "—") +
      kv("黑名单命中", d.dnsblHit != null && d.dnsblHit !== "" ? (parseInt(d.dnsblHit, 10) > 0 ? "<span class='pill pill-bad'>" + esc(d.dnsblHit) + " 项命中</span>" : "<span class='pill pill-good'>无命中</span>") : "—") +
      "</div></div>";
  }

  async function load() {
    var area = document.getElementById("reportArea");
    var pathId = (location.pathname.match(/\/report\/([A-Za-z0-9]+)/) || [])[1] || "";
    var qs = new URLSearchParams(location.search);
    var cmp = (qs.get("cmp") || "").split(",").filter(Boolean);
    var ids = [];
    if (pathId) ids.push(pathId);
    cmp.forEach(function (x) { if (ids.indexOf(x) === -1) ids.push(x); });
    if (!ids.length) {
      area.innerHTML = "<div class='card'><div class='error-text'>链接缺少报告编号。</div></div>";
      return;
    }
    var results = await Promise.all(ids.map(async function (id) {
      try {
        const r = await NP.fetchT("/api/report/" + encodeURIComponent(id), null, 12000);
        const j = await r.json().catch(function () { return null; });
        return (r.ok && j && j.ok) ? { id: id, d: j.d, t: j.t } : null;
      } catch (e) { return null; }
    }));
    var found = results.filter(Boolean);
    if (!found.length) {
      area.innerHTML = "<div class='card'><div class='error-text'>报告不存在或已过期（快照保存 30 天）。</div></div>";
      return;
    }
    var html = "";
    if (found.length >= 2) {
      html += "<div class='grade-conclusion' style='margin:0 0 8px'>对比报告：" +
        "A 纯净度 " + (found[0].d.purity || "—") + "，B 纯净度 " + (found[1].d.purity || "—") + "。" +
        "下方依次为两份快照。</div>";
      html += reportCard(found[0].d, "A · " + found[0].id);
      html += reportCard(found[1].d, "B · " + found[1].id);
    } else {
      html += reportCard(found[0].d);
    }
    var t = new Date(found[0].t);
    html += "<p class='muted small'>快照生成于 " + t.toLocaleString("zh-CN", { hour12: false }) + " · <a href='/ip/?q=" + encodeURIComponent(found[0].d.ip || "") + "'>重新检测这个 IP →</a></p>";
    area.innerHTML = html;
    // 隐藏IP 支持
    var box = document.getElementById("ipMaskToggle");
    if (box) box.addEventListener("change", function () {
      var on = box.checked;
      document.querySelectorAll(".ip-text").forEach(function (el) {
        if (!el.dataset.real) el.dataset.real = el.textContent.trim();
        if (!el.dataset.real) return;
        var want = on ? NP.maskIp(el.dataset.real) : el.dataset.real;
        if (el.textContent !== want) el.textContent = want;
      });
    });
  }

  load();
})();
