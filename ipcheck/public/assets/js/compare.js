/* ============================================================
   NetProbe — IP 对比（原创实现）
   两个 IP 各拉一次 /api/ipscore + /api/cfrisk，表格逐维度对比。
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;

  function pill(ok, yesText, noText, warnText) {
    if (ok === null || ok === undefined) return "<span class='pill pill-muted'>—</span>";
    if (ok === "warn") return "<span class='pill pill-warn'>" + esc(warnText || "部分") + "</span>";
    return ok
      ? "<span class='pill pill-good'>" + esc(yesText || "是") + "</span>"
      : "<span class='pill pill-muted'>" + esc(noText || "否") + "</span>";
  }

  function purityPill(v) {
    if (v == null || !isFinite(v)) return "<span class='pill pill-muted'>—</span>";
    var cls = v >= 85 ? "pill-good" : v >= 60 ? "pill-warn" : "pill-bad";
    var txt = v >= 85 ? "纯净" : v >= 60 ? "一般" : "较差";
    return "<b>" + v + "</b> / 100 <span class='pill " + cls + "'>" + txt + "</span>";
  }

  async function fetchScore(ip) {
    async function once() {
      try {
        const r = await NP.fetchT("/api/ipscore/" + encodeURIComponent(ip), null, 45000);
        const d = await r.json().catch(function () { return null; });
        if (!r.ok || !d || !d.risk) return { s: null, err: (d && d.error) || "HTTP " + r.status };
        let cfr = null;
        try {
          const rc = await NP.fetchT("/api/cfrisk/" + encodeURIComponent(ip), null, 45000);
          cfr = await rc.json().catch(function () { return null; });
        } catch (e) {}
        return { s: d, c: cfr };
      } catch (e) {
        return { s: null, err: (e && e.message) || "网络异常" };
      }
    }
    var r = await once();
    if (!r.s) {
      // 可能是限流或瞬时失败：等 8 秒自动重试一次
      await new Promise(function (res) { setTimeout(res, 8000); });
      r = await once();
    }
    return r;
  }

  function summarize(A, B) {
    var sa = A.s || {}, sb = B.s || {};
    var ra = sa.risk || {}, rb = sb.risk || {};
    var ca = A.c, cb = B.c;
    var purityA = ca && typeof ca.score === "number" ? 100 - ca.score : null;
    var purityB = cb && typeof cb.score === "number" ? 100 - cb.score : null;

    function dnsblHits(dbl) {
      if (!dbl) return null;
      var hit = dbl.filter(function (x) { return x.listed; }).length;
      var refused = dbl.filter(function (x) { return x.refused; }).length;
      return { hit: hit, refused: refused, total: dbl.length };
    }
    var ha = dnsblHits(sa.dnsblFull), hb = dnsblHits(sb.dnsblFull);

    var rows = [];
    rows.push({ k: "出口类型", a: ra.label || "—", b: rb.label || "—",
      verdict: ra.label && rb.label ? (ra.label === rb.label ? "两者类型相同" : ra.is_datacenter === rb.is_datacenter ? "同为大类，细分不同" : "类型不同（机房 vs 非机房）") : "数据不足" });
    rows.push({ k: "纯净度", a: purityA, b: purityB,
      verdict: purityA != null && purityB != null ? (purityA === purityB ? "纯净度持平" : purityA > purityB ? "A 更干净（高 " + (purityA - purityB) + " 分）" : "B 更干净（高 " + (purityB - purityA) + " 分）") : "数据不足" });
    rows.push({ k: "ASN / 运营商", a: ra.asn ? "AS" + ra.asn + " " + (ra.asname || ra.org || "") : "—",
      b: rb.asn ? "AS" + rb.asn + " " + (rb.asname || rb.org || "") : "—",
      verdict: ra.asn && rb.asn ? (ra.asn === rb.asn ? "同一 ASN" : "不同网络") : "数据不足" });
    rows.push({ k: "归属地", a: [ra.country, ra.region, ra.city].filter(Boolean).join(" · ") || "—",
      b: [rb.country, rb.region, rb.city].filter(Boolean).join(" · ") || "—",
      verdict: ra.country_code && rb.country_code ? (ra.country_code === rb.country_code ? "同一国家/地区" : "不同国家/地区") : "数据不足" });
    rows.push({ k: "反向解析 (PTR)", a: ra.reverse || sa.deep && sa.deep.ptr || "无", b: rb.reverse || sb.deep && sb.deep.ptr || "无",
      verdict: (!ra.reverse && !rb.reverse) ? "双方均无 PTR" : "以各侧显示为准" });
    rows.push({ k: "RPKI 路由验证", a: sa.rpki && sa.rpki.status || null, b: sb.rpki && sb.rpki.status || null,
      pillThree: true, verdict: (sa.rpki && sa.rpki.status) === (sb.rpki && sb.rpki.status) ? "验证状态一致" : "验证状态不同" });
    rows.push({ k: "黑名单命中", a: ha ? ha.hit + " / " + ha.total + (ha.refused ? "（" + ha.refused + " 项未判定）" : "") : null,
      b: hb ? hb.hit + " / " + hb.total + (hb.refused ? "（" + hb.refused + " 项未判定）" : "") : null,
      verdict: ha && hb ? (ha.hit === hb.hit ? "命中数相同" : ha.hit < hb.hit ? "A 命中更少" : "B 命中更少") : "数据不足" });
    rows.push({ k: "代理特征", a: ra.is_proxy, b: rb.is_proxy, pill: true, verdict: "是=非机房网络上的匿名/代理特征" });
    rows.push({ k: "机房 / 云服务器", a: ra.is_datacenter, b: rb.is_datacenter, pill: true,
      verdict: ra.is_datacenter !== rb.is_datacenter ? "机房属性不同——这对风控敏感服务影响明显" : "机房属性一致" });
    rows.push({ k: "风险指数（0-100）", a: ca ? ca.score + "（" + ca.band + "）" : null, b: cb ? cb.score + "（" + cb.band + "）" : null,
      verdict: ca && cb ? (ca.score === cb.score ? "风险持平" : ca.score < cb.score ? "A 环境更干净" : "B 环境更干净") : "数据不足" });

    return rows;
  }

  function cellHtml(row, side) {
    var v = side === "a" ? row.a : row.b;
    if (row.pill) return pill(v, "是", "否");
    if (row.pillThree) {
      if (!v) return "<span class='pill pill-muted'>—</span>";
      var cls = v === "valid" ? "pill-good" : v === "invalid" ? "pill-bad" : "pill-warn";
      var txt = v === "valid" ? "有效" : v === "invalid" ? "无效" : v || "—";
      return "<span class='pill " + cls + "'>" + esc(txt) + "</span>";
    }
    if (row.k === "纯净度") return purityPill(v);
    return esc(v == null ? "—" : String(v));
  }

  async function run() {
    var a = document.getElementById("ipA").value.trim();
    var b = document.getElementById("ipB").value.trim();
    var hint = document.getElementById("cmpHint");
    if (!a && !b) { a = ""; b = "8.8.8.8"; hint.textContent = "未填写 IP：A = 本机出口，B = 8.8.8.8 示例。"; }
    else if (!a || !b) { hint.textContent = "两个都填写才能对比；也可以都留空用示例。"; return; }
    else hint.textContent = "";

    document.getElementById("cmpResult").style.display = "";
    document.getElementById("cmpRows").innerHTML = "<tr><td colspan='4'><span class='spin'></span> 检测中…（重接口约 5-20 秒，受多源数据影响）</td></tr>";
    document.getElementById("cmpVerdict").textContent = "";
    var btn = document.getElementById("cmpGo");
    btn.disabled = true;

    try {
      var selfIpPromise = a ? Promise.resolve(a) : NP.fetchT("/api/session", null, 8000).then(function (r) { return r.json(); }).then(function (d) { return d.ip; });
      var ipA = await selfIpPromise;
      var ipB = b;
      var A = await fetchScore(ipA);
      var B = await fetchScore(ipB);

      // 限流/失败提示：显示真实原因 + 重试指引
      var failed = [];
      if (!A.s) failed.push("IP A（" + (A.err || "未知错误") + "）");
      if (!B.s) failed.push("IP B（" + (B.err || "未知错误") + "）");
      if (failed.length) {
        document.getElementById("cmpRows").innerHTML =
          "<tr><td colspan='4'><div class='verdict verdict-warn' style='margin:0'>" +
          esc(failed.join("；")) +
          "。重接口限速为每分钟 12 次，若是限流请等 1 分钟再点「开始对比」。</div></td></tr>";
        btn.disabled = false;
        return;
      }

      document.getElementById("headA").innerHTML = NP.flag(A.s.risk && A.s.risk.country_code) + " " + esc(ipA);
      document.getElementById("headSubA").textContent = [A.s.risk && A.s.risk.country, A.s.risk && A.s.risk.city].filter(Boolean).join(" · ");
      document.getElementById("headB").innerHTML = NP.flag(B.s.risk && B.s.risk.country_code) + " " + esc(ipB);
      document.getElementById("headSubB").textContent = [B.s.risk && B.s.risk.country, B.s.risk && B.s.risk.city].filter(Boolean).join(" · ");

      var rows = summarize(A, B);
      document.getElementById("cmpRows").innerHTML = rows.map(function (row) {
        return "<tr><td><b>" + esc(row.k) + "</b></td><td>" + cellHtml(row, "a") + "</td><td>" + cellHtml(row, "b") + "</td><td class='muted small'>" + esc(row.verdict) + "</td></tr>";
      }).join("");

      var pa = A.c && typeof A.c.score === "number" ? 100 - A.c.score : null;
      var pb = B.c && typeof B.c.score === "number" ? 100 - B.c.score : null;
      var v = document.getElementById("cmpVerdict");
      if (pa != null && pb != null) {
        var diff = pa - pb;
        if (Math.abs(diff) < 5) v.innerHTML = "两个 IP 的环境干净程度接近（纯净度差 " + Math.abs(diff) + " 分以内），按用途选择延迟更好的那个即可。";
        else if (diff > 0) v.innerHTML = "结论：<b>IP A 更干净</b>（纯净度 " + pa + " vs " + pb + "）。对风控敏感的服务（AI 注册、电商、社媒）优先用 A。";
        else v.innerHTML = "结论：<b>IP B 更干净</b>（纯净度 " + pb + " vs " + pa + "）。对风控敏感的服务（AI 注册、电商、社媒）优先用 B。";
      } else {
        v.textContent = "部分数据不可用，以上表格以已有维度为准。";
      }

      var la = document.getElementById("cmpLinkA"), lb = document.getElementById("cmpLinkB");
      la.style.display = ""; la.href = "/ip/?q=" + encodeURIComponent(ipA);
      lb.style.display = ""; lb.href = "/ip/?q=" + encodeURIComponent(ipB);

      document.getElementById("cmpShare").onclick = function () {
        makeShare(ipA, ipB, A, B);
      };
    } catch (e) {
      document.getElementById("cmpRows").innerHTML = "<tr><td colspan='4' class='error-text'>检测失败：" + esc(e.message || "网络异常") + "，稍后重试。</td></tr>";
    } finally {
      btn.disabled = false;
    }
  }

  async function makeShare(ipA, ipB, A, B) {
    var btn = document.getElementById("cmpShare");
    btn.disabled = true; btn.textContent = "生成中…";
    try {
      var maskOn = document.getElementById("cmpMask") && document.getElementById("cmpMask").checked;
      var ttl = parseInt((document.getElementById("cmpTtl") || {}).value || "604800", 10);
      function maskTail(v) {
        var t = String(v || "");
        if (/^d{1,3}(.d{1,3}){3}$/.test(t)) {
          var p = t.split(".");
          return p[0] + "." + p[1] + "." + p[2] + ".x";
        }
        if (t.indexOf(":") !== -1) {
          var parts = t.split(":");
          return parts.slice(0, Math.max(3, parts.length - 2)).join(":") + "::x";
        }
        return t;
      }
      function snap(x, ip) {
        var r = (x.s && x.s.risk) || {};
        var c = x.c || {};
        return {
          ip: maskOn ? maskTail(ip) : ip, label: r.label || "", score: c.score != null ? String(c.score) : "",
          purity: typeof c.score === "number" ? String(100 - c.score) : "",
          asn: r.asn ? "AS" + r.asn : "", org: r.org || r.isp || "",
          cc: r.country_code || "", city: r.city || "", region: r.region || "",
          rpki: (x.s && x.s.rpki && x.s.rpki.status) || "",
          dnsblHit: x.s && x.s.dnsblFull ? String(x.s.dnsblFull.filter(function (y) { return y.listed; }).length) : "",
        };
      }
      var r = await fetch("/api/report", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(Object.assign(snap(A, ipA), { ttl: ttl })),
        signal: AbortSignal.timeout(15000),
      });
      // 分别创建两条报告（A 与 B），分享链接同时携带两个 id
      var rB = await fetch("/api/report", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(Object.assign(snap(B, ipB), { ttl: ttl })),
        signal: AbortSignal.timeout(15000),
      });
      var dA = await r.json(), dB = await rB.json();
      var base = location.origin;
      var url = base + "/report/" + (dB.id || dA.id) + "?cmp=" + (dA.id || "") + "," + (dB.id || "");
      navigator.clipboard.writeText(url).then(function () {
        btn.textContent = "✓ 链接已复制";
      }).catch(function () {
        btn.textContent = "链接：" + url;
      });
      setTimeout(function () { btn.textContent = "🔗 生成分享报告"; btn.disabled = false; }, 4000);
    } catch (e) {
      btn.textContent = "生成失败，请重试";
      btn.disabled = false;
    }
  }

  document.getElementById("cmpGo").addEventListener("click", run);
  document.getElementById("ipB").addEventListener("keydown", function (e) { if (e.key === "Enter") run(); });
  document.getElementById("ipA").addEventListener("keydown", function (e) { if (e.key === "Enter") run(); });

  // URL 预填 ?a=1.2.3.4&b=5.6.7.8
  var qs = new URLSearchParams(location.search);
  if (qs.get("a")) document.getElementById("ipA").value = qs.get("a");
  if (qs.get("b")) document.getElementById("ipB").value = qs.get("b");
  if (qs.get("a") && qs.get("b")) run();
})();
