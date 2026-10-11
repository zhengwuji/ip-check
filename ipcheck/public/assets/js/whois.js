/* ============================================================
   NetProbe — Whois 查询（原创实现，RDAP 协议）
   优先走本站后端代理 /api/whois?q=（避免个别注册局无 CORS），
   后端不可用时浏览器直连 rdap.org。
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;

  function classify(q) {
    var t = q.trim();
    if (/^as\d+$/i.test(t)) return { type: "asn", value: t.replace(/^as/i, "") };
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) return { type: "ip", value: t };
    if (/^[0-9a-f:]+$/i.test(t) && t.indexOf(":") !== -1) return { type: "ip", value: t };
    if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(t)) return { type: "domain", value: t.toLowerCase() };
    return null;
  }

  async function rdapQuery(query) {
    // 后端代理优先
    try {
      const r = await fetch("/api/whois?q=" + encodeURIComponent(query), { signal: AbortSignal.timeout(12000) });
      if (r.ok) return { data: await r.json(), via: "后端代理" };
    } catch (e) {}
    // 直连 rdap.org（自动按类型跳转对应注册局）
    const r2 = await fetch("https://rdap.org/" + (classify(query) ? query : "domain/" + query),
      { headers: { accept: "application/rdap+json" }, signal: AbortSignal.timeout(12000) });
    if (!r2.ok) throw new Error("RDAP 查询失败（HTTP " + r2.status + "）");
    return { data: await r2.json(), via: "rdap.org 直连" };
  }

  function firstEvent(data, action) {
    var ev = (data.events || []).find(function (e) { return e.eventAction === action; });
    return ev ? ev.eventDate : null;
  }

  function fmtDate(s) {
    if (!s) return "—";
    try { return new Date(s).toLocaleString("zh-CN", { hour12: false }); } catch (e) { return s; }
  }

  function entityName(data) {
    var ents = data.entities || [];
    var reg = ents.find(function (e) { return (e.roles || []).indexOf("registrar") !== -1; });
    if (reg && reg.vcardArray && Array.isArray(reg.vcardArray[1])) {
      var fn = reg.vcardArray[1].find(function (p) { return p[0] === "fn"; });
      if (fn) return fn[3];
    }
    return null;
  }

  function render(data, via, query) {
    var html = "";
    var title = data.handle && /^AS\d+$/i.test(data.handle) ? "ASN " + data.handle
      : (data.ldhName || data.name || data.startAddress || query);

    html += "<div class='card'><p class='card-title'>查询结果：" + esc(String(title)) +
      " <span class='muted small'>（" + esc(via) + "）</span></p><div class='kv-grid'>";

    function kv(k, v, mono) {
      html += "<div class='kv'><div class='k'>" + esc(k) + "</div><div class='v" + (mono ? " ip-cell" : "") + "'>" + v + "</div></div>";
    }

    if (data.type === "domain" || data.ldhName) {
      kv("域名", esc(data.ldhName || query));
      kv("注册商", esc(entityName(data) || "—"));
      kv("注册时间", esc(fmtDate(firstEvent(data, "registration"))));
      kv("到期时间", esc(fmtDate(firstEvent(data, "expiration"))));
      kv("更新时间", esc(fmtDate(firstEvent(data, "last changed") || firstEvent(data, "last update of RDAP database"))));
      kv("DNSSEC", esc(data.secureDNS && data.secureDNS.delegationSigned ? "已启用" : "未启用"));
      var ns = (data.nameservers || []).map(function (n) { return n.ldhName; }).filter(Boolean);
      kv("域名服务器", esc(ns.length ? ns.join("、") : "—"));
      var statuses = data.status || [];
      kv("状态", esc(statuses.length ? statuses.join("、") : "—"));
    } else if (data.startAddress || data.handle && /^NET/.test(data.handle)) {
      kv("网段", esc((data.startAddress || "?") + " ~ " + (data.endAddress || "?")));
      kv("网段名称", esc(data.name || "—"));
      kv("类型", esc(data.type || "—"));
      kv("国家", esc(data.country || "—"));
      kv("Handle", esc(data.handle || "—"));
      var remarks = (data.remarks || []).find(function (r) { return r.description && r.description.length; });
      if (remarks) kv("备注", esc(remarks.description.join(" ")));
    } else if (data.handle && /^AS\d+$/i.test(data.handle)) {
      kv("ASN", esc(data.handle));
      kv("名称", esc(data.name || "—"));
      kv("类型", esc((data.type === "DIRECT ALLOCATION" ? "直接分配" : data.type) || "—"));
      kv("注册国家", esc(data.country || "—"));
      var remarks2 = (data.remarks || []).find(function (r) { return r.description && r.description.length; });
      if (remarks2) kv("描述", esc(remarks2.description.join(" ")));
    } else {
      kv("Handle", esc(data.handle || "—"));
      kv("名称", esc(data.name || "—"));
    }
    html += "</div></div>";

    var nsHtml = "";
    (data.nameservers || []).forEach(function (n) {
      if (n.ipAddresses) {
        Object.keys(n.ipAddresses).forEach(function (t) {
          (n.ipAddresses[t] || []).forEach(function (ip) {
            nsHtml += "<a class='split-ip-cell' href='/ip/?q=" + encodeURIComponent(ip) + "' target='_blank' rel='noopener'>" + esc(ip) + "</a>";
          });
        });
      }
    });
    if (nsHtml) {
      html += "<div class='card'><p class='card-title'>域名服务器 IP（点击查评分）</p><div class='split-ip-grid'>" + nsHtml + "</div></div>";
    }

    html += "<div class='card'><p class='card-title'>原始数据</p><details><summary class='muted small' style='cursor:pointer'>展开 JSON</summary><pre>" +
      esc(JSON.stringify(data, null, 2)) + "</pre></details></div>";

    document.getElementById("resultArea").innerHTML = html;
  }

  async function run(q) {
    var area = document.getElementById("resultArea");
    var c = classify(q);
    if (!c) {
      area.innerHTML = "<div class='card'><div class='verdict verdict-bad'>无法识别输入类型，请输入域名、IP 或 ASN（如 AS13335）。</div></div>";
      return;
    }
    var rdapTarget = c.type === "asn" ? "AS" + c.value : c.value;
    area.innerHTML = "<div class='card'><div class='v'><span class='spin'></span> 查询 " + esc(rdapTarget) + " …</div></div>";
    try {
      var res = await rdapQuery(rdapTarget);
      render(res.data, res.via, rdapTarget);
    } catch (e) {
      area.innerHTML = "<div class='card'><div class='verdict verdict-bad'>查询失败：" + esc(e.message) + "</div></div>";
    }
  }

  document.getElementById("form").addEventListener("submit", function (e) {
    e.preventDefault();
    var q = document.getElementById("q").value.trim();
    if (!q) return;
    location.hash = "#q=" + encodeURIComponent(q);
    run(q);
  });

  window.addEventListener("hashchange", function () {
    var m = location.hash.match(/#q=(.+)$/);
    if (m) {
      var q = decodeURIComponent(m[1]);
      document.getElementById("q").value = q;
      run(q);
    }
  });

  (function init() {
    var m = location.hash.match(/#q=(.+)$/);
    if (m) {
      var q = decodeURIComponent(m[1]);
      document.getElementById("q").value = q;
      run(q);
    }
    loadTlds();
  })();

  /* ---------- 支持的域名后缀（IANA 根区真实统计） ---------- */
  var ALL_TLDS = [];
  async function loadTlds() {
    try {
      const r = await fetch("/api/whois/tlds", { signal: AbortSignal.timeout(15000) });
      if (!r.ok) throw new Error("tlds unavailable");
      const d = await r.json();
      ALL_TLDS = d.tlds || [];
      document.getElementById("tldStats").innerHTML =
        "<div class='card'><p class='card-title'>可查询域名后缀</p><div style='font-size:1.9em;font-weight:800;color:var(--good)'>" +
        d.total.toLocaleString() + "</div><div class='muted small'>IANA 根区全部国家域与新通用域</div></div>" +
        "<div class='card'><p class='card-title'>RDAP 直连注册局</p><div style='font-size:1.9em;font-weight:800;color:var(--good)'>" +
        d.rdapCount.toLocaleString() + "</div><div class='muted small'>现代协议、结构化数据、秒级响应</div></div>" +
        "<div class='card'><p class='card-title'>传统 WHOIS 兜底</p><div style='font-size:1.9em;font-weight:800;color:var(--good)'>" +
        Math.max(0, d.total - d.rdapCount).toLocaleString() + "</div><div class='muted small'>无 RDAP 的后缀自动回退 43 端口查询</div></div>" +
        "<div class='card'><p class='card-title'>查询维度</p><div style='font-size:1.9em;font-weight:800;color:var(--good)'>10+</div>" +
        "<div class='muted small'>注册商 / 日期 / 状态 / DNS / DNSSEC / 归属等</div></div>";
      renderTlds("");
    } catch (e) {
      document.getElementById("tldStats").innerHTML =
        "<div class='card'><div class='muted small'>IANA 根区统计暂时不可用（不影响查询功能）</div></div>";
    }
  }

  function renderTlds(filter) {
    var list = filter
      ? ALL_TLDS.filter(function (t) { return t.indexOf(filter) === 0; })
      : ALL_TLDS.slice(0, 120);
    document.getElementById("tldShown").textContent = filter
      ? "匹配 " + list.length + " 个后缀"
      : (ALL_TLDS.length ? "展示前 120 / " + ALL_TLDS.length + " 个，可搜索" : "");
    document.getElementById("tldList").innerHTML = list.slice(0, 200).map(function (t) {
      return "<span class='split-ip-cell'>." + esc(t) + "</span>";
    }).join("");
  }

  document.getElementById("tldSearch").addEventListener("input", function (e) {
    renderTlds(e.target.value.trim().toLowerCase().replace(/^\./, ""));
  });
})();
