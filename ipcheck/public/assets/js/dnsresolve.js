/* ============================================================
   NetProbe — DNS 多渠道解析对比（原创实现）
   通道一（本机直查）：浏览器直接 fetch 开放 CORS 的 DoH JSON API
   通道二（服务器代查）：/api/doh?u=<白名单端点> 由服务器代查
   服务商注册表 REGION 用于地区筛选；结果按「答案集合」对比一致性。
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;

  var PROVIDERS = [
    { id: "google",   name: "Google",       region: "美国", mode: "direct", url: "https://dns.google/resolve?name={n}&type={t}" },
    { id: "cloudflare", name: "Cloudflare", region: "美国", mode: "direct", url: "https://cloudflare-dns.com/dns-query?name={n}&type={t}" },
    { id: "alidns",   name: "AliDNS",       region: "中国", mode: "direct", url: "https://dns.alidns.com/resolve?name={n}&type={t}" },
    { id: "controld", name: "ControlD",     region: "美国", mode: "direct", url: "https://freedns.controld.com/v0/p0?name={n}&type={t}" },
    { id: "adguard",  name: "AdGuard",      region: "全球", mode: "proxy",  url: "https://dns.adguard-dns.com/resolve?name={n}&type={t}" },
    { id: "quad9",    name: "Quad9",        region: "瑞士", mode: "proxy",  url: "https://dns.quad9.net:5053/dns-query?name={n}&type={t}" },
    { id: "dnspod",   name: "DNSPod",       region: "中国", mode: "proxy",  url: "https://doh.pub/dns-query?name={n}&type={t}" },
    { id: "dnssb",    name: "DNS.SB",       region: "欧洲", mode: "proxy",  url: "https://doh.sb/dns-query?name={n}&type={t}" },
    { id: "dns0",     name: "dns0.eu",      region: "欧盟", mode: "proxy",  url: "https://dns0.eu/resolve?name={n}&type={t}" },
  ];
  var REGIONS = ["全部", "美国", "中国", "欧洲", "欧盟", "瑞士", "全球"];
  var curRegion = "全部";

  function regionBar() {
    document.getElementById("regionBar").innerHTML = REGIONS.map(function (r) {
      var n = r === "全部" ? PROVIDERS.length : PROVIDERS.filter(function (p) { return p.region === r; }).length;
      if (r !== "全部" && n === 0) return "";
      return "<button class='btn btn-ghost small" + (r === curRegion ? " active" : "") + "' data-region='" + r + "'>" +
        r + " (" + (r === "全部" ? n : n) + ")</button>";
    }).join("");
    document.querySelectorAll("[data-region]").forEach(function (b) {
      b.addEventListener("click", function () {
        curRegion = b.dataset.region;
        regionBar();
        filterRows();
      });
    });
  }

  function activeProviders() {
    return curRegion === "全部" ? PROVIDERS : PROVIDERS.filter(function (p) { return p.region === curRegion; });
  }

  function cleanDomain(raw) {
    var s = (raw || "").trim();
    s = s.replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
    s = s.replace(/:\d+$/, "");
    return s;
  }

  async function queryProvider(p, name, type, forceProxy) {
    var url = p.url.replace("{n}", encodeURIComponent(name)).replace("{t}", encodeURIComponent(type));
    var fetchUrl = p.mode === "proxy" || forceProxy ? "/api/doh?u=" + encodeURIComponent(url) : url;
    const r = await fetch(fetchUrl, {
      headers: { accept: "application/dns-json" },
      cache: "no-store",
      signal: AbortSignal.timeout(9000),
    });
    if (!r.ok) throw new Error("HTTP " + r.status);
    var d = await r.json();
    if (typeof d.Status !== "number") throw new Error("bad payload");
    return d;
  }

  function answersOf(d) {
    var out = [];
    (d.Answer || []).forEach(function (a) {
      var data = a.data == null ? "" : String(a.data);
      if (a.type === 6) return; // SOA 不展示
      out.push({ type: a.type, data: data.replace(/^"|"$/g, ""), ttl: a.TTL });
    });
    return out;
  }

  function fmtType(t) {
    return ({ 1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA" })[t] || t;
  }

  function renderRow(p, state, fallback) {
    var tr = document.getElementById("row-" + p.id);
    if (!tr) return;
    var cell = tr.querySelector(".res-cell");
    var ttlCell = tr.querySelector(".ttl-cell");
    if (state === "pending") { cell.innerHTML = "<span class='spin'></span>"; ttlCell.textContent = "—"; return; }
    if (state === "fail") {
      cell.innerHTML = "<span class='error-text small'>查询失败/超时</span>";
      ttlCell.textContent = "—";
      return;
    }
    var ans = state.ans;
    var d = state.d;
    if (!ans.length) {
      cell.innerHTML = d.Status === 3
        ? "<span class='muted small'>NXDOMAIN（域名不存在）</span>"
        : "<span class='muted small'>无记录（Status " + d.Status + "）</span>";
      ttlCell.textContent = "—";
      return;
    }
    if (fallback) {
      var modeCell = tr.querySelector("td:last-child");
      if (modeCell) modeCell.innerHTML = "<span class='pill pill-muted'>直查失败→代查</span>";
    }
    var parts = ans.map(function (a) {
      var txt = a.data.length > 90 ? a.data.slice(0, 90) + "…" : a.data;
      return "<span class='pill pill-muted' style='margin:1px 4px 1px 0'>" + fmtType(a.type) + "</span>" + esc(txt);
    });
    cell.innerHTML = parts.join("<br>");
    var ttls = ans.map(function (a) { return a.ttl; }).filter(function (x) { return typeof x === "number"; });
    ttlCell.textContent = ttls.length ? Math.min.apply(null, ttls) + "s" : "—";
  }

  function buildTable(list) {
    var html = list.map(function (p) {
      var modeBadge = p.mode === "direct"
        ? "<span class='pill pill-good'>本机直查</span>"
        : "<span class='pill pill-muted'>服务器代查</span>";
      return "<tr id='row-" + p.id + "' data-region='" + p.region + "'>" +
        "<td><b>" + esc(p.name) + "</b> " + NP.flag(regionCC(p.region), "split-flag") +
        " <span class='muted small'>" + esc(p.region) + "</span></td>" +
        "<td class='res-cell'><span class='spin'></span></td>" +
        "<td class='ttl-cell muted small'>—</td>" +
        "<td>" + modeBadge + "</td></tr>";
    }).join("");
    document.getElementById("resBody").innerHTML = html;
  }

  function regionCC(r) {
    return ({ "美国": "us", "中国": "cn", "欧洲": "eu", "欧盟": "eu", "瑞士": "ch", "全球": "" })[r] || "";
  }

  function filterRows() {
    document.querySelectorAll("#resBody tr").forEach(function (tr) {
      tr.style.display = curRegion === "全部" || tr.dataset.region === curRegion ? "" : "none";
    });
  }

  function setConsistency(list, results) {
    // 对比：所有成功行的答案集合是否一致
    var keys = [];
    list.forEach(function (p) {
      var st = results[p.id];
      if (!st || st === "pending" || st === "fail") return;
      if (!st.ans.length) return;
      keys.push(st.ans.map(function (a) { return a.type + ":" + a.data; }).sort().join("|"));
    });
    var uniq = Array.from(new Set(keys));
    var el = document.getElementById("consistency");
    if (keys.length < 2) { el.textContent = "样本不足"; el.className = "badge"; return; }
    if (uniq.length === 1) { el.textContent = "全部一致 ✓"; el.className = "badge badge-static"; }
    else { el.textContent = uniq.length + " 组不同结果"; el.className = "badge badge-international"; }
  }

  async function run() {
    var name = cleanDomain(document.getElementById("domain").value);
    var type = document.getElementById("rtype").value;
    var btn = document.getElementById("runBtn");
    if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/.test(name)) {
      document.getElementById("progressText").textContent = "请输入合法域名（如 github.com）";
      return;
    }
    btn.disabled = true;
    var list = activeProviders();
    document.getElementById("resultCard").style.display = "";
    buildTable(list);
    filterRows();
    document.getElementById("consistency").textContent = "检测中…";
    document.getElementById("note").style.display = list.some(function (p) { return p.mode === "proxy"; }) ? "" : "none";
    document.getElementById("progressText").textContent = "并行查询 " + list.length + " 家服务商…";

    var results = {};
    await NP.withLimit(list, 5, async function (p) {
      try {
        var d = await queryProvider(p, name, type, false);
        results[p.id] = { d: d, ans: answersOf(d), fb: false };
        renderRow(p, results[p.id]);
      } catch (e) {
        // 直查失败（网络/被墙）时自动改走服务器代查一次
        if (p.mode === "direct") {
          try {
            var d2 = await queryProvider(p, name, type, true);
            results[p.id] = { d: d2, ans: answersOf(d2), fb: true };
            renderRow(p, results[p.id], true);
            return;
          } catch (e2) { /* 仍然失败 */ }
        }
        results[p.id] = "fail";
        renderRow(p, "fail");
      }
    });

    setConsistency(list, results);
    var okN = list.filter(function (p) { return results[p.id] && results[p.id] !== "pending" && results[p.id] !== "fail"; }).length;
    document.getElementById("progressText").textContent = "完成：成功 " + okN + " / " + list.length + " 家（域名 " + esc(name) + " · " + type + "）";
    btn.disabled = false;
  }

  document.getElementById("runBtn").addEventListener("click", run);
  document.getElementById("domain").addEventListener("keydown", function (e) { if (e.key === "Enter") run(); });
  regionBar();
  // 预填并自动跑一次示例，让页面打开即有内容
  document.getElementById("domain").value = "github.com";
  run();
})();
