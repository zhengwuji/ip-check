/* ============================================================
   NetProbe — DNS 泄露检测（原创实现）
   快速/深度测试：
     1) 真实泄露测试：浏览器请求随机子域名触发本机 DNS 解析，
        权威侧记录查询来源（优先自托管 DNS_ZONE；否则用 ipleak.net
        唯一子域名 + 本站后端代理读取结果）。
     2) DoH 对照：浏览器分别通过各家公共 DoH 解析
        o-o.myaddr.l.google.com 的 TXT 回显（部分服务商无 CORS 会失败）。
   深度测试 = 3 轮独立 token + 全部 DoH 对照；快速测试 = 1 轮 + 2 家对照。
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;

  var dohProviders = [
    { name: "AliDNS", url: "https://dns.alidns.com/resolve?name=o-o.myaddr.l.google.com&type=TXT" },
    { name: "Google", url: "https://dns.google/resolve?name=o-o.myaddr.l.google.com&type=TXT" },
    { name: "Cloudflare", url: "https://cloudflare-dns.com/dns-query?name=o-o.myaddr.l.google.com&type=TXT" },
    // Quad9 已移除：其 JSON 接口既不开放 CORS，也过滤 Cloudflare Workers 出口段（5053/443/dns11 均超时），
    // 站点跑在 CF Workers 上时代查不通；恢复 VPS 部署时可重新加回（/api/doh 白名单已保留）。
    { name: "AdGuard", url: "https://dns.adguard-dns.com/resolve?name=o-o.myaddr.l.google.com&type=TXT", proxy: true },
    { name: "DNSPod", url: "https://doh.pub/dns-query?name=o-o.myaddr.l.google.com&type=TXT", proxy: true },
  ];

  function randomToken() {
    var s = "";
    var chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    for (var i = 0; i < 22; i++) s += chars[Math.floor(Math.random() * chars.length)];
    return s;
  }

  function setProgress(pct, text) {
    document.querySelector("#progress i").style.width = pct + "%";
    document.getElementById("progressText").textContent = text || "";
  }

  async function renderResolvers(list) {
    document.getElementById("resolverCard").style.display = "";
    // 并发补齐每个解析器出口的归属信息
    await Promise.allSettled(list.map(async function (x) {
      if (x.ip && !x.geoText) {
        var g = await GEO.lookup(x.ip).catch(function () { return null; });
        if (g) x.geoText = { cc: g.countryCode, text: [g.country, g.city, g.isp].filter(Boolean).join(" ") };
      }
    }));
    var html = list.map(function (x) {
      var ip = x.ip || (typeof x === "string" ? x : "");
      var hits = x.hits ? " <span class='muted small'>(" + esc(String(x.hits)) + " hits)</span>" : "";
      var geoHtml = "";
      if (x.geoText) {
        geoHtml = "<br>" + NP.flag(x.geoText.cc) + " <span class='muted small'>" + esc(x.geoText.text) + "</span>";
      }
      return "<div class='kv' style='margin-bottom:8px'><div class='k'>解析器出口</div><div class='v ip-cell'>" +
        esc(ip || "未知") + hits + geoHtml + "</div></div>";
    }).join("");
    document.getElementById("resolverList").innerHTML = html || "<p class='muted small'>未捕获到解析记录</p>";
  }

  function renderDoh(rows) {
    document.getElementById("dohCard").style.display = "";
    document.getElementById("dohBody").innerHTML = rows.map(function (r) {
      var nameHtml = esc(r.name) + (r.proxied ? " <span class='muted small'>· 服务器代查</span>" : "");
      var failText = r.proxied ? "查询失败（服务器代查未成功）" : "查询失败（该服务商未开放跨域访问）";
      return "<tr><td>" + nameHtml + "</td><td class='ip-cell'>" +
        (r.value === null ? "<span class='error-text'>" + failText + "</span>" : esc(r.value)) +
        "</td><td class='geo-cell'>" + esc(r.geo || "") + "</td></tr>";
    }).join("");
    var anyProxied = rows.some(function (r) { return r.proxied; });
    var note = document.getElementById("dohNote");
    if (note) note.style.display = anyProxied ? "" : "none";
  }

  /* ---------- 真实泄露测试 ---------- */
  // ipleak 检测节点：对 {token}-{n}.ipleak.net/dnsdetection/ 发起请求，
  // 该请求会触发浏览器本机 DNS 解析唯一子域名，权威侧记录解析器来源，
  // 并在响应中直接返回 {ip: {解析器IP: 次数}}（该接口开放 CORS）。
  async function leakTestOnce(rounds) {
    var cfg = null;
    try {
      cfg = await NP.fetchT("/api/dns/config", null, 4000).then(function (r) { return r.ok ? r.json() : null; });
    } catch (e) {}

    if (cfg && cfg.enabled && cfg.zone) {
      // 自托管：请求 {token}.{zone}，本机权威 DNS 记录来源
      var token = randomToken();
      for (var j = 0; j < 3; j++) {
        var img = new Image();
        img.src = "https://" + token + "-" + j + "." + cfg.zone + "/pixel.gif?_=" + Date.now();
        img.onload = img.onerror = function () {};
      }
      await new Promise(function (r) { setTimeout(r, 4500); });
      var r = await NP.fetchT("/api/dns/result/" + token, null, 6000).catch(function () { return null; });
      if (r && r.ok) {
        var d = await r.json();
        return { mode: "自托管权威 DNS（" + cfg.zone + "）", resolvers: (d.resolvers || []).map(function (x) { return typeof x === "string" ? { ip: x } : x; }) };
      }
      return { mode: "自托管权威 DNS", resolvers: [] };
    }

    // ipleak.net 多轮检测
    var token2 = randomToken();
    var found = new Map();
    var okAny = false;
    for (var i = 1; i <= (rounds || 5); i++) {
      try {
        const resp = await NP.fetchT("https://" + token2 + "-" + i + ".ipleak.net/dnsdetection/?_=" + Date.now(), null, 6000);
        const data = await resp.json();
        okAny = true;
        if (data && !Array.isArray(data) && data.ip) {
          Object.keys(data.ip).forEach(function (ip) {
            if (!found.has(ip)) found.set(ip, { ip: ip, hits: data.ip[ip] });
          });
        }
      } catch (e) { /* 单轮失败忽略 */ }
      setProgress(10 + Math.round((i / (rounds || 5)) * 35), "唯一子域名解析中（" + i + "/" + (rounds || 5) + "）…");
    }
    if (!okAny) throw new Error("leak-unavailable");
    return { mode: "公共检测节点（ipleak.net）", resolvers: [...found.values()] };
  }

  /* ---------- DoH TXT 回显对照 ---------- */
  async function dohEcho(names) {
    var rows = [];
    var list = dohProviders.filter(function (p) { return !names || names.indexOf(p.name) !== -1; });
    for (var i = 0; i < list.length; i++) {
      var p = list[i];
      var entry = { name: p.name, value: null, geo: null, proxied: !!p.proxy };
      try {
        // 先本机直查（CORS 且网络可达时，反映本机真实 DNS 出口）；失败则回退服务器代查
        var d = null, proxied = false;
        if (!p.proxy) {
          try {
            const r = await NP.fetchT(p.url, { headers: { accept: "application/dns-json" } }, 6000);
            const dd = await r.json();
            if (r.ok && dd && !dd.error) d = dd;
          } catch (e) {}
        }
        if (!d) {
          const target = "/api/doh?u=" + encodeURIComponent(p.url);
          const r2 = await NP.fetchT(target, null, 9000);
          d = await r2.json();
          if (!r2.ok || !d || d.error) throw new Error((d && d.error) || "HTTP " + r2.status);
          proxied = true;
        }
        entry.proxied = proxied;
        var txts = [];
        (d.Answer || []).forEach(function (a) {
          if (a.type === 16) txts.push(String(a.data).replace(/^"|"$/g, ""));
        });
        entry.value = txts.join(" ") || "（无 TXT 回显）";
        var ipM = entry.value.match(/\d{1,3}(?:\.\d{1,3}){3}/) || entry.value.match(/(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}/);
        if (ipM) {
          var g = await GEO.lookup(ipM[0]).catch(function () { return null; });
          if (g) entry.geo = [g.country, g.city, g.isp].filter(Boolean).join(" ");
        }
      } catch (e) {}
      rows.push(entry);
      setProgress(55 + Math.round(((i + 1) / list.length) * 40), "DoH 对照 " + (i + 1) + "/" + list.length);
      renderDoh(rows);
    }
    return rows;
  }

  async function loadSelfIp() {
    try {
      const t = await NP.selfTrace();
      if (!t) throw new Error("no exit ip");
      var g = await GEO.lookup(t.ip).catch(function () { return null; });
      document.getElementById("selfIp").innerHTML =
        "<div class='kv'><div class='k'>出口 IP</div><div class='v ip-cell'>" + esc(t.ip) + "</div></div>" +
        "<div class='kv'><div class='k'>国家/地区</div><div class='v'>" + esc(g ? g.country : (t.loc || "未知")) + "</div></div>" +
        "<div class='kv'><div class='k'>ISP</div><div class='v'>" + esc(g ? g.isp : "") + "</div></div>";
    } catch (e) {
      document.getElementById("selfIp").innerHTML = "<p class='error-text small'>获取本机出口失败</p>";
    }
  }

  async function start(deep) {
    var btns = [document.getElementById("fastBtn"), document.getElementById("deepBtn")];
    btns.forEach(function (b) { b.disabled = true; });
    document.getElementById("verdictArea").innerHTML = "";
    document.getElementById("resolverCard").style.display = "none";
    setProgress(5, "准备中…");
    loadSelfIp();

    var allResolvers = [];
    var mode = "";
    var rounds = deep ? 12 : 5;
    var leakFailed = false;
    for (var i = 0; i < (deep ? 3 : 1); i++) {
      setProgress(10 + Math.round((i / (deep ? 3 : 1)) * 40), "唯一子域名解析中…");
      try {
        var res = await leakTestOnce(rounds);
        mode = res.mode;
        allResolvers = allResolvers.concat(res.resolvers);
      } catch (e) {
        leakFailed = true;
      }
    }
    // 去重
    var seen = new Map();
    allResolvers.forEach(function (x) {
      if (x && x.ip && !seen.has(x.ip)) seen.set(x.ip, x);
    });
    var uniq = [...seen.values()];

    setProgress(55, "DoH 出口对照中…");
    await dohEcho(deep ? null : ["AliDNS", "Google"]);
    setProgress(100, "完成");

    var verdict;
    if (leakFailed && uniq.length === 0) {
      verdict = "<div class='verdict verdict-warn'>△ 泄露测试节点暂时不可用（可能被网络拦截）。可参考下方 DoH 对照表判断你的 DNS 出口。</div>";
    } else if (uniq.length === 0) {
      verdict = "<div class='verdict verdict-safe'>✓ 未检测到 DNS 解析器出口 IP——你的 DNS 很可能已加密（DoH/DoT），权威 DNS 没有收到来自你的明文查询。若你正在使用 Clash 等代理客户端的 fake-IP 模式，本机 DNS 已被客户端接管，同样会得到此结果。</div>";
      document.getElementById("resolverCard").style.display = "none";
    } else {
      var html = "<div class='verdict " + (uniq.length > 3 ? "verdict-warn" : "verdict-safe") + "'>" +
        "检测到 " + uniq.length + " 个 DNS 解析出口（" + esc(mode) + "）。";
      html += uniq.length > 3
        ? "出口数量偏多，若你正在使用代理/VPN，可能存在 DNS 泄露。"
        : "出口数量正常。若使用代理/VPN，请核对这些出口是否属于代理服务商。";
      html += "</div>";
      verdict = html;
      await renderResolvers(uniq);
    }
    document.getElementById("verdictArea").innerHTML = verdict;
    btns.forEach(function (b) { b.disabled = false; });
  }

  document.getElementById("fastBtn").addEventListener("click", function () { start(false); });
  document.getElementById("deepBtn").addEventListener("click", function () { start(true); });
})();
