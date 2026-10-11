/* ============================================================
   NetProbe — 全球 Ping（原创实现）
   模式一：后端代理 check-host.net，从全球节点 ICMP Ping 目标，
           轮询结果并展示各节点 min/avg/max。受限时给出降级提示。
   模式二：浏览器对各大 Anycast 网络端点做 12 轮 HTTP 探测取中位。
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;

  var NETWORKS = [
    { name: "Cloudflare", domain: "cloudflare.com", url: "https://1.1.1.1/cdn-cgi/trace", region: "全球 Anycast" },
    { name: "Google", domain: "google.com", url: "https://www.google.com/generate_204", region: "全球 Anycast" },
    { name: "Fastly", domain: "fastly.com", url: "https://fastly.jsdelivr.net/favicon.ico", region: "全球 CDN" },
    { name: "AWS CloudFront", domain: "aws.amazon.com", url: "https://d1.awsstatic.com/favicon.ico", region: "全球 CDN" },
    { name: "Akamai", domain: "akamai.com", url: "https://www.akamai.com/favicon.ico", region: "全球 CDN" },
    { name: "Gcore", domain: "gcore.com", url: "https://gcore.com/favicon.ico", region: "全球 CDN" },
    { name: "Cloudflare 中国", domain: "cloudflare-cn.com", url: "https://www.cloudflare-cn.com/favicon.ico", region: "中国大陆" },
    { name: "阿里云", domain: "aliyun.com", url: "https://www.aliyun.com/favicon.ico", region: "中国大陆" },
    { name: "腾讯云", domain: "tencent.com", url: "https://cloud.tencent.com/favicon.ico", region: "中国大陆" },
    { name: "百度", domain: "baidu.com", url: "https://www.baidu.com/favicon.ico", region: "中国大陆" },
    { name: "阿里 DNS", domain: "alidns.com", url: "https://dns.alidns.com/favicon.ico", region: "中国大陆" },
    { name: "Wikipedia", domain: "wikipedia.org", url: "https://www.wikipedia.org/static/favicon/wikipedia.ico", region: "欧洲/全球" },
  ];

  var REGION_ORDER = ["亚洲", "美洲", "欧洲", "大洋洲", "其他"];
  var runToken = 0;
  function freshToken() { return ++runToken; }
  var ROUNDS = 12;
  var history = NETWORKS.map(function () { return []; });

  /* ---------- 模式一：全球节点 ---------- */
  function summarize(pings) {
    if (!pings || !pings.length) return null;
    var ok = pings.filter(function (x) { return Array.isArray(x) && x.length >= 1; });
    // check-host 返回每个节点若干次 ICMP 的 [time, ttl]
    var times = [];
    ok.forEach(function (arr) {
      arr.forEach(function (t) {
        var v = Array.isArray(t) ? t[0] : t;
        var num = parseFloat(v);
        if (!isNaN(num)) times.push(num);
      });
    });
    if (!times.length) return null;
    times.sort(function (a, b) { return a - b; });
    var sum = times.reduce(function (a, b) { return a + b; }, 0);
    return {
      min: times[0],
      avg: sum / times.length,
      max: times[times.length - 1],
      n: times.length,
    };
  }

  var NODE_CITY_CN = {
    Vienna: "维也纳", Vancouver: "温哥华", Nuremberg: "纽伦堡", Madrid: "马德里",
    Budapest: "布达佩斯", Warsaw: "华沙", Bucharest: "布加勒斯特", Moscow: "莫斯科",
    Stockholm: "斯德哥尔摩", Kyiv: "基辅", Amsterdam: "阿姆斯特丹", Paris: "巴黎",
    London: "伦敦", Frankfurt: "法兰克福", Helsinki: "赫尔辛基", Istanbul: "伊斯坦布尔",
    "Tel Aviv": "特拉维夫", Mumbai: "孟买", Jakarta: "雅加达", Singapore: "新加坡",
    Tokyo: "东京", Seoul: "首尔", Sydney: "悉尼", "Los Angeles": "洛杉矶",
    "New York": "纽约", Chicago: "芝加哥", Dallas: "达拉斯", Atlanta: "亚特兰大",
    Toronto: "多伦多", Montreal: "蒙特利尔", "Sao Paulo": "圣保罗", Santiago: "圣地亚哥",
    "Buenos Aires": "布宜诺斯艾利斯", "Mexico City": "墨西哥城", Johannesburg: "约翰内斯堡",
    Cairo: "开罗", Dubai: "迪拜", Tehran: "德黑兰", Almaty: "阿拉木图",
    Hongkong: "中国香港", HongKong: "中国香港", Shanghai: "上海", Beijing: "北京",
    "Kuala Lumpur": "吉隆坡", Bangkok: "曼谷", Manila: "马尼拉", Taipei: "台北",
    Osaka: "大阪", Zurich: "苏黎世", Milan: "米兰", Prague: "布拉格", Oslo: "奥斯陆",
    Copenhagen: "哥本哈根", Dublin: "都柏林", Lisbon: "里斯本", Riga: "里加",
    Tallinn: "塔林", Vilnius: "维尔纽斯", Sofia: "索菲亚", Belgrade: "贝尔格莱德",
    Zagreb: "萨格勒布", Athens: "雅典", Berlin: "柏林", Munich: "慕尼黑",
  };

  function nodeLocationName(nodeKey) {
    return nodeKey.split(".")[0];
  }

  var NODE_REGION = {
    de: "欧洲", nl: "欧洲", fr: "欧洲", se: "欧洲", ch: "欧洲", es: "欧洲", pl: "欧洲", it: "欧洲", uk: "欧洲", gb: "欧洲", ru: "欧洲", ua: "欧洲", at: "欧洲", fi: "欧洲", no: "欧洲", dk: "欧洲", cz: "欧洲", ro: "欧洲", hu: "欧洲", bg: "欧洲",
    us: "美洲", ca: "美洲", br: "美洲", mx: "美洲", ar: "美洲", cl: "美洲",
    cn: "亚洲", jp: "亚洲", hk: "亚洲", sg: "亚洲", in: "亚洲", id: "亚洲", vn: "亚洲", th: "亚洲", kr: "亚洲", my: "亚洲", ph: "亚洲", il: "亚洲", tr: "亚洲", ae: "亚洲", sa: "亚洲", ir: "亚洲", pk: "亚洲", tw: "亚洲", kz: "亚洲", ir1: "亚洲",
    au: "大洋洲", nz: "大洋洲",
    za: "其他", eg: "其他", ng: "其他", ke: "其他",
  };
  var REGION_NAMES = { "亚洲": "🌏 亚洲", "美洲": "🌎 美洲", "欧洲": "🌍 欧洲", "大洋洲": "🌏 大洋洲", "其他": "🌍 其他" };

  async function runNodePing(target) {
    var myTok = freshToken();
    document.getElementById("nodeArea").innerHTML =
      "<div class='card'><p class='card-title'>全球节点 Ping：" + esc(target) + "</p>" +
      "<div class='v'><span class='spin'></span> 正在分发检测任务…</div></div>";
    document.getElementById("rttArea").style.display = "none";
    setProgress(5, "分发任务…");

    var start;
    try {
      const r = await fetch("/api/ping/start?host=" + encodeURIComponent(target), { signal: AbortSignal.timeout(15000) });
      start = await r.json();
    } catch (e) {
      start = { error: "dispatch_failed" };
    }
    if (start.error) {
      if (start.error === "private_target") {
        document.getElementById("nodeArea").innerHTML =
          "<div class='card'><div class='verdict verdict-warn'>目标 " + esc(target) + " 是内网/回环地址，无法从公网节点 Ping。</div></div>";
      } else {
        document.getElementById("nodeArea").innerHTML =
          "<div class='card'><div class='verdict verdict-warn'>全球节点暂时受限（" + esc(start.error) + "），已自动切换为「本机延迟测试」。</div></div>";
        runRtt();
      }
      return;
    }
    var requestId = start.request_id;
    var nodes = Object.keys(start.nodes || {});
    var nodeMeta = start.nodes || {}; // nk → [cc, country, city, ip, asn]
    var results = {}; // nodeKey → summary | "pending" | "unavailable"

    function nodeName(nk) {
      var meta = nodeMeta[nk] || [];
      var city = meta[2] || "";
      var cn = NODE_CITY_CN[city];
      var cc = meta[0] || "";
      var label = cn || city || nodeLocationName(nk);
      return NP.flag(cc, "split-flag") + " " + esc(label) + " <span class='muted small'>" + esc(cc.toUpperCase()) + "</span>";
    }

    function renderNodes(done) {
      // 分组
      var groups = {};
      nodes.forEach(function (nk) {
        var cc = nodeLocationName(nk).replace(/\d+$/, "");
        var region = NODE_REGION[cc] || "其他";
        (groups[region] = groups[region] || []).push(nk);
      });
      var html = "<div class='card'><p class='card-title'>全球节点 Ping：" + esc(target) +
        "（" + nodes.length + " 节点）</p>";
      html += "<div class='tbl-wrap'><table class='tbl' style='min-width:560px'><thead><tr><th>节点</th><th style='width:90px'>最小</th><th style='width:90px'>平均</th><th style='width:90px'>最大</th></tr></thead><tbody>";
      REGION_ORDER.forEach(function (region) {
        if (!groups[region]) return;
        html += "<tr><td colspan='4' style='background:var(--bg-soft);font-weight:700'>" + REGION_NAMES[region] + "</td></tr>";
        groups[region].forEach(function (nk) {
          var s = results[nk];
          var stat = s === undefined ? "<span class='spin'></span>"
            : s === "pending" ? "<span class='muted small'>检测中…</span>"
            : s === "unavailable" ? "<span class='error-text small'>不可用</span>"
            : "<span style='color:var(--good)'>" + s.min.toFixed(1) + " / " + s.avg.toFixed(1) + " / " + s.max.toFixed(1) + " ms</span>";
          html += "<tr><td>" + nodeName(nk) + "</td><td colspan='3'>" + stat + "</td></tr>";
        });
      });
      html += "</tbody></table></div></div>";
      document.getElementById("nodeArea").innerHTML = html;
    }
    renderNodes();

    // 轮询结果（最多 45 秒）
    for (var i = 0; i < 18 && myTok === runToken; i++) {
      await new Promise(function (r) { setTimeout(r, 2500); });
      setProgress(Math.min(95, (i + 1) * 6), "收集节点结果…（" + (i + 1) + "/18）");
      var d;
      try {
        const rr = await fetch("/api/ping/result/" + requestId, { signal: AbortSignal.timeout(12000) });
        d = await rr.json();
      } catch (e) { continue; }
      var pending = 0;
      nodes.forEach(function (nk) {
        var v = d[nk];
        if (v === undefined) { pending++; results[nk] = results[nk] === "unavailable" ? "unavailable" : "pending"; return; }
        if (v && Array.isArray(v)) {
          var s = summarize(v);
          results[nk] = s || "unavailable";
        } else {
          results[nk] = "unavailable";
        }
      });
      renderNodes();
      if (pending === 0) break;
    }
    setProgress(100, "完成");
  }

  /* ---------- 模式二：本机 Anycast RTT ---------- */
  async function probe(url) {
    var t0 = performance.now();
    try {
      await fetch(url, { mode: "no-cors", cache: "no-store", signal: AbortSignal.timeout(3000) });
      return Math.round(performance.now() - t0);
    } catch (e) { return -1; }
  }

  function rttColor(ms) {
    if (ms < 0) return "var(--bad)";
    if (ms < 100) return "var(--good)";
    if (ms < 300) return "#3fae5f";
    if (ms < 800) return "#e0b341";
    return "var(--warn)";
  }

  function renderRttRows() {
    document.getElementById("tbody").innerHTML = NETWORKS.map(function (n, i) {
      return "<tr id='pr-" + i + "'><td><div class='site-cell'>" + NP.favicon(n.domain, n.name) +
        "<div><span class='site-name'>" + esc(n.name) + "</span> <span class='muted small'>" + esc(n.region) + "</span></div></div></td>" +
        "<td class='med-cell' style='color:var(--text-muted);font-weight:600'>--</td>" +
        "<td class='rounds-cell small muted' style='display:none'></td></tr>";
    }).join("");
  }

  function updateRttRow(i) {
    var row = document.getElementById("pr-" + i);
    if (!row) return;
    var med = NP.median(history[i]);
    var medCell = row.querySelector(".med-cell");
    if (med >= 0) {
      medCell.textContent = med + "ms";
      medCell.style.color = rttColor(med);
    } else {
      medCell.textContent = "超时";
      medCell.style.color = rttColor(-1);
    }
    row.querySelector(".rounds-cell").textContent = history[i].join(" ") || "--";
  }

  async function runRtt() {
    var myTok = freshToken();
    document.getElementById("nodeArea").innerHTML = "";
    document.getElementById("rttArea").style.display = "";
    history = NETWORKS.map(function () { return []; });
    renderRttRows();

    await Promise.allSettled(NETWORKS.map(function (n) { return probe(n.url); }));
    for (var round = 0; round < ROUNDS && myTok === runToken; round++) {
      await Promise.allSettled(NETWORKS.map(async function (n, i) {
        var ms = await probe(n.url);
        if (ms >= 0) history[i].push(ms);
        updateRttRow(i);
      }));
      setProgress(Math.round(((round + 1) / ROUNDS) * 100), "第 " + (round + 1) + " / " + ROUNDS + " 轮");
    }
    setProgress(100, "完成");
  }

  /* ---------- 模式三：Globalping 探针（ping / traceroute） ---------- */
  var GP_COUNTRIES = ["US", "DE", "GB", "JP", "SG", "HK", "TW", "AU", "BR", "IN", "RU", "ZA"];
  var GP_CC_NAME = {
    US: "美国", DE: "德国", GB: "英国", JP: "日本", SG: "新加坡", HK: "中国香港",
    TW: "中国台湾", AU: "澳大利亚", BR: "巴西", IN: "印度", RU: "俄罗斯", ZA: "南非",
  };

  async function gpRun(type, target) {
    var myTok = freshToken();
    var area = document.getElementById("nodeArea");
    document.getElementById("rttArea").style.display = "none";
    var typeName = type === "mtr" || type === "traceroute" ? "路由追踪" : "Ping";
    area.innerHTML = "<div class='card'><p class='card-title'>Globalping " + typeName + "：" + esc(target) + "</p>" +
      "<div class='v'><span class='spin'></span> 正在向 " + GP_COUNTRIES.length + " 个国家的探针分发任务…</div></div>";
    setProgress(5, "分发任务…");

    var id;
    try {
      const r = await fetch("https://api.globalping.io/v1/measurements", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          type: type,
          target: target,
          locations: GP_COUNTRIES.map(function (cc) { return { country: cc }; }),
          limit: 1,
        }),
        signal: AbortSignal.timeout(15000),
      });
      if (r.status === 429) throw new Error("探针网络限额已用尽（匿名每小时限量），请稍后再试");
      if (!r.ok) throw new Error("HTTP " + r.status);
      id = (r.headers.get("Location") || "").split("/").pop() || "";
      if (!id) throw new Error("未返回任务 ID");
    } catch (e) {
      area.innerHTML = "<div class='card'><div class='verdict verdict-warn'>Globalping 任务分发失败：" + esc(e.message || String(e)) + "。可改用「全球节点 Ping」或「本机延迟测试」。</div></div>";
      setProgress(100, "");
      return;
    }

    var d = null;
    for (var i = 0; i < 20 && myTok === runToken; i++) {
      await new Promise(function (r) { setTimeout(r, 2500); });
      setProgress(Math.min(95, (i + 1) * 5), "收集探针结果…（" + (i + 1) + "/20）");
      try {
        var cur = await fetch("https://api.globalping.io/v1/measurements/" + id, { cache: "no-store", signal: AbortSignal.timeout(12000) });
        d = await cur.json();
        if (d.status === "finished") break;
      } catch (e) { /* 继续轮询 */ }
    }
    if (!d || d.status !== "finished") {
      area.innerHTML = "<div class='card'><div class='verdict verdict-warn'>探针结果收集超时，请稍后重试。</div></div>";
      setProgress(100, "");
      return;
    }

    var html = "<div class='card'><p class='card-title'>Globalping " + typeName + "：" + esc(target) + "（" + (d.results || []).length + " 个探针）</p>";
    html += "<div class='tbl-wrap'><table class='tbl' style='min-width:640px'><thead><tr><th style='min-width:150px'>探针</th><th>" + (typeName === "路由追踪" ? "路径 / 汇总" : "延迟") + "</th></tr></thead><tbody>";
    (d.results || []).forEach(function (pr) {
      var probe = pr.probe || {};
      var cc = probe.country || "";
      var where = (probe.city || "") + (probe.network ? " · " + probe.network.replace(/\s*\(.*\)$/, "") : "");
      var res = pr.result || {};
      var stat = res.status === "finished" ? "<span class='pill pill-good'>完成</span>" : "<span class='pill pill-bad'>" + esc(res.status || "失败") + "</span>";
      var body = "";
      if (typeName === "路由追踪") {
        var hops = (res.hops || []);
        var lines = hops.map(function (h, hi) {
          var rtts = (h.timings || []).map(function (t) { return t && t.rtt; }).filter(function (v) { return typeof v === "number"; });
          var rttTxt = rtts.length ? Math.min.apply(null, rtts).toFixed(1) + "ms" : "";
          return "#" + (hi + 1) + " " + (h.resolvedAddress || "*") + (h.resolvedHostname ? " (" + h.resolvedHostname + ")" : "") + " " + rttTxt;
        });
        body = lines.length ? lines.join("<br>") : "<span class='muted small'>" + esc((res.rawOutput || "无数据").slice(0, 400)) + "</span>";
      } else {
        var stats = (pr.result || {}).stats || {};
        function statVal(v) { return typeof v === "number" ? v : Array.isArray(v) ? v[0] : null; }
        var avg = statVal(stats.avg);
        var min = statVal(stats.min);
        var max = statVal(stats.max);
        body = avg != null
          ? "<span style='color:var(--good)'>" + (min != null ? min.toFixed(1) : "?") + " / " + avg.toFixed(1) + " / " + (max != null ? max.toFixed(1) : "?") + " ms</span>"
          : "<span class='muted small'>无数据</span>";
      }
      html += "<tr><td>" + NP.flag(cc.toLowerCase()) + " " + esc(GP_CC_NAME[cc] || cc) +
        "<br><span class='muted small'>" + esc(where) + "</span></td>" +
        "<td>" + stat + " " + body + "</td></tr>";
    });
    html += "</tbody></table></div></div>";
    area.innerHTML = html;
    setProgress(100, "完成");
  }

  function setProgress(pct, text) {
    document.querySelector("#progress i").style.width = pct + "%";
    document.getElementById("progressText").textContent = text || "";
  }

  async function visitorIp() {
    try {
      const r = await fetch("/api/session", { signal: AbortSignal.timeout(5000) });
      const d = await r.json();
      return d.ip || "";
    } catch (e) { return ""; }
  }

  document.getElementById("nodeBtn").addEventListener("click", function () {
    var t = document.getElementById("target").value.trim() || "";
    if (!t) { visitorIp().then(function (ip) { runNodePing(ip || "1.1.1.1"); }); }
    else runNodePing(t);
  });
  document.getElementById("gpBtn").addEventListener("click", function () {
    var t = document.getElementById("target").value.trim() || "";
    if (!t) { visitorIp().then(function (ip) { gpRun("ping", ip || "1.1.1.1"); }); }
    else gpRun("ping", t);
  });
  document.getElementById("mtrBtn").addEventListener("click", function () {
    var t = document.getElementById("target").value.trim() || "";
    if (!t) { visitorIp().then(function (ip) { gpRun("traceroute", ip || "1.1.1.1"); }); }
    else gpRun("traceroute", t);
  });
  document.getElementById("rttBtn").addEventListener("click", runRtt);
  document.getElementById("showRounds").addEventListener("change", function (e) {
    var show = e.target.checked;
    document.querySelectorAll(".rounds-cell").forEach(function (el) { el.style.display = show ? "" : "none"; });
    document.getElementById("roundsHead").style.display = show ? "" : "none";
  });

  (async function init() {
    var ip = await visitorIp();
    if (ip) document.getElementById("target").placeholder = "目标 IP 或域名（默认 = 你的出口 IP " + ip + "）";
    // 默认运行本机延迟测试（节点模式依赖公共检测网络，配额有限）
    runRtt();
  })();
})();
