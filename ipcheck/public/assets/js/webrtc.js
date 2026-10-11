/* ============================================================
   NetProbe — WebRTC 泄露检测（原创实现）
   1) 多 STUN 并行：每个服务器独立 RTCPeerConnection，
      记录 srflx 映射 (ip, port, rtt) + host 候选
   2) NAT 映射类型判定：各服务器映射一致 → 锥型（端口无关）；
      端口随服务器变化 → 对称型；host 为公网地址且等于映射 → 无 NAT
   3) SDP 日志：保存 offer SDP 与逐条候选，展开可查
   4) 泄露判定：srflx 与 HTTP 出口对比（保留原逻辑）
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;

  var STUN_SERVERS = [
    "stun:stun.l.google.com:19302",
    "stun:stun1.l.google.com:19302",
    "stun:stun.cloudflare.com:3478",
    "stun:global.stun.twilio.com:3478",
  ];

  function isPrivateV4(ip) {
    var m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (!m) return false;
    var a = +m[1], b = +m[2];
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    return false;
  }
  function isIPv4(s) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(s); }
  function isIPv6(s) { return s.indexOf(":") !== -1 && s.indexOf(".local") === -1; }

  /* 每个 STUN 服务器独立探测 */
  function probeStun(url) {
    return new Promise(function (resolve) {
      var out = { url: url, srflx: [], host: [], sdpLog: [], error: null };
      var pc;
      try {
        pc = new RTCPeerConnection({ iceServers: [{ urls: url }] });
      } catch (e) { out.error = e.message; resolve(out); return; }
      var t0 = performance.now();
      var timer = setTimeout(finish, 7000);
      var firstSrflxAt = null;
      try { pc.createDataChannel(""); } catch (e) {}
      pc.onicecandidate = function (e) {
        var c = e.candidate ? (e.candidate.candidate || "") : "";
        if (c) {
          out.sdpLog.push("[" + Math.round(performance.now() - t0) + "ms] " + c);
          var m = c.match(/candidate:\S+ \d+ \S+ \d+ ([^\s]+) (\d+) typ (\w+)/);
          if (m) {
            var entry = { addr: m[1], port: +m[2], typ: m[3], ms: Math.round(performance.now() - t0) };
            if (m[3] === "srflx") {
              if (firstSrflxAt === null) firstSrflxAt = entry.ms;
              if (!out.srflx.some(function (x) { return x.addr === entry.addr && x.port === entry.port; })) out.srflx.push(entry);
            } else if (m[3] === "host") {
              if (!out.host.some(function (x) { return x.addr === entry.addr; })) out.host.push(entry);
            }
          }
        } else { clearTimeout(timer); finish(); }
      };
      pc.createOffer().then(function (o) {
        out.sdpLog.unshift("[offer] " + (o.sdp || "").split("\n").filter(function (l) { return /a=candidate|o=-|c=IN/.test(l); }).join("\n"));
        return pc.setLocalDescription(o);
      }).catch(function () {});
      function finish() {
        clearTimeout(timer);
        try { pc.close(); } catch (e) {}
        resolve(out);
      }
    });
  }

  /* NAT 判定 */
  function natVerdict(results, httpIp) {
    var allSrflx = [];
    results.forEach(function (r) { allSrflx = allSrflx.concat(r.srflx); });
    var v4Srflx = allSrflx.filter(function (x) { return isIPv4(x.addr); });
    var publicHost = [];
    results.forEach(function (r) {
      r.host.forEach(function (h) {
        if (isIPv4(h.addr) && !isPrivateV4(h.addr)) publicHost.push(h);
      });
    });
    if (!allSrflx.length) {
      return { label: "未获得 STUN 映射", cls: "pill-muted", desc: "UDP 被完全拦截或 WebRTC 被禁用，无泄露通道。", nat: null };
    }
    /* host 公网直连：无 NAT */
    if (publicHost.length && v4Srflx.some(function (x) { return publicHost.some(function (h) { return h.addr === x.addr && h.port === x.port; }); })) {
      return { label: "无 NAT（公网直连）", cls: "pill-warn", desc: "本地网卡直接持有公网 IPv4，映射地址与 host 一致——设备完全暴露在公网上，建议在路由器后上网。", nat: "none" };
    }
    var ips = {};
    var ports = {};
    v4Srflx.forEach(function (x) { ips[x.addr] = 1; ports[x.addr + ":" + x.port] = 1; });
    var ipCount = Object.keys(ips).length;
    var portCount = Object.keys(ports).length;
    var nat;
    var label, cls, desc;
    if (ipCount > 1) {
      nat = "symmetric-ip";
      label = "对称型（IP 级，多出口）";
      cls = "pill-warn";
      desc = "不同 STUN 服务器看到了不同的映射 IP——通常意味着运营商级多出口 NAT，映射几乎无法被外部预测，P2P 连接困难，但也最难被反向探测。";
    } else if (portCount > 1) {
      nat = "symmetric-port";
      label = "端口对称型";
      cls = "pill-warn";
      desc = "同一 IP 但每个 STUN 服务器看到的端口都不同（端口与端口相关联的映射），属于对称型 NAT：P2P 打洞成功率低，WebRTC 通常会退回中继。";
    } else {
      nat = "cone";
      label = "锥型（端口无关映射）";
      cls = "pill-info";
      desc = "所有服务器看到的映射地址与端口一致，P2P 直连友好；同一映射也会被你连接过的对端记住。";
    }
    return { label: label, cls: cls, desc: desc, nat: nat };
  }

  function rowsHtml(results) {
    var rows = [];
    results.forEach(function (r) {
      var serverLabel = r.url.replace(/^stun:/, "");
      if (r.error) {
        rows.push("<tr><td>" + esc(serverLabel) + "</td><td colspan='3' class='muted small'>连接失败：" + esc(r.error) + "</td></tr>");
        return;
      }
      if (!r.srflx.length && !r.host.length) {
        rows.push("<tr><td>" + esc(serverLabel) + "</td><td colspan='3' class='muted small'>未获得候选（UDP 可能被拦截）</td></tr>");
        return;
      }
      r.srflx.forEach(function (x, i) {
        rows.push("<tr><td>" + (i === 0 ? esc(serverLabel) : "") + "</td>" +
          "<td><span class='badge badge-international'>srflx</span></td>" +
          "<td class='ip-cell' data-geo-ip='" + esc(x.addr) + "'>" + esc(x.addr) + ":" + x.port + "</td>" +
          "<td class='muted small'>公网映射 · " + x.ms + "ms</td></tr>");
      });
      r.host.forEach(function (x) {
        var mdns = x.addr.indexOf(".local") !== -1;
        rows.push("<tr><td></td>" +
          "<td><span class='badge badge-static'>host</span></td>" +
          "<td class='ip-cell'>" + esc(x.addr) + "</td>" +
          "<td class='muted small'>" + (mdns ? "mDNS 混淆（浏览器已保护）" : isPrivateV4(x.addr) ? "局域网地址" : "公网 host") + " · " + x.ms + "ms</td></tr>");
      });
    });
    if (!rows.length) return "<tr><td colspan='4' class='muted small'>未收集到候选地址（可能被浏览器策略阻止）</td></tr>";
    return rows.join("");
  }

  function renderSdp(results) {
    var host = document.getElementById("sdpArea");
    if (!host) return;
    var html = results.map(function (r, i) {
      var serverLabel = r.url.replace(/^stun:/, "");
      var body = r.sdpLog.length ? r.sdpLog.join("\n") : "（无日志）";
      return "<details class='read-card'><summary>SDP 日志 · " + esc(serverLabel) + "（" + r.sdpLog.length + " 条）</summary>" +
        "<div class='read-body' style='white-space:pre-wrap;font-family:var(--mono,monospace);font-size:0.78em;max-height:260px;overflow:auto'>" + esc(body) + "</div></details>";
    }).join("");
    host.innerHTML = html;
  }

  async function httpExit() {
    const t = await NP.selfTrace();
    if (!t) return {};
    var loc = t.loc;
    if (!loc) {
      var g = await GEO.lookup(t.ip).catch(function () { return null; });
      if (g && g.countryCode) loc = g.countryCode;
    }
    return { ip: t.ip, loc: loc };
  }

  async function start() {
    var btn = document.getElementById("startBtn");
    btn.disabled = true;
    document.getElementById("statusText").textContent = "并行探测 " + STUN_SERVERS.length + " 个 STUN 服务器…";
    document.getElementById("verdictArea").innerHTML = "";
    document.getElementById("natCard").style.display = "none";
    document.getElementById("sdpCard").style.display = "none";

    var http = await httpExit();
    document.getElementById("httpIp").innerHTML =
      "<div class='kv'><div class='k'>HTTP 出口 IP</div><div class='v ip-cell'>" + esc(http.ip || "获取失败") + "</div></div>" +
      "<div class='kv'><div class='k'>国家</div><div class='v'>" + esc((http.loc || "").toUpperCase() || "未知") + "</div></div>";

    var results = await Promise.all(STUN_SERVERS.map(function (u) { return probeStun(u); }));
    document.getElementById("statusText").textContent = "";
    document.getElementById("candBody").innerHTML = rowsHtml(results);
    renderSdp(results);
    document.getElementById("sdpCard").style.display = "";

    /* 为 srflx 地址补归属 */
    var uniqIps = [];
    results.forEach(function (r) { r.srflx.forEach(function (x) { if (uniqIps.indexOf(x.addr) === -1) uniqIps.push(x.addr); }); });
    var geoMap = {};
    await Promise.allSettled(uniqIps.map(async function (ip) {
      var g = await GEO.lookup(ip).catch(function () { return null; });
      if (g) geoMap[ip] = { cc: g.countryCode, text: [g.country, g.city, g.isp].filter(Boolean).join(" ") };
    }));
    document.querySelectorAll("#candBody [data-geo-ip]").forEach(function (el) {
      var g = geoMap[el.dataset.geoIp];
      if (g) el.innerHTML = el.textContent + "<br>" + NP.flag(g.cc) + " <span class='muted small'>" + esc(g.text) + "</span>";
    });

    /* NAT 卡片 */
    var nat = natVerdict(results, http.ip);
    document.getElementById("natCard").style.display = "";
    document.getElementById("natBody").innerHTML =
      "<div class='kv'><div class='k'>NAT 映射类型</div><div class='v'><span class='pill " + nat.cls + "'>" + esc(nat.label) + "</span></div></div>" +
      "<div class='kv'><div class='k'>说明</div><div class='v small muted'>" + esc(nat.desc) + "</div></div>";

    /* 泄露判定（与原逻辑一致） */
    var allSrflx = [];
    results.forEach(function (r) { allSrflx = allSrflx.concat(r.srflx); });
    var verdict;
    if (!results.some(function (r) { return r.srflx.length || r.host.length; })) {
      verdict = "<div class='verdict verdict-safe'>✓ 未收集到任何 ICE 候选，WebRTC 可能已被浏览器/扩展禁用。</div>";
    } else if (!allSrflx.length) {
      verdict = "<div class='verdict verdict-safe'>✓ 未见 STUN 公网映射（srflx）。UDP 打洞失败或被代理拦截，WebRTC 泄露风险低。</div>";
    } else {
      var leakedReal = allSrflx.some(function (r) { return r.addr === http.ip; });
      if (http.ip && leakedReal) {
        verdict = "<div class='verdict verdict-bad'>✗ 检测到泄露：WebRTC（UDP）看到的公网 IP 与 HTTP 出口一致（" + esc(http.ip) + "）。若你依赖仅代理 HTTP/S 的方案，真实 IP 已通过 UDP 暴露。</div>";
      } else {
        var uniqIps2 = [];
        allSrflx.forEach(function (r) { if (uniqIps2.indexOf(r.addr) === -1) uniqIps2.push(r.addr); });
        var ips = uniqIps2.join("、");
        verdict = "<div class='verdict verdict-warn'>△ STUN 映射地址：" + esc(ips) + "，与 HTTP 出口（" + esc(http.ip || "未知") + "）不同。若映射地址是你的真实宽带 IP，仍属于局部泄露（UDP 直连）。</div>";
      }
    }
    document.getElementById("verdictArea").innerHTML = verdict;
    btn.disabled = false;
  }

  document.getElementById("startBtn").addEventListener("click", start);
})();
