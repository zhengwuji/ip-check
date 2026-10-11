/* ============================================================
   NetProbe — Torrent 地址检测（原创实现）
   为本页访客生成随机 info_hash（20 字节，会话内保持不变），拼成
   仅含本站 Tracker 的 Magnet 链接；BT 客户端添加后向
   /api/torrent/announce 发起 announce，本页每 5 秒轮询
   /api/torrent/results 回显 announce 来源——即 BT 客户端真实出口。
   info_hash 随机生成、不关联身份，服务端 2 小时无活动自动清除。
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;
  var POLL_MS = 5000;
  var GEO_TTL = 10 * 60 * 1000;
  var geoCache = {};
  var selfIp = null;
  var lastOk = false;

  var HASH = (function () {
    var h = "";
    try { h = sessionStorage.getItem("np_bt_hash") || ""; } catch (e) {}
    if (!/^[0-9a-f]{40}$/.test(h)) {
      var b = new Uint8Array(20);
      if (window.crypto && crypto.getRandomValues) crypto.getRandomValues(b);
      else for (var i = 0; i < 20; i++) b[i] = Math.floor(Math.random() * 256);
      h = Array.prototype.map.call(b, function (x) { return ("0" + x.toString(16)).slice(-2); }).join("");
      try { sessionStorage.setItem("np_bt_hash", h); } catch (e) {}
    }
    return h;
  })();

  var ANNOUNCE = location.origin + "/api/torrent/announce";
  var MAGNET = "magnet:?xt=urn:btih:" + HASH + "&dn=NetProbe+IP+Check&tr=" + encodeURIComponent(ANNOUNCE);

  function fmtTime(ts) {
    if (!ts) return "—";
    try { return new Date(ts).toLocaleTimeString("zh-CN", { hour12: false }); } catch (e) { return String(ts); }
  }

  function eventText(ev) {
    if (ev === "started") return "开始";
    if (ev === "stopped") return "停止";
    if (ev === "completed") return "完成";
    if (ev === "paused") return "暂停";
    return ev ? esc(ev) : "常规";
  }

  async function geoOf(ip) {
    if (!ip) return "";
    var now = Date.now();
    if (geoCache[ip] && now - geoCache[ip].t < GEO_TTL) return geoCache[ip].v;
    var v = "";
    try {
      var g = await GEO.lookup(ip).catch(function () { return null; });
      if (g) v = [g.country, g.city, g.isp].filter(Boolean).join(" ");
    } catch (e) {}
    geoCache[ip] = { v: v, t: now };
    return v;
  }

  /* ---------- Magnet 卡片 ---------- */
  (function initMagnet() {
    document.getElementById("magnetText").textContent = MAGNET;
    var open = document.getElementById("magnetOpen");
    open.href = MAGNET;
    document.getElementById("copyBtn").addEventListener("click", function () {
      var done = function () {
        var tip = document.getElementById("copyTip");
        tip.textContent = "已复制，去 BT 客户端里「添加链接 / 添加 Magnet」粘贴即可";
        setTimeout(function () { tip.textContent = ""; }, 4000);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(MAGNET).then(done, function () { fallbackCopy(done); });
      } else fallbackCopy(done);
    });
    document.getElementById("resetBtn").addEventListener("click", function () {
      try { sessionStorage.removeItem("np_bt_hash"); } catch (e) {}
      location.reload();
    });
  })();

  function fallbackCopy(done) {
    var ta = document.createElement("textarea");
    ta.value = MAGNET;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); done(); } catch (e) {}
    document.body.removeChild(ta);
  }

  /* ---------- 本机出口参考 ---------- */
  (async function initSelfIp() {
    var el = document.getElementById("selfIp");
    try {
      var t = await NP.selfTrace();
      if (!t) throw new Error("no exit ip");
      selfIp = t.ip;
      var g = await GEO.lookup(t.ip).catch(function () { return null; });
      el.innerHTML =
        "<div class='kv'><div class='k'>浏览器出口</div><div class='v ip-cell'>" + esc(t.ip) + "</div></div>" +
        "<div class='kv'><div class='k'>归属</div><div class='v'>" + esc(g ? [g.country, g.city, g.isp].filter(Boolean).join(" ") : (t.loc || "未知")) + "</div></div>";
    } catch (e) {
      el.innerHTML = "<p class='error-text small'>获取本机出口失败</p>";
    }
  })();

  /* ---------- 结果轮询 ---------- */
  function render(peers, updated) {
    var body = document.getElementById("btBody");
    if (!peers.length) {
      body.innerHTML = "<tr><td colspan='7' class='muted small'>暂无数据——请先确认 Magnet 链接已添加到 BT 客户端。通常添加后几秒内就会出现第一条记录；若一直没有，说明该客户端无法访问本站域名。</td></tr>";
    } else {
      body.innerHTML = peers.map(function (x) {
        var mark = "";
        if (selfIp) mark = x.ip === selfIp
          ? " <span class='chip-flat' style='color:var(--good)'>＝ 与浏览器出口一致</span>"
          : " <span class='chip-flat' style='color:var(--bad,#e5484d)'>≠ 与浏览器出口不同</span>";
        var geoHtml = x.geo ? "<br><span class='muted small'>" + esc(x.geo) + "</span>" : "";
        return "<tr><td class='ip-cell'>" + esc(x.ip) + mark + geoHtml + "</td>" +
          "<td>" + esc(String(x.port || "—")) + "</td>" +
          "<td>" + esc(x.client || "—") + "</td>" +
          "<td>" + eventText(x.event) + "</td>" +
          "<td>" + fmtTime(x.first) + "</td>" +
          "<td>" + fmtTime(x.last) + "</td>" +
          "<td>" + esc(String(x.count || 1)) + "</td></tr>";
      }).join("");
    }
    document.getElementById("btUpdated").textContent = updated
      ? "最近更新 " + fmtTime(updated) + "。"
      : "";
    document.getElementById("btDump").textContent = peers.length
      ? JSON.stringify(peers, null, 2)
      : "（暂无）";
  }

  async function poll() {
    try {
      var r = await NP.fetchT("/api/torrent/results?h=" + encodeURIComponent(HASH), null, 6000);
      var d = await r.json();
      if (!d || !d.ok) throw new Error((d && d.error) || "bad response");
      var peers = d.peers || [];
      for (var i = 0; i < peers.length; i++) {
        peers[i].geo = await geoOf(peers[i].ip);
      }
      lastOk = true;
      render(peers, d.updated);
    } catch (e) {
      if (!lastOk) {
        document.getElementById("btUpdated").textContent = "轮询失败（网络原因），自动重试中…";
      }
    }
  }
  poll();
  setInterval(poll, POLL_MS);
})();
