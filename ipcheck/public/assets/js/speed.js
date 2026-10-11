/* ============================================================
   NetProbe — 网速测试（原创实现）
   探针：speed.cloudflare.com（公开测速端点，CORS 开放）
     · 延迟/抖动：__down?bytes=0 多轮 RTT
     · 下载：__down?bytes=N 流式读取，滑动窗口实时速率
     · 上传：__up POST 随机块，XHR onprogress 实时速率
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;
  var BASE = "https://speed.cloudflare.com";
  var aborted = false;

  /* ---------- 工具 ---------- */
  function fmtMbps(bps) {
    if (!isFinite(bps) || bps <= 0) return "—";
    var mb = bps / 1e6;
    return mb >= 100 ? Math.round(mb).toString() : mb >= 10 ? mb.toFixed(1) : mb.toFixed(2);
  }
  function setPhase(text) { document.getElementById("phaseText").textContent = text; }
  function setProgress(pct) { document.querySelector("#progress i").style.width = pct + "%"; }
  function setVal(id, text) { document.getElementById(id).textContent = text; }

  /* 滑动窗口实时速率：把 (时间, 字节) 样本放进队列，窗口 250ms */
  function speedMeter(onTick) {
    var q = [];
    var lastBytes = 0;
    return {
      push: function (bytes) {
        var now = performance.now();
        q.push([now, bytes]);
        while (q.length > 2 && now - q[0][0] > 250) q.shift();
        var dt = (now - q[0][0]) / 1000;
        var db = bytes - q[0][1];
        if (dt > 0.05 && db >= 0) onTick(db / dt * 8);
      },
      total: function () { return lastBytes; },
      setTotal: function (b) { lastBytes = b; },
    };
  }

  /* ---------- 节点信息 ---------- */
  async function probeEdge() {
    try {
      const r = await fetch(BASE + "/__down?bytes=0", { cache: "no-store", signal: AbortSignal.timeout(8000) });
      var colo = r.headers.get("cf-meta-colo") || r.headers.get("cf-ray") || "";
      if (colo.indexOf("-") !== -1) colo = colo.split("-")[1];
      var ip = r.headers.get("cf-meta-ip") || "";
      var asn = r.headers.get("cf-meta-asn") || "";
      var city = r.headers.get("cf-meta-city") || "";
      var country = r.headers.get("cf-meta-country") || "";
      document.getElementById("edgeCard").style.display = "";
      document.getElementById("edgeInfo").innerHTML =
        "<div class='kv'><div class='k'>边缘节点 (IATA)</div><div class='v'>" + esc(colo || "—") + (city ? " · " + esc(city) : "") + "</div></div>" +
        "<div class='kv'><div class='k'>你的出口 IP（Cloudflare 侧）</div><div class='v ip-cell'>" + esc(ip || "—") + "</div></div>" +
        "<div class='kv'><div class='k'>出口 ASN</div><div class='v'>" + esc(asn ? "AS" + asn : "—") + "</div></div>" +
        "<div class='kv'><div class='k'>国家/地区</div><div class='v'>" + NP.flag(country.toLowerCase()) + " " + esc(country || "—") + "</div></div>";
      return { colo: colo, ip: ip };
    } catch (e) {
      return null;
    }
  }

  /* ---------- 延迟 / 抖动 ---------- */
  async function measureLatency() {
    var rtts = [];
    for (var i = 0; i < 5; i++) {
      if (aborted) return rtts;
      var t0 = performance.now();
      try {
        await fetch(BASE + "/__down?bytes=0", { cache: "no-store", signal: AbortSignal.timeout(5000) });
        rtts.push(performance.now() - t0);
      } catch (e) { /* 丢弃该轮 */ }
      setPhase("测量延迟…（" + rtts.length + "/5）");
      setProgress(3 + (i + 1) * 4);
      setVal("vPing", rtts.length ? Math.round(NP.median(rtts)) : "—");
      setVal("vJit", rtts.length > 1 ? jitterOf(rtts).toFixed(1) : "—");
    }
    return rtts;
  }
  function jitterOf(arr) {
    if (arr.length < 2) return 0;
    var avg = arr.reduce(function (a, b) { return a + b; }, 0) / arr.length;
    var dev = arr.reduce(function (a, b) { return a + Math.abs(b - avg); }, 0) / arr.length;
    return dev;
  }

  /* ---------- 下载 ---------- */
  function downloadOnce(bytes, onTick) {
    return new Promise(function (resolve) {
      var t0 = performance.now();
      fetch(BASE + "/__down?bytes=" + bytes, { cache: "no-store", signal: aborted ? undefined : undefined })
        .then(function (r) { return r.body ? r.body.getReader() : null; })
        .then(function (reader) {
          if (!reader) { resolve({ ok: false }); return; }
          var received = 0;
          function pump() {
            return reader.read().then(function (chunk) {
              if (aborted) { try { reader.cancel(); } catch (e) {} resolve({ ok: false }); return; }
              if (chunk.done) {
                var sec = (performance.now() - t0) / 1000;
                resolve({ ok: received > 0, sec: sec, bytes: received });
                return;
              }
              received += chunk.value.byteLength;
              onTick(received);
              pump();
            });
          }
          pump();
        })
        .catch(function () { resolve({ ok: false }); });
    });
  }

  /* ---------- 上传（XHR 才有 upload.onprogress） ---------- */
  function uploadOnce(bytes, onTick) {
    return new Promise(function (resolve) {
      try {
        var blob = new Blob([new Uint8Array(Math.min(bytes, 65536))], { type: "application/octet-stream" });
        // 用重复块拼出目标大小，避免一次性生成超大随机数组
        var parts = [];
        var total = 0;
        while (total < bytes) { parts.push(blob); total += blob.size; }
        var payload = new Blob(parts, { type: "application/octet-stream" });
        var xhr = new XMLHttpRequest();
        var t0 = performance.now();
        xhr.open("POST", BASE + "/__up", true);
        xhr.upload.onprogress = function (e) { if (e.loaded) onTick(e.loaded); };
        xhr.onload = function () {
          var sec = (performance.now() - t0) / 1000;
          resolve({ ok: xhr.status >= 200 && xhr.status < 300 && sec > 0, sec: sec, bytes: payload.size });
        };
        xhr.onerror = function () { resolve({ ok: false }); };
        xhr.ontimeout = function () { resolve({ ok: false }); };
        xhr.timeout = 30000;
        xhr.send(payload);
      } catch (e) { resolve({ ok: false }); }
    });
  }

  /* ---------- 评分 ---------- */
  function dlVerdict(mbps) {
    if (mbps >= 100) return ["优秀", "pill-good", "满足 4K 流媒体 / 大文件下载 / 多人共用"];
    if (mbps >= 30) return ["良好", "pill-good", "满足 1080P 流媒体 / 日常办公"];
    if (mbps >= 10) return ["一般", "pill-info", "满足网页浏览 / 标清视频"];
    if (mbps > 0) return ["偏慢", "pill-warn", "大文件下载与高清视频会明显吃力"];
    return ["未测得", "pill-muted", "下载测速未完成"];
  }
  function pingVerdict(ms) {
    if (ms < 0) return ["未测得", "pill-muted"];
    if (ms < 50) return ["极快", "pill-good"];
    if (ms < 100) return ["优秀", "pill-good"];
    if (ms < 200) return ["良好", "pill-info"];
    if (ms < 400) return ["一般", "pill-warn"];
    return ["偏高", "pill-bad"];
  }

  /* ---------- 主流程 ---------- */
  async function run() {
    var btn = document.getElementById("startBtn");
    var stopBtn = document.getElementById("stopBtn");
    btn.disabled = true;
    stopBtn.style.display = "";
    aborted = false;
    document.getElementById("resultCard").style.display = "";
    document.getElementById("roundBody").innerHTML = "";
    setVal("vDl", "—"); setVal("vUl", "—"); setVal("vPing", "—"); setVal("vJit", "—");
    document.getElementById("verdictArea").innerHTML = "";

    var dlBytes = parseInt(document.getElementById("dlSize").value, 10);
    var ulBytes = parseInt(document.getElementById("ulSize").value, 10);
    var ROUNDS = 4;

    setPhase("连接测速节点…");
    probeEdge();

    /* 1. 延迟 */
    var rtts = await measureLatency();
    var pingMs = rtts.length ? NP.median(rtts) : -1;
    var jit = rtts.length > 1 ? jitterOf(rtts) : -1;

    /* 2. 下载 */
    var dlMbps = 0;
    var dlRows = [];
    for (var i = 0; i < ROUNDS; i++) {
      if (aborted) break;
      setPhase("下载测速…（第 " + (i + 1) + " / " + ROUNDS + " 轮）");
      var meter = speedMeter(function (bps) { setVal("vDl", fmtMbps(bps)); });
      var res = await downloadOnce(dlBytes, function (bytes) {
        meter.push(bytes);
        setProgress(25 + (i / ROUNDS) * 30 + 5);
      });
      if (res.ok) {
        var mbps = res.bytes * 8 / res.sec;
        dlMbps += mbps; dlRows.push(mbps);
        setVal("vDl", fmtMbps(dlMbps / dlRows.length));
      }
      renderRounds(dlRows, []);
    }

    /* 3. 上传 */
    var ulMbps = 0, ulRows = [];
    for (var j = 0; j < ROUNDS && !aborted; j++) {
      setPhase("上传测速…（第 " + (j + 1) + " / " + ROUNDS + " 轮）");
      var meterU = speedMeter(function (bps) { setVal("vUl", fmtMbps(bps)); });
      var resU = await uploadOnce(ulBytes, function (bytes) {
        meterU.push(bytes);
        setProgress(55 + (j / ROUNDS) * 30 + 5);
      });
      if (resU.ok) {
        var u = resU.bytes * 8 / resU.sec;
        ulMbps += u; ulRows.push(u);
        setVal("vUl", fmtMbps(ulMbps / ulRows.length));
      }
      renderRounds(dlRows, ulRows);
    }

    setProgress(100, "");
    var avgDl = dlRows.length ? dlMbps / dlRows.length : -1;
    var avgUl = ulRows.length ? ulMbps / ulRows.length : -1;
    setVal("vDl", avgDl > 0 ? fmtMbps(avgDl) : "—");
    setVal("vUl", avgUl > 0 ? fmtMbps(avgUl) : "—");
    setVal("vPing", pingMs >= 0 ? Math.round(pingMs) : "—");
    setVal("vJit", jit >= 0 ? jit.toFixed(1) : "—");

    /* 4. 结论 */
    var v = dlVerdict(avgDl);
    var pv = pingVerdict(pingMs);
    var html = "<div class='verdict " + (avgDl >= 30 ? "verdict-safe" : avgDl > 0 ? "verdict-warn" : "verdict-info") + "'>" +
      "下载 <b>" + fmtMbps(avgDl) + "</b> Mbps（" + v[0] + "），延迟 " +
      (pingMs >= 0 ? "<b>" + Math.round(pingMs) + "</b> ms（" + pv[0] + "）" : "未测得") + "。" + esc(v[2] || "") +
      (aborted ? "（已中止）" : "") + "</div>";
    if (jit >= 0) html += "<div class='muted small' style='margin-top:4px'>抖动 " + jit.toFixed(1) + " ms：" +
      (jit < 5 ? "链路非常稳定，适合实时语音/游戏。" : jit < 20 ? "链路稳定性尚可。" : "链路波动明显，实时应用可能卡顿。") + "</div>";
    document.getElementById("verdictArea").innerHTML = html;
    renderRounds(dlRows, ulRows);

    btn.disabled = false;
    stopBtn.style.display = "none";
    setPhase(aborted ? "已中止，可重新测速" : "测速完成");
  }

  function renderRounds(dlRows, ulRows) {
    var n = Math.max(dlRows.length, ulRows.length);
    var html = "";
    for (var i = 0; i < n; i++) {
      html += "<tr><td>第 " + (i + 1) + " 轮</td><td>" + (dlRows[i] != null ? fmtMbps(dlRows[i]) : "—") + "</td><td>" +
        (ulRows[i] != null ? fmtMbps(ulRows[i]) : "—") + "</td></tr>";
    }
    if (!n) html = "<tr><td colspan='3' class='muted small'>暂无数据</td></tr>";
    document.getElementById("roundBody").innerHTML = html;
  }

  document.getElementById("startBtn").addEventListener("click", run);
  document.getElementById("stopBtn").addEventListener("click", function () { aborted = true; setPhase("正在停止…"); });
})();
