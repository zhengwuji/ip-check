/* ============================================================
   NetProbe — 封锁测试（原创实现）
   通道一：OONI 开放数据 api.ooni.io（CORS 开放）
     /api/v1/measurements?probe_cc=<CC>&domain=<D>&since=&until=&limit=800
     本地统计 total / anomaly / confirmed。
   通道二：Globalping 公共探针 api.globalping.io（CORS 开放，匿名限额）
     POST /v1/measurements {type:"http", target, locations, limit}
     轮询 GET /v1/measurements/{id}。
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;

  /* 参与统计的国家（与 NetProbe 其它页面的地区库对齐） */
  var COUNTRIES = [
    ["CN", "中国"], ["HK", "中国香港"], ["TW", "中国台湾"], ["JP", "日本"], ["KR", "韩国"],
    ["SG", "新加坡"], ["MY", "马来西亚"], ["TH", "泰国"], ["VN", "越南"], ["ID", "印度尼西亚"],
    ["IN", "印度"], ["US", "美国"], ["CA", "加拿大"], ["MX", "墨西哥"], ["BR", "巴西"],
    ["AR", "阿根廷"], ["GB", "英国"], ["DE", "德国"], ["FR", "法国"], ["IT", "意大利"],
    ["ES", "西班牙"], ["NL", "荷兰"], ["SE", "瑞典"], ["CH", "瑞士"], ["PL", "波兰"],
    ["RU", "俄罗斯"], ["TR", "土耳其"], ["UA", "乌克兰"], ["AE", "阿联酋"], ["SA", "沙特"],
    ["IR", "伊朗"], ["EG", "埃及"], ["NG", "尼日利亚"], ["ZA", "南非"], ["AU", "澳大利亚"], ["NZ", "新西兰"],
  ];
  var CC_NAME = {};
  COUNTRIES.forEach(function (c) { CC_NAME[c[0]] = c[1]; });
  /* 实时测试的快捷分组 */
  var HEAVY_CENSOR = ["CN", "RU", "TR", "SA", "IR", "EG"];
  var OPEN_COUNTRIES = ["US", "DE", "JP", "SG", "GB"];
  var picked = new Set();

  function daysAgoIso(days) {
    return new Date(Date.now() - days * 86400000).toISOString();
  }
  function todayIso() {
    return new Date().toISOString();
  }

  function fmtDate(iso) {
    try { return new Date(iso).toLocaleDateString("zh-CN"); } catch (e) { return ""; }
  }

  /* ---------------- OONI 观测统计 ---------------- */
  async function ooniCountry(cc, domain, since, until) {
    var url = "https://api.ooni.io/api/v1/measurements?probe_cc=" + cc +
      "&domain=" + encodeURIComponent(domain) +
      "&since=" + encodeURIComponent(since) + "&until=" + encodeURIComponent(until) +
      "&limit=800&order=desc";
    const r = await fetch("/api/ooni?path=" + encodeURIComponent(url.replace("https://api.ooni.io", "")), { cache: "no-store", signal: AbortSignal.timeout(20000) });
    if (!r.ok) throw new Error("HTTP " + r.status);
    var d = await r.json();
    var results = d.results || [];
    var anomaly = 0, confirmed = 0;
    results.forEach(function (m) {
      if (m.anomaly) anomaly++;
      if (m.confirmed) confirmed++;
    });
    return { total: results.length, anomaly: anomaly, confirmed: confirmed, capped: results.length >= 800 };
  }

  function classify(c) {
    if (!c.total) return ["无数据", "pill-muted"];
    var pct = c.anomaly / c.total;
    if (c.confirmed > 0 || (pct >= 0.25 && c.total >= 20)) return ["疑似屏蔽", "pill-bad"];
    if (c.anomaly > 0) return ["观测到异常", "pill-warn"];
    return ["正常可达", "pill-good"];
  }

  async function runObs() {
    var raw = document.getElementById("domain").value.trim();
    var domain = raw.replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
    var btn = document.getElementById("runBtn");
    if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/.test(domain)) {
      document.getElementById("progressText").textContent = "请输入合法域名";
      return;
    }
    btn.disabled = true;
    document.getElementById("liveArea").style.display = "none";
    document.getElementById("obsArea").innerHTML = "";
    var since = daysAgoIso(30), until = todayIso();

    document.getElementById("progressText").textContent = "查询 OONI 观测数据（" + COUNTRIES.length + " 个国家/地区）…";
    var rows = [];
    var scanned = 0;
    await NP.withLimit(COUNTRIES, 6, async function (c) {
      var cc = c[0], name = c[1];
      try {
        var stat = await ooniCountry(cc, domain, since, until);
        rows.push({ cc: cc, name: name, stat: stat });
      } catch (e) {
        rows.push({ cc: cc, name: name, stat: null });
      }
      scanned++;
      document.querySelector("#progress i").style.width = Math.round((scanned / COUNTRIES.length) * 100) + "%";
      document.getElementById("progressText").textContent = "查询观测数据…（" + scanned + "/" + COUNTRIES.length + "）";
    });

    renderObs(domain, since, until, rows);
    btn.disabled = false;
    document.getElementById("progressText").textContent = "完成";
    document.querySelector("#progress i").style.width = "100%";
  }

  function renderObs(domain, since, until, rows) {
    var blocked = rows.filter(function (r) { return r.stat && (r.stat.confirmed > 0 || (r.stat.total >= 20 && r.stat.anomaly / r.stat.total >= 0.25)); });
    var measured = rows.filter(function (r) { return r.stat && r.stat.total > 0; });
    var html = "<div class='card' style='margin-top:14px'>" +
      "<p class='card-title'>过去 30 天的全球观测（" + fmtDate(since) + " → " + fmtDate(until) + "）</p>";
    if (blocked.length) {
      html += "<div class='verdict verdict-bad'>在 <b>" + blocked.length + "</b> 个国家/地区观测到屏蔽或干扰迹象：" +
        blocked.map(function (r) { return esc(r.name); }).join("、") + "。</div>";
    } else if (measured.length) {
      html += "<div class='verdict verdict-safe'>✓ 在有测量数据的 " + measured.length + " 个国家/地区，未观测到系统性屏蔽迹象。</div>";
    } else {
      html += "<div class='verdict verdict-info'>最近 30 天没有找到关于 " + esc(domain) + " 的观测记录。可能是该域名冷门，也可能查询受限；可稍后重试或试试更常见的域名。</div>";
    }

    /* 有数据的行按严重度排序 */
    var sorted = rows.filter(function (r) { return r.stat && r.stat.total > 0; }).sort(function (a, b) {
      return (b.stat.anomaly / b.stat.total) - (a.stat.anomaly / a.stat.total) || b.stat.total - a.stat.total;
    });
    if (sorted.length) {
      html += "<div class='tbl-wrap'><table class='tbl' style='min-width:640px'>" +
        "<thead><tr><th style='min-width:150px'>国家/地区</th><th style='width:110px'>判定</th><th style='width:190px'>异常率</th><th>测量数（近 30 天）</th></tr></thead><tbody>";
      sorted.forEach(function (r) {
        var tag = classify(r.stat);
        var pct = Math.round((r.stat.anomaly / r.stat.total) * 100);
        html += "<tr><td>" + NP.flag(r.cc.toLowerCase()) + " " + esc(r.name) + "</td>" +
          "<td><span class='pill " + tag[1] + "'>" + tag[0] + "</span></td>" +
          "<td><div style='display:flex;align-items:center;gap:8px'><div style='flex:1;height:6px;background:var(--bg-soft);border-radius:3px;overflow:hidden'><i style='display:block;height:100%;width:" + pct + "%;background:" + (pct >= 25 ? "var(--bad)" : pct > 0 ? "var(--warn)" : "var(--good)") + "'></i></div><span class='small'>" + pct + "%</span></div></td>" +
          "<td class='muted small'>" + r.stat.total + (r.stat.capped ? "+" : "") + (r.stat.confirmed ? " · 确认 " + r.stat.confirmed : "") +
          " <a href='https://explorer.ooni.org/domain/" + encodeURIComponent(domain) + "?since=" + encodeURIComponent(since.slice(0, 10)) + "&until=" + encodeURIComponent(until.slice(0, 10)) + "&cc=" + r.cc + "' target='_blank' rel='noopener noreferrer'>详情 ↗</a></td></tr>";
      });
      html += "</tbody></table></div>";
      var noData = rows.filter(function (r) { return !r.stat || !r.stat.total; }).map(function (r) { return r.name; });
      if (noData.length) {
        html += "<p class='muted small' style='margin-top:8px'>以下国家/地区暂无该域名的测量数据：" + esc(noData.join("、")) + "。</p>";
      }
    }
    html += "</div>";
    document.getElementById("obsArea").innerHTML = html;

    /* 实时测试区：命中国家默认选中 */
    if (measured.length) {
      document.getElementById("liveArea").style.display = "";
      picked = new Set(blocked.slice(0, 8).map(function (r) { return r.cc; }));
      if (!picked.size) picked = new Set(OPEN_COUNTRIES);
      renderPicker(blocked);
    }
  }

  function renderPicker(blocked) {
    var chip = function (cc, label, extraCls) {
      var on = picked.has(cc);
      return "<button class='btn btn-ghost small" + (on ? " active" : "") + "' data-cc='" + cc + "'>" + NP.flag(cc.toLowerCase()) + " " + esc(label) + "</button>";
    };
    var html = "";
    if (blocked && blocked.length) {
      html += "<div style='width:100%' class='muted small'>命中封锁的国家：</div>" +
        blocked.map(function (r) { return chip(r.cc, r.name); }).join("");
    }
    html += "<div style='width:100%' class='muted small' style='margin-top:4px'>审查较严：</div>" +
      HEAVY_CENSOR.filter(function (cc) { return !blocked || !blocked.some(function (r) { return r.cc === cc; }); })
        .map(function (cc) { return chip(cc, CC_NAME[cc]); }).join("");
    html += "<div style='width:100%' class='muted small'>通常开放：</div>" +
      OPEN_COUNTRIES.map(function (cc) { return chip(cc, CC_NAME[cc]); }).join("");
    var picker = document.getElementById("probePicker");
    picker.innerHTML = html;
    picker.querySelectorAll("[data-cc]").forEach(function (b) {
      b.addEventListener("click", function () {
        var cc = b.dataset.cc;
        if (picked.has(cc)) picked.delete(cc); else picked.add(cc);
        renderPicker(blocked);
      });
    });
  }

  /* ---------------- Globalping 实时测试 ---------------- */
  function gpRequest(body) {
    return fetch("/api/gp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(20000),
    }).then(async function (r) {
      if (r.status === 429) throw new Error("请求过于频繁，请稍后再试");
      if (!r.ok) throw new Error("HTTP " + r.status);
      var loc = r.headers.get("X-GP-Location") || "";
      return loc.split("/").pop() || "";
    });
  }

  function gpPoll(id) {
    return fetch("/api/gp/poll?id=" + encodeURIComponent(id), { cache: "no-store", signal: AbortSignal.timeout(15000) })
      .then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      });
  }

  async function runLive() {
    var domain = document.getElementById("domain").value.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
    var btn = document.getElementById("liveBtn");
    var ccs = Array.from(picked);
    if (!ccs.length) { document.getElementById("liveText").textContent = "请先选择至少一个国家"; return; }
    if (!domain) { document.getElementById("liveText").textContent = "请先在上方输入域名并查询"; return; }
    btn.disabled = true;
    document.getElementById("liveResult").innerHTML = "";
    document.getElementById("liveText").textContent = "分发探针任务（每国 2 个）…";

    var jobs = {};
    var failed = false;
    await NP.withLimit(ccs, 3, async function (cc) {
      try {
        jobs[cc] = await gpRequest({
          type: "http",
          target: domain,
          locations: [{ country: cc }, { country: cc }],
          limit: 2,
        });
      } catch (e) {
        jobs[cc] = null;
        if (String(e.message).indexOf("限额") !== -1) failed = true;
      }
    });

    if (failed && !Object.keys(jobs).filter(function (k) { return jobs[k]; }).length) {
      document.getElementById("liveText").textContent = "";
      document.getElementById("liveResult").innerHTML =
        "<div class='card' style='margin-top:14px'><div class='verdict verdict-warn'>实时测试不可用：" + esc(failed ? "探针网络限额已用尽" : "分发失败") + "。请稍后再试，或参考上方的历史观测数据。</div></div>";
      btn.disabled = false;
      return;
    }

    /* 轮询（最多 45 秒） */
    var results = {}; // cc → [{ok, delay, probe}]
    for (var i = 0; i < 18; i++) {
      await new Promise(function (r) { setTimeout(r, 2500); });
      var pending = 0;
      await Promise.allSettled(Object.keys(jobs).filter(function (k) { return jobs[k]; }).map(async function (cc) {
        if (results[cc]) return;
        try {
          var d = await gpPoll(jobs[cc]);
          if (d.status !== "in-progress") {
            results[cc] = (d.results || []).map(function (pr) {
              var res = pr.result || {};
              var ok = res.status === "finished" && res.rawOutput && !/Failed|timed out|Could not resolve|Connection refused|SSL|TLS/i.test(res.rawOutput);
              var delay = null;
              try {
                var dm = (res.timings || {}).total;
                if (typeof dm === "number") delay = Math.round(dm);
                else if (Array.isArray(dm) && dm[0] != null) delay = Math.round(dm[0]);
              } catch (e) {}
              return { ok: ok, delay: delay, probe: ((pr.probe || {}).city || "") + ", " + ((pr.probe || {}).country || "") };
            });
          } else pending++;
        } catch (e) { /* 下一轮再试 */ }
      }));
      renderLive(ccs, results);
      document.getElementById("liveText").textContent = "收集探针结果…（" + (i + 1) + "/18）";
      if (!pending) break;
    }
    renderLive(ccs, results, true);
    document.getElementById("liveText").textContent = "完成";
    btn.disabled = false;
  }

  function renderLive(ccs, results, final) {
    var html = "<div class='card' style='margin-top:14px'><p class='card-title'>实时访问结果</p><div class='tbl-wrap'><table class='tbl' style='min-width:640px'>" +
      "<thead><tr><th>国家/地区</th><th>探针 #1</th><th>探针 #2</th><th>判定</th></tr></thead><tbody>";
    var anyBlock = false;
    ccs.forEach(function (cc) {
      var list = results[cc];
      var cell = function (r) {
        if (!r) return final ? "<span class='muted small'>无结果</span>" : "<span class='spin'></span>";
        return r.ok
          ? "<span class='pill pill-good'>可达" + (r.delay != null ? " " + r.delay + "ms" : "") + "</span>"
          : "<span class='pill pill-bad'>失败</span>";
      };
      var okN = list ? list.filter(function (r) { return r.ok; }).length : -1;
      var verdict;
      if (!list) verdict = "<span class='muted small'>探针不足</span>";
      else if (okN === 2) verdict = "<span class='pill pill-good'>可访问</span>";
      else if (okN === 0) { verdict = "<span class='pill pill-bad'>均失败</span>"; anyBlock = true; }
      else verdict = "<span class='pill pill-warn'>结果不一致</span>";
      var loc = list && list[0] ? esc(list[0].probe) : "";
      html += "<tr><td>" + NP.flag(cc.toLowerCase()) + " " + esc(CC_NAME[cc] || cc) + (loc ? "<br><span class='muted small'>" + loc + "</span>" : "") + "</td>" +
        "<td>" + cell(list ? list[0] : null) + "</td><td>" + cell(list ? list[1] : null) + "</td><td>" + verdict + "</td></tr>";
    });
    html += "</tbody></table></div>";
    if (final) {
      html += "<div class='verdict " + (anyBlock ? "verdict-warn" : "verdict-safe") + "' style='margin-top:10px'>" +
        (anyBlock
          ? "△ 有探针全部访问失败。结合异常率与失败形态（连接重置/DNS 失败/超时）判断是否为封锁；也可能是目标站点对数据中心 IP 的限制。"
          : "✓ 所选国家的探针均可正常访问该域名。") + "</div>";
    }
    html += "</div>";
    document.getElementById("liveResult").innerHTML = html;
  }

  document.getElementById("runBtn").addEventListener("click", runObs);
  document.getElementById("domain").addEventListener("keydown", function (e) { if (e.key === "Enter") runObs(); });
  document.getElementById("liveBtn").addEventListener("click", runLive);
})();
