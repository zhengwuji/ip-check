/* ============================================================
   NetProbe — IP 黑名单检查（原创实现）
   原理：DNSBL = 反转 IP 拼接 zone 的 A 记录查询，返回 127.0.0.x 即命中。
   查询通道：dns.google DoH JSON（浏览器直查，CORS 开放）。
   命中分三性质：bad 不良记录 / anon 匿名标记 / net 网段参考。
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;

  var CATS = {
    bad: { label: "不良记录", cls: "pill-bad" },
    anon: { label: "匿名标记", cls: "pill-warn" },
    net: { label: "网段参考", cls: "pill-info" },
  };

  /* zone 清单：class 为名单性质；note 为命中时的解读；delist 为移除入口 */
  var ZONES = [
    { z: "zen.spamhaus.org", c: "bad", note: "Spamhaus 综合（SBL+XBL+PBL），业界引用最广", delist: "https://check.spamhaus.org/", caveat: true },
    { z: "sbl.spamhaus.org", c: "bad", note: "Spamhaus 垃圾邮件/僵尸网络记录", delist: "https://check.spamhaus.org/", caveat: true },
    { z: "xbl.spamhaus.org", c: "bad", note: "Spamhaus 被入侵主机（CBL+NJABL）", delist: "https://check.spamhaus.org/", caveat: true },
    { z: "pbl.spamhaus.org", c: "net", note: "Spamhaus 政策名单：不应直接发信的动态/宽带段", delist: "https://check.spamhaus.org/", caveat: true },
    { z: "bl.spamcop.net", c: "bad", note: "SpamCop 用户举报式名单", delist: "https://www.spamcop.net/" },
    { z: "b.barracudacentral.org", c: "bad", note: "Barracuda 声誉名单（多数命中可在官网移除）", delist: "https://www.barracudacentral.org/lookups" },
    { z: "dnsbl.sorbs.net", c: "bad", note: "SORBS 聚合名单", delist: "https://www.sorbs.net/" },
    { z: "spam.dnsbl.sorbs.net", c: "bad", note: "SORBS 滥发垃圾邮件记录", delist: "https://www.sorbs.net/" },
    { z: "spam.spamrats.com", c: "bad", note: "SpamRats 垃圾邮件行为记录", delist: "https://www.spamrats.com/" },
    { z: "all.s5h.net", c: "bad", note: "s5h 开放代理与滥发记录" },
    { z: "dnsbl.imp.ch", c: "bad", note: "IMPF/eXpurgate 滥用记录" },
    { z: "bl.blocklist.de", c: "bad", note: "blocklist.de 攻击者 IP（ fail2ban 上报聚合）", delist: "https://www.blocklist.de/" },
    { z: "psbl.surriel.com", c: "bad", note: "PSBL 低误报垃圾邮件名单" },
    { z: "bl.mailspike.net", c: "bad", note: "Mailspike 声誉名单" },
    { z: "dnsbl.dronebl.org", c: "bad", note: "DroneBL 僵尸网络/被入侵主机", delist: "https://www.dronebl.org/" },
    { z: "truncate.gbudb.net", c: "bad", note: "GBUdb 极差信誉（整段清理）" },
    { z: "db.wpbl.info", c: "bad", note: "WPBL 垃圾邮件名单" },
    { z: "ips.backscatterer.org", c: "bad", note: "退信风暴（backscatter）源头" },
    { z: "dnsbl-1.uceprotect.net", c: "bad", note: "UCEPROTECT 一级（单 IP 精确）", delist: "http://www.uceprotect.net/" },
    { z: "dnsbl-2.uceprotect.net", c: "net", note: "UCEPROTECT 二级（/24 网段连带）", delist: "http://www.uceprotect.net/" },
    { z: "dnsbl-3.uceprotect.net", c: "net", note: "UCEPROTECT 三级（更粗的网段连带）", delist: "http://www.uceprotect.net/" },
    { z: "tor.dan.me.uk", c: "anon", note: "Tor 出口节点清单" },
    { z: "torexit.dan.me.uk", c: "anon", note: "Tor 出口节点清单（子集）" },
    { z: "dnsbl.proxybl.org", c: "anon", note: "开放代理/中继记录（ProxyBL）" },
    { z: "socks.dnsbl.sorbs.net", c: "anon", note: "SORBS 开放 SOCKS 代理" },
    { z: "http.dnsbl.sorbs.net", c: "anon", note: "SORBS 开放 HTTP 代理" },
    { z: "web.dnsbl.sorbs.net", c: "anon", note: "SORBS 被入侵的僵尸主机（web）" },
    { z: "misc.dnsbl.sorbs.net", c: "anon", note: "SORBS 杂项滥用（开放中继等）" },
    { z: "bogons.cymru.com", c: "net", note: "Team Cymru 保留/未分配地址（命中即异常）" },
    { z: "bl.score.senderscore.com", c: "net", note: "Senderscore 网段信誉（命中=低分网段）" },
    { z: "bl.0spam.org", c: "net", note: "0SPAM 项目名单（含段级记录）" },
    { z: "dnswl.spfbl.net", c: "net", note: "SPFBL 名单（反向语义，命中即列入）" },
  ];

  function isV4(s) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(s); }
  function isV6(s) { return s && s.indexOf(":") !== -1; }

  /* DNSBL 查询名：反转 IPv4 → 4.3.2.1.zone */
  function queryName(ip, zone) {
    return ip.split(".").reverse().join(".") + "." + zone;
  }

  async function dnsQuery(name) {
    // 优先浏览器直查 Google DoH；失败（网络不通/被墙）时回退本站服务器代查
    try {
      const r = await fetch("https://dns.google/resolve?name=" + encodeURIComponent(name) + "&type=A", {
        cache: "no-store",
        signal: AbortSignal.timeout(7000),
      });
      if (!r.ok) throw new Error("HTTP " + r.status);
      return await r.json();
    } catch (e) {
      const r2 = await fetch("/api/doh?u=" + encodeURIComponent("https://dns.google/resolve?name=" + name + "&type=A"), {
        cache: "no-store",
        signal: AbortSignal.timeout(12000),
      });
      if (!r2.ok) throw new Error("HTTP " + r2.status);
      return await r2.json();
    }
  }

  async function dnsblQuery(ip, zone) {
    // DNSBL = 反转 IP 拼接 zone 的 A 记录查询；Spamhaus 系对公共解析器有限制，命中需人工复核
    var name = queryName(ip, zone);
    var d = await dnsQuery(name);
    if (d.Status !== 0 && d.Status !== 3) throw new Error("Status " + d.Status);
    var codes = [];
    (d.Answer || []).forEach(function (a) {
      if (a.type === 1 && /^127\.0\.0\.\d+$/.test(a.data)) codes.push(a.data);
    });
    // NXDOMAIN / 空答案 = 未列入
    return codes; // 空 = 未命中
  }

  function buildTable() {
    document.getElementById("resBody").innerHTML = ZONES.map(function (it, i) {
      return "<tr id='bl-" + i + "'>" +
        "<td><span style='font-family:var(--mono,monospace);font-size:0.86em'>" + esc(it.z) + "</span>" +
        (it.caveat ? " <span class='muted small' title='该名单限制从公共 DNS 查询，结果仅供初筛'>⚠</span>" : "") + "</td>" +
        "<td><span class='pill " + CATS[it.c].cls + "'>" + CATS[it.c].label + "</span></td>" +
        "<td class='st-cell'><span class='spin'></span></td>" +
        "<td class='muted small note-cell'>—</td></tr>";
    }).join("");
  }

  function updateRow(i, codes, err) {
    var tr = document.getElementById("bl-" + i);
    if (!tr) return;
    var st = tr.querySelector(".st-cell");
    var note = tr.querySelector(".note-cell");
    var it = ZONES[i];
    if (err) {
      st.innerHTML = "<span class='muted small'>查询失败</span>";
      note.textContent = "";
      return;
    }
    if (!codes.length) {
      st.innerHTML = "<span class='pill pill-good'>未命中</span>";
      note.textContent = "";
      return;
    }
    st.innerHTML = "<span class='pill " + CATS[it.c].cls + "'>命中</span>";
    var extra = it.delist ? " <a href='" + esc(it.delist) + "' target='_blank' rel='noopener noreferrer' class='small'>移除申请 ↗</a>" : "";
    note.innerHTML = esc(it.note) + "（返回 " + esc(codes.join(", ")) + "）" + extra;
  }

  function renderSummary(ip, stats, caveatHits) {
    var total = ZONES.length;
    var el = document.getElementById("summary");
    var parts = "检查 <b>" + esc(ip) + "</b>：" +
      "<span class='pill " + (stats.bad ? "pill-bad" : "pill-good") + "'>不良记录 " + stats.bad + "</span> " +
      "<span class='pill " + (stats.anon ? "pill-warn" : "pill-good") + "'>匿名标记 " + stats.anon + "</span> " +
      "<span class='pill " + (stats.net ? "pill-info" : "pill-muted") + "'>网段参考 " + stats.net + "</span> " +
      "<span class='muted small'>共 " + total + " 个名单</span>";
    el.innerHTML = parts + "<div style='margin-top:8px'>";
    if (!stats.bad && !stats.anon && !stats.net) {
      el.innerHTML += "<div class='verdict verdict-safe'>✓ 全部名单未命中。该 IP 在主流 DNSBL 里声誉良好。</div>";
    } else {
      var lines = [];
      if (stats.bad) lines.push("存在不良记录命中：发信、注册等场景可能被拦截，建议按行内「移除申请」处理。");
      if (stats.anon) lines.push("被标记为匿名网络出口：如果你正在使用代理/VPN，这属于正常现象；网站可能因此要求额外验证。");
      if (stats.net) lines.push("有网段级参考命中：标记的是整个地址段的属性（动态池/粗名单），不代表你本人有滥用行为。");
      el.innerHTML += "<div class='verdict " + (stats.bad ? "verdict-warn" : "verdict-info") + "'>" + lines.join("<br>") + "</div>";
    }
    if (caveatHits) {
      el.innerHTML += "<div class='muted small' style='margin-top:6px'>⚠ 含 Spamhaus 系命中：该名单限制从公共 DNS 查询，公共解析器路径可能返回受限结果，命中请以 <a href='https://check.spamhaus.org/' target='_blank' rel='noopener noreferrer'>官方查询页</a> 为准。</div>";
    }
    el.innerHTML += "</div>";
  }

  async function run() {
    var btn = document.getElementById("runBtn");
    btn.disabled = true;
    var ip = document.getElementById("ip").value.trim();
    if (!ip) {
      document.getElementById("progressText").textContent = "正在获取你的出口 IP…";
      var t = await NP.selfTrace();
      ip = t && t.ip ? t.ip : "";
    }
    if (!isV4(ip)) {
      document.getElementById("progressText").textContent = isV6(ip)
        ? "该 IP 是 IPv6 地址：绝大多数传统 DNSBL 只支持 IPv4，请提供一个 IPv4 地址。"
        : "请输入合法的 IPv4 地址（如 1.2.3.4）。";
      btn.disabled = false;
      return;
    }
    document.getElementById("summaryCard").style.display = "";
    document.getElementById("resultCard").style.display = "";
    document.getElementById("summary").innerHTML = "<span class='spin'></span> 检测中…";
    buildTable();

    var stats = { bad: 0, anon: 0, net: 0 };
    var done = 0, caveatHits = false;
    await NP.withLimit(ZONES, 8, async function (it, i) {
      try {
        var codes = await dnsblQuery(ip, it.z);
        updateRow(i, codes, null);
        if (codes.length) {
          stats[it.c]++;
          if (it.caveat) caveatHits = true;
        }
      } catch (e) {
        updateRow(i, null, e);
      }
      done++;
      document.querySelector("#progress i").style.width = Math.round((done / ZONES.length) * 100) + "%";
      document.getElementById("progressText").textContent = "查询名单中…（" + done + "/" + ZONES.length + "）";
    });
    document.getElementById("progressText").textContent = "完成（" + ZONES.length + " 个名单 · " + esc(ip) + "）";
    renderSummary(ip, stats, caveatHits);
    btn.disabled = false;
  }

  document.getElementById("runBtn").addEventListener("click", run);
  document.getElementById("ip").addEventListener("keydown", function (e) { if (e.key === "Enter") run(); });
})();
