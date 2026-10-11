/* ============================================================
   NetProbe — IP 计算器（原创实现，纯本地）
   输入自动识别：
     · IPv4 / IPv6 地址与 CIDR（含 ::缩写、内嵌 IPv4、zone id）
     · 地址范围 a-b（v4/v6）→ 最少 CIDR 拆分（贪心对齐）
     · 前缀列表（逗号/空格/换行）→ 去除包含 + 合并相邻兄弟块
     · 纯十进制/0x 十六进制整数 → 还原地址（<2^32 视为 v4）
   数值一律用 BigInt，避免 32 位溢出。
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;

  var ZERO = 0n, ONE = 1n;
  var M32 = (ONE << 32n) - ONE;
  var M128 = (ONE << 128n) - ONE;

  /* ---------------- IPv4 ---------------- */
  function v4ToInt(s) {
    var p = s.split(".");
    if (p.length !== 4) return null;
    var n = ZERO;
    for (var i = 0; i < 4; i++) {
      if (!/^\d{1,3}$/.test(p[i])) return null;
      var o = parseInt(p[i], 10);
      if (o > 255) return null;
      n = (n << 8n) | BigInt(o);
    }
    return n;
  }
  function intToV4(n) {
    return [(n >> 24n) & 255n, (n >> 16n) & 255n, (n >> 8n) & 255n, n & 255n].map(String).join(".");
  }
  function v4MaskBits(prefix) {
    if (prefix === 0) return ZERO;
    return (~((ONE << BigInt(32 - prefix)) - ONE)) & M32;
  }
  function v4Type(n) {
    var a = Number((n >> 24n) & 255n), b = Number((n >> 16n) & 255n);
    if (a === 127) return "回环地址";
    if (a === 10) return "私有地址 (RFC1918)";
    if (a === 172 && b >= 16 && b <= 31) return "私有地址 (RFC1918)";
    if (a === 192 && b === 168) return "私有地址 (RFC1918)";
    if (a === 169 && b === 254) return "链路本地 (APIPA)";
    if (a === 100 && b >= 64 && b <= 127) return "运营商级 NAT (CGNAT)";
    if (a >= 224 && a <= 239) return "组播地址";
    if (a >= 240) return "保留地址";
    if (a === 0) return "保留（本网络）";
    return "公网地址";
  }

  /* ---------------- IPv6 ---------------- */
  function expandV6(s) {
    var zone = "";
    var si = s.indexOf("%");
    if (si !== -1) { zone = s.slice(si + 1); s = s.slice(0, si); }
    var tail4 = null;
    var m = s.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
    if (m) {
      tail4 = v4ToInt(m[2]);
      if (tail4 === null) return null;
      s = m[1] + ((tail4 >> 16n) & 0xffffn).toString(16) + ":" + (tail4 & 0xffffn).toString(16);
    }
    var dc = s.split("::");
    if (dc.length > 2) return null;
    var head = dc[0] ? dc[0].split(":").filter(Boolean) : [];
    var tail = dc.length === 2 ? (dc[1] ? dc[1].split(":").filter(Boolean) : []) : [];
    var missing = 8 - head.length - tail.length;
    if (dc.length === 2) { if (missing < 1) return null; }
    else if (head.length !== 8) return null;
    var groups = [];
    for (var i = 0; i < head.length; i++) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(head[i])) return null;
      groups.push(parseInt(head[i], 16));
    }
    if (dc.length === 2) for (var j = 0; j < missing; j++) groups.push(0);
    for (var k = 0; k < tail.length; k++) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(tail[k])) return null;
      groups.push(parseInt(tail[k], 16));
    }
    if (groups.length !== 8) return null;
    return { groups: groups, zone: zone };
  }
  function v6ToBig(groups) {
    var n = ZERO;
    for (var i = 0; i < 8; i++) n = (n << 16n) | BigInt(groups[i]);
    return n;
  }
  function bigToGroups(n) {
    var gs = [];
    for (var i = 0; i < 8; i++) gs[i] = Number((n >> BigInt((7 - i) * 16)) & 0xffffn);
    return gs;
  }
  function bigToV6(n) {
    return compressV6(bigToGroups(n));
  }
  function compressV6(gs) {
    var bestS = -1, bestL = 0, curS = -1, curL = 0;
    for (var i = 0; i < 8; i++) {
      if (gs[i] === 0) {
        if (curS < 0) { curS = i; curL = 1; } else curL++;
        if (curL > bestL) { bestS = curS; bestL = curL; }
      } else { curS = -1; curL = 0; }
    }
    if (bestL < 2) bestS = -1;
    var parts = [];
    for (var j = 0; j < 8; j++) {
      if (j === bestS) {
        parts.push("");
        j += bestL - 1;
        if (bestS + bestL === 8) parts.push("");
        continue;
      }
      parts.push(gs[j].toString(16));
    }
    return parts.join(":");
  }
  function v6Type(groups, n) {
    if (n === ZERO) return "未指定地址 (::)";
    if (n === ONE) return "回环地址 (::1)";
    if (groups[5] === 0xffff) return "IPv4 映射地址 (::ffff:x.x.x.x)";
    if ((groups[0] & 0xff00) === 0xff00) return "组播地址 (ff00::/8)";
    if ((groups[0] & 0xffc0) === 0xfe80) return "链路本地 (fe80::/10)";
    if ((groups[0] & 0xfe00) === 0xfc00) return "唯一本地地址 (ULA, fc00::/7)";
    if (groups[0] === 0x2001 && groups[1] === 0x0db8) return "文档专用 (2001:db8::/32)";
    if (groups[0] === 0x2001 && groups[1] === 0x0000) return "Teredo 隧道 (2001::/32)";
    if (groups[0] === 0x2002) return "6to4 隧道 (2002::/16)";
    return "全球单播 (2000::/3)";
  }
  /* EUI-64：IID 前 8 字节中第 4-5 字节为 ff:fe，翻转第 1 字节第 2 低位得 MAC */
  function v6Eui64Mac(groups) {
    var g4 = groups[4], g5 = groups[5], g6 = groups[6], g7 = groups[7];
    var b0 = (g4 >> 8) & 0xff, b1 = g4 & 0xff, b2 = (g5 >> 8) & 0xff;
    if ((g5 & 0xff) !== 0xff || ((g6 >> 8) & 0xff) !== 0xfe) return null;
    if (!g4 && !g5 && !g6 && !g7) return null;
    var bytes = [b0 ^ 0x02, b1, b2, g6 & 0xff, (g7 >> 8) & 0xff, g7 & 0xff];
    return bytes.map(function (x) { return x.toString(16).padStart(2, "0").toUpperCase(); }).join(":");
  }

  /* ---------------- 范围 → 最少 CIDR（贪心对齐） ---------------- */
  function rangeToPrefixes(start, end, bits, toStr) {
    var out = [];
    var cur = start;
    var guard = 0;
    while (cur <= end && guard++ < 4096) {
      var align = 0;
      if (cur === ZERO) align = bits;
      else {
        var t = cur;
        while ((t & ONE) === ZERO && align < bits) { t >>= ONE; align++; }
      }
      var remaining = end - cur + ONE;
      var p = BigInt(align);
      while (p > ZERO && (ONE << p) > remaining) p -= ONE;
      var size = ONE << p;
      out.push(toStr(cur, bits - Number(p)));
      cur += size;
    }
    return out;
  }

  /* ---------------- 前缀列表合并 ---------------- */
  function mergePrefixes(items, bits, toStr) {
    // 规范化：对齐到自己的掩码
    var norm = items.map(function (x) {
      var size = ONE << BigInt(bits - x.prefix);
      return { start: x.start & ~(size - ONE), prefix: x.prefix };
    }).sort(function (a, b) {
      return a.start < b.start ? -1 : a.start > b.start ? 1 : a.prefix - b.prefix;
    });
    // 去除被包含项
    var kept = [];
    for (var i = 0; i < norm.length; i++) {
      var it = norm[i];
      var size = ONE << BigInt(bits - it.prefix);
      var end = it.start + size - ONE;
      var covered = kept.some(function (k) {
        var ks = ONE << BigInt(bits - k.prefix);
        return k.start <= it.start && (k.start + ks - ONE) >= end;
      });
      if (!covered) kept.push(it);
    }
    // 相邻同长兄弟块 → 合并为大一号块，循环直到不动点
    var changed = true;
    while (changed) {
      changed = false;
      kept.sort(function (a, b) { return a.start < b.start ? -1 : a.start > b.start ? 1 : a.prefix - b.prefix; });
      outer:
      for (var a = 0; a < kept.length; a++) {
        for (var b = 0; b < kept.length; b++) {
          if (a === b) continue;
          var ka = kept[a], kb = kept[b];
          if (ka.prefix !== kb.prefix || ka.prefix === 0) continue;
          var half = ONE << BigInt(bits - ka.prefix);
          if (kb.start !== ka.start + half) continue;
          if (ka.start % (half * 2n) !== ZERO) continue; // a 必须落在偶数半块上
          var merged = { start: ka.start, prefix: ka.prefix - 1 };
          kept = kept.filter(function (x) { return x !== ka && x !== kb; });
          kept.push(merged);
          changed = true;
          break outer;
        }
      }
    }
    kept.sort(function (x, y) { return x.start < y.start ? -1 : 1; });
    return kept.map(function (x) { return toStr(x.start, x.prefix); });
  }

  /* ---------------- 解析入口 ---------------- */
  function parseInput(raw) {
    var s = (raw || "").trim();
    if (!s) return null;
    if (/^(0x[0-9a-fA-F]+|\d+)$/.test(s)) {
      var big = BigInt(s);
      if (big <= M32) return { kind: "int4", n: big };
      if (big <= M128) return { kind: "int6", n: big };
      return { kind: "bad", msg: "数字超出 IPv6 地址空间" };
    }
    var list = s.split(/[\s,;]+/).filter(Boolean);
    if (list.length > 1) {
      var parsed = [];
      for (var i = 0; i < list.length; i++) {
        var one = parsePrefix(list[i]);
        if (!one) return { kind: "bad", msg: "第 " + (i + 1) + " 项「" + list[i] + "」不是合法前缀（每项需带 /掩码）" };
        parsed.push(one);
      }
      var all4 = parsed.every(function (p) { return p.is4; });
      var all6 = parsed.every(function (p) { return !p.is4; });
      if (!all4 && !all6) return { kind: "bad", msg: "列表里混用了 IPv4 与 IPv6 前缀" };
      return { kind: all4 ? "list4" : "list6", items: parsed };
    }
    var rm = s.match(/^(.+?)\s*[-–]\s*(.+)$/);
    if (rm && rm[1].indexOf("/") === -1 && rm[2].indexOf("/") === -1) {
      var a = parseAddr(rm[1]), b = parseAddr(rm[2]);
      if (a && b && a.is4 === b.is4) {
        if (a.n > b.n) return { kind: "bad", msg: "范围的起点大于终点" };
        return { kind: a.is4 ? "range4" : "range6", start: a.n, end: b.n };
      }
      if (a && b) return { kind: "bad", msg: "范围两端必须同为 IPv4 或同为 IPv6" };
    }
    var pre = parsePrefix(s);
    if (pre) return pre.is4 ? { kind: "cidr4", start: pre.start, prefix: pre.prefix }
                            : { kind: "cidr6", start: pre.start, prefix: pre.prefix, groups: pre.groups };
    var addr = parseAddr(s);
    if (addr) return addr.is4 ? { kind: "addr4", n: addr.n, start: addr.n } : { kind: "addr6", n: addr.n, start: addr.n, groups: addr.groups, zone: addr.zone || "" };
    return { kind: "bad", msg: "无法识别的输入" };
  }
  function parseAddr(s) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
      var n = v4ToInt(s);
      return n === null ? null : { is4: true, n: n };
    }
    var ex = expandV6(s);
    if (ex) return { is4: false, n: v6ToBig(ex.groups), groups: ex.groups, zone: ex.zone };
    return null;
  }
  function parsePrefix(s) {
    var m = s.match(/^(.+)\/(\d{1,3})$/);
    if (!m) return null;
    var bits = parseInt(m[2], 10);
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(m[1])) {
      var n = v4ToInt(m[1]);
      if (n === null || bits > 32) return null;
      return { is4: true, prefix: bits, start: n & v4MaskBits(bits) };
    }
    var ex = expandV6(m[1]);
    if (ex) {
      if (bits > 128) return null;
      return { is4: false, prefix: bits, start: v6ToBig(ex.groups), groups: ex.groups };
    }
    return null;
  }

  /* ---------------- 渲染 ---------------- */
  function card(title, rows, extra) {
    var html = "<div class='card' style='margin-top:14px'><p class='card-title'>" + esc(title) + "</p><div class='kv-rows'>";
    rows.forEach(function (r) {
      html += "<div class='kv-row'><span class='k'>" + esc(r[0]) + "</span><span class='v" +
        (r[2] ? " ip-cell" : "") + "'>" + r[1] + "</span></div>";
    });
    html += "</div>" + (extra || "") + "</div>";
    return html;
  }
  function code(s) { return "<span style='font-family:var(--mono,monospace)'>" + esc(s) + "</span>"; }
  function fmtBigCount(n) {
    if (n < 10000n) return n.toString();
    if (n < (ONE << 32n)) return (n / 10000n).toString() + " 万+";
    return "约 2^" + (n.toString(2).length - 1) + " 个";
  }

  function render(res) {
    var badge = document.getElementById("kindBadge");
    badge.style.display = "";
    var out = "";
    var NAMES = {
      addr4: "IPv4 地址", addr6: "IPv6 地址", cidr4: "IPv4 网段 (CIDR)", cidr6: "IPv6 网段 (CIDR)",
      range4: "IPv4 地址范围", range6: "IPv6 地址范围", list4: "IPv4 前缀列表", list6: "IPv6 前缀列表",
      int4: "整数 → IPv4", int6: "整数 → IPv6", bad: "无法识别",
    };
    badge.textContent = res.kind === "bad" ? "识别失败" : "识别为：" + NAMES[res.kind];

    if (res.kind === "bad") {
      document.getElementById("outArea").innerHTML =
        "<div class='card' style='margin-top:14px'><div class='verdict verdict-warn'>" + esc(res.msg || "无法识别输入") +
        "。支持：IPv4/IPv6 地址、CIDR（如 10.0.0.0/8）、范围（10.0.0.5-10.0.0.20）、前缀列表（逗号/空格分隔）、纯数字。</div></div>";
      return;
    }

    if (res.kind === "addr4" || res.kind === "cidr4") {
      var isCidr = res.kind === "cidr4";
      var prefix = isCidr ? res.prefix : 32;
      var mask = v4MaskBits(prefix);
      var net = res.start & mask;
      var size = ONE << BigInt(32 - prefix);
      var bcast = net + size - ONE;
      var usable = prefix === 32 ? ONE : prefix === 31 ? 2n : size - 2n;
      var rows = [
        ["地址", code(intToV4(res.start)), 1],
        ["类型", esc(v4Type(res.start))],
        ["CIDR 写法", code(intToV4(net) + "/" + prefix), 1],
        ["子网掩码", code(intToV4(mask)), 1],
        ["反掩码 (wildcard)", code(intToV4(~mask & M32)), 1],
        ["网络地址", code(intToV4(net)), 1],
        ["广播地址", prefix < 31 ? code(intToV4(bcast)) : "—（/31、/32 无广播地址）", 1],
        ["地址总数", size.toString()],
        ["可用主机数", usable.toString() + (prefix < 31 ? "（扣除网络与广播）" : "")],
      ];
      if (!isCidr) rows.push(["整数形式", res.n.toString()]);
      if (prefix < 31) {
        rows.push(["第一个可用", code(intToV4(net + ONE)), 1]);
        rows.push(["最后一个可用", code(intToV4(bcast - ONE)), 1]);
      }
      out += card("IPv4 子网信息", rows);
    }

    if (res.kind === "addr6" || res.kind === "cidr6") {
      var isC6 = res.kind === "cidr6";
      var pre6 = isC6 ? res.prefix : 128;
      var sizeB = ONE << BigInt(128 - pre6);
      var net6 = pre6 === 0 ? ZERO : (res.start & (~(sizeB - ONE) & M128));
      var groups = res.groups || bigToGroups(res.start);
      var rows6 = [
        ["地址", code(bigToV6(res.start) + (res.zone ? "%" + res.zone : "")), 1],
        ["完整展开", code(bigToGroups(res.start).map(function (g) { return g.toString(16).padStart(4, "0"); }).join(":")), 1],
        ["类型", esc(v6Type(groups, res.start))],
        ["CIDR 写法", code(bigToV6(net6) + "/" + pre6), 1],
        ["地址总数", fmtBigCount(sizeB)],
        ["首地址", code(bigToV6(net6)), 1],
        ["末地址", code(bigToV6(net6 + sizeB - ONE)), 1],
      ];
      out += card("IPv6 地址信息", rows6);

      if (pre6 > 64) {
        var iid = res.start & ((ONE << 64n) - ONE);
        var mac = v6Eui64Mac(groups);
        var gs = bigToGroups(iid);
        var rowsE = [["接口标识（IID）", code(gs.map(function (g) { return g.toString(16).padStart(4, "0"); }).join(":")), 1]];
        if (mac) {
          rowsE.push(["内嵌 MAC（EUI-64）", code(mac) + " <span class='pill pill-bad'>暴露风险</span>", 1]);
          rowsE.push(["说明", "该地址的接口标识由网卡 MAC 生成，设备可被跨网络追踪；建议开启系统的随机接口标识（隐私扩展）"]);
        } else {
          rowsE.push(["MAC 推断", "接口标识不是 EUI-64 格式（缺少 ff:fe 标记），未直接暴露网卡 MAC"]);
        }
        out += card("接口标识解读", rowsE);
      }
    }

    if (res.kind === "int4" || res.kind === "int6") {
      var is4 = res.kind === "int4";
      out += card("整数还原", [
        ["输入数字", code(res.n.toString())],
        ["十六进制", code("0x" + res.n.toString(16).toUpperCase())],
        ["还原为 " + (is4 ? "IPv4" : "IPv6"), code(is4 ? intToV4(res.n) : bigToV6(res.n)), 1],
        ["类型", esc(is4 ? v4Type(res.n) : v6Type(bigToGroups(res.n), res.n))],
      ]);
    }

    if (res.kind === "range4" || res.kind === "range6") {
      var bitsR = res.kind === "range4" ? 32 : 128;
      var baseR = res.kind === "range4" ? intToV4 : bigToV6;
      var toStrR = function (n, p) { return baseR(n) + "/" + p; };
      var listR = rangeToPrefixes(res.start, res.end, bitsR, toStrR);
      var rowsR = [
        ["起始", code(toStrR(res.start)), 1],
        ["结束", code(toStrR(res.end)), 1],
        ["地址总数", fmtBigCount(res.end - res.start + ONE)],
        ["最少 CIDR 条数", listR.length + " 条"],
      ];
      out += card("范围 → 最少 CIDR 拆分", rowsR,
        "<div class='code-box' style='margin-top:8px;max-height:240px;overflow:auto'>" + esc(listR.join("\n")) + "</div>");
    }

    if (res.kind === "list4" || res.kind === "list6") {
      var bitsL = res.kind === "list4" ? 32 : 128;
      var baseL = res.kind === "list4" ? intToV4 : bigToV6;
      var toStrL = function (n, p) { return baseL(n) + "/" + p; };
      var merged = mergePrefixes(res.items, bitsL, toStrL);
      var origs = res.items.map(function (p) {
        return baseL(p.start) + "/" + p.prefix;
      });
      out += card("前缀列表合并", [
        ["输入条数", res.items.length + " 条"],
        ["合并后条数", merged.length + " 条"],
      ],
        "<div class='muted small' style='margin-top:6px'>输入：</div><div class='code-box' style='max-height:120px;overflow:auto'>" + esc(origs.join("\n")) + "</div>" +
        "<div class='muted small' style='margin-top:6px'>合并后：</div><div class='code-box' style='max-height:240px;overflow:auto'>" + esc(merged.join("\n")) + "</div>");
    }

    document.getElementById("outArea").innerHTML = out;
  }

  function calc() {
    try {
      render(parseInput(document.getElementById("expr").value));
    } catch (e) {
      document.getElementById("outArea").innerHTML =
        "<div class='card' style='margin-top:14px'><div class='verdict verdict-bad'>计算出错：" + esc(e.message || String(e)) + "</div></div>";
    }
  }

  var DEMOS = ["192.168.1.0/24", "2001:db8::1", "10.0.0.5-10.0.0.20", "10.0.1.0/24, 10.0.1.0/25, 10.0.2.0/24", "3221226219", "fe80::1234:56ff:fe78:9abc"];
  var demoIdx = 0;

  document.getElementById("calcBtn").addEventListener("click", calc);
  document.getElementById("expr").addEventListener("keydown", function (e) { if (e.key === "Enter") calc(); });
  document.getElementById("demoBtn").addEventListener("click", function () {
    document.getElementById("expr").value = DEMOS[demoIdx % DEMOS.length];
    demoIdx++;
    calc();
  });

  document.getElementById("expr").value = "192.168.1.0/24";
  calc();
})();
