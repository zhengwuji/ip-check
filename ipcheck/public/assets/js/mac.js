/* ============================================================
   NetProbe — MAC 地址查询（原创实现，纯本地）
   数据：IEEE OUI 注册库（standards-oui.ieee.org/oui/oui.csv 预处理后
   存为 /assets/data/oui.txt，行格式 "前缀,组织"，仅 /mac/ 页按需加载）。
   属性判定只看第 1 字节：bit0 = 单播/组播，bit1 = 全球/本地。
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;

  var ouiMap = null;   // Map(prefix6 → org)
  var ouiCount = 0;

  function loadOui() {
    if (ouiMap) return Promise.resolve(ouiMap);
    return fetch("/assets/data/oui.txt", { cache: "force-cache" })
      .then(function (r) { return r.text(); })
      .then(function (txt) {
        var m = new Map();
        txt.split("\n").forEach(function (line) {
          var i = line.indexOf(",");
          if (i !== 6) return;
          m.set(line.slice(0, 6), line.slice(7));
        });
        ouiMap = m;
        ouiCount = m.size;
        return m;
      });
  }

  /* 解析用户输入：支持 : - . 空格分隔、12/9/6 位十六进制、通配 * */
  function parseMac(raw) {
    var s = (raw || "").trim();
    if (!s) return null;
    // Cisco 式 aabb.ccdd.eeff
    var hex = s.replace(/[.:\-\s]/g, "").toUpperCase();
    if (/^[0-9A-F*]{6}$/.test(hex)) return { prefix: hex, full: false };
    if (/^[0-9A-F]{12}$/.test(hex)) return { prefix: hex.slice(0, 6), full: true, bytes: hex };
    if (/^[0-9A-F]{7,11}$/.test(hex)) return { prefix: hex.slice(0, 6), full: false, warn: "输入不足 12 位，按前缀 " + hex.slice(0, 6) + " 查询制造商" };
    return null;
  }

  function bytesOf(parsed) {
    var b = parsed.bytes || (parsed.prefix + "000000").slice(0, 12);
    var out = [];
    for (var i = 0; i < 12; i += 2) out.push(parseInt(b.slice(i, i + 2), 16));
    return out;
  }

  function render(parsed, org) {
    var b = bytesOf(parsed);
    var isMulticast = (b[0] & 0x01) === 1;
    var isLocal = (b[0] & 0x02) !== 0;
    var blockStart = parsed.prefix + ":00:00:00";
    var blockEnd = parsed.prefix + ":FF:FF:FF";
    var blockSize = 16777216; // MA-L 满块 = /40 前缀下的 2^24 个地址

    var rows = [
      ["查询输入", "<span class='ip-cell'>" + esc(parsed.bytes || parsed.prefix) + "</span>", 1],
      ["OUI 前缀", "<span class='ip-cell'>" + esc(parsed.prefix) + "</span>", 1],
      ["制造商", org ? "<b>" + esc(org) + "</b>" : "<span class='muted'>未在 IEEE OUI 库中注册（可能是随机化地址或未收录前缀）</span>"],
      ["区块起始", "<span class='ip-cell'>" + esc(blockStart) + "</span>", 1],
      ["区块结束", "<span class='ip-cell'>" + esc(blockEnd) + "</span>", 1],
      ["区块大小", blockSize.toLocaleString() + " 个地址（MA-L 满块）"],
      ["地址类型", isMulticast
        ? "<span class='pill pill-warn'>组播 / 广播</span> 第 1 字节最低位为 1，不对应单一网卡"
        : "<span class='pill pill-good'>单播</span> 对应一块具体网卡"],
      ["管理属性", isLocal
        ? "<span class='pill pill-warn'>本地管理</span> 非 IEEE 分配，常见于随机化 MAC / 虚拟网卡 / 手工指定"
        : "<span class='pill pill-good'>全球唯一</span> 由 IEEE 分配给上表制造商"],
    ];
    if (isLocal) {
      var nib = (b[0] & 0x0f).toString(16).toUpperCase();
      rows.push(["随机化判断", (parsed.full && /[26AE]/.test(parsed.bytes[1]))
        ? "第 1 字节为 0x" + nib + "，符合常见随机化 MAC 的取值特征（第 2 位十六进制为 2/6/A/E）"
        : "本地管理地址；若来自手机/电脑 Wi-Fi，大概率是隐私随机化产物"]);
    }
    var extra = "";
    if (parsed.warn) extra = "<div class='muted small' style='margin-top:6px'>" + esc(parsed.warn) + "</div>";
    document.getElementById("outArea").innerHTML =
      card("制造商信息（IEEE OUI）", rows, extra) +
      card("地址属性", [
        ["单播 / 组播", isMulticast ? "组播（I/G=1）" : "单播（I/G=0）"],
        ["全球 / 本地", isLocal ? "本地管理（U/L=1）" : "全球唯一（U/L=0）"],
        ["完整字节", "<span class='ip-cell'>" + esc((parsed.bytes || parsed.prefix + ":00:00:00").replace(/:/g, parsed.bytes ? "" : ":")) + "</span>", 1],
      ]);
  }

  function card(title, rows, extra) {
    var html = "<div class='card' style='margin-top:14px'><p class='card-title'>" + esc(title) + "</p><div class='kv-rows'>";
    rows.forEach(function (r) {
      html += "<div class='kv-row'><span class='k'>" + esc(r[0]) + "</span><span class='v" + (r[2] ? " ip-cell" : "") + "'>" + r[1] + "</span></div>";
    });
    html += "</div>" + (extra || "") + "</div>";
    return html;
  }

  async function run() {
    var parsed = parseMac(document.getElementById("mac").value);
    var pt = document.getElementById("progressText");
    if (!parsed) {
      pt.textContent = "无法解析：请输入 12 位 MAC（冒号/横杠/空格均可）或 6 位前缀。";
      return;
    }
    pt.textContent = ouiMap ? "" : "加载 IEEE OUI 数据（约 1MB，首次稍慢）…";
    document.getElementById("outArea").innerHTML = "";
    try {
      await loadOui();
    } catch (e) {
      pt.textContent = "OUI 数据加载失败，请刷新重试。";
      return;
    }
    var org = ouiMap.get(parsed.prefix) || null;
    pt.textContent = "已检索 " + ouiCount.toLocaleString() + " 条 OUI 记录";
    render(parsed, org);
  }

  document.getElementById("runBtn").addEventListener("click", run);
  document.getElementById("mac").addEventListener("keydown", function (e) { if (e.key === "Enter") run(); });
  document.querySelectorAll("[data-demo]").forEach(function (a) {
    a.addEventListener("click", function () {
      document.getElementById("mac").value = a.dataset.demo;
      run();
    });
  });
})();
