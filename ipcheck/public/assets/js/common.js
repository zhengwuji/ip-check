/* ============================================================
   NetProbe — 公共脚本（原创实现）
   导航注入 / 主题切换 / 通用工具函数
   ============================================================ */
(function () {
  "use strict";

  /* 全局脚本错误横幅：脚本异常时给出可见提示（通常是浏览器缓存了旧版脚本） */
  window.addEventListener("error", function (e) {
    if (window.__npErrShown || !e || !e.message) return;
    window.__npErrShown = true;
    var b = document.createElement("div");
    b.style.cssText = "position:fixed;top:0;left:0;right:0;z-index:9999;background:#b91c1c;color:#fff;padding:8px 14px;font-size:13px;text-align:center";
    b.innerHTML = "页面脚本异常：" + String(e.message).replace(/[<>]/g, "") +
      " —— 请按 <b>Ctrl+F5</b> 强制刷新；若仍复现请联系站长。";
    (document.body || document.documentElement).appendChild(b);
  }, true);
  window.addEventListener("unhandledrejection", function (e) {
    if (window.__npErrShown || !e || !e.reason) return;
    var msg = e.reason && e.reason.message ? e.reason.message : String(e.reason);
    if (!msg) return;
    window.__npErrShown = true;
    var b = document.createElement("div");
    b.style.cssText = "position:fixed;top:0;left:0;right:0;z-index:9999;background:#b91c1c;color:#fff;padding:8px 14px;font-size:13px;text-align:center";
    b.innerHTML = "页面脚本异常：" + String(msg).replace(/[<>]/g, "") +
      " —— 请按 <b>Ctrl+F5</b> 强制刷新；若仍复现请联系站长。";
    (document.body || document.documentElement).appendChild(b);
  });

  /* ---------- 主题：cookie + localStorage 双写，auto 跟随系统 ---------- */
  function readCookie(name) {
    var m = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
    return m ? decodeURIComponent(m[1]) : null;
  }
  function writeThemeCookie(v) {
    var base = "; path=/; max-age=31536000; samesite=lax";
    if (location.protocol === "https:") base += "; secure";
    document.cookie = "theme=" + encodeURIComponent(v) + base;
  }
  function clearThemeCookie() {
    document.cookie = "theme=; path=/; max-age=0";
  }
  function currentMode() {
    return readCookie("theme") || localStorage.getItem("theme") || "auto";
  }
  function effectiveMode() {
    var c = currentMode();
    if (c === "auto") return matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    return c;
  }
  function applyTheme() {
    document.documentElement.setAttribute("data-theme", effectiveMode());
  }
  function setMode(mode) {
    if (mode === "auto") {
      localStorage.removeItem("theme");
      clearThemeCookie();
      document.documentElement.removeAttribute("data-theme");
    } else {
      localStorage.setItem("theme", mode);
      writeThemeCookie(mode);
      document.documentElement.setAttribute("data-theme", mode);
    }
    paintThemeBtn();
  }
  function paintThemeBtn() {
    var btn = document.getElementById("ts-btn");
    var menu = document.getElementById("ts-menu");
    if (!btn || !menu) return;
    var cur = currentMode();
    btn.querySelectorAll("[data-mode-icon]").forEach(function (el) {
      el.style.display = el.dataset.modeIcon === cur ? "block" : "none";
    });
    menu.querySelectorAll(".ts-item").forEach(function (it) {
      if (it.dataset.mode === cur) it.setAttribute("aria-current", "true");
      else it.removeAttribute("aria-current");
    });
  }
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function () {
    if (currentMode() === "auto") applyTheme();
  });
  applyTheme();

  /* ---------- 导航 ---------- */
  var NAV_ITEMS = [
    { href: "/", full: "IP查询", short: "查询" },
    { href: "/claude/", full: "Claude 检测", short: "Claude" },
    { href: "/ip/", full: "IP评分", short: "评分" },
    { href: "/gpt/", full: "GPT 检测", short: "GPT" },
    { href: "/link/", full: "网络连通", short: "连通" },
    { href: "/egress/", full: "分流出口", short: "出口" },
    { href: "/dns/", full: "DNS泄露", short: "DNS" },
    { href: "/webrtc/", full: "WebRTC", short: "UDP" },
    { href: "/speed/", full: "网速测试", short: "测速" },
    { href: "/fingerprint/", full: "指纹检测", short: "指纹" },
    { href: "/cloudflare/", full: "Cloudflare", short: "CF" },
    { href: "/ping/", full: "全球Ping", short: "Ping" },
    { href: "/status/", full: "服务状态", short: "状态" },
  ];
  var NAV_MORE = [
    { href: "/whois/", full: "Whois查询", short: "Whois" },
    { href: "/dnsresolve/", full: "DNS解析对比", short: "解析" },
    { href: "/blocklist/", full: "IP黑名单", short: "黑名单" },
    { href: "/censor/", full: "封锁测试", short: "封锁" },
    { href: "/persona/", full: "画像检测", short: "画像" },
    { href: "/ipcalc/", full: "IP计算器", short: "计算器" },
    { href: "/mac/", full: "MAC查询", short: "MAC" },
    { href: "/checklist/", full: "安全清单", short: "清单" },
    { href: "/news/", full: "AI资讯", short: "资讯" },
    { href: "/card/", full: "IP卡片", short: "卡片" },
    { href: "/torrent/", full: "Torrent 检测", short: "Torrent" },
    { href: "/compare/", full: "IP对比", short: "对比" },
    { href: "/docs/", full: "API文档", short: "API" },
  ];

  function buildNav() {
    var host = document.getElementById("nav");
    if (!host) return;
    var path = location.pathname;
    function isActive(href) {
      if (href === "/") return path === "/" || path === "/index.html";
      return path.indexOf(href) === 0;
    }
    var mq = matchMedia("(max-width: 860px)");

    function navHtml(itemsBar, moreBar) {
      // itemsBar / moreBar：平铺在主导航里的主项与次级项（其余全部收进「更多」下拉）
      function topLink(it) {
        var cls = isActive(it.href) ? ' class="active" aria-current="page"' : "";
        var title = it.full !== it.short ? ' title="' + it.full + '"' : "";
        return '<a href="' + it.href + '"' + cls + title + '><span class="full">' + it.full + '</span><span class="short" style="display:none">' + it.short + "</span></a>";
      }
      var html = '<div class="nav-scroll">' +
        '<a href="/" class="brand"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M3.5 9h17M3.5 15h17M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/></svg>NetProbe</a>';
      itemsBar.forEach(function (it) { html += topLink(it); });
      moreBar.forEach(function (it) { html += topLink(it); });
      html += "</div>";
      // 「更多」下拉必须放在 .nav-scroll 之外，否则 overflow-x:auto 会把下拉菜单裁掉。
      // 菜单内容 = 未平铺的主项（按原顺序）+ 未平铺的次级项
      var menuList = NAV_ITEMS.filter(function (it) { return itemsBar.indexOf(it) === -1; })
        .concat(NAV_MORE.filter(function (it) { return moreBar.indexOf(it) === -1; }));
      var moreActive = menuList.some(function (it) { return isActive(it.href); });
      html += '<div class="ts-wrap nav-more" id="nav-more-wrap"' + (menuList.length ? "" : ' style="display:none"') + ">" +
        '<button class="ts-btn nav-more-btn' + (moreActive ? " active" : "") + '" id="nav-more-btn" aria-haspopup="menu" aria-expanded="false">更多</button>' +
        '<div class="ts-menu" id="nav-more-menu" role="menu">' +
        menuList.map(function (it) {
          return '<a class="ts-item' + (isActive(it.href) ? " active" : "") + '" href="' + it.href + '" role="menuitem">' + it.full + "</a>";
        }).join("") +
        "</div></div>";
      // 语言切换（英文入口页）
      html += '<a href="' + (path === "/en/" || path.indexOf("/en/") === 0 ? "/" : "/en/") + '" style="flex:0 0 auto;font-size:0.85em;padding:5px 8px" title="English">' +
        (path.indexOf("/en/") === 0 ? "中文" : "EN") + "</a>";
      html +=
        '<div class="ts-wrap" id="ts-wrap">' +
        '<button class="ts-btn" id="ts-btn" aria-label="切换主题模式" aria-haspopup="menu" aria-expanded="false">' +
        '<svg data-mode-icon="light" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>' +
        '<svg data-mode-icon="dark" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" style="display:none"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>' +
        '<svg data-mode-icon="auto" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:none"><circle cx="12" cy="12" r="9"/><path d="M12 3 A 9 9 0 0 0 12 21 Z" fill="currentColor" stroke="none"/></svg>' +
        "</button>" +
        '<div class="ts-menu" id="ts-menu" role="menu">' +
        '<button class="ts-item" data-mode="light" role="menuitem">亮色模式</button>' +
        '<button class="ts-item" data-mode="dark" role="menuitem">暗黑模式</button>' +
        '<button class="ts-item" data-mode="auto" role="menuitem">跟随系统</button>' +
        "</div></div>";
      return html;
    }

    // 每次渲染后绑定到新 DOM 的监听（随旧 DOM 一起销毁，不会累积）
    function attachNavEvents() {
      var btn = document.getElementById("ts-btn");
      var menu = document.getElementById("ts-menu");
      btn.addEventListener("click", function (e) {
        e.stopPropagation();
        var open = menu.classList.toggle("open");
        btn.setAttribute("aria-expanded", String(open));
      });
      menu.querySelectorAll(".ts-item").forEach(function (it) {
        it.addEventListener("click", function () {
          setMode(it.dataset.mode);
          menu.classList.remove("open");
          btn.setAttribute("aria-expanded", "false");
        });
      });

      var moreBtn = document.getElementById("nav-more-btn");
      var moreMenu = document.getElementById("nav-more-menu");
      if (moreBtn && moreMenu) {
        moreBtn.addEventListener("click", function (e) {
          e.stopPropagation();
          var open = moreMenu.classList.toggle("open");
          moreBtn.setAttribute("aria-expanded", String(open));
        });
      }
    }

    // 文档级监听只挂一次，事件时再查当前 DOM（fitNav 反复重建导航也不会重复堆积）
    document.addEventListener("click", function (e) {
      var tsMenu = document.getElementById("ts-menu");
      if (tsMenu && tsMenu.classList.contains("open") && !e.target.closest("#ts-wrap")) {
        tsMenu.classList.remove("open");
        var tsBtn = document.getElementById("ts-btn");
        if (tsBtn) tsBtn.setAttribute("aria-expanded", "false");
      }
      var moreMenu = document.getElementById("nav-more-menu");
      if (moreMenu && moreMenu.classList.contains("open") && !e.target.closest("#nav-more-wrap")) {
        moreMenu.classList.remove("open");
        var moreBtn = document.getElementById("nav-more-btn");
        if (moreBtn) moreBtn.setAttribute("aria-expanded", "false");
      }
    });
    document.addEventListener("keydown", function (e) {
      if (e.key !== "Escape") return;
      [["ts-menu", "ts-btn"], ["nav-more-menu", "nav-more-btn"]].forEach(function (ids) {
        var menu = document.getElementById(ids[0]);
        var btn = document.getElementById(ids[1]);
        if (menu && menu.classList.contains("open")) {
          menu.classList.remove("open");
          if (btn) { btn.setAttribute("aria-expanded", "false"); btn.focus(); }
        }
      });
    });

    // 窄屏时只显示短标题（仅顶层链接；「更多」下拉内条目不含短标题）
    function applyResponsive() {
      host.querySelectorAll(".nav-scroll > a:not(.brand)").forEach(function (a) {
        var f = a.querySelector(".full"), s = a.querySelector(".short");
        if (f) f.style.display = mq.matches ? "none" : "inline";
        if (s) s.style.display = mq.matches ? "inline" : "none";
      });
    }

    function renderNav(itemsBar, moreBar) {
      host.innerHTML = navHtml(itemsBar, moreBar);
      attachNavEvents();
      applyResponsive();
      scrollActiveNav();
    }

    // 移动端：导航条横向滚动时，让当前页的高亮项保持在可视区中央。
    // 字体/图标晚于首帧加载会改变条宽，因此即时设置后再校准两次。
    function scrollActiveNav() {
      var s = host.querySelector(".nav-scroll");
      if (!s) return;
      var a = s.querySelector("a.active");
      if (!a) return;
      var apply = function () {
        if (!s.isConnected || !a.isConnected) return;
        var sr = s.getBoundingClientRect(), ar = a.getBoundingClientRect();
        var rel = ar.left - sr.left + s.scrollLeft;
        var target = rel - (s.clientWidth - ar.width) / 2;
        target = Math.max(0, Math.min(target, s.scrollWidth - s.clientWidth));
        if (Math.abs(s.scrollLeft - target) > 2) s.scrollLeft = target;
      };
      apply();
      requestAnimationFrame(function () { requestAnimationFrame(apply); });
      setTimeout(apply, 300);
    }

    function navOverflowing() {
      var s = host.querySelector(".nav-scroll");
      return !!s && s.scrollWidth > s.clientWidth + 1;
    }

    // 先全部平铺；放不下时先收次级项，再从尾部收主项（当前页 active 项尽量保留在顶栏），
    // 手机上不做横向滑动——看不见的直接进「更多」。
    function fitNav() {
      var itemsBar = NAV_ITEMS.slice();
      var moreBar = NAV_MORE.slice();
      renderNav(itemsBar, moreBar);
      while (navOverflowing() && (moreBar.length > 0 || itemsBar.length > 1)) {
        if (moreBar.length > 0) {
          moreBar.pop();
        } else {
          var idx = -1;
          for (var i = itemsBar.length - 1; i >= 0; i--) {
            if (!isActive(itemsBar[i].href)) { idx = i; break; }
          }
          if (idx === -1) idx = itemsBar.length - 1;
          itemsBar.splice(idx, 1);
        }
        renderNav(itemsBar, moreBar);
      }
    }
    var fitTimer = null;
    function fitDebounced() {
      clearTimeout(fitTimer);
      fitTimer = setTimeout(fitNav, 120);
    }
    window.addEventListener("resize", fitDebounced);
    mq.addEventListener("change", fitDebounced);
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(fitNav);
    fitNav();
  }

  /* ---------- 工具函数 ---------- */
  var NP = (window.NP = {
    esc: function (s) {
      return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
        return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
      });
    },
    fetchT: function (url, opts, ms) {
      opts = opts || {};
      opts.signal = AbortSignal.timeout(ms || 6000);
      opts.cache = opts.cache || "no-store";
      return fetch(url, opts);
    },
    toast: function (msg) {
      var el = document.getElementById("np-toast");
      if (!el) {
        el = document.createElement("div");
        el.id = "np-toast";
        el.className = "toast";
        document.body.appendChild(el);
      }
      el.textContent = msg;
      el.classList.add("show");
      clearTimeout(NP._toastT);
      NP._toastT = setTimeout(function () { el.classList.remove("show"); }, 1600);
    },
    copy: function (text) {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(
          function () { NP.toast("已复制"); },
          function () { NP.toast("复制失败"); }
        );
      } else {
        var ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand("copy"); NP.toast("已复制"); } catch (e) { NP.toast("复制失败"); }
        ta.remove();
      }
    },
    // favicon：DuckDuckGo 图标服务；加载失败时保留首字母占位
    favicon: function (domain, name) {
      var initial = NP.esc((name || domain || "?").charAt(0));
      return (
        '<span class="fav-fallback">' + initial + "</span>" +
        '<img class="favicon" alt="" style="margin-left:-18px" src="https://icons.duckduckgo.com/ip3/' +
        NP.esc(domain) + '.ico" onerror="this.style.display=\'none\'">'
      );
    },
    // 国旗：flagcdn.com，cn 特判为可读文案
    flag: function (cc, cls) {
      if (!cc) return "";
      cc = String(cc).toLowerCase();
      if (!/^[a-z]{2}$/.test(cc)) return "";
      var alt = cc === "tw" ? "中国台湾省" : cc.toUpperCase();
      return (
        '<img class="' + (cls || "flag-icon") + '" width="40" height="27" alt="' + alt +
        '" title="' + alt + '" src="https://flagcdn.com/w40/' + cc +
        '.png" onerror="this.style.display=\'none\'">'
      );
    },
    // 信任评分表盘（0-100）
    gauge: function (score, labelText) {
      var s = Math.max(0, Math.min(100, Math.round(score)));
      return (
        '<div class="score-num">' + s + "</div>" +
        '<div class="score-bar"><i class="score-marker" style="left:calc(' + s + "% - 2px)\"></i></div>" +
        '<div class="score-scale"><span>0 高危</span><span>25</span><span>50</span><span>75</span><span>100 可信</span></div>' +
        '<div class="score-label" style="margin-top:8px">' + NP.esc(labelText || "") + "</div>"
      );
    },
    // 并发窗口
    withLimit: function (items, limit, worker) {
      return new Promise(function (resolve) {
        var cursor = 0, active = 0, done = 0;
        var total = items.length;
        if (!total) return resolve();
        function next() {
          while (active < limit && cursor < total) {
            var idx = cursor++;
            active++;
            Promise.resolve(worker(items[idx], idx)).catch(function () {}).then(function () {
              active--; done++;
              if (done === total) resolve();
              else next();
            });
          }
        }
        next();
      });
    },
    median: function (arr) {
      if (!arr.length) return -1;
      var s = arr.slice().sort(function (a, b) { return a - b; });
      return s[Math.floor(s.length / 2)];
    },
    maskIp: function (text) {
      var t = String(text || "").trim();
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) {
        var p = t.split(".");
        return p[0] + "." + p[1] + ".*.*";
      }
      if (t.indexOf(":") !== -1) {
        var parts = t.split(":");
        if (parts.length >= 3) return parts[0] + ":" + parts[1] + ":*";
      }
      return t;
    },

    /* 读取 Cloudflare cdn-cgi/trace（多页面共用） */
    fetchTrace: async function (host, timeoutMs) {
      const r = await NP.fetchT("https://" + host + "/cdn-cgi/trace", null, timeoutMs || 6000);
      const map = {};
      (await r.text()).trim().split("\n").forEach(function (l) {
        var i = l.indexOf("=");
        if (i > 0) map[l.slice(0, i)] = l.slice(i + 1);
      });
      return map;
    },

    /* 本机出口 IP：同源 /api/session 优先。
       1.1.1.1/cdn-cgi/trace 只作回退——部分网络（如国内直连、Clash fake-IP）到 1.1.1.1 的
       HTTPS 不通，直接在浏览器里请求会超时导致“获取本机出口失败”。 */
    selfTrace: async function () {
      try {
        const r = await NP.fetchT("/api/session", null, 6000);
        const d = await r.json();
        if (d && d.ip) return { ip: d.ip, loc: "", via: "session" };
      } catch (e) {}
      try {
        const map = await NP.fetchTrace("1.1.1.1", 5000);
        if (map.ip) return { ip: map.ip, loc: map.loc || "", via: "trace" };
      } catch (e) {}
      return null;
    },

    /* 隐藏IP 开关绑定：切换时对容器内 .ip-text 做掩码 */
    bindIpMask: function (onChange) {
      var box = document.getElementById("ipMaskToggle");
      if (!box) return;
      box.addEventListener("change", function () {
        NP.applyIpMask();
        if (onChange) onChange();
      });
    },
    applyIpMask: function () {
      var box = document.getElementById("ipMaskToggle");
      if (!box) return;
      var on = box.checked;
      document.querySelectorAll(".container .ip-text").forEach(function (el) {
        if (!el.dataset.real) el.dataset.real = el.textContent.trim();
        if (!el.dataset.real) return;
        var want = on ? NP.maskIp(el.dataset.real) : el.dataset.real;
        if (el.textContent !== want) el.textContent = want;
      });
    },
    maskText: function (ip) {
      var box = document.getElementById("ipMaskToggle");
      return box && box.checked ? NP.maskIp(ip) : ip;
    },
  });

  /* PWA Service Worker：HTTPS 环境生效（HTTP 下注册会被浏览器拒绝，静默忽略） */
  if ("serviceWorker" in navigator && location.protocol === "https:") {
    window.addEventListener("load", function () {
      navigator.serviceWorker.register("/sw.js").catch(function () {});
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", buildNav);
  } else {
    buildNav();
  }
})();
