/* ============================================================
   NetProbe — 安全检查清单（原创内容，本地进度）
   每项 { t: 标题, d: 说明, lv: 必要|可选|高级 }，12 大类。
   状态（checked/ignored）存 localStorage，仅本机。
   ============================================================ */
(function () {
  "use strict";
  var esc = NP.esc;

  var DATA = [
    { name: "身份验证", items: [
      { t: "使用密码管理器生成与保存密码", d: "不再靠记忆和重复使用：Bitwarden/1Password 等管理器为每个站点生成独立随机密码，你只需记住一个主密码。", lv: "必要" },
      { t: "重要账户开启两步验证（2FA）", d: "邮箱、网盘、支付、社交主号优先。验证器 App（TOTP）优于短信——SIM 卡可被补办劫持。", lv: "必要" },
      { t: "两步验证的恢复码离线保存", d: "手机丢失时恢复码是唯一的救命稻草，打印或抄写到纸上，别存在手机里。", lv: "必要" },
      { t: "不跨站点重复使用密码", d: "一个站点被拖库，撞库机器人会拿同一组密码去试你所有的账号。检查重复密码可用管理器的安全审计功能。", lv: "必要" },
      { t: "主密码足够长且唯一", d: "长度大于复杂度：一句只有你知道的话 + 数字符号，比 P@ss123 安全得多。", lv: "必要" },
      { t: "给敏感账户设置独立的恢复邮箱", d: "恢复邮箱不要和主邮箱相同，避免一锅端。", lv: "可选" },
      { t: "定期检查账户的异地登录与安全事件", d: "Google/Apple/微信等都有「登录活动」页，看到陌生设备立即改密并下线。", lv: "必要" },
      { t: "不再使用的账户及时注销", d: "僵尸账户是泄露数据的持续来源：它们还在被旧平台的数据库拖累。", lv: "可选" },
      { t: "对支持 Passkey 的服务启用通行密钥", d: "通行密钥绑定设备生物识别，钓鱼网站拿不走它，正在快速替代传统密码。", lv: "高级" },
      { t: "警惕「紧急」场景下的登录请求", d: "验证码和登录推送是钓鱼的新入口：任何让你报验证码的「客服」都是骗子。", lv: "必要" },
      { t: "为不同风险级别使用不同邮箱", d: "注册 Newsletter、临时服务用一个马甲邮箱，银行与主业用另一套。", lv: "可选" },
      { t: "检查邮箱是否出现在历史泄露库", d: "在 haveibeenpwned 等服务查一下自己的邮箱，命中后优先改那几个站点的密码。", lv: "可选" },
    ]},
    { name: "网页浏览", items: [
      { t: "浏览器保持自动更新", d: "浏览器是最大的攻击面，0day 修补基本只认最新版本。", lv: "必要" },
      { t: "只用必要的浏览器扩展，定期清理", d: "每个扩展都能读你访问的页面。少装、装官方店里有大量评价的，用完即删。", lv: "必要" },
      { t: "启用 HTTPS-Only / 强制 HTTPS 模式", d: "防止页面降级到明文 HTTP 被中间人注入。", lv: "必要" },
      { t: "广告与跟踪拦截扩展（uBlock Origin）", d: "大部分恶意广告与挖矿脚本来自广告位；uBlock Origin 默认规则即可拦截绝大多数。", lv: "可选" },
      { t: "重要操作核对域名拼写与证书", d: "paypa1.com 与 paypal.com 只差一个字符；地址栏点开证书看一眼签发者。", lv: "必要" },
      { t: "不在重要会话中使用公共电脑", d: "网吧/酒店电脑可能带键盘记录与流量镜像，用完也等于用过。", lv: "必要" },
      { t: "公共 Wi-Fi 上避免明文登录", d: "优先用手机流量或可信 VPN；必须用时确认全站 HTTPS。", lv: "可选" },
      { t: "定期清理 Cookie 与站点数据", d: "登录态与跟踪 ID 大量存于 Cookie，清一次能甩掉大部分长期跟踪。", lv: "可选" },
      { t: "隐私场景使用隔离的浏览器配置或容器", d: "Firefox Multi-Account Containers / 独立 Profile，把工作、个人、匿名身份分开。", lv: "高级" },
      { t: "警惕伪装成下载按钮的广告", d: "下载站页面上最大的那个「下载」往往不是真链接。", lv: "必要" },
      { t: "对新网站用一次性邮箱/虚拟卡支付", d: "不熟悉的电商先用最小白鼠姿势下单，降低泄露主邮箱与卡号的概率。", lv: "高级" },
      { t: "关闭浏览器「保存并同步密码到云端」", d: "同步密码库的密钥由浏览器厂商持有，独立密码管理器的安全模型更清晰。", lv: "可选" },
    ]},
    { name: "电子邮件", items: [
      { t: "不点击邮件里的登录链接", d: "「账户异常，点此验证」是钓鱼标配：手动打开官网或用 App 操作。", lv: "必要" },
      { t: "检查发件人真实地址而非显示名", d: "显示名可以随便写，展开详情看 @ 后面的域名才作数。", lv: "必要" },
      { t: "对附件保持「先隔离」习惯", d: "不确定的附件（尤其 Office 宏、exe、iso、lnk）先扔沙箱或虚拟机里看。", lv: "必要" },
      { t: "关闭邮件的远程图片自动加载", d: "远程图片带跟踪像素，能记录你打开邮件的时间与 IP。", lv: "可选" },
      { t: "使用独立别名注册不重要的服务", d: "Gmail 的 + 后缀、Apple Hide My Email、SimpleLogin 别名，泄露后能定位到具体站点。", lv: "可选" },
      { t: "重要邮箱开启登录提醒", d: "第一时间知道异常登录。", lv: "必要" },
      { t: "不转发工作邮件到个人邮箱", d: "离职时工作数据仍留在个人邮箱，属于合规与法律风险。", lv: "可选" },
      { t: "警惕「老板/同事」要求转账或买卡的邮件", d: "冒充上级的 BEC 诈骗是金额最大的邮件犯罪：口头二次确认。", lv: "必要" },
    ]},
    { name: "即时通讯", items: [
      { t: "对高敏感对话开启端到端加密模式", d: "Signal 全程 E2EE；WhatsApp/微信的加密范围不同，敏感内容选择可靠渠道。", lv: "必要" },
      { t: "关闭「通过手机号找到我」", d: "减少陌生人通过通讯录匹配骚扰与诈骗。", lv: "可选" },
      { t: "验证关键联系人的身份变化", d: "换号、借钱、发文件的「好友」先视频或电话回拨确认。", lv: "必要" },
      { t: "不转发来历不明的链接与文件", d: "群聊是恶意链接传播的主渠道，连带你的信誉一起透支。", lv: "必要" },
      { t: "定期清理群聊中的文件缓存", d: "IM 的自动下载会在本地留存所有群文件，包含你从未点开过的内容。", lv: "可选" },
      { t: "检查各 IM 的「在线状态与最后上线」可见性", d: "把「最后上线时间」设为仅联系人，避免被跟踪作息。", lv: "可选" },
    ]},
    { name: "社交媒体", items: [
      { t: "盘点隐私设置中的「谁可以看到」", d: "每年至少过一遍：历史帖子可见范围、故事、好友列表、被标记照片。", lv: "必要" },
      { t: "不发布行程与定位实时动态", d: "「全家出国两周」配定位等于告诉贼你家这几天没人。", lv: "必要" },
      { t: "谨慎回答安全问题式的帖子", d: "「你的第一只宠物叫什么」这类互动帖的答案正是账户安全问题答案。", lv: "必要" },
      { t: "审查第三方应用授权", d: "「用微信/Google 登录」的小程序们每年清一次，把不再用的撤销掉。", lv: "必要" },
      { t: "关闭基于兴趣的广告个性化", d: "减少画像精度；平台仍有广告，但不再围绕你的敏感标签。", lv: "可选" },
      { t: "对家人长辈做一次防诈提醒", d: "家族群是伪冒亲人诈骗的重灾区，约定一句「打钱先视频」。", lv: "必要" },
    ]},
    { name: "网络设备", items: [
      { t: "修改路由器管理后台的默认密码", d: "admin/admin 的路由器每天在被扫描接入。", lv: "必要" },
      { t: "路由器固件保持更新或开启自动更新", d: "家用路由的远程漏洞被大范围武器化已不是新闻。", lv: "必要" },
      { t: "关闭路由器的 WAN 侧远程管理", d: "除非明确需要，从公网访问家里后台的入口应该关死。", lv: "必要" },
      { t: "访客网络与主网络隔离", d: "给客人和 IoT 设备单独的 SSID，即使被入侵也摸不到你的电脑和 NAS。", lv: "高级" },
      { t: "WPA3/WPA2-AES 加密，停用 WEP/WPA", d: "老加密几分钟就能破解。", lv: "必要" },
      { t: "排查家庭网络里的陌生设备", d: "在路由器后台核对设备列表，发现不认识的先拉黑再排查。", lv: "可选" },
      { t: "摄像头的查看端口不要映射到公网", d: "用厂商 App 的 P2P 或自建 VPN，别把 RTSP/管理端口直接暴露。", lv: "必要" },
      { t: "物联网设备尽量断网改造", d: "能不联网的智能设备就不联网，联网的改掉默认密码。", lv: "可选" },
    ]},
    { name: "移动设备", items: [
      { t: "设置 6 位以上锁屏密码 + 生物识别", d: "纯 4 位数字 15 分钟内可暴力枚举；6 位以上或字母混合显著提高成本。", lv: "必要" },
      { t: "系统与 App 保持自动更新", d: "移动端 0day 大多针对未更新系统。", lv: "必要" },
      { t: "只从官方应用商店安装应用", d: "侧载 APK 是安卓最主要的木马入口。", lv: "必要" },
      { t: "审查 App 权限，最小化授权", d: "手电筒要通讯录？拒绝。按「使用时允许」授权定位、麦克风、相册。", lv: "必要" },
      { t: "开启远程查找与擦除", d: "查找我的 iPhone / 查找我的设备，丢机后能远程锁死抹除。", lv: "必要" },
      { t: "SIM 卡设置 PIN 码", d: "防止手机丢失后被拔卡插入他机接收短信验证码。", lv: "可选" },
      { t: "向运营商开通 SIM 卡防护（补卡验证）", d: "部分运营商支持「补卡需本人到厅」，防 SIM 劫持的最后防线。", lv: "高级" },
      { t: "维修或转卖前彻底清除数据", d: "退出账户并恢复出厂，iPhone 还需关闭激活锁。", lv: "必要" },
      { t: "充电只用可信电源或数据阻断线", d: "公共充电桩的数据线可能同时传输数据（juice jacking）。", lv: "可选" },
    ]},
    { name: "个人电脑", items: [
      { t: "操作系统开启自动更新", d: "补丁延迟 = 给漏洞留门。", lv: "必要" },
      { t: "为每个用户使用独立账户，日常不用管理员", d: "限制恶意程序的提权路径。", lv: "可选" },
      { t: "全盘加密（BitLocker/FileVault/LUKS）", d: "笔记本丢了，不加密等于把硬盘双手奉上。", lv: "必要" },
      { t: "启用系统自带防火墙", d: "Windows Defender 防火墙/macOS 防火墙默认够用，保持开启。", lv: "必要" },
      { t: "软件只从官网或官方商店下载", d: "「绿色下载站」的安装包经常捆绑后门。校验官网哈希更好。", lv: "必要" },
      { t: "破解软件与激活工具隔离使用", d: "它们是挖矿木马与远控的最大载体：用旧电脑或虚拟机。", lv: "必要" },
      { t: "定期备份并验证可恢复", d: "3-2-1 原则：3 份副本、2 种介质、1 份异地。勒索软件面前备份就是一切。", lv: "必要" },
      { t: "锁屏快捷键成为肌肉记忆", d: "Win+L / Ctrl+Cmd+Q，离开座位随手一按。", lv: "必要" },
      { t: "摄像头贴片、麦克风授权检查", d: "物理遮挡最可靠；系统设置里核对哪些 App 有麦克风权限。", lv: "可选" },
      { t: "对可疑文件使用在线沙箱预检", d: "VirusTotal 多引擎扫描 + Any.Run 行为沙箱，比双击试探安全得多。", lv: "高级" },
      { t: "清理浏览器/系统里的旧凭据", d: "存了三年的旧密码库、旧证书、旧 SSH 私钥，该删就删。", lv: "可选" },
    ]},
    { name: "智能家居", items: [
      { t: "改掉所有智能设备的默认密码", d: "摄像头、门铃、音箱的默认口令全网都能查到。", lv: "必要" },
      { t: "能不联网的设备保持离线", d: "传统家电没有云端就不会被远程攻破。", lv: "可选" },
      { t: "语音助手的录音存储设置检查", d: "关闭人工审听（人类抽检录音）选项，定期删除历史录音。", lv: "可选" },
      { t: "智能门锁的备用方案演练", d: "断网/断电/电池耗尽时的机械钥匙在哪、家人是否知道。", lv: "必要" },
      { t: "家庭摄像头不对准门口街道全景", d: "既是隐私也是安全：云端泄露时别把家门钥匙位置一起直播。", lv: "可选" },
      { t: "二手智能设备重置后再入网", d: "前主人的账号绑定不清掉，设备可能仍向其推送画面。", lv: "可选" },
    ]},
    { name: "个人财务", items: [
      { t: "银行卡关闭小额免密或设置限额", d: "免密盗刷的主要通道；按需开启限额。", lv: "可选" },
      { t: "支付 App 单独设置手势/独立密码", d: "别和锁屏密码一致。", lv: "必要" },
      { t: "线上支付优先用虚拟卡/数字卡", d: "主卡号不外泄，退款和纠纷也好处理。", lv: "高级" },
      { t: "核对每笔账单，订阅费逐月清点", d: "很多「免费试用」的续费藏在第二个月。", lv: "必要" },
      { t: "不在聊天工具里发送卡号/证件照片", d: "聊天记录的云端备份不属于支付级加密。", lv: "必要" },
      { t: "警惕任何「屏幕共享」要求", d: "客服/公检法不会要看你的银行屏幕；远程控制+验证码=账户清空。", lv: "必要" },
    ]},
    { name: "人为因素", items: [
      { t: "建立「慢一拍」的反应习惯", d: "紧迫感是所有诈骗的通用配方：倒计时、限量、领导催促。真事不差这一小时。", lv: "必要" },
      { t: "核实对方身份用第三渠道", d: "邮件里的事电话确认，电话里的事当面确认。", lv: "必要" },
      { t: "不信任「主动找上门」的技术支持", d: "弹窗说你中毒了？那个页面本身就是毒。", lv: "必要" },
      { t: "对「奖励/退款/理赔」保持怀疑", d: "你没参与过的抽奖和中奖，都是钩子。", lv: "必要" },
      { t: "家人共享一份应急联络方式", d: "约定暗语与备用电话，出事时能互相验证。", lv: "高级" },
      { t: "定期给全家做 10 分钟反诈闲聊", d: "讲一个本周新闻里的新骗局，比年关突击说教有效。", lv: "可选" },
    ]},
    { name: "物理安全", items: [
      { t: "笔记本与手机启用丢失模式", d: "确认查找功能在所有设备上可用且在线。", lv: "必要" },
      { t: "重要文件不留在 U 盘上", d: "U 盘易丢易坏，需要携带时全盘加密（BitLocker To Go）。", lv: "必要" },
      { t: "处置旧设备前安全擦除", d: "普通删除可恢复，需全盘加密擦除或专业擦写工具。", lv: "必要" },
      { t: "门禁卡与工牌不外借不外晒", d: "照片里能复刻 NFC 卡；丢卡立即挂失。", lv: "可选" },
      { t: "重要纸质文件碎纸后再丢", d: "快递单、银行对账单上的信息足够拼出你的身份。", lv: "可选" },
      { t: "旅行时设备不离视线", d: "酒店房间的设备也可能被动手脚，使用时优先自己带线自带充电头。", lv: "可选" },
    ]},
  ];

  var LV_ORDER = ["必要", "可选", "高级"];
  var STORE_KEY = "np_checklist_v1";
  var state = { checked: {}, ignored: {} };
  try {
    var saved = JSON.parse(localStorage.getItem(STORE_KEY) || "{}");
    if (saved && typeof saved === "object") {
      state.checked = saved.checked || {};
      state.ignored = saved.ignored || {};
    }
  } catch (e) {}
  function persist() {
    try { localStorage.setItem(STORE_KEY, JSON.stringify(state)); } catch (e) {}
  }

  var curFilter = "all"; // all | unchecked | checked | ignored
  var curSection = 0;

  function itemKey(si, ii) { return si + "-" + ii; }
  function isIgnored(si, ii) { return !!state.ignored[itemKey(si, ii)]; }
  function isChecked(si, ii) { return !!state.checked[itemKey(si, ii)]; }

  function renderSummary() {
    var total = 0, done = 0, ign = 0;
    var byCat = {}, byLv = {};
    DATA.forEach(function (sec, si) {
      var d = 0, i = 0;
      sec.items.forEach(function (_, ii) {
        total++;
        if (isChecked(si, ii)) { done++; d++; } else if (isIgnored(si, ii)) { ign++; i++; }
      });
      byCat[sec.name] = { done: d, ign: i, total: sec.items.length };
    });
    LV_ORDER.forEach(function (lv) {
      var t = 0, d = 0;
      DATA.forEach(function (sec, si) {
        sec.items.forEach(function (it, ii) {
          if (it.lv !== lv) return;
          t++;
          if (isChecked(si, ii) || isIgnored(si, ii)) d++;
        });
      });
      byLv[lv] = { done: d, total: t };
    });
    var pending = total - done - ign;
    document.getElementById("clSummary").innerHTML =
      "<span class='cl-stat'><b>" + total + "</b><span class='muted small'>总项数</span></span>" +
      "<span class='cl-stat' style='color:var(--good)'><b>" + done + "</b><span class='muted small'>已检查</span></span>" +
      "<span class='cl-stat'><b>" + ign + "</b><span class='muted small'>已忽略</span></span>" +
      "<span class='cl-stat' style='color:var(--warn)'><b>" + pending + "</b><span class='muted small'>未检查</span></span>" +
      "<span class='cl-stat'><b>" + (total ? Math.round(((done + ign) / total) * 100) : 0) + "%</b><span class='muted small'>整体完成</span></span>";
    document.getElementById("clCatBars").innerHTML = LV_ORDER.map(function (lv) {
      var st = byLv[lv];
      var pct = st.total ? Math.round((st.done / st.total) * 100) : 0;
      return "<div class='cl-lvrow'><span class='cl-lvname'>" + lv + "</span>" +
        "<div class='progress-line' style='flex:1'><i style='width:" + pct + "%'></i></div>" +
        "<span class='muted small' style='width:64px;text-align:right'>" + st.done + "/" + st.total + "</span></div>";
    }).join("");
  }

  function renderNav() {
    var html = DATA.map(function (sec, si) {
      var d = 0;
      sec.items.forEach(function (_, ii) { if (isChecked(si, ii) || isIgnored(si, ii)) d++; });
      return "<button class='btn btn-ghost small" + (si === curSection ? " active" : "") + "' data-sec='" + si + "'>" +
        esc(sec.name) + " <span class='muted small'>" + d + "/" + sec.items.length + "</span></button>";
    }).join("");
    document.getElementById("clNav").innerHTML = html;
    document.querySelectorAll("[data-sec]").forEach(function (b) {
      b.addEventListener("click", function () {
        curSection = parseInt(b.dataset.sec, 10);
        renderNav();
        renderSections();
        var el = document.getElementById("cl-sec-" + curSection);
        if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    });
  }

  function renderFilter() {
    var F = [["all", "全部"], ["unchecked", "未检查"], ["checked", "已检查"], ["ignored", "已忽略"]];
    document.getElementById("clFilter").innerHTML = F.map(function (f) {
      return "<button class='btn btn-ghost small" + (curFilter === f[0] ? " active" : "") + "' data-filter='" + f[0] + "'>" + f[1] + "</button>";
    }).join("");
    document.querySelectorAll("[data-filter]").forEach(function (b) {
      b.addEventListener("click", function () {
        curFilter = b.dataset.filter;
        renderFilter();
        renderSections();
      });
    });
  }

  function renderSections() {
    var html = "";
    DATA.forEach(function (sec, si) {
      var rows = "";
      sec.items.forEach(function (it, ii) {
        var ck = isChecked(si, ii), ig = isIgnored(si, ii);
        if (curFilter === "unchecked" && (ck || ig)) return;
        if (curFilter === "checked" && !ck) return;
        if (curFilter === "ignored" && !ig) return;
        rows += "<div class='cl-item" + (ck ? " cl-done" : "") + (ig ? " cl-ignored" : "") + "'>" +
          "<button class='cl-check" + (ck ? " on" : "") + "' data-check='" + si + "-" + ii + "' title='" + (ck ? "取消勾选" : "标记为已检查") + "'>" + (ck ? "✓" : "") + "</button>" +
          "<div style='flex:1;min-width:0'>" +
          "<div class='cl-title'>" + esc(it.t) + " <span class='pill " + (it.lv === "必要" ? "pill-bad" : it.lv === "可选" ? "pill-info" : "pill-muted") + "'>" + it.lv + "</span></div>" +
          "<div class='muted small cl-desc'>" + esc(it.d) + "</div></div>" +
          "<label class='toggle' title='忽略此项'><span class='toggle-label small'>忽略</span>" +
          "<input type='checkbox' data-ignore='" + si + "-" + ii + "'" + (ig ? " checked" : "") + "><span class='slider'></span></label>" +
          "</div>";
      });
      if (!rows) return;
      html += "<div class='card' id='cl-sec-" + si + "' style='margin-top:14px'><p class='card-title'>" + esc(sec.name) + "</p>" + rows + "</div>";
    });
    if (!html) html = "<div class='card' style='margin-top:14px'><div class='verdict verdict-safe'>✓ 当前筛选下没有条目。</div></div>";
    document.getElementById("clSections").innerHTML = html;
    bindItems();
  }

  function bindItems() {
    document.querySelectorAll("[data-check]").forEach(function (b) {
      b.addEventListener("click", function () {
        var k = b.dataset.check.split("-");
        var si = parseInt(k[0], 10), ii = parseInt(k[1], 10);
        if (isChecked(si, ii)) delete state.checked[itemKey(si, ii)];
        else { state.checked[itemKey(si, ii)] = 1; delete state.ignored[itemKey(si, ii)]; }
        persist(); renderSummary(); renderNav(); renderSections();
      });
    });
    document.querySelectorAll("[data-ignore]").forEach(function (b) {
      b.addEventListener("change", function () {
        var k = b.dataset.ignore.split("-");
        var si = parseInt(k[0], 10), ii = parseInt(k[1], 10);
        if (b.checked) { state.ignored[itemKey(si, ii)] = 1; delete state.checked[itemKey(si, ii)]; }
        else delete state.ignored[itemKey(si, ii)];
        persist(); renderSummary(); renderNav(); renderSections();
      });
    });
  }

  document.getElementById("resetBtn").addEventListener("click", function () {
    if (!confirm("确定要清空全部勾选与忽略记录吗？")) return;
    state = { checked: {}, ignored: {} };
    persist(); renderSummary(); renderNav(); renderFilter(); renderSections();
  });

  renderSummary();
  renderNav();
  renderFilter();
  renderSections();
})();
