# NetProbe — 多合一 IP 检测与网络诊断工具箱

从零实现的纯前端优先 IP / 网络检测工具站：所有检测默认在你的浏览器里完成，服务端只提供少量聚合 API 与静态页面。包含 **19 个功能页面**，覆盖 IP 查询、风险评分、分流出口、DNS / WebRTC 泄露、网速测试、浏览器指纹、封锁观测、ASN / Whois 查询等场景。

> 纯净实现：不依赖任何第三方统计 / 广告 / 账号体系；无需登录即可使用全部功能。

---

## ✨ 功能总览

| 页面 | 功能 | 说明 |
|---|---|---|
| `/` | IP 查询首页 | 本机 IP 多源归属地 + 全站连通性点阵 + 35 站分流出口 + 查询统计条 |
| `/ip/` | IP 风险评分 | 六档评分色带、ASN/路由图、DNSBL、子网趋势、分享报告（可遮 IP 尾段 / 设有效期 / 一键复制给 AI 诊断）、语音搜索 |
| `/claude/` | Claude 检测 | IP 纯净度 + 中国用户特征六项加权评分（时区/语言/字体/区域/偏移/Emoji） |
| `/gpt/` | ChatGPT 检测 | chatgpt.com / api.openai.com 可达性 + ASN 分类 |
| `/link/` | 网络连通性 | 40+ 目标分组探测，**支持添加自定义目标**（保存在本机浏览器） |
| `/egress/` | 分流出口检测 | 并行探测 11 个目标站的真实出口 IP + 地图聚合，验证代理分流规则 |
| `/dns/` | DNS 泄露检测 | 唯一子域名触发真实解析 + 多家 DoH TXT 回显对照 |
| `/dnsresolve/` | DNS 解析对比 🆕 | 9 家公共 DNS 并行解析同一域名，本机直查 / 服务器代查双通道，地区筛选与结果一致性判定 |
| `/webrtc/` | WebRTC 泄露 | 多 STUN 并行 + **NAT 类型判定** + **SDP 协商日志** + mDNS 保护识别 |
| `/speed/` | 网速测试 🆕 | Cloudflare 边缘测速：下载 / 上传 / 延迟 / 抖动四指标，包大小可选，逐轮明细 |
| `/fingerprint/` | 浏览器指纹 | Canvas/WebGL/音频/字体等 16 项指纹 + TLS 握手指纹，SHA-256 指纹 ID |
| `/cloudflare/` | Cloudflare 检测 | trace 全字段 + Turnstile 人机校验 + reCAPTCHA v3 演示 + 边缘延迟 |
| `/ping/` | 全球 Ping | check-host 全球节点 + Globalping 探针 🆕 + **路由追踪** 🆕 + 本机 Anycast 延迟 |
| `/censor/` | 封锁测试 🆕 | 基于 OONI 开放观测数据查 36 国 30 天封锁记录 + Globalping 实时复核 |
| `/blocklist/` | IP 黑名单 🆕 | 32 个公开 DNSBL（DNSBL 实时名单 + 威胁情报），命中分「不良记录 / 匿名标记 / 网段参考」 |
| `/persona/` | 画像检测 🆕 | 任选目标国家，把浏览器真实呈现的「你」与本地人画像逐项对照打分 |
| `/checklist/` | 安全清单 🆕 | 96 项原创网络安全自查清单，12 大类、按优先级推进、进度仅存本机 |
| `/ipcalc/` | IP 计算器 🆕 | IPv4/IPv6 地址、CIDR、范围转最少 CIDR、前缀列表合并、整数还原、EUI-64 解读，纯本地 |
| `/mac/` | MAC 查询 🆕 | IEEE OUI 制造商归属、单播/组播、全球/本地管理、随机化地址识别，纯本地 |
| `/compare/` `/whois/` `/status/` `/card/` `/torrent/` `/news/` `/docs/` | 其他工具 | IP 对比 / RDAP Whois / 服务状态 / 信息卡片 / Torrent 检测 / AI 资讯 / 公开 API 文档 |

🆕 = 本次更新新增。

---

## 📦 目录结构

```
├── ipcheck/                 # Node 版（可独立部署到任意 VPS）
│   ├── server.js            # HTTP 服务：静态页面 + 聚合 API（零 npm 依赖）
│   ├── lib/                 # GeoIP / 风险评分 / DNSBL / RDAP / 缓存等模块
│   ├── public/              # 全部前端页面与脚本（源码，纯静态）
│   ├── scripts/             # 辅助脚本
│   └── data/                # 运行时数据（自动生成，不入库）
└── Workers 和 Pages/        # Cloudflare Workers 版（同一套前端 + Worker 运行时）
    ├── src/worker.js        # Worker 入口：路由 / 限流 / DO 计数 / 报告存储
    ├── src/lib/             # 与 Node 版对应的运行时适配层
    ├── scripts/prepare.js   # 部署前构建：复制 public/ 并烘焙资源版本号
    ├── dev-server.mjs       # 本地测试架（加载真实 worker.js）
    └── wrangler.jsonc       # Wrangler 配置
```

---

## 🚀 怎么使用

### 方式一：访问在线站点

部署后浏览器直接打开即可，无需注册登录，所有检测点击按钮即用。

### 方式二：本地 / VPS 运行（Node 版）

```bash
# 要求 Node ≥ 14，零 npm 依赖
cd ipcheck
node server.js              # 默认监听 80 端口
PORT=18999 node server.js   # 自定义端口
```

打开 `http://127.0.0.1:18999` 即可使用。

**可选环境变量：**

| 变量 | 作用 |
|---|---|
| `PORT` | 监听端口（默认 80） |
| `DNS_ZONE` | 自托管 DNS 泄露检测的域名（如 `d.example.com`，需把 NS 记录指向本机并开放 UDP 53；不配置则自动降级为公共第三方检测） |
| `TG_BOT_TOKEN` / `TG_CHAT_ID` | 服务异常时发送 Telegram 通知（可选） |
| `IPINFO_TOKEN` | ipinfo.io 数据源 token（可选，用于增强 GeoIP） |

管理员 token 首次启动时自动生成于 `data/admin-token`（用于 `GET /api/admin/purge?token=...` 清缓存，勿泄露）。

### 方式三：部署到 Cloudflare Workers

```bash
cd "Workers 和 Pages"
npm install
npm run deploy      # = prepare.js 构建 + wrangler deploy
```

首次部署需 `npx wrangler login` 登录 Cloudflare 账号。配置要点（`wrangler.jsonc`）：

- 使用 Workers Assets 托管静态页面；
- `TORRENT_DO` / `COUNTERS_DO` 两个 Durable Object（SQLite）负责 Torrent announce 记录、全站查询计数与分享报告持久化，首次部署自动执行迁移；
- 管理接口需在 Workers 里配置环境变量 `ADMIN_TOKEN`（自定随机字符串）。

本地调试 Worker：`npm run dev`（prepare 构建 + dev-server.mjs 加载真实 worker 代码，默认 8787 端口）。

---

## 🔐 隐私与安全设计

- 检测默认在**浏览器本地**完成：指纹、IP 计算器、MAC 查询、画像检测、安全清单进度等完全不上传；
- 服务端**不落库任何个人数据**：查询计数仅存匿名次数，分享报告可遮盖 IP 尾段并按 1/3/7 天自动过期；
- 所有凭据走环境变量，代码中不含任何密钥；reCAPTCHA / Turnstile 使用官方公开测试密钥（仅演示链路）；
- 第三方数据源（GeoIP、OONI、Globalping、公共 DoH 等）均为公开开放接口。

---

## 📝 更新内容

### v1.1.0（2026-10-12）

**新增 8 个工具页**

- `/speed/` 网速测试：Cloudflare 边缘测速，下载/上传/延迟/抖动四指标，包大小可选，逐轮明细与结论
- `/dnsresolve/` DNS 解析对比：9 家公共 DNS 并行解析，本机直查 + 服务器代查双通道，直查失败自动回退代查，地区筛选与结果一致性判定
- `/blocklist/` IP 黑名单检查：32 个公开 DNSBL（实时黑名单 + 威胁情报），命中分「不良记录 / 匿名标记 / 网段参考」三性质，附移除申请入口
- `/ipcalc/` IP 计算器：自动识别地址/CIDR/范围/前缀列表/整数等 10 类输入，范围转最少 CIDR、前缀合并、IPv6 EUI-64 解读，全本地 BigInt 计算
- `/mac/` MAC 地址查询：IEEE OUI 4 万条记录本地检索，制造商/单播组播/全球本地/随机化识别
- `/censor/` 封锁测试：OONI 开放数据查 36 国 30 天封锁观测（异常率/确认数），Globalping 探针实时复核
- `/persona/` 深度画像检测：任选 33 个目标国家，时区/语言/区域格式/UTC 偏移/文字系统五信号加权对照打分并给修正建议
- `/checklist/` 安全检查清单：96 条原创条目、12 大类、按优先级推进，进度仅存本机浏览器

**功能升级**

- WebRTC 检测：4 个 STUN 并行、NAT 映射类型判定（锥型/端口对称/多出口）、SDP 协商日志展开查看
- 全球 Ping：新增 Globalping 探针模式与路由追踪（traceroute），与 check-host 互为备份
- 网络连通性：支持添加/移除自定义测试目标（本机保存）
- IP 评分页：分享报告新增「遮盖 IP 尾段」「有效期 1/3/7 天」「一键复制给 AI 诊断」；修复分享报告作用域缺陷

**修复与优化**

- 修复分享报告跨实例丢失：报告迁移至 Durable Object（SQLite）持久化，支持按 TTL 自动过期
- 修复分享报告生成的变量作用域错误（此前该按钮实际不可用）
- 修复报告 TTL 单位换算、评分序列化、Globalping 任务 ID 提取与统计字段解析等多处问题
- 页面脚本异常提示扩展：未捕获的 Promise 拒绝同样会显示统一错误横幅
- 地图弹窗对缺失国家代码的数据判空，避免「toUpperCase」报错
- 导航与页脚同步更新，`/docs/` 补充 `/api/doh`、报告 TTL 说明

### v1.0.0（2026-10-11）

- 首个公开版本：IP 查询 / Claude·GPT 检测 / IP 评分 / 分流出口 / DNS·WebRTC 泄露 / 浏览器指纹 / Cloudflare 检测 / 全球 Ping / 服务状态 / Whois / IP 对比 / 信息卡片 / Torrent 检测 / AI 资讯 / 公开 API

---

## 📄 开源协议

MIT
