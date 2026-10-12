# NetProbe — 多合一 IP 检测与网络诊断工具箱

从零实现的纯前端优先 IP / 网络检测工具站：所有检测默认在你的浏览器里完成，服务端只提供少量聚合 API 与静态页面。包含 **19 个功能页面**，覆盖 IP 查询、风险评分、分流出口、DNS / WebRTC 泄露、网速测试、浏览器指纹、封锁观测、ASN / Whois 查询等场景。

> 纯净实现：不依赖任何第三方统计 / 广告 / 账号体系；无需登录即可使用全部功能。

---

## ✨ 功能总览

| 页面 | 功能 | 说明 |
|---|---|---|
| `/` | IP 查询首页 | 本机 IP 多源归属地 + 全站连通性点阵 + 35 站分流出口 + 查询统计条 |
| `/ip/` | IP 风险评分 | 六档评分色带、ASN/路由图、DNSBL、子网趋势、**ISP 家宽判定** 🆕、**中转站路径追踪** 🆕、分享报告（可遮 IP 尾段 / 设有效期 / 一键复制给 AI 诊断）、语音搜索 |
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
| `RECAPTCHA_SECRET` | reCAPTCHA v3 服务端密钥（可选；不配置则用 Google 公开测试密钥，**无防护能力**，仅演示链路） |
| `TURNSTILE_SECRET` | Turnstile 服务端密钥（可选；不配置则用 Cloudflare 公开测试密钥，**无防护能力**，仅演示链路） |

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
- 所有私密凭据走**环境变量**（`TG_BOT_TOKEN`、`IPINFO_TOKEN`、`ADMIN_TOKEN`、`RECAPTCHA_SECRET`、`TURNSTILE_SECRET`），代码库中不含任何私有密钥；仓库内置的 reCAPTCHA / Turnstile 值是 Google 与 Cloudflare **官方文档公开的测试密钥**（恒通过，无防护作用），仅用于演示校验链路，生产环境应通过环境变量替换为自有密钥；
- 第三方数据源（GeoIP、OONI、Globalping、公共 DoH 等）均为公开开放接口。

### 仓库安全约定

以下内容**不纳入版本控制**（见 `.gitignore`），提交前请确认：

| 路径 | 内容 |
|---|---|
| `_deploy/` | 本地部署脚本（含 SSH 主机与凭据） |
| `ipcheck/data/` | 运行时数据（`admin-token`、查询缓存、分享报告） |
| `Workers 和 Pages/public/` | 构建产物（由 `scripts/prepare.js` 生成） |
| `Workers 和 Pages/.wrangler/` | Wrangler 本地缓存 |
| `.env` / `.dev.vars` / `*.pem` / `*.key` | 环境变量与私钥 |

自建部署请勿把上述文件提交到公开仓库。

---

## 📝 更新内容

### v1.2.0（2026-10-12）

**IP 评分页新增两项深度分析**

- **ISP 家宽判定**：多信号加权判定目标 IP 是否属于 ISP 家用宽带接入网段。综合 PeeringDB 自报网络类型（`Cable/DSL/ISP` 等）、ip-api 机房/移动标志、运营商名称启发式、反向 DNS 命名习惯与 ASN 归属，输出档位（ISP 家宽 / 宽带接入 / 移动网络 / 机房托管）与置信度，并逐条列出加权依据。生产实测：Comcast `73.158.0.1` → ISP 家宽（60%）；Hetzner `213.133.117.197` → 机房托管（92%）。
- **中转站路径追踪**：通过 Globalping 全球探测点实测 traceroute，还原目标 IP 的完整转发路径。展示探测点跨洲分布、途经中转网络（ASN 聚合，区分机房与运营商）、中转站 IP 明细（含 RTT 与归属）、各探测点逐跳路径，以及 RIPE RIS 观测的 AS 级 BGP 上游链路。

**新增数据源与模块**

- 新增 `lib/ipapi.js`（ip-api 批量富化，单次最多 100 个 IP）、`lib/isp.js`（家宽判定）、`lib/transit.js`（中转路径聚合），Node 版与 Workers 版各一份，**零新增 npm 依赖**。
- 中转路径主数据源为 Globalping API，check-host.net 作为备用降级（后者对 Cloudflare 出口返回 403）。
- Workers 版新增限流规则：`/api/transit/*` 30 次/分、`/api/isp/*` 40 次/分。

**修复与优化**

- 修复 RIPEstat `bgplay` 路径解析：`initial_state` 的 `path` 位于顶层而非 `attrs` 下，此前 AS 级链路统计恒为空（Node/Workers 两版均已修正）。
- 修复 `DATACENTER_ORG` 机房特征词过宽导致的误判：`communications` / `networks` 等通用词会把 Comcast Cable **Communications** 这类接入 ISP 判为机房并扣分；已收窄词表，并让家宽特征词优先于机房词，避免双向计权互相抵消。
- 修复 Workers 版中转任务状态丢失：各 isolate 不共享内存，任务 Map 在 start 与 result 落在不同 isolate 时查不到。result 端点改为无状态——从 Globalping 测量结果自身回读目标 IP，并支持前端传 `?ip=` 回退。
- 修复中转 ASN 聚合出现 `ASnull` 分组：无 ASN 归属的跳不再计入 ASN 统计。
- 修复 Globalping 探测点分布集中问题：`locations` 由 `magic:"World"` 改为显式国家列表，探测点跨洲分布更均匀。
- 人机校验密钥改为环境变量可覆盖（`RECAPTCHA_SECRET` / `TURNSTILE_SECRET`），默认值仍为官方公开测试密钥。
- `.gitignore` 补充 `.wrangler/`（Wrangler 本地缓存）。

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
