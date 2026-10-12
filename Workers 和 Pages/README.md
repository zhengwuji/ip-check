# NetProbe — Cloudflare Workers 版

与 VPS 版（`../ipcheck`）同一套前端页面 + 同一套检测逻辑，改写为 Cloudflare Workers 运行时。
常规缓存走 Worker 实例内存（不绑定 KV / R2）；Torrent announce 记录与全站查询计数使用 Durable Object 保持跨隔离一致。

## 目录结构

```
Workers 和 Pages/
├── wrangler.jsonc        # Worker + 静态资源(Assets) + Durable Object 配置
├── package.json          # type:module；scripts 见下
├── dev-server.mjs        # 本地测试架：直接加载 src/worker.js + 磁盘 mock ASSETS
├── scripts/prepare.js    # 从 ../ipcheck/public 复制页面并烘焙资源版本号
├── src/worker.js         # Worker 入口：路由 / 限流 / 深链接回退
└── src/lib/              # 与 VPS 版 lib/ 一一对应的运行时适配层
    ├── util.js           # fetch / IP 工具 / RDAP（去 Node http/https，用全局 fetch）
    ├── caches.js         # 内存 TTL 缓存（去定时器，机会式清理）
    ├── doh.js            # DNS over HTTPS —— 替代 Node dns 模块（DNSBL/PTR 全走 DoH）
    ├── geo.js            # GeoIP/趋势/位置历史（去磁盘持久化，内存化）
    ├── dnsbl.js          # 12 源黑名单（DoH 版，命中判定与 VPS 版一致）
    ├── ripe.js           # RIPEstat/RDAP（纯 fetch，不变）
    ├── ipdeep.js         # PTR + 任播识别（端口扫描在 Workers 不可用，已优雅降级）
    ├── cfrisk.js         # CF 环境风险评估（不变）
    ├── card.js           # IP 卡片 SVG（不变）
    ├── score.js          # ipscore 编排（子请求数已压到免费版 50 上限内）
    └── status.js         # 服务状态巡检（无常驻定时器 → 访问时惰性巡检）
```

## 部署

### 方式 A：命令行（推荐）

```bash
cd "Workers 和 Pages"
npm install            # 安装 wrangler（仅本地开发工具，不进产物）
npx wrangler login     # 浏览器授权一次
npm run deploy         # = prepare + wrangler deploy
```

部署完成后得到 `https://netprobe.<你的子域>.workers.dev`。
绑定自定义域名：`wrangler.jsonc` 加 `"routes": [{ "pattern": "你的域名/*", "custom_domain": true }]` 再 deploy。

### 方式 B：Dashboard 网页操作

1. dash.cloudflare.com → **Workers 和 Pages → 创建 → Workers → Hello World**
2. 部署后进入 **编辑代码**：把 `src/worker.js` 与 `src/lib/*.js` 合并粘贴
   （Worker 编辑器支持多文件模块：在右侧文件树新建 `lib/*.js` 粘贴对应内容）
3. **设置(Setting) → 域和路由 → Assets（资产）→ 上传文件夹**：选本目录 `public/`
4. 保存即生效；前端页面无需任何修改

### 可选环境变量

| 变量 | 作用 |
|---|---|
| `ADMIN_TOKEN` | 启用 `/api/admin/purge` 清缓存接口（不配则该接口停用） |
| `RECAPTCHA_SECRET` | reCAPTCHA v3 服务端密钥（可选；不配则用 Google 公开测试密钥，无防护能力） |
| `TURNSTILE_SECRET` | Turnstile 服务端密钥（可选；不配则用 Cloudflare 公开测试密钥，无防护能力） |
| ~~KV 绑定~~ | **不需要**。当前版本刻意零存储；想持久化报告/趋势再自行加 `NP_KV` |

## 与 VPS 版的功能差异

| 能力 | VPS 版 | Workers 版 |
|---|---|---|
| 静态页面 / 全部前端功能 | ✅ | ✅ 完全一致 |
| GeoIP / 风险分类 / 评分 / RPKI / BGP 路由 / ASN | ✅ | ✅ 一致 |
| DNSBL 12 源 / Tor | UDP/53 直查 | DoH JSON 查询（结果一致） |
| 端口扫描（ipDeep） | ✅ 23 端口 + 哨兵 | ❌ Workers 无 TCP socket，返回空并注明 |
| 网段热度趋势 / 位置历史 | 磁盘持久 30 天 | 内存级（实例回收/多地区实例间不共享） |
| 报告分享 /report/<id> | 磁盘 30 天 | 内存级（实例生命周期内有效） |
| 状态巡检 | 常驻定时 5 分钟 | 惰性巡检（访问时触发，首位访客多等几秒） |
| 自托管 DNS 泄露采集（UDP 53） | 可选支持 | ❌ 走 ipleak 公共接口（与 VPS 未配置 DNS_ZONE 时一致） |
| 限流 | 全局精确 | 按隔离实例（各边缘节点独立计数，整体更宽松） |

## 本地测试

```bash
npm run dev    # 复制资源并启动 http://127.0.0.1:8787（真实 worker 代码 + mock 资源层）
```

已验证路由：全部页面与深链接回退、session、geoip、iprisk、ipscore（冷 5s/热 0.6s）、
trend、cfrisk(v4/v6)、card.svg、turnstile verify、whois、tlds、ping 代理、doh 代理、
报告创建/读取、status/history、限流（精确 12 次后 429）、admin/purge 权限。

## 定期重新同步

本目录的 `public/` 由 `scripts/prepare.js` 从主项目复制生成。
主项目页面有改动后，在主目录正常改，然后到本目录跑一次 `npm run deploy` 即会重新复制并烘焙。
