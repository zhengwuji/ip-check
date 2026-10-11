# NetProbe — IP 查询与分流测试工具站

从零重写的纯前端 IP 检测工具站（服务端仅提供少量聚合 API），功能对齐主流 IP 分流测试站：

| 页面 | 功能 | 检测原理 |
|---|---|---|
| `/` | 本机 IP + 归属地 + 连通性 + 35 站分流出口 | ip138/ip.cn 文本解析；各站 `cdn-cgi/trace`、CDN 响应头（`cdn-user-ip` / `x-request-ip`）、alicdn JSONP |
| `/claude/` | Claude IP 纯净度 | claude.ai / anthropic.com trace + API 可达性 + ASN 分类 + 地区支持核对 |
| `/gpt/` | ChatGPT · Codex IP 检测 | chatgpt.com trace + api.openai.com 可达性（401 即网络通）+ ASN 分类 |
| `/ip/` | 任意 IP 评分 | `/api/iprisk`：GeoIP + ASN/组织名启发式（机房/家宽/教育）→ A/B/C 评级 |
| `/dns/` | DNS 泄露检测 | 唯一子域名触发真实解析（第三方 ipleak.net 或自托管 DNS_ZONE）+ 多家 DoH 对 `o-o.myaddr.l.google.com` 的 TXT 回显 |
| `/webrtc/` | WebRTC 泄露 | RTCPeerConnection + 公共 STUN，解析 host/srflx/relay、IPv4/IPv6、mDNS |
| `/cloudflare/` | CF 全面检测 | trace 全字段（ip/loc/colo/warp/tls/http/sni）+ 边缘延迟 + `__down`/`__up` 测速 |
| `/link/` | 网络连通性 | 40+ 目标 no-cors fetch 计时，国内/国际/AI/其他地区分组 |
| `/ping/` | 全球延迟 | 浏览器 → 各大 Anycast 网络（Cloudflare/Google/AWS/Fastly…）12 轮取中位 |
| `/status/` | 服务状态监控 | 各官方 Statuspage 实例 `summary.json` 实时聚合 |
| `/whois/` | Whois 查询 | RDAP 协议（后端代理优先，失败回退浏览器直连 rdap.org） |

## 运行

```bash
node server.js          # 监听 80 端口（PORT 环境变量可改）
```

无任何 npm 依赖，Node ≥ 14 即可。

### API

- `GET /api/geoip/:ip` — GeoIP 聚合（`/24` 子网缓存 30 天，落盘 `data/geoip-cache.json`；上游 ip.sb → ipwho.is）
- `GET /api/iprisk/:ip` — IP 风险分类（机房/家宽/教育，ASN + 组织名启发式）
- `GET /api/whois?q=` — RDAP 代理（iana dns.json 引导至对应注册局）
- `GET /api/dns/config`、`GET /api/dns/result/:token` — 自托管 DNS 泄露检测（需配置 `DNS_ZONE`）

### 自托管 DNS 泄露检测（可选）

1. 准备一个域名，例如 `d.example.com`；
2. 在域名 DNS 处添加 NS 记录：`*（或 _dns）.d.example.com → 本服务器`；
3. 以环境变量启动：`DNS_ZONE=d.example.com node server.js`；
4. 服务端会监听 UDP 53 记录查询来源（需 root/CAP_NET_BIND_SERVICE）。
未配置时自动降级为公共第三方检测（ipleak.net）。

## systemd 部署

```ini
# /etc/systemd/system/netprobe.service
[Unit]
Description=NetProbe
After=network.target

[Service]
ExecStart=/usr/bin/node /opt/netprobe/server.js
Environment=PORT=80
Restart=always
# 允许绑定 53（自托管 DNS 时需要）
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

## 注意

- 站点为纯静态前端 + 轻量 API，所有检测均在访问者浏览器中发起，不存储用户数据。
- GeoIP/风险分类为启发式结果，仅供参考；AI 平台风控以官方为准。
