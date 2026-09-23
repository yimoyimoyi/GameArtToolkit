# Pixiv ECH 隧道方案

> 让 Pixiv 主站恢复直连——不经过任何代理，用加密的 ClientHello 穿过 SNI 阻断。

| | |
|---|---|
| 状态 | 可行性已验证，方向已决策 |
| 技术选型 | Go 1.26 标准库（纳入构建流程） |
| 优先级 | ECH 优先于代理 relay |
| 范围 | 先验证 pixiv_web，稳定后扩展至其余 10 个 Cloudflare 服务 |

---

## 一、结论

**可行，且已端到端验证。** Go 标准库自 1.23 起原生支持客户端 ECH，无需任何第三方依赖。原型实测：

| 指标 | 结果 |
|---|---|
| 端到端成功率 | **10/10**（ECH 全部被 Cloudflare 接受） |
| 平均耗时 | **577 ms**（含完整 TLS 握手与 ECH 解密） |
| 产物体积 | **8.3 MB** 静态单文件，零第三方依赖 |
| 对照组（明文 SNI） | **0/10**，全部 RST |

---

## 二、问题回顾

第一轮诊断已定位：`pixiv_web` 的候选 IP 池是 `cdn-origin.pixiv.net` 的回源地址，那批机器不承载 `www` / `accounts` / `app-api` 等 vhost，一律返回 403。而 Pixiv 主站已迁至 Cloudflare，真实入口是 `104.18.42.239` 一类的边缘地址。

换对 IP 之后仍有一道墙——GFW 按 `pixiv` 关键字封锁整段子域的明文 SNI：

| 连接方式 | 目标 | 结果 | 原因 |
|---|---|---|---|
| 明文 SNI | `www.pixiv.net` | ❌ 0/10 | 全部 RST，按关键字阻断 |
| 空 SNI | Cloudflare 边缘 | ❌ 失败 | CF 靠 SNI 路由，直接拒绝握手 |
| 打回源站 | `cdn-origin` | ❌ 403 | 不承载主站 vhost |
| **ECH** | Cloudflare 边缘 | ✅ 200 | 外层掩护域名过墙，内层 SNI 解密后正确路由 |

### 关键机制

ECH 的公钥由 **Cloudflare 全网共享**，发布在 bootstrap 域名 `cloudflare-ech.com` 上，而非各站点自己的 DNS 记录。Pixiv 无需开启任何开关，客户端借这把共享钥匙即可加密发往任意 CF 站点的握手。

这个 bootstrap 域名的 HTTPS 记录**国内可直连获取**（AliDNS 实测稳定），所以 ECHConfig 的自举不需要翻墙。

> 注意：`www.pixiv.net` 自己的 HTTPS 记录里确实**没有** `ech=` 参数——这点容易误判为"ECH 不可行"。真正要查的是 `cloudflare-ech.com`。

---

## 三、验证实验

在同一网络、同一时段下，用 Rust（rustls）与 Go 两套独立实现交叉验证。

| 编号 | 测试项 | 实现 | 成功率 | 平均耗时 |
|---|---|---|---|---|
| A | 明文 SNI `cloudflare-ech.com` → CF | rustls | 12/12 | 196 ms |
| B | ECH → `www.pixiv.net`，每次新建连接 | rustls | 9–12/12 | 0.65–4.1 s |
| C | ECH → `www.pixiv.net`，连接池复用 | rustls | 2–10/12 | 波动大 |
| D | **ECH → `www.pixiv.net`，Go 标准库** | Go | **10/10** | **577 ms** |

**A 组**说明 `cloudflare-ech.com` 这个 SNI 本身不在封锁名单内——外层掩护是成立的。

**B/C 组的剧烈波动**暴露了真正的工程难点：连接池会复用到已被静默掐死的连接，导致每次都要等满超时。这正是 Pixiv 第三方客户端要配置 `http2_keep_alive_while_idle` 与 25 秒心跳的原因。

> **网络现状**：同一测试项在不同时段的结果从 0/12 到 12/12 都出现过。这是当前校园网对 Cloudflare 连接的整体质量，**不是 ECH 特有**——明文 SNI 打同一批 CF 地址同样抖动。方案必须靠重试、多 IP 轮换和快速失败来摊薄，不能假设单次连接必成。

### 阶段 1 期间发现：DoH 解析不可信

实现过程中发现一个此前未预料的问题：**国内 DoH 对 pixiv 域名的解析是间歇性污染的**。同一时刻三个端点会给出三个不同的假地址：

| DoH 端点 | 返回 | 判定 |
|---|---|---|
| `223.5.5.5` | `103.240.180.117` | ❌ 污染 |
| `dns.alidns.com` | `69.63.176.15` | ❌ Facebook 网段 |
| `doh.pub` | `31.13.95.38` | ❌ Facebook 网段 |

而境外 DoH（Yandex、switch.ch、Cloudflare）在本网络**全部不可达**。

这与第一轮查到的 `104.18.42.239`（正确值）并不矛盾——那是运气好命中了干净缓存。

**应对**：用 **Cloudflare 官方网段**作为确定性判据过滤解析结果。污染地址都来自完全无关的 ASN，而真实地址必然落在 CF 网段内。过滤后仍无结果时回退**静态 IP 池**——在当前的网络条件下，静态池实际是主力路径而非兜底。

> 这个发现也解释了 Pixiv 第三方客户端为何坚持用硬编码的 IP 池配合 DoH，而不是单纯依赖 DNS。

---

## 四、架构设计

```
浏览器 ──TLS(本地 CA 证书)──▶ nginx :443
                                 │
                                 │ 明文 HTTP（回环 127.0.0.1:PORT）
                                 ▼
                          ECH 隧道 (Go · 8.3 MB)
                            inner SNI = Host 头
                                 │
                                 │ TLS + ECH
                                 │ 外层 SNI = cloudflare-ech.com
                                 ▼
                          Cloudflare 边缘 ──解密 ECH──▶ 路由至 pixiv origin

        ┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈
        GFW 观察者：只能看到 cloudflare-ech.com
        内层真实域名 www.pixiv.net 封在 HPKE 密文里
```

### 为什么 nginx 到隧道之间走明文

这是整个方案唯一一处反直觉的设计。ECH 必须在 **ClientHello 构造的那一刻**注入——它加密的正是 ClientHello 本身。因此这条 TLS 连接必须由隧道自己发起，无法由 nginx 发起后再由中继改写。

若 nginx 仍以 `https` 连上游，就会形成 TLS-in-TLS：nginx 握手完了在里面说 HTTP，而隧道要先把这层 TLS 解开才能把自己的 ECH 握手送出去，语义立刻混乱。所以 nginx 这一跳改为明文 HTTP，隧道从 `Host` 头拿到目标域名，作为 ECH 的内层 SNI。

代价可控：这一跳是**回环地址**，流量不出机器；且 nginx 仍在为浏览器提供 TLS，用户侧的加密链路没有任何削弱。

### 与现有中继机制的关系

项目已有 `l4_relay` 的「端口 → 域名」代理转发模式，启用条件是「直连全挂 + 本地代理可用」。ECH 隧道与它**平级而非替代**，接入后的优先级：

1. **rank0 直连**可用 → 直接用（现状不变）
2. 直连不可用 → **优先 ECH 隧道**（出境不绕路，延迟更低）
3. ECH 也不可用 → 回落代理 relay（现有路径）

---

## 五、组件设计

核心逻辑约 150 行，标准库即可完成。用 `httputil.ReverseProxy` 保留流式语义与 WebSocket 升级。

```go
// ECHConfig 来自 bootstrap 域名，非目标域名（关键）
const bootstrap = "cloudflare-ech.com"

func newTransport(echCfg []byte) *http.Transport {
    return &http.Transport{
        TLSClientConfig: &tls.Config{
            // 内层真实 SNI 由 Host 头动态给出
            ServerName:                     "", // 每请求填充
            EncryptedClientHelloConfigList: echCfg,
            MinVersion:                     tls.VersionTLS13,
        },
        ForceAttemptHTTP2: true,
        // 必须：防止复用已被静默掐死的连接
        HTTP2KeepAliveWhileIdle: true,
        // 快速失败，把挂起变成可重试的错误
        DialContext:            (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
        ResponseHeaderTimeout:  8 * time.Second,
    }
}

func handler(w http.ResponseWriter, r *http.Request) {
    // Host 头即目标域名，白名单校验防滥用
    if !allowed(r.Host) {
        http.Error(w, "forbidden", 403)
        return
    }
    proxy.ServeHTTP(w, r) // 上游 https:// + ECH
}
```

### 必须处理的三件事

- **死连接探测**——实测中连接池复用反而比新建更差。需要 HTTP/2 心跳（25 s）配合空闲超时（60 s），主动淘汰已被掐断的连接。
- **ECHConfig 轮换**——Cloudflare 定期更换密钥。需要定时从 DoH 刷新配置，并识别「ECH 被拒绝」的错误特征后强制重取重连。
- **流式与升级**——`/ws/` 是 WebSocket（超时 7200 s），`proxy_buffering off` 的流式响应也要原样透传。`ReverseProxy` 原生支持，但需实机验证。

---

## 六、改动清单

| 文件 | 改动 | 规模 |
|---|---|---|
| `tools/ech_tunnel/` | 新增：Go 隧道源码与构建脚本 | 新增 |
| `app/ech_tunnel.py` | 新增：进程管理（参照 `nginx_manager.py`）、端口分配、健康检查 | 新增 |
| `app/service_profile.py` | 修正 `pixiv_web` 候选 IP；新增 ECH 可用性标记 | 小 |
| `app/nginx_generator.py` | pixiv 模板增加 ECH 分支：`proxy_pass http://` + 去掉 `proxy_ssl_*` | 中 |
| `app/cdn_optimizer.py` | 上游生成增加 ECH 优先级分支；修正回退掩蔽故障的问题 | 中 |
| `build.py` / `.spec` / `installer.iss` | 把隧道 exe 纳入打包（沿用 nginx 的部署方式） | 小 |

> **顺带修掉**：第一轮发现的结构性问题与 ECH 无关，但建议一并处理——`cdn_optimizer` 在全部探测失败时会静默回退到候选池兜底，把故障伪装成可用配置。这正是 403 长期没被察觉的原因。无论走哪条路，这个回退都不该再掩蔽失败。

---

## 七、实施阶段

### ✅ 阶段 1 · 隧道 MVP，手工验证 —— 已完成

代码落在 `tools/ech_tunnel/`，构建产物 7.1 MB。实测结果：

| 链路 | 结果 |
|---|---|
| 首页 `/` | ✅ 200 · 74 KB · 连续 8/8 成功 |
| 排行榜 `/ranking.php` | ✅ 200 · 160 KB |
| 搜索 API `/ajax/search/artworks/` | ✅ 200 · 71 KB 真实 JSON |
| pixivision | ✅ 302 重定向 |
| `/ws/` WebSocket 路径 | ✅ 请求正确转发（404 为 pixiv 业务响应） |
| 白名单拦截 | ✅ 403 |
| 连接复用 | ✅ 首次 2.7 s 建连，后续 0.23 s |

响应头带 `Cf-Ray: ...-HKG`，内容含当日更新的作品，确认走的是 Cloudflare 香港边缘。

**端口规划**（实施中发现）：`relay_port_for` 占用 `44311–44374`，ECH 隧道必须避开该段，规划使用 **44401** 起。

**测试套件**：202 passed（曾出现 1 例失败，定位为隧道占用 relay 端口导致的 bind 冲突，非代码问题）。

### ✅ 阶段 2 · 接入主程序 —— 已完成

端到端打通：**浏览器 → nginx:443 → ECH 隧道:44401 → Cloudflare → pixiv**，
实测首页 200 · 74 KB、排行榜 200 · 160 KB、搜索 API 200 · 71 KB，
响应头 `Cf-Ray: ...-HKG` 确认经香港边缘。测试套件 202 passed。

| 文件 | 改动 |
|---|---|
| `app/ech_tunnel.py` | 新增：进程管理、域名白名单聚合、健康检查、日志读取 |
| `app/service_profile.py` | `pixiv_web` 候选 IP 改为 CF 边缘；新增 `ech_enabled` 字段 |
| `app/nginx_generator.py` | pixiv 模板增加 ECH 分支（明文上游 + 不输出 `proxy_ssl_*`） |
| `app/cdn_optimizer.py` | upstream 生成增加 ECH 分支；探测失败判定排除 ECH 服务 |
| `app/pyside_app.py` | 启动流程拉起隧道（先于 CDN 优化）、停止时回收 |
| `build.py` | 打包纳入隧道 exe，缺失时尝试现场构建 |

**优先级**：`rank0 直连 > ECH 隧道 > 代理 relay`。有 rank0 时说明直连确实可用，
不占用隧道；否则由隧道接管。

**实施中发现的两个坑**（都已修）：

1. **ECH 分支必须置于增量合并之前**。`generate_upstream_conf` 对未参与测速的服务会沿用
   已有 upstream 块并 `continue`。ECH 服务的上游是本地隧道端口、与探测结果无关，
   若放在合并之后，隧道状态变化会被旧块永久掩盖——症状是分支写了却永不生效。

2. **两个既有测试断言了已被修正的旧行为**：一个注入了 `pixiv_web` 的 rank0 节点
   （现在由隧道接管，不再走该路径），另一个硬编码了旧的错误 IP
   `210.140.139.151`。两者均已更新：前者改用非 ECH 服务测兜底意图，
   后者改为从 `CANDIDATE_IPS` 动态取 IP，避免再次腐化。

**回滚**：本次改动前的 nginx 配置已备份至 `backups/ech_rollout_<时间戳>/`。

### ✅ 阶段 3 · 通用化 —— 已完成（范围小于预期）

原计划把另外 10 个 Cloudflare 托管服务一并纳入，**但全量实测推翻了该前提**。

**全量直连测试结论**（33 个 L7 服务）：

| 分类 | 数量 | 判定 |
|---|---|---|
| 直连可用，**无需 ECH** | 20 | 含 npm / unpkg / cdnjs / jsdelivr / maven / github 系 / pixiv_img / fanbox / pixivision 等 |
| 直连不可用且**非 CF 托管**，ECH 不适用 | 9 | steam×3 / ubisoft / gog（Akamai、Fastly）、github_s3（S3）、pypi / crates_io（Fastly）、google_fonts |
| 直连不可用且 **CF 托管**，ECH 有效 | 2 | `pixiv_web`（已接入）、`booth_pm`（本次接入） |
| 待定 | 2 | — |

**关键发现**：配置里那 10 个服务标注的「双通道探测全部失败」是 **8-25 生成的陈旧数据**。用实际候选 IP 重新探测，`npm` rank0=6/6、`unpkg` rank0=5/5，延迟 150–210 ms 完全正常。按「能直连的不加」原则，它们本就不该纳入。

**booth_pm 的实测对比**（ECH 的唯一新增受益者）：

| 路径 | 结果 |
|---|---|
| 明文 SNI 直连 | 403（稳定 3/3） |
| 经 ECH 隧道 | 302 → `https://booth.pm/ja`，页面 201 KB 正常加载 |

两者差别在于 Cloudflare 观察到的连接特征不同。端到端验证：booth 首页 302、`/ja` 200 · 201 KB；pixiv 各端点 200；非 ECH 服务（unpkg、cdnjs）不受影响。

**同时补全**了通用渲染函数的 ECH 分支（此前只有 pixiv 专用模板支持），使 `ech_enabled` 可作用于任意服务。

---

## 八、风险与缓解

| 风险 | 影响 | 缓解 |
|---|---|---|
| 网络抖动导致连接失败 | 偶发加载失败 | 重试 + 多 CF IP 轮换 + 快速失败（超时压到 5–8 s） |
| 连接池复用死连接 | 每次请求等满超时 | HTTP/2 心跳保活，已在验证中定位 |
| ECHConfig 轮换失效 | 连接被拒 | 定时 DoH 刷新 + 内置配置冷启动兜底 + 拒绝后重取重连 |
| GFW 将来封锁 ECH 掩护域名 | 方案整体失效 | 回落代理 relay；当前实测 `cloudflare-ech.com` 12/12 可达 |
| Go 1.26.4 存在 ECH 相关 CVE | 握手信息泄露 | **CVE-2026-42505，修复于 1.26.5**——构建前升级 |
| 打包体积增加 | 发布包 +8.3 MB | 可接受；如需可 UPX 压缩 |

> **构建注意**：本机 `go env GOARCH` 当前是 `386`，而主程序是 64 位——构建命令必须显式指定 `GOARCH=amd64`，否则产出的 exe 无法与 nginx 和主程序协同工作。

---

## 九、决策记录

2026-09-23 已确认：

| 事项 | 决策 |
|---|---|
| 文档格式 | Markdown |
| Go 工具链 | 纳入构建流程 |
| 优先级 | ECH 优先于代理 relay |
| 启用范围 | 先验证 pixiv_web，稳定后再扩大 |
