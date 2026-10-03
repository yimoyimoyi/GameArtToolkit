// GameArt Toolkit - ECH 隧道 (Encrypted Client Hello Tunnel)
//
// 作用: 在本地回环上提供一个 HTTP 入口, 把收到的请求以带 ECH 的 TLS 连接
// 转发到 Cloudflare 边缘。用于绕过针对明文字符串的 SNI 阻断。
//
// 为什么 nginx 到本隧道走明文 HTTP: ECH 加密的正是 ClientHello 本身, 必须在
// 构造那一刻注入, 因此这条 TLS 连接只能由本程序发起。若 nginx 仍以 https 连
// 上游就形成 TLS-in-TLS, 无法工作。回环上的明文不削弱用户侧加密。
//
// 用法:
//
//	ech-tunnel -listen 127.0.0.1:44311 -domains pixiv.net,pximg.net
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/http2"
)

const (
	// 握手与响应预算: 偏紧, 目的是把"挂起"尽快变成可重试的错误。
	// 实测本网络存在间歇性连接失败, 长时间等待没有意义。
	tlsHandshakeTimeout   = 6 * time.Second
	responseHeaderTimeout = 8 * time.Second
	dialTimeout           = 5 * time.Second
	// 拨号时最多尝试几个候选 IP(总预算 dialTimeout, 在它们之间均分)
	maxDialAttempts = 3

	// 死连接防护: 空闲连接 30s 强制退役, 避免复用到已被静默掐断的连接。
	// 实测"连接池复用"若不设限反而比每次新建更慢(每次都要等满超时)。
	idleConnTimeout = 30 * time.Second

	// HTTP/2 心跳: 连接空闲这么久没有收到任何帧时发一个 PING 探测存活。
	// 这是死连接问题的正解 —— 没有它, 复用到的死连接只能靠超时才发现。
	h2ReadIdleTimeout = 25 * time.Second
	// PING 发出后这么久仍无响应, 判定连接已死并关闭, 让下次请求重连。
	h2PingTimeout = 10 * time.Second
)

// Tunnel 是隧道主体, 按目标域名缓存 Transport(内含 ECH 配置与连接池)。
type Tunnel struct {
	ech      *ECHConfigManager
	resolver *Resolver
	allowAll bool
	allow    []string // 允许的域名后缀

	mu      sync.Mutex
	entries map[string]*entry
}

type entry struct {
	echCfg []byte // 创建该 Transport 时使用的 ECHConfig, 用于检测轮换
	proxy  *httputil.ReverseProxy
}

func NewTunnel(ech *ECHConfigManager, resolver *Resolver, domains []string) *Tunnel {
	t := &Tunnel{
		ech:      ech,
		resolver: resolver,
		entries:  make(map[string]*entry),
	}
	if len(domains) == 0 {
		t.allowAll = true
	}
	for _, d := range domains {
		d = normalizeAllowEntry(d)
		if d != "" {
			t.allow = append(t.allow, d)
		}
	}
	// 给了域名却一个都没活下来 = 零覆盖。这不是"不限制", 而是"每个请求都 403",
	// 两者后果相反, 所以必须以 allowAll=false + 空 allow 收场(全部拒绝),
	// 绝不能因为 allow 为空就退回 allowAll —— 那会把一个配置错误变成开放代理。
	return t
}

func (t *Tunnel) allowed(host string) bool {
	if t.allowAll {
		return true
	}
	for _, suffix := range t.allow {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

// normalizeAllowEntry 把 `-domains` 里的一个条目规范化成后缀匹配能用的形式。
//
// 为什么需要 (缺陷 W3, 2026-10-04): 匹配规则是
// `host == suffix || HasSuffix(host, "."+suffix)`, 所以 `suffix` 必须是**裸主机名**。
// 字面 `*.booth.pm` 既不等于 `accounts.booth.pm`, 也不以 `.*.booth.pm` 结尾 ⇒
// **永远不匹配** —— 症状是"服务声明覆盖了该子域, 但隧道对每一个子域都回 403"。
//
// `*.x` 与裸 `x` 在本匹配规则下是同一件事, 所以剥离是语义等价变换。
// Python 侧 (app/ech_tunnel.py 的 normalize_ech_allow_entry) 已经这么做; 这里再兜一层,
// 是为了让**手工加的参数**或将来别的调用方也不会静默失效 —— 白名单失效是静默的,
// 不会报错, 只会 403。
func normalizeAllowEntry(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	// 前导点写法 (`.x`, NRPT 风格) 同样按裸后缀处理。
	s = strings.TrimPrefix(s, ".")
	if strings.HasPrefix(s, "*.") {
		s = s[2:]
	}
	// 裸 `*` 没有后缀语义: 匹配规则是 `host == "*" || HasSuffix(host, ".*")`,
	// 而合法主机名不含 `*`, 所以它既不匹配任何东西、又"看起来像放行"。
	// 收敛成空串由调用方丢弃 —— 与 Python 侧 normalize_ech_allow_entry 同一口径。
	if s == "*" {
		return ""
	}
	return s
}

func (t *Tunnel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := stripPort(r.Host)
	if host == "" {
		http.Error(w, "missing host", http.StatusBadRequest)
		return
	}
	if !t.allowed(host) {
		log.Printf("[deny] 域名不在白名单: %s", host)
		http.Error(w, "domain not allowed", http.StatusForbidden)
		return
	}
	t.proxyFor(host).ServeHTTP(w, r)
}

// proxyFor 返回该域名的反向代理; ECHConfig 变化时自动重建(丢弃旧连接池,
// 因为旧连接是用已失效的配置建立的)。
func (t *Tunnel) proxyFor(host string) *httputil.ReverseProxy {
	cfg := t.ech.Get()

	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.entries[host]; ok && equalBytes(e.echCfg, cfg) {
		return e.proxy
	}

	p := t.buildProxy(host, cfg)
	t.entries[host] = &entry{echCfg: cfg, proxy: p}
	return p
}

func (t *Tunnel) buildProxy(host string, echCfg []byte) *httputil.ReverseProxy {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			// 内层真实 SNI: 由 Cloudflare 解密 ECH 后据此路由
			ServerName:                     host,
			EncryptedClientHelloConfigList: echCfg,
			MinVersion:                     tls.VersionTLS13,
		},
		// 强制解析: 绕开被污染的系统 DNS, 直接用候选 IP 连接
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			ips, err := t.resolver.ResolveAll(ctx, host)
			if err != nil {
				return nil, err
			}
			// 依次尝试候选 IP: 本网络对 Cloudflare 的连通会间歇性中断,
			// 一个 IP 不通时换下一个, 比在同一个 IP 上重试更有效
			attempts := len(ips)
			if attempts > maxDialAttempts {
				attempts = maxDialAttempts
			}
			perIP := dialTimeout / time.Duration(attempts)
			var lastErr error
			for _, ip := range ips[:attempts] {
				conn, err := (&net.Dialer{Timeout: perIP}).DialContext(
					ctx, "tcp", net.JoinHostPort(ip, "443"))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       idleConnTimeout,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
	}

	// 配置 HTTP/2 心跳。这是"连接池复用死连接"的解法:
	// 空闲 25s 主动发 PING, 10s 内无响应即判死并关闭, 下次请求自然重连。
	if h2, err := http2.ConfigureTransports(tr); err == nil {
		h2.ReadIdleTimeout = h2ReadIdleTimeout
		h2.PingTimeout = h2PingTimeout
	} else {
		log.Printf("[warn] HTTP/2 配置失败, 将退化到 HTTP/1.1: %v", err)
	}

	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "https"
			req.URL.Host = host
			req.Host = host
		},
		Transport: &retryTransport{tunnel: t, host: host, base: tr},
		// -1 = 不缓冲, 每片数据立即下发。项目 nginx 侧配了 proxy_buffering off,
		// 这里必须保持一致, 否则流式响应(SSE/长轮询)会被卡住。
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// 只记 host, 不记 r.URL.Path。
			//
			// 为什么: 请求行里的路径与查询串可能带 API key / 会话 token / 单次
			// 签名, 而这是一份**追加写、不轮转**的本地日志。项目在 nginx 侧已经
			// 因为同一个原因做了处理 (access_log off, 实测旧实例的 access.log
			// 曾达 183.9 MB 且记录解密后的完整请求行)。隧道这一跳承载的是同一批
			// 流量, 没有理由把同样的东西再写一遍。
			// host 已经由白名单限定 (else 分支根本走不到这里), 所以它不构成新的
			// 隐私面; 排查"哪个域名在失败"也只需要它。
			log.Printf("[err] %s: %v", host, err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
}

// retryTransport 在 ECH 握手被拒时刷新配置并重试一次。
//
// Cloudflare 会轮换 ECH 密钥, 此时旧配置构造的握手会被服务器拒绝。识别到该
// 特征后必须重新查询配置, 否则会一直失败。
type retryTransport struct {
	tunnel *Tunnel
	host   string
	base   *http.Transport
}

func (rt *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.base.RoundTrip(req)
	if err == nil || !isECHRejected(err) {
		return resp, err
	}
	// 仅重试天然幂等的方法, 避免重复提交副作用
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return nil, err
	}

	log.Printf("[ech] %s 握手被拒(配置可能已轮换), 刷新后重试", rt.host)
	rt.tunnel.ech.refreshNow(req.Context())

	fresh := rt.tunnel.transportFor(rt.host)
	if fresh == nil {
		return nil, err
	}
	if req.GetBody != nil {
		if b, e := req.GetBody(); e == nil {
			req.Body = b
		}
	}
	return fresh.RoundTrip(req)
}

// transportFor 取出当前生效的 Transport(重建后返回新的那个)。
func (t *Tunnel) transportFor(host string) *http.Transport {
	p := t.proxyFor(host)
	if inner, ok := p.Transport.(*retryTransport); ok {
		return inner.base
	}
	return nil
}

// isECHRejected 判断错误是否为 ECH 握手被拒。
func isECHRejected(err error) bool {
	var echErr *tls.ECHRejectionError
	if errors.As(err, &echErr) {
		return true
	}
	// 部分路径会把握手失败包成普通错误串, 用 bootstrap 域名作特征匹配
	msg := err.Error()
	return strings.Contains(msg, "ECH") || strings.Contains(msg, echBootstrapHost)
}

func stripPort(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(hostport)
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseHostPools 解析 `-host-ip-pool` 的 `host=ip1,ip2;host2=ip3` 形式。
//
// 为什么需要"每主机"的池 (2026-10-03 实测): 全局池是各画像候选的并集, 里面混着**别的
// zone** 的边缘。对权威解析不是 Cloudflare 的主机 (n2.pawchive.pw 的 DoH 答案落在
// DDoS-Guard), 过滤后只能回退全局池 —— 实测会把 1.8MB 的原图打成**截断**(439KB/903KB)
// 甚至 **502**, 而换成该 zone 自己的边缘 6/6 完整。故池必须与目标匹配。
func parseHostPools(s string) map[string][]string {
	out := map[string][]string{}
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			log.Printf("[warn] -host-ip-pool 条目格式应为 host=ip1,ip2, 已忽略: %q", part)
			continue
		}
		host := strings.ToLower(strings.TrimSpace(kv[0]))
		ips := splitCSV(kv[1])
		if host == "" || len(ips) == 0 {
			continue
		}
		out[host] = ips
	}
	return out
}

func main() {
	listen := flag.String("listen", "127.0.0.1:44311", "监听地址")
	domains := flag.String("domains", "", "允许的域名后缀, 逗号分隔 (留空=不限制)")
	doh := flag.String("doh", "https://223.5.5.5/resolve,https://dns.alidns.com/resolve",
		"DoH 端点, 逗号分隔, 按序容灾")
	pool := flag.String("ip-pool", "", "全局静态 IP 池兜底, 逗号分隔 (DoH 不可用或结果被投毒时使用)")
	hostPool := flag.String("host-ip-pool", "",
		"每主机专属 IP 池: host=ip1,ip2;host2=ip3 (host 可为注册域, 自动覆盖其子域)。"+
			"用于\"权威解析不是 Cloudflare\"的主机 —— 它们只能靠专属池拿到本 zone 的真实边缘")
	echRefresh := flag.Duration("ech-refresh", 30*time.Minute, "ECHConfig 刷新周期")
	dnsTTL := flag.Duration("dns-ttl", 10*time.Minute, "DoH 解析结果缓存时长")
	allowNonCF := flag.Bool("allow-non-cf", false,
		"允许解析到 Cloudflare 网段之外的地址 (默认关闭: 用于过滤被投毒的 DoH 结果)")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("[boot] ECH 隧道启动, 监听 %s", *listen)

	dohURLs := splitCSV(*doh)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ech := NewECHConfigManager(dohURLs, *echRefresh)
	ech.Start(ctx)

	resolver := NewResolver(dohURLs, splitCSV(*pool), parseHostPools(*hostPool),
		*dnsTTL, !*allowNonCF)
	tunnel := NewTunnel(ech, resolver, splitCSV(*domains))

	srv := &http.Server{
		Addr:              *listen,
		Handler:           tunnel,
		ReadHeaderTimeout: 10 * time.Second,
		// 不设 WriteTimeout: 流式响应与 WebSocket 会长时间保持打开
	}

	// 优雅退出: 收到信号后停止接收新连接
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		log.Printf("[exit] 收到退出信号, 正在关闭...")
		cancel()
		shutdownCtx, c := context.WithTimeout(context.Background(), 3*time.Second)
		defer c()
		srv.Shutdown(shutdownCtx)
	}()

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("[fatal] 监听 %s 失败: %v", *listen, err)
	}
	log.Printf("[exit] 已停止")
}
