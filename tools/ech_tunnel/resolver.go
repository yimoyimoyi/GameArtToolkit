package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// cloudflareV4 是 Cloudflare 的官方 IPv4 网段 (https://www.cloudflare.com/ips-v4)。
//
// 用途: 过滤被投毒的 DoH 解析结果。实测国内 DoH 对 pixiv 域名的返回是
// 间歇性污染的 —— 同一时刻三个端点会给出三个不同的假地址 (落在 Facebook /
// Twitter 等完全无关的网段), 而真实地址必然在 Cloudflare 网段内。
// 这是个确定性判据, 比"换一个 DoH 端点"可靠得多。
var cloudflareV4 = parseCIDRs([]string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
})

func parseCIDRs(cidrs []string) []*net.IPNet {
	var out []*net.IPNet
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// inCloudflare 判断地址是否落在 Cloudflare 网段内。
func inCloudflare(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() == nil {
		return false
	}
	for _, n := range cloudflareV4 {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Resolver 通过 DoH 解析目标域名的真实地址。
//
// 必须走 DoH 的原因: 本机系统 DNS 对 pixiv 等域名返回污染结果。但 DoH 本身
// 也不完全可靠(见 cloudflareV4 注释), 所以还要叠加网段过滤与静态池兜底。
type Resolver struct {
	dohURLs       []string
	pool          []string // 静态 IP 池兜底(来自服务配置, 视为可信)
	ttl           time.Duration
	requireCFNet  bool // 只接受 Cloudflare 网段内的解析结果
	client        *http.Client

	mu    sync.RWMutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	ips     []string
	expires time.Time
}

func NewResolver(dohURLs, pool []string, ttl time.Duration, requireCFNet bool) *Resolver {
	return &Resolver{
		dohURLs:      dohURLs,
		pool:         pool,
		ttl:          ttl,
		requireCFNet: requireCFNet,
		client:       &http.Client{Timeout: 5 * time.Second},
		cache:        make(map[string]cacheEntry),
	}
}

// poolCacheTTL 是回退到静态池时的缓存时长。
//
// 刻意短于 DoH 结果的 TTL: 静态池只是兜底, 一旦 DoH 恢复干净就应该尽快切回去。
// 早先这里漏了写缓存, 导致每个请求都要重新走一遍注定失败的 DoH 查询, 白白
// 叠加数秒延迟。
const poolCacheTTL = 90 * time.Second

// ResolveAll 返回目标域名的候选 IP 列表(按优先级)。解析顺序: 缓存 -> DoH -> 静态池。
//
// 返回列表而非单值, 是为了让调用方在某个 IP 不可达时能换下一个 ——
// 实测本网络对 Cloudflare 的连通性会间歇性中断, 单 IP 假设不可靠。
func (r *Resolver) ResolveAll(ctx context.Context, host string) ([]string, error) {
	r.mu.RLock()
	entry, ok := r.cache[host]
	r.mu.RUnlock()
	if ok && time.Now().Before(entry.expires) && len(entry.ips) > 0 {
		return entry.ips, nil
	}

	// 依次尝试各 DoH 端点; 任一端点给出通过过滤的结果即采信
	var rejected []string
	for _, ep := range r.dohURLs {
		ips, err := r.queryDoH(ctx, ep, host)
		if err != nil || len(ips) == 0 {
			continue
		}
		clean := ips
		if r.requireCFNet {
			clean = nil
			for _, ip := range ips {
				if inCloudflare(ip) {
					clean = append(clean, ip)
				} else if !contains(rejected, ip) {
					rejected = append(rejected, ip)
				}
			}
			if len(clean) == 0 {
				// 该端点整体返回污染结果, 换下一个端点
				continue
			}
		}
		// DoH 结果后面接上静态池作后备。
		// 实测: DoH 给出的地址即便落在 Cloudflare 网段内也未必可达 ——
		// jsdelivr 的 DoH 结果是 104.17.207.5, 连接被 RST; 而静态池里各服务
		// 验证过的地址正常。两张表合并后由拨号逻辑依次尝试, 单个失效不影响整体。
		merged := append([]string{}, clean...)
		for _, ip := range r.pool {
			if !contains(merged, ip) {
				merged = append(merged, ip)
			}
		}
		r.store(host, merged, r.ttl)
		return merged, nil
	}

	// DoH 不可用或全被过滤: 退回静态池。池内地址来自服务配置, 视为可信。
	if len(r.pool) > 0 {
		reason := "DoH 不可用"
		if len(rejected) > 0 {
			reason = "DoH 结果疑似投毒(" + strings.Join(rejected, ", ") + ")"
		}
		log.Printf("[dns] %s 回退静态池(%s): %s", host, reason, strings.Join(r.pool, ", "))
		r.store(host, r.pool, poolCacheTTL)
		return r.pool, nil
	}
	return nil, fmt.Errorf("无法解析 %s: DoH 不可用/被投毒且无静态池兜底", host)
}

// Resolve 返回单个首选 IP(保留给只需单值的调用方)。
func (r *Resolver) Resolve(ctx context.Context, host string) (string, error) {
	ips, err := r.ResolveAll(ctx, host)
	if err != nil {
		return "", err
	}
	return ips[0], nil
}

func (r *Resolver) store(host string, ips []string, ttl time.Duration) {
	r.mu.Lock()
	r.cache[host] = cacheEntry{ips: ips, expires: time.Now().Add(ttl)}
	r.mu.Unlock()
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func (r *Resolver) queryDoH(ctx context.Context, endpoint, host string) ([]string, error) {
	url := fmt.Sprintf("%s?name=%s&type=A", endpoint, host)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json, application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}

	var parsed struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}

	var ips []string
	for _, ans := range parsed.Answer {
		if ans.Type != 1 { // 只取 A 记录, 忽略 CNAME(类型 5)
			continue
		}
		if ip := strings.TrimSpace(ans.Data); net.ParseIP(ip) != nil {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}
