package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// ECH bootstrap 域名。
//
// 关键: Cloudflare 的 ECH 公钥是**全网共享**的, 发布在这个 bootstrap 域名上,
// 而不是各站点自己的 DNS 记录。因此请求 www.pixiv.net 时也要从这里取配置 ——
// pixiv 域名的 HTTPS 记录里并没有 ech 参数 (实测确认)。
const echBootstrapHost = "cloudflare-ech.com"

// 内置兜底配置 (2026-09-23 从 AliDNS HTTPS 记录获取)。
//
// 用途: 首次请求免去 DoH 往返; 若已因密钥轮换失效, 握手会被服务器拒绝,
// 由重试路径识别后强制重新查询。
const builtinECHConfigB64 = "AEX+DQBBbAAgACA/tthYOg3XZRU2ALy1bOllCOWuga/Ys3HvRDdv75lfVgAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="

// ECHConfigManager 负责获取、缓存并刷新 ECHConfigList。
//
// 数据流: 内置兜底立即可用 -> 后台 DoH 查询真实配置 -> 定期刷新。
// Cloudflare 会轮换密钥, 所以必须周期性重取, 不能只查一次。
type ECHConfigManager struct {
	dohURLs   []string
	refresh   time.Duration
	client    *http.Client

	mu       sync.RWMutex
	current  []byte
	fetched  time.Time
	fallback bool // 当前用的是内置兜底(而非 DoH 实取)

	// refreshMu 串行化显式刷新, 避免多个请求同时撞上轮换时打出重复的 DoH 查询
	refreshMu sync.Mutex
}

func NewECHConfigManager(dohURLs []string, refresh time.Duration) *ECHConfigManager {
	m := &ECHConfigManager{
		dohURLs: dohURLs,
		refresh: refresh,
		// DoH 客户端不走系统代理, 且必须快速失败 (它是自举路径, 不能拖慢首请求)
		client: &http.Client{Timeout: 6 * time.Second},
	}

	// 内置兜底作为初始值, 保证任何时刻都有可用配置
	if raw, err := base64.StdEncoding.DecodeString(builtinECHConfigB64); err == nil {
		m.current = raw
		m.fallback = true
	} else {
		log.Printf("[ech] 内置兜底配置解码失败: %v", err)
	}
	return m
}

// Get 返回当前生效的 ECHConfigList。始终非空(除非内置配置也解码失败)。
func (m *ECHConfigManager) Get() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

// Start 启动后台刷新循环, 立即尝试一次并随后按 refresh 周期重取。
func (m *ECHConfigManager) Start(ctx context.Context) {
	go func() {
		m.refreshOnce(ctx)
		ticker := time.NewTicker(m.refresh)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.refreshOnce(ctx)
			}
		}
	}()
}

// refreshNow 立即同步刷新一次(阻塞)。用于 ECH 握手被拒后的恢复路径:
// 此时缓存里的配置已被判定失效, 必须拿到新的才能重试成功。
//
// 用 refreshMu 串行化 —— 密钥轮换会让一批请求同时失败, 没有这层保护会
// 打出大量重复的 DoH 查询。
func (m *ECHConfigManager) refreshNow(ctx context.Context) {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()

	// 双检: 若在等锁期间已有其他请求刷新成功, 本轮无需再查
	m.mu.RLock()
	fresh := !m.fallback && time.Since(m.fetched) < 10*time.Second
	m.mu.RUnlock()
	if fresh {
		return
	}
	m.refreshOnce(ctx)
}

// refreshOnce 依次尝试各 DoH 端点, 首个成功即返回(多端点容灾)。
func (m *ECHConfigManager) refreshOnce(ctx context.Context) {
	for _, ep := range m.dohURLs {
		cfg, err := m.queryDoH(ctx, ep)
		if err != nil {
			log.Printf("[ech] %s 查询失败: %v", ep, err)
			continue
		}
		m.mu.Lock()
		changed := !equalBytes(m.current, cfg) || m.fallback
		m.current = cfg
		m.fetched = time.Now()
		m.fallback = false
		m.mu.Unlock()
		if changed {
			log.Printf("[ech] 已更新 ECHConfig (%d 字节, 来自 %s)", len(cfg), ep)
		}
		return
	}
	log.Printf("[ech] 全部 DoH 端点查询失败, 继续沿用当前配置")
}

// queryDoH 向单个 DoH 端点查询 bootstrap 域名的 HTTPS(type=65) 记录并取出 ech 参数。
func (m *ECHConfigManager) queryDoH(ctx context.Context, endpoint string) ([]byte, error) {
	url := fmt.Sprintf("%s?name=%s&type=HTTPS", endpoint, echBootstrapHost)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// 两个端点要求的 Accept 头不同, 同时给出以兼容
	req.Header.Set("Accept", "application/dns-json, application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}

	var parsed dohResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("解析 DoH 响应失败: %w", err)
	}

	for _, ans := range parsed.Answer {
		echB64 := extractSvcParam(ans.Data, "ech")
		if echB64 == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(echB64)
		if err != nil {
			return nil, fmt.Errorf("ech 参数 base64 解码失败: %w", err)
		}
		if len(raw) == 0 {
			return nil, fmt.Errorf("ech 参数解码后为空")
		}
		return raw, nil
	}
	return nil, fmt.Errorf("响应中未找到 ech 参数")
}

// dohResponse 是 DoH JSON 响应的最小结构(只取我们需要的字段)。
type dohResponse struct {
	Answer []struct {
		Data string `json:"data"`
	} `json:"Answer"`
}

// extractSvcParam 从 SvcParam 文本中提取指定 key 的值。
// 输入形如: 1 . alpn="h3,h2" ipv4hint="..." ech="AEX+..." ipv6hint="..."
func extractSvcParam(data, key string) string {
	needle := key + `="`
	idx := indexOf(data, needle)
	if idx < 0 {
		return ""
	}
	rest := data[idx+len(needle):]
	end := indexOfByte(rest, '"')
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func indexOfByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
