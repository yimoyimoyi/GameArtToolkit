// ECH 隧道 · 白名单匹配语义的回归测试
//
// 背景 (缺陷 W3, 2026-10-04): 匹配规则是
//
//	host == suffix || strings.HasSuffix(host, "."+suffix)
//
// 所以 `suffix` 必须是**裸主机名**。字面 `*.booth.pm` 既不等于 `accounts.booth.pm`,
// 也不以 `.*.booth.pm` 结尾 ⇒ **永远不匹配**。症状是"画像声明覆盖了该子域, 而隧道
// 对每一个子域都回 403" —— 属于本项目最忌讳的"假可用"形态, 且**不会报错**。
//
// 这个测试锁两件事:
//  1. normalizeAllowEntry 把 `*.x` / `.x` / 大小写 / 尾点 都收敛成裸 `x`;
//  2. 收敛后的条目在真实匹配规则下**确实覆盖 apex 与所有层级子域**,
//     且**不会**误命中"以同一字符串结尾但不是其子域"的名字 (点边界)。
package main

import "testing"

func TestNormalizeAllowEntry(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// 核心用例: 通配必须变成裸后缀, 否则整条白名单条目失效
		{"*.booth.pm", "booth.pm"},
		{"booth.pm", "booth.pm"},
		// NRPT 风格的前导点: 同样是"子树"的意思
		{".booth.pm", "booth.pm"},
		// 大小写与首尾空白: 白名单是逐字节比较, 不一致就等于不匹配
		{"  *.BOOTH.PM  ", "booth.pm"},
		{"BOOTH.PM", "booth.pm"},
		// 绝对域名写法 (尾点) 要收敛
		{"booth.pm.", "booth.pm"},
		{"*.booth.pm.", "booth.pm"},
		// 裸 `*` 没有后缀语义: 放行它等于开放代理, 必须收敛成空串由调用方丢弃
		{"*", ""},
		{"", ""},
		{"   ", ""},
	}
	for _, c := range cases {
		if got := normalizeAllowEntry(c.in); got != c.want {
			t.Errorf("normalizeAllowEntry(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}

// TestAllowedCoversApexAndSubdomains 是本案的要害: 用**真实的 allowed()** 断言
// 收敛后的白名单覆盖 apex 与所有层级子域。
func TestAllowedCoversApexAndSubdomains(t *testing.T) {
	// 模拟 Python 侧传来的、已收敛的白名单(booth_pm 画像)
	tun := NewTunnel(nil, nil, []string{"booth.pm", "www.booth.pm", "*.booth.pm"})

	mustAllow := []string{
		"booth.pm",          // apex —— 通配本以为不覆盖它, 但 nginx 的 `*.booth.pm` 覆盖一级, 故必须放行
		"www.booth.pm",      // 显式子域
		"accounts.booth.pm", // ← 修复前必然 403 的那一类
		"a.b.booth.pm",      // 多层级子域
		"assets.booth.pm",   // 显式子域
	}
	for _, h := range mustAllow {
		if !tun.allowed(h) {
			t.Errorf("allowed(%q) = false, 期望 true (白名单含 booth.pm 的子树)", h)
		}
	}

	mustDeny := []string{
		"notbooth.pm",       // 点边界: 不能因为"以 booth.pm 结尾"就放行
		"evilbooth.pm",      // 同上
		"booth.pm.evil.com", // 后缀不在末尾
		"pixiv.net",         // 完全无关
	}
	for _, h := range mustDeny {
		if tun.allowed(h) {
			t.Errorf("allowed(%q) = true, 期望 false (点边界必须成立)", h)
		}
	}
}

// TestEmptyDomainsMeansAllowAll 锁住"留空 = 不限制"这一既有语义没有被我改动。
func TestEmptyDomainsMeansAllowAll(t *testing.T) {
	tun := NewTunnel(nil, nil, nil)
	if !tun.allowAll {
		t.Fatal("domains 为空时 allowAll 应为 true (既有语义: 留空=不限制)")
	}
	if !tun.allowed("anything.example.com") {
		t.Error("allowAll 状态下应放行任意主机")
	}
}

// TestAllEntriesInvalidDoesNotBecomeOpenProxy 是最重要的一条安全断言:
// 给了域名但全部无效时, 结果必须是"全部拒绝", **绝不能**退化成"不限制"。
func TestAllEntriesInvalidDoesNotBecomeOpenProxy(t *testing.T) {
	tun := NewTunnel(nil, nil, []string{"*", "  ", ""})
	if tun.allowAll {
		t.Fatal("给了域名但全部无效时, 绝不允许退化成 allowAll (那等于开放代理)")
	}
	if len(tun.allow) != 0 {
		t.Fatalf("期望 allow 为空, 实际 %v", tun.allow)
	}
	if tun.allowed("anything.example.com") {
		t.Error("零覆盖时必须全部拒绝, 而不是放行")
	}
}
