module github.com/pixivtoolkit/ech-tunnel

// 1.26.5 是硬下限, 不是偏好: CVE-2026-42505 / GO-2026-5856 (crypto/tls) 会让
// ECH 握手被被动网络观察者去匿名化 —— 正是本隧道"隐藏内层域名"这条承诺本身。
// 受影响范围: from go1.26.0-0 before go1.26.5。
// 抬高这一行 + GOTOOLCHAIN=auto 会让 go 自动拉取满足要求的工具链, 因此这是
// "下限"的单一真源; build.ps1 会独立校验同一数字并硬失败。
// 见 https://pkg.go.dev/vuln/GO-2026-5856
go 1.26.5

require golang.org/x/net v0.48.0

require golang.org/x/text v0.32.0 // indirect
