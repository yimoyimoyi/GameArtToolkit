# ECH 隧道构建脚本
#
# 用法:
#   .\build.ps1                     # 输出到 tools\ech_tunnel\ech-tunnel.exe
#   .\build.ps1 -Output D:\out.exe  # 指定输出路径

param(
    [string]$Output = "$PSScriptRoot\ech-tunnel.exe"
)

$ErrorActionPreference = "Stop"

# --- 工具链版本下限 (硬约束, 不是建议) ---
#
# 为什么必须卡在 1.26.5: CVE-2026-42505 / GO-2026-5856 (crypto/tls) ——
#   "使用了 ECH 的握手可被被动网络观察者去匿名化, 原因是未加密的 ClientHello
#    中泄露了预共享密钥身份 (pre-shared key identities)"
#   受影响: from go1.26.0-0 before go1.26.5
#   核实: https://pkg.go.dev/vuln/GO-2026-5856
#
# ⚠ 这条对本项目是**要命**的, 不是例行公事: 本隧道的全部安全价值就是"网络观察者
#   看不到内层真实域名"。该 CVE 攻击的正是这条保证, 而它**不影响连通性** ——
#   也就是说所有功能测试都会通过, 只有威胁模型被打穿。因此下限必须做成构建期
#   硬失败: 谁在低版本上重跑一次, 就会再产出一个"功能全绿但承诺已破"的二进制。
$MinGoVersion = [version]"1.26.5"

# --- 定位 Go 工具链 (优先项目约定的 E:\go, 其次 PATH) ---
$go = "E:\go\bin\go.exe"
if (-not (Test-Path $go)) {
    $cmd = Get-Command go -ErrorAction SilentlyContinue
    if ($cmd) { $go = $cmd.Source } else { throw "未找到 Go 工具链 (尝试过 E:\go\bin\go.exe 与 PATH)" }
}

# --- 版本校验: 读工具链自报的版本, 低于下限则显式改用 go.mod 钉住的版本 ---
#
# 两条路径的区别很重要:
#   · 本地工具链已达标  → 直接用 (不触网)
#   · 本地工具链过低    → **显式**设 GOTOOLCHAIN=go$MinGoVersion, 让 go 去取钉住的
#                        版本; 只有在取不到时才硬失败
# 为什么是"显式指定版本"而不是"交给默认的 auto": 默认 GOTOOLCHAIN=auto 只在
# **go.mod 要求的版本高于本地**时才升级, 而本机 go1.26.4 恰好满足旧的约束 ——
# 也就是说在默认设置下, 这个构建**会用有缺陷的工具链静默成功**。版本下限如果
# 依赖调用方的环境变量, 它就不是下限, 只是一个建议。
function Read-GoVersion([string]$exe, [string[]]$argv) {
    $raw = (& $exe @argv 2>&1 | Select-Object -First 1)
    if (-not $raw) { return $null }
    $mm = [regex]::Match([string]$raw, 'go(\d+\.\d+(\.\d+)?)')
    if (-not $mm.Success) { return $null }
    return [version]$mm.Groups[1].Value
}

$localVersion = Read-GoVersion $go @('env', 'GOVERSION')
if ($null -eq $localVersion) {
    throw "无法读取 Go 版本 ($go env GOVERSION 返回空或无法解析)"
}

Push-Location $PSScriptRoot
try {
    if ($localVersion -lt $MinGoVersion) {
        Write-Host "本地 Go 工具链 go$localVersion 低于下限 go$MinGoVersion; 尝试改用 go.mod 钉住的 go$MinGoVersion"
        $env:GOTOOLCHAIN = "go$MinGoVersion"
        $effectiveVersion = Read-GoVersion $go @('env', 'GOVERSION')
        if ($null -eq $effectiveVersion -or $effectiveVersion -lt $MinGoVersion) {
            throw @"
Go 工具链版本过低, 且无法取得满足下限的版本。
  本地: go$localVersion    要求: >= go$MinGoVersion    实际生效: go$effectiveVersion

原因: CVE-2026-42505 / GO-2026-5856 (crypto/tls) —— 低于 1.26.5 的 ECH 握手会被
      被动网络观察者去匿名化, 即本隧道"隐藏内层域名"这条承诺直接失效。
      功能测试不会发现这个问题 (它不影响连通性), 所以这里必须硬失败。
修法: 升级本地工具链到 >= go$MinGoVersion; 或确认 GOTOOLCHAIN 未被设为 local
      且工具链可下载 (本脚本已把 GOPROXY 指向镜像)。
参考: https://pkg.go.dev/vuln/GO-2026-5856
"@
        }
        Write-Host "已切换到 go$effectiveVersion (由 go.mod 钉住的下限)"
    } else {
        Write-Host "本地 Go 工具链 go$localVersion 满足下限 go$MinGoVersion"
    }

    # --- 国内模块代理 ---
    # 官方 proxy.golang.org 在境内不可达 (实测 dial tcp i/o timeout),
    # 必须走镜像才能拉到 golang.org/x/net。
    $env:GOPROXY = "https://goproxy.cn,direct"
    $env:GOSUMDB = "sum.golang.google.cn"

    # --- 目标平台 ---
    # 必须显式指定 amd64: 本机 `go env GOARCH` 默认为 386, 产出的 32 位 exe
    # 无法与 64 位的 nginx 和主程序协同工作。
    $env:GOARCH = "amd64"
    $env:CGO_ENABLED = "0"   # 纯静态, 不依赖 msvcrt

    Write-Host "构建 ECH 隧道 (GOARCH=$env:GOARCH)..."
    & $go build -trimpath -ldflags "-s -w" -o $Output .
    if ($LASTEXITCODE -ne 0) { throw "go build 失败 (exit $LASTEXITCODE)" }

    # --- 产物自检: 二进制里记录的 Go 版本也必须达标 ---
    # 为什么再查一次: 上面的校验查的是**构建时用的工具链**, 这里查的是**产物里
    # 实际记录的版本**。两者不一致只可能发生在"构建被跳过 / 产物是旧的"这种
    # 情况下, 而那正是最危险的情形 (看起来构建成功了, 其实发的是旧二进制)。
    $built = (& $go version -m $Output 2>&1 | Select-Object -First 1)
    if ($built -notmatch 'go(\d+\.\d+(\.\d+)?)') {
        throw "无法从产物读取 Go 版本: $built"
    }
    $builtVersion = [version]$Matches[1]
    if ($builtVersion -lt $MinGoVersion) {
        throw "产物自检失败: $Output 记录的 Go 版本是 go$builtVersion, 低于要求的 go$MinGoVersion"
    }

    $item = Get-Item $Output
    Write-Host ("构建成功: {0} ({1} KB, 由 go{2} 构建)" -f $item.FullName, [math]::Round($item.Length / 1KB), $builtVersion)
} finally {
    Pop-Location
}
