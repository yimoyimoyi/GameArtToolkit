# ECH 隧道构建脚本
#
# 用法:
#   .\build.ps1                     # 输出到 tools\ech_tunnel\ech-tunnel.exe
#   .\build.ps1 -Output D:\out.exe  # 指定输出路径

param(
    [string]$Output = "$PSScriptRoot\ech-tunnel.exe"
)

$ErrorActionPreference = "Stop"

# --- 定位 Go 工具链 (优先项目约定的 E:\go, 其次 PATH) ---
$go = "E:\go\bin\go.exe"
if (-not (Test-Path $go)) {
    $cmd = Get-Command go -ErrorAction SilentlyContinue
    if ($cmd) { $go = $cmd.Source } else { throw "未找到 Go 工具链 (尝试过 E:\go\bin\go.exe 与 PATH)" }
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

Push-Location $PSScriptRoot
try {
    Write-Host "构建 ECH 隧道 (GOARCH=$env:GOARCH)..."
    & $go build -trimpath -ldflags "-s -w" -o $Output .
    if ($LASTEXITCODE -ne 0) { throw "go build 失败 (exit $LASTEXITCODE)" }

    $item = Get-Item $Output
    Write-Host ("构建成功: {0} ({1} KB)" -f $item.FullName, [math]::Round($item.Length / 1KB))
} finally {
    Pop-Location
}
