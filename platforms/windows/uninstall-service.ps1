# uninstall-service.ps1 —— RILLANE Windows 服务卸载（platform-packaging.md §3）
#
# 以管理员身份在 PowerShell 运行：
#   .\uninstall-service.ps1            # 停止并删除服务（配置保留）
#   .\uninstall-service.ps1 -RemoveConfig   # 连同 C:\ProgramData\rillane 一并清理

param(
    [switch]$RemoveConfig
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "run as Administrator (sc.exe requires elevation)"
}

sc.exe stop rillane | Out-Null
# 1060=服务未安装、1062=服务未启动：均为幂等卸载的可接受退出码
sc.exe delete rillane | Out-Null
if ($LASTEXITCODE -notin 0, 1060, 1062) {
    throw "sc.exe delete failed (exit $LASTEXITCODE)"
}

if ($RemoveConfig) {
    Remove-Item -Recurse -Force "C:\ProgramData\rillane" -ErrorAction SilentlyContinue
    Write-Host "config removed."
} else {
    Write-Host "config kept at C:\ProgramData\rillane (use -RemoveConfig to clean)."
}
Write-Host "service 'rillane' removed."
