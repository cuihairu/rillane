# install-service.ps1 —— SEEP Windows 服务安装（sc.exe 模板级，platform-packaging.md §3）
#
# 以管理员身份在 PowerShell 运行：
#   .\install-service.ps1                                  # 缺省安装目录=脚本所在目录
#   .\install-service.ps1 -InstallDir C:\seep -ConfigPath C:\ProgramData\seep\seep.yaml
#
# 已知边界（platform-packaging.md §3.3）：seepd 尚未实现 SCM 控制协议
# （windows-service crate 集成归后续增量），`sc.exe start seep` 会被 SCM
# 判定错误 1053（服务未及时响应启动请求）并停止。可行替代：WinSW/NSSM
# 外部包装（见 README.txt / 仓内 platforms/windows/README.md）。

param(
    [string]$InstallDir = $PSScriptRoot,
    [string]$ConfigPath = "C:\ProgramData\seep\seep.yaml"
)

$ErrorActionPreference = "Stop"
$Seepd = Join-Path $InstallDir "seepd.exe"
if (-not (Test-Path $Seepd)) { throw "seepd.exe not found: $Seepd" }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "run as Administrator (sc.exe requires elevation)"
}

# 配置落位：包内仅带示例；目标配置缺席时复制（对应 Linux deb 的 conffiles 语义）
New-Item -ItemType Directory -Force -Path (Split-Path $ConfigPath -Parent) | Out-Null
if (-not (Test-Path $ConfigPath)) {
    Copy-Item (Join-Path $InstallDir "seep.yaml.example") $ConfigPath
    Write-Host "placed example config at $ConfigPath (edit admin_token before use)"
}

# 服务创建 + 崩溃恢复三段退避（systemd Restart=on-failure 对应面）
sc.exe create seep binPath= "`"$Seepd`"" start= auto DisplayName= "SEEP Proxy" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed (exit $LASTEXITCODE)" }
sc.exe description seep "SEEP smart egress proxy daemon" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc.exe description failed (exit $LASTEXITCODE)" }
sc.exe failure seep reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc.exe failure failed (exit $LASTEXITCODE)" }

# 配置路径注入：服务级注册表 Environment 键（sc.exe 无环境参数面；
# seepd 无 --config 旗标，仅读 SEEP_CONFIG 环境变量）
$svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\seep"
New-ItemProperty -Path $svcKey -Name Environment -PropertyType MultiString `
    -Value @("SEEP_CONFIG=$ConfigPath") -Force | Out-Null

Write-Warning "known boundary: seepd does not implement the SCM control protocol yet; 'sc.exe start seep' will fail with error 1053. Use a wrapper (WinSW/NSSM) or wait for the windows-service integration increment."
Write-Host "service 'seep' created (not started)."
