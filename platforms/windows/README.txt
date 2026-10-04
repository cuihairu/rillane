SEEP for Windows (x86_64) - quick notes
========================================

1. Unzip this folder to an install directory (e.g. C:\seep).
2. Place a config (or let install-service.ps1 copy the bundled example):
   C:\ProgramData\seep\seep.yaml  (edit admin_token!)
3. Administrator PowerShell:
      .\install-service.ps1
4. Known boundary: seepd does not implement the Windows Service Control
   Manager protocol yet, so `sc.exe start seep` fails with error 1053.
   Until the native SCM integration lands, wrap seepd.exe with WinSW or
   NSSM instead:
      nssm install seep C:\seep\seepd.exe
      nssm set seep AppEnvironmentExtra SEEP_CONFIG=C:\ProgramData\seep\seep.yaml
      nssm start seep
5. Uninstall: .\uninstall-service.ps1 (add -RemoveConfig to clean config).

Config path is injected via the SEEP_CONFIG environment variable; seepd has
no --config flag. Full docs: platforms/windows/README.md in the repository.
