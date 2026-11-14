RILLANE for Windows (x86_64) - quick notes
========================================

1. Unzip this folder to an install directory (e.g. C:\rillane).
2. Place a config (or let install-service.ps1 copy the bundled example):
   C:\ProgramData\rillane\rillane.yaml  (edit admin_token!)
3. Administrator PowerShell:
      .\install-service.ps1
4. Known boundary: rillaned does not implement the Windows Service Control
   Manager protocol yet, so `sc.exe start rillane` fails with error 1053.
   Until the native SCM integration lands, wrap rillaned.exe with WinSW or
   NSSM instead:
      nssm install rillane C:\rillane\rillaned.exe
      nssm set rillane AppEnvironmentExtra RILLANE_CONFIG=C:\ProgramData\rillane\rillane.yaml
      nssm start rillane
5. Uninstall: .\uninstall-service.ps1 (add -RemoveConfig to clean config).

Config path is injected via the RILLANE_CONFIG environment variable; rillaned has
no --config flag. Full docs: platforms/windows/README.md in the repository.
