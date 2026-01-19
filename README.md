# Fix-RDNA3-DisplayWake

A small PowerShell utility for AMD RDNA3 users who experience:
- black screen after display sleep
- monitor won’t wake
- weird wake/resume issues

## What it changes

**Recommended mode changes:**
- **Disable MPO** (Windows DWM overlays) by setting:
  - `HKLM\SOFTWARE\Microsoft\Windows\Dwm\OverlayTestMode = 5`
- **Disable PCIe Link State Power Management (ASPM)** for the *current* power plan
- **Disable ULPS** by setting `EnableUlps=0` *only where it already exists*

**Safety / trust:**
- Requires Admin
- Writes a JSON backup before changes
- Has built-in revert from the latest backup
- Does **not** change PowerShell execution policy inside the script
- Does **not** touch `EnableUlps_NA` unless you explicitly opt-in, and even then only if it is already `REG_DWORD` (no type forcing)

## How to run (recommended)

Open **PowerShell as Administrator** in the script folder and run:

USAGE
- Recommended:
```powershell
  powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1
```powershell

- Non-interactive:
```powershell
  powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -ApplyRecommended -Force
  powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -RevertFromLatestBackup -Force
  powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -DryRun -ApplyRecommended
```powershell