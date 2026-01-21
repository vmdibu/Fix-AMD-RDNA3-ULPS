# Fix-RDNA3-DisplayWake

A small PowerShell utility for AMD **RDNA3** users who experience:

- black screen after display sleep
- monitor won’t wake
- weird wake/resume / display re-init issues

This script applies a few *common mitigations* (registry + power settings) and generates **timestamped backups** so you can revert.

---

## What it changes

### Recommended mode (safe defaults)
When you choose **1) Apply RECOMMENDED fixes**, the script applies:

1) **Disable MPO (Windows DWM overlays)**  
   Many users report MPO-related flicker/black-screen issues on some GPU + monitor combinations.

- Registry:
  - `HKLM\SOFTWARE\Microsoft\Windows\Dwm\OverlayTestMode = 5` (DWORD)

2) **Disable PCIe Link State Power Management (ASPM) for the current power plan**  
   This disables “Link State Power Management” on both AC/DC for the currently active plan.

- Power settings:
  - `powercfg -setacvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 0`
  - `powercfg -setdcvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 0`

3) **Disable ULPS only where it already exists**  
   ULPS is an AMD low power state mechanism. The script sets it to `0` only if the value is already present.

- Registry (per display adapter instance under the display class):
  - `...\{4d36e968-e325-11ce-bfc1-08002be10318}\000x\EnableUlps = 0` (DWORD)
  - Only applied **if `EnableUlps` exists** on that instance.

The script targets *display adapter instances only* under the Windows display class key.  
It does **not** blindly create ULPS keys that aren’t already there.

---

## What it does NOT change (important)

- **It does not touch `EnableUlps_NA`** unless you explicitly opt-in using the Advanced option.
- Even in Advanced mode, it will only change `EnableUlps_NA` if it is **already `REG_DWORD`**.  
  It will **never convert types** (for example, it will not change `REG_SZ` → `REG_DWORD`).
- It does **not** change PowerShell execution policy inside the script.
- It does **not** install/uninstall drivers, modify Adrenalin settings, or change BIOS settings.

---

## Safety / trust features

- Requires **Administrator**
- Prints a clear “plan” before applying changes
- Creates timestamped files next to the script:
  - `Fix-RDNA3-DisplayWake.backup.YYYYMMDD-HHMMSS.json`
  - `Fix-RDNA3-DisplayWake.log.YYYYMMDD-HHMMSS.txt`
- Built-in rollback: revert from the **latest backup**
- `-DryRun` mode: preview changes without applying anything
- **Verify** mode: read-only report of current settings

---

## Requirements

- Windows 10/11
- PowerShell 5.1+ (Windows PowerShell) or PowerShell 7+
- Run in an **elevated** PowerShell (Admin)

---

## How to run (recommended)

Open **PowerShell as Administrator** in the script folder and run:

USAGE
- Recommended:
```powershell
  powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1
```

- Non-interactive:
```powershell
  powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -ApplyRecommended -Force
  powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -RevertFromLatestBackup -Force
  powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -DryRun -ApplyRecommended
```