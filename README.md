# Fix-RDNA3-DisplayWake

A small PowerShell utility for AMD **RDNA3** users who experience:

- black screen after display sleep
- monitor won’t wake
- weird wake/resume / display re-init issues

This script applies a few *common mitigations* (registry + power settings) and generates **timestamped backups** so you can revert.

It can also install an optional persistent ULPS protection task that re-checks AMD display adapter registry instances after driver/device installation events and at system startup.

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

### Optional persistent ULPS protection

The script can install a Windows Scheduled Task named `Fix-RDNA3-DisplayWake-ULPS-Protection`.

The task:

- runs as `SYSTEM` with highest privileges
- triggers at system startup
- triggers after relevant Plug and Play / driver installation events
- waits about 45 seconds before checking the registry
- enumerates actual AMD display adapters, then resolves each adapter’s Display Class registry instance from its PNP device ID
- only changes `EnableUlps` when it already exists and is set to `1`
- leaves `EnableUlps=0` unchanged
- never modifies `EnableUlps_NA`
- does not run the full Recommended fixes
- does not require `data\adrenalin-mapping.csv`
- writes timestamped ULPS protection logs, and writes a backup when it changes a value

Install, verify, and remove it from an elevated PowerShell:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -InstallUlpsProtectionTask
powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -VerifyUlpsProtectionTask
powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -UninstallUlpsProtectionTask
```

You can also run the same narrow repair manually:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -RepairUlpsFromTask
```

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
  - `Fix-RDNA3-DisplayWake.ulps-protection.backup.YYYYMMDD-HHMMSS.json`
  - `Fix-RDNA3-DisplayWake.ulps-protection.log.YYYYMMDD-HHMMSS.txt`
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

---

## Contributing / Support

If you encounter issues:

1. Run **Verify current settings**:
   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -VerifySettings
   ```

---

## Disclaimer

This script modifies Windows registry values and power management settings.

Use at your own risk

Always keep the generated backup .json files

Revert using the built-in rollback option if needed

The author assumes no responsibility for system instability or data loss.
