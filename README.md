# Fix-RDNA3-DisplayWake

A small Windows tool for AMD Radeon users who get display wake problems, such as:

- black screen after the monitor goes to sleep
- monitor will not wake without unplugging/replugging or rebooting
- odd display reset or resume problems after sleep

The script applies common display-stability fixes and creates backup files before changing registry settings, so you have a way back.

## Quick Start

1. Download this repository as a ZIP and extract it somewhere easy, for example your Desktop.
2. Open the extracted folder.
3. Right-click inside the folder and choose **Open in Terminal** or **Open PowerShell window here**.
4. Run this command:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1
```

5. If Windows asks for administrator permission, allow it.
6. Choose **1) Apply RECOMMENDED fixes**.
7. Read the plan shown by the script.
8. Type `Y` to continue.
9. Reboot Windows when it finishes.

If you are unsure what to choose, use option **1** first.

## Before You Run It

This tool changes Windows power/display settings. It is meant for people who are already having AMD display wake problems.

Recommended precautions:

- close games and important work first
- create a Windows restore point if you want an extra safety net
- keep the generated `.json` backup files
- reboot after applying fixes

## After AMD Driver Updates

AMD driver updates can change display power settings again. After installing a new AMD driver, you can do one of these:

- download the latest release of this tool and run Recommended mode again
- if you installed the persistent ULPS protection task, let it repair ULPS automatically after the driver update
- if you cloned the repository with Git, update `data\adrenalin-mapping.csv` manually before running Recommended mode

The persistent ULPS protection task does **not** update `data\adrenalin-mapping.csv` on your computer. It only checks the Windows registry and repairs existing `EnableUlps` values if AMD turns them back on.

The CSV is updated in this GitHub repository by the daily workflow. To get that newer CSV on your own computer, download the latest release/ZIP again or run the manual updater described below.

## What Recommended Mode Does

Recommended mode applies these fixes:

1. **Disables MPO**

   MPO is a Windows display overlay feature. On some systems it is linked with flicker, black screens, or wake issues.

2. **Disables PCIe Link State Power Management**

   This stops Windows from putting the PCIe graphics link into a lower-power state on the current power plan.

3. **Disables HAGS**

   HAGS means Hardware-accelerated GPU scheduling. Some AMD users report fewer display reset or wake problems with it disabled.

4. **Optionally disables ULPS**

   ULPS is an AMD ultra-low-power feature. The script only changes it when the driver version policy says Recommended mode should do so.

## Safety Rules

The script is deliberately conservative:

- it requires Administrator rights
- it prints a plan before making changes
- it supports `-DryRun` preview mode
- it writes timestamped backup and log files
- it can revert from the latest backup
- it only changes `EnableUlps` if that value already exists
- it never creates missing ULPS registry values
- it never touches `EnableUlps_NA` unless you explicitly choose the advanced option

Backups and logs are created next to the script:

```text
Fix-RDNA3-DisplayWake.backup.YYYYMMDD-HHMMSS.json
Fix-RDNA3-DisplayWake.log.YYYYMMDD-HHMMSS.txt
Fix-RDNA3-DisplayWake.ulps-protection.backup.YYYYMMDD-HHMMSS.json
Fix-RDNA3-DisplayWake.ulps-protection.log.YYYYMMDD-HHMMSS.txt
```

## Common Commands

Run the normal menu:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1
```

Preview Recommended mode without changing anything:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -DryRun -ApplyRecommended
```

Apply Recommended mode without the menu:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -ApplyRecommended -Force
```

Check current settings without changing anything:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -VerifySettings
```

Revert from the latest backup:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -RevertFromLatestBackup -Force
```

## Optional Persistent ULPS Protection

AMD driver updates can sometimes turn ULPS back on. This script can install a Windows Scheduled Task that checks ULPS again after driver/device installation events and at system startup.

Install it:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -InstallUlpsProtectionTask
```

Verify it:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -VerifyUlpsProtectionTask
```

Remove it:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -UninstallUlpsProtectionTask
```

The scheduled task:

- runs as `SYSTEM` with highest privileges
- waits about 45 seconds before checking the registry
- only performs the narrow ULPS repair
- does not change MPO, HAGS, ASPM, hibernate, timeouts, or any other Recommended-mode setting
- does not store one fixed GPU registry path when you install it
- re-detects the actual AMD display adapter and its PNP device ID each time it runs
- only repairs existing `EnableUlps` values from `1` to `0`
- leaves `EnableUlps=0` unchanged
- never changes `EnableUlps_NA`
- does not run the full Recommended fixes
- does not require `data\adrenalin-mapping.csv`

This means the task can still find the AMD display adapter after a driver update changes the Display Class registry instance. It uses the current PNP device information at run time, then follows that to the matching registry location.

## Individual Fixes

Use these only if you know you want one specific change:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -DisableMpo -Force
powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -RevertMpo -Force
powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -DisableHags -Force
powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -RevertHags -Force
powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -DisableAspm -Force
powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -DisableUlps -Force
```

## Advanced Details

Recommended mode may change:

- `HKLM\SOFTWARE\Microsoft\Windows\Dwm\OverlayTestMode = 5`
- `HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\HwSchMode = 1`
- current power plan PCIe ASPM AC/DC values to `0`
- existing AMD display-class `EnableUlps` values to `0`, depending on driver policy

The script does not:

- install or uninstall GPU drivers
- change AMD Adrenalin settings
- change BIOS/UEFI settings
- permanently change PowerShell execution policy
- create missing ULPS registry values
- automatically modify `EnableUlps_NA`

The advanced `EnableUlps_NA` option is intentionally separate. Even then, it only changes the value if it already exists as `REG_DWORD`.

## Maintaining Driver Mapping

`data\adrenalin-mapping.csv` is updated by a daily GitHub Actions workflow from AMD GPUOpen's Radeon Vulkan driver version table. When the workflow detects a mapping update, it commits the refreshed CSV and creates a GitHub Release tagged with the newest Adrenalin and Windows Driver Store versions.

Most users do not need to maintain this file themselves. The easiest manual update is:

1. Open the GitHub Releases page for this project.
2. Download the newest release or source ZIP.
3. Extract it.
4. Run the script from that fresh folder.

If you cloned this repository and have PowerShell 7+ installed, you can update the CSV in your local copy:

```powershell
pwsh ./scripts/Update-AdrenalinMapping.ps1
pwsh ./scripts/Update-AdrenalinMapping.ps1 -VerifyOnly
```

If `pwsh` is not recognized, install PowerShell 7 from Microsoft or use the latest release ZIP instead.

## Troubleshooting

If something does not look right, run:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -VerifySettings
```

If you want to undo the latest script changes, run:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1 -RevertFromLatestBackup -Force
```

## Disclaimer

This script modifies Windows registry values and power management settings.

Use at your own risk. Keep the generated backup `.json` files so you can revert if needed.
