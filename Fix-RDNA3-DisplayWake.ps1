<#  Fix-RDNA3-DisplayWake.ps1

WHAT THIS DOES
- Optionally disables MPO (Windows DWM overlays) via OverlayTestMode=5
- Disables PCIe Link State Power Management (ASPM) for the CURRENT power plan
- Disables AMD ULPS (EnableUlps=0) ONLY where the value already exists
- NEVER touches EnableUlps_NA unless you explicitly opt-in, and even then:
    - it will ONLY change it if it already exists as a REG_DWORD (no type forcing)

SAFETY FEATURES
- Requires Admin
- Writes a JSON backup BEFORE changes
- Has built-in rollback from latest backup
- Has DryRun mode (preview only)
- Prints a clear "plan" before applying changes

USAGE
- Recommended (from an elevated PowerShell):
  powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1

- Non-interactive:
  .\Fix-RDNA3-DisplayWake.ps1 -ApplyRecommended -Force
  .\Fix-RDNA3-DisplayWake.ps1 -RevertFromLatestBackup -Force
  .\Fix-RDNA3-DisplayWake.ps1 -DryRun -ApplyRecommended

#>

[CmdletBinding()]
param(
  # High level actions
  [switch]$ApplyRecommended,
  [switch]$RevertFromLatestBackup,
  [switch]$ListBackups,
  [switch]$DryRun,
  [switch]$Force,
  [switch]$VerifySettings,

  # Individual toggles (advanced / scripting use)
  [switch]$DisableMpo,
  [switch]$RevertMpo,
  [switch]$DisableAspm,
  [switch]$DisableUlps,
  [switch]$TouchUlpsNA,      # advanced + opt-in
  [switch]$DisableHibernate,
  [switch]$SetTimeouts,
  [ValidateRange(0, 240)]
  [int]$MonitorTimeoutMinutes = 10,
  [ValidateRange(0, 240)]
  [int]$SleepTimeoutMinutes = 0
)

# ---------------- Helpers ----------------

function Get-DisplayClassInstances {
  $displayClass = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
  if (-not (Test-Path $displayClass)) { return @() }
  return @(Get-ChildItem $displayClass -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d{4}$' })
}

function Get-AmdDisplayClassInstances {
  $base = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
  if (-not (Test-Path $base)) { return @() }

  $results = @()

  try {
    $children = Get-ChildItem -Path $base -ErrorAction SilentlyContinue
  } catch {
    Write-Host "ULPS: Cannot enumerate display class keys (ACL restriction)." -ForegroundColor Yellow
    return @()
  }

  foreach ($c in $children) {
    try {
      $p = Get-ItemProperty -Path $c.PSPath -ErrorAction SilentlyContinue

      if (
        ($p.ProviderName -eq "Advanced Micro Devices, Inc.") -or
        ($p.DriverDesc   -match "AMD|Radeon")
      ) {
        $results += $c
      }
    } catch {
      # skip unreadable instance
    }
  }

  return $results
}

function Load-StoreToAdrenalinMap_NoHeader {
  param([Parameter(Mandatory=$true)][string]$Path)

  if (-not (Test-Path $Path)) { return @{} }

  $map = @{}
  $lines = Get-Content -Path $Path -Encoding UTF8 -ErrorAction Stop

  foreach ($line in $lines) {
    $t = $line.Trim()
    if (-not $t) { continue }
    if ($t.StartsWith('#')) { continue }

    # split into 2 parts max: storeDriver, adrenalin
    $parts = $t -split ',', 2
    if ($parts.Count -lt 2) { continue }

    $store = $parts[0].Trim()
    $adre  = $parts[1].Trim()

    if ($store -and $adre) {
      $map[$store] = $adre
    }
  }

  return $map
}

function Get-AmdStoreDriverVersion {
  $amd = @(Get-CimInstance Win32_VideoController | Where-Object { $_.Name -match 'AMD|Radeon' })
  if ($amd.Count -eq 0) { return $null }
  return [string]$amd[0].DriverVersion
}

function Resolve-AdrenalinFromStoreDriver {
  param(
    [Parameter(Mandatory=$true)][hashtable]$Map,
    [Parameter(Mandatory=$true)][string]$StoreDriverVersion
  )

  if (-not $StoreDriverVersion) { return $null }
  if ($Map.ContainsKey($StoreDriverVersion)) { return $Map[$StoreDriverVersion] }
  return $null
}

function Resolve-UlpsPolicy {
  param([string]$AdrenalinVersion)

  $threshold = [version]'25.3.1'

  $policy = [pscustomobject]@{
    Name = 'Unknown_DefaultSafe'
    DisableUlpsInRecommended = $false
    Note = 'Adrenalin unknown; ULPS untouched by default'
  }

  if (-not $AdrenalinVersion) { return $policy }

  try { $v = [version]$AdrenalinVersion } catch { return $policy }

  if ($v -gt $threshold) {
    return [pscustomobject]@{
      Name = 'After_25.3.1'
      DisableUlpsInRecommended = $true
      Note = 'Adrenalin > 25.3.1: Recommended disables ULPS'
    }
  }

  return [pscustomobject]@{
    Name = 'AtOrBefore_25.3.1'
    DisableUlpsInRecommended = $false
    Note = 'Adrenalin <= 25.3.1: Recommended leaves ULPS untouched'
  }
}

function Verify-CurrentSettings {

  Write-Section "Verifying current system state (read-only)"

  # In "Recommended" mode these are always targeted:
  $wouldDisableMpo  = $true
  $wouldDisableAspm = $true

  # ULPS is driver-aware (policy decides)
  $wouldDisableUlps = $false

  function Show-Setting {
    param(
      [Parameter(Mandatory=$true)][string]$Title,
      [Parameter(Mandatory=$true)][string]$Current,
      [Parameter(Mandatory=$true)][string]$Planned,
      [Parameter(Mandatory=$true)][bool]$WillChange
    )

    if ($WillChange) {
      Write-Host ("[WILL CHANGE] {0}" -f $Title) -ForegroundColor Red
    } else {
      Write-Host ("[NO CHANGE ] {0}" -f $Title) -ForegroundColor Green
    }
    Write-Host ("  Current: {0}" -f $Current)
    Write-Host ("  Planned: {0}" -f $Planned)
    Write-Host ""
  }

  # ---------------- MPO ----------------
  $dwmPath = "HKLM:\SOFTWARE\Microsoft\Windows\Dwm"
  $overlayVal = $null
  $mpoCurrent = "Enabled/default (OverlayTestMode not set)"

  try {
    $mpo = Get-ItemProperty -Path $dwmPath -Name OverlayTestMode -ErrorAction Stop
    $overlayVal = $mpo.OverlayTestMode
    $mpoCurrent = ("OverlayTestMode={0}" -f $overlayVal)
  } catch {}

  $mpoPlanned = "OverlayTestMode=5 (disable MPO)"
  $mpoWillChange = $false
  if ($wouldDisableMpo) {
    if ($overlayVal -ne 5) { $mpoWillChange = $true }
  }

  Write-Host ""
  Write-Host "MPO (Windows DWM overlays):" -ForegroundColor Cyan
  Show-Setting -Title "OverlayTestMode" -Current $mpoCurrent -Planned $mpoPlanned -WillChange $mpoWillChange

  # ---------------- ASPM ----------------
  $acCur = $null
  $dcCur = $null
  try {
    $q = powercfg -query SCHEME_CURRENT SUB_PCIEXPRESS ASPM
    $acLine = $q | Select-String "Current AC Power Setting Index" | Select-Object -First 1
    $dcLine = $q | Select-String "Current DC Power Setting Index" | Select-Object -First 1
    if ($acLine) { $acCur = ($acLine -replace '.*:\s*','') }
    if ($dcLine) { $dcCur = ($dcLine -replace '.*:\s*','') }
  } catch {}

  $acTxt = "<unknown>"
  $dcTxt = "<unknown>"
  if ($acCur) { $acTxt = $acCur }
  if ($dcCur) { $dcTxt = $dcCur }

  $aspmCurrent = ("AC={0}, DC={1}" -f $acTxt, $dcTxt)
  $aspmPlanned = "AC=0x00000000, DC=0x00000000 (OFF)"
  $aspmWillChange = $false
  if ($wouldDisableAspm) {
    if (($acCur -ne "0x00000000") -or ($dcCur -ne "0x00000000")) { $aspmWillChange = $true }
  }

  Write-Host "PCIe ASPM (Link State Power Management):" -ForegroundColor Cyan
  Show-Setting -Title "Power scheme PCIe ASPM" -Current $aspmCurrent -Planned $aspmPlanned -WillChange $aspmWillChange

  # ---------------- Driver mapping (Store -> Adrenalin) + ULPS policy ----------------
  Write-Host "AMD Driver mapping (Windows Store -> Adrenalin):" -ForegroundColor Cyan

  $mapPath = Join-Path (Get-ScriptDir) "data\adrenalin-mapping.csv"

  $storeVer = Get-AmdStoreDriverVersion
  $storeTxt = "<unknown>"
  if ($storeVer) { $storeTxt = $storeVer }

  $adreVer  = $null
  $adreTxt  = "<unknown> (not in mapping)"
  $policy   = Resolve-UlpsPolicy -AdrenalinVersion $null

  if (-not (Test-Path $mapPath)) {
    Write-Host "  Mapping file not found:" -ForegroundColor Yellow
    Write-Host ("    {0}" -f $mapPath) -ForegroundColor Yellow
    Write-Host "  (Create it with lines like: 32.0.13031.3015,25.3.1)" -ForegroundColor Yellow
  } else {
    $map = Load-StoreToAdrenalinMap_NoHeader -Path $mapPath
    if ($storeVer) {
      $adreVer = Resolve-AdrenalinFromStoreDriver -Map $map -StoreDriverVersion $storeVer
      if ($adreVer) { $adreTxt = $adreVer } else { $adreTxt = "<unknown> (not in mapping)" }
      $policy = Resolve-UlpsPolicy -AdrenalinVersion $adreVer
    }
  }

  Write-Host ("  AMD store driver: {0}" -f $storeTxt)
  Write-Host ("  Adrenalin:        {0}" -f $adreTxt)
  Write-Host ("  ULPS policy:      {0}" -f $policy.Note)

  if ($policy -and $policy.DisableUlpsInRecommended) { $wouldDisableUlps = $true }

  # ---------------- ULPS (per adapter instance) ----------------
  Write-Host ""
  Write-Host "ULPS (AMD display adapters):" -ForegroundColor Cyan

  $instances = Get-AmdDisplayClassInstances
  if ($instances.Count -eq 0) {
    Write-Host "  No display-class instances found." -ForegroundColor Yellow
  } else {
    foreach ($inst in $instances) {
      $p  = $inst.PSPath
      $id = $inst.PSChildName

      # EnableUlps
      $ulpsExists = $false
      $ulpsCurVal = $null
      $ulpsCurTxt = "(not present)"

      try {
        $item = Get-ItemProperty -Path $p -Name "EnableUlps" -ErrorAction Stop
        $ulpsExists = $true
        $ulpsCurVal = [int]$item.EnableUlps
        $ulpsCurTxt = ("EnableUlps={0}" -f $ulpsCurVal)
      } catch {}

      $ulpsPlannedTxt = "Leave as-is"
      $ulpsWillChange = $false

      if ($wouldDisableUlps) {
        if ($ulpsExists) {
          $ulpsPlannedTxt = "EnableUlps=0"
          if ($ulpsCurVal -ne 0) { $ulpsWillChange = $true }
        } else {
          $ulpsPlannedTxt = "Skip (not present)"
        }
      }

      Show-Setting -Title ("Instance {0} - EnableUlps" -f $id) -Current $ulpsCurTxt -Planned $ulpsPlannedTxt -WillChange $ulpsWillChange

      # EnableUlps_NA (verify only; recommended never changes)
      $naCurTxt = "(not present)"
      try {
        $na = Get-ItemProperty -Path $p -Name "EnableUlps_NA" -ErrorAction Stop
        $kind = (Get-Item -Path $p).GetValueKind("EnableUlps_NA")
        $naCurTxt = ("EnableUlps_NA={0} ({1})" -f $na.EnableUlps_NA, $kind)
      } catch {}

      Show-Setting -Title ("Instance {0} - EnableUlps_NA" -f $id) -Current $naCurTxt -Planned "Leave as-is (recommended never touches it)" -WillChange $false
    }
  }

  Write-Host ""
  Write-Host "Verification complete. No changes were made." -ForegroundColor Green
}

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "ERROR: Please run PowerShell as Administrator." -ForegroundColor Red
    Write-Host "Example:" -ForegroundColor Yellow
    Write-Host "  powershell.exe -ExecutionPolicy Bypass -File .\Fix-RDNA3-DisplayWake.ps1" -ForegroundColor Yellow
    throw "Not running as Administrator."
  }
}

function Get-ScriptDir {
  if ($PSCommandPath) {
    return Split-Path -Parent $PSCommandPath
  }

  # Fallbacks (older hosts / edge cases)
  if ($MyInvocation.MyCommand -and $MyInvocation.MyCommand.Path) {
    return Split-Path -Parent $MyInvocation.MyCommand.Path
  }

  # Last resort: current directory
  return (Get-Location).Path
}


function Backup-RegistryValue {
  param(
    [Parameter(Mandatory)] [string]$Path,
    [Parameter(Mandatory)] [string]$Name
  )
  try {
    $item = Get-ItemProperty -Path $Path -ErrorAction Stop
    if ($null -ne $item.$Name) {
      $k = Get-Item -Path $Path -ErrorAction Stop
      return @{
        Exists = $true
        Value  = $item.$Name
        Type   = $k.GetValueKind($Name).ToString()
      }
    }
  } catch {}
  return @{ Exists = $false }
}

function Ensure-Key {
  param([Parameter(Mandatory)] [string]$Path)
  if (-not (Test-Path $Path)) {
    if ($script:IsDryRun) { return }
    New-Item -Path $Path -Force | Out-Null
  }
}

function Set-RegistryDword {
  param(
    [Parameter(Mandatory)] [string]$Path,
    [Parameter(Mandatory)] [string]$Name,
    [Parameter(Mandatory)] [int]$Value
  )
  Ensure-Key -Path $Path
  if ($script:IsDryRun) { return }
  New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
}

function Set-RegistryString {
  param(
    [Parameter(Mandatory)] [string]$Path,
    [Parameter(Mandatory)] [string]$Name,
    [Parameter(Mandatory)] [string]$Value
  )
  Ensure-Key -Path $Path
  if ($script:IsDryRun) { return }
  New-ItemProperty -Path $Path -Name $Name -PropertyType String -Value $Value -Force | Out-Null
}

function Remove-RegistryValue {
  param(
    [Parameter(Mandatory)] [string]$Path,
    [Parameter(Mandatory)] [string]$Name
  )
  if ($script:IsDryRun) { return $true }
  try {
    Remove-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
    return $true
  } catch {
    return $false
  }
}

function Write-Section($title) {
  Write-Host ""
  Write-Host "=== $title ===" -ForegroundColor Cyan
}

function Confirm-OrAbort {
  param([string]$Message)

  if ($Force) { return $true }

  $ans = (Read-Host "$Message (Y/N)").Trim()
  if ($ans -in @('Y','y','YES','Yes','yes')) {
    return $true
  }

  Write-Host "Cancelled by user." -ForegroundColor Yellow
  return $false
}

function Get-LatestBackupFile {
  $dir = Get-ScriptDir
  $files = Get-ChildItem -Path $dir -Filter "Fix-RDNA3-DisplayWake.backup.*.json" -ErrorAction SilentlyContinue |
           Sort-Object LastWriteTime -Descending
  if ($files.Count -eq 0) { return $null }
  return $files[0].FullName
}

function Restore-FromBackupJson {
  param([Parameter(Mandatory)] [string]$BackupFile)

  if (-not (Test-Path $BackupFile)) {
    throw "Backup file not found: $BackupFile"
  }

  $json = Get-Content -Raw -Path $BackupFile | ConvertFrom-Json
  $changes = @($json.Changes)

  Write-Section "Reverting from backup"
  Write-Host "Backup: $BackupFile"
  Write-Host "Entries: $($changes.Count)"
  Write-Host ""

  foreach ($c in $changes) {
    $path = [string]$c.Key
    $name = [string]$c.Name
    $prev = $c.Previous

    if ($null -eq $prev -or -not $prev.Exists) {
      $ok = Remove-RegistryValue -Path $path -Name $name
      if ($ok) { Write-Host "Removed (didn't exist before): $path -> $name" -ForegroundColor Yellow }
      else     { Write-Host "Could not remove / already absent: $path -> $name" -ForegroundColor DarkYellow }
      continue
    }

    $kind = [string]$prev.Type
    $value = $prev.Value

    if ($script:IsDryRun) {
      Write-Host "Would restore: $path -> $name ($kind) = $value" -ForegroundColor Yellow
      continue
    }

    Ensure-Key -Path $path

    switch ($kind) {
      "DWord" { Set-RegistryDword -Path $path -Name $name -Value ([int]$value) }
      "String" { Set-RegistryString -Path $path -Name $name -Value ([string]$value) }
      "ExpandString" {
        New-ItemProperty -Path $path -Name $name -PropertyType ExpandString -Value ([string]$value) -Force | Out-Null
      }
      "QWord" {
        New-ItemProperty -Path $path -Name $name -PropertyType QWord -Value ([long]$value) -Force | Out-Null
      }
      "MultiString" {
        $arr = @()
        if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) { $arr = @($value) }
        else { $arr = @([string]$value) }
        New-ItemProperty -Path $path -Name $name -PropertyType MultiString -Value $arr -Force | Out-Null
      }
      "Binary" {
        $bytes = if ($value -is [byte[]]) { $value } else { [byte[]]@($value) }
        New-ItemProperty -Path $path -Name $name -PropertyType Binary -Value $bytes -Force | Out-Null
      }
      default {
        Write-Host "Skipping unsupported type '$kind' for $path -> $name" -ForegroundColor Red
        continue
      }
    }

    Write-Host "Restored: $path -> $name ($kind) = $value" -ForegroundColor Green
  }
}

# ---------------- Plan + State ----------------

$script:IsDryRun = [bool]$DryRun
$log = New-Object System.Collections.Generic.List[string]
$backup = [ordered]@{
  Timestamp = (Get-Date).ToString("s")
  Changes   = @()
}
$script:DidChangeSomething = $false

Assert-Admin

$scriptDir = Get-ScriptDir

# If no explicit mode chosen, show menu
$explicit =
  $ApplyRecommended -or $RevertFromLatestBackup -or $ListBackups -or
  $DisableMpo -or $RevertMpo -or $DisableAspm -or $DisableUlps -or $TouchUlpsNA -or $DisableHibernate -or $SetTimeouts

function Show-MenuAndGetChoice {
  while ($true) {
    Write-Host ""
    Write-Host "Fix-RDNA3-DisplayWake" -ForegroundColor Cyan
    Write-Host "Pick an option:" -ForegroundColor Cyan
    Write-Host "  1) Apply RECOMMENDED fixes (safe defaults)" -ForegroundColor Green
    Write-Host "  2) Revert from LATEST backup" -ForegroundColor Yellow
    Write-Host "  3) Disable MPO only" -ForegroundColor White
    Write-Host "  4) Disable PCIe ASPM only" -ForegroundColor White
    Write-Host "  5) Disable ULPS only (EnableUlps=0 where present)" -ForegroundColor White
    Write-Host "  6) Set OLED-safe timeouts only" -ForegroundColor White
    Write-Host "  7) Advanced: Touch EnableUlps_NA (ONLY if DWORD, opt-in)" -ForegroundColor DarkYellow
    Write-Host "  8) List backups" -ForegroundColor White
    Write-Host "  9) Verify current settings (read-only)" -ForegroundColor White
    Write-Host "  0) Exit" -ForegroundColor White
    Write-Host ""

    $choice = (Read-Host "Enter 0-9").Trim()

    switch ($choice) {
      '1' { return "APPLY_RECOMMENDED" }
      '2' { return "REVERT_LATEST" }
      '3' { return "DISABLE_MPO" }
      '4' { return "DISABLE_ASPM" }
      '5' { return "DISABLE_ULPS" }
      '6' { return "SET_TIMEOUTS" }
      '7' { return "TOUCH_ULPS_NA" }
      '8' { return "LIST_BACKUPS" }
      '9' { return "VERIFY" }
      '0' { return "EXIT" }
      default {
        Write-Host "Invalid choice '$choice'. Please enter a number 1-9." -ForegroundColor Yellow
      }
    }
  }
}

if (-not $explicit) {
  $action = Show-MenuAndGetChoice

  switch ($action) {
    "APPLY_RECOMMENDED" { $ApplyRecommended = $true }
    "REVERT_LATEST"     { $RevertFromLatestBackup = $true }
    "DISABLE_MPO"       { $DisableMpo = $true }
    "DISABLE_ASPM"      { $DisableAspm = $true }
    "DISABLE_ULPS"      { $DisableUlps = $true }
    "SET_TIMEOUTS"      { $SetTimeouts = $true }
    "TOUCH_ULPS_NA"     { $TouchUlpsNA = $true }
    "LIST_BACKUPS"      { $ListBackups = $true }
    "VERIFY"            { $VerifySettings = $true }
    "EXIT" {
      Write-Host "Exiting." -ForegroundColor Yellow
      return
    }
  }
}

if ($VerifySettings) {
  Verify-CurrentSettings
  return
}

if ($ApplyRecommended) {
  $DisableMpo  = $true
  $DisableAspm = $true

  $mapPath  = Join-Path (Get-ScriptDir) "data\adrenalin-mapping.csv"
  $map      = Load-StoreToAdrenalinMap_NoHeader -Path $mapPath
  $storeVer = Get-AmdStoreDriverVersion
  $adreVer  = if ($storeVer) { Resolve-AdrenalinFromStoreDriver -Map $map -StoreDriverVersion $storeVer } else { $null }
  $policy   = Resolve-UlpsPolicy -AdrenalinVersion $adreVer

  Write-Host ""
  Write-Host "Driver-aware Recommended policy:" -ForegroundColor Cyan
  Write-Host ("  AMD store driver: {0}" -f $(if ($storeVer) { $storeVer } else { "<unknown>" }))
  Write-Host ("  Adrenalin:        {0}" -f $(if ($adreVer)  { $adreVer }  else { "<unknown> (not in mapping)" }))
  Write-Host ("  Policy:           {0} - {1}" -f $policy.Name, $policy.Note)

  if ($policy.DisableUlpsInRecommended) {
    $DisableUlps = $true
    Write-Host "  Action: ULPS will be disabled (EnableUlps=0 where present)" -ForegroundColor Yellow
  } else {
    $DisableUlps = $false
    Write-Host "  Action: ULPS will NOT be modified" -ForegroundColor Green
  }
}

# ---------------- Backups / List / Revert ----------------

if ($ListBackups) {
  Write-Section "Available backups"
  $files = Get-ChildItem -Path $scriptDir -Filter "Fix-RDNA3-DisplayWake.backup.*.json" -ErrorAction SilentlyContinue |
           Sort-Object LastWriteTime -Descending
  if ($files.Count -eq 0) {
    Write-Host "No backups found in: $scriptDir" -ForegroundColor Yellow
  } else {
    $files | ForEach-Object { Write-Host $_.Name }
  }
  return
}

if ($RevertFromLatestBackup) {
  $latest = Get-LatestBackupFile
  if (-not $latest) {
    Write-Host "No backup files found in: $scriptDir" -ForegroundColor Red
    return
  }

  Write-Section "Plan"
  Write-Host "Action: Revert from latest backup" -ForegroundColor Yellow
  Write-Host "DryRun: $($script:IsDryRun)"
  Write-Host "Backup: $latest"
  if (-not (Confirm-OrAbort "Proceed to revert?")) { return }

  Restore-FromBackupJson -BackupFile $latest

  Write-Host ""
  Write-Host "Done. Reboot recommended:" -ForegroundColor Cyan
  Write-Host "  shutdown /r /t 0"
  return
}

# ---------------- Compute plan (preview) ----------------

Write-Section "Plan (what will happen)"
Write-Host ("DryRun: {0}" -f $script:IsDryRun) -ForegroundColor Yellow

if ($DisableMpo) { Write-Host " - Set OverlayTestMode=5 (disable MPO)" }
if ($RevertMpo)  { Write-Host " - Remove OverlayTestMode (revert MPO tweak)" }
if ($DisableAspm){ Write-Host " - Set PCIe ASPM (Link State Power Mgmt) OFF for current power plan" }
if ($DisableUlps){ Write-Host " - Set EnableUlps=0 where present under display class instances" }
if ($TouchUlpsNA){ Write-Host " - Advanced: Set EnableUlps_NA=0 ONLY if it exists as DWORD (no type forcing)" -ForegroundColor DarkYellow }
if ($DisableHibernate){ Write-Host " - Disable hibernate" }
if ($SetTimeouts) {
  Write-Host " - Set monitor timeout: $MonitorTimeoutMinutes min (AC/DC)"
  Write-Host " - Set sleep timeout:   $SleepTimeoutMinutes min (AC/DC)"
}

Write-Host ""
Write-Host "Safety note:" -ForegroundColor Cyan
Write-Host " - A JSON backup will be written before applying any registry changes."
Write-Host " - EnableUlps_NA is NOT touched unless you explicitly choose it."
Write-Host ""

if (-not (Confirm-OrAbort "Proceed with these changes?")) { return }

# ---------------- Apply changes ----------------

$backupFile = Join-Path $scriptDir ("Fix-RDNA3-DisplayWake.backup.{0}.json" -f (Get-Date).ToString("yyyyMMdd-HHmmss"))
$logFile    = Join-Path $scriptDir ("Fix-RDNA3-DisplayWake.log.{0}.txt" -f (Get-Date).ToString("yyyyMMdd-HHmmss"))

# --- 1) MPO ---
$dwmPath = "HKLM:\SOFTWARE\Microsoft\Windows\Dwm"
if ($RevertMpo) {
  $prev = Backup-RegistryValue -Path $dwmPath -Name "OverlayTestMode"
  $backup.Changes += [ordered]@{
    Key      = $dwmPath
    Name     = "OverlayTestMode"
    Previous = $prev
    New      = @{ Type="(removed)"; Value=$null }
  }

  $removed = Remove-RegistryValue -Path $dwmPath -Name "OverlayTestMode"
  $log.Add("MPO: removed OverlayTestMode (revert). Removed=$removed")
  $script:DidChangeSomething = $true
}
elseif ($DisableMpo) {
  $prev = Backup-RegistryValue -Path $dwmPath -Name "OverlayTestMode"
  $backup.Changes += [ordered]@{
    Key      = $dwmPath
    Name     = "OverlayTestMode"
    Previous = $prev
    New      = @{ Type="REG_DWORD"; Value=5 }
  }
  Set-RegistryDword -Path $dwmPath -Name "OverlayTestMode" -Value 5
  $log.Add("MPO: set OverlayTestMode=5 (disable MPO)")
  $script:DidChangeSomething = $true
}

# --- 2) ULPS (display adapter class instances) ---
$instances = Get-AmdDisplayClassInstances
if ($DisableUlps -or $TouchUlpsNA) {
  if ($instances.Count -eq 0) {
    $log.Add("ULPS: No display-class instances found (unexpected).")
  } else {
    foreach ($inst in $instances) {
      $p = $inst.PSPath

      if ($DisableUlps) {
        $prevUlps = Backup-RegistryValue -Path $p -Name "EnableUlps"
        if ($prevUlps.Exists) {
          $backup.Changes += [ordered]@{
            Key      = $p
            Name     = "EnableUlps"
            Previous = $prevUlps
            New      = @{ Type="REG_DWORD"; Value=0 }
          }
          Set-RegistryDword -Path $p -Name "EnableUlps" -Value 0
          $log.Add("ULPS: [$($inst.PSChildName)] Set EnableUlps=0")
          $script:DidChangeSomething = $true
        } else {
          $log.Add("ULPS: [$($inst.PSChildName)] EnableUlps not found -> skipped")
        }
      }

      if ($TouchUlpsNA) {
        $prevUlpsNA = Backup-RegistryValue -Path $p -Name "EnableUlps_NA"
        if (-not $prevUlpsNA.Exists) {
          $log.Add("ULPS_NA: [$($inst.PSChildName)] EnableUlps_NA not found -> skipped")
        }
        elseif ($prevUlpsNA.Type -ne "DWord") {
          $log.Add("ULPS_NA: [$($inst.PSChildName)] Exists but type is $($prevUlpsNA.Type) -> skipped (no type forcing)")
        }
        else {
          $backup.Changes += [ordered]@{
            Key      = $p
            Name     = "EnableUlps_NA"
            Previous = $prevUlpsNA
            New      = @{ Type="REG_DWORD"; Value=0 }
          }
          Set-RegistryDword -Path $p -Name "EnableUlps_NA" -Value 0
          $log.Add("ULPS_NA: [$($inst.PSChildName)] Set EnableUlps_NA=0 (DWORD only, opt-in)")
          $script:DidChangeSomething = $true
        }
      }
    }
  }
}

# --- 3) PCIe ASPM OFF ---
if ($DisableAspm) {
  try {
    if (-not $script:IsDryRun) {
      powercfg -setacvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 0 | Out-Null
      powercfg -setdcvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 0 | Out-Null
      powercfg -setactive SCHEME_CURRENT | Out-Null
    }
    $log.Add("Powercfg: Set PCIe ASPM OFF for current power scheme (AC/DC).")
    $script:DidChangeSomething = $true
  } catch {
    $log.Add("Powercfg: Failed to set ASPM off. Error: $($_.Exception.Message)")
  }
}

# --- 4) Hibernate OFF (optional) ---
if ($DisableHibernate) {
  try {
    if (-not $script:IsDryRun) { powercfg /hibernate off | Out-Null }
    $log.Add("Powercfg: Disabled hibernate.")
    $script:DidChangeSomething = $true
  } catch {
    $log.Add("Powercfg: Failed to disable hibernate. Error: $($_.Exception.Message)")
  }
}

# --- 5) Timeouts (optional) ---
if ($SetTimeouts) {
  try {
    if (-not $script:IsDryRun) {
      powercfg -change -monitor-timeout-ac $MonitorTimeoutMinutes | Out-Null
      powercfg -change -monitor-timeout-dc $MonitorTimeoutMinutes | Out-Null
      powercfg -change -standby-timeout-ac $SleepTimeoutMinutes | Out-Null
      powercfg -change -standby-timeout-dc $SleepTimeoutMinutes | Out-Null
    }
    $log.Add("Powercfg: Set monitor timeout to $MonitorTimeoutMinutes min (AC/DC), sleep timeout to $SleepTimeoutMinutes min (AC/DC).")
    $script:DidChangeSomething = $true
  } catch {
    $log.Add("Powercfg: Failed to set timeouts. Error: $($_.Exception.Message)")
  }
}

# ---------------- Write backup + logs ----------------
try {
  ($backup | ConvertTo-Json -Depth 10) | Out-File -FilePath $backupFile -Encoding UTF8
  $log | Out-File -FilePath $logFile -Encoding UTF8
} catch {
  Write-Host "Warning: couldn't write log/backup: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Section "Done"
Write-Host "Log:    $logFile"
Write-Host "Backup: $backupFile"
Write-Host ""
$log | ForEach-Object { Write-Host $_ }

Write-Host ""
if ($script:IsDryRun) {
  Write-Host "DryRun complete. No changes were applied." -ForegroundColor Yellow
} else {
  Write-Host "Reboot recommended:" -ForegroundColor Cyan
  Write-Host "  shutdown /r /t 0"
}
