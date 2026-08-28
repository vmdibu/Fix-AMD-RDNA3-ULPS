[CmdletBinding()]
param(
  [string]$MappingPath = (Join-Path $PSScriptRoot "..\data\adrenalin-mapping.csv"),
  [string]$SourceUri = "https://gpuopen.com/version-table/",
  [switch]$VerifyOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Normalize-CellText {
  param([Parameter(Mandatory=$true)][string]$Text)

  $decoded = [System.Net.WebUtility]::HtmlDecode($Text)
  $withoutTags = $decoded -replace '<[^>]+>', ' '
  $normalized = $withoutTags -replace '\s+', ' '
  return $normalized.Trim()
}

function Read-ExistingMapping {
  param([Parameter(Mandatory=$true)][string]$Path)

  $rows = New-Object System.Collections.Generic.List[object]
  if (-not (Test-Path $Path)) { return $rows }

  foreach ($line in Get-Content -Path $Path -Encoding UTF8) {
    $trimmed = $line.Trim().TrimStart([char]0xFEFF)
    if (-not $trimmed) { continue }
    if ($trimmed.StartsWith("#")) { continue }

    $parts = $trimmed -split ',', 2
    if ($parts.Count -lt 2) { continue }

    $store = $parts[0].Trim().TrimEnd(".")
    $adrenalin = $parts[1].Trim()
    if ($store -and $adrenalin) {
      $rows.Add([pscustomobject]@{
        StoreDriver = $store
        Adrenalin   = $adrenalin
      })
    }
  }

  return $rows
}

function Get-GpuOpenMapping {
  param([Parameter(Mandatory=$true)][string]$Uri)

  Write-Host "Fetching AMD driver version table: $Uri"
  $response = Invoke-WebRequest -Uri $Uri -UseBasicParsing
  $html = [string]$response.Content

  $rows = New-Object System.Collections.Generic.List[object]
  $rowMatches = [regex]::Matches($html, '(?is)<tr[^>]*>(.*?)</tr>')

  foreach ($rowMatch in $rowMatches) {
    $cellMatches = [regex]::Matches($rowMatch.Groups[1].Value, '(?is)<t[dh][^>]*>(.*?)</t[dh]>')
    if ($cellMatches.Count -lt 4) { continue }

    $cells = @()
    foreach ($cellMatch in $cellMatches) {
      $cells += Normalize-CellText -Text $cellMatch.Groups[1].Value
    }

    $releaseText = $cells[0]
    $storeText = $cells[3].Trim().TrimEnd(".")

    $releaseMatch = [regex]::Match($releaseText, '\d+\.\d+(?:\.\d+)?')
    $storeMatch = [regex]::Match($storeText, '\d+\.\d+\.\d+(?:\.\d+)?')
    if (-not $releaseMatch.Success -or -not $storeMatch.Success) { continue }

    $rows.Add([pscustomobject]@{
      StoreDriver = $storeMatch.Value.TrimEnd(".")
      Adrenalin   = $releaseMatch.Value
    })
  }

  if ($rows.Count -lt 20) {
    throw "Parsed only $($rows.Count) mapping rows from $Uri; refusing to update."
  }

  return $rows
}

function Merge-MappingRows {
  param(
    [Parameter(Mandatory=$true)]$FreshRows,
    [Parameter(Mandatory=$true)]$ExistingRows
  )

  $seen = @{}
  $merged = New-Object System.Collections.Generic.List[object]

  foreach ($row in @($FreshRows) + @($ExistingRows)) {
    if (-not $row.StoreDriver -or -not $row.Adrenalin) { continue }
    if ($seen.ContainsKey($row.StoreDriver)) { continue }

    $seen[$row.StoreDriver] = $true
    $merged.Add([pscustomobject]@{
      StoreDriver = $row.StoreDriver
      Adrenalin   = $row.Adrenalin
    })
  }

  return $merged
}

function Convert-MappingToText {
  param([Parameter(Mandatory=$true)]$Rows)

  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add("# Source: AMD GPUOpen Radeon Vulkan Drivers Version Table")
  $lines.Add("# Updated by scripts/Update-AdrenalinMapping.ps1")
  $lines.Add("# Format: Windows Driver Store Version,Adrenalin Release")

  foreach ($row in $Rows) {
    $lines.Add(("{0},{1}" -f $row.StoreDriver, $row.Adrenalin))
  }

  return (($lines -join [Environment]::NewLine) + [Environment]::NewLine)
}

$resolvedMappingPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($MappingPath)
$existing = Read-ExistingMapping -Path $resolvedMappingPath
$fresh = Get-GpuOpenMapping -Uri $SourceUri
$merged = Merge-MappingRows -FreshRows $fresh -ExistingRows $existing
$newText = Convert-MappingToText -Rows $merged

$oldText = ""
if (Test-Path $resolvedMappingPath) {
  $oldText = [System.IO.File]::ReadAllText($resolvedMappingPath)
  $oldText = $oldText.TrimStart([char]0xFEFF)
}

if ($oldText -eq $newText) {
  Write-Host "Mapping is up to date. Rows: $($merged.Count)"
  return
}

if ($VerifyOnly) {
  throw "Mapping is out of date. Run scripts/Update-AdrenalinMapping.ps1 to refresh $resolvedMappingPath."
}

[System.IO.File]::WriteAllText($resolvedMappingPath, $newText, [System.Text.UTF8Encoding]::new($false))
Write-Host "Updated mapping: $resolvedMappingPath"
Write-Host "Rows: $($merged.Count)"
