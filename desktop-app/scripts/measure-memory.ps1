<#
.SYNOPSIS
  Measures Passyble's memory on Windows (Pass.exe and its WebView2 processes) in five states, and
  how fast the windows open from the tray.

.DESCRIPTION
  Run it on an installed build, with a demo vault (never your real one: it asks you to unlock).
  It starts Pass.exe tray-only with PASSYBLE_PERF=1, then walks you through:

    1. started to tray   (nothing opened yet)
    2. window open       (main window on screen, vault locked)
    3. closed to tray    (window closed again)
    4. after unlock      (unlocked, window closed to the tray)
    5. after the popups  (quick pick, a 2FA code popup, a browser prompt; all closed again)

  For each state it sums the working set and the private bytes of Pass.exe and every
  msedgewebview2.exe it started. Then it prints the open latencies Pass logged
  ("perf: <window> painted N ms after show" in %LOCALAPPDATA%\Pass\logs\pass.log).
  desktop-app/README.md ("Memory") lists what to expect.

.PARAMETER ExePath
  Pass.exe to start. Default: the per-user install, %LOCALAPPDATA%\Passyble\Pass.exe.

.PARAMETER Settle
  Seconds to wait after each step before measuring (hidden windows rest after 2 s, the windows
  built at start after 10 s). Default 15.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File desktop-app\scripts\measure-memory.ps1
#>
param(
  [string]$ExePath = (Join-Path $env:LOCALAPPDATA 'Passyble\Pass.exe'),
  [int]$Settle = 15
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $ExePath)) {
  Write-Host "Pass.exe not found at $ExePath. Pass -ExePath <path to Pass.exe>."
  exit 1
}

$log = Join-Path $env:LOCALAPPDATA 'Pass\logs\pass.log'

function Get-PassProcesses {
  $all = Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name
  $roots = @($all | Where-Object { $_.Name -ieq 'Pass.exe' })
  $ids = New-Object 'System.Collections.Generic.HashSet[int]'
  foreach ($r in $roots) { [void]$ids.Add([int]$r.ProcessId) }
  # The WebView2 browser process is a child of Pass.exe; its renderer, GPU and utility processes are
  # its children.
  do {
    $added = $false
    foreach ($p in $all) {
      if ($ids.Contains([int]$p.ParentProcessId) -and -not $ids.Contains([int]$p.ProcessId) -and $p.Name -ieq 'msedgewebview2.exe') {
        [void]$ids.Add([int]$p.ProcessId)
        $added = $true
      }
    }
  } while ($added)
  foreach ($id in $ids) {
    $proc = Get-Process -Id $id -ErrorAction SilentlyContinue
    if ($proc) { $proc }
  }
}

$results = @()

function Measure-State([string]$State) {
  $procs = @(Get-PassProcesses)
  $pass = @($procs | Where-Object { $_.ProcessName -ieq 'Pass' })
  $web = @($procs | Where-Object { $_.ProcessName -ieq 'msedgewebview2' })
  $mb = { param($bytes) [math]::Round($bytes / 1MB, 1) }
  $row = [pscustomobject]@{
    State          = $State
    'Pass WS MB'   = & $mb (($pass | Measure-Object WorkingSet64 -Sum).Sum)
    'Pass priv MB' = & $mb (($pass | Measure-Object PrivateMemorySize64 -Sum).Sum)
    WebViews       = $web.Count
    'Web WS MB'    = & $mb (($web | Measure-Object WorkingSet64 -Sum).Sum)
    'Web priv MB'  = & $mb (($web | Measure-Object PrivateMemorySize64 -Sum).Sum)
    'Total WS MB'  = & $mb (($procs | Measure-Object WorkingSet64 -Sum).Sum)
    'Total priv MB' = & $mb (($procs | Measure-Object PrivateMemorySize64 -Sum).Sum)
  }
  $script:results += $row
  $row | Format-Table -AutoSize | Out-Host
}

function Wait-Step([string]$Text) {
  Write-Host ''
  Write-Host $Text
  [void](Read-Host 'Press Enter when done')
  Write-Host "Waiting $Settle s for the windows to rest..."
  Start-Sleep -Seconds $Settle
}

if (Get-Process -Name Pass -ErrorAction SilentlyContinue) {
  Write-Host 'Passyble is running. Quit it from the tray icon (Quit), then press Enter.'
  [void](Read-Host)
  if (Get-Process -Name Pass -ErrorAction SilentlyContinue) {
    Write-Host 'Pass.exe is still running; stopping.'
    exit 1
  }
}

$logStart = 0
if (Test-Path $log) { $logStart = (Get-Item $log).Length }

Write-Host "Starting $ExePath tray-only with PASSYBLE_PERF=1..."
$env:PASSYBLE_PERF = '1'
Start-Process -FilePath $ExePath -ArgumentList '--background' | Out-Null
Remove-Item Env:PASSYBLE_PERF
Start-Sleep -Seconds $Settle
Measure-State 'started to tray'

Wait-Step '2. Open Passyble from the tray icon and leave the vault locked.'
Measure-State 'window open'

Wait-Step '3. Close the main window (X) so Passyble is in the tray again.'
Measure-State 'closed to tray'

Wait-Step '4. Open Passyble, unlock the DEMO vault, browse a little, then close the window to the tray.'
Measure-State 'after unlock'

Wait-Step ('5. Show the popups, then close each: the auto-type hotkey (quick pick, Esc), a 2FA code ' +
  'popup (from the tray or a login with a code), and a browser prompt (fill or passkey consent from ' +
  'the extension, Cancel).')
Measure-State 'after the popups'

Write-Host ''
Write-Host 'Memory per state (WS: working set, priv: private bytes):'
$results | Format-Table -AutoSize | Out-Host

Write-Host 'Open latency (show to first painted frame), from pass.log:'
if (Test-Path $log) {
  $stream = [System.IO.File]::Open($log, 'Open', 'Read', 'ReadWrite')
  try {
    # The log may have rotated meanwhile: then read it from the start.
    if ($stream.Length -ge $logStart) { [void]$stream.Seek($logStart, 'Begin') }
    $reader = New-Object System.IO.StreamReader($stream)
    $lines = $reader.ReadToEnd() -split "`r?`n" | Where-Object { $_ -match 'perf: ' }
  } finally {
    $stream.Dispose()
  }
  if ($lines) {
    $lines | ForEach-Object { Write-Host "  $_" }
    $ms = $lines | ForEach-Object { if ($_ -match 'perf: (\w+) painted (\d+) ms') { [pscustomobject]@{ Window = $Matches[1]; Ms = [int]$Matches[2] } } }
    $ms | Group-Object Window | ForEach-Object {
      $stats = $_.Group | Measure-Object Ms -Average -Maximum
      Write-Host ("  {0}: {1} opens, average {2:N0} ms, slowest {3} ms (target: under 150 ms)" -f $_.Name, $stats.Count, $stats.Average, $stats.Maximum)
    }
  } else {
    Write-Host '  No perf lines: is this build older than the memory work, or was PASSYBLE_PERF not passed on?'
  }
} else {
  Write-Host "  $log not found."
}
Write-Host ''
Write-Host 'Quit Passyble from the tray when done (the next normal start logs no perf lines).'
