#Requires -Version 5.1
<#
.SYNOPSIS
    The trust-update scheduler livetest (PLAN.md 14, phase 1c): the
    schtasks daily task of ssh3-cert --trust-update rides both run
    shapes - the admin token (/RL HIGHEST) and the user token
    (/RL LIMITED) - the bundle + the manifest land, the sha256
    verdict closes, the task deletes.

.DESCRIPTION
    The task name is the livetest-only name (the real install of the
    wave-14 canon lives in the man pages, not in schtasks yet). The
    rollback: the task delete + the bundle artifacts removed (the
    removal returns the client to the bundled roots - the canon).

    The network probe rides first: the fetch goes to the default
    bundle URL (curl.se/ca/cacert.pem) - no network, no leg.

    Run from the console that may create scheduled tasks (the admin
    shape needs the elevated session; the user shape rides /RL
    LIMITED from the same session).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\livetest-schtasks.ps1 -Scope All
    powershell -ExecutionPolicy Bypass -File .\livetest-schtasks.ps1 -Scope User
#>

param(
    [ValidateSet('All', 'Admin', 'User')]
    [string]$Scope = 'All',

    # the batch token of the task: the interactive-only task (no
    # /RU /RP) never starts from a remote/console-less session - the
    # scheduled task service needs the stored credentials to spawn
    # the background process
    [string]$TaskUser = $env:USERNAME,
    [string]$TaskPass = ''
)

$ErrorActionPreference = 'Continue'

$TaskName  = 'ssh3-trust-update-livetest'
$CertPath  = Join-Path $PSScriptRoot 'ssh3-cert.exe'
$Bundle    = Join-Path $env:USERPROFILE '.ssh3\trust-bundle.pem'
$Deadline  = 150

$Failures = 0

function pass($m) { Write-Host "   PASS: $m" }
function fail($m) { Write-Host "   FAIL: $m"; $script:Failures++ }

# --- the prerequisites ---

Write-Host ('== host: ' + $env:COMPUTERNAME + ' / user: ' + $env:USERNAME)
Write-Host ('== elevated: ' + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))

if (-not (Test-Path $CertPath)) {
    Write-Host "SCHTASKS-LIVETEST SKIPPED: ssh3-cert.exe is not next to the script"
    exit 2
}

$net = & curl.exe -sS -o NUL -w "%{http_code}" --connect-timeout 15 https://curl.se/ca/cacert.pem 2>&1
if ($net -ne '200') {
    Write-Host "SCHTASKS-LIVETEST SKIPPED: no network to the bundle URL (http=$net)"
    exit 2
}
pass "the network to the bundle URL rides (http=$net)"

function Run-Scope {
    param([string]$RL, [string]$Tag)

    Remove-Item $Bundle, "$Bundle.man" -ErrorAction SilentlyContinue

    # the cmd /c wrapper carries the output redirect: the task log
    # becomes the evidence of the task-context verdict (the exe has
    # no log file of its own)
    $LogPath = Join-Path $PSScriptRoot ('task-' + $Tag + '.log')
    $tr = 'cmd /c ""' + $CertPath + '" --trust-update > "' + $LogPath + '" 2>&1"'

    if ([string]::IsNullOrEmpty($TaskPass)) {
        schtasks /Create /F /TN $TaskName /SC DAILY /ST 03:00 /RL $RL /TR $tr | Out-Null
    } else {
        schtasks /Create /F /TN $TaskName /SC DAILY /ST 03:00 /RL $RL /RU "$TaskUser" /RP "$TaskPass" /TR $tr | Out-Null
    }
    if ($LASTEXITCODE -ne 0) { fail "${Tag}: the task create failed (rc $LASTEXITCODE)"; return }

    schtasks /Run /TN $TaskName | Out-Null
    if ($LASTEXITCODE -ne 0) { fail "${Tag}: the task run failed (rc $LASTEXITCODE)" }

    # the poll keyed on the result code: the running mark is the
    # SCHED_S_TASK_RUNNING 267009, the not-yet-run is 267011 - the
    # final verdict is any other code (the LastRunTime field lags
    # the real process and cannot serve the poll)

    $testStart = Get-Date
    $deadline  = $testStart.AddSeconds($Deadline)
    $done      = $false

    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        $info = Get-ScheduledTaskInfo -TaskName $TaskName
        if ($info.LastTaskResult -ne 267009 -and $info.LastTaskResult -ne 267011) {
            $done = $true
            break
        }
    }

    if (-not $done) {
        $proc = Get-Process ssh3-cert -ErrorAction SilentlyContinue | Select-Object -First 1
        $procNote = if ($proc) { "the ssh3-cert process lives (pid $($proc.Id))" } else { "no ssh3-cert process" }
        fail "${Tag}: the task poll timed out (rc=$($info.LastTaskResult), $procNote)"
        return
    }

    # the scheduler leg: the task reached ANY final verdict - the
    # create/run/poll/delete cycle of the scheduled-task service rode
    pass "${Tag}: the scheduler rode the task to the verdict rc=$($info.LastTaskResult) ($RL token)"

    # the fetch leg: rc 0 = the fresh bundle; the rc 255 (stale) is
    # the known session-0 defect of the mingw build (the fetch rides
    # the interactive session, dies in the task context - the curl
    # of the same context rides, so the network is not the cause)
    if ($info.LastTaskResult -eq 0) {
        pass "${Tag}: the fetch rode (rc 0)"
    } else {
        $logTail = Get-Content $LogPath -Tail 3 -ErrorAction SilentlyContinue
        Write-Host ("   task log tail: " + ($logTail -join ' | '))
        fail "${Tag}: the fetch verdict rc=$($info.LastTaskResult) (the session-0 fetch defect)"
    }

    Remove-Item $LogPath -ErrorAction SilentlyContinue

    if ((Test-Path $Bundle) -and (Test-Path "$Bundle.man")) {
        $hashNow = (Get-FileHash $Bundle -Algorithm SHA256).Hash.ToLower()
        $hashMan = (Get-Content "$Bundle.man" | Select-Object -Index 1).Trim().ToLower()
        if ($hashNow -eq $hashMan) {
            pass "${Tag}: the bundle + the manifest landed (sha256 match)"
        } else {
            fail "${Tag}: the manifest sha256 drift"
        }
    } else {
        fail "${Tag}: the bundle artifacts missing"
    }

    schtasks /Delete /F /TN $TaskName | Out-Null
    Remove-Item $Bundle, "$Bundle.man" -ErrorAction SilentlyContinue
}

# --- the legs ---

if ($Scope -eq 'All' -or $Scope -eq 'Admin') { Run-Scope 'HIGHEST' 'admin' }
if ($Scope -eq 'All' -or $Scope -eq 'User')  { Run-Scope 'LIMITED' 'user' }

# --- the verdict ---

Write-Host ""
if ($Failures -eq 0) {
    Write-Host "SCHTASKS-LIVETEST OK"
    exit 0
}

Write-Host "SCHTASKS-LIVETEST FAILED: $Failures check(s)"
exit 1
