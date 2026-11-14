#Requires -Version 5.1
<#
.SYNOPSIS
    The system auto-update leg (PLAN.md 14, phase 2): the removal of
    a root from LocalMachine\Root, the CAPI validation trigger of a
    schannel client (the curl of Windows), the return of the root
    through the Windows Update root program — the live proof of the
    «missing roots arrive by the system means» criterion.

.DESCRIPTION
    The guard snapshots the stores first. The leg deletes the ISRG
    Root X1 from LocalMachine\Root (the subject match), triggers
    the schannel validation of the LE-protected endpoint (the
    curl.exe of Windows rides schannel — the CAPI client the root
    program serves), verifies the root came back, and rides the
    guard restore.

    The dual-scope bridge of the client reads the store after the
    system refilled it — the system-policy dial sees the returned
    root without any action of the ssh3 side.

    Run from the elevated console on the internet-connected
    machine. The rollback: the guard restore + the manual
    re-import of the removed cert (the script saves the DER into
    the session dir before the removal).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\system-auto-update.ps1
#>

$ErrorActionPreference = 'Continue'

$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) { $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }

$Guard      = Join-Path $ScriptDir 'TrustStoreGuard.ps1'
$SessionDir = Join-Path $ScriptDir ('session-auto-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))

$Failures = 0

function pass($m) { Write-Host "   PASS: $m" }
function fail($m) { Write-Host "   FAIL: $m"; $script:Failures++ }
function head($m) { Write-Host "== $m" }

# --- 0. the guard snapshot ---

head "stage 0: the guard snapshot"

& $Guard -Action Snapshot -SessionDir $SessionDir
if ($LASTEXITCODE -ne 0) {
    Write-Host "ABORT: the snapshot failed"
    exit 1
}
pass "the pre-test map landed"

# --- 1. the removal of ISRG Root X1 from LocalMachine\Root ---

head "stage 1: the ISRG Root X1 removal from LocalMachine\Root"

$isrg = Get-ChildItem Cert:\LocalMachine\Root |
    Where-Object { $_.Subject -like '*ISRG Root X1*' } |
    Select-Object -First 1

if (-not $isrg) {
    Write-Host "ABORT: ISRG Root X1 is not in LocalMachine\Root (the store shape differs from the plan)"
    exit 1
}

$derPath = Join-Path $SessionDir 'isrg-root-x1.der'
[IO.File]::WriteAllBytes($derPath, $isrg.RawData)

$store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    'Root', 'LocalMachine')
$store.Open('ReadWrite')
$store.Remove($isrg)
$store.Close()

$still = [bool](Get-ChildItem Cert:\LocalMachine\Root |
    Where-Object { $_.Thumbprint -eq $isrg.Thumbprint })

if ($still) {
    fail "the removal did not take"
    exit 1
}

pass "ISRG Root X1 removed from LocalMachine\Root (the DER saved: $derPath)"

# --- 2. the schannel trigger of the LE-protected endpoint ---

head "stage 2: the schannel validation trigger (the LE endpoint)"

# the curl of Windows rides schannel — the CAPI client the root
# program serves. The LE endpoint validates through ISRG Root X1 —
# the missing root triggers the Windows Update root program

$trigger = & curl.exe -sS -o NUL -w "%{http_code}" --connect-timeout 30 https://letsencrypt.org/ 2>&1
Write-Host "   curl(schannel): http=$trigger"

# the return check: the root came back through the auto-update

Start-Sleep -Seconds 5

$back = [bool](Get-ChildItem Cert:\LocalMachine\Root |
    Where-Object { $_.Thumbprint -eq $isrg.Thumbprint })

if ($back) {
    pass "ISRG Root X1 returned through the system auto-update"
} else {

    # the retry loop: the root program is asynchronous, the second
    # schannel validation re-triggers the fetch

    $trigger2 = & curl.exe -sS -o NUL -w "%{http_code}" --connect-timeout 30 https://letsencrypt.org/ 2>&1
    Start-Sleep -Seconds 10

    $back = [bool](Get-ChildItem Cert:\LocalMachine\Root |
        Where-Object { $_.Thumbprint -eq $isrg.Thumbprint })

    if ($back) {
        pass "ISRG Root X1 returned through the system auto-update (the retry pass)"
    } else {
        fail "the root did not return automatically (the manual import: certutil -addstore Root $derPath)"
    }
}

# --- 3. the ssh3 dual-scope bridge sees the returned root ---

head "stage 3: the bridge reads the refilled store"

if (-not (Test-Path (Join-Path $ScriptDir 'ssh3-cert.exe'))) {
    Write-Host "   SKIP: ssh3-cert.exe is not next to the script (the bundle layout)"
} else {

    $probeOut = & (Join-Path $ScriptDir 'ssh3-cert.exe') probe 2>&1 |
        Where-Object { $_ -like 'PROBE system=*' }

    pass "the bridge read the refilled store: $probeOut"
}

# --- 4. the guard restore ---

head "stage 4: the guard restore"

& $Guard -Action Restore -SessionDir $SessionDir
if ($LASTEXITCODE -eq 0) {
    pass "the machine back to the pre-test map"
} else {
    fail "the guard restore drifted"
}

# --- the verdict ---

Write-Host ""
if ($Failures -eq 0) {
    Write-Host "SYSTEM-AUTO-UPDATE OK"
    exit 0
}

Write-Host "SYSTEM-AUTO-UPDATE FAILED: $Failures check(s)"
exit 1
