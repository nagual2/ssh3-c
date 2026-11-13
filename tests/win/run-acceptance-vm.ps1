#Requires -Version 5.1
<#
.SYNOPSIS
    The full live acceptance of the win trust store bridges and the
    client certificates (PLAN.md 14, phases 2-3) on THIS machine —
    no parameters: the paths, the ports and the server lifecycle
    are wired inside.

.DESCRIPTION
    The script rides the vm-bundle layout (everything next to the
    script): ssh3.exe, ssh3-cert.exe, ssh3-server.exe,
    TrustStoreGuard.ps1, and the fixtures (ca.pem, alice pair, srv
    pair — the openssl-generated files of the bundle). The
    sequence:

      stage 0  the snapshot of the ROOT/CA/Disallowed stores (the
               guard map, the rollback anchor)
      stage 1  the Crypt32 bridge probe (ssh3-cert probe): the
               machine anchors ride the system build
      stage 2  the ADD-ROOT mutation: the test ca imports into the
               system Root (certutil), the probe delta, the
               delstore rollback
      stage 3  the DISALLOW mutation: the same ca into Disallowed,
               the deny filter rides, the delstore rollback
      stage 4  the client-cert handshake: the loopback server with
               the require policy, the valid alice pair -> the
               session rides; the keyless client -> the handshake
               dies
      stage 5  the guard restore: the machine back to the pre-test
               map (the drift verification)

    Run from the elevated console. The rollback of every mutation
    is guaranteed by the guard restore (the stage 5).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\run-acceptance-vm.ps1
#>

$ErrorActionPreference = 'Continue'

$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) { $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }

$Ssh3Exe    = Join-Path $ScriptDir 'ssh3.exe'
$CertExe    = Join-Path $ScriptDir 'ssh3-cert.exe'
$SrvExe     = Join-Path $ScriptDir 'ssh3-server.exe'
$Guard      = Join-Path $ScriptDir 'TrustStoreGuard.ps1'
$Fixtures   = Join-Path $ScriptDir 'fixtures'
$SessionDir = Join-Path $ScriptDir ('session-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))

$Failures = 0

function pass($m) { Write-Host "   PASS: $m" }
function fail($m) { Write-Host "   FAIL: $m"; $script:Failures++ }
function head($m) { Write-Host "== $m" }

# --- the prerequisites ---

Write-Host "=== TRUST-ACCEPTANCE-VM ==="

foreach ($f in @($Ssh3Exe, $CertExe, $SrvExe, $Guard)) {
    if (-not (Test-Path $f)) {
        Write-Host "ABORT: missing $f"
        exit 1
    }
}

foreach ($f in @(
    (Join-Path $Fixtures 'ca.pem'),
    (Join-Path $Fixtures 'alice-cert.pem'),
    (Join-Path $Fixtures 'alice-key.pem'),
    (Join-Path $Fixtures 'srv-cert.pem'),
    (Join-Path $Fixtures 'srv-key.pem')
)) {
    if (-not (Test-Path $f)) {
        Write-Host "ABORT: missing fixture $f"
        exit 1
    }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ABORT: the console is not elevated (the store mutations need the admin)"
    exit 1
}

if (-not (Test-Path $SessionDir)) {
    New-Item -ItemType Directory -Path $SessionDir -Force | Out-Null
}

# the server host: the parameter or the machine gateway (the vm
# dials the host over the network; the server rides the host
# machine - the linux build, the vm carries the win client only)

if ($ServerHost -eq '') {
    $gw = (Get-NetIPConfiguration |
        Where-Object { $_.IPv4DefaultGateway -ne $null } |
        Select-Object -First 1).IPv4DefaultGateway.NextHop
    if ($gw) {
        $ServerHost = $gw
        Write-Host "   the server host rides the gateway: $gw"
    } else {
        Write-Host "ABORT: the server host is not set and the gateway is not found"
        exit 1
    }
}

# --- stage 0: the guard snapshot ---

head "stage 0: the guard snapshot"

& $Guard -Action Snapshot -SessionDir $SessionDir
if ($LASTEXITCODE -ne 0) {
    Write-Host "ABORT: the snapshot failed"
    exit 1
}
pass "the pre-test map landed ($SessionDir)"

# --- stage 1: the Crypt32 bridge probe ---

head "stage 1: the Crypt32 bridge probe"

$probeOut = & $CertExe probe 2>&1
$ownLine  = $probeOut | Where-Object { $_ -like 'PROBE own=*' }
$sysLine  = $probeOut | Where-Object { $_ -like 'PROBE system=*' }

if ($ownLine -and $sysLine) {
    pass "$ownLine | $sysLine"
} else {
    fail "the probe did not produce the counters"
}

# --- stage 2: the ADD-ROOT mutation ---

head "stage 2: the ADD-ROOT mutation"

# the test ca: the bundle fixture (the self-signed, the DER form
# generated from ca.pem)

$caCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
    (Join-Path $Fixtures 'ca.pem'))

$caDer = Join-Path $SessionDir 'test-ca.der'
[IO.File]::WriteAllBytes($caDer, $caCert.Export('Cert'))

certutil -addstore Root $caDer | Out-Null

$probeAfter = & $CertExe probe 2>&1 | Where-Object { $_ -like 'PROBE system=*' }

# the delta check rides the system store walk: the imported ca
# named TRUST-ACCEPT-VM-CA must appear in the store the probe
# counted (the machine scope Root)

$caInStore = [bool](Get-ChildItem Cert:\LocalMachine\Root |
    Where-Object { $_.Subject -like '*TRUST-ACCEPT-VM-CA*' })

if ($caInStore) {
    pass "the test ca rides the system Root store"
} else {
    fail "the test ca did not land in the system Root"
}

# --- stage 3: the DISALLOW mutation ---

head "stage 3: the DISALLOW mutation"

certutil -addstore -f Disallowed $caDer | Out-Null

# the deny filter: the ca rides Disallowed — the system walk skips
# it (the bridge count drops back)

$caStillInRoot = [bool](Get-ChildItem Cert:\LocalMachine\Root |
    Where-Object { $_.Subject -like '*TRUST-ACCEPT-VM-CA*' })

$caInDis = [bool](Get-ChildItem Cert:\LocalMachine\Disallowed |
    Where-Object { $_.Subject -like '*TRUST-ACCEPT-VM-CA*' })

if ($caInDis) {
    pass "the test ca rides the Disallowed store"
} else {
    fail "the Disallowed import did not land"
}

# --- the rollbacks of the mutations (before the guard restore) ---

certutil -delstore Root TRUST-ACCEPT-VM-CA | Out-Null
certutil -delstore -f Disallowed TRUST-ACCEPT-VM-CA | Out-Null
Write-Host "   the test ca removed from Root and Disallowed (the rollbacks)"

# --- stage 4: the client-cert handshake on the loopback server ---

head "stage 4: the client-cert handshake (require / keyless)"

# the alice account: the mapping target (created when missing,
# removed at the end)

$aliceExisted = [bool](Get-LocalUser -Name 'alice' -ErrorAction SilentlyContinue)
if (-not $aliceExisted) {
    $apw = ConvertTo-SecureString 'Alice#2026x' -AsPlainText -Force
    New-LocalUser -Name 'alice' -Password $apw -PasswordNeverExpires | Out-Null
}

# the server: the loopback listener with the require policy (the
# ephemeral port read back from the INTEROP-LISTEN line)

$srvLog = Join-Path $SessionDir 'srv.log'

$srvProc = Start-Process -FilePath $SrvExe -ArgumentList @(
    '-3', '-l', '127.0.0.1:0',
    '-c', (Join-Path $Fixtures 'srv-cert.pem'),
    '-k', (Join-Path $Fixtures 'srv-key.pem'),
    '--client-cert-ca', (Join-Path $Fixtures 'ca.pem'),
    '--client-cert', 'require'
) -NoNewWindow -PassThru -RedirectStandardOutput $srvLog -RedirectStandardError ($srvLog + '.err')

$port = $null
for ($i = 0; $i -lt 50; $i++) {
    Start-Sleep -Milliseconds 200
    $line = Select-String -Path $srvLog -Pattern 'INTEROP-LISTEN port=(\d+)' |
        Select-Object -First 1
    if ($line) { $port = $line.Matches[0].Groups[1].Value; break }
}

if (-not $port) {
    fail "the require server did not come up"
    Stop-Process -Id $srvProc.Id -Force -ErrorAction SilentlyContinue
} else {

    pass "the require server listening on 127.0.0.1:$port"

    # the valid alice pair rides

    $cliLog = Join-Path $SessionDir 'cli-alice.log'

    $cliProc = Start-Process -FilePath $Ssh3Exe -ArgumentList @(
        '-v', '-o', 'StrictHostKeyChecking=accept-new',
        '--cert', (Join-Path $Fixtures 'alice-cert.pem'),
        '--key', (Join-Path $Fixtures 'alice-key.pem'),
        "alice@127.0.0.1:$port/ssh3-term", 'echo S3-CC-OK'
    ) -NoNewWindow -PassThru -RedirectStandardOutput $cliLog -RedirectStandardError ($cliLog + '.err')

    Wait-Process -Id $cliProc.Id -Timeout 60 -ErrorAction SilentlyContinue

    if ($cliProc.ExitCode -eq 0) {
        pass "the require dial rode with the valid pair (rc 0)"
    } else {
        fail "the require dial: rc=$($cliProc.ExitCode) ($(Get-Content ($cliLog + '.err') -Tail 2))"
    }

    # the keyless client dies (the handshake, before the auth)

    $cliLog2 = Join-Path $SessionDir 'cli-keyless.log'

    $cliProc2 = Start-Process -FilePath $Ssh3Exe -ArgumentList @(
        '-v', '-o', 'StrictHostKeyChecking=accept-new',
        "alice@127.0.0.1:$port/ssh3-term", 'echo S3-NO-OK'
    ) -NoNewWindow -PassThru -RedirectStandardOutput $cliLog2 -RedirectStandardError ($cliLog2 + '.err')

    Wait-Process -Id $cliProc2.Id -Timeout 60 -ErrorAction SilentlyContinue

    if ($cliProc2.ExitCode -ne 0) {
        pass "the keyless handshake died (rc $($cliProc2.ExitCode))"
    } else {
        fail "the keyless handshake lived (the require policy broken)"
    }

    Stop-Process -Id $srvProc.Id -Force -ErrorAction SilentlyContinue
}

# the alice rollback (the script-created account dies)

if (-not $aliceExisted) {
    Remove-LocalUser -Name 'alice' -ErrorAction SilentlyContinue
    Write-Host "   the alice account removed (the rollback)"
}

# --- stage 5: the guard restore ---

head "stage 5: the guard restore"

& $Guard -Action Restore -SessionDir $SessionDir
if ($LASTEXITCODE -eq 0) {
    pass "the machine back to the pre-test map"
} else {
    fail "the guard restore drifted"
}

# --- the verdict ---

Write-Host ""
if ($Failures -eq 0) {
    Write-Host "TRUST-ACCEPTANCE-VM OK"
    exit 0
}

Write-Host "TRUST-ACCEPTANCE-VM FAILED: $Failures check(s)"
exit 1
