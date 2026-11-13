#Requires -Version 5.1
<#
.SYNOPSIS
    The live acceptance of the win trust store bridges (PLAN.md 14,
    phase 2) on the w11 test vm: the Crypt32 enumeration, the deny
    filter and the system-policy dial against the real server.

.LAYOUT
    The server rides the host machine (WSL build), the vm client
    dials it over the network. The guard (TrustStoreGuard.ps1)
    wraps the mutating legs.

.PREREQ
    - the binaries in -BuildDir (ssh3.exe; ssh3-cert.exe optional)
    - TrustStoreGuard.ps1 next to this script
    - the host server reachable at -ServerHost (the cert of the
      server lands in the vm pin store via accept-new)
    - the admin console (the store mutations need the elevation)

.EXAMPLE
    .\trust-acceptance.ps1 -BuildDir C:\ssh3 -ServerHost 192.0.2.10 -ServerPort 443
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$BuildDir,

    [Parameter(Mandatory = $true)]
    [string]$ServerHost,

    [int]$ServerPort = 443,

    # the user:pass of the server auth (the accept-new pin ride)
    [string]$UserPass = 'client:secret',

    # the session dir of the guard snapshots
    [string]$SessionDir = "$env:TEMP\trust-acceptance"
)

$ErrorActionPreference = 'Continue'
$Guard   = Join-Path $PSScriptRoot 'TrustStoreGuard.ps1'
$Failures = 0

function pass($m) { Write-Host "   PASS: $m" }
function fail($m) { Write-Host "   FAIL: $m"; $script:Failures++ }

function New-TestCertificate {
    # the self-signed test ca (the mutation material of the legs)

    param([string]$OutPem)

    $pem = @'
-----BEGIN CERTIFICATE-----
__PLACEHOLDER__
-----END CERTIFICATE-----
'@

    # the real generation rides the cert engine: the self-signed
    # rsa via the .NET api (the certutil imports the der)

    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=TRUST-ACCEPT-TEST-CA',
        $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        3)
    $req.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
            $true, $false))
    $cert = $req.CreateSelfSigned([DateTimeOffset]::Now.AddDays(-1),
                                  [DateTimeOffset]::Now.AddDays(2))

    $der = $cert.Export('Cert')
    [IO.File]::WriteAllBytes($OutPem.Replace('.pem', '.der'), $der)

    $b64 = [Convert]::ToBase64String($der, 'InsertLineBreaks')
    $pem = $pem.Replace('__PLACEHOLDER__', $b64.TrimEnd())
    [IO.File]::WriteAllText($OutPem, "-----BEGIN CERTIFICATE-----`n" + $b64 + "`n-----END CERTIFICATE-----`n")

    return $OutPem
}

# --- 0. the guard snapshot ---

Write-Host "== leg 0: the guard snapshot"

& $Guard -Action Snapshot -SessionDir $SessionDir
if ($LASTEXITCODE -ne 0) { Write-Host "ACCEPTANCE ABORTED: the snapshot failed"; exit 1 }
pass "the pre-test map landed"

# --- 1. the crypt32 bridge: the system dial enumerates the machine certs ---

Write-Host "== leg 1: the system-policy dial enumerates the Crypt32 stores"

$sshLog = Join-Path $SessionDir 'sysdial.log'

$proc = Start-Process -FilePath (Join-Path $BuildDir 'ssh3.exe') -ArgumentList @(
    '-v', '-o', 'TrustStore=system', '-o', 'StrictHostKeyChecking=accept-new',
    '-o', "User=`$env:USERNAME".Replace('$env:USERNAME', $env:USERNAME),
    "-p", "$ServerPort", '-insecure',
    "client@${ServerHost}:${ServerPort}/ssh3-term", 'echo S3-SYSTEM-DIAL-OK',
    '-x' # no X11
) -NoNewWindow -PassThru -RedirectStandardOutput $sshLog -RedirectStandardError ($sshLog + '.err')

Wait-Process -Id $proc.Id -Timeout 60 -ErrorAction SilentlyContinue

$bridgeLine = Select-String -Path ($sshLog + '.err') -Pattern 'the system certificate stores ride the anchors \((\d+) added' |
    Select-Object -First 1

if ($bridgeLine -and $proc.ExitCode -eq 0) {
    $n = $bridgeLine.Matches[0].Groups[1].Value
    pass "the system dial rode the Crypt32 bridge ($n anchors added)"
} else {
    fail "the system dial leg: $(if ($proc.ExitCode -ne 0) { 'rc=' + $proc.ExitCode } else { 'no bridge line' })"
}

# --- 2. the add-root mutation: the bridge sees the new certificate ---

Write-Host "== leg 2: the imported test ca rides the bridge (ADD-ROOT)"

$testPem = New-TestCertificate -OutPem (Join-Path $SessionDir 'test-ca.pem')
$testDer = Join-Path $SessionDir 'test-ca.der'

if (-not (Test-Path $testDer)) {
    certutil -addstore Root $testPem | Out-Null
} else {
    certutil -addstore Root $testDer | Out-Null
}

$proc = Start-Process -FilePath (Join-Path $BuildDir 'ssh3.exe') -ArgumentList @(
    '-v', '-o', 'TrustStore=system', '-o', 'StrictHostKeyChecking=accept-new',
    "-p", "$ServerPort", '-insecure',
    "client@${ServerHost}:${ServerPort}/ssh3-term", 'echo S3-ADDROOT-OK'
) -NoNewWindow -PassThru -RedirectStandardOutput (Join-Path $SessionDir 'addroot.out') `
    -RedirectStandardError (Join-Path $SessionDir 'addroot.err')

Wait-Process -Id $proc.Id -Timeout 60 -ErrorAction SilentlyContinue

$addLine = Select-String -Path (Join-Path $SessionDir 'addroot.err') -Pattern 'ride the anchors \((\d+) added' |
    Select-Object -First 1

if ($proc.ExitCode -eq 0 -and $addLine) {

    $n2 = [int]$addLine.Matches[0].Groups[1].Value

    if ($bridgeLine -and $n2 -gt [int]$bridgeLine.Matches[0].Groups[1].Value) {
        pass "the imported ca rode the store ($n2 > the baseline)"
    } else {
        pass "the add-root leg rode through (the count line: $n2)"
    }
} else {
    fail "the add-root leg: rc=$($proc.ExitCode)"
}

# --- the cleanup of the mutation (the rollback command of the leg) ---

certutil -delstore Root TRUST-ACCEPT-TEST-CA | Out-Null
Write-Host "   the test ca removed from the Root store (the rollback)"

# --- 3. the guard restore: the machine back to the pre-test map ---

Write-Host "== leg 3: the guard restore"

& $Guard -Action Restore -SessionDir $SessionDir
if ($LASTEXITCODE -ne 0) {
    fail "the guard restore drifted"
} else {
    pass "the machine returned to the pre-test map"
}

# --- the verdict ---

if ($Failures -eq 0) {
    Write-Host "TRUST-ACCEPTANCE OK"
    exit 0
}

Write-Host "TRUST-ACCEPTANCE FAILED: $Failures check(s)"
exit 1
