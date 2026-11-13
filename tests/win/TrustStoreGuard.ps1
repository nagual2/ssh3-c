#Requires -Version 5.1
<#
.SYNOPSIS
    The certificate store guard of the wave-14 acceptance (PLAN.md 14,
    phase 2): the snapshot of the ROOT/CA/Disallowed stores before the
    test and the full restore after it - the machine state returns to
    the pre-test map whatever the functional legs did.

.DESCRIPTION
    The map carries every certificate of the three stores as the
    base64 of its DER (the byte-exact identity, the duplicates of the
    same DER inside one store ride once). The restore:

      - removes the certificates that appeared after the snapshot
        (the functional legs added them),
      - re-imports the certificates that disappeared (a leg deleted
        or a system update moved them mid-test),
      - leaves the untouched certificates alone (no re-import churn).

    The snapshots land in a timestamped session directory; the
    restore verifies the post-state against the map and reports the
    drift.

.CONFIRM
    The restore touches the system certificate stores (the machine
    scope). Run on the test VM only.

.EXAMPLE
    .\TrustStoreGuard.ps1 -Action Snapshot -SessionDir D:\ts\session1
    .\TrustStoreGuard.ps1 -Action Restore  -SessionDir D:\ts\session1
    .\TrustStoreGuard.ps1 -Action Verify   -SessionDir D:\ts\session1
#>
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Snapshot', 'Restore', 'Verify', 'Report')]
    [string]$Action,

    [Parameter(Mandatory = $true)]
    [string]$SessionDir,

    # the stores the guard covers (the wave-14 acceptance set)
    [string[]]$Stores = @('Root', 'CA', 'Disallowed')
)

$ErrorActionPreference = 'Stop'

$MapFile     = Join-Path $SessionDir 'store-map.json'
$AddedDir    = Join-Path $SessionDir 'added'
$RemovedDir  = Join-Path $SessionDir 'removed'

# --- the store read/write primitives (the DER identity) ---

function Get-StoreMap {
    # every certificate of every store as the der-base64 -> the
    # subject line (the human-readable map for the diff reports)

    $map = @{}

    foreach ($store in $Stores) {
        $list = @()

        $certs = Get-ChildItem "Cert:\LocalMachine\$store" -ErrorAction SilentlyContinue
        foreach ($c in $certs) {
            $der64 = [Convert]::ToBase64String($c.RawData)
            $list += [pscustomobject]@{
                Thumbprint = $c.Thumbprint
                Der64      = $der64
                Subject    = $c.Subject
                NotAfter   = $c.NotAfter.ToString('yyyy-MM-dd')
            }
            $map[$store + '::' + $der64] = $c.Subject
        }

        # the per-store list file (the restore re-imports from it)
        $list | ConvertTo-Json -Depth 3 |
            Set-Content (Join-Path $SessionDir ("map-{0}.json" -f $store)) -Encoding UTF8
    }

    $map | ConvertTo-Json -Depth 3 |
        Set-Content $MapFile -Encoding UTF8

    return $map
}

function Get-CurrentMap {
    $map = @{}
    foreach ($store in $Stores) {
        $certs = Get-ChildItem "Cert:\LocalMachine\$store" -ErrorAction SilentlyContinue
        foreach ($c in $certs) {
            $map[$store + '::' + [Convert]::ToBase64String($c.RawData)] = $c.Subject
        }
    }
    return $map
}

function Import-StoreCertificate {
    # the DER re-import into the named store (the restore of a
    # removed certificate)

    param([string]$Store, [string]$Der64)

    $der = [Convert]::FromBase64String($Der64)
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $cert.Import($der)

    $x509Store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        $Store, 'LocalMachine')
    $x509Store.Open('ReadWrite')
    $x509Store.Add($cert)
    $x509Store.Close()
}

function Remove-StoreCertificate {
    param([string]$Store, [string]$Der64)

    $der = [Convert]::FromBase64String($Der64)
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $cert.Import($der)

    $x509Store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        $Store, 'LocalMachine')
    $x509Store.Open('ReadWrite')

    foreach ($c in $x509Store.Certificates) {
        if ([Convert]::ToBase64String($c.RawData) -eq $Der64) {
            $x509Store.Remove($c)
        }
    }

    $x509Store.Close()
}

# --- the actions ---

switch ($Action) {

    'Snapshot' {

        if (-not (Test-Path $SessionDir)) {
            New-Item -ItemType Directory -Path $SessionDir -Force | Out-Null
        }
        foreach ($d in @($AddedDir, $RemovedDir)) {
            if (-not (Test-Path $d)) {
                New-Item -ItemType Directory -Path $d -Force | Out-Null
            }
        }

        $map = Get-StoreMap

        Write-Host ("SNAPSHOT OK: {0} certificates mapped ({1})" -f
            $map.Count, ($Stores -join '/'))

        # the machine baseline: the serialised store of the probe
        # (the functional legs diff against it)
        $map.Keys.Count | Set-Content (Join-Path $SessionDir 'baseline-count.txt')
    }

    'Restore' {

        if (-not (Test-Path $MapFile)) {
            throw "the map file is missing: $MapFile (run -Action Snapshot first)"
        }

        $before = Get-Content $MapFile -Raw | ConvertFrom-Json
        $now    = Get-CurrentMap

        $added = @()
        $removed = @()

        # the appeared: in the machine now, absent from the map

        foreach ($k in $now.Keys) {
            if (-not $before.PSObject.Properties[$k]) {
                $added += $k
            }
        }

        # the disappeared: in the map, absent from the machine now

        foreach ($prop in $before.PSObject.Properties) {
            if (-not $now.ContainsKey($prop.Name)) {
                $removed += $prop.Name
            }
        }

        # the restore: the appeared removed, the disappeared
        # re-imported from the per-store lists

        foreach ($k in $added) {
            $parts = $k -split "::", 2
            $store = $parts[0]
            $der64 = $parts[1]
            Remove-StoreCertificate -Store $store -Der64 $der64
            Write-Host ("RESTORE removed: {0} :: {1}" -f $store, $before[$k])
        }

        foreach ($k in $removed) {
            $parts = $k -split '::', 2
            $store = $parts[0]
            $der64 = $parts[1]
            $listFile = Join-Path $SessionDir ("map-{0}.json" -f $store)
            $list = Get-Content $listFile -Raw | ConvertFrom-Json
            $entry = $list | Where-Object {
                ($store + '::' + $_.Der64) -eq $k
            }
            if ($entry) {
                Import-StoreCertificate -Store $store -Der64 $entry.Der64
                Write-Host ("RESTORE re-imported: {0} :: {1}" -f $store, $entry.Subject)
            }
        }

        # the post-verify: the drift count after the restore

        $now2 = Get-CurrentMap
        $drift = 0
        foreach ($prop in $before.PSObject.Properties) {
            if (-not $now2.ContainsKey($prop.Name)) { $drift++ }
        }
        foreach ($k in $now2.Keys) {
            if (-not $before.PSObject.Properties[$k]) { $drift++ }
        }

        if ($drift -eq 0) {
            Write-Host "RESTORE OK: the machine state matches the pre-test map"
            exit 0
        }

        Write-Host "RESTORE DRIFT: $drift certificate(s) differ from the pre-test map"
        exit 1
    }

    'Verify' {

        # the read-only drift check without any mutation (the test
        # harness calls it between the legs)

        if (-not (Test-Path $MapFile)) {
            throw "the map file is missing: $MapFile"
        }

        $before = Get-Content $MapFile -Raw | ConvertFrom-Json
        $now    = Get-CurrentMap
        $drift  = 0

        foreach ($prop in $before.PSObject.Properties) {
            if (-not $now.ContainsKey($prop.Name)) {
                Write-Host ("MISSING: {0} :: {1}" -f $prop.Name, $prop.Value)
                $drift++
            }
        }
        foreach ($k in $now.Keys) {
            if (-not $before.PSObject.Properties[$k]) {
                Write-Host ("EXTRA:   {0} :: {1}" -f $k, $now[$k])
                $drift++
            }
        }

        Write-Host ("VERIFY: {0} drift certificate(s)" -f $drift)

        if ($drift -eq 0) {
            exit 0
        }
        exit 1
    }

    'Report' {

        # the human-readable map dump (the pre-test inventory)

        $before = Get-Content $MapFile -Raw | ConvertFrom-Json

        foreach ($store in $Stores) {
            Write-Host "== $store =="
            foreach ($prop in $before.PSObject.Properties) {
                if ($prop.Name.StartsWith($store + '::')) {
                    Write-Host ("  {0}" -f $prop.Value)
                }
            }
        }
    }
}
