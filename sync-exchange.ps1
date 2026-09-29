#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Syncs MariaDB EOP Anti-Spam individual tables with Microsoft 365 Exchange Online Protection.
    Runs on Debian Linux using PowerShell 7 (pwsh).
.PARAMETER PolicyName
    The name of the Exchange Online hosted content filter policy (e.g. "Default").
.PARAMETER Action
    Sync direction: "Pull" (default for cron) or "Push" (manual admin push only).
    - Pull: Authenticates with certificate auth, retrieves Allowed/Blocked senders and
            domains via Get-HostedContentFilterPolicy and writes them to the JSON file
            named by $env:EOP_PULL_OUTPUT. Does NOT modify Exchange Online and does NOT
            touch the database directly; cron-sync.php performs the MariaDB writes.
    - Push: Applies MariaDB individual tables to Exchange Online via Set-HostedContentFilterPolicy.
.NOTES
    Authentication values (tenant, client id, thumbprint, organization) arrive through
    the environment from cron-sync.php, which reads them from the active eop_auth_config
    record. Certificate material arrives as a PKCS#12 bundle path in
    $env:EOP_CERT_PFX_PATH, because eop_auth_config stores the private key only.
#>

param (
    [string]$PolicyName = "Default",
    [ValidateSet("Pull", "Push")]
    [string]$Action = "Pull",
    # Only required for the manual Push path. The Pull path never connects to MariaDB.
    # Each falls back to the environment so the database password never has to
    # appear in the process table; cron-sync.php and the web UI both export these.
    # DbPort defaults to 0 rather than 3306 so that "unset" is distinguishable from
    # "explicitly 3306" and the environment can still supply it.
    [string]$DbHost = "",
    [int]$DbPort = 0,
    [string]$DbName = "",
    [string]$DbUser = "",
    [string]$DbPass = ""
)

if ([string]::IsNullOrWhiteSpace($DbHost)) { $DbHost = [string]$env:EOP_DB_HOST }
if ($DbPort -le 0) {
    $envPort = [int]$env:EOP_DB_PORT
    $DbPort = if ($envPort -gt 0) { $envPort } else { 3306 }
}
if ([string]::IsNullOrWhiteSpace($DbName))  { $DbName = [string]$env:EOP_DB_NAME }
if ([string]::IsNullOrWhiteSpace($DbUser))  { $DbUser = [string]$env:EOP_DB_USER }
if ([string]::IsNullOrWhiteSpace($DbPass))  { $DbPass = [string]$env:EOP_DB_PASS }

Write-Host "=========================================================="
Write-Host "EOP Anti-Spam Sync: Policy='$PolicyName' | Action=$Action"
if ($Action -eq "Pull") {
    Write-Host "CRON MODE: PULL ONLY (Exchange Online -> MariaDB)" -ForegroundColor Yellow
    Write-Host "Cron job will only pull changes from EOP; local entries are NOT pushed." -ForegroundColor Yellow
} else {
    Write-Host "MANUAL ADMIN MODE: PUSH (MariaDB -> Exchange Online)" -ForegroundColor Magenta
}
Write-Host "=========================================================="

# Authentication values are supplied by cron-sync.php from the active
# eop_auth_config record so that certificate and App Registration changes take
# effect without editing this script.
$tenantId       = $env:EOP_TENANT_ID
$clientId       = $env:EOP_CLIENT_ID
$certThumbprint = $env:EOP_CERT_THUMBPRINT
$organization   = $env:EOP_ORGANIZATION

$missing = @()
if ([string]::IsNullOrWhiteSpace($tenantId))       { $missing += 'EOP_TENANT_ID' }
if ([string]::IsNullOrWhiteSpace($clientId))       { $missing += 'EOP_CLIENT_ID' }
if ([string]::IsNullOrWhiteSpace($certThumbprint)) { $missing += 'EOP_CERT_THUMBPRINT' }
if ($missing.Count -gt 0) {
    Write-Error "Missing authentication values: $($missing -join ', '). cron-sync.php populates these from the active eop_auth_config record."
    exit 1
}

try {
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
} catch {
    Write-Error "ExchangeOnlineManagement module could not be loaded: $($_.Exception.Message)"
    exit 1
}

Write-Host "Certificate Thumbprint: $certThumbprint (App: $clientId, Tenant: $tenantId, Org: $organization)" -ForegroundColor Cyan

# Returns a flat, all-string array regardless of the shape handed back.
#
# Exchange Online returns these policy properties as single-level string lists,
# but the exact shape is not guaranteed across ExchangeOnlineManagement module
# versions, and both failure modes are destructive downstream:
#   * A one-element array unrolls on return and serialises as a bare JSON string
#     instead of a one-element array, so the leading comma below is required.
#   * A nested collection serialises as an array-of-arrays. The PHP reconciler
#     casts each element to string, which yields the literal "Array" for every
#     entry, collapsing the whole list to one key and making every local row look
#     absent from Exchange Online.
#
# A queue is used rather than recursion, and the accumulator is a local variable
# rather than a typed parameter: PowerShell can bind a strongly-typed
# parameterised argument as a copy, which would discard every Add() call.
function Get-FlatStringArray {
    param($Values)

    $flat = [System.Collections.Generic.List[string]]::new()
    $queue = [System.Collections.Generic.Queue[object]]::new()
    if ($null -ne $Values) {
        $queue.Enqueue($Values)
    }

    while ($queue.Count -gt 0) {
        $item = $queue.Dequeue()

        if ($null -eq $item) { continue }

        if ($item -is [string]) {
            $text = ([string]$item).Trim()
            if ($text -ne '') { $flat.Add($text) }
            continue
        }

        if ($item -is [System.Collections.IDictionary]) {
            foreach ($key in $item.Keys) { $queue.Enqueue($item[$key]) }
            continue
        }

        if ($item -is [System.Collections.IEnumerable]) {
            foreach ($child in $item) { $queue.Enqueue($child) }
            continue
        }

        # Any other leaf is coerced rather than discarded, so an unexpected
        # return type degrades to a string instead of emptying the list.
        $text = ([string]$item).Trim()
        if ($text -ne '') { $flat.Add($text) }
    }

    return , $flat.ToArray()
}

function Connect-EopExchangeOnline {
    param (
        [string]$AppId,
        [string]$Thumbprint,
        [string]$Organization,
        [string]$PfxFile,
        [string]$PfxSecret
    )

    $cert = $null

    # 1. Cross-platform .NET loading of PKCS#12 certificate (Debian Linux & Windows compatible)
    # Does not rely on Windows-only Import-PfxCertificate cmdlet or Windows-specific Cert:\ drive
    if (-not [string]::IsNullOrWhiteSpace($PfxFile) -and (Test-Path -LiteralPath $PfxFile)) {
        Write-Host "Loading PKCS#12 certificate from '$PfxFile'..."
        try {
            $keyFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
            if ([string]::IsNullOrEmpty($PfxSecret)) {
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxFile, "", $keyFlags)
            } else {
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxFile, $PfxSecret, $keyFlags)
            }
            Write-Host "Certificate loaded successfully: Subject='$($cert.Subject)', Thumbprint='$($cert.Thumbprint)'" -ForegroundColor Cyan
        } catch {
            Write-Warning "Could not instantiate X509Certificate2 from '${PfxFile}': $($_.Exception.Message)"
        }

        # 2. Register in CurrentUser X509 store via cross-platform .NET API
        if ($null -ne $cert) {
            try {
                $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
                    [System.Security.Cryptography.X509Certificates.StoreName]::My,
                    [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
                )
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $store.Add($cert)
                $store.Close()
                Write-Host "Certificate registered in CurrentUser X509 store."
            } catch {
                # Store registration is optional when passing -Certificate object directly
            }
        }
    }

    Write-Host "Connecting to Exchange Online (AppId: $AppId, Organization: $Organization)..."
    $connected = $false
    $connectErrors = @()

    # Method 1: Pass [X509Certificate2] object directly (-Certificate parameter)
    if ($null -ne $cert) {
        try {
            Write-Host "Attempting Connect-ExchangeOnline with -Certificate object..."
            Connect-ExchangeOnline -Certificate $cert -AppId $AppId -Organization $Organization -ErrorAction Stop
            $connected = $true
        } catch {
            $connectErrors += "Method 1 (-Certificate): $($_.Exception.Message)"
        }
    }

    # Method 2: Pass certificate file path + SecureString password
    if (-not $connected -and -not [string]::IsNullOrWhiteSpace($PfxFile) -and (Test-Path -LiteralPath $PfxFile)) {
        try {
            Write-Host "Attempting Connect-ExchangeOnline with -CertificateFilePath..."
            $secPwd = ConvertTo-SecureString -String ($PfxSecret ?? "") -AsPlainText -Force
            Connect-ExchangeOnline -CertificateFilePath $PfxFile -CertificatePassword $secPwd -AppId $AppId -Organization $Organization -ErrorAction Stop
            $connected = $true
        } catch {
            $connectErrors += "Method 2 (-CertificateFilePath): $($_.Exception.Message)"
        }
    }

    # Method 3: Connect with -CertificateThumbprint (requires cert in store)
    if (-not $connected -and -not [string]::IsNullOrWhiteSpace($Thumbprint)) {
        try {
            Write-Host "Attempting Connect-ExchangeOnline with -CertificateThumbprint ($Thumbprint)..."
            Connect-ExchangeOnline -AppId $AppId -CertificateThumbprint $Thumbprint -Organization $Organization -ErrorAction Stop
            $connected = $true
        } catch {
            $connectErrors += "Method 3 (-CertificateThumbprint): $($_.Exception.Message)"
        }
    }

    if (-not $connected) {
        Write-Error "Connect-ExchangeOnline failed on all authentication methods: $($connectErrors -join ' | ')"
        exit 1
    }

    Write-Host "Successfully connected to Exchange Online." -ForegroundColor Green
}

if ($Action -eq "Pull") {
    # --------------------------------------------------------------------------
    # CRON JOB ACTION: PULL ONLY from EOP (Get-HostedContentFilterPolicy)
    # --------------------------------------------------------------------------
    $pfxPath     = $env:EOP_CERT_PFX_PATH
    $pfxPassword = $env:EOP_CERT_PFX_PASSWORD
    $pullOutput  = $env:EOP_PULL_OUTPUT

    if ([string]::IsNullOrWhiteSpace($pullOutput)) {
        Write-Error "EOP_PULL_OUTPUT is not set. cron-sync.php must supply the JSON output path."
        exit 1
    }

    if ([string]::IsNullOrWhiteSpace($pfxPath) -or -not (Test-Path -LiteralPath $pfxPath)) {
        Write-Error "No PKCS#12 certificate found at '$pfxPath'. Certificate authentication needs a .pfx containing the certificate and its private key; eop_auth_config only stores the private key."
        exit 1
    }

    # Connect to Exchange Online using cross-platform .NET certificate authentication
    Connect-EopExchangeOnline -AppId $clientId -Thumbprint $certThumbprint -Organization $organization -PfxFile $pfxPath -PfxSecret $pfxPassword

    Write-Host "[CRON PULL] Querying policy '$PolicyName' via Get-HostedContentFilterPolicy..."
    try {
        $eopPolicy = Get-HostedContentFilterPolicy -Identity $PolicyName -ErrorAction Stop
    } catch {
        Write-Error "Get-HostedContentFilterPolicy failed for '$PolicyName': $($_.Exception.Message)"
        Disconnect-ExchangeOnline -ErrorAction SilentlyContinue | Out-Null
        exit 1
    }

    $payload = [ordered]@{
        policy_name     = $PolicyName
        allowed_senders = Get-FlatStringArray $eopPolicy.AllowedSenders
        blocked_senders = Get-FlatStringArray $eopPolicy.BlockedSenders
        allowed_domains = Get-FlatStringArray $eopPolicy.AllowedSenderDomains
        blocked_domains = Get-FlatStringArray $eopPolicy.BlockedSenderDomains
    }

    # Depth 4 with the payload as the pipeline input serialises each list as a
    # real JSON array. Set-Content must not be in the same pipeline as
    # ConvertTo-Json, or the JSON is stringified before it is written.
    $json = $payload | ConvertTo-Json -Depth 4 -Compress
    Set-Content -LiteralPath $pullOutput -Value $json -Encoding UTF8

    Write-Host ("Retrieved remote entries: allowed_senders={0} blocked_senders={1} allowed_domains={2} blocked_domains={3}" -f `
        $payload.allowed_senders.Count, $payload.blocked_senders.Count, `
        $payload.allowed_domains.Count, $payload.blocked_domains.Count) -ForegroundColor Green
    Write-Host "Remote policy written to $pullOutput. MariaDB writes are performed by cron-sync.php." -ForegroundColor Green

    Disconnect-ExchangeOnline -ErrorAction SilentlyContinue | Out-Null
    Write-Host "SUCCESS: Remote policy retrieved. No changes were pushed to Exchange Online." -ForegroundColor Green
    exit 0
} else {
    # --------------------------------------------------------------------------
    # MANUAL ADMIN ACTION: PUSH from MariaDB to EOP (Set-HostedContentFilterPolicy)
    # --------------------------------------------------------------------------
    if ([string]::IsNullOrWhiteSpace($DbPass) -or [string]::IsNullOrWhiteSpace($DbUser)) {
        Write-Error "The Push action requires -DbHost, -DbName, -DbUser and -DbPass. Credentials are no longer hardcoded in this script."
        exit 1
    }

    function Query-MariaDbList {
        param ([string]$TableName, [string]$ColumnName, [string]$Policy)
        $policyClean = $Policy -replace "'", "''"
        $query = "SELECT $ColumnName FROM $TableName WHERE policy_name = '$policyClean';"
        $dbCli = if (Get-Command mariadb -ErrorAction SilentlyContinue) { "mariadb" } else { "mysql" }
        $result = & $dbCli -h $DbHost -P $DbPort -u $DbUser "-p$DbPass" -D $DbName -s -N -e $query 2>&1
        if ($result) {
            return @($result -split "\r?\n" | Where-Object { $_ -ne "" })
        }
        return @()
    }

    $allowedSenders = @(Get-FlatStringArray (Query-MariaDbList -TableName "eop_allowed_senders" -ColumnName "sender_email" -Policy $PolicyName))
    $blockedSenders = @(Get-FlatStringArray (Query-MariaDbList -TableName "eop_blocked_senders" -ColumnName "sender_email" -Policy $PolicyName))
    $allowedDomains = @(Get-FlatStringArray (Query-MariaDbList -TableName "eop_allowed_domains" -ColumnName "domain_name" -Policy $PolicyName))
    $blockedDomains = @(Get-FlatStringArray (Query-MariaDbList -TableName "eop_blocked_domains" -ColumnName "domain_name" -Policy $PolicyName))

    Write-Host "Found in MariaDB for Policy '$PolicyName':"
    Write-Host " - Allowed Senders: $($allowedSenders.Count)"
    Write-Host " - Blocked Senders: $($blockedSenders.Count)"
    Write-Host " - Allowed Domains: $($allowedDomains.Count)"
    Write-Host " - Blocked Domains: $($blockedDomains.Count)"

    Write-Host "Executing Manual Admin Push to EOP via Set-HostedContentFilterPolicy..."
    try {
        Connect-EopExchangeOnline -AppId $clientId -Thumbprint $certThumbprint -Organization $organization -PfxFile $env:EOP_CERT_PFX_PATH -PfxSecret $env:EOP_CERT_PFX_PASSWORD
        Set-HostedContentFilterPolicy -Identity $PolicyName `
            -AllowedSenders $allowedSenders `
            -BlockedSenders $blockedSenders `
            -AllowedSenderDomains $allowedDomains `
            -BlockedSenderDomains $blockedDomains `
            -ErrorAction Stop
    } catch {
        Write-Error "Push to Exchange Online failed: $($_.Exception.Message)"
        exit 1
    }

    Disconnect-ExchangeOnline -ErrorAction SilentlyContinue | Out-Null
    Write-Host "SUCCESS: Policy '$PolicyName' pushed to Exchange Online!" -ForegroundColor Green
    exit 0
}
