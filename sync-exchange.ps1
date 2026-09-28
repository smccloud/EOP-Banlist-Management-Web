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
    [string]$DbHost = "",
    [int]$DbPort = 3306,
    [string]$DbName = "",
    [string]$DbUser = "",
    [string]$DbPass = ""
)

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

function Get-NonEmptyArray {
    param($Values)
    if ($null -eq $Values) { return @() }
    return @($Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
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

    Write-Host "[CRON PULL] Importing certificate into the current user store..."
    $securePassword = ConvertTo-SecureString -String $pfxPassword -AsPlainText -Force
    $keyFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistLocalMachine `
              -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
    try {
        Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation Cert:\CurrentUser\My -Password $securePassword -KeyStorageFlags $keyFlags | Out-Null
    } catch {
        Write-Error "Import-PfxCertificate failed: $($_.Exception.Message)"
        exit 1
    }

    Write-Host "[CRON PULL] Connecting to Exchange Online via Connect-ExchangeOnline..."
    try {
        Connect-ExchangeOnline -AppId $clientId -CertificateThumbprint $certThumbprint -Organization $organization -ErrorAction Stop
    } catch {
        Write-Error "Connect-ExchangeOnline failed: $($_.Exception.Message)"
        exit 1
    }

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
        allowed_senders = Get-NonEmptyArray $eopPolicy.AllowedSenders
        blocked_senders = Get-NonEmptyArray $eopPolicy.BlockedSenders
        allowed_domains = Get-NonEmptyArray $eopPolicy.AllowedSenderDomains
        blocked_domains = Get-NonEmptyArray $eopPolicy.BlockedSenderDomains
    }

    $payload | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $pullOutput -Encoding UTF8

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

    $allowedSenders = Query-MariaDbList -TableName "eop_allowed_senders" -ColumnName "sender_email" -Policy $PolicyName
    $blockedSenders = Query-MariaDbList -TableName "eop_blocked_senders" -ColumnName "sender_email" -Policy $PolicyName
    $allowedDomains = Query-MariaDbList -TableName "eop_allowed_domains" -ColumnName "domain_name" -Policy $PolicyName
    $blockedDomains = Query-MariaDbList -TableName "eop_blocked_domains" -ColumnName "domain_name" -Policy $PolicyName

    Write-Host "Found in MariaDB for Policy '$PolicyName':"
    Write-Host " - Allowed Senders: $($allowedSenders.Count)"
    Write-Host " - Blocked Senders: $($blockedSenders.Count)"
    Write-Host " - Allowed Domains: $($allowedDomains.Count)"
    Write-Host " - Blocked Domains: $($blockedDomains.Count)"

    Write-Host "Executing Manual Admin Push to EOP via Set-HostedContentFilterPolicy..."
    try {
        Connect-ExchangeOnline -AppId $clientId -CertificateThumbprint $certThumbprint -Organization $organization -ErrorAction Stop
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
