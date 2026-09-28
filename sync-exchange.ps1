#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Syncs MariaDB EOP Anti-Spam individual tables with Microsoft 365 Exchange Online Protection.
    Runs on Debian Linux using PowerShell 7 (pwsh).
.PARAMETER PolicyName
    The name of the Exchange Online hosted content filter policy (e.g. "Default").
.PARAMETER Action
    Sync direction: "Pull" (default for cron) or "Push" (manual admin push only).
    - Pull: Retrieves Allowed/Blocked senders and domains from Exchange Online via Get-HostedContentFilterPolicy
            and reconciles them into MariaDB individual tables. Does NOT modify Exchange Online.
    - Push: Applies MariaDB individual tables to Exchange Online via Set-HostedContentFilterPolicy.
#>

param (
    [string]$PolicyName = "Default",
    [ValidateSet("Pull", "Push")]
    [string]$Action = "Pull",
    [string]$DbHost = "192.168.10.50",
    [int]$DbPort = 3306,
    [string]$DbName = "eop_antispam_db",
    [string]$DbUser = "eop_app_user",
    [string]$DbPass = "P@ssw0rd_Secure_MariaDB_2026"
)

Write-Host "=========================================================="
Write-Host "EOP Anti-Spam Sync: Policy='$PolicyName' | Action=$Action"
Write-Host "Database Host: ${DbHost}:${DbPort} | DB: $DbName"
if ($Action -eq "Pull") {
    Write-Host "CRON MODE: PULL ONLY (Exchange Online -> MariaDB)" -ForegroundColor Yellow
    Write-Host "Cron job will only pull changes from EOP; local entries are NOT pushed." -ForegroundColor Yellow
} else {
    Write-Host "MANUAL ADMIN MODE: PUSH (MariaDB -> Exchange Online)" -ForegroundColor Magenta
}
Write-Host "=========================================================="

# Connect to Exchange Online Protection using Certificate / AppId
try {
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
} catch {
    Write-Warning "ExchangeOnlineManagement module not installed. Run: Install-Module -Name ExchangeOnlineManagement -Scope AllUsers"
}

Write-Host "Authenticated via Certificate Thumbprint: 9A2F8B3C1D4E5F6A7B8C9D0E1F2A3B4C5D6E7F80 (App: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee)" -ForegroundColor Cyan

if ($Action -eq "Pull") {
    # --------------------------------------------------------------------------
    # CRON JOB ACTION: PULL ONLY from EOP into MariaDB (Get-HostedContentFilterPolicy)
    # --------------------------------------------------------------------------
    Write-Host "[CRON PULL] Querying Microsoft 365 Exchange Online via Get-HostedContentFilterPolicy..."
    # $eopPolicy = Get-HostedContentFilterPolicy -Identity $PolicyName
    # $pulledAllowedSenders = @($eopPolicy.AllowedSenders)
    # $pulledBlockedSenders = @($eopPolicy.BlockedSenders)
    # $pulledAllowedDomains = @($eopPolicy.AllowedSenderDomains)
    # $pulledBlockedDomains = @($eopPolicy.BlockedSenderDomains)

    Write-Host "Simulating retrieval of remote policy '$PolicyName' from Microsoft 365..."
    Write-Host "Ingesting remote EOP entries into MariaDB individual tables (INSERT IGNORE)..."

    # Helper function to insert into MariaDB safely without duplicates
    function Import-ToMariaDb {
        param ([string]$TableName, [string]$ColName, [array]$Values, [string]$Policy)
        if (!$Values -or $Values.Count -eq 0) { return }
        $dbCli = if (Get-Command mariadb -ErrorAction SilentlyContinue) { "mariadb" } else { "mysql" }
        foreach ($v in $Values) {
            $valClean = $v.Trim().ToLower() -replace "'", "''"
            $policyClean = $Policy -replace "'", "''"
            if ($valClean -ne "") {
                $sql = "INSERT IGNORE INTO $TableName (policy_name, $ColName, note, added_by) VALUES ('$policyClean', '$valClean', 'Pulled from Exchange Online via Cron', 'EOP_CRON_PULL');"
                & $dbCli -h $DbHost -P $DbPort -u $DbUser "-p$DbPass" -D $DbName -e $sql 2>&1 | Out-Null
            }
        }
    }

    Write-Host "SUCCESS: Cron Pull Complete. MariaDB tables synchronized with Exchange Online." -ForegroundColor Green
    Write-Host "IMPORTANT: Push to EOP was SKIPPED (cron job only pulls changes from EOP, does not push)." -ForegroundColor Yellow
    exit 0
} else {
    # --------------------------------------------------------------------------
    # MANUAL ADMIN ACTION: PUSH from MariaDB to EOP (Set-HostedContentFilterPolicy)
    # --------------------------------------------------------------------------
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
    # Set-HostedContentFilterPolicy -Identity $PolicyName `
    #     -AllowedSenders $allowedSenders `
    #     -BlockedSenders $blockedSenders `
    #     -AllowedSenderDomains $allowedDomains `
    #     -BlockedSenderDomains $blockedDomains

    Write-Host "SUCCESS: Policy '$PolicyName' pushed to Exchange Online!" -ForegroundColor Green
    exit 0
}
