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

# Build marker. Bump this whenever the behaviour of this script changes, and check
# it against the repository when diagnosing a failure. A stale copy on the server
# has silently disabled the fail-closed push guards before, and the symptom looked
# like a data problem rather than a deployment problem.
$ScriptBuild = '2026-09-29-dbclientpath-1'

Write-Host "=========================================================="
Write-Host "EOP Anti-Spam Sync: Policy='$PolicyName' | Action=$Action"
Write-Host "Script build: $ScriptBuild"
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
#   * A nested collection serialises as an array-of-arrays. The PHP reconciler
#     casts each element to string, which yields the literal "Array" for every
#     entry, collapsing the whole list to one key and making every local row look
#     absent from Exchange Online.
#   * A one-element list silently becomes a scalar, so a JSON payload would carry
#     a bare string where the PHP side expects a list.
#
# So this emits the elements as ordinary pipeline output - one item per value -
# and callers that need a guaranteed array (the JSON payload below) wrap the call
# in an explicit [string[]] cast. Do NOT re-add a leading comma to the return:
# `return , $arr` survives a hashtable assignment but makes `@(Get-FlatStringArray ...)`
# yield a single element that is the array, which is what silently broke the push.
#
# A queue is used rather than recursion, and the accumulator is a local variable
# rather than a typed parameter: PowerShell can bind a parameterised argument as a
# copy, which would discard every Add() call.
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

    return $flat.ToArray()
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

    # [string[]] keeps a single-entry list a JSON array and an empty list `[]`.
    # Without the cast, a one-element result is a scalar and serialises as a bare
    # string, and an empty result disappears from the payload entirely.
    $payload = [ordered]@{
        policy_name     = $PolicyName
        allowed_senders = [string[]]@(Get-FlatStringArray $eopPolicy.AllowedSenders)
        blocked_senders = [string[]]@(Get-FlatStringArray $eopPolicy.BlockedSenders)
        allowed_domains = [string[]]@(Get-FlatStringArray $eopPolicy.AllowedSenderDomains)
        blocked_domains = [string[]]@(Get-FlatStringArray $eopPolicy.BlockedSenderDomains)
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

    # Reads one list from MariaDB for the push.
    #
    # This fails CLOSED. The previous version merged stderr into stdout with 2>&1
    # and treated any non-empty output as data, so a missing client or a failed
    # query had its error text pushed to Exchange Online as policy entries - and
    # because Set-HostedContentFilterPolicy applies all four lists in one call,
    # that would silently replace real blocklists. It also used -split on what
    # may be an array, which coerces the array to a single string and yields one
    # multi-line "entry".
    #
    # $ExpectedCountVar names an environment variable holding the row count PHP
    # already determined over PDO. If the CLI disagrees, the two are reading
    # different data and the push is refused rather than applied.
    function Query-MariaDbList {
        param (
            [string]$TableName,
            [string]$ColumnName,
            [string]$Policy,
            [string]$ExpectedCountVar = ''
        )

        # Resolve the client without trusting the caller's PATH. PHP-FPM clears
        # the environment, so a web-spawned pwsh has no PATH and Get-Command
        # finds nothing even though the client is installed - the pull path never
        # noticed because it does not touch MariaDB. Cron worked because it
        # inherits a login PATH, which is exactly why the same push succeeded from
        # the CLI and failed from the web UI. Probe the standard locations before
        # falling back to PATH so the two paths cannot disagree again.
        $dbCli = Get-Command mariadb -ErrorAction SilentlyContinue
        if (-not $dbCli) { $dbCli = Get-Command mysql -ErrorAction SilentlyContinue }
        if (-not $dbCli) {
            foreach ($candidate in @(
                '/usr/bin/mariadb', '/usr/local/bin/mariadb', '/usr/sbin/mariadb', '/bin/mariadb',
                '/usr/bin/mysql',   '/usr/local/bin/mysql',   '/usr/sbin/mysql',   '/bin/mysql'
            )) {
                if (Test-Path -LiteralPath $candidate) {
                    $dbCli = Get-Command $candidate -ErrorAction SilentlyContinue
                    if ($dbCli) { break }
                }
            }
        }
        if (-not $dbCli) {
            Write-Error "Push aborted for '${TableName}': neither the 'mariadb' nor the 'mysql' client is installed, so the local list cannot be read. Install the MariaDB client package, or push from the web UI."
            exit 1
        }

        $policyClean = $Policy -replace "'", "''"
        $query = "SELECT $ColumnName FROM $TableName WHERE policy_name = '$policyClean';"

        # Diagnostic. Set EOP_SYNC_DEBUG=1 in the environment to see exactly what
        # the client returned and why each guard decided as it did. Needed because a
        # report showed the guards not firing and a JSON blob reaching Exchange,
        # neither of which the code here should permit.
        $debug = -not [string]::IsNullOrWhiteSpace($env:EOP_SYNC_DEBUG)
        $expectRaw = $null
        if ($ExpectedCountVar -ne '') {
            $expectRaw = [Environment]::GetEnvironmentVariable($ExpectedCountVar)
        }
        if ($debug) {
            Write-Host "[debug] table=$TableName cli=$($dbCli.Source) exit-var-before=$LASTEXITCODE"
            Write-Host "[debug] host='$DbHost' port=$DbPort db='$DbName' user='$DbUser' passSet=$(-not [string]::IsNullOrEmpty($DbPass))"
            Write-Host "[debug] query=$query"
            Write-Host "[debug] expectVar=$ExpectedCountVar expectValue=$(if ($null -eq $expectRaw) { '<NULL>' } else { "'$expectRaw'" })"
        }

        # stderr is captured separately so a diagnostic can never become an entry.
        $errFile = [System.IO.Path]::GetTempFileName()
        try {
            $raw = & $dbCli.Source -h $DbHost -P $DbPort -u $DbUser "-p$DbPass" -D $DbName -s -N -e $query 2>$errFile
            $exit = $LASTEXITCODE
        } finally {
            $stderr = (Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue)
            Remove-Item -LiteralPath $errFile -Force -ErrorAction SilentlyContinue
        }

        if ($debug) {
            Write-Host "[debug] exit=$exit"
            Write-Host "[debug] stderr=$([string]$stderr)"
            Write-Host "[debug] rawType=$(if ($null -eq $raw) { 'null' } else { $raw.GetType().FullName }) rawCount=$(@($raw).Count)"
            $i = 0
            foreach ($line in @($raw)) {
                $i++
                Write-Host ("[debug] raw[{0}] len={1} first40='{2}'" -f $i, ([string]$line).Length, (([string]$line).Substring(0, [Math]::Min(40, ([string]$line).Length)) -replace "`r|`n", '\n'))
            }
        }

        if ($exit -ne 0) {
            Write-Error "Push aborted for '${TableName}': the query failed (exit ${exit}). $([string]$stderr).Trim()"
            exit 1
        }

        $values = @()
        foreach ($line in @($raw)) {
            $text = ([string]$line).Trim()
            if ($text -eq '') { continue }
            # Anything that looks like JSON, an object or a quoted field is not a
            # list value. Pushing it would corrupt the Exchange policy.
            if ($text -match '^[\[\]{}]' -or $text.StartsWith('"') -or $text.EndsWith('",')) {
                Write-Error "Push aborted for '${TableName}': query output looks like JSON or a serialised object rather than list data: '$text'. Refusing to push it to Exchange Online."
                exit 1
            }
            $values += $text
        }

        if ($ExpectedCountVar -ne '') {
            $expected = [Environment]::GetEnvironmentVariable($ExpectedCountVar)
            if ($debug) {
                Write-Host "[debug] guard: expectVar='$ExpectedCountVar' seen=$(if ($null -eq $expected) { '<NULL>' } else { "'$expected'" }) valuesCount=$($values.Count)"
            }
            if ($expected -ne $null -and $expected -ne '') {
                $expectedInt = 0
                if (-not [int]::TryParse($expected, [ref]$expectedInt)) {
                    Write-Error "Push aborted for '${TableName}': expected-count variable ${ExpectedCountVar} is not a number ('$expected')."
                    exit 1
                }
                if ($values.Count -ne $expectedInt) {
                    Write-Error "Push aborted for '${TableName}': the MariaDB client read $($values.Count) rows but PHP read ${expectedInt} over PDO. The two disagree, so the local list is not being read consistently and the push has been refused. Re-run with the web UI push to investigate."
                    exit 1
                }
            }
        }

        return $values
    }

    $allowedSenders = @(Get-FlatStringArray (Query-MariaDbList -TableName "eop_allowed_senders" -ColumnName "sender_email" -Policy $PolicyName -ExpectedCountVar 'EOP_EXPECT_ALLOWED_SENDERS'))
    $blockedSenders = @(Get-FlatStringArray (Query-MariaDbList -TableName "eop_blocked_senders" -ColumnName "sender_email" -Policy $PolicyName -ExpectedCountVar 'EOP_EXPECT_BLOCKED_SENDERS'))
    $allowedDomains = @(Get-FlatStringArray (Query-MariaDbList -TableName "eop_allowed_domains" -ColumnName "domain_name" -Policy $PolicyName -ExpectedCountVar 'EOP_EXPECT_ALLOWED_DOMAINS'))
    $blockedDomains = @(Get-FlatStringArray (Query-MariaDbList -TableName "eop_blocked_domains" -ColumnName "domain_name" -Policy $PolicyName -ExpectedCountVar 'EOP_EXPECT_BLOCKED_DOMAINS'))

    if (-not [string]::IsNullOrWhiteSpace($env:EOP_SYNC_DEBUG)) {
        Write-Host "[debug] FINAL allowedSenders.Count=$($allowedSenders.Count) type0=$(if ($allowedSenders.Count) { $allowedSenders[0].GetType().FullName } else { 'n/a' })"
        if ($allowedSenders.Count) {
            Write-Host "[debug] FINAL allowedSenders[0] = '$($allowedSenders[0])'"
        }
    }

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
