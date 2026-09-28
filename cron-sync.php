<?php
// ==============================================================================
// CLI Crontab Sync Runner for Debian
// 
// CRON POLICY ENFORCEMENT:
// The cron job strictly PULLS changes from Exchange Online Protection (EOP)
// into MariaDB. It does NOT push local MariaDB changes to EOP.
// 
// Usage in crontab (e.g. every 15 minutes):
// */15 * * * * www-data /usr/bin/php /var/www/eop-antispam/cron-sync.php --policy="Default Inbound Anti-Spam Policy"
// ==============================================================================

declare(strict_types=1);

if (php_sapi_name() !== 'cli') {
    die("This script must be run from the command line.\n");
}

if (!file_exists(__DIR__ . '/config.php')) {
    fwrite(STDERR, "[" . date('Y-m-d H:i:s') . "] CRON ERROR: /var/www/eop-antispam/config.php not found. Please complete initial setup at http://<server-ip>/setup.php\n");
    exit(1);
}

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';

$options = getopt('', ['policy::', 'action::', 'help']);

if (isset($options['help'])) {
    echo "Usage: php cron-sync.php [--policy=PolicyName] [--action=pull]\n";
    echo "Notice: The cron job strictly PULLS from Exchange Online to MariaDB (never pushes).\n";
    exit(0);
}

$policy = $options['policy'] ?? DEFAULT_POLICY_NAME;
$action = strtolower($options['action'] ?? 'pull');

// Enforce pull-only in cron
if ($action !== 'pull') {
    fwrite(STDERR, "[CRON POLICY ERROR] The cron job is configured to ONLY pull changes from EOP, not push them.\n");
    fwrite(STDERR, "To push changes, an authorized administrator must use the Web UI or run with explicit manual confirmation.\n");
    exit(1);
}

echo "[" . date('Y-m-d H:i:s') . "] Starting EOP Anti-Spam CRON PULL for policy: {$policy}\n";
echo "Sync Direction: PULL ONLY (Exchange Online -> MariaDB)\n";
echo "Notice: Local MariaDB changes will NOT be pushed to EOP.\n";

// Execute PowerShell sync script in Pull-only mode on Debian
$psScript = __DIR__ . '/sync-exchange.ps1';
if (!file_exists($psScript)) {
    fwrite(STDERR, "[" . date('Y-m-d H:i:s') . "] CRON ERROR: PowerShell script not found at {$psScript}\n");
    exit(1);
}

$pwsh = trim((string)shell_exec('command -v pwsh 2>/dev/null'));
if ($pwsh === '') {
    fwrite(STDERR, "[" . date('Y-m-d H:i:s') . "] CRON ERROR: pwsh not found. Install PowerShell 7 (https://aka.ms/powershell)\n");
    exit(1);
}

// PowerShell's Platform.SelectProductNameForDirectory('CACHE') returns an empty
// string on Debian when XDG_CACHE_HOME is unset, which makes PowerShellGet fail
// to initialise. Only applied when the crontab has not supplied one already.
if (getenv('XDG_CACHE_HOME') === false) {
    $xdgCache = '/var/cache/eop-antispam';
    if (!is_dir($xdgCache)) {
        @mkdir($xdgCache, 0755, true);
    }
    if (is_dir($xdgCache)) {
        putenv('XDG_CACHE_HOME=' . $xdgCache);
    }
}

// Exchange Online App-Only authentication values are read from the active
// eop_auth_config record rather than hardcoded in the PowerShell script, so that
// rotating the certificate or App Registration in the Web UI takes effect here
// without a code change.
$authConfig = Database::getEopAuthConfig();

$requiredAuthFields = ['tenant_id', 'client_id', 'certificate_thumbprint'];
$missingAuthFields = [];
foreach ($requiredAuthFields as $field) {
    if (empty($authConfig[$field])) {
        $missingAuthFields[] = $field;
    }
}

if ($missingAuthFields) {
    $detail = implode(', ', $missingAuthFields);
    fwrite(STDERR, "[" . date('Y-m-d H:i:s') . "] CRON ERROR: active eop_auth_config record is missing {$detail}.\n");
    fwrite(STDERR, "Upload the certificate details in the Web UI (Authentication tab) before running the sync.\n");
    Database::updatePolicySyncStatus($policy, 'failed', "eop_auth_config missing {$detail}");
    exit(1);
}

putenv('EOP_TENANT_ID=' . $authConfig['tenant_id']);
putenv('EOP_CLIENT_ID=' . $authConfig['client_id']);
putenv('EOP_CERT_THUMBPRINT=' . $authConfig['certificate_thumbprint']);
putenv('EOP_ORGANIZATION=' . ($authConfig['organization'] ?? ''));

// Certificate material. Certificate authentication on Linux needs a PKCS#12
// bundle holding the certificate together with its key. The bundle is taken from
// the encrypted pkcs12_bundle column when one is stored, otherwise from a
// provisioned path on disk.
$pfxPath = getenv('EOP_CERT_PFX_PATH') ?: '/etc/eop-antispam/eop-cert.pfx';
$tempPfx = null;
$pfxFromDatabase = false;

$storedBundle = trim((string)($authConfig['pkcs12_bundle'] ?? ''));
if ($storedBundle !== '') {
    $blob = base64_decode((string)preg_replace('/\s+/', '', $storedBundle), true);
    if ($blob === false || !str_starts_with($blob, "\x30")) {
        fwrite(STDERR, "[" . date('Y-m-d H:i:s') . "] CRON ERROR: the stored PKCS#12 bundle in eop_auth_config is not a DER bundle.\n");
        Database::updatePolicySyncStatus($policy, 'failed', 'Stored PKCS#12 bundle is malformed');
        exit(1);
    }

    $tempPfx = tempnam(sys_get_temp_dir(), 'eopcert_');
    file_put_contents($tempPfx, $blob);
    chmod($tempPfx, 0600);
    $pfxPath = $tempPfx;
    $pfxFromDatabase = true;
}

if (!is_readable($pfxPath)) {
    fwrite(STDERR, "[" . date('Y-m-d H:i:s') . "] CRON ERROR: no readable PKCS#12 certificate bundle at {$pfxPath}.\n");
    fwrite(STDERR, "Certificate authentication needs a .pfx containing the certificate and its private key. Upload one in the Web UI or set EOP_CERT_PFX_PATH.\n");
    Database::updatePolicySyncStatus($policy, 'failed', "PKCS#12 certificate not readable at {$pfxPath}");
    exit(1);
}

$pfxPassword = (string)($authConfig['encrypted_password'] ?? '');

if ($pfxFromDatabase && $pfxPassword === '') {
    fwrite(STDERR, "[" . date('Y-m-d H:i:s') . "] NOTICE: no stored passphrase for the PKCS#12 bundle, attempting an empty passphrase.\n");
}

// Paths and the policy name are passed to PowerShell through the environment
// rather than interpolated into the command string, so values containing spaces
// or quotes cannot break out of the PowerShell argument.
putenv('EOP_PS_SCRIPT=' . $psScript);
putenv('EOP_POLICY=' . $policy);

$pullOutput = tempnam(sys_get_temp_dir(), 'eoppull_');

putenv('EOP_CERT_PFX_PATH=' . $pfxPath);
putenv('EOP_CERT_PFX_PASSWORD=' . $pfxPassword);
putenv('EOP_PULL_OUTPUT=' . $pullOutput);

// The decrypted passphrase and any reconstructed bundle are removed on every
// exit path, including fatal errors.
register_shutdown_function(static function () use ($pullOutput, $tempPfx): void {
    foreach ([$pullOutput, $tempPfx] as $tempPath) {
        if ($tempPath && is_file($tempPath)) {
            @unlink($tempPath);
        }
    }
});

// Every pwsh invocation is a separate process, so importing the module here
// would not carry over to the run below. The import is therefore performed in
// the *same* session that executes sync-exchange.ps1. The preflight below exists
// only to report the import failure loudly, instead of letting the script fall
// through to its own success message.
$importCmd = 'Import-Module ExchangeOnlineManagement -ErrorAction Stop';

$preflightShell = sprintf(
    '%s -NoProfile -NonInteractive -Command %s 2>&1',
    escapeshellarg($pwsh),
    escapeshellarg($importCmd)
);

$preflightOutput = [];
$preflightExit = 0;
exec($preflightShell, $preflightOutput, $preflightExit);

if ($preflightExit !== 0) {
    fwrite(STDERR, "[" . date('Y-m-d H:i:s') . "] CRON ERROR: could not import ExchangeOnlineManagement (exit {$preflightExit}).\n");
    foreach ($preflightOutput as $line) {
        fwrite(STDERR, '    ' . $line . "\n");
    }
    Database::updatePolicySyncStatus($policy, 'failed', 'ExchangeOnlineManagement module import failed');
    exit(1);
}

echo "ExchangeOnlineManagement module imported successfully.\n";

$runShell = sprintf(
    '%s -NoProfile -NonInteractive -Command %s 2>&1',
    escapeshellarg($pwsh),
    escapeshellarg(sprintf(
        '$ErrorActionPreference = "Stop"; %s; & $env:EOP_PS_SCRIPT -PolicyName $env:EOP_POLICY -Action Pull',
        $importCmd
    ))
);

passthru($runShell, $returnVar);

if ($returnVar === 0) {
    $remote = null;
    if (is_readable($pullOutput)) {
        $decoded = json_decode((string)file_get_contents($pullOutput), true);
        if (is_array($decoded)) {
            $remote = $decoded;
        }
    }

    if ($remote === null) {
        fwrite(STDERR, "[" . date('Y-m-d H:i:s') . "] CRON ERROR: the pull finished but wrote no readable policy payload.\n");
        Database::updatePolicySyncStatus($policy, 'failed', 'Cron pull produced no readable remote policy payload');
        exit(1);
    }

    $listMap = [
        'allowed_senders' => 'allowed_senders',
        'blocked_senders' => 'blocked_senders',
        'allowed_domains' => 'allowed_domains',
        'blocked_domains' => 'blocked_domains',
    ];

    $totalInserted = 0;
    $totalRemoved = 0;

    foreach ($listMap as $listType => $payloadKey) {
        $values = $remote[$payloadKey] ?? [];
        if (!is_array($values)) {
            $values = [];
        }

        $result = Database::reconcileListWithRemote($listType, $policy, $values, 'CRON_DAEMON');
        $totalInserted += $result['inserted'];
        $totalRemoved += $result['removed'];

        printf(
            "  %-18s remote=%-5d inserted=%-5d removed=%-5d\n",
            $listType,
            $result['remote'],
            $result['inserted'],
            $result['removed']
        );

        foreach ($result['errors'] as $insertError) {
            fwrite(STDERR, '    ' . $insertError . "\n");
        }
    }

    $summary = "Cron pull: {$totalInserted} added, {$totalRemoved} removed";
    Database::updatePolicySyncStatus($policy, 'synced', $summary);
    Database::logAudit('SYNC', 'SYSTEM', $policy, 'ALL', "Crontab pulled changes from Exchange Online (Pull-Only): {$summary}", 'CRON_DAEMON');
    echo "[" . date('Y-m-d H:i:s') . "] Cron EOP pull completed successfully.\n";
} else {
    Database::updatePolicySyncStatus($policy, 'failed', "Crontab pull exited with code {$returnVar}");
    fwrite(STDERR, "[" . date('Y-m-d H:i:s') . "] Cron pull failed with code {$returnVar}\n");
    exit(1);
}
