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

// Paths and the policy name are passed to PowerShell through the environment
// rather than interpolated into the command string, so values containing spaces
// or quotes cannot break out of the PowerShell argument.
putenv('EOP_PS_SCRIPT=' . $psScript);
putenv('EOP_POLICY=' . $policy);

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
    Database::updatePolicySyncStatus($policy, 'synced', 'Crontab automatic PULL from EOP completed');
    Database::logAudit('SYNC', 'SYSTEM', $policy, 'ALL', 'Crontab pulled changes from Exchange Online (Pull-Only)', 'CRON_DAEMON');
    echo "[" . date('Y-m-d H:i:s') . "] Cron EOP pull completed successfully.\n";
} else {
    Database::updatePolicySyncStatus($policy, 'failed', "Crontab pull exited with code {$returnVar}");
    fwrite(STDERR, "[" . date('Y-m-d H:i:s') . "] Cron pull failed with code {$returnVar}\n");
    exit(1);
}
