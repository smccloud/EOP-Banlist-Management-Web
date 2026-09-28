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
if (file_exists($psScript)) {
    $cmd = sprintf('pwsh -File %s -PolicyName %s -Action Pull 2>&1', escapeshellarg($psScript), escapeshellarg($policy));
    passthru($cmd, $returnVar);

    if ($returnVar === 0) {
        Database::updatePolicySyncStatus($policy, 'synced', 'Crontab automatic PULL from EOP completed');
        Database::logAudit('SYNC', 'SYSTEM', $policy, 'ALL', 'Crontab pulled changes from Exchange Online (Pull-Only)', 'CRON_DAEMON');
        echo "[" . date('Y-m-d H:i:s') . "] Cron EOP pull completed successfully.\n";
    } else {
        Database::updatePolicySyncStatus($policy, 'failed', "Crontab pull exited with code {$returnVar}");
        echo "[" . date('Y-m-d H:i:s') . "] Cron pull failed with code {$returnVar}.
";
    }
} else {
    echo "Error: PowerShell script not found at {$psScript}
";
}
