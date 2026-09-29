<?php
// ==============================================================================
// CLI Crontab Sync Runner for Debian
//
// SYNC DIRECTION:
//   The default, and the safe default, is PULL: Exchange Online -> MariaDB.
//   Pushing MariaDB changes to Exchange Online is opt-in and must be enabled
//   explicitly, because an unattended job that writes to production anti-spam
//   policies can lock mail out or stop blocking at 3am with nobody watching.
//
//   Enable with EOP_CRON_ALLOW_PUSH=true (see README). Even then, a push is
//   refused if any of the four local lists is empty, because the push applies
//   all four to Exchange and an empty list CLEARS it there. Override only with
//   EOP_CRON_PUSH_ALLOW_EMPTY=true.
//
// Usage in crontab (e.g. every 15 minutes):
//   */15 * * * * www-data /usr/bin/php /var/www/eop-antispam/cron-sync.php --policy="Default Inbound Anti-Spam Policy"
//   */15 * * * * www-data /usr/bin/php /var/www/eop-antispam/cron-sync.php --policy="..." --action=push
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
require_once __DIR__ . '/functions.php';

/**
 * Read a boolean flag from the environment. config.php loads .env via putenv, so
 * a value written there is visible here; the crontab can also export it.
 */
function eopReadFlag(string $key, bool $default = false): bool {
    $raw = getenv($key);
    if ($raw === false || trim($raw) === '') {
        return $default;
    }
    return in_array(strtolower(trim($raw)), ['1', 'true', 'yes', 'on'], true);
}

$options = getopt('', ['policy::', 'action::', 'help']);

if (isset($options['help'])) {
    echo "Usage: php cron-sync.php [--policy=PolicyName] [--action=pull|push]\n";
    echo "  pull  (default) Exchange Online -> MariaDB. Always allowed.\n";
    echo "  push  MariaDB -> Exchange Online. Requires EOP_CRON_ALLOW_PUSH=true,\n";
    echo "        and is refused if any of the four local lists is empty unless\n";
    echo "        EOP_CRON_PUSH_ALLOW_EMPTY=true is also set.\n";
    exit(0);
}

$policy = $options['policy'] ?? Database::getDefaultPolicyName();
$action = strtolower(trim((string)($options['action'] ?? 'pull')));

if (!in_array($action, ['pull', 'push'], true)) {
    fwrite(STDERR, "[CRON ERROR] Unknown --action '{$action}'. Expected 'pull' or 'push'.\n");
    exit(1);
}

$isPush = ($action === 'push');
$allowPush = eopReadFlag('EOP_CRON_ALLOW_PUSH');
$allowEmptyPush = eopReadFlag('EOP_CRON_PUSH_ALLOW_EMPTY');

// Pushing from an unattended job modifies production anti-spam policies, so it
// has to be turned on deliberately rather than being reachable by a crontab edit.
if ($isPush && !$allowPush) {
    fwrite(STDERR, "[CRON POLICY ERROR] Push is disabled. The cron job pulls only unless EOP_CRON_ALLOW_PUSH=true is set.\n");
    fwrite(STDERR, "To push, either set EOP_CRON_ALLOW_PUSH=true in .env (see README), or have an authorized administrator use the Web UI.\n");
    exit(1);
}

echo "[" . date('Y-m-d H:i:s') . "] Starting EOP Anti-Spam CRON {$action} for policy: {$policy}\n";
if ($isPush) {
    echo "Sync Direction: PUSH (MariaDB -> Exchange Online) - APPLIES TO PRODUCTION\n";
} else {
    echo "Sync Direction: PULL ONLY (Exchange Online -> MariaDB)\n";
    echo "Notice: Local MariaDB changes will NOT be pushed to EOP.\n";
}


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
// without a code change. The web UI's manual sync uses the same helper, so the
// two paths cannot drift apart again.
$authConfig = Database::getEopAuthConfig();
$syncEnv = eopPrepareSyncEnvironment($authConfig, getenv('EOP_CERT_PFX_PATH') ?: '/etc/eop-antispam/eop-cert.pfx');

if (!$syncEnv['ok']) {
    fwrite(STDERR, '[' . date('Y-m-d H:i:s') . '] CRON ERROR: ' . $syncEnv['error'] . "\n");
    Database::updatePolicySyncStatus($policy, 'failed', $syncEnv['error']);
    exit(1);
}

$pfxPath = $syncEnv['pfx_path'];

if (trim((string)($authConfig['pkcs12_bundle'] ?? '')) !== '' && (string)($authConfig['encrypted_password'] ?? '') === '') {
    fwrite(STDERR, "[" . date('Y-m-d H:i:s') . "] NOTICE: no stored passphrase for the PKCS#12 bundle, attempting an empty passphrase.\n");
}

// Paths and the policy name are passed to PowerShell through the environment
// rather than interpolated into the command string, so values containing spaces
// or quotes cannot break out of the PowerShell argument.
putenv('EOP_PS_SCRIPT=' . $psScript);
putenv('EOP_POLICY=' . $policy);

// -----------------------------------------------------------------------------
// PUSH: MariaDB -> Exchange Online (opt-in)
// -----------------------------------------------------------------------------
if ($isPush) {
    // The push reads the local lists from MariaDB, so it needs the credentials.
    eopExportSyncDatabaseEnvironment();

    // Set-HostedContentFilterPolicy is applied with all four lists at once, so an
    // empty local list does not mean "no change" - it CLEARS that list in
    // Exchange. Refuse rather than discover that at 3am, unless the operator has
    // explicitly said an empty list is intended.
    $pushLists = ['allowed_senders', 'blocked_senders', 'allowed_domains', 'blocked_domains'];
    $counts = [];
    $empty = [];
    foreach ($pushLists as $listType) {
        $counts[$listType] = Database::countListItems($listType, $policy);
        if ($counts[$listType] === 0) {
            $empty[] = $listType;
        }
    }

    if ($empty !== [] && !$allowEmptyPush) {
        $detail = implode(', ', $empty);
        fwrite(STDERR, '[' . date('Y-m-d H:i:s') . "] CRON POLICY ERROR: push refused for policy '{$policy}'.\n");
        fwrite(STDERR, "These local lists are empty: {$detail}.\n");
        fwrite(STDERR, "A push applies all four lists at once, so an empty list would CLEAR it in Exchange Online.\n");
        fwrite(STDERR, "Populate the list(s), or set EOP_CRON_PUSH_ALLOW_EMPTY=true if clearing them is intended.\n");
        Database::updatePolicySyncStatus($policy, 'failed', "Push refused: empty local list(s) {$detail}");
        Database::logAudit('SYNC', 'SYSTEM', $policy, 'ALL', "Cron push refused: empty local list(s) {$detail}", 'CRON_DAEMON');
        exit(1);
    }

    foreach ($counts as $listType => $count) {
        printf("  local %-18s %d\n", $listType, $count);
    }
    if ($empty !== []) {
        fwrite(STDERR, '[' . date('Y-m-d H:i:s') . '] WARNING: ' . count($empty) . " list(s) are empty and WILL BE CLEARED in Exchange Online (EOP_CRON_PUSH_ALLOW_EMPTY is set).\n");
    }

    $pushShell = sprintf(
        '%s -NoProfile -NonInteractive -File %s -PolicyName %s -Action Push 2>&1',
        escapeshellarg($pwsh),
        escapeshellarg($psScript),
        escapeshellarg($policy)
    );

    $pushOutput = [];
    $pushExit = 0;
    passthru($pushShell, $pushExit);

    if ($pushExit === 0) {
        $total = array_sum($counts);
        Database::updatePolicySyncStatus($policy, 'synced', "Cron push applied {$total} entries across 4 lists");
        Database::logAudit('SYNC', 'SYSTEM', $policy, 'ALL', "Crontab pushed MariaDB -> Exchange Online (Push): {$total} entries across 4 lists", 'CRON_DAEMON');
        echo "[" . date('Y-m-d H:i:s') . "] Cron EOP push completed successfully.\n";
        exit(0);
    }

    Database::updatePolicySyncStatus($policy, 'failed', "Cron push exited with code {$pushExit}");
    Database::logAudit('SYNC', 'SYSTEM', $policy, 'ALL', "Crontab push failed with code {$pushExit}", 'CRON_DAEMON');
    fwrite(STDERR, '[' . date('Y-m-d H:i:s') . "] Cron push failed with code {$pushExit}\n");
    exit(1);
}

// -----------------------------------------------------------------------------
// PULL: Exchange Online -> MariaDB (default)
// -----------------------------------------------------------------------------
$pullOutput = tempnam(sys_get_temp_dir(), 'eoppull_');
if ($pullOutput === false) {
    fwrite(STDERR, '[' . date('Y-m-d H:i:s') . "] CRON ERROR: could not create a temporary file for the pull response.\n");
    exit(1);
}

putenv('EOP_PULL_OUTPUT=' . $pullOutput);

// The pull transcript is removed on every exit path, including fatal errors. The
// temporary PKCS#12 bundle is cleaned up by eopPrepareSyncEnvironment().
register_shutdown_function(static function () use ($pullOutput): void {
    if (is_file($pullOutput)) {
        @unlink($pullOutput);
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
    $awaitingDecision = [];
    $heldByDecision = [];

    foreach ($listMap as $listType => $payloadKey) {
        $values = $remote[$payloadKey] ?? [];
        if (!is_array($values)) {
            // A one-entry PowerShell list serialises as a bare JSON string rather
            // than an array (a function return unrolls a single-element array).
            // sync-exchange.ps1 now prevents that, but older payloads may still
            // exist, so a lone string is wrapped rather than discarded.
            if (is_string($values)) {
                $values = ($values === '') ? [] : [$values];
            } else {
                fwrite(STDERR, "[" . date('Y-m-d H:i:s') . "] CRON ERROR: the remote payload for '{$listType}' is neither a list nor a string.\n");
                Database::updatePolicySyncStatus($policy, 'failed', "Remote payload for {$listType} was not a list");
                exit(1);
            }
        }

        try {
            $result = Database::reconcileListWithRemoteGuarded($listType, $policy, $values, 'CRON_DAEMON');
        } catch (RuntimeException $e) {
            // Never reconcile against a payload we could not read: the reconciler
            // deletes local rows absent from the remote list, so a malformed
            // payload would wipe the table.
            fwrite(STDERR, '[' . date('Y-m-d H:i:s') . '] CRON ERROR: ' . $e->getMessage() . "\n");
            Database::updatePolicySyncStatus($policy, 'failed', "Malformed remote payload for {$listType}");
            exit(1);
        }

        $guard = $result['guard'] ?? 'none';
        $confirmation = $result['confirmation'] ?? null;
        $localCount = (int)($confirmation['local_count'] ?? 0);

        if ($guard === 'prompted' || $guard === 'awaiting_decision') {
            // Deletion withheld and still needs a human decision.
            $awaitingDecision[$listType] = ['local_count' => $localCount, 'guard' => $guard];
            printf(
                "  %-18s remote=%-5d held=%-5d confirmation required\n",
                $listType, $result['remote'], $localCount
            );
        } elseif ($guard === 'denied') {
            // An administrator already refused; entries are deliberately kept and
            // cron must not nag about it on every run.
            $heldByDecision[$listType] = ['local_count' => $localCount, 'guard' => 'denied'];
            printf(
                "  %-18s remote=%-5d kept=%-5d deletion previously denied\n",
                $listType, $result['remote'], $localCount
            );
        } else {
            // 'none', or 'applied' where an accepted decision was executed now.
            $totalInserted += $result['inserted'];
            $totalRemoved += $result['removed'];

            printf(
                "  %-18s remote=%-5d inserted=%-5d removed=%-5d\n",
                $listType, $result['remote'], $result['inserted'], $result['removed']
            );
        }

        foreach ($result['errors'] as $insertError) {
            fwrite(STDERR, '    ' . $insertError . "\n");
        }
    }

    if ($heldByDecision !== []) {
        echo "NOTE: deletion of an empty remote list was previously DENIED for "
            . count($heldByDecision) . ' list(s); those entries were kept by request: '
            . implode(', ', array_keys($heldByDecision)) . ".\n";
        echo "      The confirmation clears automatically once Exchange Online returns entries.\n";
    }

    if ($awaitingDecision !== []) {
        // The pull itself succeeded, so this is not a failure exit: it is a state
        // that needs a human decision. Surfaced loudly because a crontab mailer
        // grepping for the success line would otherwise read this as clean.
        echo str_repeat('-', 74), "\n";
        echo "ACTION REQUIRED: remote lists came back EMPTY but local entries exist.\n";
        echo "Deletion has been WITHHELD. Nothing was removed for the lists below.\n";
        foreach ($awaitingDecision as $listType => $info) {
            $state = $info['guard'] === 'prompted'
                ? 'confirmation raised, awaiting a decision'
                : 'already awaiting a decision';
            printf("  - %-18s local entries=%-6d %s\n", $listType, $info['local_count'], $state);
        }
        echo "Review and accept or deny each list in the web UI under this policy.\n";
        echo str_repeat('-', 74), "\n";

        Database::updatePolicySyncStatus(
            $policy,
            'pending',
            count($awaitingDecision) . ' list(s) withheld: empty remote list needs administrator confirmation'
        );
        echo "[" . date('Y-m-d H:i:s') . "] Cron EOP pull completed; administrator confirmation required.\n";
    } else {
        $summary = "Cron pull: {$totalInserted} added, {$totalRemoved} removed";
        Database::updatePolicySyncStatus($policy, 'synced', $summary);
        Database::logAudit('SYNC', 'SYSTEM', $policy, 'ALL', "Crontab pulled changes from Exchange Online (Pull-Only): {$summary}", 'CRON_DAEMON');
        echo "[" . date('Y-m-d H:i:s') . "] Cron EOP pull completed successfully.\n";
    }
} else {
    Database::updatePolicySyncStatus($policy, 'failed', "Crontab pull exited with code {$returnVar}");
    fwrite(STDERR, "[" . date('Y-m-d H:i:s') . "] Cron pull failed with code {$returnVar}\n");
    exit(1);
}
