<?php
/**
 * POST Action Controller
 * Enforces CSRF tokens, user authorization, and data validation
 */

declare(strict_types=1);

if (!file_exists(__DIR__ . '/config.php')) {
    header('Location: setup.php');
    exit;
}

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';
require_once __DIR__ . '/functions.php';

$user = requireAuth();

$action = $_POST['action'] ?? ($_GET['action'] ?? '');
$listType = $_POST['list'] ?? ($_GET['list'] ?? 'allowed_senders');
$policyName = $_POST['policy'] ?? ($_GET['policy'] ?? DEFAULT_POLICY_NAME);

// CSRF validation
$token = $_POST['csrf_token'] ?? ($_GET['csrf'] ?? '');
if (!verifyCsrfToken($token)) {
    setFlash('error', 'CSRF validation failed. Action aborted.');
    header("Location: index.php?policy=" . urlencode($policyName) . "&tab=" . urlencode($listType));
    exit;
}

// --------------------------------------------------------------------------
// 1. Add Single Entry (Enforces Duplicate Prevention)
// --------------------------------------------------------------------------
if ($action === 'add_single') {
    $value = trim($_POST['value'] ?? '');
    $note = trim($_POST['note'] ?? '');

    // Format validation
    if (str_contains($listType, 'sender')) {
        if (!isValidEmail($value)) {
            setFlash('error', "Invalid email address format: '{$value}'");
            header("Location: index.php?policy=" . urlencode($policyName) . "&tab=" . urlencode($listType));
            exit;
        }
    } else {
        if (!isValidDomain($value)) {
            setFlash('error', "Invalid domain format: '{$value}' (must be FQDN e.g. domain.com or *.domain.com)");
            header("Location: index.php?policy=" . urlencode($policyName) . "&tab=" . urlencode($listType));
            exit;
        }
    }

    // Check if entry already exists (duplicate prevention)
    if (Database::itemExists($listType, $policyName, $value)) {
        $_SESSION['duplicate_popup'] = [
            'value'     => $value,
            'listType'  => $listType,
            'policy'    => $policyName,
            'timestamp' => date('Y-m-d H:i:s'),
        ];
        setFlash('error', "Duplicate entry rejected: '{$value}' already exists in {$listType} for policy '{$policyName}'.");
        header("Location: index.php?policy=" . urlencode($policyName) . "&tab=" . urlencode($listType));
        exit;
    }

    $success = Database::addItem($listType, $policyName, $value, $note, $user['username']);
    if ($success) {
        setFlash('success', "Added '{$value}' to {$listType} for policy '{$policyName}'");
    } else {
        setFlash('error', "Failed to add entry to {$listType}. An entry with this value may already exist.");
    }

    header("Location: index.php?policy=" . urlencode($policyName) . "&tab=" . urlencode($listType));
    exit;
}

// --------------------------------------------------------------------------
// 2. Delete Single Entry
// --------------------------------------------------------------------------
if ($action === 'delete_item') {
    $id = (int)($_POST['id'] ?? 0);
    $deleted = Database::deleteItem($listType, $id, $user['username']);

    if ($deleted) {
        setFlash('success', "Item removed successfully.");
    } else {
        setFlash('error', "Failed to remove item.");
    }

    header("Location: index.php?policy=" . urlencode($policyName) . "&tab=" . urlencode($listType));
    exit;
}

// --------------------------------------------------------------------------
// 3. Bulk Import
// --------------------------------------------------------------------------
if ($action === 'bulk_import') {
    $bulkData = trim($_POST['bulk_data'] ?? '');
    $lines = explode("\n", str_replace("\r", "", $bulkData));
    $parsed = [];

    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '') continue;

        // Support CSV format: value, optional note
        $parts = explode(',', $line, 2);
        $val = trim($parts[0]);
        $note = isset($parts[1]) ? trim($parts[1]) : '';

        // Validate format
        if (str_contains($listType, 'sender')) {
            if (!isValidEmail($val)) continue;
        } else {
            if (!isValidDomain($val)) continue;
        }

        $parsed[] = ['value' => $val, 'note' => $note];
    }

    if (empty($parsed)) {
        setFlash('error', "No valid items found in bulk data.");
    } else {
        $result = Database::bulkInsert($listType, $policyName, $parsed, $user['username']);
        if ($result['inserted'] === 0 && $result['skipped'] > 0) {
            setFlash('warning', "Duplicate Prevention: All {$result['skipped']} entries already exist in {$listType} for policy '{$policyName}'. No duplicates were added.");
        } else if ($result['skipped'] > 0) {
            setFlash('success', "Bulk Import Complete: {$result['inserted']} new items added. {$result['skipped']} duplicate entries were automatically skipped.");
        } else {
            setFlash('success', "Bulk Import Complete: {$result['inserted']} items added successfully.");
        }
    }

    header("Location: index.php?policy=" . urlencode($policyName) . "&tab=" . urlencode($listType));
    exit;
}

// --------------------------------------------------------------------------
// 3b. Smart Sort & Import (Auto-sort Mixed List of Senders and Domains)
// --------------------------------------------------------------------------
if ($action === 'smart_sort_import') {
    $targetMode = $_POST['target_mode'] ?? 'blocked'; // 'allowed' or 'blocked'
    if ($targetMode !== 'allowed' && $targetMode !== 'blocked') {
        $targetMode = 'blocked';
    }

    $bulkData = trim($_POST['bulk_data'] ?? '');
    $defaultNote = trim($_POST['default_note'] ?? 'Smart Auto-Sorted Import');
    $lines = explode("\n", str_replace("\r", "", $bulkData));

    $senders = [];
    $domains = [];
    $skippedDuplicates = 0;
    $invalidLines = 0;

    $sendersListType = ($targetMode === 'blocked') ? 'blocked_senders' : 'allowed_senders';
    $domainsListType = ($targetMode === 'blocked') ? 'blocked_domains' : 'allowed_domains';

    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) continue;

        $parts = explode(',', $line, 2);
        $val = strtolower(trim($parts[0]));
        $note = isset($parts[1]) && trim($parts[1]) !== '' ? trim($parts[1]) : $defaultNote;

        if ($val === '') continue;

        if (str_contains($val, '@')) {
            // Sender Email Address
            if (!isValidEmail($val)) {
                $invalidLines++;
                continue;
            }
            if (Database::itemExists($sendersListType, $policyName, $val)) {
                $skippedDuplicates++;
                continue;
            }
            $senders[] = ['value' => $val, 'note' => $note];
        } else {
            // Domain Name
            if (!isValidDomain($val)) {
                $invalidLines++;
                continue;
            }
            if (Database::itemExists($domainsListType, $policyName, $val)) {
                $skippedDuplicates++;
                continue;
            }
            $domains[] = ['value' => $val, 'note' => $note];
        }
    }

    $insertedSenders = 0;
    $insertedDomains = 0;

    if (!empty($senders)) {
        $resSenders = Database::bulkInsert($sendersListType, $policyName, $senders, $user['username']);
        $insertedSenders = $resSenders['inserted'];
        $skippedDuplicates += $resSenders['skipped'];
    }

    if (!empty($domains)) {
        $resDomains = Database::bulkInsert($domainsListType, $policyName, $domains, $user['username']);
        $insertedDomains = $resDomains['inserted'];
        $skippedDuplicates += $resDomains['skipped'];
    }

    $totalInserted = $insertedSenders + $insertedDomains;
    $targetLabel = ucfirst($targetMode);

    if ($totalInserted === 0 && $skippedDuplicates > 0) {
        setFlash('warning', "Smart Sort: All {$skippedDuplicates} parsed items already exist in {$targetLabel} lists for policy '{$policyName}'. No duplicates were added.");
    } elseif ($totalInserted === 0) {
        setFlash('error', "No valid email addresses or domain names were found in input.");
    } else {
        $msg = "Smart Sort Complete: Sorted {$totalInserted} items into {$targetLabel} lists ({$insertedSenders} senders to eop_{$sendersListType}, {$insertedDomains} domains to eop_{$domainsListType}).";
        if ($skippedDuplicates > 0) {
            $msg .= " Skipped {$skippedDuplicates} duplicate entries.";
        }
        setFlash('success', $msg);
    }

    $redirectTab = $targetMode === 'blocked' ? 'blocked_senders' : 'allowed_senders';
    header("Location: index.php?policy=" . urlencode($policyName) . "&tab=" . urlencode($redirectTab));
    exit;
}

// --------------------------------------------------------------------------
// 4. Export CSV
// --------------------------------------------------------------------------
if ($action === 'export_csv') {
    $items = Database::getListItems($listType, $policyName, '', 10000, 0);

    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename=eop_' . $listType . '_' . preg_replace('/[^a-zA-Z0-9_-]/', '_', $policyName) . '_' . date('Ymd_His') . '.csv');

    $output = fopen('php://output', 'w');
    fputcsv($output, ['ID', 'Policy Name', 'Item Value', 'Note', 'Added By', 'Created At']);

    foreach ($items as $row) {
        fputcsv($output, [
            $row['id'],
            $row['policy_name'],
            $row['item_value'],
            $row['note'],
            $row['added_by'],
            $row['created_at'],
        ]);
    }
    fclose($output);
    exit;
}

// --------------------------------------------------------------------------
// 5. Trigger Exchange Online Sync (Pull or Manual Admin Push)
// --------------------------------------------------------------------------
if ($action === 'trigger_sync') {
    $direction = strtolower(trim($_POST['direction'] ?? 'pull'));
    $actionParam = ($direction === 'push') ? 'Push' : 'Pull';
    $redirect = "Location: index.php?policy=" . urlencode($policyName) . "&tab=sync_center";

    // sync-exchange.ps1 reads its app-only auth values and the PKCS#12 bundle from
    // the environment, not from parameters. This path never exported them, so every
    // web-initiated sync failed with "Missing authentication values" - the cron path
    // worked because cron-sync.php does export them.
    $env = eopPrepareSyncEnvironment(Database::getEopAuthConfig());
    if (!$env['ok']) {
        Database::updatePolicySyncStatus($policyName, 'failed', $env['error']);
        setFlash('error', "Exchange Online sync could not start: " . $env['error']);
        header($redirect);
        exit;
    }

    // A push reads the local lists from MariaDB, so it needs the credentials too.
    if ($actionParam === 'Push') {
        eopExportSyncDatabaseEnvironment();

        // Hand the PDO row counts to the PowerShell side, which reads the same
        // lists through the MariaDB CLI. If the two disagree the push is refused
        // rather than applied, so a failed or missing client cannot replace the
        // Exchange policy with garbage.
        $expectEnvMap = [
            'allowed_senders' => 'EOP_EXPECT_ALLOWED_SENDERS',
            'blocked_senders' => 'EOP_EXPECT_BLOCKED_SENDERS',
            'allowed_domains' => 'EOP_EXPECT_ALLOWED_DOMAINS',
            'blocked_domains' => 'EOP_EXPECT_BLOCKED_DOMAINS',
        ];
        foreach ($expectEnvMap as $listType => $varName) {
            putenv($varName . '=' . Database::countListItems($listType, $policyName));
        }
    }

    $shellParts = [
        escapeshellarg(SYNC_SCRIPT_PATH),
        '-PolicyName ' . escapeshellarg($policyName),
        '-Action ' . escapeshellarg($actionParam),
    ];
    if ($actionParam === 'Pull') {
        // The Pull path stages its JSON through a temp file named by the environment.
        $pullOutput = tempnam(sys_get_temp_dir(), 'eoppull_');
        if ($pullOutput === false) {
            setFlash('error', 'Could not create a temporary file for the Exchange Online pull response.');
            header($redirect);
            exit;
        }
        register_shutdown_function(static function () use ($pullOutput): void {
            if (is_file($pullOutput)) {
                @unlink($pullOutput);
            }
        });
        putenv('EOP_PULL_OUTPUT=' . $pullOutput);
    }

    $cmd = 'pwsh -NoProfile -NonInteractive -File ' . implode(' ', $shellParts) . ' 2>&1';

    $output = [];
    $returnVar = 0;
    exec($cmd, $output, $returnVar);

    $logMsg = implode("\n", $output);
    if ($returnVar === 0) {
        if ($actionParam === 'Pull') {
            Database::updatePolicySyncStatus($policyName, 'synced', 'Pulled changes from Exchange Online into MariaDB');
            Database::logAudit('SYNC', 'SYSTEM', $policyName, 'ALL', 'Manual pull from Exchange Online completed', $user['username']);
            setFlash('success', "Exchange Online pull completed successfully! Remote entries ingested into MariaDB for policy '{$policyName}'.");
        } else {
            Database::updatePolicySyncStatus($policyName, 'synced', 'Pushed changes to Exchange Online');
            Database::logAudit('SYNC', 'SYSTEM', $policyName, 'ALL', 'Manual push to Exchange Online completed', $user['username']);
            
            // Capture entries pushed to each list for the post-push summary popup
            $pushedAllowedSenders = array_column(Database::getListItems('allowed_senders', $policyName, '', 500, 0), 'item_value');
            $pushedBlockedSenders = array_column(Database::getListItems('blocked_senders', $policyName, '', 500, 0), 'item_value');
            $pushedAllowedDomains = array_column(Database::getListItems('allowed_domains', $policyName, '', 500, 0), 'item_value');
            $pushedBlockedDomains = array_column(Database::getListItems('blocked_domains', $policyName, '', 500, 0), 'item_value');

            $_SESSION['push_summary'] = [
                'policy'         => $policyName,
                'timestamp'      => date('Y-m-d H:i:s'),
                'allowedSenders' => $pushedAllowedSenders,
                'blockedSenders' => $pushedBlockedSenders,
                'allowedDomains' => $pushedAllowedDomains,
                'blockedDomains' => $pushedBlockedDomains,
            ];

            $totPushed = count($pushedAllowedSenders) + count($pushedBlockedSenders) + count($pushedAllowedDomains) + count($pushedBlockedDomains);
            setFlash('success', "Exchange Online push completed successfully! Pushed {$totPushed} entries across all 4 tables to Microsoft 365: " . count($pushedAllowedSenders) . " Allowed Senders, " . count($pushedBlockedSenders) . " Blocked Senders, " . count($pushedAllowedDomains) . " Allowed Domains, " . count($pushedBlockedDomains) . " Blocked Domains for policy '{$policyName}'.");
        }
    } else {
        Database::updatePolicySyncStatus($policyName, 'failed', $logMsg);
        Database::logAudit('SYNC', 'SYSTEM', $policyName, 'ALL', "Sync ({$actionParam}) failed: " . substr($logMsg, 0, 200), $user['username']);
        setFlash('warning', "Sync script exited with code {$returnVar}. Output: " . htmlspecialchars(substr($logMsg, 0, 300)));
    }

    header("Location: index.php?policy=" . urlencode($policyName) . "&tab=sync_center");
    exit;
}

// --------------------------------------------------------------------------
// 6. Update Database-Stored LDAP Connection Configuration (eop_ldap_config)
// --------------------------------------------------------------------------
if ($action === 'update_ldap_config') {
    $ldapData = [
        'host'                => trim($_POST['ldap_host'] ?? ''),
        'port'                => (int)($_POST['ldap_port'] ?? 389),
        'protocol'            => trim($_POST['ldap_protocol'] ?? 'ldap'),
        'use_ssl'             => (($_POST['ldap_protocol'] ?? '') === 'ldaps' || !empty($_POST['ldap_use_ssl'])) ? 1 : 0,
        'use_tls'             => (($_POST['ldap_protocol'] ?? '') === 'starttls' || !empty($_POST['ldap_use_tls'])) ? 1 : 0,
        'base_dn'             => trim($_POST['ldap_base_dn'] ?? ''),
        'authorized_group_dn' => trim($_POST['ldap_group_dn'] ?? ''),
        'bind_dn'             => trim($_POST['ldap_bind_dn'] ?? ''),
        'bind_password'       => trim($_POST['ldap_bind_pass'] ?? ''),
        'account_suffix'      => trim($_POST['ldap_account_suffix'] ?? '@corp.example.com'),
        'netbios_domain'      => trim($_POST['ldap_netbios_domain'] ?? 'CORP'),
        'timeout_seconds'     => max(1, (int)($_POST['ldap_timeout'] ?? 5)),
    ];

    if (empty($ldapData['host']) || empty($ldapData['base_dn']) || empty($ldapData['authorized_group_dn'])) {
        setFlash('error', 'LDAP Host, Base DN, and Authorized Group DN cannot be empty.');
    } else {
        $saved = Database::saveLdapConfig($ldapData, $user['username']);
        if ($saved) {
            setFlash('success', 'LDAP connection configuration successfully saved into database table (eop_ldap_config)!');
        } else {
            setFlash('error', 'Failed to update LDAP configuration in database table.');
        }
    }

    header("Location: index.php?policy=" . urlencode($policyName) . "&tab=config_center");
    exit;
}

// --------------------------------------------------------------------------
// 7. Upload & Save EOP PKCS#12 Certificate Bundle (eop_auth_config)
//    Only a full PKCS#12 (.pfx/.p12) bundle is accepted. A bare PEM private key
//    is rejected: Connect-ExchangeOnline needs the certificate and its key
//    together, so a PEM-only record could never authenticate the scheduled pull.
// --------------------------------------------------------------------------
if ($action === 'upload_eop_key') {
    $passphrase = (string)($_POST['key_password'] ?? '');
    $redirect = "Location: index.php?policy=" . urlencode($policyName) . "&tab=config_center";

    if (empty($_FILES['pfx_file']['tmp_name']) || !is_uploaded_file($_FILES['pfx_file']['tmp_name'])) {
        setFlash('error', 'A PKCS#12 (.pfx or .p12) bundle is required. PEM private keys are not accepted.');
        header($redirect);
        exit;
    }

    $upload = $_FILES['pfx_file'];
    if (($upload['error'] ?? UPLOAD_ERR_OK) !== UPLOAD_ERR_OK) {
        setFlash('error', "PKCS#12 upload failed (error code {$upload['error']}).");
        header($redirect);
        exit;
    }

    $pkcs12Raw = file_get_contents($upload['tmp_name']);
    if ($pkcs12Raw === false || $pkcs12Raw === '') {
        setFlash('error', 'The uploaded PKCS#12 file could not be read.');
        header($redirect);
        exit;
    }

    // openssl_pkcs12_read only succeeds on a real bundle, so this also proves the
    // file is a PKCS#12 and not a renamed PEM, CER or P7B.
    $parsed = [];
    if (!openssl_pkcs12_read($pkcs12Raw, $parsed, $passphrase)) {
        $err = openssl_error_string() ?: 'not a valid PKCS#12 bundle';
        setFlash('error', "PKCS#12 validation failed: {$err}. Check that the passphrase is correct and the file really is a .pfx/.p12 bundle.");
        header($redirect);
        exit;
    }

    if (empty($parsed['cert']) || empty($parsed['pkey'])) {
        setFlash('error', 'The PKCS#12 bundle must contain both a certificate and its private key.');
        header($redirect);
        exit;
    }

    $fileName = basename((string)($upload['name'] ?? 'eop-cert.pfx'));

    // The bundle holds the certificate that Connect-ExchangeOnline will import, so
    // its thumbprint is authoritative. Fall back to the typed value only when the
    // fingerprint cannot be derived (openssl_x509_fingerprint is PHP 8.1+).
    $thumbprint = trim($_POST['certificate_thumbprint'] ?? '');
    $derived = function_exists('openssl_x509_fingerprint')
        ? strtoupper(str_replace(':', '', (string)openssl_x509_fingerprint($parsed['cert'], 'sha1')))
        : '';

    if ($derived !== '') {
        if ($thumbprint !== '' && $thumbprint !== $derived) {
            setFlash('warning', "Thumbprint overridden: the form said {$thumbprint} but the uploaded bundle is {$derived}. The bundle is what gets imported, so {$derived} was stored.");
        }
        $thumbprint = $derived;
    }

    if ($thumbprint === '') {
        setFlash('error', 'Certificate Thumbprint could not be determined from the bundle and was not supplied.');
        header($redirect);
        exit;
    }

    $saved = Database::saveEopAuthConfig([
        // private_key is kept populated from the bundle so the record stays usable
        // by anything that still reads the PEM column.
        'private_key'           => trim($parsed['pkey']),
        'pkcs12_bundle'         => base64_encode($pkcs12Raw),
        'key_filename'          => $fileName,
        'password'              => $passphrase,
        'certificate_thumbprint'=> $thumbprint,
        'tenant_id'             => trim($_POST['tenant_id'] ?? ''),
        'client_id'             => trim($_POST['client_id'] ?? ''),
        'organization'          => trim($_POST['organization'] ?? 'corp.example.com'),
        'key_type'              => 'PKCS12_PFX',
    ], $user['username']);

    if ($saved) {
        setFlash(
            'success',
            "PKCS#12 bundle '{$fileName}' (thumbprint {$thumbprint}) was AES-256-GCM encrypted and saved into MariaDB table 'eop_auth_config'."
        );
    } else {
        setFlash('error', 'Failed to save the certificate configuration into database table.');
    }

    header($redirect);
    exit;
}

// --------------------------------------------------------------------------
// 8. Test EOP Private Key Decryption & Signature Verification
// --------------------------------------------------------------------------
// 8. Test EOP Certificate: AES-256-GCM decryption + PKCS#12 readability
// --------------------------------------------------------------------------
if ($action === 'test_eop_key') {
    $activeAuth = Database::getEopAuthConfig();
    if (!$activeAuth) {
        setFlash('error', 'No active certificate record found in MariaDB table eop_auth_config.');
    } elseif (empty($activeAuth['pkcs12_bundle'])) {
        setFlash('error', 'The active record has no PKCS#12 bundle. Upload a .pfx, otherwise the scheduled pull cannot authenticate.');
    } else {
        // getEopAuthConfig already decrypts the stored secrets
        $passphrase = (string)($activeAuth['encrypted_password'] ?? '');
        $blob = base64_decode((string)$activeAuth['pkcs12_bundle'], true);

        if ($blob === false || $blob === '') {
            setFlash('error', 'The decrypted PKCS#12 bundle is not valid base64. The record is corrupt.');
        } else {
            // Verify the same artifact the cron imports, not just the extracted PEM
            $parsed = [];
            if (!openssl_pkcs12_read($blob, $parsed, $passphrase)) {
                $err = openssl_error_string() ?: 'unreadable with the stored passphrase';
                setFlash('error', "Decryption succeeded but the PKCS#12 bundle could not be opened: {$err}. The stored passphrase may not match the bundle.");
            } elseif (empty($parsed['pkey'])) {
                setFlash('error', 'The PKCS#12 bundle contains no private key.');
            } else {
                $details = openssl_pkey_get_details(openssl_pkey_get_private($parsed['pkey']));
                $bits = $details['bits'] ?? 'unknown';
                $type = ($details['type'] === OPENSSL_KEYTYPE_RSA) ? 'RSA' : 'Other';
                setFlash('success', "Certificate verified: AES-256-GCM decryption OK, PKCS#12 opened, key type {$type}, {$bits} bits, thumbprint {$activeAuth['certificate_thumbprint']}. Ready for Exchange Online certificate authentication.");
            }
        }
    }

    header("Location: index.php?policy=" . urlencode($policyName) . "&tab=config_center");
    exit;
}

// --------------------------------------------------------------------------
// 9. Update Default Policy Name (Stored in MariaDB eop_policies & .env)
// --------------------------------------------------------------------------
if ($action === 'update_default_policy') {
    $newPolicyName = trim($_POST['default_policy_name'] ?? '');
    $policyDesc = trim($_POST['policy_description'] ?? '');
    $targetPolicy = $newPolicyName !== '' ? $newPolicyName : $policyName;
    $redirect = "Location: index.php?policy=" . urlencode($targetPolicy) . "&tab=config_center";

    if ($newPolicyName === '') {
        setFlash('error', 'Default policy name cannot be empty.');
        header($redirect);
        exit;
    }

    $updated = Database::setDefaultPolicyName($newPolicyName, $user['username'], $policyDesc);
    if ($updated) {
        $_SESSION['active_policy'] = $newPolicyName;
        setFlash('success', "Default policy successfully updated to '{$newPolicyName}'. Updated in MariaDB (table eop_policies) and environment configuration.");
    } else {
        setFlash('error', "Failed to update default policy name in database.");
    }

    header($redirect);
    exit;
}

// --------------------------------------------------------------------------
// 10. Accept or Deny a Withheld Deletion (empty remote list confirmation)
// --------------------------------------------------------------------------
if ($action === 'resolve_sync_confirmation') {
    $targetPolicy = trim($_POST['target_policy'] ?? $policyName);
    $targetList = trim($_POST['target_list'] ?? '');
    $decision = trim($_POST['decision'] ?? '');
    $redirect = "Location: index.php?policy=" . urlencode($targetPolicy) . "&tab=" . urlencode($targetList);

    $validLists = ['allowed_senders', 'blocked_senders', 'allowed_domains', 'blocked_domains'];
    if ($targetPolicy === '' || !in_array($targetList, $validLists, true)) {
        setFlash('error', 'Invalid confirmation target.');
        header("Location: index.php");
        exit;
    }
    if (!in_array($decision, ['accepted', 'denied'], true)) {
        setFlash('error', 'Invalid decision. Expected accept or deny.');
        header($redirect);
        exit;
    }

    $ok = Database::resolveSyncConfirmation($targetPolicy, $targetList, $decision, $user['username']);

    if (!$ok) {
        setFlash('error', 'That confirmation no longer exists. It may have been cleared by a newer sync run.');
    } elseif ($decision === 'accepted') {
        setFlash('success', "Deletion of the '{$targetList}' entries for policy '{$targetPolicy}' approved. The next cron run will apply it.");
    } else {
        setFlash('success', "Deletion denied. The '{$targetList}' entries for policy '{$targetPolicy}' will be kept.");
    }

    header($redirect);
    exit;
}

header("Location: index.php");
exit;
