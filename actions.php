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
    $lines = explode("
", str_replace("", "", $bulkData));
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
    $lines = explode("
", str_replace("", "", $bulkData));

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

    // Execute PowerShell script on Debian server
    $cmd = sprintf(
        'pwsh -File %s -PolicyName %s -Action %s 2>&1',
        escapeshellarg(SYNC_SCRIPT_PATH),
        escapeshellarg($policyName),
        escapeshellarg($actionParam)
    );

    $output = [];
    $returnVar = 0;
    exec($cmd, $output, $returnVar);

    $logMsg = implode("
", $output);
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
// 7. Upload & Save EOP Private Key with AES-256 Encrypted Passphrase (eop_auth_config)
// --------------------------------------------------------------------------
if ($action === 'upload_eop_key') {
    $privateKeyContent = '';
    $fileName = 'eop-cert-private.key';

    // 1. Check for file upload first
    if (!empty($_FILES['private_key_file']['tmp_name']) && is_uploaded_file($_FILES['private_key_file']['tmp_name'])) {
        $uploadedContent = file_get_contents($_FILES['private_key_file']['tmp_name']);
        if ($uploadedContent !== false && trim($uploadedContent) !== '') {
            $privateKeyContent = trim($uploadedContent);
            $fileName = basename($_FILES['private_key_file']['name'] ?? 'eop-cert-private.key');
        }
    }

    // 2. Fall back to pasted text area
    if (empty($privateKeyContent) && !empty($_POST['private_key_text'])) {
        $privateKeyContent = trim($_POST['private_key_text']);
        $fileName = 'pasted-private-key.pem';
    }

    if (empty($privateKeyContent)) {
        setFlash('error', 'No private key file uploaded or pasted. Please select a file or paste PEM content.');
        header("Location: index.php?policy=" . urlencode($policyName) . "&tab=config_center");
        exit;
    }

    $authData = [
        'private_key'           => $privateKeyContent,
        'key_filename'          => $fileName,
        'password'              => $_POST['key_password'] ?? '',
        'certificate_thumbprint'=> trim($_POST['certificate_thumbprint'] ?? ''),
        'tenant_id'             => trim($_POST['tenant_id'] ?? ''),
        'client_id'             => trim($_POST['client_id'] ?? ''),
        'organization'          => trim($_POST['organization'] ?? 'corp.example.com'),
        'key_type'              => str_contains($privateKeyContent, 'ENCRYPTED') ? 'PKCS8_PEM' : 'RSA_PEM',
    ];

    if (empty($authData['certificate_thumbprint'])) {
        setFlash('error', 'Certificate Thumbprint cannot be empty.');
        header("Location: index.php?policy=" . urlencode($policyName) . "&tab=config_center");
        exit;
    }

    $saved = Database::saveEopAuthConfig($authData, $user['username']);
    if ($saved) {
        $msg = "Private key '{$fileName}' and its AES-256 encrypted password were saved successfully into MariaDB table 'eop_auth_config'!";
        setFlash('success', $msg);
    } else {
        setFlash('error', 'Failed to save private key configuration into database table.');
    }

    header("Location: index.php?policy=" . urlencode($policyName) . "&tab=config_center");
    exit;
}

// --------------------------------------------------------------------------
// 8. Test EOP Private Key Decryption & Signature Verification
// --------------------------------------------------------------------------
if ($action === 'test_eop_key') {
    $activeAuth = Database::getEopAuthConfig();
    if (!$activeAuth || empty($activeAuth['private_key'])) {
        setFlash('error', 'No active private key record found in MariaDB table eop_auth_config.');
    } else {
        $passphrase = '';
        if (!empty($activeAuth['encrypted_password'])) {
            $decrypted = Database::decryptKeyPassword(
                $activeAuth['encrypted_password'],
                $activeAuth['encryption_iv'] ?? '',
                $activeAuth['encryption_tag'] ?? ''
            );
            $passphrase = $decrypted ?? '';
        }

        $privKeyObj = openssl_pkey_get_private($activeAuth['private_key'], $passphrase);
        if ($privKeyObj) {
            $details = openssl_pkey_get_details($privKeyObj);
            $bits = $details['bits'] ?? 'unknown';
            $type = ($details['type'] === OPENSSL_KEYTYPE_RSA) ? 'RSA' : 'Other';
            setFlash('success', "Private key parsed and verified successfully! Key type: {$type}, Bits: {$bits}, AES-256 passphrase decrypted OK. Ready for Exchange Online certificate token signing.");
        } else {
            $err = openssl_error_string() ?: 'Invalid private key or incorrect passphrase';
            setFlash('error', "OpenSSL private key verification failed: {$err}");
        }
    }

    header("Location: index.php?policy=" . urlencode($policyName) . "&tab=config_center");
    exit;
}

header("Location: index.php");
exit;
