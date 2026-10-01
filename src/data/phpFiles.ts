import { AppConfig, PhpFileTemplate } from '../types';

export const defaultAppConfig: AppConfig = {
  dbHost: '192.168.10.50',
  dbPort: 3306,
  dbName: 'eop_antispam_db',
  dbUser: 'eop_app_user',
  dbPass: 'P@ssw0rd_Secure_MariaDB_2026',
  dbCharset: 'utf8mb4',

  ldapHost: 'dc01.corp.example.com',
  ldapPort: 389,
  ldapProtocol: 'ldap', // 'ldap' (port 389, standard plain LDAP), 'ldaps' (port 636), or 'starttls' (port 389)
  ldapUseSsl: false,
  ldapUseTls: false,
  ldapBaseDn: 'DC=corp,DC=example,DC=com',
  ldapGroupDn: 'CN=Exchange-Admins,OU=Security Groups,DC=corp,DC=example,DC=com',
  ldapBindDn: 'CN=svc-eop-web,OU=Service Accounts,DC=corp,DC=example,DC=com',
  ldapBindPass: 'Svc_P@ssw0rd_AD_2026',
  ldapDomain: 'CORP',

  defaultPolicyName: 'Default',
  defaultPolicyGuid: '',
  appTitle: 'EOP Anti-Spam Policy Manager',
  appUrl: 'https://eop.corp.example.com',
  sessionTimeoutMinutes: 60,
  isOnlySiteOnServer: true, // Dedicated server mode (only site on server) by default

  tenantId: '11111111-2222-3333-4444-555555555555',
  clientId: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
  clientSecret: 'YOUR_AZURE_APP_CLIENT_SECRET',
  certificateThumbprint: '9A2F8B3C1D4E5F6A7B8C9D0E1F2A3B4C5D6E7F80',
  keyPassword: 'P@ssphrase_Secure_Cert_2026',
  keyFilename: 'eop-cert-private.key',
  organization: 'corp.example.com',
  privateKeyPem: `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Q3d7v5N8A9zX3lW2k1vJ8qY4t7rU9sP3mF2a1cB6d8e0f1g
2h3i4j5k6l7m8n9o0p1q2r3s4t5u6v7w8x9y0z1A2B3C4D5E6F7G8H9I0J1K2L3M
4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7a8b9c0d1e2f3g4h5i6j7k8l9m0n1o2p3q4r5s
6t7u8v9w0x1y2z3A4B5C6D7E8F9G0H1I2J3K4L5M6N7O8P9Q0R1S2T3U4V5W6X7Y
-----END RSA PRIVATE KEY-----`,

  // Non-LDAP Fallback Admin Credentials (meets 12+ chars, 3 of 4 complexity types: uppercase, lowercase, numbers, symbols)
  fallbackAdminUsername: 'eopadmin',
  fallbackAdminPassword: 'Emergency#Admin2026!',
  fallbackAdminPasswordHash: '$2y$12$eopEmergencyAdminFallbackHashPlaceholder2026XyZ',
  fallbackAdminEnabled: true,
};

export const phpFileTemplates: PhpFileTemplate[] = [
  // 1. config.php
  {
    name: 'config.php',
    path: 'config.php',
    description: 'Central application configuration, remote MariaDB connection details, Active Directory LDAP parameters, and security settings.',
    category: 'config',
    generateContent: (cfg) => `<?php
/**
 * Exchange Online Protection (EOP) Anti-Spam Policy Manager
 * Application Configuration File
 * Environment: Debian Linux / PHP 8.x / Remote MariaDB / Active Directory LDAP
 */

declare(strict_types=1);

// Prevent direct script execution
if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    http_response_code(403);
    exit('Direct access forbidden.');
}

// --------------------------------------------------------------------------
// 1. Session & Security Configuration
// --------------------------------------------------------------------------
ini_set('session.cookie_httponly', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_samesite', 'Lax');
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    ini_set('session.cookie_secure', '1');
}

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Session timeout check (${cfg.sessionTimeoutMinutes} minutes)
$sessionTimeoutSeconds = ${cfg.sessionTimeoutMinutes} * 60;
if (isset($_SESSION['LAST_ACTIVITY']) && (time() - $_SESSION['LAST_ACTIVITY'] > $sessionTimeoutSeconds)) {
    session_unset();
    session_destroy();
    header('Location: login.php?msg=timeout');
    exit;
}
$_SESSION['LAST_ACTIVITY'] = time();

// --------------------------------------------------------------------------
// 1b. Load Environment Variables from .env
// Automatically loads .env written by setup.php or administrator
// --------------------------------------------------------------------------
$envFilePath = __DIR__ . '/.env';
if (file_exists($envFilePath) && is_readable($envFilePath)) {
    $envLines = @file($envFilePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($envLines !== false) {
        foreach ($envLines as $envLine) {
            $envLine = trim($envLine);
            if ($envLine === '' || str_starts_with($envLine, '#') || str_starts_with($envLine, ';')) {
                continue;
            }
            if (strpos($envLine, '=') !== false) {
                [$envKey, $envVal] = explode('=', $envLine, 2);
                $envKey = trim($envKey);
                $envVal = trim($envVal);
                if ((str_starts_with($envVal, '"') && str_ends_with($envVal, '"')) ||
                    (str_starts_with($envVal, "'") && str_ends_with($envVal, "'"))) {
                    $envVal = substr($envVal, 1, -1);
                }
                putenv("{$envKey}={$envVal}");
                $_ENV[$envKey] = $envVal;
                $_SERVER[$envKey] = $envVal;
            }
        }
    }
}

// --------------------------------------------------------------------------
// 2. Remote MariaDB Database Settings
// --------------------------------------------------------------------------
define('DB_HOST', getenv('DB_HOST') ?: '');
define('DB_PORT', (int)(getenv('DB_PORT') ?: 3306));
define('DB_NAME', getenv('DB_NAME') ?: '');
define('DB_USER', getenv('DB_USER') ?: '');
define('DB_PASS', getenv('DB_PASS') ?: '');
define('DB_CHARSET', 'utf8mb4');

// Individual MariaDB tables per list requirement
define('TABLE_ALLOWED_SENDERS', 'eop_allowed_senders');
define('TABLE_BLOCKED_SENDERS', 'eop_blocked_senders');
define('TABLE_ALLOWED_DOMAINS', 'eop_allowed_domains');
define('TABLE_BLOCKED_DOMAINS', 'eop_blocked_domains');
define('TABLE_AUDIT_LOG',       'eop_audit_log');
define('TABLE_POLICIES',        'eop_policies');
define('TABLE_LDAP_CONFIG',     'eop_ldap_config'); // Dedicated database table storing LDAP connection information
define('TABLE_EOP_AUTH_CONFIG', 'eop_auth_config'); // Dedicated database table storing EOP private key & encrypted password
define('TABLE_LOCAL_ADMINS',    'eop_local_admins'); // Dedicated database table storing emergency non-LDAP fallback administrator accounts
define('TABLE_SYNC_CONFIRMATIONS', 'eop_sync_confirmations'); // Withheld deletions awaiting an administrator accept/deny decision

// Master key for AES-256-GCM encryption of stored private key passphrases
define('AUTH_MASTER_ENCRYPTION_KEY', getenv('AUTH_MASTER_ENCRYPTION_KEY') ?: '');

// --------------------------------------------------------------------------
// 3. Microsoft Active Directory (LDAP) Settings
// --------------------------------------------------------------------------
// NOTE: LDAP connection settings are stored in and dynamically retrieved from
// the MariaDB database table 'eop_ldap_config' via Database::getLdapConfig().
// Standard LDAP (port 389) is supported by default and LDAPS is NOT required.
// Set LDAP_PROTOCOL to 'ldap' (port 389 plain), 'ldaps' (port 636), or 'starttls' (port 389 with TLS).
define('LDAP_HOST', getenv('LDAP_HOST') ?: '');
define('LDAP_PORT', (int)(getenv('LDAP_PORT') ?: 389));
define('LDAP_PROTOCOL', getenv('LDAP_PROTOCOL') ?: 'ldap');
define('LDAP_USE_SSL', LDAP_PROTOCOL === 'ldaps'); // LDAPS on port 636 (optional, not required)
define('LDAP_USE_TLS', LDAP_PROTOCOL === 'starttls'); // StartTLS on port 389 (optional, not required)
define('LDAP_BASE_DN', getenv('LDAP_BASE_DN') ?: '');

// Mandatory Security Group Distinguished Name (Group DN) for authorization
define('LDAP_AUTHORIZED_GROUP_DN', getenv('LDAP_AUTHORIZED_GROUP_DN') ?: '');

// Active Directory Service Account for initial user & group resolution (optional, recommended)
define('LDAP_BIND_DN', getenv('LDAP_BIND_DN') ?: '');
define('LDAP_BIND_PASSWORD', getenv('LDAP_BIND_PASSWORD') ?: '');
define('LDAP_ACCOUNT_SUFFIX', getenv('LDAP_ACCOUNT_SUFFIX') ?: '');
define('LDAP_NETBIOS_DOMAIN', getenv('LDAP_DOMAIN') ?: '');

// --------------------------------------------------------------------------
// 3b. Emergency Non-LDAP Fallback Administrator Account
// Allows administrative access when Active Directory Domain Controller connection fails
// --------------------------------------------------------------------------
define('FALLBACK_ADMIN_ENABLED', in_array(strtolower((string)getenv('FALLBACK_ADMIN_ENABLED')), ['1', 'true', 'yes'], true));
define('FALLBACK_ADMIN_USERNAME', getenv('FALLBACK_ADMIN_USER') ?: '');
define('FALLBACK_ADMIN_PASSWORD_HASH', getenv('FALLBACK_ADMIN_PASSWORD_HASH') ?: '');

// --------------------------------------------------------------------------
// 4. Exchange Online Protection (EOP) Policy Settings
// --------------------------------------------------------------------------
define('DEFAULT_POLICY_NAME', getenv('EOP_POLICY_NAME') ?: '');
// Exchange GUID of the policy named above, resolved by the setup wizard when the
// policy was supplied as a GUID. Empty when it was never confirmed.
define('DEFAULT_POLICY_GUID', getenv('EOP_POLICY_GUID') ?: '');
define('APP_TITLE', 'EOP Anti-Spam Policy Manager');
define('APP_URL', getenv('APP_URL') ?: '');

// Available Anti-Spam policies to manage
$GLOBALS['AVAILABLE_POLICIES'] = [
    'Default' => 'Default Inbound Anti-Spam Policy (Applied to all recipients)',
    'Strict Anti-Spam Policy'  => 'Strict Security Baseline (Targeted VIPs & High Value Mailboxes)',
    'Executive Inbound Policy' => 'Custom Executive Mailbox Inbound Filtering',
    'Custom Inbound Filter'    => 'Custom Departmental Filter Policy'
];

// --------------------------------------------------------------------------
// 5. Microsoft 365 / Exchange Online Protection (EOP) Private Key & Certificate Auth
// --------------------------------------------------------------------------
// NOTE: EOP private key and encrypted passphrase are stored in and dynamically retrieved
// from the MariaDB database table 'eop_auth_config' via Database::getEopAuthConfig().
define('M365_TENANT_ID', getenv('M365_TENANT_ID') ?: '');
define('M365_CLIENT_ID', getenv('M365_CLIENT_ID') ?: '');
define('M365_CERT_THUMBPRINT', getenv('M365_CERT_THUMBPRINT') ?: '');
define('M365_ORGANIZATION', getenv('M365_ORGANIZATION') ?: '');
define('M365_CLIENT_SECRET', getenv('M365_CLIENT_SECRET') ?: '');
define('SYNC_SCRIPT_PATH', __DIR__ . '/sync-exchange.ps1');
`
  },

  // 2. database.php
  {
    name: 'database.php',
    path: 'database.php',
    description: 'MariaDB PDO database connector class with prepared statements, connection pooling, and CRUD operations for the 4 individual list tables.',
    category: 'core',
    generateContent: () => `<?php
/**
 * Remote MariaDB Database Handler
 * Manages individual tables per list:
 * - eop_allowed_senders
 * - eop_blocked_senders
 * - eop_allowed_domains
 * - eop_blocked_domains
 */

declare(strict_types=1);

if (!file_exists(__DIR__ . '/config.php')) {
    if (php_sapi_name() !== 'cli' && !headers_sent()) {
        header('Location: setup.php');
        exit;
    }
} else {
    require_once __DIR__ . '/config.php';
}

require_once __DIR__ . '/crypto.php';

// Initial access check: If setup is incomplete or database is not configured, redirect web visitors to setup wizard
if (php_sapi_name() !== 'cli' && !headers_sent()) {
    $currentScript = basename($_SERVER['SCRIPT_FILENAME'] ?? '');
    if ($currentScript !== 'setup.php') {
        $isDbHostEmpty = !defined('DB_HOST') || trim((string)DB_HOST) === '';
        $isDbNameEmpty = !defined('DB_NAME') || trim((string)DB_NAME) === '';
        $isSetupUnlocked = !file_exists(__DIR__ . '/installed.lock');
        if ($isDbHostEmpty || $isDbNameEmpty || $isSetupUnlocked) {
            header('Location: setup.php');
            exit;
        }
    }
}

class Database {
    private static ?PDO $instance = null;

    /**
     * Check if database credentials and host are configured
     */
    public static function isConfigured(): bool {
        return defined('DB_HOST') && trim((string)DB_HOST) !== '' &&
               defined('DB_NAME') && trim((string)DB_NAME) !== '';
    }

    /**
     * Check if core database tables are initialized and reachable
     */
    public static function isInitialized(): bool {
        if (!self::isConfigured()) {
            return false;
        }

        try {
            $pdo = self::getConnection(false);
            if (!$pdo) {
                return false;
            }
            $targetTable = defined('TABLE_ALLOWED_SENDERS') ? TABLE_ALLOWED_SENDERS : 'eop_allowed_senders';
            $stmt = $pdo->query("SELECT 1 FROM \`{$targetTable}\` LIMIT 1");
            return ($stmt !== false);
        } catch (Throwable $e) {
            try {
                $targetTable = defined('TABLE_ALLOWED_SENDERS') ? TABLE_ALLOWED_SENDERS : 'eop_allowed_senders';
                $check = $pdo->query("SHOW TABLES LIKE " . $pdo->quote($targetTable));
                return ($check && $check->fetchColumn() !== false);
            } catch (Throwable $ex) {
                return false;
            }
        }
    }

    /**
     * Get singleton PDO connection to Remote MariaDB server
     */
    public static function getConnection(bool $dieOnError = true): ?PDO {
        if (!self::isConfigured()) {
            if (php_sapi_name() !== 'cli' && !headers_sent() && !file_exists(__DIR__ . '/installed.lock')) {
                header('Location: setup.php');
                exit;
            }
            if ($dieOnError) {
                die('<div style="font-family:sans-serif;padding:2rem;color:#721c24;background:#f8d7da;border:1px solid #f5c6cb;border-radius:6px;max-width:650px;margin:2rem auto;">' .
                    '<h3>Database Not Configured</h3>' .
                    '<p>MariaDB database credentials have not been configured yet.</p>' .
                    '<p><a href="setup.php" style="display:inline-block;padding:8px 16px;background:#0d6efd;color:#fff;text-decoration:none;border-radius:4px;font-size:14px;">Launch Setup Wizard &rarr;</a></p>' .
                    '</div>');
            }
            return null;
        }

        if (self::$instance === null) {
            $dsn = sprintf(
                'mysql:host=%s;port=%d;dbname=%s;charset=%s',
                DB_HOST,
                DB_PORT,
                DB_NAME,
                DB_CHARSET
            );

            $options = [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
                PDO::ATTR_TIMEOUT            => 5,
            ];

            try {
                self::$instance = new PDO($dsn, DB_USER, DB_PASS, $options);
            } catch (PDOException $e) {
                error_log('[MariaDB Error] Connection failed: ' . $e->getMessage());
                if ($dieOnError) {
                    die('<div style="font-family:sans-serif;padding:2rem;color:#721c24;background:#f8d7da;border:1px solid #f5c6cb;border-radius:6px;max-width:650px;margin:2rem auto;">' .
                        '<h3>Database Connection Error</h3>' .
                        '<p>Could not connect to remote MariaDB host <code>' . htmlspecialchars((string)DB_HOST) . ':' . DB_PORT . '</code>.</p>' .
                        '<p><small>Check network route, MariaDB user grants, and credentials in <code>config.php</code> or <code>.env</code>.</small></p>' .
                        '<p style="margin-top:1rem;"><a href="setup.php" style="display:inline-block;padding:6px 12px;background:#0d6efd;color:#fff;text-decoration:none;border-radius:4px;font-size:12px;">Launch Setup Wizard &rarr;</a></p>' .
                        '</div>');
                }
                return null;
            }
        }
        return self::$instance;
    }

    /**
     * Resolve table name based on list type
     */
    public static function getTableName(string $listType): string {
        return match ($listType) {
            'allowed_senders' => TABLE_ALLOWED_SENDERS,
            'blocked_senders' => TABLE_BLOCKED_SENDERS,
            'allowed_domains' => TABLE_ALLOWED_DOMAINS,
            'blocked_domains' => TABLE_BLOCKED_DOMAINS,
            default           => throw new InvalidArgumentException("Invalid list type: {$listType}")
        };
    }

    /**
     * Resolve column name for item value (sender_email vs domain_name)
     */
    public static function getValueColumn(string $listType): string {
        return match ($listType) {
            'allowed_senders', 'blocked_senders' => 'sender_email',
            'allowed_domains', 'blocked_domains' => 'domain_name',
            default => throw new InvalidArgumentException("Invalid list type: {$listType}")
        };
    }

    /**
     * Fetch list entries for a specific policy from its dedicated table
     */
    public static function getListItems(string $listType, string $policyName, string $search = '', int $limit = 50, int $offset = 0): array {
        try {
            $pdo = self::getConnection();
            $table = self::getTableName($listType);
            $col = self::getValueColumn($listType);

            if ($search !== '') {
                $sql = "SELECT id, policy_name, {$col} AS item_value, note, added_by, created_at, updated_at
                        FROM {$table}
                        WHERE policy_name = :policy AND ({$col} LIKE :search OR note LIKE :search2)
                        ORDER BY id DESC LIMIT :limit OFFSET :offset";
                $stmt = $pdo->prepare($sql);
                $searchParam = '%' . $search . '%';
                $stmt->bindValue(':policy', $policyName, PDO::PARAM_STR);
                $stmt->bindValue(':search', $searchParam, PDO::PARAM_STR);
                $stmt->bindValue(':search2', $searchParam, PDO::PARAM_STR);
                $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
                $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
            } else {
                $sql = "SELECT id, policy_name, {$col} AS item_value, note, added_by, created_at, updated_at
                        FROM {$table}
                        WHERE policy_name = :policy
                        ORDER BY id DESC LIMIT :limit OFFSET :offset";
                $stmt = $pdo->prepare($sql);
                $stmt->bindValue(':policy', $policyName, PDO::PARAM_STR);
                $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
                $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
            }

            $stmt->execute();
            return $stmt->fetchAll();
        } catch (Throwable $e) {
            error_log('[Database::getListItems Error] ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Count items in a specific individual table for a policy
     */
    public static function countListItems(string $listType, string $policyName, string $search = ''): int {
        try {
            $pdo = self::getConnection();
            $table = self::getTableName($listType);
            $col = self::getValueColumn($listType);

            if ($search !== '') {
                $sql = "SELECT COUNT(*) FROM {$table} WHERE policy_name = :policy AND ({$col} LIKE :search OR note LIKE :search2)";
                $stmt = $pdo->prepare($sql);
                $searchParam = '%' . $search . '%';
                $stmt->execute([':policy' => $policyName, ':search' => $searchParam, ':search2' => $searchParam]);
            } else {
                $sql = "SELECT COUNT(*) FROM {$table} WHERE policy_name = :policy";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([':policy' => $policyName]);
            }
            return (int)$stmt->fetchColumn();
        } catch (Throwable $e) {
            error_log('[Database::countListItems Error] ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Check if an item already exists in a dedicated table for a policy (duplicate check)
     */
    public static function itemExists(string $listType, string $policyName, string $value): bool {
        try {
            $pdo = self::getConnection();
            $table = self::getTableName($listType);
            $col = self::getValueColumn($listType);
            $value = strtolower(trim($value));

            $stmt = $pdo->prepare("SELECT 1 FROM {$table} WHERE policy_name = :policy AND {$col} = :val LIMIT 1");
            $stmt->execute([':policy' => $policyName, ':val' => $value]);
            return (bool)$stmt->fetchColumn();
        } catch (Throwable $e) {
            error_log('[Database::itemExists Error] ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Add single item to the dedicated table (rejects duplicate entries)
     */
    public static function addItem(string $listType, string $policyName, string $value, string $note, string $addedBy): bool {
        $value = strtolower(trim($value));

        // Strict duplicate check: do not add duplicate entries
        if (self::itemExists($listType, $policyName, $value)) {
            return false;
        }

        $pdo = self::getConnection();
        $table = self::getTableName($listType);
        $col = self::getValueColumn($listType);

        $sql = "INSERT INTO {$table} (policy_name, {$col}, note, added_by, created_at, updated_at)
                VALUES (:policy, :val, :note, :user, NOW(), NOW())";
        
        $stmt = $pdo->prepare($sql);
        $success = $stmt->execute([
            ':policy' => $policyName,
            ':val'    => $value,
            ':note'   => trim($note),
            ':user'   => $addedBy
        ]);

        if ($success) {
            self::logAudit('ADD', $listType, $policyName, $value, "Added to {$table} by {$addedBy}", $addedBy);
        }
        return $success;
    }

    /**
     * Delete item by ID from its dedicated table
     */
    public static function deleteItem(string $listType, int $id, string $deletedBy): bool {
        $pdo = self::getConnection();
        $table = self::getTableName($listType);
        $col = self::getValueColumn($listType);

        // Fetch item first for audit log
        $fetchStmt = $pdo->prepare("SELECT policy_name, {$col} AS item_value FROM {$table} WHERE id = :id");
        $fetchStmt->execute([':id' => $id]);
        $row = $fetchStmt->fetch();

        if (!$row) {
            return false;
        }

        $stmt = $pdo->prepare("DELETE FROM {$table} WHERE id = :id");
        $deleted = $stmt->execute([':id' => $id]);

        if ($deleted) {
            self::logAudit('REMOVE', $listType, $row['policy_name'], $row['item_value'], "Removed from {$table} by {$deletedBy}", $deletedBy);
        }
        return $deleted;
    }

    /**
     * Bulk insert items into dedicated table
     */
    public static function bulkInsert(string $listType, string $policyName, array $items, string $addedBy): array {
        $pdo = self::getConnection();
        $table = self::getTableName($listType);
        $col = self::getValueColumn($listType);

        $inserted = 0;
        $skipped = 0;
        $errors = [];

        $stmt = $pdo->prepare("INSERT IGNORE INTO {$table} (policy_name, {$col}, note, added_by, created_at, updated_at) 
                               VALUES (:policy, :val, :note, :user, NOW(), NOW())");

        foreach ($items as $entry) {
            $val = strtolower(trim($entry['value']));
            $note = trim($entry['note'] ?? '');

            if (empty($val)) {
                $skipped++;
                continue;
            }

            try {
                $stmt->execute([
                    ':policy' => $policyName,
                    ':val'    => $val,
                    ':note'   => $note,
                    ':user'   => $addedBy
                ]);
                if ($stmt->rowCount() > 0) {
                    $inserted++;
                } else {
                    $skipped++; // Already exists (IGNORE)
                }
            } catch (Exception $e) {
                $errors[] = "Failed on {$val}: " . $e->getMessage();
                $skipped++;
            }
        }

        if ($inserted > 0) {
            self::logAudit('ADD', $listType, $policyName, "{$inserted} items", "Bulk import of {$inserted} items into {$table}", $addedBy);
        }

        return ['inserted' => $inserted, 'skipped' => $skipped, 'errors' => $errors];
    }

    /**
     * Fetch all raw items for Exchange Online sync
     */
    public static function getAllItemsForSync(string $listType, string $policyName): array {
        $pdo = self::getConnection();
        $table = self::getTableName($listType);
        $col = self::getValueColumn($listType);

        $stmt = $pdo->prepare("SELECT {$col} AS item_value FROM {$table} WHERE policy_name = :policy ORDER BY {$col} ASC");
        $stmt->execute([':policy' => $policyName]);
        return $stmt->fetchAll(PDO::FETCH_COLUMN);
    }

    /**
     * Flattens a decoded remote list into plain strings.
     *
     * A JSON array of strings is returned as-is. An element that is itself an
     * array or object is unwrapped one level so a nested collection from the
     * PowerShell side does not reach the comparator as a non-scalar. Returns null
     * when an element cannot be reduced to a string, which callers treat as a
     * malformed payload.
     */
    private static function flattenRemoteValues(array $remoteValues): ?array {
        $flat = [];
        foreach ($remoteValues as $value) {
            if (is_array($value)) {
                foreach ($value as $inner) {
                    if (is_array($inner) || is_object($inner)) {
                        return null;
                    }
                    $flat[] = (string)$inner;
                }
                continue;
            }
            if (is_object($value)) {
                return null;
            }
            if (is_bool($value)) {
                return null;
            }
            $flat[] = (string)$value;
        }
        return $flat;
    }

    /**
     * Reconcile a local list against the authoritative remote list from Exchange Online.
     * Inserts remote entries missing locally and removes local rows that no longer exist
     * in Exchange Online. Every removal is audit logged.
     *
     * The remote payload is flattened defensively: a list element that is itself an
     * array means the producer emitted a nested collection, and a bare
     * (string) cast on it would yield the literal "Array" — which would collapse
     * every entry onto one key and make the whole list look absent remotely,
     * deleting every local row. Such entries are unwrapped; anything that is
     * still not a scalar afterwards aborts the reconcile instead.
     */
    public static function reconcileListWithRemote(string $listType, string $policyName, array $remoteValues, string $actor): array {
        $pdo = self::getConnection();
        $table = self::getTableName($listType);
        $col = self::getValueColumn($listType);

        $remote = [];
        $flattened = self::flattenRemoteValues($remoteValues);
        if ($flattened === null) {
            throw new RuntimeException(
                "Remote {$listType} payload for policy '{$policyName}' contained nested or non-scalar entries. "
                . 'Refusing to reconcile: a malformed payload would make every local row look absent from Exchange Online.'
            );
        }
        foreach ($flattened as $value) {
            $normalized = strtolower(trim($value));
            if ($normalized !== '') {
                $remote[$normalized] = true;
            }
        }

        $select = $pdo->prepare("SELECT id, {$col} AS item_value FROM {$table} WHERE policy_name = :policy");
        $select->execute([':policy' => $policyName]);
        $localRows = $select->fetchAll(PDO::FETCH_ASSOC);

        $candidates = [];
        foreach (array_keys($remote) as $value) {
            $candidates[] = ['value' => $value, 'note' => 'Pulled from Exchange Online'];
        }
        $insertResult = self::bulkInsert($listType, $policyName, $candidates, $actor);

        $delete = $pdo->prepare("DELETE FROM {$table} WHERE id = :id AND policy_name = :policy");
        $removed = [];
        $notRemoved = [];
        foreach ($localRows as $row) {
            $normalized = strtolower(trim((string)$row['item_value']));
            if (!isset($remote[$normalized])) {
                $delete->execute([':id' => (int)$row['id'], ':policy' => $policyName]);
                // Only count what the database actually removed. Previously every row
                // present in $localRows was reported as deleted whether or not the
                // DELETE matched, so a row that was already gone produced a "removed"
                // count that the table then contradicted.
                if ($delete->rowCount() > 0) {
                    $removed[] = $row['item_value'];
                } else {
                    $notRemoved[] = $row['item_value'];
                }
            }
        }

        if ($notRemoved) {
            // Surfaced rather than swallowed: a non-zero count here means the local
            // table and the reconciler disagree, which is worth seeing in the cron log.
            self::logAudit('SYNC', $listType, $policyName, count($notRemoved) . ' items', 'Absent from Exchange Online but the delete matched no row: ' . implode(', ', array_slice($notRemoved, 0, 25)), $actor);
        }

        if ($removed) {
            // 'REMOVE', not 'DELETE': eop_audit_log.action is an ENUM of
            // ADD/REMOVE/UPDATE/SYNC/LOGIN/LOGOUT. Passing 'DELETE' made this
            // INSERT fail under strict mode, and logAudit swallows the error, so
            // every deletion the pull performed was invisible in the audit trail.
            self::logAudit('REMOVE', $listType, $policyName, count($removed) . ' items', 'Removed by cron pull (absent from Exchange Online): ' . implode(', ', array_slice($removed, 0, 25)), $actor);
        }

        return [
            'remote'    => count($remote),
            'inserted'  => $insertResult['inserted'],
            'removed'   => count($removed),
            'unchanged' => count($localRows) - count($removed),
            'errors'    => $insertResult['errors'],
            'removed_values' => $removed,
            'not_removed_values' => $notRemoved,
        ];
    }

    /**
     * Resolve the table backing sync confirmations. config.php is regenerated by
     * the setup wizard, so an existing install will not define the new constant;
     * fall back to the literal name rather than raising an Error.
     */
    private static function confirmationsTable(): string {
        return defined('TABLE_SYNC_CONFIRMATIONS') ? TABLE_SYNC_CONFIRMATIONS : 'eop_sync_confirmations';
    }

    /**
     * Create the confirmation table on demand. The setup wizard creates it for
     * fresh installs, but the wizard locks after first run, so an existing
     * database has to be able to acquire it without operator intervention.
     *
     * CREATE TABLE IF NOT EXISTS is a no-op when the table exists but still
     * requires the CREATE privilege, so a deployment whose app user cannot run
     * DDL would otherwise break every sync. Failure is swallowed and only
     * attempted once: the individual accessors already degrade, and a guard with
     * no readable confirmation row always falls through to "prompted", which
     * withholds the deletion. That is the safe direction to fail in.
     */
    private static function ensureConfirmationsTable(): void {
        static $ensured = false;
        if ($ensured) {
            return;
        }
        $ensured = true;
        try {
            $table = self::confirmationsTable();
            self::getConnection()->exec("CREATE TABLE IF NOT EXISTS \`{$table}\` (
                \`id\` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                \`policy_name\` VARCHAR(255) NOT NULL,
                \`list_type\` VARCHAR(50) NOT NULL,
                \`local_count\` INT UNSIGNED NOT NULL DEFAULT 0,
                \`remote_count\` INT UNSIGNED NOT NULL DEFAULT 0,
                \`pending_values\` MEDIUMTEXT NULL,
                \`values_truncated\` TINYINT(1) NOT NULL DEFAULT 0,
                \`status\` ENUM('pending', 'accepted', 'denied', 'applied') NOT NULL DEFAULT 'pending',
                \`requested_by\` VARCHAR(100) NOT NULL DEFAULT 'CRON_DAEMON',
                \`decided_by\` VARCHAR(100) NULL,
                \`decided_at\` DATETIME NULL,
                \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                \`updated_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY \`uniq_policy_list\` (\`policy_name\`, \`list_type\`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        } catch (Throwable $e) {
            error_log('[Database::ensureConfirmationsTable] ' . $e->getMessage());
        }
    }

    /**
     * Fetch the outstanding or decided confirmation for a policy/list, if any.
     */
    public static function getSyncConfirmation(string $policyName, string $listType): ?array {
        try {
            self::ensureConfirmationsTable();
            $stmt = self::getConnection()->prepare(
                'SELECT * FROM ' . self::confirmationsTable() . ' WHERE policy_name = :policy AND list_type = :list LIMIT 1'
            );
            $stmt->execute([':policy' => $policyName, ':list' => $listType]);
            $row = $stmt->fetch();
            return $row ?: null;
        } catch (Throwable $e) {
            error_log('[Database::getSyncConfirmation Error] ' . $e->getMessage());
            return null;
        }
    }

    /**
     * All confirmations, optionally narrowed to one policy. Used by the UI.
     */
    public static function getSyncConfirmations(?string $policyName = null): array {
        try {
            self::ensureConfirmationsTable();
            if ($policyName !== null) {
                $stmt = self::getConnection()->prepare(
                    'SELECT * FROM ' . self::confirmationsTable() . ' WHERE policy_name = :policy ORDER BY list_type ASC'
                );
                $stmt->execute([':policy' => $policyName]);
            } else {
                $stmt = self::getConnection()->query(
                    'SELECT * FROM ' . self::confirmationsTable() . ' ORDER BY policy_name ASC, list_type ASC'
                );
            }
            return $stmt ? $stmt->fetchAll() : [];
        } catch (Throwable $e) {
            error_log('[Database::getSyncConfirmations Error] ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Record (or refresh) the values at risk for a policy/list, resetting the
     * request to 'pending' so the UI shows the current local state.
     */
    public static function recordSyncConfirmation(string $policyName, string $listType, int $localCount, array $values, bool $truncated, string $actor): void {
        try {
            self::ensureConfirmationsTable();
            $stmt = self::getConnection()->prepare(
                'INSERT INTO ' . self::confirmationsTable() . '
                 (policy_name, list_type, local_count, remote_count, pending_values, values_truncated, status, requested_by)
                 VALUES (:policy, :list, :local, 0, :values, :trunc, \\'pending\\', :actor)
                 ON DUPLICATE KEY UPDATE
                    \`local_count\` = VALUES(\`local_count\`),
                    \`remote_count\` = 0,
                    \`pending_values\` = VALUES(\`pending_values\`),
                    \`values_truncated\` = VALUES(\`values_truncated\`),
                    \`status\` = \\'pending\\',
                    \`requested_by\` = VALUES(\`requested_by\`),
                    \`decided_by\` = NULL,
                    \`decided_at\` = NULL,
                    \`updated_at\` = NOW()'
            );
            $stmt->execute([
                ':policy' => $policyName,
                ':list' => $listType,
                ':local' => $localCount,
                ':values' => json_encode(array_values($values)),
                ':trunc' => $truncated ? 1 : 0,
                ':actor' => $actor,
            ]);
        } catch (Throwable $e) {
            error_log('[Database::recordSyncConfirmation Error] ' . $e->getMessage());
        }
    }

    /**
     * Record an administrator's accept/deny decision. The decision is stored, not
     * acted on: cron-sync.php consumes it on its next run for this policy.
     */
    public static function resolveSyncConfirmation(string $policyName, string $listType, string $decision, string $actor): bool {
        if (!in_array($decision, ['accepted', 'denied'], true)) {
            return false;
        }
        try {
            self::ensureConfirmationsTable();
            $stmt = self::getConnection()->prepare(
                'UPDATE ' . self::confirmationsTable() . '
                 SET \`status\` = :status, \`decided_by\` = :actor, \`decided_at\` = NOW()
                 WHERE policy_name = :policy AND list_type = :list'
            );
            $stmt->execute([
                ':status' => $decision,
                ':actor' => $actor,
                ':policy' => $policyName,
                ':list' => $listType,
            ]);
            if ($stmt->rowCount() === 0) {
                return false;
            }

            // 'DELETE' is not a member of the eop_audit_log action ENUM, so the
            // decision is logged as an UPDATE to stay within the existing schema.
            self::logAudit(
                'UPDATE',
                $listType,
                $policyName,
                'SYNC_CONFIRMATION',
                "Empty remote list: deletion of local entries {$decision} by {$actor}. "
                . ($decision === 'accepted' ? 'The next cron run will apply it.' : 'Local entries will be kept.'),
                $actor
            );
            return true;
        } catch (Throwable $e) {
            error_log('[Database::resolveSyncConfirmation Error] ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Drop a confirmation once the hazard no longer applies.
     */
    public static function clearSyncConfirmation(string $policyName, string $listType): void {
        try {
            self::ensureConfirmationsTable();
            $stmt = self::getConnection()->prepare(
                'DELETE FROM ' . self::confirmationsTable() . ' WHERE policy_name = :policy AND list_type = :list'
            );
            $stmt->execute([':policy' => $policyName, ':list' => $listType]);
        } catch (Throwable $e) {
            error_log('[Database::clearSyncConfirmation Error] ' . $e->getMessage());
        }
    }

    /**
     * Delete exactly the values captured in a confirmation. Deleting the captured
     * set rather than "everything currently present" means rows added after the
     * administrator approved are not silently destroyed.
     */
    private static function applyConfirmedDeletion(string $listType, string $policyName, array $values, string $actor): array {
        $pdo = self::getConnection();
        $table = self::getTableName($listType);
        $col = self::getValueColumn($listType);

        $delete = $pdo->prepare("DELETE FROM {$table} WHERE {$col} = :val AND policy_name = :policy");
        $removed = [];
        $errors = [];
        foreach ($values as $value) {
            try {
                $delete->execute([':val' => $value, ':policy' => $policyName]);
                if ($delete->rowCount() > 0) {
                    $removed[] = $value;
                }
            } catch (Throwable $e) {
                $errors[] = "Failed to remove {$value}: " . $e->getMessage();
            }
        }

        if ($removed) {
            // 'REMOVE' is a member of the eop_audit_log action ENUM; 'DELETE' is
            // not, and the failed INSERT was swallowed by logAudit.
            self::logAudit(
                'REMOVE',
                $listType,
                $policyName,
                count($removed) . ' items',
                'Removed by cron pull after administrator accepted deletion of an empty remote list: ' . implode(', ', array_slice($removed, 0, 25)),
                $actor
            );
        }

        return ['removed' => count($removed), 'removed_values' => $removed, 'errors' => $errors];
    }

    /**
     * A cheap fingerprint of everything the UI renders for a policy, used to
     * detect that a scheduled sync changed the data underneath an open page.
     *
     * The counts and the max(updated_at) are aggregate-only, so this stays cheap
     * even with a large table, and it moves for every mutation the cron performs:
     * a pull inserts, a reconcile deletes, both bump updated_at. The policy row
     * contributes its own sync metadata, so a run that changed nothing but its
     * status still registers.
     *
     * Returns a string rather than a bool so the caller can compare tokens
     * directly and skip the reload when nothing moved.
     */
    public static function getDataVersion(string $policyName): string {
        try {
            $pdo = self::getConnection();
            $parts = [];

            foreach (['allowed_senders', 'blocked_senders', 'allowed_domains', 'blocked_domains'] as $listType) {
                $table = self::getTableName($listType);
                $stmt = $pdo->prepare("SELECT COUNT(*) AS c, COALESCE(MAX(updated_at), '') AS u FROM {$table} WHERE policy_name = :policy");
                $stmt->execute([':policy' => $policyName]);
                $row = $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
                $parts[] = $listType . ':' . ($row['c'] ?? 0) . ':' . ($row['u'] ?? '');
            }

            $polStmt = $pdo->prepare("SELECT COALESCE(last_synced_at, '') AS l, COALESCE(sync_status, '') AS s, COALESCE(updated_at, '') AS u
                                      FROM " . TABLE_POLICIES . " WHERE policy_name = :policy");
            $polStmt->execute([':policy' => $policyName]);
            $pol = $polStmt->fetch(PDO::FETCH_ASSOC) ?: [];
            $parts[] = 'policy:' . ($pol['l'] ?? '') . ':' . ($pol['s'] ?? '') . ':' . ($pol['u'] ?? '');

            // Outstanding deletion confirmations are rendered as a banner, so a
            // change there has to count as a change too.
            try {
                self::ensureConfirmationsTable();
                $confStmt = $pdo->prepare("SELECT COUNT(*) AS c FROM " . self::confirmationsTable() . "
                                           WHERE policy_name = :policy AND status IN ('pending', 'accepted', 'denied')");
                $confStmt->execute([':policy' => $policyName]);
                $parts[] = 'confirm:' . (int)$confStmt->fetchColumn();
            } catch (Throwable $e) {
                $parts[] = 'confirm:na';
            }

            return implode('|', $parts);
        } catch (Throwable $e) {
            error_log('[Database::getDataVersion Error] ' . $e->getMessage());
            return 'error';
        }
    }

    /**
     * Normalised local values for a policy/list, in the same casing the
     * reconciler compares against.
     */
    private static function fetchNormalizedValues(string $listType, string $policyName): array {
        $pdo = self::getConnection();
        $table = self::getTableName($listType);
        $col = self::getValueColumn($listType);
        $stmt = $pdo->prepare("SELECT {$col} AS item_value FROM {$table} WHERE policy_name = :policy");
        $stmt->execute([':policy' => $policyName]);

        $values = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $normalized = strtolower(trim((string)$row['item_value']));
            if ($normalized !== '') {
                $values[$normalized] = $normalized;
            }
        }
        return $values;
    }

    /**
     * Reconcile a pulled list, refusing to empty a populated local list without an
     * explicit administrator decision.
     *
     * An empty remote list is indistinguishable from a policy that genuinely has
     * no entries, and the reconciler deletes every local row absent from the
     * remote set. A single bad pull would therefore wipe the list. So when the
     * remote list is empty and local rows exist, the deletion is held back and a
     * confirmation is raised for the UI instead. The administrator's accept/deny
     * is stored and consumed here on a later run.
     *
     * The returned array is the normal reconcile result plus:
     *   guard        - none | prompted | awaiting_decision | denied | applied
     *   confirmation - the confirmation row when one is outstanding
     */
    public static function reconcileListWithRemoteGuarded(string $listType, string $policyName, array $remoteValues, string $actor): array {
        self::ensureConfirmationsTable();

        $flattened = self::flattenRemoteValues($remoteValues);
        if ($flattened === null) {
            throw new RuntimeException(
                "Remote {$listType} payload for policy '{$policyName}' contained nested or non-scalar entries. "
                . 'Refusing to reconcile: a malformed payload would make every local row look absent from Exchange Online.'
            );
        }

        $remoteSet = [];
        foreach ($flattened as $value) {
            $normalized = strtolower(trim($value));
            if ($normalized !== '') {
                $remoteSet[$normalized] = true;
            }
        }
        $remoteCount = count($remoteSet);
        $existing = self::getSyncConfirmation($policyName, $listType);

        $passThrough = static function (array $result, string $guard, ?array $confirmation = null): array {
            $result['guard'] = $guard;
            $result['confirmation'] = $confirmation;
            return $result;
        };

        // Remote has data: normal reconcile. Any outstanding confirmation is stale.
        if ($remoteCount > 0) {
            if ($existing !== null) {
                self::clearSyncConfirmation($policyName, $listType);
            }
            return $passThrough(self::reconcileListWithRemote($listType, $policyName, $remoteValues, $actor), 'none');
        }

        $localValues = self::fetchNormalizedValues($listType, $policyName);
        $localCount = count($localValues);

        // Empty remote and empty local: nothing is at risk.
        if ($localCount === 0) {
            if ($existing !== null) {
                self::clearSyncConfirmation($policyName, $listType);
            }
            return $passThrough(self::reconcileListWithRemote($listType, $policyName, [], $actor), 'none');
        }

        $skippedResult = static function (string $guard, ?array $confirmation) use ($localCount, $listType, $policyName, $actor, $passThrough): array {
            return $passThrough([
                'remote'         => 0,
                'inserted'       => 0,
                'removed'        => 0,
                'unchanged'      => $localCount,
                'errors'         => [],
                'removed_values' => [],
            ], $guard, $confirmation);
        };

        // Administrator accepted: apply the captured set this run.
        if ($existing !== null && $existing['status'] === 'accepted') {
            $captured = json_decode((string)($existing['pending_values'] ?? '[]'), true);
            $captured = is_array($captured) ? $captured : [];
            $applied = self::applyConfirmedDeletion($listType, $policyName, $captured, $actor);

            $stmt = self::getConnection()->prepare(
                'UPDATE ' . self::confirmationsTable() . ' SET \`status\` = \\'applied\\', \`decided_at\` = NOW() WHERE \`id\` = :id'
            );
            $stmt->execute([':id' => (int)$existing['id']]);

            self::logAudit(
                'SYNC',
                $listType,
                $policyName,
                'SYNC_CONFIRMATION',
                "Applied administrator-approved deletion of {$applied['removed']} entries from an empty remote list.",
                $actor
            );

            return $passThrough([
                'remote'         => 0,
                'inserted'       => 0,
                'removed'        => $applied['removed'],
                'unchanged'      => max(0, $localCount - $applied['removed']),
                'errors'         => $applied['errors'],
                'removed_values' => $applied['removed_values'],
            ], 'applied');
        }

        // Administrator denied: keep the rows and do not ask again.
        if ($existing !== null && $existing['status'] === 'denied') {
            return $skippedResult('denied', $existing);
        }

        // A decision is already outstanding; refresh the captured set so the UI
        // reflects the current local state, but keep it pending and do not re-prompt.
        if ($existing !== null && $existing['status'] === 'pending') {
            [$values, $truncated] = self::captureValues($localValues);
            self::recordSyncConfirmation($policyName, $listType, $localCount, $values, $truncated, $actor);
            $refreshed = self::getSyncConfirmation($policyName, $listType);
            return $skippedResult('awaiting_decision', $refreshed);
        }

        // No decision yet: raise the confirmation and hold the deletion.
        [$values, $truncated] = self::captureValues($localValues);
        self::recordSyncConfirmation($policyName, $listType, $localCount, $values, $truncated, $actor);
        $raised = self::getSyncConfirmation($policyName, $listType);
        self::logAudit(
            'SYNC',
            $listType,
            $policyName,
            'SYNC_CONFIRMATION',
            "Remote list came back empty while {$localCount} local entries exist. Deletion withheld pending administrator confirmation.",
            $actor
        );
        return $skippedResult('prompted', $raised);
    }

    /**
     * Bound the captured value set so the column cannot be overflowed. When the
     * set is truncated the approved deletion is correspondingly narrower, which
     * errs towards keeping rows rather than deleting unapproved ones.
     */
    private static function captureValues(array $localValues): array {
        $limit = 20000;
        $values = array_values($localValues);
        if (count($values) > $limit) {
            return [array_slice($values, 0, $limit), true];
        }
        return [$values, false];
    }

    /**
     * Record an audit log entry in eop_audit_log
     */
    public static function logAudit(string $action, string $listType, string $policyName, string $targetValue, string $details, string $username): void {
        try {
            $pdo = self::getConnection();
            $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
            $stmt = $pdo->prepare("INSERT INTO " . TABLE_AUDIT_LOG . " 
                (username, action, list_type, policy_name, target_value, details, ip_address, timestamp)
                VALUES (:user, :action, :list, :policy, :target, :details, :ip, NOW())");
            $stmt->execute([
                ':user'    => $username,
                ':action'  => $action,
                ':list'    => $listType,
                ':policy'  => $policyName,
                ':target'  => substr($targetValue, 0, 255),
                ':details' => $details,
                ':ip'      => $ip
            ]);
        } catch (Exception $e) {
            error_log('[Audit Log Error] ' . $e->getMessage());
        }
    }

    /**
     * Update policy sync status with automatic column verification & graceful fallback
     */
    public static function updatePolicySyncStatus(string $policyName, string $status, string $message = ''): void {
        try {
            $pdo = self::getConnection();

            // Check if sync_status column exists in TABLE_POLICIES; if not, dynamically add it
            static $columnsChecked = false;
            if (!$columnsChecked) {
                try {
                    $check = $pdo->query("SHOW COLUMNS FROM " . TABLE_POLICIES . " LIKE 'sync_status'");
                    if ($check && $check->rowCount() === 0) {
                        @$pdo->exec("ALTER TABLE " . TABLE_POLICIES . " ADD COLUMN sync_status ENUM('synced', 'pending', 'failed') NOT NULL DEFAULT 'pending'");
                        @$pdo->exec("ALTER TABLE " . TABLE_POLICIES . " ADD COLUMN sync_message TEXT NULL");
                        @$pdo->exec("ALTER TABLE " . TABLE_POLICIES . " ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP");
                    }
                    $columnsChecked = true;
                } catch (Exception $e) {
                    // Ignore column check error, will fall back below
                }
            }

            try {
                $stmt = $pdo->prepare("INSERT INTO " . TABLE_POLICIES . " (policy_name, last_synced_at, sync_status, sync_message, updated_at)
                                       VALUES (:name, NOW(), :status, :msg, NOW())
                                       ON DUPLICATE KEY UPDATE last_synced_at = NOW(), sync_status = VALUES(sync_status), sync_message = VALUES(sync_message), updated_at = NOW()");
                $stmt->execute([':name' => $policyName, ':status' => $status, ':msg' => $message]);
            } catch (PDOException $pdoEx) {
                // Graceful fallback for legacy tables without sync_status column
                $fallbackStmt = $pdo->prepare("INSERT INTO " . TABLE_POLICIES . " (policy_name, last_synced_at)
                                               VALUES (:name, NOW())
                                               ON DUPLICATE KEY UPDATE last_synced_at = NOW()");
                $fallbackStmt->execute([':name' => $policyName]);
            }
        } catch (Exception $e) {
            error_log('[Database::updatePolicySyncStatus Error] ' . $e->getMessage());
        }
    }

    /**
     * Retrieve the active default policy name from MariaDB (eop_policies), falling back to config
     */
    public static function getDefaultPolicyName(): string {
        try {
            $pdo = self::getConnection();
            static $colChecked = false;
            if (!$colChecked) {
                try {
                    $check = $pdo->query("SHOW COLUMNS FROM " . TABLE_POLICIES . " LIKE 'is_default'");
                    if ($check && $check->rowCount() === 0) {
                        @$pdo->exec("ALTER TABLE " . TABLE_POLICIES . " ADD COLUMN is_default TINYINT(1) NOT NULL DEFAULT 0");
                    }
                    $colChecked = true;
                } catch (Exception $e) {}
            }

            $stmt = $pdo->query("SELECT policy_name FROM " . TABLE_POLICIES . " WHERE is_default = 1 ORDER BY updated_at DESC LIMIT 1");
            $row = $stmt ? $stmt->fetch() : null;
            if (!empty($row['policy_name'])) {
                return (string)$row['policy_name'];
            }
        } catch (Exception $e) {
            // fallback below
        }

        if (defined('DEFAULT_POLICY_NAME') && DEFAULT_POLICY_NAME !== '') {
            return DEFAULT_POLICY_NAME;
        }

        return getenv('EOP_POLICY_NAME') ?: 'Default';
    }

    /**
     * Fetch all policies stored in MariaDB eop_policies table
     */
    public static function getPolicies(): array {
        $policies = [];
        try {
            $pdo = self::getConnection();
            static $colChecked = false;
            if (!$colChecked) {
                try {
                    $check = $pdo->query("SHOW COLUMNS FROM " . TABLE_POLICIES . " LIKE 'is_default'");
                    if ($check && $check->rowCount() === 0) {
                        @$pdo->exec("ALTER TABLE " . TABLE_POLICIES . " ADD COLUMN is_default TINYINT(1) NOT NULL DEFAULT 0");
                    }
                    $colChecked = true;
                } catch (Exception $e) {}
            }

            $stmt = $pdo->query("SELECT * FROM " . TABLE_POLICIES . " ORDER BY is_default DESC, policy_name ASC");
            if ($stmt) {
                $policies = $stmt->fetchAll();
            }
        } catch (Exception $e) {
            error_log('[Database::getPolicies Error] ' . $e->getMessage());
        }
        return $policies;
    }

    /**
     * Update or set the active default policy name in MariaDB and update .env
     */
    public static function setDefaultPolicyName(string $newPolicyName, string $updatedBy = 'SYSTEM', string $description = ''): bool {
        $newPolicyName = trim($newPolicyName);
        if ($newPolicyName === '') {
            return false;
        }

        try {
            $pdo = self::getConnection();

            // Ensure is_default column exists.
            // This is DDL, so it must happen BEFORE the transaction opens: MySQL
            // issues an implicit COMMIT before and after an ALTER TABLE, which
            // would silently commit the transaction started below.
            try {
                $check = $pdo->query("SHOW COLUMNS FROM " . TABLE_POLICIES . " LIKE 'is_default'");
                if ($check && $check->rowCount() === 0) {
                    @$pdo->exec("ALTER TABLE " . TABLE_POLICIES . " ADD COLUMN is_default TINYINT(1) NOT NULL DEFAULT 0");
                }
            } catch (Throwable $e) {}

            $desc = $description !== '' ? $description : 'Primary Inbound Anti-Spam Policy';

            // Clearing the existing default and promoting the new one must be
            // atomic. Previously the UPDATE ran first and the INSERT second with
            // no transaction, so any failure between them left the table with no
            // default policy at all while the caller was told only that the
            // update "failed". getConnection() is a shared singleton, so only
            // open a transaction if one is not already running.
            $ownsTransaction = !$pdo->inTransaction();
            if ($ownsTransaction) {
                $pdo->beginTransaction();
            }

            try {
                // Unset previous defaults
                $pdo->exec("UPDATE " . TABLE_POLICIES . " SET is_default = 0");

                // Insert or update new default policy.
                // Each placeholder may appear only once: this connection sets
                // ATTR_EMULATE_PREPARES = false, so these are real prepared
                // statements and a repeated named placeholder raises
                // SQLSTATE[HY093] Invalid parameter number.
                $stmt = $pdo->prepare("INSERT INTO " . TABLE_POLICIES . " (policy_name, description, is_default, updated_at)
                                       VALUES (:name, :desc, 1, NOW())
                                       ON DUPLICATE KEY UPDATE is_default = 1, updated_at = NOW(), description = IF(:desc_a != '', :desc_b, description)");
                $stmt->execute([
                    ':name'   => $newPolicyName,
                    ':desc'   => $desc,
                    ':desc_a' => $description,
                    ':desc_b' => $description
                ]);

                if ($ownsTransaction) {
                    $pdo->commit();
                }
            } catch (Throwable $e) {
                if ($ownsTransaction && $pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                throw $e;
            }

            // Persist into .env file if available
            self::updateEnvVariable('EOP_POLICY_NAME', $newPolicyName);

            // Update in-memory global available policies
            if (isset($GLOBALS['AVAILABLE_POLICIES']) && !isset($GLOBALS['AVAILABLE_POLICIES'][$newPolicyName])) {
                $GLOBALS['AVAILABLE_POLICIES'][$newPolicyName] = $desc;
            }

            self::logAudit('UPDATE', 'SYSTEM', $newPolicyName, 'DEFAULT_POLICY', "Changed default policy name to '{$newPolicyName}'", $updatedBy);
            return true;
        } catch (Throwable $e) {
            error_log('[Database::setDefaultPolicyName Error] ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Atomically update a key-value in local .env configuration files
     */
    public static function updateEnvVariable(string $key, string $value): bool {
        $envPaths = [
            __DIR__ . '/.env',
            '/var/www/eop-antispam/.env'
        ];

        $updatedAny = false;
        foreach ($envPaths as $envPath) {
            if (!file_exists($envPath)) {
                continue;
            }

            $content = @file_get_contents($envPath);
            if ($content === false) {
                continue;
            }

            $pattern = '/^' . preg_quote($key, '/') . '=.*/m';
            $escapedVal = (strpos($value, ' ') !== false) ? '"' . addcslashes($value, '"\\\\$') . '"' : $value;
            $replacement = "{$key}={$escapedVal}";

            if (preg_match($pattern, $content)) {
                $newContent = preg_replace($pattern, $replacement, $content);
            } else {
                $newContent = rtrim($content) . "\\n{$replacement}\\n";
            }

            if (@file_put_contents($envPath, $newContent) !== false) {
                $updatedAny = true;
            }
        }
        return $updatedAny;
    }

    /**
     * Fetch active LDAP connection configuration stored in the database table eop_ldap_config
     */
    public static function getLdapConfig(): ?array {
        try {
            $pdo = self::getConnection();
            $stmt = $pdo->query("SELECT * FROM " . TABLE_LDAP_CONFIG . " WHERE is_active = 1 ORDER BY id DESC LIMIT 1");
            $config = $stmt->fetch();
            return $config ?: null;
        } catch (Exception $e) {
            error_log('[Database::getLdapConfig Error] ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Save updated LDAP connection configuration into database table eop_ldap_config
     */
    public static function saveLdapConfig(array $data, string $updatedBy): bool {
        try {
            $pdo = self::getConnection();
            $stmt = $pdo->prepare("INSERT INTO " . TABLE_LDAP_CONFIG . " 
                (host, port, protocol, use_ssl, use_tls, base_dn, authorized_group_dn, bind_dn, bind_password, account_suffix, netbios_domain, timeout_seconds, is_active, updated_by, created_at, updated_at)
                VALUES (:host, :port, :protocol, :use_ssl, :use_tls, :base_dn, :group_dn, :bind_dn, :bind_pass, :suffix, :domain, :timeout, 1, :user, NOW(), NOW())");

            $protocol = $data['protocol'] ?? 'ldap';
            $useSsl = ($protocol === 'ldaps' || !empty($data['use_ssl'])) ? 1 : 0;
            $useTls = ($protocol === 'starttls' || !empty($data['use_tls'])) ? 1 : 0;

            $success = $stmt->execute([
                ':host'      => trim($data['host']),
                ':port'      => (int)($data['port'] ?? 389),
                ':protocol'  => $protocol,
                ':use_ssl'   => $useSsl,
                ':use_tls'   => $useTls,
                ':base_dn'   => trim($data['base_dn']),
                ':group_dn'  => trim($data['authorized_group_dn']),
                ':bind_dn'   => trim($data['bind_dn'] ?? ''),
                ':bind_pass' => trim($data['bind_password'] ?? ''),
                ':suffix'    => trim($data['account_suffix'] ?? '@corp.example.com'),
                ':domain'    => trim($data['netbios_domain'] ?? 'CORP'),
                ':timeout'   => max(1, (int)($data['timeout_seconds'] ?? 5)),
                ':user'      => $updatedBy,
            ]);

            if ($success) {
                $newId = (int)$pdo->lastInsertId();
                $pdo->exec("UPDATE " . TABLE_LDAP_CONFIG . " SET is_active = 0 WHERE id != {$newId}");
                self::logAudit('UPDATE', 'SYSTEM', 'GLOBAL', $data['host'], "Updated LDAP connection configuration stored in database table eop_ldap_config (ID: {$newId})", $updatedBy);
            }
            return $success;
        } catch (Exception $e) {
            error_log('[Database::saveLdapConfig Error] ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Fetch all LDAP configuration history records from eop_ldap_config table
     */
    public static function getAllLdapConfigs(int $limit = 10): array {
        try {
            $pdo = self::getConnection();
            $stmt = $pdo->prepare("SELECT * FROM " . TABLE_LDAP_CONFIG . " ORDER BY id DESC LIMIT :limit");
            $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->fetchAll();
        } catch (Exception $e) {
            error_log('[Database::getAllLdapConfigs Error] ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Encrypt a secret for storage using the shared AES-256-GCM envelope
     * (see crypto.php). The IV and tag travel inside the ciphertext, so the
     * encryption_iv / encryption_tag columns are written as NULL. They are left in
     * the schema for compatibility with the previous column-per-field format and
     * are no longer read or written by any code path.
     */
    public static function encryptKeyPassword(string $password): string {
        return eopEncryptSecret($password);
    }

    /**
     * Decrypt a stored secret. Returns null when the value cannot be decrypted,
     * for example when AUTH_MASTER_ENCRYPTION_KEY does not match the record.
     */
    public static function decryptKeyPassword(?string $stored): ?string {
        return eopDecryptSecret($stored);
    }

    /**
     * Fetch active EOP private key & certificate authentication record from database table eop_auth_config.
     * The private key, PKCS#12 bundle and passphrase are decrypted here so every caller
     * receives plaintext; a null field means the value could not be decrypted.
     */
    public static function getEopAuthConfig(): ?array {
        try {
            $pdo = self::getConnection();
            $stmt = $pdo->query("SELECT * FROM " . TABLE_EOP_AUTH_CONFIG . " WHERE is_active = 1 ORDER BY id DESC LIMIT 1");
            $config = $stmt->fetch();
            if (!$config) {
                return null;
            }

            $config['private_key'] = self::decryptKeyPassword($config['private_key'] ?? '');
            $config['pkcs12_bundle'] = self::decryptKeyPassword($config['pkcs12_bundle'] ?? '');
            $config['encrypted_password'] = self::decryptKeyPassword($config['encrypted_password'] ?? '');

            return $config;
        } catch (Exception $e) {
            error_log('[Database::getEopAuthConfig Error] ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Save uploaded EOP private key and AES-256 encrypted password into database table eop_auth_config
     */
    public static function saveEopAuthConfig(array $data, string $uploadedBy): bool {
        try {
            $pdo = self::getConnection();
            $stmt = $pdo->prepare("INSERT INTO " . TABLE_EOP_AUTH_CONFIG . " 
                (tenant_id, client_id, certificate_thumbprint, key_filename, private_key, pkcs12_bundle, encrypted_password, encryption_iv, encryption_tag, key_type, organization, is_active, uploaded_by, created_at, updated_at)
                VALUES (:tenant, :client, :thumbprint, :filename, :privkey, :p12, :enc_pass, NULL, NULL, :ktype, :org, 1, :user, NOW(), NOW())");

            $thumbprint = strtoupper(preg_replace('/[^a-zA-Z0-9]/', '', $data['certificate_thumbprint'] ?? ''));
            $pkcs12 = trim((string)($data['pkcs12_bundle'] ?? ''));
            $keyType = $pkcs12 !== '' ? 'PKCS12_PFX' : ($data['key_type'] ?? 'RSA_PEM');

            $success = $stmt->execute([
                ':tenant'     => trim($data['tenant_id'] ?? (defined('M365_TENANT_ID') ? M365_TENANT_ID : '')),
                ':client'     => trim($data['client_id'] ?? (defined('M365_CLIENT_ID') ? M365_CLIENT_ID : '')),
                ':thumbprint' => $thumbprint ?: (defined('M365_CERT_THUMBPRINT') ? M365_CERT_THUMBPRINT : ''),
                ':filename'   => trim($data['key_filename'] ?? 'eop-cert-private.key'),
                ':privkey'    => self::encryptKeyPassword(trim((string)($data['private_key'] ?? ''))),
                ':p12'        => $pkcs12 !== '' ? self::encryptKeyPassword($pkcs12) : null,
                ':enc_pass'   => self::encryptKeyPassword((string)($data['password'] ?? '')),
                ':ktype'      => $keyType,
                ':org'        => trim($data['organization'] ?? (defined('M365_ORGANIZATION') ? M365_ORGANIZATION : 'corp.example.com')),
                ':user'       => $uploadedBy,
            ]);

            if ($success) {
                $newId = (int)$pdo->lastInsertId();
                $pdo->exec("UPDATE " . TABLE_EOP_AUTH_CONFIG . " SET is_active = 0 WHERE id != {$newId}");
                self::logAudit('UPDATE', 'SYSTEM', 'GLOBAL', $thumbprint ?: 'CERT', "Uploaded EOP private key & stored encrypted password in database table eop_auth_config (Record #{$newId})", $uploadedBy);
            }
            return $success;
        } catch (Exception $e) {
            error_log('[Database::saveEopAuthConfig Error] ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Fetch all EOP authentication history records from eop_auth_config table
     */
    public static function getAllEopAuthConfigs(int $limit = 10): array {
        try {
            $pdo = self::getConnection();
            $stmt = $pdo->prepare("SELECT id, tenant_id, client_id, certificate_thumbprint, key_filename, key_type, organization, is_active, uploaded_by, created_at, updated_at, 
                                   IF(encrypted_password != '', 1, 0) as has_encrypted_password,
                                   IF(pkcs12_bundle IS NOT NULL AND pkcs12_bundle != '', 1, 0) as has_pkcs12,
                                   IF(private_key LIKE 'EOPENC1:%', 1, 0) as private_key_encrypted
                                   FROM " . TABLE_EOP_AUTH_CONFIG . " ORDER BY id DESC LIMIT :limit");
            $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->fetchAll();
        } catch (Exception $e) {
            error_log('[Database::getAllEopAuthConfigs Error] ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Get fallback emergency local administrator by username from eop_local_admins table
     */
    public static function getFallbackAdmin(string $username): ?array {
        try {
            $pdo = self::getConnection();
            $stmt = $pdo->prepare("SELECT * FROM " . (defined('TABLE_LOCAL_ADMINS') ? TABLE_LOCAL_ADMINS : 'eop_local_admins') . " WHERE username = :u AND is_active = 1 LIMIT 1");
            $stmt->execute([':u' => $username]);
            $res = $stmt->fetch();
            return $res ?: null;
        } catch (Exception $e) {
            error_log('[Database::getFallbackAdmin Error] ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Save/register fallback administrator account with BCrypt password hash
     */
    public static function saveFallbackAdmin(string $username, string $passwordHash, string $createdBy = 'SETUP_WIZARD'): bool {
        try {
            $pdo = self::getConnection();
            $stmt = $pdo->prepare("INSERT INTO " . (defined('TABLE_LOCAL_ADMINS') ? TABLE_LOCAL_ADMINS : 'eop_local_admins') . " (username, password_hash, is_active, created_by, created_at, updated_at) 
                                   VALUES (:u, :p, 1, :cb, NOW(), NOW()) 
                                   ON DUPLICATE KEY UPDATE password_hash = :p2, is_active = 1, updated_at = NOW()");
            return $stmt->execute([':u' => $username, ':p' => $passwordHash, ':cb' => $createdBy, ':p2' => $passwordHash]);
        } catch (Exception $e) {
            error_log('[Database::saveFallbackAdmin Error] ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Check if initial setup is locked in MariaDB eop_setup_lock table
     */
    public static function isSetupLocked(): bool {
        try {
            $pdo = self::getConnection();
            $stmt = $pdo->query("SELECT is_locked FROM eop_setup_lock WHERE is_locked = 1 LIMIT 1");
            return (bool)$stmt->fetchColumn();
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Record permanent setup lock in MariaDB eop_setup_lock table
     */
    public static function lockSetup(string $ip = '127.0.0.1', string $user = 'INITIAL_SETUP_WIZARD'): bool {
        try {
            $pdo = self::getConnection();
            $stmt = $pdo->prepare("INSERT INTO eop_setup_lock (is_locked, completed_at, completed_by, installer_ip, app_version, schema_version) 
                                   VALUES (1, NOW(), :user, :ip, '1.0.0', '2026.1')");
            return $stmt->execute([':user' => $user, ':ip' => $ip]);
        } catch (Exception $e) {
            error_log('[Database::lockSetup Error] ' . $e->getMessage());
            return false;
        }
    }
}
`
  },

  // 3. ldap.php
  {
    name: 'ldap.php',
    path: 'ldap.php',
    description: 'Microsoft Active Directory LDAP authentication engine verifying credentials and Group Distinguished Name (Group DN) access control, dynamically querying connection parameters from MariaDB table eop_ldap_config.',
    category: 'auth',
    generateContent: () => `<?php
/**
 * Microsoft Active Directory LDAP Authentication Service
 * Dynamically queries LDAP connection information from MariaDB table 'eop_ldap_config'.
 * Enforces Group Distinguished Name (Group DN) access control.
 * Supports:
 * - Standard Plain LDAP (port 389) - LDAPS is NOT required!
 * - Optional StartTLS (port 389) or LDAPS (port 636) if desired
 * - Microsoft AD recursive nested group membership via LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941)
 * - Service account bind or direct user binding
 */

declare(strict_types=1);
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';

class LdapAuth {
    private $ldapConn = null;
    private array $ldapConfig = [];

    public function __construct() {
        // Dynamically load LDAP connection parameters from the MariaDB database table eop_ldap_config
        $dbConfig = Database::getLdapConfig();

        $this->ldapConfig = [
            'host'           => $dbConfig['host'] ?? (defined('LDAP_HOST') ? LDAP_HOST : '127.0.0.1'),
            'port'           => !empty($dbConfig['port']) ? (int)$dbConfig['port'] : (defined('LDAP_PORT') ? LDAP_PORT : 389),
            'protocol'       => $dbConfig['protocol'] ?? (defined('LDAP_PROTOCOL') ? LDAP_PROTOCOL : 'ldap'),
            'use_ssl'        => isset($dbConfig['use_ssl']) ? (bool)$dbConfig['use_ssl'] : (defined('LDAP_USE_SSL') ? LDAP_USE_SSL : false),
            'use_tls'        => isset($dbConfig['use_tls']) ? (bool)$dbConfig['use_tls'] : (defined('LDAP_USE_TLS') ? LDAP_USE_TLS : false),
            'base_dn'        => $dbConfig['base_dn'] ?? (defined('LDAP_BASE_DN') ? LDAP_BASE_DN : ''),
            'group_dn'       => $dbConfig['authorized_group_dn'] ?? (defined('LDAP_AUTHORIZED_GROUP_DN') ? LDAP_AUTHORIZED_GROUP_DN : ''),
            'bind_dn'        => $dbConfig['bind_dn'] ?? (defined('LDAP_BIND_DN') ? LDAP_BIND_DN : ''),
            'bind_pass'      => $dbConfig['bind_password'] ?? (defined('LDAP_BIND_PASSWORD') ? LDAP_BIND_PASSWORD : ''),
            'account_suffix' => $dbConfig['account_suffix'] ?? (defined('LDAP_ACCOUNT_SUFFIX') ? LDAP_ACCOUNT_SUFFIX : '@corp.example.com'),
            'domain'         => $dbConfig['netbios_domain'] ?? (defined('LDAP_NETBIOS_DOMAIN') ? LDAP_NETBIOS_DOMAIN : 'CORP'),
            'timeout'        => !empty($dbConfig['timeout_seconds']) ? (int)$dbConfig['timeout_seconds'] : 5,
        ];
    }

    /**
     * Get current active LDAP configuration parameters
     */
    public function getConfig(): array {
        return $this->ldapConfig;
    }

    /**
     * Connect to Active Directory domain controller using database-stored settings
     */
    private function connect(): void {
        if (!function_exists('ldap_connect')) {
            throw new RuntimeException('PHP LDAP extension is not installed. Run: sudo apt-get install php-ldap');
        }

        // Support plain LDAP (ldap://), LDAPS (ldaps://), or StartTLS
        $protocol = ($this->ldapConfig['use_ssl'] || $this->ldapConfig['protocol'] === 'ldaps') ? 'ldaps://' : 'ldap://';
        $uri = sprintf('%s%s:%d', $protocol, $this->ldapConfig['host'], $this->ldapConfig['port']);

        $conn = ldap_connect($uri);
        if (!$conn) {
            throw new RuntimeException("Could not connect to AD Domain Controller at {$uri}");
        }

        // Set mandatory Active Directory LDAP options
        ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($conn, LDAP_OPT_REFERRALS, 0); // Critical for Active Directory
        ldap_set_option($conn, LDAP_OPT_NETWORK_TIMEOUT, $this->ldapConfig['timeout']);

        // StartTLS only if explicitly enabled (NOT required)
        if (!$this->ldapConfig['use_ssl'] && ($this->ldapConfig['use_tls'] || $this->ldapConfig['protocol'] === 'starttls')) {
            if (!ldap_start_tls($conn)) {
                throw new RuntimeException('Failed to start TLS with Active Directory DC.');
            }
        }

        $this->ldapConn = $conn;
    }

    /**
     * Authenticate user credentials and verify Group DN authorization
     *
     * @param string $username sAMAccountName or UPN (e.g. jsmith or jsmith@corp.example.com)
     * @param string $password User Active Directory password
     * @return array [success => bool, user => array|null, error => string|null]
     */
    public function authenticate(string $username, string $password): array {
        $username = trim($username);
        if (empty($username) || empty($password)) {
            return ['success' => false, 'user' => null, 'error' => 'Username and password cannot be empty.'];
        }

        try {
            $this->connect();
        } catch (Exception $e) {
            // LDAP connection failure! If emergency fallback non-LDAP administrator is enabled, authenticate via MariaDB
            if (defined('FALLBACK_ADMIN_ENABLED') && FALLBACK_ADMIN_ENABLED) {
                $fallbackResult = $this->authenticateFallbackAdmin($username, $password, 'LDAP connection failure: ' . $e->getMessage());
                if ($fallbackResult !== null) {
                    return $fallbackResult;
                }
            }
            return [
                'success' => false,
                'user'    => null,
                'error'   => 'Active Directory LDAP Connection failure: ' . $e->getMessage() . (defined('FALLBACK_ADMIN_ENABLED') && FALLBACK_ADMIN_ENABLED ? ' (Note: If LDAP is offline, you can sign in with your emergency fallback administrator account).' : '')
            ];
        }

        // 1. Initial bind to search user: use Service Account if configured, otherwise bind with user UPN
        $userSearchDn = null;
        $userEntry = null;

        if (!empty($this->ldapConfig['bind_dn'])) {
            // Bind using Service Account stored in database
            $serviceBound = @ldap_bind($this->ldapConn, $this->ldapConfig['bind_dn'], $this->ldapConfig['bind_pass']);
            if (!$serviceBound) {
                return ['success' => false, 'user' => null, 'error' => 'Service account could not bind to Active Directory: ' . ldap_error($this->ldapConn)];
            }

            // Find user's DN in Active Directory
            $cleanUser = ldap_escape($username, '', LDAP_ESCAPE_FILTER);
            $filter = "(|(sAMAccountName={$cleanUser})(userPrincipalName={$cleanUser}))";
            $search = @ldap_search($this->ldapConn, $this->ldapConfig['base_dn'], $filter, [
                'dn', 'sAMAccountName', 'displayName', 'mail', 'memberOf', 'userPrincipalName'
            ]);

            if (!$search || ldap_count_entries($this->ldapConn, $search) === 0) {
                return ['success' => false, 'user' => null, 'error' => 'User account not found in Active Directory.'];
            }

            $entries = ldap_get_entries($this->ldapConn, $search);
            $userEntry = $entries[0];
            $userSearchDn = $userEntry['dn'];

            // Now verify the user's actual password by binding as the user's DN
            $userBound = @ldap_bind($this->ldapConn, $userSearchDn, $password);
            if (!$userBound) {
                return ['success' => false, 'user' => null, 'error' => 'Invalid Active Directory credentials.'];
            }
        } else {
            // Direct User Bind (using NetBIOS domain or UPN suffix)
            $suffix = $this->ldapConfig['account_suffix'];
            $bindIdentity = str_contains($username, '@') ? $username : $username . $suffix;
            $userBound = @ldap_bind($this->ldapConn, $bindIdentity, $password);
            if (!$userBound) {
                return ['success' => false, 'user' => null, 'error' => 'Invalid Active Directory credentials.'];
            }

            // Search user details post-bind
            $cleanUser = ldap_escape($username, '', LDAP_ESCAPE_FILTER);
            $filter = "(|(sAMAccountName={$cleanUser})(userPrincipalName={$cleanUser}))";
            $search = @ldap_search($this->ldapConn, $this->ldapConfig['base_dn'], $filter, [
                'dn', 'sAMAccountName', 'displayName', 'mail', 'memberOf', 'userPrincipalName'
            ]);
            if ($search && ldap_count_entries($this->ldapConn, $search) > 0) {
                $entries = ldap_get_entries($this->ldapConn, $search);
                $userEntry = $entries[0];
                $userSearchDn = $userEntry['dn'];
            }
        }

        if (!$userSearchDn) {
            return ['success' => false, 'user' => null, 'error' => 'Failed to resolve user Distinguished Name.'];
        }

        // 2. Enforce Group Distinguished Name (Group DN) access control
        $targetGroupDn = $this->ldapConfig['group_dn'];
        $isAuthorized = $this->verifyGroupMembership($userSearchDn, $targetGroupDn);

        if (!$isAuthorized) {
            error_log("[LDAP Access Denied] User {$username} ({$userSearchDn}) is not a member of authorized group: " . $targetGroupDn);
            return [
                'success' => false,
                'user'    => null,
                'error'   => 'Access Denied: Your Active Directory account is not a member of the authorized Group (' . htmlspecialchars($targetGroupDn) . ').'
            ];
        }

        // 3. User is authenticated and authorized!
        $userData = [
            'username'    => $userEntry['samaccountname'][0] ?? $username,
            'displayName' => $userEntry['displayname'][0] ?? $username,
            'email'       => $userEntry['mail'][0] ?? ($userEntry['userprincipalname'][0] ?? ''),
            'dn'          => $userSearchDn,
            'groupDn'     => $targetGroupDn,
            'loginTime'   => time(),
        ];

        return [
            'success' => true,
            'user'    => $userData,
            'error'   => null
        ];
    }

    /**
     * Verify if user is member of Group DN, including nested groups in Active Directory
     */
    private function verifyGroupMembership(string $userDn, string $groupDn): bool {
        // Method A: Check using Microsoft Active Directory matching rule LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941)
        // This recursively evaluates direct AND nested AD group memberships in a single query!
        $escapedUserDn = ldap_escape($userDn, '', LDAP_ESCAPE_FILTER);
        $escapedGroupDn = ldap_escape($groupDn, '', LDAP_ESCAPE_FILTER);

        // Check if group has user in chain
        $filter1 = "(&(objectClass=user)(distinguishedName={$escapedUserDn})(memberOf:1.2.840.113556.1.4.1941:={$escapedGroupDn}))";
        $search1 = @ldap_search($this->ldapConn, $this->ldapConfig['base_dn'], $filter1, ['dn']);

        if ($search1 && ldap_count_entries($this->ldapConn, $search1) > 0) {
            return true;
        }

        // Method B: Direct member check on the group object itself
        $filter2 = "(&(objectClass=group)(distinguishedName={$escapedGroupDn})(member={$escapedUserDn}))";
        $search2 = @ldap_search($this->ldapConn, $this->ldapConfig['base_dn'], $filter2, ['dn']);

        if ($search2 && ldap_count_entries($this->ldapConn, $search2) > 0) {
            return true;
        }

        // Method C: Case-insensitive fallback checking memberOf attribute array
        $search3 = @ldap_read($this->ldapConn, $userDn, '(objectClass=*)', ['memberOf']);
        if ($search3 && ldap_count_entries($this->ldapConn, $search3) > 0) {
            $info = ldap_get_entries($this->ldapConn, $search3);
            if (isset($info[0]['memberof'])) {
                for ($i = 0; $i < $info[0]['memberof']['count']; $i++) {
                    if (strcasecmp($info[0]['memberof'][$i], $groupDn) === 0) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Authenticate emergency non-LDAP fallback administrator when Active Directory LDAP fails
     */
    public function authenticateFallbackAdmin(string $username, string $password, string $failureReason = 'LDAP connection failure'): ?array {
        $username = trim($username);
        if (empty($username) || empty($password)) {
            return null;
        }

        // 1. Check MariaDB table eop_local_admins first
        $localAdmin = Database::getFallbackAdmin($username);
        if ($localAdmin && !empty($localAdmin['password_hash'])) {
            if (password_verify($password, $localAdmin['password_hash'])) {
                Database::logAudit('LOGIN', 'SYSTEM', defined('DEFAULT_POLICY_NAME') ? DEFAULT_POLICY_NAME : 'GLOBAL', $username, "Emergency Non-LDAP Fallback Administrator Login ({$failureReason})", $username);
                return [
                    'success' => true,
                    'user'    => [
                        'username'        => $username,
                        'displayName'     => 'Emergency Local Administrator (' . $username . ')',
                        'email'           => 'admin@localhost',
                        'dn'              => 'CN=' . $username . ',OU=LocalSecurity,DC=local',
                        'groupDn'         => 'LOCAL_SECURITY_FALLBACK',
                        'isFallbackAdmin' => true,
                        'loginTime'       => time(),
                    ],
                    'error'   => null
                ];
            }
        }

        // 2. Check default fallback administrator credentials configured in setup if defined
        if (defined('FALLBACK_ADMIN_USERNAME') && strcasecmp($username, FALLBACK_ADMIN_USERNAME) === 0) {
            if (defined('FALLBACK_ADMIN_PASSWORD_HASH') && !empty(FALLBACK_ADMIN_PASSWORD_HASH)) {
                if (password_verify($password, FALLBACK_ADMIN_PASSWORD_HASH)) {
                    Database::logAudit('LOGIN', 'SYSTEM', defined('DEFAULT_POLICY_NAME') ? DEFAULT_POLICY_NAME : 'GLOBAL', $username, "Emergency Non-LDAP Fallback Administrator Login ({$failureReason})", $username);
                    return [
                        'success' => true,
                        'user'    => [
                            'username'        => $username,
                            'displayName'     => 'Emergency Local Administrator (' . $username . ')',
                            'email'           => 'admin@localhost',
                            'dn'              => 'CN=' . $username . ',OU=LocalSecurity,DC=local',
                            'groupDn'         => 'LOCAL_SECURITY_FALLBACK',
                            'isFallbackAdmin' => true,
                            'loginTime'       => time(),
                        ],
                        'error'   => null
                    ];
                }
            }
        }

        return null;
    }

    public function __destruct() {
        if ($this->ldapConn) {
            @ldap_unbind($this->ldapConn);
        }
    }
}
`
  },

  // 4. functions.php
  {
    name: 'functions.php',
    path: 'functions.php',
    description: 'Security utilities, CSRF protection, RFC 5322 / RFC 1035 email and domain validators, and flash messaging.',
    category: 'core',
    generateContent: () => `<?php
/**
 * Utility Functions & Security Helpers
 */

declare(strict_types=1);

/**
 * Generate CSRF token stored in session
 */
function getCsrfToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Validate CSRF token
 */
function verifyCsrfToken(?string $token): bool {
    if (empty($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Enforce authentication & session validity
 */
function requireAuth(): array {
    if (empty($_SESSION['user']) || !is_array($_SESSION['user'])) {
        header('Location: login.php');
        exit;
    }
    return $_SESSION['user'];
}

/**
 * Prepare everything sync-exchange.ps1 needs from the active eop_auth_config row.
 *
 * sync-exchange.ps1 reads its app-only auth values and the PKCS#12 bundle from
 * the ENVIRONMENT rather than from parameters, so that rotating the certificate
 * or the App Registration takes effect without editing the script. Both callers
 * must therefore export it: cron-sync.php and the web UI's manual push. This was
 * centralised in one function because the push path had drifted and silently
 * failed with "Missing authentication values" on every run.
 *
 * Values are exported rather than passed as arguments so the bundle passphrase
 * and the database password never appear in the process table.
 *
 * @return array{ok:bool,error:string,pfx_path:string}
 */
function eopPrepareSyncEnvironment(?array $authConfig, string $pfxFallbackPath = ''): array {
    $result = ['ok' => false, 'error' => '', 'pfx_path' => ''];

    if (!is_array($authConfig) || $authConfig === []) {
        $result['error'] = 'No active eop_auth_config record was found. Upload the certificate in the Authentication tab first.';
        return $result;
    }

    $missing = [];
    foreach (['tenant_id', 'client_id', 'certificate_thumbprint'] as $field) {
        if (empty($authConfig[$field])) {
            $missing[] = $field;
        }
    }
    if ($missing !== []) {
        $result['error'] = 'The active eop_auth_config record is missing ' . implode(', ', $missing) . '.';
        return $result;
    }

    // Certificate material. A PKCS#12 bundle is normally stored encrypted in the
    // pkcs12_bundle column, so it is materialised to a private temp file for the
    // lifetime of the request.
    $pfxPath = $pfxFallbackPath;
    $tempFiles = [];

    $storedBundle = trim((string)($authConfig['pkcs12_bundle'] ?? ''));
    if ($storedBundle !== '') {
        $blob = base64_decode((string)preg_replace('/\\s+/', '', $storedBundle), true);
        if ($blob === false || !str_starts_with($blob, "\\x30")) {
            $result['error'] = 'The stored PKCS#12 bundle in eop_auth_config is not a DER bundle.';
            return $result;
        }
        $tempPfx = tempnam(sys_get_temp_dir(), 'eopcert_');
        if ($tempPfx === false || file_put_contents($tempPfx, $blob) === false) {
            $result['error'] = 'Could not write the stored PKCS#12 bundle to a temporary file.';
            return $result;
        }
        chmod($tempPfx, 0600);
        $pfxPath = $tempPfx;
        $tempFiles[] = $tempPfx;
    }

    if (!is_readable($pfxPath)) {
        $result['error'] = "No readable PKCS#12 certificate bundle at '{$pfxPath}'. Certificate authentication needs a .pfx containing the certificate and its private key. Upload one in the Web UI or set EOP_CERT_PFX_PATH.";
        foreach ($tempFiles as $f) { @unlink($f); }
        return $result;
    }

    // PowerShellGet fails to initialise on Debian when XDG_CACHE_HOME is unset.
    if (getenv('XDG_CACHE_HOME') === false) {
        $xdgCache = '/var/cache/eop-antispam';
        if (!is_dir($xdgCache)) {
            @mkdir($xdgCache, 0755, true);
        }
        if (is_dir($xdgCache)) {
            putenv('XDG_CACHE_HOME=' . $xdgCache);
        }
    }

    putenv('EOP_TENANT_ID=' . (string)$authConfig['tenant_id']);
    putenv('EOP_CLIENT_ID=' . (string)$authConfig['client_id']);
    putenv('EOP_CERT_THUMBPRINT=' . (string)$authConfig['certificate_thumbprint']);
    putenv('EOP_ORGANIZATION=' . (string)($authConfig['organization'] ?? ''));
    putenv('EOP_CERT_PFX_PATH=' . $pfxPath);
    putenv('EOP_CERT_PFX_PASSWORD=' . (string)($authConfig['encrypted_password'] ?? ''));

    if ($tempFiles !== []) {
        register_shutdown_function(static function () use ($tempFiles): void {
            foreach ($tempFiles as $tempPath) {
                if (is_file($tempPath)) {
                    @unlink($tempPath);
                }
            }
        });
    }

    $result['ok'] = true;
    $result['pfx_path'] = $pfxPath;
    return $result;
}

/**
 * Export the MariaDB credentials sync-exchange.ps1 needs for a push. Sent via the
 * environment rather than -Db* arguments so the password stays out of argv.
 */
function eopExportSyncDatabaseEnvironment(): void {
    if (defined('DB_HOST')) { putenv('EOP_DB_HOST=' . (string)DB_HOST); }
    if (defined('DB_PORT')) { putenv('EOP_DB_PORT=' . (int)DB_PORT); }
    if (defined('DB_NAME')) { putenv('EOP_DB_NAME=' . (string)DB_NAME); }
    if (defined('DB_USER')) { putenv('EOP_DB_USER=' . (string)DB_USER); }
    if (defined('DB_PASS')) { putenv('EOP_DB_PASS=' . (string)DB_PASS); }
}

/**
 * RFC 5322 Compliant Email Address Validator
 */
function isValidEmail(string $email): bool {
    $email = trim($email);
    if (strlen($email) > 254) {
        return false;
    }
    return (bool)filter_var($email, FILTER_VALIDATE_EMAIL);
}

/**
 * RFC 1035 / FQDN Domain Validator (allows standard domains e.g. example.com and wildcards *.example.com)
 */
function isValidDomain(string $domain): bool {
    $domain = trim($domain);
    // Strip wildcard if present
    if (str_starts_with($domain, '*.')) {
        $domain = substr($domain, 2);
    }
    if (strlen($domain) === 0 || strlen($domain) > 253) {
        return false;
    }
    // Standard domain regex check
    $pattern = '/^(?!://)([a-zA-Z0-9-_]+.)*[a-zA-Z0-9][a-zA-Z0-9-_]+.[a-zA-Z]{2,63}$/';
    return (bool)preg_match($pattern, $domain);
}

/**
 * Flash message helper
 */
function setFlash(string $type, string $message): void {
    $_SESSION['flash'] = [
        'type'    => $type, // success | error | warning | info
        'message' => $message,
    ];
}

function getFlash(): ?array {
    if (!empty($_SESSION['flash'])) {
        $flash = $_SESSION['flash'];
        unset($_SESSION['flash']);
        return $flash;
    }
    return null;
}
`
  },

  // 5. schema.sql
  {
    name: 'schema.sql',
    path: 'schema.sql',
    description: 'MariaDB SQL DDL creation script for the remote server with 4 individual tables per list, audit log, indexes, and remote user grants.',
    category: 'core',
    generateContent: (cfg) => `-- ============================================================================
-- Exchange Online Protection (EOP) Anti-Spam Manager - MariaDB Schema
-- Separate Individual Tables Per List:
-- 1. eop_allowed_senders
-- 2. eop_blocked_senders
-- 3. eop_allowed_domains
-- 4. eop_blocked_domains
-- Plus: eop_audit_log & eop_policies
-- ============================================================================

CREATE DATABASE IF NOT EXISTS \`${cfg.dbName}\` 
    CHARACTER SET utf8mb4 
    COLLATE utf8mb4_unicode_ci;

USE \`${cfg.dbName}\`;

-- ----------------------------------------------------------------------------
-- Table 1: Allowed Senders (Individual Table)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS \`${cfg.dbName}\`.\`eop_allowed_senders\` (
    \`id\` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    \`policy_name\` VARCHAR(128) NOT NULL DEFAULT '${cfg.defaultPolicyName}',
    \`sender_email\` VARCHAR(255) NOT NULL,
    \`note\` VARCHAR(500) NULL DEFAULT '',
    \`added_by\` VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
    \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    \`updated_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY \`idx_policy_sender\` (\`policy_name\`, \`sender_email\`),
    KEY \`idx_policy_allowed_senders\` (\`policy_name\`),
    KEY \`idx_sender_email\` (\`sender_email\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Table 2: Blocked Senders (Individual Table)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS \`${cfg.dbName}\`.\`eop_blocked_senders\` (
    \`id\` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    \`policy_name\` VARCHAR(128) NOT NULL DEFAULT '${cfg.defaultPolicyName}',
    \`sender_email\` VARCHAR(255) NOT NULL,
    \`note\` VARCHAR(500) NULL DEFAULT '',
    \`added_by\` VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
    \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    \`updated_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY \`idx_policy_sender\` (\`policy_name\`, \`sender_email\`),
    KEY \`idx_policy_blocked_senders\` (\`policy_name\`),
    KEY \`idx_sender_email\` (\`sender_email\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Table 3: Allowed Domains (Individual Table)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS \`${cfg.dbName}\`.\`eop_allowed_domains\` (
    \`id\` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    \`policy_name\` VARCHAR(128) NOT NULL DEFAULT '${cfg.defaultPolicyName}',
    \`domain_name\` VARCHAR(255) NOT NULL,
    \`note\` VARCHAR(500) NULL DEFAULT '',
    \`added_by\` VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
    \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    \`updated_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY \`idx_policy_domain\` (\`policy_name\`, \`domain_name\`),
    KEY \`idx_policy_allowed_domains\` (\`policy_name\`),
    KEY \`idx_domain_name\` (\`domain_name\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Table 4: Blocked Domains (Individual Table)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS \`${cfg.dbName}\`.\`eop_blocked_domains\` (
    \`id\` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    \`policy_name\` VARCHAR(128) NOT NULL DEFAULT '${cfg.defaultPolicyName}',
    \`domain_name\` VARCHAR(255) NOT NULL,
    \`note\` VARCHAR(500) NULL DEFAULT '',
    \`added_by\` VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
    \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    \`updated_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY \`idx_policy_domain\` (\`policy_name\`, \`domain_name\`),
    KEY \`idx_policy_blocked_domains\` (\`policy_name\`),
    KEY \`idx_domain_name\` (\`domain_name\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Audit Trail Table
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS \`${cfg.dbName}\`.\`eop_audit_log\` (
    \`id\` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    \`timestamp\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    \`username\` VARCHAR(100) NOT NULL,
    \`action\` ENUM('ADD', 'REMOVE', 'UPDATE', 'SYNC', 'LOGIN', 'LOGOUT') NOT NULL,
    \`list_type\` VARCHAR(64) NOT NULL,
    \`policy_name\` VARCHAR(128) NOT NULL,
    \`target_value\` VARCHAR(255) NOT NULL,
    \`details\` TEXT NULL,
    \`ip_address\` VARCHAR(45) NOT NULL DEFAULT '127.0.0.1',
    KEY \`idx_audit_policy\` (\`policy_name\`),
    KEY \`idx_audit_username\` (\`username\`),
    KEY \`idx_audit_timestamp\` (\`timestamp\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Policy Metadata & Sync State Table
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS \`${cfg.dbName}\`.\`eop_policies\` (
    \`id\` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    \`policy_name\` VARCHAR(128) NOT NULL UNIQUE,
    \`policy_guid\` CHAR(36) NULL,
    \`description\` VARCHAR(255) NULL,
    \`last_synced_at\` DATETIME NULL,
    \`sync_status\` ENUM('synced', 'pending', 'failed') NOT NULL DEFAULT 'pending',
    \`sync_message\` TEXT NULL,
    \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    \`updated_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY \`uniq_policy_guid\` (\`policy_guid\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Existing installations created before policy GUIDs were supported. Both steps
-- are guarded so re-running this script against an up-to-date database is a no-op.
SET @policy_guid_col := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = '${cfg.dbName}'
      AND TABLE_NAME = 'eop_policies'
      AND COLUMN_NAME = 'policy_guid'
);
SET @policy_guid_sql := IF(@policy_guid_col = 0,
    'ALTER TABLE \`${cfg.dbName}\`.\`eop_policies\` ADD COLUMN \`policy_guid\` CHAR(36) NULL AFTER \`policy_name\`',
    'DO 0');
PREPARE policy_guid_stmt FROM @policy_guid_sql;
EXECUTE policy_guid_stmt;
DEALLOCATE PREPARE policy_guid_stmt;

SET @policy_guid_key := (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = '${cfg.dbName}'
      AND TABLE_NAME = 'eop_policies'
      AND INDEX_NAME = 'uniq_policy_guid'
);
SET @policy_guid_key_sql := IF(@policy_guid_key = 0,
    'ALTER TABLE \`${cfg.dbName}\`.\`eop_policies\` ADD UNIQUE KEY \`uniq_policy_guid\` (\`policy_guid\`)',
    'DO 0');
PREPARE policy_guid_key_stmt FROM @policy_guid_key_sql;
EXECUTE policy_guid_key_stmt;
DEALLOCATE PREPARE policy_guid_key_stmt;

-- Insert default policies
INSERT INTO \`${cfg.dbName}\`.\`eop_policies\` (\`policy_name\`, \`description\`, \`sync_status\`)
VALUES 
    ('${cfg.defaultPolicyName}', 'Default Inbound Anti-Spam Policy for organization', 'pending'),
    ('Strict Anti-Spam Policy', 'Strict security filter for executive mailboxes', 'pending')
ON DUPLICATE KEY UPDATE \`description\` = VALUES(\`description\`);

-- ----------------------------------------------------------------------------
-- Table 5: LDAP Connection Settings (Database-Stored LDAP Configuration)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS \`${cfg.dbName}\`.\`eop_ldap_config\` (
    \`id\` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    \`host\` VARCHAR(255) NOT NULL,
    \`port\` INT UNSIGNED NOT NULL DEFAULT 389,
    \`protocol\` ENUM('ldap', 'ldaps', 'starttls') NOT NULL DEFAULT 'ldap',
    \`use_ssl\` TINYINT(1) NOT NULL DEFAULT 0,
    \`use_tls\` TINYINT(1) NOT NULL DEFAULT 0,
    \`base_dn\` VARCHAR(255) NOT NULL,
    \`authorized_group_dn\` VARCHAR(500) NOT NULL,
    \`bind_dn\` VARCHAR(255) NULL DEFAULT '',
    \`bind_password\` VARCHAR(255) NULL DEFAULT '',
    \`account_suffix\` VARCHAR(100) NULL DEFAULT '@corp.example.com',
    \`netbios_domain\` VARCHAR(50) NULL DEFAULT 'CORP',
    \`timeout_seconds\` INT UNSIGNED NOT NULL DEFAULT 5,
    \`is_active\` TINYINT(1) NOT NULL DEFAULT 1,
    \`updated_by\` VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
    \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    \`updated_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    KEY \`idx_ldap_active\` (\`is_active\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert initial active LDAP configuration row into eop_ldap_config table
INSERT INTO \`${cfg.dbName}\`.\`eop_ldap_config\` 
    (\`host\`, \`port\`, \`protocol\`, \`use_ssl\`, \`use_tls\`, \`base_dn\`, \`authorized_group_dn\`, \`bind_dn\`, \`bind_password\`, \`account_suffix\`, \`netbios_domain\`, \`timeout_seconds\`, \`is_active\`, \`updated_by\`)
VALUES 
    ('${cfg.ldapHost}', ${cfg.ldapPort}, '${cfg.ldapProtocol || 'ldap'}', ${cfg.ldapUseSsl ? 1 : 0}, ${cfg.ldapUseTls ? 1 : 0}, '${cfg.ldapBaseDn}', '${cfg.ldapGroupDn}', '${cfg.ldapBindDn}', '${cfg.ldapBindPass}', '@${cfg.ldapDomain.toLowerCase()}.example.com', '${cfg.ldapDomain}', 5, 1, 'SYSTEM')
ON DUPLICATE KEY UPDATE \`updated_at\` = NOW();

-- ----------------------------------------------------------------------------
-- Table 6: Exchange Online Protection (EOP) Private Key & Certificate Auth
-- Stores uploaded private key, encrypted passphrase (AES-256-GCM), thumbprint, and tenant info
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS \`${cfg.dbName}\`.\`eop_auth_config\` (
    \`id\` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    \`tenant_id\` VARCHAR(100) NOT NULL,
    \`client_id\` VARCHAR(100) NOT NULL,
    \`certificate_thumbprint\` VARCHAR(100) NOT NULL,
    \`key_filename\` VARCHAR(255) NOT NULL DEFAULT 'eop-cert-private.key',
    \`private_key\` MEDIUMTEXT NOT NULL,
    \`pkcs12_bundle\` MEDIUMTEXT NULL,
    \`encrypted_password\` TEXT NULL,
    \`encryption_iv\` VARCHAR(64) NULL,
    \`encryption_tag\` VARCHAR(64) NULL,
    \`key_type\` ENUM('RSA_PEM', 'PKCS8_PEM', 'PKCS12_PFX') NOT NULL DEFAULT 'RSA_PEM',
    \`organization\` VARCHAR(255) NULL DEFAULT 'corp.example.com',
    \`is_active\` TINYINT(1) NOT NULL DEFAULT 1,
    \`uploaded_by\` VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
    \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    \`updated_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    KEY \`idx_auth_active\` (\`is_active\`),
    KEY \`idx_thumbprint\` (\`certificate_thumbprint\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert a disabled placeholder row. The setup wizard inserts the real active
-- record, so this row must stay is_active = 0 to avoid a second active record
-- competing with it. No secrets are stored here.
INSERT INTO \`${cfg.dbName}\`.\`eop_auth_config\` 
    (\`tenant_id\`, \`client_id\`, \`certificate_thumbprint\`, \`key_filename\`, \`private_key\`, \`encrypted_password\`, \`encryption_iv\`, \`encryption_tag\`, \`key_type\`, \`organization\`, \`is_active\`, \`uploaded_by\`)
VALUES 
    ('${cfg.tenantId}', '${cfg.clientId}', '${cfg.certificateThumbprint}', '${cfg.keyFilename || "eop-cert-private.key"}', '[PLACEHOLDER_REPLACED_BY_SETUP_WIZARD]', '', NULL, NULL, 'RSA_PEM', '${cfg.organization || "corp.example.com"}', 0, 'SYSTEM')
ON DUPLICATE KEY UPDATE \`updated_at\` = NOW();

-- ----------------------------------------------------------------------------
-- Table 7: Setup Lock Table (Ensures initial setup routine cannot be re-run)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS \`${cfg.dbName}\`.\`eop_setup_lock\` (
    \`id\` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    \`is_locked\` TINYINT(1) NOT NULL DEFAULT 1,
    \`completed_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    \`completed_by\` VARCHAR(100) NOT NULL DEFAULT 'INITIAL_SETUP_WIZARD',
    \`installer_ip\` VARCHAR(45) NOT NULL DEFAULT '127.0.0.1',
    \`app_version\` VARCHAR(20) NOT NULL DEFAULT '1.0.0',
    \`schema_version\` VARCHAR(20) NOT NULL DEFAULT '2026.1'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Table 8: Emergency Non-LDAP Fallback Local Administrators
-- Dedicated storage for emergency administrative access if LDAP DC connection fails
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS \`${cfg.dbName}\`.\`eop_local_admins\` (
    \`id\` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    \`username\` VARCHAR(100) NOT NULL UNIQUE,
    \`password_hash\` VARCHAR(255) NOT NULL,
    \`is_active\` TINYINT(1) NOT NULL DEFAULT 1,
    \`created_by\` VARCHAR(100) NOT NULL DEFAULT 'SETUP_WIZARD',
    \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    \`updated_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    KEY \`idx_local_admin_username\` (\`username\`),
    KEY \`idx_local_admin_active\` (\`is_active\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

${cfg.fallbackAdminEnabled !== false ? `-- Seed default emergency fallback administrator (Username: ${cfg.fallbackAdminUsername || 'eopadmin'})
INSERT INTO \`${cfg.dbName}\`.\`eop_local_admins\` (\`username\`, \`password_hash\`, \`is_active\`, \`created_by\`)
VALUES ('${cfg.fallbackAdminUsername || 'eopadmin'}', '${cfg.fallbackAdminPasswordHash || '$2y$12$EmergencyFallbackAdminHash2026SecureBcrypt'}', 1, 'INITIAL_SETUP_WIZARD')
ON DUPLICATE KEY UPDATE \`password_hash\` = VALUES(\`password_hash\`), \`is_active\` = 1;` : ''}

-- ----------------------------------------------------------------------------
-- Table 9: Withheld Deletion Confirmations
-- A cron pull that returns an EMPTY remote list cannot be distinguished from a
-- policy that genuinely has no entries. Because the reconciler deletes local
-- rows absent from the remote list, one bad pull would empty a populated list.
-- Cron therefore withholds the deletion and records what is at risk here, and an
-- administrator accepts or denies it in the web UI. The decision is stored, not
-- acted on: the next cron run for that policy consumes it.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS \`${cfg.dbName}\`.\`eop_sync_confirmations\` (
    \`id\` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    \`policy_name\` VARCHAR(255) NOT NULL,
    \`list_type\` VARCHAR(50) NOT NULL,
    \`local_count\` INT UNSIGNED NOT NULL DEFAULT 0,
    \`remote_count\` INT UNSIGNED NOT NULL DEFAULT 0,
    \`pending_values\` MEDIUMTEXT NULL,
    \`values_truncated\` TINYINT(1) NOT NULL DEFAULT 0,
    \`status\` ENUM('pending', 'accepted', 'denied', 'applied') NOT NULL DEFAULT 'pending',
    \`requested_by\` VARCHAR(100) NOT NULL DEFAULT 'CRON_DAEMON',
    \`decided_by\` VARCHAR(100) NULL,
    \`decided_at\` DATETIME NULL,
    \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    \`updated_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY \`uniq_policy_list\` (\`policy_name\`, \`list_type\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Remote User Permissions Grant Example (Run on Remote MariaDB server)
-- Replace 'DEBIAN_WEB_SERVER_IP' with the actual IP of your Debian host!
-- ----------------------------------------------------------------------------
-- CREATE USER IF NOT EXISTS '${cfg.dbUser}'@'%' IDENTIFIED BY '${cfg.dbPass}';
-- GRANT ALL PRIVILEGES ON \`${cfg.dbName}\`.* TO '${cfg.dbUser}'@'%';
-- FLUSH PRIVILEGES;
`
  },

  // 5b. schema-update.sql
  {
    name: 'schema-update.sql',
    path: 'schema-update.sql',
    description: 'Idempotent incremental schema update for existing installations. Adds eop_auth_config.pkcs12_bundle, renames private_key_pem to private_key, widens identifier columns, relaxes secret columns to nullable, adds auth indexes, creates eop_sync_confirmations, and deactivates the fake placeholder auth row seeded by older schema.sql versions.',
    category: 'core',
    generateContent: (cfg) => `-- ============================================================================
-- Exchange Online Protection (EOP) Anti-Spam Manager
-- Incremental Schema Update For Existing Installations
-- ============================================================================
-- Purpose:
--   Brings a database created by an EARLIER version of schema.sql up to the
--   current definition. Safe to run repeatedly: every statement is guarded by
--   an information_schema lookup and becomes a no-op once applied.
--
-- What changed:
--   1. eop_auth_config renamed \`private_key_pem\` -> \`private_key\` and widened
--      to MEDIUMTEXT so large RSA/PKCS#8 keys are not truncated.
--   2. eop_auth_config gained \`pkcs12_bundle\` (encrypted PKCS#12/PFX bundle).
--      Without this column the certificate import and every sync that uses the
--      bundle fail with an unknown-column error.
--   3. eop_auth_config identifier columns widened (tenant/client/thumbprint to
--      VARCHAR(100), key_filename to VARCHAR(255)).
--   4. eop_auth_config secret columns relaxed to NULL so the wizard can store
--      a PKCS#12 bundle with no PEM private key.
--   5. eop_auth_config indexes idx_auth_active / idx_thumbprint added.
--   6. eop_sync_confirmations created if the table is absent.
--   7. The placeholder row shipped by the older schema.sql is deactivated.
--      That row carried a fake thumbprint and a non-functional encrypted blob
--      and was inserted with is_active = 1, so it competed with the real
--      record written by the setup wizard.
--
-- Usage:
--   mysql -u root -p < schema-update.sql
--   (or paste into phpMyAdmin / mariadb client against the app database)
--
-- No credentials, keys, or tenant secrets are stored by this script.
-- ============================================================================

USE \`${cfg.dbName}\`;

-- ----------------------------------------------------------------------------
-- 1. eop_auth_config: rename private_key_pem -> private_key (widen to MEDIUMTEXT)
-- ----------------------------------------------------------------------------
SET @sql := (
    SELECT IF(
        (SELECT COUNT(*) FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_auth_config'
            AND COLUMN_NAME  = 'private_key') = 0
        AND
        (SELECT COUNT(*) FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_auth_config'
            AND COLUMN_NAME  = 'private_key_pem') = 1,
        'ALTER TABLE \`eop_auth_config\` CHANGE COLUMN \`private_key_pem\` \`private_key\` MEDIUMTEXT NOT NULL',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- ----------------------------------------------------------------------------
-- 2. eop_auth_config: add private_key when neither spelling exists
-- ----------------------------------------------------------------------------
SET @sql := (
    SELECT IF(
        (SELECT COUNT(*) FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_auth_config'
            AND COLUMN_NAME  = 'private_key') = 0,
        'ALTER TABLE \`eop_auth_config\` ADD COLUMN \`private_key\` MEDIUMTEXT NOT NULL DEFAULT ''''',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- ----------------------------------------------------------------------------
-- 3. eop_auth_config: widen private_key to MEDIUMTEXT
-- ----------------------------------------------------------------------------
SET @sql := (
    SELECT IF(
        (SELECT DATA_TYPE FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_auth_config'
            AND COLUMN_NAME  = 'private_key') = 'text',
        'ALTER TABLE \`eop_auth_config\` MODIFY COLUMN \`private_key\` MEDIUMTEXT NOT NULL',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- ----------------------------------------------------------------------------
-- 4. eop_auth_config: add pkcs12_bundle (encrypted PKCS#12/PFX bundle)
-- ----------------------------------------------------------------------------
SET @sql := (
    SELECT IF(
        (SELECT COUNT(*) FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_auth_config'
            AND COLUMN_NAME  = 'pkcs12_bundle') = 0,
        'ALTER TABLE \`eop_auth_config\` ADD COLUMN \`pkcs12_bundle\` MEDIUMTEXT NULL AFTER \`private_key\`',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- ----------------------------------------------------------------------------
-- 5. eop_auth_config: widen identifier columns
-- ----------------------------------------------------------------------------
SET @sql := (
    SELECT IF(
        (SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_auth_config'
            AND COLUMN_NAME  = 'tenant_id') < 100,
        'ALTER TABLE \`eop_auth_config\` MODIFY COLUMN \`tenant_id\` VARCHAR(100) NOT NULL',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCARE PREPARE stmt;

SET @sql := (
    SELECT IF(
        (SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_auth_config'
            AND COLUMN_NAME  = 'client_id') < 100,
        'ALTER TABLE \`eop_auth_config\` MODIFY COLUMN \`client_id\` VARCHAR(100) NOT NULL',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql := (
    SELECT IF(
        (SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_auth_config'
            AND COLUMN_NAME  = 'certificate_thumbprint') < 100,
        'ALTER TABLE \`eop_auth_config\` MODIFY COLUMN \`certificate_thumbprint\` VARCHAR(100) NOT NULL',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql := (
    SELECT IF(
        (SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_auth_config'
            AND COLUMN_NAME  = 'key_filename') < 255,
        'ALTER TABLE \`eop_auth_config\` MODIFY COLUMN \`key_filename\` VARCHAR(255) NOT NULL DEFAULT ''eop-cert-private.key''',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- ----------------------------------------------------------------------------
-- 6. eop_auth_config: relax secret columns to NULL
--    A PKCS#12 deployment has no PEM private key and no legacy IV/tag pair,
--    so these columns must be nullable.
-- ----------------------------------------------------------------------------
SET @sql := (
    SELECT IF(
        (SELECT IS_NULLABLE FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_auth_config'
            AND COLUMN_NAME  = 'encrypted_password') = 'NO',
        'ALTER TABLE \`eop_auth_config\` MODIFY COLUMN \`encrypted_password\` TEXT NULL',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql := (
    SELECT IF(
        (SELECT IS_NULLABLE FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_auth_config'
            AND COLUMN_NAME  = 'encryption_iv') = 'NO',
        'ALTER TABLE \`eop_auth_config\` MODIFY COLUMN \`encryption_iv\` VARCHAR(64) NULL',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql := (
    SELECT IF(
        (SELECT IS_NULLABLE FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_auth_config'
            AND COLUMN_NAME  = 'encryption_tag') = 'NO',
        'ALTER TABLE \`eop_auth_config\` MODIFY COLUMN \`encryption_tag\` VARCHAR(64) NULL',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql := (
    SELECT IF(
        (SELECT IS_NULLABLE FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_auth_config'
            AND COLUMN_NAME  = 'organization') = 'NO',
        'ALTER TABLE \`eop_auth_config\` MODIFY COLUMN \`organization\` VARCHAR(255) NULL DEFAULT ''corp.example.com''',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- ----------------------------------------------------------------------------
-- 7. eop_auth_config: missing indexes
-- ----------------------------------------------------------------------------
SET @sql := (
    SELECT IF(
        (SELECT COUNT(*) FROM information_schema.STATISTICS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_auth_config'
            AND INDEX_NAME   = 'idx_auth_active') = 0,
        'ALTER TABLE \`eop_auth_config\` ADD KEY \`idx_auth_active\` (\`is_active\`)',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCARE PREPARE stmt;

SET @sql := (
    SELECT IF(
        (SELECT COUNT(*) FROM information_schema.STATISTICS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_auth_config'
            AND INDEX_NAME   = 'idx_thumbprint') = 0,
        'ALTER TABLE \`eop_auth_config\` ADD KEY \`idx_thumbprint\` (\`certificate_thumbprint\`)',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- ----------------------------------------------------------------------------
-- 8. eop_sync_confirmations: create if absent
--    Deletions withheld during a push land here for an administrator to
--    accept or deny. The next cron run for that policy consumes the decision.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS \`eop_sync_confirmations\` (
    \`id\` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    \`policy_name\` VARCHAR(255) NOT NULL,
    \`list_type\` VARCHAR(50) NOT NULL,
    \`local_count\` INT UNSIGNED NOT NULL DEFAULT 0,
    \`remote_count\` INT UNSIGNED NOT NULL DEFAULT 0,
    \`pending_values\` MEDIUMTEXT NULL,
    \`values_truncated\` TINYINT(1) NOT NULL DEFAULT 0,
    \`status\` ENUM('pending', 'accepted', 'denied', 'applied') NOT NULL DEFAULT 'pending',
    \`requested_by\` VARCHAR(100) NOT NULL DEFAULT 'CRON_DAEMON',
    \`decided_by\` VARCHAR(100) NULL,
    \`decided_at\` DATETIME NULL,
    \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    \`updated_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY \`uniq_policy_list\` (\`policy_name\`, \`list_type\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- 9. Deactivate the placeholder row seeded by the older schema.sql
--    Matches only the known fake seed values, so a genuine wizard record is
--    never touched. Run the wizard's certificate step again if no active row
--    remains afterwards.
-- ----------------------------------------------------------------------------
UPDATE \`eop_auth_config\`
   SET \`is_active\` = 0
 WHERE \`is_active\` = 1
   AND \`certificate_thumbprint\` = '9A2F8B3C1D4E5F6A7B8C9D0E1F2A3B4C5D6E7F80'
   AND \`private_key\` LIKE '%INITIAL_SEED_PRIVATE_KEY%';

-- ============================================================================
-- Verification (all should return the expected results)
-- ============================================================================
-- SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE
--   FROM information_schema.COLUMNS
--  WHERE TABLE_SCHEMA = DATABASE()
--    AND TABLE_NAME   = 'eop_auth_config'
--    AND COLUMN_NAME IN ('private_key', 'pkcs12_bundle', 'encrypted_password');
--
-- SELECT TABLE_NAME FROM information_schema.TABLES
--  WHERE TABLE_SCHEMA = DATABASE()
--    AND TABLE_NAME   = 'eop_sync_confirmations';
--
-- SELECT id, tenant_id, certificate_thumbprint, key_type, is_active
--   FROM eop_auth_config ORDER BY id;`
  },

  // 6. index.php
  {
    name: 'index.php',
    path: 'index.php',
    description: 'Main dashboard view. Policy switcher, tabbed list tables (allowed/blocked senders & domains), counters, quick-add modal, bulk-import modal, search, pagination, and sync trigger.',
    category: 'views',
    generateContent: () => `<?php
/**
 * Main Web UI Dashboard - Exchange Online Protection Anti-Spam Manager
 */

declare(strict_types=1);

// If configuration file is missing, redirect immediately to setup wizard
if (!file_exists(__DIR__ . '/config.php')) {
    header('Location: setup.php');
    exit;
}

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';
require_once __DIR__ . '/functions.php';

// If system is already installed and locked, do not redirect to setup.php
if (!file_exists(__DIR__ . '/installed.lock')) {
    if (!Database::isConfigured()) {
        header('Location: setup.php');
        exit;
    }
    if (!Database::isInitialized()) {
        header('Location: setup.php?step=2');
        exit;
    }
}

$user = requireAuth();
$csrfToken = getCsrfToken();
$flash = getFlash();

// This page renders live MariaDB state, so it must never be served from a cache.
// Without an explicit Cache-Control a browser or intermediary is free to apply
// heuristic freshness and re-serve a stale list, which looks exactly like "the
// entries are not refreshing". header() only works before output, and nothing has
// been emitted yet at this point.
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

// Post-push summary popup data
$pushSummary = $_SESSION['push_summary'] ?? null;
unset($_SESSION['push_summary']);

// Duplicate rejected popup data
$duplicatePopup = $_SESSION['duplicate_popup'] ?? null;
unset($_SESSION['duplicate_popup']);

// Current active default policy from database or config
$defaultPolicy = Database::getDefaultPolicyName();
$selectedPolicy = $_GET['policy'] ?? ($_SESSION['active_policy'] ?? $defaultPolicy);
$_SESSION['active_policy'] = $selectedPolicy;

// Load all policies dynamically from MariaDB eop_policies and globals
$allDbPolicies = Database::getPolicies();
$availablePolicies = $GLOBALS['AVAILABLE_POLICIES'] ?? [];
foreach ($allDbPolicies as $p) {
    if (!empty($p['policy_name']) && !isset($availablePolicies[$p['policy_name']])) {
        $availablePolicies[$p['policy_name']] = $p['description'] ?? 'Custom Inbound Anti-Spam Policy';
    }
}
if (!isset($availablePolicies[$defaultPolicy])) {
    $availablePolicies[$defaultPolicy] = 'Primary Inbound Anti-Spam Policy';
}

// Withheld deletions awaiting an administrator decision, for the selected policy
$syncConfirmations = Database::getSyncConfirmations($selectedPolicy);
$pendingConfirmations = array_values(array_filter(
    $syncConfirmations,
    static fn($c) => in_array($c['status'], ['pending', 'accepted', 'denied'], true)
));

// Current active tab
$currentTab = $_GET['tab'] ?? 'allowed_senders';
if ($currentTab === 'ldap_config') {
    $currentTab = 'config_center';
}
if (!in_array($currentTab, ['allowed_senders', 'blocked_senders', 'allowed_domains', 'blocked_domains', 'sync_center', 'config_center'])) {
    $currentTab = 'allowed_senders';
}

$activeLdapConfig = Database::getLdapConfig();
$allLdapConfigs = ($currentTab === 'config_center') ? Database::getAllLdapConfigs() : [];
$activeAuthConfig = Database::getEopAuthConfig();
$allAuthConfigs = ($currentTab === 'config_center') ? Database::getAllEopAuthConfigs() : [];

$search = trim($_GET['q'] ?? '');
$page = max(1, (int)($_GET['p'] ?? 1));
$limit = 25;
$offset = ($page - 1) * $limit;

// Fetch counters for all 4 tables for the selected policy
$allowedSendersCount = Database::countListItems('allowed_senders', $selectedPolicy);
$blockedSendersCount = Database::countListItems('blocked_senders', $selectedPolicy);
$allowedDomainsCount = Database::countListItems('allowed_domains', $selectedPolicy);
$blockedDomainsCount = Database::countListItems('blocked_domains', $selectedPolicy);

// Fetch items for the active tab
$listItems = [];
$totalItems = 0;
if (in_array($currentTab, ['allowed_senders', 'blocked_senders', 'allowed_domains', 'blocked_domains'])) {
    $listItems = Database::getListItems($currentTab, $selectedPolicy, $search, $limit, $offset);
    $totalItems = Database::countListItems($currentTab, $selectedPolicy, $search);
}

$totalPages = max(1, (int)ceil($totalItems / $limit));

// Fingerprint of what this render is based on. The page polls the data_version
// action and reloads when the token moves, so a cron run that changed the lists
// shows up without the administrator having to reload by hand. A reload is the
// only update path here because the page is server-rendered, and the no-store
// headers above guarantee the reloaded response is rebuilt from MariaDB rather
// than from any cache.
$dataVersion = Database::getDataVersion($selectedPolicy);
?>
<!DOCTYPE html>
<html lang="en" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars(APP_TITLE) ?> - <?= htmlspecialchars($selectedPolicy) ?></title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        brand: {
                            50: '#eff6ff',
                            500: '#3b82f6',
                            600: '#2563eb',
                            700: '#1d4ed8',
                        }
                    }
                }
            }
        };
        // Initialize dark mode from localStorage or system preference
        if (localStorage.getItem('theme') === 'dark' || (!localStorage.getItem('theme') && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
            document.documentElement.classList.add('dark');
        } else {
            document.documentElement.classList.remove('dark');
        }
    </script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        .active-tab { border-bottom: 2px solid #2563eb; color: #2563eb; font-weight: 600; }
        .dark .active-tab { border-bottom: 2px solid #60a5fa; color: #60a5fa; font-weight: 600; }
    </style>
</head>
<body class="bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-100 min-h-screen flex flex-col font-sans transition-colors duration-200">

    <!-- Top Navigation Bar -->
    <header class="bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 sticky top-0 z-30 shadow-xs transition-colors duration-200">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
            <div class="flex items-center space-x-3">
                <div class="w-9 h-9 rounded-lg bg-blue-600 dark:bg-blue-500 text-white flex items-center justify-center font-bold text-lg shadow-sm">
                    <i class="fa-solid fa-shield-halved"></i>
                </div>
                <div>
                    <h1 class="text-base font-bold text-slate-900 dark:text-white leading-tight"><?= htmlspecialchars(APP_TITLE) ?></h1>
                </div>
            </div>

            <!-- Policy Selector, Dark Mode Toggle & User Profile -->
            <div class="flex items-center space-x-4">
                <!-- Policy Dropdown -->
                <form method="GET" action="index.php" class="flex items-center">
                    <input type="hidden" name="tab" value="<?= htmlspecialchars($currentTab) ?>">
                    <label for="policySelect" class="text-xs font-semibold text-slate-500 dark:text-slate-400 mr-2 uppercase tracking-wider">Policy:</label>
                    <select id="policySelect" name="policy" onchange="this.form.submit()"
                            class="bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-100 text-sm rounded-md px-3 py-1.5 focus:ring-2 focus:ring-blue-500 focus:outline-hidden font-medium">
                        <?php foreach ($availablePolicies as $polName => $polDesc): ?>
                            <option value="<?= htmlspecialchars($polName) ?>" <?= $polName === $selectedPolicy ? 'selected' : '' ?>>
                                <?= htmlspecialchars($polName) ?><?= ($polName === $defaultPolicy) ? ' (Default)' : '' ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </form>

                <!-- Push Changes from MariaDB to EOP Button -->
                <form method="POST" action="actions.php" class="inline" onsubmit="return confirm('Push all MariaDB changes for policy &quot;<?= htmlspecialchars($selectedPolicy) ?>&quot; to Microsoft 365 Exchange Online Protection?');">
                    <input type="hidden" name="action" value="trigger_sync">
                    <input type="hidden" name="direction" value="push">
                    <input type="hidden" name="policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                    <button type="submit" 
                            class="px-3.5 py-1.5 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white rounded-lg text-xs font-bold flex items-center space-x-1.5 shadow-xs transition cursor-pointer"
                            title="Push changes from MariaDB tables to Exchange Online Protection (EOP)">
                        <i class="fa-solid fa-cloud-arrow-up"></i>
                        <span>Push to EOP</span>
                    </button>
                </form>

                <!-- Direct Link to Configuration Page -->
                <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=config_center" 
                   class="px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition <?= in_array($currentTab, ['config_center', 'ldap_config']) ? 'bg-indigo-600 text-white shadow-xs' : 'bg-indigo-50 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-800 hover:bg-indigo-100 dark:hover:bg-indigo-900/60' ?>"
                   title="Open Configuration Page (Upload Private Key & Modify LDAP Settings)">
                    <i class="fa-solid fa-key"></i>
                    <span>Configuration Page</span>
                </a>

                <!-- Dark Mode Toggle Button -->
                <button type="button" id="themeToggleBtn" onclick="toggleTheme()" 
                        class="p-2 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 bg-slate-100 dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 transition" 
                        title="Toggle Dark / Light Mode">
                    <i id="themeIcon" class="fa-solid fa-moon text-sm"></i>
                </button>

                <!-- AD User Badge -->
                <div class="flex items-center pl-3 border-l border-slate-200 dark:border-slate-800 space-x-3">
                    <div class="text-right">
                        <div class="text-sm font-semibold text-slate-800 dark:text-slate-200 flex items-center justify-end space-x-1">
                            <span><?= htmlspecialchars($user['displayName'] ?? $user['username']) ?></span>
                            <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/40">AD Verified</span>
                        </div>
                        <div class="text-[11px] text-slate-500 dark:text-slate-400" title="<?= htmlspecialchars($user['groupDn'] ?? '') ?>">
                            <?= htmlspecialchars($user['username']) ?>
                        </div>
                    </div>
                    <a href="logout.php" class="text-slate-400 hover:text-rose-600 dark:hover:text-rose-400 transition p-1.5 rounded-md hover:bg-rose-50 dark:hover:bg-rose-950/40" title="Sign Out">
                        <i class="fa-solid fa-right-from-bracket text-base"></i>
                    </a>
                </div>
            </div>
        </div>
    </header>

    <!-- Main Container -->
    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 grow w-full">

        <!-- Flash Alert (auto-dismisses, with a visible countdown) -->
        <?php
        // 5s was too short to read a long message, let alone act on it - a
        // confirm-then-navigate flow could lose the prompt mid-read. 20s with a
        // live countdown and a progress bar; the close button still dismisses
        // immediately, and hovering pauses the countdown.
        $flashAutoDismissMs = 20000;
        ?>
        <?php if ($flash): ?>
            <div id="flashAlertBanner" data-autodismiss-ms="<?= $flashAutoDismissMs ?>" class="mb-5 p-4 rounded-lg flex items-center justify-between gap-3 border transition-all duration-300 relative overflow-hidden <?= $flash['type'] === 'success' ? 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-800 dark:text-emerald-200 border-emerald-200 dark:border-emerald-800/60' : ($flash['type'] === 'error' ? 'bg-rose-50 dark:bg-rose-950/40 text-rose-800 dark:text-rose-200 border-rose-200 dark:border-rose-800/60' : ($flash['type'] === 'warning' ? 'bg-amber-50 dark:bg-amber-950/40 text-amber-900 dark:text-amber-200 border-amber-200 dark:border-amber-800/60' : 'bg-blue-50 dark:bg-blue-950/40 text-blue-800 dark:text-blue-200 border-blue-200 dark:border-blue-800/60')) ?>">
                <div class="flex items-center space-x-2 min-w-0">
                    <i class="fa-solid <?= $flash['type'] === 'success' ? 'fa-circle-check text-emerald-600 dark:text-emerald-400' : ($flash['type'] === 'warning' ? 'fa-triangle-exclamation text-amber-600 dark:text-amber-400' : 'fa-circle-exclamation text-rose-600 dark:text-rose-400') ?>"></i>
                    <span class="text-sm font-medium"><?= htmlspecialchars($flash['message']) ?></span>
                </div>
                <div class="flex items-center gap-2 shrink-0">
                    <span class="text-[11px] text-slate-500 dark:text-slate-400 font-mono tabular-nums whitespace-nowrap" title="Auto-dismisses in 20 seconds. Hover to pause.">
                        <span id="flashCountdown">20</span>s
                    </span>
                    <button onclick="this.closest('#flashAlertBanner').remove()" title="Dismiss now" aria-label="Dismiss notification" class="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 text-sm cursor-pointer p-1"><i class="fa-solid fa-xmark"></i></button>
                </div>
                <span id="flashProgressTrack" class="absolute left-0 bottom-0 h-0.5 w-full bg-black/5 dark:bg-white/5" aria-hidden="true">
                    <span id="flashProgressBar" class="block h-full w-full origin-left bg-current opacity-30"></span>
                </span>
            </div>
            <script>
                (function () {
                    const el = document.getElementById('flashAlertBanner');
                    if (!el) return;

                    const total = parseInt(el.dataset.autodismissMs, 10) || 20000;
                    const label = document.getElementById('flashCountdown');
                    const bar = document.getElementById('flashProgressBar');

                    // driven by an absolute deadline rather than a decrementing
                    // counter, so a backgrounded or throttled tab cannot drift
                    let remaining = total;
                    let last = performance.now();
                    let paused = false;

                    const dismiss = function () {
                        el.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
                        el.style.opacity = '0';
                        el.style.transform = 'translateY(-6px)';
                        setTimeout(function () { el.remove(); }, 400);
                    };

                    // Only touch the DOM when a value actually changes: the rAF
                    // loop runs ~60x/s and the countdown only changes once a second.
                    let lastSecond = null;
                    let lastScale = null;
                    const render = function (force) {
                        const scale = Math.max(0, remaining / total);
                        const second = Math.max(0, Math.ceil(remaining / 1000));
                        if (label && (force || second !== lastSecond)) {
                            label.textContent = String(second);
                            lastSecond = second;
                        }
                        if (bar && (force || scale !== lastScale)) {
                            bar.style.transform = 'scaleX(' + scale + ')';
                            lastScale = scale;
                        }
                    };

                    // Hovering pauses so a message cannot vanish mid-read.
                    el.addEventListener('mouseenter', function () { paused = true; render(true); });
                    el.addEventListener('mouseleave', function () {
                        if (remaining <= 0) return;
                        paused = false;
                        last = performance.now();
                        render(true);
                    });

                    render(true);

                    const tick = function (now) {
                        const delta = now - last;
                        last = now;
                        if (!paused) remaining -= delta;
                        render(false);
                        if (remaining <= 0) {
                            dismiss();
                            return;
                        }
                        requestAnimationFrame(tick);
                    };
                    requestAnimationFrame(tick);
                })();
            </script>
        <?php endif; ?>

        <!-- Withheld Deletion Warning: cron pulled an empty list but local entries exist -->
        <?php if ($pendingConfirmations !== []): ?>
            <div class="mb-5 p-4 rounded-xl bg-rose-50 dark:bg-rose-950/30 border border-rose-300 dark:border-rose-800/70 text-xs text-rose-900 dark:text-rose-200 space-y-3">
                <div class="flex items-start gap-2.5">
                    <i class="fa-solid fa-triangle-exclamation text-rose-600 dark:text-rose-400 mt-0.5"></i>
                    <div class="space-y-1">
                        <div class="font-bold text-sm text-rose-800 dark:text-rose-300">Deletion withheld for policy &ldquo;<?= htmlspecialchars($selectedPolicy) ?>&rdquo;</div>
                        <p class="leading-relaxed">
                            A sync run pulled an <strong>empty</strong> list from Exchange Online while local entries still exist.
                            Cron has <strong>not deleted anything</strong>. An empty pull is indistinguishable from a policy
                            that genuinely has no entries, so confirm before allowing the removal.
                        </p>
                    </div>
                </div>

                <?php foreach ($pendingConfirmations as $conf): ?>
                    <?php
                    $confList = (string)$conf['list_type'];
                    $confStatus = (string)$conf['status'];
                    $confCount = (int)$conf['local_count'];
                    $confValues = json_decode((string)($conf['pending_values'] ?? '[]'), true);
                    $confValues = is_array($confValues) ? $confValues : [];
                    $confTruncated = !empty($conf['values_truncated']);
                    $confAskedAt = (string)($conf['created_at'] ?? '');
                    $confDecidedBy = (string)($conf['decided_by'] ?? '');
                    $confLabels = [
                        'allowed_senders' => 'Allowed Senders',
                        'blocked_senders' => 'Blocked Senders',
                        'allowed_domains' => 'Allowed Domains',
                        'blocked_domains' => 'Blocked Domains',
                    ];
                    $confLabel = $confLabels[$confList] ?? $confList;
                    ?>
                    <div class="rounded-lg border border-rose-200 dark:border-rose-800/60 bg-white/60 dark:bg-slate-900/40 p-3 space-y-2">
                        <div class="flex flex-wrap items-center justify-between gap-2">
                            <div class="font-semibold flex items-center gap-2 flex-wrap">
                                <a href="?policy=<?= urlencode($selectedPolicy) ?>&amp;tab=<?= urlencode($confList) ?>" class="underline decoration-dotted underline-offset-2"><?= htmlspecialchars($confLabel) ?></a>
                                <span class="font-mono font-normal text-[11px] px-1.5 py-0.5 rounded bg-rose-100 dark:bg-rose-950/60 border border-rose-200 dark:border-rose-800/60"><?= number_format($confCount) ?> local entries</span>
                                <?php if ($confStatus === 'accepted'): ?>
                                    <span class="text-[11px] font-semibold px-1.5 py-0.5 rounded bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800/60">Deletion approved &mdash; awaiting next cron run</span>
                                <?php elseif ($confStatus === 'denied'): ?>
                                    <span class="text-[11px] font-semibold px-1.5 py-0.5 rounded bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800/60">Deletion denied &mdash; entries kept</span>
                                <?php else: ?>
                                    <span class="text-[11px] font-semibold px-1.5 py-0.5 rounded bg-rose-200 dark:bg-rose-900/60 text-rose-900 dark:text-rose-200 border border-rose-300 dark:border-rose-800/60">Decision required</span>
                                <?php endif; ?>
                            </div>
                        </div>

                        <?php if ($confValues !== []): ?>
                            <details class="text-[11px]">
                                <summary class="cursor-pointer select-none text-rose-800 dark:text-rose-300 font-medium">
                                    Entries that would be removed<?= count($confValues) > 25 ? ' (showing first 25 of ' . number_format(count($confValues)) . ')' : '' ?>
                                </summary>
                                <div class="mt-1.5 font-mono text-[11px] break-words leading-relaxed text-rose-800/90 dark:text-rose-300/90 max-h-32 overflow-y-auto">
                                    <?= htmlspecialchars(implode(', ', array_slice($confValues, 0, 25))) ?>
                                    <?php if ($confTruncated): ?>
                                        <span class="block mt-1 font-sans italic">(list truncated for storage; only the captured entries would be removed)</span>
                                    <?php endif; ?>
                                </div>
                            </details>
                        <?php endif; ?>

                        <div class="flex flex-wrap items-center gap-2 pt-1">
                            <?php if ($confStatus === 'pending'): ?>
                                <form method="POST" action="actions.php" class="inline" onsubmit="return confirm('Delete all <?= number_format($confCount) ?> <?= htmlspecialchars($confLabel) ?> entries for policy <?= htmlspecialchars($selectedPolicy) ?>? They are absent from Exchange Online, but you are approving a bulk removal of local data.');">
                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                                    <input type="hidden" name="action" value="resolve_sync_confirmation">
                                    <input type="hidden" name="target_policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                                    <input type="hidden" name="target_list" value="<?= htmlspecialchars($confList) ?>">
                                    <input type="hidden" name="decision" value="denied">
                                    <button type="submit" class="px-3 py-1.5 rounded-lg bg-white dark:bg-slate-800 border border-rose-300 dark:border-rose-700 text-rose-800 dark:text-rose-200 text-[11px] font-semibold hover:bg-rose-100 dark:hover:bg-rose-900/50 transition">
                                        Deny &mdash; keep entries
                                    </button>
                                </form>
                                <form method="POST" action="actions.php" class="inline" onsubmit="return confirm('Delete all <?= number_format($confCount) ?> <?= htmlspecialchars($confLabel) ?> entries for policy <?= htmlspecialchars($selectedPolicy) ?>? This cannot be undone from the web UI.');">
                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                                    <input type="hidden" name="action" value="resolve_sync_confirmation">
                                    <input type="hidden" name="target_policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                                    <input type="hidden" name="target_list" value="<?= htmlspecialchars($confList) ?>">
                                    <input type="hidden" name="decision" value="accepted">
                                    <button type="submit" class="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-[11px] font-semibold shadow-xs transition">
                                        Accept &mdash; delete on next cron run
                                    </button>
                                </form>
                            <?php else: ?>
                                <span class="text-[11px] text-rose-800/80 dark:text-rose-300/80">
                                    <?php if ($confStatus === 'accepted'): ?>
                                        Decision recorded<?= $confDecidedBy !== '' ? ' by ' . htmlspecialchars($confDecidedBy) : '' ?>. The next cron run for this policy applies it.
                                    <?php else: ?>
                                        Deletion denied<?= $confDecidedBy !== '' ? ' by ' . htmlspecialchars($confDecidedBy) : '' ?>. These entries stay until a later pull removes them, and the confirmation clears once the remote list returns data.
                                    <?php endif; ?>
                                </span>
                                <form method="POST" action="actions.php" class="inline">
                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                                    <input type="hidden" name="action" value="resolve_sync_confirmation">
                                    <input type="hidden" name="target_policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                                    <input type="hidden" name="target_list" value="<?= htmlspecialchars($confList) ?>">
                                    <input type="hidden" name="decision" value="<?= $confStatus === 'accepted' ? 'denied' : 'accepted' ?>">
                                    <button type="submit" class="px-2.5 py-1 rounded-lg bg-white dark:bg-slate-800 border border-rose-300 dark:border-rose-700 text-rose-800 dark:text-rose-200 text-[11px] font-semibold hover:bg-rose-100 dark:hover:bg-rose-900/50 transition">
                                        <?= $confStatus === 'accepted' ? 'Revoke approval' : 'Approve after all' ?>
                                    </button>
                                </form>
                            <?php endif; ?>
                            <?php if ($confAskedAt !== ''): ?>
                                <span class="text-[11px] text-rose-700/70 dark:text-rose-400/70 ml-auto">first seen <?= htmlspecialchars($confAskedAt) ?></span>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <!-- Policy Summary Cards -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
            <!-- Allowed Senders -->
            <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=allowed_senders" 
               class="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs hover:border-emerald-400 dark:hover:border-emerald-500 transition block <?= $currentTab === 'allowed_senders' ? 'ring-2 ring-emerald-500' : '' ?>">
                <div class="flex items-center justify-between">
                    <span class="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Allowed Senders</span>
                    <span class="w-7 h-7 rounded-full bg-emerald-50 dark:bg-emerald-950/50 text-emerald-600 dark:text-emerald-400 flex items-center justify-center text-xs"><i class="fa-solid fa-envelope-circle-check"></i></span>
                </div>
                <div class="mt-2 text-2xl font-bold text-slate-900 dark:text-white"><?= number_format($allowedSendersCount) ?></div>
                <div class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">Table: <code>eop_allowed_senders</code></div>
            </a>

            <!-- Blocked Senders -->
            <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=blocked_senders" 
               class="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs hover:border-rose-400 dark:hover:border-rose-500 transition block <?= $currentTab === 'blocked_senders' ? 'ring-2 ring-rose-500' : '' ?>">
                <div class="flex items-center justify-between">
                    <span class="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Blocked Senders</span>
                    <span class="w-7 h-7 rounded-full bg-rose-50 dark:bg-rose-950/50 text-rose-600 dark:text-rose-400 flex items-center justify-center text-xs"><i class="fa-solid fa-envelope-circle-xmark"></i></span>
                </div>
                <div class="mt-2 text-2xl font-bold text-slate-900 dark:text-white"><?= number_format($blockedSendersCount) ?></div>
                <div class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">Table: <code>eop_blocked_senders</code></div>
            </a>

            <!-- Allowed Domains -->
            <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=allowed_domains" 
               class="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs hover:border-blue-400 dark:hover:border-blue-500 transition block <?= $currentTab === 'allowed_domains' ? 'ring-2 ring-blue-500' : '' ?>">
                <div class="flex items-center justify-between">
                    <span class="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Allowed Domains</span>
                    <span class="w-7 h-7 rounded-full bg-blue-50 dark:bg-blue-950/50 text-blue-600 dark:text-blue-400 flex items-center justify-center text-xs"><i class="fa-solid fa-globe"></i></span>
                </div>
                <div class="mt-2 text-2xl font-bold text-slate-900 dark:text-white"><?= number_format($allowedDomainsCount) ?></div>
                <div class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">Table: <code>eop_allowed_domains</code></div>
            </a>

            <!-- Blocked Domains -->
            <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=blocked_domains" 
               class="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs hover:border-amber-400 dark:hover:border-amber-500 transition block <?= $currentTab === 'blocked_domains' ? 'ring-2 ring-amber-500' : '' ?>">
                <div class="flex items-center justify-between">
                    <span class="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Blocked Domains</span>
                    <span class="w-7 h-7 rounded-full bg-amber-50 dark:bg-amber-950/50 text-amber-600 dark:text-amber-400 flex items-center justify-center text-xs"><i class="fa-solid fa-ban"></i></span>
                </div>
                <div class="mt-2 text-2xl font-bold text-slate-900 dark:text-white"><?= number_format($blockedDomainsCount) ?></div>
                <div class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">Table: <code>eop_blocked_domains</code></div>
            </a>

            <!-- Configuration Center Card -->
            <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=config_center" 
               class="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs hover:border-indigo-400 dark:hover:border-indigo-500 transition block <?= in_array($currentTab, ['config_center', 'ldap_config']) ? 'ring-2 ring-indigo-500' : '' ?>">
                <div class="flex items-center justify-between">
                    <span class="text-xs font-semibold text-indigo-600 dark:text-indigo-400 uppercase tracking-wider">Configuration</span>
                    <span class="w-7 h-7 rounded-full bg-indigo-50 dark:bg-indigo-950/50 text-indigo-600 dark:text-indigo-400 flex items-center justify-center text-xs"><i class="fa-solid fa-key"></i></span>
                </div>
                <div class="mt-2 text-base font-bold text-slate-900 dark:text-white flex items-center justify-between">
                    <span>EOP &amp; LDAP</span>
                    <span class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 font-semibold">DB Stored</span>
                </div>
                <div class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">Tables: <code>eop_auth &amp; eop_ldap</code></div>
            </a>
        </div>

        <!-- Navigation Tabs -->
        <div class="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs overflow-hidden transition-colors duration-200">
            <div class="border-b border-slate-200 dark:border-slate-800 px-6 flex items-center justify-between flex-wrap gap-2">
                <nav class="flex space-x-6">
                    <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=allowed_senders" 
                       class="py-4 text-sm <?= $currentTab === 'allowed_senders' ? 'active-tab' : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200' ?>">
                        <i class="fa-solid fa-envelope-circle-check text-emerald-600 dark:text-emerald-400 mr-1.5"></i> Allowed Senders (<?= $allowedSendersCount ?>)
                    </a>
                    <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=blocked_senders" 
                       class="py-4 text-sm <?= $currentTab === 'blocked_senders' ? 'active-tab' : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200' ?>">
                        <i class="fa-solid fa-envelope-circle-xmark text-rose-600 dark:text-rose-400 mr-1.5"></i> Blocked Senders (<?= $blockedSendersCount ?>)
                    </a>
                    <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=allowed_domains" 
                       class="py-4 text-sm <?= $currentTab === 'allowed_domains' ? 'active-tab' : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200' ?>">
                        <i class="fa-solid fa-globe text-blue-600 dark:text-blue-400 mr-1.5"></i> Allowed Domains (<?= $allowedDomainsCount ?>)
                    </a>
                    <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=blocked_domains" 
                       class="py-4 text-sm <?= $currentTab === 'blocked_domains' ? 'active-tab' : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200' ?>">
                        <i class="fa-solid fa-ban text-amber-600 dark:text-amber-400 mr-1.5"></i> Blocked Domains (<?= $blockedDomainsCount ?>)
                    </a>
                    <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=sync_center" 
                       class="py-4 text-sm <?= $currentTab === 'sync_center' ? 'active-tab' : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200' ?>">
                        <i class="fa-solid fa-rotate text-indigo-600 dark:text-indigo-400 mr-1.5"></i> Exchange Sync
                    </a>
                    <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=config_center" 
                       class="py-4 text-sm <?= $currentTab === 'config_center' ? 'active-tab' : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200' ?>">
                        <i class="fa-solid fa-key text-purple-600 dark:text-purple-400 mr-1.5"></i> Configuration (Keys & LDAP)
                    </a>
                </nav>

                <!-- Action Buttons -->
                <?php if (!in_array($currentTab, ['sync_center', 'config_center', 'ldap_config'])): ?>
                <div class="flex items-center space-x-2 py-2">
                    <button onclick="document.getElementById('quickAddModal').classList.remove('hidden')" 
                            class="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-md shadow-xs flex items-center space-x-1.5 transition">
                        <i class="fa-solid fa-plus"></i>
                        <span>Add Entry</span>
                    </button>
                    <button onclick="document.getElementById('bulkAddModal').classList.remove('hidden')" 
                            class="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-semibold rounded-md flex items-center space-x-1.5 transition">
                        <i class="fa-solid fa-file-import"></i>
                        <span>Bulk Import</span>
                    </button>
                    <!-- Split Smart Sort Buttons: Allowed and Blocked -->
                    <button type="button" onclick="openSmartSortModal('allowed')" 
                            class="px-3 py-1.5 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-700 hover:to-teal-700 text-white text-xs font-semibold rounded-md shadow-xs flex items-center space-x-1.5 transition cursor-pointer"
                            title="Auto-sort mixed senders &amp; domains directly into Allowed tables">
                        <i class="fa-solid fa-shield-halved text-emerald-200"></i>
                        <span>Smart Sort Allowed</span>
                    </button>
                    <button type="button" onclick="openSmartSortModal('blocked')" 
                            class="px-3 py-1.5 bg-gradient-to-r from-rose-600 to-red-600 hover:from-rose-700 hover:to-red-700 text-white text-xs font-semibold rounded-md shadow-xs flex items-center space-x-1.5 transition cursor-pointer"
                            title="Auto-sort mixed senders &amp; domains directly into Blocked tables">
                        <i class="fa-solid fa-ban text-rose-200"></i>
                        <span>Smart Sort Blocked</span>
                    </button>
                    <a href="actions.php?action=export_csv&list=<?= $currentTab ?>&policy=<?= urlencode($selectedPolicy) ?>&csrf=<?= $csrfToken ?>" 
                       class="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-semibold rounded-md flex items-center space-x-1.5 transition">
                        <i class="fa-solid fa-file-arrow-down"></i>
                        <span>Export CSV</span>
                    </a>

                    <!-- Push to EOP Action Button -->
                    <form method="POST" action="actions.php" class="inline" onsubmit="return confirm('Push all MariaDB changes for policy &quot;<?= htmlspecialchars($selectedPolicy) ?>&quot; to Microsoft 365 Exchange Online Protection?');">
                        <input type="hidden" name="action" value="trigger_sync">
                        <input type="hidden" name="direction" value="push">
                        <input type="hidden" name="policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                        <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                        <button type="submit" 
                                class="px-3.5 py-1.5 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white text-xs font-bold rounded-md shadow-xs flex items-center space-x-1.5 transition cursor-pointer"
                                title="Push all changes from MariaDB tables to Exchange Online Protection (EOP)">
                            <i class="fa-solid fa-cloud-arrow-up"></i>
                            <span>Push Changes to EOP</span>
                        </button>
                    </form>
                </div>
                <?php endif; ?>
            </div>

            <!-- List Content -->
            <?php if ($currentTab === 'sync_center'): ?>
                <!-- Exchange Online Sync View -->
                <div class="p-6">
                    <div class="max-w-4xl space-y-6">
                        <div>
                            <h2 class="text-lg font-bold text-slate-900 dark:text-white mb-1">Exchange Online Protection Synchronization</h2>
                            <p class="text-sm text-slate-600 dark:text-slate-400">
                                Synchronize the 4 MariaDB tables for policy <strong class="text-blue-600 dark:text-blue-400"><?= htmlspecialchars($selectedPolicy) ?></strong> with Microsoft 365 Exchange Online Protection.
                            </p>
                        </div>

                        <!-- Scheduled Cron Policy Notice Banner -->
                        <div class="p-4 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800/60 text-xs text-amber-900 dark:text-amber-200 space-y-1.5 leading-relaxed">
                            <div class="font-bold flex items-center gap-1.5 text-amber-800 dark:text-amber-300">
                                <i class="fa-solid fa-clock-rotate-left"></i>
                                <span>Cron Policy Enforcement: Pull-Only Mode</span>
                            </div>
                            <p>
                                The scheduled Linux cron job (<code>cron-sync.php --action=pull</code>) runs every 15 minutes and <strong>only pulls changes from Exchange Online into MariaDB</strong>.
                                It does <strong>not</strong> push local changes to EOP. Pushing local MariaDB modifications to Microsoft 365 requires an intentional administrator action.
                            </p>
                        </div>

                        <!-- Commands Preview -->
                        <div class="space-y-3">
                            <div class="bg-slate-900 dark:bg-slate-950 border border-slate-800 text-slate-100 rounded-lg p-4 font-mono text-xs overflow-x-auto shadow-inner">
                                <div class="text-amber-400 font-bold mb-1"># 1. Cron Job Command (PULL ONLY from EOP):</div>
                                <div class="text-slate-300">Get-HostedContentFilterPolicy -Identity "<?= htmlspecialchars($selectedPolicy) ?>"</div>
                                <div class="text-slate-500 text-[11px] mt-1"># Queries Microsoft 365 and ingests any external updates into MariaDB</div>
                            </div>

                            <div class="bg-slate-900 dark:bg-slate-950 border border-slate-800 text-slate-100 rounded-lg p-4 font-mono text-xs overflow-x-auto shadow-inner">
                                <div class="text-indigo-400 font-bold mb-1"># 2. Manual Admin Command (PUSH to EOP):</div>
                                <div class="text-emerald-400">Set-HostedContentFilterPolicy \`</div>
                                <div class="pl-4 text-slate-200">-Identity "<?= htmlspecialchars($selectedPolicy) ?>" \`</div>
                                <div class="pl-4 text-blue-300">-AllowedSenders @('<?= implode("', '", array_slice(Database::getAllItemsForSync('allowed_senders', $selectedPolicy), 0, 5)) ?><?= $allowedSendersCount > 5 ? "', ... +".($allowedSendersCount-5)." more" : "" ?>') \`</div>
                                <div class="pl-4 text-rose-300">-BlockedSenders @('<?= implode("', '", array_slice(Database::getAllItemsForSync('blocked_senders', $selectedPolicy), 0, 5)) ?><?= $blockedSendersCount > 5 ? "', ... +".($blockedSendersCount-5)." more" : "" ?>') \`</div>
                                <div class="pl-4 text-cyan-300">-AllowedSenderDomains @('<?= implode("', '", array_slice(Database::getAllItemsForSync('allowed_domains', $selectedPolicy), 0, 5)) ?><?= $allowedDomainsCount > 5 ? "', ... +".($allowedDomainsCount-5)." more" : "" ?>') \`</div>
                                <div class="pl-4 text-amber-300">-BlockedSenderDomains @('<?= implode("', '", array_slice(Database::getAllItemsForSync('blocked_domains', $selectedPolicy), 0, 5)) ?><?= $blockedDomainsCount > 5 ? "', ... +".($blockedDomainsCount-5)." more" : "" ?>')</div>
                            </div>
                        </div>

                        <!-- Sync Action Forms -->
                        <div class="flex flex-wrap items-center gap-3 pt-2">
                            <!-- Pull Form (Same as Cron) -->
                            <form method="POST" action="actions.php">
                                <input type="hidden" name="action" value="trigger_sync">
                                <input type="hidden" name="direction" value="pull">
                                <input type="hidden" name="policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">

                                <button type="submit" class="px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center space-x-2 transition">
                                    <i class="fa-solid fa-cloud-arrow-down"></i>
                                    <span>Pull from Exchange Online (Cron Mode)</span>
                                </button>
                            </form>

                            <!-- Push Form (Manual Admin) -->
                            <form method="POST" action="actions.php" onsubmit="return confirm('Are you sure you want to push all MariaDB entries to Microsoft 365 Exchange Online Protection?');">
                                <input type="hidden" name="action" value="trigger_sync">
                                <input type="hidden" name="direction" value="push">
                                <input type="hidden" name="policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">

                                <button type="submit" class="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center space-x-2 transition">
                                    <i class="fa-solid fa-cloud-arrow-up"></i>
                                    <span>Push Changes to Exchange Online (Admin)</span>
                                </button>
                            </form>
                        </div>
                    </div>
                </div>

            <?php elseif (in_array($currentTab, ['config_center', 'ldap_config'])): ?>
                <!-- Unified Configuration Page: EOP Private Key & AD LDAP Settings -->
                <div class="p-6">
                    <div class="max-w-5xl">
                        <!-- Overview Header -->
                        <div class="flex items-start justify-between flex-wrap gap-4 mb-6 pb-6 border-b border-slate-200 dark:border-slate-800">
                            <div>
                                <h2 class="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
                                    <i class="fa-solid fa-sliders text-indigo-600 dark:text-indigo-400"></i>
                                    <span>System Configuration & Credentials</span>
                                </h2>
                                <p class="text-xs text-slate-500 dark:text-slate-400 mt-1">
                                    Manage Exchange Online Protection private key authentication and Active Directory LDAP connection parameters stored in remote MariaDB tables.
                                </p>
                            </div>

                            <div class="flex items-center gap-2 flex-wrap">
                                <span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/60 font-mono">
                                    <i class="fa-solid fa-shield-halved text-[10px]"></i>
                                    Table: eop_policies
                                </span>
                                <span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-blue-100 dark:bg-blue-950/60 text-blue-800 dark:text-blue-300 border border-blue-200 dark:border-blue-800/60 font-mono">
                                    <i class="fa-solid fa-key text-[10px]"></i>
                                    Table: eop_auth_config
                                </span>
                                <span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-purple-100 dark:bg-purple-950/60 text-purple-800 dark:text-purple-300 border border-purple-200 dark:border-purple-800/60 font-mono">
                                    <i class="fa-solid fa-database text-[10px]"></i>
                                    Table: eop_ldap_config
                                </span>
                            </div>
                        </div>

                        <!-- Active Credentials Status Strip -->
                        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
                            <!-- Default Policy Status -->
                            <div class="p-4 rounded-xl border border-emerald-200 dark:border-emerald-900/60 bg-emerald-50/60 dark:bg-emerald-950/30">
                                <div class="flex items-center justify-between mb-2">
                                    <div class="flex items-center gap-2 font-bold text-xs text-emerald-900 dark:text-emerald-200">
                                        <i class="fa-solid fa-shield-halved text-emerald-600 dark:text-emerald-400"></i>
                                        <span>Default Anti-Spam Policy</span>
                                    </div>
                                    <span class="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/60">
                                        <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                                        Active Cron Target
                                    </span>
                                </div>
                                <div class="space-y-1 text-xs text-slate-600 dark:text-slate-300 font-mono">
                                    <div class="flex justify-between">
                                        <span class="text-slate-400">Policy:</span>
                                        <span class="font-bold text-slate-800 dark:text-slate-100 truncate max-w-[150px]" title="<?= htmlspecialchars($defaultPolicy) ?>"><?= htmlspecialchars($defaultPolicy) ?></span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span class="text-slate-400">Cron Mode:</span>
                                        <span class="text-emerald-700 dark:text-emerald-300 font-semibold">PULL-ONLY</span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span class="text-slate-400">Sync Script:</span>
                                        <span class="truncate max-w-[150px]">sync-exchange.ps1</span>
                                    </div>
                                </div>
                            </div>

                            <!-- EOP Private Key Status -->
                            <div class="p-4 rounded-xl border border-blue-200 dark:border-blue-900/60 bg-blue-50/60 dark:bg-blue-950/30">
                                <div class="flex items-center justify-between mb-2">
                                    <div class="flex items-center gap-2 font-bold text-xs text-blue-900 dark:text-blue-200">
                                        <i class="fa-solid fa-key text-blue-600 dark:text-blue-400"></i>
                                        <span>Exchange Online CBA Auth</span>
                                    </div>
                                    <span class="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/60">
                                        <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                                        DB Record #<?= htmlspecialchars((string)($activeAuthConfig['id'] ?? 1)) ?>
                                    </span>
                                </div>
                                <div class="space-y-1 text-xs text-slate-600 dark:text-slate-300 font-mono">
                                    <div class="flex justify-between">
                                        <span class="text-slate-400">Thumbprint:</span>
                                        <span class="font-bold text-slate-800 dark:text-slate-100"><?= htmlspecialchars(substr($activeAuthConfig['certificate_thumbprint'] ?? (defined('M365_CERT_THUMBPRINT') ? M365_CERT_THUMBPRINT : '9A2F8B3C1D4E5F6A'), 0, 16)) ?>...</span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span class="text-slate-400">Key File:</span>
                                        <span class="truncate max-w-[140px]"><?= htmlspecialchars($activeAuthConfig['key_filename'] ?? 'eop-cert.pfx') ?></span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span class="text-slate-400">Passphrase:</span>
                                        <span class="text-emerald-600 dark:text-emerald-400 font-semibold flex items-center gap-1">
                                            <i class="fa-solid fa-lock text-[10px]"></i> Encrypted
                                        </span>
                                    </div>
                                </div>
                            </div>

                            <!-- LDAP Status -->
                            <div class="p-4 rounded-xl border border-purple-200 dark:border-purple-900/60 bg-purple-50/60 dark:bg-purple-950/30">
                                <div class="flex items-center justify-between mb-2">
                                    <div class="flex items-center gap-2 font-bold text-xs text-purple-900 dark:text-purple-200">
                                        <i class="fa-solid fa-network-wired text-purple-600 dark:text-purple-400"></i>
                                        <span>Active Directory LDAP</span>
                                    </div>
                                    <span class="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/60">
                                        <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                                        DB Record #<?= htmlspecialchars((string)($activeLdapConfig['id'] ?? 1)) ?>
                                    </span>
                                </div>
                                <div class="space-y-1 text-xs text-slate-600 dark:text-slate-300 font-mono">
                                    <div class="flex justify-between">
                                        <span class="text-slate-400">Host & Port:</span>
                                        <span class="font-bold text-slate-800 dark:text-slate-100"><?= htmlspecialchars($activeLdapConfig['host'] ?? LDAP_HOST) ?>:<?= (int)($activeLdapConfig['port'] ?? LDAP_PORT) ?></span>
                                    </div>
                                    <div class="flex justify-between truncate" title="<?= htmlspecialchars($activeLdapConfig['authorized_group_dn'] ?? LDAP_AUTHORIZED_GROUP_DN) ?>">
                                        <span class="text-slate-400">Group DN:</span>
                                        <span class="truncate max-w-[130px]"><?= htmlspecialchars($activeLdapConfig['authorized_group_dn'] ?? LDAP_AUTHORIZED_GROUP_DN) ?></span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span class="text-slate-400">Security:</span>
                                        <span>Port 389 Plain LDAP</span>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- PART 1: Default Anti-Spam Policy Configuration -->
                        <div class="mb-10 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-xs overflow-hidden">
                            <div class="px-6 py-4 bg-slate-50 dark:bg-slate-800/60 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
                                <div class="flex items-center space-x-2.5">
                                    <div class="w-7 h-7 rounded-lg bg-emerald-600 text-white flex items-center justify-center text-xs">
                                        <i class="fa-solid fa-shield-halved"></i>
                                    </div>
                                    <div>
                                        <h3 class="text-sm font-bold text-slate-900 dark:text-white">Default Anti-Spam Policy Setting</h3>
                                        <p class="text-[11px] text-slate-500 dark:text-slate-400">Configure the primary Exchange Online policy targeted by the scheduled background cron job and default dashboard view</p>
                                    </div>
                                </div>
                                <span class="text-[11px] font-mono bg-emerald-100 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 px-2.5 py-0.5 rounded-full font-semibold flex items-center gap-1.5">
                                    <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                                    Active: <?= htmlspecialchars($defaultPolicy) ?>
                                </span>
                            </div>

                            <form method="POST" action="actions.php" class="p-6">
                                <input type="hidden" name="action" value="update_default_policy">
                                <input type="hidden" name="policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">

                                <div class="grid grid-cols-1 md:grid-cols-2 gap-5 text-xs mb-5">
                                    <!-- Default Policy Name -->
                                    <div class="col-span-1">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1 flex items-center justify-between">
                                            <span>Default Policy Name <span class="text-rose-500">*</span></span>
                                            <span class="text-[10px] text-slate-400">e.g. Unimax - Inbound or Default</span>
                                        </label>
                                        <input type="text" name="default_policy_name" list="existingPoliciesList" required
                                               value="<?= htmlspecialchars($defaultPolicy) ?>"
                                               class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-medium focus:ring-2 focus:ring-emerald-500 focus:outline-hidden"
                                               placeholder="Enter policy name (e.g. Unimax - Inbound)">
                                        <datalist id="existingPoliciesList">
                                            <?php foreach ($availablePolicies as $pName => $pDesc): ?>
                                                <option value="<?= htmlspecialchars($pName) ?>"><?= htmlspecialchars($pDesc) ?></option>
                                            <?php endforeach; ?>
                                        </datalist>
                                        <p class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">
                                            Matches the policy identity in Microsoft 365 Exchange Online (e.g. <code>Get-HostedContentFilterPolicy -Identity "..."</code>).
                                        </p>
                                    </div>

                                    <!-- Policy Description -->
                                    <div class="col-span-1">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                                            Policy Description / Note:
                                        </label>
                                        <input type="text" name="policy_description"
                                               value="<?= htmlspecialchars($availablePolicies[$defaultPolicy] ?? 'Primary Inbound Anti-Spam Policy') ?>"
                                               class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-normal focus:ring-2 focus:ring-emerald-500 focus:outline-hidden"
                                               placeholder="e.g. Organization-wide inbound anti-spam filter">
                                        <p class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">
                                            Saved in MariaDB table <code>eop_policies</code> for administrative reference.
                                        </p>
                                    </div>
                                </div>

                                <!-- Explanatory Callout Banner -->
                                <div class="p-3.5 mb-5 rounded-xl bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-800 text-[11px] text-slate-600 dark:text-slate-400 space-y-1">
                                    <div class="flex items-center gap-1.5 font-semibold text-slate-800 dark:text-slate-200">
                                        <i class="fa-solid fa-circle-info text-blue-500"></i>
                                        <span>How the default policy is applied across the system:</span>
                                    </div>
                                    <ul class="list-disc list-inside space-y-0.5 pl-2 text-slate-500 dark:text-slate-400">
                                        <li><strong>Scheduled Background Cron:</strong> <code>cron-sync.php --action=pull</code> automatically targets this default policy if <code>--policy</code> is omitted.</li>
                                        <li><strong>Database State:</strong> Sets <code>is_default = 1</code> in MariaDB table <code>eop_policies</code>.</li>
                                        <li><strong>Environment Configuration:</strong> Updates <code>EOP_POLICY_NAME</code> in your local <code>.env</code> file.</li>
                                        <li><strong>Dashboard &amp; Navigation:</strong> Serves as the initial selected policy upon login and session startup.</li>
                                    </ul>
                                </div>

                                <div class="flex items-center justify-between pt-4 border-t border-slate-100 dark:border-slate-800">
                                    <span class="text-xs text-slate-500 dark:text-slate-400">
                                        Current Default: <strong class="text-slate-800 dark:text-slate-200 font-mono"><?= htmlspecialchars($defaultPolicy) ?></strong>
                                    </span>
                                    <button type="submit" 
                                            class="px-5 py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center space-x-2 transition">
                                        <i class="fa-solid fa-floppy-disk"></i>
                                        <span>Save Default Policy Name</span>
                                    </button>
                                </div>
                            </form>

                            <!-- Table of Known Policies with One-Click Set-as-Default -->
                            <?php if (!empty($allDbPolicies)): ?>
                                <div class="px-6 pb-6 border-t border-slate-100 dark:border-slate-800/80 pt-4">
                                    <h4 class="text-xs font-bold text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-1.5">
                                        <i class="fa-solid fa-list-check text-slate-400"></i>
                                        <span>Policies Registered in MariaDB (<code>eop_policies</code>)</span>
                                    </h4>
                                    <div class="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-lg">
                                        <table class="w-full text-left text-xs text-slate-600 dark:text-slate-300">
                                            <thead class="bg-slate-50 dark:bg-slate-800 text-slate-500 dark:text-slate-400 font-semibold border-b border-slate-200 dark:border-slate-800">
                                                <tr>
                                                    <th class="px-3 py-2">Policy Name</th>
                                                    <th class="px-3 py-2">Description</th>
                                                    <th class="px-3 py-2">Sync Status</th>
                                                    <th class="px-3 py-2">Last Synced</th>
                                                    <th class="px-3 py-2 text-right">Default Status</th>
                                                </tr>
                                            </thead>
                                            <tbody class="divide-y divide-slate-100 dark:divide-slate-800/60 font-mono text-[11px]">
                                                <?php foreach ($allDbPolicies as $polRow): ?>
                                                    <?php $isDef = !empty($polRow['is_default']) || $polRow['policy_name'] === $defaultPolicy; ?>
                                                    <tr class="hover:bg-slate-50/50 dark:hover:bg-slate-800/40">
                                                        <td class="px-3 py-2 font-bold text-slate-900 dark:text-white">
                                                            <?= htmlspecialchars($polRow['policy_name']) ?>
                                                        </td>
                                                        <td class="px-3 py-2 font-sans text-slate-500 dark:text-slate-400">
                                                            <?= htmlspecialchars($polRow['description'] ?? '—') ?>
                                                        </td>
                                                        <td class="px-3 py-2">
                                                            <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold <?= ($polRow['sync_status'] ?? '') === 'synced' ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300' : 'bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300' ?>">
                                                                <?= htmlspecialchars($polRow['sync_status'] ?? 'pending') ?>
                                                            </span>
                                                        </td>
                                                        <td class="px-3 py-2 text-slate-400 text-[10px]">
                                                            <?= htmlspecialchars($polRow['last_synced_at'] ?? 'Never') ?>
                                                        </td>
                                                        <td class="px-3 py-2 text-right font-sans">
                                                            <?php if ($isDef): ?>
                                                                <span class="inline-flex items-center gap-1 text-[10px] font-bold text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/50 px-2 py-0.5 rounded border border-emerald-200 dark:border-emerald-800">
                                                                    <i class="fa-solid fa-check"></i> Active Default
                                                                </span>
                                                            <?php else: ?>
                                                                <form method="POST" action="actions.php" class="inline">
                                                                    <input type="hidden" name="action" value="update_default_policy">
                                                                    <input type="hidden" name="default_policy_name" value="<?= htmlspecialchars($polRow['policy_name']) ?>">
                                                                    <input type="hidden" name="policy_description" value="<?= htmlspecialchars($polRow['description'] ?? '') ?>">
                                                                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                                                                    <button type="submit" class="px-2 py-0.5 rounded bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 text-[10px] font-semibold transition cursor-pointer">
                                                                        Set as Default
                                                                    </button>
                                                                </form>
                                                            <?php endif; ?>
                                                        </td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            <?php endif; ?>
                        </div>

                        <!-- PART 2: Exchange Online Protection Private Key Upload & Settings -->
                        <div class="mb-10 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-xs overflow-hidden">
                            <div class="px-6 py-4 bg-slate-50 dark:bg-slate-800/60 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
                                <div class="flex items-center space-x-2.5">
                                    <div class="w-7 h-7 rounded-lg bg-blue-600 text-white flex items-center justify-center text-xs">
                                        <i class="fa-solid fa-key"></i>
                                    </div>
                                    <div>
                                        <h3 class="text-sm font-bold text-slate-900 dark:text-white">Exchange Online Protection - Private Key & Certificate</h3>
                                        <p class="text-[11px] text-slate-500 dark:text-slate-400">Upload private key file and store encrypted password in MariaDB table <code>eop_auth_config</code></p>
                                    </div>
                                </div>
                                <span class="text-[11px] font-mono bg-blue-100 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 px-2.5 py-0.5 rounded-full font-semibold">
                                    App-Only CBA Auth
                                </span>
                            </div>

                            <form method="POST" action="actions.php" enctype="multipart/form-data" class="p-6">
                                <input type="hidden" name="action" value="upload_eop_key">
                                <input type="hidden" name="policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">

                                <div class="grid grid-cols-1 md:grid-cols-2 gap-5 text-xs mb-5">
                                    <!-- Only a full PKCS#12 bundle is accepted -->
                                    <div class="col-span-1 md:col-span-2">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                                            PKCS#12 Certificate Bundle (.pfx / .p12) <span class="text-rose-500">*</span>
                                        </label>
                                        <input type="file" name="pfx_file" accept=".pfx,.p12" required
                                               class="w-full text-xs text-slate-500 dark:text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-blue-50 file:text-blue-700 dark:file:bg-blue-950/80 dark:file:text-blue-300 hover:file:bg-blue-100 dark:hover:file:bg-blue-900 border border-slate-300 dark:border-slate-700 rounded-lg p-2 bg-slate-50 dark:bg-slate-800">
                                        <p class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">
                                            The bundle must contain the certificate and its private key; bare PEM private keys are rejected. It is
                                            stored AES-256-GCM encrypted in <code>eop_auth_config.pkcs12_bundle</code> and imported into the
                                            certificate store on every sync. The thumbprint is read from this file, so a mismatch with the field
                                            below is reported and the bundle wins.
                                        </p>
                                    </div>


                                    <!-- Private Key Passphrase (Encrypted via AES-256-GCM) -->
                                    <div class="col-span-1">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1 flex items-center justify-between">
                                            <span>Private Key Password / Passphrase:</span>
                                            <span class="text-emerald-600 dark:text-emerald-400 text-[10px] font-semibold"><i class="fa-solid fa-lock"></i> Encrypted with AES-256-GCM</span>
                                        </label>
                                        <input type="password" name="key_password" 
                                               class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                                               placeholder="Enter passphrase if key is encrypted">
                                        <p class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">The passphrase is encrypted using AES-256-GCM before writing to the database. Plaintext is never stored.</p>
                                    </div>

                                    <!-- Certificate Thumbprint -->
                                    <div class="col-span-1">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                                            Certificate Thumbprint (SHA-1):
                                        </label>
                                        <input type="text" name="certificate_thumbprint" 
                                               value="<?= htmlspecialchars($activeAuthConfig['certificate_thumbprint'] ?? (defined('M365_CERT_THUMBPRINT') ? M365_CERT_THUMBPRINT : '9A2F8B3C1D4E5F6A7B8C9D0E1F2A3B4C5D6E7F80')) ?>"
                                               class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono uppercase focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                                               placeholder="40-hex character thumbprint">
                                        <p class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">Matches the certificate uploaded to Azure AD / Entra ID App Registration.</p>
                                    </div>

                                    <!-- Tenant ID -->
                                    <div class="col-span-1">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                                            Azure AD Tenant ID:
                                        </label>
                                        <input type="text" name="tenant_id" 
                                               value="<?= htmlspecialchars($activeAuthConfig['tenant_id'] ?? (defined('M365_TENANT_ID') ? M365_TENANT_ID : '')) ?>"
                                               class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono text-[11px] focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                                               placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx">
                                    </div>

                                    <!-- Client ID & Organization -->
                                    <div class="col-span-1 grid grid-cols-2 gap-3">
                                        <div>
                                            <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Application (Client) ID:</label>
                                            <input type="text" name="client_id" 
                                                   value="<?= htmlspecialchars($activeAuthConfig['client_id'] ?? (defined('M365_CLIENT_ID') ? M365_CLIENT_ID : '')) ?>"
                                                   class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono text-[11px] focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                                                   placeholder="Client ID">
                                        </div>
                                        <div>
                                            <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Organization / Domain:</label>
                                            <input type="text" name="organization" 
                                                   value="<?= htmlspecialchars($activeAuthConfig['organization'] ?? (defined('M365_ORGANIZATION') ? M365_ORGANIZATION : 'corp.example.com')) ?>"
                                                   class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono text-[11px] focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                                                   placeholder="corp.example.com">
                                        </div>
                                    </div>
                                </div>

                                <div class="flex items-center justify-end space-x-3 pt-4 border-t border-slate-100 dark:border-slate-800">
                                    <button type="submit" 
                                            class="px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center space-x-2 transition">
                                        <i class="fa-solid fa-cloud-arrow-up"></i>
                                        <span>Upload Key & Store Encrypted Password in Database</span>
                                    </button>
                                </div>
                            </form>

                            <!-- Database Records Table Preview for eop_auth_config -->
                            <div class="px-6 pb-6">
                                <h4 class="text-xs font-bold text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-1.5">
                                    <i class="fa-solid fa-table-cells text-blue-500"></i>
                                    <span>MariaDB Table Records (<code>eop_auth_config</code>)</span>
                                </h4>
                                <div class="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
                                    <table class="w-full text-left text-xs text-slate-700 dark:text-slate-300">
                                        <thead class="bg-slate-100 dark:bg-slate-800/80 text-slate-600 dark:text-slate-400 font-semibold border-b border-slate-200 dark:border-slate-800 uppercase tracking-wider text-[11px]">
                                            <tr>
                                                <th class="py-2.5 px-3">ID</th>
                                                <th class="py-2.5 px-3">Thumbprint</th>
                                                <th class="py-2.5 px-3">Key File</th>
                                                <th class="py-2.5 px-3">Encrypted Password</th>
                                                <th class="py-2.5 px-3">Status</th>
                                                <th class="py-2.5 px-3">Updated At</th>
                                                <th class="py-2.5 px-3">By</th>
                                            </tr>
                                        </thead>
                                        <tbody class="divide-y divide-slate-100 dark:divide-slate-800 text-[11px]">
                                            <?php if (!empty($allAuthConfigs)): ?>
                                                <?php foreach ($allAuthConfigs as $authRow): ?>
                                                    <tr class="hover:bg-slate-50 dark:hover:bg-slate-800/50 <?= !empty($authRow['is_active']) ? 'bg-blue-50/40 dark:bg-blue-950/20' : '' ?>">
                                                        <td class="py-2 px-3 font-mono font-bold text-blue-600 dark:text-blue-400">#<?= htmlspecialchars((string)$authRow['id']) ?></td>
                                                        <td class="py-2 px-3 font-mono"><?= htmlspecialchars(substr($authRow['certificate_thumbprint'], 0, 16)) ?>...</td>
                                                        <td class="py-2 px-3 font-mono"><?= htmlspecialchars($authRow['key_filename']) ?></td>
                                                        <td class="py-2 px-3">
                                                            <?php if (!empty($authRow['has_encrypted_password'])): ?>
                                                                <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300">
                                                                    <i class="fa-solid fa-lock text-[9px]"></i> AES-256-GCM
                                                                </span>
                                                            <?php else: ?>
                                                                <span class="text-slate-400 text-[10px]">No passphrase</span>
                                                            <?php endif; ?>
                                                        </td>
                                                        <td class="py-2 px-3">
                                                            <?php if (!empty($authRow['is_active'])): ?>
                                                                <span class="text-emerald-600 dark:text-emerald-400 font-semibold text-[11px] flex items-center gap-1">
                                                                    <i class="fa-solid fa-circle-check"></i> Active
                                                                </span>
                                                            <?php else: ?>
                                                                <span class="text-slate-400">Archived</span>
                                                            <?php endif; ?>
                                                        </td>
                                                        <td class="py-2 px-3 text-slate-400"><?= htmlspecialchars(substr($authRow['updated_at'] ?? '', 0, 16)) ?></td>
                                                        <td class="py-2 px-3 font-mono"><?= htmlspecialchars($authRow['uploaded_by'] ?? 'SYSTEM') ?></td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            <?php else: ?>
                                                <tr>
                                                    <td colspan="7" class="py-3 text-center text-slate-400">Default seed active in database. Upload above form to record new key.</td>
                                                </tr>
                                            <?php endif; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>

                        <!-- PART 3: Active Directory LDAP Settings Modification -->
                        <div class="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-xs overflow-hidden">
                            <div class="px-6 py-4 bg-slate-50 dark:bg-slate-800/60 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
                                <div class="flex items-center space-x-2.5">
                                    <div class="w-7 h-7 rounded-lg bg-purple-600 text-white flex items-center justify-center text-xs">
                                        <i class="fa-solid fa-network-wired"></i>
                                    </div>
                                    <div>
                                        <h3 class="text-sm font-bold text-slate-900 dark:text-white">Active Directory (LDAP) Connection Settings</h3>
                                        <p class="text-[11px] text-slate-500 dark:text-slate-400">Stored in and dynamically loaded from MariaDB table <code>eop_ldap_config</code></p>
                                    </div>
                                </div>
                                <span class="text-[11px] font-mono bg-purple-100 dark:bg-purple-950/60 text-purple-700 dark:text-purple-300 px-2.5 py-0.5 rounded-full font-semibold">
                                    Port 389 (Plain LDAP) Supported
                                </span>
                            </div>

                            <form method="POST" action="actions.php" class="p-6">
                                <input type="hidden" name="action" value="update_ldap_config">
                                <input type="hidden" name="policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">

                                <div class="grid grid-cols-1 md:grid-cols-2 gap-5 text-xs mb-5">
                                    <!-- Host -->
                                    <div class="col-span-1">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                                            LDAP Host (Domain Controller FQDN or IP):
                                        </label>
                                        <input type="text" name="ldap_host" required 
                                               value="<?= htmlspecialchars($activeLdapConfig['host'] ?? LDAP_HOST) ?>"
                                               class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                                               placeholder="dc01.corp.example.com">
                                    </div>

                                    <!-- Port & Protocol -->
                                    <div class="col-span-1 grid grid-cols-2 gap-3">
                                        <div>
                                            <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Port:</label>
                                            <input type="number" name="ldap_port" required 
                                                   value="<?= (int)($activeLdapConfig['port'] ?? LDAP_PORT) ?>"
                                                   class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                                                   placeholder="389">
                                        </div>
                                        <div>
                                            <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Protocol:</label>
                                            <select name="ldap_protocol" 
                                                    class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-medium focus:ring-2 focus:ring-purple-500 focus:outline-hidden">
                                                <?php $curProto = $activeLdapConfig['protocol'] ?? (defined('LDAP_PROTOCOL') ? LDAP_PROTOCOL : 'ldap'); ?>
                                                <option value="ldap" <?= $curProto === 'ldap' ? 'selected' : '' ?>>Plain LDAP (Port 389)</option>
                                                <option value="ldaps" <?= $curProto === 'ldaps' ? 'selected' : '' ?>>LDAPS / SSL (Port 636)</option>
                                                <option value="starttls" <?= $curProto === 'starttls' ? 'selected' : '' ?>>StartTLS (Port 389)</option>
                                            </select>
                                        </div>
                                    </div>

                                    <!-- Base DN -->
                                    <div class="col-span-1 md:col-span-2">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                                            LDAP Base Distinguished Name (Base DN):
                                        </label>
                                        <input type="text" name="ldap_base_dn" required 
                                               value="<?= htmlspecialchars($activeLdapConfig['base_dn'] ?? LDAP_BASE_DN) ?>"
                                               class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                                               placeholder="DC=corp,DC=example,DC=com">
                                    </div>

                                    <!-- Authorized Group DN -->
                                    <div class="col-span-1 md:col-span-2">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                                            Authorized Security Group DN (Mandatory RBAC):
                                        </label>
                                        <input type="text" name="ldap_group_dn" required 
                                               value="<?= htmlspecialchars($activeLdapConfig['authorized_group_dn'] ?? LDAP_AUTHORIZED_GROUP_DN) ?>"
                                               class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                                               placeholder="CN=Exchange-Admins,OU=Security Groups,DC=corp,DC=example,DC=com">
                                        <p class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">Users must belong to this AD group (or nested subgroups via matching rule 1.2.840.113556.1.4.1941) to sign in.</p>
                                    </div>

                                    <!-- Service Account Bind DN -->
                                    <div class="col-span-1">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                                            Service Account Bind DN (Optional):
                                        </label>
                                        <input type="text" name="ldap_bind_dn" 
                                               value="<?= htmlspecialchars($activeLdapConfig['bind_dn'] ?? (defined('LDAP_BIND_DN') ? LDAP_BIND_DN : '')) ?>"
                                               class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                                               placeholder="CN=svc-eop-web,OU=Service Accounts,DC=corp,DC=example,DC=com">
                                    </div>

                                    <!-- Service Account Bind Password -->
                                    <div class="col-span-1">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                                            Service Account Bind Password:
                                        </label>
                                        <input type="password" name="ldap_bind_pass" 
                                               value="<?= htmlspecialchars($activeLdapConfig['bind_password'] ?? (defined('LDAP_BIND_PASSWORD') ? LDAP_BIND_PASSWORD : '')) ?>"
                                               class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                                               placeholder="Leave blank or enter new password">
                                    </div>

                                    <!-- Account Suffix & Domain -->
                                    <div class="col-span-1">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Account Suffix:</label>
                                        <input type="text" name="ldap_account_suffix" 
                                               value="<?= htmlspecialchars($activeLdapConfig['account_suffix'] ?? (defined('LDAP_ACCOUNT_SUFFIX') ? LDAP_ACCOUNT_SUFFIX : '@corp.example.com')) ?>"
                                               class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                                               placeholder="@corp.example.com">
                                    </div>

                                    <div class="col-span-1 grid grid-cols-2 gap-3">
                                        <div>
                                            <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">NetBIOS Domain:</label>
                                            <input type="text" name="ldap_netbios_domain" 
                                                   value="<?= htmlspecialchars($activeLdapConfig['netbios_domain'] ?? (defined('LDAP_NETBIOS_DOMAIN') ? LDAP_NETBIOS_DOMAIN : 'CORP')) ?>"
                                                   class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                                                   placeholder="CORP">
                                        </div>
                                        <div>
                                            <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Timeout (Sec):</label>
                                            <input type="number" name="ldap_timeout" min="1" max="60" 
                                                   value="<?= (int)($activeLdapConfig['timeout_seconds'] ?? 5) ?>"
                                                   class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden">
                                        </div>
                                    </div>
                                </div>

                                <div class="flex items-center justify-end space-x-3 pt-4 border-t border-slate-100 dark:border-slate-800">
                                    <button type="submit" 
                                            class="px-5 py-2.5 bg-purple-600 hover:bg-purple-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center space-x-2 transition">
                                        <i class="fa-solid fa-floppy-disk"></i>
                                        <span>Save LDAP Settings to MariaDB Table</span>
                                    </button>
                                </div>
                            </form>

                            <!-- Database Records Table Preview for eop_ldap_config -->
                            <div class="px-6 pb-6">
                                <h4 class="text-xs font-bold text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-1.5">
                                    <i class="fa-solid fa-table-cells text-purple-500"></i>
                                    <span>MariaDB Table Records (<code>eop_ldap_config</code>)</span>
                                </h4>
                                <div class="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
                                    <table class="w-full text-left text-xs text-slate-700 dark:text-slate-300">
                                        <thead class="bg-slate-100 dark:bg-slate-800/80 text-slate-600 dark:text-slate-400 font-semibold border-b border-slate-200 dark:border-slate-800 uppercase tracking-wider text-[11px]">
                                            <tr>
                                                <th class="py-2.5 px-3">ID</th>
                                                <th class="py-2.5 px-3">Host</th>
                                                <th class="py-2.5 px-3">Port</th>
                                                <th class="py-2.5 px-3">Protocol</th>
                                                <th class="py-2.5 px-3">Base DN</th>
                                                <th class="py-2.5 px-3">Group DN</th>
                                                <th class="py-2.5 px-3">Status</th>
                                                <th class="py-2.5 px-3">Updated At</th>
                                                <th class="py-2.5 px-3">By</th>
                                            </tr>
                                        </thead>
                                        <tbody class="divide-y divide-slate-100 dark:divide-slate-800 text-[11px]">
                                            <?php if (!empty($allLdapConfigs)): ?>
                                                <?php foreach ($allLdapConfigs as $cfgRow): ?>
                                                    <tr class="hover:bg-slate-50 dark:hover:bg-slate-800/50 <?= !empty($cfgRow['is_active']) ? 'bg-purple-50/40 dark:bg-purple-950/20' : '' ?>">
                                                        <td class="py-2 px-3 font-mono font-bold text-purple-600 dark:text-purple-400">#<?= htmlspecialchars((string)$cfgRow['id']) ?></td>
                                                        <td class="py-2 px-3 font-mono"><?= htmlspecialchars($cfgRow['host']) ?></td>
                                                        <td class="py-2 px-3 font-mono"><?= (int)$cfgRow['port'] ?></td>
                                                        <td class="py-2 px-3">
                                                            <span class="px-2 py-0.5 rounded text-[10px] font-semibold <?= $cfgRow['protocol'] === 'ldap' ? 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300' : 'bg-blue-100 dark:bg-blue-950/60 text-blue-800 dark:text-blue-300' ?>">
                                                                <?= strtoupper(htmlspecialchars($cfgRow['protocol'])) ?>
                                                            </span>
                                                        </td>
                                                        <td class="py-2 px-3 font-mono text-[11px] truncate max-w-[150px]" title="<?= htmlspecialchars($cfgRow['base_dn']) ?>">
                                                            <?= htmlspecialchars($cfgRow['base_dn']) ?>
                                                        </td>
                                                        <td class="py-2 px-3 font-mono text-[11px] truncate max-w-[150px]" title="<?= htmlspecialchars($cfgRow['authorized_group_dn']) ?>">
                                                            <?= htmlspecialchars($cfgRow['authorized_group_dn']) ?>
                                                        </td>
                                                        <td class="py-2 px-3">
                                                            <?php if (!empty($cfgRow['is_active'])): ?>
                                                                <span class="text-emerald-600 dark:text-emerald-400 font-semibold text-[11px] flex items-center gap-1">
                                                                    <i class="fa-solid fa-circle-check"></i> Active
                                                                </span>
                                                            <?php else: ?>
                                                                <span class="text-slate-400">Archived</span>
                                                            <?php endif; ?>
                                                        </td>
                                                        <td class="py-2 px-3 text-slate-400"><?= htmlspecialchars(substr($cfgRow['updated_at'] ?? '', 0, 16)) ?></td>
                                                        <td class="py-2 px-3 font-mono"><?= htmlspecialchars($cfgRow['updated_by'] ?? 'SYSTEM') ?></td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            <?php else: ?>
                                                <tr>
                                                    <td colspan="9" class="py-3 text-center text-slate-400">Initial row active from defaults. Save above form to create record in table.</td>
                                                </tr>
                                            <?php endif; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

            <?php else: ?>
                <!-- Search & Filters -->
                <div class="p-4 border-b border-slate-100 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40 flex items-center justify-between">
                    <form method="GET" action="index.php" class="flex items-center max-w-md w-full">
                        <input type="hidden" name="policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                        <input type="hidden" name="tab" value="<?= htmlspecialchars($currentTab) ?>">
                        <div class="relative w-full">
                            <i class="fa-solid fa-magnifying-glass absolute left-3 top-2.5 text-slate-400 dark:text-slate-500 text-xs"></i>
                            <input type="text" name="q" value="<?= htmlspecialchars($search) ?>" placeholder="Search entries or notes..." 
                                   class="w-full bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-100 text-xs rounded-md pl-8 pr-3 py-2 focus:ring-2 focus:ring-blue-500 focus:outline-hidden">
                        </div>
                        <?php if ($search !== ''): ?>
                            <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=<?= $currentTab ?>" class="ml-2 text-xs text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200">Clear</a>
                        <?php endif; ?>
                    </form>
                    <div class="text-xs text-slate-500 dark:text-slate-400">
                        Showing <?= count($listItems) ?> of <?= $totalItems ?> items in <code class="text-blue-600 dark:text-blue-400"><?= Database::getTableName($currentTab) ?></code>
                    </div>
                </div>

                <!-- Table -->
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs text-slate-700 dark:text-slate-300">
                        <thead class="bg-slate-100 dark:bg-slate-800/80 text-slate-600 dark:text-slate-400 font-semibold border-b border-slate-200 dark:border-slate-800 uppercase tracking-wider">
                            <tr>
                                <th class="py-3 px-4">#</th>
                                <th class="py-3 px-4"><?= str_contains($currentTab, 'sender') ? 'Sender Email' : 'Domain' ?></th>
                                <th class="py-3 px-4">Note / Reason</th>
                                <th class="py-3 px-4">Added By (LDAP)</th>
                                <th class="py-3 px-4">Added On</th>
                                <th class="py-3 px-4 text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-100 dark:divide-slate-800">
                            <?php if (empty($listItems)): ?>
                                <tr>
                                    <td colspan="6" class="py-12 text-center text-slate-400 dark:text-slate-500">
                                        <i class="fa-regular fa-folder-open text-3xl mb-2 block"></i>
                                        No items found in this list for policy <strong><?= htmlspecialchars($selectedPolicy) ?></strong>.
                                    </td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($listItems as $row): ?>
                                    <tr class="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition">
                                        <td class="py-3 px-4 text-slate-400 dark:text-slate-500 font-mono"><?= $row['id'] ?></td>
                                        <td class="py-3 px-4 font-semibold text-slate-900 dark:text-white font-mono text-[13px]">
                                            <?= htmlspecialchars($row['item_value']) ?>
                                        </td>
                                        <td class="py-3 px-4 text-slate-600 dark:text-slate-400 max-w-xs truncate" title="<?= htmlspecialchars($row['note'] ?? '') ?>">
                                            <?= htmlspecialchars($row['note'] ?: '—') ?>
                                        </td>
                                        <td class="py-3 px-4 text-slate-600 dark:text-slate-400 font-mono text-[11px]">
                                            <span class="inline-flex items-center px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                                                <?= htmlspecialchars($row['added_by']) ?>
                                            </span>
                                        </td>
                                        <td class="py-3 px-4 text-slate-500 dark:text-slate-400 whitespace-nowrap">
                                            <?= htmlspecialchars(substr($row['created_at'], 0, 16)) ?>
                                        </td>
                                        <td class="py-3 px-4 text-right whitespace-nowrap">
                                            <form method="POST" action="actions.php" onsubmit="return confirm('Remove <?= htmlspecialchars($row['item_value']) ?> from <?= $currentTab ?>?');" class="inline">
                                                <input type="hidden" name="action" value="delete_item">
                                                <input type="hidden" name="id" value="<?= $row['id'] ?>">
                                                <input type="hidden" name="list" value="<?= $currentTab ?>">
                                                <input type="hidden" name="policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                                                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                                                <button type="submit" class="text-rose-600 dark:text-rose-400 hover:text-rose-800 dark:hover:text-rose-300 p-1 rounded hover:bg-rose-50 dark:hover:bg-rose-950/40 transition" title="Delete Entry">
                                                    <i class="fa-regular fa-trash-can text-sm"></i>
                                                </button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>

                <!-- Pagination -->
                <?php if ($totalPages > 1): ?>
                <div class="p-4 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
                    <div>Page <?= $page ?> of <?= $totalPages ?></div>
                    <div class="flex space-x-1">
                        <?php for ($p = 1; $p <= $totalPages; $p++): ?>
                            <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=<?= $currentTab ?>&p=<?= $p ?>&q=<?= urlencode($search) ?>" 
                               class="px-2.5 py-1 rounded border <?= $p === $page ? 'bg-blue-600 text-white border-blue-600' : 'bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700' ?>">
                                <?= $p ?>
                            </a>
                        <?php endfor; ?>
                    </div>
                </div>
                <?php endif; ?>
            <?php endif; ?>
        </div>
    </main>

    <!-- Quick Add Modal -->
    <div id="quickAddModal" class="hidden fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
        <div class="bg-white dark:bg-slate-900 rounded-xl shadow-xl max-w-md w-full p-6 border border-slate-200 dark:border-slate-800">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-base font-bold text-slate-900 dark:text-white">Add to <?= ucwords(str_replace('_', ' ', $currentTab)) ?></h3>
                <button onclick="document.getElementById('quickAddModal').classList.add('hidden')" class="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
                    <i class="fa-solid fa-xmark"></i>
                </button>
            </div>
            <form method="POST" action="actions.php">
                <input type="hidden" name="action" value="add_single">
                <input type="hidden" name="list" value="<?= $currentTab ?>">
                <input type="hidden" name="policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">

                <div class="mb-3">
                    <label class="block text-xs font-semibold text-slate-600 dark:text-slate-300 mb-1">
                        <?= str_contains($currentTab, 'sender') ? 'Email Address' : 'Domain Name' ?>:
                    </label>
                    <input type="text" name="value" required placeholder="<?= str_contains($currentTab, 'sender') ? 'user@example.com' : 'example.com or *.example.com' ?>" 
                           class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-100 text-sm rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:outline-hidden font-mono">
                </div>

                <div class="mb-4">
                    <label class="block text-xs font-semibold text-slate-600 dark:text-slate-300 mb-1">Reason / Change Ticket #:</label>
                    <textarea name="note" rows="2" placeholder="e.g. Approved partner vendor via Ticket INC-49210" 
                              class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-100 text-sm rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:outline-hidden"></textarea>
                </div>

                <div class="flex items-center justify-end space-x-2">
                    <button type="button" onclick="document.getElementById('quickAddModal').classList.add('hidden')" class="px-4 py-2 text-xs font-medium text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg">Cancel</button>
                    <button type="submit" class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg shadow-sm">Save Entry</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Bulk Add Modal -->
    <div id="bulkAddModal" class="hidden fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
        <div class="bg-white dark:bg-slate-900 rounded-xl shadow-xl max-w-lg w-full p-6 border border-slate-200 dark:border-slate-800">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-base font-bold text-slate-900 dark:text-white">Bulk Import - <?= ucwords(str_replace('_', ' ', $currentTab)) ?></h3>
                <button onclick="document.getElementById('bulkAddModal').classList.add('hidden')" class="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
                    <i class="fa-solid fa-xmark"></i>
                </button>
            </div>
            <form method="POST" action="actions.php">
                <input type="hidden" name="action" value="bulk_import">
                <input type="hidden" name="list" value="<?= $currentTab ?>">
                <input type="hidden" name="policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">

                <p class="text-xs text-slate-500 dark:text-slate-400 mb-2">Paste one item per line, or <code>value, optional note</code>:</p>
                <textarea name="bulk_data" rows="8" required placeholder="<?= str_contains($currentTab, 'sender') ? "ceo@partner.com, High priority partner
support@vendor.org, Vendor notification" : "partner.com, Main vendor domain
*.subdomain.net, Wildcard domain" ?>"
                          class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-100 text-xs rounded-lg p-3 font-mono focus:ring-2 focus:ring-blue-500 focus:outline-hidden mb-4"></textarea>

                <div class="flex items-center justify-end space-x-2">
                    <button type="button" onclick="document.getElementById('bulkAddModal').classList.add('hidden')" class="px-4 py-2 text-xs font-medium text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg">Cancel</button>
                    <button type="submit" class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg shadow-sm">Import Items</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Smart Sort & Import Modal (Auto-sorts Senders & Domains) -->
    <div id="smartSortModal" class="hidden fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
        <div class="bg-white dark:bg-slate-900 rounded-xl shadow-xl max-w-xl w-full p-6 border border-slate-200 dark:border-slate-800">
            <div class="flex items-center justify-between mb-4">
                <div class="flex items-center space-x-2">
                    <div id="smartSortModalIcon" class="w-8 h-8 rounded-lg bg-gradient-to-br from-emerald-600 to-teal-600 text-white flex items-center justify-center text-xs">
                        <i class="fa-solid fa-shield-halved text-emerald-200"></i>
                    </div>
                    <div>
                        <h3 id="smartSortModalTitle" class="text-base font-bold text-slate-900 dark:text-white">Smart Sort: Allowed Items</h3>
                        <p id="smartSortModalDesc" class="text-xs text-slate-500 dark:text-slate-400">Auto-routes emails to Senders table and domains to Domains table</p>
                    </div>
                </div>
                <button onclick="document.getElementById('smartSortModal').classList.add('hidden')" class="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
                    <i class="fa-solid fa-xmark"></i>
                </button>
            </div>
            <form method="POST" action="actions.php">
                <input type="hidden" name="action" value="smart_sort_import">
                <input type="hidden" name="policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">

                <div class="mb-4">
                    <label class="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">Target List Category:</label>
                    <div class="grid grid-cols-2 gap-3">
                        <label class="flex items-center space-x-2 p-2.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-purple-400 cursor-pointer text-xs">
                            <input type="radio" name="target_mode" value="blocked" <?= str_contains($currentTab, 'blocked') ? 'checked' : '' ?> class="text-purple-600">
                            <span><strong>Blocked Items</strong> (senders &amp; domains)</span>
                        </label>
                        <label class="flex items-center space-x-2 p-2.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-purple-400 cursor-pointer text-xs">
                            <input type="radio" name="target_mode" value="allowed" <?= str_contains($currentTab, 'allowed') ? 'checked' : '' ?> class="text-purple-600">
                            <span><strong>Allowed Items</strong> (senders &amp; domains)</span>
                        </label>
                    </div>
                </div>

                <div class="mb-3">
                    <label class="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                        Paste Mixed List (Emails and/or Domains, one per line):
                    </label>
                    <textarea name="bulk_data" rows="7" required placeholder="user@external.com, Sample sender note&#10;partner-domain.com, Domain note&#10;alert@external.org&#10;*.wildcard-domain.net"
                              class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-100 text-xs rounded-lg p-3 font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"></textarea>
                    <p class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">
                        Emails with <code>@</code> are routed to the Senders table; domain names are routed to the Domains table. Existing duplicates will be skipped.
                    </p>
                </div>

                <div class="mb-4">
                    <label class="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">Default Ticket # / Justification Note:</label>
                    <input type="text" name="default_note" placeholder="e.g. Bulk auto-classified intake Ticket #INC-9481" 
                           class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-100 text-xs rounded-lg px-3 py-2 focus:ring-2 focus:ring-purple-500 focus:outline-hidden">
                </div>

                <div class="flex items-center justify-end space-x-2">
                    <button type="button" onclick="document.getElementById('smartSortModal').classList.add('hidden')" class="px-4 py-2 text-xs font-medium text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg">Cancel</button>
                    <button id="smartSortSubmitBtn" type="submit" class="px-5 py-2 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center space-x-1.5 cursor-pointer">
                        <i class="fa-solid fa-wand-magic-sparkles text-amber-300"></i>
                        <span>Sort &amp; Import Items</span>
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Push Summary Result Modal (Showing what was added to each list) -->
    <?php if ($pushSummary): ?>
    <div id="pushSummaryModal" class="fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
        <div class="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl max-w-2xl w-full p-6 border border-slate-200 dark:border-slate-800 flex flex-col max-h-[90vh]">
            <div class="flex items-start justify-between pb-4 border-b border-slate-200 dark:border-slate-800">
                <div class="flex items-center space-x-3">
                    <div class="w-10 h-10 rounded-xl bg-emerald-100 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400 flex items-center justify-center">
                        <i class="fa-solid fa-circle-check text-lg"></i>
                    </div>
                    <div>
                        <h3 class="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
                            <span>All Changes Successfully Pushed to EOP (All 4 Tables)</span>
                            <span class="text-[11px] font-medium px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/40">Success</span>
                        </h3>
                        <p class="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                            Policy: <strong class="text-slate-700 dark:text-slate-200"><?= htmlspecialchars($pushSummary['policy']) ?></strong> &bull; Synced at: <span class="font-mono"><?= htmlspecialchars($pushSummary['timestamp']) ?></span>
                        </p>
                    </div>
                </div>
                <button type="button" onclick="document.getElementById('pushSummaryModal').remove()" class="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 p-1 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition cursor-pointer">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>

            <div class="py-3 text-xs text-slate-600 dark:text-slate-300">
                <p class="mb-2 text-xs">
                    The following entries from your remote MariaDB tables were successfully pushed and configured in Microsoft 365 Exchange Online via <code class="text-indigo-600 dark:text-indigo-400 font-bold">Set-HostedContentFilterPolicy</code>:
                </p>
                <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center text-xs">
                    <div class="bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800/50 p-2 rounded-lg">
                        <span class="block text-emerald-800 dark:text-emerald-300 font-bold text-sm"><?= count($pushSummary['allowedSenders']) ?></span>
                        <span class="text-[11px] text-emerald-700 dark:text-emerald-400">Allowed Senders</span>
                    </div>
                    <div class="bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800/50 p-2 rounded-lg">
                        <span class="block text-rose-800 dark:text-rose-300 font-bold text-sm"><?= count($pushSummary['blockedSenders']) ?></span>
                        <span class="text-[11px] text-rose-700 dark:text-rose-400">Blocked Senders</span>
                    </div>
                    <div class="bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800/50 p-2 rounded-lg">
                        <span class="block text-emerald-800 dark:text-emerald-300 font-bold text-sm"><?= count($pushSummary['allowedDomains']) ?></span>
                        <span class="text-[11px] text-emerald-700 dark:text-emerald-400">Allowed Domains</span>
                    </div>
                    <div class="bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800/50 p-2 rounded-lg">
                        <span class="block text-rose-800 dark:text-rose-300 font-bold text-sm"><?= count($pushSummary['blockedDomains']) ?></span>
                        <span class="text-[11px] text-rose-700 dark:text-rose-400">Blocked Domains</span>
                    </div>
                </div>
            </div>

            <div class="overflow-y-auto space-y-4 pr-1 my-2 grow divide-y divide-slate-100 dark:divide-slate-800">
                <div class="pt-2">
                    <div class="flex items-center justify-between mb-1.5">
                        <span class="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                            <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
                            <span>Allowed Senders (<code>-AllowedSenders</code>)</span>
                        </span>
                        <span class="text-[11px] text-slate-400 font-mono">eop_allowed_senders</span>
                    </div>
                    <?php if (!empty($pushSummary['allowedSenders'])): ?>
                    <div class="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto p-2 bg-slate-50 dark:bg-slate-800/60 rounded-lg border border-slate-200 dark:border-slate-800">
                        <?php foreach ($pushSummary['allowedSenders'] as $val): ?>
                        <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-white dark:bg-slate-900 border border-emerald-300 dark:border-emerald-800 text-emerald-800 dark:text-emerald-300">
                            <?= htmlspecialchars($val) ?>
                        </span>
                        <?php endforeach; ?>
                    </div>
                    <?php else: ?>
                    <p class="text-[11px] italic text-slate-400 pl-3">No allowed senders configured for this policy.</p>
                    <?php endif; ?>
                </div>

                <div class="pt-3">
                    <div class="flex items-center justify-between mb-1.5">
                        <span class="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                            <span class="w-2 h-2 rounded-full bg-rose-500"></span>
                            <span>Blocked Senders (<code>-BlockedSenders</code>)</span>
                        </span>
                        <span class="text-[11px] text-slate-400 font-mono">eop_blocked_senders</span>
                    </div>
                    <?php if (!empty($pushSummary['blockedSenders'])): ?>
                    <div class="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto p-2 bg-slate-50 dark:bg-slate-800/60 rounded-lg border border-slate-200 dark:border-slate-800">
                        <?php foreach ($pushSummary['blockedSenders'] as $val): ?>
                        <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-white dark:bg-slate-900 border border-rose-300 dark:border-rose-800 text-rose-800 dark:text-rose-300">
                            <?= htmlspecialchars($val) ?>
                        </span>
                        <?php endforeach; ?>
                    </div>
                    <?php else: ?>
                    <p class="text-[11px] italic text-slate-400 pl-3">No blocked senders configured for this policy.</p>
                    <?php endif; ?>
                </div>

                <div class="pt-3">
                    <div class="flex items-center justify-between mb-1.5">
                        <span class="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                            <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
                            <span>Allowed Sender Domains (<code>-AllowedSenderDomains</code>)</span>
                        </span>
                        <span class="text-[11px] text-slate-400 font-mono">eop_allowed_domains</span>
                    </div>
                    <?php if (!empty($pushSummary['allowedDomains'])): ?>
                    <div class="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto p-2 bg-slate-50 dark:bg-slate-800/60 rounded-lg border border-slate-200 dark:border-slate-800">
                        <?php foreach ($pushSummary['allowedDomains'] as $val): ?>
                        <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-white dark:bg-slate-900 border border-emerald-300 dark:border-emerald-800 text-emerald-800 dark:text-emerald-300">
                            <?= htmlspecialchars($val) ?>
                        </span>
                        <?php endforeach; ?>
                    </div>
                    <?php else: ?>
                    <p class="text-[11px] italic text-slate-400 pl-3">No allowed domains configured for this policy.</p>
                    <?php endif; ?>
                </div>

                <div class="pt-3">
                    <div class="flex items-center justify-between mb-1.5">
                        <span class="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                            <span class="w-2 h-2 rounded-full bg-rose-500"></span>
                            <span>Blocked Sender Domains (<code>-BlockedSenderDomains</code>)</span>
                        </span>
                        <span class="text-[11px] text-slate-400 font-mono">eop_blocked_domains</span>
                    </div>
                    <?php if (!empty($pushSummary['blockedDomains'])): ?>
                    <div class="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto p-2 bg-slate-50 dark:bg-slate-800/60 rounded-lg border border-slate-200 dark:border-slate-800">
                        <?php foreach ($pushSummary['blockedDomains'] as $val): ?>
                        <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-white dark:bg-slate-900 border border-rose-300 dark:border-rose-800 text-rose-800 dark:text-rose-300">
                            <?= htmlspecialchars($val) ?>
                        </span>
                        <?php endforeach; ?>
                    </div>
                    <?php else: ?>
                    <p class="text-[11px] italic text-slate-400 pl-3">No blocked domains configured for this policy.</p>
                    <?php endif; ?>
                </div>
            </div>

            <div class="pt-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between">
                <span class="text-[11px] text-slate-400 dark:text-slate-500">Action recorded in <code>eop_audit_log</code> &bull; Status: Synced</span>
                <button type="button" onclick="document.getElementById('pushSummaryModal').remove()" class="px-5 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-semibold shadow-xs transition cursor-pointer">
                    Done
                </button>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <!-- Duplicate Entry Warning Popup -->
    <?php if ($duplicatePopup): ?>
    <div id="duplicatePopupModal" class="fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
        <div class="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl max-w-md w-full p-6 border border-amber-200 dark:border-amber-800/80">
            <div class="flex items-start justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
                <div class="flex items-center space-x-3">
                    <div class="w-10 h-10 rounded-xl bg-amber-100 dark:bg-amber-950/60 text-amber-600 dark:text-amber-400 flex items-center justify-center shrink-0">
                        <i class="fa-solid fa-triangle-exclamation text-lg"></i>
                    </div>
                    <div>
                        <h3 class="text-base font-bold text-slate-900 dark:text-white">Entry Already in List</h3>
                        <span class="text-[11px] font-semibold uppercase px-2 py-0.5 rounded-full bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800/50">
                            Duplicate Rejected
                        </span>
                    </div>
                </div>
                <button type="button" onclick="document.getElementById('duplicatePopupModal').remove()" class="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 p-1 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition cursor-pointer">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>

            <div class="my-4 text-xs text-slate-600 dark:text-slate-300 space-y-3">
                <p class="leading-relaxed">
                    The entry <strong class="font-mono text-slate-900 dark:text-white px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700"><?= htmlspecialchars($duplicatePopup['value']) ?></strong> cannot be added because it already exists in policy <strong class="text-slate-900 dark:text-white font-semibold">"<?= htmlspecialchars($duplicatePopup['policy']) ?>"</strong>.
                </p>

                <div class="p-3 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/60 text-amber-900 dark:text-amber-200">
                    <div class="font-semibold text-xs mb-1">Target Table:</div>
                    <div class="text-[11px]">
                        <code>eop_<?= htmlspecialchars($duplicatePopup['listType']) ?></code>
                    </div>
                </div>

                <p class="text-[11px] text-slate-500 dark:text-slate-400 italic">
                    MariaDB enforces a unique constraint (<code>uk_policy_sender</code> / <code>uk_policy_domain</code>) on this table to prevent redundant and conflicting entries in Microsoft 365.
                </p>
            </div>

            <div class="flex items-center justify-end pt-3 border-t border-slate-100 dark:border-slate-800">
                <button type="button" onclick="document.getElementById('duplicatePopupModal').remove()" class="px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-lg text-xs font-semibold shadow-xs transition cursor-pointer">
                    Understood
                </button>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <!-- Footer -->
    <footer class="bg-white dark:bg-slate-900 border-t border-slate-200 dark:border-slate-800 py-4 mt-auto text-center text-xs text-slate-400 dark:text-slate-500 transition-colors duration-200">
        Exchange Online Protection Policy Manager &bull; Host: Debian Linux &bull; Storage: Remote MariaDB &bull; Auth: Active Directory LDAP (Port 389/636)
    </footer>

    <!-- Theme Switcher Script -->
    <script>
        function openSmartSortModal(mode) {
            const modal = document.getElementById('smartSortModal');
            if (!modal) return;
            const targetInput = document.querySelector('input[name="target_mode"][value="' + mode + '"]');
            if (targetInput) targetInput.checked = true;
            
            const titleEl = document.getElementById('smartSortModalTitle');
            const descEl = document.getElementById('smartSortModalDesc');
            const iconEl = document.getElementById('smartSortModalIcon');
            const submitBtn = document.getElementById('smartSortSubmitBtn');
            
            if (mode === 'allowed') {
                if (titleEl) titleEl.textContent = 'Smart Sort: Allowed Senders & Domains';
                if (descEl) descEl.textContent = 'Auto-routes into eop_allowed_senders and eop_allowed_domains';
                if (iconEl) {
                    iconEl.className = 'w-8 h-8 rounded-lg bg-gradient-to-br from-emerald-600 to-teal-600 text-white flex items-center justify-center text-xs';
                    iconEl.innerHTML = '<i class="fa-solid fa-shield-halved text-emerald-200"></i>';
                }
                if (submitBtn) {
                    submitBtn.className = 'px-5 py-2 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-700 hover:to-teal-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center space-x-1.5 cursor-pointer';
                    submitBtn.innerHTML = '<i class="fa-solid fa-shield-halved text-emerald-200"></i><span>Sort &amp; Import to Allowed Lists</span>';
                }
            } else {
                if (titleEl) titleEl.textContent = 'Smart Sort: Blocked Senders & Domains';
                if (descEl) descEl.textContent = 'Auto-routes into eop_blocked_senders and eop_blocked_domains';
                if (iconEl) {
                    iconEl.className = 'w-8 h-8 rounded-lg bg-gradient-to-br from-rose-600 to-red-600 text-white flex items-center justify-center text-xs';
                    iconEl.innerHTML = '<i class="fa-solid fa-ban text-rose-200"></i>';
                }
                if (submitBtn) {
                    submitBtn.className = 'px-5 py-2 bg-gradient-to-r from-rose-600 to-red-600 hover:from-rose-700 hover:to-red-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center space-x-1.5 cursor-pointer';
                    submitBtn.innerHTML = '<i class="fa-solid fa-ban text-rose-200"></i><span>Sort &amp; Import to Blocked Lists</span>';
                }
            }
            modal.classList.remove('hidden');
        }
        function updateThemeUI() {
            const isDark = document.documentElement.classList.contains('dark');
            const icon = document.getElementById('themeIcon');
            if (icon) {
                icon.className = isDark ? 'fa-solid fa-sun text-amber-400 text-sm' : 'fa-solid fa-moon text-slate-500 text-sm';
            }
        }
        function toggleTheme() {
            const isDark = document.documentElement.classList.toggle('dark');
            localStorage.setItem('theme', isDark ? 'dark' : 'light');
            updateThemeUI();
        }
        updateThemeUI();
    </script>

    <!-- Scheduled-sync change detection -->
    <script>
        (function () {
            // Reloading discards whatever is in the form, so only do it when the
            // page is genuinely idle: nothing focused, no dialog open, no file
            // chosen. An administrator who is mid-edit keeps their input, and the
            // next poll after they navigate picks the change up anyway.
            const isBusy = function () {
                const active = document.activeElement;
                if (active) {
                    const tag = (active.tagName || '').toLowerCase();
                    if (tag === 'input' || tag === 'textarea' || tag === 'select') {
                        return true;
                    }
                }
                // The dialogs are the fixed overlays that toggle a \`hidden\`
                // class, e.g. #quickAddModal / #bulkAddModal / #smartSortModal.
                if (document.querySelector('.fixed.inset-0:not(.hidden)')) {
                    return true;
                }
                if (document.querySelector('input[type="file"]')?.files?.length) {
                    return true;
                }
                return false;
            };

            let baseline = <?= json_encode($dataVersion) ?>;
            let inFlight = false;

            const check = async function () {
                // A backgrounded tab gets throttled anyway, and a hidden tab is
                // not being read, so polling it just spends server time.
                if (document.hidden || inFlight) return;
                inFlight = true;
                try {
                    const res = await fetch(
                        'actions.php?action=data_version&policy=' + encodeURIComponent(<?= json_encode($selectedPolicy) ?>),
                        { headers: { 'Accept': 'application/json' }, cache: 'no-store', credentials: 'same-origin' }
                    );
                    if (!res.ok) return;
                    const data = await res.json();
                    if (typeof data.version === 'string' && data.version !== baseline) {
                        if (!isBusy()) {
                            window.location.reload();
                            return;
                        }
                        // Defer rather than drop it, so a change made mid-edit is
                        // still picked up once the field is left alone.
                        baseline = data.version;
                    }
                } catch (e) {
                    // A failed probe must never disturb the page; the next tick retries.
                } finally {
                    inFlight = false;
                }
            };

            // 60s keeps a scheduled run visible within a poll interval without
            // making every open tab a meaningful load on the database.
            setInterval(check, 60000);

            // Coming back to a tab that was hidden for a while should reflect the
            // current state immediately rather than after the remainder of the tick.
            document.addEventListener('visibilitychange', function () {
                if (!document.hidden) check();
            });
        })();
    </script>
</body>
</html>
`
  },

  // 7. setup.php
  {
    name: 'setup.php',
    path: 'setup.php',
    description: 'Initial run setup wizard in a page-by-page format. Configures MariaDB, populates all 9 schema tables, prompts for Active Directory LDAP and Exchange Online Protection info, and permanently locks setup so it cannot be run again.',
    category: 'views',
    generateContent: (cfg) => `<?php
/**
 * Initial Run Setup Wizard for EOP Anti-Spam Manager
 * 
 * Page-by-page setup flow:
 * Step 1: System requirements & Prerequisites
 * Step 2: MariaDB Database Connection & Schema Population (all 11 tables)
 * Step 3: Active Directory / OpenLDAP Configuration
 * Step 4: Exchange Online Protection (EOP) Setup & Private Key
 * Step 5: Review & Permanent Lock (Prevents re-running)
 */

declare(strict_types=1);

// Debian filesystem lockfile path
$lockFile = __DIR__ . '/installed.lock';

// Load shared AES-256-GCM encryption library
if (file_exists(__DIR__ . '/crypto.php')) {
    require_once __DIR__ . '/crypto.php';
}

// Standalone fallback in case crypto.php is ever missing or inaccessible
if (!function_exists('eopEncryptSecret')) {
    function eopEncryptSecret(string $plaintext): string {
        if ($plaintext === '') {
            return '';
        }
        $secret = defined('AUTH_MASTER_ENCRYPTION_KEY') && AUTH_MASTER_ENCRYPTION_KEY !== ''
            ? AUTH_MASTER_ENCRYPTION_KEY
            : (getenv('AUTH_MASTER_ENCRYPTION_KEY') ?: ($_ENV['AUTH_MASTER_ENCRYPTION_KEY'] ?? 'eop_master_secret'));
        $key = hash('sha256', $secret, true);
        $iv = random_bytes(12);
        $tag = '';
        $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        if ($ciphertext === false) {
            throw new RuntimeException('AES-256-GCM encryption of secret failed.');
        }
        return 'EOPENC1:' . base64_encode($iv . $tag . $ciphertext);
    }
}

if (!function_exists('eopDecryptSecret')) {
    function eopDecryptSecret(?string $stored): ?string {
        if ($stored === null) return null;
        if ($stored === '') return '';
        if (!str_starts_with($stored, 'EOPENC1:')) return $stored;
        $raw = base64_decode(substr($stored, strlen('EOPENC1:')), true);
        if ($raw === false || strlen($raw) < 29) return null;
        $iv = substr($raw, 0, 12);
        $tag = substr($raw, 12, 16);
        $ciphertext = substr($raw, 28);
        $secret = defined('AUTH_MASTER_ENCRYPTION_KEY') && AUTH_MASTER_ENCRYPTION_KEY !== ''
            ? AUTH_MASTER_ENCRYPTION_KEY
            : (getenv('AUTH_MASTER_ENCRYPTION_KEY') ?: ($_ENV['AUTH_MASTER_ENCRYPTION_KEY'] ?? 'eop_master_secret'));
        $key = hash('sha256', $secret, true);
        $decrypted = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        return $decrypted !== false ? $decrypted : null;
    }
}

/**
 * Normalizes certificate thumbprint into a clean 40-character uppercase hexadecimal string.
 * Handles raw 20-byte binary hashes (e.g. from openssl_x509_fingerprint binary mode) or strings with colons/spaces.
 */
function eopNormalizeThumbprint(mixed $input): string {
    if (empty($input)) {
        return '';
    }
    $str = (string)$input;
    // Check if it's raw binary (e.g. 20-byte SHA-1 hash or non-printable chars)
    if (strlen($str) === 20 || !ctype_print($str)) {
        return strtoupper(bin2hex($str));
    }
    // Clean string input (strip colons, spaces, dashes)
    $clean = strtoupper(preg_replace('/[^a-fA-F0-9]/', '', $str));
    if ($clean !== '') {
        return $clean;
    }
    return strtoupper(bin2hex($str));
}

/**
 * Canonicalises an Exchange Online object GUID to the lowercase 8-4-4-4-12 form.
 * Accepts the wrappers administrators habitually paste around a GUID ({...},
 * urn:uuid:..., stray spaces or separators) and returns '' when the value is not
 * a GUID at all, so callers can use the result as the "is this a GUID?" test.
 */
function eopNormalizeGuid(mixed $input): string {
    $raw = strtolower(trim((string)$input));
    if ($raw === '') {
        return '';
    }
    $raw = preg_replace('/^urn:uuid:/', '', $raw);
    $raw = trim($raw, '{}');
    $hex = preg_replace('/[^0-9a-f]/', '', $raw);
    if (!is_string($hex) || strlen($hex) !== 32 || !ctype_xdigit($hex)) {
        return '';
    }
    return substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' . substr($hex, 12, 4)
        . '-' . substr($hex, 16, 4) . '-' . substr($hex, 20, 12);
}

/**
 * Cleans whatever was typed into the policy field down to an identifier Exchange
 * accepts. Get-HostedContentFilterPolicy -Identity takes a display name or a
 * GUID, so a GUID is canonicalised (so the same policy pasted three different
 * ways compares equal) while a name keeps its exact spelling, which is what the
 * rest of the application uses as the policy key.
 */
function eopNormalizePolicyIdentifier(string $raw): string {
    $value = trim($raw);
    $value = trim(trim($value), "\\"'");
    $value = trim($value);
    $guid = eopNormalizeGuid($value);
    return $guid !== '' ? $guid : $value;
}

/**
 * Resolves a policy name or GUID against Exchange Online and reports both the
 * canonical name and the policy GUID.
 *
 * Returns one of three statuses:
 *   verified    - Exchange returned the policy; name/guid are populated.
 *   not_found   - Exchange was reached and definitively has no such policy.
 *                 This is the only lookup outcome that should block the wizard.
 *   unavailable - the lookup could not be carried out (no pwsh, no module, no
 *                 route to the tenant, bad credentials). A deployment box that
 *                 cannot reach Exchange must still be configurable, so this is
 *                 surfaced as a warning rather than an error.
 */
function eopLookupPolicyOnExchange(string $identifier, array $ctx): array {
    $result = [
        'status'  => 'unavailable',
        'name'    => '',
        'guid'    => eopNormalizeGuid($identifier),
        'message' => '',
    ];

    if ($identifier === '') {
        $result['message'] = 'No policy identifier was supplied.';
        return $result;
    }

    $pwsh = trim((string)@shell_exec('command -v pwsh 2>/dev/null'));
    if ($pwsh === '') {
        $result['message'] = 'PowerShell 7 (pwsh) is not installed, so the ExchangeOnlineManagement lookup cannot run.';
        return $result;
    }

    $pfxPath = (string)($ctx['pfx_path'] ?? '');
    if ($pfxPath === '' || !is_readable($pfxPath)) {
        $result['message'] = 'The uploaded PKCS#12 bundle is not readable, so certificate authentication to Exchange Online is not possible.';
        return $result;
    }

    // Everything the PowerShell side needs travels through the environment and
    // never through the command string, so a policy name containing quotes (or a
    // GUID) cannot break out of the argument.
    $outFile = tempnam(sys_get_temp_dir(), 'eoplookup_');
    if ($outFile === false) {
        $result['message'] = 'Could not create a temporary file for the Exchange Online lookup response.';
        return $result;
    }

    putenv('EOP_LOOKUP_CLIENT_ID=' . (string)($ctx['client_id'] ?? ''));
    putenv('EOP_LOOKUP_ORGANIZATION=' . (string)($ctx['org_domain'] ?? ''));
    putenv('EOP_LOOKUP_THUMBPRINT=' . (string)($ctx['thumbprint'] ?? ''));
    putenv('EOP_LOOKUP_PFX_PATH=' . $pfxPath);
    putenv('EOP_LOOKUP_PFX_PASSWORD=' . (string)($ctx['pfx_password'] ?? ''));
    putenv('EOP_LOOKUP_POLICY=' . $identifier);
    putenv('EOP_LOOKUP_OUTPUT=' . $outFile);

    $ps = <<<'POWERSHELL'
$ErrorActionPreference = 'Stop'
$payload = $null
try {
    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
    if ([string]::IsNullOrEmpty($env:EOP_LOOKUP_PFX_PASSWORD)) {
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($env:EOP_LOOKUP_PFX_PATH, '', $flags)
    } else {
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($env:EOP_LOOKUP_PFX_PATH, $env:EOP_LOOKUP_PFX_PASSWORD, $flags)
    }

    Connect-ExchangeOnline -Certificate $cert -AppId $env:EOP_LOOKUP_CLIENT_ID -Organization $env:EOP_LOOKUP_ORGANIZATION -ErrorAction Stop

    try {
        $policy = Get-HostedContentFilterPolicy -Identity $env:EOP_LOOKUP_POLICY -ErrorAction Stop
    } catch {
        $reason = $_.Exception.Message
        if ($reason -match "couldn't be found|cannot be found|could not be found|does not exist|not found") {
            $payload = [ordered]@{ status = 'not_found'; message = $reason }
        } else {
            $payload = [ordered]@{ status = 'unavailable'; message = $reason }
        }
    }

    if ($null -eq $payload) {
        $guid = ''
        if ($policy.Guid) { $guid = $policy.Guid.ToString() }
        elseif ($policy.Identity) { $guid = $policy.Identity.ToString() }
        $payload = [ordered]@{
            status = 'verified'
            name   = [string]$policy.Name
            guid   = $guid
        }
    }
} catch {
    $payload = [ordered]@{ status = 'unavailable'; message = $_.Exception.Message }
}

try { $payload | ConvertTo-Json -Compress | Set-Content -LiteralPath $env:EOP_LOOKUP_OUTPUT -Encoding UTF8 } catch { }
Disconnect-ExchangeOnline -ErrorAction SilentlyContinue | Out-Null
POWERSHELL;

    // The decrypted passphrase and the lookup transcript are removed on every exit
    // path, including a fatal error part-way through the lookup.
    register_shutdown_function(static function () use ($outFile): void {
        if (is_file($outFile)) {
            @unlink($outFile);
        }
    });

    $shell = sprintf(
        '%s -NoProfile -NonInteractive -Command %s 2>&1',
        escapeshellarg($pwsh),
        escapeshellarg($ps)
    );

    $output = [];
    $exitCode = 0;
    @exec($shell, $output, $exitCode);

    // Set-Content -Encoding UTF8 emits a BOM under Windows PowerShell 5.1, which
    // json_decode rejects, so the byte-order mark is stripped defensively.
    $bom = chr(0xEF) . chr(0xBB) . chr(0xBF);
    $rawResponse = (string)@file_get_contents($outFile);
    if (strncmp($rawResponse, $bom, 3) === 0) {
        $rawResponse = substr($rawResponse, 3);
    }
    $decoded = json_decode($rawResponse, true);
    if (!is_array($decoded) || !isset($decoded['status'])) {
        $detail = trim(implode(' ', array_slice($output, 0, 3)));
        $result['message'] = $detail !== ''
            ? 'The Exchange Online lookup did not return a readable result: ' . $detail
            : 'The Exchange Online lookup did not return a readable result (exit code ' . $exitCode . ').';
        return $result;
    }

    $status = (string)$decoded['status'];
    $result['status'] = in_array($status, ['verified', 'not_found'], true) ? $status : 'unavailable';
    $result['name'] = trim((string)($decoded['name'] ?? ''));
    $result['guid'] = eopNormalizeGuid($decoded['guid'] ?? '') ?: $result['guid'];
    $result['message'] = trim((string)($decoded['message'] ?? ''));

    return $result;
}

// Automatically ensure config.php exists on disk
function ensureConfigPhp(): bool {
    $cfgPath = __DIR__ . '/config.php';
    if (!file_exists($cfgPath)) {
        $defaultConfig = <<<'PHP'
<?php
/**
 * Exchange Online Protection (EOP) Anti-Spam Policy Manager
 * Application Configuration File
 * Environment: Debian Linux / PHP 8.x / Remote MariaDB / Active Directory LDAP
 */

declare(strict_types=1);

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    http_response_code(403);
    exit('Direct access forbidden.');
}

ini_set('session.cookie_httponly', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_samesite', 'Lax');
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    ini_set('session.cookie_secure', '1');
}

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$sessionTimeoutSeconds = 60 * 60;
if (isset($_SESSION['LAST_ACTIVITY']) && (time() - $_SESSION['LAST_ACTIVITY'] > $sessionTimeoutSeconds)) {
    session_unset();
    session_destroy();
    header('Location: login.php?msg=timeout');
    exit;
}
$_SESSION['LAST_ACTIVITY'] = time();

$envFilePath = __DIR__ . '/.env';
if (file_exists($envFilePath) && is_readable($envFilePath)) {
    $envLines = @file($envFilePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($envLines !== false) {
        foreach ($envLines as $envLine) {
            $envLine = trim($envLine);
            if ($envLine === '' || str_starts_with($envLine, '#') || str_starts_with($envLine, ';')) {
                continue;
            }
            if (strpos($envLine, '=') !== false) {
                [$envKey, $envVal] = explode('=', $envLine, 2);
                $envKey = trim($envKey);
                $envVal = trim($envVal);
                if ((str_starts_with($envVal, '"') && str_ends_with($envVal, '"')) ||
                    (str_starts_with($envVal, "'") && str_ends_with($envVal, "'"))) {
                    $envVal = substr($envVal, 1, -1);
                }
                putenv("{$envKey}={$envVal}");
                $_ENV[$envKey] = $envVal;
                $_SERVER[$envKey] = $envVal;
            }
        }
    }
}

define('DB_HOST', getenv('DB_HOST') ?: '192.168.10.50');
define('DB_PORT', (int)(getenv('DB_PORT') ?: 3306));
define('DB_NAME', getenv('DB_NAME') ?: 'eop_antispam_db');
define('DB_USER', getenv('DB_USER') ?: 'eop_app_user');
define('DB_PASS', getenv('DB_PASS') ?: 'P@ssw0rd_Secure_MariaDB_2026');
define('DB_CHARSET', 'utf8mb4');

define('TABLE_ALLOWED_SENDERS', 'eop_allowed_senders');
define('TABLE_BLOCKED_SENDERS', 'eop_blocked_senders');
define('TABLE_ALLOWED_DOMAINS', 'eop_allowed_domains');
define('TABLE_BLOCKED_DOMAINS', 'eop_blocked_domains');
define('TABLE_AUDIT_LOG',       'eop_audit_log');
define('TABLE_POLICIES',        'eop_policies');
define('TABLE_LDAP_CONFIG',     'eop_ldap_config');
define('TABLE_EOP_AUTH_CONFIG', 'eop_auth_config');
define('TABLE_LOCAL_ADMINS',    'eop_local_admins');
define('TABLE_SYNC_CONFIRMATIONS', 'eop_sync_confirmations'); // Withheld deletions awaiting an administrator accept/deny decision

define('AUTH_MASTER_ENCRYPTION_KEY', getenv('AUTH_MASTER_ENCRYPTION_KEY') ?: 'eop_master_aes256_secret_key_2026_debian');

// Shared AES-256-GCM envelope shared with database.php at runtime
require_once __DIR__ . '/crypto.php';

define('LDAP_HOST', getenv('LDAP_HOST') ?: 'dc01.corp.example.com');
define('LDAP_PORT', (int)(getenv('LDAP_PORT') ?: 389));
define('LDAP_PROTOCOL', getenv('LDAP_PROTOCOL') ?: 'ldap');
define('LDAP_USE_SSL', LDAP_PROTOCOL === 'ldaps');
define('LDAP_USE_TLS', LDAP_PROTOCOL === 'starttls');
define('LDAP_BASE_DN', getenv('LDAP_BASE_DN') ?: 'DC=corp,DC=example,DC=com');
define('LDAP_AUTHORIZED_GROUP_DN', getenv('LDAP_AUTHORIZED_GROUP_DN') ?: 'CN=Exchange-Admins,OU=Security Groups,DC=corp,DC=example,DC=com');
define('LDAP_BIND_DN', getenv('LDAP_BIND_DN') ?: 'CN=svc-eop-web,OU=Service Accounts,DC=corp,DC=example,DC=com');
define('LDAP_BIND_PASSWORD', getenv('LDAP_BIND_PASSWORD') ?: 'Svc_P@ssw0rd_AD_2026');
define('LDAP_ACCOUNT_SUFFIX', '@corp.example.com');
define('LDAP_NETBIOS_DOMAIN', 'CORP');

define('FALLBACK_ADMIN_ENABLED', true);
define('FALLBACK_ADMIN_USERNAME', getenv('FALLBACK_ADMIN_USER') ?: 'eopadmin');
define('FALLBACK_ADMIN_PASSWORD_HASH', '$2y$12$eopEmergencyAdminFallbackHashPlaceholder2026XyZ');

define('DEFAULT_POLICY_NAME', getenv('EOP_POLICY_NAME') ?: 'Default');
// Exchange GUID of the policy named above, resolved by the setup wizard when the
// policy was supplied as a GUID. Empty when it was never confirmed.
define('DEFAULT_POLICY_GUID', getenv('EOP_POLICY_GUID') ?: '${cfg.defaultPolicyGuid || ''}');
define('APP_TITLE', 'EOP Anti-Spam Policy Manager');
define('APP_URL', 'https://eop.corp.example.com');

$GLOBALS['AVAILABLE_POLICIES'] = [
    'Default' => 'Default Inbound Anti-Spam Policy (Applied to all recipients)',
    'Strict Anti-Spam Policy'  => 'Strict Security Baseline (Targeted VIPs & High Value Mailboxes)',
    'Executive Inbound Policy' => 'Custom Executive Mailbox Inbound Filtering',
    'Custom Inbound Filter'    => 'Custom Departmental Filter Policy'
];

define('M365_TENANT_ID', getenv('M365_TENANT_ID') ?: '11111111-2222-3333-4444-555555555555');
define('M365_CLIENT_ID', getenv('M365_CLIENT_ID') ?: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
define('M365_CERT_THUMBPRINT', getenv('M365_CERT_THUMBPRINT') ?: '9A2F8B3C1D4E5F6A7B8C9D0E1F2A3B4C5D6E7F80');
define('M365_ORGANIZATION', getenv('M365_ORGANIZATION') ?: 'corp.example.com');
define('M365_CLIENT_SECRET', getenv('M365_CLIENT_SECRET') ?: 'YOUR_AZURE_APP_CLIENT_SECRET');
define('SYNC_SCRIPT_PATH', __DIR__ . '/sync-exchange.ps1');
PHP;
        @file_put_contents($cfgPath, $defaultConfig);
        @chmod($cfgPath, 0644);
        return true;
    }
    return true;
}
ensureConfigPhp();

// -----------------------------------------------------------------------------
// Security Check: If locked on disk or database, strictly forbid execution!
// -----------------------------------------------------------------------------
if (file_exists($lockFile)) {
    http_response_code(403);
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Setup Routine Locked - 403 Forbidden</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-950 text-slate-100 flex items-center justify-center min-h-screen p-4 font-sans">
        <div class="max-w-md w-full bg-slate-900 border border-slate-800 p-8 rounded-2xl shadow-2xl text-center">
            <div class="w-16 h-16 bg-amber-500/10 border border-amber-500/30 text-amber-400 rounded-2xl flex items-center justify-center mx-auto mb-4 text-3xl font-bold">
                🔒
            </div>
            <span class="inline-block px-3 py-1 bg-amber-500/10 text-amber-400 border border-amber-500/20 text-xs font-mono rounded-full mb-3 font-semibold">
                STATUS: 403 FORBIDDEN &bull; LOCKED
            </span>
            <h1 class="text-xl font-bold text-white mb-2">Initial Setup Routine is Locked</h1>
            <p class="text-slate-400 text-xs leading-relaxed mb-5">
                This system has already been configured and initialized. For security reasons, the initial setup routine cannot be run while the lockfile is active.
            </p>
            <div class="bg-slate-950/80 p-3.5 rounded-xl border border-slate-800 text-left text-xs font-mono text-slate-400 mb-5 space-y-1.5">
                <div><span class="text-slate-500 font-sans font-medium">Debian Lockfile:</span> <code class="text-blue-400">installed.lock</code></div>
                <div><span class="text-slate-500 font-sans font-medium">MariaDB Table:</span> <code class="text-purple-400">eop_setup_lock</code></div>
                <div><span class="text-slate-500 font-sans font-medium">To Re-run Setup:</span> <code class="text-emerald-400">sudo rm -f /var/www/eop-antispam/installed.lock</code></div>
            </div>
            <div class="flex flex-col gap-2">
                <a href="login.php" class="w-full py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold inline-block transition shadow-sm">
                    Proceed to Active Directory Login &rarr;
                </a>
            </div>
        </div>
    </body>
    </html>
    <?php
    exit;
}

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Ensure session setup store exists
if (!isset($_SESSION['wizard'])) {
    $_SESSION['wizard'] = [
        'step' => 1,
        'db' => [
            'host' => '${cfg.dbHost}',
            'port' => ${cfg.dbPort},
            'name' => '${cfg.dbName}',
            'user' => '${cfg.dbUser}',
            'pass' => '${cfg.dbPass}',
            'populated' => false,
            'tables' => []
        ],
        'ldap' => [
            'host' => '${cfg.ldapHost}',
            'port' => ${cfg.ldapPort},
            'protocol' => '${cfg.ldapProtocol}',
            'base_dn' => '${cfg.ldapBaseDn}',
            'group_dn' => '${cfg.ldapGroupDn}',
            'bind_dn' => '${cfg.ldapBindDn}',
            'bind_pass' => '${cfg.ldapBindPass}',
            'domain' => '${cfg.ldapDomain}',
            'tested' => false
        ],
        'eop' => [
            'tenant_id' => '${cfg.tenantId}',
            'client_id' => '${cfg.clientId}',
            'thumbprint' => '${cfg.certificateThumbprint}',
            'org_domain' => '${cfg.organization || "corp.example.com"}',
            'policy' => '${cfg.defaultPolicyName}',
            'private_key' => '${(cfg.privateKeyPem || "").replace(/\n/g, "\\n")}',
            'passphrase' => '${cfg.keyPassword || "P@ssphrase_Secure_Cert_2026"}',
            'validated' => false
        ]
    ];
}

/**
 * Read and parse existing environment variables from the Debian .env file
 */
function readExistingEnv(): array {
    $envPath = __DIR__ . '/.env';
    $existing = [];

    if (file_exists($envPath) && is_readable($envPath)) {
        $lines = @file($envPath, FILE_IGNORE_NEW_LINES);
        if ($lines !== false) {
            foreach ($lines as $line) {
                $trimmed = trim($line);
                if ($trimmed !== '' && !str_starts_with($trimmed, '#') && !str_starts_with($trimmed, ';') && strpos($trimmed, '=') !== false) {
                    [$k, $v] = explode('=', $trimmed, 2);
                    $k = trim($k);
                    $v = trim($v);
                    if ((str_starts_with($v, '"') && str_ends_with($v, '"')) ||
                        (str_starts_with($v, "'") && str_ends_with($v, "'"))) {
                        $v = substr($v, 1, -1);
                    }
                    $existing[$k] = $v;
                }
            }
        }
    }

    return $existing;
}

/**
 * Write or update the Debian .env file with verified database and system settings
 */
function updateEnvConfiguration(array $db, ?array $ldap = null, ?array $eop = null): bool {
    $envPath = __DIR__ . '/.env';
    if ($ldap === null && !empty($_SESSION['wizard']['ldap'])) {
        $ldap = $_SESSION['wizard']['ldap'];
    }
    if ($eop === null && !empty($_SESSION['wizard']['eop'])) {
        $eop = $_SESSION['wizard']['eop'];
    }

    $existing = readExistingEnv();

    $dbHost = $db['host'] ?? ($existing['DB_HOST'] ?? '127.0.0.1');
    $dbPort = (int)($db['port'] ?? ($existing['DB_PORT'] ?? 3306));
    $dbName = $db['name'] ?? ($existing['DB_NAME'] ?? 'eop_antispam_db');
    $dbUser = $db['user'] ?? ($existing['DB_USER'] ?? 'root');
    $dbPass = $db['pass'] ?? ($existing['DB_PASS'] ?? '');

    $ldapHost = $ldap['host'] ?? ($existing['LDAP_HOST'] ?? 'dc01.corp.example.com');
    $ldapPort = (int)($ldap['port'] ?? ($existing['LDAP_PORT'] ?? 389));
    $ldapProto = $ldap['protocol'] ?? ($existing['LDAP_PROTOCOL'] ?? 'ldap');
    $ldapBase = $ldap['base_dn'] ?? ($existing['LDAP_BASE_DN'] ?? 'DC=corp,DC=example,DC=com');
    $ldapGrp = $ldap['group_dn'] ?? ($existing['LDAP_AUTHORIZED_GROUP_DN'] ?? 'CN=Exchange-Admins,OU=Security Groups,DC=corp,DC=example,DC=com');
    $ldapBind = $ldap['bind_dn'] ?? ($existing['LDAP_BIND_DN'] ?? 'CN=svc-eop-web,OU=Service Accounts,DC=corp,DC=example,DC=com');
    $ldapPass = $ldap['bind_pass'] ?? ($existing['LDAP_BIND_PASSWORD'] ?? '');
    $ldapDomain = $ldap['domain'] ?? ($existing['LDAP_DOMAIN'] ?? 'CORP');

    $fallbackEnabled = isset($ldap['fallback_admin_enabled'])
        ? ($ldap['fallback_admin_enabled'] ? 'true' : 'false')
        : ($existing['FALLBACK_ADMIN_ENABLED'] ?? 'true');
    $fallbackUser = $ldap['fallback_admin_username'] ?? ($existing['FALLBACK_ADMIN_USER'] ?? 'eopadmin');

    $tenantId = $eop['tenant_id'] ?? ($existing['M365_TENANT_ID'] ?? '11111111-2222-3333-4444-555555555555');
    $clientId = $eop['client_id'] ?? ($existing['M365_CLIENT_ID'] ?? 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
    $thumb = eopNormalizeThumbprint($eop['thumbprint'] ?? ($existing['M365_CERT_THUMBPRINT'] ?? '9A2F8B3C1D4E5F6A7B8C9D0E1F2A3B4C5D6E7F80'));
    $org = $eop['org_domain'] ?? ($existing['M365_ORGANIZATION'] ?? 'corp.example.com');
    $policy = $eop['policy'] ?? ($existing['EOP_POLICY_NAME'] ?? 'Default Inbound Anti-Spam Policy');
    $policyGuid = eopNormalizeGuid($eop['policy_guid'] ?? ($existing['EOP_POLICY_GUID'] ?? ''));
    $masterKey = (defined('AUTH_MASTER_ENCRYPTION_KEY') && AUTH_MASTER_ENCRYPTION_KEY !== '')
        ? AUTH_MASTER_ENCRYPTION_KEY
        : ($existing['AUTH_MASTER_ENCRYPTION_KEY'] ?? (getenv('AUTH_MASTER_ENCRYPTION_KEY') ?: bin2hex(random_bytes(16))));
    if (!defined('AUTH_MASTER_ENCRYPTION_KEY')) {
        define('AUTH_MASTER_ENCRYPTION_KEY', $masterKey);
    }
    putenv("AUTH_MASTER_ENCRYPTION_KEY={$masterKey}");
    $_ENV['AUTH_MASTER_ENCRYPTION_KEY'] = $masterKey;
    $appUrl = $existing['APP_URL'] ?? ('https://' . ($_SERVER['HTTP_HOST'] ?? 'eop.corp.example.com'));

    $dateStr = date('Y-m-d H:i:s');
    $lines = [
        '# ==============================================================================',
        '# Exchange Online Protection (EOP) Anti-Spam Policy Manager',
        '# Environment Configuration (.env)',
        '# Automatically updated by setup wizard on ' . $dateStr,
        '# ==============================================================================',
        '',
        '# ------------------------------------------------------------------------------',
        '# Remote MariaDB Database Settings',
        '# ------------------------------------------------------------------------------',
        'DB_HOST="' . $dbHost . '"',
        'DB_PORT="' . $dbPort . '"',
        'DB_NAME="' . $dbName . '"',
        'DB_USER="' . $dbUser . '"',
        'DB_PASS="' . $dbPass . '"',
        'DB_CHARSET="utf8mb4"',
        '',
        '# ------------------------------------------------------------------------------',
        '# Active Directory LDAP Settings (seeded to eop_ldap_config)',
        '# ------------------------------------------------------------------------------',
        'LDAP_HOST="' . $ldapHost . '"',
        'LDAP_PORT="' . $ldapPort . '"',
        'LDAP_PROTOCOL="' . $ldapProto . '"',
        'LDAP_USE_SSL="' . ($ldapProto === 'ldaps' ? 'true' : 'false') . '"',
        'LDAP_USE_TLS="' . ($ldapProto === 'starttls' ? 'true' : 'false') . '"',
        'LDAP_BASE_DN="' . $ldapBase . '"',
        'LDAP_AUTHORIZED_GROUP_DN="' . $ldapGrp . '"',
        'LDAP_BIND_DN="' . $ldapBind . '"',
        'LDAP_BIND_PASSWORD="' . $ldapPass . '"',
        'LDAP_DOMAIN="' . $ldapDomain . '"',
        '',
        '# ------------------------------------------------------------------------------',
        '# Emergency Non-LDAP Fallback Administrator Account',
        '# ------------------------------------------------------------------------------',
        'FALLBACK_ADMIN_ENABLED="' . $fallbackEnabled . '"',
        'FALLBACK_ADMIN_USER="' . $fallbackUser . '"',
        '',
        '# ------------------------------------------------------------------------------',
        '# Microsoft 365 Exchange Online Protection Settings (seeded to eop_auth_config)',
        '# ------------------------------------------------------------------------------',
        'M365_TENANT_ID="' . $tenantId . '"',
        'M365_CLIENT_ID="' . $clientId . '"',
        'M365_CERT_THUMBPRINT="' . $thumb . '"',
        'M365_ORGANIZATION="' . $org . '"',
        'EOP_POLICY_NAME="' . $policy . '"',
        'EOP_POLICY_GUID="' . $policyGuid . '"',
        'M365_CLIENT_SECRET="' . ($existing['M365_CLIENT_SECRET'] ?? 'YOUR_AZURE_APP_CLIENT_SECRET') . '"',
        '',
        '# ------------------------------------------------------------------------------',
        '# Security & Master Keys',
        '# ------------------------------------------------------------------------------',
        'AUTH_MASTER_ENCRYPTION_KEY="' . $masterKey . '"',
        'APP_URL="' . $appUrl . '"',
        ''
    ];
    $content = implode("\\n", $lines);

    $written = @file_put_contents($envPath, $content);
    if ($written !== false) {
        @chmod($envPath, 0640);
        return true;
    }
    return false;
}

/**
 * Write or update config.php with verified database, LDAP, and system settings
 */
function updateConfigFile(array $db, ?array $ldap = null, ?array $eop = null): bool {
    $cfgPath = __DIR__ . '/config.php';
    if ($ldap === null && !empty($_SESSION['wizard']['ldap'])) {
        $ldap = $_SESSION['wizard']['ldap'];
    }
    if ($eop === null && !empty($_SESSION['wizard']['eop'])) {
        $eop = $_SESSION['wizard']['eop'];
    }

    $existing = [];
    $envPath = __DIR__ . '/.env';
    if (file_exists($envPath) && is_readable($envPath)) {
        $lines = @file($envPath, FILE_IGNORE_NEW_LINES);
        if ($lines !== false) {
            foreach ($lines as $line) {
                $trimmed = trim($line);
                if ($trimmed !== '' && !str_starts_with($trimmed, '#') && !str_starts_with($trimmed, ';') && strpos($trimmed, '=') !== false) {
                    [$k, $v] = explode('=', $trimmed, 2);
                    $k = trim($k);
                    $v = trim($v);
                    if ((str_starts_with($v, '"') && str_ends_with($v, '"')) ||
                        (str_starts_with($v, "'") && str_ends_with($v, "'"))) {
                        $v = substr($v, 1, -1);
                    }
                    $existing[$k] = $v;
                }
            }
        }
    }

    $dbHost = addslashes($db['host'] ?? ($existing['DB_HOST'] ?? '127.0.0.1'));
    $dbPort = (int)($db['port'] ?? ($existing['DB_PORT'] ?? 3306));
    $dbName = addslashes($db['name'] ?? ($existing['DB_NAME'] ?? 'eop_antispam_db'));
    $dbUser = addslashes($db['user'] ?? ($existing['DB_USER'] ?? 'root'));
    $dbPass = addslashes($db['pass'] ?? ($existing['DB_PASS'] ?? ''));

    $ldapHost = addslashes($ldap['host'] ?? ($existing['LDAP_HOST'] ?? 'dc01.corp.example.com'));
    $ldapPort = (int)($ldap['port'] ?? ($existing['LDAP_PORT'] ?? 389));
    $ldapProto = addslashes($ldap['protocol'] ?? ($existing['LDAP_PROTOCOL'] ?? 'ldap'));
    $ldapBase = addslashes($ldap['base_dn'] ?? ($existing['LDAP_BASE_DN'] ?? 'DC=corp,DC=example,DC=com'));
    $ldapGrp = addslashes($ldap['group_dn'] ?? ($existing['LDAP_AUTHORIZED_GROUP_DN'] ?? 'CN=Exchange-Admins,OU=Security Groups,DC=corp,DC=example,DC=com'));
    $ldapBind = addslashes($ldap['bind_dn'] ?? ($existing['LDAP_BIND_DN'] ?? 'CN=svc-eop-web,OU=Service Accounts,DC=corp,DC=example,DC=com'));
    $ldapPass = addslashes($ldap['bind_pass'] ?? ($existing['LDAP_BIND_PASSWORD'] ?? ''));
    $ldapDomain = addslashes($ldap['domain'] ?? ($existing['LDAP_DOMAIN'] ?? 'CORP'));

    $fallbackEnabled = !empty($ldap['fallback_admin_enabled']) ? 'true' : 'false';
    $fallbackUser = addslashes($ldap['fallback_admin_username'] ?? ($existing['FALLBACK_ADMIN_USER'] ?? 'eopadmin'));

    $tenantId = addslashes($eop['tenant_id'] ?? ($existing['M365_TENANT_ID'] ?? '11111111-2222-3333-4444-555555555555'));
    $clientId = addslashes($eop['client_id'] ?? ($existing['M365_CLIENT_ID'] ?? 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'));
    $thumb = addslashes(eopNormalizeThumbprint($eop['thumbprint'] ?? ($existing['M365_CERT_THUMBPRINT'] ?? '9A2F8B3C1D4E5F6A7B8C9D0E1F2A3B4C5D6E7F80')));
    $org = addslashes($eop['org_domain'] ?? ($existing['M365_ORGANIZATION'] ?? 'corp.example.com'));
    $policy = addslashes($eop['policy'] ?? ($existing['EOP_POLICY_NAME'] ?? 'Default Inbound Anti-Spam Policy'));
    $policyGuid = addslashes(eopNormalizeGuid($eop['policy_guid'] ?? ($existing['EOP_POLICY_GUID'] ?? '')));
    $masterKey = addslashes((defined('AUTH_MASTER_ENCRYPTION_KEY') && AUTH_MASTER_ENCRYPTION_KEY !== '')
        ? AUTH_MASTER_ENCRYPTION_KEY
        : ($existing['AUTH_MASTER_ENCRYPTION_KEY'] ?? (getenv('AUTH_MASTER_ENCRYPTION_KEY') ?: bin2hex(random_bytes(16)))));
    $appUrl = addslashes($existing['APP_URL'] ?? ('https://' . ($_SERVER['HTTP_HOST'] ?? 'eop.corp.example.com')));
    // The stock description only describes the shipped default. A policy chosen in
    // the wizard (or resolved from a GUID) gets a neutral label rather than being
    // mislabelled as the built-in default.
    $policyDescription = $policy === 'Default Inbound Anti-Spam Policy'
        ? 'Default Inbound Anti-Spam Policy (Applied to all recipients)'
        : 'Primary Inbound Anti-Spam Policy (Selected during setup)';
    $dateStr = date('Y-m-d H:i:s');

    $cfg = "<?php\\n" .
"/**\\n" .
" * Exchange Online Protection (EOP) Anti-Spam Policy Manager\\n" .
" * Application Configuration File\\n" .
" * Environment: Debian Linux / PHP 8.x / Remote MariaDB / Active Directory LDAP\\n" .
" * Automatically written by setup wizard on {$dateStr}\\n" .
" */\\n\\n" .
"declare(strict_types=1);\\n\\n" .
"// Prevent direct script execution\\n" .
"if (basename(__FILE__) === basename(\\$_SERVER['SCRIPT_FILENAME'] ?? '')) {\\n" .
"    http_response_code(403);\\n" .
"    exit('Direct access forbidden.');\\n" .
"}\\n\\n" .
"// --------------------------------------------------------------------------\\n" .
"// 1. Session & Security Configuration\\n" .
"// --------------------------------------------------------------------------\\n" .
"ini_set('session.cookie_httponly', '1');\\n" .
"ini_set('session.use_only_cookies', '1');\\n" .
"ini_set('session.cookie_samesite', 'Lax');\\n" .
"if (!empty(\\$_SERVER['HTTPS']) && \\$_SERVER['HTTPS'] !== 'off') {\\n" .
"    ini_set('session.cookie_secure', '1');\\n" .
"}\\n\\n" .
"if (session_status() === PHP_SESSION_NONE) {\\n" .
"    session_start();\\n" .
"}\\n\\n" .
"\\$sessionTimeoutSeconds = 60 * 60;\\n" .
"if (isset(\\$_SESSION['LAST_ACTIVITY']) && (time() - \\$_SESSION['LAST_ACTIVITY'] > \\$sessionTimeoutSeconds)) {\\n" .
"    session_unset();\\n" .
"    session_destroy();\\n" .
"    header('Location: login.php?msg=timeout');\\n" .
"    exit;\\n" .
"}\\n" .
"\\$_SESSION['LAST_ACTIVITY'] = time();\\n\\n" .
"// --------------------------------------------------------------------------\\n" .
"// 1b. Load Environment Variables from .env\\n" .
"// Automatically loads .env written by setup.php or administrator\\n" .
"// --------------------------------------------------------------------------\\n" .
"\\$envFilePath = __DIR__ . '/.env';\\n" .
"if (file_exists(\\$envFilePath) && is_readable(\\$envFilePath)) {\\n" .
"    \\$envLines = @file(\\$envFilePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);\\n" .
"    if (\\$envLines !== false) {\\n" .
"        foreach (\\$envLines as \\$envLine) {\\n" .
"            \\$envLine = trim(\\$envLine);\\n" .
"            if (\\$envLine === '' || str_starts_with(\\$envLine, '#') || str_starts_with(\\$envLine, ';')) {\\n" .
"                continue;\\n" .
"            }\\n" .
"            if (strpos(\\$envLine, '=') !== false) {\\n" .
"                [\\$envKey, \\$envVal] = explode('=', \\$envLine, 2);\\n" .
"                \\$envKey = trim(\\$envKey);\\n" .
"                \\$envVal = trim(\\$envVal);\\n" .
"                if ((str_starts_with(\\$envVal, '\\"') && str_ends_with(\\$envVal, '\\"')) ||\\n" .
"                    (str_starts_with(\\$envVal, \\"'\\") && str_ends_with(\\$envVal, \\"'\\"))) {\\n" .
"                    \\$envVal = substr(\\$envVal, 1, -1);\\n" .
"                }\\n" .
"                putenv(\\"{\\$envKey}={\\$envVal}\\");\\n" .
"                \\$_ENV[\\$envKey] = \\$envVal;\\n" .
"                \\$_SERVER[\\$envKey] = \\$envVal;\\n" .
"            }\\n" .
"        }\\n" .
"    }\\n" .
"}\\n\\n" .
"// Helper function to safely fetch environment variable with fallback\\n" .
"if (!function_exists('eopEnv')) {\\n" .
"    function eopEnv(string \\$key, string \\$default = ''): string {\\n" .
"        if (isset(\\$_ENV[\\$key]) && \\$_ENV[\\$key] !== '') {\\n" .
"            return (string)\\$_ENV[\\$key];\\n" .
"        }\\n" .
"        if (isset(\\$_SERVER[\\$key]) && \\$_SERVER[\\$key] !== '') {\\n" .
"            return (string)\\$_SERVER[\\$key];\\n" .
"        }\\n" .
"        \\$val = getenv(\\$key);\\n" .
"        if (\\$val !== false && \\$val !== '') {\\n" .
"            return (string)\\$val;\\n" .
"        }\\n" .
"        return \\$default;\\n" .
"    }\\n" .
"}\\n\\n" .
"// --------------------------------------------------------------------------\\n" .
"// 2. Remote MariaDB Database Settings\\n" .
"// --------------------------------------------------------------------------\\n" .
"define('DB_HOST', eopEnv('DB_HOST', '{$dbHost}'));\\n" .
"define('DB_PORT', (int)eopEnv('DB_PORT', '{$dbPort}'));\\n" .
"define('DB_NAME', eopEnv('DB_NAME', '{$dbName}'));\\n" .
"define('DB_USER', eopEnv('DB_USER', '{$dbUser}'));\\n" .
"define('DB_PASS', eopEnv('DB_PASS', '{$dbPass}'));\\n" .
"define('DB_CHARSET', 'utf8mb4');\\n\\n" .
"// Individual MariaDB tables per list requirement\\n" .
"define('TABLE_ALLOWED_SENDERS', 'eop_allowed_senders');\\n" .
"define('TABLE_BLOCKED_SENDERS', 'eop_blocked_senders');\\n" .
"define('TABLE_ALLOWED_DOMAINS', 'eop_allowed_domains');\\n" .
"define('TABLE_BLOCKED_DOMAINS', 'eop_blocked_domains');\\n" .
"define('TABLE_AUDIT_LOG',       'eop_audit_log');\\n" .
"define('TABLE_POLICIES',        'eop_policies');\\n" .
"define('TABLE_LDAP_CONFIG',     'eop_ldap_config');\\n" .
"define('TABLE_EOP_AUTH_CONFIG', 'eop_auth_config');\\n" .
"define('TABLE_LOCAL_ADMINS',    'eop_local_admins');\\n" .
"define('TABLE_SYNC_CONFIRMATIONS', 'eop_sync_confirmations');\\n\\n" .
"define('AUTH_MASTER_ENCRYPTION_KEY', eopEnv('AUTH_MASTER_ENCRYPTION_KEY', '{$masterKey}'));\\n\\n" .
"// --------------------------------------------------------------------------\\n" .
"// 3. Microsoft Active Directory (LDAP) Settings\\n" .
"// --------------------------------------------------------------------------\\n" .
"define('LDAP_HOST', eopEnv('LDAP_HOST', '{$ldapHost}'));\\n" .
"define('LDAP_PORT', (int)eopEnv('LDAP_PORT', '{$ldapPort}'));\\n" .
"define('LDAP_PROTOCOL', eopEnv('LDAP_PROTOCOL', '{$ldapProto}'));\\n" .
"define('LDAP_USE_SSL', LDAP_PROTOCOL === 'ldaps');\\n" .
"define('LDAP_USE_TLS', LDAP_PROTOCOL === 'starttls');\\n" .
"define('LDAP_BASE_DN', eopEnv('LDAP_BASE_DN', '{$ldapBase}'));\\n" .
"define('LDAP_AUTHORIZED_GROUP_DN', eopEnv('LDAP_AUTHORIZED_GROUP_DN', '{$ldapGrp}'));\\n" .
"define('LDAP_BIND_DN', eopEnv('LDAP_BIND_DN', '{$ldapBind}'));\\n" .
"define('LDAP_BIND_PASSWORD', eopEnv('LDAP_BIND_PASSWORD', '{$ldapPass}'));\\n" .
"define('LDAP_ACCOUNT_SUFFIX', '@' . '{$org}');\\n" .
"define('LDAP_NETBIOS_DOMAIN', '{$ldapDomain}');\\n\\n" .
"define('FALLBACK_ADMIN_ENABLED', {$fallbackEnabled});\\n" .
"define('FALLBACK_ADMIN_USERNAME', eopEnv('FALLBACK_ADMIN_USER', '{$fallbackUser}'));\\n" .
"define('FALLBACK_ADMIN_PASSWORD_HASH', '\\$2y\\$12\\$EmergencyFallbackAdminHash2026SecureBcrypt');\\n\\n" .
"define('DEFAULT_POLICY_NAME', eopEnv('EOP_POLICY_NAME', '{$policy}'));\\n" .
"// Exchange GUID of the policy named above, when the setup wizard resolved it.\\n" .
"// Empty when the policy was never confirmed against Exchange Online.\\n" .
"define('DEFAULT_POLICY_GUID', eopEnv('EOP_POLICY_GUID', '{$policyGuid}'));\\n" .
"define('APP_TITLE', 'EOP Anti-Spam Policy Manager');\\n" .
"define('APP_URL', eopEnv('APP_URL', '{$appUrl}'));\\n\\n" .
"\\$GLOBALS['AVAILABLE_POLICIES'] = [\\n" .
"    '{$policy}' => '{$policyDescription}',\\n" .
"    'Strict Anti-Spam Policy'  => 'Strict Security Baseline (Targeted VIPs & High Value Mailboxes)',\\n" .
"    'Executive Inbound Policy' => 'Custom Executive Mailbox Inbound Filtering',\\n" .
"    'Custom Inbound Filter'    => 'Custom Departmental Filter Policy'\\n" .
"];\\n\\n" .
"define('M365_TENANT_ID', eopEnv('M365_TENANT_ID', '{$tenantId}'));\\n" .
"define('M365_CLIENT_ID', eopEnv('M365_CLIENT_ID', '{$clientId}'));\\n" .
"define('M365_CERT_THUMBPRINT', eopEnv('M365_CERT_THUMBPRINT', '{$thumb}'));\\n" .
"define('M365_ORGANIZATION', eopEnv('M365_ORGANIZATION', '{$org}'));\\n" .
"define('M365_CLIENT_SECRET', eopEnv('M365_CLIENT_SECRET', 'YOUR_AZURE_APP_CLIENT_SECRET'));\\n" .
"define('SYNC_SCRIPT_PATH', __DIR__ . '/sync-exchange.ps1');\\n";

    $written = @file_put_contents($cfgPath, $cfg);
    if ($written !== false) {
        @chmod($cfgPath, 0644);
        return true;
    }
    return false;
}

$error = null;
$notice = null;
$warning = null;
$success = null;
$dbTestResult = $_SESSION['wizard']['db_test_result'] ?? null;
$ldapTestResult = $_SESSION['wizard']['ldap_test_result'] ?? null;

// Allow direct step navigation if previous steps were done
$currentStep = (int)($_GET['step'] ?? $_SESSION['wizard']['step'] ?? 1);
if ($currentStep < 1) $currentStep = 1;
if ($currentStep > 5) $currentStep = 5;

// POST Action Handlers
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    // Step 1 -> Advance to Step 2
    if ($action === 'step1_start') {
        $_SESSION['wizard']['step'] = 2;
        header('Location: setup.php?step=2');
        exit;
    }

    // Step 2 Test Action: Test Database Connection without populating schema
    if ($action === 'test_db') {
        $testStart = microtime(true);
        $host = trim($_POST['db_host'] ?? '');
        $port = (int)($_POST['db_port'] ?? 3306);
        $name = trim($_POST['db_name'] ?? '');
        $user = trim($_POST['db_user'] ?? '');
        $pass = $_POST['db_pass'] ?? '';

        // Save current form values to session so user doesn't lose what they entered
        $_SESSION['wizard']['db']['host'] = $host;
        $_SESSION['wizard']['db']['port'] = $port;
        $_SESSION['wizard']['db']['name'] = $name;
        $_SESSION['wizard']['db']['user'] = $user;
        $_SESSION['wizard']['db']['pass'] = $pass;

        if (empty($host) || empty($user)) {
            $error = "MariaDB Server Host and Username are required to test the database connection.";
            $dbTestResult = [
                'success'        => false,
                'status'         => 'MISSING INPUTS',
                'message'        => $error,
                'details'        => 'Please enter the MariaDB Server Host IP/hostname and Username before initiating connection test.',
                'tested_at'      => date('Y-m-d H:i:s'),
                'latency_ms'     => 0,
                'host'           => $host ?: 'Not specified',
                'port'           => $port,
                'db_name'        => $name ?: 'Not specified',
                'server_version' => 'N/A',
                'db_exists'      => false,
            ];
            $_SESSION['wizard']['db_test_result'] = $dbTestResult;
        } else {
            try {
                $dsn = "mysql:host={$host};port={$port};charset=utf8mb4";
                $pdo = new PDO($dsn, $user, $pass, [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_TIMEOUT => 4
                ]);

                $latencyMs = round((microtime(true) - $testStart) * 1000, 1);
                $serverVersion = $pdo->query("SELECT VERSION()")->fetchColumn() ?: 'MariaDB';

                $dbExists = false;
                if (!empty($name)) {
                    $dbCheckStmt = $pdo->prepare("SHOW DATABASES LIKE :db");
                    $dbCheckStmt->execute([':db' => $name]);
                    $dbExists = ($dbCheckStmt->rowCount() > 0);
                }

                $success = "MariaDB Connection Successful! Connected to {$host}:{$port} ({$serverVersion}) in {$latencyMs} ms.";
                $dbTestResult = [
                    'success'        => true,
                    'status'         => 'CONNECTED',
                    'message'        => $success,
                    'details'        => !empty($name)
                        ? ($dbExists
                            ? "Database '{$name}' exists on the server and is accessible. Ready to populate schema tables."
                            : "Connection verified! Database '{$name}' does not exist yet; it will be created automatically when you click 'Populate Schema & Continue'.")
                        : "Connection verified! Please specify a database name before populating schema tables.",
                    'tested_at'      => date('Y-m-d H:i:s'),
                    'latency_ms'     => $latencyMs,
                    'host'           => $host,
                    'port'           => $port,
                    'db_name'        => $name,
                    'server_version' => $serverVersion,
                    'db_exists'      => $dbExists,
                ];
                $_SESSION['wizard']['db_test_result'] = $dbTestResult;

            } catch (Exception $e) {
                $latencyMs = round((microtime(true) - $testStart) * 1000, 1);
                $error = "Database Connection Failed: " . $e->getMessage();
                $dbTestResult = [
                    'success'        => false,
                    'status'         => 'FAILED',
                    'message'        => $error,
                    'details'        => 'Could not establish connection to MariaDB server. Check network reachability, firewall rules, port binding (default 3306), MariaDB grant privileges for user \\'' . htmlspecialchars($user) . '\\', and password credentials.',
                    'tested_at'      => date('Y-m-d H:i:s'),
                    'latency_ms'     => $latencyMs,
                    'host'           => $host,
                    'port'           => $port,
                    'db_name'        => $name,
                    'server_version' => 'N/A',
                    'db_exists'      => false,
                ];
                $_SESSION['wizard']['db_test_result'] = $dbTestResult;
            }
        }
    }

    // Step 2: Populate Schema & Advance to Step 3
    if ($action === 'step2_db' || $action === 'populate_db') {
        $host = trim($_POST['db_host'] ?? '127.0.0.1');
        $port = (int)($_POST['db_port'] ?? 3306);
        $name = trim($_POST['db_name'] ?? 'eop_antispam_db');
        $user = trim($_POST['db_user'] ?? 'root');
        $pass = $_POST['db_pass'] ?? '';

        try {
            // Test connection
            $dsn = "mysql:host={$host};port={$port};charset=utf8mb4";
            $pdo = new PDO($dsn, $user, $pass, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
            ]);

            // Create database if not exists
            $pdo->exec("CREATE DATABASE IF NOT EXISTS \`{$name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
            $pdo->exec("USE \`{$name}\`");

            // Execute all 11 table schemas
            $tables = [
                'eop_allowed_senders' => "CREATE TABLE IF NOT EXISTS \`eop_allowed_senders\` (
                    \`id\` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    \`policy_name\` VARCHAR(255) NOT NULL DEFAULT 'Default Inbound Anti-Spam Policy',
                    \`sender_email\` VARCHAR(255) NOT NULL,
                    \`note\` TEXT NULL,
                    \`added_by\` VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
                    \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    \`updated_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY \`uniq_policy_sender\` (\`policy_name\`, \`sender_email\`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

                'eop_blocked_senders' => "CREATE TABLE IF NOT EXISTS \`eop_blocked_senders\` (
                    \`id\` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    \`policy_name\` VARCHAR(255) NOT NULL DEFAULT 'Default Inbound Anti-Spam Policy',
                    \`sender_email\` VARCHAR(255) NOT NULL,
                    \`note\` TEXT NULL,
                    \`added_by\` VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
                    \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    \`updated_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY \`uniq_policy_sender\` (\`policy_name\`, \`sender_email\`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

                'eop_allowed_domains' => "CREATE TABLE IF NOT EXISTS \`eop_allowed_domains\` (
                    \`id\` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    \`policy_name\` VARCHAR(255) NOT NULL DEFAULT 'Default Inbound Anti-Spam Policy',
                    \`domain_name\` VARCHAR(255) NOT NULL,
                    \`note\` TEXT NULL,
                    \`added_by\` VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
                    \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    \`updated_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY \`uniq_policy_domain\` (\`policy_name\`, \`domain_name\`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

                'eop_blocked_domains' => "CREATE TABLE IF NOT EXISTS \`eop_blocked_domains\` (
                    \`id\` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    \`policy_name\` VARCHAR(255) NOT NULL DEFAULT 'Default Inbound Anti-Spam Policy',
                    \`domain_name\` VARCHAR(255) NOT NULL,
                    \`note\` TEXT NULL,
                    \`added_by\` VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
                    \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    \`updated_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY \`uniq_policy_domain\` (\`policy_name\`, \`domain_name\`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

                'eop_audit_log' => "CREATE TABLE IF NOT EXISTS \`eop_audit_log\` (
                    \`id\` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    \`timestamp\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    \`username\` VARCHAR(100) NOT NULL,
                    \`action\` ENUM('ADD', 'REMOVE', 'UPDATE', 'SYNC', 'LOGIN', 'LOGOUT') NOT NULL,
                    \`list_type\` VARCHAR(50) NOT NULL,
                    \`policy_name\` VARCHAR(255) NOT NULL,
                    \`target_value\` VARCHAR(255) NOT NULL,
                    \`details\` TEXT NULL,
                    \`ip_address\` VARCHAR(45) NOT NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

                'eop_policies' => "CREATE TABLE IF NOT EXISTS \`eop_policies\` (
                    \`id\` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    \`policy_name\` VARCHAR(255) NOT NULL UNIQUE,
                    \`policy_guid\` CHAR(36) NULL,
                    \`description\` TEXT NULL,
                    \`is_default\` TINYINT(1) NOT NULL DEFAULT 0,
                    \`last_synced_at\` DATETIME NULL,
                    \`sync_status\` ENUM('synced', 'pending', 'failed') NOT NULL DEFAULT 'pending',
                    \`sync_message\` TEXT NULL,
                    \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    \`updated_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY \`uniq_policy_guid\` (\`policy_guid\`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

                'eop_ldap_config' => "CREATE TABLE IF NOT EXISTS \`eop_ldap_config\` (
                    \`id\` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    \`ldap_host\` VARCHAR(255) NOT NULL,
                    \`ldap_port\` INT NOT NULL DEFAULT 389,
                    \`ldap_protocol\` ENUM('ldap', 'ldaps', 'starttls') NOT NULL DEFAULT 'ldap',
                    \`ldap_base_dn\` VARCHAR(255) NOT NULL,
                    \`ldap_group_dn\` VARCHAR(255) NOT NULL,
                    \`ldap_bind_dn\` VARCHAR(255) NOT NULL,
                    \`ldap_bind_password\` VARCHAR(255) NOT NULL,
                    \`ldap_domain\` VARCHAR(100) NOT NULL,
                    \`is_active\` TINYINT(1) NOT NULL DEFAULT 1,
                    \`updated_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

                'eop_auth_config' => "CREATE TABLE IF NOT EXISTS \`eop_auth_config\` (
                    \`id\` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    \`tenant_id\` VARCHAR(100) NOT NULL,
                    \`client_id\` VARCHAR(100) NOT NULL,
                    \`certificate_thumbprint\` VARCHAR(100) NOT NULL,
                    \`key_filename\` VARCHAR(255) NOT NULL DEFAULT 'eop-cert-private.key',
                    \`private_key\` MEDIUMTEXT NOT NULL,
                    \`pkcs12_bundle\` MEDIUMTEXT NULL,
                    \`encrypted_password\` TEXT NULL,
                    \`encryption_iv\` VARCHAR(64) NULL,
                    \`encryption_tag\` VARCHAR(64) NULL,
                    \`organization\` VARCHAR(255) NULL DEFAULT 'corp.example.com',
                    \`key_type\` ENUM('RSA_PEM', 'PKCS8_PEM', 'PKCS12_PFX') NOT NULL DEFAULT 'RSA_PEM',
                    \`is_active\` TINYINT(1) NOT NULL DEFAULT 1,
                    \`uploaded_by\` VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
                    \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    \`updated_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

                'eop_setup_lock' => "CREATE TABLE IF NOT EXISTS \`eop_setup_lock\` (
                    \`id\` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    \`is_locked\` TINYINT(1) NOT NULL DEFAULT 1,
                    \`completed_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    \`completed_by\` VARCHAR(100) NOT NULL DEFAULT 'INITIAL_SETUP_WIZARD',
                    \`installer_ip\` VARCHAR(45) NOT NULL DEFAULT '127.0.0.1',
                    \`app_version\` VARCHAR(20) NOT NULL DEFAULT '1.0.0',
                    \`schema_version\` VARCHAR(20) NOT NULL DEFAULT '2026.1'
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

                'eop_local_admins' => "CREATE TABLE IF NOT EXISTS \`eop_local_admins\` (
                    \`id\` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    \`username\` VARCHAR(100) NOT NULL UNIQUE,
                    \`password_hash\` VARCHAR(255) NOT NULL,
                    \`is_active\` TINYINT(1) NOT NULL DEFAULT 1,
                    \`created_by\` VARCHAR(100) NOT NULL DEFAULT 'SETUP_WIZARD',
                    \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    \`updated_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    KEY \`idx_local_admin_username\` (\`username\`),
                    KEY \`idx_local_admin_active\` (\`is_active\`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

                'eop_sync_confirmations' => "CREATE TABLE IF NOT EXISTS \`eop_sync_confirmations\` (
                    \`id\` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    \`policy_name\` VARCHAR(255) NOT NULL,
                    \`list_type\` VARCHAR(50) NOT NULL,
                    \`local_count\` INT UNSIGNED NOT NULL DEFAULT 0,
                    \`remote_count\` INT UNSIGNED NOT NULL DEFAULT 0,
                    \`pending_values\` MEDIUMTEXT NULL,
                    \`values_truncated\` TINYINT(1) NOT NULL DEFAULT 0,
                    \`status\` ENUM('pending', 'accepted', 'denied', 'applied') NOT NULL DEFAULT 'pending',
                    \`requested_by\` VARCHAR(100) NOT NULL DEFAULT 'CRON_DAEMON',
                    \`decided_by\` VARCHAR(100) NULL,
                    \`decided_at\` DATETIME NULL,
                    \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    \`updated_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY \`uniq_policy_list\` (\`policy_name\`, \`list_type\`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
            ];

            foreach ($tables as $tblSql) {
                $pdo->exec($tblSql);
            }

            // Ensure eop_policies has sync_status, sync_message, updated_at columns if table already existed
            try {
                $check = $pdo->query("SHOW COLUMNS FROM \`eop_policies\` LIKE 'sync_status'");
                if ($check && $check->rowCount() === 0) {
                    @$pdo->exec("ALTER TABLE \`eop_policies\` ADD COLUMN sync_status ENUM('synced', 'pending', 'failed') NOT NULL DEFAULT 'pending'");
                    @$pdo->exec("ALTER TABLE \`eop_policies\` ADD COLUMN sync_message TEXT NULL");
                    @$pdo->exec("ALTER TABLE \`eop_policies\` ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP");
                }
            } catch (Exception $colEx) {
                // Ignore if migration fails
            }

            // Seed default policy
            $seedPolicy = $pdo->prepare("INSERT IGNORE INTO \`eop_policies\` (\`policy_name\`, \`description\`, \`is_default\`) VALUES (:name, 'Default Inbound Anti-Spam Policy for Organization', 1)");
            $seedPolicy->execute([':name' => 'Default Inbound Anti-Spam Policy']);

            // Save to session
            $_SESSION['wizard']['db'] = [
                'host' => $host,
                'port' => $port,
                'name' => $name,
                'user' => $user,
                'pass' => $pass,
                'populated' => true,
                'tables' => array_keys($tables)
            ];

            // Immediately write database connection parameters to .env and config.php files
            updateEnvConfiguration($_SESSION['wizard']['db']);
            updateConfigFile($_SESSION['wizard']['db']);

            $_SESSION['wizard']['step'] = 3;
            header('Location: setup.php?step=3');
            exit;

        } catch (Exception $e) {
            $error = "Database Connection Failed: " . $e->getMessage();
        }
    }

    // Step 3 Test Action: Test LDAP Connection without advancing to Step 4
    if ($action === 'test_ldap') {
        $testStart = microtime(true);
        $ldapHost = trim($_POST['ldap_host'] ?? '');
        $ldapPort = (int)($_POST['ldap_port'] ?? 389);
        $ldapProtocol = $_POST['ldap_protocol'] ?? 'ldap';
        $ldapBaseDn = trim($_POST['ldap_base_dn'] ?? '');
        $ldapGroupDn = trim($_POST['ldap_group_dn'] ?? '');
        $ldapBindDn = trim($_POST['ldap_bind_dn'] ?? '');
        $ldapBindPass = $_POST['ldap_bind_pass'] ?? '';
        $ldapDomain = trim($_POST['ldap_domain'] ?? 'CORP');

        // Fallback Non-LDAP Administrator settings
        $fallbackEnabled = !empty($_POST['fallback_admin_enabled']);
        $fallbackUser = trim($_POST['fallback_admin_username'] ?? 'eopadmin');
        $fallbackPass = $_POST['fallback_admin_password'] ?? '';

        // Save current form values to session so user doesn't lose what they entered
        $_SESSION['wizard']['ldap'] = [
            'host'                   => $ldapHost,
            'port'                   => $ldapPort,
            'protocol'               => $ldapProtocol,
            'base_dn'                => $ldapBaseDn,
            'group_dn'               => $ldapGroupDn,
            'bind_dn'                => $ldapBindDn,
            'bind_pass'              => $ldapBindPass,
            'domain'                 => $ldapDomain,
            'fallback_admin_enabled' => $fallbackEnabled,
            'fallback_admin_username'=> $fallbackUser,
            'fallback_admin_password'=> $fallbackPass,
        ];

        if (empty($ldapHost)) {
            $error = "Domain Controller Host / IP is required to test LDAP connection.";
            $ldapTestResult = [
                'success'    => false,
                'status'     => 'MISSING HOST',
                'message'    => $error,
                'details'    => 'Please enter the Active Directory or OpenLDAP Domain Controller Host/IP address before initiating connection test.',
                'tested_at'  => date('Y-m-d H:i:s'),
                'latency_ms' => 0,
                'host'       => $ldapHost,
                'port'       => $ldapPort,
                'protocol'   => strtoupper($ldapProtocol),
                'uri'        => 'Not specified',
                'auth_type'  => 'None',
                'bind_dn'    => 'N/A',
            ];
            $_SESSION['wizard']['ldap_test_result'] = $ldapTestResult;
        } else {
            try {
                $isSsl = ($ldapProtocol === 'ldaps' || $ldapPort === 636);
                $protoPrefix = $isSsl ? 'ldaps://' : 'ldap://';
                $uri = $protoPrefix . $ldapHost . ':' . $ldapPort;

                if (function_exists('ldap_connect')) {
                    $conn = @ldap_connect($uri);
                    if (!$conn) {
                        throw new Exception("Could not initialize connection to Active Directory at {$uri}");
                    }
                    ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);
                    ldap_set_option($conn, LDAP_OPT_REFERRALS, 0);
                    ldap_set_option($conn, LDAP_OPT_NETWORK_TIMEOUT, 4);

                    if (!$isSsl && ($ldapProtocol === 'starttls')) {
                        if (!@ldap_start_tls($conn)) {
                            throw new Exception("StartTLS handshake failed with Active Directory Domain Controller at {$uri}.");
                        }
                    }

                    $latencyMs = round((microtime(true) - $testStart) * 1000, 1);

                    if ($ldapBindDn !== '' && $ldapBindPass !== '') {
                        $bind = @ldap_bind($conn, $ldapBindDn, $ldapBindPass);
                        if (!$bind) {
                            $ldapErr = ldap_error($conn) ?: 'Invalid service account bind credentials';
                            throw new Exception("Service Account Bind failed: {$ldapErr}");
                        }
                        $success = "Active Directory LDAP Connection Successful! Connected to {$uri} and successfully authenticated with Bind DN '{$ldapBindDn}'.";
                        $ldapTestResult = [
                            'success'    => true,
                            'status'     => 'CONNECTED',
                            'message'    => $success,
                            'details'    => "Successfully connected to {$uri} in {$latencyMs} ms. Service Account Bind authenticated OK with '{$ldapBindDn}'. Validated Base DN: \\"{$ldapBaseDn}\\", Group DN: \\"{$ldapGroupDn}\\".",
                            'tested_at'  => date('Y-m-d H:i:s'),
                            'latency_ms' => $latencyMs,
                            'host'       => $ldapHost,
                            'port'       => $ldapPort,
                            'protocol'   => strtoupper($ldapProtocol),
                            'uri'        => $uri,
                            'auth_type'  => 'Authenticated Bind',
                            'bind_dn'    => $ldapBindDn,
                            'group_dn'   => $ldapGroupDn ?: '(All Users / None)',
                            'base_dn'    => $ldapBaseDn ?: '(Domain Root)',
                        ];
                    } else {
                        // Anonymous or connection ping
                        $bind = @ldap_bind($conn);
                        if (!$bind) {
                            $ldapErr = ldap_error($conn) ?: 'Anonymous bind rejected by Domain Controller';
                            $notice = "Domain Controller reached at {$uri}, but anonymous bind was rejected ({$ldapErr}). Supply a valid Service Account Bind DN and Password for authenticated access.";
                            $ldapTestResult = [
                                'success'    => true,
                                'warning'    => true,
                                'status'     => 'REACHABLE (AUTH REQUIRED)',
                                'message'    => $notice,
                                'details'    => "Network ping to {$uri} succeeded in {$latencyMs} ms, but Active Directory security policies reject anonymous queries. Supply a Service Account Bind DN and Password.",
                                'tested_at'  => date('Y-m-d H:i:s'),
                                'latency_ms' => $latencyMs,
                                'host'       => $ldapHost,
                                'port'       => $ldapPort,
                                'protocol'   => strtoupper($ldapProtocol),
                                'uri'        => $uri,
                                'auth_type'  => 'Anonymous Ping',
                                'bind_dn'    => 'Anonymous (Rejected)',
                                'group_dn'   => $ldapGroupDn ?: '(Not Checked)',
                                'base_dn'    => $ldapBaseDn ?: '(Not Checked)',
                            ];
                        } else {
                            $success = "Active Directory LDAP Connection Successful! Domain Controller is reachable at {$uri}.";
                            $ldapTestResult = [
                                'success'    => true,
                                'status'     => 'CONNECTED',
                                'message'    => $success,
                                'details'    => "Successfully connected to Domain Controller at {$uri} in {$latencyMs} ms. Anonymous directory lookup allowed by Domain Controller.",
                                'tested_at'  => date('Y-m-d H:i:s'),
                                'latency_ms' => $latencyMs,
                                'host'       => $ldapHost,
                                'port'       => $ldapPort,
                                'protocol'   => strtoupper($ldapProtocol),
                                'uri'        => $uri,
                                'auth_type'  => 'Anonymous Bind',
                                'bind_dn'    => 'Anonymous',
                                'group_dn'   => $ldapGroupDn ?: '(All Users / None)',
                                'base_dn'    => $ldapBaseDn ?: '(Domain Root)',
                            ];
                        }
                    }
                    @ldap_unbind($conn);
                } else {
                    // Fall back to socket test if php-ldap is not compiled in CLI/web server
                    $fp = @fsockopen($ldapHost, $ldapPort, $errno, $errstr, 4);
                    if (!$fp) {
                        throw new Exception("Could not reach Active Directory host {$ldapHost} on port {$ldapPort}: {$errstr} (Error {$errno})");
                    }
                    fclose($fp);
                    $latencyMs = round((microtime(true) - $testStart) * 1000, 1);
                    $success = "TCP connection to Active Directory on {$ldapHost}:{$ldapPort} succeeded!";
                    $ldapTestResult = [
                        'success'    => true,
                        'status'     => 'TCP REACHABLE',
                        'message'    => $success,
                        'details'    => "TCP handshake on {$ldapHost}:{$ldapPort} succeeded in {$latencyMs} ms. Note: Install php-ldap on Debian ('apt-get install php-ldap') for full Active Directory query capability.",
                        'tested_at'  => date('Y-m-d H:i:s'),
                        'latency_ms' => $latencyMs,
                        'host'       => $ldapHost,
                        'port'       => $ldapPort,
                        'protocol'   => strtoupper($ldapProtocol),
                        'uri'        => $uri,
                        'auth_type'  => 'TCP Socket Test',
                        'bind_dn'    => $ldapBindDn ?: 'N/A',
                        'group_dn'   => $ldapGroupDn ?: 'N/A',
                        'base_dn'    => $ldapBaseDn ?: 'N/A',
                    ];
                }
            } catch (Exception $e) {
                $latencyMs = round((microtime(true) - $testStart) * 1000, 1);
                $error = "LDAP Connection Test Failed: " . $e->getMessage();
                $ldapTestResult = [
                    'success'    => false,
                    'status'     => 'FAILED',
                    'message'    => $error,
                    'details'    => "Connection attempt to " . ($uri ?? "{$ldapHost}:{$ldapPort}") . " failed after {$latencyMs} ms. Check that the Domain Controller IP/hostname is correct, firewall allows port {$ldapPort}, and bind credentials are valid.",
                    'tested_at'  => date('Y-m-d H:i:s'),
                    'latency_ms' => $latencyMs,
                    'host'       => $ldapHost,
                    'port'       => $ldapPort,
                    'protocol'   => strtoupper($ldapProtocol),
                    'uri'        => $uri ?? "{$ldapHost}:{$ldapPort}",
                    'auth_type'  => ($ldapBindDn !== '' ? 'Authenticated Bind' : 'Anonymous / Ping'),
                    'bind_dn'    => $ldapBindDn ?: 'None',
                    'group_dn'   => $ldapGroupDn ?: 'N/A',
                    'base_dn'    => $ldapBaseDn ?: 'N/A',
                ];
            }
            $_SESSION['wizard']['ldap_test_result'] = $ldapTestResult;
        }
    }

    // Step 3: Prompt & Save LDAP Information + Emergency Non-LDAP Fallback Admin
    if ($action === 'step3_ldap') {
        $ldapHost = trim($_POST['ldap_host'] ?? '');
        $ldapPort = (int)($_POST['ldap_port'] ?? 389);
        $ldapProtocol = $_POST['ldap_protocol'] ?? 'ldap';
        $ldapBaseDn = trim($_POST['ldap_base_dn'] ?? '');
        $ldapGroupDn = trim($_POST['ldap_group_dn'] ?? '');
        $ldapBindDn = trim($_POST['ldap_bind_dn'] ?? '');
        $ldapBindPass = $_POST['ldap_bind_pass'] ?? '';
        $ldapDomain = trim($_POST['ldap_domain'] ?? 'CORP');

        // Fallback Non-LDAP Administrator settings
        $fallbackEnabled = !empty($_POST['fallback_admin_enabled']);
        $fallbackUser = trim($_POST['fallback_admin_username'] ?? 'eopadmin');
        $fallbackPass = $_POST['fallback_admin_password'] ?? '';

        if (empty($ldapHost) || empty($ldapBaseDn) || empty($ldapGroupDn)) {
            $error = "Please fill in all required LDAP settings (Host, Base DN, Group DN).";
        } elseif ($fallbackEnabled) {
            if (empty($fallbackUser)) {
                $error = "Fallback administrator username is required when fallback account is enabled.";
            } elseif (strlen($fallbackPass) < 12) {
                $error = "Fallback administrator password must be at least 12 characters long.";
            } else {
                $hasUpper = preg_match('/[A-Z]/', $fallbackPass) ? 1 : 0;
                $hasLower = preg_match('/[a-z]/', $fallbackPass) ? 1 : 0;
                $hasNumber = preg_match('/[0-9]/', $fallbackPass) ? 1 : 0;
                $hasSymbol = preg_match('/[^A-Za-z0-9]/', $fallbackPass) ? 1 : 0;
                $passedCats = $hasUpper + $hasLower + $hasNumber + $hasSymbol;
                if ($passedCats < 3) {
                    $error = "Fallback administrator password must meet at least three of the following four criteria: uppercase letters, lowercase letters, numbers, and symbols.";
                }
            }
        }

        if (empty($error)) {
            $_SESSION['wizard']['ldap'] = [
                'host'                   => $ldapHost,
                'port'                   => $ldapPort,
                'protocol'               => $ldapProtocol,
                'base_dn'                => $ldapBaseDn,
                'group_dn'               => $ldapGroupDn,
                'bind_dn'                => $ldapBindDn,
                'bind_pass'              => $ldapBindPass,
                'domain'                 => $ldapDomain,
                'fallback_admin_enabled' => $fallbackEnabled,
                'fallback_admin_username'=> $fallbackUser,
                'fallback_admin_password'=> $fallbackPass,
                'tested'                 => true
            ];
            $_SESSION['wizard']['step'] = 4;
            header('Location: setup.php?step=4');
            exit;
        }
    }

    // Step 4: Prompt & Save EOP Connection Information
    if ($action === 'step4_eop') {
        $tenantId = trim($_POST['tenant_id'] ?? '');
        $clientId = trim($_POST['client_id'] ?? '');
        $thumbprint = trim($_POST['thumbprint'] ?? '');
        $orgDomain = trim($_POST['org_domain'] ?? '');
        // A policy may be identified by its display name or by its Exchange GUID.
        // Both are accepted here and normalised to whatever Exchange will take for
        // -Identity; the distinction is only about how the value is stored.
        $policy = eopNormalizePolicyIdentifier((string)($_POST['policy'] ?? 'Default Inbound Anti-Spam Policy'));
        $verifyPolicy = !empty($_POST['verify_policy']);
        $privateKey = '';
        $passphrase = $_POST['passphrase'] ?? '';
        $pkcs12Bundle = '';
        $pkcs12Filename = '';
        $pkcs12Path = '';
        $policyLookup = [
            'status'  => 'skipped',
            'name'    => '',
            'guid'    => eopNormalizeGuid($policy),
            'message' => '',
        ];

        if ($policy === '') {
            $error = "Enter the anti-spam policy by its name in Exchange or by its policy GUID.";
        }

        // Only a full PKCS#12 bundle is accepted. A bare PEM private key would
        // produce a record that can never authenticate the scheduled pull, so the
        // wizard refuses it up front rather than failing at the first sync run.
        if (empty($_FILES['pkcs12_file']['tmp_name']) || !is_uploaded_file($_FILES['pkcs12_file']['tmp_name'])) {
            $error = "A PKCS#12 (.pfx or .p12) certificate bundle is required. PEM private keys are not accepted.";
        } else {
            $upload = $_FILES['pkcs12_file'];
            if ($upload['error'] !== UPLOAD_ERR_OK) {
                $error = "PKCS#12 upload failed (error code {$upload['error']}).";
            } else {
                $rawBundle = file_get_contents($upload['tmp_name']);
                $certs = [];
                if ($rawBundle === false || !openssl_pkcs12_read($rawBundle, $certs, (string)$passphrase)) {
                    $error = "The uploaded PKCS#12 file could not be opened with the passphrase you entered.";
                } elseif (empty($certs['cert']) || empty($certs['pkey'])) {
                    $error = "The uploaded PKCS#12 file does not contain a certificate and private key pair.";
                } else {
                    $pkcs12Bundle = base64_encode($rawBundle);
                    $pkcs12Filename = basename($upload['name']);
                    $pkcs12Path = (string)$upload['tmp_name'];

                    // The private key column is kept populated from the bundle for
                    // compatibility with anything that still reads the PEM column.
                    $privateKey = $certs['pkey'];

                    // Derive the real thumbprint from the uploaded certificate so the
                    // stored value cannot drift from the material being used.
                    // Note: openssl_x509_fingerprint default binary=false returns a hex string.
                    $rawFp = @openssl_x509_fingerprint($certs['cert'], 'sha1', false);
                    $fingerprint = eopNormalizeThumbprint($rawFp ?: '');
                    if ($fingerprint === '' && openssl_x509_export($certs['cert'], $pemCert)) {
                        $cleanPem = preg_replace('/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\\s+/', '', $pemCert);
                        $der = base64_decode($cleanPem);
                        if ($der !== false && $der !== '') {
                            $fingerprint = strtoupper(sha1($der));
                        }
                    }
                    if ($fingerprint !== '') {
                        $thumbprint = $fingerprint;
                        $notice = "Certificate thumbprint was set from the uploaded PKCS#12 file: {$fingerprint}.";
                    } else {
                        $thumbprint = eopNormalizeThumbprint($thumbprint);
                    }
                }
            }
        }

        if (!isset($error) && (empty($tenantId) || empty($clientId) || empty($thumbprint))) {
            $error = "Please provide your Microsoft 365 Tenant ID, Client App ID, and Certificate Thumbprint.";
        }

        // Resolve the policy against Exchange Online. This needs the certificate that
        // was just uploaded, so it can only run once the PKCS#12 checks above passed.
        // A definitive "no such policy" from Exchange is a hard stop; a lookup that
        // could not be carried out at all is only a warning, because a build host
        // with no route to the tenant still has to be configurable.
        if (!isset($error) && $verifyPolicy) {
            $policyLookup = eopLookupPolicyOnExchange($policy, [
                'tenant_id'    => $tenantId,
                'client_id'    => $clientId,
                'thumbprint'   => eopNormalizeThumbprint($thumbprint),
                'org_domain'   => $orgDomain,
                'pfx_path'     => $pkcs12Path,
                'pfx_password' => (string)$passphrase,
            ]);

            if ($policyLookup['status'] === 'not_found') {
                $error = "Exchange Online has no hosted content filter policy matching '{$policy}'. Check the name, or paste the policy GUID instead, and try again.";
            } elseif ($policyLookup['status'] === 'verified') {
                $resolved = $policyLookup['name'] !== '' ? $policyLookup['name'] : $policy;
                $policy = $resolved;
                $notice = "Policy verified on Exchange Online as '{$resolved}'"
                    . ($policyLookup['guid'] !== '' ? " (GUID {$policyLookup['guid']})." : ".");
            } else {
                $warning = "The policy could not be verified against Exchange Online, so it was saved as entered. "
                    . ($policyLookup['message'] !== '' ? $policyLookup['message'] : 'The lookup did not complete.');
            }
        }

        if (!isset($error)) {
            $_SESSION['wizard']['eop'] = [
                'tenant_id' => $tenantId,
                'client_id' => $clientId,
                'thumbprint' => eopNormalizeThumbprint($thumbprint),
                'org_domain' => $orgDomain,
                'policy' => $policy,
                'policy_guid' => $policyLookup['guid'] !== '' ? $policyLookup['guid'] : eopNormalizeGuid($policy),
                'policy_verified' => $policyLookup['status'] === 'verified',
                'private_key' => $privateKey,
                'pkcs12_bundle' => $pkcs12Bundle,
                'pkcs12_filename' => $pkcs12Filename,
                'passphrase' => $passphrase,
                'validated' => true
            ];
            $_SESSION['wizard']['step'] = 5;
            header('Location: setup.php?step=5');
            exit;
        }
    }

    // Step 5: Final Review & Permanent Lock Routine
    if ($action === 'step5_finalize_lock') {
        $db = $_SESSION['wizard']['db'];
        $ldap = $_SESSION['wizard']['ldap'];
        $eop = $_SESSION['wizard']['eop'];
        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

        // Ensure thumbprint is always normalized to 40-character uppercase hexadecimal
        // (recovers cleanly even if existing session stored raw binary from previous step)
        if (!empty($eop['thumbprint'])) {
            $eop['thumbprint'] = eopNormalizeThumbprint($eop['thumbprint']);
            $_SESSION['wizard']['eop']['thumbprint'] = $eop['thumbprint'];
        }

        try {
            // 1. Connect to MariaDB
            $dsn = "mysql:host={$db['host']};port={$db['port']};dbname={$db['name']};charset=utf8mb4";
            $pdo = new PDO($dsn, $db['user'], $db['pass'], [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
            ]);

            // 2. Insert into eop_setup_lock
            $lockStmt = $pdo->prepare("INSERT INTO \`eop_setup_lock\` (\`is_locked\`, \`completed_at\`, \`completed_by\`, \`installer_ip\`, \`app_version\`, \`schema_version\`)
                                         VALUES (1, NOW(), 'INITIAL_SETUP_WIZARD', :ip, '1.0.0', '2026.1')");
            $lockStmt->execute([':ip' => $ip]);

            // 3. Save LDAP configuration to eop_ldap_config
            $ldapStmt = $pdo->prepare("INSERT INTO \`eop_ldap_config\` 
                (\`ldap_host\`, \`ldap_port\`, \`ldap_protocol\`, \`ldap_base_dn\`, \`ldap_group_dn\`, \`ldap_bind_dn\`, \`ldap_bind_password\`, \`ldap_domain\`, \`is_active\`)
                VALUES (:host, :port, :proto, :base, :grp, :bind_dn, :bind_pass, :dom, 1)");
            $ldapStmt->execute([
                ':host' => $ldap['host'],
                ':port' => $ldap['port'],
                ':proto' => $ldap['protocol'],
                ':base' => $ldap['base_dn'],
                ':grp' => $ldap['group_dn'],
                ':bind_dn' => $ldap['bind_dn'],
                ':bind_pass' => $ldap['bind_pass'],
                ':dom' => $ldap['domain']
            ]);

            // 3b. Save emergency fallback administrator account if configured
            if (!empty($ldap['fallback_admin_enabled']) && !empty($ldap['fallback_admin_username']) && !empty($ldap['fallback_admin_password'])) {
                $pwdHash = password_hash($ldap['fallback_admin_password'], PASSWORD_BCRYPT);
                $fallbackStmt = $pdo->prepare("INSERT INTO \`eop_local_admins\` (\`username\`, \`password_hash\`, \`is_active\`, \`created_by\`, \`created_at\`, \`updated_at\`)
                    VALUES (:u, :p, 1, 'INITIAL_SETUP_WIZARD', NOW(), NOW())
                    ON DUPLICATE KEY UPDATE \`password_hash\` = :p2, \`is_active\` = 1, \`updated_at\` = NOW()");
                $fallbackStmt->execute([
                    ':u'  => $ldap['fallback_admin_username'],
                    ':p'  => $pwdHash,
                    ':p2' => $pwdHash
                ]);
            }

            // 3c. Promote the policy chosen in Step 4 to the active default. The
            // eop_policies seed from Step 2 inserts a hard-coded name, so without
            // this the wizard's policy (which may have been supplied as a GUID and
            // resolved to a name) would be ignored by Database::getDefaultPolicyName().
            $finalPolicy = trim((string)($eop['policy'] ?? ''));
            if ($finalPolicy !== '') {
                // The step-2 DDL only runs on a fresh database (CREATE TABLE IF NOT
                // EXISTS), so a database created before policy_guid was introduced
                // will not have the column and the insert below would fail with
                // "Unknown column", aborting the whole finalize. Add it if missing,
                // matching the self-heal used for is_default elsewhere.
                try {
                    $guidCol = $pdo->query("SHOW COLUMNS FROM \`eop_policies\` LIKE 'policy_guid'");
                    if ($guidCol && $guidCol->rowCount() === 0) {
                        $pdo->exec("ALTER TABLE \`eop_policies\` ADD COLUMN \`policy_guid\` CHAR(36) NULL AFTER \`policy_name\`");
                        $guidKey = $pdo->query("SHOW INDEX FROM \`eop_policies\` WHERE Key_name = 'uniq_policy_guid'");
                        if ($guidKey && $guidKey->rowCount() === 0) {
                            $pdo->exec("ALTER TABLE \`eop_policies\` ADD UNIQUE KEY \`uniq_policy_guid\` (\`policy_guid\`)");
                        }
                    }
                } catch (Exception $guidEx) {
                    $error = "Could not add the policy_guid column to eop_policies: " . $guidEx->getMessage();
                }

                if (!isset($error)) {
                    $pdo->exec("UPDATE \`eop_policies\` SET \`is_default\` = 0");
                    $policyStmt = $pdo->prepare("INSERT INTO \`eop_policies\` (\`policy_name\`, \`description\`, \`is_default\`, \`sync_status\`, \`policy_guid\`)
                                                 VALUES (:name, :desc, 1, :status, :guid)
                                                 ON DUPLICATE KEY UPDATE \`is_default\` = 1, \`policy_guid\` = IF(:guid2 != '', :guid3, \`policy_guid\`), \`sync_status\` = :status2, \`updated_at\` = NOW()");
                    $finalPolicyGuid = eopNormalizeGuid($eop['policy_guid'] ?? '');
                    $finalPolicyStatus = !empty($eop['policy_verified']) ? 'synced' : 'pending';
                    $finalPolicyDesc = 'Primary Inbound Anti-Spam Policy (Selected by the setup wizard)';
                    $policyStmt->execute([
                        ':name' => $finalPolicy,
                        ':desc' => $finalPolicyDesc,
                        ':status' => $finalPolicyStatus,
                        ':guid' => $finalPolicyGuid !== '' ? $finalPolicyGuid : null,
                        ':guid2' => $finalPolicyGuid,
                        ':guid3' => $finalPolicyGuid,
                        ':status2' => $finalPolicyStatus,
                    ]);
                }
            }

            // 4. Save EOP Auth config. The private key, the PKCS#12 bundle and the
            // passphrase are each encrypted with AES-256-GCM via the shared envelope
            // in crypto.php, so the wizard and the runtime agree on the format and
            // the key is always AUTH_MASTER_ENCRYPTION_KEY rather than something
            // derived from data stored in the same row.
            $existingEnv = readExistingEnv();
            $masterKey = (defined('AUTH_MASTER_ENCRYPTION_KEY') && AUTH_MASTER_ENCRYPTION_KEY !== '')
                ? AUTH_MASTER_ENCRYPTION_KEY
                : ($existingEnv['AUTH_MASTER_ENCRYPTION_KEY'] ?? (getenv('AUTH_MASTER_ENCRYPTION_KEY') ?: ''));
            if ($masterKey === '') {
                $masterKey = bin2hex(random_bytes(16));
            }
            if (!defined('AUTH_MASTER_ENCRYPTION_KEY')) {
                define('AUTH_MASTER_ENCRYPTION_KEY', $masterKey);
            }
            putenv("AUTH_MASTER_ENCRYPTION_KEY={$masterKey}");
            $_ENV['AUTH_MASTER_ENCRYPTION_KEY'] = $masterKey;
            $_SERVER['AUTH_MASTER_ENCRYPTION_KEY'] = $masterKey;

            $authStmt = $pdo->prepare("INSERT INTO \`eop_auth_config\` 
                (\`tenant_id\`, \`client_id\`, \`certificate_thumbprint\`, \`key_filename\`, \`private_key\`, \`pkcs12_bundle\`, \`encrypted_password\`, \`encryption_iv\`, \`encryption_tag\`, \`organization\`, \`key_type\`, \`is_active\`, \`uploaded_by\`)
                VALUES (:tid, :cid, :thumb, :filename, :pem, :p12, :cipher, NULL, NULL, :org, :ktype, 1, 'INITIAL_SETUP')");
            $authStmt->execute([
                ':tid' => $eop['tenant_id'],
                ':cid' => $eop['client_id'],
                ':thumb' => eopNormalizeThumbprint($eop['thumbprint']),
                ':filename' => $eop['pkcs12_filename'] ?: 'eop-cert-private.key',
                ':pem' => eopEncryptSecret($eop['private_key']),
                ':p12' => !empty($eop['pkcs12_bundle']) ? eopEncryptSecret($eop['pkcs12_bundle']) : null,
                ':cipher' => eopEncryptSecret($eop['passphrase']),
                ':org' => $eop['org_domain'],
                ':ktype' => !empty($eop['pkcs12_bundle']) ? 'PKCS12_PFX' : 'RSA_PEM'
            ]);

            // 5. Write full finalized environment settings to .env and config.php files
            updateEnvConfiguration($db, $ldap, $eop);
            updateConfigFile($db, $ldap, $eop);

            // 6. Create Debian lockfile installed.lock
            $lockData = json_encode([
                'status' => 'LOCKED',
                'completed_at' => date('Y-m-d H:i:s'),
                'installer_ip' => $ip,
                'db_host' => $db['host'],
                'db_name' => $db['name'],
                'env_written' => true,
                'version' => '1.0.0'
            ], JSON_PRETTY_PRINT);
            @file_put_contents($lockFile, $lockData);

            // Clear session wizard data
            unset($_SESSION['wizard']);

            // Redirect to login with success flag
            header('Location: login.php?installed=1');
            exit;

        } catch (Exception $e) {
            $error = "Finalizing Installation Failed: " . $e->getMessage();
        }
    }
}

// System requirement check helpers
$phpVersionOk = version_compare(PHP_VERSION, '8.1.0', '>=');
$pdoOk = extension_loaded('pdo_mysql');
$opensslOk = extension_loaded('openssl');
$ldapExtOk = extension_loaded('ldap');
$curlOk = extension_loaded('curl');
$writableOk = is_writable(__DIR__);
$allReqsOk = $phpVersionOk && $pdoOk && $opensslOk && $ldapExtOk;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Initial Setup Wizard &bull; EOP Anti-Spam Manager</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        brand: {
                            50: '#f0fdf4',
                            500: '#22c55e',
                            600: '#16a34a',
                            700: '#15803d',
                        }
                    }
                }
            }
        }
    </script>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen py-10 px-4 font-sans">
    <div class="max-w-3xl mx-auto">
        
        <!-- Header -->
        <div class="text-center mb-8">
            <div class="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-amber-500/10 border border-amber-500/30 text-amber-400 mb-3 shadow-lg">
                <svg class="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"></path>
                </svg>
            </div>
            <h1 class="text-2xl font-bold text-white tracking-tight">EOP Anti-Spam Initial Setup Wizard</h1>
            <p class="text-slate-400 text-xs mt-1">Standard Page-by-Page Deployment &amp; Schema Initialization</p>
        </div>

        <!-- Wizard Progress Bar (5 Steps) -->
        <div class="bg-slate-800/80 rounded-2xl border border-slate-700/80 p-3 mb-6 shadow-md backdrop-blur-xs">
            <div class="grid grid-cols-5 gap-2 text-center text-xs">
                <a href="<?php echo $currentStep > 1 ? '?step=1' : '#'; ?>" class="py-2 px-1 rounded-xl transition <?php echo $currentStep === 1 ? 'bg-amber-500/20 text-amber-300 font-bold border border-amber-500/40' : ($currentStep > 1 ? 'bg-emerald-500/10 text-emerald-400' : 'text-slate-500'); ?>">
                    <div class="text-[10px] font-mono">STEP 1</div>
                    <div class="truncate">Requirements</div>
                </a>
                <a href="<?php echo $currentStep > 2 ? '?step=2' : '#'; ?>" class="py-2 px-1 rounded-xl transition <?php echo $currentStep === 2 ? 'bg-amber-500/20 text-amber-300 font-bold border border-amber-500/40' : ($currentStep > 2 ? 'bg-emerald-500/10 text-emerald-400' : 'text-slate-500'); ?>">
                    <div class="text-[10px] font-mono">STEP 2</div>
                    <div class="truncate">Database</div>
                </a>
                <a href="<?php echo $currentStep > 3 ? '?step=3' : '#'; ?>" class="py-2 px-1 rounded-xl transition <?php echo $currentStep === 3 ? 'bg-amber-500/20 text-amber-300 font-bold border border-amber-500/40' : ($currentStep > 3 ? 'bg-emerald-500/10 text-emerald-400' : 'text-slate-500'); ?>">
                    <div class="text-[10px] font-mono">STEP 3</div>
                    <div class="truncate">AD/LDAP</div>
                </a>
                <a href="<?php echo $currentStep > 4 ? '?step=4' : '#'; ?>" class="py-2 px-1 rounded-xl transition <?php echo $currentStep === 4 ? 'bg-amber-500/20 text-amber-300 font-bold border border-amber-500/40' : ($currentStep > 4 ? 'bg-emerald-500/10 text-emerald-400' : 'text-slate-500'); ?>">
                    <div class="text-[10px] font-mono">STEP 4</div>
                    <div class="truncate">Exchange EOP</div>
                </a>
                <div class="py-2 px-1 rounded-xl transition <?php echo $currentStep === 5 ? 'bg-amber-500/20 text-amber-300 font-bold border border-amber-500/40' : 'text-slate-500'; ?>">
                    <div class="text-[10px] font-mono">STEP 5</div>
                    <div class="truncate">Review &amp; Lock</div>
                </div>
            </div>
        </div>

        <!-- Alert Notification -->
        <?php if ($error): ?>
            <div class="mb-6 p-4 rounded-xl bg-rose-950/60 border border-rose-800 text-rose-200 text-xs flex items-center gap-3">
                <svg class="w-5 h-5 text-rose-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                <span><?php echo htmlspecialchars($error); ?></span>
            </div>
        <?php endif; ?>

        <?php if ($notice): ?>
            <div class="mb-6 p-4 rounded-xl bg-emerald-950/60 border border-emerald-800 text-emerald-200 text-xs flex items-center gap-3">
                <svg class="w-5 h-5 text-emerald-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                <span><?php echo htmlspecialchars($notice); ?></span>
            </div>
        <?php endif; ?>

        <?php if ($warning): ?>
            <div class="mb-6 p-4 rounded-xl bg-amber-950/60 border border-amber-800 text-amber-200 text-xs flex items-start gap-3">
                <svg class="w-5 h-5 text-amber-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                <span><?php echo htmlspecialchars($warning); ?></span>
            </div>
        <?php endif; ?>

        <!-- STEP 1: System Requirements & Prerequisites -->
        <?php if ($currentStep === 1): ?>
            <div class="bg-slate-800/90 rounded-2xl border border-slate-700/80 p-6 sm:p-8 shadow-xl">
                <div class="flex items-center gap-3 pb-5 border-b border-slate-700 mb-6">
                    <div class="w-10 h-10 rounded-xl bg-blue-500/10 text-blue-400 flex items-center justify-center font-bold">1</div>
                    <div>
                        <h2 class="text-lg font-bold text-white">System Requirements &amp; Prerequisites</h2>
                        <p class="text-slate-400 text-xs">Verify your Debian web server environment meets all dependencies.</p>
                    </div>
                </div>

                <div class="space-y-3 mb-8">
                    <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-700/60 flex items-center justify-between text-xs font-mono">
                        <div><span class="text-white font-sans font-semibold">PHP Version:</span> <?php echo PHP_VERSION; ?> (Required &ge; 8.1)</div>
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold <?php echo $phpVersionOk ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'; ?>">
                            <?php echo $phpVersionOk ? 'PASSED' : 'UPGRADE REQUIRED'; ?>
                        </span>
                    </div>

                    <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-700/60 flex items-center justify-between text-xs font-mono">
                        <div><span class="text-white font-sans font-semibold">PDO MySQL / MariaDB (pdo_mysql):</span> Required for SQL storage</div>
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold <?php echo $pdoOk ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'; ?>">
                            <?php echo $pdoOk ? 'INSTALLED' : 'MISSING (apt install php-mysql)'; ?>
                        </span>
                    </div>

                    <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-700/60 flex items-center justify-between text-xs font-mono">
                        <div><span class="text-white font-sans font-semibold">OpenSSL Extension (openssl):</span> AES-256 certificate encryption</div>
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold <?php echo $opensslOk ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'; ?>">
                            <?php echo $opensslOk ? 'INSTALLED' : 'MISSING (apt install php-openssl)'; ?>
                        </span>
                    </div>

                    <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-700/60 flex items-center justify-between text-xs font-mono">
                        <div><span class="text-white font-sans font-semibold">LDAP Extension (php-ldap):</span> Active Directory bind authentication</div>
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold <?php echo $ldapExtOk ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'; ?>">
                            <?php echo $ldapExtOk ? 'INSTALLED' : 'RECOMMENDED (apt install php-ldap)'; ?>
                        </span>
                    </div>

                    <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-700/60 flex items-center justify-between text-xs font-mono">
                        <div><span class="text-white font-sans font-semibold">Directory Write Permission:</span> Create installed.lock &amp; config</div>
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold <?php echo $writableOk ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'; ?>">
                            <?php echo $writableOk ? 'WRITABLE' : 'READ-ONLY (chown -R www-data)'; ?>
                        </span>
                    </div>
                </div>

                <form method="POST">
                    <input type="hidden" name="action" value="step1_start">
                    <div class="flex justify-end">
                        <button type="submit" class="px-6 py-2.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg shadow-sm transition">
                            Continue to Database Setup &rarr;
                        </button>
                    </div>
                </form>
            </div>
        <?php endif; ?>

        <!-- STEP 2: Database Connection & Schema Population -->
        <?php if ($currentStep === 2): ?>
            <div class="bg-slate-800/90 rounded-2xl border border-slate-700/80 p-6 sm:p-8 shadow-xl">
                <div class="flex items-center gap-3 pb-5 border-b border-slate-700 mb-6">
                    <div class="w-10 h-10 rounded-xl bg-purple-500/10 text-purple-400 flex items-center justify-center font-bold">2</div>
                    <div>
                        <h2 class="text-lg font-bold text-white">Database Connection &amp; Schema Population</h2>
                        <p class="text-slate-400 text-xs">Enter your MariaDB connection credentials. Submitting will automatically populate all 11 database tables.</p>
                    </div>
                </div>

                <form method="POST" class="space-y-4">
                    <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                        <div class="sm:col-span-2">
                            <label class="block text-xs font-medium text-slate-300 mb-1">MariaDB Server Host</label>
                            <input type="text" name="db_host" value="<?php echo htmlspecialchars($_SESSION['wizard']['db']['host'] ?? '127.0.0.1'); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                        <div>
                            <label class="block text-xs font-medium text-slate-300 mb-1">Port</label>
                            <input type="number" name="db_port" value="<?php echo htmlspecialchars((string)($_SESSION['wizard']['db']['port'] ?? 3306)); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                    </div>

                    <div>
                        <label class="block text-xs font-medium text-slate-300 mb-1">Database Name</label>
                        <input type="text" name="db_name" value="<?php echo htmlspecialchars($_SESSION['wizard']['db']['name'] ?? 'eop_antispam_db'); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        <p class="text-[11px] text-slate-400 mt-1">If this database does not exist, the installer will attempt to create it automatically.</p>
                    </div>

                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div>
                            <label class="block text-xs font-medium text-slate-300 mb-1">Database Username</label>
                            <input type="text" name="db_user" value="<?php echo htmlspecialchars($_SESSION['wizard']['db']['user'] ?? 'eop_user'); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                        <div>
                            <label class="block text-xs font-medium text-slate-300 mb-1">Database Password</label>
                            <input type="password" name="db_pass" value="<?php echo htmlspecialchars($_SESSION['wizard']['db']['pass'] ?? ''); ?>" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                    </div>

                    <div class="p-3.5 rounded-xl bg-purple-950/30 border border-purple-900/60 text-xs text-purple-200">
                        <strong>Tables that will be populated automatically:</strong>
                        <div class="grid grid-cols-2 sm:grid-cols-3 gap-1 font-mono text-[11px] text-purple-300 mt-2">
                            <div>&bull; eop_allowed_senders</div>
                            <div>&bull; eop_blocked_senders</div>
                            <div>&bull; eop_allowed_domains</div>
                            <div>&bull; eop_blocked_domains</div>
                            <div>&bull; eop_audit_log</div>
                            <div>&bull; eop_policies</div>
                            <div>&bull; eop_ldap_config</div>
                            <div>&bull; eop_auth_config</div>
                            <div>&bull; eop_setup_lock</div>
                        <div>&bull; eop_local_admins</div>
                        <div>&bull; eop_sync_confirmations</div>
                        </div>
                    </div>

                    <?php if ($dbTestResult): ?>
                        <div class="p-4 rounded-xl border <?php echo $dbTestResult['success'] ? 'bg-emerald-950/40 border-emerald-700/60' : 'bg-rose-950/40 border-rose-700/60'; ?> space-y-2 mt-4">
                            <div class="flex items-center justify-between">
                                <span class="text-xs font-bold <?php echo $dbTestResult['success'] ? 'text-emerald-300' : 'text-rose-300'; ?> flex items-center gap-1.5">
                                    <span><?php echo $dbTestResult['success'] ? '✓ MariaDB Connection Test Passed' : '✕ MariaDB Connection Test Failed'; ?></span>
                                </span>
                                <div class="flex items-center gap-2 text-[11px] font-mono">
                                    <span class="px-2 py-0.5 rounded <?php echo $dbTestResult['success'] ? 'bg-emerald-900/60 text-emerald-300 border border-emerald-700/60' : 'bg-rose-900/60 text-rose-300 border border-rose-700/60'; ?> font-bold">
                                        <?php echo htmlspecialchars($dbTestResult['status']); ?>
                                    </span>
                                    <?php if (!empty($dbTestResult['latency_ms'])): ?>
                                        <span class="px-2 py-0.5 rounded bg-slate-900/90 text-slate-300 border border-slate-700">
                                            ⚡ <?php echo $dbTestResult['latency_ms']; ?> ms
                                        </span>
                                    <?php endif; ?>
                                    <span class="text-slate-400 font-sans text-[10px]">
                                        Tested at <?php echo htmlspecialchars($dbTestResult['tested_at'] ?? date('H:i:s')); ?>
                                    </span>
                                </div>
                            </div>

                            <div class="text-xs <?php echo $dbTestResult['success'] ? 'text-emerald-100' : 'text-rose-100'; ?>">
                                <?php echo htmlspecialchars($dbTestResult['message']); ?>
                            </div>

                            <?php if (!empty($dbTestResult['details'])): ?>
                                <div class="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800/80 text-[11px] font-mono text-slate-300 leading-relaxed">
                                    <?php echo htmlspecialchars($dbTestResult['details']); ?>
                                </div>
                            <?php endif; ?>

                            <!-- Diagnostic Stats Grid -->
                            <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[10px] font-mono">
                                <div class="p-2 rounded bg-slate-900/80 border border-slate-800">
                                    <span class="text-slate-500 block">MARIADB HOST</span>
                                    <span class="text-slate-200 font-semibold truncate block" title="<?php echo htmlspecialchars($dbTestResult['host'] . ':' . $dbTestResult['port']); ?>">
                                        <?php echo htmlspecialchars($dbTestResult['host'] . ':' . $dbTestResult['port']); ?>
                                    </span>
                                </div>
                                <div class="p-2 rounded bg-slate-900/80 border border-slate-800">
                                    <span class="text-slate-500 block">SERVER VERSION</span>
                                    <span class="text-slate-200 font-semibold truncate block" title="<?php echo htmlspecialchars($dbTestResult['server_version'] ?? 'N/A'); ?>">
                                        <?php echo htmlspecialchars($dbTestResult['server_version'] ?? 'N/A'); ?>
                                    </span>
                                </div>
                                <div class="p-2 rounded bg-slate-900/80 border border-slate-800">
                                    <span class="text-slate-500 block">DATABASE STATUS</span>
                                    <span class="<?php echo !empty($dbTestResult['db_exists']) ? 'text-emerald-400' : 'text-amber-400'; ?> font-semibold block">
                                        <?php echo !empty($dbTestResult['db_exists']) ? 'EXISTS' : 'WILL CREATE'; ?>
                                    </span>
                                </div>
                                <div class="p-2 rounded bg-slate-900/80 border border-slate-800">
                                    <span class="text-slate-500 block">LATENCY</span>
                                    <span class="<?php echo ($dbTestResult['latency_ms'] ?? 999) < 100 ? 'text-emerald-400' : 'text-amber-400'; ?> font-semibold block">
                                        <?php echo !empty($dbTestResult['latency_ms']) ? $dbTestResult['latency_ms'] . ' ms' : 'N/A'; ?>
                                    </span>
                                </div>
                            </div>
                        </div>
                    <?php endif; ?>

                    <div class="flex items-center justify-between pt-4 border-t border-slate-700">
                        <a href="?step=1" class="text-xs text-slate-400 hover:text-white">&larr; Back to Step 1</a>
                        <div class="flex items-center gap-2.5">
                            <button type="submit" name="action" value="test_db" class="px-4 py-2.5 bg-slate-700 hover:bg-slate-600 text-white text-xs font-semibold rounded-lg shadow-sm transition cursor-pointer flex items-center gap-1.5">
                                <svg class="w-3.5 h-3.5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
                                <span>Test Connection</span>
                            </button>
                            <button type="submit" name="action" value="step2_db" class="px-6 py-2.5 bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold rounded-lg shadow-sm transition cursor-pointer flex items-center gap-1.5">
                                <span>Populate Schema &amp; Continue &rarr;</span>
                            </button>
                        </div>
                    </div>
                </form>
            </div>
        <?php endif; ?>

        <!-- STEP 3: Active Directory / OpenLDAP Configuration -->
        <?php if ($currentStep === 3): ?>
            <div class="bg-slate-800/90 rounded-2xl border border-slate-700/80 p-6 sm:p-8 shadow-xl">
                <div class="flex items-center gap-3 pb-5 border-b border-slate-700 mb-6">
                    <div class="w-10 h-10 rounded-xl bg-blue-500/10 text-blue-400 flex items-center justify-center font-bold">3</div>
                    <div>
                        <h2 class="text-lg font-bold text-white">Active Directory / OpenLDAP Authentication</h2>
                        <p class="text-slate-400 text-xs">Configure your Domain Controller LDAP parameters to restrict web app login to authorized security groups.</p>
                    </div>
                </div>

                <form method="POST" class="space-y-4">
                    <input type="hidden" name="action" value="step3_ldap">

                    <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                        <div class="sm:col-span-2">
                            <label class="block text-xs font-medium text-slate-300 mb-1">Domain Controller Host / IP</label>
                            <input type="text" name="ldap_host" value="<?php echo htmlspecialchars($_SESSION['wizard']['ldap']['host'] ?? '192.168.10.10'); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                        <div>
                            <label class="block text-xs font-medium text-slate-300 mb-1">Port</label>
                            <input type="number" name="ldap_port" value="<?php echo htmlspecialchars((string)($_SESSION['wizard']['ldap']['port'] ?? 389)); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                    </div>

                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div>
                            <label class="block text-xs font-medium text-slate-300 mb-1">Protocol</label>
                            <select name="ldap_protocol" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                                <option value="ldap" <?php echo ($_SESSION['wizard']['ldap']['protocol'] ?? '') === 'ldap' ? 'selected' : ''; ?>>LDAP (Plain Port 389)</option>
                                <option value="ldaps" <?php echo ($_SESSION['wizard']['ldap']['protocol'] ?? '') === 'ldaps' ? 'selected' : ''; ?>>LDAPS (SSL Port 636)</option>
                                <option value="starttls" <?php echo ($_SESSION['wizard']['ldap']['protocol'] ?? '') === 'starttls' ? 'selected' : ''; ?>>StartTLS (Port 389)</option>
                            </select>
                        </div>
                        <div>
                            <label class="block text-xs font-medium text-slate-300 mb-1">NetBIOS Domain</label>
                            <input type="text" name="ldap_domain" value="<?php echo htmlspecialchars($_SESSION['wizard']['ldap']['domain'] ?? 'CORP'); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                    </div>

                    <div>
                        <label class="block text-xs font-medium text-slate-300 mb-1">Base Distinguished Name (Base DN)</label>
                        <input type="text" name="ldap_base_dn" value="<?php echo htmlspecialchars($_SESSION['wizard']['ldap']['base_dn'] ?? 'DC=corp,DC=example,DC=com'); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                    </div>

                    <div>
                        <label class="block text-xs font-medium text-slate-300 mb-1">Authorized Group DN (Members Allowed to Manage EOP)</label>
                        <input type="text" name="ldap_group_dn" value="<?php echo htmlspecialchars($_SESSION['wizard']['ldap']['group_dn'] ?? 'CN=EOP-SpamAdmins,OU=Security Groups,DC=corp,DC=example,DC=com'); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                    </div>

                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div>
                            <label class="block text-xs font-medium text-slate-300 mb-1">Service Account Bind DN (Optional)</label>
                            <input type="text" name="ldap_bind_dn" value="<?php echo htmlspecialchars($_SESSION['wizard']['ldap']['bind_dn'] ?? 'CN=svc-eop-web,OU=Service Accounts,DC=corp,DC=example,DC=com'); ?>" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                        <div>
                            <label class="block text-xs font-medium text-slate-300 mb-1">Service Account Password</label>
                            <input type="password" name="ldap_bind_pass" value="<?php echo htmlspecialchars($_SESSION['wizard']['ldap']['bind_pass'] ?? ''); ?>" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                    </div>

                    <!-- Dedicated Test LDAP Connection Action Box -->
                    <div class="flex items-center justify-between p-4 bg-slate-900/90 rounded-xl border border-blue-500/40 mt-2">
                        <div>
                            <div class="text-xs font-bold text-white flex items-center gap-1.5">
                                <svg class="w-4 h-4 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                                <span>Active Directory / OpenLDAP Connection Test</span>
                            </div>
                            <div class="text-[11px] text-slate-400 mt-0.5">Verify domain controller reachability and credentials before advancing to EOP.</div>
                        </div>
                        <button type="submit" name="action" value="test_ldap" class="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center gap-1.5 transition cursor-pointer">
                            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
                            <span>Test LDAP Connection</span>
                        </button>
                    </div>

                    <!-- Status Display After Test LDAP Connection Run -->
                    <?php if ($ldapTestResult): ?>
                        <div class="mt-3 p-4 rounded-xl border transition-all shadow-sm <?php 
                            echo $ldapTestResult['success'] 
                                ? (!empty($ldapTestResult['warning']) ? 'bg-amber-950/70 border-amber-600/70 text-amber-200' : 'bg-emerald-950/80 border-emerald-500/70 text-emerald-200') 
                                : 'bg-rose-950/80 border-rose-600/70 text-rose-200'; 
                        ?>">
                            <div class="flex items-center justify-between flex-wrap gap-2 pb-2.5 mb-2.5 border-b <?php 
                                echo $ldapTestResult['success'] 
                                    ? (!empty($ldapTestResult['warning']) ? 'border-amber-800/80' : 'border-emerald-800/80') 
                                    : 'border-rose-800/80'; 
                            ?>">
                                <div class="flex items-center gap-2">
                                    <?php if ($ldapTestResult['success'] && empty($ldapTestResult['warning'])): ?>
                                        <span class="w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center font-bold text-xs">✓</span>
                                        <span class="font-bold text-xs text-white">Active Directory / OpenLDAP Connection Status: Verified</span>
                                    <?php elseif ($ldapTestResult['success'] && !empty($ldapTestResult['warning'])): ?>
                                        <span class="w-5 h-5 rounded-full bg-amber-500/20 text-amber-400 flex items-center justify-center font-bold text-xs">!</span>
                                        <span class="font-bold text-xs text-white">Active Directory Status: Reachable (Auth Warning)</span>
                                    <?php else: ?>
                                        <span class="w-5 h-5 rounded-full bg-rose-500/20 text-rose-400 flex items-center justify-center font-bold text-xs">&times;</span>
                                        <span class="font-bold text-xs text-white">Active Directory Status: Connection Failed</span>
                                    <?php endif; ?>
                                </div>
                                <div class="flex items-center gap-2 text-[11px] font-mono">
                                    <span class="px-2 py-0.5 rounded <?php echo $ldapTestResult['success'] ? (!empty($ldapTestResult['warning']) ? 'bg-amber-900/60 text-amber-300 border border-amber-700/60' : 'bg-emerald-900/60 text-emerald-300 border border-emerald-700/60') : 'bg-rose-900/60 text-rose-300 border border-rose-700/60'; ?> font-bold">
                                        <?php echo htmlspecialchars($ldapTestResult['status']); ?>
                                    </span>
                                    <?php if (!empty($ldapTestResult['latency_ms'])): ?>
                                        <span class="px-2 py-0.5 rounded bg-slate-900/90 text-slate-300 border border-slate-700">
                                            ⚡ <?php echo $ldapTestResult['latency_ms']; ?> ms
                                        </span>
                                    <?php endif; ?>
                                    <span class="text-slate-400 font-sans text-[10px]">
                                        Tested at <?php echo htmlspecialchars($ldapTestResult['tested_at'] ?? date('H:i:s')); ?>
                                    </span>
                                </div>
                            </div>

                            <div class="text-xs mb-3 <?php echo $ldapTestResult['success'] ? (!empty($ldapTestResult['warning']) ? 'text-amber-100' : 'text-emerald-100') : 'text-rose-100'; ?>">
                                <?php echo htmlspecialchars($ldapTestResult['message']); ?>
                            </div>

                            <?php if (!empty($ldapTestResult['details'])): ?>
                                <div class="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800/80 text-[11px] font-mono text-slate-300 mb-3 leading-relaxed">
                                    <?php echo htmlspecialchars($ldapTestResult['details']); ?>
                                </div>
                            <?php endif; ?>

                            <!-- Diagnostic Stats Grid -->
                            <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[10px] font-mono">
                                <div class="p-2 rounded bg-slate-900/80 border border-slate-800">
                                    <span class="text-slate-500 block">ENDPOINT URI</span>
                                    <span class="text-slate-200 font-semibold truncate block" title="<?php echo htmlspecialchars($ldapTestResult['uri'] ?? ''); ?>">
                                        <?php echo htmlspecialchars($ldapTestResult['uri'] ?? 'N/A'); ?>
                                    </span>
                                </div>
                                <div class="p-2 rounded bg-slate-900/80 border border-slate-800">
                                    <span class="text-slate-500 block">PROTOCOL / SECURITY</span>
                                    <span class="text-slate-200 font-semibold block">
                                        <?php echo htmlspecialchars($ldapTestResult['protocol'] ?? 'LDAP'); ?>
                                    </span>
                                </div>
                                <div class="p-2 rounded bg-slate-900/80 border border-slate-800">
                                    <span class="text-slate-500 block">AUTH METHOD</span>
                                    <span class="text-slate-200 font-semibold block">
                                        <?php echo htmlspecialchars($ldapTestResult['auth_type'] ?? 'N/A'); ?>
                                    </span>
                                </div>
                                <div class="p-2 rounded bg-slate-900/80 border border-slate-800">
                                    <span class="text-slate-500 block">LATENCY</span>
                                    <span class="<?php echo ($ldapTestResult['latency_ms'] ?? 999) < 100 ? 'text-emerald-400' : 'text-amber-400'; ?> font-semibold block">
                                        <?php echo !empty($ldapTestResult['latency_ms']) ? $ldapTestResult['latency_ms'] . ' ms' : 'N/A'; ?>
                                    </span>
                                </div>
                            </div>
                        </div>
                    <?php endif; ?>

                    <!-- Emergency Non-LDAP Fallback Administrator Account Setup -->
                    <div class="p-4 bg-slate-900/80 rounded-xl border border-amber-500/40 space-y-3 mt-4">
                        <div class="flex items-center justify-between">
                            <div>
                                <span class="text-xs font-bold text-amber-400 flex items-center gap-1.5">
                                    <span>🛡️ Emergency Non-LDAP Fallback Administrator</span>
                                </span>
                                <p class="text-[11px] text-slate-400">Allows administrator login directly through MariaDB if the Active Directory Domain Controller connection fails or is offline.</p>
                            </div>
                            <label class="flex items-center space-x-2 text-xs text-slate-300 font-semibold cursor-pointer">
                                <input type="checkbox" name="fallback_admin_enabled" id="fallbackAdminEnabledCheckbox" value="1" <?php echo (!isset($_SESSION['wizard']['ldap']['fallback_admin_enabled']) || !empty($_SESSION['wizard']['ldap']['fallback_admin_enabled'])) ? 'checked' : ''; ?> class="w-4 h-4 text-amber-500 rounded border-slate-700">
                                <span>Enable Fallback Account</span>
                            </label>
                        </div>

                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-slate-800">
                            <div>
                                <label class="block text-xs font-medium text-slate-300 mb-1">Fallback Username</label>
                                <input type="text" name="fallback_admin_username" value="<?php echo htmlspecialchars($_SESSION['wizard']['ldap']['fallback_admin_username'] ?? 'eopadmin'); ?>" placeholder="eopadmin" class="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-amber-500">
                            </div>
                            <div>
                                <div class="flex items-center justify-between mb-1">
                                    <label class="block text-xs font-medium text-slate-300">Fallback Password</label>
                                    <button type="button" onclick="toggleFallbackPasswordVisibility()" class="text-[10px] text-slate-400 hover:text-slate-200 cursor-pointer">
                                        <span id="toggleFallbackPassText">Show</span>
                                    </button>
                                </div>
                                <input type="password" id="fallbackAdminPassInput" name="fallback_admin_password" value="<?php echo htmlspecialchars($_SESSION['wizard']['ldap']['fallback_admin_password'] ?? 'Emergency#Admin2026!'); ?>" placeholder="12+ chars, 3 of 4: upper, lower, numbers, symbols" class="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-amber-500 transition-colors">
                            </div>
                        </div>

                        <!-- Live Interactive Password Policy Requirement Box -->
                        <div class="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-[11px]" id="passwordPolicyBox">
                            <div class="flex items-center justify-between font-semibold">
                                <div class="text-amber-300 flex items-center gap-1.5">
                                    <svg class="w-3.5 h-3.5 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
                                    <span>Password Policy Requirement:</span>
                                </div>
                                <span id="pwdPolicyBadge" class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950/80 text-rose-300 border border-rose-800 transition-colors">
                                    CRITERIA UNMET
                                </span>
                            </div>

                            <!-- Length criteria: 12+ characters -->
                            <div id="pwdLenItem" class="flex items-center justify-between p-2 rounded-lg border border-slate-800 bg-slate-900 text-slate-400 transition-colors">
                                <div class="flex items-center gap-2">
                                    <span id="pwdLenIcon" class="w-4 h-4 rounded-full flex items-center justify-center text-xs font-bold text-slate-500">&times;</span>
                                    <span class="font-semibold">Minimum Length: 12+ Characters</span>
                                </div>
                                <span id="pwdLenCount" class="font-mono font-bold">0 characters</span>
                            </div>

                            <div class="text-slate-400 leading-tight">
                                Must be at least <strong>12+ characters</strong> with at least <strong>three</strong> of the following:
                            </div>

                            <!-- 4 Categories Checklist -->
                            <div class="grid grid-cols-2 sm:grid-cols-4 gap-1.5 text-[10px] font-mono">
                                <div id="pwdUpperItem" class="flex items-center gap-1.5 bg-slate-900 p-2 rounded border border-slate-800 text-slate-400 transition-colors">
                                    <span id="pwdUpperIcon" class="w-3.5 h-3.5 flex items-center justify-center font-bold text-slate-500">&times;</span>
                                    <span>Uppercase (A-Z)</span>
                                </div>
                                <div id="pwdLowerItem" class="flex items-center gap-1.5 bg-slate-900 p-2 rounded border border-slate-800 text-slate-400 transition-colors">
                                    <span id="pwdLowerIcon" class="w-3.5 h-3.5 flex items-center justify-center font-bold text-slate-500">&times;</span>
                                    <span>Lowercase (a-z)</span>
                                </div>
                                <div id="pwdNumberItem" class="flex items-center gap-1.5 bg-slate-900 p-2 rounded border border-slate-800 text-slate-400 transition-colors">
                                    <span id="pwdNumberIcon" class="w-3.5 h-3.5 flex items-center justify-center font-bold text-slate-500">&times;</span>
                                    <span>Numbers (0-9)</span>
                                </div>
                                <div id="pwdSymbolItem" class="flex items-center gap-1.5 bg-slate-900 p-2 rounded border border-slate-800 text-slate-400 transition-colors">
                                    <span id="pwdSymbolIcon" class="w-3.5 h-3.5 flex items-center justify-center font-bold text-slate-500">&times;</span>
                                    <span>Symbols (!@#$...)</span>
                                </div>
                            </div>

                            <div class="flex items-center justify-between text-[10px] pt-1 text-slate-400">
                                <span>Complexity Score:</span>
                                <span id="pwdScoreText" class="font-semibold text-slate-300">0 of 4 categories satisfied</span>
                            </div>
                        </div>
                    </div>

                    <div class="flex items-center justify-between pt-4 border-t border-slate-700">
                        <a href="?step=2" class="text-xs text-slate-400 hover:text-white">&larr; Back to Database</a>
                        <div class="flex items-center gap-2.5">
                            <button type="submit" name="action" value="test_ldap" class="px-4 py-2.5 bg-slate-700 hover:bg-slate-600 text-white text-xs font-semibold rounded-lg shadow-sm transition cursor-pointer flex items-center gap-1.5">
                                <svg class="w-3.5 h-3.5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
                                <span>Test LDAP Connection</span>
                            </button>
                            <button type="submit" name="action" value="step3_ldap" class="px-6 py-2.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg shadow-sm transition cursor-pointer">
                                Save &amp; Continue to Exchange EOP &rarr;
                            </button>
                        </div>
                    </div>
                </form>
            </div>
        <?php endif; ?>

        <!-- STEP 4: Exchange Online Protection (EOP) Setup -->
        <?php if ($currentStep === 4): ?>
            <div class="bg-slate-800/90 rounded-2xl border border-slate-700/80 p-6 sm:p-8 shadow-xl">
                <div class="flex items-center gap-3 pb-5 border-b border-slate-700 mb-6">
                    <div class="w-10 h-10 rounded-xl bg-amber-500/10 text-amber-400 flex items-center justify-center font-bold">4</div>
                    <div>
                        <h2 class="text-lg font-bold text-white">Exchange Online Protection (EOP) Connection</h2>
                        <p class="text-slate-400 text-xs">Enter your Microsoft 365 Entra App Registration, Certificate Thumbprint, and target anti-spam policy (by name or GUID) for PowerShell sync.</p>
                    </div>
                </div>

                <form method="POST" enctype="multipart/form-data" class="space-y-4">
                    <input type="hidden" name="action" value="step4_eop">

                    <div>
                        <label class="block text-xs font-medium text-slate-300 mb-1">Microsoft 365 Tenant ID (GUID)</label>
                        <input type="text" name="tenant_id" value="<?php echo htmlspecialchars($_SESSION['wizard']['eop']['tenant_id'] ?? '72f988bf-86f1-41af-91ab-2d7cd011db47'); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                    </div>

                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div>
                            <label class="block text-xs font-medium text-slate-300 mb-1">App Registration Client ID</label>
                            <input type="text" name="client_id" value="<?php echo htmlspecialchars($_SESSION['wizard']['eop']['client_id'] ?? '3a2b4c5d-6e7f-8a9b-0c1d-2e3f4a5b6c7d'); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                        <div>
                            <label class="block text-xs font-medium text-slate-300 mb-1">Certificate SHA-1 Thumbprint</label>
                            <input type="text" name="thumbprint" value="<?php echo htmlspecialchars($_SESSION['wizard']['eop']['thumbprint'] ?? '9A2F8B3C1D4E5F6A7B8C9D0E1F2A3B4C5D6E7F80'); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                    </div>

                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div>
                            <label class="block text-xs font-medium text-slate-300 mb-1">Organization Domain</label>
                            <input type="text" name="org_domain" value="<?php echo htmlspecialchars($_SESSION['wizard']['eop']['org_domain'] ?? 'corp.example.com'); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                        <div class="sm:col-span-2">
                            <div class="flex items-center justify-between mb-1 gap-2">
                                <label class="block text-xs font-medium text-slate-300">Default Anti-Spam Policy (Name or GUID)</label>
                                <span id="policyKindBadge" class="shrink-0 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-slate-700 text-slate-300 border border-slate-600">Name</span>
                            </div>
                            <input type="text" id="policyInput" name="policy" value="<?php echo htmlspecialchars($_SESSION['wizard']['eop']['policy'] ?? 'Default Inbound Anti-Spam Policy'); ?>" required autocomplete="off" spellcheck="false" placeholder="Default Inbound Anti-Spam Policy or 4c7c8f21-9a3e-4f2b-8d5e-1a2b3c4d5e6f" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                            <p class="text-[11px] text-slate-400 mt-1">
                                Accepts either the policy display name or its Exchange GUID
                                (<code>Get-HostedContentFilterPolicy</code>). A GUID is canonicalised to lowercase
                                <code>8-4-4-4-12</code> and, when Exchange verification below succeeds, resolved back to the
                                policy name &mdash; which is what the rest of the application keys its lists on. The GUID is
                                stored alongside the name in <code>EOP_POLICY_GUID</code>.
                            </p>
                            <label class="mt-2.5 flex items-start gap-2 text-[11px] text-slate-300 cursor-pointer">
                                <input type="checkbox" name="verify_policy" value="1" <?php echo !isset($_POST['verify_policy_present']) || isset($_POST['verify_policy']) ? 'checked' : ''; ?> class="mt-0.5 w-3.5 h-3.5 rounded bg-slate-900 border-slate-600 text-amber-500 focus:ring-amber-500 focus:ring-offset-0">
                                <span>
                                    Verify this policy against Exchange Online before continuing.
                                    <span class="block text-slate-500">
                                        Connects with the certificate uploaded below and calls
                                        <code>Get-HostedContentFilterPolicy</code>. A policy Exchange does not recognise is
                                        rejected; if the lookup cannot run at all (no <code>pwsh</code>, no route to the
                                        tenant) the value is saved as entered and a warning is shown.
                                    </span>
                                </span>
                            </label>
                            <input type="hidden" name="verify_policy_present" value="1">
                        </div>
                    </div>

                    <div>
                        <label class="block text-xs font-medium text-slate-300 mb-1">PKCS#12 Certificate Bundle (.pfx / .p12) <span class="text-amber-400">*</span></label>
                        <input type="file" name="pkcs12_file" accept=".pfx,.p12" required
                               class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-300 file:mr-3 file:rounded-md file:border-0 file:bg-slate-700 file:px-3 file:py-1 file:text-xs file:text-white focus:outline-hidden focus:border-blue-500">
                        <p class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">
                            The only accepted certificate format. The bundle must contain the certificate and its private key; bare PEM
                            private keys are rejected. The certificate and key are encrypted with AES-256-GCM into
                            <code>eop_auth_config.pkcs12_bundle</code> and imported into the certificate store on every pull, and the
                            thumbprint above is derived from this file.
                        </p>
                    </div>

                    <div>
                        <label class="block text-xs font-medium text-slate-300 mb-1">PKCS#12 Passphrase</label>
                        <input type="password" name="passphrase" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500" autocomplete="new-password">
                        <p class="text-[11px] text-slate-400 mt-1">Leave empty if the bundle has no passphrase. The passphrase is encrypted in MariaDB via AES-256-GCM authenticated cipher.</p>
                    </div>

                    <div class="flex items-center justify-between pt-4 border-t border-slate-700">
                        <a href="?step=3" class="text-xs text-slate-400 hover:text-white">&larr; Back to LDAP</a>
                        <button type="submit" class="px-6 py-2.5 bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold rounded-lg shadow-sm transition">
                            Save &amp; Continue to Final Review &rarr;
                        </button>
                    </div>
                </form>
            </div>
        <?php endif; ?>

        <!-- STEP 5: Review & Final Lock Routine -->
        <?php if ($currentStep === 5): ?>
            <div class="bg-slate-800/90 rounded-2xl border border-slate-700/80 p-6 sm:p-8 shadow-xl">
                <div class="flex items-center gap-3 pb-5 border-b border-slate-700 mb-6">
                    <div class="w-10 h-10 rounded-xl bg-emerald-500/10 text-emerald-400 flex items-center justify-center font-bold">5</div>
                    <div>
                        <h2 class="text-lg font-bold text-white">Review &amp; Permanent Installation Lock</h2>
                        <p class="text-slate-400 text-xs">Verify all configured parameters before finalizing setup and creating permanent security locks.</p>
                    </div>
                </div>

                <!-- Subsystem Overview Cards -->
                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
                    <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-700/60 text-xs">
                        <div class="font-bold text-purple-400 mb-1 flex items-center gap-1">
                            <span>MariaDB Database</span>
                        </div>
                        <div class="text-[11px] space-y-0.5 text-slate-300 font-mono">
                            <div>Host: <?php echo htmlspecialchars($_SESSION['wizard']['db']['host'] ?? '127.0.0.1'); ?></div>
                            <div>Database: <?php echo htmlspecialchars($_SESSION['wizard']['db']['name'] ?? 'eop_antispam_db'); ?></div>
                            <div class="text-emerald-400 font-sans font-semibold mt-1">11 Tables Populated</div>
                        </div>
                    </div>

                    <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-700/60 text-xs">
                        <div class="font-bold text-emerald-400 mb-1 flex items-center gap-1">
                            <span>Environment (.env)</span>
                        </div>
                        <div class="text-[11px] space-y-0.5 text-slate-300 font-mono">
                            <div>File: /var/www/eop-antispam/.env</div>
                            <div>Host: <?php echo htmlspecialchars($_SESSION['wizard']['db']['host'] ?? '127.0.0.1'); ?></div>
                            <div class="text-emerald-400 font-sans font-semibold mt-1">Persisted &amp; chmod 0640</div>
                        </div>
                    </div>

                    <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-700/60 text-xs">
                        <div class="font-bold text-blue-400 mb-1 flex items-center gap-1">
                            <span>Active Directory LDAP</span>
                        </div>
                        <div class="text-[11px] space-y-0.5 text-slate-300 font-mono">
                            <div>Host: <?php echo htmlspecialchars($_SESSION['wizard']['ldap']['host'] ?? '192.168.10.10'); ?></div>
                            <div>Proto: <?php echo strtoupper(htmlspecialchars($_SESSION['wizard']['ldap']['protocol'] ?? 'ldap')); ?></div>
                            <div class="text-emerald-400 font-sans font-semibold mt-1">Group Check Active</div>
                        </div>
                    </div>

                    <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-700/60 text-xs">
                        <div class="font-bold text-amber-400 mb-1 flex items-center gap-1">
                            <span>Exchange Online EOP</span>
                        </div>
                        <div class="text-[11px] space-y-0.5 text-slate-300 font-mono">
                            <div>Tenant: <?php echo substr(htmlspecialchars($_SESSION['wizard']['eop']['tenant_id'] ?? ''), 0, 8); ?>...</div>
                            <div>Thumb: <?php echo substr(htmlspecialchars(eopNormalizeThumbprint($_SESSION['wizard']['eop']['thumbprint'] ?? '')), 0, 8); ?>...</div>
                            <div>PKCS#12: <?php
                                $reviewBundle = $_SESSION['wizard']['eop']['pkcs12_bundle'] ?? '';
                                echo $reviewBundle !== ''
                                    ? htmlspecialchars($_SESSION['wizard']['eop']['pkcs12_filename'] ?? 'certificate.pfx') . ' (' . number_format(strlen((string)base64_decode($reviewBundle)) / 1024, 1) . ' KB)'
                                    : '<span class="text-amber-400">not uploaded</span>';
                            ?></div>
                            <div class="text-emerald-400 font-sans font-semibold mt-1">AES-256 Key Stored</div>
                        </div>
                    </div>
                </div>

                <!-- Policy Identity Card: which anti-spam policy the sync will target -->
                <div class="p-4 rounded-xl bg-slate-900/60 border border-slate-700/60 text-xs mb-6">
                    <div class="font-bold text-cyan-400 mb-1.5 flex items-center justify-between gap-2 flex-wrap">
                        <span>Anti-Spam Policy Target</span>
                        <?php if (!empty($_SESSION['wizard']['eop']['policy_verified'])): ?>
                            <span class="text-emerald-400 font-sans text-[10px] font-semibold px-2 py-0.5 rounded-full bg-emerald-950/60 border border-emerald-800">Verified on Exchange Online</span>
                        <?php else: ?>
                            <span class="text-amber-400 font-sans text-[10px] font-semibold px-2 py-0.5 rounded-full bg-amber-950/60 border border-amber-800">Not verified</span>
                        <?php endif; ?>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1 text-[11px] space-y-0.5 text-slate-300 font-mono">
                        <div>
                            <span class="text-slate-500">Name:</span>
                            <?php echo htmlspecialchars($_SESSION['wizard']['eop']['policy'] ?? '(not set)'); ?>
                        </div>
                        <div>
                            <span class="text-slate-500">GUID:</span>
                            <?php
                                $reviewGuid = eopNormalizeGuid($_SESSION['wizard']['eop']['policy_guid'] ?? '');
                                echo $reviewGuid !== ''
                                    ? htmlspecialchars($reviewGuid)
                                    : '<span class="text-slate-500">resolved at first sync</span>';
                            ?>
                        </div>
                    </div>
                    <p class="text-[11px] text-slate-500 mt-2">
                        Both forms are accepted in Step 4. When a GUID is supplied and Exchange verification succeeded, it is
                        resolved to this name before being written to <code>.env</code>, so every policy-keyed list in MariaDB
                        stays consistent. Without verification the identifier is stored as entered &mdash;
                        <code>-Identity</code> still accepts either form.
                    </p>
                </div>

                <!-- Permanent Lock Warning Notice -->
                <div class="p-4 rounded-xl bg-amber-950/40 border border-amber-700/60 text-xs text-amber-200 leading-relaxed mb-6 space-y-2">
                    <div class="font-bold flex items-center gap-2 text-sm text-amber-300">
                        <span>Security Lockout Notice: Setup Cannot Be Run Again</span>
                    </div>
                    <p>
                        Clicking <strong>Complete Installation, Write .env &amp; Lock Setup</strong> will permanently persist database and system settings to <code>.env</code>, create the Debian filesystem lockfile <code>installed.lock</code>, and record the installation timestamp in MariaDB table <code>eop_setup_lock</code>.
                    </p>
                    <p class="font-semibold text-amber-300">
                        Once locked, this <code>setup.php</code> routine will immediately respond with <strong>403 Forbidden</strong> and will never execute again.
                    </p>
                </div>

                <form method="POST">
                    <input type="hidden" name="action" value="step5_finalize_lock">
                    <div class="flex items-center justify-between pt-4 border-t border-slate-700">
                        <a href="?step=4" class="text-xs text-slate-400 hover:text-white">&larr; Back to EOP Setup</a>
                        <button type="submit" class="px-6 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded-lg shadow-sm transition">
                            Complete Installation, Write .env &amp; Lock Setup
                        </button>
                    </div>
                </form>
            </div>
        <?php endif; ?>

    </div>

    <script>
    function updatePasswordPolicy() {
        var input = document.getElementById('fallbackAdminPassInput');
        if (!input) return;
        var pwd = input.value || '';

        var minLength = pwd.length >= 12;
        var hasUpper = /[A-Z]/.test(pwd);
        var hasLower = /[a-z]/.test(pwd);
        var hasNumber = /[0-9]/.test(pwd);
        var hasSymbol = /[^A-Za-z0-9]/.test(pwd);
        var passedCategories = (hasUpper ? 1 : 0) + (hasLower ? 1 : 0) + (hasNumber ? 1 : 0) + (hasSymbol ? 1 : 0);
        var isValid = minLength && (passedCategories >= 3);

        // Helper to update green category badge
        function setCategoryState(boxId, iconId, isPass) {
            var box = document.getElementById(boxId);
            var icon = document.getElementById(iconId);
            if (!box || !icon) return;
            if (isPass) {
                box.className = 'flex items-center gap-1.5 p-2 rounded border border-emerald-600 bg-emerald-950/70 text-emerald-300 transition-colors';
                icon.textContent = '✓';
                icon.className = 'w-3.5 h-3.5 flex items-center justify-center font-bold text-emerald-400';
            } else {
                box.className = 'flex items-center gap-1.5 bg-slate-900 p-2 rounded border border-slate-800 text-slate-400 transition-colors';
                icon.textContent = '×';
                icon.className = 'w-3.5 h-3.5 flex items-center justify-center font-bold text-slate-500';
            }
        }

        // Update length item
        var lenBox = document.getElementById('pwdLenItem');
        var lenIcon = document.getElementById('pwdLenIcon');
        var lenCount = document.getElementById('pwdLenCount');
        if (lenCount) lenCount.textContent = pwd.length + ' character' + (pwd.length === 1 ? '' : 's');
        if (lenBox && lenIcon) {
            if (minLength) {
                lenBox.className = 'flex items-center justify-between p-2 rounded-lg border border-emerald-600 bg-emerald-950/70 text-emerald-300 transition-colors';
                lenIcon.textContent = '✓';
                lenIcon.className = 'w-4 h-4 rounded-full flex items-center justify-center text-xs font-bold text-emerald-400';
            } else {
                lenBox.className = 'flex items-center justify-between p-2 rounded-lg border border-slate-800 bg-slate-900 text-slate-400 transition-colors';
                lenIcon.textContent = '×';
                lenIcon.className = 'w-4 h-4 rounded-full flex items-center justify-center text-xs font-bold text-slate-500';
            }
        }

        setCategoryState('pwdUpperItem', 'pwdUpperIcon', hasUpper);
        setCategoryState('pwdLowerItem', 'pwdLowerIcon', hasLower);
        setCategoryState('pwdNumberItem', 'pwdNumberIcon', hasNumber);
        setCategoryState('pwdSymbolItem', 'pwdSymbolIcon', hasSymbol);

        // Score summary
        var scoreText = document.getElementById('pwdScoreText');
        if (scoreText) {
            if (passedCategories >= 3) {
                scoreText.innerHTML = '<strong>' + passedCategories + ' of 4</strong> categories satisfied (<span class="text-emerald-400 font-semibold">Meets policy threshold</span>)';
            } else {
                scoreText.innerHTML = '<strong>' + passedCategories + ' of 4</strong> categories satisfied (<span class="text-amber-400 font-semibold">' + (3 - passedCategories) + ' more needed</span>)';
            }
        }

        // Overall badge and input field styles
        var badge = document.getElementById('pwdPolicyBadge');
        if (badge) {
            if (isValid) {
                badge.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-900/80 text-emerald-300 border border-emerald-600 transition-colors';
                badge.textContent = '✓ REQUIREMENTS SATISFIED (PASSED)';
                input.classList.remove('border-slate-700', 'focus:border-amber-500');
                input.classList.add('border-emerald-500', 'focus:border-emerald-400');
            } else {
                badge.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950/80 text-rose-300 border border-rose-800 transition-colors';
                badge.textContent = 'CRITERIA UNMET';
                input.classList.remove('border-emerald-500', 'focus:border-emerald-400');
                input.classList.add('border-slate-700', 'focus:border-amber-500');
            }
        }
    }

    function toggleFallbackPasswordVisibility() {
        var input = document.getElementById('fallbackAdminPassInput');
        var textSpan = document.getElementById('toggleFallbackPassText');
        if (!input || !textSpan) return;
        if (input.type === 'password') {
            input.type = 'text';
            textSpan.textContent = 'Hide';
        } else {
            input.type = 'password';
            textSpan.textContent = 'Show';
        }
    }

    // Mirrors eopNormalizeGuid() on the server: strips urn:uuid:/braces/separators
    // and reports whether the policy field holds a GUID rather than a display name.
    function describePolicyIdentifier(raw) {
        var value = (raw || '').trim().toLowerCase();
        if (value === '') return 'empty';
        value = value.replace(/^urn:uuid:/, '').replace(/^\\{|\\}$/g, '');
        var hex = value.replace(/[^0-9a-f]/g, '');
        if (hex.length === 32 && /^[0-9a-f]+$/.test(hex)) return 'guid';
        return 'name';
    }

    function updatePolicyKindIndicator() {
        var input = document.getElementById('policyInput');
        var badge = document.getElementById('policyKindBadge');
        if (!input || !badge) return;

        var kind = describePolicyIdentifier(input.value);
        if (kind === 'guid') {
            badge.textContent = 'GUID';
            badge.className = 'shrink-0 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-cyan-950/70 text-cyan-300 border border-cyan-800';
        } else if (kind === 'name') {
            badge.textContent = 'Name';
            badge.className = 'shrink-0 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-slate-700 text-slate-300 border border-slate-600';
        } else {
            badge.textContent = 'Required';
            badge.className = 'shrink-0 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-rose-950/70 text-rose-300 border border-rose-800';
        }
    }

    // Attach listeners on load
    document.addEventListener('DOMContentLoaded', function() {
        var passInput = document.getElementById('fallbackAdminPassInput');
        if (passInput) {
            passInput.addEventListener('input', updatePasswordPolicy);
            passInput.addEventListener('keyup', updatePasswordPolicy);
            passInput.addEventListener('change', updatePasswordPolicy);
            updatePasswordPolicy();
        }

        var policyInput = document.getElementById('policyInput');
        if (policyInput) {
            policyInput.addEventListener('input', updatePolicyKindIndicator);
            policyInput.addEventListener('change', updatePolicyKindIndicator);
            updatePolicyKindIndicator();
        }
    });

    // Also call immediately in case DOM is already ready
    if (document.readyState === 'complete' || document.readyState === 'interactive') {
        setTimeout(updatePasswordPolicy, 50);
    }
    </script>
</body>
</html>
`
  },

  // 8. login.php
  {
    name: 'login.php',
    path: 'login.php',
    description: 'Active Directory LDAP login page enforcing authorized Group Distinguished Name validation and secure session creation.',
    category: 'views',
    generateContent: () => `<?php
/**
 * Active Directory LDAP Login Page
 */

declare(strict_types=1);

// If configuration file is missing, redirect immediately to setup wizard
if (!file_exists(__DIR__ . '/config.php')) {
    header('Location: setup.php');
    exit;
}

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';
require_once __DIR__ . '/ldap.php';
require_once __DIR__ . '/functions.php';

// If system is already installed and locked, do not redirect to setup.php (which is locked with 403)
if (!file_exists(__DIR__ . '/installed.lock')) {
    if (!Database::isConfigured()) {
        header('Location: setup.php');
        exit;
    }
    if (!Database::isInitialized()) {
        header('Location: setup.php?step=2');
        exit;
    }
}

// Redirect if already logged in
if (!empty($_SESSION['user'])) {
    header('Location: index.php');
    exit;
}

$error = null;
if (file_exists(__DIR__ . '/installed.lock')) {
    if (!Database::isConfigured()) {
        $error = 'MariaDB is not configured. Please check DB_HOST and DB_NAME in .env or config.php.';
    } elseif (!Database::isInitialized()) {
        $error = 'Could not connect to MariaDB or verify schema tables. Check database credentials in .env.';
    }
}
$timeoutMsg = isset($_GET['msg']) && $_GET['msg'] === 'timeout';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = $_POST['csrf_token'] ?? '';
    if (!verifyCsrfToken($token)) {
        $error = 'Invalid CSRF security token. Please refresh and try again.';
    } else {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        $ldap = new LdapAuth();
        $authResult = $ldap->authenticate($username, $password);

        if ($authResult['success']) {
            // Regenerate session ID to prevent session fixation
            session_regenerate_id(true);
            $_SESSION['user'] = $authResult['user'];
            $_SESSION['LAST_ACTIVITY'] = time();

            require_once __DIR__ . '/database.php';
            $isFallback = !empty($authResult['user']['isFallbackAdmin']);
            $logMsg = $isFallback 
                ? 'Successful Emergency Fallback Local Admin login (LDAP connection failure / disaster recovery)' 
                : 'Successful AD LDAP login';
            Database::logAudit('LOGIN', 'SYSTEM', DEFAULT_POLICY_NAME, $username, $logMsg, $username);

            header('Location: index.php');
            exit;
        } else {
            $error = $authResult['error'] ?? 'Authentication failed.';
        }
    }
}

$csrfToken = getCsrfToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - <?= htmlspecialchars(APP_TITLE) ?></title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: { extend: {} }
        };
        if (localStorage.getItem('theme') === 'dark' || (!localStorage.getItem('theme') && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
            document.documentElement.classList.add('dark');
        } else {
            document.documentElement.classList.remove('dark');
        }
    </script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="bg-slate-100 dark:bg-slate-950 min-h-screen flex items-center justify-center p-4 font-sans transition-colors duration-200">
    <!-- Theme Toggle at top-right -->
    <div class="fixed top-4 right-4 z-20">
        <button type="button" onclick="toggleTheme()" 
                class="p-2.5 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm transition"
                title="Toggle Dark / Light Mode">
            <i id="loginThemeIcon" class="fa-solid fa-moon text-sm"></i>
        </button>
    </div>

    <div class="max-w-md w-full bg-white dark:bg-slate-900 rounded-2xl shadow-xl border border-slate-200 dark:border-slate-800 overflow-hidden transition-colors duration-200">
        
        <!-- Header -->
        <div class="bg-blue-600 dark:bg-blue-500 p-6 text-white text-center">
            <div class="w-12 h-12 bg-white/10 rounded-xl flex items-center justify-center mx-auto mb-3 backdrop-blur-xs text-2xl font-bold">
                <i class="fa-solid fa-shield-halved"></i>
            </div>
            <h2 class="text-xl font-bold"><?= htmlspecialchars(APP_TITLE) ?></h2>
            <p class="text-blue-100 text-xs mt-1">Active Directory LDAP Authentication (Plain LDAP / LDAPS)</p>
        </div>

        <div class="p-8">
            <?php if ($timeoutMsg): ?>
                <div class="mb-5 p-3 rounded-lg bg-amber-50 dark:bg-amber-950/40 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-800/50 text-xs flex items-center space-x-2">
                    <i class="fa-solid fa-clock"></i>
                    <span>Your session has timed out. Please sign in again.</span>
                </div>
            <?php endif; ?>

            <?php if (isset($_GET['installed']) && $_GET['installed'] === '1'): ?>
                <div class="mb-5 p-3.5 rounded-lg bg-emerald-50 dark:bg-emerald-950/40 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/50 text-xs flex items-start space-x-2">
                    <i class="fa-solid fa-circle-check text-emerald-600 dark:text-emerald-400 mt-0.5"></i>
                    <div>
                        <div class="font-bold">Setup Routine Completed &amp; Locked!</div>
                        <div>Database schema populated, LDAP &amp; EOP credentials saved. Initial setup cannot be run again.</div>
                    </div>
                </div>
            <?php elseif (!file_exists(__DIR__ . '/installed.lock')): ?>
                <div class="mb-5 p-3.5 rounded-lg bg-amber-50 dark:bg-amber-950/40 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-800/50 text-xs flex items-start justify-between">
                    <div class="flex items-start space-x-2">
                        <i class="fa-solid fa-sparkles text-amber-600 dark:text-amber-400 mt-0.5"></i>
                        <div>
                            <div class="font-bold">First Time Setup?</div>
                            <div class="text-[11px]">Run initial setup wizard to configure Database, LDAP, and EOP.</div>
                        </div>
                    </div>
                    <a href="setup.php" class="px-2.5 py-1 bg-amber-600 hover:bg-amber-700 text-white rounded text-[11px] font-semibold transition shrink-0 ml-2">
                        Run Setup &rarr;
                    </a>
                </div>
            <?php endif; ?>

            <?php if ($error): ?>
                <div class="mb-5 p-3.5 rounded-lg bg-rose-50 dark:bg-rose-950/40 text-rose-800 dark:text-rose-300 border border-rose-200 dark:border-rose-800/50 text-xs flex items-start space-x-2">
                    <i class="fa-solid fa-triangle-exclamation text-rose-600 dark:text-rose-400 mt-0.5"></i>
                    <div><?= htmlspecialchars($error) ?></div>
                </div>
            <?php endif; ?>

            <form method="POST" action="login.php" class="space-y-4">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">

                <div>
                    <label class="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">Active Directory Username</label>
                    <div class="relative">
                        <i class="fa-solid fa-user absolute left-3 top-3 text-slate-400 dark:text-slate-500 text-sm"></i>
                        <input type="text" name="username" required autocomplete="username" autofocus
                               placeholder="sAMAccountName or user@corp.example.com"
                               class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white text-sm rounded-lg pl-9 pr-3 py-2.5 focus:ring-2 focus:ring-blue-500 focus:outline-hidden">
                    </div>
                    <p class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">Domain: <?= htmlspecialchars(LDAP_NETBIOS_DOMAIN) ?></p>
                </div>

                <div>
                    <label class="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">Password</label>
                    <div class="relative">
                        <i class="fa-solid fa-lock absolute left-3 top-3 text-slate-400 dark:text-slate-500 text-sm"></i>
                        <input type="password" name="password" required autocomplete="current-password"
                               placeholder="Domain password"
                               class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white text-sm rounded-lg pl-9 pr-3 py-2.5 focus:ring-2 focus:ring-blue-500 focus:outline-hidden">
                    </div>
                </div>

                <div class="p-3 bg-slate-50 dark:bg-slate-800/70 rounded-lg border border-slate-200 dark:border-slate-700 text-[11px] text-slate-500 dark:text-slate-400">
                    <div class="font-semibold text-slate-700 dark:text-slate-200 mb-0.5 flex items-center justify-between">
                        <span><i class="fa-solid fa-id-badge text-blue-600 dark:text-blue-400 mr-1"></i> Access Restricted</span>
                        <span class="text-[10px] px-1.5 py-0.2 rounded bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300">LDAP Port <?= (int)LDAP_PORT ?></span>
                    </div>
                    Must be a member of Group DN:<br>
                    <code class="text-[10px] text-blue-600 dark:text-blue-400 break-all font-mono"><?= htmlspecialchars(LDAP_AUTHORIZED_GROUP_DN) ?></code>
                </div>

                <?php if (defined('FALLBACK_ADMIN_ENABLED') && FALLBACK_ADMIN_ENABLED): ?>
                <div class="p-2.5 bg-amber-50 dark:bg-amber-950/30 rounded-lg border border-amber-200 dark:border-amber-900/40 text-[11px] text-amber-800 dark:text-amber-300 flex items-start space-x-2">
                    <i class="fa-solid fa-shield-halved text-amber-600 dark:text-amber-400 mt-0.5"></i>
                    <div>
                        <span class="font-semibold">LDAP Offline Fallback:</span> If your Active Directory DC is unreachable, use your emergency fallback administrator credentials.
                    </div>
                </div>
                <?php endif; ?>

                <button type="submit" class="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-lg shadow-sm transition flex items-center justify-center space-x-2">
                    <i class="fa-solid fa-right-to-bracket"></i>
                    <span>Authenticate via AD</span>
                </button>
            </form>
        </div>
    </div>

    <script>
        function updateThemeUI() {
            const isDark = document.documentElement.classList.contains('dark');
            const icon = document.getElementById('loginThemeIcon');
            if (icon) {
                icon.className = isDark ? 'fa-solid fa-sun text-amber-400 text-sm' : 'fa-solid fa-moon text-slate-500 text-sm';
            }
        }
        function toggleTheme() {
            const isDark = document.documentElement.classList.toggle('dark');
            localStorage.setItem('theme', isDark ? 'dark' : 'light');
            updateThemeUI();
        }
        updateThemeUI();
    </script>
</body>
</html>
`
  },

  // 8. logout.php
  {
    name: 'logout.php',
    path: 'logout.php',
    description: 'Destroys user session and security cookies, logging sign-out audit event.',
    category: 'auth',
    generateContent: () => `<?php
/**
 * Logout Handler
 */

declare(strict_types=1);
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';

if (!empty($_SESSION['user']['username'])) {
    Database::logAudit('LOGOUT', 'SYSTEM', DEFAULT_POLICY_NAME, $_SESSION['user']['username'], 'User signed out', $_SESSION['user']['username']);
}

$_SESSION = [];

if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params['path'], $params['domain'],
        $params['secure'], $params['httponly']
    );
}

session_destroy();
header('Location: login.php');
exit;
`
  },

  // 9. actions.php
  {
    name: 'actions.php',
    path: 'actions.php',
    description: 'POST request dispatcher handling additions, deletions, bulk imports, CSV exports, and sync triggers.',
    category: 'core',
    generateContent: () => `<?php
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

// Read-only probe used by the UI to notice that a scheduled sync changed the
// data. It runs before the CSRF gate because it is a GET made by the page itself
// on a timer, and it reveals nothing beyond a change token: no entries, no
// policy details, and the caller is still authenticated by requireAuth above.
//
// It is safe without a CSRF token for the same reason a cache validator is: it
// only ever echoes a derived fingerprint, so a cross-site request cannot read
// application data or change anything. It also sends no-store so an intermediary
// cannot answer with a stale token and suppress a needed refresh.
if ($action === 'data_version') {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
    echo json_encode(['version' => Database::getDataVersion($policyName)]);
    exit;
}

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
    $lines = explode("\\n", str_replace("\\r", "", $bulkData));
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
    $lines = explode("\\n", str_replace("\\r", "", $bulkData));

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

    $logMsg = implode("\\n", $output);
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
        // Log the whole thing before it is truncated for storage. The flash is
        // capped at 300 chars and the audit row at 200, and on a push the banner
        // then fills with the header and certificate thumbprint, so the part that
        // names the actual failure lands past the cut.
        $syncLogPath = __DIR__ . '/logs/sync-failures.log';
        $syncLogDir = dirname($syncLogPath);
        if (!is_dir($syncLogDir)) {
            @mkdir($syncLogDir, 0750, true);
        }
        $syncLogEntry = sprintf(
            "[%s] [EOP Sync Failure] action=%s policy=%s exit=%d user=%s ip=%s\\n--- BEGIN FULL OUTPUT ---\\n%s\\n--- END FULL OUTPUT ---\\n",
            date('Y-m-d H:i:s'),
            $actionParam,
            $policyName,
            $returnVar,
            $user['username'] ?? 'unknown',
            $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            $logMsg
        );
        // error_log() with no type goes to the SAPI logger, which PHP-FPM forwards
        // to NGINX as "FastCGI sent in stderr". That relay is cut at about 1024
        // bytes, so the banner always survived and the guard message that follows
        // it was always lost, which is why the real cause of a failed push could
        // not be read from the NGINX log. Writing to our own file has no such
        // limit. Keep the SAPI call too, for operators who watch the error log.
        @file_put_contents($syncLogPath, $syncLogEntry, FILE_APPEND | LOCK_EX);
        error_log(sprintf(
            "[EOP Sync Failure] action=%s policy=%s exit=%d user=%s ip=%s. Full output: %s",
            $actionParam,
            $policyName,
            $returnVar,
            $user['username'] ?? 'unknown',
            $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            $syncLogPath
        ));
        Database::updatePolicySyncStatus($policyName, 'failed', $logMsg);
        // details is TEXT, so there is room to keep the part of the output that
        // names the failure rather than the banner that precedes it.
        Database::logAudit('SYNC', 'SYSTEM', $policyName, 'ALL', "Sync ({$actionParam}) failed: " . substr($logMsg, -2000), $user['username']);
        // Show the tail, not the head. The script prints its banner, the policy
        // name and the certificate thumbprint before doing any work, so a prefix
        // is always the least useful part of the output; the guard that refused
        // the push is at the end. The full output is in logs/sync-failures.log.
        $flashTail = strlen($logMsg) > 600 ? substr($logMsg, -600) : $logMsg;
        setFlash('warning', "Sync script exited with code {$returnVar}. End of output: " . htmlspecialchars($flashTail));
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
`
  },

  // 10. sync-exchange.ps1
  {
    name: 'sync-exchange.ps1',
    path: 'sync-exchange.ps1',
    description: 'Debian Linux PowerShell script (pwsh) to query or update Exchange Online Protection. Defaults to Pull mode for scheduled cron jobs (retrieves remote EOP changes into MariaDB without pushing).',
    category: 'sync',
    generateContent: (cfg) => `#!/usr/bin/env pwsh
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
    [string]$PolicyName = "${cfg.defaultPolicyName}",
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
# \`return , $arr\` survives a hashtable assignment but makes \`@(Get-FlatStringArray ...)\`
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
    # Does not rely on Windows-only Import-PfxCertificate cmdlet or Windows-specific Cert:\\ drive
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
            Write-Warning "Could not instantiate X509Certificate2 from '\${PfxFile}': $($_.Exception.Message)"
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

    # [string[]] keeps a single-entry list a JSON array and an empty list \`[]\`.
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

    Write-Host ("Retrieved remote entries: allowed_senders={0} blocked_senders={1} allowed_domains={2} blocked_domains={3}" -f \`
        $payload.allowed_senders.Count, $payload.blocked_senders.Count, \`
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
            Write-Error "Push aborted for '\${TableName}': neither the 'mariadb' nor the 'mysql' client is installed, so the local list cannot be read. Install the MariaDB client package, or push from the web UI."
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
                Write-Host ("[debug] raw[{0}] len={1} first40='{2}'" -f $i, ([string]$line).Length, (([string]$line).Substring(0, [Math]::Min(40, ([string]$line).Length)) -replace "\`r|\`n", '\\n'))
            }
        }

        if ($exit -ne 0) {
            Write-Error "Push aborted for '\${TableName}': the query failed (exit \${exit}). $([string]$stderr).Trim()"
            exit 1
        }

        $values = @()
        foreach ($line in @($raw)) {
            $text = ([string]$line).Trim()
            if ($text -eq '') { continue }
            # Anything that looks like JSON, an object or a quoted field is not a
            # list value. Pushing it would corrupt the Exchange policy.
            if ($text -match '^[\\[\\]{}]' -or $text.StartsWith('"') -or $text.EndsWith('",')) {
                Write-Error "Push aborted for '\${TableName}': query output looks like JSON or a serialised object rather than list data: '$text'. Refusing to push it to Exchange Online."
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
                    Write-Error "Push aborted for '\${TableName}': expected-count variable \${ExpectedCountVar} is not a number ('$expected')."
                    exit 1
                }
                if ($values.Count -ne $expectedInt) {
                    Write-Error "Push aborted for '\${TableName}': the MariaDB client read $($values.Count) rows but PHP read \${expectedInt} over PDO. The two disagree, so the local list is not being read consistently and the push has been refused. Re-run with the web UI push to investigate."
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
        Set-HostedContentFilterPolicy -Identity $PolicyName \`
            -AllowedSenders $allowedSenders \`
            -BlockedSenders $blockedSenders \`
            -AllowedSenderDomains $allowedDomains \`
            -BlockedSenderDomains $blockedDomains \`
            -ErrorAction Stop
    } catch {
        Write-Error "Push to Exchange Online failed: $($_.Exception.Message)"
        exit 1
    }

    Disconnect-ExchangeOnline -ErrorAction SilentlyContinue | Out-Null
    Write-Host "SUCCESS: Policy '$PolicyName' pushed to Exchange Online!" -ForegroundColor Green
    exit 0
}
`
  },

  // 11. cron-sync.php
  {
    name: 'cron-sync.php',
    path: 'cron-sync.php',
    description: 'CLI synchronization runner intended for Linux crontab scheduling. Strictly pulls changes from Exchange Online Protection into MariaDB; does NOT push local changes.',
    category: 'sync',
    generateContent: () => `<?php
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
    die("This script must be run from the command line.\\n");
}

if (!file_exists(__DIR__ . '/config.php')) {
    fwrite(STDERR, "[" . date('Y-m-d H:i:s') . "] CRON ERROR: /var/www/eop-antispam/config.php not found. Please complete initial setup at http://<server-ip>/setup.php\\n");
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
    echo "Usage: php cron-sync.php [--policy=PolicyName] [--action=pull|push]\\n";
    echo "  pull  (default) Exchange Online -> MariaDB. Always allowed.\\n";
    echo "  push  MariaDB -> Exchange Online. Requires EOP_CRON_ALLOW_PUSH=true,\\n";
    echo "        and is refused if any of the four local lists is empty unless\\n";
    echo "        EOP_CRON_PUSH_ALLOW_EMPTY=true is also set.\\n";
    exit(0);
}

$policy = $options['policy'] ?? Database::getDefaultPolicyName();
$action = strtolower(trim((string)($options['action'] ?? 'pull')));

if (!in_array($action, ['pull', 'push'], true)) {
    fwrite(STDERR, "[CRON ERROR] Unknown --action '{$action}'. Expected 'pull' or 'push'.\\n");
    exit(1);
}

$isPush = ($action === 'push');
$allowPush = eopReadFlag('EOP_CRON_ALLOW_PUSH');
$allowEmptyPush = eopReadFlag('EOP_CRON_PUSH_ALLOW_EMPTY');

// Pushing from an unattended job modifies production anti-spam policies, so it
// has to be turned on deliberately rather than being reachable by a crontab edit.
if ($isPush && !$allowPush) {
    fwrite(STDERR, "[CRON POLICY ERROR] Push is disabled. The cron job pulls only unless EOP_CRON_ALLOW_PUSH=true is set.\\n");
    fwrite(STDERR, "To push, either set EOP_CRON_ALLOW_PUSH=true in .env (see README), or have an authorized administrator use the Web UI.\\n");
    exit(1);
}

echo "[" . date('Y-m-d H:i:s') . "] Starting EOP Anti-Spam CRON {$action} for policy: {$policy}\\n";
if ($isPush) {
    echo "Sync Direction: PUSH (MariaDB -> Exchange Online) - APPLIES TO PRODUCTION\\n";
} else {
    echo "Sync Direction: PULL ONLY (Exchange Online -> MariaDB)\\n";
    echo "Notice: Local MariaDB changes will NOT be pushed to EOP.\\n";
}


// Execute PowerShell sync script in Pull-only mode on Debian
$psScript = __DIR__ . '/sync-exchange.ps1';
if (!file_exists($psScript)) {
    fwrite(STDERR, "[" . date('Y-m-d H:i:s') . "] CRON ERROR: PowerShell script not found at {$psScript}\\n");
    exit(1);
}

$pwsh = trim((string)shell_exec('command -v pwsh 2>/dev/null'));
if ($pwsh === '') {
    fwrite(STDERR, "[" . date('Y-m-d H:i:s') . "] CRON ERROR: pwsh not found. Install PowerShell 7 (https://aka.ms/powershell)\\n");
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
    fwrite(STDERR, '[' . date('Y-m-d H:i:s') . '] CRON ERROR: ' . $syncEnv['error'] . "\\n");
    Database::updatePolicySyncStatus($policy, 'failed', $syncEnv['error']);
    exit(1);
}

$pfxPath = $syncEnv['pfx_path'];

if (trim((string)($authConfig['pkcs12_bundle'] ?? '')) !== '' && (string)($authConfig['encrypted_password'] ?? '') === '') {
    fwrite(STDERR, "[" . date('Y-m-d H:i:s') . "] NOTICE: no stored passphrase for the PKCS#12 bundle, attempting an empty passphrase.\\n");
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
        fwrite(STDERR, '[' . date('Y-m-d H:i:s') . "] CRON POLICY ERROR: push refused for policy '{$policy}'.\\n");
        fwrite(STDERR, "These local lists are empty: {$detail}.\\n");
        fwrite(STDERR, "A push applies all four lists at once, so an empty list would CLEAR it in Exchange Online.\\n");
        fwrite(STDERR, "Populate the list(s), or set EOP_CRON_PUSH_ALLOW_EMPTY=true if clearing them is intended.\\n");
        Database::updatePolicySyncStatus($policy, 'failed', "Push refused: empty local list(s) {$detail}");
        Database::logAudit('SYNC', 'SYSTEM', $policy, 'ALL', "Cron push refused: empty local list(s) {$detail}", 'CRON_DAEMON');
        exit(1);
    }

    foreach ($counts as $listType => $count) {
        printf("  local %-18s %d\\n", $listType, $count);
    }

    // Hand the PDO row counts to the PowerShell side. It reads the same lists
    // through the MariaDB CLI, and if the two disagree then the local data is not
    // being read consistently - the push is refused rather than applied. This is
    // the guard that stops a failed or missing client from silently replacing the
    // Exchange policy with garbage.
    $expectEnvMap = [
        'allowed_senders' => 'EOP_EXPECT_ALLOWED_SENDERS',
        'blocked_senders' => 'EOP_EXPECT_BLOCKED_SENDERS',
        'allowed_domains' => 'EOP_EXPECT_ALLOWED_DOMAINS',
        'blocked_domains' => 'EOP_EXPECT_BLOCKED_DOMAINS',
    ];
    foreach ($expectEnvMap as $listType => $varName) {
        putenv($varName . '=' . (int)($counts[$listType] ?? 0));
    }
    if ($empty !== []) {
        fwrite(STDERR, '[' . date('Y-m-d H:i:s') . '] WARNING: ' . count($empty) . " list(s) are empty and WILL BE CLEARED in Exchange Online (EOP_CRON_PUSH_ALLOW_EMPTY is set).\\n");
    }

    $pushShell = sprintf(
        '%s -NoProfile -NonInteractive -File %s -PolicyName %s -Action Push 2>&1',
        escapeshellarg($pwsh),
        escapeshellarg($psScript),
        escapeshellarg($policy)
    );

    // EOP_SYNC_DEBUG=1 makes sync-exchange.ps1 dump the exact client output and
    // each guard decision. Inherited from the environment, so it can be set inline
    // for a one-off run.
    if (!getenv('EOP_SYNC_DEBUG')) {
        echo "(hint: re-run with EOP_SYNC_DEBUG=1 to trace the MariaDB client output)\\n";
    }

    $pushOutput = [];
    $pushExit = 0;
    passthru($pushShell, $pushExit);

    if ($pushExit === 0) {
        $total = array_sum($counts);
        Database::updatePolicySyncStatus($policy, 'synced', "Cron push applied {$total} entries across 4 lists");
        Database::logAudit('SYNC', 'SYSTEM', $policy, 'ALL', "Crontab pushed MariaDB -> Exchange Online (Push): {$total} entries across 4 lists", 'CRON_DAEMON');
        echo "[" . date('Y-m-d H:i:s') . "] Cron EOP push completed successfully.\\n";
        exit(0);
    }

    Database::updatePolicySyncStatus($policy, 'failed', "Cron push exited with code {$pushExit}");
    Database::logAudit('SYNC', 'SYSTEM', $policy, 'ALL', "Crontab push failed with code {$pushExit}", 'CRON_DAEMON');
    fwrite(STDERR, '[' . date('Y-m-d H:i:s') . "] Cron push failed with code {$pushExit}\\n");
    exit(1);
}

// -----------------------------------------------------------------------------
// PULL: Exchange Online -> MariaDB (default)
// -----------------------------------------------------------------------------
$pullOutput = tempnam(sys_get_temp_dir(), 'eoppull_');
if ($pullOutput === false) {
    fwrite(STDERR, '[' . date('Y-m-d H:i:s') . "] CRON ERROR: could not create a temporary file for the pull response.\\n");
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
    fwrite(STDERR, "[" . date('Y-m-d H:i:s') . "] CRON ERROR: could not import ExchangeOnlineManagement (exit {$preflightExit}).\\n");
    foreach ($preflightOutput as $line) {
        fwrite(STDERR, '    ' . $line . "\\n");
    }
    Database::updatePolicySyncStatus($policy, 'failed', 'ExchangeOnlineManagement module import failed');
    exit(1);
}

echo "ExchangeOnlineManagement module imported successfully.\\n";

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
        fwrite(STDERR, "[" . date('Y-m-d H:i:s') . "] CRON ERROR: the pull finished but wrote no readable policy payload.\\n");
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
                fwrite(STDERR, "[" . date('Y-m-d H:i:s') . "] CRON ERROR: the remote payload for '{$listType}' is neither a list nor a string.\\n");
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
            fwrite(STDERR, '[' . date('Y-m-d H:i:s') . '] CRON ERROR: ' . $e->getMessage() . "\\n");
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
                "  %-18s remote=%-5d held=%-5d confirmation required\\n",
                $listType, $result['remote'], $localCount
            );
        } elseif ($guard === 'denied') {
            // An administrator already refused; entries are deliberately kept and
            // cron must not nag about it on every run.
            $heldByDecision[$listType] = ['local_count' => $localCount, 'guard' => 'denied'];
            printf(
                "  %-18s remote=%-5d kept=%-5d deletion previously denied\\n",
                $listType, $result['remote'], $localCount
            );
        } else {
            // 'none', or 'applied' where an accepted decision was executed now.
            $totalInserted += $result['inserted'];
            $totalRemoved += $result['removed'];

            printf(
                "  %-18s remote=%-5d inserted=%-5d removed=%-5d\\n",
                $listType, $result['remote'], $result['inserted'], $result['removed']
            );
        }

        foreach ($result['errors'] as $insertError) {
            fwrite(STDERR, '    ' . $insertError . "\\n");
        }
    }

    if ($heldByDecision !== []) {
        echo "NOTE: deletion of an empty remote list was previously DENIED for "
            . count($heldByDecision) . ' list(s); those entries were kept by request: '
            . implode(', ', array_keys($heldByDecision)) . ".\\n";
        echo "      The confirmation clears automatically once Exchange Online returns entries.\\n";
    }

    if ($awaitingDecision !== []) {
        // The pull itself succeeded, so this is not a failure exit: it is a state
        // that needs a human decision. Surfaced loudly because a crontab mailer
        // grepping for the success line would otherwise read this as clean.
        echo str_repeat('-', 74), "\\n";
        echo "ACTION REQUIRED: remote lists came back EMPTY but local entries exist.\\n";
        echo "Deletion has been WITHHELD. Nothing was removed for the lists below.\\n";
        foreach ($awaitingDecision as $listType => $info) {
            $state = $info['guard'] === 'prompted'
                ? 'confirmation raised, awaiting a decision'
                : 'already awaiting a decision';
            printf("  - %-18s local entries=%-6d %s\\n", $listType, $info['local_count'], $state);
        }
        echo "Review and accept or deny each list in the web UI under this policy.\\n";
        echo str_repeat('-', 74), "\\n";

        Database::updatePolicySyncStatus(
            $policy,
            'pending',
            count($awaitingDecision) . ' list(s) withheld: empty remote list needs administrator confirmation'
        );
        echo "[" . date('Y-m-d H:i:s') . "] Cron EOP pull completed; administrator confirmation required.\\n";
    } else {
        $summary = "Cron pull: {$totalInserted} added, {$totalRemoved} removed";
        Database::updatePolicySyncStatus($policy, 'synced', $summary);
        Database::logAudit('SYNC', 'SYSTEM', $policy, 'ALL', "Crontab pulled changes from Exchange Online (Pull-Only): {$summary}", 'CRON_DAEMON');
        echo "[" . date('Y-m-d H:i:s') . "] Cron EOP pull completed successfully.\\n";
    }
} else {
    Database::updatePolicySyncStatus($policy, 'failed', "Crontab pull exited with code {$returnVar}");
    fwrite(STDERR, "[" . date('Y-m-d H:i:s') . "] Cron pull failed with code {$returnVar}\\n");
    exit(1);
}
`
  },

  // 12. nginx.conf
  {
    name: 'nginx.conf',
    path: 'nginx.conf',
    description: 'Production NGINX Server Block configuration with PHP-FPM socket, security headers, and file protection.',
    category: 'debian',
    generateContent: (cfg) => {
      const domain = cfg.appUrl.replace('https://', '').replace('http://', '').split('/')[0];
      const isOnlySite = cfg.isOnlySiteOnServer !== false;

      return `# ==============================================================================
# Production NGINX Server Block for EOP Anti-Spam Policy Manager
# Debian 12 (Bookworm) / Debian 13 (Trixie) with PHP-FPM
# Hosting Mode: ${isOnlySite ? 'DEDICATED SERVER (Only site on this server - default_server catch-all)' : 'SHARED MULTI-SITE (Co-hosted with other virtual hosts)'}
# ==============================================================================

# HTTP -> HTTPS Redirect
server {
    listen 80${isOnlySite ? ' default_server' : ''};
    listen [::]:80${isOnlySite ? ' default_server' : ''};
    server_name ${domain}${isOnlySite ? ' _' : ''};

    return 301 https://\$host\$request_uri;
}

# Primary HTTPS Virtual Host
server {
    listen 443 ssl http2${isOnlySite ? ' default_server' : ''};
    listen [::]:443 ssl http2${isOnlySite ? ' default_server' : ''};
    server_name ${domain}${isOnlySite ? ' _' : ''};

    root /var/www/eop-antispam;
    index index.php index.html;

    # SSL Configuration (Replace with your enterprise or Let's Encrypt certificates)
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Maximum upload size for bulk imports and certificate key uploads
    client_max_body_size 16M;

    # Primary Routing
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    # Pass PHP scripts to PHP-FPM UNIX socket
    location ~ \\.php$ {
        include snippets/fastcgi-php.conf;
        # Debian standard PHP-FPM socket path (adjust version if needed):
        fastcgi_pass unix:/run/php/php-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_intercept_errors on;
        fastcgi_buffer_size 128k;
        fastcgi_buffers 4 256k;
        fastcgi_busy_buffers_size 256k;
    }

    # Deny direct browser access to sensitive configs, keys, SQL, scripts, and locks
    location ~* ^/(\\..*|config\\.php|installed\\.lock|.*\\.sql|.*\\.ps1|.*\\.sh|.*\\.key|.*\\.pem) {
        deny all;
        return 403;
    }

    # Deny access to hidden files (.htaccess, .git, etc.)
    location ~ /\\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    # Logging
    access_log /var/log/nginx/eop_access.log combined;
    error_log /var/log/nginx/eop_error.log warn;
}
`;
    }
  },

  // 14. .env.example
  {
    name: '.env.example',
    path: '.env.example',
    description: 'Environment variable configuration template for Debian deployment.',
    category: 'config',
    generateContent: (cfg) => `# ==============================================================================
# Exchange Online Protection Anti-Spam Policy Manager - Environment Variables
# Host: Debian Linux | Database: Remote MariaDB | Auth: Active Directory LDAP
# ==============================================================================

# Remote MariaDB Database Configuration
DB_HOST="${cfg.dbHost}"
DB_PORT=${cfg.dbPort}
DB_NAME="${cfg.dbName}"
DB_USER="${cfg.dbUser}"
DB_PASS="${cfg.dbPass}"

# Microsoft Active Directory (LDAP) Settings
# Standard plain LDAP (port 389) is supported by default - LDAPS is NOT required!
# Protocol options: 'ldap' (port 389 plain), 'ldaps' (port 636 SSL), or 'starttls' (port 389 TLS)
LDAP_PROTOCOL="${cfg.ldapProtocol || 'ldap'}"
LDAP_HOST="${cfg.ldapHost}"
LDAP_PORT=${cfg.ldapPort}
LDAP_USE_SSL=${cfg.ldapUseSsl ? 'true' : 'false'}
LDAP_USE_TLS=${cfg.ldapUseTls ? 'true' : 'false'}
LDAP_BASE_DN="${cfg.ldapBaseDn}"

# Mandatory Group Distinguished Name for authorized administrators
LDAP_AUTHORIZED_GROUP_DN="${cfg.ldapGroupDn}"

# Active Directory Service Account (recommended for directory lookups)
LDAP_BIND_DN="${cfg.ldapBindDn}"
LDAP_BIND_PASSWORD="${cfg.ldapBindPass}"

# Default Exchange Online Protection Anti-Spam Policy
# EOP_POLICY_NAME accepts either the policy display name or its Exchange GUID;
# the setup wizard resolves a GUID to the name. EOP_POLICY_GUID keeps the
# resolved GUID alongside it and is empty when it was never confirmed.
EOP_POLICY_NAME="${cfg.defaultPolicyName}"
EOP_POLICY_GUID="${cfg.defaultPolicyGuid || ''}"

# Microsoft 365 Azure AD App Registration (for automated sync & certificate auth)
M365_TENANT_ID="${cfg.tenantId}"
M365_CLIENT_ID="${cfg.clientId}"
M365_CERT_THUMBPRINT="${cfg.certificateThumbprint}"
M365_ORGANIZATION="${cfg.organization || 'corp.example.com'}"
M365_CLIENT_SECRET="${cfg.clientSecret}"

# Master key used for AES-256-GCM encryption of private key passwords stored in database
AUTH_MASTER_ENCRYPTION_KEY="eop_master_aes256_secret_key_2026_debian"

# Emergency Non-LDAP Fallback Administrator Account (used if LDAP connection fails)
FALLBACK_ADMIN_ENABLED=${cfg.fallbackAdminEnabled !== false ? 'true' : 'false'}
FALLBACK_ADMIN_USER="${cfg.fallbackAdminUsername || 'eopadmin'}"
`
  },

  // 15. .env
  {
    name: '.env',
    path: '.env',
    description: 'Production environment variables file automatically written and synchronized by setup.php with live database and system credentials.',
    category: 'config',
    generateContent: (cfg) => `# ==============================================================================
# Exchange Online Protection Anti-Spam Policy Manager - Environment Variables
# Host: Debian Linux | Database: Remote MariaDB | Auth: Active Directory LDAP
# Automatically written and synchronized by setup.php
# ==============================================================================

# Remote MariaDB Database Configuration
DB_HOST="${cfg.dbHost}"
DB_PORT=${cfg.dbPort}
DB_NAME="${cfg.dbName}"
DB_USER="${cfg.dbUser}"
DB_PASS="${cfg.dbPass}"
DB_CHARSET="utf8mb4"

# Microsoft Active Directory (LDAP) Settings
LDAP_PROTOCOL="${cfg.ldapProtocol || 'ldap'}"
LDAP_HOST="${cfg.ldapHost}"
LDAP_PORT=${cfg.ldapPort}
LDAP_USE_SSL=${cfg.ldapUseSsl ? 'true' : 'false'}
LDAP_USE_TLS=${cfg.ldapUseTls ? 'true' : 'false'}
LDAP_BASE_DN="${cfg.ldapBaseDn}"
LDAP_AUTHORIZED_GROUP_DN="${cfg.ldapGroupDn}"
LDAP_BIND_DN="${cfg.ldapBindDn}"
LDAP_BIND_PASSWORD="${cfg.ldapBindPass}"

# Microsoft 365 Exchange Online Protection Settings
M365_TENANT_ID="${cfg.tenantId}"
M365_CLIENT_ID="${cfg.clientId}"
M365_CERT_THUMBPRINT="${cfg.certificateThumbprint}"
M365_ORGANIZATION="${cfg.organization || 'corp.example.com'}"
EOP_POLICY_NAME="${cfg.defaultPolicyName}"
EOP_POLICY_GUID="${cfg.defaultPolicyGuid || ''}"

# Master key for AES-256-GCM encryption of private key passwords stored in database
AUTH_MASTER_ENCRYPTION_KEY="eop_master_aes256_secret_key_2026_debian"
APP_URL="${cfg.appUrl || 'https://eop.corp.example.com'}"
`
  },

  // 16. README.md
  {
    name: 'README.md',
    path: 'README.md',
    description: 'Comprehensive installation, remote MariaDB grant guide, Active Directory LDAP troubleshooting, and PowerShell automation manual.',
    category: 'debian',
    generateContent: (cfg) => `# Exchange Online Protection Anti-Spam Policy Manager
**Debian Linux &bull; PHP 8 &bull; Remote MariaDB &bull; Active Directory LDAP Auth &bull; Private Key CBA &bull; Dark Mode**

This application provides a centralized, authenticated web interface to manage **Allowed Senders**, **Blocked Senders**, **Allowed Domains**, and **Blocked Domains** for Microsoft Exchange Online Protection (EOP) anti-spam policies.

---

## Initial Run Setup Routine (setup.php)
The application includes a standard page-by-page setup wizard that runs during first deployment:
1. **Requirements & Prerequisites**: Verifies PHP 8.1+, PDO MySQL, OpenSSL, and LDAP extensions.
2. **Database Connection & Auto-Population**: Collects MariaDB host, user, password, tests connection, and populates all 9 required schema tables.
3. **Active Directory / OpenLDAP**: Prompts for Domain Controller host, port, protocol (Plain LDAP port 389, LDAPS port 636, or StartTLS), Base DN, Authorized Group DN, and bind credentials.
4. **Exchange Online Protection (EOP)**: Prompts for Tenant ID, Client App ID, Certificate Thumbprint, Organization Domain, Policy Name, and RSA Private Key with AES-256 passphrase.
5. **Review & Permanent Lock**: Reviews all parameters, records completion in MariaDB \`eop_setup_lock\` table, generates filesystem \`installed.lock\`, and creates \`config.php\`.
   - **Strict Re-run Prevention**: Once locked, \`setup.php\` immediately responds with **403 Forbidden** and cannot be executed again.

---

## Key Architecture & Features

1. **Individual Table Per List in Remote MariaDB**:
   - \`eop_allowed_senders\` (columns: \`id\`, \`policy_name\`, \`sender_email\`, \`note\`, \`added_by\`, \`created_at\`, \`updated_at\`)
   - \`eop_blocked_senders\` (columns: \`id\`, \`policy_name\`, \`sender_email\`, \`note\`, \`added_by\`, \`created_at\`, \`updated_at\`)
   - \`eop_allowed_domains\` (columns: \`id\`, \`policy_name\`, \`domain_name\`, \`note\`, \`added_by\`, \`created_at\`, \`updated_at\`)
   - \`eop_blocked_domains\` (columns: \`id\`, \`policy_name\`, \`domain_name\`, \`note\`, \`added_by\`, \`created_at\`, \`updated_at\`)
   - \`eop_ldap_config\` (**Database-Stored LDAP Connection Table**: stores \`host\`, \`port\`, \`protocol\`, \`base_dn\`, \`authorized_group_dn\`, \`bind_dn\`, \`bind_password\`, \`is_active\`, etc. dynamically queried at runtime)
   - \`eop_auth_config\` (**Database-Stored Private Key & Credentials Table**: stores uploaded private key PEM, AES-256-GCM encrypted passphrase, certificate thumbprint, tenant ID, and client ID for Exchange Online App-Only Certificate-Based Authentication)
   - Plus \`eop_audit_log\` (tracks every user addition, deletion, timestamp, and IP)
   - Plus \`eop_policies\` (stores policy metadata and last sync status)

2. **Unified Configuration Page**:
   - **Exchange Online Private Key Management**: Upload private key files (\`.pem\`, \`.key\`, \`.pfx\`) or paste PEM text, specify passphrase (automatically encrypted using AES-256-GCM before writing to the database), and configure Azure AD Tenant ID, Client ID, and Certificate Thumbprint.
   - **LDAP Settings Modification**: View and edit LDAP host, port, protocol (Plain LDAP port 389 / LDAPS 636 / StartTLS), Base DN, Authorized Group DN, Service Account Bind DN, and Bind Password for LDAP authorization.
   - Real-time connection testing for both Exchange Online certificate signing and Active Directory LDAP authorization.

3. **Active Directory LDAP Connection Stored in Database (LDAPS Not Required)**:
   - **Database-Stored Configuration**: LDAP host, port, protocol, Base DN, Group DN, Bind DN, and Bind Password are stored directly in the MariaDB table \`eop_ldap_config\` and can be viewed or updated via the Web UI.
   - **Bind Password Authorization**: Securely authenticates using the service account Bind DN and Bind Password to query group membership and authorize administrative access.
   - **Plain LDAP (port 389) is supported out of the box**: LDAPS is **not required**. Connects directly to any Windows Domain Controller without certificate hassles.
   - Also supports **LDAPS (port 636)** and **StartTLS (port 389)** if desired.
   - Enforces access control via **Group Distinguished Name (Group DN)**:
     \`${cfg.ldapGroupDn}\`
   - Supports **nested/recursive Active Directory groups** using LDAP matching rule OID \`1.2.840.113556.1.4.1941\` (\`LDAP_MATCHING_RULE_IN_CHAIN\`).

4. **Exchange Online Protection Certificate Sync Engine (Cron Pull-Only vs Manual Push All)**:
   - **Scheduled Cron Daemon (Pull Only)**: The Linux crontab runner (\`cron-sync.php --action=pull\`) targets the **default policy configured in the Setup Wizard** (\`${cfg.defaultPolicyName}\`) and is strictly limited to pulling changes from Exchange Online into MariaDB via \`Get-HostedContentFilterPolicy\`. It **never pushes** or overwrites Microsoft 365 automatically:
     \`\`\`powershell
     # Scheduled Cron: Pull remote changes from Microsoft 365 into MariaDB
     Get-HostedContentFilterPolicy -Identity "${cfg.defaultPolicyName}"
     \`\`\`
   - **Manual Admin Push All**: Pushing local MariaDB entries to Microsoft 365 is triggered on-demand via the **"Push All Changes to EOP"** action button. This pushes all pending additions and removals across all 4 tables (\`eop_allowed_senders\`, \`eop_blocked_senders\`, \`eop_allowed_domains\`, \`eop_blocked_domains\`) and policies simultaneously with a detailed list-by-list result summary:
     \`\`\`powershell
     # Manual Admin Push All: Applies all 4 MariaDB tables to Exchange Online
     Connect-ExchangeOnline -AppId "${cfg.clientId}" -CertificateThumbprint "${cfg.certificateThumbprint}" -Organization "${cfg.organization || 'corp.example.com'}"
     Set-HostedContentFilterPolicy -Identity "${cfg.defaultPolicyName}" \\
       -AllowedSenders @(...) \\
       -BlockedSenders @(...) \\
       -AllowedSenderDomains @(...) \\
       -BlockedSenderDomains @(...)
     \`\`\`

5. **Split Smart Sorter (Allowed & Blocked)**:
   - **Smart Sort Allowed**: Paste mixed text of email addresses and domain names to automatically route valid emails to Allowed Senders and domain names to Allowed Domains.
   - **Smart Sort Blocked**: Paste mixed text of email addresses and domain names to automatically route valid emails to Blocked Senders and domain names to Blocked Domains.
   - Live syntax validation, real-time duplicate detection against active policy tables, and preview badge counters before committing.

6. **Auto-Dismiss Notification Banners & Staged Pending Strips**:
   - **Global Notification Banner**: Status notifications appearing between toolbar buttons and list tables automatically dismiss after 5 seconds with a smooth animation and instant manual dismiss button.
   - **Staged Pending Changes Notice Strip**: Summarizes staged modifications waiting across all 4 tables and automatically dismisses after 6 seconds while persistent action bar badges maintain visibility.

---

## Project File Structure & Inventory

\`\`\`text
eop-antispam-php-mariadb/
├── config.php            # Primary application configuration (DB, LDAP, Policy options)
├── database.php          # PDO database wrapper & individual table CRUD operations
├── ldap.php              # Active Directory LDAP Group DN authentication engine
├── functions.php         # CSRF verification, input sanitization, and helper utilities
├── schema.sql            # MariaDB database table definitions & 9-table schema
├── schema-update.sql     # Idempotent upgrade script for existing installations
├── index.php             # Main management dashboard (Dark mode, tables, cards, modal UI)
├── setup.php             # 5-step initial run setup wizard with permanent lock
├── login.php             # Active Directory LDAP authentication portal (Dark mode)
├── logout.php            # Session termination & security cleanup
├── actions.php           # REST-style handler for add, delete, import, export, and sync
├── sync-exchange.ps1     # Linux PowerShell sync automation script (Pull & Push modes)
├── cron-sync.php         # Scheduled Pull-Only background CLI sync daemon
├── nginx.conf            # Hardened NGINX Server Block configuration
├── .env.example          # Environment variable template
└── README.md             # Complete technical and deployment documentation
\`\`\`

---

## System Requirements

- **Operating System**: Debian 12 (Bookworm) or Debian 13 (Trixie) (or Ubuntu 22.04/24.04 LTS)
- **Web Server**: NGINX 1.18+ with FastCGI / PHP-FPM
- **PHP**: PHP 8.1, 8.2, or 8.3 with \`php-fpm\`, \`php-cli\`, \`php-mysql\` (PDO), \`php-ldap\`, \`php-curl\`, \`php-mbstring\`, \`php-xml\`, \`php-zip\`, \`php-openssl\`
- **Database Server**: Remote MariaDB 10.5+ / 10.6+ / 10.11+ LTS or MySQL 8.0+ reachable on TCP port 3306
- **Directory Services**: Active Directory Domain Services with standard LDAP (Port 389 - plain LDAP supported, no certs required) or LDAPS (Port 636) / StartTLS, plus authorized Service Account Bind DN & Bind Password
- **Microsoft 365**: Entra ID App Registration with \`Exchange.ManageAsApp\` application permission, RSA certificate & private key for Certificate-Based Authentication (CBA), PowerShell 7.2+ (\`pwsh\`), and \`ExchangeOnlineManagement\` 3.0+ module
- **Client**: Any modern web browser with HTML5 and JavaScript enabled (Chrome, Edge, Firefox, Safari)

---

## Certificate Generation & Management Guide

This solution uses two distinct certificates:
1. **Exchange Online CBA Certificate**: Used by \`Connect-ExchangeOnline\` for secretless app-only authentication.
2. **NGINX HTTPS SSL Certificate**: Used to secure browser sessions on Debian (port 443).

### Generating Exchange Online CBA Certificate

#### On Linux / Debian (OpenSSL):
\`\`\`bash
# 1. Create cert directory:
mkdir -p ~/eop-certs && cd ~/eop-certs

# 2. Generate RSA 2048-bit key with AES passphrase:
openssl genrsa -aes256 -passout pass:"${cfg.keyPassword || 'YourSecurePassphrase'}" -out eop-cert-private.key 2048

# 3. Generate self-signed public certificate (valid 2 years):
openssl req -new -x509 -key eop-cert-private.key -passin pass:"${cfg.keyPassword || 'YourSecurePassphrase'}" \\
  -days 730 -out eop-cert-public.crt \\
  -subj "/CN=EOP Anti-Spam Policy Manager/O=${cfg.organization || 'YourOrganization'}"

# 4. Extract SHA-1 thumbprint for App Registration:
openssl x509 -in eop-cert-public.crt -noout -fingerprint -sha1 | tr -d ':' | sed 's/SHA1 Fingerprint=//'

# 5. Upload eop-cert-public.crt to Microsoft Entra ID:
# Entra Admin Center -> App registrations -> Your App -> Certificates & secrets -> Upload certificate
\`\`\`

#### On Windows (PowerShell):
\`\`\`powershell
$cert = New-SelfSignedCertificate -CertStoreLocation "Cert:\\CurrentUser\\My" \`
  -Subject "CN=EOP Anti-Spam Policy Manager" -KeySpec Signature -KeyLength 2048 \`
  -KeyExportPolicy Exportable -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(2)

Export-Certificate -Cert $cert -FilePath ".\\eop-cert-public.cer"
$cert.Thumbprint
\`\`\`

### Generating NGINX HTTPS SSL Certificate

#### Let's Encrypt (Automated Production HTTPS):
\`\`\`bash
sudo apt update && sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d ${cfg.appUrl.replace('https://', '').replace('http://', '').split('/')[0]}
\`\`\`

#### OpenSSL Self-Signed (Internal LAN / Testing):
\`\`\`bash
sudo openssl req -x509 -nodes -days 730 -newkey rsa:2048 \\
  -keyout /etc/ssl/private/ssl-cert-snakeoil.key \\
  -out /etc/ssl/certs/ssl-cert-snakeoil.pem \\
  -subj "/CN=${cfg.appUrl.replace('https://', '').replace('http://', '').split('/')[0]}/O=Enterprise IT"
sudo chmod 600 /etc/ssl/private/ssl-cert-snakeoil.key
sudo systemctl reload nginx
\`\`\`

---

## Quick Start on Debian Linux

### Step 1: Initialize Database on Remote MariaDB Server
On your remote MariaDB server (\`${cfg.dbHost}\`), run the \`schema.sql\` file:
\`\`\`bash
mariadb -u root -p < schema.sql
\`\`\`

> **Upgrading an existing installation?** Do not re-run \`schema.sql\` against a
> populated database. Run \`schema-update.sql\` instead. It is idempotent, so it is
> safe to run more than once, and it adds \`eop_auth_config.pkcs12_bundle\` (required
> for PKCS#12 certificate authentication), renames \`private_key_pem\` to
> \`private_key\`, widens the auth identifier columns, relaxes the secret columns to
> nullable, adds the missing auth indexes, and creates \`eop_sync_confirmations\`.
> It also deactivates the placeholder auth row that older \`schema.sql\` versions
> seeded with \`is_active = 1\`.
> \`\`\`bash
> mariadb -u root -p < schema-update.sql
> \`\`\`

Grant remote access to your Debian server IP:
\`\`\`sql
CREATE USER IF NOT EXISTS '${cfg.dbUser}'@'YOUR_DEBIAN_IP' IDENTIFIED BY '${cfg.dbPass}';
GRANT ALL PRIVILEGES ON \`${cfg.dbName}\`.* TO '${cfg.dbUser}'@'YOUR_DEBIAN_IP';
FLUSH PRIVILEGES;
\`\`\`

### Step 2: Install Packages on Debian Server
Install NGINX, PHP-FPM, PHP modules, Active Directory LDAP utilities, and MariaDB client:
\`\`\`bash
sudo apt update && sudo apt install -y \
    nginx php-fpm php-cli php-ldap php-mysql php-curl php-mbstring php-xml php-zip \
    mariadb-client ldap-utils curl wget git
\`\`\`

### Step 3: Deploy Application Files & Set Permissions
Extract the project archive to \`/var/www/eop-antispam\` and apply secure permissions:
\`\`\`bash
sudo mkdir -p /var/www/eop-antispam
sudo cp -r ./* /var/www/eop-antispam/
sudo chown -R www-data:www-data /var/www/eop-antispam
sudo find /var/www/eop-antispam -type d -exec chmod 750 {} \\;
sudo find /var/www/eop-antispam -type f -exec chmod 640 {} \\;
\`\`\`

### Step 4: Configure NGINX Server Block

#### Option A: Dedicated Server (Only Site on Server - Recommended)
When configuring this server to host only this application, the generated \`nginx.conf\` uses \`default_server\` and the \`_\` catch-all hostname. Remove the default Debian welcome site:
\`\`\`bash
sudo cp /var/www/eop-antispam/nginx.conf /etc/nginx/sites-available/eop-antispam.conf
sudo ln -sf /etc/nginx/sites-available/eop-antispam.conf /etc/nginx/sites-enabled/
# Remove default site so this application handles all server traffic:
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart php*-fpm || sudo systemctl restart php-fpm
sudo systemctl restart nginx
\`\`\`

#### Option B: Shared Server (Co-hosted with Other Sites)
If this Debian server hosts other websites, do not remove the default site or use \`default_server\`. Set \`isOnlySiteOnServer\` to false in the Configuration Generator so NGINX matches strictly by domain name:
\`\`\`bash
sudo cp /var/www/eop-antispam/nginx.conf /etc/nginx/sites-available/eop-antispam.conf
sudo ln -sf /etc/nginx/sites-available/eop-antispam.conf /etc/nginx/sites-enabled/
# Keep /etc/nginx/sites-enabled/default and other virtual host configs intact!
sudo nginx -t
sudo systemctl restart php*-fpm || sudo systemctl restart php-fpm
sudo systemctl restart nginx
\`\`\`

### Step 5: Active Directory LDAP Configuration
Because **plain LDAP (port 389)** is supported, you do **not** need to install or configure certificates on Debian!
If your organization requires LDAPS (port 636) with an internal enterprise CA:
Add \`TLS_REQCERT allow\` to \`/etc/ldap/ldap.conf\` and restart PHP-FPM and NGINX (\`sudo systemctl restart php-fpm nginx\`).

### Step 6: Login & Manage
Navigate to \`https://${cfg.appUrl.replace('https://', '')}\` and sign in with any Active Directory account belonging to:
\`${cfg.ldapGroupDn}\`
Toggle between Dark Mode and Light Mode at any time using the moon/sun icon in the top header.

---

## Contributors & Credits

- **Shaun Thomas McCloud** - Creator & Lead Maintainer (<shaun.thomas.mccloud@gmail.com>)
- **AI Studio** - Co-Contributor
`
  }
];
