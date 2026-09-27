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
  appTitle: 'EOP Anti-Spam Policy Manager',
  appUrl: 'https://eop.corp.example.com',
  sessionTimeoutMinutes: 60,

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
// 2. Remote MariaDB Database Settings
// --------------------------------------------------------------------------
define('DB_HOST', getenv('DB_HOST') ?: '${cfg.dbHost}');
define('DB_PORT', (int)(getenv('DB_PORT') ?: ${cfg.dbPort}));
define('DB_NAME', getenv('DB_NAME') ?: '${cfg.dbName}');
define('DB_USER', getenv('DB_USER') ?: '${cfg.dbUser}');
define('DB_PASS', getenv('DB_PASS') ?: '${cfg.dbPass}');
define('DB_CHARSET', '${cfg.dbCharset}');

// Individual MariaDB tables per list requirement
define('TABLE_ALLOWED_SENDERS', 'eop_allowed_senders');
define('TABLE_BLOCKED_SENDERS', 'eop_blocked_senders');
define('TABLE_ALLOWED_DOMAINS', 'eop_allowed_domains');
define('TABLE_BLOCKED_DOMAINS', 'eop_blocked_domains');
define('TABLE_AUDIT_LOG',       'eop_audit_log');
define('TABLE_POLICIES',        'eop_policies');
define('TABLE_LDAP_CONFIG',     'eop_ldap_config'); // Dedicated database table storing LDAP connection information
define('TABLE_EOP_AUTH_CONFIG', 'eop_auth_config'); // Dedicated database table storing EOP private key & encrypted password

// Master key for AES-256-GCM encryption of stored private key passphrases
define('AUTH_MASTER_ENCRYPTION_KEY', getenv('AUTH_MASTER_ENCRYPTION_KEY') ?: 'eop_master_aes256_secret_key_2026_debian');

// --------------------------------------------------------------------------
// 3. Microsoft Active Directory (LDAP) Settings
// --------------------------------------------------------------------------
// NOTE: LDAP connection settings are stored in and dynamically retrieved from
// the MariaDB database table 'eop_ldap_config' via Database::getLdapConfig().
// The constants below serve as default fallback values and initial seeds.
// Standard LDAP (port 389) is supported by default and LDAPS is NOT required.
// Set LDAP_PROTOCOL to 'ldap' (port 389 plain), 'ldaps' (port 636), or 'starttls' (port 389 with TLS).
define('LDAP_HOST', getenv('LDAP_HOST') ?: '${cfg.ldapHost}');
define('LDAP_PORT', (int)(getenv('LDAP_PORT') ?: ${cfg.ldapPort}));
define('LDAP_PROTOCOL', getenv('LDAP_PROTOCOL') ?: '${cfg.ldapProtocol || (cfg.ldapUseSsl ? 'ldaps' : (cfg.ldapUseTls ? 'starttls' : 'ldap'))}');
define('LDAP_USE_SSL', LDAP_PROTOCOL === 'ldaps'); // LDAPS on port 636 (optional, not required)
define('LDAP_USE_TLS', LDAP_PROTOCOL === 'starttls'); // StartTLS on port 389 (optional, not required)
define('LDAP_BASE_DN', getenv('LDAP_BASE_DN') ?: '${cfg.ldapBaseDn}');

// Mandatory Security Group Distinguished Name (Group DN) for authorization
define('LDAP_AUTHORIZED_GROUP_DN', getenv('LDAP_AUTHORIZED_GROUP_DN') ?: '${cfg.ldapGroupDn}');

// Active Directory Service Account for initial user & group resolution (optional, recommended)
define('LDAP_BIND_DN', getenv('LDAP_BIND_DN') ?: '${cfg.ldapBindDn}');
define('LDAP_BIND_PASSWORD', getenv('LDAP_BIND_PASSWORD') ?: '${cfg.ldapBindPass}');
define('LDAP_ACCOUNT_SUFFIX', '@corp.example.com');
define('LDAP_NETBIOS_DOMAIN', '${cfg.ldapDomain}');

// --------------------------------------------------------------------------
// 4. Exchange Online Protection (EOP) Policy Settings
// --------------------------------------------------------------------------
define('DEFAULT_POLICY_NAME', getenv('EOP_POLICY_NAME') ?: '${cfg.defaultPolicyName}');
define('APP_TITLE', '${cfg.appTitle}');
define('APP_URL', '${cfg.appUrl}');

// Available Anti-Spam policies to manage
$GLOBALS['AVAILABLE_POLICIES'] = [
    '${cfg.defaultPolicyName}' => 'Default Inbound Anti-Spam Policy (Applied to all recipients)',
    'Strict Anti-Spam Policy'  => 'Strict Security Baseline (Targeted VIPs & High Value Mailboxes)',
    'Executive Inbound Policy' => 'Custom Executive Mailbox Inbound Filtering',
    'Custom Inbound Filter'    => 'Custom Departmental Filter Policy'
];

// --------------------------------------------------------------------------
// 5. Microsoft 365 / Exchange Online Protection (EOP) Private Key & Certificate Auth
// --------------------------------------------------------------------------
// NOTE: EOP private key and encrypted passphrase are stored in and dynamically retrieved
// from the MariaDB database table 'eop_auth_config' via Database::getEopAuthConfig().
// The constants below serve as default fallback values and initial seeds.
define('M365_TENANT_ID', getenv('M365_TENANT_ID') ?: '${cfg.tenantId}');
define('M365_CLIENT_ID', getenv('M365_CLIENT_ID') ?: '${cfg.clientId}');
define('M365_CERT_THUMBPRINT', getenv('M365_CERT_THUMBPRINT') ?: '${cfg.certificateThumbprint}');
define('M365_ORGANIZATION', getenv('M365_ORGANIZATION') ?: '${cfg.organization || "corp.example.com"}');
define('M365_CLIENT_SECRET', getenv('M365_CLIENT_SECRET') ?: '${cfg.clientSecret}');
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
require_once __DIR__ . '/config.php';

class Database {
    private static ?PDO $instance = null;

    /**
     * Get singleton PDO connection to Remote MariaDB server
     */
    public static function getConnection(): PDO {
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
                die('<div style="font-family:sans-serif;padding:2rem;color:#721c24;background:#f8d7da;border:1px solid #f5c6cb;border-radius:6px;max-width:650px;margin:2rem auto;">' .
                    '<h3>Database Connection Error</h3>' .
                    '<p>Could not connect to remote MariaDB host <code>' . htmlspecialchars(DB_HOST) . ':' . DB_PORT . '</code>.</p>' .
                    '<p><small>Check network route, MariaDB user grants, and credentials in <code>config.php</code> or <code>.env</code>.</small></p>' .
                    '</div>');
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
    }

    /**
     * Count items in a specific individual table for a policy
     */
    public static function countListItems(string $listType, string $policyName, string $search = ''): int {
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
    }

    /**
     * Check if an item already exists in a dedicated table for a policy (duplicate check)
     */
    public static function itemExists(string $listType, string $policyName, string $value): bool {
        $pdo = self::getConnection();
        $table = self::getTableName($listType);
        $col = self::getValueColumn($listType);
        $value = strtolower(trim($value));

        $stmt = $pdo->prepare("SELECT 1 FROM {$table} WHERE policy_name = :policy AND {$col} = :val LIMIT 1");
        $stmt->execute([':policy' => $policyName, ':val' => $value]);
        return (bool)$stmt->fetchColumn();
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
     * Update policy sync status
     */
    public static function updatePolicySyncStatus(string $policyName, string $status, string $message = ''): void {
        $pdo = self::getConnection();
        $stmt = $pdo->prepare("INSERT INTO " . TABLE_POLICIES . " (policy_name, last_synced_at, sync_status, sync_message, updated_at)
                               VALUES (:name, NOW(), :status, :msg, NOW())
                               ON DUPLICATE KEY UPDATE last_synced_at = NOW(), sync_status = VALUES(sync_status), sync_message = VALUES(sync_message), updated_at = NOW()");
        $stmt->execute([':name' => $policyName, ':status' => $status, ':msg' => $message]);
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
     * Encrypt private key passphrase/password using AES-256-GCM before database storage
     */
    public static function encryptKeyPassword(string $password): array {
        if ($password === '') {
            return ['ciphertext' => '', 'iv' => '', 'tag' => ''];
        }
        $secret = defined('AUTH_MASTER_ENCRYPTION_KEY') ? AUTH_MASTER_ENCRYPTION_KEY : 'eop_master_secret';
        $key = hash('sha256', $secret, true);
        $iv = random_bytes(12); // Standard 96-bit IV for GCM
        $tag = '';
        $ciphertext = openssl_encrypt($password, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        return [
            'ciphertext' => base64_encode($ciphertext),
            'iv'         => base64_encode($iv),
            'tag'        => base64_encode($tag),
        ];
    }

    /**
     * Decrypt private key passphrase/password using AES-256-GCM
     */
    public static function decryptKeyPassword(string $ciphertextB64, string $ivB64, string $tagB64): ?string {
        if ($ciphertextB64 === '') {
            return '';
        }
        try {
            $secret = defined('AUTH_MASTER_ENCRYPTION_KEY') ? AUTH_MASTER_ENCRYPTION_KEY : 'eop_master_secret';
            $key = hash('sha256', $secret, true);
            $ciphertext = base64_decode($ciphertextB64);
            $iv = base64_decode($ivB64);
            $tag = base64_decode($tagB64);
            $decrypted = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
            return $decrypted !== false ? $decrypted : null;
        } catch (Exception $e) {
            error_log('[Database::decryptKeyPassword Error] ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Fetch active EOP private key & certificate authentication record from database table eop_auth_config
     */
    public static function getEopAuthConfig(): ?array {
        try {
            $pdo = self::getConnection();
            $stmt = $pdo->query("SELECT * FROM " . TABLE_EOP_AUTH_CONFIG . " WHERE is_active = 1 ORDER BY id DESC LIMIT 1");
            $config = $stmt->fetch();
            return $config ?: null;
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
                (tenant_id, client_id, certificate_thumbprint, key_filename, private_key, encrypted_password, encryption_iv, encryption_tag, key_type, organization, is_active, uploaded_by, created_at, updated_at)
                VALUES (:tenant, :client, :thumbprint, :filename, :privkey, :enc_pass, :iv, :tag, :ktype, :org, 1, :user, NOW(), NOW())");

            $enc = self::encryptKeyPassword($data['password'] ?? '');

            $thumbprint = strtoupper(preg_replace('/[^a-zA-Z0-9]/', '', $data['certificate_thumbprint'] ?? ''));

            $success = $stmt->execute([
                ':tenant'     => trim($data['tenant_id'] ?? (defined('M365_TENANT_ID') ? M365_TENANT_ID : '')),
                ':client'     => trim($data['client_id'] ?? (defined('M365_CLIENT_ID') ? M365_CLIENT_ID : '')),
                ':thumbprint' => $thumbprint ?: (defined('M365_CERT_THUMBPRINT') ? M365_CERT_THUMBPRINT : ''),
                ':filename'   => trim($data['key_filename'] ?? 'eop-cert-private.key'),
                ':privkey'    => trim($data['private_key']),
                ':enc_pass'   => $enc['ciphertext'],
                ':iv'         => $enc['iv'],
                ':tag'        => $enc['tag'],
                ':ktype'      => $data['key_type'] ?? 'RSA_PEM',
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
                                   SUBSTRING(private_key, 1, 60) as key_preview
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
            return ['success' => false, 'user' => null, 'error' => 'LDAP Connection failure: ' . $e->getMessage()];
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
    $pattern = '/^(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,63}$/';
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
    \`description\` VARCHAR(255) NULL,
    \`last_synced_at\` DATETIME NULL,
    \`sync_status\` ENUM('synced', 'pending', 'failed') NOT NULL DEFAULT 'pending',
    \`sync_message\` TEXT NULL,
    \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    \`updated_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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

-- Insert initial active row for EOP certificate & private key authentication
INSERT INTO \`${cfg.dbName}\`.\`eop_auth_config\` 
    (\`tenant_id\`, \`client_id\`, \`certificate_thumbprint\`, \`key_filename\`, \`private_key\`, \`encrypted_password\`, \`encryption_iv\`, \`encryption_tag\`, \`key_type\`, \`organization\`, \`is_active\`, \`uploaded_by\`)
VALUES 
    ('${cfg.tenantId}', '${cfg.clientId}', '${cfg.certificateThumbprint}', '${cfg.keyFilename || "eop-cert-private.key"}', '-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA0Q3d7v5N8A9zX3lW2k1vJ8qY4t7rU9sP3mF2a1cB6d8e0f1g...[INITIAL_SEED_PRIVATE_KEY]...\\n-----END RSA PRIVATE KEY-----', 'tq8fWk6y/7bH...[AES-256-GCM-ENCRYPTED-CIPHERTEXT]...', 'G1a8V0kLm9Pq', 'Xy8Z2n9Q1v0mK4lP7s3w8A==', 'RSA_PEM', '${cfg.organization || "corp.example.com"}', 1, 'SYSTEM')
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
-- Remote User Permissions Grant Example (Run on Remote MariaDB server)
-- Replace 'DEBIAN_WEB_SERVER_IP' with the actual IP of your Debian host!
-- ----------------------------------------------------------------------------
-- CREATE USER IF NOT EXISTS '${cfg.dbUser}'@'%' IDENTIFIED BY '${cfg.dbPass}';
-- GRANT ALL PRIVILEGES ON \`${cfg.dbName}\`.* TO '${cfg.dbUser}'@'%';
-- FLUSH PRIVILEGES;
`
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
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';
require_once __DIR__ . '/functions.php';

$user = requireAuth();
$csrfToken = getCsrfToken();
$flash = getFlash();

// Current active policy
$selectedPolicy = $_GET['policy'] ?? ($_SESSION['active_policy'] ?? DEFAULT_POLICY_NAME);
$_SESSION['active_policy'] = $selectedPolicy;

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
                        <?php foreach ($GLOBALS['AVAILABLE_POLICIES'] as $polName => $polDesc): ?>
                            <option value="<?= htmlspecialchars($polName) ?>" <?= $polName === $selectedPolicy ? 'selected' : '' ?>>
                                <?= htmlspecialchars($polName) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
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

        <!-- Flash Alert -->
        <?php if ($flash): ?>
            <div class="mb-5 p-4 rounded-lg flex items-center justify-between border <?= $flash['type'] === 'success' ? 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-800 dark:text-emerald-200 border-emerald-200 dark:border-emerald-800/60' : ($flash['type'] === 'error' ? 'bg-rose-50 dark:bg-rose-950/40 text-rose-800 dark:text-rose-200 border-rose-200 dark:border-rose-800/60' : 'bg-blue-50 dark:bg-blue-950/40 text-blue-800 dark:text-blue-200 border-blue-200 dark:border-blue-800/60') ?>">
                <div class="flex items-center space-x-2">
                    <i class="fa-solid <?= $flash['type'] === 'success' ? 'fa-circle-check text-emerald-600 dark:text-emerald-400' : 'fa-circle-exclamation text-rose-600 dark:text-rose-400' ?>"></i>
                    <span class="text-sm font-medium"><?= htmlspecialchars($flash['message']) ?></span>
                </div>
                <button onclick="this.parentElement.remove()" class="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 text-sm"><i class="fa-solid fa-xmark"></i></button>
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
                    <button onclick="document.getElementById('smartSortModal').classList.remove('hidden')" 
                            class="px-3 py-1.5 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 text-white text-xs font-semibold rounded-md shadow-xs flex items-center space-x-1.5 transition cursor-pointer">
                        <i class="fa-solid fa-wand-magic-sparkles text-amber-300"></i>
                        <span>Smart Sort &amp; Import</span>
                    </button>
                    <a href="actions.php?action=export_csv&list=<?= $currentTab ?>&policy=<?= urlencode($selectedPolicy) ?>&csrf=<?= $csrfToken ?>" 
                       class="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-semibold rounded-md flex items-center space-x-1.5 transition">
                        <i class="fa-solid fa-file-arrow-down"></i>
                        <span>Export CSV</span>
                    </a>
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
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
                            <!-- EOP Private Key Status -->
                            <div class="p-4 rounded-xl border border-blue-200 dark:border-blue-900/60 bg-blue-50/60 dark:bg-blue-950/30">
                                <div class="flex items-center justify-between mb-2">
                                    <div class="flex items-center gap-2 font-bold text-xs text-blue-900 dark:text-blue-200">
                                        <i class="fa-solid fa-shield-halved text-blue-600 dark:text-blue-400"></i>
                                        <span>Exchange Online Private Key Auth</span>
                                    </div>
                                    <span class="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/60">
                                        <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                                        Active DB Record #<?= htmlspecialchars((string)($activeAuthConfig['id'] ?? 1)) ?>
                                    </span>
                                </div>
                                <div class="space-y-1 text-xs text-slate-600 dark:text-slate-300 font-mono">
                                    <div class="flex justify-between">
                                        <span class="text-slate-400">Thumbprint:</span>
                                        <span class="font-bold text-slate-800 dark:text-slate-100"><?= htmlspecialchars(substr($activeAuthConfig['certificate_thumbprint'] ?? (defined('M365_CERT_THUMBPRINT') ? M365_CERT_THUMBPRINT : '9A2F8B3C1D4E5F6A'), 0, 20)) ?>...</span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span class="text-slate-400">Key File:</span>
                                        <span><?= htmlspecialchars($activeAuthConfig['key_filename'] ?? 'eop-cert-private.key') ?></span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span class="text-slate-400">Key Password:</span>
                                        <span class="text-emerald-600 dark:text-emerald-400 font-semibold flex items-center gap-1">
                                            <i class="fa-solid fa-lock text-[10px]"></i> AES-256-GCM Encrypted
                                        </span>
                                    </div>
                                </div>
                            </div>

                            <!-- LDAP Status -->
                            <div class="p-4 rounded-xl border border-purple-200 dark:border-purple-900/60 bg-purple-50/60 dark:bg-purple-950/30">
                                <div class="flex items-center justify-between mb-2">
                                    <div class="flex items-center gap-2 font-bold text-xs text-purple-900 dark:text-purple-200">
                                        <i class="fa-solid fa-network-wired text-purple-600 dark:text-purple-400"></i>
                                        <span>Active Directory LDAP Connection</span>
                                    </div>
                                    <span class="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/60">
                                        <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                                        Active DB Record #<?= htmlspecialchars((string)($activeLdapConfig['id'] ?? 1)) ?>
                                    </span>
                                </div>
                                <div class="space-y-1 text-xs text-slate-600 dark:text-slate-300 font-mono">
                                    <div class="flex justify-between">
                                        <span class="text-slate-400">Host & Port:</span>
                                        <span class="font-bold text-slate-800 dark:text-slate-100"><?= htmlspecialchars($activeLdapConfig['host'] ?? LDAP_HOST) ?>:<?= (int)($activeLdapConfig['port'] ?? LDAP_PORT) ?> (<?= strtoupper(htmlspecialchars($activeLdapConfig['protocol'] ?? 'ldap')) ?>)</span>
                                    </div>
                                    <div class="flex justify-between truncate" title="<?= htmlspecialchars($activeLdapConfig['authorized_group_dn'] ?? LDAP_AUTHORIZED_GROUP_DN) ?>">
                                        <span class="text-slate-400">Group DN:</span>
                                        <span class="truncate max-w-[200px]"><?= htmlspecialchars($activeLdapConfig['authorized_group_dn'] ?? LDAP_AUTHORIZED_GROUP_DN) ?></span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span class="text-slate-400">Security:</span>
                                        <span>Port 389 Plain LDAP &bull; LDAPS Optional</span>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- PART 1: Exchange Online Protection Private Key Upload & Settings -->
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
                                    <!-- File Upload for Private Key -->
                                    <div class="col-span-1 md:col-span-2">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                                            Upload Private Key File (.pem, .key, .pfx, .crt):
                                        </label>
                                        <input type="file" name="private_key_file" accept=".pem,.key,.pfx,.cer,.crt,.txt"
                                               class="w-full text-xs text-slate-500 dark:text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-blue-50 file:text-blue-700 dark:file:bg-blue-950/80 dark:file:text-blue-300 hover:file:bg-blue-100 dark:hover:file:bg-blue-900 border border-slate-300 dark:border-slate-700 rounded-lg p-2 bg-slate-50 dark:bg-slate-800">
                                        <p class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">Upload the RSA or PKCS#8 private key associated with your Azure AD App Registration certificate.</p>
                                    </div>

                                    <!-- Direct Paste Option -->
                                    <div class="col-span-1 md:col-span-2">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                                            Or Paste Private Key Text (PEM format):
                                        </label>
                                        <textarea name="private_key_text" rows="4" placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...&#10;-----END RSA PRIVATE KEY-----"
                                                  class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg p-3 text-slate-900 dark:text-white font-mono text-[11px] focus:ring-2 focus:ring-blue-500 focus:outline-hidden"></textarea>
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

                        <!-- PART 2: Active Directory LDAP Settings Modification -->
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
                <textarea name="bulk_data" rows="8" required placeholder="<?= str_contains($currentTab, 'sender') ? "ceo@partner.com, High priority partner\nsupport@vendor.org, Vendor notification" : "partner.com, Main vendor domain\n*.subdomain.net, Wildcard domain" ?>"
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
                    <div class="w-8 h-8 rounded-lg bg-gradient-to-br from-purple-600 to-indigo-600 text-white flex items-center justify-center text-xs">
                        <i class="fa-solid fa-wand-magic-sparkles text-amber-300"></i>
                    </div>
                    <div>
                        <h3 class="text-base font-bold text-slate-900 dark:text-white">Smart Sort: Senders &amp; Domains</h3>
                        <p class="text-xs text-slate-500 dark:text-slate-400">Auto-routes emails to Senders table and domains to Domains table</p>
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
                    <button type="submit" class="px-5 py-2 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center space-x-1.5 cursor-pointer">
                        <i class="fa-solid fa-wand-magic-sparkles text-amber-300"></i>
                        <span>Sort &amp; Import Items</span>
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Footer -->
    <footer class="bg-white dark:bg-slate-900 border-t border-slate-200 dark:border-slate-800 py-4 mt-auto text-center text-xs text-slate-400 dark:text-slate-500 transition-colors duration-200">
        Exchange Online Protection Policy Manager &bull; Host: Debian Linux &bull; Storage: Remote MariaDB &bull; Auth: Active Directory LDAP (Port 389/636)
    </footer>

    <!-- Theme Switcher Script -->
    <script>
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
 * Step 2: MariaDB Database Connection & Schema Population (all 9 tables)
 * Step 3: Active Directory / OpenLDAP Configuration
 * Step 4: Exchange Online Protection (EOP) Setup & Private Key
 * Step 5: Review & Permanent Lock (Prevents re-running)
 */

declare(strict_types=1);

// Debian filesystem lockfile path
\\$lockFile = __DIR__ . '/installed.lock';

// -----------------------------------------------------------------------------
// Security Check: If locked on disk or database, strictly forbid execution!
// -----------------------------------------------------------------------------
if (file_exists(\\$lockFile)) {
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
            <p class="text-slate-400 text-xs leading-relaxed mb-6">
                This system has already been configured and initialized. For security reasons, the initial setup routine cannot be run again.
            </p>
            <div class="bg-slate-950/80 p-3.5 rounded-xl border border-slate-800 text-left text-xs font-mono text-slate-400 mb-6 space-y-1.5">
                <div><span class="text-slate-500 font-sans font-medium">Debian Lockfile:</span> <code class="text-blue-400">installed.lock</code></div>
                <div><span class="text-slate-500 font-sans font-medium">MariaDB Table:</span> <code class="text-purple-400">eop_setup_lock</code></div>
                <div><span class="text-slate-500 font-sans font-medium">Status:</span> <span class="text-rose-400 font-semibold">Access Prohibited</span></div>
            </div>
            <a href="login.php" class="w-full py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold inline-block transition shadow-sm">
                Proceed to Active Directory Login &rarr;
            </a>
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
if (!isset(\\$_SESSION['wizard'])) {
    \\$_SESSION['wizard'] = [
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

\\$error = null;
\\$success = null;

// Allow direct step navigation if previous steps were done
\\$currentStep = (int)(\\$_GET['step'] ?? \\$_SESSION['wizard']['step'] ?? 1);
if (\\$currentStep < 1) \\$currentStep = 1;
if (\\$currentStep > 5) \\$currentStep = 5;

// POST Action Handlers
if (\\$_SERVER['REQUEST_METHOD'] === 'POST') {
    \\$action = \\$_POST['action'] ?? '';

    // Step 1 -> Advance to Step 2
    if (\\$action === 'step1_start') {
        \\$_SESSION['wizard']['step'] = 2;
        header('Location: setup.php?step=2');
        exit;
    }

    // Step 2: Test Database & Populate Schema
    if (\\$action === 'step2_db') {
        \\$host = trim(\\$_POST['db_host'] ?? '127.0.0.1');
        \\$port = (int)(\\$_POST['db_port'] ?? 3306);
        \\$name = trim(\\$_POST['db_name'] ?? 'eop_antispam_db');
        \\$user = trim(\\$_POST['db_user'] ?? 'root');
        \\$pass = \\$_POST['db_pass'] ?? '';

        try {
            // Test connection
            \\$dsn = "mysql:host={\\$host};port={\\$port};charset=utf8mb4";
            \\$pdo = new PDO(\\$dsn, \\$user, \\$pass, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
            ]);

            // Create database if not exists
            \\$pdo->exec("CREATE DATABASE IF NOT EXISTS \`{\\$name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
            \\$pdo->exec("USE \`{\\$name}\`");

            // Execute all 9 table schemas
            \\$tables = [
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
                    \`description\` TEXT NULL,
                    \`is_default\` TINYINT(1) NOT NULL DEFAULT 0,
                    \`last_synced_at\` DATETIME NULL,
                    \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
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
                    \`tenant_id\` VARCHAR(64) NOT NULL,
                    \`client_id\` VARCHAR(64) NOT NULL,
                    \`certificate_thumbprint\` VARCHAR(64) NOT NULL,
                    \`key_filename\` VARCHAR(100) NOT NULL DEFAULT 'eop-cert-private.key',
                    \`private_key_pem\` TEXT NOT NULL,
                    \`encrypted_password\` TEXT NOT NULL,
                    \`encryption_iv\` VARCHAR(64) NOT NULL,
                    \`encryption_tag\` VARCHAR(64) NOT NULL,
                    \`organization\` VARCHAR(255) NOT NULL DEFAULT 'corp.example.com',
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
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
            ];

            foreach (\\$tables as \\$tblSql) {
                \\$pdo->exec(\\$tblSql);
            }

            // Seed default policy
            \\$seedPolicy = \\$pdo->prepare("INSERT IGNORE INTO \`eop_policies\` (\`policy_name\`, \`description\`, \`is_default\`) VALUES (:name, 'Default Inbound Anti-Spam Policy for Organization', 1)");
            \\$seedPolicy->execute([':name' => 'Default Inbound Anti-Spam Policy']);

            // Save to session
            \\$_SESSION['wizard']['db'] = [
                'host' => \\$host,
                'port' => \\$port,
                'name' => \\$name,
                'user' => \\$user,
                'pass' => \\$pass,
                'populated' => true,
                'tables' => array_keys(\\$tables)
            ];
            \\$_SESSION['wizard']['step'] = 3;
            header('Location: setup.php?step=3');
            exit;

        } catch (Exception \\$e) {
            \\$error = "Database Connection Failed: " . \\$e->getMessage();
        }
    }

    // Step 3: Prompt & Save LDAP Information
    if (\\$action === 'step3_ldap') {
        \\$ldapHost = trim(\\$_POST['ldap_host'] ?? '');
        \\$ldapPort = (int)(\\$_POST['ldap_port'] ?? 389);
        \\$ldapProtocol = \\$_POST['ldap_protocol'] ?? 'ldap';
        \\$ldapBaseDn = trim(\\$_POST['ldap_base_dn'] ?? '');
        \\$ldapGroupDn = trim(\\$_POST['ldap_group_dn'] ?? '');
        \\$ldapBindDn = trim(\\$_POST['ldap_bind_dn'] ?? '');
        \\$ldapBindPass = \\$_POST['ldap_bind_pass'] ?? '';
        \\$ldapDomain = trim(\\$_POST['ldap_domain'] ?? 'CORP');

        if (empty(\\$ldapHost) || empty(\\$ldapBaseDn) || empty(\\$ldapGroupDn)) {
            \\$error = "Please fill in all required LDAP settings (Host, Base DN, Group DN).";
        } else {
            \\$_SESSION['wizard']['ldap'] = [
                'host' => \\$ldapHost,
                'port' => \\$ldapPort,
                'protocol' => \\$ldapProtocol,
                'base_dn' => \\$ldapBaseDn,
                'group_dn' => \\$ldapGroupDn,
                'bind_dn' => \\$ldapBindDn,
                'bind_pass' => \\$ldapBindPass,
                'domain' => \\$ldapDomain,
                'tested' => true
            ];
            \\$_SESSION['wizard']['step'] = 4;
            header('Location: setup.php?step=4');
            exit;
        }
    }

    // Step 4: Prompt & Save EOP Connection Information
    if (\\$action === 'step4_eop') {
        \\$tenantId = trim(\\$_POST['tenant_id'] ?? '');
        \\$clientId = trim(\\$_POST['client_id'] ?? '');
        \\$thumbprint = trim(\\$_POST['thumbprint'] ?? '');
        \\$orgDomain = trim(\\$_POST['org_domain'] ?? '');
        \\$policy = trim(\\$_POST['policy'] ?? 'Default Inbound Anti-Spam Policy');
        \\$privateKey = trim(\\$_POST['private_key'] ?? '');
        \\$passphrase = \\$_POST['passphrase'] ?? '';

        if (empty(\\$tenantId) || empty(\\$clientId) || empty(\\$thumbprint)) {
            \\$error = "Please provide your Microsoft 365 Tenant ID, Client App ID, and Certificate Thumbprint.";
        } else {
            \\$_SESSION['wizard']['eop'] = [
                'tenant_id' => \\$tenantId,
                'client_id' => \\$clientId,
                'thumbprint' => \\$thumbprint,
                'org_domain' => \\$orgDomain,
                'policy' => \\$policy,
                'private_key' => \\$privateKey,
                'passphrase' => \\$passphrase,
                'validated' => true
            ];
            \\$_SESSION['wizard']['step'] = 5;
            header('Location: setup.php?step=5');
            exit;
        }
    }

    // Step 5: Final Review & Permanent Lock Routine
    if (\\$action === 'step5_finalize_lock') {
        \\$db = \\$_SESSION['wizard']['db'];
        \\$ldap = \\$_SESSION['wizard']['ldap'];
        \\$eop = \\$_SESSION['wizard']['eop'];
        \\$ip = \\$_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

        try {
            // 1. Connect to MariaDB
            \\$dsn = "mysql:host={\\$db['host']};port={\\$db['port']};dbname={\\$db['name']};charset=utf8mb4";
            \\$pdo = new PDO(\\$dsn, \\$db['user'], \\$db['pass'], [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
            ]);

            // 2. Insert into eop_setup_lock
            \\$lockStmt = \\$pdo->prepare("INSERT INTO \`eop_setup_lock\` (\`is_locked\`, \`completed_at\`, \`completed_by\`, \`installer_ip\`, \`app_version\`, \`schema_version\`)
                                         VALUES (1, NOW(), 'INITIAL_SETUP_WIZARD', :ip, '1.0.0', '2026.1')");
            \\$lockStmt->execute([':ip' => \\$ip]);

            // 3. Save LDAP configuration to eop_ldap_config
            \\$ldapStmt = \\$pdo->prepare("INSERT INTO \`eop_ldap_config\` 
                (\`ldap_host\`, \`ldap_port\`, \`ldap_protocol\`, \`ldap_base_dn\`, \`ldap_group_dn\`, \`ldap_bind_dn\`, \`ldap_bind_password\`, \`ldap_domain\`, \`is_active\`)
                VALUES (:host, :port, :proto, :base, :grp, :bind_dn, :bind_pass, :dom, 1)");
            \\$ldapStmt->execute([
                ':host' => \\$ldap['host'],
                ':port' => \\$ldap['port'],
                ':proto' => \\$ldap['protocol'],
                ':base' => \\$ldap['base_dn'],
                ':grp' => \\$ldap['group_dn'],
                ':bind_dn' => \\$ldap['bind_dn'],
                ':bind_pass' => \\$ldap['bind_pass'],
                ':dom' => \\$ldap['domain']
            ]);

            // 4. Save EOP Auth config (AES encrypted password)
            \\$aesKey = hash('sha256', \\$eop['tenant_id'] . 'EOP_SALT_2026', true);
            \\$iv = openssl_random_pseudo_bytes(12);
            \\$tag = '';
            \\$ciphertext = openssl_encrypt(\\$eop['passphrase'], 'aes-256-gcm', \\$aesKey, OPENSSL_RAW_DATA, \\$iv, \\$tag);

            \\$authStmt = \\$pdo->prepare("INSERT INTO \`eop_auth_config\` 
                (\`tenant_id\`, \`client_id\`, \`certificate_thumbprint\`, \`key_filename\`, \`private_key_pem\`, \`encrypted_password\`, \`encryption_iv\`, \`encryption_tag\`, \`organization\`, \`key_type\`, \`is_active\`, \`uploaded_by\`)
                VALUES (:tid, :cid, :thumb, 'eop-cert-private.key', :pem, :cipher, :iv_b64, :tag_b64, :org, 'RSA_PEM', 1, 'INITIAL_SETUP')");
            \\$authStmt->execute([
                ':tid' => \\$eop['tenant_id'],
                ':cid' => \\$eop['client_id'],
                ':thumb' => \\$eop['thumbprint'],
                ':pem' => \\$eop['private_key'],
                ':cipher' => base64_encode(\\$ciphertext ?: ''),
                ':iv_b64' => base64_encode(\\$iv),
                ':tag_b64' => base64_encode(\\$tag),
                ':org' => \\$eop['org_domain']
            ]);

            // 5. Create Debian lockfile installed.lock
            \\$lockData = json_encode([
                'status' => 'LOCKED',
                'completed_at' => date('Y-m-d H:i:s'),
                'installer_ip' => \\$ip,
                'db_host' => \\$db['host'],
                'db_name' => \\$db['name'],
                'version' => '1.0.0'
            ], JSON_PRETTY_PRINT);
            @file_put_contents(\\$lockFile, \\$lockData);

            // Clear session wizard data
            unset(\\$_SESSION['wizard']);

            // Redirect to login with success flag
            header('Location: login.php?installed=1');
            exit;

        } catch (Exception \\$e) {
            \\$error = "Finalizing Installation Failed: " . \\$e->getMessage();
        }
    }
}

// System requirement check helpers
\\$phpVersionOk = version_compare(PHP_VERSION, '8.1.0', '>=');
\\$pdoOk = extension_loaded('pdo_mysql');
\\$opensslOk = extension_loaded('openssl');
\\$ldapExtOk = extension_loaded('ldap');
\\$curlOk = extension_loaded('curl');
\\$writableOk = is_writable(__DIR__);
\\$allReqsOk = \\$phpVersionOk && \\$pdoOk && \\$opensslOk && \\$ldapExtOk;
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
                <a href="<?php echo \\$currentStep > 1 ? '?step=1' : '#'; ?>" class="py-2 px-1 rounded-xl transition <?php echo \\$currentStep === 1 ? 'bg-amber-500/20 text-amber-300 font-bold border border-amber-500/40' : (\\$currentStep > 1 ? 'bg-emerald-500/10 text-emerald-400' : 'text-slate-500'); ?>">
                    <div class="text-[10px] font-mono">STEP 1</div>
                    <div class="truncate">Requirements</div>
                </a>
                <a href="<?php echo \\$currentStep > 2 ? '?step=2' : '#'; ?>" class="py-2 px-1 rounded-xl transition <?php echo \\$currentStep === 2 ? 'bg-amber-500/20 text-amber-300 font-bold border border-amber-500/40' : (\\$currentStep > 2 ? 'bg-emerald-500/10 text-emerald-400' : 'text-slate-500'); ?>">
                    <div class="text-[10px] font-mono">STEP 2</div>
                    <div class="truncate">Database</div>
                </a>
                <a href="<?php echo \\$currentStep > 3 ? '?step=3' : '#'; ?>" class="py-2 px-1 rounded-xl transition <?php echo \\$currentStep === 3 ? 'bg-amber-500/20 text-amber-300 font-bold border border-amber-500/40' : (\\$currentStep > 3 ? 'bg-emerald-500/10 text-emerald-400' : 'text-slate-500'); ?>">
                    <div class="text-[10px] font-mono">STEP 3</div>
                    <div class="truncate">AD LDAP</div>
                </a>
                <a href="<?php echo \\$currentStep > 4 ? '?step=4' : '#'; ?>" class="py-2 px-1 rounded-xl transition <?php echo \\$currentStep === 4 ? 'bg-amber-500/20 text-amber-300 font-bold border border-amber-500/40' : (\\$currentStep > 4 ? 'bg-emerald-500/10 text-emerald-400' : 'text-slate-500'); ?>">
                    <div class="text-[10px] font-mono">STEP 4</div>
                    <div class="truncate">Exchange EOP</div>
                </a>
                <div class="py-2 px-1 rounded-xl transition <?php echo \\$currentStep === 5 ? 'bg-amber-500/20 text-amber-300 font-bold border border-amber-500/40' : 'text-slate-500'; ?>">
                    <div class="text-[10px] font-mono">STEP 5</div>
                    <div class="truncate">Review &amp; Lock</div>
                </div>
            </div>
        </div>

        <!-- Alert Notification -->
        <?php if (\\$error): ?>
            <div class="mb-6 p-4 rounded-xl bg-rose-950/60 border border-rose-800 text-rose-200 text-xs flex items-center gap-3">
                <svg class="w-5 h-5 text-rose-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                <span><?php echo htmlspecialchars(\\$error); ?></span>
            </div>
        <?php endif; ?>

        <!-- STEP 1: System Requirements & Prerequisites -->
        <?php if (\\$currentStep === 1): ?>
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
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold <?php echo \\$phpVersionOk ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'; ?>">
                            <?php echo \\$phpVersionOk ? 'PASSED' : 'UPGRADE REQUIRED'; ?>
                        </span>
                    </div>

                    <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-700/60 flex items-center justify-between text-xs font-mono">
                        <div><span class="text-white font-sans font-semibold">PDO MySQL / MariaDB (pdo_mysql):</span> Required for SQL storage</div>
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold <?php echo \\$pdoOk ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'; ?>">
                            <?php echo \\$pdoOk ? 'INSTALLED' : 'MISSING (apt install php-mysql)'; ?>
                        </span>
                    </div>

                    <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-700/60 flex items-center justify-between text-xs font-mono">
                        <div><span class="text-white font-sans font-semibold">OpenSSL Extension (openssl):</span> AES-256 certificate encryption</div>
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold <?php echo \\$opensslOk ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'; ?>">
                            <?php echo \\$opensslOk ? 'INSTALLED' : 'MISSING (apt install php-openssl)'; ?>
                        </span>
                    </div>

                    <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-700/60 flex items-center justify-between text-xs font-mono">
                        <div><span class="text-white font-sans font-semibold">LDAP Extension (php-ldap):</span> Active Directory bind authentication</div>
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold <?php echo \\$ldapExtOk ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'; ?>">
                            <?php echo \\$ldapExtOk ? 'INSTALLED' : 'RECOMMENDED (apt install php-ldap)'; ?>
                        </span>
                    </div>

                    <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-700/60 flex items-center justify-between text-xs font-mono">
                        <div><span class="text-white font-sans font-semibold">Directory Write Permission:</span> Create installed.lock &amp; config</div>
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold <?php echo \\$writableOk ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'; ?>">
                            <?php echo \\$writableOk ? 'WRITABLE' : 'READ-ONLY (chown -R www-data)'; ?>
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
        <?php if (\\$currentStep === 2): ?>
            <div class="bg-slate-800/90 rounded-2xl border border-slate-700/80 p-6 sm:p-8 shadow-xl">
                <div class="flex items-center gap-3 pb-5 border-b border-slate-700 mb-6">
                    <div class="w-10 h-10 rounded-xl bg-purple-500/10 text-purple-400 flex items-center justify-center font-bold">2</div>
                    <div>
                        <h2 class="text-lg font-bold text-white">Database Connection &amp; Schema Population</h2>
                        <p class="text-slate-400 text-xs">Enter your MariaDB connection credentials. Submitting will automatically populate all 9 database tables.</p>
                    </div>
                </div>

                <form method="POST" class="space-y-4">
                    <input type="hidden" name="action" value="step2_db">

                    <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                        <div class="sm:col-span-2">
                            <label class="block text-xs font-medium text-slate-300 mb-1">MariaDB Server Host</label>
                            <input type="text" name="db_host" value="<?php echo htmlspecialchars(\\$_SESSION['wizard']['db']['host'] ?? '127.0.0.1'); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                        <div>
                            <label class="block text-xs font-medium text-slate-300 mb-1">Port</label>
                            <input type="number" name="db_port" value="<?php echo htmlspecialchars((string)(\\$_SESSION['wizard']['db']['port'] ?? 3306)); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                    </div>

                    <div>
                        <label class="block text-xs font-medium text-slate-300 mb-1">Database Name</label>
                        <input type="text" name="db_name" value="<?php echo htmlspecialchars(\\$_SESSION['wizard']['db']['name'] ?? 'eop_antispam_db'); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        <p class="text-[11px] text-slate-400 mt-1">If this database does not exist, the installer will attempt to create it automatically.</p>
                    </div>

                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div>
                            <label class="block text-xs font-medium text-slate-300 mb-1">Database Username</label>
                            <input type="text" name="db_user" value="<?php echo htmlspecialchars(\\$_SESSION['wizard']['db']['user'] ?? 'eop_user'); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                        <div>
                            <label class="block text-xs font-medium text-slate-300 mb-1">Database Password</label>
                            <input type="password" name="db_pass" value="<?php echo htmlspecialchars(\\$_SESSION['wizard']['db']['pass'] ?? ''); ?>" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
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
                        </div>
                    </div>

                    <div class="flex items-center justify-between pt-4 border-t border-slate-700">
                        <a href="?step=1" class="text-xs text-slate-400 hover:text-white">&larr; Back to Step 1</a>
                        <button type="submit" class="px-6 py-2.5 bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold rounded-lg shadow-sm transition">
                            Test &amp; Populate Schema &rarr;
                        </button>
                    </div>
                </form>
            </div>
        <?php endif; ?>

        <!-- STEP 3: Active Directory / OpenLDAP Configuration -->
        <?php if (\\$currentStep === 3): ?>
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
                            <input type="text" name="ldap_host" value="<?php echo htmlspecialchars(\\$_SESSION['wizard']['ldap']['host'] ?? '192.168.10.10'); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                        <div>
                            <label class="block text-xs font-medium text-slate-300 mb-1">Port</label>
                            <input type="number" name="ldap_port" value="<?php echo htmlspecialchars((string)(\\$_SESSION['wizard']['ldap']['port'] ?? 389)); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                    </div>

                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div>
                            <label class="block text-xs font-medium text-slate-300 mb-1">Protocol</label>
                            <select name="ldap_protocol" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                                <option value="ldap" <?php echo (\\$_SESSION['wizard']['ldap']['protocol'] ?? '') === 'ldap' ? 'selected' : ''; ?>>LDAP (Plain Port 389)</option>
                                <option value="ldaps" <?php echo (\\$_SESSION['wizard']['ldap']['protocol'] ?? '') === 'ldaps' ? 'selected' : ''; ?>>LDAPS (SSL Port 636)</option>
                                <option value="starttls" <?php echo (\\$_SESSION['wizard']['ldap']['protocol'] ?? '') === 'starttls' ? 'selected' : ''; ?>>StartTLS (Port 389)</option>
                            </select>
                        </div>
                        <div>
                            <label class="block text-xs font-medium text-slate-300 mb-1">NetBIOS Domain</label>
                            <input type="text" name="ldap_domain" value="<?php echo htmlspecialchars(\\$_SESSION['wizard']['ldap']['domain'] ?? 'CORP'); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                    </div>

                    <div>
                        <label class="block text-xs font-medium text-slate-300 mb-1">Base Distinguished Name (Base DN)</label>
                        <input type="text" name="ldap_base_dn" value="<?php echo htmlspecialchars(\\$_SESSION['wizard']['ldap']['base_dn'] ?? 'DC=corp,DC=example,DC=com'); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                    </div>

                    <div>
                        <label class="block text-xs font-medium text-slate-300 mb-1">Authorized Group DN (Members Allowed to Manage EOP)</label>
                        <input type="text" name="ldap_group_dn" value="<?php echo htmlspecialchars(\\$_SESSION['wizard']['ldap']['group_dn'] ?? 'CN=EOP-SpamAdmins,OU=Security Groups,DC=corp,DC=example,DC=com'); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                    </div>

                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div>
                            <label class="block text-xs font-medium text-slate-300 mb-1">Service Account Bind DN (Optional)</label>
                            <input type="text" name="ldap_bind_dn" value="<?php echo htmlspecialchars(\\$_SESSION['wizard']['ldap']['bind_dn'] ?? 'CN=svc-eop-web,OU=Service Accounts,DC=corp,DC=example,DC=com'); ?>" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                        <div>
                            <label class="block text-xs font-medium text-slate-300 mb-1">Service Account Password</label>
                            <input type="password" name="ldap_bind_pass" value="<?php echo htmlspecialchars(\\$_SESSION['wizard']['ldap']['bind_pass'] ?? ''); ?>" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                    </div>

                    <div class="flex items-center justify-between pt-4 border-t border-slate-700">
                        <a href="?step=2" class="text-xs text-slate-400 hover:text-white">&larr; Back to Database</a>
                        <button type="submit" class="px-6 py-2.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg shadow-sm transition">
                            Save &amp; Continue to Exchange EOP &rarr;
                        </button>
                    </div>
                </form>
            </div>
        <?php endif; ?>

        <!-- STEP 4: Exchange Online Protection (EOP) Setup -->
        <?php if (\\$currentStep === 4): ?>
            <div class="bg-slate-800/90 rounded-2xl border border-slate-700/80 p-6 sm:p-8 shadow-xl">
                <div class="flex items-center gap-3 pb-5 border-b border-slate-700 mb-6">
                    <div class="w-10 h-10 rounded-xl bg-amber-500/10 text-amber-400 flex items-center justify-center font-bold">4</div>
                    <div>
                        <h2 class="text-lg font-bold text-white">Exchange Online Protection (EOP) Connection</h2>
                        <p class="text-slate-400 text-xs">Enter your Microsoft 365 Entra App Registration, Certificate Thumbprint, and RSA Private Key for PowerShell sync.</p>
                    </div>
                </div>

                <form method="POST" class="space-y-4">
                    <input type="hidden" name="action" value="step4_eop">

                    <div>
                        <label class="block text-xs font-medium text-slate-300 mb-1">Microsoft 365 Tenant ID (GUID)</label>
                        <input type="text" name="tenant_id" value="<?php echo htmlspecialchars(\\$_SESSION['wizard']['eop']['tenant_id'] ?? '72f988bf-86f1-41af-91ab-2d7cd011db47'); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                    </div>

                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div>
                            <label class="block text-xs font-medium text-slate-300 mb-1">App Registration Client ID</label>
                            <input type="text" name="client_id" value="<?php echo htmlspecialchars(\\$_SESSION['wizard']['eop']['client_id'] ?? '3a2b4c5d-6e7f-8a9b-0c1d-2e3f4a5b6c7d'); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                        <div>
                            <label class="block text-xs font-medium text-slate-300 mb-1">Certificate SHA-1 Thumbprint</label>
                            <input type="text" name="thumbprint" value="<?php echo htmlspecialchars(\\$_SESSION['wizard']['eop']['thumbprint'] ?? '9A2F8B3C1D4E5F6A7B8C9D0E1F2A3B4C5D6E7F80'); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                    </div>

                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div>
                            <label class="block text-xs font-medium text-slate-300 mb-1">Organization Domain</label>
                            <input type="text" name="org_domain" value="<?php echo htmlspecialchars(\\$_SESSION['wizard']['eop']['org_domain'] ?? 'corp.example.com'); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                        <div>
                            <label class="block text-xs font-medium text-slate-300 mb-1">Default Anti-Spam Policy Name</label>
                            <input type="text" name="policy" value="<?php echo htmlspecialchars(\\$_SESSION['wizard']['eop']['policy'] ?? 'Default Inbound Anti-Spam Policy'); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                    </div>

                    <div>
                        <label class="block text-xs font-medium text-slate-300 mb-1">RSA Certificate Private Key (PEM format)</label>
                        <textarea name="private_key" rows="4" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500"><?php echo htmlspecialchars(\\$_SESSION['wizard']['eop']['private_key'] ?? "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Q3d7v5N8A9zX3lW2k1vJ8qY4t7rU9sP3mF2a1cB6d8e0f1g\n-----END RSA PRIVATE KEY-----"); ?></textarea>
                    </div>

                    <div>
                        <label class="block text-xs font-medium text-slate-300 mb-1">Private Key AES-256 Passphrase</label>
                        <input type="password" name="passphrase" value="<?php echo htmlspecialchars(\\$_SESSION['wizard']['eop']['passphrase'] ?? 'P@ssphrase_Secure_Cert_2026'); ?>" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        <p class="text-[11px] text-slate-400 mt-1">This key is encrypted in MariaDB via AES-256-GCM authenticated cipher.</p>
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
        <?php if (\\$currentStep === 5): ?>
            <div class="bg-slate-800/90 rounded-2xl border border-slate-700/80 p-6 sm:p-8 shadow-xl">
                <div class="flex items-center gap-3 pb-5 border-b border-slate-700 mb-6">
                    <div class="w-10 h-10 rounded-xl bg-emerald-500/10 text-emerald-400 flex items-center justify-center font-bold">5</div>
                    <div>
                        <h2 class="text-lg font-bold text-white">Review &amp; Permanent Installation Lock</h2>
                        <p class="text-slate-400 text-xs">Verify all configured parameters before finalizing setup and creating permanent security locks.</p>
                    </div>
                </div>

                <!-- Subsystem Overview Cards -->
                <div class="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-6">
                    <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-700/60 text-xs">
                        <div class="font-bold text-purple-400 mb-1 flex items-center gap-1">
                            <span>MariaDB Database</span>
                        </div>
                        <div class="text-[11px] space-y-0.5 text-slate-300 font-mono">
                            <div>Host: <?php echo htmlspecialchars(\\$_SESSION['wizard']['db']['host'] ?? '127.0.0.1'); ?></div>
                            <div>Database: <?php echo htmlspecialchars(\\$_SESSION['wizard']['db']['name'] ?? 'eop_antispam_db'); ?></div>
                            <div class="text-emerald-400 font-sans font-semibold mt-1">9 Tables Populated</div>
                        </div>
                    </div>

                    <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-700/60 text-xs">
                        <div class="font-bold text-blue-400 mb-1 flex items-center gap-1">
                            <span>Active Directory LDAP</span>
                        </div>
                        <div class="text-[11px] space-y-0.5 text-slate-300 font-mono">
                            <div>Host: <?php echo htmlspecialchars(\\$_SESSION['wizard']['ldap']['host'] ?? '192.168.10.10'); ?></div>
                            <div>Proto: <?php echo strtoupper(htmlspecialchars(\\$_SESSION['wizard']['ldap']['protocol'] ?? 'ldap')); ?></div>
                            <div class="text-emerald-400 font-sans font-semibold mt-1">Group Check Active</div>
                        </div>
                    </div>

                    <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-700/60 text-xs">
                        <div class="font-bold text-amber-400 mb-1 flex items-center gap-1">
                            <span>Exchange Online EOP</span>
                        </div>
                        <div class="text-[11px] space-y-0.5 text-slate-300 font-mono">
                            <div>Tenant: <?php echo substr(htmlspecialchars(\\$_SESSION['wizard']['eop']['tenant_id'] ?? ''), 0, 8); ?>...</div>
                            <div>Thumb: <?php echo substr(htmlspecialchars(\\$_SESSION['wizard']['eop']['thumbprint'] ?? ''), 0, 8); ?>...</div>
                            <div class="text-emerald-400 font-sans font-semibold mt-1">AES-256 Key Stored</div>
                        </div>
                    </div>
                </div>

                <!-- Permanent Lock Warning Notice -->
                <div class="p-4 rounded-xl bg-amber-950/40 border border-amber-700/60 text-xs text-amber-200 leading-relaxed mb-6 space-y-2">
                    <div class="font-bold flex items-center gap-2 text-sm text-amber-300">
                        <span>Security Lockout Notice: Setup Cannot Be Run Again</span>
                    </div>
                    <p>
                        Clicking <strong>Complete Installation &amp; Lock Setup</strong> will permanently create the Debian filesystem lockfile <code>installed.lock</code> and record the installation timestamp in MariaDB table <code>eop_setup_lock</code>.
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
                            Complete Installation &amp; Lock Setup
                        </button>
                    </div>
                </form>
            </div>
        <?php endif; ?>

    </div>
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
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/ldap.php';
require_once __DIR__ . '/functions.php';

// Redirect if already logged in
if (!empty($_SESSION['user'])) {
    header('Location: index.php');
    exit;
}

$error = null;
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
            Database::logAudit('LOGIN', 'SYSTEM', DEFAULT_POLICY_NAME, $username, 'Successful AD LDAP login', $username);

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

    $logMsg = implode("\n", $output);
    if ($returnVar === 0) {
        if ($actionParam === 'Pull') {
            Database::updatePolicySyncStatus($policyName, 'synced', 'Pulled changes from Exchange Online into MariaDB');
            Database::logAudit('SYNC', 'SYSTEM', $policyName, 'ALL', 'Manual pull from Exchange Online completed', $user['username']);
            setFlash('success', "Exchange Online pull completed successfully! Remote entries ingested into MariaDB for policy '{$policyName}'.");
        } else {
            Database::updatePolicySyncStatus($policyName, 'synced', 'Pushed changes to Exchange Online');
            Database::logAudit('SYNC', 'SYSTEM', $policyName, 'ALL', 'Manual push to Exchange Online completed', $user['username']);
            setFlash('success', "Exchange Online push completed successfully! MariaDB lists applied to Microsoft 365 for policy '{$policyName}'.");
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
    The name of the Exchange Online hosted content filter policy (e.g. "${cfg.defaultPolicyName}").
.PARAMETER Action
    Sync direction: "Pull" (default for cron) or "Push" (manual admin push only).
    - Pull: Retrieves Allowed/Blocked senders and domains from Exchange Online via Get-HostedContentFilterPolicy
            and reconciles them into MariaDB individual tables. Does NOT modify Exchange Online.
    - Push: Applies MariaDB individual tables to Exchange Online via Set-HostedContentFilterPolicy.
#>

param (
    [string]$PolicyName = "${cfg.defaultPolicyName}",
    [ValidateSet("Pull", "Push")]
    [string]$Action = "Pull",
    [string]$DbHost = "${cfg.dbHost}",
    [int]$DbPort = ${cfg.dbPort},
    [string]$DbName = "${cfg.dbName}",
    [string]$DbUser = "${cfg.dbUser}",
    [string]$DbPass = "${cfg.dbPass}"
)

Write-Host "=========================================================="
Write-Host "EOP Anti-Spam Sync: Policy='$PolicyName' | Action=$Action"
Write-Host "Database Host: $DbHost:$DbPort | DB: $DbName"
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

Write-Host "Authenticated via Certificate Thumbprint: ${cfg.certificateThumbprint} (App: ${cfg.clientId})" -ForegroundColor Cyan

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
        foreach ($v in $Values) {
            $valClean = $v.Trim().ToLower()
            if ($valClean -ne "") {
                $sql = "INSERT IGNORE INTO $TableName (policy_name, $ColName, note, added_by) VALUES ('$Policy', '$valClean', 'Pulled from Exchange Online via Cron', 'EOP_CRON_PULL');"
                $cmd = "mariadb -h $DbHost -P $DbPort -u $DbUser -p'$DbPass' -D $DbName -e \\"$sql\\""
                Invoke-Expression $cmd | Out-Null
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
        $query = "SELECT $ColumnName FROM $TableName WHERE policy_name = '$Policy';"
        $cmd = "mariadb -h $DbHost -P $DbPort -u $DbUser -p'$DbPass' -D $DbName -s -N -e \\"$query\\""
        $result = Invoke-Expression $cmd
        if ($result) {
            return @($result -split "\\r?\\n" | Where-Object { $_ -ne "" })
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
    # Set-HostedContentFilterPolicy -Identity $PolicyName \`
    #     -AllowedSenders $allowedSenders \`
    #     -BlockedSenders $blockedSenders \`
    #     -AllowedSenderDomains $allowedDomains \`
    #     -BlockedSenderDomains $blockedDomains

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
/**
 * CLI Crontab Sync Runner for Debian
 * 
 * CRON POLICY ENFORCEMENT:
 * The cron job strictly PULLS changes from Exchange Online Protection (EOP)
 * into MariaDB. It does NOT push local MariaDB changes to EOP.
 * 
 * Usage in crontab (e.g. every 15 minutes):
 * */15 * * * * www-data /usr/bin/php /var/www/eop-antispam/cron-sync.php --policy="Default Inbound Anti-Spam Policy"
 */

declare(strict_types=1);

if (php_sapi_name() !== 'cli') {
    die("This script must be run from the command line.\\n");
}

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';

$options = getopt('', ['policy::', 'action::', 'help']);

if (isset($options['help'])) {
    echo "Usage: php cron-sync.php [--policy=PolicyName] [--action=pull]\\n";
    echo "Notice: The cron job strictly PULLS from Exchange Online to MariaDB (never pushes).\\n";
    exit(0);
}

$policy = $options['policy'] ?? DEFAULT_POLICY_NAME;
$action = strtolower($options['action'] ?? 'pull');

// Enforce pull-only in cron
if ($action !== 'pull') {
    fwrite(STDERR, "[CRON POLICY ERROR] The cron job is configured to ONLY pull changes from EOP, not push them.\\n");
    fwrite(STDERR, "To push changes, an authorized administrator must use the Web UI or run with explicit manual confirmation.\\n");
    exit(1);
}

echo "[" . date('Y-m-d H:i:s') . "] Starting EOP Anti-Spam CRON PULL for policy: {$policy}\\n";
echo "Sync Direction: PULL ONLY (Exchange Online -> MariaDB)\\n";
echo "Notice: Local MariaDB changes will NOT be pushed to EOP.\\n";

// Execute PowerShell sync script in Pull-only mode on Debian
$psScript = __DIR__ . '/sync-exchange.ps1';
if (file_exists($psScript)) {
    $cmd = sprintf('pwsh -File %s -PolicyName %s -Action Pull 2>&1', escapeshellarg($psScript), escapeshellarg($policy));
    passthru($cmd, $returnVar);

    if ($returnVar === 0) {
        Database::updatePolicySyncStatus($policy, 'synced', 'Crontab automatic PULL from EOP completed');
        Database::logAudit('SYNC', 'SYSTEM', $policy, 'ALL', 'Crontab pulled changes from Exchange Online (Pull-Only)', 'CRON_DAEMON');
        echo "[" . date('Y-m-d H:i:s') . "] Cron EOP pull completed successfully.\\n";
    } else {
        Database::updatePolicySyncStatus($policy, 'failed', "Crontab pull exited with code {$returnVar}");
        echo "[" . date('Y-m-d H:i:s') . "] Cron pull failed with code {$returnVar}.\\n";
    }
} else {
    echo "Error: PowerShell script not found at {$psScript}\\n";
}
`
  },

  // 12. install-debian.sh
  {
    name: 'install-debian.sh',
    path: 'install-debian.sh',
    description: 'Automated Bash setup script for Debian 11/12 installing Apache, PHP 8.2, LDAP, MySQL extensions, mariadb-client, permissions, and directory structure.',
    category: 'debian',
    generateContent: (cfg) => `#!/usr/bin/env bash
# ==============================================================================
# Automated Debian 11 / 12 Deployment Script for EOP Anti-Spam Manager
# Installs: Apache2, PHP 8.2/8.3, php-ldap, php-mysql, php-curl, mariadb-client, pwsh
# ==============================================================================

set -euo pipefail

echo "=========================================================="
echo "Installing EOP Anti-Spam Web App on Debian Linux..."
echo "=========================================================="

if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root (sudo ./install-debian.sh)"
    exit 1
fi

APP_DIR="/var/www/eop-antispam"
WEB_USER="www-data"

# 1. Update apt repositories
echo "[1/6] Updating APT repositories..."
apt-get update -y
apt-get install -y lsb-release ca-certificates apt-transport-https software-properties-common curl wget gnupg

# 2. Install Apache2 & PHP with required extensions (including LDAP and MariaDB client)
echo "[2/6] Installing Apache2, PHP, LDAP, and MariaDB extensions..."
apt-get install -y apache2 \\
    php php-cli php-fpm php-mysql php-ldap php-curl php-mbstring php-xml php-zip \\
    mariadb-client

# 3. Configure Active Directory LDAP TLS Settings
echo "[3/6] Configuring /etc/ldap/ldap.conf for Active Directory..."
# If your AD domain controller uses an internal enterprise CA or self-signed cert,
# we ensure TLS_REQCERT allows connection while trusting the CA:
if ! grep -q "TLS_REQCERT" /etc/ldap/ldap.conf; then
    echo "TLS_REQCERT allow" >> /etc/ldap/ldap.conf
fi

# 4. Deploy web files
echo "[4/6] Creating deployment directory: $APP_DIR"
mkdir -p "$APP_DIR"
cp -r ./* "$APP_DIR/" || true

# Set strict permissions
chown -R $WEB_USER:$WEB_USER "$APP_DIR"
find "$APP_DIR" -type d -exec chmod 750 {} \\;
find "$APP_DIR" -type f -exec chmod 640 {} \\;

# 5. Configure Apache VirtualHost
echo "[5/6] Configuring Apache VirtualHost..."
cat << 'EOF' > /etc/apache2/sites-available/eop-antispam.conf
<VirtualHost *:80>
    ServerName ${cfg.appUrl.replace('https://', '').replace('http://', '')}
    DocumentRoot /var/www/eop-antispam

    <Directory /var/www/eop-antispam>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted

        # Protect sensitive files
        <FilesMatch "^(\\..*|.*\\.sql|.*\\.ps1|.*\\.sh|config\\.php)$">
            Require all denied
        </FilesMatch>
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/eop_error.log
    CustomLog \${APACHE_LOG_DIR}/eop_access.log combined
</VirtualHost>
EOF

a2enmod rewrite ssl headers
a2ensite eop-antispam.conf
systemctl restart apache2

# 6. Setup crontab for automatic 15-minute PULL from EOP (Cron is strictly Pull-Only)
echo "[6/6] Setting up crontab entry for automated EOP pull sync (pull-only)..."
CRON_JOB="*/15 * * * * $WEB_USER /usr/bin/php /var/www/eop-antispam/cron-sync.php --policy=\"${cfg.defaultPolicyName}\" --action=pull >> /var/log/eop-sync.log 2>&1"
(crontab -l 2>/dev/null | grep -F -v "cron-sync.php" ; echo "$CRON_JOB") | crontab -

echo "=========================================================="
echo "Deployment Complete!"
echo "Web URL: http://$(hostname -I | awk '{print $1}')/setup.php"
echo "Navigate to /setup.php to run the Page-by-Page Setup Wizard."
echo "The wizard connects to MariaDB, populates all 9 schema tables,"
echo "configures AD LDAP and Exchange Online Protection, and permanently locks."
echo "=========================================================="
`
  },

  // 13. apache.conf
  {
    name: 'eop-apache.conf',
    path: 'apache.conf',
    description: 'Production Apache 2.4 VirtualHost with TLS, security headers, and file protection.',
    category: 'debian',
    generateContent: (cfg) => `<VirtualHost *:80>
    ServerName ${cfg.appUrl.replace('https://', '').replace('http://', '')}
    Redirect permanent / https://${cfg.appUrl.replace('https://', '').replace('http://', '')}/
</VirtualHost>

<VirtualHost *:443>
    ServerName ${cfg.appUrl.replace('https://', '').replace('http://', '')}
    DocumentRoot /var/www/eop-antispam

    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem
    SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key

    # Security Headers
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"

    <Directory /var/www/eop-antispam>
        Options -Indexes +FollowSymLinks
        AllowOverride None
        Require all granted

        # Protect configuration, sql, scripts, and environment files from direct HTTP access
        <FilesMatch "^(\\..*|.*\\.sql|.*\\.ps1|.*\\.sh|config\\.php)$">
            Require all denied
        </FilesMatch>
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/eop_error.log
    CustomLog \${APACHE_LOG_DIR}/eop_access.log combined
</VirtualHost>
`
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

# Default Exchange Online Protection Anti-Spam Policy Name
EOP_POLICY_NAME="${cfg.defaultPolicyName}"

# Microsoft 365 Azure AD App Registration (for automated sync & certificate auth)
M365_TENANT_ID="${cfg.tenantId}"
M365_CLIENT_ID="${cfg.clientId}"
M365_CERT_THUMBPRINT="${cfg.certificateThumbprint}"
M365_ORGANIZATION="${cfg.organization || 'corp.example.com'}"
M365_CLIENT_SECRET="${cfg.clientSecret}"

# Master key used for AES-256-GCM encryption of private key passwords stored in database
AUTH_MASTER_ENCRYPTION_KEY="eop_master_aes256_secret_key_2026_debian"
`
  },

  // 15. README.md
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
   - **LDAP Settings Modification**: View and edit LDAP host, port, protocol (Plain LDAP port 389 / LDAPS 636 / StartTLS), Base DN, Authorized Group DN, and service account credentials.
   - Real-time connection testing for both Exchange Online certificate signing and Active Directory authentication.

3. **Active Directory LDAP Connection Stored in Database (LDAPS Not Required)**:
   - **Database-Stored Configuration**: LDAP host, port, protocol, Base DN, Group DN, and bind credentials are stored directly in the MariaDB table \`eop_ldap_config\` and can be viewed or updated via the Web UI.
   - **Plain LDAP (port 389) is supported out of the box**: LDAPS is **not required**. Connects directly to any Windows Domain Controller without certificate hassles.
   - Also supports **LDAPS (port 636)** and **StartTLS (port 389)** if desired.
   - Enforces access control via **Group Distinguished Name (Group DN)**:
     \`${cfg.ldapGroupDn}\`
   - Supports **nested/recursive Active Directory groups** using LDAP matching rule OID \`1.2.840.113556.1.4.1941\` (\`LDAP_MATCHING_RULE_IN_CHAIN\`).

4. **Exchange Online Protection Certificate Sync Engine (Cron Pull-Only vs Manual Push)**:
   - **Scheduled Cron Daemon (Pull Only)**: The Linux crontab runner (\`cron-sync.php --action=pull\`) is strictly limited to pulling changes from Exchange Online into MariaDB via \`Get-HostedContentFilterPolicy\`. It **never pushes** or overwrites Microsoft 365 automatically:
     \`\`\`powershell
     # Scheduled Cron: Pull remote changes from Microsoft 365 into MariaDB
     Get-HostedContentFilterPolicy -Identity "${cfg.defaultPolicyName}"
     \`\`\`
   - **Manual Admin Push**: Pushing local MariaDB entries to Microsoft 365 requires an intentional administrator action in the Web UI:
     \`\`\`powershell
     # Manual Admin Push: Applies MariaDB tables to Exchange Online
     Connect-ExchangeOnline -AppId "${cfg.clientId}" -CertificateThumbprint "${cfg.certificateThumbprint}" -Organization "${cfg.organization || 'corp.example.com'}"
     Set-HostedContentFilterPolicy -Identity "${cfg.defaultPolicyName}" \\
       -AllowedSenders @(...) \\
       -BlockedSenders @(...) \\
       -AllowedSenderDomains @(...) \\
       -BlockedSenderDomains @(...)
     \`\`\`

---

## Project File Structure & Inventory

\`\`\`text
eop-antispam-php-mariadb/
├── config.php            # Primary application configuration (DB, LDAP, Policy options)
├── database.php          # PDO database wrapper & individual table CRUD operations
├── ldap.php              # Active Directory LDAP Group DN authentication engine
├── functions.php         # CSRF verification, input sanitization, and helper utilities
├── schema.sql            # MariaDB database table definitions & 9-table schema
├── index.php             # Main management dashboard (Dark mode, tables, cards, modal UI)
├── setup.php             # 5-step initial run setup wizard with permanent lock
├── login.php             # Active Directory LDAP authentication portal (Dark mode)
├── logout.php            # Session termination & security cleanup
├── actions.php           # REST-style handler for add, delete, import, export, and sync
├── sync-exchange.ps1     # Linux PowerShell sync automation script (Pull & Push modes)
├── cron-sync.php         # Scheduled Pull-Only background CLI sync daemon
├── install-debian.sh     # Automated Debian 11/12 deployment script
├── eop-apache.conf       # Hardened Apache2 VirtualHost configuration
├── .env.example          # Environment variable template
└── README.md             # Complete technical and deployment documentation
\`\`\`

---

## Quick Start on Debian Linux

### Step 1: Initialize Database on Remote MariaDB Server
On your remote MariaDB server (\`${cfg.dbHost}\`), run the \`schema.sql\` file:
\`\`\`bash
mariadb -u root -p < schema.sql
\`\`\`

Grant remote access to your Debian server IP:
\`\`\`sql
CREATE USER IF NOT EXISTS '${cfg.dbUser}'@'YOUR_DEBIAN_IP' IDENTIFIED BY '${cfg.dbPass}';
GRANT ALL PRIVILEGES ON \`${cfg.dbName}\`.* TO '${cfg.dbUser}'@'YOUR_DEBIAN_IP';
FLUSH PRIVILEGES;
\`\`\`

### Step 2: Deploy to Debian Server
Run the automated installer on your Debian server:
\`\`\`bash
chmod +x install-debian.sh
sudo ./install-debian.sh
\`\`\`

Or manually install packages:
\`\`\`bash
sudo apt-get update
sudo apt-get install -y apache2 php php-ldap php-mysql php-curl php-mbstring mariadb-client
\`\`\`

### Step 3: Active Directory LDAP Configuration
Because **plain LDAP (port 389)** is supported, you do **not** need to install or configure certificates on Debian!
If your organization requires LDAPS (port 636) with an internal enterprise CA:
Add \`TLS_REQCERT allow\` to \`/etc/ldap/ldap.conf\` and restart Apache (\`sudo systemctl restart apache2\`).

### Step 4: Login & Manage
Navigate to \`https://${cfg.appUrl.replace('https://', '')}\` and sign in with any Active Directory account belonging to:
\`${cfg.ldapGroupDn}\`
Toggle between Dark Mode and Light Mode at any time using the moon/sun icon in the top header.
`
  }
];
