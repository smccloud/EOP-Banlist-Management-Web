<?php
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

// Session timeout check (60 minutes)
$sessionTimeoutSeconds = 60 * 60;
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

// Helper function to safely fetch environment variable with fallback
if (!function_exists('eopEnv')) {
    function eopEnv(string $key, string $default = ''): string {
        if (isset($_ENV[$key]) && $_ENV[$key] !== '') {
            return (string)$_ENV[$key];
        }
        if (isset($_SERVER[$key]) && $_SERVER[$key] !== '') {
            return (string)$_SERVER[$key];
        }
        $val = getenv($key);
        if ($val !== false && $val !== '') {
            return (string)$val;
        }
        return $default;
    }
}

// --------------------------------------------------------------------------
// 2. Remote MariaDB Database Settings
// --------------------------------------------------------------------------
define('DB_HOST', eopEnv('DB_HOST', '192.168.10.50'));
define('DB_PORT', (int)eopEnv('DB_PORT', '3306'));
define('DB_NAME', eopEnv('DB_NAME', 'eop_antispam_db'));
define('DB_USER', eopEnv('DB_USER', 'eop_app_user'));
define('DB_PASS', eopEnv('DB_PASS', 'P@ssw0rd_Secure_MariaDB_2026'));
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

// Master key for AES-256-GCM encryption of stored private key passphrases
define('AUTH_MASTER_ENCRYPTION_KEY', eopEnv('AUTH_MASTER_ENCRYPTION_KEY', 'eop_master_aes256_secret_key_2026_debian'));

// --------------------------------------------------------------------------
// 3. Microsoft Active Directory (LDAP) Settings
// --------------------------------------------------------------------------
// NOTE: LDAP connection settings are stored in and dynamically retrieved from
// the MariaDB database table 'eop_ldap_config' via Database::getLdapConfig().
// The constants below serve as default fallback values and initial seeds.
// Standard LDAP (port 389) is supported by default and LDAPS is NOT required.
// Set LDAP_PROTOCOL to 'ldap' (port 389 plain), 'ldaps' (port 636), or 'starttls' (port 389 with TLS).
define('LDAP_HOST', eopEnv('LDAP_HOST', 'dc01.corp.example.com'));
define('LDAP_PORT', (int)eopEnv('LDAP_PORT', '389'));
define('LDAP_PROTOCOL', eopEnv('LDAP_PROTOCOL', 'ldap'));
define('LDAP_USE_SSL', LDAP_PROTOCOL === 'ldaps'); // LDAPS on port 636 (optional, not required)
define('LDAP_USE_TLS', LDAP_PROTOCOL === 'starttls'); // StartTLS on port 389 (optional, not required)
define('LDAP_BASE_DN', eopEnv('LDAP_BASE_DN', 'DC=corp,DC=example,DC=com'));

// Mandatory Security Group Distinguished Name (Group DN) for authorization
define('LDAP_AUTHORIZED_GROUP_DN', eopEnv('LDAP_AUTHORIZED_GROUP_DN', 'CN=Exchange-Admins,OU=Security Groups,DC=corp,DC=example,DC=com'));

// Active Directory Service Account for initial user & group resolution (optional, recommended)
define('LDAP_BIND_DN', eopEnv('LDAP_BIND_DN', 'CN=svc-eop-web,OU=Service Accounts,DC=corp,DC=example,DC=com'));
define('LDAP_BIND_PASSWORD', eopEnv('LDAP_BIND_PASSWORD', 'Svc_P@ssw0rd_AD_2026'));
define('LDAP_ACCOUNT_SUFFIX', '@corp.example.com');
define('LDAP_NETBIOS_DOMAIN', eopEnv('LDAP_DOMAIN', 'CORP'));

// --------------------------------------------------------------------------
// 3b. Emergency Non-LDAP Fallback Administrator Account
// Allows administrative access when Active Directory Domain Controller connection fails
// --------------------------------------------------------------------------
define('FALLBACK_ADMIN_ENABLED', eopEnv('FALLBACK_ADMIN_ENABLED', 'true') === 'true');
define('FALLBACK_ADMIN_USERNAME', eopEnv('FALLBACK_ADMIN_USER', 'eopadmin'));
// Default hashed password fallback (BCrypt)
define('FALLBACK_ADMIN_PASSWORD_HASH', '$2y$12$eopEmergencyAdminFallbackHashPlaceholder2026XyZ');

// --------------------------------------------------------------------------
// 4. Exchange Online Protection (EOP) Policy Settings
// --------------------------------------------------------------------------
define('DEFAULT_POLICY_NAME', eopEnv('EOP_POLICY_NAME', 'Default'));
define('APP_TITLE', 'EOP Anti-Spam Policy Manager');
define('APP_URL', eopEnv('APP_URL', 'https://eop.corp.example.com'));

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
// The constants below serve as default fallback values and initial seeds.
define('M365_TENANT_ID', eopEnv('M365_TENANT_ID', '11111111-2222-3333-4444-555555555555'));
define('M365_CLIENT_ID', eopEnv('M365_CLIENT_ID', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'));
define('M365_CERT_THUMBPRINT', eopEnv('M365_CERT_THUMBPRINT', '9A2F8B3C1D4E5F6A7B8C9D0E1F2A3B4C5D6E7F80'));
define('M365_ORGANIZATION', eopEnv('M365_ORGANIZATION', 'corp.example.com'));
define('M365_CLIENT_SECRET', eopEnv('M365_CLIENT_SECRET', 'YOUR_AZURE_APP_CLIENT_SECRET'));
define('SYNC_SCRIPT_PATH', __DIR__ . '/sync-exchange.ps1');
