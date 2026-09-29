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
define('DB_HOST', eopEnv('DB_HOST', ''));
define('DB_PORT', (int)eopEnv('DB_PORT', '3306'));
define('DB_NAME', eopEnv('DB_NAME', ''));
define('DB_USER', eopEnv('DB_USER', ''));
define('DB_PASS', eopEnv('DB_PASS', ''));
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
define('AUTH_MASTER_ENCRYPTION_KEY', eopEnv('AUTH_MASTER_ENCRYPTION_KEY', ''));

// --------------------------------------------------------------------------
// 3. Microsoft Active Directory (LDAP) Settings
// --------------------------------------------------------------------------
// NOTE: LDAP connection settings are stored in and dynamically retrieved from
// the MariaDB database table 'eop_ldap_config' via Database::getLdapConfig().
// Standard LDAP (port 389) is supported by default and LDAPS is NOT required.
// Set LDAP_PROTOCOL to 'ldap' (port 389 plain), 'ldaps' (port 636), or 'starttls' (port 389 with TLS).
define('LDAP_HOST', eopEnv('LDAP_HOST', ''));
define('LDAP_PORT', (int)eopEnv('LDAP_PORT', '389'));
define('LDAP_PROTOCOL', eopEnv('LDAP_PROTOCOL', 'ldap'));
define('LDAP_USE_SSL', LDAP_PROTOCOL === 'ldaps'); // LDAPS on port 636 (optional, not required)
define('LDAP_USE_TLS', LDAP_PROTOCOL === 'starttls'); // StartTLS on port 389 (optional, not required)
define('LDAP_BASE_DN', eopEnv('LDAP_BASE_DN', ''));

// Mandatory Security Group Distinguished Name (Group DN) for authorization
define('LDAP_AUTHORIZED_GROUP_DN', eopEnv('LDAP_AUTHORIZED_GROUP_DN', ''));

// Active Directory Service Account for initial user & group resolution (optional, recommended)
define('LDAP_BIND_DN', eopEnv('LDAP_BIND_DN', ''));
define('LDAP_BIND_PASSWORD', eopEnv('LDAP_BIND_PASSWORD', ''));
define('LDAP_ACCOUNT_SUFFIX', eopEnv('LDAP_ACCOUNT_SUFFIX', ''));
define('LDAP_NETBIOS_DOMAIN', eopEnv('LDAP_DOMAIN', ''));

// --------------------------------------------------------------------------
// 3b. Emergency Non-LDAP Fallback Administrator Account
// Allows administrative access when Active Directory Domain Controller connection fails
// --------------------------------------------------------------------------
define('FALLBACK_ADMIN_ENABLED', in_array(strtolower(eopEnv('FALLBACK_ADMIN_ENABLED', '')), ['1', 'true', 'yes'], true));
define('FALLBACK_ADMIN_USERNAME', eopEnv('FALLBACK_ADMIN_USER', ''));
define('FALLBACK_ADMIN_PASSWORD_HASH', eopEnv('FALLBACK_ADMIN_PASSWORD_HASH', ''));

// --------------------------------------------------------------------------
// 4. Exchange Online Protection (EOP) Policy Settings
// --------------------------------------------------------------------------
define('DEFAULT_POLICY_NAME', eopEnv('EOP_POLICY_NAME', ''));
define('APP_TITLE', 'EOP Anti-Spam Policy Manager');
define('APP_URL', eopEnv('APP_URL', ''));

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
define('M365_TENANT_ID', eopEnv('M365_TENANT_ID', ''));
define('M365_CLIENT_ID', eopEnv('M365_CLIENT_ID', ''));
define('M365_CERT_THUMBPRINT', eopEnv('M365_CERT_THUMBPRINT', ''));
define('M365_ORGANIZATION', eopEnv('M365_ORGANIZATION', ''));
define('M365_CLIENT_SECRET', eopEnv('M365_CLIENT_SECRET', ''));
define('SYNC_SCRIPT_PATH', __DIR__ . '/sync-exchange.ps1');
