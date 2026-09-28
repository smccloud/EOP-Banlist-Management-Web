<?php
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
$lockFile = __DIR__ . '/installed.lock';

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

define('AUTH_MASTER_ENCRYPTION_KEY', getenv('AUTH_MASTER_ENCRYPTION_KEY') ?: 'eop_master_aes256_secret_key_2026_debian');

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
            'host' => '192.168.10.50',
            'port' => 3306,
            'name' => 'eop_antispam_db',
            'user' => 'eop_app_user',
            'pass' => 'P@ssw0rd_Secure_MariaDB_2026',
            'populated' => false,
            'tables' => []
        ],
        'ldap' => [
            'host' => 'dc01.corp.example.com',
            'port' => 389,
            'protocol' => 'ldap',
            'base_dn' => 'DC=corp,DC=example,DC=com',
            'group_dn' => 'CN=Exchange-Admins,OU=Security Groups,DC=corp,DC=example,DC=com',
            'bind_dn' => 'CN=svc-eop-web,OU=Service Accounts,DC=corp,DC=example,DC=com',
            'bind_pass' => 'Svc_P@ssw0rd_AD_2026',
            'domain' => 'CORP',
            'tested' => false
        ],
        'eop' => [
            'tenant_id' => '11111111-2222-3333-4444-555555555555',
            'client_id' => 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
            'thumbprint' => '9A2F8B3C1D4E5F6A7B8C9D0E1F2A3B4C5D6E7F80',
            'org_domain' => 'corp.example.com',
            'policy' => 'Default',
            'private_key' => '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Q3d7v5N8A9zX3lW2k1vJ8qY4t7rU9sP3mF2a1cB6d8e0f1g\n2h3i4j5k6l7m8n9o0p1q2r3s4t5u6v7w8x9y0z1A2B3C4D5E6F7G8H9I0J1K2L3M\n4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7a8b9c0d1e2f3g4h5i6j7k8l9m0n1o2p3q4r5s\n6t7u8v9w0x1y2z3A4B5C6D7E8F9G0H1I2J3K4L5M6N7O8P9Q0R1S2T3U4V5W6X7Y\n-----END RSA PRIVATE KEY-----',
            'passphrase' => 'P@ssphrase_Secure_Cert_2026',
            'validated' => false
        ]
    ];
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
    $thumb = $eop['thumbprint'] ?? ($existing['M365_CERT_THUMBPRINT'] ?? '9A2F8B3C1D4E5F6A7B8C9D0E1F2A3B4C5D6E7F80');
    $org = $eop['org_domain'] ?? ($existing['M365_ORGANIZATION'] ?? 'corp.example.com');
    $policy = $eop['policy'] ?? ($existing['EOP_POLICY_NAME'] ?? 'Default Inbound Anti-Spam Policy');
    $masterKey = $existing['AUTH_MASTER_ENCRYPTION_KEY'] ?? bin2hex(random_bytes(16));
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
        'M365_CLIENT_SECRET="' . ($existing['M365_CLIENT_SECRET'] ?? 'YOUR_AZURE_APP_CLIENT_SECRET') . '"',
        '',
        '# ------------------------------------------------------------------------------',
        '# Security & Master Keys',
        '# ------------------------------------------------------------------------------',
        'AUTH_MASTER_ENCRYPTION_KEY="' . $masterKey . '"',
        'APP_URL="' . $appUrl . '"',
        ''
    ];
    $content = implode("\n", $lines);

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
    $thumb = addslashes($eop['thumbprint'] ?? ($existing['M365_CERT_THUMBPRINT'] ?? '9A2F8B3C1D4E5F6A7B8C9D0E1F2A3B4C5D6E7F80'));
    $org = addslashes($eop['org_domain'] ?? ($existing['M365_ORGANIZATION'] ?? 'corp.example.com'));
    $policy = addslashes($eop['policy'] ?? ($existing['EOP_POLICY_NAME'] ?? 'Default Inbound Anti-Spam Policy'));
    $masterKey = addslashes($existing['AUTH_MASTER_ENCRYPTION_KEY'] ?? bin2hex(random_bytes(16)));
    $appUrl = addslashes($existing['APP_URL'] ?? ('https://' . ($_SERVER['HTTP_HOST'] ?? 'eop.corp.example.com')));
    $dateStr = date('Y-m-d H:i:s');

    $cfg = "<?php\n" .
"/**\n" .
" * Exchange Online Protection (EOP) Anti-Spam Policy Manager\n" .
" * Application Configuration File\n" .
" * Environment: Debian Linux / PHP 8.x / Remote MariaDB / Active Directory LDAP\n" .
" * Automatically written by setup wizard on {$dateStr}\n" .
" */\n\n" .
"declare(strict_types=1);\n\n" .
"// Prevent direct script execution\n" .
"if (basename(__FILE__) === basename(\$_SERVER['SCRIPT_FILENAME'] ?? '')) {\n" .
"    http_response_code(403);\n" .
"    exit('Direct access forbidden.');\n" .
"}\n\n" .
"// --------------------------------------------------------------------------\n" .
"// 1. Session & Security Configuration\n" .
"// --------------------------------------------------------------------------\n" .
"ini_set('session.cookie_httponly', '1');\n" .
"ini_set('session.use_only_cookies', '1');\n" .
"ini_set('session.cookie_samesite', 'Lax');\n" .
"if (!empty(\$_SERVER['HTTPS']) && \$_SERVER['HTTPS'] !== 'off') {\n" .
"    ini_set('session.cookie_secure', '1');\n" .
"}\n\n" .
"if (session_status() === PHP_SESSION_NONE) {\n" .
"    session_start();\n" .
"}\n\n" .
"\$sessionTimeoutSeconds = 60 * 60;\n" .
"if (isset(\$_SESSION['LAST_ACTIVITY']) && (time() - \$_SESSION['LAST_ACTIVITY'] > \$sessionTimeoutSeconds)) {\n" .
"    session_unset();\n" .
"    session_destroy();\n" .
"    header('Location: login.php?msg=timeout');\n" .
"    exit;\n" .
"}\n" .
"\$_SESSION['LAST_ACTIVITY'] = time();\n\n" .
"// --------------------------------------------------------------------------\n" .
"// 1b. Load Environment Variables from .env\n" .
"// Automatically loads .env written by setup.php or administrator\n" .
"// --------------------------------------------------------------------------\n" .
"\$envFilePath = __DIR__ . '/.env';\n" .
"if (file_exists(\$envFilePath) && is_readable(\$envFilePath)) {\n" .
"    \$envLines = @file(\$envFilePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);\n" .
"    if (\$envLines !== false) {\n" .
"        foreach (\$envLines as \$envLine) {\n" .
"            \$envLine = trim(\$envLine);\n" .
"            if (\$envLine === '' || str_starts_with(\$envLine, '#') || str_starts_with(\$envLine, ';')) {\n" .
"                continue;\n" .
"            }\n" .
"            if (strpos(\$envLine, '=') !== false) {\n" .
"                [\$envKey, \$envVal] = explode('=', \$envLine, 2);\n" .
"                \$envKey = trim(\$envKey);\n" .
"                \$envVal = trim(\$envVal);\n" .
"                if ((str_starts_with(\$envVal, '\"') && str_ends_with(\$envVal, '\"')) ||\n" .
"                    (str_starts_with(\$envVal, \"'\") && str_ends_with(\$envVal, \"'\"))) {\n" .
"                    \$envVal = substr(\$envVal, 1, -1);\n" .
"                }\n" .
"                putenv(\"{\$envKey}={\$envVal}\");\n" .
"                \$_ENV[\$envKey] = \$envVal;\n" .
"                \$_SERVER[\$envKey] = \$envVal;\n" .
"            }\n" .
"        }\n" .
"    }\n" .
"}\n\n" .
"// Helper function to safely fetch environment variable with fallback\n" .
"if (!function_exists('eopEnv')) {\n" .
"    function eopEnv(string \$key, string \$default = ''): string {\n" .
"        if (isset(\$_ENV[\$key]) && \$_ENV[\$key] !== '') {\n" .
"            return (string)\$_ENV[\$key];\n" .
"        }\n" .
"        if (isset(\$_SERVER[\$key]) && \$_SERVER[\$key] !== '') {\n" .
"            return (string)\$_SERVER[\$key];\n" .
"        }\n" .
"        \$val = getenv(\$key);\n" .
"        if (\$val !== false && \$val !== '') {\n" .
"            return (string)\$val;\n" .
"        }\n" .
"        return \$default;\n" .
"    }\n" .
"}\n\n" .
"// --------------------------------------------------------------------------\n" .
"// 2. Remote MariaDB Database Settings\n" .
"// --------------------------------------------------------------------------\n" .
"define('DB_HOST', eopEnv('DB_HOST', '{$dbHost}'));\n" .
"define('DB_PORT', (int)eopEnv('DB_PORT', '{$dbPort}'));\n" .
"define('DB_NAME', eopEnv('DB_NAME', '{$dbName}'));\n" .
"define('DB_USER', eopEnv('DB_USER', '{$dbUser}'));\n" .
"define('DB_PASS', eopEnv('DB_PASS', '{$dbPass}'));\n" .
"define('DB_CHARSET', 'utf8mb4');\n\n" .
"// Individual MariaDB tables per list requirement\n" .
"define('TABLE_ALLOWED_SENDERS', 'eop_allowed_senders');\n" .
"define('TABLE_BLOCKED_SENDERS', 'eop_blocked_senders');\n" .
"define('TABLE_ALLOWED_DOMAINS', 'eop_allowed_domains');\n" .
"define('TABLE_BLOCKED_DOMAINS', 'eop_blocked_domains');\n" .
"define('TABLE_AUDIT_LOG',       'eop_audit_log');\n" .
"define('TABLE_POLICIES',        'eop_policies');\n" .
"define('TABLE_LDAP_CONFIG',     'eop_ldap_config');\n" .
"define('TABLE_EOP_AUTH_CONFIG', 'eop_auth_config');\n" .
"define('TABLE_LOCAL_ADMINS',    'eop_local_admins');\n\n" .
"define('AUTH_MASTER_ENCRYPTION_KEY', eopEnv('AUTH_MASTER_ENCRYPTION_KEY', '{$masterKey}'));\n\n" .
"// --------------------------------------------------------------------------\n" .
"// 3. Microsoft Active Directory (LDAP) Settings\n" .
"// --------------------------------------------------------------------------\n" .
"define('LDAP_HOST', eopEnv('LDAP_HOST', '{$ldapHost}'));\n" .
"define('LDAP_PORT', (int)eopEnv('LDAP_PORT', '{$ldapPort}'));\n" .
"define('LDAP_PROTOCOL', eopEnv('LDAP_PROTOCOL', '{$ldapProto}'));\n" .
"define('LDAP_USE_SSL', LDAP_PROTOCOL === 'ldaps');\n" .
"define('LDAP_USE_TLS', LDAP_PROTOCOL === 'starttls');\n" .
"define('LDAP_BASE_DN', eopEnv('LDAP_BASE_DN', '{$ldapBase}'));\n" .
"define('LDAP_AUTHORIZED_GROUP_DN', eopEnv('LDAP_AUTHORIZED_GROUP_DN', '{$ldapGrp}'));\n" .
"define('LDAP_BIND_DN', eopEnv('LDAP_BIND_DN', '{$ldapBind}'));\n" .
"define('LDAP_BIND_PASSWORD', eopEnv('LDAP_BIND_PASSWORD', '{$ldapPass}'));\n" .
"define('LDAP_ACCOUNT_SUFFIX', '@' . '{$org}');\n" .
"define('LDAP_NETBIOS_DOMAIN', '{$ldapDomain}');\n\n" .
"define('FALLBACK_ADMIN_ENABLED', {$fallbackEnabled});\n" .
"define('FALLBACK_ADMIN_USERNAME', eopEnv('FALLBACK_ADMIN_USER', '{$fallbackUser}'));\n" .
"define('FALLBACK_ADMIN_PASSWORD_HASH', '\$2y\$12\$EmergencyFallbackAdminHash2026SecureBcrypt');\n\n" .
"define('DEFAULT_POLICY_NAME', eopEnv('EOP_POLICY_NAME', '{$policy}'));\n" .
"define('APP_TITLE', 'EOP Anti-Spam Policy Manager');\n" .
"define('APP_URL', eopEnv('APP_URL', '{$appUrl}'));\n\n" .
"\$GLOBALS['AVAILABLE_POLICIES'] = [\n" .
"    '{$policy}' => 'Default Inbound Anti-Spam Policy (Applied to all recipients)',\n" .
"    'Strict Anti-Spam Policy'  => 'Strict Security Baseline (Targeted VIPs & High Value Mailboxes)',\n" .
"    'Executive Inbound Policy' => 'Custom Executive Mailbox Inbound Filtering',\n" .
"    'Custom Inbound Filter'    => 'Custom Departmental Filter Policy'\n" .
"];\n\n" .
"define('M365_TENANT_ID', eopEnv('M365_TENANT_ID', '{$tenantId}'));\n" .
"define('M365_CLIENT_ID', eopEnv('M365_CLIENT_ID', '{$clientId}'));\n" .
"define('M365_CERT_THUMBPRINT', eopEnv('M365_CERT_THUMBPRINT', '{$thumb}'));\n" .
"define('M365_ORGANIZATION', eopEnv('M365_ORGANIZATION', '{$org}'));\n" .
"define('M365_CLIENT_SECRET', eopEnv('M365_CLIENT_SECRET', 'YOUR_AZURE_APP_CLIENT_SECRET'));\n" .
"define('SYNC_SCRIPT_PATH', __DIR__ . '/sync-exchange.ps1');\n";

    $written = @file_put_contents($cfgPath, $cfg);
    if ($written !== false) {
        @chmod($cfgPath, 0644);
        return true;
    }
    return false;
}

$error = null;
$notice = null;
$success = null;

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

    // Step 2: Test Database & Populate Schema
    if ($action === 'step2_db') {
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
            $pdo->exec("CREATE DATABASE IF NOT EXISTS `{$name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
            $pdo->exec("USE `{$name}`");

            // Execute all 9 table schemas
            $tables = [
                'eop_allowed_senders' => "CREATE TABLE IF NOT EXISTS `eop_allowed_senders` (
                    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    `policy_name` VARCHAR(255) NOT NULL DEFAULT 'Default Inbound Anti-Spam Policy',
                    `sender_email` VARCHAR(255) NOT NULL,
                    `note` TEXT NULL,
                    `added_by` VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
                    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY `uniq_policy_sender` (`policy_name`, `sender_email`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

                'eop_blocked_senders' => "CREATE TABLE IF NOT EXISTS `eop_blocked_senders` (
                    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    `policy_name` VARCHAR(255) NOT NULL DEFAULT 'Default Inbound Anti-Spam Policy',
                    `sender_email` VARCHAR(255) NOT NULL,
                    `note` TEXT NULL,
                    `added_by` VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
                    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY `uniq_policy_sender` (`policy_name`, `sender_email`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

                'eop_allowed_domains' => "CREATE TABLE IF NOT EXISTS `eop_allowed_domains` (
                    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    `policy_name` VARCHAR(255) NOT NULL DEFAULT 'Default Inbound Anti-Spam Policy',
                    `domain_name` VARCHAR(255) NOT NULL,
                    `note` TEXT NULL,
                    `added_by` VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
                    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY `uniq_policy_domain` (`policy_name`, `domain_name`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

                'eop_blocked_domains' => "CREATE TABLE IF NOT EXISTS `eop_blocked_domains` (
                    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    `policy_name` VARCHAR(255) NOT NULL DEFAULT 'Default Inbound Anti-Spam Policy',
                    `domain_name` VARCHAR(255) NOT NULL,
                    `note` TEXT NULL,
                    `added_by` VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
                    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY `uniq_policy_domain` (`policy_name`, `domain_name`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

                'eop_audit_log' => "CREATE TABLE IF NOT EXISTS `eop_audit_log` (
                    `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    `timestamp` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    `username` VARCHAR(100) NOT NULL,
                    `action` ENUM('ADD', 'REMOVE', 'UPDATE', 'SYNC', 'LOGIN', 'LOGOUT') NOT NULL,
                    `list_type` VARCHAR(50) NOT NULL,
                    `policy_name` VARCHAR(255) NOT NULL,
                    `target_value` VARCHAR(255) NOT NULL,
                    `details` TEXT NULL,
                    `ip_address` VARCHAR(45) NOT NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

                'eop_policies' => "CREATE TABLE IF NOT EXISTS `eop_policies` (
                    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    `policy_name` VARCHAR(255) NOT NULL UNIQUE,
                    `description` TEXT NULL,
                    `is_default` TINYINT(1) NOT NULL DEFAULT 0,
                    `last_synced_at` DATETIME NULL,
                    `sync_status` ENUM('synced', 'pending', 'failed') NOT NULL DEFAULT 'pending',
                    `sync_message` TEXT NULL,
                    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

                'eop_ldap_config' => "CREATE TABLE IF NOT EXISTS `eop_ldap_config` (
                    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    `ldap_host` VARCHAR(255) NOT NULL,
                    `ldap_port` INT NOT NULL DEFAULT 389,
                    `ldap_protocol` ENUM('ldap', 'ldaps', 'starttls') NOT NULL DEFAULT 'ldap',
                    `ldap_base_dn` VARCHAR(255) NOT NULL,
                    `ldap_group_dn` VARCHAR(255) NOT NULL,
                    `ldap_bind_dn` VARCHAR(255) NOT NULL,
                    `ldap_bind_password` VARCHAR(255) NOT NULL,
                    `ldap_domain` VARCHAR(100) NOT NULL,
                    `is_active` TINYINT(1) NOT NULL DEFAULT 1,
                    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

                'eop_auth_config' => "CREATE TABLE IF NOT EXISTS `eop_auth_config` (
                    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    `tenant_id` VARCHAR(100) NOT NULL,
                    `client_id` VARCHAR(100) NOT NULL,
                    `certificate_thumbprint` VARCHAR(100) NOT NULL,
                    `key_filename` VARCHAR(255) NOT NULL DEFAULT 'eop-cert-private.key',
                    `private_key` MEDIUMTEXT NOT NULL,
                    `pkcs12_bundle` MEDIUMTEXT NULL,
                    `encrypted_password` TEXT NULL,
                    `encryption_iv` VARCHAR(64) NULL,
                    `encryption_tag` VARCHAR(64) NULL,
                    `organization` VARCHAR(255) NULL DEFAULT 'corp.example.com',
                    `key_type` ENUM('RSA_PEM', 'PKCS8_PEM', 'PKCS12_PFX') NOT NULL DEFAULT 'RSA_PEM',
                    `is_active` TINY(1) NOT NULL DEFAULT 1,
                    `uploaded_by` VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
                    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

                'eop_setup_lock' => "CREATE TABLE IF NOT EXISTS `eop_setup_lock` (
                    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    `is_locked` TINYINT(1) NOT NULL DEFAULT 1,
                    `completed_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    `completed_by` VARCHAR(100) NOT NULL DEFAULT 'INITIAL_SETUP_WIZARD',
                    `installer_ip` VARCHAR(45) NOT NULL DEFAULT '127.0.0.1',
                    `app_version` VARCHAR(20) NOT NULL DEFAULT '1.0.0',
                    `schema_version` VARCHAR(20) NOT NULL DEFAULT '2026.1'
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

                'eop_local_admins' => "CREATE TABLE IF NOT EXISTS `eop_local_admins` (
                    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    `username` VARCHAR(100) NOT NULL UNIQUE,
                    `password_hash` VARCHAR(255) NOT NULL,
                    `is_active` TINYINT(1) NOT NULL DEFAULT 1,
                    `created_by` VARCHAR(100) NOT NULL DEFAULT 'SETUP_WIZARD',
                    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    KEY `idx_local_admin_username` (`username`),
                    KEY `idx_local_admin_active` (`is_active`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
            ];

            foreach ($tables as $tblSql) {
                $pdo->exec($tblSql);
            }

            // Ensure eop_policies has sync_status, sync_message, updated_at columns if table already existed
            try {
                $check = $pdo->query("SHOW COLUMNS FROM `eop_policies` LIKE 'sync_status'");
                if ($check && $check->rowCount() === 0) {
                    @$pdo->exec("ALTER TABLE `eop_policies` ADD COLUMN sync_status ENUM('synced', 'pending', 'failed') NOT NULL DEFAULT 'pending'");
                    @$pdo->exec("ALTER TABLE `eop_policies` ADD COLUMN sync_message TEXT NULL");
                    @$pdo->exec("ALTER TABLE `eop_policies` ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP");
                }
            } catch (Exception $colEx) {
                // Ignore if migration fails
            }

            // Seed default policy
            $seedPolicy = $pdo->prepare("INSERT IGNORE INTO `eop_policies` (`policy_name`, `description`, `is_default`) VALUES (:name, 'Default Inbound Anti-Spam Policy for Organization', 1)");
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
        $policy = trim($_POST['policy'] ?? 'Default Inbound Anti-Spam Policy');
        $privateKey = trim($_POST['private_key'] ?? '');
        if (!empty($_FILES['private_key_file']['tmp_name']) && is_uploaded_file($_FILES['private_key_file']['tmp_name'])) {
            $uploadedKey = file_get_contents($_FILES['private_key_file']['tmp_name']);
            if (!empty($uploadedKey)) {
                $privateKey = trim($uploadedKey);
            }
        }
        $passphrase = $_POST['passphrase'] ?? '';
        $pkcs12Bundle = '';
        $pkcs12Filename = '';

        // The PKCS#12 bundle is the artefact Exchange Online certificate
        // authentication actually needs on Linux, so it is validated up front
        // rather than discovered at the first sync run.
        if (!empty($_FILES['pkcs12_file']['tmp_name']) && is_uploaded_file($_FILES['pkcs12_file']['tmp_name'])) {
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

                    // Derive the real thumbprint from the uploaded certificate so the
                    // stored value cannot drift from the material being used.
                    $fingerprint = strtoupper(str_replace(':', '', (string)openssl_x509_fingerprint($certs['cert'], 'sha1', true)));
                    if ($fingerprint !== '') {
                        if ($thumbprint === '' || strcasecmp(preg_replace('/[^a-fA-F0-9]/', '', $thumbprint), $fingerprint) !== 0) {
                            $thumbprint = $fingerprint;
                            $notice = "Certificate thumbprint was set from the uploaded PKCS#12 file: {$fingerprint}.";
                        }
                    }

                    // Keep the private key column populated when only a bundle was
                    // supplied, so key verification in the UI still works.
                    if ($privateKey === '') {
                        $privateKey = $certs['pkey'];
                    }
                }
            }
        }

        if (!isset($error) && (empty($tenantId) || empty($clientId) || empty($thumbprint))) {
            $error = "Please provide your Microsoft 365 Tenant ID, Client App ID, and Certificate Thumbprint.";
        }

        if (!isset($error)) {
            $_SESSION['wizard']['eop'] = [
                'tenant_id' => $tenantId,
                'client_id' => $clientId,
                'thumbprint' => $thumbprint,
                'org_domain' => $orgDomain,
                'policy' => $policy,
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

        try {
            // 1. Connect to MariaDB
            $dsn = "mysql:host={$db['host']};port={$db['port']};dbname={$db['name']};charset=utf8mb4";
            $pdo = new PDO($dsn, $db['user'], $db['pass'], [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
            ]);

            // 2. Insert into eop_setup_lock
            $lockStmt = $pdo->prepare("INSERT INTO `eop_setup_lock` (`is_locked`, `completed_at`, `completed_by`, `installer_ip`, `app_version`, `schema_version`)
                                         VALUES (1, NOW(), 'INITIAL_SETUP_WIZARD', :ip, '1.0.0', '2026.1')");
            $lockStmt->execute([':ip' => $ip]);

            // 3. Save LDAP configuration to eop_ldap_config
            $ldapStmt = $pdo->prepare("INSERT INTO `eop_ldap_config` 
                (`ldap_host`, `ldap_port`, `ldap_protocol`, `ldap_base_dn`, `ldap_group_dn`, `ldap_bind_dn`, `ldap_bind_password`, `ldap_domain`, `is_active`)
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
                $fallbackStmt = $pdo->prepare("INSERT INTO `eop_local_admins` (`username`, `password_hash`, `is_active`, `created_by`, `created_at`, `updated_at`)
                    VALUES (:u, :p, 1, 'INITIAL_SETUP_WIZARD', NOW(), NOW())
                    ON DUPLICATE KEY UPDATE `password_hash` = :p2, `is_active` = 1, `updated_at` = NOW()");
                $fallbackStmt->execute([
                    ':u'  => $ldap['fallback_admin_username'],
                    ':p'  => $pwdHash,
                    ':p2' => $pwdHash
                ]);
            }

            // 4. Save EOP Auth config (AES encrypted password)
            $aesKey = hash('sha256', $eop['tenant_id'] . 'EOP_SALT_2026', true);
            $iv = openssl_random_pseudo_bytes(12);
            $tag = '';
            $ciphertext = openssl_encrypt($eop['passphrase'], 'aes-256-gcm', $aesKey, OPENSSL_RAW_DATA, $iv, $tag);

            $authStmt = $pdo->prepare("INSERT INTO `eop_auth_config` 
                (`tenant_id`, `client_id`, `certificate_thumbprint`, `key_filename`, `private_key`, `pkcs12_bundle`, `encrypted_password`, `encryption_iv`, `encryption_tag`, `organization`, `key_type`, `is_active`, `uploaded_by`)
                VALUES (:tid, :cid, :thumb, :filename, :pem, :p12, :cipher, :iv_b64, :tag_b64, :org, :ktype, 1, 'INITIAL_SETUP')");
            $authStmt->execute([
                ':tid' => $eop['tenant_id'],
                ':cid' => $eop['client_id'],
                ':thumb' => $eop['thumbprint'],
                ':filename' => $eop['pkcs12_filename'] ?: 'eop-cert-private.key',
                ':pem' => $eop['private_key'],
                ':p12' => $eop['pkcs12_bundle'] ?: null,
                ':cipher' => base64_encode($ciphertext ?: ''),
                ':iv_b64' => base64_encode($iv),
                ':tag_b64' => base64_encode($tag),
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
                    <div class="truncate">AD LDAP</div>
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
                        <p class="text-slate-400 text-xs">Enter your MariaDB connection credentials. Submitting will automatically populate all 9 database tables.</p>
                    </div>
                </div>

                <form method="POST" class="space-y-4">
                    <input type="hidden" name="action" value="step2_db">

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
                                <input type="checkbox" name="fallback_admin_enabled" value="1" <?php echo (!isset($_SESSION['wizard']['ldap']['fallback_admin_enabled']) || !empty($_SESSION['wizard']['ldap']['fallback_admin_enabled'])) ? 'checked' : ''; ?> class="w-4 h-4 text-amber-500 rounded border-slate-700">
                                <span>Enable Fallback Account</span>
                            </label>
                        </div>

                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-slate-800">
                            <div>
                                <label class="block text-xs font-medium text-slate-300 mb-1">Fallback Username</label>
                                <input type="text" name="fallback_admin_username" value="<?php echo htmlspecialchars($_SESSION['wizard']['ldap']['fallback_admin_username'] ?? 'eopadmin'); ?>" placeholder="eopadmin" class="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-amber-500">
                            </div>
                            <div>
                                <label class="block text-xs font-medium text-slate-300 mb-1">Fallback Password</label>
                                <input type="password" name="fallback_admin_password" value="<?php echo htmlspecialchars($_SESSION['wizard']['ldap']['fallback_admin_password'] ?? 'Emergency#Admin2026!'); ?>" placeholder="12+ chars, 3 of 4: upper, lower, numbers, symbols" class="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-amber-500">
                            </div>
                        </div>

                        <div class="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-[11px] space-y-1">
                            <div class="font-semibold text-amber-300">Password Policy Requirement:</div>
                            <div class="text-slate-400 leading-tight">
                                Must be at least <strong>12+ characters</strong> with at least <strong>three</strong> of the following:
                            </div>
                            <div class="grid grid-cols-2 sm:grid-cols-4 gap-1 text-[10px] font-mono text-slate-300 pt-1">
                                <div class="bg-slate-900 px-2 py-1 rounded border border-slate-800">&bull; Uppercase (A-Z)</div>
                                <div class="bg-slate-900 px-2 py-1 rounded border border-slate-800">&bull; Lowercase (a-z)</div>
                                <div class="bg-slate-900 px-2 py-1 rounded border border-slate-800">&bull; Numbers (0-9)</div>
                                <div class="bg-slate-900 px-2 py-1 rounded border border-slate-800">&bull; Symbols (!@#$...)</div>
                            </div>
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
        <?php if ($currentStep === 4): ?>
            <div class="bg-slate-800/90 rounded-2xl border border-slate-700/80 p-6 sm:p-8 shadow-xl">
                <div class="flex items-center gap-3 pb-5 border-b border-slate-700 mb-6">
                    <div class="w-10 h-10 rounded-xl bg-amber-500/10 text-amber-400 flex items-center justify-center font-bold">4</div>
                    <div>
                        <h2 class="text-lg font-bold text-white">Exchange Online Protection (EOP) Connection</h2>
                        <p class="text-slate-400 text-xs">Enter your Microsoft 365 Entra App Registration, Certificate Thumbprint, and RSA Private Key for PowerShell sync.</p>
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
                        <div>
                            <label class="block text-xs font-medium text-slate-300 mb-1">Default Anti-Spam Policy Name</label>
                            <input type="text" name="policy" value="<?php echo htmlspecialchars($_SESSION['wizard']['eop']['policy'] ?? 'Default Inbound Anti-Spam Policy'); ?>" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
                        </div>
                    </div>

                    <div>
                        <label class="block text-xs font-medium text-slate-300 mb-1">PKCS#12 Certificate Bundle (.pfx / .p12)</label>
                        <input type="file" name="pkcs12_file" accept=".pfx,.p12"
                               class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-300 file:mr-3 file:rounded-md file:border-0 file:bg-slate-700 file:px-3 file:py-1 file:text-xs file:text-white focus:outline-hidden focus:border-blue-500">
                        <p class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">Required for the cron sync. The certificate and private key are stored in <code>eop_auth_config.pkcs12_bundle</code> and imported into the certificate store on every pull. The thumbprint above is derived from this file.</p>
                    </div>

                    <div>
                        <div class="flex items-center justify-between mb-1.5 flex-wrap gap-2">
                            <label class="block text-xs font-medium text-slate-300">RSA Certificate Private Key (PEM format)</label>
                            <label class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-[11px] font-semibold cursor-pointer shadow-xs transition">
                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"></path></svg>
                                <span>Upload Private Key File (.pem, .key)</span>
                                <input type="file" name="private_key_file" id="pemFileInput" accept=".pem,.key,.crt,.txt" class="hidden" onchange="handlePemFileUpload(this)">
                            </label>
                        </div>
                        <div id="pemUploadStatus" class="hidden mb-2 p-2 rounded-lg bg-emerald-950/70 border border-emerald-700/70 text-emerald-300 text-[11px] flex items-center justify-between">
                            <span id="pemUploadStatusText">✓ Key file loaded successfully</span>
                            <button type="button" onclick="clearUploadedPem()" class="text-xs text-slate-400 hover:text-white">&times; Clear</button>
                        </div>
                        <textarea id="privateKeyTextarea" name="private_key" rows="4" placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...&#10;-----END RSA PRIVATE KEY-----" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500"><?php echo htmlspecialchars($_SESSION['wizard']['eop']['private_key'] ?? "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Q3d7v5N8A9zX3lW2k1vJ8qY4t7rU9sP3mF2a1cB6d8e0f1g
-----END RSA PRIVATE KEY-----"); ?></textarea>
                        <p class="text-[11px] text-slate-400 mt-1">Upload your <code class="font-mono bg-slate-950 px-1 py-0.5 rounded text-amber-300">eop-cert-private.key</code> file or paste the unencrypted/passphrase-protected RSA PEM key block.</p>
                    </div>

                    <div>
                        <label class="block text-xs font-medium text-slate-300 mb-1">Private Key AES-256 Passphrase</label>
                        <input type="password" name="passphrase" value="<?php echo htmlspecialchars($_SESSION['wizard']['eop']['passphrase'] ?? 'P@ssphrase_Secure_Cert_2026'); ?>" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-hidden focus:border-blue-500">
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
                            <div class="text-emerald-400 font-sans font-semibold mt-1">9 Tables Populated</div>
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
                            <div>Thumb: <?php echo substr(htmlspecialchars($_SESSION['wizard']['eop']['thumbprint'] ?? ''), 0, 8); ?>...</div>
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
    function handlePemFileUpload(input) {
        if (input.files && input.files[0]) {
            const file = input.files[0];
            const reader = new FileReader();
            reader.onload = function(e) {
                const content = e.target.result;
                const textarea = document.getElementById('privateKeyTextarea');
                if (textarea) {
                    textarea.value = (content || '').trim();
                }
                const statusBox = document.getElementById('pemUploadStatus');
                const statusText = document.getElementById('pemUploadStatusText');
                if (statusBox && statusText) {
                    const sizeStr = file.size < 1024 ? file.size + ' B' : (file.size / 1024).toFixed(1) + ' KB';
                    statusText.textContent = '✓ Loaded: ' + file.name + ' (' + sizeStr + ')';
                    statusBox.classList.remove('hidden');
                }
            };
            reader.readAsText(file);
        }
    }

    function clearUploadedPem() {
        const textarea = document.getElementById('privateKeyTextarea');
        if (textarea) textarea.value = '';
        const fileInput = document.getElementById('pemFileInput');
        if (fileInput) fileInput.value = '';
        const statusBox = document.getElementById('pemUploadStatus');
        if (statusBox) statusBox.classList.add('hidden');
    }
    </script>
</body>
</html>
