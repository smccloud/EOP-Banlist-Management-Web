<?php
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
        $blob = base64_decode((string)preg_replace('/\s+/', '', $storedBundle), true);
        if ($blob === false || !str_starts_with($blob, "\x30")) {
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
