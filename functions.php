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
