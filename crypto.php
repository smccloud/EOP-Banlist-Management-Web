<?php
// ==============================================================================
// Shared encryption envelope for secrets stored in MariaDB
//
// Required by both setup.php (initial install) and database.php (runtime) so the
// key derivation and envelope format can never drift apart. They previously did
// drift: the wizard encrypted the passphrase with a tenant-derived key while the
// application decrypted with AUTH_MASTER_ENCRYPTION_KEY, so wizard-written
// passphrases could not be read back.
//
// Envelope format: EOPENC1:<base64( iv[12] || tag[16] || ciphertext )>
//
// Every value carries its own IV and tag, so the private key, the PKCS#12 bundle
// and the passphrase can be encrypted independently without sharing an IV, and no
// additional iv/tag columns are required per field.
//
// A stored value without the EOPENC1 prefix is treated as legacy plaintext and is
// returned unchanged, so records written before this format can still be read.
// ==============================================================================

declare(strict_types=1);

if (!defined('EOP_SECRET_PREFIX')) {
    define('EOP_SECRET_PREFIX', 'EOPENC1:');
}

if (!function_exists('eopEncryptionKey')) {
    /**
     * Derive the 256-bit AES key from the master key in .env (AUTH_MASTER_ENCRYPTION_KEY)
     */
    function eopEncryptionKey(): string {
        $secret = defined('AUTH_MASTER_ENCRYPTION_KEY') && AUTH_MASTER_ENCRYPTION_KEY !== ''
            ? AUTH_MASTER_ENCRYPTION_KEY
            : (getenv('AUTH_MASTER_ENCRYPTION_KEY') ?: ($_ENV['AUTH_MASTER_ENCRYPTION_KEY'] ?? ''));

        if ($secret === '') {
            $secret = 'eop_master_secret';
        }

        return hash('sha256', $secret, true);
    }
}

if (!function_exists('eopIsEncrypted')) {
    function eopIsEncrypted(?string $stored): bool {
        return $stored !== null && str_starts_with($stored, EOP_SECRET_PREFIX);
    }
}

if (!function_exists('eopEncryptSecret')) {
    /**
     * Encrypt a secret for storage. An empty value stays empty rather than becoming
     * an envelope, so NULL/empty columns keep their original meaning.
     */
    function eopEncryptSecret(string $plaintext): string {
        if ($plaintext === '') {
            return '';
        }

        $iv = random_bytes(12);
        $tag = '';
        $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', eopEncryptionKey(), OPENSSL_RAW_DATA, $iv, $tag, '', 16);

        if ($ciphertext === false) {
            throw new RuntimeException('AES-256-GCM encryption of the secret failed.');
        }

        return EOP_SECRET_PREFIX . base64_encode($iv . $tag . $ciphertext);
    }
}

if (!function_exists('eopDecryptSecret')) {
    /**
     * Decrypt a stored secret. Returns null when the envelope is malformed or the
     * master key does not match, so callers can distinguish failure from an empty value.
     */
    function eopDecryptSecret(?string $stored): ?string {
        if ($stored === null) {
            return null;
        }

        if ($stored === '') {
            return '';
        }

        if (!eopIsEncrypted($stored)) {
            return $stored;
        }

        $raw = base64_decode(substr($stored, strlen(EOP_SECRET_PREFIX)), true);
        if ($raw === false || strlen($raw) < 29) {
            error_log('[crypto] Stored secret envelope is malformed.');
            return null;
        }

        $iv = substr($raw, 0, 12);
        $tag = substr($raw, 12, 16);
        $ciphertext = substr($raw, 28);

        $decrypted = openssl_decrypt($ciphertext, 'aes-256-gcm', eopEncryptionKey(), OPENSSL_RAW_DATA, $iv, $tag);
        if ($decrypted === false) {
            error_log('[crypto] Failed to decrypt a stored secret. AUTH_MASTER_ENCRYPTION_KEY does not match this record.');
            return null;
        }

        return $decrypted;
    }
}
