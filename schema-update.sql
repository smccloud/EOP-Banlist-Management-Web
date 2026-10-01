-- ============================================================================
-- Exchange Online Protection (EOP) Anti-Spam Manager
-- Incremental Schema Update For Existing Installations
-- ============================================================================
-- Purpose:
--   Brings a database created by an EARLIER version of schema.sql up to the
--   current definition. Safe to run repeatedly: every statement is guarded by
--   an information_schema lookup and becomes a no-op once applied.
--
-- What changed:
--   1. eop_auth_config renamed `private_key_pem` -> `private_key` and widened
--      to MEDIUMTEXT so large RSA/PKCS#8 keys are not truncated.
--   2. eop_auth_config gained `pkcs12_bundle` (encrypted PKCS#12/PFX bundle).
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

USE `eop_antispam_db`;

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
        'ALTER TABLE `eop_auth_config` CHANGE COLUMN `private_key_pem` `private_key` MEDIUMTEXT NOT NULL',
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
        'ALTER TABLE `eop_auth_config` ADD COLUMN `private_key` MEDIUMTEXT NOT NULL DEFAULT ''''',
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
        'ALTER TABLE `eop_auth_config` MODIFY COLUMN `private_key` MEDIUMTEXT NOT NULL',
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
        'ALTER TABLE `eop_auth_config` ADD COLUMN `pkcs12_bundle` MEDIUMTEXT NULL AFTER `private_key`',
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
        'ALTER TABLE `eop_auth_config` MODIFY COLUMN `tenant_id` VARCHAR(100) NOT NULL',
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
            AND COLUMN_NAME  = 'client_id') < 100,
        'ALTER TABLE `eop_auth_config` MODIFY COLUMN `client_id` VARCHAR(100) NOT NULL',
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
        'ALTER TABLE `eop_auth_config` MODIFY COLUMN `certificate_thumbprint` VARCHAR(100) NOT NULL',
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
        'ALTER TABLE `eop_auth_config` MODIFY COLUMN `key_filename` VARCHAR(255) NOT NULL DEFAULT ''eop-cert-private.key''',
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
        'ALTER TABLE `eop_auth_config` MODIFY COLUMN `encrypted_password` TEXT NULL',
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
        'ALTER TABLE `eop_auth_config` MODIFY COLUMN `encryption_iv` VARCHAR(64) NULL',
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
        'ALTER TABLE `eop_auth_config` MODIFY COLUMN `encryption_tag` VARCHAR(64) NULL',
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
        'ALTER TABLE `eop_auth_config` MODIFY COLUMN `organization` VARCHAR(255) NULL DEFAULT ''corp.example.com''',
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
        'ALTER TABLE `eop_auth_config` ADD KEY `idx_auth_active` (`is_active`)',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql := (
    SELECT IF(
        (SELECT COUNT(*) FROM information_schema.STATISTICS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_auth_config'
            AND INDEX_NAME   = 'idx_thumbprint') = 0,
        'ALTER TABLE `eop_auth_config` ADD KEY `idx_thumbprint` (`certificate_thumbprint`)',
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
CREATE TABLE IF NOT EXISTS `eop_sync_confirmations` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `policy_name` VARCHAR(255) NOT NULL,
    `list_type` VARCHAR(50) NOT NULL,
    `local_count` INT UNSIGNED NOT NULL DEFAULT 0,
    `remote_count` INT UNSIGNED NOT NULL DEFAULT 0,
    `pending_values` MEDIUMTEXT NULL,
    `values_truncated` TINYINT(1) NOT NULL DEFAULT 0,
    `status` ENUM('pending', 'accepted', 'denied', 'applied') NOT NULL DEFAULT 'pending',
    `requested_by` VARCHAR(100) NOT NULL DEFAULT 'CRON_DAEMON',
    `decided_by` VARCHAR(100) NULL,
    `decided_at` DATETIME NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY `uniq_policy_list` (`policy_name`, `list_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- 9. Deactivate the placeholder row seeded by the older schema.sql
--    Matches only the known fake seed values, so a genuine wizard record is
--    never touched. Run the wizard's certificate step again if no active row
--    remains afterwards.
-- ----------------------------------------------------------------------------
UPDATE `eop_auth_config`
   SET `is_active` = 0
 WHERE `is_active` = 1
   AND `certificate_thumbprint` = '9A2F8B3C1D4E5F6A7B8C9D0E1F2A3B4C5D6E7F80'
   AND `private_key` LIKE '%INITIAL_SEED_PRIVATE_KEY%';

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
--   FROM eop_auth_config ORDER BY id;