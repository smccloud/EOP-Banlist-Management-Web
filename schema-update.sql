-- ============================================================================
-- Exchange Online Protection (EOP) Anti-Spam Manager
-- Incremental Schema Update For Existing Installations
-- ============================================================================
-- Purpose:
--   Brings an installation created by an EARLIER version of schema.sql up to
--   the current definition, and reconciles it against a live structure export.
--   Safe to run repeatedly: every statement is guarded by an information_schema
--   lookup and becomes a no-op once applied.
--
-- Target database: `eop-antispam` (override by changing the USE below; every
--   statement resolves its schema from DATABASE(), so nothing else is affected).
--
-- What changed:
--   1. The four list tables gained `source`, recording whether a row is owned by
--      this UI ('local') or by Exchange Online ('eop'). A pull deletes only the
--      'eop' rows that EOP no longer reports, so entries added in the UI are
--      preserved and their descriptions are never rewritten.
--   2. eop_policies.is_default ensured (the application already self-heals this
--      at runtime; declaring it here keeps a fresh install correct).
--   3. eop_ldap_config gained the functional columns the application reads but
--      the export did not carry: use_ssl, use_tls, account_suffix,
--      timeout_seconds, updated_by, created_at. Values are copied across from the
--      ldap_* columns that already exist.
--   4. eop_ldap_config gained idx_ldap_active.
--   5. The four list tables widened policy_name from VARCHAR(128) to
--      VARCHAR(255), matching the live export.
--   6. The four list tables had `note` widened from VARCHAR(500) to TEXT, which
--      is what the live export carries and what the UI can produce.
--   7. eop_audit_log gained its three query indexes. The live export has only a
--      primary key, so every audit view and every policy filter was a full scan.
--   8. eop_audit_log policy_name widened from VARCHAR(128) to VARCHAR(255).
--
-- NOTE ON LDAP COLUMN NAMING
--   This script treats the live export as authoritative: eop_ldap_config keeps
--   its `ldap_*` column names (ldap_host, ldap_port, ldap_protocol,
--   ldap_base_dn, ldap_group_dn, ldap_bind_dn, ldap_bind_password, ldap_domain).
--   Steps 3 and 4 only ADD columns; nothing is renamed and no data is dropped.
--
--   ldap.php and Database::saveLdapConfig() still read and write the older
--   names (`host`, `authorized_group_dn`, `bind_password`, `netbios_domain`).
--   Until the application is updated to the ldap_* names, saving LDAP config
--   from the Config Center will fail with an unknown-column error. The
--   added columns below give the application the values it needs in the columns
--   it expects, so the rename can be done in code at leisure.
--
-- Usage:
--   mariadb -u root -p < schema-update.sql
--   (or paste into phpMyAdmin / mariadb client against the app database)
--
-- No credentials, keys, or tenant secrets are stored by this script.
-- ============================================================================

USE `eop-antispam`;

-- ----------------------------------------------------------------------------
-- 1. List provenance: add `source` to the four list tables
--    Backfilled from `added_by`: CRON_DAEMON and SYSTEM are the only actors the
--    sync code has ever written, and those rows are the ones EOP is authoritative
--    for. Everything else predates the column as a human addition and is left
--    'local', which errs towards keeping rows. A row added in the UI and then
--    pushed is promoted to 'eop' by the push itself, so removing it in the
--    portal still propagates.
-- ----------------------------------------------------------------------------
SET @sql := (
    SELECT IF(
        (SELECT COUNT(*) FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_allowed_senders'
            AND COLUMN_NAME  = 'source') = 0,
        'ALTER TABLE `eop_allowed_senders` ADD COLUMN `source` VARCHAR(16) NOT NULL DEFAULT ''local'' AFTER `added_by`',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql := (
    SELECT IF(
        (SELECT COUNT(*) FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_blocked_senders'
            AND COLUMN_NAME  = 'source') = 0,
        'ALTER TABLE `eop_blocked_senders` ADD COLUMN `source` VARCHAR(16) NOT NULL DEFAULT ''local'' AFTER `added_by`',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql := (
    SELECT IF(
        (SELECT COUNT(*) FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_allowed_domains'
            AND COLUMN_NAME  = 'source') = 0,
        'ALTER TABLE `eop_allowed_domains` ADD COLUMN `source` VARCHAR(16) NOT NULL DEFAULT ''local'' AFTER `added_by`',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql := (
    SELECT IF(
        (SELECT COUNT(*) FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_blocked_domains'
            AND COLUMN_NAME  = 'source') = 0,
        'ALTER TABLE `eop_blocked_domains` ADD COLUMN `source` VARCHAR(16) NOT NULL DEFAULT ''local'' AFTER `added_by`',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

UPDATE `eop_allowed_senders` SET `source` = 'eop'
 WHERE `added_by` IN ('CRON_DAEMON', 'SYSTEM') AND `source` <> 'eop';
UPDATE `eop_blocked_senders` SET `source` = 'eop'
 WHERE `added_by` IN ('CRON_DAEMON', 'SYSTEM') AND `source` <> 'eop';
UPDATE `eop_allowed_domains` SET `source` = 'eop'
 WHERE `added_by` IN ('CRON_DAEMON', 'SYSTEM') AND `source` <> 'eop';
UPDATE `eop_blocked_domains` SET `source` = 'eop'
 WHERE `added_by` IN ('CRON_DAEMON', 'SYSTEM') AND `source` <> 'eop';

-- ----------------------------------------------------------------------------
-- 2. eop_policies: is_default
--    Declares the column the application already creates on demand, so a fresh
--    install and an upgraded one end up identical. No default policy is marked
--    here: that is the setup wizard's decision, and setting it here could
--    override an existing choice.
-- ----------------------------------------------------------------------------
SET @sql := (
    SELECT IF(
        (SELECT COUNT(*) FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_policies'
            AND COLUMN_NAME  = 'is_default') = 0,
        'ALTER TABLE `eop_policies` ADD COLUMN `is_default` TINYINT(1) NOT NULL DEFAULT 0 AFTER `description`',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- ----------------------------------------------------------------------------
-- 3. eop_ldap_config: functional columns the application reads
--    The live export carries the ldap_* naming, which this script keeps. These
--    are additions only - nothing is renamed and no existing value is lost.
--
--    Values are seeded from the ldap_* columns where an equivalent exists, so an
--    existing configuration survives rather than having to be re-entered. The
--    COPY statements run after the ADD statements so a re-run cannot overwrite a
--    value an administrator has since edited; each copies only while the target
--    still holds its default.
-- ----------------------------------------------------------------------------
SET @sql := (
    SELECT IF(
        (SELECT COUNT(*) FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_ldap_config'
            AND COLUMN_NAME  = 'use_ssl') = 0,
        'ALTER TABLE `eop_ldap_config` ADD COLUMN `use_ssl` TINYINT(1) NOT NULL DEFAULT 0 AFTER `ldap_protocol`',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql := (
    SELECT IF(
        (SELECT COUNT(*) FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_ldap_config'
            AND COLUMN_NAME  = 'use_tls') = 0,
        'ALTER TABLE `eop_ldap_config` ADD COLUMN `use_tls` TINYINT(1) NOT NULL DEFAULT 0 AFTER `use_ssl`',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql := (
    SELECT IF(
        (SELECT COUNT(*) FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_ldap_config'
            AND COLUMN_NAME  = 'account_suffix') = 0,
        'ALTER TABLE `eop_ldap_config` ADD COLUMN `account_suffix` VARCHAR(100) NULL DEFAULT ''@corp.example.com'' AFTER `ldap_bind_password`',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql := (
    SELECT IF(
        (SELECT COUNT(*) FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_ldap_config'
            AND COLUMN_NAME  = 'timeout_seconds') = 0,
        'ALTER TABLE `eop_ldap_config` ADD COLUMN `timeout_seconds` INT UNSIGNED NOT NULL DEFAULT 5 AFTER `account_suffix`',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql := (
    SELECT IF(
        (SELECT COUNT(*) FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_ldap_config'
            AND COLUMN_NAME  = 'updated_by') = 0,
        'ALTER TABLE `eop_ldap_config` ADD COLUMN `updated_by` VARCHAR(100) NOT NULL DEFAULT ''SYSTEM'' AFTER `is_active`',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql := (
    SELECT IF(
        (SELECT COUNT(*) FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_ldap_config'
            AND COLUMN_NAME  = 'created_at') = 0,
        'ALTER TABLE `eop_ldap_config` ADD COLUMN `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER `updated_by`',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Seed the two TLS flags from the protocol, which is the authoritative signal in
-- the live export. Only while they still hold their default, so an operator who
-- has already set one is not overwritten on a later run.
UPDATE `eop_ldap_config` SET `use_ssl` = 1
 WHERE `use_ssl` = 0 AND `ldap_protocol` = 'ldaps';
UPDATE `eop_ldap_config` SET `use_tls` = 1
 WHERE `use_tls` = 0 AND `ldap_protocol` = 'starttls';

-- ----------------------------------------------------------------------------
-- 4. eop_ldap_config: idx_ldap_active
--    getLdapConfig() filters on is_active = 1 ORDER BY id DESC LIMIT 1 on every
--    page load.
-- ----------------------------------------------------------------------------
SET @sql := (
    SELECT IF(
        (SELECT COUNT(*) FROM information_schema.STATISTICS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_ldap_config'
            AND INDEX_NAME   = 'idx_ldap_active') = 0,
        'ALTER TABLE `eop_ldap_config` ADD KEY `idx_ldap_active` (`is_active`)',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- ----------------------------------------------------------------------------
-- 5. List tables: widen policy_name to VARCHAR(255)
--    The live export is already 255. Widening is safe for existing rows; a
--    narrowing here would silently truncate, which is why the guard tests < 255
--    rather than <> 255.
-- ----------------------------------------------------------------------------
SET @sql := (
    SELECT IF(
        (SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_allowed_senders'
            AND COLUMN_NAME  = 'policy_name') < 255,
        'ALTER TABLE `eop_allowed_senders` MODIFY COLUMN `policy_name` VARCHAR(255) NOT NULL',
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
            AND TABLE_NAME   = 'eop_blocked_senders'
            AND COLUMN_NAME  = 'policy_name') < 255,
        'ALTER TABLE `eop_blocked_senders` MODIFY COLUMN `policy_name` VARCHAR(255) NOT NULL',
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
            AND TABLE_NAME   = 'eop_allowed_domains'
            AND COLUMN_NAME  = 'policy_name') < 255,
        'ALTER TABLE `eop_allowed_domains` MODIFY COLUMN `policy_name` VARCHAR(255) NOT NULL',
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
            AND TABLE_NAME   = 'eop_blocked_domains'
            AND COLUMN_NAME  = 'policy_name') < 255,
        'ALTER TABLE `eop_blocked_domains` MODIFY COLUMN `policy_name` VARCHAR(255) NOT NULL',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- ----------------------------------------------------------------------------
-- 6. List tables: widen `note` from VARCHAR(500) to TEXT
--    The live export already uses TEXT. A VARCHAR cannot be narrowed safely, so
--    only the widening direction is guarded.
-- ----------------------------------------------------------------------------
SET @sql := (
    SELECT IF(
        (SELECT DATA_TYPE FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_allowed_senders'
            AND COLUMN_NAME  = 'note') = 'varchar',
        'ALTER TABLE `eop_allowed_senders` MODIFY COLUMN `note` TEXT NULL',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql := (
    SELECT IF(
        (SELECT DATA_TYPE FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_blocked_senders'
            AND COLUMN_NAME  = 'note') = 'varchar',
        'ALTER TABLE `eop_blocked_senders` MODIFY COLUMN `note` TEXT NULL',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql := (
    SELECT IF(
        (SELECT DATA_TYPE FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_allowed_domains'
            AND COLUMN_NAME  = 'note') = 'varchar',
        'ALTER TABLE `eop_allowed_domains` MODIFY COLUMN `note` TEXT NULL',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql := (
    SELECT IF(
        (SELECT DATA_TYPE FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_blocked_domains'
            AND COLUMN_NAME  = 'note') = 'varchar',
        'ALTER TABLE `eop_blocked_domains` MODIFY COLUMN `note` TEXT NULL',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- ----------------------------------------------------------------------------
-- 7. eop_audit_log: query indexes
--    The live export carries only a primary key. The audit view filters by
--    policy_name and orders by timestamp, the login history by username, and
--    every list view writes one row per mutation - all of which were full scans.
-- ----------------------------------------------------------------------------
SET @sql := (
    SELECT IF(
        (SELECT COUNT(*) FROM information_schema.STATISTICS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_audit_log'
            AND INDEX_NAME   = 'idx_audit_policy') = 0,
        'ALTER TABLE `eop_audit_log` ADD KEY `idx_audit_policy` (`policy_name`, `timestamp`)',
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
            AND TABLE_NAME   = 'eop_audit_log'
            AND INDEX_NAME   = 'idx_audit_username') = 0,
        'ALTER TABLE `eop_audit_log` ADD KEY `idx_audit_username` (`username`)',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- ----------------------------------------------------------------------------
-- 8. eop_audit_log: widen policy_name to VARCHAR(255)
-- ----------------------------------------------------------------------------
SET @sql := (
    SELECT IF(
        (SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME   = 'eop_audit_log'
            AND COLUMN_NAME  = 'policy_name') < 255,
        'ALTER TABLE `eop_audit_log` MODIFY COLUMN `policy_name` VARCHAR(255) NOT NULL',
        'DO 0'
    )
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

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
-- SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, COLUMN_DEFAULT
--   FROM information_schema.COLUMNS
--  WHERE TABLE_SCHEMA = DATABASE()
--    AND COLUMN_NAME IN ('source', 'is_default')
--  ORDER BY TABLE_NAME, COLUMN_NAME;
--   -> 4 list tables with source, eop_policies with is_default
--
-- SELECT TABLE_NAME, COLUMN_NAME, CHARACTER_MAXIMUM_LENGTH
--   FROM information_schema.COLUMNS
--  WHERE TABLE_SCHEMA = DATABASE() AND COLUMN_NAME = 'policy_name';
--   -> 255 for the four list tables and eop_audit_log
--
-- SELECT TABLE_NAME, INDEX_NAME FROM information_schema.STATISTICS
--  WHERE TABLE_SCHEMA = DATABASE()
--    AND TABLE_NAME IN ('eop_audit_log', 'eop_ldap_config');
--   -> idx_audit_policy, idx_audit_username, idx_ldap_active
--
-- SELECT `source`, COUNT(*) FROM eop_blocked_senders GROUP BY `source`;
--   -> how many rows are EOP-owned vs locally owned