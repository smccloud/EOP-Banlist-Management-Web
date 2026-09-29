-- ============================================================================
-- Exchange Online Protection (EOP) Anti-Spam Manager - MariaDB Schema
-- Separate Individual Tables Per List:
-- 1. eop_allowed_senders
-- 2. eop_blocked_senders
-- 3. eop_allowed_domains
-- 4. eop_blocked_domains
-- Plus: eop_audit_log & eop_policies
-- ============================================================================

CREATE DATABASE IF NOT EXISTS `eop_antispam_db` 
    CHARACTER SET utf8mb4 
    COLLATE utf8mb4_unicode_ci;

USE `eop_antispam_db`;

-- ----------------------------------------------------------------------------
-- Table 1: Allowed Senders (Individual Table)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `eop_antispam_db`.`eop_allowed_senders` (
    `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `policy_name` VARCHAR(128) NOT NULL DEFAULT 'Default',
    `sender_email` VARCHAR(255) NOT NULL,
    `note` VARCHAR(500) NULL DEFAULT '',
    `added_by` VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY `idx_policy_sender` (`policy_name`, `sender_email`),
    KEY `idx_policy_allowed_senders` (`policy_name`),
    KEY `idx_sender_email` (`sender_email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Table 2: Blocked Senders (Individual Table)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `eop_antispam_db`.`eop_blocked_senders` (
    `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `policy_name` VARCHAR(128) NOT NULL DEFAULT 'Default',
    `sender_email` VARCHAR(255) NOT NULL,
    `note` VARCHAR(500) NULL DEFAULT '',
    `added_by` VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY `idx_policy_sender` (`policy_name`, `sender_email`),
    KEY `idx_policy_blocked_senders` (`policy_name`),
    KEY `idx_sender_email` (`sender_email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Table 3: Allowed Domains (Individual Table)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `eop_antispam_db`.`eop_allowed_domains` (
    `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `policy_name` VARCHAR(128) NOT NULL DEFAULT 'Default',
    `domain_name` VARCHAR(255) NOT NULL,
    `note` VARCHAR(500) NULL DEFAULT '',
    `added_by` VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY `idx_policy_domain` (`policy_name`, `domain_name`),
    KEY `idx_policy_allowed_domains` (`policy_name`),
    KEY `idx_domain_name` (`domain_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Table 4: Blocked Domains (Individual Table)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `eop_antispam_db`.`eop_blocked_domains` (
    `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `policy_name` VARCHAR(128) NOT NULL DEFAULT 'Default',
    `domain_name` VARCHAR(255) NOT NULL,
    `note` VARCHAR(500) NULL DEFAULT '',
    `added_by` VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY `idx_policy_domain` (`policy_name`, `domain_name`),
    KEY `idx_policy_blocked_domains` (`policy_name`),
    KEY `idx_domain_name` (`domain_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Audit Trail Table
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `eop_antispam_db`.`eop_audit_log` (
    `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `timestamp` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `username` VARCHAR(100) NOT NULL,
    `action` ENUM('ADD', 'REMOVE', 'UPDATE', 'SYNC', 'LOGIN', 'LOGOUT') NOT NULL,
    `list_type` VARCHAR(64) NOT NULL,
    `policy_name` VARCHAR(128) NOT NULL,
    `target_value` VARCHAR(255) NOT NULL,
    `details` TEXT NULL,
    `ip_address` VARCHAR(45) NOT NULL DEFAULT '127.0.0.1',
    KEY `idx_audit_policy` (`policy_name`),
    KEY `idx_audit_username` (`username`),
    KEY `idx_audit_timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Policy Metadata & Sync State Table
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `eop_antispam_db`.`eop_policies` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `policy_name` VARCHAR(128) NOT NULL UNIQUE,
    `policy_guid` CHAR(36) NULL,
    `description` VARCHAR(255) NULL,
    `last_synced_at` DATETIME NULL,
    `sync_status` ENUM('synced', 'pending', 'failed') NOT NULL DEFAULT 'pending',
    `sync_message` TEXT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY `uniq_policy_guid` (`policy_guid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Existing installations created before policy GUIDs were supported. Both steps
-- are guarded so re-running this script against an up-to-date database is a no-op.
SET @policy_guid_col := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = 'eop_antispam_db'
      AND TABLE_NAME = 'eop_policies'
      AND COLUMN_NAME = 'policy_guid'
);
SET @policy_guid_sql := IF(@policy_guid_col = 0,
    'ALTER TABLE `eop_antispam_db`.`eop_policies` ADD COLUMN `policy_guid` CHAR(36) NULL AFTER `policy_name`',
    'DO 0');
PREPARE policy_guid_stmt FROM @policy_guid_sql;
EXECUTE policy_guid_stmt;
DEALLOCATE PREPARE policy_guid_stmt;

SET @policy_guid_key := (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = 'eop_antispam_db'
      AND TABLE_NAME = 'eop_policies'
      AND INDEX_NAME = 'uniq_policy_guid'
);
SET @policy_guid_key_sql := IF(@policy_guid_key = 0,
    'ALTER TABLE `eop_antispam_db`.`eop_policies` ADD UNIQUE KEY `uniq_policy_guid` (`policy_guid`)',
    'DO 0');
PREPARE policy_guid_key_stmt FROM @policy_guid_key_sql;
EXECUTE policy_guid_key_stmt;
DEALLOCATE PREPARE policy_guid_key_stmt;

-- Insert default policies
INSERT INTO `eop_antispam_db`.`eop_policies` (`policy_name`, `description`, `sync_status`)
VALUES 
    ('Default', 'Default Inbound Anti-Spam Policy for organization', 'pending'),
    ('Strict Anti-Spam Policy', 'Strict security filter for executive mailboxes', 'pending')
ON DUPLICATE KEY UPDATE `description` = VALUES(`description`);

-- ----------------------------------------------------------------------------
-- Table 5: LDAP Connection Settings (Database-Stored LDAP Configuration)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `eop_antispam_db`.`eop_ldap_config` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `host` VARCHAR(255) NOT NULL,
    `port` INT UNSIGNED NOT NULL DEFAULT 389,
    `protocol` ENUM('ldap', 'ldaps', 'starttls') NOT NULL DEFAULT 'ldap',
    `use_ssl` TINYINT(1) NOT NULL DEFAULT 0,
    `use_tls` TINYINT(1) NOT NULL DEFAULT 0,
    `base_dn` VARCHAR(255) NOT NULL,
    `authorized_group_dn` VARCHAR(500) NOT NULL,
    `bind_dn` VARCHAR(255) NULL DEFAULT '',
    `bind_password` VARCHAR(255) NULL DEFAULT '',
    `account_suffix` VARCHAR(100) NULL DEFAULT '@corp.example.com',
    `netbios_domain` VARCHAR(50) NULL DEFAULT 'CORP',
    `timeout_seconds` INT UNSIGNED NOT NULL DEFAULT 5,
    `is_active` TINYINT(1) NOT NULL DEFAULT 1,
    `updated_by` VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    KEY `idx_ldap_active` (`is_active`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert initial active LDAP configuration row into eop_ldap_config table
INSERT INTO `eop_antispam_db`.`eop_ldap_config` 
    (`host`, `port`, `protocol`, `use_ssl`, `use_tls`, `base_dn`, `authorized_group_dn`, `bind_dn`, `bind_password`, `account_suffix`, `netbios_domain`, `timeout_seconds`, `is_active`, `updated_by`)
VALUES 
    ('dc01.corp.example.com', 389, 'ldap', 0, 0, 'DC=corp,DC=example,DC=com', 'CN=Exchange-Admins,OU=Security Groups,DC=corp,DC=example,DC=com', 'CN=svc-eop-web,OU=Service Accounts,DC=corp,DC=example,DC=com', 'Svc_P@ssw0rd_AD_2026', '@corp.example.com', 'CORP', 5, 1, 'SYSTEM')
ON DUPLICATE KEY UPDATE `updated_at` = NOW();

-- ----------------------------------------------------------------------------
-- Table 6: Exchange Online Protection (EOP) Private Key & Certificate Auth
-- Stores uploaded private key, encrypted passphrase (AES-256-GCM), thumbprint, and tenant info
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `eop_antispam_db`.`eop_auth_config` (
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
    `key_type` ENUM('RSA_PEM', 'PKCS8_PEM', 'PKCS12_PFX') NOT NULL DEFAULT 'RSA_PEM',
    `organization` VARCHAR(255) NULL DEFAULT 'corp.example.com',
    `is_active` TINYINT(1) NOT NULL DEFAULT 1,
    `uploaded_by` VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    KEY `idx_auth_active` (`is_active`),
    KEY `idx_thumbprint` (`certificate_thumbprint`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert a disabled placeholder row. The setup wizard inserts the real active
-- record, so this row must stay is_active = 0 to avoid a second active record
-- competing with it. No secrets are stored here.
INSERT INTO `eop_antispam_db`.`eop_auth_config` 
    (`tenant_id`, `client_id`, `certificate_thumbprint`, `key_filename`, `private_key`, `encrypted_password`, `encryption_iv`, `encryption_tag`, `key_type`, `organization`, `is_active`, `uploaded_by`)
VALUES 
    ('11111111-2222-3333-4444-555555555555', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', '9A2F8B3C1D4E5F6A7B8C9D0E1F2A3B4C5D6E7F80', 'eop-cert-private.key', '[PLACEHOLDER_REPLACED_BY_SETUP_WIZARD]', '', NULL, NULL, 'RSA_PEM', 'corp.example.com', 0, 'SYSTEM')
ON DUPLICATE KEY UPDATE `updated_at` = NOW();

-- ----------------------------------------------------------------------------
-- Table 7: Setup Lock Table (Ensures initial setup routine cannot be re-run)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `eop_antispam_db`.`eop_setup_lock` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `is_locked` TINYINT(1) NOT NULL DEFAULT 1,
    `completed_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `completed_by` VARCHAR(100) NOT NULL DEFAULT 'INITIAL_SETUP_WIZARD',
    `installer_ip` VARCHAR(45) NOT NULL DEFAULT '127.0.0.1',
    `app_version` VARCHAR(20) NOT NULL DEFAULT '1.0.0',
    `schema_version` VARCHAR(20) NOT NULL DEFAULT '2026.1'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Table 8: Emergency Non-LDAP Fallback Local Administrators
-- Dedicated storage for emergency administrative access if LDAP DC connection fails
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `eop_antispam_db`.`eop_local_admins` (
    `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(100) NOT NULL UNIQUE,
    `password_hash` VARCHAR(255) NOT NULL,
    `is_active` TINYINT(1) NOT NULL DEFAULT 1,
    `created_by` VARCHAR(100) NOT NULL DEFAULT 'SETUP_WIZARD',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    KEY `idx_local_admin_username` (`username`),
    KEY `idx_local_admin_active` (`is_active`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed default emergency fallback administrator (Username: eopadmin)
INSERT INTO `eop_antispam_db`.`eop_local_admins` (`username`, `password_hash`, `is_active`, `created_by`)
VALUES ('eopadmin', '$2y$12$eopEmergencyAdminFallbackHashPlaceholder2026XyZ', 1, 'INITIAL_SETUP_WIZARD')
ON DUPLICATE KEY UPDATE `password_hash` = VALUES(`password_hash`), `is_active` = 1;

-- ----------------------------------------------------------------------------
-- Remote User Permissions Grant Example (Run on Remote MariaDB server)
-- Replace 'DEBIAN_WEB_SERVER_IP' with the actual IP of your Debian host!
-- ----------------------------------------------------------------------------
-- CREATE USER IF NOT EXISTS 'eop_app_user'@'%' IDENTIFIED BY 'P@ssw0rd_Secure_MariaDB_2026';
-- GRANT ALL PRIVILEGES ON `eop_antispam_db`.* TO 'eop_app_user'@'%';
-- FLUSH PRIVILEGES;
