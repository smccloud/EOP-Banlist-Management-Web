-- Temporary schema alignment update (generated from comparison)
USE eop-antispam;

-- Ensure eop_auth_config columns match target
SET @sql := IF(NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='eop_auth_config' AND COLUMN_NAME='pkcs12_bundle'), 'ALTER TABLE eop_auth_config ADD COLUMN pkcs12_bundle MEDIUMTEXT NULL AFTER private_key', 'DO 0');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql := IF(EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='eop_auth_config' AND COLUMN_NAME='private_key' AND IS_NULLABLE='NO' AND DATA_TYPE='text'), 'ALTER TABLE eop_auth_config MODIFY COLUMN private_key MEDIUMTEXT NOT NULL', 'DO 0');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql := IF(EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='eop_auth_config' AND COLUMN_NAME='encrypted_password' AND IS_NULLABLE='NO'), 'ALTER TABLE eop_auth_config MODIFY COLUMN encrypted_password TEXT NULL', 'DO 0');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql := IF(EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='eop_auth_config' AND COLUMN_NAME='encryption_iv' AND IS_NULLABLE='NO'), 'ALTER TABLE eop_auth_config MODIFY COLUMN encryption_iv VARCHAR(64) NULL', 'DO 0');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql := IF(EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='eop_auth_config' AND COLUMN_NAME='encryption_tag' AND IS_NULLABLE='NO'), 'ALTER TABLE eop_auth_config MODIFY COLUMN encryption_tag VARCHAR(64) NULL', 'DO 0');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS eop_sync_confirmations ( id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY, policy_name VARCHAR(255) NOT NULL, list_type VARCHAR(50) NOT NULL, local_count INT UNSIGNED NOT NULL DEFAULT 0, emote_count INT UNSIGNED NOT NULL DEFAULT 0, pending_values MEDIUMTEXT NULL, alues_truncated TINYINT(1) NOT NULL DEFAULT 0, status ENUM('pending','accepted','denied','applied') NOT NULL DEFAULT 'pending', equested_by VARCHAR(100) NOT NULL DEFAULT 'CRON_DAEMON', decided_by VARCHAR(100) NULL, decided_at DATETIME NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, UNIQUE KEY uniq_policy_list (policy_name,list_type) ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

