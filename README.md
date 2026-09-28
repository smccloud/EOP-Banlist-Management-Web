# Exchange Online Protection (EOP) Anti-Spam Policy Manager

A production-ready **PHP 8** web application designed for **Debian Linux** and backed by a **remote MariaDB server** across individual dedicated tables, authenticated via **Microsoft Active Directory (AD) LDAP Group Distinguished Name (Group DN)** with **Service Account Bind Password Authorization**, featuring **Dark Mode**, **App-Only Certificate-Based Authentication (CBA)**, an **Exchange Online PowerShell / Cron automation engine**, and an interactive **React & TypeScript workbench / simulator**.

---

## 📑 Table of Contents

- [Overview & Architecture](#overview--architecture)
- [Key Features & Highlights](#key-features--highlights)
  - [Push All Changes to EOP (Global Staging & List-by-List Breakdown)](#push-all-changes-to-eop-global-staging--list-by-list-breakdown)
  - [Split Smart Sorter (Allowed & Blocked Buttons)](#split-smart-sorter-allowed--blocked-buttons)
  - [Active Directory LDAP with Bind Password Authorization](#active-directory-ldap-with-bind-password-authorization)
  - [Emergency Non-LDAP Fallback Administrator](#emergency-non-ldap-fallback-administrator)
  - [Dedicated Table Per List Architecture](#dedicated-table-per-list-architecture)
  - [Exchange Online Certificate-Based Authentication (CBA)](#exchange-online-certificate-based-authentication-cba)
  - [In-App Modals & Duplicate Entry Prevention](#in-app-modals--duplicate-entry-prevention)
  - [Auto-Dismiss Notification Banners & Staged Pending Strips](#auto-dismiss-notification-banners--staged-pending-strips)
- [Initial Run Setup Routine (`setup.php`)](#initial-run-setup-routine-setupphp)
- [Database Schema (9 Dedicated MariaDB Tables)](#database-schema-9-dedicated-mariadb-tables)
- [Active Directory LDAP Authentication & Authorization](#active-directory-ldap-authentication--authorization)
- [Exchange Online Protection Sync Engine](#exchange-online-protection-sync-engine)
  - [Scheduled Cron Daemon (Pull-Only)](#scheduled-cron-daemon-pull-only)
  - [Manual Admin Push All (Exchange Online)](#manual-admin-push-all-exchange-online)
- [Web Interface & UX Capabilities](#web-interface--ux-capabilities)
  - [Smart Sorter Classification Engine](#smart-sorter-classification-engine)
  - [Smart Domain Hierarchy Views](#smart-domain-hierarchy-views)
  - [Dark Mode & Audit Trail](#dark-mode--audit-trail)
- [Debian Linux Server Deployment](#debian-linux-server-deployment)
  - [Prerequisites](#prerequisites)
  - [Step 1: Remote MariaDB Database Setup](#step-1-remote-mariadb-database-setup)
  - [Step 2: Automated Installation on Debian](#step-2-automated-installation-on-debian)
  - [Step 3: Manual Debian Setup (Alternative)](#step-3-manual-debian-setup-alternative)
  - [Step 4: NGINX Server Block Configuration](#step-4-nginx-server-block-configuration)
  - [Step 5: Exchange Online Management on Linux](#step-5-exchange-online-management-on-linux)
- [Project File Structure & Inventory](#project-file-structure--inventory)
- [Configuration Reference (`config.php`, `.env`, & Database Tables)](#configuration-reference-configphp-env--database-tables)
- [Troubleshooting & FAQ](#troubleshooting--faq)
- [License](#license)

---

## Overview & Architecture

Microsoft 365 Exchange Online Protection (EOP) allows administrators to configure anti-spam policies (`Set-HostedContentFilterPolicy`) with custom lists of allowed senders, blocked senders, allowed domains, and blocked domains. In enterprise environments, managing these entries directly in PowerShell or the Microsoft Defender Portal can lead to lack of auditability, accidental overwrites, or administrative bottlenecks.

This solution provides:
1. **Centralized Web Portal**: Secure, multi-user web dashboard with dark mode, full search/filter capabilities, smart domain clustering, and CSV export.
2. **Dedicated MariaDB Tables**: Uses an **individual MariaDB table per list** on a remote database server for strict data isolation, indexing, and transactional integrity.
3. **Global Change Staging & Push All**: Any pending additions or removals across **all 4 tables** and policies are staged globally and pushed together to Microsoft 365 in a single operation, with full list-by-list reporting.
4. **Split Smart Sorters (Allowed & Blocked)**: Dedicated one-click intake buttons that parse mixed batches of emails and domains, auto-routing them directly into the appropriate Allowlist or Blocklist tables.
5. **Database-Stored Configuration**: LDAP directory connection settings (`eop_ldap_config`) and Exchange Online authentication credentials (`eop_auth_config`) can be safely modified through the UI without editing server configuration files.
6. **Active Directory Security with Bind Password Authorization**: Restricts system login strictly to members of an authorized **Active Directory Group Distinguished Name (Group DN)**. Supports service account **Bind DN and Bind Password** authorization using standard **plain LDAP (Port 389)**. **LDAPS is NOT required**, removing certificate hassles while optionally supporting LDAPS (Port 636) and StartTLS.
7. **Emergency Non-LDAP Fallback Account**: Provides an emergency local administrative login with enforced password complexity if the Active Directory domain controller is offline or unreachable.
8. **Exchange Online Sync Safeguards**:
   - **Scheduled Cron is strictly Pull-Only**: Never blindly overwrites Microsoft 365 in the background; only pulls remote changes into MariaDB.
   - **Manual Admin Push All**: Pushing MariaDB lists to Microsoft 365 requires an intentional administrator action with pre-push confirmation modals and post-push summaries.
9. **Initial Run Setup Routine (`setup.php`)**: A 5-step deployment wizard that validates database and directory connectivity, builds the schema, and permanently locks itself against re-execution.

---

## Key Features & Highlights

### Push All Changes to EOP (Global Staging & List-by-List Breakdown)

- **Cross-Table Global Staging**:
  - Additions and deletions across all 4 anti-spam tables (`eop_allowed_senders`, `eop_blocked_senders`, `eop_allowed_domains`, and `eop_blocked_domains`) are staged into a unified pending change queue.
  - The administrator does not need to push each table individually; clicking **"Push All Changes to EOP"** pushes all pending modifications across all lists and policies in a single, atomic operation.
  - Dynamic pending change counter badges on the action bar and navigation bar display the exact number of staged changes waiting to be pushed.
- **Pre-Push Confirmation Modal**:
  - Outlines the policy name, target tenant, and an itemized breakdown of staged additions and removals for each of the 4 tables.
- **Post-Push Result Notification & Audit Summary**:
  - Immediately following push execution, an informative modal and banner clearly detail:
    - **Allowed Senders**: Exact items added or removed (or confirmation that existing entries were preserved).
    - **Blocked Senders**: Exact items added or removed.
    - **Allowed Domains**: Exact items added or removed.
    - **Blocked Domains**: Exact items added or removed.
    - Resulting active EOP list entries in Microsoft 365.
    - The executed PowerShell cmdlet (`Set-HostedContentFilterPolicy`).
    - Recorded audit log entry in `eop_audit_log`.

### Split Smart Sorter (Allowed & Blocked Buttons)

The unified intake engine is split into two dedicated, color-coded buttons on the list toolbar:

1. **Smart Sort Allowed** (Emerald/Green theme with shield icon):
   - Directly targets `eop_allowed_senders` and `eop_allowed_domains`.
   - Automatically routes email addresses containing `@` into the Allowed Senders table.
   - Automatically routes domain names (including wildcards like `*.partner.com`) into the Allowed Domains table.
2. **Smart Sort Blocked** (Rose/Red theme with ban icon):
   - Directly targets `eop_blocked_senders` and `eop_blocked_domains`.
   - Automatically routes email addresses containing `@` into the Blocked Senders table.
   - Automatically routes domain names into the Blocked Domains table.
3. **Real-Time Classification & Deduplication Engine**:
   - Syntax validation for RFC-compliant email addresses and valid domain names.
   - Duplicate prevention against current MariaDB table records and within the batch.
   - Live visual preview displaying sender count, domain count, duplicate count, and batch routing breakdown before committing.

### Active Directory LDAP with Bind Password Authorization

- **Standard Plain LDAP (Port 389) Supported by Default**: LDAPS is **not required**. Connects directly to Windows Domain Controllers without importing internal CA certificates on Debian. Also supports LDAPS (636) and StartTLS (389).
- **Service Account Bind Password Authorization**:
  - Supports entering an authorized service account **Bind DN** and **Bind Password** used by `LdapAuth` to authenticate against Active Directory before querying group memberships.
  - Stored securely in MariaDB `eop_ldap_config` table.
  - Password visibility toggle (Show/Hide) and lock indicator in the setup wizard and Keys & LDAP settings view.
- **Group Distinguished Name (Group DN) Access Control**:
  - Evaluates recursive / nested group membership using LDAP matching rule OID `1.2.840.113556.1.4.1941` (`LDAP_MATCHING_RULE_IN_CHAIN`).
- **Live Connection & Authorization Test**:
  - Interactive test utility verifying domain controller reachability, bind credentials, Base DN resolution, and Group DN lookup.

### Emergency Non-LDAP Fallback Administrator

- In the event of an Active Directory domain controller outage or network isolation, an emergency local fallback administrator account can be configured during initial setup or in `config.php`.
- **Enforced Password Policy**: Minimum 12 characters requiring at least three character categories (uppercase, lowercase, numbers, special characters).
- Stored as a secure PHP `password_hash()` (Bcrypt / Argon2id).

### Dedicated Table Per List Architecture

- Each list resides in its own dedicated MariaDB table:
  - `eop_allowed_senders`
  - `eop_blocked_senders`
  - `eop_allowed_domains`
  - `eop_blocked_domains`
- Additional dedicated tables support audit logging (`eop_audit_log`), policy registries (`eop_policies`), runtime LDAP settings (`eop_ldap_config`), Exchange Online certificates (`eop_auth_config`), and setup lockout (`eop_setup_lock`).

### Exchange Online Certificate-Based Authentication (CBA)

- Secure, secretless app-only authentication to Exchange Online Protection.
- RSA private key (`.pem`, `.key`, `.pfx`) stored in MariaDB `eop_auth_config`.
- Passphrase encrypted using **AES-256-GCM** before writing to the database.

### In-App Modals & Duplicate Entry Prevention

- Designed specifically for modern sandboxed environments (where browser `alert()` or `confirm()` are blocked).
- **Duplicate Entry Warning Modal**: Pops up immediately if an administrator attempts to add an existing email or domain, displaying who added the original record, timestamp, and justification note.
- **Delete Confirmation Modal**: Clear verification dialog before staging deletions.

### Auto-Dismiss Notification Banners & Staged Pending Strips

To keep the interface clean, compact, and responsive, items that appear dynamically between the action toolbar buttons and the anti-spam list automatically dismiss:
- **Global Notification Banner**: Success, warning, and operational status alerts (e.g. entry additions, bulk import results, Smart Sorter completions, deletions, and CSV export notices) automatically dismiss after **5 seconds** with a smooth fade animation. An immediate "Dismiss" button with an `X` icon is also available for instant closure.
- **Staged Pending Changes Notice Strip**: When additions or deletions are staged across any of the 4 tables, an informative blue summary strip appears between the toolbar buttons and the list detailing what was staged, and automatically dismisses after **6 seconds**. Persistent badges on the **"Push All Changes to EOP"** action button and top navigation bar maintain continuous visibility of pending counts without permanently shifting the table layout.

---

## Initial Run Setup Routine (`setup.php`)

The application features an automated initial setup routine (`setup.php`) executed upon first deployment:

1. **Step 1 - Requirements & Environment Check**:
   - Verifies PHP 8.1+, PDO MySQL extension, OpenSSL, and LDAP module (`php-ldap`).
2. **Step 2 - Remote MariaDB Database Setup**:
   - Collects host, port, database name, and credentials.
   - Tests remote database connectivity and populates all 9 required schema tables.
3. **Step 3 - Active Directory LDAP & Fallback Admin**:
   - Configures Domain Controller host, port, protocol (Plain LDAP 389, LDAPS 636, StartTLS), Base DN, **Service Account Bind DN**, and **Bind Password for LDAP Authorization**.
   - Configures the mandatory **Authorized Group DN** with live bind testing.
   - Optionally configures the emergency non-LDAP fallback administrator.
4. **Step 4 - Microsoft 365 Exchange Online Protection (EOP)**:
   - Configures Tenant ID, Client App ID, Certificate Thumbprint, Organization Domain, target anti-spam policy name, and RSA Private Key with AES-256-GCM encrypted passphrase.
5. **Step 5 - Review & Permanent Security Lock**:
   - Summarizes all configured parameters.
   - Writes `config.php` and creates a filesystem lock file (`installed.lock`) alongside the MariaDB `eop_setup_lock` table.
   - **Strict Re-Run Prevention**: Subsequent requests to `setup.php` immediately respond with **403 Forbidden** and cannot be re-executed without deliberate root-level intervention.

---

## Database Schema (9 Dedicated MariaDB Tables)

All policy lists and system configurations are stored across individual dedicated tables on your remote MariaDB server:

```sql
CREATE DATABASE IF NOT EXISTS `eop_antispam_db` 
  DEFAULT CHARACTER SET utf8mb4 
  COLLATE utf8mb4_unicode_ci;

USE `eop_antispam_db`;

-- 1. Allowed Senders Table
CREATE TABLE IF NOT EXISTS `eop_allowed_senders` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `policy_name` VARCHAR(128) NOT NULL,
  `sender_email` VARCHAR(255) NOT NULL,
  `note` TEXT NULL,
  `added_by` VARCHAR(128) NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY `uk_policy_sender` (`policy_name`, `sender_email`),
  INDEX `idx_sender_email` (`sender_email`)
) ENGINE=InnoDB;

-- 2. Blocked Senders Table
CREATE TABLE IF NOT EXISTS `eop_blocked_senders` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `policy_name` VARCHAR(128) NOT NULL,
  `sender_email` VARCHAR(255) NOT NULL,
  `note` TEXT NULL,
  `added_by` VARCHAR(128) NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY `uk_policy_blocked_sender` (`policy_name`, `sender_email`),
  INDEX `idx_blocked_sender` (`sender_email`)
) ENGINE=InnoDB;

-- 3. Allowed Domains Table
CREATE TABLE IF NOT EXISTS `eop_allowed_domains` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `policy_name` VARCHAR(128) NOT NULL,
  `domain_name` VARCHAR(255) NOT NULL,
  `note` TEXT NULL,
  `added_by` VARCHAR(128) NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY `uk_policy_domain` (`policy_name`, `domain_name`),
  INDEX `idx_domain_name` (`domain_name`)
) ENGINE=InnoDB;

-- 4. Blocked Domains Table
CREATE TABLE IF NOT EXISTS `eop_blocked_domains` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `policy_name` VARCHAR(128) NOT NULL,
  `domain_name` VARCHAR(255) NOT NULL,
  `note` TEXT NULL,
  `added_by` VARCHAR(128) NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY `uk_policy_blocked_domain` (`policy_name`, `domain_name`),
  INDEX `idx_blocked_domain` (`domain_name`)
) ENGINE=InnoDB;

-- 5. Audit Trail Log Table
CREATE TABLE IF NOT EXISTS `eop_audit_log` (
  `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `action` VARCHAR(32) NOT NULL,
  `target_table` VARCHAR(64) NOT NULL,
  `policy_name` VARCHAR(128) NOT NULL,
  `target_value` VARCHAR(255) NOT NULL,
  `username` VARCHAR(128) NOT NULL,
  `details` TEXT NULL,
  `ip_address` VARCHAR(45) NOT NULL,
  `timestamp` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_policy_timestamp` (`policy_name`, `timestamp`)
) ENGINE=InnoDB;

-- 6. Anti-Spam Policy Registry Table
CREATE TABLE IF NOT EXISTS `eop_policies` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `policy_name` VARCHAR(128) NOT NULL UNIQUE,
  `description` VARCHAR(255) NULL,
  `last_synced_at` DATETIME NULL,
  `sync_status` VARCHAR(32) DEFAULT 'PENDING',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 7. Database-Stored LDAP Connection Configuration Table (With Bind Password)
CREATE TABLE IF NOT EXISTS `eop_ldap_config` (
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
  INDEX `idx_ldap_active` (`is_active`)
) ENGINE=InnoDB;

-- 8. Database-Stored Exchange Online CBA Credentials Table
CREATE TABLE IF NOT EXISTS `eop_auth_config` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `tenant_id` VARCHAR(100) NOT NULL,
  `client_id` VARCHAR(100) NOT NULL,
  `certificate_thumbprint` VARCHAR(100) NOT NULL,
  `organization` VARCHAR(255) NOT NULL,
  `key_filename` VARCHAR(255) NOT NULL DEFAULT 'eop-cert-private.key',
  `private_key_pem` MEDIUMTEXT NOT NULL,
  `encrypted_passphrase` TEXT NULL,
  `auth_type` VARCHAR(50) NOT NULL DEFAULT 'CertificateThumbprint',
  `is_active` TINYINT(1) NOT NULL DEFAULT 1,
  `updated_by` VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 9. Setup Wizard Lockout Table
CREATE TABLE IF NOT EXISTS `eop_setup_lock` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `is_locked` TINYINT(1) NOT NULL DEFAULT 1,
  `locked_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `locked_by_ip` VARCHAR(45) NOT NULL,
  `install_version` VARCHAR(20) NOT NULL DEFAULT '1.0.0'
) ENGINE=InnoDB;
```

---

## Active Directory LDAP Authentication & Authorization

The application queries Active Directory connection parameters directly from the `eop_ldap_config` table:

1. **Service Account Bind Authorization**:
   - If a service account Bind DN and Bind Password are configured in `eop_ldap_config`, `LdapAuth` first binds using those credentials:
     ```php
     $serviceBound = @ldap_bind($this->ldapConn, $this->ldapConfig['bind_dn'], $this->ldapConfig['bind_pass']);
     ```
   - If no service account is configured, anonymous or direct user bind is used.
2. **User Search & Authentication**:
   - Searches for the user by `sAMAccountName` or `userPrincipalName` under `base_dn`:
     ```ldap
     (|(sAMAccountName=<USER>)(userPrincipalName=<USER>))
     ```
   - Re-binds using the resolved user DN and provided credentials to verify password authenticity.
3. **Access Control via Group Distinguished Name**:
   - Evaluates whether the user belongs to the required `authorized_group_dn`:
     ```ldap
     (&(objectCategory=user)(sAMAccountName=<USER>)(memberOf:1.2.840.113556.1.4.1941:=<GROUP_DN>))
     ```
   - Supports **nested/recursive Active Directory groups** using LDAP matching rule OID `1.2.840.113556.1.4.1941` (`LDAP_MATCHING_RULE_IN_CHAIN`).
4. **Session Security**:
   - `session_regenerate_id(true)` upon successful login.
   - Inactivity timeout (default: 60 minutes).
   - Strict CSRF token validation on every POST/action request.

---

## Exchange Online Protection Sync Engine

### Scheduled Cron Daemon (Pull-Only)

To prevent unintended overwrites of Microsoft 365 policies, the background cron daemon (`cron-sync.php --action=pull`) is **strictly pull-only**:
- It pulls remote entries from Microsoft 365 using `Get-HostedContentFilterPolicy`.
- Discovered entries are reconciled into the corresponding MariaDB tables without modifying Exchange Online.

```powershell
# Scheduled Cron (Pull Only): Reconcile remote changes into MariaDB
Get-HostedContentFilterPolicy -Identity "Default"
```

### Manual Admin Push All (Exchange Online)

Pushing local MariaDB changes to Microsoft 365 is an intentional administrative action:
- **Global Scope**: Pushes all pending staged additions and removals across **all 4 tables** (`eop_allowed_senders`, `eop_blocked_senders`, `eop_allowed_domains`, and `eop_blocked_domains`) and policies at once.
- **PowerShell Execution**: Connects via Certificate-Based Authentication and updates all 4 lists:
  ```powershell
  Connect-ExchangeOnline -AppId $ClientId -CertificateThumbprint $CertThumbprint -Organization $Organization
  Set-HostedContentFilterPolicy -Identity $PolicyName `
    -AllowedSenders $AllowedSenders `
    -BlockedSenders $BlockedSenders `
    -AllowedSenderDomains $AllowedDomains `
    -BlockedSenderDomains $BlockedDomains
  ```
- **List-by-List Push Summary**: Displays a breakdown of exactly what additions and removals were pushed to each list (e.g. Added 3 senders to Allowed Senders, Removed 1 domain from Blocked Domains, etc.) and records the audit log in `eop_audit_log`.

---

## Web Interface & UX Capabilities

### Smart Sorter Classification Engine

- **Smart Sort Allowed**: Paste mixed text of email addresses and domain names to automatically route valid emails to Allowed Senders and domain names to Allowed Domains.
- **Smart Sort Blocked**: Paste mixed text of email addresses and domain names to automatically route valid emails to Blocked Senders and domain names to Blocked Domains.
- Live syntax validation, real-time duplicate detection against active policy tables, and preview badge counters before committing.

### Smart Domain Hierarchy Views

- **Domain Cluster**: Groups subdomains under their parent domain (e.g., `api.service.corp.com` under `corp.com`).
- **Subdomain Tree**: Visual tree-nested display showing root domain and branch subdomains.
- **TLD Group**: Organizes entries by Top-Level Domain (`.com`, `.net`, `.io`, `.gov`).
- **Standard A-Z**: Alphabetical sorting by entry value or date added.

### Dark Mode & Audit Trail

- High-contrast **Dark Mode** and clean **Light Mode** toggled with a single click.
- Real-time **Audit Log** tab tracking additions, deletions, bulk imports, and sync runs with user identity, timestamp, and client IP address.

---

## Debian Linux Server Deployment

### Prerequisites

- A server running **Debian 11 (Bullseye)** or **Debian 12 (Bookworm)**.
- A remote **MariaDB / MySQL Server** reachable on port 3306.
- A **Windows Server Domain Controller** reachable on port 389 (LDAP).

### Step 1: Remote MariaDB Database Setup

On your remote MariaDB server, run the schema script:

```bash
mariadb -u root -p < schema.sql
```

Grant remote network privileges to your Debian server's IP address:

```sql
CREATE USER IF NOT EXISTS 'eop_app_user'@'YOUR_DEBIAN_IP' IDENTIFIED BY 'YourStrongPasswordHere';
GRANT ALL PRIVILEGES ON `eop_antispam_db`.* TO 'eop_app_user'@'YOUR_DEBIAN_IP';
FLUSH PRIVILEGES;
```

> **Note**: Verify `/etc/mysql/mariadb.conf.d/50-server.cnf` on the remote server has `bind-address = 0.0.0.0` (or your internal LAN IP) and firewall port 3306 is open to the Debian server.

### Step 2: Automated Installation on Debian

Copy the application archive to your Debian server, extract it, and run the automated installer:

```bash
chmod +x install-debian.sh
sudo ./install-debian.sh
```

The script automatically:
1. Installs NGINX, PHP 8 (PHP-FPM), `php-ldap`, `php-mysql`, `php-curl`, `php-mbstring`, and `mariadb-client`.
2. Copies files to `/var/www/eop-antispam`.
3. Sets secure permissions (`chown -R www-data:www-data`, directories 750, files 640).
4. Configures the NGINX fastcgi pass to the PHP-FPM UNIX socket and sensitive file rules.
5. Enables the NGINX server block and restarts `nginx` and `php-fpm`.

### Step 3: Manual Debian Setup (Alternative)

If you prefer installing packages manually:

```bash
sudo apt-get update
sudo apt-get install -y nginx \
    php-fpm php-cli php-mysql php-ldap php-curl php-mbstring php-xml php-zip \
    mariadb-client curl wget
```

Test your remote MariaDB connection from the Debian terminal:

```bash
mariadb -h 192.168.10.50 -P 3306 -u eop_app_user -p'YourStrongPasswordHere' -D eop_antispam_db -e "SHOW TABLES;"
```

Test your Active Directory connection over standard LDAP (port 389) with service account credentials:

```bash
sudo apt-get install -y ldap-utils
ldapsearch -x -H ldap://dc01.corp.example.com:389 \
  -b "DC=corp,DC=example,DC=com" \
  -D "CN=svc-eop,OU=Service Accounts,DC=corp,DC=example,DC=com" \
  -w "ServiceAccountPassword" "(sAMAccountName=*)" dn
```

### Step 4: NGINX Server Block Configuration

Create `/etc/nginx/sites-available/eop-antispam.conf`:

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name eop.corp.example.com;

    root /var/www/eop-antispam;
    index index.php index.html;

    client_max_body_size 16M;

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Primary Routing
    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    # Pass PHP scripts to PHP-FPM
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }

    # Block direct browser access to config, scripts, keys, and SQL files
    location ~* ^/(\..*|config\.php|installed\.lock|.*\.sql|.*\.ps1|.*\.sh|.*\.key|.*\.pem) {
        deny all;
        return 403;
    }

    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    access_log /var/log/nginx/eop_access.log combined;
    error_log /var/log/nginx/eop_error.log warn;
}
```

Enable the site, disable the default site, test configuration, and restart NGINX + PHP-FPM:

```bash
sudo ln -sf /etc/nginx/sites-available/eop-antispam.conf /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart php*-fpm || sudo systemctl restart php-fpm
sudo systemctl restart nginx
```

### Step 5: Exchange Online Management on Linux

To enable automated Exchange Online synchronization via PowerShell on Debian:

1. Install PowerShell (`pwsh`) on Debian:
   ```bash
   sudo apt-get install -y powershell
   ```
2. Install the Exchange Online Management module:
   ```bash
   sudo pwsh -Command "Install-Module -Name ExchangeOnlineManagement -Scope AllUsers -Force"
   ```
3. Set up the Pull-Only cron schedule for user `www-data`:
   ```bash
   sudo crontab -u www-data -e
   ```
   Add:
   ```cron
   */15 * * * * /usr/bin/php /var/www/eop-antispam/cron-sync.php --action=pull --policy="Default" >> /var/log/eop-sync.log 2>&1
   ```

---

## Project File Structure & Inventory

```text
eop-antispam-php-mariadb/
├── config.php            # Primary application configuration (DB, LDAP, Policy options)
├── database.php          # PDO database wrapper & individual table CRUD operations
├── ldap.php              # Active Directory LDAP Group DN & Bind Password auth engine
├── functions.php         # CSRF verification, input sanitization, and helper utilities
├── schema.sql            # MariaDB database table definitions & 9-table schema
├── index.php             # Main dashboard (Dark mode, tables, cards, modal UI, split smart sort)
├── setup.php             # 5-step initial run setup wizard with permanent lock
├── login.php             # Active Directory LDAP & Fallback auth portal (Dark mode)
├── logout.php            # Session termination & security cleanup
├── actions.php           # REST-style handler for add, delete, import, export, and sync
├── sync-exchange.ps1     # Linux PowerShell sync automation script (Pull & Push modes)
├── cron-sync.php         # Scheduled Pull-Only background CLI sync daemon
├── install-debian.sh     # Automated Debian 11/12 deployment script
├── eop-nginx.conf        # Hardened NGINX Server Block configuration
├── .env.example          # Environment variable template
└── README.md             # Complete technical and deployment documentation
```

---

## Configuration Reference (`config.php`, `.env`, & Database Tables)

Key application parameters:

| Parameter | Location | Description | Default |
|---|---|---|---|
| `DB_HOST` | `config.php` / `.env` | Remote MariaDB server hostname or IP | `192.168.10.50` |
| `DB_PORT` | `config.php` / `.env` | Remote MariaDB server port | `3306` |
| `DB_NAME` | `config.php` / `.env` | Database name | `eop_antispam_db` |
| `DB_USER` | `config.php` / `.env` | MariaDB username with remote permissions | `eop_app_user` |
| `DB_PASS` | `config.php` / `.env` | MariaDB password | *Configured* |
| `host` | `eop_ldap_config` (DB) | Domain Controller FQDN | `dc01.corp.example.com` |
| `port` | `eop_ldap_config` (DB) | LDAP port (389 plain LDAP, 636 LDAPS) | `389` |
| `protocol` | `eop_ldap_config` (DB) | Protocol (`ldap`, `ldaps`, `starttls`) | `ldap` |
| `base_dn` | `eop_ldap_config` (DB) | Search Base DN for directory queries | `DC=corp,DC=example,DC=com` |
| `authorized_group_dn` | `eop_ldap_config` (DB) | Mandatory Group DN required for login | `CN=Exchange-Admins,OU=Groups,DC=...` |
| `bind_dn` | `eop_ldap_config` (DB) | Service account Bind DN for LDAP search | `CN=svc-eop-web,OU=Service Accounts,...` |
| `bind_password` | `eop_ldap_config` (DB) | Bind password for LDAP authorization | *Service account password* |
| `FALLBACK_ADMIN_ENABLED`| `config.php` | Enable emergency local fallback admin | `true` |
| `tenant_id` | `eop_auth_config` (DB) | Microsoft 365 / Azure AD Tenant ID | GUID |
| `client_id` | `eop_auth_config` (DB) | App Registration Client ID | GUID |
| `certificate_thumbprint` | `eop_auth_config` (DB) | App-Only Certificate Thumbprint | SHA1 Hex |
| `DEFAULT_POLICY_NAME` | `config.php` | Target Exchange Online Protection policy | `Default` |
| `SESSION_TIMEOUT` | `config.php` | Seconds before inactivity timeout | `3600` (60 min) |

---

## Troubleshooting & FAQ

#### Q: Do I need LDAPS (port 636) or SSL certificates for Active Directory?
**No.** The application supports standard plain LDAP on port 389 by default. You do **not** need to install internal CA certificates or generate keystores. LDAPS (port 636) and StartTLS (port 389) are fully supported options if your corporate policy requires encryption in transit.

#### Q: What is the Bind Password used for in LDAP?
Active Directory domain controllers frequently restrict directory searches to authenticated identities. When configured, `bind_dn` and `bind_password` allow the application to bind as an authorized service account to locate user objects and verify Group DN membership.

#### Q: What happens when I click "Push All Changes to EOP"?
Unlike single-table updates, "Push All Changes to EOP" stages and commits all pending additions and deletions across all 4 anti-spam tables (`eop_allowed_senders`, `eop_blocked_senders`, `eop_allowed_domains`, and `eop_blocked_domains`) and policies. Upon completion, a list-by-list summary outlines exactly which records were added, removed, or preserved.

#### Q: How does nested Active Directory group membership work?
The `ldap.php` authentication class utilizes the LDAP matching rule OID `1.2.840.113556.1.4.1941` (`LDAP_MATCHING_RULE_IN_CHAIN`). If an administrator belongs to a group nested inside `authorized_group_dn`, Active Directory automatically resolves membership without requiring manual individual group assignments.

#### Q: Why is the scheduled Cron job "Pull-Only"?
To prevent accidental policy overwrites or race conditions in Microsoft 365, automated background synchronization only pulls updates into MariaDB. Pushing MariaDB lists to Microsoft 365 is restricted to intentional manual administrator actions via the web portal or explicitly triggered administrator scripts.

#### Q: Remote MariaDB returns `Host 'xxx' is not allowed to connect`
1. On your remote MariaDB server, check `/etc/mysql/mariadb.conf.d/50-server.cnf` and verify `bind-address = 0.0.0.0` (or your internal LAN subnet IP).
2. Ensure you executed `GRANT ALL PRIVILEGES ON eop_antispam_db.* TO 'eop_app_user'@'DEBIAN_IP'; FLUSH PRIVILEGES;`.

#### Q: Can I run this behind an HTTPS reverse proxy (e.g. Cloudflare, Traefik, HAProxy, AWS ALB)?
Yes. Configure your upstream reverse proxy to forward requests to NGINX with `X-Forwarded-Proto https`, `X-Forwarded-Host`, and `X-Forwarded-For`. The application and NGINX configuration include security headers (`X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`) to protect your deployment.

---

## License

Apache License 2.0. Open-source and free for enterprise or commercial use.
