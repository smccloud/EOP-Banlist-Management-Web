# Exchange Online Protection (EOP) Anti-Spam Policy Manager

A production-ready **PHP 8** web application designed for **Debian Linux** and backed by a **remote MariaDB server** across individual dedicated tables, authenticated via **Microsoft Active Directory (AD) LDAP Group Distinguished Name (Group DN)**, featuring **Dark Mode**, **App-Only Certificate-Based Authentication (CBA)**, and an **Exchange Online PowerShell / Cron automation engine**.

This repository contains both the **production PHP 8 / Debian deployment codebase** and an interactive **React & TypeScript workbench / simulator** for testing, generating configuration files, and exporting complete deployment archives.

---

## 📑 Table of Contents

- [Overview & Architecture](#overview--architecture)
- [Key Features](#key-features)
- [Initial Run Setup Routine (`setup.php`)](#initial-run-setup-routine-setupphp)
- [Database Schema (Dedicated Table Per List)](#database-schema-dedicated-table-per-list)
- [Active Directory LDAP Authentication](#active-directory-ldap-authentication)
- [Exchange Online Protection Sync Engine](#exchange-online-protection-sync-engine)
  - [Scheduled Cron Daemon (Pull-Only)](#scheduled-cron-daemon-pull-only)
  - [Manual Admin Push (Exchange Online)](#manual-admin-push-exchange-online)
  - [Certificate-Based Authentication (CBA)](#certificate-based-authentication-cba)
- [Web Interface & UX Capabilities](#web-interface--ux-capabilities)
  - [Smart Domain Sorting & Hierarchy](#smart-domain-sorting--hierarchy)
  - [In-App Confirmation Safeguards](#in-app-confirmation-safeguards)
  - [Dark Mode & Audit Trail](#dark-mode--audit-trail)
- [Debian Linux Server Deployment](#debian-linux-server-deployment)
  - [Prerequisites](#prerequisites)
  - [Step 1: Remote MariaDB Database Setup](#step-1-remote-mariadb-database-setup)
  - [Step 2: Automated Installation on Debian](#step-2-automated-installation-on-debian)
  - [Step 3: Manual Debian Setup (Alternative)](#step-3-manual-debian-setup-alternative)
  - [Step 4: Apache VirtualHost Configuration](#step-4-apache-virtualhost-configuration)
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
3. **Database-Stored Configuration**: LDAP directory connection settings (`eop_ldap_config`) and Exchange Online authentication credentials (`eop_auth_config`) can be safely modified through the UI without editing server configuration files.
4. **Active Directory Security**: Restricts system login strictly to members of an authorized **Active Directory Group Distinguished Name (Group DN)** using standard **plain LDAP (Port 389)**. **LDAPS is NOT required**, removing certificate hassles while optionally supporting LDAPS (Port 636) and StartTLS.
5. **Exchange Online Sync Safeguards**:
   - **Scheduled Cron is strictly Pull-Only**: Never blindly overwrites Microsoft 365 in the background; only pulls remote changes into MariaDB.
   - **Manual Admin Push**: Pushing MariaDB lists to Microsoft 365 requires an intentional administrator action with built-in confirmation modals.
6. **Initial Run Setup Routine (`setup.php`)**: A 5-step deployment wizard that validates database and directory connectivity, builds the schema, and permanently locks itself against re-execution.

---

## Key Features

- **Individual Table Per List in Remote MariaDB**:
  - `eop_allowed_senders`: Whitelisted sender email addresses.
  - `eop_blocked_senders`: Blacklisted sender email addresses.
  - `eop_allowed_domains`: Whitelisted domains (e.g., `partner.com`, `*.vendor.net`).
  - `eop_blocked_domains`: Blacklisted domains.
  - `eop_audit_log`: Complete audit trail recording who made the change, action type, IP address, timestamp, and notes/ticket numbers.
  - `eop_policies`: Stores policy metadata and last sync timestamps.
  - `eop_ldap_config`: Database-backed LDAP host, port, protocol, Base DN, Group DN, and bind credentials.
  - `eop_auth_config`: Database-backed Azure AD Tenant ID, Client App ID, Certificate Thumbprint, and encrypted RSA Private Key.
  - `eop_setup_lock`: Cryptographic lock tracking first-run completion.
- **Active Directory LDAP Group Authorization (LDAPS Not Required)**:
  - Connects to Windows Server Domain Controllers via standard **LDAP (port 389)** by default.
  - No need to configure internal CA root certificates or OpenLDAP TLS keystores on Debian.
  - Enforces access control via exact **Group Distinguished Name (Group DN)**.
  - Supports **nested/recursive Active Directory groups** using LDAP matching rule OID `1.2.840.113556.1.4.1941` (`LDAP_MATCHING_RULE_IN_CHAIN`).
- **Safe UX with In-App Modals**:
  - Non-blocking in-app modal confirmations for record deletion and Exchange Online pushes.
  - Displays user profile badge (e.g. `John Smith AD Authorized`) while tracking underlying account identifiers (`jsmith`).
- **One-Click Push from MariaDB to EOP**:
  - Immediate **"Push to EOP"** quick button in the header and **"Push Changes to EOP"** button in each policy list toolbar to apply staged MariaDB entries directly to Microsoft 365 without navigating through submenus.
  - Triggers an in-app confirmation modal before running `Set-HostedContentFilterPolicy`.
- **Dark Mode Support**:
  - Built-in Dark and Light themes with a one-click toggle in the header.
  - Respects system `prefers-color-scheme` and remembers preference in `localStorage`.
- **Policy Switcher**:
  - Seamlessly switch between any anti-spam policy (e.g., `Default`, `Strict Anti-Spam Policy`, `Executive Inbound Policy`).
- **Smart Sorting & Bulk Import**:
  - RFC-compliant domain grouping, subdomain hierarchy tree, and TLD clustering.
  - Rapidly paste hundred-item bulk lists with duplicate suppression and CSV export.

---

## Initial Run Setup Routine (`setup.php`)

The application features an automated initial setup routine (`setup.php`) executed upon first deployment:

1. **Step 1 - Requirements & Environment Check**:
   - Verifies PHP 8.1+, PDO MySQL extension, OpenSSL, and LDAP module (`php-ldap`).
2. **Step 2 - Remote MariaDB Database Setup**:
   - Collects host, port, database name, and credentials.
   - Tests remote database connectivity and populates all 9 required schema tables.
3. **Step 3 - Active Directory / OpenLDAP Configuration**:
   - Configures Domain Controller host, port, protocol (Plain LDAP 389, LDAPS 636, or StartTLS), Base DN, service account, and the mandatory **Authorized Group DN**.
   - Performs a live bind test and validates group membership query syntax.
4. **Step 4 - Microsoft 365 Exchange Online Protection (EOP)**:
   - Configures Tenant ID, Client App ID, Certificate Thumbprint, Organization Domain, target anti-spam policy name, and RSA Private Key with AES-256-GCM encrypted passphrase.
5. **Step 5 - Review & Permanent Security Lock**:
   - Summarizes all configured parameters.
   - Writes `config.php` and creates a filesystem lock file (`installed.lock`) alongside the MariaDB `eop_setup_lock` table.
   - **Permanent Re-Run Prevention**: Subsequent requests to `setup.php` immediately respond with **403 Forbidden** and cannot be re-executed without deliberate root-level intervention.

---

## Database Schema (Dedicated Table Per List)

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

-- 7. Database-Stored LDAP Connection Configuration Table
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

## Active Directory LDAP Authentication

The application queries Active Directory connection parameters directly from the `eop_ldap_config` table:

1. **Database-Stored Parameters**:
   - LDAP server address (`host`), port (`port`), protocol (`ldap`, `ldaps`, `starttls`), `base_dn`, `authorized_group_dn`, and bind credentials can be viewed or updated in the **Configuration Page** without touching server files.
2. **User Authentication**:
   - Users provide their Windows Active Directory username (`sAMAccountName` or UPN `user@corp.example.com`) and domain password.
   - Binds directly against `ldap://<DC_FQDN>:389` (or `ldaps://<DC_FQDN>:636`).
   - Plain LDAP does **not** require any SSL/TLS certificates or enterprise CA trust configurations on Debian.
3. **Access Control via Group Distinguished Name**:
   - Upon successful bind, the user's distinguished name (DN) is resolved.
   - Evaluates whether the user belongs to the required `authorized_group_dn`:
     ```ldap
     (&(objectCategory=user)(sAMAccountName=<USER>)(memberOf:1.2.840.113556.1.4.1941:=<GROUP_DN>))
     ```
   - Supports **nested/recursive Active Directory groups** using LDAP matching rule OID `1.2.840.113556.1.4.1941` (`LDAP_MATCHING_RULE_IN_CHAIN`).
4. **Session Hardening**:
   - `session_regenerate_id(true)` on login to prevent session fixation.
   - Inactivity timeout (default: 60 minutes).
   - `HttpOnly`, `SameSite=Lax`, and `Secure` cookie attributes.
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

### Manual Admin Push (Exchange Online)

Pushing local MariaDB changes to Microsoft 365 is an intentional administrative action with dedicated push buttons across the interface:
- **Main Policy List Action Bar**: A dedicated **"Push Changes to EOP"** button is located right alongside *Add Entry*, *Bulk Import*, *Smart Sort*, and *Export CSV*, allowing administrators to stage entries and immediately push changes to Microsoft 365 without navigating away.
- **Top Header Quick Action**: A **"Push to EOP"** button is positioned right next to the active policy selector for one-click deployment from anywhere in the application.
- **Exchange Sync Center**: A full manual push panel displaying the exact `Set-HostedContentFilterPolicy` syntax with active parameter values before execution.

When triggered, an in-app confirmation modal outlines the policy name and all 4 tables being updated. Once confirmed:
- The application executes `sync-exchange.ps1` with `-Action Push`.
- Gathers all records from `eop_allowed_senders`, `eop_blocked_senders`, `eop_allowed_domains`, and `eop_blocked_domains`.
- Connects using Certificate-Based Authentication (CBA) and applies the staged lists:
  ```powershell
  Connect-ExchangeOnline -AppId $ClientId -CertificateThumbprint $CertThumbprint -Organization $Organization
  Set-HostedContentFilterPolicy -Identity $PolicyName `
    -AllowedSenders $AllowedSenders `
    -BlockedSenders $BlockedSenders `
    -AllowedSenderDomains $AllowedDomains `
    -BlockedSenderDomains $BlockedDomains
  ```
- Logs the push execution in `eop_audit_log` with the administrator's Active Directory username, client IP, timestamp, and record counts.
- Updates the policy's `last_synced_at` and `sync_status` in `eop_policies`.
- **Post-Push Summary Modal**: Immediately following push completion, displays a detailed popup showing exactly what entries were applied to Microsoft 365 across all four policy lists (`eop_allowed_senders`, `eop_blocked_senders`, `eop_allowed_domains`, and `eop_blocked_domains`) along with item counts, timestamp, and target policy identity.

### Certificate-Based Authentication (CBA)

The application supports modern, secure **App-Only Certificate-Based Authentication (CBA)** for Microsoft 365 Exchange Online:
- RSA private key (`.pem`, `.key`, or `.pfx`) stored in MariaDB `eop_auth_config`.
- Passphrase encrypted with **AES-256-GCM** before saving to the database.
- Completely passwordless and client-secret-free authentication to Exchange Online PowerShell.

---

## Web Interface & UX Capabilities

### Smart Domain Sorting & Hierarchy
The web interface features multi-mode intelligent sorting:
- **Domain Cluster**: Groups subdomains under their parent domain (e.g., `api.service.corp.com` under `corp.com`).
- **Subdomain Tree**: Visual tree-nested display showing root domain and branch subdomains.
- **TLD Group**: Organizes entries by Top-Level Domain (`.com`, `.net`, `.io`, `.gov`).
- **Standard A-Z**: Alphabetical sorting by entry value or date added.

### In-App Confirmation Safeguards & Push Verification
To comply with modern browser sandboxes and iframe restrictions (where browser-native `alert()` or `confirm()` are blocked), all destructive and high-impact actions use in-app modals:
- **Delete Confirmation Modal**: Shows the exact email or domain, target table, and warns that it will be removed on the next push.
- **Exchange Online Push Modal**: Outlines the policy name and record counts before triggering `Set-HostedContentFilterPolicy`.
- **Post-Push List Summary Popup**: A comprehensive completion dialog that pops up immediately following a push to Microsoft 365, verifying and listing all configured entries across:
  - **Allowed Senders** (`-AllowedSenders` &rarr; `eop_allowed_senders`)
  - **Blocked Senders** (`-BlockedSenders` &rarr; `eop_blocked_senders`)
  - **Allowed Sender Domains** (`-AllowedSenderDomains` &rarr; `eop_allowed_domains`)
  - **Blocked Sender Domains** (`-BlockedSenderDomains` &rarr; `eop_blocked_domains`)

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
1. Installs Apache2, PHP 8, `php-ldap`, `php-mysql`, `php-curl`, `php-mbstring`, and `mariadb-client`.
2. Copies files to `/var/www/eop-antispam`.
3. Sets secure permissions (`chown -R www-data:www-data`, directories 750, files 640).
4. Enables required Apache modules (`rewrite`, `ssl`, `headers`).
5. Configures the Apache VirtualHost site.

### Step 3: Manual Debian Setup (Alternative)

If you prefer installing packages manually:

```bash
sudo apt-get update
sudo apt-get install -y apache2 \
    php php-cli php-fpm php-mysql php-ldap php-curl php-mbstring php-xml php-zip \
    mariadb-client curl wget
```

Test your remote MariaDB connection from the Debian terminal:

```bash
mariadb -h 192.168.10.50 -P 3306 -u eop_app_user -p'YourStrongPasswordHere' -D eop_antispam_db -e "SHOW TABLES;"
```

Test your Active Directory connection over standard LDAP (port 389):

```bash
sudo apt-get install -y ldap-utils
ldapsearch -x -H ldap://dc01.corp.example.com:389 \
  -b "DC=corp,DC=example,DC=com" \
  -D "CN=svc-eop,OU=Service Accounts,DC=corp,DC=example,DC=com" \
  -w "ServiceAccountPassword" "(sAMAccountName=*)" dn
```

### Step 4: Apache VirtualHost Configuration

Create `/etc/apache2/sites-available/eop-antispam.conf`:

```apache
<VirtualHost *:80>
    ServerName eop.corp.example.com
    DocumentRoot /var/www/eop-antispam

    <Directory /var/www/eop-antispam>
        Options -Indexes +FollowSymLinks
        AllowOverride None
        Require all granted

        # Block direct browser access to config, scripts, keys, and SQL files
        <FilesMatch "^(\..*|.*\.sql|.*\.ps1|.*\.sh|.*\.key|.*\.pem|config\.php)$">
            Require all denied
        </FilesMatch>
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/eop_error.log
    CustomLog ${APACHE_LOG_DIR}/eop_access.log combined
</VirtualHost>
```

Enable the site and restart Apache:

```bash
sudo a2enmod rewrite headers
sudo a2ensite eop-antispam.conf
sudo systemctl restart apache2
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
├── ldap.php              # Active Directory LDAP Group DN authentication engine
├── functions.php         # CSRF verification, input sanitization, and helper utilities
├── schema.sql            # MariaDB database table definitions & indices
├── index.php             # Main management dashboard (Dark mode, tables, cards, modal UI)
├── setup.php             # 5-step initial run setup wizard with permanent lock
├── login.php             # Active Directory LDAP authentication portal (Dark mode)
├── logout.php            # Session termination & security cleanup
├── actions.php           # REST-style handler for add, delete, import, export, and sync
├── sync-exchange.ps1     # Linux PowerShell sync automation script (Pull & Push modes)
├── cron-sync.php         # Scheduled Pull-Only background CLI sync daemon
├── install-debian.sh     # Automated Debian 11/12 deployment script
├── eop-apache.conf       # Hardened Apache2 VirtualHost configuration
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
| `tenant_id` | `eop_auth_config` (DB) | Microsoft 365 / Azure AD Tenant ID | GUID |
| `client_id` | `eop_auth_config` (DB) | App Registration Client ID | GUID |
| `certificate_thumbprint` | `eop_auth_config` (DB) | App-Only Certificate Thumbprint | SHA1 Hex |
| `DEFAULT_POLICY_NAME` | `config.php` | Target Exchange Online Protection policy | `Default` |
| `SESSION_TIMEOUT` | `config.php` | Seconds before inactivity timeout | `3600` (60 min) |

---

## Troubleshooting & FAQ

#### Q: Do I need LDAPS (port 636) or SSL certificates for Active Directory?
**No.** The application is built to support standard plain LDAP on port 389 by default. You do **not** need to install internal CA certificates or generate keystores. LDAPS (port 636) and StartTLS (port 389) are fully supported options if your corporate policy requires encryption in transit.

#### Q: How does nested Active Directory group membership work?
The `ldap.php` authentication class utilizes the LDAP matching rule OID `1.2.840.113556.1.4.1941` (`LDAP_MATCHING_RULE_IN_CHAIN`). If an administrator belongs to a group nested inside `authorized_group_dn`, Active Directory automatically resolves membership without requiring manual individual group assignments.

#### Q: Why is the scheduled Cron job "Pull-Only"?
To prevent accidental policy overwrites or race conditions in Microsoft 365, automated background synchronization only pulls updates into MariaDB. Pushing MariaDB lists to Microsoft 365 is restricted to intentional manual administrator actions via the web portal or explicitly triggered administrator scripts.

#### Q: Remote MariaDB returns `Host 'xxx' is not allowed to connect`
1. On your remote MariaDB server, check `/etc/mysql/mariadb.conf.d/50-server.cnf` and verify `bind-address = 0.0.0.0` (or your internal LAN subnet IP).
2. Ensure you executed `GRANT ALL PRIVILEGES ON eop_antispam_db.* TO 'eop_app_user'@'DEBIAN_IP'; FLUSH PRIVILEGES;`.

#### Q: Can I run this behind an HTTPS reverse proxy (e.g. Nginx, Cloudflare, Traefik)?
Yes. Configure your reverse proxy to forward requests to Apache with `X-Forwarded-Proto https` and `X-Forwarded-For`. The application includes security headers (`X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`) to protect your deployment.

---

## License

Apache License 2.0. Open-source and free for enterprise or commercial use.
