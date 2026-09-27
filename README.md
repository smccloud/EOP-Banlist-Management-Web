# Exchange Online Protection (EOP) Anti-Spam Policy Manager

A production-ready **PHP 8** web application designed to run on **Debian Linux**, storing policy lists in a **remote MariaDB server** across individual dedicated tables, authenticated via **Microsoft Active Directory (AD) LDAP Group Distinguished Name (Group DN)**, featuring **Dark Mode** and **Exchange Online PowerShell / Cron automation**.

---

## 📑 Table of Contents

- [Overview & Architecture](#overview--architecture)
- [Key Features](#key-features)
- [Database Schema (Individual Table Per List)](#database-schema-individual-table-per-list)
- [Active Directory LDAP Authentication](#active-directory-ldap-authentication)
- [Dark Mode & UI Design](#dark-mode--ui-design)
- [Debian Linux Server Deployment](#debian-linux-server-deployment)
  - [Prerequisites](#prerequisites)
  - [Step 1: Remote MariaDB Database Setup](#step-1-remote-mariadb-database-setup)
  - [Step 2: Automated Installation on Debian](#step-2-automated-installation-on-debian)
  - [Step 3: Manual Debian Setup (Alternative)](#step-3-manual-debian-setup-alternative)
  - [Step 4: Apache VirtualHost Configuration](#step-4-apache-virtualhost-configuration)
- [Exchange Online Synchronization](#exchange-online-synchronization)
  - [PowerShell Automation Script (`sync-exchange.ps1`)](#powershell-automation-script-sync-exchangeps1)
  - [Cron Daemon (`cron-sync.php`)](#cron-daemon-cron-syncphp)
- [Project File Structure](#project-file-structure)
- [Configuration Reference (`config.php` & `.env`)](#configuration-reference-configphp--env)
- [Troubleshooting & FAQ](#troubleshooting--faq)
- [License](#license)

---

## Overview & Architecture

Microsoft 365 Exchange Online Protection (EOP) allows administrators to configure anti-spam policies (`Set-HostedContentFilterPolicy`) with custom lists of allowed senders, blocked senders, allowed domains, and blocked domains. In enterprise environments, managing these entries directly in PowerShell or the Microsoft Defender Portal can lead to lack of auditability, accidental overwrites, or bottlenecks.

This solution provides:
1. **Centralized Web Portal**: Secure, multi-user web dashboard with dark mode and search/filter capabilities.
2. **Dedicated MariaDB Tables**: Uses an **individual MariaDB table per list** on a remote database server for strict data isolation, indexing, and transactional integrity.
3. **Active Directory Security**: Restricts system login strictly to members of an authorized **Active Directory Group Distinguished Name (Group DN)** using standard **plain LDAP (Port 389)**. **LDAPS is NOT required**, removing certificate hassles while optionally supporting LDAPS (Port 636) and StartTLS.
4. **Exchange Online Sync**: Automatically pulls entries from MariaDB and runs `Set-HostedContentFilterPolicy` targeting the specified anti-spam policy name.

---

## Key Features

- **Individual Table Per List in Remote MariaDB**:
  - `eop_allowed_senders`: Whitelisted sender email addresses.
  - `eop_blocked_senders`: Blacklisted sender email addresses.
  - `eop_allowed_domains`: Whitelisted domains (e.g., `partner.com`, `*.vendor.net`).
  - `eop_blocked_domains`: Blacklisted domains.
  - `eop_audit_log`: Complete audit trail recording who made the change, action type, IP address, timestamp, and notes/ticket numbers.
  - `eop_policies`: Stores policy metadata and last sync timestamps.
- **Active Directory LDAP Group Authorization (LDAPS Not Required)**:
  - Connects to Windows Server Domain Controllers via standard **LDAP (port 389)** by default.
  - No need to configure internal CA root certificates or OpenLDAP TLS keystores on Debian.
  - Enforces access control via exact **Group Distinguished Name (Group DN)**.
  - Supports **nested/recursive Active Directory groups** using LDAP matching rule OID `1.2.840.113556.1.4.1941` (`LDAP_MATCHING_RULE_IN_CHAIN`).
- **Dark Mode Support**:
  - Built-in Dark and Light themes with a one-click toggle in the header.
  - Automatically respects `prefers-color-scheme` and stores user preference in `localStorage`.
- **Policy Switcher**:
  - Specify and switch between any anti-spam policy (e.g. `Default`, `Strict Anti-Spam Policy`, `Executive Inbound Policy`).
- **Bulk Import & CSV Export**:
  - Rapidly paste hundred-item bulk lists with duplicate suppression.
  - Export filtered lists directly to CSV.
- **PowerShell & Cron Sync Engine**:
  - Linux PowerShell (`pwsh`) script to update Exchange Online.
  - Includes crontab automation to keep Exchange Online synced on a scheduled basis.

---

## Database Schema (Individual Table Per List)

All lists are stored in individual tables on your remote MariaDB server:

```sql
CREATE DATABASE IF NOT EXISTS `eop_antispam_db` 
  DEFAULT CHARACTER SET utf8mb4 
  COLLATE utf8mb4_unicode_ci;

USE `eop_antispam_db`;

-- 1. Allowed Senders
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

-- 2. Blocked Senders
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

-- 3. Allowed Domains
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

-- 4. Blocked Domains
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

-- 5. Audit Trail
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

-- 6. Policy Registry
CREATE TABLE IF NOT EXISTS `eop_policies` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `policy_name` VARCHAR(128) NOT NULL UNIQUE,
  `description` VARCHAR(255) NULL,
  `last_synced_at` DATETIME NULL,
  `sync_status` VARCHAR(32) DEFAULT 'PENDING',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 7. Database-Stored LDAP Connection Configuration
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
```

---

## Active Directory LDAP Authentication & Database Storage

The application dynamically stores and retrieves LDAP connection settings directly from the MariaDB database table `eop_ldap_config`:

1. **Database-Stored Connection Parameters**:
   - The LDAP server address (`host`), port (`port`), protocol (`ldap`, `ldaps`, `starttls`), `base_dn`, `authorized_group_dn`, and optional service credentials are stored in `eop_ldap_config`.
   - Settings can be updated directly from the **LDAP Config (DB Table)** tab in the web interface or via SQL.
   - Any runtime changes to the database table take effect immediately without restarting Apache or editing server files.

2. **User Authentication**:
   - The user inputs their Windows Active Directory username (`sAMAccountName` or UPN `user@corp.example.com`) and domain password.
   - Binds directly against `ldap://<DC_FQDN>:389` (or `ldaps://<DC_FQDN>:636` if desired).
   - Plain LDAP does **not** require any SSL/TLS certificates or enterprise CA trust configurations on Debian.
3. **Access Control via Group Distinguished Name**:
   - Once authenticated, the user's distinguished name (DN) is resolved.
   - A search query evaluates whether the user belongs to the required `LDAP_AUTHORIZED_GROUP_DN`:
     ```ldap
     (&(objectCategory=user)(sAMAccountName=<USER>)(memberOf:1.2.840.113556.1.4.1941:=<GROUP_DN>))
     ```
   - If the user is a direct or nested member, access is granted. Otherwise, login is denied with an authorization error.
3. **Session Hardening**:
   - `session_regenerate_id(true)` on login to prevent session fixation.
   - Inactivity timeout (default: 60 minutes).
   - HttpOnly, SameSite cookies and CSRF tokens across all form actions.

---

## Dark Mode & UI Design

- **Tailwind CSS Engine**: Full dark mode styling (`dark:`) for headers, metric cards, data tables, modals, and input fields.
- **Theme Switcher**: An icon button in the top navigation bar toggles between dark and light themes instantly without page reload.
- **Persistence**: Remembers the selected theme in the browser's `localStorage` and falls back to system preferences (`prefers-color-scheme: dark`).

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

        # Block direct browser access to config, scripts, and SQL files
        <FilesMatch "^(\..*|.*\.sql|.*\.ps1|.*\.sh|config\.php)$">
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

---

## Exchange Online Synchronization

### PowerShell Automation Script (`sync-exchange.ps1`)

To push list entries into Microsoft 365 Exchange Online Protection:

1. Install PowerShell on Debian:
   ```bash
   sudo apt-get install -y powershell
   ```
2. Install the Exchange Online Management module:
   ```bash
   sudo pwsh -Command "Install-Module -Name ExchangeOnlineManagement -Scope AllUsers -Force"
   ```
3. Run the sync script:
   ```bash
   pwsh /var/www/eop-antispam/sync-exchange.ps1 -PolicyName "Strict Anti-Spam Policy"
   ```

The script pulls current lists from `eop_allowed_senders`, `eop_blocked_senders`, `eop_allowed_domains`, and `eop_blocked_domains`, then runs:

```powershell
Set-HostedContentFilterPolicy -Identity $PolicyName `
  -AllowedSenders $AllowedSenders `
  -BlockedSenders $BlockedSenders `
  -AllowedSenderDomains $AllowedDomains `
  -BlockedSenderDomains $BlockedDomains
```

### Cron Daemon (`cron-sync.php`)

To keep Exchange Online automatically synced every 15 minutes, add a crontab entry for `www-data`:

```bash
sudo crontab -u www-data -e
```

Add the following line:

```cron
*/15 * * * * /usr/bin/php /var/www/eop-antispam/cron-sync.php --policy="Default" >> /var/log/eop-sync.log 2>&1
```

---

## Project File Structure

```text
eop-antispam-php-mariadb/
├── config.php            # Primary configuration file (DB, LDAP, Policy options)
├── database.php          # PDO database wrapper & individual table CRUD operations
├── ldap.php              # Active Directory LDAP Group DN authentication engine
├── functions.php         # CSRF verification, input sanitization, and helper utilities
├── index.php             # Main management dashboard (Dark mode, tables, cards, modal UI)
├── login.php             # Active Directory LDAP authentication portal (Dark mode)
├── logout.php            # Session termination & security cleanup
├── actions.php           # REST-style handler for add, delete, import, export, and sync
├── schema.sql            # MariaDB database table definition & indices
├── sync-exchange.ps1     # Linux PowerShell sync automation script
├── cron-sync.php         # Automated background CLI sync daemon
├── apache.conf           # Hardened Apache2 VirtualHost configuration
├── install-debian.sh     # One-click Debian installation & deployment script
├── .env.example          # Environment variable template
└── README.md             # Complete technical and deployment documentation
```

---

## Configuration Reference (`config.php` & `.env`)

Key settings in `config.php`:

| Constant | Description | Default |
|---|---|---|
| `DB_HOST` | Remote MariaDB server hostname or IP | `192.168.10.50` |
| `DB_PORT` | Remote MariaDB server port | `3306` |
| `DB_NAME` | Database name | `eop_antispam_db` |
| `DB_USER` | MariaDB username with remote permissions | `eop_app_user` |
| `DB_PASS` | MariaDB password | *Configured* |
| `LDAP_PROTOCOL` | Connection protocol (`'ldap'`, `'ldaps'`, or `'starttls'`) | `'ldap'` |
| `LDAP_HOST` | Active Directory Domain Controller FQDN | `dc01.corp.example.com` |
| `LDAP_PORT` | LDAP port (389 for plain LDAP, 636 for LDAPS) | `389` |
| `LDAP_USE_SSL` | Enable SSL (`ldaps://`) | `false` |
| `LDAP_BASE_DN` | Search Base DN for directory queries | `DC=corp,DC=example,DC=com` |
| `LDAP_AUTHORIZED_GROUP_DN` | Mandatory Group DN required for login | `CN=Exchange-Admins,OU=Security Groups,DC=corp...` |
| `DEFAULT_POLICY_NAME` | Target Exchange Online Protection policy | `Default` |
| `SESSION_TIMEOUT` | Seconds before inactivity timeout | `3600` (60 min) |

---

## Troubleshooting & FAQ

#### Q: Do I need LDAPS (port 636) or SSL certificates?
**No.** The application is built to support standard plain LDAP on port 389 by default. You do **not** need to install internal CA certificates or generate keystores. LDAPS (port 636) and StartTLS (port 389) are optional features if your corporate policy requires encryption in transit.

#### Q: How does nested Active Directory group membership work?
The `ldap.php` authentication class utilizes the LDAP matching rule OID `1.2.840.113556.1.4.1941` (`LDAP_MATCHING_RULE_IN_CHAIN`). If an administrator belongs to a group nested inside `LDAP_AUTHORIZED_GROUP_DN`, Active Directory automatically resolves membership without requiring manual group assignments.

#### Q: Remote MariaDB returns `Host 'xxx' is not allowed to connect`
1. On your remote MariaDB server, check `/etc/mysql/mariadb.conf.d/50-server.cnf` and verify `bind-address = 0.0.0.0`.
2. Ensure you executed `GRANT ALL PRIVILEGES ON eop_antispam_db.* TO 'eop_app_user'@'DEBIAN_IP'; FLUSH PRIVILEGES;`.

#### Q: Can I run this behind an HTTPS reverse proxy (e.g. Nginx, Cloudflare)?
Yes. Configure your reverse proxy to forward requests to Apache with `X-Forwarded-Proto https` and `X-Forwarded-For`. The application includes security headers (`X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`) to protect your deployment.

---

## License

Apache License 2.0. Open-source and free for enterprise or commercial use.
