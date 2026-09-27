import React, { useState } from 'react';
import { AppConfig } from '../types';
import { Terminal, Copy, Check, Server, Shield, Database, Clock, AlertCircle, FileCode, Key } from 'lucide-react';

interface DebianGuideProps {
  config: AppConfig;
}

export const DebianGuide: React.FC<DebianGuideProps> = ({ config }) => {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const handleCopy = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const steps = [
    {
      title: 'Step 1: Install Required Packages on Debian 11/12',
      icon: <Terminal className="w-5 h-5 text-blue-500" />,
      description: 'Update Debian APT repositories and install Apache2, PHP 8.x, php-ldap, php-mysql, and the MariaDB client.',
      command: `sudo apt-get update -y
sudo apt-get install -y apache2 \\
    php php-cli php-fpm php-mysql php-ldap php-curl php-mbstring php-xml php-zip \\
    mariadb-client curl wget git`,
    },
    {
      title: 'Step 2: Configure Remote MariaDB Permissions & Initialize Schema',
      icon: <Database className="w-5 h-5 text-emerald-500" />,
      description: `On your remote MariaDB server (${config.dbHost}), import the schema to create the individual list tables, policies, audit log, eop_ldap_config, and eop_auth_config database tables.`,
      command: `# 1. Import schema on remote MariaDB server:
mariadb -h ${config.dbHost} -u root -p < schema.sql

# 2. Grant permissions to Debian server (replace DEBIAN_SERVER_IP with your Debian IP):
mariadb -h ${config.dbHost} -u root -p -e "
CREATE USER IF NOT EXISTS '${config.dbUser}'@'DEBIAN_SERVER_IP' IDENTIFIED BY '${config.dbPass}';
GRANT ALL PRIVILEGES ON \`${config.dbName}\`.* TO '${config.dbUser}'@'DEBIAN_SERVER_IP';
FLUSH PRIVILEGES;
"

# 3. Test remote connection from your Debian terminal:
mariadb -h ${config.dbHost} -P ${config.dbPort} -u ${config.dbUser} -p'${config.dbPass}' -D ${config.dbName} -e "SHOW TABLES;"
# You will see: eop_allowed_senders, eop_blocked_senders, eop_allowed_domains, eop_blocked_domains, eop_audit_log, eop_policies, eop_ldap_config, eop_auth_config`,
    },
    {
      title: 'Step 3: Private Key EOP Auth & AD LDAP in Database (Tables: eop_auth_config & eop_ldap_config)',
      icon: <Key className="w-5 h-5 text-indigo-500" />,
      description: 'Exchange Online Protection private key credentials (with AES-256 encrypted password) and AD LDAP parameters are both stored and managed directly in database tables.',
      command: `# EOP Private Key & Certificate Auth:
# Table 'eop_auth_config' stores the RSA private key PEM, certificate thumbprint, and AES-256-GCM encrypted passphrase.
# Users can upload new keys and passphrases directly on the web app's Configuration Page (/index.php?tab=config_center).

# Active Directory LDAP Connection:
# Table 'eop_ldap_config' stores Domain Controller host, port, protocol (Plain LDAP port 389 - no certs needed!), Base DN, and Group DN.
# Modify settings anytime on the Configuration page or query the active row:
mariadb -h ${config.dbHost} -u ${config.dbUser} -p'${config.dbPass}' -D ${config.dbName} -e "SELECT id, certificate_thumbprint, key_filename, is_active FROM eop_auth_config; SELECT id, host, port, protocol, base_dn, is_active FROM eop_ldap_config;"`,
    },
    {
      title: 'Step 4: Deploy Web Application Files to /var/www/eop-antispam',
      icon: <FileCode className="w-5 h-5 text-amber-500" />,
      description: 'Extract the project archive, set proper file permissions, and enable the Apache virtual host.',
      command: `# Create application directory:
sudo mkdir -p /var/www/eop-antispam

# Copy or unzip all downloaded project files to /var/www/eop-antispam:
# sudo unzip eop-antispam-php-mariadb.zip -d /var/www/eop-antispam/

# Set security permissions (owned by www-data):
sudo chown -R www-data:www-data /var/www/eop-antispam
sudo find /var/www/eop-antispam -type d -exec chmod 750 {} \\;
sudo find /var/www/eop-antispam -type f -exec chmod 640 {} \\;

# Enable Apache site and required modules:
sudo cp /var/www/eop-antispam/apache.conf /etc/apache2/sites-available/eop-antispam.conf
sudo a2enmod rewrite ssl headers
sudo a2ensite eop-antispam.conf
sudo systemctl restart apache2`,
    },
    {
      title: 'Step 5: Install PowerShell 7 & Exchange Module (For Sync Engine)',
      icon: <Terminal className="w-5 h-5 text-rose-500" />,
      description: 'Install PowerShell Core (pwsh) and the ExchangeOnlineManagement module on Debian to execute Set-HostedContentFilterPolicy.',
      command: `# Install Microsoft repository for Debian:
sudo apt-get install -y wget apt-transport-https software-properties-common
wget -q "https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb"
sudo dpkg -i packages-microsoft-prod.deb
sudo apt-get update
sudo apt-get install -y powershell

# Install ExchangeOnlineManagement module in PowerShell:
sudo pwsh -Command "Install-Module -Name ExchangeOnlineManagement -Scope AllUsers -Force"`,
    },
    {
      title: 'Step 6: Setup Crontab for Automated Background Sync',
      icon: <Clock className="w-5 h-5 text-indigo-500" />,
      description: 'Automate synchronization between MariaDB and Microsoft 365 EOP every 15 minutes.',
      command: `# Add scheduled task to /etc/crontab or www-data crontab:
(sudo crontab -u www-data -l 2>/dev/null; echo "*/15 * * * * /usr/bin/php /var/www/eop-antispam/cron-sync.php --policy=\\"${config.defaultPolicyName}\\" >> /var/log/eop-sync.log 2>&1") | sudo crontab -u www-data -`,
    },
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 transition-colors duration-200">
      {/* Header */}
      <div className="mb-8">
        <h2 className="text-2xl font-bold text-slate-900 dark:text-white tracking-tight">Debian Linux Server Deployment Guide</h2>
        <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
          Complete step-by-step instructions for hosting the PHP application on Debian 11/12, integrating with your remote MariaDB server and Microsoft Active Directory.
        </p>
      </div>

      {/* Architecture Highlights */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        <div className="p-4 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs transition-colors duration-200">
          <div className="text-xs font-semibold text-blue-600 dark:text-blue-400 uppercase tracking-wider mb-1">Architecture</div>
          <div className="text-sm font-bold text-slate-900 dark:text-white">Separate MariaDB Tables</div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            4 individual tables for high concurrency and clear segregation: <code>eop_allowed_senders</code>, <code>eop_blocked_senders</code>, <code>eop_allowed_domains</code>, <code>eop_blocked_domains</code>.
          </p>
        </div>

        <div className="p-4 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs transition-colors duration-200">
          <div className="text-xs font-semibold text-emerald-600 dark:text-emerald-400 uppercase tracking-wider mb-1">Authorization</div>
          <div className="text-sm font-bold text-slate-900 dark:text-white">Active Directory Group DN</div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Enforced via LDAP: <code>{config.ldapGroupDn}</code> with recursive nested group support using OID <code>1.2.840.113556.1.4.1941</code>.
          </p>
        </div>

        <div className="p-4 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs transition-colors duration-200">
          <div className="text-xs font-semibold text-purple-600 dark:text-purple-400 uppercase tracking-wider mb-1">Automation</div>
          <div className="text-sm font-bold text-slate-900 dark:text-white">PowerShell & Crontab</div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Native Linux pwsh script updates <code>Set-HostedContentFilterPolicy -Identity "{config.defaultPolicyName}"</code> on demand or every 15 minutes.
          </p>
        </div>
      </div>

      {/* Step by Step list */}
      <div className="space-y-6">
        {steps.map((step, idx) => (
          <div key={idx} className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-xs overflow-hidden transition-colors duration-200">
            <div className="p-5 border-b border-slate-100 dark:border-slate-800 flex items-start justify-between">
              <div className="flex items-start space-x-3">
                <div className="p-2 rounded-xl bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 mt-0.5">{step.icon}</div>
                <div>
                  <h3 className="text-base font-bold text-slate-900 dark:text-white">{step.title}</h3>
                  <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5">{step.description}</p>
                </div>
              </div>
              <button
                onClick={() => handleCopy(step.command, idx)}
                className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 rounded-lg text-xs font-medium transition border border-slate-200 dark:border-slate-700"
              >
                {copiedIndex === idx ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
                    <span className="text-emerald-700 dark:text-emerald-300 font-semibold">Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy Commands</span>
                  </>
                )}
              </button>
            </div>

            <div className="bg-slate-950 p-4 font-mono text-xs text-slate-200 overflow-x-auto border-t border-slate-800">
              <pre className="leading-relaxed">
                <code>{step.command}</code>
              </pre>
            </div>
          </div>
        ))}
      </div>

      {/* Troubleshooting FAQ */}
      <div className="mt-8 bg-slate-50 dark:bg-slate-900/60 rounded-2xl border border-slate-200 dark:border-slate-800 p-6 transition-colors duration-200">
        <h3 className="text-base font-bold text-slate-900 dark:text-white mb-4 flex items-center space-x-2">
          <AlertCircle className="w-5 h-5 text-amber-500" />
          <span>Debian / Active Directory Troubleshooting Tips</span>
        </h3>

        <div className="space-y-4 text-xs text-slate-700 dark:text-slate-300">
          <div>
            <span className="font-bold text-slate-900 dark:text-white block mb-1">Q: Do I need LDAPS (port 636) or SSL certificates?</span>
            <p className="text-slate-600 dark:text-slate-400">
              <strong>No.</strong> Standard plain LDAP on port 389 is enabled and supported by default. You do not need to install internal CA certificates or generate keystores. LDAPS (port 636) and StartTLS (port 389) are optional choices if your corporate policy requires them.
            </p>
          </div>

          <div>
            <span className="font-bold text-slate-900 dark:text-white block mb-1">Q: LDAPS connection fails with "Can't contact LDAP server"</span>
            <p className="text-slate-600 dark:text-slate-400">
              If you opted into LDAPS (port 636) or StartTLS, ensure <code>TLS_REQCERT allow</code> is added to <code>/etc/ldap/ldap.conf</code> on Debian so OpenLDAP does not drop the handshake due to self-signed or enterprise CA certs. Also verify that port 636 is open through your internal network firewalls.
            </p>
          </div>

          <div>
            <span className="font-bold text-slate-900 dark:text-white block mb-1">Q: MariaDB error "Host 'debian_ip' is not allowed to connect to this MariaDB server"</span>
            <p className="text-slate-600 dark:text-slate-400">
              1. On your remote MariaDB server, check <code>/etc/mysql/mariadb.conf.d/50-server.cnf</code> and verify <code>bind-address = 0.0.0.0</code> instead of <code>127.0.0.1</code>.<br />
              2. Ensure you ran <code>GRANT ALL PRIVILEGES ON {config.dbName}.* TO '{config.dbUser}'@'DEBIAN_IP' IDENTIFIED BY '...'; FLUSH PRIVILEGES;</code>.
            </p>
          </div>

          <div>
            <span className="font-bold text-slate-900 dark:text-white block mb-1">Q: How does nested AD group membership work?</span>
            <p className="text-slate-600 dark:text-slate-400">
              The <code>ldap.php</code> service employs the Microsoft Active Directory LDAP matching rule OID <code>1.2.840.113556.1.4.1941</code> (LDAP_MATCHING_RULE_IN_CHAIN). If a user is a member of "Security-Team" and "Security-Team" is nested inside <code>{config.ldapGroupDn}</code>, the user is authorized without needing direct group assignment.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
