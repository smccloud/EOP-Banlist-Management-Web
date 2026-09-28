import React, { useState } from 'react';
import { Image, ExternalLink, Shield, Layers, Settings, Zap, ArrowUpRight, CheckCircle2 } from 'lucide-react';

interface ScreenshotItem {
  id: string;
  title: string;
  subtitle: string;
  filename: string;
  category: string;
  badge: string;
  badgeColor: string;
  description: string;
  highlights: string[];
}

export const ScreenshotsView: React.FC = () => {
  const [selectedImage, setSelectedImage] = useState<string | null>(null);

  const screenshotItems: ScreenshotItem[] = [
    {
      id: 'dashboard',
      title: 'Main Anti-Spam Policy Dashboard',
      subtitle: 'Multi-table management, live delta counters, and high-contrast dark theme',
      filename: '/screenshots/dashboard-dark.png',
      category: 'Dashboard & Core UI',
      badge: 'Dark Mode UI',
      badgeColor: 'bg-blue-600/20 text-blue-400 border-blue-500/30',
      description:
        'The main administrative workspace displays active tenant metrics, policy selection, search/filter controls, domain clustering views, staged changes counter, and the multi-table anti-spam registry.',
      highlights: [
        'Dedicated tabs for Allowed Senders, Blocked Senders, Allowed Domains, and Blocked Domains',
        'Staged modifications counter badge (🚀 Push All Changes to EOP [4])',
        'Real-time status pills (● ACTIVE vs ▲ STAGED ADD with single-click Undo)',
        'Domain clustering by Parent Domain, Subdomain Tree, and Top-Level Domain (TLD)',
      ],
    },
    {
      id: 'smart-sorter',
      title: 'Split Smart Sorter Intake Engine',
      subtitle: 'Batch intake with RFC 5322 regex validation and real-time deduplication',
      filename: '/screenshots/smart-sorter-modal.png',
      category: 'Smart Sorter',
      badge: 'Batch Intake Engine',
      badgeColor: 'bg-emerald-600/20 text-emerald-400 border-emerald-500/30',
      description:
        'Administrators paste mixed bulk text containing email addresses, FQDNs, and wildcard domains. The Smart Sorter automatically parses RFC syntax, filters out existing duplicates, and routes entries to individual MariaDB tables.',
      highlights: [
        'Automatic routing of @ addresses to eop_allowed_senders or eop_blocked_senders',
        'Automatic routing of domain names and wildcards to eop_allowed_domains / blocked_domains',
        'Real-time deduplication against current remote MariaDB database records',
        'Visual live classification metrics (Senders, Domains, Duplicates Filtered, Syntax Errors)',
      ],
    },
    {
      id: 'setup-wizard',
      title: '5-Step Initial Run Setup Wizard (setup.php)',
      subtitle: 'Automated remote database schema creation and live Active Directory LDAP testing',
      filename: '/screenshots/setup-wizard.png',
      category: 'Initial Setup',
      badge: 'Security Locked',
      badgeColor: 'bg-amber-600/20 text-amber-400 border-amber-500/30',
      description:
        'Initial deployment wizard that verifies PHP 8 environment prerequisites, populates all 9 MariaDB schema tables, tests Active Directory LDAP bind credentials, uploads Exchange Online CBA certificates, and creates a permanent security lockout.',
      highlights: [
        'Plain LDAP (Port 389) supported out-of-the-box — no Debian certificate setup required',
        'Service Account Bind DN and Bind Password authorization for directory searches',
        'Recursive Group DN membership verification via Active Directory matching rule OID',
        'Permanent security lockout via MariaDB eop_setup_lock and installed.lock file',
      ],
    },
    {
      id: 'push-summary',
      title: 'Global Push All Changes to EOP Summary',
      subtitle: 'Itemized list-by-list audit report and PowerShell execution payload',
      filename: '/screenshots/push-summary-modal.png',
      category: 'Exchange Online Sync',
      badge: 'Atomic Push Engine',
      badgeColor: 'bg-purple-600/20 text-purple-400 border-purple-500/30',
      description:
        'Pushes all pending staged additions and removals across all 4 anti-spam tables to Microsoft 365 Exchange Online Protection in a single, atomic administrative operation.',
      highlights: [
        'Itemized audit breakdown detailing exact senders/domains added, removed, or preserved',
        'Applies changes using Set-HostedContentFilterPolicy via Certificate-Based Authentication',
        'Full execution history logged permanently to MariaDB eop_audit_log table',
        'Automatic reconciliation keeps remote MariaDB and Microsoft 365 synchronized',
      ],
    },
    {
      id: 'config-center',
      title: 'Centralized Configuration Center',
      subtitle: 'Active Directory LDAP parameters and Exchange Online CBA private key management',
      filename: '/screenshots/config-center.png',
      category: 'Configuration',
      badge: 'Database Stored',
      badgeColor: 'bg-indigo-600/20 text-indigo-400 border-indigo-500/30',
      description:
        'Manage Active Directory LDAP connection parameters and rotate Microsoft 365 Exchange Online RSA private keys directly in the database without modifying server configuration files.',
      highlights: [
        'All settings stored securely in eop_ldap_config and eop_auth_config tables',
        'RSA Private Key Passphrase encrypted with AES-256-GCM',
        'Live AD LDAP connection and group membership verification utility',
        'Zero filesystem permission edits or server restarts required for credential rotation',
      ],
    },
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 transition-colors duration-200">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-blue-600 flex items-center justify-center text-white shadow-md shadow-blue-600/30">
            <Image className="w-5 h-5 text-white" />
          </div>
          <div>
            <h2 className="text-2xl font-bold text-slate-900 dark:text-white tracking-tight">
              Application Screenshots &amp; UI Architecture
            </h2>
            <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
              High-resolution visual tour of the EOP Anti-Spam Policy Manager, dark-mode dashboards, setup wizard, and sync workflows.
            </p>
          </div>
        </div>
      </div>

      {/* Grid of Screenshots */}
      <div className="space-y-12">
        {screenshotItems.map((item, idx) => (
          <div
            key={item.id}
            className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-md overflow-hidden transition-all duration-200"
          >
            {/* Top Bar for Card */}
            <div className="p-5 border-b border-slate-100 dark:border-slate-800 flex flex-wrap items-center justify-between gap-4">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-bold text-blue-600 dark:text-blue-400 uppercase tracking-wider">
                    Screenshot {idx + 1} of {screenshotItems.length} &bull; {item.category}
                  </span>
                  <span className={`px-2 py-0.5 rounded-full text-xs font-semibold border ${item.badgeColor}`}>
                    {item.badge}
                  </span>
                </div>
                <h3 className="text-lg font-bold text-slate-900 dark:text-white mt-1">{item.title}</h3>
                <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5">{item.subtitle}</p>
              </div>

              <div className="flex items-center space-x-2">
                <a
                  href={item.filename}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 rounded-lg text-xs font-medium transition border border-slate-200 dark:border-slate-700"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  <span>Open Full Resolution (1440&times;900)</span>
                </a>
              </div>
            </div>

            {/* Image Preview Container */}
            <div
              className="bg-slate-950 p-4 sm:p-6 flex items-center justify-center cursor-pointer group relative overflow-hidden"
              onClick={() => setSelectedImage(item.filename)}
            >
              <img
                src={item.filename}
                alt={item.title}
                referrerPolicy="no-referrer"
                className="w-full max-h-[560px] object-contain rounded-xl border border-slate-800 shadow-2xl transition-transform duration-300 group-hover:scale-[1.01]"
              />
              <div className="absolute inset-0 bg-blue-600/10 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center pointer-events-none">
                <span className="px-4 py-2 bg-slate-900/90 text-white rounded-lg text-xs font-semibold shadow-lg border border-slate-700">
                  Click to Expand Fullscreen View
                </span>
              </div>
            </div>

            {/* Description & Key Feature Highlights */}
            <div className="p-6 bg-slate-50 dark:bg-slate-900/60 border-t border-slate-100 dark:border-slate-800">
              <p className="text-sm text-slate-700 dark:text-slate-300 mb-4">{item.description}</p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                {item.highlights.map((h, hIdx) => (
                  <div key={hIdx} className="flex items-start space-x-2 text-xs text-slate-600 dark:text-slate-400">
                    <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
                    <span>{h}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Lightbox Modal */}
      {selectedImage && (
        <div
          className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm p-4 sm:p-8 flex flex-col items-center justify-center cursor-zoom-out"
          onClick={() => setSelectedImage(null)}
        >
          <div className="max-w-6xl w-full relative">
            <button
              onClick={() => setSelectedImage(null)}
              className="absolute -top-10 right-0 text-white text-sm font-semibold bg-slate-800/80 px-3 py-1 rounded-md hover:bg-slate-700 border border-slate-600"
            >
              ✕ Close
            </button>
            <img
              src={selectedImage}
              alt="Enlarged screenshot"
              referrerPolicy="no-referrer"
              className="w-full max-h-[85vh] object-contain rounded-xl shadow-2xl border border-slate-700"
            />
          </div>
        </div>
      )}
    </div>
  );
};
