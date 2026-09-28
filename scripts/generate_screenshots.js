import { Resvg } from '@resvg/resvg-js';
import fs from 'fs';
import path from 'path';

const outDirs = ['public/screenshots', 'docs/screenshots'];
outDirs.forEach((dir) => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// Helper for window chrome
function renderBrowserChrome(title, url, width = 1440) {
  return `
    <!-- Window Bar -->
    <rect width="${width}" height="42" fill="#090d16" rx="10" ry="10" />
    <rect y="32" width="${width}" height="10" fill="#090d16" />
    <!-- Window Controls -->
    <circle cx="24" cy="21" r="6" fill="#ef4444" />
    <circle cx="44" cy="21" r="6" fill="#f59e0b" />
    <circle cx="64" cy="21" r="6" fill="#10b981" />
    <!-- URL Bar -->
    <rect x="180" y="8" width="${width - 360}" height="26" rx="6" fill="#1e293b" />
    <text x="195" y="25" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif" font-size="12" font-weight="500">🔒 https://${url}</text>
    <text x="${width - 120}" y="25" fill="#64748b" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif" font-size="12">EOP Portal v1.0</text>
  `;
}

// 1. Dashboard Screenshot SVG
function generateDashboardSvg() {
  const width = 1440;
  const height = 900;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}">
    <defs>
      <linearGradient id="bgGrad" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#0b0f19" />
        <stop offset="100%" stop-color="#020617" />
      </linearGradient>
      <linearGradient id="cardGrad" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#1e293b" />
        <stop offset="100%" stop-color="#0f172a" />
      </linearGradient>
      <linearGradient id="blueGrad" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%" stop-color="#2563eb" />
        <stop offset="100%" stop-color="#3b82f6" />
      </linearGradient>
      <linearGradient id="emeraldGrad" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%" stop-color="#059669" />
        <stop offset="100%" stop-color="#10b981" />
      </linearGradient>
      <linearGradient id="roseGrad" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%" stop-color="#dc2626" />
        <stop offset="100%" stop-color="#ef4444" />
      </linearGradient>
      <filter id="shadow" x="-5%" y="-5%" width="110%" height="110%">
        <feDropShadow dx="0" dy="4" stdDeviation="6" flood-color="#000000" flood-opacity="0.4"/>
      </filter>
    </defs>

    <rect width="${width}" height="${height}" fill="url(#bgGrad)" />
    ${renderBrowserChrome('EOP Anti-Spam Manager', 'eop.corp.example.com/index.php')}

    <!-- Top App Navigation -->
    <rect y="42" width="${width}" height="64" fill="#0f172a" stroke="#1e293b" stroke-width="1" />
    <!-- App Logo & Title -->
    <rect x="28" y="54" width="40" height="40" rx="10" fill="url(#blueGrad)" />
    <path d="M48 62 L58 66 L58 76 C58 82 48 86 48 86 C48 86 38 82 38 76 L38 66 Z" fill="none" stroke="#ffffff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" />
    <path d="M44 74 L47 77 L53 71" fill="none" stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />

    <text x="80" y="72" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="16" font-weight="700">EOP Anti-Spam Policy Manager</text>
    <text x="80" y="88" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="12">Microsoft 365 Exchange Online Protection</text>

    <!-- Tenant & Policy Selector in Header -->
    <rect x="420" y="56" width="310" height="36" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1" />
    <text x="435" y="78" fill="#64748b" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="600">POLICY:</text>
    <text x="488" y="78" fill="#f8fafc" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="600">Default (Inbound Anti-Spam)</text>
    <path d="M710 74 L715 79 L720 74" fill="none" stroke="#94a3b8" stroke-width="2" stroke-linecap="round" />

    <!-- Tenant Pill -->
    <rect x="745" y="56" width="220" height="36" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1" />
    <circle cx="760" cy="74" r="4" fill="#10b981" />
    <text x="772" y="78" fill="#cbd5e1" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12" font-weight="500">corp.onmicrosoft.com</text>

    <!-- User Profile & Mode -->
    <rect x="${width - 240}" y="56" width="90" height="36" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1" />
    <text x="${width - 225}" y="78" fill="#f1f5f9" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12" font-weight="600">🌙 Dark</text>

    <rect x="${width - 138}" y="56" width="114" height="36" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1" />
    <circle cx="${width - 120}" cy="74" r="10" fill="#3b82f6" />
    <text x="${width - 124}" y="78" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">ST</text>
    <text x="${width - 100}" y="78" fill="#f8fafc" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12" font-weight="600">smccloud</text>

    <!-- Main Workspace Area -->
    <!-- Metric Stat Cards -->
    <g transform="translate(28, 122)">
      <!-- Card 1: Allowed Senders -->
      <rect width="325" height="88" rx="12" fill="url(#cardGrad)" stroke="#1e293b" stroke-width="1" />
      <text x="20" y="30" fill="#10b981" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700" letter-spacing="1">ALLOWED SENDERS</text>
      <text x="20" y="65" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="30" font-weight="800">1,420</text>
      <text x="110" y="62" fill="#64748b" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">eop_allowed_senders</text>
      <rect x="260" y="24" width="45" height="45" rx="10" fill="#064e3b" opacity="0.6" />
      <text x="274" y="52" fill="#34d399" font-size="20">✓</text>

      <!-- Card 2: Blocked Senders -->
      <rect x="350" width="325" height="88" rx="12" fill="url(#cardGrad)" stroke="#1e293b" stroke-width="1" />
      <text x="370" y="30" fill="#ef4444" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700" letter-spacing="1">BLOCKED SENDERS</text>
      <text x="370" y="65" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="30" font-weight="800">845</text>
      <text x="445" y="62" fill="#64748b" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">eop_blocked_senders</text>
      <rect x="610" y="24" width="45" height="45" rx="10" fill="#7f1d1d" opacity="0.6" />
      <text x="624" y="52" fill="#f87171" font-size="20">✕</text>

      <!-- Card 3: Allowed Domains -->
      <rect x="700" width="325" height="88" rx="12" fill="url(#cardGrad)" stroke="#1e293b" stroke-width="1" />
      <text x="720" y="30" fill="#06b6d4" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700" letter-spacing="1">ALLOWED DOMAINS</text>
      <text x="720" y="65" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="30" font-weight="800">312</text>
      <text x="790" y="62" fill="#64748b" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">eop_allowed_domains</text>
      <rect x="960" y="24" width="45" height="45" rx="10" fill="#164e63" opacity="0.6" />
      <text x="973" y="52" fill="#22d3ee" font-size="18">🌐</text>

      <!-- Card 4: Staged Pending Changes -->
      <rect x="1050" width="334" height="88" rx="12" fill="#1e293b" stroke="#3b82f6" stroke-width="1.5" />
      <text x="1070" y="30" fill="#60a5fa" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700" letter-spacing="1">PENDING STAGED CHANGES</text>
      <text x="1070" y="65" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="30" font-weight="800">4</text>
      <text x="1105" y="62" fill="#93c5fd" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">Ready to push to M365</text>
      <rect x="1310" y="24" width="55" height="45" rx="10" fill="#1d4ed8" />
      <text x="1327" y="52" fill="#ffffff" font-size="18">🚀</text>
    </g>

    <!-- Table Tab Bar -->
    <g transform="translate(28, 226)">
      <!-- Tab 1: Allowed Senders (Active) -->
      <rect width="190" height="42" rx="8" fill="#2563eb" />
      <text x="22" y="26" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="700">Allowed Senders (1,420)</text>

      <!-- Tab 2: Blocked Senders -->
      <rect x="200" width="190" height="42" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1" />
      <text x="222" y="26" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="600">Blocked Senders (845)</text>

      <!-- Tab 3: Allowed Domains -->
      <rect x="400" width="190" height="42" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1" />
      <text x="422" y="26" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="600">Allowed Domains (312)</text>

      <!-- Tab 4: Blocked Domains -->
      <rect x="600" width="190" height="42" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1" />
      <text x="622" y="26" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="600">Blocked Domains (628)</text>

      <!-- Tab 5: Audit Log -->
      <rect x="800" width="140" height="42" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1" />
      <text x="825" y="26" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="600">Audit Log</text>
    </g>

    <!-- Action Toolbar -->
    <g transform="translate(28, 280)">
      <!-- Split Smart Sorter Allowed Button -->
      <rect width="180" height="40" rx="8" fill="url(#emeraldGrad)" />
      <text x="20" y="25" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="700">⚡ Smart Sort Allowed</text>

      <!-- Split Smart Sorter Blocked Button -->
      <rect x="190" width="180" height="40" rx="8" fill="url(#roseGrad)" />
      <text x="210" y="25" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="700">🚫 Smart Sort Blocked</text>

      <!-- Add Single Entry Button -->
      <rect x="380" width="130" height="40" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1" />
      <text x="405" y="25" fill="#f8fafc" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="600">+ Add Entry</text>

      <!-- Import CSV -->
      <rect x="520" width="120" height="40" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1" />
      <text x="545" y="25" fill="#f8fafc" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="600">📥 Import</text>

      <!-- Export CSV -->
      <rect x="650" width="120" height="40" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1" />
      <text x="675" y="25" fill="#f8fafc" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="600">📤 Export</text>

      <!-- Push All Changes to EOP (Primary Call to Action) -->
      <rect x="${width - 316}" width="260" height="40" rx="8" fill="url(#blueGrad)" />
      <text x="${width - 300}" y="25" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="700">🚀 Push All Changes to EOP</text>
      <!-- Staged Badge -->
      <circle cx="${width - 76}" cy="20" r="11" fill="#ef4444" />
      <text x="${width - 80}" y="24" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="800">4</text>
    </g>

    <!-- Filter & Search Bar -->
    <g transform="translate(28, 332)">
      <rect width="${width - 56}" height="42" rx="8" fill="#0f172a" stroke="#1e293b" stroke-width="1" />
      <text x="20" y="26" fill="#64748b" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13">🔍 Search senders, domains, notes, or administrators...</text>
      <text x="${width - 380}" y="26" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">Domain View: [ All Entries ▼ ]</text>
      <text x="${width - 180}" y="26" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">Sort: [ Newest First ▼ ]</text>
    </g>

    <!-- Main Data Table Container -->
    <g transform="translate(28, 386)">
      <rect width="${width - 56}" height="480" rx="12" fill="#0f172a" stroke="#1e293b" stroke-width="1" />

      <!-- Table Header -->
      <rect width="${width - 56}" height="44" rx="12" fill="#1e293b" />
      <rect y="32" width="${width - 56}" height="12" fill="#1e293b" />
      <text x="24" y="27" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">STATUS</text>
      <text x="140" y="27" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">SENDER EMAIL ADDRESS</text>
      <text x="460" y="27" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">TARGET TABLE</text>
      <text x="660" y="27" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">ADDED BY</text>
      <text x="800" y="27" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">DATE ADDED</text>
      <text x="960" y="27" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">JUSTIFICATION / NOTE</text>
      <text x="${width - 140}" y="27" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">ACTIONS</text>

      <!-- Row 1: Staged Added Entry -->
      <rect y="44" width="${width - 56}" height="54" fill="#1e3a5f" opacity="0.3" />
      <rect x="24" y="60" width="85" height="22" rx="6" fill="#1e40af" />
      <text x="32" y="75" fill="#bfdbfe" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="10" font-weight="700">▲ STAGED ADD</text>
      <text x="140" y="76" fill="#60a5fa" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="600">billing-system@trustedpartner.com</text>
      <text x="460" y="76" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">eop_allowed_senders</text>
      <text x="660" y="76" fill="#e2e8f0" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">smccloud</text>
      <text x="800" y="76" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">Just now</text>
      <text x="960" y="76" fill="#cbd5e1" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">Q4 Invoicing gateway integration</text>
      <rect x="${width - 140}" y="57" width="60" height="28" rx="6" fill="#1e293b" stroke="#3b82f6" stroke-width="1" />
      <text x="${width - 128}" y="75" fill="#60a5fa" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="600">Undo</text>

      <!-- Row 2: Staged Added Entry -->
      <rect y="98" width="${width - 56}" height="54" fill="#1e3a5f" opacity="0.3" />
      <rect x="24" y="114" width="85" height="22" rx="6" fill="#1e40af" />
      <text x="32" y="129" fill="#bfdbfe" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="10" font-weight="700">▲ STAGED ADD</text>
      <text x="140" y="130" fill="#60a5fa" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="600">security-alerts@cloud-monitor.org</text>
      <text x="460" y="130" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">eop_allowed_senders</text>
      <text x="660" y="130" fill="#e2e8f0" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">smccloud</text>
      <text x="800" y="130" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">2 mins ago</text>
      <text x="960" y="130" fill="#cbd5e1" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">SOC automated incident reporting</text>
      <rect x="${width - 140}" y="111" width="60" height="28" rx="6" fill="#1e293b" stroke="#3b82f6" stroke-width="1" />
      <text x="${width - 128}" y="129" fill="#60a5fa" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="600">Undo</text>

      <!-- Row 3: Active Synchronized Entry -->
      <line x1="0" y1="152" x2="${width - 56}" y2="152" stroke="#1e293b" />
      <rect x="24" y="168" width="65" height="22" rx="6" fill="#064e3b" />
      <text x="34" y="183" fill="#34d399" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="10" font-weight="700">● ACTIVE</text>
      <text x="140" y="184" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="500">ceo-notifications@internal-exec.com</text>
      <text x="460" y="184" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">eop_allowed_senders</text>
      <text x="660" y="184" fill="#e2e8f0" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">jdoe_admin</text>
      <text x="800" y="184" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">2026-09-27 16:42</text>
      <text x="960" y="184" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">Executive office briefing distribution</text>
      <rect x="${width - 140}" y="165" width="32" height="28" rx="6" fill="#7f1d1d" opacity="0.6" />
      <text x="${width - 130}" y="183" fill="#fca5a5" font-size="13">🗑️</text>

      <!-- Row 4: Active Synchronized Entry -->
      <line x1="0" y1="206" x2="${width - 56}" y2="206" stroke="#1e293b" />
      <rect x="24" y="222" width="65" height="22" rx="6" fill="#064e3b" />
      <text x="34" y="237" fill="#34d399" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="10" font-weight="700">● ACTIVE</text>
      <text x="140" y="238" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="500">dispatch@freight-logistics.net</text>
      <text x="460" y="238" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">eop_allowed_senders</text>
      <text x="660" y="238" fill="#e2e8f0" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">asmith_adm</text>
      <text x="800" y="238" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">2026-09-25 09:15</text>
      <text x="960" y="238" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">Supply chain automated tracking emails</text>
      <rect x="${width - 140}" y="219" width="32" height="28" rx="6" fill="#7f1d1d" opacity="0.6" />
      <text x="${width - 130}" y="237" fill="#fca5a5" font-size="13">🗑️</text>

      <!-- Row 5: Active Synchronized Entry -->
      <line x1="0" y1="260" x2="${width - 56}" y2="260" stroke="#1e293b" />
      <rect x="24" y="276" width="65" height="22" rx="6" fill="#064e3b" />
      <text x="34" y="291" fill="#34d399" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="10" font-weight="700">● ACTIVE</text>
      <text x="140" y="292" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="500">newsletter@cybersecurity-feed.org</text>
      <text x="460" y="292" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">eop_allowed_senders</text>
      <text x="660" y="292" fill="#e2e8f0" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">jdoe_admin</text>
      <text x="800" y="292" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">2026-09-22 11:30</text>
      <text x="960" y="292" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">Infosec industry threat intelligence alerts</text>
      <rect x="${width - 140}" y="273" width="32" height="28" rx="6" fill="#7f1d1d" opacity="0.6" />
      <text x="${width - 130}" y="291" fill="#fca5a5" font-size="13">🗑️</text>

      <!-- Pagination Footer -->
      <rect y="430" width="${width - 56}" height="50" rx="12" fill="#1e293b" />
      <text x="24" y="460" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">Showing 1 to 25 of 1,420 Allowed Senders (Remote MariaDB: eop_allowed_senders)</text>
      <text x="${width - 320}" y="460" fill="#cbd5e1" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">Page 1 of 57   [Previous]  [1] [2] [3] ... [57]  [Next]</text>
    </g>
  </svg>`;
}

// 2. Split Smart Sorter Modal Screenshot
function generateSmartSorterSvg() {
  const width = 1440;
  const height = 900;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}">
    <defs>
      <linearGradient id="bgGrad2" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#0b0f19" />
        <stop offset="100%" stop-color="#020617" />
      </linearGradient>
      <linearGradient id="emeraldGrad2" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%" stop-color="#059669" />
        <stop offset="100%" stop-color="#10b981" />
      </linearGradient>
    </defs>

    <rect width="${width}" height="${height}" fill="url(#bgGrad2)" />
    ${renderBrowserChrome('EOP Anti-Spam Manager - Smart Sorter', 'eop.corp.example.com/index.php')}

    <!-- Dimmed Background Overlay -->
    <rect y="42" width="${width}" height="${height - 42}" fill="#000000" opacity="0.65" />

    <!-- Modal Box Container -->
    <g transform="translate(240, 90)">
      <rect width="960" height="740" rx="16" fill="#0f172a" stroke="#334155" stroke-width="1.5" />

      <!-- Modal Header -->
      <rect width="960" height="70" rx="16" fill="#1e293b" />
      <rect y="50" width="960" height="20" fill="#1e293b" />
      <circle cx="45" cy="35" r="18" fill="#065f46" />
      <text x="37" y="42" fill="#34d399" font-size="20">⚡</text>

      <text x="75" y="36" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="18" font-weight="700">Split Smart Sorter: Allowlist Engine</text>
      <text x="75" y="55" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">Automatically routes mixed text into eop_allowed_senders (@) and eop_allowed_domains (FQDN)</text>
      <text x="915" y="42" fill="#64748b" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="22" font-weight="300">✕</text>

      <!-- Textarea Input Area -->
      <g transform="translate(35, 90)">
        <text x="0" y="0" fill="#f8fafc" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="600">PASTE BATCH DATA (EMAILS, DOMAINS, WILDCARDS, CSV SNIPPETS)</text>
        <rect y="12" width="890" height="210" rx="10" fill="#020617" stroke="#3b82f6" stroke-width="1.5" />

        <!-- Mock Input Text Lines -->
        <text x="20" y="40" fill="#38bdf8" font-family="Courier, monospace" font-size="13"># Paste mixed vendor entries</text>
        <text x="20" y="65" fill="#f8fafc" font-family="Courier, monospace" font-size="13">support-gateway@partner-invoicing.com</text>
        <text x="20" y="90" fill="#f8fafc" font-family="Courier, monospace" font-size="13">cloud-services.trusted-network.io</text>
        <text x="20" y="115" fill="#f8fafc" font-family="Courier, monospace" font-size="13">api-notifications@partner-invoicing.com</text>
        <text x="20" y="140" fill="#f8fafc" font-family="Courier, monospace" font-size="13">*.global-logistics-partner.net</text>
        <text x="20" y="165" fill="#f8fafc" font-family="Courier, monospace" font-size="13">ceo-notifications@internal-exec.com    <tspan fill="#f59e0b">[Existing in DB]</tspan></text>
        <text x="20" y="190" fill="#f8fafc" font-family="Courier, monospace" font-size="13">vendor-procurement.corp.de</text>
      </g>

      <!-- Live Classification Summary Badges -->
      <g transform="translate(35, 335)">
        <text x="0" y="0" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12" font-weight="700" letter-spacing="1">LIVE CLASSIFICATION &amp; DEDUPLICATION METRICS</text>

        <!-- Allowed Senders Box -->
        <rect y="12" width="205" height="74" rx="10" fill="#1e293b" stroke="#059669" stroke-width="1.5" />
        <text x="18" y="36" fill="#34d399" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">ALLOWED SENDERS (@)</text>
        <text x="18" y="68" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="26" font-weight="800">2</text>
        <text x="50" y="66" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11">eop_allowed_senders</text>

        <!-- Allowed Domains Box -->
        <rect x="225" y="12" width="205" height="74" rx="10" fill="#1e293b" stroke="#0284c7" stroke-width="1.5" />
        <text x="243" y="36" fill="#38bdf8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">ALLOWED DOMAINS (FQDN)</text>
        <text x="243" y="68" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="26" font-weight="800">3</text>
        <text x="275" y="66" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11">eop_allowed_domains</text>

        <!-- Duplicates Box -->
        <rect x="450" y="12" width="205" height="74" rx="10" fill="#1e293b" stroke="#d97706" stroke-width="1.5" />
        <text x="468" y="36" fill="#fbbf24" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">DUPLICATES FILTERED</text>
        <text x="468" y="68" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="26" font-weight="800">1</text>
        <text x="500" y="66" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11">Already in MariaDB</text>

        <!-- Syntax Invalid Box -->
        <rect x="675" y="12" width="215" height="74" rx="10" fill="#1e293b" stroke="#334155" stroke-width="1" />
        <text x="693" y="36" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">SYNTAX ERRORS</text>
        <text x="693" y="68" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="26" font-weight="800">0</text>
        <text x="725" y="66" fill="#10b981" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11">All Valid RFC/DNS</text>
      </g>

      <!-- Routing Breakdown Preview -->
      <g transform="translate(35, 440)">
        <text x="0" y="0" fill="#f8fafc" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="600">STAGING ROUTING PREVIEW (WILL BE ADDED TO MARIADB ON CONFIRM):</text>
        <rect y="12" width="890" height="135" rx="8" fill="#020617" stroke="#1e293b" stroke-width="1" />

        <text x="20" y="40" fill="#10b981" font-family="Courier, monospace" font-size="12">→ support-gateway@partner-invoicing.com</text>
        <text x="440" y="40" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">Route to: <tspan fill="#34d399" font-weight="700">eop_allowed_senders</tspan></text>

        <text x="20" y="68" fill="#0284c7" font-family="Courier, monospace" font-size="12">→ cloud-services.trusted-network.io</text>
        <text x="440" y="68" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">Route to: <tspan fill="#38bdf8" font-weight="700">eop_allowed_domains</tspan></text>

        <text x="20" y="96" fill="#0284c7" font-family="Courier, monospace" font-size="12">→ *.global-logistics-partner.net</text>
        <text x="440" y="96" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">Route to: <tspan fill="#38bdf8" font-weight="700">eop_allowed_domains</tspan> (Wildcard Domain)</text>

        <text x="20" y="124" fill="#0284c7" font-family="Courier, monospace" font-size="12">→ vendor-procurement.corp.de</text>
        <text x="440" y="124" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">Route to: <tspan fill="#38bdf8" font-weight="700">eop_allowed_domains</tspan></text>
      </g>

      <!-- Justification & Action Buttons -->
      <g transform="translate(35, 605)">
        <text x="0" y="0" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12" font-weight="600">CHANGE JUSTIFICATION / AUDIT NOTE:</text>
        <rect y="10" width="890" height="38" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1" />
        <text x="15" y="34" fill="#f8fafc" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13">Approved Q4 vendor onboarding and logistics tracking automation</text>

        <rect x="520" y="65" width="100" height="42" rx="8" fill="#1e293b" stroke="#475569" stroke-width="1" />
        <text x="548" y="91" fill="#cbd5e1" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="600">Cancel</text>

        <rect x="635" y="65" width="255" height="42" rx="8" fill="url(#emeraldGrad2)" />
        <text x="655" y="91" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="700">Stage 5 Entries into Allowlist</text>
      </g>
    </g>
  </svg>`;
}

// 3. Setup Wizard Screenshot SVG
function generateSetupWizardSvg() {
  const width = 1440;
  const height = 900;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}">
    <defs>
      <linearGradient id="bgGrad3" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#0b0f19" />
        <stop offset="100%" stop-color="#020617" />
      </linearGradient>
      <linearGradient id="blueGrad3" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%" stop-color="#2563eb" />
        <stop offset="100%" stop-color="#3b82f6" />
      </linearGradient>
    </defs>

    <rect width="${width}" height="${height}" fill="url(#bgGrad3)" />
    ${renderBrowserChrome('EOP Initial Run Setup Wizard', 'eop.corp.example.com/setup.php')}

    <!-- Top Wizard Brand -->
    <rect y="42" width="${width}" height="70" fill="#0f172a" stroke="#1e293b" stroke-width="1" />
    <rect x="40" y="56" width="42" height="42" rx="10" fill="url(#blueGrad3)" />
    <path d="M61 65 L71 69 L71 79 C71 85 61 89 61 89 C61 89 51 85 51 79 L51 69 Z" fill="none" stroke="#ffffff" stroke-width="2.5" />
    <text x="96" y="74" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="17" font-weight="700">EOP Anti-Spam Deployment Wizard</text>
    <text x="96" y="91" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">Initial 5-Step Automated Environment Provisioning &amp; Lockout</text>

    <!-- Step Progress Bar -->
    <g transform="translate(180, 135)">
      <!-- Step 1 Complete -->
      <circle cx="60" cy="20" r="16" fill="#10b981" />
      <text x="55" y="25" fill="#ffffff" font-weight="700" font-size="14">✓</text>
      <text x="25" y="50" fill="#10b981" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="600">1. ENVIRONMENT</text>

      <line x1="85" y1="20" x2="255" y2="20" stroke="#10b981" stroke-width="3" />

      <!-- Step 2 Complete -->
      <circle cx="280" cy="20" r="16" fill="#10b981" />
      <text x="275" y="25" fill="#ffffff" font-weight="700" font-size="14">✓</text>
      <text x="248" y="50" fill="#10b981" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="600">2. MARIADB DB</text>

      <line x1="305" y1="20" x2="475" y2="20" stroke="#3b82f6" stroke-width="3" />

      <!-- Step 3 Active -->
      <circle cx="500" cy="20" r="18" fill="#2563eb" stroke="#93c5fd" stroke-width="3" />
      <text x="495" y="26" fill="#ffffff" font-weight="800" font-size="14">3</text>
      <text x="460" y="50" fill="#60a5fa" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">3. AD LDAP AUTH</text>

      <line x1="525" y1="20" x2="695" y2="20" stroke="#334155" stroke-width="2" />

      <!-- Step 4 Pending -->
      <circle cx="720" cy="20" r="16" fill="#1e293b" stroke="#475569" stroke-width="1.5" />
      <text x="715" y="25" fill="#94a3b8" font-weight="700" font-size="13">4</text>
      <text x="685" y="50" fill="#64748b" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="600">4. EOP CBA KEYS</text>

      <line x1="745" y1="20" x2="915" y2="20" stroke="#334155" stroke-width="2" />

      <!-- Step 5 Pending -->
      <circle cx="940" cy="20" r="16" fill="#1e293b" stroke="#475569" stroke-width="1.5" />
      <text x="935" y="25" fill="#94a3b8" font-weight="700" font-size="13">5</text>
      <text x="905" y="50" fill="#64748b" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="600">5. LOCK &amp; FINISH</text>
    </g>

    <!-- Main Wizard Card (Step 3 Content) -->
    <g transform="translate(180, 205)">
      <rect width="1080" height="660" rx="16" fill="#0f172a" stroke="#1e293b" stroke-width="1" />

      <!-- Card Title -->
      <text x="40" y="45" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="20" font-weight="700">Step 3: Active Directory LDAP &amp; Bind Password Authorization</text>
      <text x="40" y="68" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13">Configures domain controller reachability, service account search credentials, and mandatory group DN authorization.</text>

      <!-- Protocol Selection -->
      <g transform="translate(40, 95)">
        <text x="0" y="15" fill="#e2e8f0" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="600">LDAP PROTOCOL MODE:</text>
        <rect x="0" y="26" width="310" height="42" rx="8" fill="#1e3a5f" stroke="#3b82f6" stroke-width="1.5" />
        <circle cx="25" cy="47" r="6" fill="#3b82f6" />
        <text x="42" y="52" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="600">Plain LDAP: Port 389 (Default)</text>

        <rect x="330" y="26" width="310" height="42" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1" />
        <circle cx="355" cy="47" r="6" fill="none" stroke="#64748b" stroke-width="2" />
        <text x="372" y="52" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13">LDAPS: Port 636 (SSL)</text>

        <rect x="660" y="26" width="340" height="42" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1" />
        <circle cx="685" cy="47" r="6" fill="none" stroke="#64748b" stroke-width="2" />
        <text x="702" y="52" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13">StartTLS: Port 389 (Explicit)</text>
      </g>

      <!-- Inputs Grid -->
      <g transform="translate(40, 185)">
        <!-- Domain Controller -->
        <text x="0" y="0" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12" font-weight="600">DOMAIN CONTROLLER FQDN / IP:</text>
        <rect y="10" width="480" height="40" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1" />
        <text x="15" y="35" fill="#f8fafc" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13">dc01.corp.example.com</text>

        <!-- Search Base DN -->
        <text x="520" y="0" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12" font-weight="600">SEARCH BASE DISTINGUISHED NAME (BASE DN):</text>
        <rect x="520" y="10" width="480" height="40" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1" />
        <text x="535" y="35" fill="#f8fafc" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13">DC=corp,DC=example,DC=com</text>

        <!-- Service Account Bind DN -->
        <text x="0" y="75" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12" font-weight="600">SERVICE ACCOUNT BIND DN (FOR DIRECTORY SEARCHES):</text>
        <rect y="85" width="480" height="40" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1" />
        <text x="15" y="110" fill="#f8fafc" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13">CN=svc-eop-web,OU=Service Accounts,DC=corp,DC=example,DC=com</text>

        <!-- Service Account Bind Password -->
        <text x="520" y="75" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12" font-weight="600">SERVICE ACCOUNT BIND PASSWORD:</text>
        <rect x="520" y="85" width="480" height="40" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1" />
        <text x="535" y="110" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="16">••••••••••••••••••••••••</text>
        <text x="940" y="110" fill="#3b82f6" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12" font-weight="600">Show</text>

        <!-- Authorized Group DN -->
        <text x="0" y="150" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12" font-weight="600">AUTHORIZED ACCESS GROUP DISTINGUISHED NAME (GROUP DN):</text>
        <rect y="160" width="1000" height="40" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1" />
        <text x="15" y="185" fill="#f8fafc" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13">CN=Exchange-Admins,OU=Security Groups,OU=Administration,DC=corp,DC=example,DC=com</text>
      </g>

      <!-- Test Connection Result Box -->
      <g transform="translate(40, 415)">
        <rect width="1000" height="150" rx="10" fill="#020617" stroke="#059669" stroke-width="1.5" />

        <circle cx="30" cy="30" r="12" fill="#065f46" />
        <text x="25" y="35" fill="#34d399" font-size="14" font-weight="700">✓</text>
        <text x="55" y="35" fill="#34d399" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="14" font-weight="700">LIVE ACTIVE DIRECTORY CONNECTION TEST: ALL PASSED</text>

        <text x="55" y="65" fill="#e2e8f0" font-family="Courier, monospace" font-size="12">[✓] TCP Socket to dc01.corp.example.com:389 - CONNECTED (3ms)</text>
        <text x="55" y="90" fill="#e2e8f0" font-family="Courier, monospace" font-size="12">[✓] Service Account Bind (CN=svc-eop-web,OU=Service Accounts...) - AUTHENTICATED</text>
        <text x="55" y="115" fill="#e2e8f0" font-family="Courier, monospace" font-size="12">[✓] Group DN Resolution (CN=Exchange-Admins...) - RESOLVED (14 nested members authorized)</text>
        <text x="55" y="140" fill="#94a3b8" font-family="Courier, monospace" font-size="11">[i] Recursive search rule OID 1.2.840.113556.1.4.1941 supported and verified.</text>
      </g>

      <!-- Bottom Nav Buttons -->
      <g transform="translate(40, 590)">
        <rect width="160" height="42" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1" />
        <text x="40" y="26" fill="#cbd5e1" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="600">&lt; Back: Step 2</text>

        <rect x="180" width="220" height="42" rx="8" fill="#1e293b" stroke="#3b82f6" stroke-width="1" />
        <text x="210" y="26" fill="#60a5fa" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="600">⚡ Retest AD Connection</text>

        <rect x="740" width="260" height="42" rx="8" fill="url(#blueGrad3)" />
        <text x="765" y="26" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="700">Save &amp; Continue to Step 4 &gt;</text>
      </g>
    </g>
  </svg>`;
}

// 4. Push Summary Modal Screenshot SVG
function generatePushSummarySvg() {
  const width = 1440;
  const height = 900;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}">
    <defs>
      <linearGradient id="bgGrad4" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#0b0f19" />
        <stop offset="100%" stop-color="#020617" />
      </linearGradient>
      <linearGradient id="blueGrad4" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%" stop-color="#2563eb" />
        <stop offset="100%" stop-color="#3b82f6" />
      </linearGradient>
    </defs>

    <rect width="${width}" height="${height}" fill="url(#bgGrad4)" />
    ${renderBrowserChrome('Push All Changes to EOP', 'eop.corp.example.com/index.php')}

    <rect y="42" width="${width}" height="${height - 42}" fill="#000000" opacity="0.7" />

    <!-- Push Modal Container -->
    <g transform="translate(220, 95)">
      <rect width="1000" height="730" rx="16" fill="#0f172a" stroke="#3b82f6" stroke-width="1.5" />

      <!-- Modal Header -->
      <rect width="1000" height="74" rx="16" fill="#1e293b" />
      <rect y="54" width="1000" height="20" fill="#1e293b" />
      <circle cx="45" cy="37" r="18" fill="#1e40af" />
      <text x="35" y="44" fill="#93c5fd" font-size="20">🚀</text>

      <text x="75" y="38" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="18" font-weight="700">Push All Staged Changes to Microsoft 365 Exchange Online</text>
      <text x="75" y="58" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">Target Policy: Default (Inbound Anti-Spam)   |   Tenant: corp.onmicrosoft.com</text>
      <text x="955" y="44" fill="#64748b" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="22">✕</text>

      <!-- Itemized Delta List Boxes -->
      <g transform="translate(35, 95)">
        <text x="0" y="0" fill="#f8fafc" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="700">ITEMIZED AUDIT BREAKDOWN OF STAGED MODIFICATIONS (4 CHANGES):</text>

        <!-- Box 1: Allowed Senders -->
        <rect y="12" width="930" height="70" rx="8" fill="#1e293b" stroke="#059669" stroke-width="1" />
        <rect x="15" y="24" width="150" height="24" rx="6" fill="#064e3b" />
        <text x="24" y="40" fill="#34d399" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">ALLOWED SENDERS (2)</text>
        <text x="180" y="40" fill="#10b981" font-family="Courier, monospace" font-size="12" font-weight="700">+ ADD: billing-system@trustedpartner.com</text>
        <text x="560" y="40" fill="#10b981" font-family="Courier, monospace" font-size="12" font-weight="700">+ ADD: security-alerts@cloud-monitor.org</text>
        <text x="180" y="62" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11">Applies to: Set-HostedContentFilterPolicy -AllowedSenders</text>

        <!-- Box 2: Blocked Senders -->
        <rect y="92" width="930" height="70" rx="8" fill="#1e293b" stroke="#dc2626" stroke-width="1" />
        <rect x="15" y="104" width="150" height="24" rx="6" fill="#7f1d1d" />
        <text x="24" y="120" fill="#fca5a5" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">BLOCKED SENDERS (1)</text>
        <text x="180" y="120" fill="#ef4444" font-family="Courier, monospace" font-size="12" font-weight="700">+ ADD: phish-campaign@malicious-sender.top</text>
        <text x="180" y="142" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11">Applies to: Set-HostedContentFilterPolicy -BlockedSenders</text>

        <!-- Box 3: Allowed Domains -->
        <rect y="172" width="930" height="60" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1" />
        <rect x="15" y="184" width="150" height="24" rx="6" fill="#334155" />
        <text x="24" y="200" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">ALLOWED DOMAINS (0)</text>
        <text x="180" y="200" fill="#64748b" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">No staged modifications — all 312 existing Allowed Domains preserved in Microsoft 365.</text>

        <!-- Box 4: Blocked Domains -->
        <rect y="242" width="930" height="70" rx="8" fill="#1e293b" stroke="#d97706" stroke-width="1" />
        <rect x="15" y="254" width="150" height="24" rx="6" fill="#78350f" />
        <text x="24" y="270" fill="#fde68a" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">BLOCKED DOMAINS (1)</text>
        <text x="180" y="270" fill="#f59e0b" font-family="Courier, monospace" font-size="12" font-weight="700">- REMOVE: retired-vendor-domain.biz</text>
        <text x="180" y="292" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11">Applies to: Set-HostedContentFilterPolicy -BlockedSenderDomains</text>
      </g>

      <!-- PowerShell Payload Preview Box -->
      <g transform="translate(35, 435)">
        <text x="0" y="0" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12" font-weight="700">AUTOMATION SCRIPT PAYLOAD (pwsh + ExchangeOnlineManagement):</text>
        <rect y="12" width="930" height="150" rx="8" fill="#020617" stroke="#1e293b" stroke-width="1" />

        <text x="20" y="38" fill="#38bdf8" font-family="Courier, monospace" font-size="12">Connect-ExchangeOnline -AppId $ClientId -CertificateThumbprint $CertThumbprint -Organization $Organization</text>
        <text x="20" y="65" fill="#f8fafc" font-family="Courier, monospace" font-size="12">Set-HostedContentFilterPolicy -Identity "Default" \`</text>
        <text x="40" y="90" fill="#34d399" font-family="Courier, monospace" font-size="12">-AllowedSenders @('user@trustedpartner.com', 'billing-system@trustedpartner.com', 'security-alerts@cloud-monitor.org', ...) \`</text>
        <text x="40" y="115" fill="#f87171" font-family="Courier, monospace" font-size="12">-BlockedSenders @('spam@botnet.ru', 'phish-campaign@malicious-sender.top', ...) \`</text>
        <text x="40" y="140" fill="#cbd5e1" font-family="Courier, monospace" font-size="12">-AllowedSenderDomains @('partner.com', 'trusted-network.io', ...) -BlockedSenderDomains @('badactor.xyz', ...)</text>
      </g>

      <!-- Action Buttons -->
      <g transform="translate(35, 620)">
        <rect x="520" y="20" width="120" height="42" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1" />
        <text x="560" y="46" fill="#cbd5e1" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="600">Cancel</text>

        <rect x="660" y="20" width="270" height="42" rx="8" fill="url(#blueGrad4)" />
        <text x="685" y="46" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="700">Confirm &amp; Execute Push to EOP</text>
      </g>
    </g>
  </svg>`;
}

// 5. Configuration Center Screenshot SVG
function generateConfigCenterSvg() {
  const width = 1440;
  const height = 900;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}">
    <defs>
      <linearGradient id="bgGrad5" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#0b0f19" />
        <stop offset="100%" stop-color="#020617" />
      </linearGradient>
      <linearGradient id="cardGrad5" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#1e293b" />
        <stop offset="100%" stop-color="#0f172a" />
      </linearGradient>
    </defs>

    <rect width="${width}" height="${height}" fill="url(#bgGrad5)" />
    ${renderBrowserChrome('Centralized Configuration Center', 'eop.corp.example.com/index.php?tab=config_center')}

    <!-- Header Navigation -->
    <rect y="42" width="${width}" height="64" fill="#0f172a" stroke="#1e293b" stroke-width="1" />
    <text x="35" y="78" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="17" font-weight="700">⚙️ Centralized Configuration Center</text>
    <text x="360" y="78" fill="#64748b" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">Stored in MariaDB: eop_ldap_config &amp; eop_auth_config (Zero filesystem edits)</text>

    <!-- Two-Column Configuration Grid -->
    <g transform="translate(35, 125)">
      <!-- Left Column: Active Directory LDAP Settings -->
      <rect width="665" height="740" rx="14" fill="url(#cardGrad5)" stroke="#1e293b" stroke-width="1" />
      <rect width="665" height="54" rx="14" fill="#1e293b" />
      <text x="25" y="34" fill="#60a5fa" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="15" font-weight="700">Active Directory LDAP Parameters (eop_ldap_config)</text>

      <g transform="translate(25, 75)">
        <text x="0" y="0" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">DOMAIN CONTROLLER FQDN</text>
        <rect y="8" width="615" height="38" rx="8" fill="#0f172a" stroke="#334155" stroke-width="1" />
        <text x="15" y="32" fill="#f8fafc" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13">dc01.corp.example.com</text>

        <text x="0" y="65" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">PORT &amp; PROTOCOL</text>
        <rect y="73" width="615" height="38" rx="8" fill="#0f172a" stroke="#334155" stroke-width="1" />
        <text x="15" y="97" fill="#f8fafc" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13">389 (Standard Plain LDAP - No Certificates Required)</text>

        <text x="0" y="130" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">SEARCH BASE DISTINGUISHED NAME (BASE DN)</text>
        <rect y="138" width="615" height="38" rx="8" fill="#0f172a" stroke="#334155" stroke-width="1" />
        <text x="15" y="162" fill="#f8fafc" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13">DC=corp,DC=example,DC=com</text>

        <text x="0" y="195" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">MANDATORY AUTHORIZED GROUP DN (RECURSIVE RESOLUTION)</text>
        <rect y="203" width="615" height="38" rx="8" fill="#0f172a" stroke="#334155" stroke-width="1" />
        <text x="15" y="227" fill="#f8fafc" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">CN=Exchange-Admins,OU=Security Groups,DC=corp,DC=example,DC=com</text>

        <text x="0" y="260" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">SERVICE ACCOUNT BIND DN</text>
        <rect y="268" width="615" height="38" rx="8" fill="#0f172a" stroke="#334155" stroke-width="1" />
        <text x="15" y="292" fill="#f8fafc" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">CN=svc-eop-web,OU=Service Accounts,DC=corp,DC=example,DC=com</text>

        <text x="0" y="325" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">SERVICE ACCOUNT BIND PASSWORD</text>
        <rect y="333" width="615" height="38" rx="8" fill="#0f172a" stroke="#334155" stroke-width="1" />
        <text x="15" y="357" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="16">••••••••••••••••••••••••</text>
        <text x="560" y="357" fill="#3b82f6" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12" font-weight="600">Show</text>

        <rect y="400" width="220" height="40" rx="8" fill="#2563eb" />
        <text x="35" y="425" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="700">Test LDAP Connection</text>
      </g>

      <!-- Right Column: Exchange Online CBA Settings -->
      <g transform="translate(695, 0)">
        <rect width="675" height="740" rx="14" fill="url(#cardGrad5)" stroke="#1e293b" stroke-width="1" />
        <rect width="675" height="54" rx="14" fill="#1e293b" />
        <text x="25" y="34" fill="#a855f7" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="15" font-weight="700">Exchange Online CBA Credentials (eop_auth_config)</text>

        <g transform="translate(25, 75)">
          <text x="0" y="0" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">MICROSOFT 365 TENANT ID (AZURE AD)</text>
          <rect y="8" width="625" height="38" rx="8" fill="#0f172a" stroke="#334155" stroke-width="1" />
          <text x="15" y="32" fill="#f8fafc" font-family="Courier, monospace" font-size="13">7a8b9c0d-1234-5678-abcd-ef0123456789</text>

          <text x="0" y="65" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">APP REGISTRATION CLIENT ID</text>
          <rect y="73" width="625" height="38" rx="8" fill="#0f172a" stroke="#334155" stroke-width="1" />
          <text x="15" y="97" fill="#f8fafc" font-family="Courier, monospace" font-size="13">3b4c5d6e-9876-5432-fedc-ba9876543210</text>

          <text x="0" y="130" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">APP-ONLY CERTIFICATE THUMBPRINT (SHA-1)</text>
          <rect y="138" width="625" height="38" rx="8" fill="#0f172a" stroke="#334155" stroke-width="1" />
          <text x="15" y="162" fill="#f8fafc" font-family="Courier, monospace" font-size="13">9F2E7B8A1C4D5E6F0123456789ABCDEF01234567</text>

          <text x="0" y="195" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">ORGANIZATION DOMAIN</text>
          <rect y="203" width="625" height="38" rx="8" fill="#0f172a" stroke="#334155" stroke-width="1" />
          <text x="15" y="227" fill="#f8fafc" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13">corp.onmicrosoft.com</text>

          <!-- RSA Key Card with Encryption Status -->
          <text x="0" y="260" fill="#94a3b8" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11" font-weight="700">RSA PRIVATE KEY STATUS</text>
          <rect y="268" width="625" height="90" rx="8" fill="#020617" stroke="#10b981" stroke-width="1.5" />
          <circle cx="25" cy="295" r="10" fill="#065f46" />
          <text x="21" y="300" fill="#34d399" font-size="13" font-weight="800">✓</text>
          <text x="45" y="300" fill="#34d399" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="700">Active RSA Private Key Loaded (2048-bit)</text>
          <text x="45" y="322" fill="#cbd5e1" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="12">Key File: eop-cert-private.key  |  Passphrase: <tspan fill="#38bdf8">AES-256-GCM Encrypted in DB</tspan></text>
          <text x="45" y="342" fill="#64748b" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="11">Last updated: 2026-09-28 08:00:12 by smccloud</text>

          <rect y="380" width="260" height="40" rx="8" fill="#7e22ce" />
          <text x="35" y="405" fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="700">Upload New Private Key (.pem)</text>

          <rect x="280" y="380" width="200" height="40" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1" />
          <text x="315" y="405" fill="#cbd5e1" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="13" font-weight="600">Test M365 Auth</text>
        </g>
      </g>
    </g>
  </svg>`;
}

// Generate all images
const screenshots = [
  { name: 'dashboard-dark', svgFn: generateDashboardSvg },
  { name: 'smart-sorter-modal', svgFn: generateSmartSorterSvg },
  { name: 'setup-wizard', svgFn: generateSetupWizardSvg },
  { name: 'push-summary-modal', svgFn: generatePushSummarySvg },
  { name: 'config-center', svgFn: generateConfigCenterSvg },
];

console.log('Rendering screenshots...');
for (const s of screenshots) {
  const svg = s.svgFn();
  const resvg = new Resvg(svg, {
    fitTo: { mode: 'width', value: 1440 },
  });
  const pngBuffer = resvg.render().asPng();

  outDirs.forEach((dir) => {
    fs.writeFileSync(path.join(dir, `${s.name}.svg`), svg, 'utf-8');
    fs.writeFileSync(path.join(dir, `${s.name}.png`), pngBuffer);
    console.log(`Saved: ${dir}/${s.name}.png & .svg (${pngBuffer.length} bytes)`);
  });
}

console.log('All screenshots rendered successfully!');
