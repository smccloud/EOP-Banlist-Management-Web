import React, { useState } from 'react';
import { AppConfig } from '../types';
import { Database, Shield, Sliders, RefreshCw, Key, CheckCircle2, Lock, Radio, ArrowRight, Eye, EyeOff, Server, Globe, Terminal, FileKey, Copy, ChevronDown, ChevronUp, Check, Upload, X, FileCheck } from 'lucide-react';
import { defaultAppConfig } from '../data/phpFiles';

interface ConfigGeneratorProps {
  config: AppConfig;
  setConfig: React.Dispatch<React.SetStateAction<AppConfig>>;
  onOpenConfigPage?: () => void;
}

export const ConfigGenerator: React.FC<ConfigGeneratorProps> = ({ config, setConfig, onOpenConfigPage }) => {
  const [showConfigBindPass, setShowConfigBindPass] = useState(false);
  const [showConfigCertDirections, setShowConfigCertDirections] = useState(false);
  const [configCertTab, setConfigCertTab] = useState<'openssl' | 'powershell'>('openssl');
  const [copiedConfigCertCmd, setCopiedConfigCertCmd] = useState(false);
  const [uploadedKeyName, setUploadedKeyName] = useState<string | null>(null);
  const configKeyInputRef = React.useRef<HTMLInputElement>(null);

  const handleKeyFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      if (text) {
        handleChange('privateKeyPem', text.trim());
        setUploadedKeyName(`${file.name} (${file.size < 1024 ? `${file.size} B` : `${(file.size / 1024).toFixed(1)} KB`})`);
      }
    };
    reader.readAsText(file);
  };

  const handleChange = (field: keyof AppConfig, value: any) => {
    setConfig((prev) => ({
      ...prev,
      [field]: value,
    }));
  };

  const handleProtocolChange = (protocol: 'ldap' | 'ldaps' | 'starttls') => {
    setConfig((prev) => ({
      ...prev,
      ldapProtocol: protocol,
      ldapPort: protocol === 'ldaps' ? 636 : 389,
      ldapUseSsl: protocol === 'ldaps',
      ldapUseTls: protocol === 'starttls',
    }));
  };

  const handleReset = () => {
    setConfig(defaultAppConfig);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 transition-colors duration-200">
      {/* Banner linking to the interactive Configuration Page */}
      {onOpenConfigPage && (
        <div className="mb-6 p-4 rounded-2xl border border-indigo-200 dark:border-indigo-900/60 bg-indigo-50/80 dark:bg-indigo-950/40 flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-xs shadow-xs">
          <div className="flex items-start sm:items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-indigo-600 text-white flex items-center justify-center shrink-0 shadow-xs">
              <Key className="w-5 h-5" />
            </div>
            <div>
              <div className="font-bold text-sm text-indigo-950 dark:text-indigo-200">
                Looking for the Live Configuration Page?
              </div>
              <div className="text-indigo-800/90 dark:text-indigo-300/90 mt-0.5 leading-relaxed">
                Upload your private key, decrypt passphrases with AES-256-GCM, and modify Active Directory LDAP connection parameters stored in MariaDB tables.
              </div>
            </div>
          </div>
          <button
            type="button"
            onClick={onOpenConfigPage}
            className="px-4 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-xl shadow-xs whitespace-nowrap transition flex items-center justify-center space-x-2 shrink-0 cursor-pointer"
          >
            <span>Open Configuration Page</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Title & info */}
      <div className="mb-6 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-slate-900 dark:text-white tracking-tight">Setup Parameters Generator</h2>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
            Customize initial parameters for Debian NGINX server blocks, remote MariaDB database credentials, and defaults.
            Standard LDAP (port 389) is supported without requiring LDAPS.
          </p>
        </div>
        <button
          onClick={handleReset}
          className="flex items-center space-x-1.5 px-3.5 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 rounded-lg text-xs font-semibold transition self-start md:self-auto border border-slate-200 dark:border-slate-700 cursor-pointer"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Reset to Defaults</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Section 1: Remote MariaDB Database */}
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm p-6 transition-colors duration-200">
          <div className="flex items-center space-x-3 pb-4 mb-4 border-b border-slate-100 dark:border-slate-800">
            <div className="w-9 h-9 rounded-xl bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 flex items-center justify-center">
              <Database className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white">Remote MariaDB Server</h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">4 individual tables per list stored on remote host</p>
            </div>
          </div>

          <div className="space-y-4 text-xs">
            <div className="grid grid-cols-3 gap-3">
              <div className="col-span-2">
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">MariaDB Server Host / IP</label>
                <input
                  type="text"
                  value={config.dbHost}
                  onChange={(e) => handleChange('dbHost', e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                  placeholder="192.168.10.50 or db.internal.corp"
                />
              </div>
              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Port</label>
                <input
                  type="number"
                  value={config.dbPort}
                  onChange={(e) => handleChange('dbPort', parseInt(e.target.value) || 3306)}
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                  placeholder="3306"
                />
              </div>
            </div>

            <div>
              <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Database Name</label>
              <input
                type="text"
                value={config.dbName}
                onChange={(e) => handleChange('dbName', e.target.value)}
                className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                placeholder="eop_antispam_db"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Database User</label>
                <input
                  type="text"
                  value={config.dbUser}
                  onChange={(e) => handleChange('dbUser', e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                  placeholder="eop_app_user"
                />
              </div>
              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Database Password</label>
                <input
                  type="password"
                  value={config.dbPass}
                  onChange={(e) => handleChange('dbPass', e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                  placeholder="••••••••••••"
                />
              </div>
            </div>

            <div className="p-3 bg-blue-50/60 dark:bg-blue-950/40 rounded-xl border border-blue-100 dark:border-blue-800/60 text-[11px] text-blue-800 dark:text-blue-300">
              <span className="font-semibold block mb-0.5">Separate Tables Provisioned:</span>
              <ul className="list-disc list-inside space-y-0.5 text-blue-700 dark:text-blue-400 font-mono text-[10px]">
                <li><code>eop_allowed_senders</code></li>
                <li><code>eop_blocked_senders</code></li>
                <li><code>eop_allowed_domains</code></li>
                <li><code>eop_blocked_domains</code></li>
              </ul>
            </div>
          </div>
        </div>

        {/* Section 2: Active Directory LDAP Authentication */}
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm p-6 transition-colors duration-200">
          <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-100 dark:border-slate-800">
            <div className="flex items-center space-x-3">
              <div className="w-9 h-9 rounded-xl bg-emerald-50 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400 flex items-center justify-center">
                <Shield className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-white">Active Directory LDAP Authentication</h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">Standard LDAP (port 389) supported &bull; LDAPS not required</p>
              </div>
            </div>
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-purple-100 dark:bg-purple-950/60 text-purple-700 dark:text-purple-300 font-mono font-medium hidden sm:inline-block">
              DB Table: eop_ldap_config
            </span>
          </div>

          <div className="space-y-4 text-xs">
            {/* Protocol Selector */}
            <div>
              <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                LDAP Protocol Mode:
              </label>
              <div className="grid grid-cols-3 gap-2">
                <button
                  type="button"
                  onClick={() => handleProtocolChange('ldap')}
                  className={`p-2.5 rounded-lg border text-left transition ${
                    (config.ldapProtocol === 'ldap' || (!config.ldapProtocol && !config.ldapUseSsl))
                      ? 'border-emerald-500 bg-emerald-50 dark:bg-emerald-950/50 text-emerald-900 dark:text-emerald-200 ring-2 ring-emerald-500/20'
                      : 'border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:border-slate-300 dark:hover:border-slate-600'
                  }`}
                >
                  <div className="font-bold flex items-center space-x-1.5 text-xs">
                    <span>Plain LDAP</span>
                    <span className="text-[10px] px-1 py-0.2 rounded bg-emerald-200 dark:bg-emerald-800 text-emerald-800 dark:text-emerald-100 font-normal">Port 389</span>
                  </div>
                  <div className="text-[10px] text-slate-500 dark:text-slate-400 mt-1 leading-tight">
                    Standard &bull; No LDAPS / No SSL certs needed
                  </div>
                </button>

                <button
                  type="button"
                  onClick={() => handleProtocolChange('ldaps')}
                  className={`p-2.5 rounded-lg border text-left transition ${
                    config.ldapProtocol === 'ldaps'
                      ? 'border-blue-500 bg-blue-50 dark:bg-blue-950/50 text-blue-900 dark:text-blue-200 ring-2 ring-blue-500/20'
                      : 'border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:border-slate-300 dark:hover:border-slate-600'
                  }`}
                >
                  <div className="font-bold flex items-center space-x-1.5 text-xs">
                    <span>LDAPS (SSL)</span>
                    <span className="text-[10px] px-1 py-0.2 rounded bg-blue-200 dark:bg-blue-800 text-blue-800 dark:text-blue-100 font-normal">Port 636</span>
                  </div>
                  <div className="text-[10px] text-slate-500 dark:text-slate-400 mt-1 leading-tight">
                    Encrypted SSL connection
                  </div>
                </button>

                <button
                  type="button"
                  onClick={() => handleProtocolChange('starttls')}
                  className={`p-2.5 rounded-lg border text-left transition ${
                    config.ldapProtocol === 'starttls'
                      ? 'border-purple-500 bg-purple-50 dark:bg-purple-950/50 text-purple-900 dark:text-purple-200 ring-2 ring-purple-500/20'
                      : 'border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:border-slate-300 dark:hover:border-slate-600'
                  }`}
                >
                  <div className="font-bold flex items-center space-x-1.5 text-xs">
                    <span>StartTLS</span>
                    <span className="text-[10px] px-1 py-0.2 rounded bg-purple-200 dark:bg-purple-800 text-purple-800 dark:text-purple-100 font-normal">Port 389</span>
                  </div>
                  <div className="text-[10px] text-slate-500 dark:text-slate-400 mt-1 leading-tight">
                    Upgrade plain port 389 to TLS
                  </div>
                </button>
              </div>
            </div>

            {/* Note banner when plain LDAP is selected */}
            {(config.ldapProtocol === 'ldap' || (!config.ldapProtocol && !config.ldapUseSsl)) && (
              <div className="p-3 bg-emerald-50/70 dark:bg-emerald-950/40 rounded-xl border border-emerald-200 dark:border-emerald-800/60 text-[11px] text-emerald-800 dark:text-emerald-300 flex items-start space-x-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <span className="font-semibold block">Plain LDAP (Port 389) Active &bull; No LDAPS Required</span>
                  Connecting via standard LDAP to your Windows Domain Controller on port 389. No enterprise CA certificates or SSL handshake configurations are required on Debian.
                </div>
              </div>
            )}

            <div className="grid grid-cols-3 gap-3">
              <div className="col-span-2">
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Domain Controller FQDN</label>
                <input
                  type="text"
                  value={config.ldapHost}
                  onChange={(e) => handleChange('ldapHost', e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                  placeholder="dc01.corp.example.com"
                />
              </div>
              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">LDAP Port</label>
                <input
                  type="number"
                  value={config.ldapPort}
                  onChange={(e) => handleChange('ldapPort', parseInt(e.target.value) || 389)}
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                  placeholder="389"
                />
              </div>
            </div>

            <div>
              <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                Authorized Group Distinguished Name (Group DN) <span className="text-rose-500">*</span>
              </label>
              <textarea
                rows={2}
                value={config.ldapGroupDn}
                onChange={(e) => handleChange('ldapGroupDn', e.target.value)}
                className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono text-[11px] focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                placeholder="CN=Exchange-Admins,OU=Security Groups,DC=corp,DC=example,DC=com"
              />
              <span className="text-[10px] text-slate-500 dark:text-slate-400">
                Only users who belong to this exact group (direct or nested) can log in.
              </span>
            </div>

            <div>
              <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Active Directory Base DN</label>
              <input
                type="text"
                value={config.ldapBaseDn}
                onChange={(e) => handleChange('ldapBaseDn', e.target.value)}
                className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono text-[11px] focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                placeholder="DC=corp,DC=example,DC=com"
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Service Account Bind DN (Optional)</label>
                <input
                  type="text"
                  value={config.ldapBindDn}
                  onChange={(e) => handleChange('ldapBindDn', e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono text-[11px] focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                  placeholder="CN=svc-eop,OU=Service Accounts,DC=corp..."
                />
                <p className="text-[10px] text-slate-400 mt-1">Service account DN for querying Active Directory</p>
              </div>
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="block font-semibold text-slate-700 dark:text-slate-300">Bind Password for LDAP Authorization</label>
                  <button
                    type="button"
                    onClick={() => setShowConfigBindPass(!showConfigBindPass)}
                    className="text-[10px] text-blue-600 dark:text-blue-400 hover:underline flex items-center gap-1 cursor-pointer"
                  >
                    {showConfigBindPass ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                    <span>{showConfigBindPass ? 'Hide' : 'Show'}</span>
                  </button>
                </div>
                <input
                  type={showConfigBindPass ? 'text' : 'password'}
                  value={config.ldapBindPass}
                  onChange={(e) => handleChange('ldapBindPass', e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono text-[11px] focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                  placeholder="••••••••••••"
                />
                <p className="text-[10px] text-slate-400 mt-1">Active Directory service account password for LDAP authorization</p>
              </div>
            </div>
          </div>
        </div>

        {/* Section 3: EOP Anti-Spam Policy Settings */}
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm p-6 transition-colors duration-200">
          <div className="flex items-center space-x-3 pb-4 mb-4 border-b border-slate-100 dark:border-slate-800">
            <div className="w-9 h-9 rounded-xl bg-purple-50 dark:bg-purple-950/60 text-purple-600 dark:text-purple-400 flex items-center justify-center">
              <Sliders className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white">Exchange Online Anti-Spam Policy</h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">Target policy name in Microsoft 365 EOP</p>
            </div>
          </div>

          <div className="space-y-4 text-xs">
            <div>
              <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                Default Anti-Spam Policy Name <span className="text-rose-500">*</span>
              </label>
              <input
                type="text"
                value={config.defaultPolicyName}
                onChange={(e) => handleChange('defaultPolicyName', e.target.value)}
                className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-medium focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                placeholder="Default or Strict Anti-Spam Policy"
              />
              <span className="text-[10px] text-slate-500 dark:text-slate-400">
                Matches <code>-Identity "&lt;PolicyName&gt;"</code> in Exchange PowerShell <code>Set-HostedContentFilterPolicy</code>.
              </span>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">App Title</label>
                <input
                  type="text"
                  value={config.appTitle}
                  onChange={(e) => handleChange('appTitle', e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                />
              </div>
              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Debian Host FQDN / URL</label>
                <input
                  type="text"
                  value={config.appUrl}
                  onChange={(e) => handleChange('appUrl', e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                  placeholder="https://eop.corp.example.com"
                />
              </div>
            </div>

            <div>
              <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Session Inactivity Timeout (Minutes)</label>
              <input
                type="number"
                value={config.sessionTimeoutMinutes}
                onChange={(e) => handleChange('sessionTimeoutMinutes', parseInt(e.target.value) || 60)}
                className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                placeholder="60"
              />
            </div>

            {/* Server Hosting Option: Only site on server vs Shared Multi-site */}
            <div className="pt-3 border-t border-slate-100 dark:border-slate-800">
              <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1.5 flex items-center justify-between">
                <span className="flex items-center gap-1.5">
                  <Server className="w-3.5 h-3.5 text-blue-500" />
                  <span>Server Hosting Option (NGINX Server Block)</span>
                </span>
                <span className={`text-[10px] px-2 py-0.5 rounded-full font-mono font-bold ${
                  config.isOnlySiteOnServer !== false
                    ? 'bg-blue-100 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300'
                    : 'bg-amber-100 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300'
                }`}>
                  {config.isOnlySiteOnServer !== false ? 'DEDICATED / ONLY SITE' : 'SHARED MULTI-SITE'}
                </span>
              </label>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <button
                  type="button"
                  onClick={() => handleChange('isOnlySiteOnServer', true)}
                  className={`p-3 rounded-xl border text-left transition cursor-pointer flex flex-col justify-between ${
                    config.isOnlySiteOnServer !== false
                      ? 'border-blue-500 bg-blue-50/70 dark:bg-blue-950/40 text-blue-950 dark:text-blue-100 shadow-xs ring-1 ring-blue-500'
                      : 'border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40 text-slate-600 dark:text-slate-400 hover:border-slate-300 dark:hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-bold text-xs flex items-center gap-1.5">
                      <span className={`w-2 h-2 rounded-full ${config.isOnlySiteOnServer !== false ? 'bg-blue-500' : 'bg-slate-300 dark:bg-slate-600'}`}></span>
                      Only Site on this Server
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-200/80 dark:bg-blue-900/60 text-blue-800 dark:text-blue-200 font-mono">
                      default_server
                    </span>
                  </div>
                  <p className="text-[11px] leading-relaxed opacity-90">
                    Makes this application the default catch-all on ports 80/443. Any inbound traffic to the server IP or domain routes here. Default Debian site is removed.
                  </p>
                </button>

                <button
                  type="button"
                  onClick={() => handleChange('isOnlySiteOnServer', false)}
                  className={`p-3 rounded-xl border text-left transition cursor-pointer flex flex-col justify-between ${
                    config.isOnlySiteOnServer === false
                      ? 'border-amber-500 bg-amber-50/70 dark:bg-amber-950/40 text-amber-950 dark:text-amber-100 shadow-xs ring-1 ring-amber-500'
                      : 'border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40 text-slate-600 dark:text-slate-400 hover:border-slate-300 dark:hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-bold text-xs flex items-center gap-1.5">
                      <span className={`w-2 h-2 rounded-full ${config.isOnlySiteOnServer === false ? 'bg-amber-500' : 'bg-slate-300 dark:bg-slate-600'}`}></span>
                      Shared Multi-Site Server
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-200/80 dark:bg-amber-900/60 text-amber-800 dark:text-amber-200 font-mono">
                      domain-only
                    </span>
                  </div>
                  <p className="text-[11px] leading-relaxed opacity-90">
                    NGINX strictly matches the configured FQDN. Coexists safely with other websites and virtual hosts on the same Debian server without intercepting other traffic.
                  </p>
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Section 4: Microsoft 365 Azure App Registration & Certificate Auth */}
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm p-6 transition-colors duration-200">
          <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-100 dark:border-slate-800">
            <div className="flex items-center space-x-3">
              <div className="w-9 h-9 rounded-xl bg-amber-50 dark:bg-amber-950/60 text-amber-600 dark:text-amber-400 flex items-center justify-center">
                <Key className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-white">Exchange Online Certificate &amp; Private Key Auth</h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">Private key and AES-256 encrypted password stored in database</p>
              </div>
            </div>
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-indigo-100 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-300 font-mono font-medium hidden sm:inline-block">
              DB Table: eop_auth_config
            </span>
          </div>

          <div className="space-y-4 text-xs">
            {/* Certificate Generation Directions */}
            <div className="rounded-xl border border-amber-200 dark:border-amber-800/80 bg-amber-50/50 dark:bg-amber-950/20 overflow-hidden">
              <button
                type="button"
                className="w-full p-3.5 flex items-center justify-between text-left cursor-pointer hover:bg-amber-100/40 dark:hover:bg-amber-950/40 transition"
                onClick={() => setShowConfigCertDirections(!showConfigCertDirections)}
              >
                <div className="flex items-center space-x-2.5">
                  <div className="p-1 rounded-md bg-amber-100 dark:bg-amber-900/60 text-amber-700 dark:text-amber-300">
                    <FileKey className="w-4 h-4" />
                  </div>
                  <div>
                    <span className="font-bold text-amber-950 dark:text-amber-200 block text-xs">
                      Need a certificate? Directions for Generating Certificate &amp; Thumbprint
                    </span>
                    <span className="text-[10px] text-amber-800/70 dark:text-amber-300/70">
                      Copy-paste commands for Linux (OpenSSL) or Windows (PowerShell)
                    </span>
                  </div>
                </div>
                <div className="flex items-center space-x-1 text-amber-700 dark:text-amber-300 text-[11px] font-semibold">
                  <span>{showConfigCertDirections ? 'Hide' : 'Show Directions'}</span>
                  {showConfigCertDirections ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                </div>
              </button>

              {showConfigCertDirections && (
                <div className="p-3.5 pt-0 border-t border-amber-200/70 dark:border-amber-800/60 space-y-3">
                  <div className="flex items-center space-x-2 pt-2.5">
                    <button
                      type="button"
                      onClick={() => setConfigCertTab('openssl')}
                      className={`px-2.5 py-1 rounded-md text-[11px] font-semibold transition cursor-pointer flex items-center gap-1 ${
                        configCertTab === 'openssl'
                          ? 'bg-amber-600 text-white'
                          : 'bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700'
                      }`}
                    >
                      <Terminal className="w-3 h-3" />
                      <span>Linux OpenSSL</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setConfigCertTab('powershell')}
                      className={`px-2.5 py-1 rounded-md text-[11px] font-semibold transition cursor-pointer flex items-center gap-1 ${
                        configCertTab === 'powershell'
                          ? 'bg-amber-600 text-white'
                          : 'bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700'
                      }`}
                    >
                      <Terminal className="w-3 h-3" />
                      <span>Windows PowerShell</span>
                    </button>
                  </div>

                  {configCertTab === 'openssl' ? (
                    <div className="relative">
                      <pre className="p-3 bg-slate-900 text-slate-100 rounded-lg font-mono text-[10px] overflow-x-auto leading-relaxed">
{`# 1. Generate RSA 2048-bit key with passphrase:
openssl genrsa -aes256 -passout pass:"${config.keyPassword || 'YourPassphrase'}" -out eop-cert-private.key 2048

# 2. Generate self-signed public certificate (valid 2 years):
openssl req -new -x509 -key eop-cert-private.key -passin pass:"${config.keyPassword || 'YourPassphrase'}" \\
  -days 730 -out eop-cert-public.crt \\
  -subj "/CN=EOP Anti-Spam Policy Manager/O=${config.organization || 'YourOrg'}"

# 3. Print SHA-1 Thumbprint:
openssl x509 -in eop-cert-public.crt -noout -fingerprint -sha1 | tr -d ':' | sed 's/SHA1 Fingerprint=//'`}
                      </pre>
                      <button
                        type="button"
                        onClick={() => {
                          const cmd = `# 1. Generate RSA 2048-bit key with passphrase:\nopenssl genrsa -aes256 -passout pass:"${config.keyPassword || 'YourPassphrase'}" -out eop-cert-private.key 2048\n\n# 2. Generate self-signed public certificate (valid 2 years):\nopenssl req -new -x509 -key eop-cert-private.key -passin pass:"${config.keyPassword || 'YourPassphrase'}" \\\n  -days 730 -out eop-cert-public.crt \\\n  -subj "/CN=EOP Anti-Spam Policy Manager/O=${config.organization || 'YourOrg'}"\n\n# 3. Print SHA-1 Thumbprint:\nopenssl x509 -in eop-cert-public.crt -noout -fingerprint -sha1 | tr -d ':' | sed 's/SHA1 Fingerprint=//'`;
                          navigator.clipboard.writeText(cmd);
                          setCopiedConfigCertCmd(true);
                          setTimeout(() => setCopiedConfigCertCmd(false), 2000);
                        }}
                        className="absolute top-2 right-2 px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[10px] font-semibold flex items-center gap-1 border border-slate-700 cursor-pointer"
                      >
                        {copiedConfigCertCmd ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedConfigCertCmd ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                  ) : (
                    <div className="relative">
                      <pre className="p-3 bg-slate-900 text-slate-100 rounded-lg font-mono text-[10px] overflow-x-auto leading-relaxed">
{`# 1. Create certificate in Windows personal cert store:
$cert = New-SelfSignedCertificate -CertStoreLocation "Cert:\\CurrentUser\\My" \`
  -Subject "CN=EOP Anti-Spam Policy Manager" -KeySpec Signature -KeyLength 2048 \`
  -KeyExportPolicy Exportable -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(2)

# 2. Export public certificate (.cer) for Microsoft Entra upload:
Export-Certificate -Cert $cert -FilePath ".\\eop-cert-public.cer"

# 3. Output SHA-1 Thumbprint:
$cert.Thumbprint`}
                      </pre>
                      <button
                        type="button"
                        onClick={() => {
                          const cmd = `# 1. Create certificate in Windows personal cert store:\n$cert = New-SelfSignedCertificate -CertStoreLocation "Cert:\\CurrentUser\\My" \\\n  -Subject "CN=EOP Anti-Spam Policy Manager" -KeySpec Signature -KeyLength 2048 \\\n  -KeyExportPolicy Exportable -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(2)\n\n# 2. Export public certificate (.cer) for Microsoft Entra upload:\nExport-Certificate -Cert $cert -FilePath ".\\eop-cert-public.cer"\n\n# 3. Output SHA-1 Thumbprint:\n$cert.Thumbprint`;
                          navigator.clipboard.writeText(cmd);
                          setCopiedConfigCertCmd(true);
                          setTimeout(() => setCopiedConfigCertCmd(false), 2000);
                        }}
                        className="absolute top-2 right-2 px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[10px] font-semibold flex items-center gap-1 border border-slate-700 cursor-pointer"
                      >
                        {copiedConfigCertCmd ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedConfigCertCmd ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Azure AD Tenant ID</label>
                <input
                  type="text"
                  value={config.tenantId}
                  onChange={(e) => handleChange('tenantId', e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono text-[11px] focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                  placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Application (Client) ID</label>
                <input
                  type="text"
                  value={config.clientId}
                  onChange={(e) => handleChange('clientId', e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono text-[11px] focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                  placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Certificate Thumbprint (SHA-1)</label>
                <input
                  type="text"
                  value={config.certificateThumbprint || ''}
                  onChange={(e) => handleChange('certificateThumbprint', e.target.value.toUpperCase())}
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono text-[11px] focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                  placeholder="9A2F8B3C1D4E5F6A7B8C9D0E1F2A3B4C5D6E7F80"
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Private Key Passphrase (Encrypted in DB)
                </label>
                <input
                  type="password"
                  value={config.keyPassword || ''}
                  onChange={(e) => handleChange('keyPassword', e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono text-[11px] focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                  placeholder="••••••••••••••••••••••••"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <label className="block font-semibold text-slate-700 dark:text-slate-300">
                  RSA Certificate Private Key (PEM format)
                </label>
                <div className="flex items-center gap-2">
                  <input
                    type="file"
                    ref={configKeyInputRef}
                    accept=".pem,.key,.crt,.txt"
                    className="hidden"
                    onChange={handleKeyFileUpload}
                  />
                  <button
                    type="button"
                    onClick={() => configKeyInputRef.current?.click()}
                    className="px-2.5 py-1 rounded-md bg-amber-600 hover:bg-amber-500 text-white text-[11px] font-semibold transition flex items-center gap-1.5 cursor-pointer shadow-xs"
                  >
                    <Upload className="w-3 h-3" />
                    <span>Upload Private Key File (.pem, .key)</span>
                  </button>
                  {uploadedKeyName && (
                    <button
                      type="button"
                      onClick={() => {
                        setUploadedKeyName(null);
                        if (configKeyInputRef.current) configKeyInputRef.current.value = '';
                      }}
                      className="p-1 rounded text-slate-400 hover:text-rose-500 text-xs transition cursor-pointer"
                      title="Clear uploaded file"
                    >
                      <X className="w-3 h-3" />
                    </button>
                  )}
                </div>
              </div>

              {uploadedKeyName && (
                <div className="p-2 rounded-lg bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800 text-emerald-800 dark:text-emerald-200 text-[11px] flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <FileCheck className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 shrink-0" />
                    <span>Loaded from file: <strong className="font-mono">{uploadedKeyName}</strong></span>
                  </div>
                  <span className="text-[10px] font-mono bg-emerald-100 dark:bg-emerald-900/60 px-1.5 py-0.5 rounded text-emerald-700 dark:text-emerald-300 font-semibold">
                    PEM Parsed
                  </span>
                </div>
              )}

              <textarea
                rows={3}
                value={config.privateKeyPem || ''}
                onChange={(e) => {
                  handleChange('privateKeyPem', e.target.value);
                  if (uploadedKeyName) setUploadedKeyName(null);
                }}
                placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...&#10;-----END RSA PRIVATE KEY-----"
                className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg p-2.5 text-slate-900 dark:text-white font-mono text-[10px] focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
              />
            </div>

            <div className="p-3 bg-indigo-50/70 dark:bg-indigo-950/40 rounded-xl border border-indigo-100 dark:border-indigo-800/60 text-[11px] text-indigo-900 dark:text-indigo-200 space-y-1">
              <div className="font-semibold flex items-center gap-1.5 text-indigo-950 dark:text-indigo-100">
                <CheckCircle2 className="w-4 h-4 text-indigo-600 dark:text-indigo-400 shrink-0" />
                <span>Database-Backed Key Storage (Table: <code>eop_auth_config</code>)</span>
              </div>
              <p className="text-indigo-800/90 dark:text-indigo-300/90 leading-relaxed text-[11px]">
                Users can upload the private key and modify LDAP settings anytime on the Configuration page. Passphrases are securely encrypted with AES-256-GCM before writing to MariaDB.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
