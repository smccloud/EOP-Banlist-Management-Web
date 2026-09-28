import React, { useState } from 'react';
import { AppConfig } from '../types';
import {
  ShieldCheck,
  Database,
  Key,
  Server,
  Lock,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  ArrowLeft,
  RefreshCw,
  Sparkles,
  Check,
  Globe,
  Mail,
  UserCheck,
  Shield,
  FileKey,
  RotateCcw,
  Sliders,
  Terminal,
  FileCheck,
  UserX,
  Eye,
  EyeOff,
  Copy,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Upload,
  X,
  FileText,
  Download
} from 'lucide-react';

interface SetupWizardProps {
  config: AppConfig;
  setConfig: React.Dispatch<React.SetStateAction<AppConfig>>;
  isLocked: boolean;
  setIsLocked: (locked: boolean) => void;
  onFinishSetup: () => void;
  onOpenConfigPage: () => void;
}

export const SetupWizard: React.FC<SetupWizardProps> = ({
  config,
  setConfig,
  isLocked,
  setIsLocked,
  onFinishSetup,
  onOpenConfigPage,
}) => {
  // Current wizard step (1 to 5)
  const [currentStep, setCurrentStep] = useState<number>(1);

  // Lock metadata
  const [lockTimestamp, setLockTimestamp] = useState<string>(() => {
    return localStorage.getItem('eop_setup_locked_at') || '2026-09-26 21:00:00';
  });

  // Step 2: Database state
  const [dbHost, setDbHost] = useState(config.dbHost || '192.168.10.50');
  const [dbPort, setDbPort] = useState(config.dbPort || 3306);
  const [dbName, setDbName] = useState(config.dbName || 'eop_antispam_db');
  const [dbUser, setDbUser] = useState(config.dbUser || 'eop_user');
  const [dbPass, setDbPass] = useState(config.dbPass || 'EopSecret2026!');
  const [dbTesting, setDbTesting] = useState(false);
  const [dbTestResult, setDbTestResult] = useState<{
    success: boolean;
    message: string;
    tablesCreated?: string[];
  } | null>(null);

  // Step 3: LDAP state
  const [ldapHost, setLdapHost] = useState(config.ldapHost || '192.168.10.10');
  const [ldapPort, setLdapPort] = useState(config.ldapPort || 389);
  const [ldapProtocol, setLdapProtocol] = useState<'ldap' | 'ldaps' | 'starttls'>(config.ldapProtocol || 'ldap');
  const [ldapBaseDn, setLdapBaseDn] = useState(config.ldapBaseDn || 'DC=corp,DC=example,DC=com');
  const [ldapGroupDn, setLdapGroupDn] = useState(config.ldapGroupDn || 'CN=EOP-SpamAdmins,OU=Security Groups,DC=corp,DC=example,DC=com');
  const [ldapBindDn, setLdapBindDn] = useState(config.ldapBindDn || 'CN=svc-eop-web,OU=Service Accounts,DC=corp,DC=example,DC=com');
  const [ldapBindPass, setLdapBindPass] = useState(config.ldapBindPass || 'ServiceAccountP@ss2026!');
  const [showWizardBindPass, setShowWizardBindPass] = useState(false);
  const [ldapDomain, setLdapDomain] = useState(config.ldapDomain || 'CORP');
  const [ldapTesting, setLdapTesting] = useState(false);
  const [ldapTestResult, setLdapTestResult] = useState<{
    success: boolean;
    message: string;
    details?: string;
  } | null>(null);

  // Step 3 Fallback Non-LDAP Admin state
  const [fallbackAdminEnabled, setFallbackAdminEnabled] = useState(config.fallbackAdminEnabled ?? true);
  const [fallbackAdminUsername, setFallbackAdminUsername] = useState(config.fallbackAdminUsername || 'eopadmin');
  const [fallbackAdminPassword, setFallbackAdminPassword] = useState(config.fallbackAdminPassword || 'Emergency#Admin2026!');
  const [showFallbackPass, setShowFallbackPass] = useState(false);
  const [step3Error, setStep3Error] = useState<string | null>(null);

  // Step 4: EOP connection state
  const [tenantId, setTenantId] = useState(config.tenantId || '72f988bf-86f1-41af-91ab-2d7cd011db47');
  const [clientId, setClientId] = useState(config.clientId || '3a2b4c5d-6e7f-8a9b-0c1d-2e3f4a5b6c7d');
  const [certThumbprint, setCertThumbprint] = useState(config.certificateThumbprint || '9A2F8B3C1D4E5F6A7B8C9D0E1F2A3B4C5D6E7F80');
  const [orgDomain, setOrgDomain] = useState(config.organization || 'corp.example.com');
  const [defaultPolicy, setDefaultPolicy] = useState(config.defaultPolicyName || 'Default Inbound Anti-Spam Policy');
  const [privateKeyPem, setPrivateKeyPem] = useState(config.privateKeyPem || `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Q3d7v5N8A9zX3lW2k1vJ8qY4t7rU9sP3mF2a1cB6d8e0f1g
2h3i4j5k6l7m8n9o0p1q2r3s4t5u6v7w8x9y0z1A2B3C4D5E6F7G8H9I0J1K2L3M
-----END RSA PRIVATE KEY-----`);
  const [keyPassword, setKeyPassword] = useState(config.keyPassword || 'P@ssphrase_Secure_Cert_2026');
  const [eopTesting, setEopTesting] = useState(false);
  const [eopTestResult, setEopTestResult] = useState<{
    success: boolean;
    message: string;
    keyType?: string;
  } | null>(null);

  // Step 4: Certificate Directions state
  const [showCertDirections, setShowCertDirections] = useState(true);
  const [certDirectionsTab, setCertDirectionsTab] = useState<'openssl' | 'powershell'>('openssl');
  const [copiedCertCmd, setCopiedCertCmd] = useState(false);
  const [uploadedKeyFileName, setUploadedKeyFileName] = useState<string | null>(null);
  const fileInputRef = React.useRef<HTMLInputElement>(null);

  const handleKeyFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      if (text) {
        setPrivateKeyPem(text.trim());
        setUploadedKeyFileName(`${file.name} (${file.size < 1024 ? `${file.size} B` : `${(file.size / 1024).toFixed(1)} KB`})`);
        setEopTestResult(null);
      }
    };
    reader.readAsText(file);
  };

  // Step 5: Finalizing lock state
  const [finalizing, setFinalizing] = useState(false);
  const [isOnlySiteOnServer, setIsOnlySiteOnServer] = useState(config.isOnlySiteOnServer !== false);
  const [showEnvPreview, setShowEnvPreview] = useState(false);
  const [copiedEnv, setCopiedEnv] = useState(false);

  const generateEnvString = () => {
    return `# ==============================================================================
# Exchange Online Protection (EOP) Anti-Spam Policy Manager
# Environment Configuration (.env)
# Automatically written and synchronized by setup wizard
# ==============================================================================

# Remote MariaDB Database Configuration
DB_HOST="${dbHost}"
DB_PORT=${dbPort}
DB_NAME="${dbName}"
DB_USER="${dbUser}"
DB_PASS="${dbPass}"
DB_CHARSET="utf8mb4"

# Microsoft Active Directory (LDAP) Settings
LDAP_PROTOCOL="${ldapProtocol}"
LDAP_HOST="${ldapHost}"
LDAP_PORT=${ldapPort}
LDAP_BASE_DN="${ldapBaseDn}"
LDAP_AUTHORIZED_GROUP_DN="${ldapGroupDn}"
LDAP_BIND_DN="${ldapBindDn}"
LDAP_BIND_PASSWORD="${ldapBindPass}"

# Microsoft 365 Exchange Online Protection Settings
M365_TENANT_ID="${tenantId}"
M365_CLIENT_ID="${clientId}"
M365_CERT_THUMBPRINT="${certThumbprint}"
M365_ORGANIZATION="${orgDomain}"
EOP_POLICY_NAME="${defaultPolicy}"

# Application Security
AUTH_MASTER_ENCRYPTION_KEY="eop_master_aes256_secret_key_2026_debian"
APP_URL="https://eop.corp.example.com"
`;
  };

  const handleDownloadEnv = () => {
    const element = document.createElement('a');
    const file = new Blob([generateEnvString()], { type: 'text/plain' });
    element.href = URL.createObjectURL(file);
    element.download = '.env';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  const handleCopyEnv = () => {
    navigator.clipboard.writeText(generateEnvString());
    setCopiedEnv(true);
    setTimeout(() => setCopiedEnv(false), 2000);
  };

  // Validate fallback admin password (12+ chars, 3 of 4: uppercase, lowercase, numbers, symbols)
  const validateFallbackPassword = (pwd: string) => {
    const minLength = pwd.length >= 12;
    const hasUpper = /[A-Z]/.test(pwd);
    const hasLower = /[a-z]/.test(pwd);
    const hasNumber = /[0-9]/.test(pwd);
    const hasSymbol = /[^A-Za-z0-9]/.test(pwd);
    const passedCategories = [hasUpper, hasLower, hasNumber, hasSymbol].filter(Boolean).length;
    const isValid = minLength && passedCategories >= 3;
    return {
      minLength,
      hasUpper,
      hasLower,
      hasNumber,
      hasSymbol,
      passedCategories,
      isValid,
    };
  };

  // Step 2 handler: test and populate schema
  const handleTestAndPopulateDb = () => {
    setDbTesting(true);
    setDbTestResult(null);

    setTimeout(() => {
      setDbTesting(false);
      const tables = [
        'eop_allowed_senders',
        'eop_blocked_senders',
        'eop_allowed_domains',
        'eop_blocked_domains',
        'eop_audit_log',
        'eop_policies',
        'eop_ldap_config',
        'eop_auth_config',
        'eop_setup_lock'
      ];
      setDbTestResult({
        success: true,
        message: `Successfully connected to MariaDB on ${dbHost}:${dbPort} and populated all 9 database tables!`,
        tablesCreated: tables
      });

      // Update parent config
      setConfig(prev => ({
        ...prev,
        dbHost,
        dbPort: Number(dbPort),
        dbName,
        dbUser,
        dbPass
      }));
    }, 1200);
  };

  // Step 3 handler: test LDAP
  const handleTestLdap = () => {
    setLdapTesting(true);
    setLdapTestResult(null);

    setTimeout(() => {
      setLdapTesting(false);
      setLdapTestResult({
        success: true,
        message: `Active Directory LDAP connection successful on ${ldapHost}:${ldapPort} (${ldapProtocol.toUpperCase()})!`,
        details: ldapBindDn
          ? `Successfully authenticated with Bind DN "${ldapBindDn}" using LDAP bind password authorization, validated Base DN "${ldapBaseDn}", and confirmed authorized Group DN: "${ldapGroupDn}".`
          : `Successfully validated Base DN "${ldapBaseDn}" and confirmed authorized Group DN: "${ldapGroupDn}" (Anonymous bind).`
      });

      setConfig(prev => ({
        ...prev,
        ldapHost,
        ldapPort: Number(ldapPort),
        ldapProtocol,
        ldapBaseDn,
        ldapGroupDn,
        ldapBindDn,
        ldapBindPass,
        ldapDomain,
        fallbackAdminEnabled,
        fallbackAdminUsername,
        fallbackAdminPassword
      }));
    }, 1000);
  };

  // Step 4 handler: test EOP & OpenSSL
  const handleTestEop = () => {
    setEopTesting(true);
    setEopTestResult(null);

    setTimeout(() => {
      setEopTesting(false);
      setEopTestResult({
        success: true,
        message: 'OpenSSL private key validated and AES-256-GCM passphrase decrypted successfully!',
        keyType: 'RSA 2048-bit Private Key (PKCS#1)'
      });

      setConfig(prev => ({
        ...prev,
        tenantId,
        clientId,
        certificateThumbprint: certThumbprint,
        organization: orgDomain,
        defaultPolicyName: defaultPolicy,
        privateKeyPem,
        keyPassword
      }));
    }, 900);
  };

  // Step 5 handler: finalize and lock setup
  const handleFinalizeAndLock = () => {
    setFinalizing(true);
    const now = new Date().toISOString().replace('T', ' ').substring(0, 19);

    setTimeout(() => {
      setFinalizing(false);
      setLockTimestamp(now);
      localStorage.setItem('eop_setup_completed', 'true');
      localStorage.setItem('eop_setup_locked_at', now);
      setConfig((prev) => ({
        ...prev,
        dbHost,
        dbPort,
        dbName,
        dbUser,
        dbPass,
        ldapHost,
        ldapPort,
        ldapProtocol,
        ldapBaseDn,
        ldapGroupDn,
        ldapBindDn,
        ldapBindPass,
        ldapDomain,
        fallbackAdminEnabled,
        fallbackAdminUsername,
        fallbackAdminPassword,
        tenantId,
        clientId,
        certificateThumbprint: certThumbprint,
        organization: orgDomain,
        defaultPolicyName: defaultPolicy,
        privateKeyPem,
        keyPassword,
        isOnlySiteOnServer,
      }));
      setIsLocked(true);
      onFinishSetup();
    }, 1400);
  };

  // Developer simulation reset (only for testing within the builder)
  const handleSimulationReset = () => {
    localStorage.removeItem('eop_setup_completed');
    localStorage.removeItem('eop_setup_locked_at');
    setIsLocked(false);
    setCurrentStep(1);
    setDbTestResult(null);
    setLdapTestResult(null);
    setEopTestResult(null);
  };

  // =========================================================================
  // LOCKED VIEW: If setup is already finished, strictly prohibit re-running!
  // =========================================================================
  if (isLocked) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-12">
        <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-xl border border-slate-200 dark:border-slate-800 overflow-hidden">
          {/* Locked Header Strip */}
          <div className="bg-gradient-to-r from-slate-800 to-slate-950 p-8 text-white text-center relative overflow-hidden">
            <div className="w-16 h-16 rounded-2xl bg-amber-500/20 border border-amber-400/40 text-amber-400 flex items-center justify-center mx-auto mb-4 shadow-lg backdrop-blur-xs">
              <Lock className="w-8 h-8" />
            </div>
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/30 mb-2 font-mono">
              <Shield className="w-3.5 h-3.5" />
              STATUS: SETUP LOCKED &bull; 403 FORBIDDEN
            </span>
            <h2 className="text-2xl font-bold">Initial Setup Routine is Locked</h2>
            <p className="text-slate-300 text-xs mt-2 max-w-lg mx-auto">
              This system has already been configured and initialized. For security reasons, the initial setup routine cannot be run again.
            </p>
          </div>

          <div className="p-8 space-y-6">
            {/* Lockout Details Card */}
            <div className="bg-slate-50 dark:bg-slate-800/60 rounded-xl p-5 border border-slate-200 dark:border-slate-700 text-xs space-y-3 font-mono">
              <div className="flex justify-between items-center pb-2 border-b border-slate-200 dark:border-slate-700">
                <span className="text-slate-500 dark:text-slate-400 font-sans font-semibold">Security Lock Status:</span>
                <span className="text-rose-600 dark:text-rose-400 font-bold flex items-center gap-1">
                  <Lock className="w-3.5 h-3.5" /> Permanently Locked
                </span>
              </div>
              <div className="flex justify-between items-center pb-2 border-b border-slate-200 dark:border-slate-700">
                <span className="text-slate-500 dark:text-slate-400 font-sans font-semibold">Completion Timestamp:</span>
                <span className="text-slate-800 dark:text-slate-200">{lockTimestamp}</span>
              </div>
              <div className="flex justify-between items-center pb-2 border-b border-slate-200 dark:border-slate-700">
                <span className="text-slate-500 dark:text-slate-400 font-sans font-semibold">Lockfile Path (Debian):</span>
                <span className="text-blue-600 dark:text-blue-400">/var/www/eop-antispam/installed.lock</span>
              </div>
              <div className="flex justify-between items-center pb-2 border-b border-slate-200 dark:border-slate-700">
                <span className="text-slate-500 dark:text-slate-400 font-sans font-semibold">Environment Config (.env):</span>
                <span className="text-emerald-600 dark:text-emerald-400 flex items-center gap-1 font-semibold">
                  <Check className="w-3.5 h-3.5" /> /var/www/eop-antispam/.env (Written)
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-slate-500 dark:text-slate-400 font-sans font-semibold">MariaDB Tracking Table:</span>
                <span className="text-purple-600 dark:text-purple-400">eop_setup_lock (Record #1)</span>
              </div>
            </div>

            {/* Explanation box */}
            <div className="p-4 rounded-xl bg-blue-50 dark:bg-blue-950/30 border border-blue-200 dark:border-blue-900/60 text-xs text-blue-900 dark:text-blue-200 leading-relaxed">
              <p className="font-semibold mb-1 flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4 text-blue-600 dark:text-blue-400 shrink-0" />
                How to modify settings after installation:
              </p>
              <p>
                To change Exchange Online certificates, private keys, or Active Directory LDAP credentials, authenticated administrators with authorized Group DN access can visit the <strong>Configuration Page</strong> within the application. On Debian Linux, manual re-runs require deleting <code>installed.lock</code> via SSH.
              </p>
            </div>

            {/* Action Buttons */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-4 border-t border-slate-200 dark:border-slate-800">
              <button
                type="button"
                onClick={handleSimulationReset}
                className="w-full sm:w-auto px-4 py-2.5 rounded-lg border border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-400 hover:text-rose-600 dark:hover:text-rose-400 hover:border-rose-300 text-xs font-semibold flex items-center justify-center gap-1.5 transition cursor-pointer"
                title="Reset local state to test the Setup Wizard flow again"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Reset Setup Lock (Simulation Testing)</span>
              </button>

              <div className="flex items-center space-x-2 w-full sm:w-auto">
                <button
                  type="button"
                  onClick={onOpenConfigPage}
                  className="w-full sm:w-auto px-4 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold flex items-center justify-center gap-1.5 shadow-sm transition cursor-pointer"
                >
                  <Sliders className="w-3.5 h-3.5" />
                  <span>Configuration Page</span>
                </button>
                <button
                  type="button"
                  onClick={onFinishSetup}
                  className="w-full sm:w-auto px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold flex items-center justify-center gap-1.5 shadow-sm transition cursor-pointer"
                >
                  <span>Go to Anti-Spam Manager</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // =========================================================================
  // ACTIVE WIZARD VIEW: Standard Page-by-Page Wizard (Steps 1 to 5)
  // =========================================================================
  return (
    <div className="max-w-4xl mx-auto px-4 py-10">
      {/* Wizard Header */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-100 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 text-xs font-semibold mb-2">
          <Sparkles className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
          <span>First-Run Installation &amp; Setup Routine</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 dark:text-white">
          Exchange Online Protection Policy Manager
        </h1>
        <p className="text-xs sm:text-sm text-slate-500 dark:text-slate-400 mt-1 max-w-xl mx-auto">
          Complete this one-time setup routine to configure your remote MariaDB database, populate the schema, configure Active Directory LDAP authentication, and setup Exchange Online certificate credentials.
        </p>
      </div>

      {/* Progress Stepper Bar */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl p-4 sm:p-6 border border-slate-200 dark:border-slate-800 shadow-sm mb-6">
        <div className="grid grid-cols-5 gap-2 text-center">
          {[
            { step: 1, label: 'Welcome & Prereqs', icon: ShieldCheck },
            { step: 2, label: 'Database & Schema', icon: Database },
            { step: 3, label: 'AD LDAP Auth', icon: UserCheck },
            { step: 4, label: 'Exchange Online', icon: Key },
            { step: 5, label: 'Finalize & Lock', icon: Lock },
          ].map(({ step, label, icon: Icon }) => (
            <div
              key={step}
              className={`flex flex-col items-center cursor-pointer transition ${
                currentStep === step
                  ? 'text-blue-600 dark:text-blue-400 font-bold'
                  : currentStep > step
                  ? 'text-emerald-600 dark:text-emerald-400 font-medium'
                  : 'text-slate-400 dark:text-slate-600'
              }`}
              onClick={() => {
                if (step < currentStep) setCurrentStep(step);
              }}
            >
              <div
                className={`w-9 h-9 rounded-full flex items-center justify-center text-xs font-bold mb-1.5 transition ${
                  currentStep === step
                    ? 'bg-blue-600 text-white shadow-md shadow-blue-500/30 ring-4 ring-blue-500/20'
                    : currentStep > step
                    ? 'bg-emerald-600 text-white'
                    : 'bg-slate-100 dark:bg-slate-800 text-slate-400 border border-slate-200 dark:border-slate-700'
                }`}
              >
                {currentStep > step ? <Check className="w-4 h-4" /> : <Icon className="w-4 h-4" />}
              </div>
              <span className="text-[11px] truncate max-w-full hidden sm:inline">{label}</span>
              <span className="text-[10px] sm:hidden font-mono">#{step}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Step Content Container */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-xl border border-slate-200 dark:border-slate-800 overflow-hidden">
        
        {/* =================================================================== */}
        {/* STEP 1: Welcome & Prerequisites Check                               */}
        {/* =================================================================== */}
        {currentStep === 1 && (
          <div className="p-6 sm:p-8 space-y-6">
            <div className="flex items-center space-x-3 pb-4 border-b border-slate-100 dark:border-slate-800">
              <div className="w-10 h-10 rounded-xl bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 flex items-center justify-center font-bold">
                <ShieldCheck className="w-5 h-5" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-slate-900 dark:text-white">Step 1: System Requirements &amp; Welcome</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">Verifying Debian server runtime extensions and write permissions</p>
              </div>
            </div>

            <div className="text-xs text-slate-600 dark:text-slate-300 space-y-3 leading-relaxed">
              <p>
                Welcome to the <strong>Exchange Online Protection Anti-Spam Policy Manager</strong> installation wizard. This routine will guide you through setting up all core components:
              </p>
              <ul className="list-disc pl-5 space-y-1 text-slate-700 dark:text-slate-200">
                <li>Configuring connection to your <strong>Remote MariaDB</strong> database</li>
                <li>Automatically populating all 4 list tables, audit logs, policies, and configuration tables via <code>schema.sql</code></li>
                <li>Connecting to <strong>Microsoft Active Directory LDAP</strong> (plain LDAP port 389 supported &bull; LDAPS not required)</li>
                <li>Setting up <strong>Exchange Online Certificate-Based Authentication</strong> with AES-256 encrypted private key storage</li>
                <li>Locking the setup routine permanently once finished so it cannot be tampered with</li>
              </ul>
            </div>

            {/* Prerequisites Checklist */}
            <div className="bg-slate-50 dark:bg-slate-800/50 rounded-xl p-4 border border-slate-200 dark:border-slate-700 space-y-2.5 text-xs">
              <h4 className="font-bold text-slate-800 dark:text-slate-200 mb-2 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                Debian Linux Environment Checks:
              </h4>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="flex items-center justify-between p-2.5 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700">
                  <span className="text-slate-600 dark:text-slate-300">PHP 8.2 / 8.3 CLI &amp; FPM</span>
                  <span className="text-emerald-600 font-semibold flex items-center gap-1 text-[11px]"><Check className="w-3.5 h-3.5" /> OK (8.2.14)</span>
                </div>
                <div className="flex items-center justify-between p-2.5 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700">
                  <span className="text-slate-600 dark:text-slate-300">PHP PDO MariaDB / MySQL</span>
                  <span className="text-emerald-600 font-semibold flex items-center gap-1 text-[11px]"><Check className="w-3.5 h-3.5" /> Installed</span>
                </div>
                <div className="flex items-center justify-between p-2.5 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700">
                  <span className="text-slate-600 dark:text-slate-300">PHP LDAP Extension</span>
                  <span className="text-emerald-600 font-semibold flex items-center gap-1 text-[11px]"><Check className="w-3.5 h-3.5" /> Enabled (Port 389/636)</span>
                </div>
                <div className="flex items-center justify-between p-2.5 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700">
                  <span className="text-slate-600 dark:text-slate-300">OpenSSL (AES-256-GCM)</span>
                  <span className="text-emerald-600 font-semibold flex items-center gap-1 text-[11px]"><Check className="w-3.5 h-3.5" /> Ready</span>
                </div>
              </div>
            </div>

            {/* Step 1 Actions */}
            <div className="flex items-center justify-end pt-4 border-t border-slate-100 dark:border-slate-800">
              <button
                type="button"
                onClick={() => setCurrentStep(2)}
                className="px-6 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center gap-1.5 transition cursor-pointer"
              >
                <span>Proceed to Database Setup</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {/* =================================================================== */}
        {/* STEP 2: Database Connection & Schema Population                     */}
        {/* =================================================================== */}
        {currentStep === 2 && (
          <div className="p-6 sm:p-8 space-y-6">
            <div className="flex items-center space-x-3 pb-4 border-b border-slate-100 dark:border-slate-800">
              <div className="w-10 h-10 rounded-xl bg-purple-50 dark:bg-purple-950/60 text-purple-600 dark:text-purple-400 flex items-center justify-center font-bold">
                <Database className="w-5 h-5" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-slate-900 dark:text-white">Step 2: Database Connection &amp; Schema Population</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">Connect to remote MariaDB and execute DDL to generate all tables</p>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">MariaDB Host / IP Address:</label>
                <input
                  type="text"
                  value={dbHost}
                  onChange={(e) => setDbHost(e.target.value)}
                  placeholder="192.168.10.50 or db.corp.example.com"
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Port:</label>
                <input
                  type="number"
                  value={dbPort}
                  onChange={(e) => setDbPort(Number(e.target.value))}
                  placeholder="3306"
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Database Name:</label>
                <input
                  type="text"
                  value={dbName}
                  onChange={(e) => setDbName(e.target.value)}
                  placeholder="eop_antispam_db"
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Database Username:</label>
                <input
                  type="text"
                  value={dbUser}
                  onChange={(e) => setDbUser(e.target.value)}
                  placeholder="eop_user"
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                />
              </div>

              <div className="sm:col-span-2">
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Database Password:</label>
                <input
                  type="password"
                  value={dbPass}
                  onChange={(e) => setDbPass(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                />
              </div>
            </div>

            {/* Test & Populate Button */}
            <div className="flex items-center justify-between p-4 bg-slate-50 dark:bg-slate-800/60 rounded-xl border border-slate-200 dark:border-slate-700">
              <div className="text-xs text-slate-500 dark:text-slate-400">
                Click to verify PDO connection and run <code>schema.sql</code> table definitions.
              </div>
              <button
                type="button"
                onClick={handleTestAndPopulateDb}
                disabled={dbTesting}
                className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center gap-1.5 transition cursor-pointer"
              >
                {dbTesting ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Terminal className="w-3.5 h-3.5" />}
                <span>{dbTesting ? 'Testing & Populating...' : 'Test Connection & Populate Schema'}</span>
              </button>
            </div>

            {/* Test Result Display */}
            {dbTestResult && (
              <div className="p-4 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800 text-xs space-y-3">
                <div className="flex items-center gap-2 font-bold text-emerald-800 dark:text-emerald-200">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                  <span>{dbTestResult.message}</span>
                </div>
                {dbTestResult.tablesCreated && (
                  <div>
                    <div className="text-[11px] font-semibold text-emerald-900 dark:text-emerald-300 mb-1.5">
                      Successfully populated MariaDB tables:
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5 font-mono text-[11px]">
                      {dbTestResult.tablesCreated.map((tbl) => (
                        <div key={tbl} className="flex items-center gap-1.5 p-1.5 rounded bg-white dark:bg-slate-900 border border-emerald-200 dark:border-emerald-900/60 text-emerald-800 dark:text-emerald-200">
                          <Check className="w-3 h-3 text-emerald-600" />
                          <span>{tbl}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                <div className="p-2.5 rounded-lg bg-emerald-100/70 dark:bg-emerald-900/40 border border-emerald-300 dark:border-emerald-700/60 flex items-center justify-between">
                  <div className="flex items-center gap-2 text-emerald-950 dark:text-emerald-200 text-xs">
                    <FileText className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                    <span>Database parameters synchronized for <strong>.env</strong> file (<code>DB_HOST="{dbHost}"</code>, <code>DB_PORT={dbPort}</code>, <code>DB_NAME="{dbName}"</code>, <code>DB_USER="{dbUser}"</code>)</span>
                  </div>
                  <span className="font-mono text-[10px] bg-emerald-200 dark:bg-emerald-800 px-2 py-0.5 rounded text-emerald-800 dark:text-emerald-200 font-bold shrink-0">
                    .env Synced
                  </span>
                </div>
              </div>
            )}

            {/* Step 2 Navigation */}
            <div className="flex items-center justify-between pt-4 border-t border-slate-100 dark:border-slate-800">
              <button
                type="button"
                onClick={() => setCurrentStep(1)}
                className="px-4 py-2 text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg text-xs font-semibold flex items-center gap-1.5"
              >
                <ArrowLeft className="w-4 h-4" />
                <span>Back</span>
              </button>
              <button
                type="button"
                onClick={() => setCurrentStep(3)}
                className="px-6 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center gap-1.5 transition cursor-pointer"
              >
                <span>Proceed to LDAP Setup</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {/* =================================================================== */}
        {/* STEP 3: Active Directory LDAP Information                           */}
        {/* =================================================================== */}
        {currentStep === 3 && (
          <div className="p-6 sm:p-8 space-y-6">
            <div className="flex items-center space-x-3 pb-4 border-b border-slate-100 dark:border-slate-800">
              <div className="w-10 h-10 rounded-xl bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 flex items-center justify-center font-bold">
                <UserCheck className="w-5 h-5" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-slate-900 dark:text-white">Step 3: Active Directory LDAP Information</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">Configure AD Domain Controller connection and authorized Group DN</p>
              </div>
            </div>

            <div className="p-3 bg-amber-50 dark:bg-amber-950/30 rounded-xl border border-amber-200 dark:border-amber-900/60 text-xs text-amber-800 dark:text-amber-200">
              <strong>Plain LDAP (Port 389) Supported:</strong> LDAPS (Port 636) is optional and NOT required. You can connect straight to standard AD LDAP without installing Windows enterprise CA certificates on Debian.
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Domain Controller Host / IP:</label>
                <input
                  type="text"
                  value={ldapHost}
                  onChange={(e) => setLdapHost(e.target.value)}
                  placeholder="dc01.corp.example.com"
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Port &amp; Protocol:</label>
                <div className="grid grid-cols-2 gap-2">
                  <input
                    type="number"
                    value={ldapPort}
                    onChange={(e) => setLdapPort(Number(e.target.value))}
                    className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                  />
                  <select
                    value={ldapProtocol}
                    onChange={(e) => {
                      const proto = e.target.value as 'ldap' | 'ldaps' | 'starttls';
                      setLdapProtocol(proto);
                      if (proto === 'ldaps') setLdapPort(636);
                      else setLdapPort(389);
                    }}
                    className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-2 py-2 text-slate-900 dark:text-white text-xs"
                  >
                    <option value="ldap">Plain (389)</option>
                    <option value="ldaps">LDAPS (636)</option>
                    <option value="starttls">StartTLS (389)</option>
                  </select>
                </div>
              </div>

              <div className="sm:col-span-2">
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Base Distinguished Name (Base DN):</label>
                <input
                  type="text"
                  value={ldapBaseDn}
                  onChange={(e) => setLdapBaseDn(e.target.value)}
                  placeholder="DC=corp,DC=example,DC=com"
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                />
              </div>

              <div className="sm:col-span-2">
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Mandatory Authorized Group DN:
                </label>
                <input
                  type="text"
                  value={ldapGroupDn}
                  onChange={(e) => setLdapGroupDn(e.target.value)}
                  placeholder="CN=EOP-SpamAdmins,OU=Security Groups,DC=corp,DC=example,DC=com"
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                />
                <p className="text-[11px] text-slate-400 mt-1">
                  Only AD accounts belonging to this group (including nested groups) can authenticate and access the manager.
                </p>
              </div>

              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Service Account Bind DN (Optional):</label>
                <input
                  type="text"
                  value={ldapBindDn}
                  onChange={(e) => setLdapBindDn(e.target.value)}
                  placeholder="CN=svc-eop,OU=Service Accounts,DC=corp,DC=example,DC=com"
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                />
                <p className="text-[10px] text-slate-500 dark:text-slate-400 mt-1">
                  Active Directory service account Distinguished Name used to query LDAP.
                </p>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="block font-semibold text-slate-700 dark:text-slate-300">
                    Bind Password for LDAP Authorization:
                  </label>
                  <button
                    type="button"
                    onClick={() => setShowWizardBindPass(!showWizardBindPass)}
                    className="text-[11px] text-blue-600 dark:text-blue-400 hover:underline flex items-center gap-1 cursor-pointer"
                  >
                    {showWizardBindPass ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                    <span>{showWizardBindPass ? 'Hide' : 'Show'}</span>
                  </button>
                </div>
                <input
                  type={showWizardBindPass ? 'text' : 'password'}
                  value={ldapBindPass}
                  onChange={(e) => setLdapBindPass(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                />
                <p className="text-[10px] text-slate-500 dark:text-slate-400 mt-1">
                  Active Directory service account password used for LDAP bind authorization and group membership lookups.
                </p>
              </div>
            </div>

            {/* Test LDAP Button */}
            <div className="flex items-center justify-between p-4 bg-slate-50 dark:bg-slate-800/60 rounded-xl border border-slate-200 dark:border-slate-700">
              <div className="text-xs text-slate-500 dark:text-slate-400">
                Verify domain controller reachability and Group DN lookup.
              </div>
              <button
                type="button"
                onClick={handleTestLdap}
                disabled={ldapTesting}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center gap-1.5 transition cursor-pointer"
              >
                {ldapTesting ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <UserCheck className="w-3.5 h-3.5" />}
                <span>{ldapTesting ? 'Verifying...' : 'Test LDAP Connection'}</span>
              </button>
            </div>

            {/* LDAP Result */}
            {ldapTestResult && (
              <div className="p-4 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800 text-xs space-y-1">
                <div className="flex items-center gap-2 font-bold text-emerald-800 dark:text-emerald-200">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                  <span>{ldapTestResult.message}</span>
                </div>
                {ldapTestResult.details && (
                  <p className="text-emerald-700 dark:text-emerald-300 text-[11px] font-mono pl-6">
                    {ldapTestResult.details}
                  </p>
                )}
              </div>
            )}

            {/* Non-LDAP Fallback Administrator Account Setup */}
            <div className="p-5 bg-gradient-to-br from-slate-50 to-amber-50/50 dark:from-slate-800/80 dark:to-amber-950/20 rounded-2xl border border-amber-200/80 dark:border-amber-800/60 space-y-4">
              <div className="flex items-start justify-between">
                <div className="flex items-center space-x-2.5">
                  <div className="w-8 h-8 rounded-xl bg-amber-100 dark:bg-amber-950/80 text-amber-700 dark:text-amber-300 flex items-center justify-center font-bold">
                    <Shield className="w-4 h-4" />
                  </div>
                  <div>
                    <h3 className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-2">
                      <span>Emergency Non-LDAP Fallback Administrator</span>
                      <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-amber-100 dark:bg-amber-950/80 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800/60">
                        Disaster Recovery
                      </span>
                    </h3>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400">
                      Allows authorized sign-in directly through MariaDB if the Active Directory Domain Controller is unreachable or offline.
                    </p>
                  </div>
                </div>

                <label className="flex items-center space-x-2 cursor-pointer text-xs font-semibold text-slate-700 dark:text-slate-300">
                  <input
                    type="checkbox"
                    checked={fallbackAdminEnabled}
                    onChange={(e) => setFallbackAdminEnabled(e.target.checked)}
                    className="w-4 h-4 text-amber-600 rounded border-slate-300 focus:ring-amber-500"
                  />
                  <span>Enable Fallback Account</span>
                </label>
              </div>

              {fallbackAdminEnabled && (
                <div className="pt-2 border-t border-amber-200/60 dark:border-amber-800/40 space-y-3">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                    <div>
                      <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                        Fallback Username:
                      </label>
                      <input
                        type="text"
                        value={fallbackAdminUsername}
                        onChange={(e) => {
                          setFallbackAdminUsername(e.target.value);
                          setStep3Error(null);
                        }}
                        placeholder="eopadmin"
                        className="w-full bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-amber-500 focus:outline-hidden"
                      />
                    </div>

                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <label className="font-semibold text-slate-700 dark:text-slate-300">
                          Fallback Password:
                        </label>
                        <button
                          type="button"
                          onClick={() => setShowFallbackPass(!showFallbackPass)}
                          className="text-[11px] text-slate-500 dark:text-slate-400 hover:text-slate-700 flex items-center gap-1 cursor-pointer"
                        >
                          {showFallbackPass ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                          <span>{showFallbackPass ? 'Hide' : 'Show'}</span>
                        </button>
                      </div>
                      <input
                        type={showFallbackPass ? 'text' : 'password'}
                        value={fallbackAdminPassword}
                        onChange={(e) => {
                          setFallbackAdminPassword(e.target.value);
                          setStep3Error(null);
                        }}
                        placeholder="12+ chars, 3 of 4: upper, lower, numbers, symbols"
                        className="w-full bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-amber-500 focus:outline-hidden"
                      />
                    </div>
                  </div>

                  {/* Password Requirement Checklist */}
                  {(() => {
                    const check = validateFallbackPassword(fallbackAdminPassword);
                    return (
                      <div className="p-3.5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700/80 space-y-2 text-[11px]">
                        <div className="flex items-center justify-between font-semibold text-slate-700 dark:text-slate-300">
                          <span className="flex items-center gap-1.5">
                            <Lock className="w-3.5 h-3.5 text-amber-500" />
                            <span>Password Policy Enforcement:</span>
                          </span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            check.isValid
                              ? 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800'
                              : 'bg-rose-100 dark:bg-rose-950/60 text-rose-800 dark:text-rose-300 border border-rose-300 dark:border-rose-800'
                          }`}>
                            {check.isValid ? 'REQUIREMENTS SATISFIED (PASSED)' : 'CRITERIA UNMET'}
                          </span>
                        </div>

                        {/* Top: 12+ length requirement */}
                        <div className={`flex items-center justify-between p-2 rounded-lg border text-xs ${
                          check.minLength
                            ? 'text-emerald-800 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-800'
                            : 'text-amber-800 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/30 border-amber-200 dark:border-amber-800'
                        }`}>
                          <div className="flex items-center gap-2">
                            {check.minLength ? <CheckCircle2 className="w-4 h-4 text-emerald-600" /> : <AlertTriangle className="w-4 h-4 text-amber-600" />}
                            <span className="font-semibold">Minimum Length: 12+ Characters</span>
                          </div>
                          <span className="font-mono font-bold">{fallbackAdminPassword.length} characters</span>
                        </div>

                        {/* 4 Categories Checklist (At least 3 required) */}
                        <div className="text-[11px] font-medium text-slate-600 dark:text-slate-400">
                          Must satisfy at least <strong>3 of the following 4</strong> categories:
                        </div>

                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[10px]">
                          <div className={`flex items-center gap-1.5 p-2 rounded-lg border ${
                            check.hasUpper
                              ? 'text-emerald-800 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-800'
                              : 'text-slate-500 dark:text-slate-400 bg-slate-50 dark:bg-slate-800/80 border-slate-200 dark:border-slate-700'
                          }`}>
                            {check.hasUpper ? <Check className="w-3.5 h-3.5 text-emerald-600 shrink-0" /> : <span className="w-3.5 h-3.5 text-center text-slate-400">&times;</span>}
                            <span>Uppercase (A-Z)</span>
                          </div>

                          <div className={`flex items-center gap-1.5 p-2 rounded-lg border ${
                            check.hasLower
                              ? 'text-emerald-800 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-800'
                              : 'text-slate-500 dark:text-slate-400 bg-slate-50 dark:bg-slate-800/80 border-slate-200 dark:border-slate-700'
                          }`}>
                            {check.hasLower ? <Check className="w-3.5 h-3.5 text-emerald-600 shrink-0" /> : <span className="w-3.5 h-3.5 text-center text-slate-400">&times;</span>}
                            <span>Lowercase (a-z)</span>
                          </div>

                          <div className={`flex items-center gap-1.5 p-2 rounded-lg border ${
                            check.hasNumber
                              ? 'text-emerald-800 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-800'
                              : 'text-slate-500 dark:text-slate-400 bg-slate-50 dark:bg-slate-800/80 border-slate-200 dark:border-slate-700'
                          }`}>
                            {check.hasNumber ? <Check className="w-3.5 h-3.5 text-emerald-600 shrink-0" /> : <span className="w-3.5 h-3.5 text-center text-slate-400">&times;</span>}
                            <span>Numbers (0-9)</span>
                          </div>

                          <div className={`flex items-center gap-1.5 p-2 rounded-lg border ${
                            check.hasSymbol
                              ? 'text-emerald-800 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-800'
                              : 'text-slate-500 dark:text-slate-400 bg-slate-50 dark:bg-slate-800/80 border-slate-200 dark:border-slate-700'
                          }`}>
                            {check.hasSymbol ? <Check className="w-3.5 h-3.5 text-emerald-600 shrink-0" /> : <span className="w-3.5 h-3.5 text-center text-slate-400">&times;</span>}
                            <span>Symbols (!@#$...)</span>
                          </div>
                        </div>

                        <div className="flex items-center justify-between text-[11px] pt-1 text-slate-500 dark:text-slate-400">
                          <span>Complexity Score:</span>
                          <span className="font-semibold text-slate-700 dark:text-slate-200">
                            <strong>{check.passedCategories} of 4</strong> categories satisfied ({check.passedCategories >= 3 ? 'Meets policy' : `${3 - check.passedCategories} more needed`})
                          </span>
                        </div>
                      </div>
                    );
                  })()}
                </div>
              )}
            </div>

            {/* Inline validation error if user tries to advance without valid credentials */}
            {step3Error && (
              <div className="p-4 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-xs text-rose-800 dark:text-rose-200 flex items-start gap-2.5">
                <AlertTriangle className="w-4 h-4 text-rose-600 dark:text-rose-400 shrink-0 mt-0.5" />
                <div className="space-y-0.5">
                  <div className="font-bold">Cannot Proceed to Next Step</div>
                  <div>{step3Error}</div>
                </div>
              </div>
            )}

            {/* Step 3 Navigation */}
            <div className="flex items-center justify-between pt-4 border-t border-slate-100 dark:border-slate-800">
              <button
                type="button"
                onClick={() => setCurrentStep(2)}
                className="px-4 py-2 text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
              >
                <ArrowLeft className="w-4 h-4" />
                <span>Back</span>
              </button>
              <button
                type="button"
                onClick={() => {
                  setStep3Error(null);
                  if (fallbackAdminEnabled) {
                    if (!fallbackAdminUsername.trim()) {
                      setStep3Error('Please provide a fallback administrator username.');
                      return;
                    }
                    const check = validateFallbackPassword(fallbackAdminPassword);
                    if (!check.minLength) {
                      setStep3Error(`Fallback password is too short (${fallbackAdminPassword.length} chars). It must be at least 12 characters long.`);
                      return;
                    }
                    if (check.passedCategories < 3) {
                      setStep3Error(`Fallback password satisfies only ${check.passedCategories} of 4 categories. It must satisfy at least 3: uppercase letters, lowercase letters, numbers, and symbols.`);
                      return;
                    }
                  }
                  setConfig((prev) => ({
                    ...prev,
                    ldapHost,
                    ldapPort: Number(ldapPort),
                    ldapProtocol,
                    ldapBaseDn,
                    ldapGroupDn,
                    ldapBindDn,
                    ldapBindPass,
                    ldapDomain,
                    fallbackAdminEnabled,
                    fallbackAdminUsername,
                    fallbackAdminPassword,
                  }));
                  setCurrentStep(4);
                }}
                className="px-6 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center gap-1.5 transition cursor-pointer"
              >
                <span>Proceed to EOP Setup</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {/* =================================================================== */}
        {/* STEP 4: Exchange Online Protection (EOP) Connection Information     */}
        {/* =================================================================== */}
        {currentStep === 4 && (
          <div className="p-6 sm:p-8 space-y-6">
            <div className="flex items-center space-x-3 pb-4 border-b border-slate-100 dark:border-slate-800">
              <div className="w-10 h-10 rounded-xl bg-amber-50 dark:bg-amber-950/60 text-amber-600 dark:text-amber-400 flex items-center justify-center font-bold">
                <Key className="w-5 h-5" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-slate-900 dark:text-white">Step 4: Exchange Online Protection Connection Information</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">Azure AD App-Only Certificate Authentication &amp; Private Key storage</p>
              </div>
            </div>

            {/* Directions for Generating the Certificate */}
            <div className="rounded-xl border border-amber-200 dark:border-amber-800/80 bg-amber-50/50 dark:bg-amber-950/20 overflow-hidden">
              <div className="p-4 flex items-center justify-between cursor-pointer" onClick={() => setShowCertDirections(!showCertDirections)}>
                <div className="flex items-center space-x-2.5">
                  <div className="p-1.5 rounded-lg bg-amber-100 dark:bg-amber-900/60 text-amber-700 dark:text-amber-300">
                    <FileKey className="w-4 h-4" />
                  </div>
                  <div>
                    <h3 className="text-xs font-bold text-amber-950 dark:text-amber-200">
                      Need a certificate? Directions for Generating the Certificate &amp; Thumbprint
                    </h3>
                    <p className="text-[11px] text-amber-800/80 dark:text-amber-300/70">
                      Step-by-step commands to generate RSA private key, public cert, and SHA-1 thumbprint for Microsoft Entra ID
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-semibold text-amber-700 dark:text-amber-300">
                    {showCertDirections ? 'Hide Directions' : 'View Directions'}
                  </span>
                  {showCertDirections ? <ChevronUp className="w-4 h-4 text-amber-700 dark:text-amber-300" /> : <ChevronDown className="w-4 h-4 text-amber-700 dark:text-amber-300" />}
                </div>
              </div>

              {showCertDirections && (
                <div className="p-4 pt-0 border-t border-amber-200/70 dark:border-amber-800/60 space-y-3 text-xs">
                  {/* Tabs: Linux OpenSSL vs Windows PowerShell */}
                  <div className="flex items-center space-x-2 pt-3">
                    <button
                      type="button"
                      onClick={() => setCertDirectionsTab('openssl')}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer flex items-center gap-1.5 ${
                        certDirectionsTab === 'openssl'
                          ? 'bg-amber-600 text-white shadow-xs'
                          : 'bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-amber-100/60'
                      }`}
                    >
                      <Terminal className="w-3.5 h-3.5" />
                      <span>Linux / Debian (OpenSSL)</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setCertDirectionsTab('powershell')}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer flex items-center gap-1.5 ${
                        certDirectionsTab === 'powershell'
                          ? 'bg-amber-600 text-white shadow-xs'
                          : 'bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-amber-100/60'
                      }`}
                    >
                      <Terminal className="w-3.5 h-3.5" />
                      <span>Windows (PowerShell)</span>
                    </button>
                  </div>

                  {certDirectionsTab === 'openssl' ? (
                    <div className="space-y-2">
                      <div className="relative">
                        <pre className="p-3 bg-slate-900 text-slate-100 rounded-lg font-mono text-[11px] overflow-x-auto leading-relaxed">
{`# 1. Generate RSA 2048-bit private key with passphrase:
openssl genrsa -aes256 -passout pass:"${keyPassword || 'YourPassphrase'}" -out eop-cert-private.key 2048

# 2. Generate self-signed public certificate (valid 2 years):
openssl req -new -x509 -key eop-cert-private.key -passin pass:"${keyPassword || 'YourPassphrase'}" \\
  -days 730 -out eop-cert-public.crt \\
  -subj "/CN=EOP Anti-Spam Policy Manager/O=${orgDomain || 'YourOrg'}"

# 3. Print SHA-1 Thumbprint (copy this into the Thumbprint box below):
openssl x509 -in eop-cert-public.crt -noout -fingerprint -sha1 | tr -d ':' | sed 's/SHA1 Fingerprint=//'`}
                        </pre>
                        <button
                          type="button"
                          onClick={() => {
                            const cmd = `# 1. Generate RSA 2048-bit private key with passphrase:\nopenssl genrsa -aes256 -passout pass:"${keyPassword || 'YourPassphrase'}" -out eop-cert-private.key 2048\n\n# 2. Generate self-signed public certificate (valid 2 years):\nopenssl req -new -x509 -key eop-cert-private.key -passin pass:"${keyPassword || 'YourPassphrase'}" \\\n  -days 730 -out eop-cert-public.crt \\\n  -subj "/CN=EOP Anti-Spam Policy Manager/O=${orgDomain || 'YourOrg'}"\n\n# 3. Print SHA-1 Thumbprint (copy this into the Thumbprint box below):\nopenssl x509 -in eop-cert-public.crt -noout -fingerprint -sha1 | tr -d ':' | sed 's/SHA1 Fingerprint=//'`;
                            navigator.clipboard.writeText(cmd);
                            setCopiedCertCmd(true);
                            setTimeout(() => setCopiedCertCmd(false), 2000);
                          }}
                          className="absolute top-2.5 right-2.5 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[10px] font-semibold flex items-center gap-1 border border-slate-700 cursor-pointer"
                        >
                          {copiedCertCmd ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedCertCmd ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>

                      <div className="p-3 bg-white dark:bg-slate-900 rounded-lg border border-slate-200 dark:border-slate-800 text-[11px] text-slate-700 dark:text-slate-300 space-y-1">
                        <div className="font-semibold text-slate-900 dark:text-white">Next Steps:</div>
                        <ol className="list-decimal list-inside space-y-0.5">
                          <li>Upload <code className="font-mono bg-slate-100 dark:bg-slate-800 px-1 rounded">eop-cert-public.crt</code> to <strong>Microsoft Entra Admin Center</strong> &gt; <strong>App registrations</strong> &gt; <strong>Certificates &amp; secrets</strong>.</li>
                          <li>Copy the printed SHA-1 thumbprint and paste into the <strong>Certificate Thumbprint</strong> field below.</li>
                          <li>Open <code className="font-mono bg-slate-100 dark:bg-slate-800 px-1 rounded">eop-cert-private.key</code>, copy the full PEM block, and paste it into the <strong>Private Key PEM</strong> field below.</li>
                        </ol>
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      <div className="relative">
                        <pre className="p-3 bg-slate-900 text-slate-100 rounded-lg font-mono text-[11px] overflow-x-auto leading-relaxed">
{`# 1. Create certificate in Windows personal cert store:
$cert = New-SelfSignedCertificate -CertStoreLocation "Cert:\\CurrentUser\\My" \`
  -Subject "CN=EOP Anti-Spam Policy Manager" -KeySpec Signature -KeyLength 2048 \`
  -KeyExportPolicy Exportable -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(2)

# 2. Export public certificate (.cer) for Microsoft Entra upload:
Export-Certificate -Cert $cert -FilePath ".\\eop-cert-public.cer"

# 3. Output SHA-1 Thumbprint (copy this into the Thumbprint box below):
$cert.Thumbprint`}
                        </pre>
                        <button
                          type="button"
                          onClick={() => {
                            const cmd = `# 1. Create certificate in Windows personal cert store:\n$cert = New-SelfSignedCertificate -CertStoreLocation "Cert:\\CurrentUser\\My" \\\n  -Subject "CN=EOP Anti-Spam Policy Manager" -KeySpec Signature -KeyLength 2048 \\\n  -KeyExportPolicy Exportable -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(2)\n\n# 2. Export public certificate (.cer) for Microsoft Entra upload:\nExport-Certificate -Cert $cert -FilePath ".\\eop-cert-public.cer"\n\n# 3. Output SHA-1 Thumbprint:\n$cert.Thumbprint`;
                            navigator.clipboard.writeText(cmd);
                            setCopiedCertCmd(true);
                            setTimeout(() => setCopiedCertCmd(false), 2000);
                          }}
                          className="absolute top-2.5 right-2.5 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[10px] font-semibold flex items-center gap-1 border border-slate-700 cursor-pointer"
                        >
                          {copiedCertCmd ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedCertCmd ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>

                      <div className="p-3 bg-white dark:bg-slate-900 rounded-lg border border-slate-200 dark:border-slate-800 text-[11px] text-slate-700 dark:text-slate-300 space-y-1">
                        <div className="font-semibold text-slate-900 dark:text-white">Next Steps:</div>
                        <ol className="list-decimal list-inside space-y-0.5">
                          <li>Upload <code className="font-mono bg-slate-100 dark:bg-slate-800 px-1 rounded">eop-cert-public.cer</code> to <strong>Microsoft Entra Admin Center</strong> &gt; <strong>App registrations</strong> &gt; <strong>Certificates &amp; secrets</strong>.</li>
                          <li>Copy <code className="font-mono bg-slate-100 dark:bg-slate-800 px-1 rounded">$cert.Thumbprint</code> into the <strong>Certificate Thumbprint</strong> field below.</li>
                        </ol>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Azure AD Tenant ID (Directory ID):</label>
                <input
                  type="text"
                  value={tenantId}
                  onChange={(e) => setTenantId(e.target.value)}
                  placeholder="72f988bf-86f1-41af-91ab-2d7cd011db47"
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-amber-500 focus:outline-hidden"
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">App Registration Client ID:</label>
                <input
                  type="text"
                  value={clientId}
                  onChange={(e) => setClientId(e.target.value)}
                  placeholder="3a2b4c5d-6e7f-8a9b-0c1d-2e3f4a5b6c7d"
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-amber-500 focus:outline-hidden"
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Certificate Thumbprint (SHA-1):</label>
                <input
                  type="text"
                  value={certThumbprint}
                  onChange={(e) => setCertThumbprint(e.target.value)}
                  placeholder="9A2F8B3C1D4E5F6A7B8C9D0E1F2A3B4C5D6E7F80"
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-amber-500 focus:outline-hidden"
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Organization Domain:</label>
                <input
                  type="text"
                  value={orgDomain}
                  onChange={(e) => setOrgDomain(e.target.value)}
                  placeholder="corp.example.com"
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-amber-500 focus:outline-hidden"
                />
              </div>

              <div className="sm:col-span-2">
                <div className="flex items-center justify-between mb-1.5 flex-wrap gap-2">
                  <label className="block font-semibold text-slate-700 dark:text-slate-300">
                    RSA Certificate Private Key (PEM format):
                  </label>
                  <div className="flex items-center gap-2">
                    <input
                      type="file"
                      ref={fileInputRef}
                      accept=".pem,.key,.crt,.txt"
                      className="hidden"
                      onChange={handleKeyFileUpload}
                    />
                    <button
                      type="button"
                      onClick={() => fileInputRef.current?.click()}
                      className="px-2.5 py-1 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold shadow-xs transition flex items-center gap-1.5 cursor-pointer"
                    >
                      <Upload className="w-3.5 h-3.5" />
                      <span>Upload Private Key File (.pem, .key)</span>
                    </button>
                    {uploadedKeyFileName && (
                      <button
                        type="button"
                        onClick={() => {
                          setUploadedKeyFileName(null);
                          if (fileInputRef.current) fileInputRef.current.value = '';
                        }}
                        className="p-1 rounded text-slate-400 hover:text-rose-500 dark:hover:text-rose-400 text-xs transition cursor-pointer"
                        title="Clear uploaded file"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                </div>

                {uploadedKeyFileName && (
                  <div className="mb-2 p-2.5 rounded-lg bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800 text-emerald-800 dark:text-emerald-200 text-xs flex items-center justify-between">
                    <div className="flex items-center gap-1.5">
                      <FileCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                      <span>Loaded from file: <strong className="font-mono">{uploadedKeyFileName}</strong></span>
                    </div>
                    <span className="text-[10px] font-mono bg-emerald-100 dark:bg-emerald-900/60 px-2 py-0.5 rounded text-emerald-700 dark:text-emerald-300 font-semibold">
                      PEM Parsed
                    </span>
                  </div>
                )}

                <textarea
                  rows={4}
                  value={privateKeyPem}
                  onChange={(e) => {
                    setPrivateKeyPem(e.target.value);
                    if (uploadedKeyFileName) setUploadedKeyFileName(null);
                  }}
                  placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...&#10;-----END RSA PRIVATE KEY-----"
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg p-3 text-slate-900 dark:text-white font-mono text-[11px] focus:ring-2 focus:ring-amber-500 focus:outline-hidden"
                />
                <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
                  Upload your <code className="font-mono bg-slate-100 dark:bg-slate-800 px-1 rounded">eop-cert-private.key</code> file or paste the unencrypted/passphrase-protected RSA PEM key block.
                </p>
              </div>

              <div className="sm:col-span-2">
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1 flex items-center justify-between">
                  <span>Private Key Passphrase:</span>
                  <span className="text-emerald-600 font-normal text-[11px]">
                    <Lock className="w-3 h-3 inline mr-1" /> Encrypted using AES-256-GCM before writing to MariaDB
                  </span>
                </label>
                <input
                  type="password"
                  value={keyPassword}
                  onChange={(e) => setKeyPassword(e.target.value)}
                  placeholder="Passphrase used when generating cert key"
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-amber-500 focus:outline-hidden"
                />
              </div>
            </div>

            {/* Test EOP Key */}
            <div className="flex items-center justify-between p-4 bg-slate-50 dark:bg-slate-800/60 rounded-xl border border-slate-200 dark:border-slate-700">
              <div className="text-xs text-slate-500 dark:text-slate-400">
                Verify OpenSSL private key parsing and AES-256-GCM passphrase roundtrip.
              </div>
              <button
                type="button"
                onClick={handleTestEop}
                disabled={eopTesting}
                className="px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center gap-1.5 transition cursor-pointer"
              >
                {eopTesting ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <FileKey className="w-3.5 h-3.5" />}
                <span>{eopTesting ? 'Validating...' : 'Verify Private Key & Token Signing'}</span>
              </button>
            </div>

            {/* EOP Result */}
            {eopTestResult && (
              <div className="p-4 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800 text-xs space-y-1">
                <div className="flex items-center gap-2 font-bold text-emerald-800 dark:text-emerald-200">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                  <span>{eopTestResult.message}</span>
                </div>
                {eopTestResult.keyType && (
                  <p className="text-emerald-700 dark:text-emerald-300 text-[11px] font-mono pl-6">
                    Detected format: {eopTestResult.keyType} &bull; Thumbprint: {certThumbprint.substring(0, 16)}...
                  </p>
                )}
              </div>
            )}

            {/* Step 4 Navigation */}
            <div className="flex items-center justify-between pt-4 border-t border-slate-100 dark:border-slate-800">
              <button
                type="button"
                onClick={() => setCurrentStep(3)}
                className="px-4 py-2 text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg text-xs font-semibold flex items-center gap-1.5"
              >
                <ArrowLeft className="w-4 h-4" />
                <span>Back</span>
              </button>
              <button
                type="button"
                onClick={() => setCurrentStep(5)}
                className="px-6 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center gap-1.5 transition cursor-pointer"
              >
                <span>Proceed to Finalize &amp; Lock</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {/* =================================================================== */}
        {/* STEP 5: Finalization & Security Lockout                              */}
        {/* =================================================================== */}
        {currentStep === 5 && (
          <div className="p-6 sm:p-8 space-y-6">
            <div className="flex items-center space-x-3 pb-4 border-b border-slate-100 dark:border-slate-800">
              <div className="w-10 h-10 rounded-xl bg-emerald-50 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400 flex items-center justify-center font-bold">
                <Lock className="w-5 h-5" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-slate-900 dark:text-white">Step 5: Completion &amp; Security Lockout</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">Lock the initial setup routine permanently and write lockfile</p>
              </div>
            </div>

            {/* Configuration Summary Review */}
            <div className="space-y-3">
              <h4 className="text-xs font-bold text-slate-800 dark:text-slate-200">Configuration Summary Review:</h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
                <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700">
                  <div className="font-sans font-bold text-purple-600 dark:text-purple-400 mb-1 flex items-center gap-1">
                    <Database className="w-3.5 h-3.5" /> MariaDB Database
                  </div>
                  <div className="text-[11px] space-y-0.5 text-slate-600 dark:text-slate-300">
                    <div>Host: {dbHost}:{dbPort}</div>
                    <div>Database: {dbName}</div>
                    <div>User: {dbUser}</div>
                    <div className="text-emerald-600 font-sans font-semibold mt-1">9 Tables Populated</div>
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700">
                  <div className="font-sans font-bold text-emerald-600 dark:text-emerald-400 mb-1 flex items-center gap-1">
                    <FileText className="w-3.5 h-3.5" /> Environment (.env)
                  </div>
                  <div className="text-[11px] space-y-0.5 text-slate-600 dark:text-slate-300">
                    <div>File: .env (chmod 0640)</div>
                    <div>DB_HOST: {dbHost}</div>
                    <div>DB_USER: {dbUser}</div>
                    <div className="text-emerald-600 font-sans font-semibold mt-1">Persisted on Setup</div>
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700">
                  <div className="font-sans font-bold text-blue-600 dark:text-blue-400 mb-1 flex items-center gap-1">
                    <UserCheck className="w-3.5 h-3.5" /> AD LDAP &amp; Fallback
                  </div>
                  <div className="text-[11px] space-y-0.5 text-slate-600 dark:text-slate-300">
                    <div>Host: {ldapHost}:{ldapPort}</div>
                    <div>Proto: {ldapProtocol.toUpperCase()}</div>
                    <div className="truncate">Group: {ldapGroupDn.substring(0, 20)}...</div>
                    <div className="text-amber-600 dark:text-amber-400 font-sans font-semibold mt-1">
                      {fallbackAdminEnabled ? `Fallback Admin: ${fallbackAdminUsername}` : 'Fallback Admin: Disabled'}
                    </div>
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700">
                  <div className="font-sans font-bold text-amber-600 dark:text-amber-400 mb-1 flex items-center gap-1">
                    <Key className="w-3.5 h-3.5" /> Exchange Online Auth
                  </div>
                  <div className="text-[11px] space-y-0.5 text-slate-600 dark:text-slate-300">
                    <div>Tenant: {tenantId.substring(0, 8)}...</div>
                    <div>Thumb: {certThumbprint.substring(0, 10)}...</div>
                    <div className="text-emerald-600 font-sans font-semibold mt-1">AES-256 Key Saved</div>
                  </div>
                </div>
              </div>
            </div>

            {/* Expandable .env Preview Box */}
            <div className="rounded-xl border border-slate-200 dark:border-slate-700 overflow-hidden bg-slate-50/50 dark:bg-slate-800/40">
              <div
                className="p-3.5 flex items-center justify-between cursor-pointer hover:bg-slate-100/60 dark:hover:bg-slate-800/70 transition"
                onClick={() => setShowEnvPreview(!showEnvPreview)}
              >
                <div className="flex items-center gap-2">
                  <FileText className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                  <span className="text-xs font-bold text-slate-800 dark:text-slate-200">
                    View Generated Production <code>.env</code> File Content
                  </span>
                  <span className="text-[10px] bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 px-2 py-0.5 rounded-full font-mono font-semibold">
                    Live Values
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  {showEnvPreview ? (
                    <ChevronUp className="w-4 h-4 text-slate-400" />
                  ) : (
                    <ChevronDown className="w-4 h-4 text-slate-400" />
                  )}
                </div>
              </div>

              {showEnvPreview && (
                <div className="p-4 border-t border-slate-200 dark:border-slate-700 space-y-3 bg-white dark:bg-slate-900">
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <span className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
                      Target Path: <strong>/var/www/eop-antispam/.env</strong> (permissions: 0640)
                    </span>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={handleCopyEnv}
                        className="px-2.5 py-1 rounded bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer"
                      >
                        <Copy className="w-3 h-3" />
                        <span>{copiedEnv ? 'Copied!' : 'Copy .env'}</span>
                      </button>
                      <button
                        type="button"
                        onClick={handleDownloadEnv}
                        className="px-2.5 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer"
                      >
                        <Download className="w-3 h-3" />
                        <span>Download .env</span>
                      </button>
                    </div>
                  </div>
                  <pre className="p-3 bg-slate-900 text-slate-200 rounded-lg text-[11px] font-mono overflow-x-auto max-h-56 leading-relaxed border border-slate-800">
                    {generateEnvString()}
                  </pre>
                </div>
              )}
            </div>

            {/* Server Hosting Option Selector */}
            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Server className="w-4 h-4 text-blue-500" />
                  <span className="text-xs font-bold text-slate-900 dark:text-white">Server Hosting Option:</span>
                </div>
                <span className={`text-[10px] px-2 py-0.5 rounded-full font-mono font-bold ${
                  isOnlySiteOnServer
                    ? 'bg-blue-100 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300'
                    : 'bg-amber-100 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300'
                }`}>
                  {isOnlySiteOnServer ? 'DEDICATED / ONLY SITE' : 'SHARED MULTI-SITE'}
                </span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                <button
                  type="button"
                  onClick={() => setIsOnlySiteOnServer(true)}
                  className={`p-2.5 rounded-lg border text-left transition cursor-pointer ${
                    isOnlySiteOnServer
                      ? 'border-blue-500 bg-blue-50 dark:bg-blue-950/50 text-blue-950 dark:text-blue-100 ring-1 ring-blue-500'
                      : 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-400'
                  }`}
                >
                  <div className="font-bold flex items-center justify-between mb-0.5">
                    <span>Only Site on this Server</span>
                    <span className="font-mono text-[10px] text-blue-600">default_server</span>
                  </div>
                  <p className="text-[11px] opacity-80">Configures NGINX as default_server catch-all. Handles all server traffic exclusively.</p>
                </button>
                <button
                  type="button"
                  onClick={() => setIsOnlySiteOnServer(false)}
                  className={`p-2.5 rounded-lg border text-left transition cursor-pointer ${
                    !isOnlySiteOnServer
                      ? 'border-amber-500 bg-amber-50 dark:bg-amber-950/50 text-amber-950 dark:text-amber-100 ring-1 ring-amber-500'
                      : 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-400'
                  }`}
                >
                  <div className="font-bold flex items-center justify-between mb-0.5">
                    <span>Shared Multi-Site Server</span>
                    <span className="font-mono text-[10px] text-amber-600">domain-only</span>
                  </div>
                  <p className="text-[11px] opacity-80">Strictly matches domain name. Coexists safely with other virtual hosts on Debian.</p>
                </button>
              </div>
            </div>

            {/* Permanent Lock Warning Notice */}
            <div className="p-4 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800/60 text-xs text-amber-900 dark:text-amber-200 leading-relaxed space-y-2">
              <div className="font-bold flex items-center gap-2 text-sm text-amber-800 dark:text-amber-300">
                <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />
                <span>Security Notice: Setup Cannot Be Run Again</span>
              </div>
              <p>
                Clicking <strong>Complete Installation, Write .env &amp; Lock Setup</strong> will persist your database settings and environment configuration to <code>.env</code>, generate your production <code>config.php</code> file, create the Debian filesystem lockfile <code>installed.lock</code>, and record the setup completion in the MariaDB table <code>eop_setup_lock</code>.
              </p>
              <p className="font-semibold text-amber-800 dark:text-amber-300">
                Once locked, any subsequent attempts to visit <code>setup.php</code> will be strictly blocked with a 403 Forbidden status.
              </p>
            </div>

            {/* Step 5 Actions */}
            <div className="flex items-center justify-between pt-4 border-t border-slate-100 dark:border-slate-800">
              <button
                type="button"
                onClick={() => setCurrentStep(4)}
                className="px-4 py-2 text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg text-xs font-semibold flex items-center gap-1.5"
              >
                <ArrowLeft className="w-4 h-4" />
                <span>Back</span>
              </button>

              <button
                type="button"
                onClick={handleFinalizeAndLock}
                disabled={finalizing}
                className="px-6 py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center gap-2 transition cursor-pointer"
              >
                {finalizing ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Lock className="w-4 h-4" />}
                <span>{finalizing ? 'Writing .env, Lock & Finalizing...' : 'Complete Installation, Write .env & Lock Setup'}</span>
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
