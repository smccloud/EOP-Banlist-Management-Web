import React, { useState, useEffect, useMemo } from 'react';
import { AppConfig, ListItem, ListType, AuditLogEntry, LdapDbConfig, EopAuthConfig } from '../types';
import {
  ShieldCheck,
  Mail,
  Ban,
  Globe,
  Plus,
  Trash2,
  Search,
  Download,
  Upload,
  RefreshCw,
  LogOut,
  UserCheck,
  Server,
  Terminal,
  Clock,
  CheckCircle,
  AlertTriangle,
  History,
  Layers,
  ArrowRight,
  ShieldAlert,
  Database,
  CheckCircle2,
  Lock,
  Key,
  FileCode,
  Check,
  Eye,
  EyeOff,
  FileKey,
  ArrowLeft,
  Sparkles,
  Split,
  CloudUpload,
  X
} from 'lucide-react';

export interface PendingChangeItem {
  id: string;
  timestamp: string;
  type: 'ADD' | 'REMOVE';
  listType: ListType;
  listLabel: string;
  value: string;
  policy: string;
  note?: string;
  user?: string;
}

export interface PushSummaryData {
  policy: string;
  timestamp: string;
  pushedChanges: PendingChangeItem[];
  allowedSenders: string[];
  blockedSenders: string[];
  allowedDomains: string[];
  blockedDomains: string[];
  changesByList: {
    allowed_senders: PendingChangeItem[];
    blocked_senders: PendingChangeItem[];
    allowed_domains: PendingChangeItem[];
    blocked_domains: PendingChangeItem[];
  };
  policiesImpacted: string[];
}

interface LiveSimulatorProps {
  config: AppConfig;
  initialTab?: ListType | 'sync' | 'audit' | 'config_center' | 'ldap_db';
  onLeaveConfigPage?: () => void;
  onTabChange?: (tab: ListType | 'sync' | 'audit' | 'config_center' | 'ldap_db') => void;
  triggerPushActionCount?: number;
  onPendingChangesCountChange?: (count: number) => void;
}

export const LiveSimulator: React.FC<LiveSimulatorProps> = ({
  config,
  initialTab = 'allowed_senders',
  onLeaveConfigPage,
  onTabChange,
  triggerPushActionCount,
  onPendingChangesCountChange,
}) => {
  // Authentication state
  const [isAuthenticated, setIsAuthenticated] = useState(true);
  const [loginUsername, setLoginUsername] = useState('jsmith');
  const [loginPassword, setLoginPassword] = useState('SecretPass123!');
  const [loginError, setLoginError] = useState<string | null>(null);
  const [isGroupMember, setIsGroupMember] = useState(true);
  const [ldapDcOnline, setLdapDcOnline] = useState(true);
  const [isFallbackLoggedIn, setIsFallbackLoggedIn] = useState(false);

  // Active Policy
  const [activePolicy, setActivePolicy] = useState(config.defaultPolicyName);
  const [policies, setPolicies] = useState<string[]>([
    config.defaultPolicyName,
    'Strict Anti-Spam Policy',
    'Executive Inbound Policy',
  ]);
  const [newPolicyName, setNewPolicyName] = useState('');

  // Active list tab
  const [activeTab, setActiveTab] = useState<ListType | 'sync' | 'audit' | 'config_center' | 'ldap_db'>(initialTab);

  const handleTabChange = (newTab: ListType | 'sync' | 'audit' | 'config_center' | 'ldap_db') => {
    setActiveTab(newTab);
    onTabChange?.(newTab);
    if (newTab !== 'config_center' && newTab !== 'ldap_db') {
      onLeaveConfigPage?.();
    }
  };

  useEffect(() => {
    if (initialTab) {
      setActiveTab(initialTab);
    }
  }, [initialTab]);
  const [searchQuery, setSearchQuery] = useState('');

  // Modals
  const [showAddModal, setShowAddModal] = useState(false);
  const [showBulkModal, setShowBulkModal] = useState(false);
  const [showSmartSortModal, setShowSmartSortModal] = useState(false);
  const [smartSortTarget, setSmartSortTarget] = useState<'blocked' | 'allowed'>('blocked');
  const [smartSortText, setSmartSortText] = useState('');
  const [smartSortNote, setSmartSortNote] = useState('');
  const [smartSortError, setSmartSortError] = useState<string | null>(null);
  const [singleValue, setSingleValue] = useState('');
  const [singleNote, setSingleNote] = useState('');
  const [bulkText, setBulkText] = useState('');
  const [addError, setAddError] = useState<string | null>(null);
  const [bulkError, setBulkError] = useState<string | null>(null);
  const [bannerMessage, setBannerMessage] = useState<{ type: 'success' | 'warning' | 'error'; text: string } | null>(null);
  const [showPendingStrip, setShowPendingStrip] = useState(false);

  // Auto-dismiss the Global Notification Banner appearing between toolbar buttons and list after 5 seconds
  useEffect(() => {
    if (!bannerMessage) return;
    const timer = setTimeout(() => {
      setBannerMessage(null);
    }, 5000);
    return () => clearTimeout(timer);
  }, [bannerMessage]);

  // State for Table 6: eop_auth_config in MariaDB (Private Key & Encrypted Passphrase)
  const [eopAuthRows, setEopAuthRows] = useState<EopAuthConfig[]>([
    {
      id: 1,
      tenant_id: config.tenantId,
      client_id: config.clientId,
      certificate_thumbprint: config.certificateThumbprint || '9A2F8B3C1D4E5F6A7B8C9D0E1F2A3B4C5D6E7F80',
      key_filename: config.keyFilename || 'eop-cert-private.key',
      private_key_pem: config.privateKeyPem || `-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Q3d7v5N8A9zX3lW2k1vJ8qY4t7rU9sP3mF2a1cB6d8e0f1g...[INITIAL_RSA_PRIVATE_KEY]...\n-----END RSA PRIVATE KEY-----`,
      encrypted_password: 'tq8fWk6y/7bH9s2m1vXy4z0A==',
      encryption_iv: 'G1a8V0kLm9Pq',
      encryption_tag: 'Xy8Z2n9Q1v0mK4lP7s3w8A==',
      organization: config.organization || 'corp.example.com',
      key_type: 'RSA_PEM',
      is_active: true,
      uploaded_by: 'SYSTEM',
      created_at: '2026-09-26 12:00:00',
      updated_at: '2026-09-26 12:00:00',
    },
  ]);

  // EOP Private Key Upload & Config editing state
  const [keyUploadFileName, setKeyUploadFileName] = useState<string>('eop-cert-private.key');
  const [keyUploadText, setKeyUploadText] = useState<string>(config.privateKeyPem || `-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Q3d7v5N8A9zX3lW2k1vJ8qY4t7rU9sP3mF2a1cB6d8e0f1g\n2h3i4j5k6l7m8n9o0p1q2r3s4t5u6v7w8x9y0z1A2B3C4D5E6F7G8H9I0J1K2L3M\n4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7a8b9c0d1e2f3g4h5i6j7k8l9m0n1o2p3q4r5s\n6t7u8v9w0x1y2z3A4B5C6D7E8F9G0H1I2J3K4L5M6N7O8P9Q0R1S2T3U4V5W6X7Y\n-----END RSA PRIVATE KEY-----`);
  const [keyPassword, setKeyPassword] = useState<string>(config.keyPassword || 'P@ssphrase_Secure_Cert_2026');
  const [keyThumbprint, setKeyThumbprint] = useState<string>(config.certificateThumbprint || '9A2F8B3C1D4E5F6A7B8C9D0E1F2A3B4C5D6E7F80');
  const [keyTenantId, setKeyTenantId] = useState<string>(config.tenantId);
  const [keyClientId, setKeyClientId] = useState<string>(config.clientId);
  const [keyOrganization, setKeyOrganization] = useState<string>(config.organization || 'corp.example.com');
  const [keyTestStatus, setKeyTestStatus] = useState<string | null>(null);
  const [keySaveMessage, setKeySaveMessage] = useState<string | null>(null);
  const [showKeyPassword, setShowKeyPassword] = useState<boolean>(false);
  const [configSubTab, setConfigSubTab] = useState<'all' | 'eop_key' | 'ldap_db'>('all');

  // State for Table 5: eop_ldap_config in MariaDB
  const [ldapDbRows, setLdapDbRows] = useState<LdapDbConfig[]>([
    {
      id: 1,
      host: config.ldapHost,
      port: config.ldapPort,
      protocol: config.ldapProtocol || 'ldap',
      use_ssl: config.ldapUseSsl,
      use_tls: config.ldapUseTls,
      base_dn: config.ldapBaseDn,
      authorized_group_dn: config.ldapGroupDn,
      bind_dn: config.ldapBindDn,
      bind_password: '••••••••••••',
      account_suffix: `@${config.ldapDomain.toLowerCase()}.example.com`,
      netbios_domain: config.ldapDomain,
      timeout_seconds: 5,
      is_active: true,
      updated_by: 'SYSTEM',
      updated_at: '2026-09-26 12:00:00',
    },
  ]);

  // Editing state for LDAP config in simulator
  const [ldapEditHost, setLdapEditHost] = useState(config.ldapHost);
  const [ldapEditPort, setLdapEditPort] = useState(config.ldapPort);
  const [ldapEditProto, setLdapEditProto] = useState<'ldap' | 'ldaps' | 'starttls'>(config.ldapProtocol || 'ldap');
  const [ldapEditBaseDn, setLdapEditBaseDn] = useState(config.ldapBaseDn);
  const [ldapEditGroupDn, setLdapEditGroupDn] = useState(config.ldapGroupDn);
  const [ldapEditBindDn, setLdapEditBindDn] = useState(config.ldapBindDn);
  const [ldapEditBindPass, setLdapEditBindPass] = useState(config.ldapBindPass || '');
  const [showLdapBindPass, setShowLdapBindPass] = useState(false);
  const [ldapTestStatus, setLdapTestStatus] = useState<string | null>(null);
  const [ldapSaveMessage, setLdapSaveMessage] = useState<string | null>(null);

  // Sync execution simulation
  const [syncLoading, setSyncLoading] = useState(false);
  const [syncActionType, setSyncActionType] = useState<'pull' | 'push'>('pull');
  const [showPushConfirmModal, setShowPushConfirmModal] = useState(false);

  // Staged pending changes across all 4 tables waiting to be pushed to EOP
  const [pendingChanges, setPendingChanges] = useState<PendingChangeItem[]>([
    {
      id: 'pc-1',
      timestamp: '2026-09-26 10:15:00',
      type: 'ADD',
      listType: 'allowed_senders',
      listLabel: 'Allowed Senders',
      value: 'billing@strategic-partner.com',
      policy: config.defaultPolicyName,
      note: 'Verified corporate invoicing vendor - Ticket #INC-9482',
      user: 'jsmith',
    },
    {
      id: 'pc-2',
      timestamp: '2026-09-26 11:20:00',
      type: 'ADD',
      listType: 'allowed_senders',
      listLabel: 'Allowed Senders',
      value: 'alerts@critical-saas-monitor.net',
      policy: config.defaultPolicyName,
      note: 'Infrastructure alert notification webhook',
      user: 'jsmith',
    },
    {
      id: 'pc-3',
      timestamp: '2026-09-26 15:40:00',
      type: 'ADD',
      listType: 'blocked_senders',
      listLabel: 'Blocked Senders',
      value: 'phishing-alert@fake-login-service.info',
      policy: config.defaultPolicyName,
      note: 'Confirmed credential harvesting campaign',
      user: 'jsmith',
    },
    {
      id: 'pc-4',
      timestamp: '2026-09-26 16:05:00',
      type: 'ADD',
      listType: 'blocked_domains',
      listLabel: 'Blocked Domains',
      value: 'malicious-phishing-host.xyz',
      policy: config.defaultPolicyName,
      note: 'Zero-day phishing infrastructure',
      user: 'jsmith',
    },
  ]);

  const [pushSummaryModal, setPushSummaryModal] = useState<PushSummaryData | null>(null);
  const [pushSummaryTab, setPushSummaryTab] = useState<'changes' | 'all_entries' | 'powershell'>('changes');
  const [duplicateWarningPopup, setDuplicateWarningPopup] = useState<{
    value: string;
    listLabel: string;
    policy: string;
    existingNote?: string;
    addedBy?: string;
    createdAt?: string;
    isConflict?: boolean;
    conflictList?: string;
  } | null>(null);
  const [deleteConfirmItem, setDeleteConfirmItem] = useState<{ id: number; value: string; tab: ListType } | null>(null);
  const [lastSyncResult, setLastSyncResult] = useState<{
    timestamp: string;
    status: 'success' | 'failed';
    direction: 'pull' | 'push';
    message: string;
  } | null>({
    timestamp: '2026-09-26 14:30:12',
    status: 'success',
    direction: 'pull',
    message: 'Cron Pull executed successfully: Retrieved remote entries from Exchange Online into MariaDB (Pull-Only).',
  });

  // State for the 4 separate individual tables
  const [allowedSenders, setAllowedSenders] = useState<ListItem[]>([
    {
      id: 1,
      policy_name: config.defaultPolicyName,
      value: 'billing@strategic-partner.com',
      note: 'Verified corporate invoicing vendor - Ticket #INC-9482',
      added_by: 'jsmith',
      created_at: '2026-09-24 10:15:00',
      updated_at: '2026-09-24 10:15:00',
    },
    {
      id: 2,
      policy_name: config.defaultPolicyName,
      value: 'alerts@critical-saas-monitor.net',
      note: 'Infrastructure alert notification webhook',
      added_by: 'jsmith',
      created_at: '2026-09-25 11:20:00',
      updated_at: '2026-09-25 11:20:00',
    },
    {
      id: 3,
      policy_name: 'Strict Anti-Spam Policy',
      value: 'cfo@subsidiary-group.com',
      note: 'Executive financial reporting contact',
      added_by: 'ad_admin',
      created_at: '2026-09-26 09:00:00',
      updated_at: '2026-09-26 09:00:00',
    },
  ]);

  const [blockedSenders, setBlockedSenders] = useState<ListItem[]>([
    {
      id: 1,
      policy_name: config.defaultPolicyName,
      value: 'phishing-alert@fake-login-service.info',
      note: 'Confirmed credential harvesting campaign',
      added_by: 'jsmith',
      created_at: '2026-09-23 15:40:00',
      updated_at: '2026-09-23 15:40:00',
    },
    {
      id: 2,
      policy_name: config.defaultPolicyName,
      value: 'spammer@unsolicited-marketing-blast.xyz',
      note: 'Repeat junk mail sender ignoring opt-outs',
      added_by: 'jsmith',
      created_at: '2026-09-25 08:30:00',
      updated_at: '2026-09-25 08:30:00',
    },
  ]);

  const [allowedDomains, setAllowedDomains] = useState<ListItem[]>([
    {
      id: 1,
      policy_name: config.defaultPolicyName,
      value: 'trustedpartner.com',
      note: 'B2B supply chain vendor domain whitelist',
      added_by: 'jsmith',
      created_at: '2026-09-20 14:00:00',
      updated_at: '2026-09-20 14:00:00',
    },
    {
      id: 2,
      policy_name: config.defaultPolicyName,
      value: 'global-logistics.org',
      note: 'Logistics partner primary communications domain',
      added_by: 'jsmith',
      created_at: '2026-09-21 16:45:00',
      updated_at: '2026-09-21 16:45:00',
    },
  ]);

  const [blockedDomains, setBlockedDomains] = useState<ListItem[]>([
    {
      id: 1,
      policy_name: config.defaultPolicyName,
      value: 'suspicious-fast-payouts.top',
      note: 'Malicious domain discovered in SOC telemetry',
      added_by: 'jsmith',
      created_at: '2026-09-22 09:12:00',
      updated_at: '2026-09-22 09:12:00',
    },
    {
      id: 2,
      policy_name: config.defaultPolicyName,
      value: 'phish-cloud-auth.biz',
      note: 'Targeted spear phishing lookalike domain',
      added_by: 'jsmith',
      created_at: '2026-09-24 13:05:00',
      updated_at: '2026-09-24 13:05:00',
    },
  ]);

  // Audit Log State
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([
    {
      id: 101,
      timestamp: '2026-09-26 14:30:12',
      username: 'jsmith',
      action: 'SYNC',
      list_type: 'SYSTEM',
      policy_name: config.defaultPolicyName,
      target_value: 'ALL',
      details: 'Executed Set-HostedContentFilterPolicy via PowerShell',
      ip_address: '192.168.10.105',
    },
    {
      id: 100,
      timestamp: '2026-09-25 11:20:00',
      username: 'jsmith',
      action: 'ADD',
      list_type: 'allowed_senders',
      policy_name: config.defaultPolicyName,
      target_value: 'alerts@critical-saas-monitor.net',
      details: 'Inserted into eop_allowed_senders',
      ip_address: '192.168.10.105',
    },
  ]);

  // Trigger push modal when instructed externally (e.g. from top Navbar)
  useEffect(() => {
    if (triggerPushActionCount && triggerPushActionCount > 0) {
      setShowPushConfirmModal(true);
    }
  }, [triggerPushActionCount]);

  // Synchronize pending changes count with parent component
  useEffect(() => {
    onPendingChangesCountChange?.(pendingChanges.length);
  }, [pendingChanges, onPendingChangesCountChange]);

  // Auto-dismiss the Staged Pending Changes Notice Strip appearing between buttons and list after 6 seconds
  useEffect(() => {
    if (pendingChanges.length > 0) {
      setShowPendingStrip(true);
      const timer = setTimeout(() => {
        setShowPendingStrip(false);
      }, 6000);
      return () => clearTimeout(timer);
    } else {
      setShowPendingStrip(false);
    }
  }, [pendingChanges.length]);

  // Total count of staged entries for active policy
  const totalStagedItems = useMemo(() => {
    return (
      allowedSenders.filter((i) => i.policy_name === activePolicy).length +
      blockedSenders.filter((i) => i.policy_name === activePolicy).length +
      allowedDomains.filter((i) => i.policy_name === activePolicy).length +
      blockedDomains.filter((i) => i.policy_name === activePolicy).length
    );
  }, [allowedSenders, blockedSenders, allowedDomains, blockedDomains, activePolicy]);

  // Total count of all items across ALL policies and tables
  const totalAllItemsCount = useMemo(() => {
    return allowedSenders.length + blockedSenders.length + allowedDomains.length + blockedDomains.length;
  }, [allowedSenders, blockedSenders, allowedDomains, blockedDomains]);

  // Pending changes for currently selected policy across all 4 tables
  const policyPendingChanges = useMemo(() => {
    return pendingChanges.filter((c) => c.policy === activePolicy);
  }, [pendingChanges, activePolicy]);

  // Grouped pending changes across ALL tables and ALL policies
  const allPendingByList = useMemo(() => {
    return {
      allowed_senders: pendingChanges.filter((c) => c.listType === 'allowed_senders'),
      blocked_senders: pendingChanges.filter((c) => c.listType === 'blocked_senders'),
      allowed_domains: pendingChanges.filter((c) => c.listType === 'allowed_domains'),
      blocked_domains: pendingChanges.filter((c) => c.listType === 'blocked_domains'),
    };
  }, [pendingChanges]);

  // Grouped pending changes per table for active policy
  const pendingByList = useMemo(() => {
    return {
      allowed_senders: policyPendingChanges.filter((c) => c.listType === 'allowed_senders'),
      blocked_senders: policyPendingChanges.filter((c) => c.listType === 'blocked_senders'),
      allowed_domains: policyPendingChanges.filter((c) => c.listType === 'allowed_domains'),
      blocked_domains: policyPendingChanges.filter((c) => c.listType === 'blocked_domains'),
    };
  }, [policyPendingChanges]);

  // Helper to get active list state
  const getCurrentList = (): ListItem[] => {
    switch (activeTab) {
      case 'allowed_senders':
        return allowedSenders.filter((item) => item.policy_name === activePolicy);
      case 'blocked_senders':
        return blockedSenders.filter((item) => item.policy_name === activePolicy);
      case 'allowed_domains':
        return allowedDomains.filter((item) => item.policy_name === activePolicy);
      case 'blocked_domains':
        return blockedDomains.filter((item) => item.policy_name === activePolicy);
      default:
        return [];
    }
  };

  // Helper to add audit log
  const logAction = (
    action: AuditLogEntry['action'],
    listType: AuditLogEntry['list_type'],
    target: string,
    details: string
  ) => {
    const newEntry: AuditLogEntry = {
      id: Date.now(),
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      username: loginUsername,
      action,
      list_type: listType,
      policy_name: activePolicy,
      target_value: target,
      details,
      ip_address: '192.168.10.105',
    };
    setAuditLogs((prev) => [newEntry, ...prev]);
  };

  // Login handler
  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError(null);

    const enteredUser = loginUsername.trim();
    const enteredPass = loginPassword;

    if (!enteredUser || !enteredPass) {
      setLoginError('Please enter both username and password.');
      return;
    }

    const fallbackUser = config.fallbackAdminUsername || 'eopadmin';
    const fallbackPass = config.fallbackAdminPassword || 'Emergency#Admin2026!';
    const fallbackEnabled = config.fallbackAdminEnabled !== false;

    // Check if user is logging in with the Emergency Fallback Non-LDAP Administrator account
    if (fallbackEnabled && enteredUser.toLowerCase() === fallbackUser.toLowerCase()) {
      if (enteredPass === fallbackPass) {
        setIsAuthenticated(true);
        setIsFallbackLoggedIn(true);
        logAction(
          'LOGIN',
          'SYSTEM',
          enteredUser,
          ldapDcOnline
            ? 'Emergency Non-LDAP Fallback Administrator Login (Direct Local Authenticated)'
            : 'Emergency Non-LDAP Fallback Administrator Login (Active Directory LDAP connection failed / offline)'
        );
        return;
      } else {
        setLoginError('Invalid emergency fallback administrator credentials. Check password configured in Setup.');
        return;
      }
    }

    // Check if Active Directory LDAP server is offline / unreachable
    if (!ldapDcOnline) {
      setLoginError(
        `Active Directory LDAP Connection Failure: Could not reach Domain Controller at ${config.ldapHost}:${config.ldapPort}. Connection timed out after 5000ms. ${
          fallbackEnabled
            ? `Emergency non-LDAP fallback account is enabled. You can authenticate using fallback administrator '${fallbackUser}'.`
            : 'No emergency fallback administrator configured.'
        }`
      );
      return;
    }

    if (!isGroupMember) {
      setLoginError(
        `Access Denied: Account '${enteredUser}' authenticated against Active Directory, but is NOT a member of authorized Group DN: ${config.ldapGroupDn}`
      );
      return;
    }

    setIsAuthenticated(true);
    setIsFallbackLoggedIn(false);
    logAction('LOGIN', 'SYSTEM', enteredUser, 'Authenticated via Active Directory LDAP');
  };

  // Add Single item with strict duplicate prevention
  const handleAddSingle = (e: React.FormEvent) => {
    e.preventDefault();
    setAddError(null);
    const val = singleValue.trim().toLowerCase();
    if (!val) return;

    // Email or domain validation
    if (activeTab === 'allowed_senders' || activeTab === 'blocked_senders') {
      if (!val.includes('@') || !val.includes('.')) {
        setAddError('Please enter a valid email address (e.g. user@domain.com)');
        return;
      }
    } else {
      if (!val.includes('.')) {
        setAddError('Please enter a valid domain name (e.g. domain.com or *.domain.com)');
        return;
      }
    }

    // 1. Strict Duplicate Check within current list for active policy
    const currentItems = getCurrentList();
    const existingItem = currentItems.find(
      (item) => item.value.toLowerCase() === val
    );

    const listLabel = activeTab.replace('_', ' ');

    if (existingItem) {
      setAddError(
        `Duplicate Entry: "${val}" already exists in ${listLabel} for policy "${activePolicy}". Duplicate entries are not allowed.`
      );
      // Trigger user-facing popup detailing the duplicate
      setDuplicateWarningPopup({
        value: val,
        listLabel: listLabel.toUpperCase(),
        policy: activePolicy,
        existingNote: existingItem.note,
        addedBy: existingItem.added_by,
        createdAt: existingItem.created_at,
        isConflict: false,
      });
      return;
    }

    // 2. Cross-list duplicate/conflict check:
    // If adding to Allowed Senders, verify it's not in Blocked Senders (and vice versa)
    if (activeTab === 'allowed_senders') {
      const conflictItem = blockedSenders.find(
        (i) => i.policy_name === activePolicy && i.value.toLowerCase() === val
      );
      if (conflictItem) {
        setAddError(
          `Conflict: "${val}" is already in Blocked Senders for policy "${activePolicy}". Remove it from Blocked Senders before adding it to Allowed Senders.`
        );
        setDuplicateWarningPopup({
          value: val,
          listLabel: 'ALLOWED SENDERS',
          policy: activePolicy,
          existingNote: conflictItem.note,
          addedBy: conflictItem.added_by,
          createdAt: conflictItem.created_at,
          isConflict: true,
          conflictList: 'BLOCKED SENDERS (eop_blocked_senders)',
        });
        return;
      }
    } else if (activeTab === 'blocked_senders') {
      const conflictItem = allowedSenders.find(
        (i) => i.policy_name === activePolicy && i.value.toLowerCase() === val
      );
      if (conflictItem) {
        setAddError(
          `Conflict: "${val}" is already in Allowed Senders for policy "${activePolicy}". Remove it from Allowed Senders before adding it to Blocked Senders.`
        );
        setDuplicateWarningPopup({
          value: val,
          listLabel: 'BLOCKED SENDERS',
          policy: activePolicy,
          existingNote: conflictItem.note,
          addedBy: conflictItem.added_by,
          createdAt: conflictItem.created_at,
          isConflict: true,
          conflictList: 'ALLOWED SENDERS (eop_allowed_senders)',
        });
        return;
      }
    } else if (activeTab === 'allowed_domains') {
      const conflictItem = blockedDomains.find(
        (i) => i.policy_name === activePolicy && i.value.toLowerCase() === val
      );
      if (conflictItem) {
        setAddError(
          `Conflict: "${val}" is already in Blocked Domains for policy "${activePolicy}". Remove it from Blocked Domains before adding it to Allowed Domains.`
        );
        setDuplicateWarningPopup({
          value: val,
          listLabel: 'ALLOWED DOMAINS',
          policy: activePolicy,
          existingNote: conflictItem.note,
          addedBy: conflictItem.added_by,
          createdAt: conflictItem.created_at,
          isConflict: true,
          conflictList: 'BLOCKED DOMAINS (eop_blocked_domains)',
        });
        return;
      }
    } else if (activeTab === 'blocked_domains') {
      const conflictItem = allowedDomains.find(
        (i) => i.policy_name === activePolicy && i.value.toLowerCase() === val
      );
      if (conflictItem) {
        setAddError(
          `Conflict: "${val}" is already in Allowed Domains for policy "${activePolicy}". Remove it from Allowed Domains before adding it to Blocked Domains.`
        );
        setDuplicateWarningPopup({
          value: val,
          listLabel: 'BLOCKED DOMAINS',
          policy: activePolicy,
          existingNote: conflictItem.note,
          addedBy: conflictItem.added_by,
          createdAt: conflictItem.created_at,
          isConflict: true,
          conflictList: 'ALLOWED DOMAINS (eop_allowed_domains)',
        });
        return;
      }
    }

    const newItem: ListItem = {
      id: Date.now(),
      policy_name: activePolicy,
      value: val,
      note: singleNote.trim() || 'Direct addition via Web App',
      added_by: loginUsername,
      created_at: new Date().toISOString().replace('T', ' ').substring(0, 19),
      updated_at: new Date().toISOString().replace('T', ' ').substring(0, 19),
    };

    if (activeTab === 'allowed_senders') setAllowedSenders((prev) => [newItem, ...prev]);
    if (activeTab === 'blocked_senders') setBlockedSenders((prev) => [newItem, ...prev]);
    if (activeTab === 'allowed_domains') setAllowedDomains((prev) => [newItem, ...prev]);
    if (activeTab === 'blocked_domains') setBlockedDomains((prev) => [newItem, ...prev]);

    // Stage pending change for EOP push
    const listLabelMap: Record<ListType, string> = {
      allowed_senders: 'Allowed Senders',
      blocked_senders: 'Blocked Senders',
      allowed_domains: 'Allowed Domains',
      blocked_domains: 'Blocked Domains',
    };
    const stagedChange: PendingChangeItem = {
      id: `pc-${Date.now()}`,
      timestamp: newItem.created_at,
      type: 'ADD',
      listType: activeTab as ListType,
      listLabel: listLabelMap[activeTab as ListType],
      value: val,
      policy: activePolicy,
      note: newItem.note,
      user: loginUsername,
    };
    setPendingChanges((prev) => [stagedChange, ...prev]);

    logAction('ADD', activeTab as ListType, val, `Added to eop_${activeTab}`);
    setSingleValue('');
    setSingleNote('');
    setAddError(null);
    setShowAddModal(false);
    setBannerMessage({
      type: 'success',
      text: `Successfully added "${val}" to ${listLabel} (policy: ${activePolicy})`
    });
  };

  // Bulk import with duplicate detection & reporting
  const handleBulkImport = (e: React.FormEvent) => {
    e.preventDefault();
    setBulkError(null);
    const lines = bulkText.split('\n');
    const now = new Date().toISOString().replace('T', ' ').substring(0, 19);

    const currentItems = getCurrentList();
    const existingValuesSet = new Set(
      currentItems.map((item) => item.value.toLowerCase())
    );

    const seenInBatch = new Set<string>();
    const newItems: ListItem[] = [];
    let duplicateCount = 0;
    let invalidCount = 0;

    lines.forEach((line) => {
      const parts = line.split(',');
      const val = parts[0]?.trim().toLowerCase();
      const note = parts[1]?.trim() || 'Bulk CSV imported';

      if (!val || val.length < 3) return;

      // Validation
      if (activeTab === 'allowed_senders' || activeTab === 'blocked_senders') {
        if (!val.includes('@') || !val.includes('.')) {
          invalidCount++;
          return;
        }
      } else {
        if (!val.includes('.')) {
          invalidCount++;
          return;
        }
      }

      // Check if duplicate in current batch or already exists in this list
      if (existingValuesSet.has(val) || seenInBatch.has(val)) {
        duplicateCount++;
        return;
      }

      seenInBatch.add(val);
      newItems.push({
        id: Date.now() + Math.floor(Math.random() * 100000) + newItems.length,
        policy_name: activePolicy,
        value: val,
        note,
        added_by: loginUsername,
        created_at: now,
        updated_at: now,
      });
    });

    if (newItems.length === 0) {
      if (duplicateCount > 0) {
        setBulkError(
          `Duplicate Prevention: All ${duplicateCount} entries already exist in this list. No duplicate records were added.`
        );
      } else if (invalidCount > 0) {
        setBulkError(`Format Error: All ${invalidCount} entries had invalid syntax.`);
      } else {
        setBulkError('No valid items found in import data.');
      }
      return;
    }

    if (activeTab === 'allowed_senders') setAllowedSenders((prev) => [...newItems, ...prev]);
    if (activeTab === 'blocked_senders') setBlockedSenders((prev) => [...newItems, ...prev]);
    if (activeTab === 'allowed_domains') setAllowedDomains((prev) => [...newItems, ...prev]);
    if (activeTab === 'blocked_domains') setBlockedDomains((prev) => [...newItems, ...prev]);

    // Stage pending changes for EOP push
    const listLabelMap: Record<ListType, string> = {
      allowed_senders: 'Allowed Senders',
      blocked_senders: 'Blocked Senders',
      allowed_domains: 'Allowed Domains',
      blocked_domains: 'Blocked Domains',
    };
    const bulkStagedChanges: PendingChangeItem[] = newItems.map((item, idx) => ({
      id: `pc-${Date.now()}-${idx}`,
      timestamp: now,
      type: 'ADD',
      listType: activeTab as ListType,
      listLabel: listLabelMap[activeTab as ListType],
      value: item.value,
      policy: activePolicy,
      note: item.note,
      user: loginUsername,
    }));
    setPendingChanges((prev) => [...bulkStagedChanges, ...prev]);

    const msg = duplicateCount > 0
      ? `Bulk imported ${newItems.length} new items. Skipped ${duplicateCount} duplicate entries.`
      : `Bulk imported ${newItems.length} items successfully.`;

    logAction('ADD', activeTab as ListType, `${newItems.length} items`, msg);
    setBulkText('');
    setBulkError(null);
    setShowBulkModal(false);
    setBannerMessage({
      type: duplicateCount > 0 ? 'warning' : 'success',
      text: msg
    });
  };

  // Smart Sorter classification engine (auto-sorts senders and domains)
  const smartSortTriage = useMemo(() => {
    const lines = smartSortText.split('\n');
    const senders: { value: string; note: string; isDuplicate: boolean; duplicateReason?: string }[] = [];
    const domains: { value: string; note: string; isDuplicate: boolean; duplicateReason?: string }[] = [];
    const invalid: { value: string; line: string; reason: string }[] = [];

    const targetSendersList = smartSortTarget === 'blocked' ? blockedSenders : allowedSenders;
    const targetDomainsList = smartSortTarget === 'blocked' ? blockedDomains : allowedDomains;

    const existingSenders = new Set(
      targetSendersList
        .filter((i) => i.policy_name === activePolicy)
        .map((i) => i.value.toLowerCase())
    );
    const existingDomains = new Set(
      targetDomainsList
        .filter((i) => i.policy_name === activePolicy)
        .map((i) => i.value.toLowerCase())
    );

    const seenSendersInBatch = new Set<string>();
    const seenDomainsInBatch = new Set<string>();

    for (const rawLine of lines) {
      const trimmed = rawLine.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;

      const parts = trimmed.split(',');
      const val = parts[0]?.trim().toLowerCase();
      const note = parts[1]?.trim() || smartSortNote.trim() || 'Smart Auto-Sorted';

      if (!val) continue;

      if (val.includes('@')) {
        // Classified as Sender Email
        if (!val.includes('.') || val.length < 5 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val)) {
          invalid.push({ value: val, line: trimmed, reason: 'Invalid email address format' });
        } else {
          const isDup = existingSenders.has(val) || seenSendersInBatch.has(val);
          senders.push({
            value: val,
            note,
            isDuplicate: isDup,
            duplicateReason: existingSenders.has(val)
              ? `Already in ${smartSortTarget === 'blocked' ? 'Blocked' : 'Allowed'} Senders table`
              : 'Duplicate within batch',
          });
          seenSendersInBatch.add(val);
        }
      } else {
        // Classified as Domain Name
        const cleanDomain = val.startsWith('*.') ? val.substring(2) : val;
        if (!cleanDomain.includes('.') || cleanDomain.length < 3) {
          invalid.push({ value: val, line: trimmed, reason: 'Invalid domain name format' });
        } else {
          const isDup = existingDomains.has(val) || seenDomainsInBatch.has(val);
          domains.push({
            value: val,
            note,
            isDuplicate: isDup,
            duplicateReason: existingDomains.has(val)
              ? `Already in ${smartSortTarget === 'blocked' ? 'Blocked' : 'Allowed'} Domains table`
              : 'Duplicate within batch',
          });
          seenDomainsInBatch.add(val);
        }
      }
    }

    const validSenders = senders.filter((s) => !s.isDuplicate);
    const validDomains = domains.filter((d) => !d.isDuplicate);
    const duplicateSendersCount = senders.filter((s) => s.isDuplicate).length;
    const duplicateDomainsCount = domains.filter((d) => d.isDuplicate).length;

    return {
      senders,
      domains,
      invalid,
      validSenders,
      validDomains,
      duplicateCount: duplicateSendersCount + duplicateDomainsCount,
      duplicateSendersCount,
      duplicateDomainsCount,
      totalValid: validSenders.length + validDomains.length,
    };
  }, [
    smartSortText,
    smartSortTarget,
    smartSortNote,
    activePolicy,
    allowedSenders,
    blockedSenders,
    allowedDomains,
    blockedDomains,
  ]);

  // Execute Smart Sort import
  const handleExecuteSmartSort = (e: React.FormEvent) => {
    e.preventDefault();
    setSmartSortError(null);

    const {
      validSenders,
      validDomains,
      duplicateCount,
      duplicateSendersCount,
      duplicateDomainsCount,
      invalid,
    } = smartSortTriage;

    if (validSenders.length === 0 && validDomains.length === 0) {
      if (duplicateCount > 0) {
        setSmartSortError(
          `All ${duplicateCount} entries already exist in the database for policy "${activePolicy}". No duplicates were added.`
        );
      } else if (invalid.length > 0) {
        setSmartSortError('All entries in the list had invalid syntax. Please verify email and domain formats.');
      } else {
        setSmartSortError('Please paste at least one sender email or domain name.');
      }
      return;
    }

    const now = new Date().toISOString().replace('T', ' ').substring(0, 19);

    const newSenderItems: ListItem[] = validSenders.map((s, idx) => ({
      id: Date.now() + Math.floor(Math.random() * 100000) + idx,
      policy_name: activePolicy,
      value: s.value,
      note: s.note,
      added_by: loginUsername,
      created_at: now,
      updated_at: now,
    }));

    const newDomainItems: ListItem[] = validDomains.map((d, idx) => ({
      id: Date.now() + 500000 + Math.floor(Math.random() * 100000) + idx,
      policy_name: activePolicy,
      value: d.value,
      note: d.note,
      added_by: loginUsername,
      created_at: now,
      updated_at: now,
    }));

    const targetLabel = smartSortTarget === 'blocked' ? 'Blocked' : 'Allowed';

    if (smartSortTarget === 'blocked') {
      if (newSenderItems.length > 0) {
        setBlockedSenders((prev) => [...newSenderItems, ...prev]);
        logAction(
          'ADD',
          'blocked_senders',
          `${newSenderItems.length} senders`,
          `Smart-sorted ${newSenderItems.length} senders into eop_blocked_senders`
        );
      }
      if (newDomainItems.length > 0) {
        setBlockedDomains((prev) => [...newDomainItems, ...prev]);
        logAction(
          'ADD',
          'blocked_domains',
          `${newDomainItems.length} domains`,
          `Smart-sorted ${newDomainItems.length} domains into eop_blocked_domains`
        );
      }
    } else {
      if (newSenderItems.length > 0) {
        setAllowedSenders((prev) => [...newSenderItems, ...prev]);
        logAction(
          'ADD',
          'allowed_senders',
          `${newSenderItems.length} senders`,
          `Smart-sorted ${newSenderItems.length} senders into eop_allowed_senders`
        );
      }
      if (newDomainItems.length > 0) {
        setAllowedDomains((prev) => [...newDomainItems, ...prev]);
        logAction(
          'ADD',
          'allowed_domains',
          `${newDomainItems.length} domains`,
          `Smart-sorted ${newDomainItems.length} domains into eop_allowed_domains`
        );
      }
    }

    // Stage smart sorted items for EOP push
    const smartStagedChanges: PendingChangeItem[] = [
      ...newSenderItems.map((s, idx) => ({
        id: `pc-smart-s-${Date.now()}-${idx}`,
        timestamp: now,
        type: 'ADD' as const,
        listType: (smartSortTarget === 'blocked' ? 'blocked_senders' : 'allowed_senders') as ListType,
        listLabel: smartSortTarget === 'blocked' ? 'Blocked Senders' : 'Allowed Senders',
        value: s.value,
        policy: activePolicy,
        note: s.note,
        user: loginUsername,
      })),
      ...newDomainItems.map((d, idx) => ({
        id: `pc-smart-d-${Date.now()}-${idx}`,
        timestamp: now,
        type: 'ADD' as const,
        listType: (smartSortTarget === 'blocked' ? 'blocked_domains' : 'allowed_domains') as ListType,
        listLabel: smartSortTarget === 'blocked' ? 'Blocked Domains' : 'Allowed Domains',
        value: d.value,
        policy: activePolicy,
        note: d.note,
        user: loginUsername,
      })),
    ];
    if (smartStagedChanges.length > 0) {
      setPendingChanges((prev) => [...smartStagedChanges, ...prev]);
    }

    const msg =
      `Smart Sort Complete: Sorted ${newSenderItems.length} senders into ${targetLabel} Senders (eop_${smartSortTarget}_senders) and ${newDomainItems.length} domains into ${targetLabel} Domains (eop_${smartSortTarget}_domains).` +
      (duplicateCount > 0
        ? ` Skipped ${duplicateCount} duplicate entries (${duplicateSendersCount} senders, ${duplicateDomainsCount} domains).`
        : '');

    setBannerMessage({
      type: duplicateCount > 0 ? 'warning' : 'success',
      text: msg,
    });

    setShowSmartSortModal(false);
    setSmartSortText('');
    setSmartSortNote('');
    setSmartSortError(null);
  };

  // Delete item - open confirmation modal
  const promptDelete = (id: number, val: string) => {
    setDeleteConfirmItem({ id, value: val, tab: activeTab as ListType });
  };

  const confirmDelete = () => {
    if (!deleteConfirmItem) return;
    const { id, value: val, tab } = deleteConfirmItem;

    if (tab === 'allowed_senders') setAllowedSenders((prev) => prev.filter((i) => i.id !== id));
    if (tab === 'blocked_senders') setBlockedSenders((prev) => prev.filter((i) => i.id !== id));
    if (tab === 'allowed_domains') setAllowedDomains((prev) => prev.filter((i) => i.id !== id));
    if (tab === 'blocked_domains') setBlockedDomains((prev) => prev.filter((i) => i.id !== id));

    // Stage pending removal for EOP push
    const listLabelMap: Record<ListType, string> = {
      allowed_senders: 'Allowed Senders',
      blocked_senders: 'Blocked Senders',
      allowed_domains: 'Allowed Domains',
      blocked_domains: 'Blocked Domains',
    };
    const stagedRemove: PendingChangeItem = {
      id: `pc-del-${Date.now()}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      type: 'REMOVE',
      listType: tab,
      listLabel: listLabelMap[tab],
      value: val,
      policy: activePolicy,
      note: `Removal from eop_${tab}`,
      user: loginUsername,
    };
    setPendingChanges((prev) => [stagedRemove, ...prev]);

    logAction('REMOVE', tab, val, `Deleted from eop_${tab}`);
    setDeleteConfirmItem(null);
    setBannerMessage({
      type: 'success',
      text: `Deleted "${val}" from ${listLabelMap[tab]} (Staged for EOP push)`
    });
  };

  // Trigger simulated Exchange sync (Pull-Only for Cron or Manual Push for Admin)
  const handleTriggerSync = (direction: 'pull' | 'push' = 'pull') => {
    setSyncLoading(true);
    setSyncActionType(direction);
    setTimeout(() => {
      setSyncLoading(false);
      const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
      if (direction === 'pull') {
        setLastSyncResult({
          timestamp,
          status: 'success',
          direction: 'pull',
          message: `Cron Pull completed successfully for policy '${activePolicy}'. Retrieved remote configuration via Get-HostedContentFilterPolicy and reconciled MariaDB tables. Note: Local entries were not pushed to EOP (Cron job is strictly Pull-Only).`,
        });
        logAction('SYNC', 'SYSTEM', activePolicy, 'Automated cron pull from EOP completed (Pull-Only)');
      } else {
        // Collect all pending changes across all 4 tables and all policies waiting to be pushed
        const changesToPush = [...pendingChanges];

        // Group changes by target list
        const changesAllowedSenders = changesToPush.filter((c) => c.listType === 'allowed_senders');
        const changesBlockedSenders = changesToPush.filter((c) => c.listType === 'blocked_senders');
        const changesAllowedDomains = changesToPush.filter((c) => c.listType === 'allowed_domains');
        const changesBlockedDomains = changesToPush.filter((c) => c.listType === 'blocked_domains');

        // Policies impacted
        const policiesImpacted = Array.from(new Set(changesToPush.map((c) => c.policy)));
        if (policiesImpacted.length === 0) {
          policiesImpacted.push(activePolicy);
        }

        const policyAllowedSenders = allowedSenders.filter((i) => i.policy_name === activePolicy).map((i) => i.value);
        const policyBlockedSenders = blockedSenders.filter((i) => i.policy_name === activePolicy).map((i) => i.value);
        const policyAllowedDomains = allowedDomains.filter((i) => i.policy_name === activePolicy).map((i) => i.value);
        const policyBlockedDomains = blockedDomains.filter((i) => i.policy_name === activePolicy).map((i) => i.value);

        // Clear staged pending changes now that they are pushed to Exchange Online
        setPendingChanges([]);

        const changesCount = changesToPush.length;
        const pushMessage = changesCount > 0
          ? `Push to EOP completed successfully! Deployed ${changesCount} pending changes across all 4 tables to Exchange Online: ${changesAllowedSenders.length} to Allowed Senders, ${changesBlockedSenders.length} to Blocked Senders, ${changesAllowedDomains.length} to Allowed Domains, ${changesBlockedDomains.length} to Blocked Domains.`
          : `Push to EOP completed successfully! Applied all current MariaDB table records for policy '${activePolicy}' to Microsoft 365 Exchange Online Protection (no pending uncommitted changes).`;

        setLastSyncResult({
          timestamp,
          status: 'success',
          direction: 'push',
          message: pushMessage,
        });

        logAction(
          'SYNC',
          'SYSTEM',
          policiesImpacted.join(', '),
          `Pushed ${changesCount} pending changes across all 4 tables to Exchange Online`
        );

        // Open comprehensive popup showing what changes were pushed to what list
        setPushSummaryModal({
          policy: policiesImpacted.length === 1 ? policiesImpacted[0] : policiesImpacted.join(', '),
          timestamp,
          pushedChanges: changesToPush,
          allowedSenders: policyAllowedSenders,
          blockedSenders: policyBlockedSenders,
          allowedDomains: policyAllowedDomains,
          blockedDomains: policyBlockedDomains,
          changesByList: {
            allowed_senders: changesAllowedSenders,
            blocked_senders: changesBlockedSenders,
            allowed_domains: changesAllowedDomains,
            blocked_domains: changesBlockedDomains,
          },
          policiesImpacted,
        });

        setPushSummaryTab('changes');

        setBannerMessage({
          type: 'success',
          text: `EOP Push Complete: Successfully deployed ${changesCount} pending changes across all tables to Exchange Online (${changesAllowedSenders.length} to Allowed Senders, ${changesBlockedSenders.length} to Blocked Senders, ${changesAllowedDomains.length} to Allowed Domains, ${changesBlockedDomains.length} to Blocked Domains).`,
        });
      }
    }, 1100);
  };

  // CSV export
  const handleExportCsv = () => {
    const items = getCurrentList();
    let csv = 'ID,Policy Name,Item Value,Note,Added By,Created At\n';
    items.forEach((item) => {
      csv += `${item.id},"${item.policy_name}","${item.value}","${item.note}","${item.added_by}","${item.created_at}"\n`;
    });
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `eop_${activeTab}_${activePolicy.replace(/\s+/g, '_')}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    setBannerMessage({
      type: 'success',
      text: `Exported ${items.length} items from eop_${activeTab} to CSV`
    });
  };

  // Save LDAP config to database table
  const handleSaveLdapDb = (e: React.FormEvent) => {
    e.preventDefault();
    const newId = ldapDbRows.length + 1;
    const now = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const newRow: LdapDbConfig = {
      id: newId,
      host: ldapEditHost,
      port: ldapEditPort,
      protocol: ldapEditProto,
      use_ssl: ldapEditProto === 'ldaps',
      use_tls: ldapEditProto === 'starttls',
      base_dn: ldapEditBaseDn,
      authorized_group_dn: ldapEditGroupDn,
      bind_dn: ldapEditBindDn,
      bind_password: ldapEditBindPass,
      account_suffix: `@${config.ldapDomain.toLowerCase()}.example.com`,
      netbios_domain: config.ldapDomain,
      timeout_seconds: 5,
      is_active: true,
      updated_by: loginUsername || 'ad_admin',
      updated_at: now,
    };

    config.ldapHost = ldapEditHost;
    config.ldapPort = ldapEditPort;
    config.ldapProtocol = ldapEditProto;
    config.ldapBaseDn = ldapEditBaseDn;
    config.ldapGroupDn = ldapEditGroupDn;
    config.ldapBindDn = ldapEditBindDn;
    config.ldapBindPass = ldapEditBindPass;

    setLdapDbRows((prev) => [newRow, ...prev.map((r) => ({ ...r, is_active: false }))]);
    logAction('UPDATE', 'SYSTEM', ldapEditHost, `Updated LDAP connection settings and bind password stored in database table eop_ldap_config (Record #${newId})`);
    setLdapSaveMessage(`Saved new active configuration with LDAP bind credentials (Record #${newId}) into MariaDB table 'eop_ldap_config'!`);
    setTimeout(() => setLdapSaveMessage(null), 4000);
  };

  // Test LDAP Connection & Authorization
  const handleTestLdap = () => {
    setLdapTestStatus('probing');
    setTimeout(() => {
      if (ldapEditBindDn && ldapEditBindPass) {
        setLdapTestStatus(`Active Directory bind authorization successful using service account (${ldapEditBindDn}). Group DN "${ldapEditGroupDn}" verified on ${ldapEditHost}:${ldapEditPort} [${ldapEditProto.toUpperCase()}].`);
      } else if (ldapEditBindDn && !ldapEditBindPass) {
        setLdapTestStatus(`Connection verified to ${ldapEditHost}:${ldapEditPort} [${ldapEditProto.toUpperCase()}]. Notice: Service account Bind DN specified without bind password; attempting anonymous bind.`);
      } else {
        setLdapTestStatus(`Connection verified to ${ldapEditHost}:${ldapEditPort} [${ldapEditProto.toUpperCase()}]. Group DN verified (Anonymous / Default bind).`);
      }
      setTimeout(() => setLdapTestStatus(null), 7000);
    }, 700);
  };

  // Upload private key file handler (.pem, .key, .pfx, .crt)
  const handleKeyFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setKeyUploadFileName(file.name);
      const reader = new FileReader();
      reader.onload = (event) => {
        const text = event.target?.result as string;
        if (text) {
          setKeyUploadText(text.trim());
          // Auto-detect thumbprint if present in header comments
          const match = text.match(/thumbprint[:\s=]+([a-fA-F0-9]{40})/i);
          if (match) {
            setKeyThumbprint(match[1].toUpperCase());
          }
        }
      };
      reader.readAsText(file);
    }
  };

  // Generate Sample 2048-bit RSA Key Pair for quick testing
  const handleGenerateSampleKey = () => {
    const randomHex = Array.from({ length: 40 }, () => Math.floor(Math.random() * 16).toString(16)).join('').toUpperCase();
    setKeyThumbprint(randomHex);
    setKeyUploadFileName('generated-eop-rsa-cert.key');
    setKeyUploadText(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA3a9bC1d0e8f7g6h5i4j3k2l1m0n9o8p7q6r5s4t3u2v1w0x9
y8z7A6B5C4D3E2F1G0H9I8J7K6L5M4N3O2P1Q0R9S8T7U6V5W4X3Y2Z1a0b9c8d7
e6f5g4h3i2j1k0l9m8n7o6p5q4r3s2t1u0v9w8x7y6z5A4B3C2D1E0F9G8H7I6J5
K4L3M2N1O0P9Q8R7S6T5U4V3W2X1Y0Z9a8b7c6d5e4f3g2h1i0j9k8l7m6n5o4p3
q2r1s0t9u8v7w6x5y4z3A2B1C0D9E8F7G6H5I4J3K2L1M0N9O8P7Q6R5S4T3U2V1
-----END RSA PRIVATE KEY-----`);
    setKeyPassword('P@ssphrase_Secure_Cert_2026');
  };

  // Save EOP Private Key & AES-256-GCM Encrypted Passphrase to MariaDB table eop_auth_config
  const handleSaveEopKey = (e: React.FormEvent) => {
    e.preventDefault();
    if (!keyUploadText.trim()) {
      alert('Please provide private key content either by file upload or pasting PEM.');
      return;
    }
    const newId = eopAuthRows.length + 1;
    const now = new Date().toISOString().replace('T', ' ').substring(0, 19);

    // Simulate AES-256-GCM encryption with IV and Tag
    const mockIv = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(12))));
    const mockTag = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
    const mockCiphertext = btoa(`ENC_AES256GCM_${keyPassword}_${Date.now()}`);

    const newRow: EopAuthConfig = {
      id: newId,
      tenant_id: keyTenantId,
      client_id: keyClientId,
      certificate_thumbprint: keyThumbprint.toUpperCase(),
      key_filename: keyUploadFileName,
      private_key_pem: keyUploadText,
      encrypted_password: mockCiphertext,
      encryption_iv: mockIv,
      encryption_tag: mockTag,
      organization: keyOrganization,
      key_type: keyUploadText.includes('ENCRYPTED') ? 'PKCS8_PEM' : 'RSA_PEM',
      is_active: true,
      uploaded_by: loginUsername || 'ad_admin',
      created_at: now,
      updated_at: now,
    };

    setEopAuthRows((prev) => [newRow, ...prev.map((r) => ({ ...r, is_active: false }))]);
    logAction('UPDATE', 'SYSTEM', keyThumbprint, `Uploaded EOP private key (${keyUploadFileName}) with AES-256 encrypted password to table eop_auth_config (Record #${newId})`);
    setKeySaveMessage(`Saved private key & encrypted password (Record #${newId}) into MariaDB table 'eop_auth_config'!`);
    setTimeout(() => setKeySaveMessage(null), 4000);
  };

  // Test EOP Private Key Decryption & Signature Verification
  const handleTestEopKey = () => {
    setKeyTestStatus('probing');
    setTimeout(() => {
      setKeyTestStatus(`Certificate verified: SHA-1 Thumbprint ${keyThumbprint.substring(0, 16)}... RSA 2048-bit Private Key decrypted with AES-256-GCM. RFC 7523 OAuth client_assertion token ready.`);
      setTimeout(() => setKeyTestStatus(null), 6000);
    }, 700);
  };

  // Counters
  const allowedSendersCount = allowedSenders.filter((i) => i.policy_name === activePolicy).length;
  const blockedSendersCount = blockedSenders.filter((i) => i.policy_name === activePolicy).length;
  const allowedDomainsCount = allowedDomains.filter((i) => i.policy_name === activePolicy).length;
  const blockedDomainsCount = blockedDomains.filter((i) => i.policy_name === activePolicy).length;

  const currentList = getCurrentList().filter(
    (item) =>
      item.value.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.note.toLowerCase().includes(searchQuery.toLowerCase())
  );

  // If user is not authenticated in simulator
  if (!isAuthenticated) {
    return (
      <div className="max-w-md mx-auto my-12 p-6 bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-xl transition-colors duration-200">
        <div className="text-center mb-6">
          <div className="w-12 h-12 bg-blue-600 dark:bg-blue-500 text-white rounded-xl flex items-center justify-center mx-auto mb-3 shadow-md">
            <Server className="w-6 h-6" />
          </div>
          <h2 className="text-lg font-bold text-slate-900 dark:text-white">{config.appTitle}</h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Active Directory LDAP Authentication &bull; Port {config.ldapPort} ({config.ldapUseSsl ? 'LDAPS' : 'Plain LDAP - No LDAPS Required'})
          </p>
        </div>

        {loginError && (
          <div className="mb-4 p-3 rounded-lg bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800/60 text-rose-800 dark:text-rose-300 text-xs flex items-start space-x-2">
            <ShieldAlert className="w-4 h-4 text-rose-600 dark:text-rose-400 shrink-0 mt-0.5" />
            <div>{loginError}</div>
          </div>
        )}

        <form onSubmit={handleLogin} className="space-y-4 text-xs">
          <div>
            <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Username</label>
            <input
              type="text"
              value={loginUsername}
              onChange={(e) => setLoginUsername(e.target.value)}
              className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
              placeholder="sAMAccountName, user@corp.example.com, or fallback admin"
            />
          </div>

          <div>
            <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Password</label>
            <input
              type="password"
              value={loginPassword}
              onChange={(e) => setLoginPassword(e.target.value)}
              className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
              placeholder="Domain password or fallback admin password"
            />
          </div>

          {/* Test toggle for AD DC connectivity & group membership simulation */}
          <div className="p-3 bg-slate-50 dark:bg-slate-800/70 rounded-xl border border-slate-200 dark:border-slate-700 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-700 dark:text-slate-300">AD Domain Controller Status:</span>
              <button
                type="button"
                onClick={() => setLdapDcOnline(!ldapDcOnline)}
                className={`text-[10px] font-bold px-2 py-0.5 rounded transition cursor-pointer ${
                  ldapDcOnline
                    ? 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300'
                    : 'bg-rose-100 dark:bg-rose-950/60 text-rose-800 dark:text-rose-300'
                }`}
              >
                {ldapDcOnline ? '🟢 DC Online (Port 389)' : '🔴 DC Offline / Connection Fails'}
              </button>
            </div>

            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-700 dark:text-slate-300">Simulate AD Group Membership:</span>
              <button
                type="button"
                onClick={() => setIsGroupMember(!isGroupMember)}
                className={`text-[10px] font-bold px-2 py-0.5 rounded transition cursor-pointer ${
                  isGroupMember ? 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300' : 'bg-rose-100 dark:bg-rose-950/60 text-rose-800 dark:text-rose-300'
                }`}
              >
                {isGroupMember ? 'In Group DN' : 'Not in Group DN'}
              </button>
            </div>

            <p className="text-[10px] text-slate-500 dark:text-slate-400 font-mono break-all leading-tight">
              Group: {config.ldapGroupDn}
            </p>
          </div>

          {/* Emergency Fallback Helper Box */}
          {config.fallbackAdminEnabled !== false && (
            <div className="p-3 rounded-xl bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800/50 space-y-2 text-[11px]">
              <div className="flex items-center justify-between text-amber-900 dark:text-amber-200 font-bold">
                <span className="flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
                  <span>Emergency Non-LDAP Fallback Admin:</span>
                </span>
                <button
                  type="button"
                  onClick={() => {
                    setLoginUsername(config.fallbackAdminUsername || 'eopadmin');
                    setLoginPassword(config.fallbackAdminPassword || 'Emergency#Admin2026!');
                  }}
                  className="px-2 py-0.5 bg-amber-600 hover:bg-amber-700 text-white rounded text-[10px] font-semibold transition cursor-pointer"
                >
                  Quick Fill Fallback
                </button>
              </div>
              <p className="text-[10px] text-amber-800 dark:text-amber-300 leading-tight">
                User: <code className="font-bold">{config.fallbackAdminUsername || 'eopadmin'}</code> &bull; Configured during setup to permit emergency administrator access if LDAP connection fails.
              </p>
            </div>
          )}

          <button
            type="submit"
            className="w-full py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg shadow-sm transition cursor-pointer"
          >
            Authenticate &amp; Sign In
          </button>
        </form>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 transition-colors duration-200">
      {/* Emergency Fallback Login Banner (If authenticated via local fallback admin) */}
      {isFallbackLoggedIn && (
        <div className="mb-4 p-3.5 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800 flex items-center justify-between text-xs text-amber-900 dark:text-amber-200">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0" />
            <div>
              <span className="font-bold">Disaster Recovery Session Active:</span> Signed in as local administrator <strong>{loginUsername}</strong> using non-LDAP fallback credentials. Active Directory LDAP connection was bypassed or offline.
            </div>
          </div>
          <span className="text-[10px] px-2 py-0.5 rounded bg-amber-200 dark:bg-amber-900/80 text-amber-900 dark:text-amber-200 font-bold uppercase tracking-wider shrink-0 ml-2">
            Non-LDAP Admin
          </span>
        </div>
      )}
      {/* Simulation Banner */}
      <div className="mb-6 p-4 rounded-xl bg-blue-50/70 dark:bg-slate-900 border border-blue-200 dark:border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs transition-colors duration-200">
        <div className="flex items-center space-x-2.5">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
          <span className="font-semibold text-blue-950 dark:text-blue-300">Live Web Application Simulator:</span>
          <span className="text-blue-800 dark:text-slate-300">
            Interactive preview of the Exchange Online Protection policy management console.
          </span>
        </div>
        <div className="flex items-center space-x-3 text-slate-600 dark:text-slate-400 flex-wrap">
          <span>Remote DB: <code className="font-mono text-blue-700 dark:text-blue-400 font-semibold">{config.dbHost}:{config.dbPort}</code></span>
          <span>&bull;</span>
          <span>LDAP in DB Table (<code>eop_ldap_config</code>): <code className="font-mono text-purple-700 dark:text-purple-400 font-semibold">{ldapDbRows.find(r => r.is_active)?.host || config.ldapHost}:{ldapDbRows.find(r => r.is_active)?.port || config.ldapPort}</code> ({ldapDbRows.find(r => r.is_active)?.protocol.toUpperCase() || 'LDAP'})</span>
          <span>&bull;</span>
          <button
            onClick={() => setIsAuthenticated(false)}
            className="text-rose-600 dark:text-rose-400 hover:text-rose-800 font-medium flex items-center space-x-1"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span>Simulate Logout</span>
          </button>
        </div>
      </div>

      {/* Embedded Simulated App Container */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-md overflow-hidden transition-colors duration-200">
        {/* Top App Header */}
        <div className="bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 px-6 py-4 flex flex-col md:flex-row md:items-center justify-between gap-4 transition-colors duration-200">
          <div className="flex items-center space-x-3">
            <div className="w-9 h-9 rounded-xl bg-blue-600 dark:bg-blue-500 text-white flex items-center justify-center font-bold">
              <Server className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-base font-bold text-slate-900 dark:text-white leading-tight">{config.appTitle}</h1>
            </div>
          </div>

          <div className="flex items-center space-x-4">
            {/* Policy Selector Dropdown */}
            <div className="flex items-center space-x-2">
              <span className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Policy:</span>
              <select
                value={activePolicy}
                onChange={(e) => {
                  if (e.target.value === '__add_new__') {
                    const custom = prompt('Enter New Anti-Spam Policy Name in Exchange:');
                    if (custom && custom.trim()) {
                      setPolicies((prev) => [...prev, custom.trim()]);
                      setActivePolicy(custom.trim());
                    }
                  } else {
                    setActivePolicy(e.target.value);
                  }
                }}
                className="bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-100 text-xs font-semibold rounded-lg px-3 py-1.5 focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
              >
                {policies.map((pol) => (
                  <option key={pol} value={pol}>
                    {pol}
                  </option>
                ))}
                <option value="__add_new__">+ Add Custom Policy...</option>
              </select>
            </div>

            {/* Prominent Push All Changes from MariaDB to EOP Button */}
            <button
              onClick={() => setShowPushConfirmModal(true)}
              disabled={syncLoading}
              className="px-3.5 py-1.5 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white rounded-lg text-xs font-bold flex items-center space-x-1.5 shadow-sm transition cursor-pointer disabled:opacity-50 ring-2 ring-indigo-500/20"
              title="Push all pending staged changes across all 4 tables to Exchange Online Protection (EOP)"
            >
              <CloudUpload className={`w-3.5 h-3.5 ${syncLoading && syncActionType === 'push' ? 'animate-spin' : ''}`} />
              <span>{syncLoading && syncActionType === 'push' ? 'Pushing All to EOP...' : 'Push All Changes to EOP'}</span>
              <span className="hidden sm:inline-block ml-1 px-1.5 py-0.2 rounded-full bg-white/20 text-[10px] font-normal">
                {pendingChanges.length > 0 ? `${pendingChanges.length} pending` : `${totalStagedItems} staged`}
              </span>
            </button>

            {/* Direct Configuration Page Link / Back Toggle */}
            <button
              onClick={() => {
                if (activeTab === 'config_center' || activeTab === 'ldap_db') {
                  handleTabChange('allowed_senders');
                } else {
                  handleTabChange('config_center');
                }
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition cursor-pointer ${
                activeTab === 'config_center' || activeTab === 'ldap_db'
                  ? 'bg-indigo-600 text-white shadow-xs'
                  : 'bg-indigo-50 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-800 hover:bg-indigo-100 dark:hover:bg-indigo-900/60'
              }`}
              title={activeTab === 'config_center' || activeTab === 'ldap_db' ? 'Exit Configuration and return to Anti-Spam Lists' : 'Open Configuration Page (Upload Private Key & Modify LDAP Settings in DB)'}
            >
              {activeTab === 'config_center' || activeTab === 'ldap_db' ? (
                <>
                  <ArrowLeft className="w-3.5 h-3.5" />
                  <span>Back to Lists</span>
                </>
              ) : (
                <>
                  <Key className="w-3.5 h-3.5" />
                  <span>Configuration Page</span>
                </>
              )}
            </button>

            {/* AD User Badge */}
            <div className="flex items-center pl-3 border-l border-slate-200 dark:border-slate-800 space-x-2.5">
              <div className="text-right">
                <div className="text-xs font-semibold text-slate-800 dark:text-slate-200 flex items-center justify-end space-x-1">
                  <span>{loginUsername === 'jsmith' ? 'John Smith' : loginUsername}</span>
                  <span className="bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/40 text-[10px] font-semibold px-1.5 py-0.2 rounded flex items-center space-x-0.5">
                    <UserCheck className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
                    <span>AD Authorized</span>
                  </span>
                </div>
                <div className="text-[10px] text-slate-400 dark:text-slate-500 truncate max-w-[180px]" title={config.ldapGroupDn}>
                  {config.ldapDomain}\{loginUsername}
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* 5 Stat Cards for MariaDB Tables (Senders, Domains & Config) */}
        <div className="p-6 bg-slate-50/60 dark:bg-slate-900/60 border-b border-slate-200 dark:border-slate-800 transition-colors duration-200">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
            {/* Allowed Senders */}
            <button
              onClick={() => handleTabChange('allowed_senders')}
              className={`p-4 rounded-xl border text-left transition cursor-pointer ${
                activeTab === 'allowed_senders'
                  ? 'bg-white dark:bg-slate-800 border-emerald-500 ring-2 ring-emerald-500/20 shadow-sm'
                  : 'bg-white dark:bg-slate-800/80 border-slate-200 dark:border-slate-700 hover:border-emerald-300 dark:hover:border-emerald-500'
              }`}
            >
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Allowed Senders</span>
                <span className="w-7 h-7 rounded-full bg-emerald-50 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400 flex items-center justify-center">
                  <Mail className="w-3.5 h-3.5" />
                </span>
              </div>
              <div className="text-2xl font-bold text-slate-900 dark:text-white mt-2">{allowedSendersCount}</div>
              <div className="text-[10px] text-slate-400 dark:text-slate-500 font-mono mt-1">Table: eop_allowed_senders</div>
            </button>

            {/* Blocked Senders */}
            <button
              onClick={() => handleTabChange('blocked_senders')}
              className={`p-4 rounded-xl border text-left transition cursor-pointer ${
                activeTab === 'blocked_senders'
                  ? 'bg-white dark:bg-slate-800 border-rose-500 ring-2 ring-rose-500/20 shadow-sm'
                  : 'bg-white dark:bg-slate-800/80 border-slate-200 dark:border-slate-700 hover:border-rose-300 dark:hover:border-rose-500'
              }`}
            >
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Blocked Senders</span>
                <span className="w-7 h-7 rounded-full bg-rose-50 dark:bg-rose-950/60 text-rose-600 dark:text-rose-400 flex items-center justify-center">
                  <Ban className="w-3.5 h-3.5" />
                </span>
              </div>
              <div className="text-2xl font-bold text-slate-900 dark:text-white mt-2">{blockedSendersCount}</div>
              <div className="text-[10px] text-slate-400 dark:text-slate-500 font-mono mt-1">Table: eop_blocked_senders</div>
            </button>

            {/* Allowed Domains */}
            <button
              onClick={() => handleTabChange('allowed_domains')}
              className={`p-4 rounded-xl border text-left transition cursor-pointer ${
                activeTab === 'allowed_domains'
                  ? 'bg-white dark:bg-slate-800 border-blue-500 ring-2 ring-blue-500/20 shadow-sm'
                  : 'bg-white dark:bg-slate-800/80 border-slate-200 dark:border-slate-700 hover:border-blue-300 dark:hover:border-blue-500'
              }`}
            >
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Allowed Domains</span>
                <span className="w-7 h-7 rounded-full bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 flex items-center justify-center">
                  <Globe className="w-3.5 h-3.5" />
                </span>
              </div>
              <div className="text-2xl font-bold text-slate-900 dark:text-white mt-2">{allowedDomainsCount}</div>
              <div className="text-[10px] text-slate-400 dark:text-slate-500 font-mono mt-1">Table: eop_allowed_domains</div>
            </button>

            {/* Blocked Domains */}
            <button
              onClick={() => handleTabChange('blocked_domains')}
              className={`p-4 rounded-xl border text-left transition cursor-pointer ${
                activeTab === 'blocked_domains'
                  ? 'bg-white dark:bg-slate-800 border-amber-500 ring-2 ring-amber-500/20 shadow-sm'
                  : 'bg-white dark:bg-slate-800/80 border-slate-200 dark:border-slate-700 hover:border-amber-300 dark:hover:border-amber-500'
              }`}
            >
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Blocked Domains</span>
                <span className="w-7 h-7 rounded-full bg-amber-50 dark:bg-amber-950/60 text-amber-600 dark:text-amber-400 flex items-center justify-center">
                  <ShieldAlert className="w-3.5 h-3.5" />
                </span>
              </div>
              <div className="text-2xl font-bold text-slate-900 dark:text-white mt-2">{blockedDomainsCount}</div>
              <div className="text-[10px] text-slate-400 dark:text-slate-500 font-mono mt-1">Table: eop_blocked_domains</div>
            </button>

            {/* Configuration Center Card */}
            <button
              onClick={() => handleTabChange('config_center')}
              className={`p-4 rounded-xl border text-left transition cursor-pointer ${
                activeTab === 'config_center' || activeTab === 'ldap_db'
                  ? 'bg-white dark:bg-slate-800 border-indigo-500 ring-2 ring-indigo-500/20 shadow-sm'
                  : 'bg-white dark:bg-slate-800/80 border-slate-200 dark:border-slate-700 hover:border-indigo-300 dark:hover:border-indigo-500'
              }`}
            >
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-indigo-600 dark:text-indigo-400 uppercase tracking-wider">Configuration</span>
                <span className="w-7 h-7 rounded-full bg-indigo-50 dark:bg-indigo-950/60 text-indigo-600 dark:text-indigo-400 flex items-center justify-center">
                  <Key className="w-3.5 h-3.5" />
                </span>
              </div>
              <div className="text-sm font-bold text-slate-900 dark:text-white mt-2 flex items-center justify-between">
                <span>EOP &amp; LDAP</span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 font-semibold">DB Stored</span>
              </div>
              <div className="text-[10px] text-slate-400 dark:text-slate-500 font-mono mt-1">Tables: eop_auth &amp; eop_ldap</div>
            </button>
          </div>
        </div>

        {/* Tab navigation & actions */}
        <div className="border-b border-slate-200 dark:border-slate-800 px-6 flex flex-col md:flex-row md:items-center justify-between gap-3 transition-colors duration-200">
          <nav className="flex space-x-4 text-xs font-semibold overflow-x-auto">
            <button
              onClick={() => handleTabChange('allowed_senders')}
              className={`py-3.5 border-b-2 transition flex items-center space-x-1.5 whitespace-nowrap cursor-pointer ${
                activeTab === 'allowed_senders'
                  ? 'border-emerald-600 text-emerald-700 dark:text-emerald-400'
                  : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
            >
              <Mail className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
              <span>Allowed Senders ({allowedSendersCount})</span>
            </button>

            <button
              onClick={() => handleTabChange('blocked_senders')}
              className={`py-3.5 border-b-2 transition flex items-center space-x-1.5 whitespace-nowrap cursor-pointer ${
                activeTab === 'blocked_senders'
                  ? 'border-rose-600 text-rose-700 dark:text-rose-400'
                  : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
            >
              <Ban className="w-3.5 h-3.5 text-rose-600 dark:text-rose-400" />
              <span>Blocked Senders ({blockedSendersCount})</span>
            </button>

            <button
              onClick={() => handleTabChange('allowed_domains')}
              className={`py-3.5 border-b-2 transition flex items-center space-x-1.5 whitespace-nowrap cursor-pointer ${
                activeTab === 'allowed_domains'
                  ? 'border-blue-600 text-blue-700 dark:text-blue-400'
                  : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
            >
              <Globe className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
              <span>Allowed Domains ({allowedDomainsCount})</span>
            </button>

            <button
              onClick={() => handleTabChange('blocked_domains')}
              className={`py-3.5 border-b-2 transition flex items-center space-x-1.5 whitespace-nowrap cursor-pointer ${
                activeTab === 'blocked_domains'
                  ? 'border-amber-600 text-amber-700 dark:text-amber-400'
                  : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
            >
              <ShieldAlert className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
              <span>Blocked Domains ({blockedDomainsCount})</span>
            </button>

            <button
              onClick={() => handleTabChange('sync')}
              className={`py-3.5 border-b-2 transition flex items-center space-x-1.5 whitespace-nowrap cursor-pointer ${
                activeTab === 'sync'
                  ? 'border-purple-600 text-purple-700 dark:text-purple-400'
                  : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
            >
              <RefreshCw className="w-3.5 h-3.5 text-purple-600 dark:text-purple-400" />
              <span>Exchange Sync Engine</span>
            </button>

            <button
              onClick={() => handleTabChange('audit')}
              className={`py-3.5 border-b-2 transition flex items-center space-x-1.5 whitespace-nowrap cursor-pointer ${
                activeTab === 'audit'
                  ? 'border-slate-800 dark:border-slate-300 text-slate-900 dark:text-white'
                  : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
            >
              <History className="w-3.5 h-3.5 text-slate-600 dark:text-slate-400" />
              <span>Audit Log ({auditLogs.length})</span>
            </button>

            <button
              onClick={() => handleTabChange('config_center')}
              className={`py-3.5 border-b-2 transition flex items-center space-x-1.5 whitespace-nowrap cursor-pointer ${
                activeTab === 'config_center' || activeTab === 'ldap_db'
                  ? 'border-indigo-600 text-indigo-700 dark:text-indigo-400 font-bold'
                  : 'border-transparent text-indigo-700 dark:text-indigo-300 hover:text-indigo-900 dark:hover:text-white'
              }`}
            >
              <Key className="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
              <span>Configuration: Keys &amp; LDAP</span>
              <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-indigo-100 dark:bg-indigo-950/80 text-indigo-700 dark:text-indigo-300 font-bold border border-indigo-200 dark:border-indigo-800/60">
                DB Page
              </span>
            </button>
          </nav>

          {activeTab !== 'sync' && activeTab !== 'audit' && activeTab !== 'config_center' && activeTab !== 'ldap_db' && (
            <div className="flex items-center space-x-2 py-2">
              <button
                onClick={() => {
                  setAddError(null);
                  setShowAddModal(true);
                }}
                className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center space-x-1.5 transition"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add Entry</span>
              </button>

              <button
                onClick={() => {
                  setBulkError(null);
                  setShowBulkModal(true);
                }}
                className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-semibold rounded-lg flex items-center space-x-1.5 transition"
              >
                <Upload className="w-3.5 h-3.5" />
                <span>Bulk Import</span>
              </button>

              {/* Split Smart Sort & Import Buttons: Allowed & Blocked */}
              <button
                onClick={() => {
                  setSmartSortTarget('allowed');
                  setSmartSortError(null);
                  setShowSmartSortModal(true);
                }}
                className="px-3 py-1.5 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-700 hover:to-teal-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center space-x-1.5 transition cursor-pointer"
                title="Paste mixed list of emails and domains to auto-sort directly into Allowed Senders & Allowed Domains tables"
              >
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-200" />
                <span>Smart Sort Allowed</span>
              </button>

              <button
                onClick={() => {
                  setSmartSortTarget('blocked');
                  setSmartSortError(null);
                  setShowSmartSortModal(true);
                }}
                className="px-3 py-1.5 bg-gradient-to-r from-rose-600 to-red-600 hover:from-rose-700 hover:to-red-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center space-x-1.5 transition cursor-pointer"
                title="Paste mixed list of emails and domains to auto-sort directly into Blocked Senders & Blocked Domains tables"
              >
                <Ban className="w-3.5 h-3.5 text-rose-200" />
                <span>Smart Sort Blocked</span>
              </button>

              <button
                onClick={handleExportCsv}
                className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-semibold rounded-lg flex items-center space-x-1.5 transition"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export CSV</span>
              </button>

              <button
                onClick={() => setShowPushConfirmModal(true)}
                disabled={syncLoading}
                className="px-3.5 py-1.5 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white text-xs font-bold rounded-lg shadow-sm flex items-center space-x-1.5 transition cursor-pointer disabled:opacity-50 ring-2 ring-indigo-500/20"
                title="Push all pending staged changes across all 4 tables to Exchange Online Protection (EOP)"
              >
                <CloudUpload className={`w-3.5 h-3.5 ${syncLoading && syncActionType === 'push' ? 'animate-spin' : ''}`} />
                <span>{syncLoading && syncActionType === 'push' ? 'Pushing All to EOP...' : 'Push All Changes to EOP'}</span>
                <span className="hidden sm:inline-block px-1.5 py-0.2 rounded-full bg-white/20 text-[10px] font-normal">
                  {pendingChanges.length > 0 ? `${pendingChanges.length} pending` : `${totalStagedItems} staged`}
                </span>
              </button>
            </div>
          )}
        </div>

        {/* Tab Body */}
        {activeTab === 'sync' ? (
          /* Exchange Sync Center */
          <div className="p-6">
            <div className="max-w-4xl space-y-6">
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-white">Exchange Online Protection Policy Sync</h3>
                <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">
                  Synchronize the 4 individual MariaDB tables with Microsoft 365 Exchange Online Protection for policy:{' '}
                  <strong className="text-blue-600 dark:text-blue-400">{activePolicy}</strong>
                </p>
              </div>

              {/* Cron Policy Enforcement Notice Banner */}
              <div className="p-4 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800/60 text-xs text-amber-900 dark:text-amber-200 space-y-1.5 leading-relaxed">
                <div className="font-bold flex items-center gap-1.5 text-amber-800 dark:text-amber-300">
                  <ShieldCheck className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0" />
                  <span>Cron Job Policy: Pull-Only from Exchange Online Protection</span>
                </div>
                <p>
                  The scheduled Linux cron job (<code>cron-sync.php --action=pull</code>) runs every 15 minutes and <strong>only pulls changes from Exchange Online into MariaDB</strong>.
                  It does <strong>not</strong> push local changes to EOP. Pushing local MariaDB modifications to Microsoft 365 requires an intentional administrator action.
                </p>
              </div>

              {/* Status card */}
              {lastSyncResult && (
                <div className="p-4 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800/60 flex items-start space-x-3 text-xs">
                  <CheckCircle className="w-5 h-5 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
                  <div>
                    <div className="font-bold text-emerald-900 dark:text-emerald-200 flex items-center gap-2">
                      <span>Last Sync: {lastSyncResult.timestamp}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase ${
                        lastSyncResult.direction === 'pull'
                          ? 'bg-blue-100 dark:bg-blue-900/60 text-blue-700 dark:text-blue-300'
                          : 'bg-purple-100 dark:bg-purple-900/60 text-purple-700 dark:text-purple-300'
                      }`}>
                        {lastSyncResult.direction === 'pull' ? 'Cron Pull (EOP -> MariaDB)' : 'Manual Admin Push (MariaDB -> EOP)'}
                      </span>
                    </div>
                    <div className="text-emerald-800 dark:text-emerald-300 mt-1">{lastSyncResult.message}</div>
                  </div>
                </div>
              )}

              {/* Generated PowerShell Code Previews */}
              <div className="space-y-4">
                {/* 1. Cron Job Command */}
                <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-xs text-slate-200 overflow-x-auto shadow-inner">
                  <div className="text-amber-400 font-bold mb-1"># 1. Scheduled Linux Cron Job (Runs every 15m - PULL ONLY from EOP):</div>
                  <div className="text-slate-300">Get-HostedContentFilterPolicy -Identity "{activePolicy}"</div>
                  <div className="text-slate-500 text-[11px] mt-1"># Ingests external additions or removals made in Microsoft 365 into MariaDB. Does NOT push local changes.</div>
                </div>

                {/* 2. Manual Admin Push Command */}
                <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-xs text-slate-200 overflow-x-auto shadow-inner">
                  <div className="text-indigo-400 font-bold mb-1"># 2. Manual Administrator Push (Applies MariaDB lists to Microsoft 365):</div>
                  <div className="text-emerald-400">Set-HostedContentFilterPolicy `</div>
                  <div className="pl-4 text-slate-100">-Identity "{activePolicy}" `</div>
                  <div className="pl-4 text-blue-300">
                    -AllowedSenders @({allowedSenders.filter((i) => i.policy_name === activePolicy).map((i) => `'${i.value}'`).join(', ') || '@()'}) `
                  </div>
                  <div className="pl-4 text-rose-300">
                    -BlockedSenders @({blockedSenders.filter((i) => i.policy_name === activePolicy).map((i) => `'${i.value}'`).join(', ') || '@()'}) `
                  </div>
                  <div className="pl-4 text-cyan-300">
                    -AllowedSenderDomains @({allowedDomains.filter((i) => i.policy_name === activePolicy).map((i) => `'${i.value}'`).join(', ') || '@()'}) `
                  </div>
                  <div className="pl-4 text-amber-300">
                    -BlockedSenderDomains @({blockedDomains.filter((i) => i.policy_name === activePolicy).map((i) => `'${i.value}'`).join(', ') || '@()'})
                  </div>
                </div>
              </div>

              {/* Dual Sync Trigger Buttons */}
              <div className="flex flex-wrap items-center gap-3 pt-2">
                <button
                  onClick={() => handleTriggerSync('pull')}
                  disabled={syncLoading}
                  className="px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center space-x-2 transition disabled:opacity-50 cursor-pointer"
                >
                  <RefreshCw className={`w-4 h-4 ${syncLoading && syncActionType === 'pull' ? 'animate-spin' : ''}`} />
                  <span>{syncLoading && syncActionType === 'pull' ? 'Executing Cron Pull...' : 'Simulate Cron Pull from EOP (Pull Only)'}</span>
                </button>

                <button
                  onClick={() => setShowPushConfirmModal(true)}
                  disabled={syncLoading}
                  className="px-5 py-2.5 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center space-x-2 transition disabled:opacity-50 cursor-pointer ring-2 ring-indigo-500/20"
                >
                  <CloudUpload className={`w-4 h-4 ${syncLoading && syncActionType === 'push' ? 'animate-spin' : ''}`} />
                  <span>{syncLoading && syncActionType === 'push' ? 'Pushing All Changes to EOP...' : 'Push All Changes to Exchange Online (Set-HostedContentFilterPolicy)'}</span>
                  {pendingChanges.length > 0 && (
                    <span className="px-2 py-0.5 rounded-full bg-white/20 text-white text-[10px] font-bold">
                      {pendingChanges.length} pending
                    </span>
                  )}
                </button>
              </div>
            </div>
          </div>
        ) : activeTab === 'audit' ? (
          /* Audit Trail Table */
          <div className="p-6">
            <h3 className="text-base font-bold text-slate-900 dark:text-white mb-4">Audit Trail (Table: <code className="text-blue-600 dark:text-blue-400">eop_audit_log</code>)</h3>
            <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-xl">
              <table className="w-full text-left text-xs text-slate-700 dark:text-slate-300">
                <thead className="bg-slate-100 dark:bg-slate-800/80 text-slate-600 dark:text-slate-400 font-semibold border-b border-slate-200 dark:border-slate-800 uppercase tracking-wider text-[11px]">
                  <tr>
                    <th className="py-2.5 px-4">Timestamp</th>
                    <th className="py-2.5 px-4">User (LDAP)</th>
                    <th className="py-2.5 px-4">Action</th>
                    <th className="py-2.5 px-4">Target Table / Item</th>
                    <th className="py-2.5 px-4">Policy</th>
                    <th className="py-2.5 px-4">IP Address</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800 font-mono text-[11px]">
                  {auditLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                      <td className="py-2 px-4 text-slate-500 dark:text-slate-400">{log.timestamp}</td>
                      <td className="py-2 px-4 font-semibold text-slate-900 dark:text-white">{log.username}</td>
                      <td className="py-2 px-4">
                        <span
                          className={`px-1.5 py-0.5 rounded font-bold text-[10px] ${
                            log.action === 'ADD'
                              ? 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300'
                              : log.action === 'REMOVE'
                              ? 'bg-rose-100 dark:bg-rose-950/60 text-rose-800 dark:text-rose-300'
                              : 'bg-blue-100 dark:bg-blue-950/60 text-blue-800 dark:text-blue-300'
                          }`}
                        >
                          {log.action}
                        </span>
                      </td>
                      <td className="py-2 px-4 text-slate-800 dark:text-slate-200">{log.target_value}</td>
                      <td className="py-2 px-4 text-slate-600 dark:text-slate-400">{log.policy_name}</td>
                      <td className="py-2 px-4 text-slate-400 dark:text-slate-500">{log.ip_address}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : (activeTab === 'config_center' || activeTab === 'ldap_db') ? (
          /* Unified Configuration Page: EOP Private Key & AD LDAP Settings */
          <div className="p-6">
            <div className="max-w-5xl space-y-6">
              {/* Header & Sub-nav with prominent Back Button */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-200 dark:border-slate-800">
                <div className="flex items-center space-x-3">
                  <button
                    type="button"
                    onClick={() => handleTabChange('allowed_senders')}
                    className="px-3.5 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 border border-slate-300 dark:border-slate-700 rounded-xl text-xs font-semibold flex items-center space-x-1.5 transition cursor-pointer shadow-2xs shrink-0"
                    title="Exit Configuration and return to Anti-Spam Lists"
                  >
                    <ArrowLeft className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                    <span>Back to Lists</span>
                  </button>
                  <div>
                    <h3 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
                      <Key className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
                      <span>Configuration Center</span>
                    </h3>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                      Manage Exchange Online Protection private key credentials &amp; Active Directory LDAP connection settings stored in MariaDB.
                    </p>
                  </div>
                </div>

                {/* Sub-view switcher */}
                <div className="flex items-center space-x-1.5 bg-slate-100 dark:bg-slate-800 p-1 rounded-lg text-xs font-semibold self-start md:self-auto">
                  <button
                    type="button"
                    onClick={() => setConfigSubTab('all')}
                    className={`px-3 py-1.5 rounded-md transition ${
                      configSubTab === 'all'
                        ? 'bg-white dark:bg-slate-700 text-slate-900 dark:text-white shadow-xs'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                    }`}
                  >
                    All Settings
                  </button>
                  <button
                    type="button"
                    onClick={() => setConfigSubTab('eop_key')}
                    className={`px-3 py-1.5 rounded-md transition flex items-center gap-1.5 ${
                      configSubTab === 'eop_key'
                        ? 'bg-white dark:bg-slate-700 text-indigo-700 dark:text-indigo-300 shadow-xs'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                    }`}
                  >
                    <Key className="w-3.5 h-3.5 text-indigo-500" />
                    <span>EOP Private Key</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setConfigSubTab('ldap_db')}
                    className={`px-3 py-1.5 rounded-md transition flex items-center gap-1.5 ${
                      configSubTab === 'ldap_db'
                        ? 'bg-white dark:bg-slate-700 text-purple-700 dark:text-purple-300 shadow-xs'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                    }`}
                  >
                    <Database className="w-3.5 h-3.5 text-purple-500" />
                    <span>AD LDAP Settings</span>
                  </button>
                </div>
              </div>

              {/* Status summary banner */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* EOP Key Summary Pill */}
                <div className="p-4 rounded-xl border border-indigo-200 dark:border-indigo-900/50 bg-indigo-50/60 dark:bg-indigo-950/30">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-indigo-950 dark:text-indigo-200 flex items-center gap-1.5">
                      <Key className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                      Exchange Online Private Key Auth
                    </span>
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/60">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                      Table: eop_auth_config (Active #{eopAuthRows.find((r) => r.is_active)?.id || 1})
                    </span>
                  </div>
                  <div className="mt-2.5 space-y-1 text-xs text-indigo-900/90 dark:text-indigo-300/90 font-mono">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-slate-500 dark:text-slate-400 font-sans">SHA-1 Thumbprint:</span>
                      <span className="font-semibold">{keyThumbprint.substring(0, 16)}...</span>
                    </div>
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-slate-500 dark:text-slate-400 font-sans">Key File:</span>
                      <span>{keyUploadFileName}</span>
                    </div>
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-slate-500 dark:text-slate-400 font-sans">Passphrase Encryption:</span>
                      <span className="text-emerald-700 dark:text-emerald-400 font-semibold flex items-center gap-1 font-sans">
                        <Lock className="w-3 h-3" /> AES-256-GCM Encrypted
                      </span>
                    </div>
                  </div>
                </div>

                {/* LDAP Config Summary Pill */}
                <div className="p-4 rounded-xl border border-purple-200 dark:border-purple-900/50 bg-purple-50/60 dark:bg-purple-950/30">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-purple-950 dark:text-purple-200 flex items-center gap-1.5">
                      <Database className="w-4 h-4 text-purple-600 dark:text-purple-400" />
                      Active Directory LDAP Settings
                    </span>
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/60">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                      Table: eop_ldap_config (Active #{ldapDbRows.find((r) => r.is_active)?.id || 1})
                    </span>
                  </div>
                  <div className="mt-2.5 space-y-1 text-xs text-purple-900/90 dark:text-purple-300/90 font-mono">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-slate-500 dark:text-slate-400 font-sans">Target DC:</span>
                      <span className="font-semibold">{ldapEditHost}:{ldapEditPort}</span>
                    </div>
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-slate-500 dark:text-slate-400 font-sans">Protocol:</span>
                      <span className="uppercase font-semibold text-purple-700 dark:text-purple-300">{ldapEditProto} (No cert required for 389)</span>
                    </div>
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-slate-500 dark:text-slate-400 font-sans">Auth Group:</span>
                      <span className="truncate max-w-[190px]" title={ldapEditGroupDn}>{ldapEditGroupDn.split(',')[0]}</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* SECTION 1: EOP Private Key Upload & Password Encryption */}
              {(configSubTab === 'all' || configSubTab === 'eop_key') && (
                <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-xs space-y-5">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-100 dark:border-slate-800">
                    <div className="flex items-center space-x-3">
                      <div className="w-9 h-9 rounded-xl bg-indigo-50 dark:bg-indigo-950/60 text-indigo-600 dark:text-indigo-400 flex items-center justify-center">
                        <Key className="w-5 h-5" />
                      </div>
                      <div>
                        <h4 className="text-sm font-bold text-slate-900 dark:text-white">
                          Exchange Online Protection Private Key &amp; Certificate Authentication
                        </h4>
                        <p className="text-xs text-slate-500 dark:text-slate-400">
                          Store private key and AES-256-GCM encrypted passphrase in database table <code className="font-mono text-indigo-600 dark:text-indigo-400">eop_auth_config</code>
                        </p>
                      </div>
                    </div>
                    <span className="text-[11px] font-mono px-2.5 py-1 rounded bg-indigo-50 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-800/60 self-start sm:self-auto">
                      RFC 7523 OAuth2 JWT
                    </span>
                  </div>

                  {/* Feedback Messages */}
                  {keySaveMessage && (
                    <div className="p-3.5 rounded-lg bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800/60 text-emerald-800 dark:text-emerald-200 text-xs flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                      <span>{keySaveMessage}</span>
                    </div>
                  )}

                  {keyTestStatus && (
                    <div className={`p-3.5 rounded-lg text-xs flex items-center gap-2 border ${
                      keyTestStatus === 'probing'
                        ? 'bg-amber-50 dark:bg-amber-950/40 border-amber-200 dark:border-amber-800/60 text-amber-800 dark:text-amber-200'
                        : 'bg-indigo-50 dark:bg-indigo-950/40 border-indigo-200 dark:border-indigo-800/60 text-indigo-800 dark:text-indigo-200'
                    }`}>
                      <RefreshCw className={`w-4 h-4 shrink-0 ${keyTestStatus === 'probing' ? 'animate-spin' : ''}`} />
                      <span>{keyTestStatus === 'probing' ? 'Testing private key decryption & validating OAuth2 client_assertion signature...' : keyTestStatus}</span>
                    </div>
                  )}

                  {/* Key Upload & Configuration Form */}
                  <form onSubmit={handleSaveEopKey} className="space-y-4">
                    {/* File Upload Zone */}
                    <div>
                      <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                        Upload Private Key (.pem, .key, .pfx, .crt, .txt)
                      </label>
                      <div className="flex flex-col sm:flex-row items-center gap-3">
                        <label className="flex-1 w-full flex items-center justify-center gap-2 px-4 py-3 border-2 border-dashed border-indigo-300 dark:border-indigo-800/80 rounded-xl hover:bg-indigo-50/50 dark:hover:bg-indigo-950/20 cursor-pointer transition text-xs font-medium text-indigo-700 dark:text-indigo-300">
                          <Upload className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                          <span>Choose Key File: <strong className="font-mono">{keyUploadFileName}</strong></span>
                          <input
                            type="file"
                            accept=".pem,.key,.pfx,.cer,.crt,.txt"
                            onChange={handleKeyFileUpload}
                            className="hidden"
                          />
                        </label>
                        <button
                          type="button"
                          onClick={handleGenerateSampleKey}
                          className="w-full sm:w-auto px-4 py-3 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 text-xs font-semibold rounded-xl flex items-center justify-center gap-1.5 transition shrink-0"
                          title="Generate a sample 2048-bit RSA key for testing"
                        >
                          <FileKey className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                          <span>Generate Sample RSA Key</span>
                        </button>
                      </div>
                    </div>

                    {/* Key PEM Content Textarea */}
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300">
                          Private Key Content (Stored in table <code className="text-indigo-600 dark:text-indigo-400">eop_auth_config.private_key_pem</code>):
                        </label>
                        <span className="text-[10px] text-slate-400 font-mono">
                          {keyUploadText.length} bytes
                        </span>
                      </div>
                      <textarea
                        rows={5}
                        required
                        value={keyUploadText}
                        onChange={(e) => setKeyUploadText(e.target.value)}
                        className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg p-3 text-slate-900 dark:text-emerald-400 font-mono text-[11px] leading-relaxed focus:ring-2 focus:ring-indigo-500 focus:outline-hidden transition-colors"
                        placeholder="-----BEGIN RSA PRIVATE KEY-----..."
                      />
                    </div>

                    {/* Encrypted Password & Thumbprint Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                      <div>
                        <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                          Private Key Password / Passphrase <span className="text-slate-400 font-normal">(Encrypted via AES-256-GCM in DB)</span>:
                        </label>
                        <div className="relative">
                          <input
                            type={showKeyPassword ? 'text' : 'password'}
                            value={keyPassword}
                            onChange={(e) => setKeyPassword(e.target.value)}
                            placeholder="Key passphrase (stored AES-256 encrypted)"
                            className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg pl-3 pr-10 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-indigo-500 focus:outline-hidden"
                          />
                          <button
                            type="button"
                            onClick={() => setShowKeyPassword(!showKeyPassword)}
                            className="absolute right-2.5 top-2.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
                            title={showKeyPassword ? 'Hide passphrase' : 'Show passphrase'}
                          >
                            {showKeyPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                          </button>
                        </div>
                        <div className="mt-1 flex items-center gap-1.5 text-[10px] text-slate-500 dark:text-slate-400">
                          <Lock className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
                          <span>Passphrase is encrypted before writing to <code>eop_auth_config.encrypted_password</code></span>
                        </div>
                      </div>

                      <div>
                        <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                          Certificate Thumbprint (SHA-1):
                        </label>
                        <input
                          type="text"
                          required
                          value={keyThumbprint}
                          onChange={(e) => setKeyThumbprint(e.target.value.toUpperCase())}
                          placeholder="9A2F8B3C1D4E5F6A7B8C9D0E1F2A3B4C5D6E7F80"
                          className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono text-[11px] focus:ring-2 focus:ring-indigo-500 focus:outline-hidden"
                        />
                        <div className="mt-1 text-[10px] text-slate-500 dark:text-slate-400">
                          Matches the certificate thumbprint registered in Azure Active Directory App.
                        </div>
                      </div>

                      <div>
                        <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                          Azure AD Tenant ID:
                        </label>
                        <input
                          type="text"
                          required
                          value={keyTenantId}
                          onChange={(e) => setKeyTenantId(e.target.value)}
                          placeholder="11111111-2222-3333-4444-555555555555"
                          className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono text-[11px] focus:ring-2 focus:ring-indigo-500 focus:outline-hidden"
                        />
                      </div>

                      <div>
                        <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                          Application (Client) ID:
                        </label>
                        <input
                          type="text"
                          required
                          value={keyClientId}
                          onChange={(e) => setKeyClientId(e.target.value)}
                          placeholder="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
                          className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono text-[11px] focus:ring-2 focus:ring-indigo-500 focus:outline-hidden"
                        />
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2 border-t border-slate-100 dark:border-slate-800">
                      <div className="flex items-center space-x-2 w-full sm:w-auto">
                        <button
                          type="button"
                          onClick={() => handleTabChange('allowed_senders')}
                          className="px-3.5 py-2 border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition cursor-pointer"
                        >
                          <ArrowLeft className="w-3.5 h-3.5" />
                          <span>Back to Lists</span>
                        </button>
                        <button
                          type="button"
                          onClick={handleTestEopKey}
                          className="px-4 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 text-xs font-semibold rounded-lg flex items-center justify-center space-x-1.5 transition cursor-pointer"
                        >
                          <RefreshCw className="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
                          <span>Test Token</span>
                        </button>
                      </div>

                      <button
                        type="submit"
                        className="w-full sm:w-auto px-5 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center justify-center space-x-1.5 transition cursor-pointer"
                      >
                        <Database className="w-3.5 h-3.5" />
                        <span>Save Private Key &amp; Encrypted Passphrase to DB</span>
                      </button>
                    </div>
                  </form>

                  {/* Live MariaDB Table: eop_auth_config */}
                  <div>
                    <h5 className="text-xs font-bold text-slate-900 dark:text-white mb-2.5 flex items-center gap-1.5">
                      <Database className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                      <span>MariaDB Table Records: <code>eop_auth_config</code></span>
                    </h5>
                    <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-xl">
                      <table className="w-full text-left text-xs text-slate-700 dark:text-slate-300">
                        <thead className="bg-slate-100 dark:bg-slate-800/80 text-slate-600 dark:text-slate-400 font-semibold border-b border-slate-200 dark:border-slate-800 uppercase tracking-wider text-[11px]">
                          <tr>
                            <th className="py-2.5 px-3">ID</th>
                            <th className="py-2.5 px-3">Key Filename</th>
                            <th className="py-2.5 px-3">Thumbprint</th>
                            <th className="py-2.5 px-3">Key Type</th>
                            <th className="py-2.5 px-3">Encrypted Passphrase (AES-256)</th>
                            <th className="py-2.5 px-3">IV / Tag</th>
                            <th className="py-2.5 px-3">Status</th>
                            <th className="py-2.5 px-3">Updated At</th>
                            <th className="py-2.5 px-3">By</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100 dark:divide-slate-800 font-mono text-[11px]">
                          {eopAuthRows.map((row) => (
                            <tr key={row.id} className={`hover:bg-slate-50 dark:hover:bg-slate-800/50 ${row.is_active ? 'bg-indigo-50/40 dark:bg-indigo-950/20' : ''}`}>
                              <td className="py-2.5 px-3 font-bold text-indigo-600 dark:text-indigo-400">#{row.id}</td>
                              <td className="py-2.5 px-3 font-semibold">{row.key_filename}</td>
                              <td className="py-2.5 px-3 text-[10px]" title={row.certificate_thumbprint}>
                                {row.certificate_thumbprint.substring(0, 14)}...
                              </td>
                              <td className="py-2.5 px-3">
                                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-indigo-100 dark:bg-indigo-950/60 text-indigo-800 dark:text-indigo-300">
                                  {row.key_type}
                                </span>
                              </td>
                              <td className="py-2.5 px-3 text-[10px]">
                                <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 font-sans font-medium">
                                  <Lock className="w-2.5 h-2.5" />
                                  {row.encrypted_password.substring(0, 12)}...
                                </span>
                              </td>
                              <td className="py-2.5 px-3 text-slate-500 text-[10px]">
                                {row.encryption_iv.substring(0, 6)}.. / {row.encryption_tag.substring(0, 6)}..
                              </td>
                              <td className="py-2.5 px-3">
                                {row.is_active ? (
                                  <span className="text-emerald-600 dark:text-emerald-400 font-semibold text-[10px] flex items-center gap-1 font-sans">
                                    <CheckCircle2 className="w-3 h-3" /> Active
                                  </span>
                                ) : (
                                  <span className="text-slate-400 text-[10px] font-sans">Archived</span>
                                )}
                              </td>
                              <td className="py-2.5 px-3 text-slate-500 dark:text-slate-400 text-[10px]">{row.updated_at}</td>
                              <td className="py-2.5 px-3">{row.uploaded_by}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

              {/* SECTION 2: Active Directory LDAP Connection Settings */}
              {(configSubTab === 'all' || configSubTab === 'ldap_db') && (
                <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-xs space-y-5">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-100 dark:border-slate-800">
                    <div className="flex items-center space-x-3">
                      <div className="w-9 h-9 rounded-xl bg-purple-50 dark:bg-purple-950/60 text-purple-600 dark:text-purple-400 flex items-center justify-center">
                        <Database className="w-5 h-5" />
                      </div>
                      <div>
                        <h4 className="text-sm font-bold text-slate-900 dark:text-white">
                          Active Directory LDAP Connection Settings
                        </h4>
                        <p className="text-xs text-slate-500 dark:text-slate-400">
                          Stored in MariaDB table <code className="font-mono text-purple-600 dark:text-purple-400">eop_ldap_config</code>
                        </p>
                      </div>
                    </div>
                    <span className="text-[11px] font-mono px-2.5 py-1 rounded bg-purple-50 dark:bg-purple-950/60 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-800/60 self-start sm:self-auto">
                      Active DB Record #{ldapDbRows.find((r) => r.is_active)?.id || 1}
                    </span>
                  </div>

                  {/* Protocol Callout */}
                  <div className="p-4 rounded-xl border border-blue-200 dark:border-blue-900/60 bg-blue-50/70 dark:bg-blue-950/40 text-blue-900 dark:text-blue-200 text-xs space-y-1">
                    <div className="font-bold flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                      <span>Standard Plain LDAP (Port 389) Supported &bull; LDAPS is NOT Required</span>
                    </div>
                    <p className="text-blue-800/90 dark:text-blue-300/90 leading-relaxed">
                      Plain LDAP on port 389 connects directly to your Windows Server Active Directory Domain Controller without certificates. You can also select LDAPS (port 636) or StartTLS (port 389).
                    </p>
                  </div>

                  {/* Feedback Alert Messages */}
                  {ldapSaveMessage && (
                    <div className="p-3.5 rounded-lg bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800/60 text-emerald-800 dark:text-emerald-200 text-xs flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                      <span>{ldapSaveMessage}</span>
                    </div>
                  )}

                  {ldapTestStatus && (
                    <div className={`p-3.5 rounded-lg text-xs flex items-center gap-2 border ${
                      ldapTestStatus === 'probing'
                        ? 'bg-amber-50 dark:bg-amber-950/40 border-amber-200 dark:border-amber-800/60 text-amber-800 dark:text-amber-200'
                        : 'bg-indigo-50 dark:bg-indigo-950/40 border-indigo-200 dark:border-indigo-800/60 text-indigo-800 dark:text-indigo-200'
                    }`}>
                      <RefreshCw className={`w-4 h-4 shrink-0 ${ldapTestStatus === 'probing' ? 'animate-spin' : ''}`} />
                      <span>{ldapTestStatus === 'probing' ? 'Testing connection to Active Directory Domain Controller...' : ldapTestStatus}</span>
                    </div>
                  )}

                  {/* Edit Form */}
                  <form onSubmit={handleSaveLdapDb} className="bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800 rounded-xl p-5 space-y-4">
                    <div className="font-semibold text-slate-800 dark:text-slate-200 text-xs flex items-center justify-between">
                      <span>Modify LDAP Settings in Database</span>
                      <span className="text-[11px] font-normal text-slate-500">Writes to remote MariaDB table</span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                      <div>
                        <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1">
                          LDAP Host (Domain Controller FQDN / IP):
                        </label>
                        <input
                          type="text"
                          required
                          value={ldapEditHost}
                          onChange={(e) => setLdapEditHost(e.target.value)}
                          className="w-full bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                          placeholder="dc01.corp.example.com"
                        />
                      </div>

                      <div className="grid grid-cols-2 gap-2">
                        <div>
                          <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1">Port:</label>
                          <input
                            type="number"
                            required
                            value={ldapEditPort}
                            onChange={(e) => setLdapEditPort(parseInt(e.target.value) || 389)}
                            className="w-full bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                          />
                        </div>
                        <div>
                          <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1">Protocol:</label>
                          <select
                            value={ldapEditProto}
                            onChange={(e) => {
                              const proto = e.target.value as 'ldap' | 'ldaps' | 'starttls';
                              setLdapEditProto(proto);
                              if (proto === 'ldaps' && ldapEditPort === 389) setLdapEditPort(636);
                              if (proto === 'ldap' && ldapEditPort === 636) setLdapEditPort(389);
                            }}
                            className="w-full bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-2.5 py-2 text-slate-900 dark:text-white font-medium focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                          >
                            <option value="ldap">Plain LDAP (389)</option>
                            <option value="ldaps">LDAPS (636)</option>
                            <option value="starttls">StartTLS (389)</option>
                          </select>
                        </div>
                      </div>

                      <div className="md:col-span-2">
                        <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1">
                          Base Distinguished Name (Base DN):
                        </label>
                        <input
                          type="text"
                          required
                          value={ldapEditBaseDn}
                          onChange={(e) => setLdapEditBaseDn(e.target.value)}
                          className="w-full bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                          placeholder="DC=corp,DC=example,DC=com"
                        />
                      </div>

                      <div className="md:col-span-2">
                        <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1">
                          Authorized Security Group DN:
                        </label>
                        <input
                          type="text"
                          required
                          value={ldapEditGroupDn}
                          onChange={(e) => setLdapEditGroupDn(e.target.value)}
                          className="w-full bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                          placeholder="CN=Exchange-Admins,OU=Security Groups,DC=corp,DC=example,DC=com"
                        />
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs md:col-span-2">
                        <div>
                          <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1">
                            Service Account Bind DN (Optional):
                          </label>
                          <input
                            type="text"
                            value={ldapEditBindDn}
                            onChange={(e) => setLdapEditBindDn(e.target.value)}
                            className="w-full bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                            placeholder="CN=svc-eop-web,OU=Service Accounts,DC=corp,DC=example,DC=com"
                          />
                          <p className="text-[10px] text-slate-500 dark:text-slate-400 mt-1">
                            Active Directory service account Distinguished Name used to query LDAP.
                          </p>
                        </div>

                        <div>
                          <div className="flex items-center justify-between mb-1">
                            <label className="block font-medium text-slate-700 dark:text-slate-300">
                              Bind Password for LDAP Authorization:
                            </label>
                            <button
                              type="button"
                              onClick={() => setShowLdapBindPass(!showLdapBindPass)}
                              className="text-[11px] text-purple-600 dark:text-purple-400 hover:underline flex items-center gap-1 cursor-pointer"
                            >
                              {showLdapBindPass ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                              <span>{showLdapBindPass ? 'Hide' : 'Show'}</span>
                            </button>
                          </div>
                          <div className="relative">
                            <input
                              type={showLdapBindPass ? 'text' : 'password'}
                              value={ldapEditBindPass}
                              onChange={(e) => setLdapEditBindPass(e.target.value)}
                              className="w-full bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden pr-9"
                              placeholder="••••••••••••"
                            />
                            <div className="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none text-slate-400">
                              <Lock className="w-3.5 h-3.5" />
                            </div>
                          </div>
                          <p className="text-[10px] text-slate-500 dark:text-slate-400 mt-1">
                            Active Directory service account password used for LDAP authorization and group verification.
                          </p>
                        </div>
                      </div>
                    </div>

                    <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2">
                      <div className="flex items-center space-x-2 w-full sm:w-auto">
                        <button
                          type="button"
                          onClick={() => handleTabChange('allowed_senders')}
                          className="px-3.5 py-2 border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition cursor-pointer"
                        >
                          <ArrowLeft className="w-3.5 h-3.5" />
                          <span>Back to Lists</span>
                        </button>
                        <button
                          type="button"
                          onClick={handleTestLdap}
                          className="px-3.5 py-2 bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-800 dark:text-slate-200 text-xs font-semibold rounded-lg flex items-center space-x-1.5 transition cursor-pointer"
                        >
                          <RefreshCw className="w-3.5 h-3.5" />
                          <span>Test LDAP Connection</span>
                        </button>
                      </div>

                      <button
                        type="submit"
                        className="w-full sm:w-auto px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center justify-center space-x-1.5 transition cursor-pointer"
                      >
                        <Database className="w-3.5 h-3.5" />
                        <span>Save to DB Table (eop_ldap_config)</span>
                      </button>
                    </div>
                  </form>

                  {/* Live MariaDB Table Records: eop_ldap_config */}
                  <div>
                    <h5 className="text-xs font-bold text-slate-900 dark:text-white mb-2.5 flex items-center gap-1.5">
                      <Database className="w-4 h-4 text-purple-600 dark:text-purple-400" />
                      <span>MariaDB Table Records: <code>eop_ldap_config</code></span>
                    </h5>
                    <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-xl">
                      <table className="w-full text-left text-xs text-slate-700 dark:text-slate-300">
                        <thead className="bg-slate-100 dark:bg-slate-800/80 text-slate-600 dark:text-slate-400 font-semibold border-b border-slate-200 dark:border-slate-800 uppercase tracking-wider text-[11px]">
                          <tr>
                            <th className="py-2.5 px-3">ID</th>
                            <th className="py-2.5 px-3">Host</th>
                            <th className="py-2.5 px-3">Port</th>
                            <th className="py-2.5 px-3">Protocol</th>
                            <th className="py-2.5 px-3">Base DN</th>
                            <th className="py-2.5 px-3">Group DN</th>
                            <th className="py-2.5 px-3">Bind DN</th>
                            <th className="py-2.5 px-3">Bind Password</th>
                            <th className="py-2.5 px-3">Status</th>
                            <th className="py-2.5 px-3">Updated At</th>
                            <th className="py-2.5 px-3">By</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100 dark:divide-slate-800 font-mono text-[11px]">
                          {ldapDbRows.map((row) => (
                            <tr key={row.id} className={`hover:bg-slate-50 dark:hover:bg-slate-800/50 ${row.is_active ? 'bg-purple-50/40 dark:bg-purple-950/20' : ''}`}>
                              <td className="py-2.5 px-3 font-bold text-purple-600 dark:text-purple-400">#{row.id}</td>
                              <td className="py-2.5 px-3">{row.host}</td>
                              <td className="py-2.5 px-3">{row.port}</td>
                              <td className="py-2.5 px-3">
                                <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${row.protocol === 'ldap' ? 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300' : 'bg-blue-100 dark:bg-blue-950/60 text-blue-800 dark:text-blue-300'}`}>
                                  {row.protocol.toUpperCase()}
                                </span>
                              </td>
                              <td className="py-2.5 px-3 truncate max-w-[130px]" title={row.base_dn}>{row.base_dn}</td>
                              <td className="py-2.5 px-3 truncate max-w-[130px]" title={row.authorized_group_dn}>{row.authorized_group_dn}</td>
                              <td className="py-2.5 px-3 truncate max-w-[120px]" title={row.bind_dn || 'None (Anonymous)'}>
                                {row.bind_dn ? row.bind_dn : <span className="text-slate-400 italic">Anonymous</span>}
                              </td>
                              <td className="py-2.5 px-3">
                                {row.bind_password ? (
                                  <span className="text-emerald-600 dark:text-emerald-400 font-semibold text-[10px] flex items-center gap-1 font-sans">
                                    <Lock className="w-3 h-3" /> Configured
                                  </span>
                                ) : (
                                  <span className="text-slate-400 italic text-[10px] font-sans">None</span>
                                )}
                              </td>
                              <td className="py-2.5 px-3">
                                {row.is_active ? (
                                  <span className="text-emerald-600 dark:text-emerald-400 font-semibold text-[10px] flex items-center gap-1 font-sans">
                                    <CheckCircle2 className="w-3 h-3" /> Active
                                  </span>
                                ) : (
                                  <span className="text-slate-400 text-[10px] font-sans">Archived</span>
                                )}
                              </td>
                              <td className="py-2.5 px-3 text-slate-500 dark:text-slate-400 text-[10px]">{row.updated_at}</td>
                              <td className="py-2.5 px-3">{row.updated_by}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

              {/* Bottom Return Bar */}
              <div className="pt-4 border-t border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs">
                <button
                  type="button"
                  onClick={() => handleTabChange('allowed_senders')}
                  className="w-full sm:w-auto px-4 py-2.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 border border-slate-300 dark:border-slate-700 rounded-xl font-semibold flex items-center justify-center space-x-2 transition cursor-pointer shadow-2xs"
                >
                  <ArrowLeft className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                  <span>Exit Configuration &amp; Return to Anti-Spam Lists</span>
                </button>
                <span className="text-slate-400 dark:text-slate-500 text-[11px]">All key and LDAP modifications persist to MariaDB tables</span>
              </div>
            </div>
          </div>
        ) : (
          /* List Table View */
          <div>
            {/* Global Notification Banner (Auto-dismisses after 5s) */}
            {bannerMessage && (
              <div className={`mx-4 sm:mx-6 mt-4 p-3.5 rounded-xl border text-xs flex items-center justify-between gap-3 shadow-xs transition-all duration-300 animate-fadeIn ${
                bannerMessage.type === 'success'
                  ? 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-800 text-emerald-800 dark:text-emerald-200'
                  : bannerMessage.type === 'warning'
                  ? 'bg-amber-50 dark:bg-amber-950/40 border-amber-200 dark:border-amber-800 text-amber-800 dark:text-amber-200'
                  : 'bg-rose-50 dark:bg-rose-950/40 border-rose-200 dark:border-rose-800 text-rose-800 dark:text-rose-200'
              }`}>
                <div className="flex items-center gap-2">
                  {bannerMessage.type === 'success' ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0" />
                  )}
                  <span className="font-medium">{bannerMessage.text}</span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-[10px] text-slate-400 dark:text-slate-500 font-mono hidden sm:inline">
                    auto-dismissing
                  </span>
                  <button
                    type="button"
                    onClick={() => setBannerMessage(null)}
                    className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 text-xs font-semibold px-2 py-0.5 rounded cursor-pointer hover:bg-black/5 dark:hover:bg-white/5 flex items-center gap-1"
                    title="Dismiss notification now"
                  >
                    <X className="w-3.5 h-3.5" />
                    <span>Dismiss</span>
                  </button>
                </div>
              </div>
            )}

            {/* Pending Staged Changes Notification Strip across ALL 4 tables (Auto-dismisses after 6s) */}
            {showPendingStrip && pendingChanges.length > 0 && (
              <div className="mx-4 sm:mx-6 mt-4 p-3 rounded-xl bg-blue-50/80 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-900/60 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 text-xs text-blue-900 dark:text-blue-200 shadow-xs transition-all duration-300 animate-fadeIn">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-blue-600 dark:bg-blue-400 shrink-0 animate-pulse"></span>
                  <div>
                    <span className="font-bold">{pendingChanges.length} Pending Changes Waiting Across All Tables</span>:
                    <span className="text-blue-700 dark:text-blue-300 ml-1.5 text-[11px]">
                      {allPendingByList.allowed_senders.length > 0 && `${allPendingByList.allowed_senders.length} in Allowed Senders${allPendingByList.blocked_senders.length > 0 || allPendingByList.allowed_domains.length > 0 || allPendingByList.blocked_domains.length > 0 ? ', ' : ''}`}
                      {allPendingByList.blocked_senders.length > 0 && `${allPendingByList.blocked_senders.length} in Blocked Senders${allPendingByList.allowed_domains.length > 0 || allPendingByList.blocked_domains.length > 0 ? ', ' : ''}`}
                      {allPendingByList.allowed_domains.length > 0 && `${allPendingByList.allowed_domains.length} in Allowed Domains${allPendingByList.blocked_domains.length > 0 ? ', ' : ''}`}
                      {allPendingByList.blocked_domains.length > 0 && `${allPendingByList.blocked_domains.length} in Blocked Domains`}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    type="button"
                    onClick={() => setShowPushConfirmModal(true)}
                    disabled={syncLoading}
                    className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-semibold shadow-xs transition flex items-center justify-center gap-1.5 shrink-0 cursor-pointer"
                  >
                    <CloudUpload className="w-3.5 h-3.5" />
                    <span>Review &amp; Push All Changes</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowPendingStrip(false)}
                    className="p-1 text-blue-400 hover:text-blue-700 dark:hover:text-blue-200 rounded cursor-pointer hover:bg-blue-100/50 dark:hover:bg-blue-900/50"
                    title="Dismiss alert"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            )}

            {/* Search Filter Bar */}
            <div className="p-4 bg-slate-50 dark:bg-slate-800/40 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between">
              <div className="relative max-w-sm w-full">
                <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400 dark:text-slate-500" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder={`Search ${activeTab.replace('_', ' ')} or notes...`}
                  className="w-full text-xs pl-8 pr-3 py-1.5 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-800 dark:text-slate-100 placeholder-slate-400 focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div className="flex items-center space-x-3">
                <div className="text-xs text-slate-500 dark:text-slate-400 font-mono hidden sm:inline">
                  Table: <span className="font-semibold text-blue-600 dark:text-blue-400">eop_{activeTab}</span>
                </div>
                <button
                  type="button"
                  onClick={() => setShowPushConfirmModal(true)}
                  disabled={syncLoading}
                  className="px-3.5 py-1.5 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white rounded-lg text-xs font-semibold flex items-center space-x-1.5 shadow-2xs transition cursor-pointer disabled:opacity-50"
                  title="Push all pending staged changes across all 4 tables to Exchange Online Protection"
                >
                  <CloudUpload className={`w-3.5 h-3.5 ${syncLoading && syncActionType === 'push' ? 'animate-spin' : ''}`} />
                  <span>Push All Changes to EOP</span>
                  {pendingChanges.length > 0 && (
                    <span className="px-1.5 py-0.2 rounded-full bg-white/25 text-white text-[10px] font-bold">
                      {pendingChanges.length}
                    </span>
                  )}
                </button>
              </div>
            </div>

            {/* Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-700 dark:text-slate-300">
                <thead className="bg-slate-100 dark:bg-slate-800/80 text-slate-600 dark:text-slate-400 font-semibold border-b border-slate-200 dark:border-slate-800 uppercase tracking-wider text-[11px]">
                  <tr>
                    <th className="py-3 px-4">#</th>
                    <th className="py-3 px-4">{activeTab.includes('sender') ? 'Sender Email' : 'Domain Name'}</th>
                    <th className="py-3 px-4">Reason / Ticket Note</th>
                    <th className="py-3 px-4">Added By (AD)</th>
                    <th className="py-3 px-4">Created At</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {currentList.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-12 text-center text-slate-400 dark:text-slate-500">
                        No entries found in this table for policy <strong>{activePolicy}</strong>.
                      </td>
                    </tr>
                  ) : (
                    currentList.map((item) => (
                      <tr key={item.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition">
                        <td className="py-3 px-4 text-slate-400 dark:text-slate-500 font-mono text-[11px]">{item.id}</td>
                        <td className="py-3 px-4 font-semibold text-slate-900 dark:text-white font-mono text-[13px]">{item.value}</td>
                        <td className="py-3 px-4 text-slate-600 dark:text-slate-400 max-w-xs truncate" title={item.note}>
                          {item.note || '—'}
                        </td>
                        <td className="py-3 px-4 text-slate-600 dark:text-slate-400 font-mono text-[11px]">
                          <span className="bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 px-2 py-0.5 rounded border border-slate-200 dark:border-slate-700">{item.added_by}</span>
                        </td>
                        <td className="py-3 px-4 text-slate-500 dark:text-slate-400 whitespace-nowrap text-[11px]">{item.created_at}</td>
                        <td className="py-3 px-4 text-right">
                          <button
                            type="button"
                            onClick={() => promptDelete(item.id, item.value)}
                            className="text-rose-600 dark:text-rose-400 hover:text-rose-800 dark:hover:text-rose-300 p-1.5 rounded-lg hover:bg-rose-50 dark:hover:bg-rose-950/40 transition cursor-pointer"
                            title={`Delete ${item.value}`}
                            aria-label={`Delete ${item.value}`}
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* Add Single Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-xl max-w-md w-full p-6 border border-slate-200 dark:border-slate-800">
            <h3 className="text-base font-bold text-slate-900 dark:text-white mb-1">
              Add to {activeTab.replace('_', ' ').toUpperCase()}
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">
              Inserting into table <code>eop_{activeTab}</code> for policy <strong>{activePolicy}</strong>
            </p>

            {/* Error Banner */}
            {addError && (
              <div className="p-3 mb-3 rounded-lg bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-rose-800 dark:text-rose-200 text-xs flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 text-rose-600 dark:text-rose-400 shrink-0 mt-0.5" />
                <div className="leading-snug">{addError}</div>
              </div>
            )}

            <form onSubmit={handleAddSingle} className="space-y-4 text-xs">
              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  {activeTab.includes('sender') ? 'Sender Email Address' : 'Domain Name'}
                </label>
                <input
                  type="text"
                  required
                  value={singleValue}
                  onChange={(e) => {
                    setSingleValue(e.target.value);
                    if (addError) setAddError(null);
                  }}
                  placeholder={activeTab.includes('sender') ? 'user@externalpartner.com' : 'partner.com or *.partner.com'}
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                />

                {/* Instant Real-Time Duplicate Warning */}
                {singleValue.trim() && getCurrentList().some((i) => i.value.toLowerCase() === singleValue.trim().toLowerCase()) && (
                  <div className="mt-1.5 p-2 rounded-md bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/60 text-amber-800 dark:text-amber-300 text-[11px] flex items-center gap-1.5 font-medium">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400 shrink-0" />
                    <span>Duplicate: Already exists in this list for {activePolicy}.</span>
                  </div>
                )}
              </div>

              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Ticket # / Justification Note</label>
                <textarea
                  rows={3}
                  value={singleNote}
                  onChange={(e) => setSingleNote(e.target.value)}
                  placeholder="e.g. Approved vendor communications per Security Ticket SEC-8291"
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                />
              </div>

              <div className="flex items-center justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg shadow-sm transition cursor-pointer"
                >
                  Save to MariaDB
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Bulk Import Modal */}
      {showBulkModal && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-xl max-w-lg w-full p-6 border border-slate-200 dark:border-slate-800">
            <h3 className="text-base font-bold text-slate-900 dark:text-white mb-1">
              Bulk Import - {activeTab.replace('_', ' ').toUpperCase()}
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">
              Paste one entry per line, or <code>value, optional note</code>. Duplicate entries will be automatically filtered and skipped.
            </p>

            {/* Error Banner */}
            {bulkError && (
              <div className="p-3 mb-3 rounded-lg bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-rose-800 dark:text-rose-200 text-xs flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 text-rose-600 dark:text-rose-400 shrink-0 mt-0.5" />
                <div className="leading-snug">{bulkError}</div>
              </div>
            )}

            <form onSubmit={handleBulkImport} className="space-y-4 text-xs">
              <textarea
                rows={8}
                required
                value={bulkText}
                onChange={(e) => {
                  setBulkText(e.target.value);
                  if (bulkError) setBulkError(null);
                }}
                placeholder={
                  activeTab.includes('sender')
                    ? "partner1@company.com, Vendor billing contact\npartner2@company.com, Logistics notification\nuser@agency.net, Marketing agency"
                    : "vendor-portal.com, Primary vendor\n*.partner-cdn.net, Wildcard domain\nsecure-invoicing.org, Financial domain"
                }
                className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg p-3 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
              />

              <div className="flex items-center justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setShowBulkModal(false)}
                  className="px-4 py-2 text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg shadow-sm cursor-pointer"
                >
                  Import Items
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Smart Sort & Mixed Import Modal */}
      {showSmartSortModal && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl max-w-2xl w-full p-6 border border-slate-200 dark:border-slate-800 max-h-[90vh] overflow-y-auto">
            {/* Modal Header */}
            <div className="flex items-start justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
              <div className="flex items-center space-x-2.5">
                <div className={`w-8 h-8 rounded-xl text-white flex items-center justify-center shadow-xs ${
                  smartSortTarget === 'allowed'
                    ? 'bg-gradient-to-br from-emerald-600 to-teal-600'
                    : 'bg-gradient-to-br from-rose-600 to-red-600'
                }`}>
                  {smartSortTarget === 'allowed' ? (
                    <ShieldCheck className="w-4 h-4 text-emerald-200" />
                  ) : (
                    <Ban className="w-4 h-4 text-rose-200" />
                  )}
                </div>
                <div>
                  <h3 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
                    <span>
                      Smart Sorter: {smartSortTarget === 'allowed' ? 'Allowed' : 'Blocked'} Items
                    </span>
                    <span className={`text-[10px] px-2 py-0.5 rounded-full font-semibold uppercase tracking-wider ${
                      smartSortTarget === 'allowed'
                        ? 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300'
                        : 'bg-rose-100 dark:bg-rose-950/60 text-rose-800 dark:text-rose-300'
                    }`}>
                      {smartSortTarget === 'allowed' ? 'Allowlist Mode' : 'Blocklist Mode'}
                    </span>
                  </h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Paste a mixed list of email addresses and domain names. They will automatically be sorted into{' '}
                    <code className="font-mono text-purple-600 dark:text-purple-400">
                      eop_{smartSortTarget}_senders
                    </code>{' '}
                    and{' '}
                    <code className="font-mono text-purple-600 dark:text-purple-400">
                      eop_{smartSortTarget}_domains
                    </code>.
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowSmartSortModal(false)}
                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 p-1 cursor-pointer"
              >
                ✕
              </button>
            </div>

            {/* Error Banner */}
            {smartSortError && (
              <div className="mt-4 p-3 rounded-lg bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-rose-800 dark:text-rose-200 text-xs flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 text-rose-600 dark:text-rose-400 shrink-0 mt-0.5" />
                <div className="leading-snug">{smartSortError}</div>
              </div>
            )}

            <form onSubmit={handleExecuteSmartSort} className="mt-4 space-y-4 text-xs">
              {/* Target List Selector */}
              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                  1. Target List Category (Where should these items be sorted?):
                </label>
                <div className="grid grid-cols-2 gap-3">
                  <button
                    type="button"
                    onClick={() => {
                      setSmartSortTarget('blocked');
                      if (smartSortError) setSmartSortError(null);
                    }}
                    className={`p-3 rounded-xl border text-left transition flex items-center space-x-3 cursor-pointer ${
                      smartSortTarget === 'blocked'
                        ? 'border-rose-500 bg-rose-50/70 dark:bg-rose-950/40 text-rose-900 dark:text-rose-200 ring-2 ring-rose-500/20 shadow-xs'
                        : 'border-slate-200 dark:border-slate-700 hover:border-rose-300 dark:hover:border-rose-700 text-slate-700 dark:text-slate-300'
                    }`}
                  >
                    <Ban className={`w-5 h-5 shrink-0 ${smartSortTarget === 'blocked' ? 'text-rose-600 dark:text-rose-400' : 'text-slate-400'}`} />
                    <div>
                      <div className="font-bold text-xs">Blocked Items</div>
                      <div className="text-[10px] text-slate-500 dark:text-slate-400 font-mono mt-0.5">
                        &rarr; eop_blocked_senders &amp; eop_blocked_domains
                      </div>
                    </div>
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      setSmartSortTarget('allowed');
                      if (smartSortError) setSmartSortError(null);
                    }}
                    className={`p-3 rounded-xl border text-left transition flex items-center space-x-3 cursor-pointer ${
                      smartSortTarget === 'allowed'
                        ? 'border-emerald-500 bg-emerald-50/70 dark:bg-emerald-950/40 text-emerald-900 dark:text-emerald-200 ring-2 ring-emerald-500/20 shadow-xs'
                        : 'border-slate-200 dark:border-slate-700 hover:border-emerald-300 dark:hover:border-emerald-700 text-slate-700 dark:text-slate-300'
                    }`}
                  >
                    <ShieldCheck className={`w-5 h-5 shrink-0 ${smartSortTarget === 'allowed' ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-400'}`} />
                    <div>
                      <div className="font-bold text-xs">Allowed Items</div>
                      <div className="text-[10px] text-slate-500 dark:text-slate-400 font-mono mt-0.5">
                        &rarr; eop_allowed_senders &amp; eop_allowed_domains
                      </div>
                    </div>
                  </button>
                </div>
              </div>

              {/* Paste Mixed Entries Input */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="block font-semibold text-slate-700 dark:text-slate-300">
                    2. Paste Mixed List (Emails and/or Domains, one per line):
                  </label>
                  <div className="flex items-center space-x-2">
                    <button
                      type="button"
                      onClick={() => {
                        if (smartSortTarget === 'blocked') {
                          setSmartSortText(
                            "phish-verify@account-update-sec.com, Phishing alert\nmalicious-spammer@darkweb-breach.org, Credential harvesting\nfake-invoicing@payroll-scam.net, Impersonation scam\nsuspicious-phish-domain.biz, Malicious domain\n*.stealer-redirect.top, Wildcard tracking domain\ncompromised-portal-auth.info, Malware distribution"
                          );
                        } else {
                          setSmartSortText(
                            "invoicing@strategic-partner.com, Supply chain vendor\nsupport@saas-monitor.io, Cloud incident webhook\nalerts@enterprise-metrics.net, Infrastructure alerting\ntrustedpartner.com, Primary vendor domain\n*.secure-cdn-vendor.net, Wildcard asset CDN\nglobal-logistics.org, Primary shipping portal"
                          );
                        }
                      }}
                      className="text-[11px] text-purple-600 dark:text-purple-400 hover:underline font-semibold"
                    >
                      Load Sample {smartSortTarget === 'blocked' ? 'Blocked' : 'Allowed'} List
                    </button>
                    <span className="text-slate-300 dark:text-slate-600">|</span>
                    <button
                      type="button"
                      onClick={() => setSmartSortText('')}
                      className="text-[11px] text-slate-500 hover:text-slate-700 dark:hover:text-slate-300"
                    >
                      Clear
                    </button>
                  </div>
                </div>

                <textarea
                  rows={7}
                  required
                  value={smartSortText}
                  onChange={(e) => {
                    setSmartSortText(e.target.value);
                    if (smartSortError) setSmartSortError(null);
                  }}
                  placeholder={
                    smartSortTarget === 'blocked'
                      ? "spammer@phishing-target.com, Fraudulent sender\nmalicious-domain.xyz, Phishing host domain\nbad-bot@automated-junk.net, Scraping bot\n*.credential-harvest.top, Wildcard malware domain"
                      : "partner-finance@company.com, Invoicing contact\nvendor-portal.com, Authorized supply portal\nalerts@critical-status.io, Monitoring webhook\n*.cdn-trusted-assets.net, Wildcard CDN"
                  }
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg p-3 text-slate-900 dark:text-white font-mono text-[11px] focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                />
              </div>

              {/* Default Note */}
              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Default Change Ticket / Reason Note <span className="text-slate-400 font-normal">(used if line has no comma note)</span>:
                </label>
                <input
                  type="text"
                  value={smartSortNote}
                  onChange={(e) => setSmartSortNote(e.target.value)}
                  placeholder="e.g. Incident Response Ticket #SEC-9842 Auto-Triage"
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                />
              </div>

              {/* Real-Time Classification & Deduplication Preview Panel */}
              {smartSortText.trim() && (
                <div className="p-3.5 bg-slate-50 dark:bg-slate-800/60 rounded-xl border border-slate-200 dark:border-slate-700 space-y-3">
                  <div className="flex items-center justify-between text-xs font-bold text-slate-900 dark:text-white">
                    <span className="flex items-center gap-1.5">
                      <Split className="w-3.5 h-3.5 text-purple-600 dark:text-purple-400" />
                      <span>Live Classification &amp; Routing Preview</span>
                    </span>
                    <span className="text-[11px] font-normal text-slate-500 dark:text-slate-400">
                      Policy: <strong className="text-slate-700 dark:text-slate-200">{activePolicy}</strong>
                    </span>
                  </div>

                  {/* Summary Badges */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center text-xs">
                    <div className="p-2 rounded-lg bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-900/60">
                      <div className="text-[10px] text-blue-700 dark:text-blue-300 font-semibold uppercase tracking-wider">
                        Senders (Emails)
                      </div>
                      <div className="text-base font-bold text-blue-900 dark:text-blue-100 mt-0.5">
                        {smartSortTriage.validSenders.length}
                        {smartSortTriage.duplicateSendersCount > 0 && (
                          <span className="text-[10px] font-normal text-amber-600 dark:text-amber-400 ml-1">
                            ({smartSortTriage.duplicateSendersCount} dup)
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="p-2 rounded-lg bg-indigo-50 dark:bg-indigo-950/40 border border-indigo-200 dark:border-indigo-900/60">
                      <div className="text-[10px] text-indigo-700 dark:text-indigo-300 font-semibold uppercase tracking-wider">
                        Domains
                      </div>
                      <div className="text-base font-bold text-indigo-900 dark:text-indigo-100 mt-0.5">
                        {smartSortTriage.validDomains.length}
                        {smartSortTriage.duplicateDomainsCount > 0 && (
                          <span className="text-[10px] font-normal text-amber-600 dark:text-amber-400 ml-1">
                            ({smartSortTriage.duplicateDomainsCount} dup)
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="p-2 rounded-lg bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-900/60">
                      <div className="text-[10px] text-emerald-700 dark:text-emerald-300 font-semibold uppercase tracking-wider">
                        Total New
                      </div>
                      <div className="text-base font-bold text-emerald-900 dark:text-emerald-100 mt-0.5">
                        {smartSortTriage.totalValid}
                      </div>
                    </div>

                    <div className="p-2 rounded-lg bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-900/60">
                      <div className="text-[10px] text-amber-700 dark:text-amber-300 font-semibold uppercase tracking-wider">
                        Duplicates Skipped
                      </div>
                      <div className="text-base font-bold text-amber-900 dark:text-amber-100 mt-0.5">
                        {smartSortTriage.duplicateCount}
                      </div>
                    </div>
                  </div>

                  {/* Classification Breakdown Columns */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px] pt-1">
                    {/* Senders Column */}
                    <div className="border border-slate-200 dark:border-slate-700/80 rounded-lg p-2.5 bg-white dark:bg-slate-900">
                      <div className="font-semibold text-slate-800 dark:text-slate-200 mb-1.5 flex items-center justify-between">
                        <span className="flex items-center gap-1 text-blue-600 dark:text-blue-400">
                          <Mail className="w-3.5 h-3.5" />
                          <span>Routing to <code>eop_{smartSortTarget}_senders</code>:</span>
                        </span>
                        <span className="text-[10px] text-slate-400 font-mono">{smartSortTriage.senders.length} items</span>
                      </div>
                      {smartSortTriage.senders.length === 0 ? (
                        <div className="text-slate-400 italic text-[10px]">No email addresses detected</div>
                      ) : (
                        <ul className="space-y-1 font-mono max-h-28 overflow-y-auto pr-1">
                          {smartSortTriage.senders.map((s, idx) => (
                            <li
                              key={idx}
                              className={`flex items-center justify-between px-1.5 py-0.5 rounded text-[10px] ${
                                s.isDuplicate
                                  ? 'bg-amber-50 dark:bg-amber-950/40 text-amber-800 dark:text-amber-300 line-through'
                                  : 'bg-blue-50 dark:bg-blue-950/40 text-blue-800 dark:text-blue-200'
                              }`}
                            >
                              <span className="truncate max-w-[200px]">{s.value}</span>
                              <span className="text-[9px] shrink-0 font-sans ml-1">
                                {s.isDuplicate ? '(Duplicate: skip)' : '(New)'}
                              </span>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>

                    {/* Domains Column */}
                    <div className="border border-slate-200 dark:border-slate-700/80 rounded-lg p-2.5 bg-white dark:bg-slate-900">
                      <div className="font-semibold text-slate-800 dark:text-slate-200 mb-1.5 flex items-center justify-between">
                        <span className="flex items-center gap-1 text-indigo-600 dark:text-indigo-400">
                          <Globe className="w-3.5 h-3.5" />
                          <span>Routing to <code>eop_{smartSortTarget}_domains</code>:</span>
                        </span>
                        <span className="text-[10px] text-slate-400 font-mono">{smartSortTriage.domains.length} items</span>
                      </div>
                      {smartSortTriage.domains.length === 0 ? (
                        <div className="text-slate-400 italic text-[10px]">No domains detected</div>
                      ) : (
                        <ul className="space-y-1 font-mono max-h-28 overflow-y-auto pr-1">
                          {smartSortTriage.domains.map((d, idx) => (
                            <li
                              key={idx}
                              className={`flex items-center justify-between px-1.5 py-0.5 rounded text-[10px] ${
                                d.isDuplicate
                                  ? 'bg-amber-50 dark:bg-amber-950/40 text-amber-800 dark:text-amber-300 line-through'
                                  : 'bg-indigo-50 dark:bg-indigo-950/40 text-indigo-800 dark:text-indigo-200'
                              }`}
                            >
                              <span className="truncate max-w-[200px]">{d.value}</span>
                              <span className="text-[9px] shrink-0 font-sans ml-1">
                                {d.isDuplicate ? '(Duplicate: skip)' : '(New)'}
                              </span>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  </div>

                  {/* Invalid syntax warnings */}
                  {smartSortTriage.invalid.length > 0 && (
                    <div className="p-2 rounded-lg bg-rose-50 dark:bg-rose-950/30 border border-rose-200 dark:border-rose-900/60 text-rose-800 dark:text-rose-300 text-[10px]">
                      <span className="font-bold">Notice:</span> {smartSortTriage.invalid.length} line(s) have invalid email/domain syntax and will be skipped:
                      <span className="font-mono ml-1 font-normal truncate inline-block max-w-[250px] align-bottom">
                        {smartSortTriage.invalid.map((i) => i.value).join(', ')}
                      </span>
                    </div>
                  )}
                </div>
              )}

              {/* Modal Actions */}
              <div className="flex items-center justify-between pt-2 border-t border-slate-100 dark:border-slate-800">
                <span className="text-[11px] text-slate-500 dark:text-slate-400">
                  Target: <strong>{smartSortTarget === 'blocked' ? 'Blocked' : 'Allowed'}</strong> &bull; Policy: <strong>{activePolicy}</strong>
                </span>

                <div className="flex items-center space-x-2">
                  <button
                    type="button"
                    onClick={() => setShowSmartSortModal(false)}
                    className="px-4 py-2 text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg font-medium"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={smartSortTriage.totalValid === 0}
                    className={`px-5 py-2 text-white font-semibold rounded-lg shadow-sm flex items-center space-x-1.5 transition ${
                      smartSortTriage.totalValid === 0
                        ? 'bg-slate-400 dark:bg-slate-600 cursor-not-allowed'
                        : smartSortTarget === 'allowed'
                        ? 'bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-700 hover:to-teal-700 cursor-pointer'
                        : 'bg-gradient-to-r from-rose-600 to-red-600 hover:from-rose-700 hover:to-red-700 cursor-pointer'
                    }`}
                  >
                    {smartSortTarget === 'allowed' ? (
                      <ShieldCheck className="w-3.5 h-3.5 text-emerald-200" />
                    ) : (
                      <Ban className="w-3.5 h-3.5 text-rose-200" />
                    )}
                    <span>
                      Sort &amp; Import {smartSortTriage.totalValid > 0 ? `${smartSortTriage.totalValid} Items ` : ''}to {smartSortTarget === 'allowed' ? 'Allowed' : 'Blocked'} Lists
                    </span>
                  </button>
                </div>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Item Confirmation Modal */}
      {deleteConfirmItem && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 flex items-center justify-center p-4 animate-in fade-in duration-150">
          <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl max-w-md w-full p-6 border border-slate-200 dark:border-slate-800">
            <div className="w-10 h-10 rounded-xl bg-rose-100 dark:bg-rose-950/60 text-rose-600 dark:text-rose-400 flex items-center justify-center mb-3">
              <Trash2 className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-slate-900 dark:text-white mb-1">
              Remove Entry from Policy?
            </h3>
            <p className="text-xs text-slate-600 dark:text-slate-400 mb-4 leading-relaxed">
              Are you sure you want to delete <strong className="font-mono text-slate-900 dark:text-white font-semibold">{deleteConfirmItem.value}</strong> from <span className="font-semibold">{deleteConfirmItem.tab.replace('_', ' ')}</span>?
              This will remove the record from MariaDB table <code>eop_{deleteConfirmItem.tab}</code> and will be omitted from Exchange Online on the next push.
            </p>

            <div className="flex items-center justify-end space-x-2 pt-3 border-t border-slate-100 dark:border-slate-800">
              <button
                type="button"
                onClick={() => setDeleteConfirmItem(null)}
                className="px-4 py-2 text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg text-xs font-medium cursor-pointer transition"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={confirmDelete}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-700 text-white rounded-lg text-xs font-semibold shadow-sm transition cursor-pointer flex items-center gap-1.5"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Delete Entry</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Manual Admin Push Confirmation Modal */}
      {showPushConfirmModal && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 flex items-center justify-center p-4 animate-in fade-in duration-150">
          <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl max-w-xl w-full p-6 border border-slate-200 dark:border-slate-800 max-h-[90vh] flex flex-col">
            <div className="flex items-center space-x-3 mb-3">
              <div className="w-10 h-10 rounded-xl bg-blue-100 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 flex items-center justify-center shrink-0">
                <CloudUpload className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-white">
                  Push All Pending Changes to Exchange Online Protection?
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Target: <strong className="text-blue-600 dark:text-blue-400">{activePolicy}</strong> &bull; All 4 MariaDB Tables
                </p>
              </div>
            </div>

            <p className="text-xs text-slate-600 dark:text-slate-400 mb-3 leading-relaxed">
              This action will push <strong>all pending changes across all tables</strong> (not just the currently active view) to Microsoft 365 Exchange Online Protection using <code className="text-blue-600 dark:text-blue-400 font-bold">Set-HostedContentFilterPolicy</code>.
            </p>

            {/* Pending Changes Summary Pill Row */}
            <div className="p-3 mb-3 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 text-xs space-y-2">
              <div className="flex items-center justify-between">
                <div className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  Pending Changes to Deploy ({pendingChanges.length} Total):
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded-full font-bold bg-blue-100 dark:bg-blue-950/80 text-blue-800 dark:text-blue-300">
                  All 4 Tables
                </span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center text-xs">
                <div className="bg-white dark:bg-slate-900 p-2 rounded-lg border border-slate-200 dark:border-slate-700">
                  <span className="block font-bold text-sm text-emerald-600 dark:text-emerald-400">
                    {allPendingByList.allowed_senders.length}
                  </span>
                  <span className="text-[10px] text-slate-500 dark:text-slate-400">Allowed Senders</span>
                </div>
                <div className="bg-white dark:bg-slate-900 p-2 rounded-lg border border-slate-200 dark:border-slate-700">
                  <span className="block font-bold text-sm text-rose-600 dark:text-rose-400">
                    {allPendingByList.blocked_senders.length}
                  </span>
                  <span className="text-[10px] text-slate-500 dark:text-slate-400">Blocked Senders</span>
                </div>
                <div className="bg-white dark:bg-slate-900 p-2 rounded-lg border border-slate-200 dark:border-slate-700">
                  <span className="block font-bold text-sm text-cyan-600 dark:text-cyan-400">
                    {allPendingByList.allowed_domains.length}
                  </span>
                  <span className="text-[10px] text-slate-500 dark:text-slate-400">Allowed Domains</span>
                </div>
                <div className="bg-white dark:bg-slate-900 p-2 rounded-lg border border-slate-200 dark:border-slate-700">
                  <span className="block font-bold text-sm text-amber-600 dark:text-amber-400">
                    {allPendingByList.blocked_domains.length}
                  </span>
                  <span className="text-[10px] text-slate-500 dark:text-slate-400">Blocked Domains</span>
                </div>
              </div>
            </div>

            {/* Scrollable list of pending staged items */}
            <div className="overflow-y-auto space-y-1.5 my-1 grow max-h-48 p-2 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800 font-mono text-xs">
              {pendingChanges.length === 0 ? (
                <div className="p-4 text-center text-slate-400 dark:text-slate-500 italic text-[11px] font-sans">
                  No new staged changes queued. Pushing will re-verify and enforce all current records across all 4 tables in Exchange Online Protection ({totalStagedItems} total items in policy "{activePolicy}").
                </div>
              ) : (
                pendingChanges.map((change) => (
                  <div
                    key={change.id}
                    className="flex items-center justify-between p-2 rounded bg-white dark:bg-slate-900 border border-slate-100 dark:border-slate-800 text-[11px]"
                  >
                    <div className="flex items-center space-x-2 truncate">
                      <span
                        className={`px-1.5 py-0.2 rounded text-[9px] font-bold shrink-0 ${
                          change.type === 'ADD'
                            ? 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300'
                            : 'bg-rose-100 dark:bg-rose-950/60 text-rose-800 dark:text-rose-300'
                        }`}
                      >
                        {change.type === 'ADD' ? '+ ADD' : '- REMOVE'}
                      </span>
                      <span className="font-bold text-slate-800 dark:text-slate-100 truncate">{change.value}</span>
                    </div>
                    <div className="flex items-center space-x-2 shrink-0 ml-2 font-sans text-[10px]">
                      <span className="px-1.5 py-0.2 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300">
                        {change.listLabel}
                      </span>
                      <span className="text-slate-400 dark:text-slate-500 hidden sm:inline">
                        {change.policy}
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>

            <div className="flex items-center justify-between pt-3 mt-3 border-t border-slate-100 dark:border-slate-800">
              <span className="text-[11px] text-slate-400 dark:text-slate-500">
                Pushes all 4 tables &bull; Records in audit trail
              </span>
              <div className="flex items-center space-x-2">
                <button
                  type="button"
                  onClick={() => setShowPushConfirmModal(false)}
                  className="px-4 py-2 text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg text-xs font-medium cursor-pointer transition"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setShowPushConfirmModal(false);
                    handleTriggerSync('push');
                  }}
                  className="px-4 py-2 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white rounded-lg text-xs font-semibold shadow-sm transition cursor-pointer flex items-center gap-1.5"
                >
                  <CloudUpload className="w-3.5 h-3.5" />
                  <span>
                    Push All {pendingChanges.length > 0 ? `${pendingChanges.length} Changes` : 'Tables'} to EOP
                  </span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Push Completion Result Modal: Showing what was added to each list */}
      {pushSummaryModal && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 flex items-center justify-center p-4 animate-in fade-in duration-200">
          <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl max-w-2xl w-full p-6 border border-slate-200 dark:border-slate-800 flex flex-col max-h-[90vh]">
            {/* Header */}
            <div className="flex items-start justify-between pb-4 border-b border-slate-200 dark:border-slate-800">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 rounded-xl bg-emerald-100 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400 flex items-center justify-center">
                  <CheckCircle className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
                    <span>All Changes Successfully Pushed to EOP</span>
                    <span className="text-[11px] font-medium px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/40">Success</span>
                  </h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    Policy: <strong className="text-slate-700 dark:text-slate-200">{pushSummaryModal.policy}</strong> &bull; Synced at: <span className="font-mono">{pushSummaryModal.timestamp}</span>
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setPushSummaryModal(null)}
                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 p-1 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition cursor-pointer"
                aria-label="Close"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Tabs Navigation */}
            <div className="flex border-b border-slate-200 dark:border-slate-800 text-xs font-semibold mt-3">
              <button
                onClick={() => setPushSummaryTab('changes')}
                className={`py-2 px-4 border-b-2 transition flex items-center gap-1.5 cursor-pointer ${
                  pushSummaryTab === 'changes'
                    ? 'border-blue-600 text-blue-600 dark:text-blue-400'
                    : 'border-transparent text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
                }`}
              >
                <span>Changes Pushed to Lists</span>
                <span className="px-1.5 py-0.2 rounded-full bg-blue-100 dark:bg-blue-950/60 text-blue-800 dark:text-blue-300 text-[10px]">
                  {pushSummaryModal.pushedChanges.length}
                </span>
              </button>
              <button
                onClick={() => setPushSummaryTab('all_entries')}
                className={`py-2 px-4 border-b-2 transition flex items-center gap-1.5 cursor-pointer ${
                  pushSummaryTab === 'all_entries'
                    ? 'border-blue-600 text-blue-600 dark:text-blue-400'
                    : 'border-transparent text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
                }`}
              >
                <span>Current Resulting EOP Lists</span>
                <span className="px-1.5 py-0.2 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 text-[10px]">
                  {pushSummaryModal.allowedSenders.length + pushSummaryModal.blockedSenders.length + pushSummaryModal.allowedDomains.length + pushSummaryModal.blockedDomains.length}
                </span>
              </button>
              <button
                onClick={() => setPushSummaryTab('powershell')}
                className={`py-2 px-4 border-b-2 transition flex items-center gap-1.5 cursor-pointer ${
                  pushSummaryTab === 'powershell'
                    ? 'border-blue-600 text-blue-600 dark:text-blue-400'
                    : 'border-transparent text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
                }`}
              >
                <span>PowerShell Cmdlet</span>
              </button>
            </div>

            {/* Subheader / Summary pill row */}
            <div className="py-2.5 text-xs text-slate-600 dark:text-slate-300">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center text-xs">
                <div className="bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800/50 p-2 rounded-lg">
                  <span className="block text-emerald-800 dark:text-emerald-300 font-bold text-sm">
                    {pushSummaryModal.changesByList.allowed_senders.length}
                  </span>
                  <span className="text-[11px] text-emerald-700 dark:text-emerald-400">Allowed Senders Changed</span>
                </div>
                <div className="bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800/50 p-2 rounded-lg">
                  <span className="block text-rose-800 dark:text-rose-300 font-bold text-sm">
                    {pushSummaryModal.changesByList.blocked_senders.length}
                  </span>
                  <span className="text-[11px] text-rose-700 dark:text-rose-400">Blocked Senders Changed</span>
                </div>
                <div className="bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800/50 p-2 rounded-lg">
                  <span className="block text-emerald-800 dark:text-emerald-300 font-bold text-sm">
                    {pushSummaryModal.changesByList.allowed_domains.length}
                  </span>
                  <span className="text-[11px] text-emerald-700 dark:text-emerald-400">Allowed Domains Changed</span>
                </div>
                <div className="bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800/50 p-2 rounded-lg">
                  <span className="block text-rose-800 dark:text-rose-300 font-bold text-sm">
                    {pushSummaryModal.changesByList.blocked_domains.length}
                  </span>
                  <span className="text-[11px] text-rose-700 dark:text-rose-400">Blocked Domains Changed</span>
                </div>
              </div>
            </div>

            {/* Tab 1: Detailed breakdown of what changes were pushed to what list */}
            {pushSummaryTab === 'changes' && (
              <div className="overflow-y-auto space-y-4 pr-1 my-2 grow divide-y divide-slate-100 dark:divide-slate-800">
                {/* 1. Allowed Senders Changes */}
                <div className="pt-2">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                      <span>1. Allowed Senders (<code>-AllowedSenders</code> / <code>eop_allowed_senders</code>)</span>
                    </span>
                    <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300">
                      {pushSummaryModal.changesByList.allowed_senders.length} changes pushed
                    </span>
                  </div>
                  {pushSummaryModal.changesByList.allowed_senders.length > 0 ? (
                    <div className="space-y-1.5 max-h-36 overflow-y-auto p-2 bg-slate-50 dark:bg-slate-800/60 rounded-lg border border-slate-200 dark:border-slate-800">
                      {pushSummaryModal.changesByList.allowed_senders.map((change) => (
                        <div key={change.id} className="flex items-center justify-between p-1.5 bg-white dark:bg-slate-900 rounded border border-slate-200/60 dark:border-slate-700/60 text-xs">
                          <div className="flex items-center space-x-2">
                            <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
                              change.type === 'ADD' ? 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300' : 'bg-rose-100 dark:bg-rose-950/60 text-rose-800 dark:text-rose-300'
                            }`}>
                              {change.type === 'ADD' ? '+ ADDED' : '- REMOVED'}
                            </span>
                            <span className="font-mono font-semibold text-slate-900 dark:text-slate-100">{change.value}</span>
                          </div>
                          <div className="text-[11px] text-slate-500 dark:text-slate-400 truncate max-w-xs">
                            {change.note || change.policy}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-[11px] italic text-slate-400 pl-3">
                      No pending changes were queued for Allowed Senders (current state maintained: {pushSummaryModal.allowedSenders.length} entries).
                    </p>
                  )}
                </div>

                {/* 2. Blocked Senders Changes */}
                <div className="pt-3">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-rose-500"></span>
                      <span>2. Blocked Senders (<code>-BlockedSenders</code> / <code>eop_blocked_senders</code>)</span>
                    </span>
                    <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-rose-100 dark:bg-rose-950/60 text-rose-800 dark:text-rose-300">
                      {pushSummaryModal.changesByList.blocked_senders.length} changes pushed
                    </span>
                  </div>
                  {pushSummaryModal.changesByList.blocked_senders.length > 0 ? (
                    <div className="space-y-1.5 max-h-36 overflow-y-auto p-2 bg-slate-50 dark:bg-slate-800/60 rounded-lg border border-slate-200 dark:border-slate-800">
                      {pushSummaryModal.changesByList.blocked_senders.map((change) => (
                        <div key={change.id} className="flex items-center justify-between p-1.5 bg-white dark:bg-slate-900 rounded border border-slate-200/60 dark:border-slate-700/60 text-xs">
                          <div className="flex items-center space-x-2">
                            <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
                              change.type === 'ADD' ? 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300' : 'bg-rose-100 dark:bg-rose-950/60 text-rose-800 dark:text-rose-300'
                            }`}>
                              {change.type === 'ADD' ? '+ ADDED' : '- REMOVED'}
                            </span>
                            <span className="font-mono font-semibold text-slate-900 dark:text-slate-100">{change.value}</span>
                          </div>
                          <div className="text-[11px] text-slate-500 dark:text-slate-400 truncate max-w-xs">
                            {change.note || change.policy}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-[11px] italic text-slate-400 pl-3">
                      No pending changes were queued for Blocked Senders (current state maintained: {pushSummaryModal.blockedSenders.length} entries).
                    </p>
                  )}
                </div>

                {/* 3. Allowed Domains Changes */}
                <div className="pt-3">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-cyan-500"></span>
                      <span>3. Allowed Sender Domains (<code>-AllowedSenderDomains</code> / <code>eop_allowed_domains</code>)</span>
                    </span>
                    <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-cyan-100 dark:bg-cyan-950/60 text-cyan-800 dark:text-cyan-300">
                      {pushSummaryModal.changesByList.allowed_domains.length} changes pushed
                    </span>
                  </div>
                  {pushSummaryModal.changesByList.allowed_domains.length > 0 ? (
                    <div className="space-y-1.5 max-h-36 overflow-y-auto p-2 bg-slate-50 dark:bg-slate-800/60 rounded-lg border border-slate-200 dark:border-slate-800">
                      {pushSummaryModal.changesByList.allowed_domains.map((change) => (
                        <div key={change.id} className="flex items-center justify-between p-1.5 bg-white dark:bg-slate-900 rounded border border-slate-200/60 dark:border-slate-700/60 text-xs">
                          <div className="flex items-center space-x-2">
                            <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
                              change.type === 'ADD' ? 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300' : 'bg-rose-100 dark:bg-rose-950/60 text-rose-800 dark:text-rose-300'
                            }`}>
                              {change.type === 'ADD' ? '+ ADDED' : '- REMOVED'}
                            </span>
                            <span className="font-mono font-semibold text-slate-900 dark:text-slate-100">{change.value}</span>
                          </div>
                          <div className="text-[11px] text-slate-500 dark:text-slate-400 truncate max-w-xs">
                            {change.note || change.policy}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-[11px] italic text-slate-400 pl-3">
                      No pending changes were queued for Allowed Domains (current state maintained: {pushSummaryModal.allowedDomains.length} entries).
                    </p>
                  )}
                </div>

                {/* 4. Blocked Domains Changes */}
                <div className="pt-3">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-amber-500"></span>
                      <span>4. Blocked Sender Domains (<code>-BlockedSenderDomains</code> / <code>eop_blocked_domains</code>)</span>
                    </span>
                    <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300">
                      {pushSummaryModal.changesByList.blocked_domains.length} changes pushed
                    </span>
                  </div>
                  {pushSummaryModal.changesByList.blocked_domains.length > 0 ? (
                    <div className="space-y-1.5 max-h-36 overflow-y-auto p-2 bg-slate-50 dark:bg-slate-800/60 rounded-lg border border-slate-200 dark:border-slate-800">
                      {pushSummaryModal.changesByList.blocked_domains.map((change) => (
                        <div key={change.id} className="flex items-center justify-between p-1.5 bg-white dark:bg-slate-900 rounded border border-slate-200/60 dark:border-slate-700/60 text-xs">
                          <div className="flex items-center space-x-2">
                            <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
                              change.type === 'ADD' ? 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300' : 'bg-rose-100 dark:bg-rose-950/60 text-rose-800 dark:text-rose-300'
                            }`}>
                              {change.type === 'ADD' ? '+ ADDED' : '- REMOVED'}
                            </span>
                            <span className="font-mono font-semibold text-slate-900 dark:text-slate-100">{change.value}</span>
                          </div>
                          <div className="text-[11px] text-slate-500 dark:text-slate-400 truncate max-w-xs">
                            {change.note || change.policy}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-[11px] italic text-slate-400 pl-3">
                      No pending changes were queued for Blocked Domains (current state maintained: {pushSummaryModal.blockedDomains.length} entries).
                    </p>
                  )}
                </div>
              </div>
            )}

            {/* Tab 2: All Active Entries in EOP */}
            {pushSummaryTab === 'all_entries' && (
              <div className="overflow-y-auto space-y-4 pr-1 my-2 grow divide-y divide-slate-100 dark:divide-slate-800">
                {/* 1. Allowed Senders */}
                <div className="pt-2">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                      <span>Allowed Senders (<code>-AllowedSenders</code>)</span>
                    </span>
                    <span className="text-[11px] text-slate-400 font-mono">eop_allowed_senders</span>
                  </div>
                  {pushSummaryModal.allowedSenders.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto p-2 bg-slate-50 dark:bg-slate-800/60 rounded-lg border border-slate-200 dark:border-slate-800">
                      {pushSummaryModal.allowedSenders.map((val) => (
                        <span key={val} className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-white dark:bg-slate-900 border border-emerald-300 dark:border-emerald-800 text-emerald-800 dark:text-emerald-300">
                          {val}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <p className="text-[11px] italic text-slate-400 pl-3">No allowed senders configured for this policy.</p>
                  )}
                </div>

                {/* 2. Blocked Senders */}
                <div className="pt-3">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-rose-500"></span>
                      <span>Blocked Senders (<code>-BlockedSenders</code>)</span>
                    </span>
                    <span className="text-[11px] text-slate-400 font-mono">eop_blocked_senders</span>
                  </div>
                  {pushSummaryModal.blockedSenders.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto p-2 bg-slate-50 dark:bg-slate-800/60 rounded-lg border border-slate-200 dark:border-slate-800">
                      {pushSummaryModal.blockedSenders.map((val) => (
                        <span key={val} className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-white dark:bg-slate-900 border border-rose-300 dark:border-rose-800 text-rose-800 dark:text-rose-300">
                          {val}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <p className="text-[11px] italic text-slate-400 pl-3">No blocked senders configured for this policy.</p>
                  )}
                </div>

                {/* 3. Allowed Domains */}
                <div className="pt-3">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-cyan-500"></span>
                      <span>Allowed Sender Domains (<code>-AllowedSenderDomains</code>)</span>
                    </span>
                    <span className="text-[11px] text-slate-400 font-mono">eop_allowed_domains</span>
                  </div>
                  {pushSummaryModal.allowedDomains.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto p-2 bg-slate-50 dark:bg-slate-800/60 rounded-lg border border-slate-200 dark:border-slate-800">
                      {pushSummaryModal.allowedDomains.map((val) => (
                        <span key={val} className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-white dark:bg-slate-900 border border-emerald-300 dark:border-emerald-800 text-emerald-800 dark:text-emerald-300">
                          {val}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <p className="text-[11px] italic text-slate-400 pl-3">No allowed domains configured for this policy.</p>
                  )}
                </div>

                {/* 4. Blocked Domains */}
                <div className="pt-3">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-rose-500"></span>
                      <span>Blocked Sender Domains (<code>-BlockedSenderDomains</code>)</span>
                    </span>
                    <span className="text-[11px] text-slate-400 font-mono">eop_blocked_domains</span>
                  </div>
                  {pushSummaryModal.blockedDomains.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto p-2 bg-slate-50 dark:bg-slate-800/60 rounded-lg border border-slate-200 dark:border-slate-800">
                      {pushSummaryModal.blockedDomains.map((val) => (
                        <span key={val} className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-white dark:bg-slate-900 border border-rose-300 dark:border-rose-800 text-rose-800 dark:text-rose-300">
                          {val}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <p className="text-[11px] italic text-slate-400 pl-3">No blocked domains configured for this policy.</p>
                  )}
                </div>
              </div>
            )}

            {/* Tab 3: PowerShell Cmdlet Executed */}
            {pushSummaryTab === 'powershell' && (
              <div className="overflow-y-auto my-2 grow p-4 bg-slate-950 rounded-xl font-mono text-xs text-slate-200 border border-slate-800">
                <div className="text-slate-500 mb-2"># Executed via PowerShell against Exchange Online Protection:</div>
                <div className="text-indigo-400 font-bold">Set-HostedContentFilterPolicy `</div>
                <div className="pl-4 text-emerald-400">-Identity "{pushSummaryModal.policy}" `</div>
                <div className="pl-4 text-blue-300">
                  -AllowedSenders @({pushSummaryModal.allowedSenders.map((s) => `'${s}'`).join(', ') || '@()'}) `
                </div>
                <div className="pl-4 text-rose-300">
                  -BlockedSenders @({pushSummaryModal.blockedSenders.map((s) => `'${s}'`).join(', ') || '@()'}) `
                </div>
                <div className="pl-4 text-cyan-300">
                  -AllowedSenderDomains @({pushSummaryModal.allowedDomains.map((d) => `'${d}'`).join(', ') || '@()'}) `
                </div>
                <div className="pl-4 text-amber-300">
                  -BlockedSenderDomains @({pushSummaryModal.blockedDomains.map((d) => `'${d}'`).join(', ') || '@()'})
                </div>
              </div>
            )}

            {/* Footer */}
            <div className="pt-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between">
              <span className="text-[11px] text-slate-400 dark:text-slate-500">
                Action recorded in <code>eop_audit_log</code> &bull; All 4 MariaDB tables in sync with EOP
              </span>
              <button
                type="button"
                onClick={() => setPushSummaryModal(null)}
                className="px-5 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-semibold shadow-xs transition cursor-pointer"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Duplicate / Existing Item Warning Popup */}
      {duplicateWarningPopup && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 flex items-center justify-center p-4 animate-in fade-in duration-150">
          <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl max-w-md w-full p-6 border border-amber-200 dark:border-amber-800/80">
            <div className="flex items-start justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 rounded-xl bg-amber-100 dark:bg-amber-950/60 text-amber-600 dark:text-amber-400 flex items-center justify-center shrink-0">
                  <AlertTriangle className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-slate-900 dark:text-white">
                    {duplicateWarningPopup.isConflict ? 'Cross-List Policy Conflict' : 'Entry Already in List'}
                  </h3>
                  <span className="text-[11px] font-semibold uppercase px-2 py-0.5 rounded-full bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800/50">
                    Duplicate Rejected
                  </span>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setDuplicateWarningPopup(null)}
                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 p-1 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition cursor-pointer"
                aria-label="Close"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="my-4 text-xs text-slate-600 dark:text-slate-300 space-y-3">
              <p className="leading-relaxed">
                The entry <strong className="font-mono text-slate-900 dark:text-white px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700">{duplicateWarningPopup.value}</strong> cannot be added because it already exists in policy <strong className="text-slate-900 dark:text-white font-semibold">"{duplicateWarningPopup.policy}"</strong>.
              </p>

              {duplicateWarningPopup.isConflict ? (
                <div className="p-3 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800/60 text-rose-800 dark:text-rose-200">
                  <div className="font-semibold text-xs mb-1">Conflicting Table:</div>
                  <div className="text-[11px] leading-relaxed">
                    This value is currently configured in <strong className="font-mono">{duplicateWarningPopup.conflictList}</strong>. An address or domain cannot be simultaneously allowed and blocked in the same policy.
                  </div>
                </div>
              ) : (
                <div className="p-3 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/60 text-amber-900 dark:text-amber-200">
                  <div className="font-semibold text-xs mb-1">Existing Record Details:</div>
                  <div className="space-y-1 text-[11px]">
                    <div><span className="text-slate-500 dark:text-slate-400">Target List:</span> <strong className="font-mono">{duplicateWarningPopup.listLabel}</strong></div>
                    {duplicateWarningPopup.addedBy && (
                      <div><span className="text-slate-500 dark:text-slate-400">Added By:</span> <span className="font-mono">{duplicateWarningPopup.addedBy}</span></div>
                    )}
                    {duplicateWarningPopup.createdAt && (
                      <div><span className="text-slate-500 dark:text-slate-400">Date Added:</span> <span>{duplicateWarningPopup.createdAt}</span></div>
                    )}
                    {duplicateWarningPopup.existingNote && (
                      <div><span className="text-slate-500 dark:text-slate-400">Note:</span> <span className="italic">{duplicateWarningPopup.existingNote}</span></div>
                    )}
                  </div>
                </div>
              )}

              <p className="text-[11px] text-slate-500 dark:text-slate-400 italic">
                MariaDB enforces a unique constraint <code>uk_policy_sender</code> / <code>uk_policy_domain</code> to ensure data integrity and prevent redundant entries in Exchange Online.
              </p>
            </div>

            <div className="flex items-center justify-end pt-3 border-t border-slate-100 dark:border-slate-800">
              <button
                type="button"
                onClick={() => setDuplicateWarningPopup(null)}
                className="px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-lg text-xs font-semibold shadow-xs transition cursor-pointer"
              >
                Understood
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
