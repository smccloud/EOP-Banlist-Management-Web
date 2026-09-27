export interface AppConfig {
  dbHost: string;
  dbPort: number;
  dbName: string;
  dbUser: string;
  dbPass: string;
  dbCharset: string;
  
  ldapHost: string;
  ldapPort: number;
  ldapProtocol: 'ldap' | 'ldaps' | 'starttls';
  ldapUseSsl: boolean;
  ldapUseTls: boolean;
  ldapBaseDn: string;
  ldapGroupDn: string;
  ldapBindDn: string;
  ldapBindPass: string;
  ldapDomain: string;

  defaultPolicyName: string;
  appTitle: string;
  appUrl: string;
  sessionTimeoutMinutes: number;

  tenantId: string;
  clientId: string;
  clientSecret: string;
  certificateThumbprint: string;
  keyPassword?: string;
  privateKeyPem?: string;
  keyFilename?: string;
  organization?: string;
}

export interface EopAuthConfig {
  id: number;
  tenant_id: string;
  client_id: string;
  certificate_thumbprint: string;
  key_filename: string;
  private_key_pem: string;
  encrypted_password: string; // Stored as AES-256-GCM encrypted in database
  encryption_iv: string;
  encryption_tag: string;
  organization: string;
  key_type: 'RSA_PEM' | 'PKCS8_PEM' | 'PKCS12_PFX';
  is_active: boolean;
  uploaded_by: string;
  created_at: string;
  updated_at: string;
}

export type ListType = 'allowed_senders' | 'blocked_senders' | 'allowed_domains' | 'blocked_domains';

export interface ListItem {
  id: number;
  policy_name: string;
  value: string; // email or domain
  note: string;
  added_by: string;
  created_at: string;
  updated_at: string;
}

export interface AuditLogEntry {
  id: number;
  timestamp: string;
  username: string;
  action: 'ADD' | 'REMOVE' | 'UPDATE' | 'SYNC' | 'LOGIN' | 'LOGOUT';
  list_type: ListType | 'SYSTEM';
  policy_name: string;
  target_value: string;
  details: string;
  ip_address: string;
}

export interface PolicyInfo {
  name: string;
  description: string;
  lastSynced: string | null;
  syncStatus: 'synced' | 'pending' | 'failed';
  allowedSendersCount: number;
  blockedSendersCount: number;
  allowedDomainsCount: number;
  blockedDomainsCount: number;
}

export interface LdapDbConfig {
  id: number;
  host: string;
  port: number;
  protocol: 'ldap' | 'ldaps' | 'starttls';
  use_ssl: boolean;
  use_tls: boolean;
  base_dn: string;
  authorized_group_dn: string;
  bind_dn: string;
  bind_password?: string;
  account_suffix: string;
  netbios_domain: string;
  timeout_seconds: number;
  is_active: boolean;
  updated_by: string;
  updated_at: string;
}

export interface PhpFileTemplate {
  name: string;
  path: string;
  description: string;
  category: 'core' | 'views' | 'auth' | 'sync' | 'config' | 'debian';
  generateContent: (config: AppConfig) => string;
}
