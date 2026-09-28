<?php
/**
 * Microsoft Active Directory LDAP Authentication Service
 * Dynamically queries LDAP connection information from MariaDB table 'eop_ldap_config'.
 * Enforces Group Distinguished Name (Group DN) access control.
 * Supports:
 * - Standard Plain LDAP (port 389) - LDAPS is NOT required!
 * - Optional StartTLS (port 389) or LDAPS (port 636) if desired
 * - Microsoft AD recursive nested group membership via LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941)
 * - Service account bind or direct user binding
 */

declare(strict_types=1);
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';

class LdapAuth {
    private $ldapConn = null;
    private array $ldapConfig = [];

    public function __construct() {
        // Dynamically load LDAP connection parameters from the MariaDB database table eop_ldap_config
        $dbConfig = Database::getLdapConfig();

        $this->ldapConfig = [
            'host'           => $dbConfig['host'] ?? (defined('LDAP_HOST') ? LDAP_HOST : '127.0.0.1'),
            'port'           => !empty($dbConfig['port']) ? (int)$dbConfig['port'] : (defined('LDAP_PORT') ? LDAP_PORT : 389),
            'protocol'       => $dbConfig['protocol'] ?? (defined('LDAP_PROTOCOL') ? LDAP_PROTOCOL : 'ldap'),
            'use_ssl'        => isset($dbConfig['use_ssl']) ? (bool)$dbConfig['use_ssl'] : (defined('LDAP_USE_SSL') ? LDAP_USE_SSL : false),
            'use_tls'        => isset($dbConfig['use_tls']) ? (bool)$dbConfig['use_tls'] : (defined('LDAP_USE_TLS') ? LDAP_USE_TLS : false),
            'base_dn'        => $dbConfig['base_dn'] ?? (defined('LDAP_BASE_DN') ? LDAP_BASE_DN : ''),
            'group_dn'       => $dbConfig['authorized_group_dn'] ?? (defined('LDAP_AUTHORIZED_GROUP_DN') ? LDAP_AUTHORIZED_GROUP_DN : ''),
            'bind_dn'        => $dbConfig['bind_dn'] ?? (defined('LDAP_BIND_DN') ? LDAP_BIND_DN : ''),
            'bind_pass'      => $dbConfig['bind_password'] ?? (defined('LDAP_BIND_PASSWORD') ? LDAP_BIND_PASSWORD : ''),
            'account_suffix' => $dbConfig['account_suffix'] ?? (defined('LDAP_ACCOUNT_SUFFIX') ? LDAP_ACCOUNT_SUFFIX : '@corp.example.com'),
            'domain'         => $dbConfig['netbios_domain'] ?? (defined('LDAP_NETBIOS_DOMAIN') ? LDAP_NETBIOS_DOMAIN : 'CORP'),
            'timeout'        => !empty($dbConfig['timeout_seconds']) ? (int)$dbConfig['timeout_seconds'] : 5,
        ];
    }

    /**
     * Get current active LDAP configuration parameters
     */
    public function getConfig(): array {
        return $this->ldapConfig;
    }

    /**
     * Connect to Active Directory domain controller using database-stored settings
     */
    private function connect(): void {
        if (!function_exists('ldap_connect')) {
            throw new RuntimeException('PHP LDAP extension is not installed. Run: sudo apt-get install php-ldap');
        }

        // Support plain LDAP (ldap://), LDAPS (ldaps://), or StartTLS
        $protocol = ($this->ldapConfig['use_ssl'] || $this->ldapConfig['protocol'] === 'ldaps') ? 'ldaps://' : 'ldap://';
        $uri = sprintf('%s%s:%d', $protocol, $this->ldapConfig['host'], $this->ldapConfig['port']);

        $conn = ldap_connect($uri);
        if (!$conn) {
            throw new RuntimeException("Could not connect to AD Domain Controller at {$uri}");
        }

        // Set mandatory Active Directory LDAP options
        ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($conn, LDAP_OPT_REFERRALS, 0); // Critical for Active Directory
        ldap_set_option($conn, LDAP_OPT_NETWORK_TIMEOUT, $this->ldapConfig['timeout']);

        // StartTLS only if explicitly enabled (NOT required)
        if (!$this->ldapConfig['use_ssl'] && ($this->ldapConfig['use_tls'] || $this->ldapConfig['protocol'] === 'starttls')) {
            if (!ldap_start_tls($conn)) {
                throw new RuntimeException('Failed to start TLS with Active Directory DC.');
            }
        }

        $this->ldapConn = $conn;
    }

    /**
     * Authenticate user credentials and verify Group DN authorization
     *
     * @param string $username sAMAccountName or UPN (e.g. jsmith or jsmith@corp.example.com)
     * @param string $password User Active Directory password
     * @return array [success => bool, user => array|null, error => string|null]
     */
    public function authenticate(string $username, string $password): array {
        $username = trim($username);
        if (empty($username) || empty($password)) {
            return ['success' => false, 'user' => null, 'error' => 'Username and password cannot be empty.'];
        }

        try {
            $this->connect();
        } catch (Exception $e) {
            // LDAP connection failure! If emergency fallback non-LDAP administrator is enabled, authenticate via MariaDB
            if (defined('FALLBACK_ADMIN_ENABLED') && FALLBACK_ADMIN_ENABLED) {
                $fallbackResult = $this->authenticateFallbackAdmin($username, $password, 'LDAP connection failure: ' . $e->getMessage());
                if ($fallbackResult !== null) {
                    return $fallbackResult;
                }
            }
            return [
                'success' => false,
                'user'    => null,
                'error'   => 'Active Directory LDAP Connection failure: ' . $e->getMessage() . (defined('FALLBACK_ADMIN_ENABLED') && FALLBACK_ADMIN_ENABLED ? ' (Note: If LDAP is offline, you can sign in with your emergency fallback administrator account).' : '')
            ];
        }

        // 1. Initial bind to search user: use Service Account if configured, otherwise bind with user UPN
        $userSearchDn = null;
        $userEntry = null;

        if (!empty($this->ldapConfig['bind_dn'])) {
            // Bind using Service Account stored in database
            $serviceBound = @ldap_bind($this->ldapConn, $this->ldapConfig['bind_dn'], $this->ldapConfig['bind_pass']);
            if (!$serviceBound) {
                return ['success' => false, 'user' => null, 'error' => 'Service account could not bind to Active Directory: ' . ldap_error($this->ldapConn)];
            }

            // Find user's DN in Active Directory
            $cleanUser = ldap_escape($username, '', LDAP_ESCAPE_FILTER);
            $filter = "(|(sAMAccountName={$cleanUser})(userPrincipalName={$cleanUser}))";
            $search = @ldap_search($this->ldapConn, $this->ldapConfig['base_dn'], $filter, [
                'dn', 'sAMAccountName', 'displayName', 'mail', 'memberOf', 'userPrincipalName'
            ]);

            if (!$search || ldap_count_entries($this->ldapConn, $search) === 0) {
                return ['success' => false, 'user' => null, 'error' => 'User account not found in Active Directory.'];
            }

            $entries = ldap_get_entries($this->ldapConn, $search);
            $userEntry = $entries[0];
            $userSearchDn = $userEntry['dn'];

            // Now verify the user's actual password by binding as the user's DN
            $userBound = @ldap_bind($this->ldapConn, $userSearchDn, $password);
            if (!$userBound) {
                return ['success' => false, 'user' => null, 'error' => 'Invalid Active Directory credentials.'];
            }
        } else {
            // Direct User Bind (using NetBIOS domain or UPN suffix)
            $suffix = $this->ldapConfig['account_suffix'];
            $bindIdentity = str_contains($username, '@') ? $username : $username . $suffix;
            $userBound = @ldap_bind($this->ldapConn, $bindIdentity, $password);
            if (!$userBound) {
                return ['success' => false, 'user' => null, 'error' => 'Invalid Active Directory credentials.'];
            }

            // Search user details post-bind
            $cleanUser = ldap_escape($username, '', LDAP_ESCAPE_FILTER);
            $filter = "(|(sAMAccountName={$cleanUser})(userPrincipalName={$cleanUser}))";
            $search = @ldap_search($this->ldapConn, $this->ldapConfig['base_dn'], $filter, [
                'dn', 'sAMAccountName', 'displayName', 'mail', 'memberOf', 'userPrincipalName'
            ]);
            if ($search && ldap_count_entries($this->ldapConn, $search) > 0) {
                $entries = ldap_get_entries($this->ldapConn, $search);
                $userEntry = $entries[0];
                $userSearchDn = $userEntry['dn'];
            }
        }

        if (!$userSearchDn) {
            return ['success' => false, 'user' => null, 'error' => 'Failed to resolve user Distinguished Name.'];
        }

        // 2. Enforce Group Distinguished Name (Group DN) access control
        $targetGroupDn = $this->ldapConfig['group_dn'];
        $isAuthorized = $this->verifyGroupMembership($userSearchDn, $targetGroupDn);

        if (!$isAuthorized) {
            error_log("[LDAP Access Denied] User {$username} ({$userSearchDn}) is not a member of authorized group: " . $targetGroupDn);
            return [
                'success' => false,
                'user'    => null,
                'error'   => 'Access Denied: Your Active Directory account is not a member of the authorized Group (' . htmlspecialchars($targetGroupDn) . ').'
            ];
        }

        // 3. User is authenticated and authorized!
        $userData = [
            'username'    => $userEntry['samaccountname'][0] ?? $username,
            'displayName' => $userEntry['displayname'][0] ?? $username,
            'email'       => $userEntry['mail'][0] ?? ($userEntry['userprincipalname'][0] ?? ''),
            'dn'          => $userSearchDn,
            'groupDn'     => $targetGroupDn,
            'loginTime'   => time(),
        ];

        return [
            'success' => true,
            'user'    => $userData,
            'error'   => null
        ];
    }

    /**
     * Verify if user is member of Group DN, including nested groups in Active Directory
     */
    private function verifyGroupMembership(string $userDn, string $groupDn): bool {
        // Method A: Check using Microsoft Active Directory matching rule LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941)
        // This recursively evaluates direct AND nested AD group memberships in a single query!
        $escapedUserDn = ldap_escape($userDn, '', LDAP_ESCAPE_FILTER);
        $escapedGroupDn = ldap_escape($groupDn, '', LDAP_ESCAPE_FILTER);

        // Check if group has user in chain
        $filter1 = "(&(objectClass=user)(distinguishedName={$escapedUserDn})(memberOf:1.2.840.113556.1.4.1941:={$escapedGroupDn}))";
        $search1 = @ldap_search($this->ldapConn, $this->ldapConfig['base_dn'], $filter1, ['dn']);

        if ($search1 && ldap_count_entries($this->ldapConn, $search1) > 0) {
            return true;
        }

        // Method B: Direct member check on the group object itself
        $filter2 = "(&(objectClass=group)(distinguishedName={$escapedGroupDn})(member={$escapedUserDn}))";
        $search2 = @ldap_search($this->ldapConn, $this->ldapConfig['base_dn'], $filter2, ['dn']);

        if ($search2 && ldap_count_entries($this->ldapConn, $search2) > 0) {
            return true;
        }

        // Method C: Case-insensitive fallback checking memberOf attribute array
        $search3 = @ldap_read($this->ldapConn, $userDn, '(objectClass=*)', ['memberOf']);
        if ($search3 && ldap_count_entries($this->ldapConn, $search3) > 0) {
            $info = ldap_get_entries($this->ldapConn, $search3);
            if (isset($info[0]['memberof'])) {
                for ($i = 0; $i < $info[0]['memberof']['count']; $i++) {
                    if (strcasecmp($info[0]['memberof'][$i], $groupDn) === 0) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Authenticate emergency non-LDAP fallback administrator when Active Directory LDAP fails
     */
    public function authenticateFallbackAdmin(string $username, string $password, string $failureReason = 'LDAP connection failure'): ?array {
        $username = trim($username);
        if (empty($username) || empty($password)) {
            return null;
        }

        // 1. Check MariaDB table eop_local_admins first
        $localAdmin = Database::getFallbackAdmin($username);
        if ($localAdmin && !empty($localAdmin['password_hash'])) {
            if (password_verify($password, $localAdmin['password_hash'])) {
                Database::logAudit('LOGIN', 'SYSTEM', defined('DEFAULT_POLICY_NAME') ? DEFAULT_POLICY_NAME : 'GLOBAL', $username, "Emergency Non-LDAP Fallback Administrator Login ({$failureReason})", $username);
                return [
                    'success' => true,
                    'user'    => [
                        'username'        => $username,
                        'displayName'     => 'Emergency Local Administrator (' . $username . ')',
                        'email'           => 'admin@localhost',
                        'dn'              => 'CN=' . $username . ',OU=LocalSecurity,DC=local',
                        'groupDn'         => 'LOCAL_SECURITY_FALLBACK',
                        'isFallbackAdmin' => true,
                        'loginTime'       => time(),
                    ],
                    'error'   => null
                ];
            }
        }

        // 2. Check default fallback administrator credentials configured in setup if defined
        if (defined('FALLBACK_ADMIN_USERNAME') && strcasecmp($username, FALLBACK_ADMIN_USERNAME) === 0) {
            if (defined('FALLBACK_ADMIN_PASSWORD_HASH') && !empty(FALLBACK_ADMIN_PASSWORD_HASH)) {
                if (password_verify($password, FALLBACK_ADMIN_PASSWORD_HASH)) {
                    Database::logAudit('LOGIN', 'SYSTEM', defined('DEFAULT_POLICY_NAME') ? DEFAULT_POLICY_NAME : 'GLOBAL', $username, "Emergency Non-LDAP Fallback Administrator Login ({$failureReason})", $username);
                    return [
                        'success' => true,
                        'user'    => [
                            'username'        => $username,
                            'displayName'     => 'Emergency Local Administrator (' . $username . ')',
                            'email'           => 'admin@localhost',
                            'dn'              => 'CN=' . $username . ',OU=LocalSecurity,DC=local',
                            'groupDn'         => 'LOCAL_SECURITY_FALLBACK',
                            'isFallbackAdmin' => true,
                            'loginTime'       => time(),
                        ],
                        'error'   => null
                    ];
                }
            }
        }

        return null;
    }

    public function __destruct() {
        if ($this->ldapConn) {
            @ldap_unbind($this->ldapConn);
        }
    }
}
