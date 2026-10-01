<?php
/**
 * Remote MariaDB Database Handler
 * Manages individual tables per list:
 * - eop_allowed_senders
 * - eop_blocked_senders
 * - eop_allowed_domains
 * - eop_blocked_domains
 */

declare(strict_types=1);

if (!file_exists(__DIR__ . '/config.php')) {
    if (php_sapi_name() !== 'cli' && !headers_sent()) {
        header('Location: setup.php');
        exit;
    }
} else {
    require_once __DIR__ . '/config.php';
}

require_once __DIR__ . '/crypto.php';

// Initial access check: If setup is incomplete or database is not configured, redirect web visitors to setup wizard
if (php_sapi_name() !== 'cli' && !headers_sent()) {
    $currentScript = basename($_SERVER['SCRIPT_FILENAME'] ?? '');
    if ($currentScript !== 'setup.php') {
        $isDbHostEmpty = !defined('DB_HOST') || trim((string)DB_HOST) === '';
        $isDbNameEmpty = !defined('DB_NAME') || trim((string)DB_NAME) === '';
        $isSetupUnlocked = !file_exists(__DIR__ . '/installed.lock');
        if ($isDbHostEmpty || $isDbNameEmpty || $isSetupUnlocked) {
            header('Location: setup.php');
            exit;
        }
    }
}

class Database {
    private static ?PDO $instance = null;

    /**
     * Check if database credentials and host are configured
     */
    public static function isConfigured(): bool {
        return defined('DB_HOST') && trim((string)DB_HOST) !== '' &&
               defined('DB_NAME') && trim((string)DB_NAME) !== '';
    }

    /**
     * Check if core database tables are initialized and reachable
     */
    public static function isInitialized(): bool {
        if (!self::isConfigured()) {
            return false;
        }

        try {
            $pdo = self::getConnection(false);
            if (!$pdo) {
                return false;
            }
            $targetTable = defined('TABLE_ALLOWED_SENDERS') ? TABLE_ALLOWED_SENDERS : 'eop_allowed_senders';
            $stmt = $pdo->query("SELECT 1 FROM `{$targetTable}` LIMIT 1");
            return ($stmt !== false);
        } catch (Throwable $e) {
            try {
                $targetTable = defined('TABLE_ALLOWED_SENDERS') ? TABLE_ALLOWED_SENDERS : 'eop_allowed_senders';
                $check = $pdo->query("SHOW TABLES LIKE " . $pdo->quote($targetTable));
                return ($check && $check->fetchColumn() !== false);
            } catch (Throwable $ex) {
                return false;
            }
        }
    }

    /**
     * Get singleton PDO connection to Remote MariaDB server
     */
    public static function getConnection(bool $dieOnError = true): ?PDO {
        if (!self::isConfigured()) {
            if (php_sapi_name() !== 'cli' && !headers_sent() && !file_exists(__DIR__ . '/installed.lock')) {
                header('Location: setup.php');
                exit;
            }
            if ($dieOnError) {
                die('<div style="font-family:sans-serif;padding:2rem;color:#721c24;background:#f8d7da;border:1px solid #f5c6cb;border-radius:6px;max-width:650px;margin:2rem auto;">' .
                    '<h3>Database Not Configured</h3>' .
                    '<p>MariaDB database credentials have not been configured yet.</p>' .
                    '<p><a href="setup.php" style="display:inline-block;padding:8px 16px;background:#0d6efd;color:#fff;text-decoration:none;border-radius:4px;font-size:14px;">Launch Setup Wizard &rarr;</a></p>' .
                    '</div>');
            }
            return null;
        }

        if (self::$instance === null) {
            $dsn = sprintf(
                'mysql:host=%s;port=%d;dbname=%s;charset=%s',
                DB_HOST,
                DB_PORT,
                DB_NAME,
                DB_CHARSET
            );

            $options = [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
                PDO::ATTR_TIMEOUT            => 5,
            ];

            try {
                self::$instance = new PDO($dsn, DB_USER, DB_PASS, $options);
            } catch (PDOException $e) {
                error_log('[MariaDB Error] Connection failed: ' . $e->getMessage());
                if ($dieOnError) {
                    die('<div style="font-family:sans-serif;padding:2rem;color:#721c24;background:#f8d7da;border:1px solid #f5c6cb;border-radius:6px;max-width:650px;margin:2rem auto;">' .
                        '<h3>Database Connection Error</h3>' .
                        '<p>Could not connect to remote MariaDB host <code>' . htmlspecialchars((string)DB_HOST) . ':' . DB_PORT . '</code>.</p>' .
                        '<p><small>Check network route, MariaDB user grants, and credentials in <code>config.php</code> or <code>.env</code>.</small></p>' .
                        '<p style="margin-top:1rem;"><a href="setup.php" style="display:inline-block;padding:6px 12px;background:#0d6efd;color:#fff;text-decoration:none;border-radius:4px;font-size:12px;">Launch Setup Wizard &rarr;</a></p>' .
                        '</div>');
                }
                return null;
            }
        }
        return self::$instance;
    }

    /**
     * Resolve table name based on list type
     */
    public static function getTableName(string $listType): string {
        return match ($listType) {
            'allowed_senders' => TABLE_ALLOWED_SENDERS,
            'blocked_senders' => TABLE_BLOCKED_SENDERS,
            'allowed_domains' => TABLE_ALLOWED_DOMAINS,
            'blocked_domains' => TABLE_BLOCKED_DOMAINS,
            default           => throw new InvalidArgumentException("Invalid list type: {$listType}")
        };
    }

    /**
     * Resolve column name for item value (sender_email vs domain_name)
     */
    public static function getValueColumn(string $listType): string {
        return match ($listType) {
            'allowed_senders', 'blocked_senders' => 'sender_email',
            'allowed_domains', 'blocked_domains' => 'domain_name',
            default => throw new InvalidArgumentException("Invalid list type: {$listType}")
        };
    }

    /**
     * Fetch list entries for a specific policy from its dedicated table
     */
    public static function getListItems(string $listType, string $policyName, string $search = '', int $limit = 50, int $offset = 0): array {
        try {
            $pdo = self::getConnection();
            $table = self::getTableName($listType);
            $col = self::getValueColumn($listType);

            if ($search !== '') {
                $sql = "SELECT id, policy_name, {$col} AS item_value, note, added_by, created_at, updated_at
                        FROM {$table}
                        WHERE policy_name = :policy AND ({$col} LIKE :search OR note LIKE :search2)
                        ORDER BY id DESC LIMIT :limit OFFSET :offset";
                $stmt = $pdo->prepare($sql);
                $searchParam = '%' . $search . '%';
                $stmt->bindValue(':policy', $policyName, PDO::PARAM_STR);
                $stmt->bindValue(':search', $searchParam, PDO::PARAM_STR);
                $stmt->bindValue(':search2', $searchParam, PDO::PARAM_STR);
                $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
                $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
            } else {
                $sql = "SELECT id, policy_name, {$col} AS item_value, note, added_by, created_at, updated_at
                        FROM {$table}
                        WHERE policy_name = :policy
                        ORDER BY id DESC LIMIT :limit OFFSET :offset";
                $stmt = $pdo->prepare($sql);
                $stmt->bindValue(':policy', $policyName, PDO::PARAM_STR);
                $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
                $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
            }

            $stmt->execute();
            return $stmt->fetchAll();
        } catch (Throwable $e) {
            error_log('[Database::getListItems Error] ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Count items in a specific individual table for a policy
     */
    public static function countListItems(string $listType, string $policyName, string $search = ''): int {
        try {
            $pdo = self::getConnection();
            $table = self::getTableName($listType);
            $col = self::getValueColumn($listType);

            if ($search !== '') {
                $sql = "SELECT COUNT(*) FROM {$table} WHERE policy_name = :policy AND ({$col} LIKE :search OR note LIKE :search2)";
                $stmt = $pdo->prepare($sql);
                $searchParam = '%' . $search . '%';
                $stmt->execute([':policy' => $policyName, ':search' => $searchParam, ':search2' => $searchParam]);
            } else {
                $sql = "SELECT COUNT(*) FROM {$table} WHERE policy_name = :policy";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([':policy' => $policyName]);
            }
            return (int)$stmt->fetchColumn();
        } catch (Throwable $e) {
            error_log('[Database::countListItems Error] ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Check if an item already exists in a dedicated table for a policy (duplicate check)
     */
    public static function itemExists(string $listType, string $policyName, string $value): bool {
        try {
            $pdo = self::getConnection();
            $table = self::getTableName($listType);
            $col = self::getValueColumn($listType);
            $value = strtolower(trim($value));

            $stmt = $pdo->prepare("SELECT 1 FROM {$table} WHERE policy_name = :policy AND {$col} = :val LIMIT 1");
            $stmt->execute([':policy' => $policyName, ':val' => $value]);
            return (bool)$stmt->fetchColumn();
        } catch (Throwable $e) {
            error_log('[Database::itemExists Error] ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Add single item to the dedicated table (rejects duplicate entries)
     */
    public static function addItem(string $listType, string $policyName, string $value, string $note, string $addedBy): bool {
        $value = strtolower(trim($value));

        // Strict duplicate check: do not add duplicate entries
        if (self::itemExists($listType, $policyName, $value)) {
            return false;
        }

        $pdo = self::getConnection();
        $table = self::getTableName($listType);
        $col = self::getValueColumn($listType);

        $sql = "INSERT INTO {$table} (policy_name, {$col}, note, added_by, created_at, updated_at)
                VALUES (:policy, :val, :note, :user, NOW(), NOW())";
        
        $stmt = $pdo->prepare($sql);
        $success = $stmt->execute([
            ':policy' => $policyName,
            ':val'    => $value,
            ':note'   => trim($note),
            ':user'   => $addedBy
        ]);

        if ($success) {
            self::logAudit('ADD', $listType, $policyName, $value, "Added to {$table} by {$addedBy}", $addedBy);
        }
        return $success;
    }

    /**
     * Delete item by ID from its dedicated table
     */
    public static function deleteItem(string $listType, int $id, string $deletedBy): bool {
        $pdo = self::getConnection();
        $table = self::getTableName($listType);
        $col = self::getValueColumn($listType);

        // Fetch item first for audit log
        $fetchStmt = $pdo->prepare("SELECT policy_name, {$col} AS item_value FROM {$table} WHERE id = :id");
        $fetchStmt->execute([':id' => $id]);
        $row = $fetchStmt->fetch();

        if (!$row) {
            return false;
        }

        $stmt = $pdo->prepare("DELETE FROM {$table} WHERE id = :id");
        $deleted = $stmt->execute([':id' => $id]);

        if ($deleted) {
            self::logAudit('REMOVE', $listType, $row['policy_name'], $row['item_value'], "Removed from {$table} by {$deletedBy}", $deletedBy);
        }
        return $deleted;
    }

    /**
     * Bulk insert items into dedicated table
     */
    public static function bulkInsert(string $listType, string $policyName, array $items, string $addedBy): array {
        $pdo = self::getConnection();
        $table = self::getTableName($listType);
        $col = self::getValueColumn($listType);

        $inserted = 0;
        $skipped = 0;
        $errors = [];

        $stmt = $pdo->prepare("INSERT IGNORE INTO {$table} (policy_name, {$col}, note, added_by, created_at, updated_at) 
                               VALUES (:policy, :val, :note, :user, NOW(), NOW())");

        foreach ($items as $entry) {
            $val = strtolower(trim($entry['value']));
            $note = trim($entry['note'] ?? '');

            if (empty($val)) {
                $skipped++;
                continue;
            }

            try {
                $stmt->execute([
                    ':policy' => $policyName,
                    ':val'    => $val,
                    ':note'   => $note,
                    ':user'   => $addedBy
                ]);
                if ($stmt->rowCount() > 0) {
                    $inserted++;
                } else {
                    $skipped++; // Already exists (IGNORE)
                }
            } catch (Exception $e) {
                $errors[] = "Failed on {$val}: " . $e->getMessage();
                $skipped++;
            }
        }

        if ($inserted > 0) {
            self::logAudit('ADD', $listType, $policyName, "{$inserted} items", "Bulk import of {$inserted} items into {$table}", $addedBy);
        }

        return ['inserted' => $inserted, 'skipped' => $skipped, 'errors' => $errors];
    }

    /**
     * Fetch all raw items for Exchange Online sync
     */
    public static function getAllItemsForSync(string $listType, string $policyName): array {
        $pdo = self::getConnection();
        $table = self::getTableName($listType);
        $col = self::getValueColumn($listType);

        $stmt = $pdo->prepare("SELECT {$col} AS item_value FROM {$table} WHERE policy_name = :policy ORDER BY {$col} ASC");
        $stmt->execute([':policy' => $policyName]);
        return $stmt->fetchAll(PDO::FETCH_COLUMN);
    }

    /**
     * Flattens a decoded remote list into plain strings.
     *
     * A JSON array of strings is returned as-is. An element that is itself an
     * array or object is unwrapped one level so a nested collection from the
     * PowerShell side does not reach the comparator as a non-scalar. Returns null
     * when an element cannot be reduced to a string, which callers treat as a
     * malformed payload.
     */
    private static function flattenRemoteValues(array $remoteValues): ?array {
        $flat = [];
        foreach ($remoteValues as $value) {
            if (is_array($value)) {
                foreach ($value as $inner) {
                    if (is_array($inner) || is_object($inner)) {
                        return null;
                    }
                    $flat[] = (string)$inner;
                }
                continue;
            }
            if (is_object($value)) {
                return null;
            }
            if (is_bool($value)) {
                return null;
            }
            $flat[] = (string)$value;
        }
        return $flat;
    }

    /**
     * Reconcile a local list against the authoritative remote list from Exchange Online.
     * Inserts remote entries missing locally and removes local rows that no longer exist
     * in Exchange Online. Every removal is audit logged.
     *
     * The remote payload is flattened defensively: a list element that is itself an
     * array means the producer emitted a nested collection, and a bare
     * (string) cast on it would yield the literal "Array" — which would collapse
     * every entry onto one key and make the whole list look absent remotely,
     * deleting every local row. Such entries are unwrapped; anything that is
     * still not a scalar afterwards aborts the reconcile instead.
     */
    public static function reconcileListWithRemote(string $listType, string $policyName, array $remoteValues, string $actor): array {
        $pdo = self::getConnection();
        $table = self::getTableName($listType);
        $col = self::getValueColumn($listType);

        $remote = [];
        $flattened = self::flattenRemoteValues($remoteValues);
        if ($flattened === null) {
            throw new RuntimeException(
                "Remote {$listType} payload for policy '{$policyName}' contained nested or non-scalar entries. "
                . 'Refusing to reconcile: a malformed payload would make every local row look absent from Exchange Online.'
            );
        }
        foreach ($flattened as $value) {
            $normalized = strtolower(trim($value));
            if ($normalized !== '') {
                $remote[$normalized] = true;
            }
        }

        $select = $pdo->prepare("SELECT id, {$col} AS item_value FROM {$table} WHERE policy_name = :policy");
        $select->execute([':policy' => $policyName]);
        $localRows = $select->fetchAll(PDO::FETCH_ASSOC);

        $candidates = [];
        foreach (array_keys($remote) as $value) {
            $candidates[] = ['value' => $value, 'note' => 'Pulled from Exchange Online'];
        }
        $insertResult = self::bulkInsert($listType, $policyName, $candidates, $actor);

        // Do not delete local items on pull from EOP - preserve items added in UI
        $removed = [];
        $notRemoved = [];

        return [
            'remote'    => count($remote),
            'inserted'  => $insertResult['inserted'],
            'removed'   => 0,
            'unchanged' => count($localRows),
            'errors'    => $insertResult['errors'],
            'removed_values' => [],
            'not_removed_values' => [],
        ];
    }

    /**
     * Resolve the table backing sync confirmations. config.php is regenerated by
     * the setup wizard, so an existing install will not define the new constant;
     * fall back to the literal name rather than raising an Error.
     */
    private static function confirmationsTable(): string {
        return defined('TABLE_SYNC_CONFIRMATIONS') ? TABLE_SYNC_CONFIRMATIONS : 'eop_sync_confirmations';
    }

    /**
     * Create the confirmation table on demand. The setup wizard creates it for
     * fresh installs, but the wizard locks after first run, so an existing
     * database has to be able to acquire it without operator intervention.
     *
     * CREATE TABLE IF NOT EXISTS is a no-op when the table exists but still
     * requires the CREATE privilege, so a deployment whose app user cannot run
     * DDL would otherwise break every sync. Failure is swallowed and only
     * attempted once: the individual accessors already degrade, and a guard with
     * no readable confirmation row always falls through to "prompted", which
     * withholds the deletion. That is the safe direction to fail in.
     */
    private static function ensureConfirmationsTable(): void {
        static $ensured = false;
        if ($ensured) {
            return;
        }
        $ensured = true;
        try {
            $table = self::confirmationsTable();
            self::getConnection()->exec("CREATE TABLE IF NOT EXISTS `{$table}` (
                `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                `policy_name` VARCHAR(255) NOT NULL,
                `list_type` VARCHAR(50) NOT NULL,
                `local_count` INT UNSIGNED NOT NULL DEFAULT 0,
                `remote_count` INT UNSIGNED NOT NULL DEFAULT 0,
                `pending_values` MEDIUMTEXT NULL,
                `values_truncated` TINYINT(1) NOT NULL DEFAULT 0,
                `status` ENUM('pending', 'accepted', 'denied', 'applied') NOT NULL DEFAULT 'pending',
                `requested_by` VARCHAR(100) NOT NULL DEFAULT 'CRON_DAEMON',
                `decided_by` VARCHAR(100) NULL,
                `decided_at` DATETIME NULL,
                `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY `uniq_policy_list` (`policy_name`, `list_type`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        } catch (Throwable $e) {
            error_log('[Database::ensureConfirmationsTable] ' . $e->getMessage());
        }
    }

    /**
     * Fetch the outstanding or decided confirmation for a policy/list, if any.
     */
    public static function getSyncConfirmation(string $policyName, string $listType): ?array {
        try {
            self::ensureConfirmationsTable();
            $stmt = self::getConnection()->prepare(
                'SELECT * FROM ' . self::confirmationsTable() . ' WHERE policy_name = :policy AND list_type = :list LIMIT 1'
            );
            $stmt->execute([':policy' => $policyName, ':list' => $listType]);
            $row = $stmt->fetch();
            return $row ?: null;
        } catch (Throwable $e) {
            error_log('[Database::getSyncConfirmation Error] ' . $e->getMessage());
            return null;
        }
    }

    /**
     * All confirmations, optionally narrowed to one policy. Used by the UI.
     */
    public static function getSyncConfirmations(?string $policyName = null): array {
        try {
            self::ensureConfirmationsTable();
            if ($policyName !== null) {
                $stmt = self::getConnection()->prepare(
                    'SELECT * FROM ' . self::confirmationsTable() . ' WHERE policy_name = :policy ORDER BY list_type ASC'
                );
                $stmt->execute([':policy' => $policyName]);
            } else {
                $stmt = self::getConnection()->query(
                    'SELECT * FROM ' . self::confirmationsTable() . ' ORDER BY policy_name ASC, list_type ASC'
                );
            }
            return $stmt ? $stmt->fetchAll() : [];
        } catch (Throwable $e) {
            error_log('[Database::getSyncConfirmations Error] ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Record (or refresh) the values at risk for a policy/list, resetting the
     * request to 'pending' so the UI shows the current local state.
     */
    public static function recordSyncConfirmation(string $policyName, string $listType, int $localCount, array $values, bool $truncated, string $actor): void {
        try {
            self::ensureConfirmationsTable();
            $stmt = self::getConnection()->prepare(
                'INSERT INTO ' . self::confirmationsTable() . '
                 (policy_name, list_type, local_count, remote_count, pending_values, values_truncated, status, requested_by)
                 VALUES (:policy, :list, :local, 0, :values, :trunc, \'pending\', :actor)
                 ON DUPLICATE KEY UPDATE
                    `local_count` = VALUES(`local_count`),
                    `remote_count` = 0,
                    `pending_values` = VALUES(`pending_values`),
                    `values_truncated` = VALUES(`values_truncated`),
                    `status` = \'pending\',
                    `requested_by` = VALUES(`requested_by`),
                    `decided_by` = NULL,
                    `decided_at` = NULL,
                    `updated_at` = NOW()'
            );
            $stmt->execute([
                ':policy' => $policyName,
                ':list' => $listType,
                ':local' => $localCount,
                ':values' => json_encode(array_values($values)),
                ':trunc' => $truncated ? 1 : 0,
                ':actor' => $actor,
            ]);
        } catch (Throwable $e) {
            error_log('[Database::recordSyncConfirmation Error] ' . $e->getMessage());
        }
    }

    /**
     * Record an administrator's accept/deny decision. The decision is stored, not
     * acted on: cron-sync.php consumes it on its next run for this policy.
     */
    public static function resolveSyncConfirmation(string $policyName, string $listType, string $decision, string $actor): bool {
        if (!in_array($decision, ['accepted', 'denied'], true)) {
            return false;
        }
        try {
            self::ensureConfirmationsTable();
            $stmt = self::getConnection()->prepare(
                'UPDATE ' . self::confirmationsTable() . '
                 SET `status` = :status, `decided_by` = :actor, `decided_at` = NOW()
                 WHERE policy_name = :policy AND list_type = :list'
            );
            $stmt->execute([
                ':status' => $decision,
                ':actor' => $actor,
                ':policy' => $policyName,
                ':list' => $listType,
            ]);
            if ($stmt->rowCount() === 0) {
                return false;
            }

            // 'DELETE' is not a member of the eop_audit_log action ENUM, so the
            // decision is logged as an UPDATE to stay within the existing schema.
            self::logAudit(
                'UPDATE',
                $listType,
                $policyName,
                'SYNC_CONFIRMATION',
                "Empty remote list: deletion of local entries {$decision} by {$actor}. "
                . ($decision === 'accepted' ? 'The next cron run will apply it.' : 'Local entries will be kept.'),
                $actor
            );
            return true;
        } catch (Throwable $e) {
            error_log('[Database::resolveSyncConfirmation Error] ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Drop a confirmation once the hazard no longer applies.
     */
    public static function clearSyncConfirmation(string $policyName, string $listType): void {
        try {
            self::ensureConfirmationsTable();
            $stmt = self::getConnection()->prepare(
                'DELETE FROM ' . self::confirmationsTable() . ' WHERE policy_name = :policy AND list_type = :list'
            );
            $stmt->execute([':policy' => $policyName, ':list' => $listType]);
        } catch (Throwable $e) {
            error_log('[Database::clearSyncConfirmation Error] ' . $e->getMessage());
        }
    }

    /**
     * Delete exactly the values captured in a confirmation. Deleting the captured
     * set rather than "everything currently present" means rows added after the
     * administrator approved are not silently destroyed.
     */
    private static function applyConfirmedDeletion(string $listType, string $policyName, array $values, string $actor): array {
        $pdo = self::getConnection();
        $table = self::getTableName($listType);
        $col = self::getValueColumn($listType);

        $delete = $pdo->prepare("DELETE FROM {$table} WHERE {$col} = :val AND policy_name = :policy");
        $removed = [];
        $errors = [];
        foreach ($values as $value) {
            try {
                $delete->execute([':val' => $value, ':policy' => $policyName]);
                if ($delete->rowCount() > 0) {
                    $removed[] = $value;
                }
            } catch (Throwable $e) {
                $errors[] = "Failed to remove {$value}: " . $e->getMessage();
            }
        }

        if ($removed) {
            // 'REMOVE' is a member of the eop_audit_log action ENUM; 'DELETE' is
            // not, and the failed INSERT was swallowed by logAudit.
            self::logAudit(
                'REMOVE',
                $listType,
                $policyName,
                count($removed) . ' items',
                'Removed by cron pull after administrator accepted deletion of an empty remote list: ' . implode(', ', array_slice($removed, 0, 25)),
                $actor
            );
        }

        return ['removed' => count($removed), 'removed_values' => $removed, 'errors' => $errors];
    }

    /**
     * A cheap fingerprint of everything the UI renders for a policy, used to
     * detect that a scheduled sync changed the data underneath an open page.
     *
     * The counts and the max(updated_at) are aggregate-only, so this stays cheap
     * even with a large table, and it moves for every mutation the cron performs:
     * a pull inserts, a reconcile deletes, both bump updated_at. The policy row
     * contributes its own sync metadata, so a run that changed nothing but its
     * status still registers.
     *
     * Returns a string rather than a bool so the caller can compare tokens
     * directly and skip the reload when nothing moved.
     */
    public static function getDataVersion(string $policyName): string {
        try {
            $pdo = self::getConnection();
            $parts = [];

            foreach (['allowed_senders', 'blocked_senders', 'allowed_domains', 'blocked_domains'] as $listType) {
                $table = self::getTableName($listType);
                $stmt = $pdo->prepare("SELECT COUNT(*) AS c, COALESCE(MAX(updated_at), '') AS u FROM {$table} WHERE policy_name = :policy");
                $stmt->execute([':policy' => $policyName]);
                $row = $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
                $parts[] = $listType . ':' . ($row['c'] ?? 0) . ':' . ($row['u'] ?? '');
            }

            $polStmt = $pdo->prepare("SELECT COALESCE(last_synced_at, '') AS l, COALESCE(sync_status, '') AS s, COALESCE(updated_at, '') AS u
                                      FROM " . TABLE_POLICIES . " WHERE policy_name = :policy");
            $polStmt->execute([':policy' => $policyName]);
            $pol = $polStmt->fetch(PDO::FETCH_ASSOC) ?: [];
            $parts[] = 'policy:' . ($pol['l'] ?? '') . ':' . ($pol['s'] ?? '') . ':' . ($pol['u'] ?? '');

            // Outstanding deletion confirmations are rendered as a banner, so a
            // change there has to count as a change too.
            try {
                self::ensureConfirmationsTable();
                $confStmt = $pdo->prepare("SELECT COUNT(*) AS c FROM " . self::confirmationsTable() . "
                                           WHERE policy_name = :policy AND status IN ('pending', 'accepted', 'denied')");
                $confStmt->execute([':policy' => $policyName]);
                $parts[] = 'confirm:' . (int)$confStmt->fetchColumn();
            } catch (Throwable $e) {
                $parts[] = 'confirm:na';
            }

            return implode('|', $parts);
        } catch (Throwable $e) {
            error_log('[Database::getDataVersion Error] ' . $e->getMessage());
            return 'error';
        }
    }

    /**
     * Normalised local values for a policy/list, in the same casing the
     * reconciler compares against.
     */
    private static function fetchNormalizedValues(string $listType, string $policyName): array {
        $pdo = self::getConnection();
        $table = self::getTableName($listType);
        $col = self::getValueColumn($listType);
        $stmt = $pdo->prepare("SELECT {$col} AS item_value FROM {$table} WHERE policy_name = :policy");
        $stmt->execute([':policy' => $policyName]);

        $values = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $normalized = strtolower(trim((string)$row['item_value']));
            if ($normalized !== '') {
                $values[$normalized] = $normalized;
            }
        }
        return $values;
    }

    /**
     * Reconcile a pulled list, refusing to empty a populated local list without an
     * explicit administrator decision.
     *
     * An empty remote list is indistinguishable from a policy that genuinely has
     * no entries, and the reconciler deletes every local row absent from the
     * remote set. A single bad pull would therefore wipe the list. So when the
     * remote list is empty and local rows exist, the deletion is held back and a
     * confirmation is raised for the UI instead. The administrator's accept/deny
     * is stored and consumed here on a later run.
     *
     * The returned array is the normal reconcile result plus:
     *   guard        - none | prompted | awaiting_decision | denied | applied
     *   confirmation - the confirmation row when one is outstanding
     */
    public static function reconcileListWithRemoteGuarded(string $listType, string $policyName, array $remoteValues, string $actor): array {
        self::ensureConfirmationsTable();

        $flattened = self::flattenRemoteValues($remoteValues);
        if ($flattened === null) {
            throw new RuntimeException(
                "Remote {$listType} payload for policy '{$policyName}' contained nested or non-scalar entries. "
                . 'Refusing to reconcile: a malformed payload would make every local row look absent from Exchange Online.'
            );
        }

        $remoteSet = [];
        foreach ($flattened as $value) {
            $normalized = strtolower(trim($value));
            if ($normalized !== '') {
                $remoteSet[$normalized] = true;
            }
        }
        $remoteCount = count($remoteSet);
        $existing = self::getSyncConfirmation($policyName, $listType);

        $passThrough = static function (array $result, string $guard, ?array $confirmation = null): array {
            $result['guard'] = $guard;
            $result['confirmation'] = $confirmation;
            return $result;
        };

        // Remote has data: normal reconcile. Any outstanding confirmation is stale.
        if ($remoteCount > 0) {
            if ($existing !== null) {
                self::clearSyncConfirmation($policyName, $listType);
            }
            return $passThrough(self::reconcileListWithRemote($listType, $policyName, $remoteValues, $actor), 'none');
        }

        $localValues = self::fetchNormalizedValues($listType, $policyName);
        $localCount = count($localValues);

        // Empty remote - don't wipe local UI additions, just skip
        if ($existing !== null) {
            self::clearSyncConfirmation($policyName, $listType);
        }
        return $passThrough(self::reconcileListWithRemote($listType, $policyName, [], $actor), 'none');

        $skippedResult = static function (string $guard, ?array $confirmation) use ($localCount, $listType, $policyName, $actor, $passThrough): array {
            return $passThrough([
                'remote'         => 0,
                'inserted'       => 0,
                'removed'        => 0,
                'unchanged'      => $localCount,
                'errors'         => [],
                'removed_values' => [],
            ], $guard, $confirmation);
        };

        // Administrator accepted: apply the captured set this run.
        if ($existing !== null && $existing['status'] === 'accepted') {
            $captured = json_decode((string)($existing['pending_values'] ?? '[]'), true);
            $captured = is_array($captured) ? $captured : [];
            $applied = self::applyConfirmedDeletion($listType, $policyName, $captured, $actor);

            $stmt = self::getConnection()->prepare(
                'UPDATE ' . self::confirmationsTable() . ' SET `status` = \'applied\', `decided_at` = NOW() WHERE `id` = :id'
            );
            $stmt->execute([':id' => (int)$existing['id']]);

            self::logAudit(
                'SYNC',
                $listType,
                $policyName,
                'SYNC_CONFIRMATION',
                "Applied administrator-approved deletion of {$applied['removed']} entries from an empty remote list.",
                $actor
            );

            return $passThrough([
                'remote'         => 0,
                'inserted'       => 0,
                'removed'        => $applied['removed'],
                'unchanged'      => max(0, $localCount - $applied['removed']),
                'errors'         => $applied['errors'],
                'removed_values' => $applied['removed_values'],
            ], 'applied');
        }

        // Administrator denied: keep the rows and do not ask again.
        if ($existing !== null && $existing['status'] === 'denied') {
            return $skippedResult('denied', $existing);
        }

        // A decision is already outstanding; refresh the captured set so the UI
        // reflects the current local state, but keep it pending and do not re-prompt.
        if ($existing !== null && $existing['status'] === 'pending') {
            [$values, $truncated] = self::captureValues($localValues);
            self::recordSyncConfirmation($policyName, $listType, $localCount, $values, $truncated, $actor);
            $refreshed = self::getSyncConfirmation($policyName, $listType);
            return $skippedResult('awaiting_decision', $refreshed);
        }

        // No decision yet: raise the confirmation and hold the deletion.
        [$values, $truncated] = self::captureValues($localValues);
        self::recordSyncConfirmation($policyName, $listType, $localCount, $values, $truncated, $actor);
        $raised = self::getSyncConfirmation($policyName, $listType);
        self::logAudit(
            'SYNC',
            $listType,
            $policyName,
            'SYNC_CONFIRMATION',
            "Remote list came back empty while {$localCount} local entries exist. Deletion withheld pending administrator confirmation.",
            $actor
        );
        return $skippedResult('prompted', $raised);
    }

    /**
     * Bound the captured value set so the column cannot be overflowed. When the
     * set is truncated the approved deletion is correspondingly narrower, which
     * errs towards keeping rows rather than deleting unapproved ones.
     */
    private static function captureValues(array $localValues): array {
        $limit = 20000;
        $values = array_values($localValues);
        if (count($values) > $limit) {
            return [array_slice($values, 0, $limit), true];
        }
        return [$values, false];
    }

    /**
     * Record an audit log entry in eop_audit_log
     */
    public static function logAudit(string $action, string $listType, string $policyName, string $targetValue, string $details, string $username): void {
        try {
            $pdo = self::getConnection();
            $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
            $stmt = $pdo->prepare("INSERT INTO " . TABLE_AUDIT_LOG . " 
                (username, action, list_type, policy_name, target_value, details, ip_address, timestamp)
                VALUES (:user, :action, :list, :policy, :target, :details, :ip, NOW())");
            $stmt->execute([
                ':user'    => $username,
                ':action'  => $action,
                ':list'    => $listType,
                ':policy'  => $policyName,
                ':target'  => substr($targetValue, 0, 255),
                ':details' => $details,
                ':ip'      => $ip
            ]);
        } catch (Exception $e) {
            error_log('[Audit Log Error] ' . $e->getMessage());
        }
    }

    /**
     * Update policy sync status with automatic column verification & graceful fallback
     */
    public static function updatePolicySyncStatus(string $policyName, string $status, string $message = ''): void {
        try {
            $pdo = self::getConnection();

            // Check if sync_status column exists in TABLE_POLICIES; if not, dynamically add it
            static $columnsChecked = false;
            if (!$columnsChecked) {
                try {
                    $check = $pdo->query("SHOW COLUMNS FROM " . TABLE_POLICIES . " LIKE 'sync_status'");
                    if ($check && $check->rowCount() === 0) {
                        @$pdo->exec("ALTER TABLE " . TABLE_POLICIES . " ADD COLUMN sync_status ENUM('synced', 'pending', 'failed') NOT NULL DEFAULT 'pending'");
                        @$pdo->exec("ALTER TABLE " . TABLE_POLICIES . " ADD COLUMN sync_message TEXT NULL");
                        @$pdo->exec("ALTER TABLE " . TABLE_POLICIES . " ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP");
                    }
                    $columnsChecked = true;
                } catch (Exception $e) {
                    // Ignore column check error, will fall back below
                }
            }

            try {
                $stmt = $pdo->prepare("INSERT INTO " . TABLE_POLICIES . " (policy_name, last_synced_at, sync_status, sync_message, updated_at)
                                       VALUES (:name, NOW(), :status, :msg, NOW())
                                       ON DUPLICATE KEY UPDATE last_synced_at = NOW(), sync_status = VALUES(sync_status), sync_message = VALUES(sync_message), updated_at = NOW()");
                $stmt->execute([':name' => $policyName, ':status' => $status, ':msg' => $message]);
            } catch (PDOException $pdoEx) {
                // Graceful fallback for legacy tables without sync_status column
                $fallbackStmt = $pdo->prepare("INSERT INTO " . TABLE_POLICIES . " (policy_name, last_synced_at)
                                               VALUES (:name, NOW())
                                               ON DUPLICATE KEY UPDATE last_synced_at = NOW()");
                $fallbackStmt->execute([':name' => $policyName]);
            }
        } catch (Exception $e) {
            error_log('[Database::updatePolicySyncStatus Error] ' . $e->getMessage());
        }
    }

    /**
     * Retrieve the active default policy name from MariaDB (eop_policies), falling back to config
     */
    public static function getDefaultPolicyName(): string {
        try {
            $pdo = self::getConnection();
            static $colChecked = false;
            if (!$colChecked) {
                try {
                    $check = $pdo->query("SHOW COLUMNS FROM " . TABLE_POLICIES . " LIKE 'is_default'");
                    if ($check && $check->rowCount() === 0) {
                        @$pdo->exec("ALTER TABLE " . TABLE_POLICIES . " ADD COLUMN is_default TINYINT(1) NOT NULL DEFAULT 0");
                    }
                    $colChecked = true;
                } catch (Exception $e) {}
            }

            $stmt = $pdo->query("SELECT policy_name FROM " . TABLE_POLICIES . " WHERE is_default = 1 ORDER BY updated_at DESC LIMIT 1");
            $row = $stmt ? $stmt->fetch() : null;
            if (!empty($row['policy_name'])) {
                return (string)$row['policy_name'];
            }
        } catch (Exception $e) {
            // fallback below
        }

        if (defined('DEFAULT_POLICY_NAME') && DEFAULT_POLICY_NAME !== '') {
            return DEFAULT_POLICY_NAME;
        }

        return getenv('EOP_POLICY_NAME') ?: 'Default';
    }

    /**
     * Fetch all policies stored in MariaDB eop_policies table
     */
    public static function getPolicies(): array {
        $policies = [];
        try {
            $pdo = self::getConnection();
            static $colChecked = false;
            if (!$colChecked) {
                try {
                    $check = $pdo->query("SHOW COLUMNS FROM " . TABLE_POLICIES . " LIKE 'is_default'");
                    if ($check && $check->rowCount() === 0) {
                        @$pdo->exec("ALTER TABLE " . TABLE_POLICIES . " ADD COLUMN is_default TINYINT(1) NOT NULL DEFAULT 0");
                    }
                    $colChecked = true;
                } catch (Exception $e) {}
            }

            $stmt = $pdo->query("SELECT * FROM " . TABLE_POLICIES . " ORDER BY is_default DESC, policy_name ASC");
            if ($stmt) {
                $policies = $stmt->fetchAll();
            }
        } catch (Exception $e) {
            error_log('[Database::getPolicies Error] ' . $e->getMessage());
        }
        return $policies;
    }

    /**
     * Update or set the active default policy name in MariaDB and update .env
     */
    public static function setDefaultPolicyName(string $newPolicyName, string $updatedBy = 'SYSTEM', string $description = ''): bool {
        $newPolicyName = trim($newPolicyName);
        if ($newPolicyName === '') {
            return false;
        }

        try {
            $pdo = self::getConnection();

            // Ensure is_default column exists.
            // This is DDL, so it must happen BEFORE the transaction opens: MySQL
            // issues an implicit COMMIT before and after an ALTER TABLE, which
            // would silently commit the transaction started below.
            try {
                $check = $pdo->query("SHOW COLUMNS FROM " . TABLE_POLICIES . " LIKE 'is_default'");
                if ($check && $check->rowCount() === 0) {
                    @$pdo->exec("ALTER TABLE " . TABLE_POLICIES . " ADD COLUMN is_default TINYINT(1) NOT NULL DEFAULT 0");
                }
            } catch (Throwable $e) {}

            $desc = $description !== '' ? $description : 'Primary Inbound Anti-Spam Policy';

            // Clearing the existing default and promoting the new one must be
            // atomic. Previously the UPDATE ran first and the INSERT second with
            // no transaction, so any failure between them left the table with no
            // default policy at all while the caller was told only that the
            // update "failed". getConnection() is a shared singleton, so only
            // open a transaction if one is not already running.
            $ownsTransaction = !$pdo->inTransaction();
            if ($ownsTransaction) {
                $pdo->beginTransaction();
            }

            try {
                // Unset previous defaults
                $pdo->exec("UPDATE " . TABLE_POLICIES . " SET is_default = 0");

                // Insert or update new default policy.
                // Each placeholder may appear only once: this connection sets
                // ATTR_EMULATE_PREPARES = false, so these are real prepared
                // statements and a repeated named placeholder raises
                // SQLSTATE[HY093] Invalid parameter number.
                $stmt = $pdo->prepare("INSERT INTO " . TABLE_POLICIES . " (policy_name, description, is_default, updated_at)
                                       VALUES (:name, :desc, 1, NOW())
                                       ON DUPLICATE KEY UPDATE is_default = 1, updated_at = NOW(), description = IF(:desc_a != '', :desc_b, description)");
                $stmt->execute([
                    ':name'   => $newPolicyName,
                    ':desc'   => $desc,
                    ':desc_a' => $description,
                    ':desc_b' => $description
                ]);

                if ($ownsTransaction) {
                    $pdo->commit();
                }
            } catch (Throwable $e) {
                if ($ownsTransaction && $pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                throw $e;
            }

            // Persist into .env file if available
            self::updateEnvVariable('EOP_POLICY_NAME', $newPolicyName);

            // Update in-memory global available policies
            if (isset($GLOBALS['AVAILABLE_POLICIES']) && !isset($GLOBALS['AVAILABLE_POLICIES'][$newPolicyName])) {
                $GLOBALS['AVAILABLE_POLICIES'][$newPolicyName] = $desc;
            }

            self::logAudit('UPDATE', 'SYSTEM', $newPolicyName, 'DEFAULT_POLICY', "Changed default policy name to '{$newPolicyName}'", $updatedBy);
            return true;
        } catch (Throwable $e) {
            error_log('[Database::setDefaultPolicyName Error] ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Atomically update a key-value in local .env configuration files
     */
    public static function updateEnvVariable(string $key, string $value): bool {
        $envPaths = [
            __DIR__ . '/.env',
            '/var/www/eop-antispam/.env'
        ];

        $updatedAny = false;
        foreach ($envPaths as $envPath) {
            if (!file_exists($envPath)) {
                continue;
            }

            $content = @file_get_contents($envPath);
            if ($content === false) {
                continue;
            }

            $pattern = '/^' . preg_quote($key, '/') . '=.*/m';
            $escapedVal = (strpos($value, ' ') !== false) ? '"' . addcslashes($value, '"\\$') . '"' : $value;
            $replacement = "{$key}={$escapedVal}";

            if (preg_match($pattern, $content)) {
                $newContent = preg_replace($pattern, $replacement, $content);
            } else {
                $newContent = rtrim($content) . "\n{$replacement}\n";
            }

            if (@file_put_contents($envPath, $newContent) !== false) {
                $updatedAny = true;
            }
        }
        return $updatedAny;
    }

    /**
     * Fetch active LDAP connection configuration stored in the database table eop_ldap_config
     */
    public static function getLdapConfig(): ?array {
        try {
            $pdo = self::getConnection();
            $stmt = $pdo->query("SELECT * FROM " . TABLE_LDAP_CONFIG . " WHERE is_active = 1 ORDER BY id DESC LIMIT 1");
            $config = $stmt->fetch();
            return $config ?: null;
        } catch (Exception $e) {
            error_log('[Database::getLdapConfig Error] ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Save updated LDAP connection configuration into database table eop_ldap_config
     */
    public static function saveLdapConfig(array $data, string $updatedBy): bool {
        try {
            $pdo = self::getConnection();
            $stmt = $pdo->prepare("INSERT INTO " . TABLE_LDAP_CONFIG . " 
                (host, port, protocol, use_ssl, use_tls, base_dn, authorized_group_dn, bind_dn, bind_password, account_suffix, netbios_domain, timeout_seconds, is_active, updated_by, created_at, updated_at)
                VALUES (:host, :port, :protocol, :use_ssl, :use_tls, :base_dn, :group_dn, :bind_dn, :bind_pass, :suffix, :domain, :timeout, 1, :user, NOW(), NOW())");

            $protocol = $data['protocol'] ?? 'ldap';
            $useSsl = ($protocol === 'ldaps' || !empty($data['use_ssl'])) ? 1 : 0;
            $useTls = ($protocol === 'starttls' || !empty($data['use_tls'])) ? 1 : 0;

            $success = $stmt->execute([
                ':host'      => trim($data['host']),
                ':port'      => (int)($data['port'] ?? 389),
                ':protocol'  => $protocol,
                ':use_ssl'   => $useSsl,
                ':use_tls'   => $useTls,
                ':base_dn'   => trim($data['base_dn']),
                ':group_dn'  => trim($data['authorized_group_dn']),
                ':bind_dn'   => trim($data['bind_dn'] ?? ''),
                ':bind_pass' => trim($data['bind_password'] ?? ''),
                ':suffix'    => trim($data['account_suffix'] ?? '@corp.example.com'),
                ':domain'    => trim($data['netbios_domain'] ?? 'CORP'),
                ':timeout'   => max(1, (int)($data['timeout_seconds'] ?? 5)),
                ':user'      => $updatedBy,
            ]);

            if ($success) {
                $newId = (int)$pdo->lastInsertId();
                $pdo->exec("UPDATE " . TABLE_LDAP_CONFIG . " SET is_active = 0 WHERE id != {$newId}");
                self::logAudit('UPDATE', 'SYSTEM', 'GLOBAL', $data['host'], "Updated LDAP connection configuration stored in database table eop_ldap_config (ID: {$newId})", $updatedBy);
            }
            return $success;
        } catch (Exception $e) {
            error_log('[Database::saveLdapConfig Error] ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Fetch all LDAP configuration history records from eop_ldap_config table
     */
    public static function getAllLdapConfigs(int $limit = 10): array {
        try {
            $pdo = self::getConnection();
            $stmt = $pdo->prepare("SELECT * FROM " . TABLE_LDAP_CONFIG . " ORDER BY id DESC LIMIT :limit");
            $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->fetchAll();
        } catch (Exception $e) {
            error_log('[Database::getAllLdapConfigs Error] ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Encrypt a secret for storage using the shared AES-256-GCM envelope
     * (see crypto.php). The IV and tag travel inside the ciphertext, so the
     * encryption_iv / encryption_tag columns are written as NULL. They are left in
     * the schema for compatibility with the previous column-per-field format and
     * are no longer read or written by any code path.
     */
    public static function encryptKeyPassword(string $password): string {
        return eopEncryptSecret($password);
    }

    /**
     * Decrypt a stored secret. Returns null when the value cannot be decrypted,
     * for example when AUTH_MASTER_ENCRYPTION_KEY does not match the record.
     */
    public static function decryptKeyPassword(?string $stored): ?string {
        return eopDecryptSecret($stored);
    }

    /**
     * Fetch active EOP private key & certificate authentication record from database table eop_auth_config.
     * The private key, PKCS#12 bundle and passphrase are decrypted here so every caller
     * receives plaintext; a null field means the value could not be decrypted.
     */
    public static function getEopAuthConfig(): ?array {
        try {
            $pdo = self::getConnection();
            $stmt = $pdo->query("SELECT * FROM " . TABLE_EOP_AUTH_CONFIG . " WHERE is_active = 1 ORDER BY id DESC LIMIT 1");
            $config = $stmt->fetch();
            if (!$config) {
                return null;
            }

            $config['private_key'] = self::decryptKeyPassword($config['private_key'] ?? '');
            $config['pkcs12_bundle'] = self::decryptKeyPassword($config['pkcs12_bundle'] ?? '');
            $config['encrypted_password'] = self::decryptKeyPassword($config['encrypted_password'] ?? '');

            return $config;
        } catch (Exception $e) {
            error_log('[Database::getEopAuthConfig Error] ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Save uploaded EOP private key and AES-256 encrypted password into database table eop_auth_config
     */
    public static function saveEopAuthConfig(array $data, string $uploadedBy): bool {
        try {
            $pdo = self::getConnection();
            $stmt = $pdo->prepare("INSERT INTO " . TABLE_EOP_AUTH_CONFIG . " 
                (tenant_id, client_id, certificate_thumbprint, key_filename, private_key, pkcs12_bundle, encrypted_password, encryption_iv, encryption_tag, key_type, organization, is_active, uploaded_by, created_at, updated_at)
                VALUES (:tenant, :client, :thumbprint, :filename, :privkey, :p12, :enc_pass, NULL, NULL, :ktype, :org, 1, :user, NOW(), NOW())");

            $thumbprint = strtoupper(preg_replace('/[^a-zA-Z0-9]/', '', $data['certificate_thumbprint'] ?? ''));
            $pkcs12 = trim((string)($data['pkcs12_bundle'] ?? ''));
            $keyType = $pkcs12 !== '' ? 'PKCS12_PFX' : ($data['key_type'] ?? 'RSA_PEM');

            $success = $stmt->execute([
                ':tenant'     => trim($data['tenant_id'] ?? (defined('M365_TENANT_ID') ? M365_TENANT_ID : '')),
                ':client'     => trim($data['client_id'] ?? (defined('M365_CLIENT_ID') ? M365_CLIENT_ID : '')),
                ':thumbprint' => $thumbprint ?: (defined('M365_CERT_THUMBPRINT') ? M365_CERT_THUMBPRINT : ''),
                ':filename'   => trim($data['key_filename'] ?? 'eop-cert-private.key'),
                ':privkey'    => self::encryptKeyPassword(trim((string)($data['private_key'] ?? ''))),
                ':p12'        => $pkcs12 !== '' ? self::encryptKeyPassword($pkcs12) : null,
                ':enc_pass'   => self::encryptKeyPassword((string)($data['password'] ?? '')),
                ':ktype'      => $keyType,
                ':org'        => trim($data['organization'] ?? (defined('M365_ORGANIZATION') ? M365_ORGANIZATION : 'corp.example.com')),
                ':user'       => $uploadedBy,
            ]);

            if ($success) {
                $newId = (int)$pdo->lastInsertId();
                $pdo->exec("UPDATE " . TABLE_EOP_AUTH_CONFIG . " SET is_active = 0 WHERE id != {$newId}");
                self::logAudit('UPDATE', 'SYSTEM', 'GLOBAL', $thumbprint ?: 'CERT', "Uploaded EOP private key & stored encrypted password in database table eop_auth_config (Record #{$newId})", $uploadedBy);
            }
            return $success;
        } catch (Exception $e) {
            error_log('[Database::saveEopAuthConfig Error] ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Fetch all EOP authentication history records from eop_auth_config table
     */
    public static function getAllEopAuthConfigs(int $limit = 10): array {
        try {
            $pdo = self::getConnection();
            $stmt = $pdo->prepare("SELECT id, tenant_id, client_id, certificate_thumbprint, key_filename, key_type, organization, is_active, uploaded_by, created_at, updated_at, 
                                   IF(encrypted_password != '', 1, 0) as has_encrypted_password,
                                   IF(pkcs12_bundle IS NOT NULL AND pkcs12_bundle != '', 1, 0) as has_pkcs12,
                                   IF(private_key LIKE 'EOPENC1:%', 1, 0) as private_key_encrypted
                                   FROM " . TABLE_EOP_AUTH_CONFIG . " ORDER BY id DESC LIMIT :limit");
            $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->fetchAll();
        } catch (Exception $e) {
            error_log('[Database::getAllEopAuthConfigs Error] ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Get fallback emergency local administrator by username from eop_local_admins table
     */
    public static function getFallbackAdmin(string $username): ?array {
        try {
            $pdo = self::getConnection();
            $stmt = $pdo->prepare("SELECT * FROM " . (defined('TABLE_LOCAL_ADMINS') ? TABLE_LOCAL_ADMINS : 'eop_local_admins') . " WHERE username = :u AND is_active = 1 LIMIT 1");
            $stmt->execute([':u' => $username]);
            $res = $stmt->fetch();
            return $res ?: null;
        } catch (Exception $e) {
            error_log('[Database::getFallbackAdmin Error] ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Save/register fallback administrator account with BCrypt password hash
     */
    public static function saveFallbackAdmin(string $username, string $passwordHash, string $createdBy = 'SETUP_WIZARD'): bool {
        try {
            $pdo = self::getConnection();
            $stmt = $pdo->prepare("INSERT INTO " . (defined('TABLE_LOCAL_ADMINS') ? TABLE_LOCAL_ADMINS : 'eop_local_admins') . " (username, password_hash, is_active, created_by, created_at, updated_at) 
                                   VALUES (:u, :p, 1, :cb, NOW(), NOW()) 
                                   ON DUPLICATE KEY UPDATE password_hash = :p2, is_active = 1, updated_at = NOW()");
            return $stmt->execute([':u' => $username, ':p' => $passwordHash, ':cb' => $createdBy, ':p2' => $passwordHash]);
        } catch (Exception $e) {
            error_log('[Database::saveFallbackAdmin Error] ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Check if initial setup is locked in MariaDB eop_setup_lock table
     */
    public static function isSetupLocked(): bool {
        try {
            $pdo = self::getConnection();
            $stmt = $pdo->query("SELECT is_locked FROM eop_setup_lock WHERE is_locked = 1 LIMIT 1");
            return (bool)$stmt->fetchColumn();
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Record permanent setup lock in MariaDB eop_setup_lock table
     */
    public static function lockSetup(string $ip = '127.0.0.1', string $user = 'INITIAL_SETUP_WIZARD'): bool {
        try {
            $pdo = self::getConnection();
            $stmt = $pdo->prepare("INSERT INTO eop_setup_lock (is_locked, completed_at, completed_by, installer_ip, app_version, schema_version) 
                                   VALUES (1, NOW(), :user, :ip, '1.0.0', '2026.1')");
            return $stmt->execute([':user' => $user, ':ip' => $ip]);
        } catch (Exception $e) {
            error_log('[Database::lockSetup Error] ' . $e->getMessage());
            return false;
        }
    }
}
