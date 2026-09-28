<?php
/**
 * Main Web UI Dashboard - Exchange Online Protection Anti-Spam Manager
 */

declare(strict_types=1);

// If configuration file is missing, redirect immediately to setup wizard
if (!file_exists(__DIR__ . '/config.php')) {
    header('Location: setup.php');
    exit;
}

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';
require_once __DIR__ . '/functions.php';

// If core database tables are not initialized yet, redirect to setup wizard Step 2
if (!Database::isInitialized()) {
    header('Location: setup.php?step=2');
    exit;
}

$user = requireAuth();
$csrfToken = getCsrfToken();
$flash = getFlash();

// Post-push summary popup data
$pushSummary = $_SESSION['push_summary'] ?? null;
unset($_SESSION['push_summary']);

// Duplicate rejected popup data
$duplicatePopup = $_SESSION['duplicate_popup'] ?? null;
unset($_SESSION['duplicate_popup']);

// Current active policy
$selectedPolicy = $_GET['policy'] ?? ($_SESSION['active_policy'] ?? DEFAULT_POLICY_NAME);
$_SESSION['active_policy'] = $selectedPolicy;

// Current active tab
$currentTab = $_GET['tab'] ?? 'allowed_senders';
if ($currentTab === 'ldap_config') {
    $currentTab = 'config_center';
}
if (!in_array($currentTab, ['allowed_senders', 'blocked_senders', 'allowed_domains', 'blocked_domains', 'sync_center', 'config_center'])) {
    $currentTab = 'allowed_senders';
}

$activeLdapConfig = Database::getLdapConfig();
$allLdapConfigs = ($currentTab === 'config_center') ? Database::getAllLdapConfigs() : [];
$activeAuthConfig = Database::getEopAuthConfig();
$allAuthConfigs = ($currentTab === 'config_center') ? Database::getAllEopAuthConfigs() : [];

$search = trim($_GET['q'] ?? '');
$page = max(1, (int)($_GET['p'] ?? 1));
$limit = 25;
$offset = ($page - 1) * $limit;

// Fetch counters for all 4 tables for the selected policy
$allowedSendersCount = Database::countListItems('allowed_senders', $selectedPolicy);
$blockedSendersCount = Database::countListItems('blocked_senders', $selectedPolicy);
$allowedDomainsCount = Database::countListItems('allowed_domains', $selectedPolicy);
$blockedDomainsCount = Database::countListItems('blocked_domains', $selectedPolicy);

// Fetch items for the active tab
$listItems = [];
$totalItems = 0;
if (in_array($currentTab, ['allowed_senders', 'blocked_senders', 'allowed_domains', 'blocked_domains'])) {
    $listItems = Database::getListItems($currentTab, $selectedPolicy, $search, $limit, $offset);
    $totalItems = Database::countListItems($currentTab, $selectedPolicy, $search);
}

$totalPages = max(1, (int)ceil($totalItems / $limit));
?>
<!DOCTYPE html>
<html lang="en" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars(APP_TITLE) ?> - <?= htmlspecialchars($selectedPolicy) ?></title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        brand: {
                            50: '#eff6ff',
                            500: '#3b82f6',
                            600: '#2563eb',
                            700: '#1d4ed8',
                        }
                    }
                }
            }
        };
        // Initialize dark mode from localStorage or system preference
        if (localStorage.getItem('theme') === 'dark' || (!localStorage.getItem('theme') && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
            document.documentElement.classList.add('dark');
        } else {
            document.documentElement.classList.remove('dark');
        }
    </script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        .active-tab { border-bottom: 2px solid #2563eb; color: #2563eb; font-weight: 600; }
        .dark .active-tab { border-bottom: 2px solid #60a5fa; color: #60a5fa; font-weight: 600; }
    </style>
</head>
<body class="bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-100 min-h-screen flex flex-col font-sans transition-colors duration-200">

    <!-- Top Navigation Bar -->
    <header class="bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 sticky top-0 z-30 shadow-xs transition-colors duration-200">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
            <div class="flex items-center space-x-3">
                <div class="w-9 h-9 rounded-lg bg-blue-600 dark:bg-blue-500 text-white flex items-center justify-center font-bold text-lg shadow-sm">
                    <i class="fa-solid fa-shield-halved"></i>
                </div>
                <div>
                    <h1 class="text-base font-bold text-slate-900 dark:text-white leading-tight"><?= htmlspecialchars(APP_TITLE) ?></h1>
                </div>
            </div>

            <!-- Policy Selector, Dark Mode Toggle & User Profile -->
            <div class="flex items-center space-x-4">
                <!-- Policy Dropdown -->
                <form method="GET" action="index.php" class="flex items-center">
                    <input type="hidden" name="tab" value="<?= htmlspecialchars($currentTab) ?>">
                    <label for="policySelect" class="text-xs font-semibold text-slate-500 dark:text-slate-400 mr-2 uppercase tracking-wider">Policy:</label>
                    <select id="policySelect" name="policy" onchange="this.form.submit()"
                            class="bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-100 text-sm rounded-md px-3 py-1.5 focus:ring-2 focus:ring-blue-500 focus:outline-hidden font-medium">
                        <?php foreach ($GLOBALS['AVAILABLE_POLICIES'] as $polName => $polDesc): ?>
                            <option value="<?= htmlspecialchars($polName) ?>" <?= $polName === $selectedPolicy ? 'selected' : '' ?>>
                                <?= htmlspecialchars($polName) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </form>

                <!-- Push Changes from MariaDB to EOP Button -->
                <form method="POST" action="actions.php" class="inline" onsubmit="return confirm('Push all MariaDB changes for policy &quot;<?= htmlspecialchars($selectedPolicy) ?>&quot; to Microsoft 365 Exchange Online Protection?');">
                    <input type="hidden" name="action" value="trigger_sync">
                    <input type="hidden" name="direction" value="push">
                    <input type="hidden" name="policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                    <button type="submit" 
                            class="px-3.5 py-1.5 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white rounded-lg text-xs font-bold flex items-center space-x-1.5 shadow-xs transition cursor-pointer"
                            title="Push changes from MariaDB tables to Exchange Online Protection (EOP)">
                        <i class="fa-solid fa-cloud-arrow-up"></i>
                        <span>Push to EOP</span>
                    </button>
                </form>

                <!-- Direct Link to Configuration Page -->
                <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=config_center" 
                   class="px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition <?= in_array($currentTab, ['config_center', 'ldap_config']) ? 'bg-indigo-600 text-white shadow-xs' : 'bg-indigo-50 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-800 hover:bg-indigo-100 dark:hover:bg-indigo-900/60' ?>"
                   title="Open Configuration Page (Upload Private Key & Modify LDAP Settings)">
                    <i class="fa-solid fa-key"></i>
                    <span>Configuration Page</span>
                </a>

                <!-- Dark Mode Toggle Button -->
                <button type="button" id="themeToggleBtn" onclick="toggleTheme()" 
                        class="p-2 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 bg-slate-100 dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 transition" 
                        title="Toggle Dark / Light Mode">
                    <i id="themeIcon" class="fa-solid fa-moon text-sm"></i>
                </button>

                <!-- AD User Badge -->
                <div class="flex items-center pl-3 border-l border-slate-200 dark:border-slate-800 space-x-3">
                    <div class="text-right">
                        <div class="text-sm font-semibold text-slate-800 dark:text-slate-200 flex items-center justify-end space-x-1">
                            <span><?= htmlspecialchars($user['displayName'] ?? $user['username']) ?></span>
                            <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/40">AD Verified</span>
                        </div>
                        <div class="text-[11px] text-slate-500 dark:text-slate-400" title="<?= htmlspecialchars($user['groupDn'] ?? '') ?>">
                            <?= htmlspecialchars($user['username']) ?>
                        </div>
                    </div>
                    <a href="logout.php" class="text-slate-400 hover:text-rose-600 dark:hover:text-rose-400 transition p-1.5 rounded-md hover:bg-rose-50 dark:hover:bg-rose-950/40" title="Sign Out">
                        <i class="fa-solid fa-right-from-bracket text-base"></i>
                    </a>
                </div>
            </div>
        </div>
    </header>

    <!-- Main Container -->
    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 grow w-full">

        <!-- Flash Alert (Auto-dismisses in 5s) -->
        <?php if ($flash): ?>
            <div id="flashAlertBanner" class="mb-5 p-4 rounded-lg flex items-center justify-between border transition-all duration-300 <?= $flash['type'] === 'success' ? 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-800 dark:text-emerald-200 border-emerald-200 dark:border-emerald-800/60' : ($flash['type'] === 'error' ? 'bg-rose-50 dark:bg-rose-950/40 text-rose-800 dark:text-rose-200 border-rose-200 dark:border-rose-800/60' : 'bg-blue-50 dark:bg-blue-950/40 text-blue-800 dark:text-blue-200 border-blue-200 dark:border-blue-800/60') ?>">
                <div class="flex items-center space-x-2">
                    <i class="fa-solid <?= $flash['type'] === 'success' ? 'fa-circle-check text-emerald-600 dark:text-emerald-400' : 'fa-circle-exclamation text-rose-600 dark:text-rose-400' ?>"></i>
                    <span class="text-sm font-medium"><?= htmlspecialchars($flash['message']) ?></span>
                </div>
                <div class="flex items-center space-x-2">
                    <span class="text-[11px] text-slate-400 font-mono hidden sm:inline">auto-dismissing</span>
                    <button onclick="this.closest('#flashAlertBanner').remove()" class="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 text-sm cursor-pointer p-1"><i class="fa-solid fa-xmark"></i></button>
                </div>
            </div>
            <script>
                setTimeout(function() {
                    const el = document.getElementById('flashAlertBanner');
                    if (el) {
                        el.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
                        el.style.opacity = '0';
                        el.style.transform = 'translateY(-6px)';
                        setTimeout(() => el.remove(), 400);
                    }
                }, 5000);
            </script>
        <?php endif; ?>

        <!-- Policy Summary Cards -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
            <!-- Allowed Senders -->
            <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=allowed_senders" 
               class="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs hover:border-emerald-400 dark:hover:border-emerald-500 transition block <?= $currentTab === 'allowed_senders' ? 'ring-2 ring-emerald-500' : '' ?>">
                <div class="flex items-center justify-between">
                    <span class="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Allowed Senders</span>
                    <span class="w-7 h-7 rounded-full bg-emerald-50 dark:bg-emerald-950/50 text-emerald-600 dark:text-emerald-400 flex items-center justify-center text-xs"><i class="fa-solid fa-envelope-circle-check"></i></span>
                </div>
                <div class="mt-2 text-2xl font-bold text-slate-900 dark:text-white"><?= number_format($allowedSendersCount) ?></div>
                <div class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">Table: <code>eop_allowed_senders</code></div>
            </a>

            <!-- Blocked Senders -->
            <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=blocked_senders" 
               class="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs hover:border-rose-400 dark:hover:border-rose-500 transition block <?= $currentTab === 'blocked_senders' ? 'ring-2 ring-rose-500' : '' ?>">
                <div class="flex items-center justify-between">
                    <span class="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Blocked Senders</span>
                    <span class="w-7 h-7 rounded-full bg-rose-50 dark:bg-rose-950/50 text-rose-600 dark:text-rose-400 flex items-center justify-center text-xs"><i class="fa-solid fa-envelope-circle-xmark"></i></span>
                </div>
                <div class="mt-2 text-2xl font-bold text-slate-900 dark:text-white"><?= number_format($blockedSendersCount) ?></div>
                <div class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">Table: <code>eop_blocked_senders</code></div>
            </a>

            <!-- Allowed Domains -->
            <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=allowed_domains" 
               class="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs hover:border-blue-400 dark:hover:border-blue-500 transition block <?= $currentTab === 'allowed_domains' ? 'ring-2 ring-blue-500' : '' ?>">
                <div class="flex items-center justify-between">
                    <span class="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Allowed Domains</span>
                    <span class="w-7 h-7 rounded-full bg-blue-50 dark:bg-blue-950/50 text-blue-600 dark:text-blue-400 flex items-center justify-center text-xs"><i class="fa-solid fa-globe"></i></span>
                </div>
                <div class="mt-2 text-2xl font-bold text-slate-900 dark:text-white"><?= number_format($allowedDomainsCount) ?></div>
                <div class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">Table: <code>eop_allowed_domains</code></div>
            </a>

            <!-- Blocked Domains -->
            <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=blocked_domains" 
               class="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs hover:border-amber-400 dark:hover:border-amber-500 transition block <?= $currentTab === 'blocked_domains' ? 'ring-2 ring-amber-500' : '' ?>">
                <div class="flex items-center justify-between">
                    <span class="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Blocked Domains</span>
                    <span class="w-7 h-7 rounded-full bg-amber-50 dark:bg-amber-950/50 text-amber-600 dark:text-amber-400 flex items-center justify-center text-xs"><i class="fa-solid fa-ban"></i></span>
                </div>
                <div class="mt-2 text-2xl font-bold text-slate-900 dark:text-white"><?= number_format($blockedDomainsCount) ?></div>
                <div class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">Table: <code>eop_blocked_domains</code></div>
            </a>

            <!-- Configuration Center Card -->
            <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=config_center" 
               class="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs hover:border-indigo-400 dark:hover:border-indigo-500 transition block <?= in_array($currentTab, ['config_center', 'ldap_config']) ? 'ring-2 ring-indigo-500' : '' ?>">
                <div class="flex items-center justify-between">
                    <span class="text-xs font-semibold text-indigo-600 dark:text-indigo-400 uppercase tracking-wider">Configuration</span>
                    <span class="w-7 h-7 rounded-full bg-indigo-50 dark:bg-indigo-950/50 text-indigo-600 dark:text-indigo-400 flex items-center justify-center text-xs"><i class="fa-solid fa-key"></i></span>
                </div>
                <div class="mt-2 text-base font-bold text-slate-900 dark:text-white flex items-center justify-between">
                    <span>EOP &amp; LDAP</span>
                    <span class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 font-semibold">DB Stored</span>
                </div>
                <div class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">Tables: <code>eop_auth &amp; eop_ldap</code></div>
            </a>
        </div>

        <!-- Navigation Tabs -->
        <div class="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs overflow-hidden transition-colors duration-200">
            <div class="border-b border-slate-200 dark:border-slate-800 px-6 flex items-center justify-between flex-wrap gap-2">
                <nav class="flex space-x-6">
                    <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=allowed_senders" 
                       class="py-4 text-sm <?= $currentTab === 'allowed_senders' ? 'active-tab' : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200' ?>">
                        <i class="fa-solid fa-envelope-circle-check text-emerald-600 dark:text-emerald-400 mr-1.5"></i> Allowed Senders (<?= $allowedSendersCount ?>)
                    </a>
                    <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=blocked_senders" 
                       class="py-4 text-sm <?= $currentTab === 'blocked_senders' ? 'active-tab' : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200' ?>">
                        <i class="fa-solid fa-envelope-circle-xmark text-rose-600 dark:text-rose-400 mr-1.5"></i> Blocked Senders (<?= $blockedSendersCount ?>)
                    </a>
                    <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=allowed_domains" 
                       class="py-4 text-sm <?= $currentTab === 'allowed_domains' ? 'active-tab' : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200' ?>">
                        <i class="fa-solid fa-globe text-blue-600 dark:text-blue-400 mr-1.5"></i> Allowed Domains (<?= $allowedDomainsCount ?>)
                    </a>
                    <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=blocked_domains" 
                       class="py-4 text-sm <?= $currentTab === 'blocked_domains' ? 'active-tab' : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200' ?>">
                        <i class="fa-solid fa-ban text-amber-600 dark:text-amber-400 mr-1.5"></i> Blocked Domains (<?= $blockedDomainsCount ?>)
                    </a>
                    <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=sync_center" 
                       class="py-4 text-sm <?= $currentTab === 'sync_center' ? 'active-tab' : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200' ?>">
                        <i class="fa-solid fa-rotate text-indigo-600 dark:text-indigo-400 mr-1.5"></i> Exchange Sync
                    </a>
                    <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=config_center" 
                       class="py-4 text-sm <?= $currentTab === 'config_center' ? 'active-tab' : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200' ?>">
                        <i class="fa-solid fa-key text-purple-600 dark:text-purple-400 mr-1.5"></i> Configuration (Keys & LDAP)
                    </a>
                </nav>

                <!-- Action Buttons -->
                <?php if (!in_array($currentTab, ['sync_center', 'config_center', 'ldap_config'])): ?>
                <div class="flex items-center space-x-2 py-2">
                    <button onclick="document.getElementById('quickAddModal').classList.remove('hidden')" 
                            class="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-md shadow-xs flex items-center space-x-1.5 transition">
                        <i class="fa-solid fa-plus"></i>
                        <span>Add Entry</span>
                    </button>
                    <button onclick="document.getElementById('bulkAddModal').classList.remove('hidden')" 
                            class="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-semibold rounded-md flex items-center space-x-1.5 transition">
                        <i class="fa-solid fa-file-import"></i>
                        <span>Bulk Import</span>
                    </button>
                    <!-- Split Smart Sort Buttons: Allowed and Blocked -->
                    <button type="button" onclick="openSmartSortModal('allowed')" 
                            class="px-3 py-1.5 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-700 hover:to-teal-700 text-white text-xs font-semibold rounded-md shadow-xs flex items-center space-x-1.5 transition cursor-pointer"
                            title="Auto-sort mixed senders &amp; domains directly into Allowed tables">
                        <i class="fa-solid fa-shield-halved text-emerald-200"></i>
                        <span>Smart Sort Allowed</span>
                    </button>
                    <button type="button" onclick="openSmartSortModal('blocked')" 
                            class="px-3 py-1.5 bg-gradient-to-r from-rose-600 to-red-600 hover:from-rose-700 hover:to-red-700 text-white text-xs font-semibold rounded-md shadow-xs flex items-center space-x-1.5 transition cursor-pointer"
                            title="Auto-sort mixed senders &amp; domains directly into Blocked tables">
                        <i class="fa-solid fa-ban text-rose-200"></i>
                        <span>Smart Sort Blocked</span>
                    </button>
                    <a href="actions.php?action=export_csv&list=<?= $currentTab ?>&policy=<?= urlencode($selectedPolicy) ?>&csrf=<?= $csrfToken ?>" 
                       class="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-semibold rounded-md flex items-center space-x-1.5 transition">
                        <i class="fa-solid fa-file-arrow-down"></i>
                        <span>Export CSV</span>
                    </a>

                    <!-- Push to EOP Action Button -->
                    <form method="POST" action="actions.php" class="inline" onsubmit="return confirm('Push all MariaDB changes for policy &quot;<?= htmlspecialchars($selectedPolicy) ?>&quot; to Microsoft 365 Exchange Online Protection?');">
                        <input type="hidden" name="action" value="trigger_sync">
                        <input type="hidden" name="direction" value="push">
                        <input type="hidden" name="policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                        <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                        <button type="submit" 
                                class="px-3.5 py-1.5 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white text-xs font-bold rounded-md shadow-xs flex items-center space-x-1.5 transition cursor-pointer"
                                title="Push all changes from MariaDB tables to Exchange Online Protection (EOP)">
                            <i class="fa-solid fa-cloud-arrow-up"></i>
                            <span>Push Changes to EOP</span>
                        </button>
                    </form>
                </div>
                <?php endif; ?>
            </div>

            <!-- List Content -->
            <?php if ($currentTab === 'sync_center'): ?>
                <!-- Exchange Online Sync View -->
                <div class="p-6">
                    <div class="max-w-4xl space-y-6">
                        <div>
                            <h2 class="text-lg font-bold text-slate-900 dark:text-white mb-1">Exchange Online Protection Synchronization</h2>
                            <p class="text-sm text-slate-600 dark:text-slate-400">
                                Synchronize the 4 MariaDB tables for policy <strong class="text-blue-600 dark:text-blue-400"><?= htmlspecialchars($selectedPolicy) ?></strong> with Microsoft 365 Exchange Online Protection.
                            </p>
                        </div>

                        <!-- Scheduled Cron Policy Notice Banner -->
                        <div class="p-4 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800/60 text-xs text-amber-900 dark:text-amber-200 space-y-1.5 leading-relaxed">
                            <div class="font-bold flex items-center gap-1.5 text-amber-800 dark:text-amber-300">
                                <i class="fa-solid fa-clock-rotate-left"></i>
                                <span>Cron Policy Enforcement: Pull-Only Mode</span>
                            </div>
                            <p>
                                The scheduled Linux cron job (<code>cron-sync.php --action=pull</code>) runs every 15 minutes and <strong>only pulls changes from Exchange Online into MariaDB</strong>.
                                It does <strong>not</strong> push local changes to EOP. Pushing local MariaDB modifications to Microsoft 365 requires an intentional administrator action.
                            </p>
                        </div>

                        <!-- Commands Preview -->
                        <div class="space-y-3">
                            <div class="bg-slate-900 dark:bg-slate-950 border border-slate-800 text-slate-100 rounded-lg p-4 font-mono text-xs overflow-x-auto shadow-inner">
                                <div class="text-amber-400 font-bold mb-1"># 1. Cron Job Command (PULL ONLY from EOP):</div>
                                <div class="text-slate-300">Get-HostedContentFilterPolicy -Identity "<?= htmlspecialchars($selectedPolicy) ?>"</div>
                                <div class="text-slate-500 text-[11px] mt-1"># Queries Microsoft 365 and ingests any external updates into MariaDB</div>
                            </div>

                            <div class="bg-slate-900 dark:bg-slate-950 border border-slate-800 text-slate-100 rounded-lg p-4 font-mono text-xs overflow-x-auto shadow-inner">
                                <div class="text-indigo-400 font-bold mb-1"># 2. Manual Admin Command (PUSH to EOP):</div>
                                <div class="text-emerald-400">Set-HostedContentFilterPolicy `</div>
                                <div class="pl-4 text-slate-200">-Identity "<?= htmlspecialchars($selectedPolicy) ?>" `</div>
                                <div class="pl-4 text-blue-300">-AllowedSenders @('<?= implode("', '", array_slice(Database::getAllItemsForSync('allowed_senders', $selectedPolicy), 0, 5)) ?><?= $allowedSendersCount > 5 ? "', ... +".($allowedSendersCount-5)." more" : "" ?>') `</div>
                                <div class="pl-4 text-rose-300">-BlockedSenders @('<?= implode("', '", array_slice(Database::getAllItemsForSync('blocked_senders', $selectedPolicy), 0, 5)) ?><?= $blockedSendersCount > 5 ? "', ... +".($blockedSendersCount-5)." more" : "" ?>') `</div>
                                <div class="pl-4 text-cyan-300">-AllowedSenderDomains @('<?= implode("', '", array_slice(Database::getAllItemsForSync('allowed_domains', $selectedPolicy), 0, 5)) ?><?= $allowedDomainsCount > 5 ? "', ... +".($allowedDomainsCount-5)." more" : "" ?>') `</div>
                                <div class="pl-4 text-amber-300">-BlockedSenderDomains @('<?= implode("', '", array_slice(Database::getAllItemsForSync('blocked_domains', $selectedPolicy), 0, 5)) ?><?= $blockedDomainsCount > 5 ? "', ... +".($blockedDomainsCount-5)." more" : "" ?>')</div>
                            </div>
                        </div>

                        <!-- Sync Action Forms -->
                        <div class="flex flex-wrap items-center gap-3 pt-2">
                            <!-- Pull Form (Same as Cron) -->
                            <form method="POST" action="actions.php">
                                <input type="hidden" name="action" value="trigger_sync">
                                <input type="hidden" name="direction" value="pull">
                                <input type="hidden" name="policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">

                                <button type="submit" class="px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center space-x-2 transition">
                                    <i class="fa-solid fa-cloud-arrow-down"></i>
                                    <span>Pull from Exchange Online (Cron Mode)</span>
                                </button>
                            </form>

                            <!-- Push Form (Manual Admin) -->
                            <form method="POST" action="actions.php" onsubmit="return confirm('Are you sure you want to push all MariaDB entries to Microsoft 365 Exchange Online Protection?');">
                                <input type="hidden" name="action" value="trigger_sync">
                                <input type="hidden" name="direction" value="push">
                                <input type="hidden" name="policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">

                                <button type="submit" class="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center space-x-2 transition">
                                    <i class="fa-solid fa-cloud-arrow-up"></i>
                                    <span>Push Changes to Exchange Online (Admin)</span>
                                </button>
                            </form>
                        </div>
                    </div>
                </div>

            <?php elseif (in_array($currentTab, ['config_center', 'ldap_config'])): ?>
                <!-- Unified Configuration Page: EOP Private Key & AD LDAP Settings -->
                <div class="p-6">
                    <div class="max-w-5xl">
                        <!-- Overview Header -->
                        <div class="flex items-start justify-between flex-wrap gap-4 mb-6 pb-6 border-b border-slate-200 dark:border-slate-800">
                            <div>
                                <h2 class="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
                                    <i class="fa-solid fa-sliders text-indigo-600 dark:text-indigo-400"></i>
                                    <span>System Configuration & Credentials</span>
                                </h2>
                                <p class="text-xs text-slate-500 dark:text-slate-400 mt-1">
                                    Manage Exchange Online Protection private key authentication and Active Directory LDAP connection parameters stored in remote MariaDB tables.
                                </p>
                            </div>

                            <div class="flex items-center gap-2 flex-wrap">
                                <span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-blue-100 dark:bg-blue-950/60 text-blue-800 dark:text-blue-300 border border-blue-200 dark:border-blue-800/60 font-mono">
                                    <i class="fa-solid fa-key text-[10px]"></i>
                                    Table: eop_auth_config
                                </span>
                                <span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-purple-100 dark:bg-purple-950/60 text-purple-800 dark:text-purple-300 border border-purple-200 dark:border-purple-800/60 font-mono">
                                    <i class="fa-solid fa-database text-[10px]"></i>
                                    Table: eop_ldap_config
                                </span>
                            </div>
                        </div>

                        <!-- Active Credentials Status Strip -->
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
                            <!-- EOP Private Key Status -->
                            <div class="p-4 rounded-xl border border-blue-200 dark:border-blue-900/60 bg-blue-50/60 dark:bg-blue-950/30">
                                <div class="flex items-center justify-between mb-2">
                                    <div class="flex items-center gap-2 font-bold text-xs text-blue-900 dark:text-blue-200">
                                        <i class="fa-solid fa-shield-halved text-blue-600 dark:text-blue-400"></i>
                                        <span>Exchange Online Private Key Auth</span>
                                    </div>
                                    <span class="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/60">
                                        <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                                        Active DB Record #<?= htmlspecialchars((string)($activeAuthConfig['id'] ?? 1)) ?>
                                    </span>
                                </div>
                                <div class="space-y-1 text-xs text-slate-600 dark:text-slate-300 font-mono">
                                    <div class="flex justify-between">
                                        <span class="text-slate-400">Thumbprint:</span>
                                        <span class="font-bold text-slate-800 dark:text-slate-100"><?= htmlspecialchars(substr($activeAuthConfig['certificate_thumbprint'] ?? (defined('M365_CERT_THUMBPRINT') ? M365_CERT_THUMBPRINT : '9A2F8B3C1D4E5F6A'), 0, 20)) ?>...</span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span class="text-slate-400">Key File:</span>
                                        <span><?= htmlspecialchars($activeAuthConfig['key_filename'] ?? 'eop-cert-private.key') ?></span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span class="text-slate-400">Key Password:</span>
                                        <span class="text-emerald-600 dark:text-emerald-400 font-semibold flex items-center gap-1">
                                            <i class="fa-solid fa-lock text-[10px]"></i> AES-256-GCM Encrypted
                                        </span>
                                    </div>
                                </div>
                            </div>

                            <!-- LDAP Status -->
                            <div class="p-4 rounded-xl border border-purple-200 dark:border-purple-900/60 bg-purple-50/60 dark:bg-purple-950/30">
                                <div class="flex items-center justify-between mb-2">
                                    <div class="flex items-center gap-2 font-bold text-xs text-purple-900 dark:text-purple-200">
                                        <i class="fa-solid fa-network-wired text-purple-600 dark:text-purple-400"></i>
                                        <span>Active Directory LDAP Connection</span>
                                    </div>
                                    <span class="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/60">
                                        <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                                        Active DB Record #<?= htmlspecialchars((string)($activeLdapConfig['id'] ?? 1)) ?>
                                    </span>
                                </div>
                                <div class="space-y-1 text-xs text-slate-600 dark:text-slate-300 font-mono">
                                    <div class="flex justify-between">
                                        <span class="text-slate-400">Host & Port:</span>
                                        <span class="font-bold text-slate-800 dark:text-slate-100"><?= htmlspecialchars($activeLdapConfig['host'] ?? LDAP_HOST) ?>:<?= (int)($activeLdapConfig['port'] ?? LDAP_PORT) ?> (<?= strtoupper(htmlspecialchars($activeLdapConfig['protocol'] ?? 'ldap')) ?>)</span>
                                    </div>
                                    <div class="flex justify-between truncate" title="<?= htmlspecialchars($activeLdapConfig['authorized_group_dn'] ?? LDAP_AUTHORIZED_GROUP_DN) ?>">
                                        <span class="text-slate-400">Group DN:</span>
                                        <span class="truncate max-w-[200px]"><?= htmlspecialchars($activeLdapConfig['authorized_group_dn'] ?? LDAP_AUTHORIZED_GROUP_DN) ?></span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span class="text-slate-400">Security:</span>
                                        <span>Port 389 Plain LDAP &bull; LDAPS Optional</span>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- PART 1: Exchange Online Protection Private Key Upload & Settings -->
                        <div class="mb-10 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-xs overflow-hidden">
                            <div class="px-6 py-4 bg-slate-50 dark:bg-slate-800/60 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
                                <div class="flex items-center space-x-2.5">
                                    <div class="w-7 h-7 rounded-lg bg-blue-600 text-white flex items-center justify-center text-xs">
                                        <i class="fa-solid fa-key"></i>
                                    </div>
                                    <div>
                                        <h3 class="text-sm font-bold text-slate-900 dark:text-white">Exchange Online Protection - Private Key & Certificate</h3>
                                        <p class="text-[11px] text-slate-500 dark:text-slate-400">Upload private key file and store encrypted password in MariaDB table <code>eop_auth_config</code></p>
                                    </div>
                                </div>
                                <span class="text-[11px] font-mono bg-blue-100 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 px-2.5 py-0.5 rounded-full font-semibold">
                                    App-Only CBA Auth
                                </span>
                            </div>

                            <form method="POST" action="actions.php" enctype="multipart/form-data" class="p-6">
                                <input type="hidden" name="action" value="upload_eop_key">
                                <input type="hidden" name="policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">

                                <div class="grid grid-cols-1 md:grid-cols-2 gap-5 text-xs mb-5">
                                    <!-- File Upload for Private Key -->
                                    <div class="col-span-1 md:col-span-2">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                                            Upload Private Key File (.pem, .key, .pfx, .crt):
                                        </label>
                                        <input type="file" name="private_key_file" accept=".pem,.key,.pfx,.cer,.crt,.txt"
                                               class="w-full text-xs text-slate-500 dark:text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-blue-50 file:text-blue-700 dark:file:bg-blue-950/80 dark:file:text-blue-300 hover:file:bg-blue-100 dark:hover:file:bg-blue-900 border border-slate-300 dark:border-slate-700 rounded-lg p-2 bg-slate-50 dark:bg-slate-800">
                                        <p class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">Upload the RSA or PKCS#8 private key associated with your Azure AD App Registration certificate.</p>
                                    </div>

                                    <!-- Direct Paste Option -->
                                    <div class="col-span-1 md:col-span-2">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                                            Or Paste Private Key Text (PEM format):
                                        </label>
                                        <textarea name="private_key_text" rows="4" placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...&#10;-----END RSA PRIVATE KEY-----"
                                                  class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg p-3 text-slate-900 dark:text-white font-mono text-[11px] focus:ring-2 focus:ring-blue-500 focus:outline-hidden"></textarea>
                                    </div>

                                    <!-- Private Key Passphrase (Encrypted via AES-256-GCM) -->
                                    <div class="col-span-1">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1 flex items-center justify-between">
                                            <span>Private Key Password / Passphrase:</span>
                                            <span class="text-emerald-600 dark:text-emerald-400 text-[10px] font-semibold"><i class="fa-solid fa-lock"></i> Encrypted with AES-256-GCM</span>
                                        </label>
                                        <input type="password" name="key_password" 
                                               class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                                               placeholder="Enter passphrase if key is encrypted">
                                        <p class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">The passphrase is encrypted using AES-256-GCM before writing to the database. Plaintext is never stored.</p>
                                    </div>

                                    <!-- Certificate Thumbprint -->
                                    <div class="col-span-1">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                                            Certificate Thumbprint (SHA-1):
                                        </label>
                                        <input type="text" name="certificate_thumbprint" 
                                               value="<?= htmlspecialchars($activeAuthConfig['certificate_thumbprint'] ?? (defined('M365_CERT_THUMBPRINT') ? M365_CERT_THUMBPRINT : '9A2F8B3C1D4E5F6A7B8C9D0E1F2A3B4C5D6E7F80')) ?>"
                                               class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono uppercase focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                                               placeholder="40-hex character thumbprint">
                                        <p class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">Matches the certificate uploaded to Azure AD / Entra ID App Registration.</p>
                                    </div>

                                    <!-- Tenant ID -->
                                    <div class="col-span-1">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                                            Azure AD Tenant ID:
                                        </label>
                                        <input type="text" name="tenant_id" 
                                               value="<?= htmlspecialchars($activeAuthConfig['tenant_id'] ?? (defined('M365_TENANT_ID') ? M365_TENANT_ID : '')) ?>"
                                               class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono text-[11px] focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                                               placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx">
                                    </div>

                                    <!-- Client ID & Organization -->
                                    <div class="col-span-1 grid grid-cols-2 gap-3">
                                        <div>
                                            <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Application (Client) ID:</label>
                                            <input type="text" name="client_id" 
                                                   value="<?= htmlspecialchars($activeAuthConfig['client_id'] ?? (defined('M365_CLIENT_ID') ? M365_CLIENT_ID : '')) ?>"
                                                   class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono text-[11px] focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                                                   placeholder="Client ID">
                                        </div>
                                        <div>
                                            <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Organization / Domain:</label>
                                            <input type="text" name="organization" 
                                                   value="<?= htmlspecialchars($activeAuthConfig['organization'] ?? (defined('M365_ORGANIZATION') ? M365_ORGANIZATION : 'corp.example.com')) ?>"
                                                   class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono text-[11px] focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                                                   placeholder="corp.example.com">
                                        </div>
                                    </div>
                                </div>

                                <div class="flex items-center justify-end space-x-3 pt-4 border-t border-slate-100 dark:border-slate-800">
                                    <button type="submit" 
                                            class="px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center space-x-2 transition">
                                        <i class="fa-solid fa-cloud-arrow-up"></i>
                                        <span>Upload Key & Store Encrypted Password in Database</span>
                                    </button>
                                </div>
                            </form>

                            <!-- Database Records Table Preview for eop_auth_config -->
                            <div class="px-6 pb-6">
                                <h4 class="text-xs font-bold text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-1.5">
                                    <i class="fa-solid fa-table-cells text-blue-500"></i>
                                    <span>MariaDB Table Records (<code>eop_auth_config</code>)</span>
                                </h4>
                                <div class="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
                                    <table class="w-full text-left text-xs text-slate-700 dark:text-slate-300">
                                        <thead class="bg-slate-100 dark:bg-slate-800/80 text-slate-600 dark:text-slate-400 font-semibold border-b border-slate-200 dark:border-slate-800 uppercase tracking-wider text-[11px]">
                                            <tr>
                                                <th class="py-2.5 px-3">ID</th>
                                                <th class="py-2.5 px-3">Thumbprint</th>
                                                <th class="py-2.5 px-3">Key File</th>
                                                <th class="py-2.5 px-3">Encrypted Password</th>
                                                <th class="py-2.5 px-3">Status</th>
                                                <th class="py-2.5 px-3">Updated At</th>
                                                <th class="py-2.5 px-3">By</th>
                                            </tr>
                                        </thead>
                                        <tbody class="divide-y divide-slate-100 dark:divide-slate-800 text-[11px]">
                                            <?php if (!empty($allAuthConfigs)): ?>
                                                <?php foreach ($allAuthConfigs as $authRow): ?>
                                                    <tr class="hover:bg-slate-50 dark:hover:bg-slate-800/50 <?= !empty($authRow['is_active']) ? 'bg-blue-50/40 dark:bg-blue-950/20' : '' ?>">
                                                        <td class="py-2 px-3 font-mono font-bold text-blue-600 dark:text-blue-400">#<?= htmlspecialchars((string)$authRow['id']) ?></td>
                                                        <td class="py-2 px-3 font-mono"><?= htmlspecialchars(substr($authRow['certificate_thumbprint'], 0, 16)) ?>...</td>
                                                        <td class="py-2 px-3 font-mono"><?= htmlspecialchars($authRow['key_filename']) ?></td>
                                                        <td class="py-2 px-3">
                                                            <?php if (!empty($authRow['has_encrypted_password'])): ?>
                                                                <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300">
                                                                    <i class="fa-solid fa-lock text-[9px]"></i> AES-256-GCM
                                                                </span>
                                                            <?php else: ?>
                                                                <span class="text-slate-400 text-[10px]">No passphrase</span>
                                                            <?php endif; ?>
                                                        </td>
                                                        <td class="py-2 px-3">
                                                            <?php if (!empty($authRow['is_active'])): ?>
                                                                <span class="text-emerald-600 dark:text-emerald-400 font-semibold text-[11px] flex items-center gap-1">
                                                                    <i class="fa-solid fa-circle-check"></i> Active
                                                                </span>
                                                            <?php else: ?>
                                                                <span class="text-slate-400">Archived</span>
                                                            <?php endif; ?>
                                                        </td>
                                                        <td class="py-2 px-3 text-slate-400"><?= htmlspecialchars(substr($authRow['updated_at'] ?? '', 0, 16)) ?></td>
                                                        <td class="py-2 px-3 font-mono"><?= htmlspecialchars($authRow['uploaded_by'] ?? 'SYSTEM') ?></td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            <?php else: ?>
                                                <tr>
                                                    <td colspan="7" class="py-3 text-center text-slate-400">Default seed active in database. Upload above form to record new key.</td>
                                                </tr>
                                            <?php endif; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>

                        <!-- PART 2: Active Directory LDAP Settings Modification -->
                        <div class="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-xs overflow-hidden">
                            <div class="px-6 py-4 bg-slate-50 dark:bg-slate-800/60 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
                                <div class="flex items-center space-x-2.5">
                                    <div class="w-7 h-7 rounded-lg bg-purple-600 text-white flex items-center justify-center text-xs">
                                        <i class="fa-solid fa-network-wired"></i>
                                    </div>
                                    <div>
                                        <h3 class="text-sm font-bold text-slate-900 dark:text-white">Active Directory (LDAP) Connection Settings</h3>
                                        <p class="text-[11px] text-slate-500 dark:text-slate-400">Stored in and dynamically loaded from MariaDB table <code>eop_ldap_config</code></p>
                                    </div>
                                </div>
                                <span class="text-[11px] font-mono bg-purple-100 dark:bg-purple-950/60 text-purple-700 dark:text-purple-300 px-2.5 py-0.5 rounded-full font-semibold">
                                    Port 389 (Plain LDAP) Supported
                                </span>
                            </div>

                            <form method="POST" action="actions.php" class="p-6">
                                <input type="hidden" name="action" value="update_ldap_config">
                                <input type="hidden" name="policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">

                                <div class="grid grid-cols-1 md:grid-cols-2 gap-5 text-xs mb-5">
                                    <!-- Host -->
                                    <div class="col-span-1">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                                            LDAP Host (Domain Controller FQDN or IP):
                                        </label>
                                        <input type="text" name="ldap_host" required 
                                               value="<?= htmlspecialchars($activeLdapConfig['host'] ?? LDAP_HOST) ?>"
                                               class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                                               placeholder="dc01.corp.example.com">
                                    </div>

                                    <!-- Port & Protocol -->
                                    <div class="col-span-1 grid grid-cols-2 gap-3">
                                        <div>
                                            <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Port:</label>
                                            <input type="number" name="ldap_port" required 
                                                   value="<?= (int)($activeLdapConfig['port'] ?? LDAP_PORT) ?>"
                                                   class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                                                   placeholder="389">
                                        </div>
                                        <div>
                                            <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Protocol:</label>
                                            <select name="ldap_protocol" 
                                                    class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-medium focus:ring-2 focus:ring-purple-500 focus:outline-hidden">
                                                <?php $curProto = $activeLdapConfig['protocol'] ?? (defined('LDAP_PROTOCOL') ? LDAP_PROTOCOL : 'ldap'); ?>
                                                <option value="ldap" <?= $curProto === 'ldap' ? 'selected' : '' ?>>Plain LDAP (Port 389)</option>
                                                <option value="ldaps" <?= $curProto === 'ldaps' ? 'selected' : '' ?>>LDAPS / SSL (Port 636)</option>
                                                <option value="starttls" <?= $curProto === 'starttls' ? 'selected' : '' ?>>StartTLS (Port 389)</option>
                                            </select>
                                        </div>
                                    </div>

                                    <!-- Base DN -->
                                    <div class="col-span-1 md:col-span-2">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                                            LDAP Base Distinguished Name (Base DN):
                                        </label>
                                        <input type="text" name="ldap_base_dn" required 
                                               value="<?= htmlspecialchars($activeLdapConfig['base_dn'] ?? LDAP_BASE_DN) ?>"
                                               class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                                               placeholder="DC=corp,DC=example,DC=com">
                                    </div>

                                    <!-- Authorized Group DN -->
                                    <div class="col-span-1 md:col-span-2">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                                            Authorized Security Group DN (Mandatory RBAC):
                                        </label>
                                        <input type="text" name="ldap_group_dn" required 
                                               value="<?= htmlspecialchars($activeLdapConfig['authorized_group_dn'] ?? LDAP_AUTHORIZED_GROUP_DN) ?>"
                                               class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                                               placeholder="CN=Exchange-Admins,OU=Security Groups,DC=corp,DC=example,DC=com">
                                        <p class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">Users must belong to this AD group (or nested subgroups via matching rule 1.2.840.113556.1.4.1941) to sign in.</p>
                                    </div>

                                    <!-- Service Account Bind DN -->
                                    <div class="col-span-1">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                                            Service Account Bind DN (Optional):
                                        </label>
                                        <input type="text" name="ldap_bind_dn" 
                                               value="<?= htmlspecialchars($activeLdapConfig['bind_dn'] ?? (defined('LDAP_BIND_DN') ? LDAP_BIND_DN : '')) ?>"
                                               class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                                               placeholder="CN=svc-eop-web,OU=Service Accounts,DC=corp,DC=example,DC=com">
                                    </div>

                                    <!-- Service Account Bind Password -->
                                    <div class="col-span-1">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                                            Service Account Bind Password:
                                        </label>
                                        <input type="password" name="ldap_bind_pass" 
                                               value="<?= htmlspecialchars($activeLdapConfig['bind_password'] ?? (defined('LDAP_BIND_PASSWORD') ? LDAP_BIND_PASSWORD : '')) ?>"
                                               class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                                               placeholder="Leave blank or enter new password">
                                    </div>

                                    <!-- Account Suffix & Domain -->
                                    <div class="col-span-1">
                                        <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Account Suffix:</label>
                                        <input type="text" name="ldap_account_suffix" 
                                               value="<?= htmlspecialchars($activeLdapConfig['account_suffix'] ?? (defined('LDAP_ACCOUNT_SUFFIX') ? LDAP_ACCOUNT_SUFFIX : '@corp.example.com')) ?>"
                                               class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                                               placeholder="@corp.example.com">
                                    </div>

                                    <div class="col-span-1 grid grid-cols-2 gap-3">
                                        <div>
                                            <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">NetBIOS Domain:</label>
                                            <input type="text" name="ldap_netbios_domain" 
                                                   value="<?= htmlspecialchars($activeLdapConfig['netbios_domain'] ?? (defined('LDAP_NETBIOS_DOMAIN') ? LDAP_NETBIOS_DOMAIN : 'CORP')) ?>"
                                                   class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"
                                                   placeholder="CORP">
                                        </div>
                                        <div>
                                            <label class="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Timeout (Sec):</label>
                                            <input type="number" name="ldap_timeout" min="1" max="60" 
                                                   value="<?= (int)($activeLdapConfig['timeout_seconds'] ?? 5) ?>"
                                                   class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden">
                                        </div>
                                    </div>
                                </div>

                                <div class="flex items-center justify-end space-x-3 pt-4 border-t border-slate-100 dark:border-slate-800">
                                    <button type="submit" 
                                            class="px-5 py-2.5 bg-purple-600 hover:bg-purple-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center space-x-2 transition">
                                        <i class="fa-solid fa-floppy-disk"></i>
                                        <span>Save LDAP Settings to MariaDB Table</span>
                                    </button>
                                </div>
                            </form>

                            <!-- Database Records Table Preview for eop_ldap_config -->
                            <div class="px-6 pb-6">
                                <h4 class="text-xs font-bold text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-1.5">
                                    <i class="fa-solid fa-table-cells text-purple-500"></i>
                                    <span>MariaDB Table Records (<code>eop_ldap_config</code>)</span>
                                </h4>
                                <div class="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
                                    <table class="w-full text-left text-xs text-slate-700 dark:text-slate-300">
                                        <thead class="bg-slate-100 dark:bg-slate-800/80 text-slate-600 dark:text-slate-400 font-semibold border-b border-slate-200 dark:border-slate-800 uppercase tracking-wider text-[11px]">
                                            <tr>
                                                <th class="py-2.5 px-3">ID</th>
                                                <th class="py-2.5 px-3">Host</th>
                                                <th class="py-2.5 px-3">Port</th>
                                                <th class="py-2.5 px-3">Protocol</th>
                                                <th class="py-2.5 px-3">Base DN</th>
                                                <th class="py-2.5 px-3">Group DN</th>
                                                <th class="py-2.5 px-3">Status</th>
                                                <th class="py-2.5 px-3">Updated At</th>
                                                <th class="py-2.5 px-3">By</th>
                                            </tr>
                                        </thead>
                                        <tbody class="divide-y divide-slate-100 dark:divide-slate-800 text-[11px]">
                                            <?php if (!empty($allLdapConfigs)): ?>
                                                <?php foreach ($allLdapConfigs as $cfgRow): ?>
                                                    <tr class="hover:bg-slate-50 dark:hover:bg-slate-800/50 <?= !empty($cfgRow['is_active']) ? 'bg-purple-50/40 dark:bg-purple-950/20' : '' ?>">
                                                        <td class="py-2 px-3 font-mono font-bold text-purple-600 dark:text-purple-400">#<?= htmlspecialchars((string)$cfgRow['id']) ?></td>
                                                        <td class="py-2 px-3 font-mono"><?= htmlspecialchars($cfgRow['host']) ?></td>
                                                        <td class="py-2 px-3 font-mono"><?= (int)$cfgRow['port'] ?></td>
                                                        <td class="py-2 px-3">
                                                            <span class="px-2 py-0.5 rounded text-[10px] font-semibold <?= $cfgRow['protocol'] === 'ldap' ? 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300' : 'bg-blue-100 dark:bg-blue-950/60 text-blue-800 dark:text-blue-300' ?>">
                                                                <?= strtoupper(htmlspecialchars($cfgRow['protocol'])) ?>
                                                            </span>
                                                        </td>
                                                        <td class="py-2 px-3 font-mono text-[11px] truncate max-w-[150px]" title="<?= htmlspecialchars($cfgRow['base_dn']) ?>">
                                                            <?= htmlspecialchars($cfgRow['base_dn']) ?>
                                                        </td>
                                                        <td class="py-2 px-3 font-mono text-[11px] truncate max-w-[150px]" title="<?= htmlspecialchars($cfgRow['authorized_group_dn']) ?>">
                                                            <?= htmlspecialchars($cfgRow['authorized_group_dn']) ?>
                                                        </td>
                                                        <td class="py-2 px-3">
                                                            <?php if (!empty($cfgRow['is_active'])): ?>
                                                                <span class="text-emerald-600 dark:text-emerald-400 font-semibold text-[11px] flex items-center gap-1">
                                                                    <i class="fa-solid fa-circle-check"></i> Active
                                                                </span>
                                                            <?php else: ?>
                                                                <span class="text-slate-400">Archived</span>
                                                            <?php endif; ?>
                                                        </td>
                                                        <td class="py-2 px-3 text-slate-400"><?= htmlspecialchars(substr($cfgRow['updated_at'] ?? '', 0, 16)) ?></td>
                                                        <td class="py-2 px-3 font-mono"><?= htmlspecialchars($cfgRow['updated_by'] ?? 'SYSTEM') ?></td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            <?php else: ?>
                                                <tr>
                                                    <td colspan="9" class="py-3 text-center text-slate-400">Initial row active from defaults. Save above form to create record in table.</td>
                                                </tr>
                                            <?php endif; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

            <?php else: ?>
                <!-- Search & Filters -->
                <div class="p-4 border-b border-slate-100 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40 flex items-center justify-between">
                    <form method="GET" action="index.php" class="flex items-center max-w-md w-full">
                        <input type="hidden" name="policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                        <input type="hidden" name="tab" value="<?= htmlspecialchars($currentTab) ?>">
                        <div class="relative w-full">
                            <i class="fa-solid fa-magnifying-glass absolute left-3 top-2.5 text-slate-400 dark:text-slate-500 text-xs"></i>
                            <input type="text" name="q" value="<?= htmlspecialchars($search) ?>" placeholder="Search entries or notes..." 
                                   class="w-full bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-100 text-xs rounded-md pl-8 pr-3 py-2 focus:ring-2 focus:ring-blue-500 focus:outline-hidden">
                        </div>
                        <?php if ($search !== ''): ?>
                            <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=<?= $currentTab ?>" class="ml-2 text-xs text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200">Clear</a>
                        <?php endif; ?>
                    </form>
                    <div class="text-xs text-slate-500 dark:text-slate-400">
                        Showing <?= count($listItems) ?> of <?= $totalItems ?> items in <code class="text-blue-600 dark:text-blue-400"><?= Database::getTableName($currentTab) ?></code>
                    </div>
                </div>

                <!-- Table -->
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs text-slate-700 dark:text-slate-300">
                        <thead class="bg-slate-100 dark:bg-slate-800/80 text-slate-600 dark:text-slate-400 font-semibold border-b border-slate-200 dark:border-slate-800 uppercase tracking-wider">
                            <tr>
                                <th class="py-3 px-4">#</th>
                                <th class="py-3 px-4"><?= str_contains($currentTab, 'sender') ? 'Sender Email' : 'Domain' ?></th>
                                <th class="py-3 px-4">Note / Reason</th>
                                <th class="py-3 px-4">Added By (LDAP)</th>
                                <th class="py-3 px-4">Added On</th>
                                <th class="py-3 px-4 text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-100 dark:divide-slate-800">
                            <?php if (empty($listItems)): ?>
                                <tr>
                                    <td colspan="6" class="py-12 text-center text-slate-400 dark:text-slate-500">
                                        <i class="fa-regular fa-folder-open text-3xl mb-2 block"></i>
                                        No items found in this list for policy <strong><?= htmlspecialchars($selectedPolicy) ?></strong>.
                                    </td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($listItems as $row): ?>
                                    <tr class="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition">
                                        <td class="py-3 px-4 text-slate-400 dark:text-slate-500 font-mono"><?= $row['id'] ?></td>
                                        <td class="py-3 px-4 font-semibold text-slate-900 dark:text-white font-mono text-[13px]">
                                            <?= htmlspecialchars($row['item_value']) ?>
                                        </td>
                                        <td class="py-3 px-4 text-slate-600 dark:text-slate-400 max-w-xs truncate" title="<?= htmlspecialchars($row['note'] ?? '') ?>">
                                            <?= htmlspecialchars($row['note'] ?: '—') ?>
                                        </td>
                                        <td class="py-3 px-4 text-slate-600 dark:text-slate-400 font-mono text-[11px]">
                                            <span class="inline-flex items-center px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                                                <?= htmlspecialchars($row['added_by']) ?>
                                            </span>
                                        </td>
                                        <td class="py-3 px-4 text-slate-500 dark:text-slate-400 whitespace-nowrap">
                                            <?= htmlspecialchars(substr($row['created_at'], 0, 16)) ?>
                                        </td>
                                        <td class="py-3 px-4 text-right whitespace-nowrap">
                                            <form method="POST" action="actions.php" onsubmit="return confirm('Remove <?= htmlspecialchars($row['item_value']) ?> from <?= $currentTab ?>?');" class="inline">
                                                <input type="hidden" name="action" value="delete_item">
                                                <input type="hidden" name="id" value="<?= $row['id'] ?>">
                                                <input type="hidden" name="list" value="<?= $currentTab ?>">
                                                <input type="hidden" name="policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                                                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                                                <button type="submit" class="text-rose-600 dark:text-rose-400 hover:text-rose-800 dark:hover:text-rose-300 p-1 rounded hover:bg-rose-50 dark:hover:bg-rose-950/40 transition" title="Delete Entry">
                                                    <i class="fa-regular fa-trash-can text-sm"></i>
                                                </button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>

                <!-- Pagination -->
                <?php if ($totalPages > 1): ?>
                <div class="p-4 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
                    <div>Page <?= $page ?> of <?= $totalPages ?></div>
                    <div class="flex space-x-1">
                        <?php for ($p = 1; $p <= $totalPages; $p++): ?>
                            <a href="?policy=<?= urlencode($selectedPolicy) ?>&tab=<?= $currentTab ?>&p=<?= $p ?>&q=<?= urlencode($search) ?>" 
                               class="px-2.5 py-1 rounded border <?= $p === $page ? 'bg-blue-600 text-white border-blue-600' : 'bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700' ?>">
                                <?= $p ?>
                            </a>
                        <?php endfor; ?>
                    </div>
                </div>
                <?php endif; ?>
            <?php endif; ?>
        </div>
    </main>

    <!-- Quick Add Modal -->
    <div id="quickAddModal" class="hidden fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
        <div class="bg-white dark:bg-slate-900 rounded-xl shadow-xl max-w-md w-full p-6 border border-slate-200 dark:border-slate-800">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-base font-bold text-slate-900 dark:text-white">Add to <?= ucwords(str_replace('_', ' ', $currentTab)) ?></h3>
                <button onclick="document.getElementById('quickAddModal').classList.add('hidden')" class="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
                    <i class="fa-solid fa-xmark"></i>
                </button>
            </div>
            <form method="POST" action="actions.php">
                <input type="hidden" name="action" value="add_single">
                <input type="hidden" name="list" value="<?= $currentTab ?>">
                <input type="hidden" name="policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">

                <div class="mb-3">
                    <label class="block text-xs font-semibold text-slate-600 dark:text-slate-300 mb-1">
                        <?= str_contains($currentTab, 'sender') ? 'Email Address' : 'Domain Name' ?>:
                    </label>
                    <input type="text" name="value" required placeholder="<?= str_contains($currentTab, 'sender') ? 'user@example.com' : 'example.com or *.example.com' ?>" 
                           class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-100 text-sm rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:outline-hidden font-mono">
                </div>

                <div class="mb-4">
                    <label class="block text-xs font-semibold text-slate-600 dark:text-slate-300 mb-1">Reason / Change Ticket #:</label>
                    <textarea name="note" rows="2" placeholder="e.g. Approved partner vendor via Ticket INC-49210" 
                              class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-100 text-sm rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:outline-hidden"></textarea>
                </div>

                <div class="flex items-center justify-end space-x-2">
                    <button type="button" onclick="document.getElementById('quickAddModal').classList.add('hidden')" class="px-4 py-2 text-xs font-medium text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg">Cancel</button>
                    <button type="submit" class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg shadow-sm">Save Entry</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Bulk Add Modal -->
    <div id="bulkAddModal" class="hidden fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
        <div class="bg-white dark:bg-slate-900 rounded-xl shadow-xl max-w-lg w-full p-6 border border-slate-200 dark:border-slate-800">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-base font-bold text-slate-900 dark:text-white">Bulk Import - <?= ucwords(str_replace('_', ' ', $currentTab)) ?></h3>
                <button onclick="document.getElementById('bulkAddModal').classList.add('hidden')" class="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
                    <i class="fa-solid fa-xmark"></i>
                </button>
            </div>
            <form method="POST" action="actions.php">
                <input type="hidden" name="action" value="bulk_import">
                <input type="hidden" name="list" value="<?= $currentTab ?>">
                <input type="hidden" name="policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">

                <p class="text-xs text-slate-500 dark:text-slate-400 mb-2">Paste one item per line, or <code>value, optional note</code>:</p>
                <textarea name="bulk_data" rows="8" required placeholder="<?= str_contains($currentTab, 'sender') ? "ceo@partner.com, High priority partner
support@vendor.org, Vendor notification" : "partner.com, Main vendor domain
*.subdomain.net, Wildcard domain" ?>"
                          class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-100 text-xs rounded-lg p-3 font-mono focus:ring-2 focus:ring-blue-500 focus:outline-hidden mb-4"></textarea>

                <div class="flex items-center justify-end space-x-2">
                    <button type="button" onclick="document.getElementById('bulkAddModal').classList.add('hidden')" class="px-4 py-2 text-xs font-medium text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg">Cancel</button>
                    <button type="submit" class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg shadow-sm">Import Items</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Smart Sort & Import Modal (Auto-sorts Senders & Domains) -->
    <div id="smartSortModal" class="hidden fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
        <div class="bg-white dark:bg-slate-900 rounded-xl shadow-xl max-w-xl w-full p-6 border border-slate-200 dark:border-slate-800">
            <div class="flex items-center justify-between mb-4">
                <div class="flex items-center space-x-2">
                    <div id="smartSortModalIcon" class="w-8 h-8 rounded-lg bg-gradient-to-br from-emerald-600 to-teal-600 text-white flex items-center justify-center text-xs">
                        <i class="fa-solid fa-shield-halved text-emerald-200"></i>
                    </div>
                    <div>
                        <h3 id="smartSortModalTitle" class="text-base font-bold text-slate-900 dark:text-white">Smart Sort: Allowed Items</h3>
                        <p id="smartSortModalDesc" class="text-xs text-slate-500 dark:text-slate-400">Auto-routes emails to Senders table and domains to Domains table</p>
                    </div>
                </div>
                <button onclick="document.getElementById('smartSortModal').classList.add('hidden')" class="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
                    <i class="fa-solid fa-xmark"></i>
                </button>
            </div>
            <form method="POST" action="actions.php">
                <input type="hidden" name="action" value="smart_sort_import">
                <input type="hidden" name="policy" value="<?= htmlspecialchars($selectedPolicy) ?>">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">

                <div class="mb-4">
                    <label class="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">Target List Category:</label>
                    <div class="grid grid-cols-2 gap-3">
                        <label class="flex items-center space-x-2 p-2.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-purple-400 cursor-pointer text-xs">
                            <input type="radio" name="target_mode" value="blocked" <?= str_contains($currentTab, 'blocked') ? 'checked' : '' ?> class="text-purple-600">
                            <span><strong>Blocked Items</strong> (senders &amp; domains)</span>
                        </label>
                        <label class="flex items-center space-x-2 p-2.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-purple-400 cursor-pointer text-xs">
                            <input type="radio" name="target_mode" value="allowed" <?= str_contains($currentTab, 'allowed') ? 'checked' : '' ?> class="text-purple-600">
                            <span><strong>Allowed Items</strong> (senders &amp; domains)</span>
                        </label>
                    </div>
                </div>

                <div class="mb-3">
                    <label class="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                        Paste Mixed List (Emails and/or Domains, one per line):
                    </label>
                    <textarea name="bulk_data" rows="7" required placeholder="user@external.com, Sample sender note&#10;partner-domain.com, Domain note&#10;alert@external.org&#10;*.wildcard-domain.net"
                              class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-100 text-xs rounded-lg p-3 font-mono focus:ring-2 focus:ring-purple-500 focus:outline-hidden"></textarea>
                    <p class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">
                        Emails with <code>@</code> are routed to the Senders table; domain names are routed to the Domains table. Existing duplicates will be skipped.
                    </p>
                </div>

                <div class="mb-4">
                    <label class="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">Default Ticket # / Justification Note:</label>
                    <input type="text" name="default_note" placeholder="e.g. Bulk auto-classified intake Ticket #INC-9481" 
                           class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-100 text-xs rounded-lg px-3 py-2 focus:ring-2 focus:ring-purple-500 focus:outline-hidden">
                </div>

                <div class="flex items-center justify-end space-x-2">
                    <button type="button" onclick="document.getElementById('smartSortModal').classList.add('hidden')" class="px-4 py-2 text-xs font-medium text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg">Cancel</button>
                    <button id="smartSortSubmitBtn" type="submit" class="px-5 py-2 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center space-x-1.5 cursor-pointer">
                        <i class="fa-solid fa-wand-magic-sparkles text-amber-300"></i>
                        <span>Sort &amp; Import Items</span>
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Push Summary Result Modal (Showing what was added to each list) -->
    <?php if ($pushSummary): ?>
    <div id="pushSummaryModal" class="fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
        <div class="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl max-w-2xl w-full p-6 border border-slate-200 dark:border-slate-800 flex flex-col max-h-[90vh]">
            <div class="flex items-start justify-between pb-4 border-b border-slate-200 dark:border-slate-800">
                <div class="flex items-center space-x-3">
                    <div class="w-10 h-10 rounded-xl bg-emerald-100 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400 flex items-center justify-center">
                        <i class="fa-solid fa-circle-check text-lg"></i>
                    </div>
                    <div>
                        <h3 class="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
                            <span>All Changes Successfully Pushed to EOP (All 4 Tables)</span>
                            <span class="text-[11px] font-medium px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/40">Success</span>
                        </h3>
                        <p class="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                            Policy: <strong class="text-slate-700 dark:text-slate-200"><?= htmlspecialchars($pushSummary['policy']) ?></strong> &bull; Synced at: <span class="font-mono"><?= htmlspecialchars($pushSummary['timestamp']) ?></span>
                        </p>
                    </div>
                </div>
                <button type="button" onclick="document.getElementById('pushSummaryModal').remove()" class="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 p-1 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition cursor-pointer">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>

            <div class="py-3 text-xs text-slate-600 dark:text-slate-300">
                <p class="mb-2 text-xs">
                    The following entries from your remote MariaDB tables were successfully pushed and configured in Microsoft 365 Exchange Online via <code class="text-indigo-600 dark:text-indigo-400 font-bold">Set-HostedContentFilterPolicy</code>:
                </p>
                <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center text-xs">
                    <div class="bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800/50 p-2 rounded-lg">
                        <span class="block text-emerald-800 dark:text-emerald-300 font-bold text-sm"><?= count($pushSummary['allowedSenders']) ?></span>
                        <span class="text-[11px] text-emerald-700 dark:text-emerald-400">Allowed Senders</span>
                    </div>
                    <div class="bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800/50 p-2 rounded-lg">
                        <span class="block text-rose-800 dark:text-rose-300 font-bold text-sm"><?= count($pushSummary['blockedSenders']) ?></span>
                        <span class="text-[11px] text-rose-700 dark:text-rose-400">Blocked Senders</span>
                    </div>
                    <div class="bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800/50 p-2 rounded-lg">
                        <span class="block text-emerald-800 dark:text-emerald-300 font-bold text-sm"><?= count($pushSummary['allowedDomains']) ?></span>
                        <span class="text-[11px] text-emerald-700 dark:text-emerald-400">Allowed Domains</span>
                    </div>
                    <div class="bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800/50 p-2 rounded-lg">
                        <span class="block text-rose-800 dark:text-rose-300 font-bold text-sm"><?= count($pushSummary['blockedDomains']) ?></span>
                        <span class="text-[11px] text-rose-700 dark:text-rose-400">Blocked Domains</span>
                    </div>
                </div>
            </div>

            <div class="overflow-y-auto space-y-4 pr-1 my-2 grow divide-y divide-slate-100 dark:divide-slate-800">
                <div class="pt-2">
                    <div class="flex items-center justify-between mb-1.5">
                        <span class="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                            <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
                            <span>Allowed Senders (<code>-AllowedSenders</code>)</span>
                        </span>
                        <span class="text-[11px] text-slate-400 font-mono">eop_allowed_senders</span>
                    </div>
                    <?php if (!empty($pushSummary['allowedSenders'])): ?>
                    <div class="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto p-2 bg-slate-50 dark:bg-slate-800/60 rounded-lg border border-slate-200 dark:border-slate-800">
                        <?php foreach ($pushSummary['allowedSenders'] as $val): ?>
                        <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-white dark:bg-slate-900 border border-emerald-300 dark:border-emerald-800 text-emerald-800 dark:text-emerald-300">
                            <?= htmlspecialchars($val) ?>
                        </span>
                        <?php endforeach; ?>
                    </div>
                    <?php else: ?>
                    <p class="text-[11px] italic text-slate-400 pl-3">No allowed senders configured for this policy.</p>
                    <?php endif; ?>
                </div>

                <div class="pt-3">
                    <div class="flex items-center justify-between mb-1.5">
                        <span class="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                            <span class="w-2 h-2 rounded-full bg-rose-500"></span>
                            <span>Blocked Senders (<code>-BlockedSenders</code>)</span>
                        </span>
                        <span class="text-[11px] text-slate-400 font-mono">eop_blocked_senders</span>
                    </div>
                    <?php if (!empty($pushSummary['blockedSenders'])): ?>
                    <div class="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto p-2 bg-slate-50 dark:bg-slate-800/60 rounded-lg border border-slate-200 dark:border-slate-800">
                        <?php foreach ($pushSummary['blockedSenders'] as $val): ?>
                        <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-white dark:bg-slate-900 border border-rose-300 dark:border-rose-800 text-rose-800 dark:text-rose-300">
                            <?= htmlspecialchars($val) ?>
                        </span>
                        <?php endforeach; ?>
                    </div>
                    <?php else: ?>
                    <p class="text-[11px] italic text-slate-400 pl-3">No blocked senders configured for this policy.</p>
                    <?php endif; ?>
                </div>

                <div class="pt-3">
                    <div class="flex items-center justify-between mb-1.5">
                        <span class="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                            <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
                            <span>Allowed Sender Domains (<code>-AllowedSenderDomains</code>)</span>
                        </span>
                        <span class="text-[11px] text-slate-400 font-mono">eop_allowed_domains</span>
                    </div>
                    <?php if (!empty($pushSummary['allowedDomains'])): ?>
                    <div class="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto p-2 bg-slate-50 dark:bg-slate-800/60 rounded-lg border border-slate-200 dark:border-slate-800">
                        <?php foreach ($pushSummary['allowedDomains'] as $val): ?>
                        <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-white dark:bg-slate-900 border border-emerald-300 dark:border-emerald-800 text-emerald-800 dark:text-emerald-300">
                            <?= htmlspecialchars($val) ?>
                        </span>
                        <?php endforeach; ?>
                    </div>
                    <?php else: ?>
                    <p class="text-[11px] italic text-slate-400 pl-3">No allowed domains configured for this policy.</p>
                    <?php endif; ?>
                </div>

                <div class="pt-3">
                    <div class="flex items-center justify-between mb-1.5">
                        <span class="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                            <span class="w-2 h-2 rounded-full bg-rose-500"></span>
                            <span>Blocked Sender Domains (<code>-BlockedSenderDomains</code>)</span>
                        </span>
                        <span class="text-[11px] text-slate-400 font-mono">eop_blocked_domains</span>
                    </div>
                    <?php if (!empty($pushSummary['blockedDomains'])): ?>
                    <div class="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto p-2 bg-slate-50 dark:bg-slate-800/60 rounded-lg border border-slate-200 dark:border-slate-800">
                        <?php foreach ($pushSummary['blockedDomains'] as $val): ?>
                        <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-white dark:bg-slate-900 border border-rose-300 dark:border-rose-800 text-rose-800 dark:text-rose-300">
                            <?= htmlspecialchars($val) ?>
                        </span>
                        <?php endforeach; ?>
                    </div>
                    <?php else: ?>
                    <p class="text-[11px] italic text-slate-400 pl-3">No blocked domains configured for this policy.</p>
                    <?php endif; ?>
                </div>
            </div>

            <div class="pt-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between">
                <span class="text-[11px] text-slate-400 dark:text-slate-500">Action recorded in <code>eop_audit_log</code> &bull; Status: Synced</span>
                <button type="button" onclick="document.getElementById('pushSummaryModal').remove()" class="px-5 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-semibold shadow-xs transition cursor-pointer">
                    Done
                </button>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <!-- Duplicate Entry Warning Popup -->
    <?php if ($duplicatePopup): ?>
    <div id="duplicatePopupModal" class="fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
        <div class="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl max-w-md w-full p-6 border border-amber-200 dark:border-amber-800/80">
            <div class="flex items-start justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
                <div class="flex items-center space-x-3">
                    <div class="w-10 h-10 rounded-xl bg-amber-100 dark:bg-amber-950/60 text-amber-600 dark:text-amber-400 flex items-center justify-center shrink-0">
                        <i class="fa-solid fa-triangle-exclamation text-lg"></i>
                    </div>
                    <div>
                        <h3 class="text-base font-bold text-slate-900 dark:text-white">Entry Already in List</h3>
                        <span class="text-[11px] font-semibold uppercase px-2 py-0.5 rounded-full bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800/50">
                            Duplicate Rejected
                        </span>
                    </div>
                </div>
                <button type="button" onclick="document.getElementById('duplicatePopupModal').remove()" class="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 p-1 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition cursor-pointer">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>

            <div class="my-4 text-xs text-slate-600 dark:text-slate-300 space-y-3">
                <p class="leading-relaxed">
                    The entry <strong class="font-mono text-slate-900 dark:text-white px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700"><?= htmlspecialchars($duplicatePopup['value']) ?></strong> cannot be added because it already exists in policy <strong class="text-slate-900 dark:text-white font-semibold">"<?= htmlspecialchars($duplicatePopup['policy']) ?>"</strong>.
                </p>

                <div class="p-3 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/60 text-amber-900 dark:text-amber-200">
                    <div class="font-semibold text-xs mb-1">Target Table:</div>
                    <div class="text-[11px]">
                        <code>eop_<?= htmlspecialchars($duplicatePopup['listType']) ?></code>
                    </div>
                </div>

                <p class="text-[11px] text-slate-500 dark:text-slate-400 italic">
                    MariaDB enforces a unique constraint (<code>uk_policy_sender</code> / <code>uk_policy_domain</code>) on this table to prevent redundant and conflicting entries in Microsoft 365.
                </p>
            </div>

            <div class="flex items-center justify-end pt-3 border-t border-slate-100 dark:border-slate-800">
                <button type="button" onclick="document.getElementById('duplicatePopupModal').remove()" class="px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-lg text-xs font-semibold shadow-xs transition cursor-pointer">
                    Understood
                </button>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <!-- Footer -->
    <footer class="bg-white dark:bg-slate-900 border-t border-slate-200 dark:border-slate-800 py-4 mt-auto text-center text-xs text-slate-400 dark:text-slate-500 transition-colors duration-200">
        Exchange Online Protection Policy Manager &bull; Host: Debian Linux &bull; Storage: Remote MariaDB &bull; Auth: Active Directory LDAP (Port 389/636)
    </footer>

    <!-- Theme Switcher Script -->
    <script>
        function openSmartSortModal(mode) {
            const modal = document.getElementById('smartSortModal');
            if (!modal) return;
            const targetInput = document.querySelector('input[name="target_mode"][value="' + mode + '"]');
            if (targetInput) targetInput.checked = true;
            
            const titleEl = document.getElementById('smartSortModalTitle');
            const descEl = document.getElementById('smartSortModalDesc');
            const iconEl = document.getElementById('smartSortModalIcon');
            const submitBtn = document.getElementById('smartSortSubmitBtn');
            
            if (mode === 'allowed') {
                if (titleEl) titleEl.textContent = 'Smart Sort: Allowed Senders & Domains';
                if (descEl) descEl.textContent = 'Auto-routes into eop_allowed_senders and eop_allowed_domains';
                if (iconEl) {
                    iconEl.className = 'w-8 h-8 rounded-lg bg-gradient-to-br from-emerald-600 to-teal-600 text-white flex items-center justify-center text-xs';
                    iconEl.innerHTML = '<i class="fa-solid fa-shield-halved text-emerald-200"></i>';
                }
                if (submitBtn) {
                    submitBtn.className = 'px-5 py-2 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-700 hover:to-teal-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center space-x-1.5 cursor-pointer';
                    submitBtn.innerHTML = '<i class="fa-solid fa-shield-halved text-emerald-200"></i><span>Sort &amp; Import to Allowed Lists</span>';
                }
            } else {
                if (titleEl) titleEl.textContent = 'Smart Sort: Blocked Senders & Domains';
                if (descEl) descEl.textContent = 'Auto-routes into eop_blocked_senders and eop_blocked_domains';
                if (iconEl) {
                    iconEl.className = 'w-8 h-8 rounded-lg bg-gradient-to-br from-rose-600 to-red-600 text-white flex items-center justify-center text-xs';
                    iconEl.innerHTML = '<i class="fa-solid fa-ban text-rose-200"></i>';
                }
                if (submitBtn) {
                    submitBtn.className = 'px-5 py-2 bg-gradient-to-r from-rose-600 to-red-600 hover:from-rose-700 hover:to-red-700 text-white text-xs font-semibold rounded-lg shadow-sm flex items-center space-x-1.5 cursor-pointer';
                    submitBtn.innerHTML = '<i class="fa-solid fa-ban text-rose-200"></i><span>Sort &amp; Import to Blocked Lists</span>';
                }
            }
            modal.classList.remove('hidden');
        }
        function updateThemeUI() {
            const isDark = document.documentElement.classList.contains('dark');
            const icon = document.getElementById('themeIcon');
            if (icon) {
                icon.className = isDark ? 'fa-solid fa-sun text-amber-400 text-sm' : 'fa-solid fa-moon text-slate-500 text-sm';
            }
        }
        function toggleTheme() {
            const isDark = document.documentElement.classList.toggle('dark');
            localStorage.setItem('theme', isDark ? 'dark' : 'light');
            updateThemeUI();
        }
        updateThemeUI();
    </script>
</body>
</html>
