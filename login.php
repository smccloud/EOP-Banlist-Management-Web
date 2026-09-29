<?php
/**
 * Active Directory LDAP Login Page
 */

declare(strict_types=1);

// If configuration file is missing, redirect immediately to setup wizard
if (!file_exists(__DIR__ . '/config.php')) {
    header('Location: setup.php');
    exit;
}

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';
require_once __DIR__ . '/ldap.php';
require_once __DIR__ . '/functions.php';

// If database is not configured or core tables are not initialized yet, redirect to setup wizard
if (!Database::isConfigured()) {
    header('Location: setup.php');
    exit;
}
if (!Database::isInitialized()) {
    header('Location: setup.php?step=2');
    exit;
}

// Redirect if already logged in
if (!empty($_SESSION['user'])) {
    header('Location: index.php');
    exit;
}

$error = null;
$timeoutMsg = isset($_GET['msg']) && $_GET['msg'] === 'timeout';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = $_POST['csrf_token'] ?? '';
    if (!verifyCsrfToken($token)) {
        $error = 'Invalid CSRF security token. Please refresh and try again.';
    } else {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        $ldap = new LdapAuth();
        $authResult = $ldap->authenticate($username, $password);

        if ($authResult['success']) {
            // Regenerate session ID to prevent session fixation
            session_regenerate_id(true);
            $_SESSION['user'] = $authResult['user'];
            $_SESSION['LAST_ACTIVITY'] = time();

            require_once __DIR__ . '/database.php';
            $isFallback = !empty($authResult['user']['isFallbackAdmin']);
            $logMsg = $isFallback 
                ? 'Successful Emergency Fallback Local Admin login (LDAP connection failure / disaster recovery)' 
                : 'Successful AD LDAP login';
            Database::logAudit('LOGIN', 'SYSTEM', DEFAULT_POLICY_NAME, $username, $logMsg, $username);

            header('Location: index.php');
            exit;
        } else {
            $error = $authResult['error'] ?? 'Authentication failed.';
        }
    }
}

$csrfToken = getCsrfToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - <?= htmlspecialchars(APP_TITLE) ?></title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: { extend: {} }
        };
        if (localStorage.getItem('theme') === 'dark' || (!localStorage.getItem('theme') && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
            document.documentElement.classList.add('dark');
        } else {
            document.documentElement.classList.remove('dark');
        }
    </script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="bg-slate-100 dark:bg-slate-950 min-h-screen flex items-center justify-center p-4 font-sans transition-colors duration-200">
    <!-- Theme Toggle at top-right -->
    <div class="fixed top-4 right-4 z-20">
        <button type="button" onclick="toggleTheme()" 
                class="p-2.5 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm transition"
                title="Toggle Dark / Light Mode">
            <i id="loginThemeIcon" class="fa-solid fa-moon text-sm"></i>
        </button>
    </div>

    <div class="max-w-md w-full bg-white dark:bg-slate-900 rounded-2xl shadow-xl border border-slate-200 dark:border-slate-800 overflow-hidden transition-colors duration-200">
        
        <!-- Header -->
        <div class="bg-blue-600 dark:bg-blue-500 p-6 text-white text-center">
            <div class="w-12 h-12 bg-white/10 rounded-xl flex items-center justify-center mx-auto mb-3 backdrop-blur-xs text-2xl font-bold">
                <i class="fa-solid fa-shield-halved"></i>
            </div>
            <h2 class="text-xl font-bold"><?= htmlspecialchars(APP_TITLE) ?></h2>
            <p class="text-blue-100 text-xs mt-1">Active Directory LDAP Authentication (Plain LDAP / LDAPS)</p>
        </div>

        <div class="p-8">
            <?php if ($timeoutMsg): ?>
                <div class="mb-5 p-3 rounded-lg bg-amber-50 dark:bg-amber-950/40 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-800/50 text-xs flex items-center space-x-2">
                    <i class="fa-solid fa-clock"></i>
                    <span>Your session has timed out. Please sign in again.</span>
                </div>
            <?php endif; ?>

            <?php if (isset($_GET['installed']) && $_GET['installed'] === '1'): ?>
                <div class="mb-5 p-3.5 rounded-lg bg-emerald-50 dark:bg-emerald-950/40 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/50 text-xs flex items-start space-x-2">
                    <i class="fa-solid fa-circle-check text-emerald-600 dark:text-emerald-400 mt-0.5"></i>
                    <div>
                        <div class="font-bold">Setup Routine Completed &amp; Locked!</div>
                        <div>Database schema populated, LDAP &amp; EOP credentials saved. Initial setup cannot be run again.</div>
                    </div>
                </div>
            <?php elseif (!file_exists(__DIR__ . '/installed.lock')): ?>
                <div class="mb-5 p-3.5 rounded-lg bg-amber-50 dark:bg-amber-950/40 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-800/50 text-xs flex items-start justify-between">
                    <div class="flex items-start space-x-2">
                        <i class="fa-solid fa-sparkles text-amber-600 dark:text-amber-400 mt-0.5"></i>
                        <div>
                            <div class="font-bold">First Time Setup?</div>
                            <div class="text-[11px]">Run initial setup wizard to configure Database, LDAP, and EOP.</div>
                        </div>
                    </div>
                    <a href="setup.php" class="px-2.5 py-1 bg-amber-600 hover:bg-amber-700 text-white rounded text-[11px] font-semibold transition shrink-0 ml-2">
                        Run Setup &rarr;
                    </a>
                </div>
            <?php endif; ?>

            <?php if ($error): ?>
                <div class="mb-5 p-3.5 rounded-lg bg-rose-50 dark:bg-rose-950/40 text-rose-800 dark:text-rose-300 border border-rose-200 dark:border-rose-800/50 text-xs flex items-start space-x-2">
                    <i class="fa-solid fa-triangle-exclamation text-rose-600 dark:text-rose-400 mt-0.5"></i>
                    <div><?= htmlspecialchars($error) ?></div>
                </div>
            <?php endif; ?>

            <form method="POST" action="login.php" class="space-y-4">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">

                <div>
                    <label class="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">Active Directory Username</label>
                    <div class="relative">
                        <i class="fa-solid fa-user absolute left-3 top-3 text-slate-400 dark:text-slate-500 text-sm"></i>
                        <input type="text" name="username" required autocomplete="username" autofocus
                               placeholder="sAMAccountName or user@corp.example.com"
                               class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white text-sm rounded-lg pl-9 pr-3 py-2.5 focus:ring-2 focus:ring-blue-500 focus:outline-hidden">
                    </div>
                    <p class="text-[11px] text-slate-400 dark:text-slate-500 mt-1">Domain: <?= htmlspecialchars(LDAP_NETBIOS_DOMAIN) ?></p>
                </div>

                <div>
                    <label class="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">Password</label>
                    <div class="relative">
                        <i class="fa-solid fa-lock absolute left-3 top-3 text-slate-400 dark:text-slate-500 text-sm"></i>
                        <input type="password" name="password" required autocomplete="current-password"
                               placeholder="Domain password"
                               class="w-full bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white text-sm rounded-lg pl-9 pr-3 py-2.5 focus:ring-2 focus:ring-blue-500 focus:outline-hidden">
                    </div>
                </div>

                <div class="p-3 bg-slate-50 dark:bg-slate-800/70 rounded-lg border border-slate-200 dark:border-slate-700 text-[11px] text-slate-500 dark:text-slate-400">
                    <div class="font-semibold text-slate-700 dark:text-slate-200 mb-0.5 flex items-center justify-between">
                        <span><i class="fa-solid fa-id-badge text-blue-600 dark:text-blue-400 mr-1"></i> Access Restricted</span>
                        <span class="text-[10px] px-1.5 py-0.2 rounded bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300">LDAP Port <?= (int)LDAP_PORT ?></span>
                    </div>
                    Must be a member of Group DN:<br>
                    <code class="text-[10px] text-blue-600 dark:text-blue-400 break-all font-mono"><?= htmlspecialchars(LDAP_AUTHORIZED_GROUP_DN) ?></code>
                </div>

                <?php if (defined('FALLBACK_ADMIN_ENABLED') && FALLBACK_ADMIN_ENABLED): ?>
                <div class="p-2.5 bg-amber-50 dark:bg-amber-950/30 rounded-lg border border-amber-200 dark:border-amber-900/40 text-[11px] text-amber-800 dark:text-amber-300 flex items-start space-x-2">
                    <i class="fa-solid fa-shield-halved text-amber-600 dark:text-amber-400 mt-0.5"></i>
                    <div>
                        <span class="font-semibold">LDAP Offline Fallback:</span> If your Active Directory DC is unreachable, use your emergency fallback administrator credentials.
                    </div>
                </div>
                <?php endif; ?>

                <button type="submit" class="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-lg shadow-sm transition flex items-center justify-center space-x-2">
                    <i class="fa-solid fa-right-to-bracket"></i>
                    <span>Authenticate via AD</span>
                </button>
            </form>
        </div>
    </div>

    <script>
        function updateThemeUI() {
            const isDark = document.documentElement.classList.contains('dark');
            const icon = document.getElementById('loginThemeIcon');
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
