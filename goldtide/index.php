<?php
/**
 * GOLD TIDE: free-to-play social casino. Gold Coins only.
 *
 * One file. Drop it on any PHP 8.1+ host with pdo_sqlite, or run:
 *     php -S localhost:8000 index.php
 * First request builds ./data/app.sqlite and writes ./admin_password.txt.
 *
 * Gold Coins have no cash value. They can't be bought, sold, redeemed,
 * transferred, or exchanged for anything. There is no store and no prize path.
 * Keep it that way: adding either turns this into a regulated product.
 */
declare(strict_types=1);

const APP_VERSION    = '1.0.0';
const SCHEMA_VERSION = 7;
define('DATA_DIR', __DIR__ . '/data');
define('DB_FILE',  DATA_DIR . '/app.sqlite');
define('PW_FILE',  __DIR__ . '/admin_password.txt');
define('LOG_FILE', DATA_DIR . '/error.log');

// php -S router mode: let the built-in server hand out real files that exist next to us
if (PHP_SAPI === 'cli-server') {
    $p = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
    if ($p !== '/' && $p !== '/index.php' && is_file(__DIR__ . $p) && !str_starts_with($p, '/data')
        && basename($p) !== 'admin_password.txt') {
        return false;
    }
}

ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);
if (!is_dir(DATA_DIR)) { @mkdir(DATA_DIR, 0750, true); }
if (!is_file(DATA_DIR . '/.htaccess')) { @file_put_contents(DATA_DIR . '/.htaccess', "Require all denied\nDeny from all\n"); }
// on apache, keep the first-run password file and any stray db files from being downloadable
if (!is_file(__DIR__ . '/.htaccess')) {
    @file_put_contents(__DIR__ . '/.htaccess', "<FilesMatch \"(admin_password\\.txt|\\.sqlite.*|\\.log)$\">\n  Require all denied\n</FilesMatch>\nOptions -Indexes\n");
}
ini_set('error_log', LOG_FILE);

set_exception_handler(function (Throwable $e) {
    // DomainException = a rule the player bumped into (not enough coins, etc), not a bug
    if ($e instanceof DomainException) { fail($e->getMessage()); }
    error_log('[' . date('c') . '] ' . $e::class . ': ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
    if (wants_json()) { json_out(['ok' => false, 'data' => null, 'error' => 'Server error. Try again.'], 500); }
    error_page(500, 'Something broke on our side', 'The error was logged. Give it another shot in a moment.');
});

/* ───────────────────────── request / security basics ───────────────────────── */

function is_https(): bool {
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https')
        || (($_SERVER['SERVER_PORT'] ?? '') === '443');
}

/* Cloudflare's edge ranges, from https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6 (published list,
 * unchanged for years; Cloudflare announces edits). Used only when the trusted_proxies setting says "cloudflare". */
const CF_RANGES = ['173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
    '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14',
    '172.64.0.0/13', '131.0.72.0/22', '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
    '2a06:98c0::/29', '2c0f:f248::/32'];

/** Is $ip inside $cidr ("10.0.0.0/8", "2a06:98c0::/29", or a bare address)? IPv4 or IPv6, never across families. */
function ip_in_cidr(string $ip, string $cidr): bool {
    [$net, $bits] = array_pad(explode('/', trim($cidr), 2), 2, null);
    $a = @inet_pton($ip); $n = @inet_pton((string)$net);
    if ($a === false || $n === false || strlen($a) !== strlen($n)) { return false; }
    $len = strlen($a) * 8;
    $bits = $bits === null ? $len : (ctype_digit($bits) ? (int)$bits : -1);
    if ($bits < 0 || $bits > $len) { return false; }
    $full = intdiv($bits, 8); $rem = $bits % 8;
    if (substr($a, 0, $full) !== substr($n, 0, $full)) { return false; }
    return $rem === 0 || ((ord($a[$full]) ^ ord($n[$full])) & ((0xFF << (8 - $rem)) & 0xFF)) === 0;
}

/** Is this TCP peer a proxy allowed to tell us the visitor's IP? Loopback always is (a cloudflared tunnel on this box);
 *  beyond that, only what the trusted_proxies setting lists (IPs / CIDRs, or the word "cloudflare" for CF_RANGES). */
function trusted_proxy(string $remote): bool {
    if (preg_match('/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i', $remote, $m)) { $remote = $m[1]; }   // IPv4-mapped IPv6 peer
    if (ip_in_cidr($remote, '127.0.0.0/8') || $remote === '::1') { return true; }
    try { $list = setting('trusted_proxies'); } catch (Throwable) { $list = ''; }
    foreach (array_filter(array_map('trim', explode(',', strtolower($list)))) as $t) {
        if ($t === 'cloudflare') { foreach (CF_RANGES as $r) { if (ip_in_cidr($remote, $r)) { return true; } } }
        elseif (ip_in_cidr($remote, $t)) { return true; }
    }
    return false;
}

function client_ip(): string {
    // CF-Connecting-IP is a header anyone can type, so it only counts when the connection itself comes from a proxy we
    // trust (see trusted_proxy()). Everything else is the TCP peer, which no client can forge: the login lockout, signup
    // throttle and audit log all key on this.
    $remote = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $cf = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? '';
    if ($cf !== '' && filter_var($cf, FILTER_VALIDATE_IP) && trusted_proxy($remote)) { return $cf; }
    return $remote;
}

function csp_nonce(): string {
    static $n = null;
    return $n ??= base64_encode(random_bytes(16));
}

function send_security_headers(): void {
    if (headers_sent()) { return; }
    $n = csp_nonce();
    $ws = rt_ws_csp();
    header("Content-Security-Policy: default-src 'self'; script-src 'nonce-$n' 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' $ws; worker-src 'self' blob:; frame-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'self'; object-src 'none'");
    header('X-Frame-Options: SAMEORIGIN');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: strict-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()');
    if (is_https()) { header('Strict-Transport-Security: max-age=31536000; includeSubDomains'); }
}

function start_session(): void {
    if (session_status() === PHP_SESSION_ACTIVE) { return; }
    session_name('gt_sess');
    session_set_cookie_params([
        'lifetime' => 0, 'path' => '/', 'secure' => is_https(),
        'httponly' => true, 'samesite' => 'Strict',
    ]);
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_start();
}

function h(mixed $v): string { return htmlspecialchars((string)($v ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function now(): string { return gmdate('Y-m-d H:i:s'); }
function coins(int|float $n): string { return number_format((int)$n); }
function method(): string { return strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET'); }
function url(string $action = '', array $q = []): string {
    if ($action !== '') { $q = ['action' => $action] + $q; }
    return '?' . http_build_query($q);
}
function redirect(string $to): never { header('Location: ' . $to, true, 303); exit; }

function wants_json(): bool {
    return (($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') === 'fetch')
        || str_contains($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json');
}

function json_out(array $payload, int $code = 200): never {
    if (!headers_sent()) {
        http_response_code($code);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
    }
    echo json_encode($payload, JSON_UNESCAPED_SLASHES);
    exit;
}
function ok(mixed $data = null): never { json_out(['ok' => true, 'data' => $data, 'error' => null]); }
function fail(string $msg, int $code = 400): never {
    if (wants_json()) { json_out(['ok' => false, 'data' => null, 'error' => $msg], $code); }
    flash('err', $msg);
    redirect($_SERVER['HTTP_REFERER'] ?? url());
}

function csrf_token(): string {
    if (empty($_SESSION['csrf'])) { $_SESSION['csrf'] = bin2hex(random_bytes(32)); }
    return $_SESSION['csrf'];
}
function csrf_field(): string { return '<input type="hidden" name="csrf" value="' . h(csrf_token()) . '">'; }
function csrf_check(): void {
    $sent = $_POST['csrf'] ?? ($_SERVER['HTTP_X_CSRF'] ?? '');
    if (!is_string($sent) || $sent === '' || !hash_equals(csrf_token(), $sent)) {
        fail('Your session expired. Refresh the page and try again.', 419);
    }
}

function flash(string $type, string $msg): void { $_SESSION['flash'][] = [$type, $msg]; }
function take_flashes(): array { $f = $_SESSION['flash'] ?? []; unset($_SESSION['flash']); return $f; }

/* ───────────────────────── database + installer ───────────────────────── */

function db(): PDO {
    static $pdo = null;
    if ($pdo) { return $pdo; }
    $fresh = !is_file(DB_FILE);
    $pdo = new PDO('sqlite:' . DB_FILE, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    $pdo->exec('PRAGMA journal_mode = WAL');
    $pdo->exec('PRAGMA foreign_keys = ON');
    $pdo->exec('PRAGMA busy_timeout = 5000');
    install($pdo, $fresh);
    return $pdo;
}

function q(string $sql, array $params = []): PDOStatement {
    $st = db()->prepare($sql);
    $st->execute($params);
    return $st;
}
function row(string $sql, array $p = []): ?array { $r = q($sql, $p)->fetch(); return $r ?: null; }
function val(string $sql, array $p = []): mixed { $v = q($sql, $p)->fetchColumn(); return $v === false ? null : $v; }

/** Run $fn inside BEGIN IMMEDIATE so balance checks and writes can't interleave. */
function tx(callable $fn): mixed {
    $pdo = db();
    $pdo->exec('BEGIN IMMEDIATE');
    try { $r = $fn(); $pdo->exec('COMMIT'); return $r; }
    catch (Throwable $e) { $pdo->exec('ROLLBACK'); throw $e; }
}

function install(PDO $pdo, bool $fresh): void {
    $have = 0;
    try { $have = (int)$pdo->query("SELECT value FROM meta WHERE key='schema_version'")->fetchColumn(); } catch (Throwable) {}
    if ($have >= SCHEMA_VERSION) { return; }

    $ts = "created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now'))";
    $pdo->exec("
    CREATE TABLE IF NOT EXISTS meta (id INTEGER PRIMARY KEY, key TEXT NOT NULL UNIQUE, value TEXT, $ts);
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, pass_hash TEXT NOT NULL, last_login_at TEXT, $ts);
    CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY, key TEXT NOT NULL UNIQUE, value TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '', $ts);
    CREATE TABLE IF NOT EXISTS players (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE CHECK (length(username) BETWEEN 3 AND 24),
        email TEXT COLLATE NOCASE,
        pass_hash TEXT NOT NULL,
        balance INTEGER NOT NULL DEFAULT 0 CHECK (balance >= 0),
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
        break_until TEXT,
        daily_streak INTEGER NOT NULL DEFAULT 0 CHECK (daily_streak >= 0),
        last_daily_at TEXT,
        last_refill_at TEXT,
        rounds_played INTEGER NOT NULL DEFAULT 0,
        total_wagered INTEGER NOT NULL DEFAULT 0,
        total_won INTEGER NOT NULL DEFAULT 0,
        biggest_win INTEGER NOT NULL DEFAULT 0,
        last_login_at TEXT,
        $ts);
    CREATE INDEX IF NOT EXISTS ix_players_balance ON players(balance DESC);
    CREATE INDEX IF NOT EXISTS ix_players_bigwin ON players(biggest_win DESC);
    CREATE TABLE IF NOT EXISTS games (
        id INTEGER PRIMARY KEY, slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL, blurb TEXT NOT NULL DEFAULT '',
        enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
        min_bet INTEGER NOT NULL DEFAULT 10 CHECK (min_bet > 0),
        max_bet INTEGER NOT NULL DEFAULT 5000 CHECK (max_bet >= min_bet),
        sort_order INTEGER NOT NULL DEFAULT 0, $ts);
    CREATE TABLE IF NOT EXISTS ledger (
        id INTEGER PRIMARY KEY,
        player_id INTEGER NOT NULL REFERENCES players(id) ON DELETE CASCADE,
        kind TEXT NOT NULL CHECK (kind IN ('signup','wager','payout','daily','refill','promo','admin')),
        game TEXT, amount INTEGER NOT NULL, balance_after INTEGER NOT NULL, detail TEXT NOT NULL DEFAULT '', $ts);
    CREATE INDEX IF NOT EXISTS ix_ledger_player ON ledger(player_id, id DESC);
    CREATE TABLE IF NOT EXISTS bj_hands (
        id INTEGER PRIMARY KEY,
        player_id INTEGER NOT NULL REFERENCES players(id) ON DELETE CASCADE,
        bet INTEGER NOT NULL CHECK (bet > 0),
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','done','void')),
        outcome TEXT, payout INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT '{}', $ts);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_bj_one_active ON bj_hands(player_id) WHERE status = 'active';
    CREATE TABLE IF NOT EXISTS rounds (
        id INTEGER PRIMARY KEY,
        player_id INTEGER NOT NULL REFERENCES players(id) ON DELETE CASCADE,
        game TEXT NOT NULL,
        bet INTEGER NOT NULL CHECK (bet > 0),
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','done','void')),
        outcome TEXT, payout INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT '{}', $ts);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_rounds_one_active ON rounds(player_id, game) WHERE status = 'active';
    CREATE INDEX IF NOT EXISTS ix_rounds_player_game ON rounds(player_id, game, id DESC);
    CREATE TABLE IF NOT EXISTS fair_seeds (
        id INTEGER PRIMARY KEY,
        player_id INTEGER NOT NULL REFERENCES players(id) ON DELETE CASCADE,
        game TEXT NOT NULL,
        server_seed TEXT NOT NULL, server_hash TEXT NOT NULL, client_seed TEXT NOT NULL,
        nonce INTEGER NOT NULL DEFAULT 0 CHECK (nonce >= 0),
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revealed')),
        revealed_at TEXT, $ts);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_fair_one_active ON fair_seeds(player_id, game) WHERE status = 'active';
    CREATE TABLE IF NOT EXISTS promo_codes (
        id INTEGER PRIMARY KEY, code TEXT NOT NULL UNIQUE COLLATE NOCASE CHECK (length(code) BETWEEN 3 AND 32),
        coins INTEGER NOT NULL CHECK (coins > 0), max_uses INTEGER NOT NULL DEFAULT 0 CHECK (max_uses >= 0),
        uses INTEGER NOT NULL DEFAULT 0, expires_at TEXT, active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
        note TEXT NOT NULL DEFAULT '', $ts);
    CREATE TABLE IF NOT EXISTS promo_redemptions (
        id INTEGER PRIMARY KEY,
        promo_id INTEGER NOT NULL REFERENCES promo_codes(id) ON DELETE CASCADE,
        player_id INTEGER NOT NULL REFERENCES players(id) ON DELETE CASCADE,
        coins INTEGER NOT NULL, $ts, UNIQUE (promo_id, player_id));
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, tbl TEXT NOT NULL DEFAULT '',
        row_id INTEGER, before_json TEXT, after_json TEXT, ip TEXT NOT NULL DEFAULT '', $ts);
    CREATE INDEX IF NOT EXISTS ix_audit_time ON audit_log(id DESC);
    CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY, attempt_key TEXT NOT NULL, $ts);
    CREATE INDEX IF NOT EXISTS ix_attempts ON login_attempts(attempt_key, created_at);
    CREATE TABLE IF NOT EXISTS poker_tables (
        id INTEGER PRIMARY KEY, name TEXT NOT NULL CHECK (length(name) BETWEEN 2 AND 40),
        seats INTEGER NOT NULL DEFAULT 6 CHECK (seats BETWEEN 2 AND 9),
        small_blind INTEGER NOT NULL CHECK (small_blind > 0), big_blind INTEGER NOT NULL CHECK (big_blind >= small_blind),
        min_buyin INTEGER NOT NULL CHECK (min_buyin > 0), max_buyin INTEGER NOT NULL CHECK (max_buyin >= min_buyin),
        bots INTEGER NOT NULL DEFAULT 0 CHECK (bots BETWEEN 0 AND 8),
        enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)), sort_order INTEGER NOT NULL DEFAULT 0, $ts);
    CREATE TABLE IF NOT EXISTS poker_seats (
        id INTEGER PRIMARY KEY,
        table_id INTEGER NOT NULL REFERENCES poker_tables(id) ON DELETE CASCADE,
        player_id INTEGER NOT NULL UNIQUE REFERENCES players(id) ON DELETE CASCADE,
        seat INTEGER NOT NULL CHECK (seat BETWEEN 0 AND 8),
        stack INTEGER NOT NULL CHECK (stack >= 0), $ts, UNIQUE (table_id, seat));
    CREATE TABLE IF NOT EXISTS poker_hands (
        id INTEGER PRIMARY KEY,
        table_id INTEGER NOT NULL REFERENCES poker_tables(id) ON DELETE CASCADE,
        hand_no INTEGER NOT NULL, deck_hash TEXT NOT NULL, deck_salt TEXT NOT NULL DEFAULT '',
        board TEXT NOT NULL DEFAULT '', pot INTEGER NOT NULL DEFAULT 0,
        record TEXT NOT NULL DEFAULT '{}', started_at TEXT NOT NULL, ended_at TEXT, $ts);
    CREATE INDEX IF NOT EXISTS ix_poker_hands_table ON poker_hands(table_id, id DESC);
    ");

    // audit log is append-only at the database level too
    $pdo->exec("CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;");
    $pdo->exec("CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;");

    $seed = $pdo->prepare('INSERT OR IGNORE INTO settings (key, value, note) VALUES (?, ?, ?)');
    foreach ([
        ['site_name', 'Gold Tide', 'Brand name in the header and title bar'],
        ['tagline', 'Sun, surf & free-to-play Gold Coins', 'Shown under the brand on the lobby'],
        ['partner_name', '', 'Optional partner casino shown as "Presented with ___"'],
        ['announcement', '', 'Optional banner across the top of every public page'],
        ['starting_coins', '10000', 'Gold Coins every new player starts with'],
        ['daily_base', '1000', 'Daily bonus on day 1 of a streak'],
        ['daily_step', '250', 'Extra coins per consecutive day'],
        ['daily_max_streak', '7', 'Streak stops growing after this many days'],
        ['refill_amount', '2500', 'Coins given by the "running low" refill'],
        ['refill_below', '500', 'Refill unlocks when balance plus chips on the table is below this'],
        ['refill_hours', '4', 'Hours between refills'],
        ['min_age', '21', 'Age players must confirm at signup'],
        ['registration_open', '1', '1 = new signups allowed, 0 = closed'],
        ['trusted_proxies', '', 'Proxies allowed to set the visitor IP via CF-Connecting-IP: comma list of IPs/CIDRs, or "cloudflare" for Cloudflare\'s edge. Loopback (cloudflared tunnel) is always trusted. Blank = trust only loopback'],
        ['ws_url', '', 'WebSocket URL for the floor and poker (e.g. wss://casino.example.com/ws). Blank = auto: same host on port 8081 in dev, wss://host/ws behind a proxy'],
        ['rt_origins', '', 'Comma-separated origins allowed to open a WebSocket (e.g. https://casino.example.com). Blank = derive from the Host header'],
        ['floor_enabled', '1', '1 = the 3D casino floor is open, 0 = hidden'],
        ['poker_action_seconds', '20', 'Seconds a poker player has to act before the clock folds them'],
    ] as $s) { $seed->execute($s); }
    // realtime secret: signs the tickets the WebSocket server checks. Never leaves the server.
    $pdo->prepare("INSERT OR IGNORE INTO meta (key, value) VALUES ('rt_secret', ?)")->execute([bin2hex(random_bytes(32))]);
    if (!(int)$pdo->query('SELECT COUNT(*) FROM poker_tables')->fetchColumn()) {
        $pt = $pdo->prepare('INSERT INTO poker_tables (name, seats, small_blind, big_blind, min_buyin, max_buyin, bots, sort_order) VALUES (?,?,?,?,?,?,?,?)');
        foreach ([
            ['Bayside 10/20', 6, 10, 20, 800, 4000, 3, 1],
            ['Harbor 50/100', 9, 50, 100, 4000, 20000, 4, 2],
            ['Coronado 250/500', 6, 250, 500, 20000, 100000, 2, 3],
        ] as $row) { $pt->execute($row); }
    }

    $g = $pdo->prepare('INSERT OR IGNORE INTO games (slug, name, blurb, min_bet, max_bet, sort_order) VALUES (?,?,?,?,?,?)');
    foreach (GAME_REGISTRY as $slug => [$name, , $blurb, $sort]) { $g->execute([$slug, $name, $blurb, 10, 5000, $sort]); }
    // v3: plinko became Pearl Drop. Only rename if staff never customized it.
    $pdn = GAME_REGISTRY['plinko'];
    $pdo->prepare("UPDATE games SET name = ?, blurb = ?, sort_order = ?, updated_at = datetime('now') WHERE slug = 'plinko' AND name = 'Pier Plinko'")->execute([$pdn[0], $pdn[2], $pdn[3]]);

    if (!(int)$pdo->query('SELECT COUNT(*) FROM admins')->fetchColumn()) {
        $pw = substr(strtr(base64_encode(random_bytes(24)), '+/=', 'xyz'), 0, 24);
        $pdo->prepare('INSERT INTO admins (username, pass_hash) VALUES (?, ?)')
            ->execute(['admin', password_hash($pw, PASSWORD_BCRYPT, ['cost' => 12])]);
        write_pw_file('admin', $pw);
    }

    $pdo->prepare("INSERT INTO meta (key, value) VALUES ('schema_version', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')")
        ->execute([(string)SCHEMA_VERSION]);
    $pdo->prepare("INSERT OR IGNORE INTO meta (key, value) VALUES ('installed_at', ?)")->execute([now()]);
}

function write_pw_file(string $user, string $pw): void {
    $body = "==========================================================\n"
          . "  GOLD TIDE admin login. SAVE THIS, THEN DELETE THIS FILE.\n"
          . "==========================================================\n"
          . "  url:      ?action=admin\n  username: $user\n  password: $pw\n\n"
          . "  Change it from the dashboard under Password.\n"
          . "  Changing it there wipes this file automatically.\n";
    @file_put_contents(PW_FILE, $body, LOCK_EX);
    @chmod(PW_FILE, 0600);
}

/* ───────────────────────── settings ───────────────────────── */

function setting(string $key, string $default = ''): string {
    static $cache = null;
    if ($cache === null) { $cache = []; foreach (q('SELECT key, value FROM settings')->fetchAll() as $r) { $cache[$r['key']] = $r['value']; } }
    return $cache[$key] ?? $default;
}
function isetting(string $key, int $default = 0): int { return (int)setting($key, (string)$default); }

/* ───────────────────────── rate limiting ───────────────────────── */

const MAX_ATTEMPTS = 5;
const ATTEMPT_WINDOW_MIN = 15;

function attempts_left(string $key): int {
    q("DELETE FROM login_attempts WHERE created_at < datetime('now', ?)", ['-' . ATTEMPT_WINDOW_MIN . ' minutes']);
    $n = (int)val("SELECT COUNT(*) FROM login_attempts WHERE attempt_key = ? AND created_at >= datetime('now', ?)",
        [$key, '-' . ATTEMPT_WINDOW_MIN . ' minutes']);
    return max(0, MAX_ATTEMPTS - $n);
}
function note_failed_attempt(string $key): void { q('INSERT INTO login_attempts (attempt_key) VALUES (?)', [$key]); }
function clear_attempts(string $key): void { q('DELETE FROM login_attempts WHERE attempt_key = ?', [$key]); }

/* ───────────────────────── realtime: tickets + socket discovery (see REALTIME.md) ───────────────────────── */

/** Signs WebSocket tickets. Lives in `meta`, generated at install, never sent to a browser. */
function rt_secret(): string {
    static $s = null;
    return $s ??= (string)(val("SELECT value FROM meta WHERE key = 'rt_secret'") ?? '');
}
function rt_host(): string {
    $h = strtolower((string)($_SERVER['HTTP_HOST'] ?? 'localhost'));
    return preg_match('/^[a-z0-9.\-\[\]:]{1,253}$/', $h) ? $h : 'localhost';
}
/** Where the browser should open its socket. Setting wins; dev on a non-standard port gets :8081; a proxied site gets /ws. */
function rt_ws_url(): string {
    $set = trim(setting('ws_url'));
    if ($set !== '' && preg_match('#^wss?://#i', $set)) { return $set; }
    $host = rt_host();
    $name = preg_replace('/:\d+$/', '', $host);
    $port = (string)($_SERVER['SERVER_PORT'] ?? '');
    $std = $port === '' || $port === '80' || $port === '443';
    if (!$std && !is_https()) { return 'ws://' . $name . ':8081/'; }
    return (is_https() ? 'wss://' : 'ws://') . $host . '/ws';
}
/** The socket origin(s) for the CSP connect-src. */
function rt_ws_csp(): string {
    try { $u = rt_ws_url(); } catch (Throwable) { return ''; }
    $p = parse_url($u);
    if (!$p || empty($p['host'])) { return ''; }
    $o = ($p['scheme'] ?? 'ws') . '://' . $p['host'] . (isset($p['port']) ? ':' . $p['port'] : '');
    return $o;
}
function rt_b64(string $bin): string { return rtrim(strtr(base64_encode($bin), '+/', '-_'), '='); }
function rt_unb64(string $s): string|false { return base64_decode(strtr($s, '-_', '+/'), true); }
/** ticket = base64url(json payload) . '.' . hex(hmac). 60 s to use it, once. */
function rt_ticket_make(array $payload): string {
    $payload += ['exp' => time() + 60, 'nonce' => bin2hex(random_bytes(8))];
    $body = rt_b64(json_encode($payload, JSON_UNESCAPED_SLASHES));
    return $body . '.' . hash_hmac('sha256', $body, rt_secret());
}
/** Returns the payload or null. Callers must also reject reused nonces. */
function rt_ticket_verify(string $ticket, ?int $now = null): ?array {
    if (rt_secret() === '' || strlen($ticket) > 1024 || substr_count($ticket, '.') !== 1) { return null; }
    [$body, $sig] = explode('.', $ticket, 2);
    if (!preg_match('/^[0-9a-f]{64}$/', $sig) || !hash_equals(hash_hmac('sha256', $body, rt_secret()), $sig)) { return null; }
    $raw = rt_unb64($body);
    $p = $raw !== false ? json_decode($raw, true) : null;
    if (!is_array($p) || empty($p['uid']) || !isset($p['exp'], $p['nonce'], $p['name'])) { return null; }
    if ((int)$p['exp'] < ($now ?? time())) { return null; }
    return $p;
}
/** POST ?action=rt_ticket → {ticket, ws, uid, name, guest}. Guests can walk and chat, not sit. */
function do_rt_ticket(): never {
    csrf_check();
    $p = current_player();
    if ($p) {
        $payload = ['uid' => 'p' . (int)$p['id'], 'pid' => (int)$p['id'], 'name' => $p['username'], 'brk' => on_break($p) !== null];
    } else {
        $_SESSION['guest'] ??= bin2hex(random_bytes(4));
        $payload = ['uid' => 'g' . $_SESSION['guest'], 'pid' => 0, 'name' => 'Guest ' . substr($_SESSION['guest'], 0, 4)];
    }
    ok(['ticket' => rt_ticket_make($payload), 'ws' => rt_ws_url(), 'uid' => $payload['uid'], 'name' => $payload['name'], 'guest' => !$p]);
}

/* ───────────────────────── audit ───────────────────────── */

function audit(string $actor, string $action, string $tbl = '', ?int $rowId = null, ?array $before = null, ?array $after = null): void {
    foreach (['pass_hash'] as $secret) {
        if ($before && isset($before[$secret])) { $before[$secret] = '•••'; }
        if ($after && isset($after[$secret])) { $after[$secret] = '•••'; }
    }
    q('INSERT INTO audit_log (actor, action, tbl, row_id, before_json, after_json, ip) VALUES (?,?,?,?,?,?,?)', [
        $actor, $action, $tbl, $rowId,
        $before ? json_encode($before, JSON_UNESCAPED_UNICODE) : null,
        $after ? json_encode($after, JSON_UNESCAPED_UNICODE) : null,
        client_ip(),
    ]);
}

/* ───────────────────────── players ───────────────────────── */

function current_player(): ?array {
    static $p = false;
    if ($p !== false) { return $p; }
    $id = (int)($_SESSION['pid'] ?? 0);
    $p = $id ? row('SELECT * FROM players WHERE id = ?', [$id]) : null;
    if ($p && $p['status'] !== 'active') { unset($_SESSION['pid']); $p = null; }
    return $p;
}

function require_player(): array {
    $p = current_player();
    if (!$p) {
        if (wants_json()) { json_out(['ok' => false, 'data' => null, 'error' => 'Log in to play.'], 401); }
        flash('info', 'Log in or grab a free account to play.');
        redirect(url('login'));
    }
    return $p;
}

/** Players on a self-imposed break can browse but not play or collect coins. */
function on_break(array $p): ?string {
    if ($p['break_until'] && $p['break_until'] > now()) { return $p['break_until']; }
    return null;
}
function require_playable(): array {
    $p = require_player();
    if ($until = on_break($p)) { fail('You\'re taking a break until ' . $until . ' UTC. See you then.', 403); }
    return $p;
}

/**
 * The only way coins move. Must be called inside tx().
 * Negative $delta that would overdraw throws, so no game can take coins you don't have.
 */
function move_coins(int $pid, int $delta, string $kind, ?string $game = null, string $detail = ''): int {
    $bal = (int)val('SELECT balance FROM players WHERE id = ?', [$pid]);
    $new = $bal + $delta;
    if ($new < 0) { throw new DomainException('Not enough Gold Coins for that.'); }
    q("UPDATE players SET balance = ?, updated_at = datetime('now') WHERE id = ?", [$new, $pid]);
    q('INSERT INTO ledger (player_id, kind, game, amount, balance_after, detail) VALUES (?,?,?,?,?,?)',
        [$pid, $kind, $game, $delta, $new, $detail]);
    return $new;
}

function record_round(int $pid, int $wagered, int $won): void {
    q("UPDATE players SET rounds_played = rounds_played + 1, total_wagered = total_wagered + ?,
        total_won = total_won + ?, biggest_win = MAX(biggest_win, ?), updated_at = datetime('now') WHERE id = ?",
        [$wagered, $won, max(0, $won - $wagered), $pid]);
}

function game_cfg(string $slug): array {
    $g = row('SELECT * FROM games WHERE slug = ?', [$slug]);
    if (!$g || !(int)$g['enabled']) { fail('That game is closed right now.', 403); }
    return $g;
}

function clamp_bet(mixed $raw, array $g): int {
    if (!is_numeric($raw) || (int)$raw != $raw) { fail('Bet must be a whole number of coins.'); }
    $b = (int)$raw;
    if ($b < (int)$g['min_bet'] || $b > (int)$g['max_bet']) {
        fail('Bets on this table run ' . coins((int)$g['min_bet']) . '–' . coins((int)$g['max_bet']) . ' GC.');
    }
    return $b;
}

/* ═════════════════════════ GAMES ═════════════════════════
 * Every outcome is decided here, server-side, with random_int (CSPRNG).
 * The browser only animates what the server already decided, so nobody can
 * pump the leaderboard by editing JavaScript.
 */

/* ── Sunset Reels ──
 * 29-stop strip, same on all three reels. Per-line RTP with this strip + paytable:
 *   sum(p(s)^3 * pay3(s)) + p(cherry)^2 * (1 - p(cherry)) * 5  ≈ 95.0%
 * Line hit rate ≈ 7.6%, so about a third of 5-line spins pay something.
 */
const SLOT_STRIP = ['cherry','lemon','shell','cherry','palm','lemon','bell','cherry','shell','lemon','bar','cherry',
    'palm','seven','lemon','cherry','shell','bell','lemon','palm','cherry','sun','shell','lemon','bar','cherry','palm','shell','bell'];
const SLOT_PAY3 = ['cherry' => 10, 'lemon' => 15, 'shell' => 24, 'palm' => 40, 'bell' => 80, 'bar' => 250, 'sun' => 400, 'seven' => 1000];
const SLOT_CHERRY2 = 5;
// row index (0 top, 1 middle, 2 bottom) on reels 1..3
const SLOT_LINES = [[1, 1, 1], [0, 0, 0], [2, 2, 2], [0, 1, 2], [2, 1, 0]];

function slots_spin(): array {
    $p = require_playable();
    $g = game_cfg('slots');
    $bet = clamp_bet($_POST['bet'] ?? '', $g);
    if ($bet % count(SLOT_LINES) !== 0) { fail('Slot bets go in steps of ' . count(SLOT_LINES) . ' (one per payline).'); }
    $lineBet = intdiv($bet, count(SLOT_LINES));

    $n = count(SLOT_STRIP);
    $grid = [];
    for ($r = 0; $r < 3; $r++) {
        $stop = random_int(0, $n - 1);
        $grid[$r] = [SLOT_STRIP[$stop], SLOT_STRIP[($stop + 1) % $n], SLOT_STRIP[($stop + 2) % $n]];
    }

    $wins = []; $payout = 0;
    foreach (SLOT_LINES as $i => $rows) {
        $s = [$grid[0][$rows[0]], $grid[1][$rows[1]], $grid[2][$rows[2]]];
        $mult = 0; $count = 0;
        if ($s[0] === $s[1] && $s[1] === $s[2]) { $mult = SLOT_PAY3[$s[0]]; $count = 3; }
        elseif ($s[0] === 'cherry' && $s[1] === 'cherry') { $mult = SLOT_CHERRY2; $count = 2; }
        if ($mult) {
            $win = $lineBet * $mult;
            $payout += $win;
            $wins[] = ['line' => $i, 'symbol' => $s[0], 'count' => $count, 'mult' => $mult, 'win' => $win];
        }
    }

    $balance = tx(function () use ($p, $bet, $payout, $grid) {
        $b = move_coins((int)$p['id'], -$bet, 'wager', 'slots');
        if ($payout > 0) { $b = move_coins((int)$p['id'], $payout, 'payout', 'slots', implode('|', array_map(fn($c) => implode(',', $c), $grid))); }
        record_round((int)$p['id'], $bet, $payout);
        return $b;
    });

    return ['grid' => $grid, 'wins' => $wins, 'bet' => $bet, 'payout' => $payout, 'balance' => $balance,
        'message' => $payout ? 'Winner! +' . coins($payout) . ' GC' : 'No luck this spin.'];
}

/* ── Harbor Blackjack ──
 * 6-deck shoe, fresh per hand. Dealer peeks for blackjack, stands on all 17s.
 * Blackjack pays 3:2, double on any first two cards. No splits (yet).
 */
function bj_shoe(): array {
    $cards = [];
    for ($d = 0; $d < 6; $d++) {
        foreach (['S', 'H', 'D', 'C'] as $s) {
            foreach (['A', '2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K'] as $r) { $cards[] = $r . $s; }
        }
    }
    for ($i = count($cards) - 1; $i > 0; $i--) {
        $j = random_int(0, $i);
        [$cards[$i], $cards[$j]] = [$cards[$j], $cards[$i]];
    }
    return $cards;
}

function bj_value(array $cards): array {
    $total = 0; $aces = 0;
    foreach ($cards as $c) {
        $r = substr($c, 0, -1);
        if ($r === 'A') { $aces++; $total += 11; }
        elseif (in_array($r, ['J', 'Q', 'K'], true)) { $total += 10; }
        else { $total += (int)$r; }
    }
    while ($total > 21 && $aces) { $total -= 10; $aces--; }
    return [$total, $aces > 0];
}
function bj_natural(array $cards): bool { return count($cards) === 2 && bj_value($cards)[0] === 21; }

function bj_active(int $pid): ?array { return row("SELECT * FROM bj_hands WHERE player_id = ? AND status = 'active'", [$pid]); }

/** What the browser is allowed to see: never the shoe, never the hole card mid-hand. */
function bj_public(?array $hand): ?array {
    if (!$hand) { return null; }
    $st = json_decode($hand['state'], true) ?: [];
    $live = $hand['status'] === 'active';
    $dealer = $st['dealer'] ?? [];
    $shown = $live ? array_slice($dealer, 0, 1) : $dealer;
    return [
        'id' => (int)$hand['id'], 'bet' => (int)$hand['bet'], 'status' => $hand['status'],
        'outcome' => $hand['outcome'], 'payout' => (int)$hand['payout'],
        'player' => $st['player'] ?? [], 'player_total' => bj_value($st['player'] ?? [])[0],
        'dealer' => $shown, 'dealer_hidden' => $live ? max(0, count($dealer) - 1) : 0,
        'dealer_total' => bj_value($shown)[0],
        'can_double' => $live && count($st['player'] ?? []) === 2,
    ];
}

const BJ_OUTCOME_TEXT = [
    'blackjack' => 'Blackjack! Pays 3:2.', 'win' => 'You win.', 'dealer_bust' => 'Dealer busts. You win.',
    'push' => 'Push. Bet returned.', 'lose' => 'Dealer wins.', 'bust' => 'Bust.',
    'dealer_blackjack' => 'Dealer has blackjack.', 'void' => 'Hand voided by staff. Bet returned.',
];

/** Finish the hand, pay out, persist. Called inside tx(). */
function bj_settle(array $hand, array $st): array {
    [$pt] = bj_value($st['player']);
    $bet = (int)$hand['bet'];
    $pNat = bj_natural($st['player']) && empty($st['doubled']);
    $dNat = bj_natural($st['dealer']);

    if ($pt > 21) { $outcome = 'bust'; $pay = 0; }
    elseif ($pNat && $dNat) { $outcome = 'push'; $pay = $bet; }
    elseif ($pNat) { $outcome = 'blackjack'; $pay = $bet + intdiv($bet * 3, 2); }
    elseif ($dNat) { $outcome = 'dealer_blackjack'; $pay = 0; }
    else {
        while (bj_value($st['dealer'])[0] < 17) { $st['dealer'][] = array_pop($st['shoe']); }
        $dt = bj_value($st['dealer'])[0];
        if ($dt > 21) { $outcome = 'dealer_bust'; $pay = $bet * 2; }
        elseif ($pt > $dt) { $outcome = 'win'; $pay = $bet * 2; }
        elseif ($pt === $dt) { $outcome = 'push'; $pay = $bet; }
        else { $outcome = 'lose'; $pay = 0; }
    }

    $pid = (int)$hand['player_id'];
    unset($st['shoe']); // no reason to keep 300 cards around once it's over
    // settle as a conditional write first: a hand that is already done or voided can never pay a second time
    $n = q("UPDATE bj_hands SET status = 'done', outcome = ?, payout = ?, state = ?, updated_at = datetime('now') WHERE id = ? AND status = 'active'",
        [$outcome, $pay, json_encode($st), $hand['id']])->rowCount();
    if ($n !== 1) { throw new DomainException('That hand is already settled.'); }
    if ($pay > 0) { move_coins($pid, $pay, 'payout', 'blackjack', 'hand #' . $hand['id'] . ' ' . $outcome); }
    record_round($pid, $bet, $pay);
    return row('SELECT * FROM bj_hands WHERE id = ?', [$hand['id']]);
}

function blackjack_act(): array {
    $p = require_playable();
    $g = game_cfg('blackjack');
    $pid = (int)$p['id'];
    $act = (string)($_POST['move'] ?? '');
    $bet = $act === 'deal' ? clamp_bet($_POST['bet'] ?? '', $g) : 0;

    $hand = tx(function () use ($pid, $act, $bet) {
        $hand = bj_active($pid);
        if ($act === 'deal') {
            if ($hand) { throw new DomainException('Finish the hand you\'re in first.'); }
            move_coins($pid, -$bet, 'wager', 'blackjack');
            $shoe = bj_shoe();
            $st = ['shoe' => $shoe, 'player' => [], 'dealer' => [], 'doubled' => false];
            $st['player'][] = array_pop($st['shoe']); $st['dealer'][] = array_pop($st['shoe']);
            $st['player'][] = array_pop($st['shoe']); $st['dealer'][] = array_pop($st['shoe']);
            q('INSERT INTO bj_hands (player_id, bet, state) VALUES (?,?,?)', [$pid, $bet, json_encode($st)]);
            $hand = row('SELECT * FROM bj_hands WHERE id = ?', [(int)db()->lastInsertId()]);
            if (bj_natural($st['player']) || bj_natural($st['dealer'])) { $hand = bj_settle($hand, $st); }
            return $hand;
        }
        if (!$hand) { throw new DomainException('No hand in play. Place a bet and deal.'); }
        $st = json_decode($hand['state'], true);

        if ($act === 'hit') {
            $st['player'][] = array_pop($st['shoe']);
            if (bj_value($st['player'])[0] >= 21) { return bj_settle($hand, $st); }
        } elseif ($act === 'double') {
            if (count($st['player']) !== 2) { throw new DomainException('You can only double on your first two cards.'); }
            move_coins($pid, -(int)$hand['bet'], 'wager', 'blackjack', 'double hand #' . $hand['id']);
            $hand['bet'] = (int)$hand['bet'] * 2;
            q('UPDATE bj_hands SET bet = ? WHERE id = ?', [$hand['bet'], $hand['id']]);
            $st['doubled'] = true;
            $st['player'][] = array_pop($st['shoe']);
            return bj_settle($hand, $st);
        } elseif ($act === 'stand') {
            return bj_settle($hand, $st);
        } else {
            throw new DomainException('Unknown move.');
        }
        q("UPDATE bj_hands SET state = ?, updated_at = datetime('now') WHERE id = ?", [json_encode($st), $hand['id']]);
        return row('SELECT * FROM bj_hands WHERE id = ?', [$hand['id']]);
    });

    $pub = bj_public($hand);
    $bal = (int)val('SELECT balance FROM players WHERE id = ?', [$pid]);
    return ['hand' => $pub, 'balance' => $bal,
        'message' => $pub['status'] === 'done' ? (BJ_OUTCOME_TEXT[$pub['outcome']] ?? 'Hand over.') : 'Hit, stand, or double?'];
}

/* ── Coronado Roulette ── single zero, standard payouts (house edge 2.7%). */
const ROULETTE_RED = [1, 3, 5, 7, 9, 12, 14, 16, 18, 19, 21, 23, 25, 27, 30, 32, 34, 36];
const ROULETTE_MAX_BETS = 40;

function roulette_wins(string $type, int $v, int $n): int {
    // returns the total returned per coin staked (stake included), 0 on a loss
    return match ($type) {
        'straight' => $n === $v ? 36 : 0,
        'red'   => $n > 0 && in_array($n, ROULETTE_RED, true) ? 2 : 0,
        'black' => $n > 0 && !in_array($n, ROULETTE_RED, true) ? 2 : 0,
        'odd'   => $n > 0 && $n % 2 === 1 ? 2 : 0,
        'even'  => $n > 0 && $n % 2 === 0 ? 2 : 0,
        'low'   => $n >= 1 && $n <= 18 ? 2 : 0,
        'high'  => $n >= 19 ? 2 : 0,
        'dozen' => $n > 0 && intdiv($n - 1, 12) + 1 === $v ? 3 : 0,
        'column' => $n > 0 && (($n - 1) % 3) + 1 === $v ? 3 : 0,
        default => 0,
    };
}

function roulette_spin(): array {
    $p = require_playable();
    $g = game_cfg('roulette');

    // JS sends a JSON list; the no-JS form sends one bet as plain fields
    $raw = $_POST['bets'] ?? null;
    $bets = is_string($raw) && $raw !== '' ? json_decode($raw, true) : [[
        'type' => $_POST['bet_type'] ?? '', 'value' => $_POST['bet_value'] ?? 0, 'amount' => $_POST['amount'] ?? 0,
    ]];
    if (!is_array($bets) || !$bets) { fail('Place at least one chip.'); }
    if (count($bets) > ROULETTE_MAX_BETS) { fail('Max ' . ROULETTE_MAX_BETS . ' bets per spin.'); }

    // one stack per spot: duplicate entries merge before the caps, so a number can never hold more than max_bet and a
    // spin never more than 10× that, the same limits parse_bets() puts on the 3D wheel and every other chip board
    $agg = [];
    foreach ($bets as $b) {
        $type = is_array($b) ? (string)($b['type'] ?? '') : '';
        $vr = $b['value'] ?? 0;
        $v = is_numeric($vr) && (int)$vr == $vr ? (int)$vr : -1;
        $ok = match ($type) {
            'straight' => $v >= 0 && $v <= 36,
            'dozen', 'column' => $v >= 1 && $v <= 3,
            'red', 'black', 'odd', 'even', 'low', 'high' => true,
            default => false,
        };
        if (!$ok) { fail('That bet isn\'t on the table.'); }
        if (!in_array($type, ['straight', 'dozen', 'column'], true)) { $v = 0; }
        $agg["$type:$v"] = ($agg["$type:$v"] ?? 0) + chip_amount($b['amount'] ?? '');
    }
    $total = cap_spots($g, $agg, 'spin');
    $clean = [];
    foreach ($agg as $key => $amt) { [$type, $v] = explode(':', $key, 2); $clean[] = ['type' => $type, 'value' => (int)$v, 'amount' => $amt]; }

    $n = random_int(0, 36);
    $payout = 0;
    foreach ($clean as &$b) { $b['returned'] = $b['amount'] * roulette_wins($b['type'], $b['value'], $n); $payout += $b['returned']; }
    unset($b);

    $balance = tx(function () use ($p, $total, $payout, $n) {
        $bal = move_coins((int)$p['id'], -$total, 'wager', 'roulette');
        if ($payout > 0) { $bal = move_coins((int)$p['id'], $payout, 'payout', 'roulette', 'landed ' . $n); }
        record_round((int)$p['id'], $total, $payout);
        return $bal;
    });

    $color = $n === 0 ? 'green' : (in_array($n, ROULETTE_RED, true) ? 'red' : 'black');
    return ['number' => $n, 'color' => $color, 'bets' => $clean, 'wagered' => $total, 'payout' => $payout,
        'balance' => $balance,
        'message' => "$n " . strtoupper($color) . ($payout ? ' · returned ' . coins($payout) . ' GC' : ' · house takes it')];
}

/* ═════════════════════════ GAME REGISTRY ═════════════════════════
 * The lobby, nav, router, admin and seeding all read this list.
 * [name, category, blurb, sort]
 */
const GAME_REGISTRY = [
    'slots'      => ['Sunset Reels', 'slots', 'The classic: three reels, five paylines, one very shiny sun.', 1],
    'abyss'      => ['Abyss Critters', 'slots', 'Glow-in-the-dark deep sea. Kraken wilds, pearl-clam free spins at 3×.', 2],
    'tinfoil'    => ['Tinfoil Hat', 'slots', 'They don\'t want you to know about these free spins. UFO scatters, 3× bonus.', 3],
    'blacksite'  => ['Black Site Breach', 'slots', 'Crack the vault. Keycard wilds, classified-file free spins at 4×.', 4],
    'coderain'   => ['Code Rain', 'slots', 'Green code falls forever. Rare free spins at a massive 5×.', 5],
    'tiki'       => ['Tiki Tides', 'slots', 'Laid-back luau. Frequent wins, volcano free spins at 2×.', 6],
    'calavera'   => ['Calavera Fiesta', 'slots', 'Día de los Muertos under the marigolds. 12+ free spins at 2×.', 7],
    'scratch'    => ['Sunset Scratchers', 'reels', 'Scratch nine spots. Match three prizes and it\'s yours.', 2],
    'keno'       => ['Kelp Keno', 'reels', 'Pick up to ten of forty. Ten numbers wash ashore.', 3],
    'roulette3d' => ['Coronado Roulette 3D', 'worlds', 'A real 3D wheel: the ball rides the track, bounces off the frets and drops.', 8],
    'craps'      => ['Harbor Craps', 'worlds', 'Full bubble craps in 3D: line, come, odds, place, buy, lay, props.', 9],
    'pusher'     => ['Pier Pusher', 'worlds', 'The boardwalk coin pusher in 3D. Drop a coin, watch them spill.', 10],
    'roulette'   => ['Coronado Roulette', 'tables', 'Single-zero European wheel. Spread your chips.', 10],
    'baccarat'   => ['Bayfront Baccarat', 'tables', 'Player, banker, or tie. The classic high-roller card game.', 11],
    'sicbo'      => ['Surf Sic Bo', 'tables', 'Three dice, a whole board of bets. Big, small, triples.', 12],
    'bigwheel'   => ['Boardwalk Big Six', 'tables', 'The carnival money wheel. Pick a number, watch it tick.', 13],
    'crabs'      => ['Crab Crawl Derby', 'tables', 'Six crabs, one finish line. Longshots pay 20 to 1.', 14],
    'blackjack'  => ['Harbor Blackjack', 'cards', 'Six decks, dealer stands on all 17s, blackjack pays 3:2.', 20],
    'videopoker' => ['Boardwalk Poker', 'cards', 'Jacks or Better video poker. Hold, draw, hope for royals.', 21],
    'threecard'  => ['Coastline 3-Card', 'cards', 'Three-card poker against the dealer, with a Pair Plus side bet.', 22],
    'hilo'       => ['Tide Hi-Lo', 'cards', 'Higher or lower? Every right call grows the multiplier.', 23],
    'poker'      => ['Bayside Hold\'em', 'cards', 'No-limit Texas hold\'em against real players. Pull up a chair, buy in, play.', 24],
    'crash'      => ['Tide Crash', 'arcade', 'The wave keeps rising until it breaks. Cash out before it does.', 30],
    'plinko'     => ['Pearl Drop', 'arcade', 'Deluxe plinko: golden pegs double your pearl, up to 20 pearls a drop, 8–16 rows.', 29],
    'mines'      => ['Reef Mines', 'arcade', 'Twenty-five tiles, hidden urchins. Find pearls, cash out.', 32],
    'dice'       => ['Lighthouse Dice', 'arcade', 'Set your odds, roll over or under. You pick the risk.', 33],
];
const GAME_SCENES = ['slots' => 'sunset', 'scratch' => 'sparkle', 'keno' => 'kelp', 'roulette' => 'chandelier', 'baccarat' => 'chandelier', 'sicbo' => 'surf', 'bigwheel' => 'carnival', 'crabs' => 'beach', 'blackjack' => 'harbor', 'videopoker' => 'synth', 'threecard' => 'dusk', 'hilo' => 'tidepool', 'crash' => 'moon', 'mines' => 'reef', 'dice' => 'beam'];
function scene_open(string $slug): string {
    // closes the section's class attribute, drops the backdrop canvas in, and leaves a void <wbr> to absorb the template's closing ">
    return isset(GAME_SCENES[$slug]) ? ' scene scene-' . $slug . '"><canvas class="scene-fx" data-scene="' . GAME_SCENES[$slug] . '" aria-hidden="true"></canvas><wbr data-scene-end="' : '';
}
const GAME_CATEGORIES = [
    'slots' => ['Slot Hall', 'Seven machines, seven worlds. 243 ways, wilds, free spins. Flip any themed slot into a 3D cabinet.'],
    'worlds' => ['3D Games', 'Real 3D gameplay: balls that bounce, dice that tumble, coins that spill.'],
    'reels' => ['Scratch & Keno', 'Scratch it, pick it, watch the numbers roll in.'],
    'tables' => ['Table Games', 'Chips on the felt, just like the floor.'],
    'cards' => ['Card Room', 'Beat the dealer, make the hand.'],
    'arcade' => ['Boardwalk Arcade', 'Fast rounds, big multipliers, your call when to stop.'],
];

/* ═════════════════════════ ROUND PLUMBING ═════════════════════════
 * Every new game writes a row to `rounds`. Multi-step games keep an 'active'
 * row (one per player per game) with hidden state the browser never sees.
 * All helpers must run inside tx().
 */
function st(?array $r): array { return $r ? (json_decode((string)$r['state'], true) ?: []) : []; }
function bal(int $pid): int { return (int)val('SELECT balance FROM players WHERE id = ?', [$pid]); }
function round_active(int $pid, string $game): ?array {
    return row("SELECT * FROM rounds WHERE player_id = ? AND game = ? AND status = 'active'", [$pid, $game]);
}
/** Chips still at risk on an active round: what a void must hand back. Craps is the only game that pays or returns
 *  chips while its round stays 'active', so there rounds.bet (everything ever placed) overstates it; state.bets is live. */
function round_at_risk(array $r): int {
    if ($r['game'] === 'craps') { return (int)array_sum(craps_state($r)['bets']); }
    return (int)$r['bet'];
}
/** Coins a player has on tables right now: live chips in active rounds, the active blackjack hand, any poker stack.
 *  The refill gate adds this to the balance so parking take-down-able chips can't fake "running low". */
function coins_in_play(int $pid): int {
    $sum = 0;
    foreach (q("SELECT * FROM rounds WHERE player_id = ? AND status = 'active'", [$pid])->fetchAll() as $r) { $sum += round_at_risk($r); }
    $sum += (int)(val("SELECT COALESCE(SUM(bet), 0) FROM bj_hands WHERE player_id = ? AND status = 'active'", [$pid]) ?? 0);
    $sum += (int)(val('SELECT COALESCE(SUM(stack), 0) FROM poker_seats WHERE player_id = ?', [$pid]) ?? 0);
    return $sum;
}
function round_last(int $pid, string $game): ?array {
    if (!empty($GLOBALS['gt_skip_last'])) { return null; }
    return row("SELECT * FROM rounds WHERE player_id = ? AND game = ? AND status != 'void' ORDER BY id DESC LIMIT 1", [$pid, $game]);
}
function round_open(int $pid, string $game, int $bet, array $state): array {
    move_coins($pid, -$bet, 'wager', $game);
    q('INSERT INTO rounds (player_id, game, bet, state) VALUES (?,?,?,?)', [$pid, $game, $bet, json_encode($state)]);
    return row('SELECT * FROM rounds WHERE id = ?', [(int)db()->lastInsertId()]);
}
function round_raise(array $r, int $more, string $why): array {
    move_coins((int)$r['player_id'], -$more, 'wager', $r['game'], $why . ' #' . $r['id']);
    q('UPDATE rounds SET bet = bet + ? WHERE id = ?', [$more, $r['id']]);
    return row('SELECT * FROM rounds WHERE id = ?', [$r['id']]);
}
function round_save(array $r, array $state): array {
    q("UPDATE rounds SET state = ?, updated_at = datetime('now') WHERE id = ?", [json_encode($state), $r['id']]);
    return row('SELECT * FROM rounds WHERE id = ?', [$r['id']]);
}
function round_close(array $r, array $state, int $payout, string $outcome): array {
    $pid = (int)$r['player_id'];
    // settle as a conditional write first: a round that is already done or voided can never pay a second time
    $n = q("UPDATE rounds SET status = 'done', outcome = ?, payout = ?, state = ?, updated_at = datetime('now') WHERE id = ? AND status = 'active'",
        [$outcome, $payout, json_encode($state), $r['id']])->rowCount();
    if ($n !== 1) { throw new DomainException('That round is already settled.'); }
    if ($payout > 0) { move_coins($pid, $payout, 'payout', $r['game'], 'round #' . $r['id'] . ' ' . $outcome); }
    record_round($pid, (int)$r['bet'], $payout);
    return row('SELECT * FROM rounds WHERE id = ?', [$r['id']]);
}
/** A game that's decided in one request: wager, settle, done. */
function round_oneshot(int $pid, string $game, int $bet, int $payout, string $outcome, array $state): array {
    return round_close(round_open($pid, $game, $bet, $state), $state, $payout, $outcome);
}

/** One chip's amount as posted: a whole number of coins, at least 1. Range against the table comes after merging. */
function chip_amount(mixed $raw): int {
    if (!is_numeric($raw) || (int)$raw != $raw || (int)$raw < 1) { fail('Bet must be a whole number of coins.'); }
    return (int)$raw;
}
/** The table limits every chip board shares: one spot holds at most max_bet (and at least min_bet), and the whole
 *  $per (spin / round) at most 10 × max_bet. $spots is already merged, one entry per spot. Returns the total. */
function cap_spots(array $g, array $spots, string $per): int {
    $max = (int)$g['max_bet']; $total = 0;
    foreach ($spots as $amt) {
        if ($amt > $max) { fail('Max ' . coins($max) . ' GC on one spot.'); }
        clamp_bet($amt, $g);
        $total += $amt;
    }
    if ($total > $max * 10) { fail('Table limit is ' . coins($max * 10) . " GC per $per."); }
    return $total;
}
/** Chip-board games post [{key, amount}, ...]; the no-JS form posts one bet_key + amount.
 *  Keys must be spelled exactly the way the table spells them (lowercase, no whitespace, no leading zeros in a number), so
 *  "total:04" can't sit beside "total:4" as a second stack. Duplicate keys merge before any limit is checked. */
function parse_bets(array $g, callable $valid): array {
    $raw = $_POST['bets'] ?? null;
    $bets = is_string($raw) && $raw !== '' ? json_decode($raw, true)
        : [['key' => $_POST['bet_key'] ?? '', 'amount' => $_POST['amount'] ?? '']];
    if (!is_array($bets) || !$bets) { fail('Put some chips down first.'); }
    if (count($bets) > 40) { fail('Max 40 spots per round.'); }
    $clean = [];
    foreach ($bets as $b) {
        $key = is_array($b) && is_string($b['key'] ?? null) ? $b['key'] : '';
        if (!preg_match('/^(?:[a-z][a-z0-9_]*|0|[1-9]\d*)(?::(?:0|[1-9]\d*))?$/', $key) || !$valid($key)) { fail('That bet isn\'t on this table.'); }
        $clean[$key] = ($clean[$key] ?? 0) + chip_amount($b['amount'] ?? '');
    }
    return [$clean, cap_spots($g, $clean, 'round')];
}

function shoe(int $decks): array {
    $cards = [];
    for ($d = 0; $d < $decks; $d++) {
        foreach (['S', 'H', 'D', 'C'] as $s) {
            foreach (['A', '2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K'] as $r) { $cards[] = $r . $s; }
        }
    }
    return csprng_shuffle($cards);
}
function csprng_shuffle(array $a): array {
    for ($i = count($a) - 1; $i > 0; $i--) { $j = random_int(0, $i); [$a[$i], $a[$j]] = [$a[$j], $a[$i]]; }
    return $a;
}
function card_rank(string $c): int { return ['A' => 14, 'K' => 13, 'Q' => 12, 'J' => 11][substr($c, 0, -1)] ?? (int)substr($c, 0, -1); }
function card_suit(string $c): string { return substr($c, -1); }

/* ── Lighthouse Dice: 1% edge at every setting ── */
function dice_play(): array {
    $p = require_playable(); $g = game_cfg('dice');
    $bet = clamp_bet($_POST['bet'] ?? '', $g);
    $dir = ($_POST['dir'] ?? 'under') === 'over' ? 'over' : 'under';
    $t = $_POST['target'] ?? '';
    if (!is_numeric($t)) { fail('Pick a target.'); }
    $target = round((float)$t, 2);
    $chance = $dir === 'under' ? $target : 100 - $target;
    if ($chance < 2 || $chance > 95) { fail('Win chance has to be between 2% and 95%.'); }
    $mult = floor(99 / $chance * 10000) / 10000;
    $roll = random_int(0, 9999) / 100;
    $win = $dir === 'under' ? $roll < $target : $roll > $target;
    $payout = $win ? (int)floor($bet * $mult) : 0;
    $pid = (int)$p['id'];
    $r = tx(fn() => round_oneshot($pid, 'dice', $bet, $payout, $win ? 'win' : 'lose',
        ['roll' => $roll, 'target' => $target, 'dir' => $dir, 'mult' => $mult, 'chance' => $chance]));
    return ['roll' => $roll, 'win' => $win, 'payout' => $payout, 'balance' => bal($pid),
        'message' => sprintf('Rolled %.2f · ', $roll) . ($win ? 'win +' . coins($payout) . ' GC' : 'miss')];
}

/* ── Pearl Drop: the flagship plinko ──
 * Rows 8–16, three risk levels, up to 20 pearls per drop, and 3 golden pegs per drop.
 * Every pearl touches exactly one hittable peg per row, so for ANY path the number of
 * golden pegs hit is hypergeometric(N = rows(rows+1)/2, K = rows, draws = 3). That makes
 * the bonus factor F = E[2^hits] the same for every path, and each table below is scaled
 * so base RTP × F lands at 98.5–99.0%. (F: 8 rows 1.81, 10 1.64, 12 1.53, 14 1.45, 16 1.39)
 *
 * Provably fair: outcomes come from HMAC-SHA256(server_seed, "client:nonce:ball:N") and
 * "client:nonce:gold". Players see sha256(server_seed) up front and get the seed on rotate.
 */
const PD_TABLES = [
    8 => [
        'low' => [5.6, 1.5, 0.6, 0.4, 0.37, 0.4, 0.6, 1.5, 5.6],
        'med' => [13, 2.4, 0.6, 0.23, 0.23, 0.23, 0.6, 2.4, 13],
        'high' => [29, 2.8, 0.34, 0.1, 0.1, 0.1, 0.34, 2.8, 29],
    ],
    10 => [
        'low' => [8.9, 2.7, 1.1, 0.6, 0.45, 0.44, 0.45, 0.6, 1.1, 2.7, 8.9],
        'med' => [22, 5.4, 1.6, 0.6, 0.3, 0.2, 0.3, 0.6, 1.6, 5.4, 22],
        'high' => [76, 9.6, 1.5, 0.29, 0.1, 0.1, 0.1, 0.29, 1.5, 9.6, 76],
    ],
    12 => [
        'low' => [10, 3.7, 1.7, 1, 0.6, 0.51, 0.5, 0.51, 0.6, 1, 1.7, 3.7, 10],
        'med' => [33, 9.2, 3.1, 1.2, 0.6, 0.33, 0.32, 0.33, 0.6, 1.2, 3.1, 9.2, 33],
        'high' => [170, 27, 5, 1, 0.3, 0.1, 0.1, 0.1, 0.3, 1, 5, 27, 170],
    ],
    14 => [
        'low' => [7.1, 3.4, 1.9, 1.2, 0.8, 0.61, 0.61, 0.61, 0.61, 0.61, 0.8, 1.2, 1.9, 3.4, 7.1],
        'med' => [58, 17, 5.8, 2.3, 1, 0.6, 0.4, 0.3, 0.4, 0.6, 1, 2.3, 5.8, 17, 58],
        'high' => [420, 74, 15, 3.2, 0.8, 0.16, 0.1, 0.1, 0.1, 0.16, 0.8, 3.2, 15, 74, 420],
    ],
    16 => [
        'low' => [16, 6.8, 3.3, 1.8, 1.2, 0.8, 0.7, 0.6, 0.55, 0.6, 0.7, 0.8, 1.2, 1.8, 3.3, 6.8, 16],
        'med' => [110, 34, 11, 4.4, 1.9, 1, 0.5, 0.4, 0.37, 0.4, 0.5, 1, 1.9, 4.4, 11, 34, 110],
        'high' => [1000, 190, 39, 8.6, 2.1, 0.6, 0.18, 0.1, 0.1, 0.1, 0.18, 0.6, 2.1, 8.6, 39, 190, 1000],
    ],
];
const PD_ROWS = [8, 10, 12, 14, 16];
const PD_BALLS = [1, 3, 5, 10, 20];
const PD_GOLD = 3;

function fair_active(int $pid, string $game): array {
    $s = row("SELECT * FROM fair_seeds WHERE player_id = ? AND game = ? AND status = 'active'", [$pid, $game]);
    if ($s) { return $s; }
    $seed = bin2hex(random_bytes(32));
    q('INSERT INTO fair_seeds (player_id, game, server_seed, server_hash, client_seed) VALUES (?,?,?,?,?)',
        [$pid, $game, $seed, hash('sha256', $seed), bin2hex(random_bytes(8))]);
    return row('SELECT * FROM fair_seeds WHERE id = ?', [(int)db()->lastInsertId()]);
}
function fair_bytes(string $seed, string $msg): array { return array_values(unpack('C*', hash_hmac('sha256', $msg, $seed, true))); }

/** The pearl's path: one bit per row, right when the byte is ≥ 128. */
function pd_path(string $seed, string $client, int $nonce, int $ball, int $rows): string {
    $b = fair_bytes($seed, "$client:$nonce:ball:$ball");
    $p = '';
    for ($r = 0; $r < $rows; $r++) { $p .= $b[$r] >= 128 ? '1' : '0'; }
    return $p;
}
/** Golden pegs: partial Fisher–Yates over every hittable peg [row, index]. */
function pd_gold(string $seed, string $client, int $nonce, int $rows): array {
    $pegs = [];
    for ($r = 0; $r < $rows; $r++) { for ($i = 1; $i <= $r + 1; $i++) { $pegs[] = [$r, $i]; } }
    $b = fair_bytes($seed, "$client:$nonce:gold");
    $n = count($pegs); $out = [];
    for ($j = 0; $j < PD_GOLD; $j++) {
        $u = ($b[$j * 4] << 24 | $b[$j * 4 + 1] << 16 | $b[$j * 4 + 2] << 8 | $b[$j * 4 + 3]) % ($n - $j);
        [$pegs[$j], $pegs[$j + $u]] = [$pegs[$j + $u], $pegs[$j]];
        $out[] = $pegs[$j];
    }
    return $out;
}
/** Which golden pegs this path touches (row r hits peg index 1 + rights-so-far). */
function pd_hits(string $path, array $gold): array {
    $hits = []; $k = 0;
    $set = []; foreach ($gold as [$r, $i]) { $set["$r:$i"] = true; }
    for ($r = 0; $r < strlen($path); $r++) {
        if (isset($set[$r . ':' . (1 + $k)])) { $hits[] = $r; }
        $k += (int)$path[$r];
    }
    return $hits;
}

function plinko_play(): array {
    $p = require_playable(); $g = game_cfg('plinko');
    $bet = clamp_bet($_POST['bet'] ?? '', $g);
    $rows = (int)($_POST['rows'] ?? 12); if (!in_array($rows, PD_ROWS, true)) { $rows = 12; }
    $risk = (string)($_POST['risk'] ?? 'med'); if (!isset(PD_TABLES[$rows][$risk])) { $risk = 'med'; }
    $n = (int)($_POST['balls'] ?? 1); if (!in_array($n, PD_BALLS, true)) { $n = 1; }
    $pid = (int)$p['id'];

    $out = tx(function () use ($pid, $bet, $rows, $risk, $n) {
        $seed = fair_active($pid, 'plinko');
        $nonce = (int)$seed['nonce'];
        q("UPDATE fair_seeds SET nonce = nonce + 1, updated_at = datetime('now') WHERE id = ?", [$seed['id']]);
        $gold = pd_gold($seed['server_seed'], $seed['client_seed'], $nonce, $rows);
        $balls = []; $payout = 0; $best = 0;
        for ($b = 0; $b < $n; $b++) {
            $path = pd_path($seed['server_seed'], $seed['client_seed'], $nonce, $b, $rows);
            $slot = substr_count($path, '1');
            $hits = pd_hits($path, $gold);
            $mult = round(PD_TABLES[$rows][$risk][$slot] * (2 ** count($hits)), 2);
            $win = (int)floor($bet * $mult);
            $payout += $win; $best = max($best, $mult);
            $balls[] = ['path' => $path, 'slot' => $slot, 'hits' => $hits, 'mult' => $mult, 'win' => $win];
        }
        $state = ['rows' => $rows, 'risk' => $risk, 'per' => $bet, 'balls' => $balls, 'gold' => $gold,
            'nonce' => $nonce, 'hash' => $seed['server_hash'], 'client' => $seed['client_seed']];
        round_oneshot($pid, 'plinko', $bet * $n, $payout, $best . 'x', $state);
        return $state + ['payout' => $payout, 'best' => $best];
    });
    $total = $bet * $n;
    return ['balls' => $out['balls'], 'gold' => $out['gold'], 'rows' => $rows, 'risk' => $risk, 'nonce' => $out['nonce'],
        'next_nonce' => $out['nonce'] + 1, 'hash' => $out['hash'], 'payout' => $out['payout'], 'bet' => $total,
        'win' => $out['payout'] > $total, 'balance' => bal($pid),
        'message' => ($n > 1 ? "$n pearls · best {$out['best']}× · " : $out['best'] . '× · ') . ($out['payout'] ? coins($out['payout']) . ' GC back' : 'nothing back')];
}

/** Rotate seeds: reveal the old server seed, start a fresh one (optionally with a new client seed). */
function fair_rotate(): never {
    csrf_check();
    $p = require_player();
    $game = 'plinko';
    $client = trim((string)($_POST['client_seed'] ?? ''));
    if ($client !== '' && !preg_match('/^[A-Za-z0-9_-]{1,64}$/', $client)) { fail('Client seed: 1–64 letters, numbers, _ or -.'); }
    $pid = (int)$p['id'];
    $res = tx(function () use ($pid, $game, $client) {
        $old = fair_active($pid, $game);
        q("UPDATE fair_seeds SET status = 'revealed', revealed_at = datetime('now'), updated_at = datetime('now') WHERE id = ?", [$old['id']]);
        $seed = bin2hex(random_bytes(32));
        $cs = $client !== '' ? $client : bin2hex(random_bytes(8));
        q('INSERT INTO fair_seeds (player_id, game, server_seed, server_hash, client_seed) VALUES (?,?,?,?,?)',
            [$pid, $game, $seed, hash('sha256', $seed), $cs]);
        return ['revealed' => ['server_seed' => $old['server_seed'], 'server_hash' => $old['server_hash'],
            'client_seed' => $old['client_seed'], 'nonces' => (int)$old['nonce']],
            'active' => ['server_hash' => hash('sha256', $seed), 'client_seed' => $cs, 'nonce' => 0]];
    });
    if (wants_json()) { ok($res + ['message' => 'Seed revealed. New seed pair is live.']); }
    flash('ok', 'Seed revealed: ' . $res['revealed']['server_seed']);
    redirect(url('plinko'));
}

/* ── Kelp Keno: 40 balls, 10 drawn. Every pick count returns ~94–96%. ── */
const KENO_PAY = [
    1 => [0, 3.8],
    2 => [0, 1.1, 9],
    3 => [0, 0, 3.5, 38],
    4 => [0, 0, 2, 8.5, 83],
    5 => [0, 0, 1.3, 4, 19, 250],
    6 => [0, 0, 0.6, 3, 8, 65, 650],
    7 => [0, 0, 0.7, 1.5, 4.5, 29, 175, 1500],
    8 => [0, 0, 0, 1.7, 3.5, 14, 70, 500, 3500],
    9 => [0, 0, 0, 0.8, 3.5, 8.5, 33, 170, 1300, 8000],
    10 => [0, 0, 0, 0.9, 1.8, 5.5, 21, 90, 500, 3500, 15000],
];
function keno_play(): array {
    $p = require_playable(); $g = game_cfg('keno');
    $bet = clamp_bet($_POST['bet'] ?? '', $g);
    $picks = $_POST['picks'] ?? [];
    if (is_string($picks)) { $picks = explode(',', $picks); }
    $picks = array_values(array_unique(array_map('intval', (array)$picks)));
    $picks = array_values(array_filter($picks, fn($n) => $n >= 1 && $n <= 40));
    if (!$picks || count($picks) > 10) { fail('Pick between 1 and 10 numbers.'); }
    sort($picks);
    $drawn = array_slice(csprng_shuffle(range(1, 40)), 0, 10);
    $hits = array_values(array_intersect($picks, $drawn));
    $mult = KENO_PAY[count($picks)][count($hits)];
    $payout = (int)floor($bet * $mult);
    $pid = (int)$p['id'];
    tx(fn() => round_oneshot($pid, 'keno', $bet, $payout, count($hits) . '/' . count($picks),
        ['picks' => $picks, 'drawn' => $drawn, 'hits' => $hits, 'mult' => $mult]));
    return ['drawn' => $drawn, 'hits' => $hits, 'payout' => $payout, 'win' => $payout > $bet, 'balance' => bal($pid),
        'message' => count($hits) . ' of ' . count($picks) . ' hit · ' . ($payout ? '+' . coins($payout) . ' GC' : 'no prize')];
}

/* ── Sunset Scratchers: fixed ticket, 9 spots, match 3. RTP 91%, ~24% of tickets win. ── */
const SCRATCH_TIERS = [1000 => 10, 100 => 100, 25 => 400, 10 => 1500, 5 => 4000, 2 => 8000, 1 => 10000]; // mult => chance per 100k
function scratch_play(): array {
    $p = require_playable(); $g = game_cfg('scratch');
    $bet = clamp_bet($_POST['bet'] ?? '', $g);
    $roll = random_int(1, 100000); $win = 0; $acc = 0;
    foreach (SCRATCH_TIERS as $m => $n) { $acc += $n; if ($roll <= $acc) { $win = $m; break; } }
    // build a card consistent with the outcome: exactly one triple on a win, no triple on a loss
    $vals = array_keys(SCRATCH_TIERS);
    $spots = $win ? [$win, $win, $win] : [];
    $count = $win ? [$win => 3] : [];
    while (count($spots) < 9) {
        $v = $vals[random_int(0, count($vals) - 1)];
        if ($v === $win || ($count[$v] ?? 0) >= 2) { continue; }
        $count[$v] = ($count[$v] ?? 0) + 1;
        $spots[] = $v;
    }
    $spots = csprng_shuffle($spots);
    $payout = $bet * $win;
    $pid = (int)$p['id'];
    tx(fn() => round_oneshot($pid, 'scratch', $bet, $payout, $win ? $win . 'x' : 'no match', ['spots' => $spots, 'win' => $win]));
    return ['spots' => $spots, 'win' => $payout > 0, 'payout' => $payout, 'balance' => bal($pid),
        'message' => $win ? 'Three ' . coins($bet * $win) . 's! +' . coins($payout) . ' GC' : 'No match this time.'];
}

/* ── Boardwalk Big Six: classic 54-stop money wheel ── */
const BIGSIX = ['1' => [24, 1], '2' => [15, 2], '5' => [7, 5], '10' => [4, 10], '20' => [2, 20], 'anchor' => [1, 45], 'sun' => [1, 45]];
function bigsix_wheel(): array {
    static $w = null;
    if ($w) { return $w; }
    $w = array_fill(0, 54, null);
    $order = BIGSIX; uasort($order, fn($a, $b) => $a[0] <=> $b[0]); // rarest first, spread evenly
    $shift = 0;
    foreach ($order as $sym => [$n]) {
        for ($i = 0; $i < $n; $i++) {
            $pos = (int)round($i * 54 / $n + $shift) % 54;
            while ($w[$pos] !== null) { $pos = ($pos + 1) % 54; }
            $w[$pos] = (string)$sym;
        }
        $shift += 3;
    }
    return $w;
}
function bigwheel_play(): array {
    $p = require_playable(); $g = game_cfg('bigwheel');
    [$bets, $total] = parse_bets($g, fn($k) => isset(BIGSIX[$k]));
    $wheel = bigsix_wheel();
    $idx = random_int(0, 53);
    $hit = $wheel[$idx];
    $payout = isset($bets[$hit]) ? $bets[$hit] * (BIGSIX[$hit][1] + 1) : 0;
    $pid = (int)$p['id'];
    tx(fn() => round_oneshot($pid, 'bigwheel', $total, $payout, $hit, ['index' => $idx, 'hit' => $hit, 'bets' => $bets]));
    return ['index' => $idx, 'hit' => $hit, 'win_keys' => $payout ? [$hit] : [], 'payout' => $payout, 'win' => $payout > 0,
        'balance' => bal($pid), 'message' => 'Landed on ' . ($hit === 'anchor' || $hit === 'sun' ? 'the ' . $hit : $hit) . ($payout ? ' · +' . coins($payout) . ' GC' : '')];
}

/* ── Surf Sic Bo ── */
const SICBO_TOTALS = [4 => 60, 5 => 30, 6 => 17, 7 => 12, 8 => 8, 9 => 6, 10 => 6, 11 => 6, 12 => 6, 13 => 8, 14 => 12, 15 => 17, 16 => 30, 17 => 60];
function sicbo_valid(string $k): bool {
    if (in_array($k, ['small', 'big', 'any_triple'], true)) { return true; }
    if (!preg_match('/^(total|single|double|triple):([1-9]\d?)$/', $k, $m)) { return false; }   // exact spelling: no "04"
    $n = (int)$m[2];
    return $m[1] === 'total' ? isset(SICBO_TOTALS[$n]) : $n >= 1 && $n <= 6;
}
function sicbo_returns(string $k, array $d): int {
    $sum = array_sum($d); $triple = $d[0] === $d[1] && $d[1] === $d[2];
    $cnt = array_count_values($d);
    if ($k === 'small') { return !$triple && $sum >= 4 && $sum <= 10 ? 2 : 0; }
    if ($k === 'big') { return !$triple && $sum >= 11 && $sum <= 17 ? 2 : 0; }
    if ($k === 'any_triple') { return $triple ? 31 : 0; }
    [$t, $n] = explode(':', $k); $n = (int)$n;
    return match ($t) {
        'total' => $sum === $n ? SICBO_TOTALS[$n] + 1 : 0,
        'single' => ($cnt[$n] ?? 0) ? 1 + $cnt[$n] : 0,
        'double' => ($cnt[$n] ?? 0) >= 2 ? 11 : 0,
        'triple' => ($cnt[$n] ?? 0) === 3 ? 181 : 0,
        default => 0,
    };
}
function sicbo_play(): array {
    $p = require_playable(); $g = game_cfg('sicbo');
    [$bets, $total] = parse_bets($g, 'sicbo_valid');
    $dice = [random_int(1, 6), random_int(1, 6), random_int(1, 6)];
    $payout = 0; $wins = [];
    foreach ($bets as $k => $amt) { $x = sicbo_returns($k, $dice); if ($x) { $payout += $amt * $x; $wins[] = $k; } }
    $pid = (int)$p['id'];
    tx(fn() => round_oneshot($pid, 'sicbo', $total, $payout, implode('-', $dice), ['dice' => $dice, 'bets' => $bets, 'wins' => $wins]));
    return ['dice' => $dice, 'win_keys' => $wins, 'payout' => $payout, 'win' => $payout > $total, 'balance' => bal($pid),
        'message' => implode(' · ', $dice) . ' = ' . array_sum($dice) . ($payout ? ' · returned ' . coins($payout) . ' GC' : '')];
}

/* ── Crab Crawl Derby: pays decimal odds, win chance ∝ 1/odds, RTP ≈ 93.9% on every crab ── */
const CRABS = [
    ['Pinchy', 3, '#ff6f59'], ['Sandy', 4, '#e8b64c'], ['Coral', 5, '#ff9fb2'],
    ['Captain Clack', 7, '#2bb3a3'], ['Barnacle Bill', 11, '#8c7ae6'], ['Sir Scuttles', 21, '#6fd3ff'],
];
function crabs_play(): array {
    $p = require_playable(); $g = game_cfg('crabs');
    [$bets, $total] = parse_bets($g, fn($k) => (bool)preg_match('/^crab:[0-5]$/', $k));
    $weights = array_map(fn($c) => intdiv(2310000, $c[1]), CRABS); // 2310000 divides evenly by 3,4,5,7,11,21
    $roll = random_int(1, array_sum($weights)); $winner = 0;
    foreach ($weights as $i => $w) { if ($roll <= $w) { $winner = $i; break; } $roll -= $w; }
    $rest = csprng_shuffle(array_values(array_diff(range(0, 5), [$winner])));
    $order = [$winner, ...$rest];
    $payout = ($bets["crab:$winner"] ?? 0) * CRABS[$winner][1];
    $pid = (int)$p['id'];
    tx(fn() => round_oneshot($pid, 'crabs', $total, $payout, CRABS[$winner][0], ['order' => $order, 'bets' => $bets]));
    return ['order' => $order, 'win_keys' => ["crab:$winner"], 'payout' => $payout, 'win' => $payout > 0, 'balance' => bal($pid),
        'message' => CRABS[$winner][0] . ' wins!' . ($payout ? ' +' . coins($payout) . ' GC' : '')];
}

/* ── Bayfront Baccarat: 8 decks, standard tableau, banker pays 0.95, tie 8:1 ── */
function bac_val(array $cards): int { $t = 0; foreach ($cards as $c) { $r = card_rank($c); $t += $r === 14 ? 1 : ($r >= 10 ? 0 : $r); } return $t % 10; }
function baccarat_play(): array {
    $p = require_playable(); $g = game_cfg('baccarat');
    [$bets, $total] = parse_bets($g, fn($k) => in_array($k, ['player', 'banker', 'tie'], true));
    $s = shoe(8);
    $P = [array_pop($s)]; $B = [array_pop($s)]; $P[] = array_pop($s); $B[] = array_pop($s);
    $order = ['P', 'B', 'P', 'B'];
    $pv = bac_val($P); $bv = bac_val($B);
    if ($pv < 8 && $bv < 8) {
        $p3 = null;
        if ($pv <= 5) { $P[] = $p3 = array_pop($s); $order[] = 'P'; }
        $bv = bac_val($B);
        if ($p3 === null) { $draw = $bv <= 5; }
        else {
            $x = card_rank($p3); $x = $x === 14 ? 1 : ($x >= 10 ? 0 : $x);
            $draw = match (true) { $bv <= 2 => true, $bv === 3 => $x !== 8, $bv === 4 => $x >= 2 && $x <= 7,
                $bv === 5 => $x >= 4 && $x <= 7, $bv === 6 => $x === 6 || $x === 7, default => false };
        }
        if ($draw) { $B[] = array_pop($s); $order[] = 'B'; }
    }
    $pv = bac_val($P); $bv = bac_val($B);
    $res = $pv > $bv ? 'player' : ($bv > $pv ? 'banker' : 'tie');
    $payout = 0;
    if ($res === 'tie') { $payout += ($bets['tie'] ?? 0) * 9 + ($bets['player'] ?? 0) + ($bets['banker'] ?? 0); }
    elseif ($res === 'player') { $payout += ($bets['player'] ?? 0) * 2; }
    else { $payout += (int)floor(($bets['banker'] ?? 0) * 1.95); }
    $pid = (int)$p['id'];
    tx(fn() => round_oneshot($pid, 'baccarat', $total, $payout, $res, ['player' => $P, 'banker' => $B, 'order' => $order, 'pv' => $pv, 'bv' => $bv, 'result' => $res, 'bets' => $bets]));
    return ['result' => $res, 'win_keys' => [$res], 'payout' => $payout, 'win' => $payout > $total, 'cards' => count($P) + count($B),
        'balance' => bal($pid), 'message' => ($res === 'tie' ? 'Tie' : ucfirst($res) . ' wins') . " {$pv}–{$bv}" . ($payout ? ' · returned ' . coins($payout) . ' GC' : '')];
}

/* ── Poker hand evaluation ── */
const VP_PAY = ['royal' => 800, 'straight_flush' => 50, 'four' => 25, 'full_house' => 9, 'flush' => 6, 'straight' => 4, 'three' => 3, 'two_pair' => 2, 'jacks' => 1];
const VP_NAMES = ['royal' => 'Royal Flush', 'straight_flush' => 'Straight Flush', 'four' => 'Four of a Kind', 'full_house' => 'Full House',
    'flush' => 'Flush', 'straight' => 'Straight', 'three' => 'Three of a Kind', 'two_pair' => 'Two Pair', 'jacks' => 'Jacks or Better'];
function vp_eval(array $cards): ?string {
    $r = array_map('card_rank', $cards); rsort($r);
    $flush = count(array_unique(array_map('card_suit', $cards))) === 1;
    $u = array_values(array_unique($r));
    $straight = count($u) === 5 && ($u[0] - $u[4] === 4 || $u === [14, 5, 4, 3, 2]);
    $c = array_count_values($r); arsort($c); $counts = array_values($c);
    if ($straight && $flush) { return $r[0] === 14 && $r[4] === 10 ? 'royal' : 'straight_flush'; }
    if ($counts[0] === 4) { return 'four'; }
    if ($counts[0] === 3 && $counts[1] === 2) { return 'full_house'; }
    if ($flush) { return 'flush'; }
    if ($straight) { return 'straight'; }
    if ($counts[0] === 3) { return 'three'; }
    if ($counts[0] === 2 && $counts[1] === 2) { return 'two_pair'; }
    if ($counts[0] === 2 && array_key_first($c) >= 11) { return 'jacks'; }
    return null;
}

/* ── Boardwalk Poker (Jacks or Better 9/6, ~99.5% with perfect holds) ── */
function videopoker_act(): array {
    $p = require_playable(); $g = game_cfg('videopoker');
    $pid = (int)$p['id']; $move = (string)($_POST['move'] ?? '');
    $bet = $move === 'deal' ? clamp_bet($_POST['bet'] ?? '', $g) : 0;
    $r = tx(function () use ($pid, $move, $bet) {
        $r = round_active($pid, 'videopoker');
        if ($move === 'deal') {
            if ($r) { throw new DomainException('Finish this hand first: pick holds and draw.'); }
            $deck = shoe(1);
            $hand = array_splice($deck, 0, 5);
            return round_open($pid, 'videopoker', $bet, ['deck' => $deck, 'hand' => $hand, 'held' => []]);
        }
        if ($move !== 'draw' || !$r) { throw new DomainException('Deal a hand first.'); }
        $s = st($r);
        $held = array_values(array_unique(array_filter(array_map('intval', (array)($_POST['hold'] ?? [])), fn($i) => $i >= 0 && $i <= 4)));
        foreach (range(0, 4) as $i) { if (!in_array($i, $held, true)) { $s['hand'][$i] = array_shift($s['deck']); } }
        $s['held'] = $held; unset($s['deck']);
        $hand = vp_eval($s['hand']);
        $s['result'] = $hand;
        return round_close($r, $s, $hand ? (int)$r['bet'] * VP_PAY[$hand] : 0, $hand ?? 'nothing');
    });
    $s = st($r);
    $done = $r['status'] === 'done';
    $name = $done ? ($s['result'] ? VP_NAMES[$s['result']] : 'No win') : (($h = vp_eval($s['hand'])) ? 'You\'re holding ' . VP_NAMES[$h] : 'Pick your holds');
    return ['payout' => (int)$r['payout'], 'win' => (int)$r['payout'] > 0, 'balance' => bal($pid),
        'message' => $done ? $name . ((int)$r['payout'] ? ' · +' . coins((int)$r['payout']) . ' GC' : '') : $name];
}

/* ── Coastline 3-Card ── */
function tc_eval(array $cards): array {
    $r = array_map('card_rank', $cards); rsort($r);
    $flush = count(array_unique(array_map('card_suit', $cards))) === 1;
    $straight = count(array_unique($r)) === 3 && ($r[0] - $r[2] === 2 || $r === [14, 3, 2]);
    if ($r === [14, 3, 2]) { $r = [3, 2, 1]; }
    $c = array_count_values($r);
    if ($straight && $flush) { return [5, $r]; }
    if (count($c) === 1) { return [4, $r]; }
    if ($straight) { return [3, $r]; }
    if ($flush) { return [2, $r]; }
    if (count($c) === 2) { $pair = array_search(2, $c, true); $kick = array_search(1, $c, true); return [1, [$pair, $kick]]; }
    return [0, $r];
}
const TC_NAMES = ['High card', 'Pair', 'Flush', 'Straight', 'Three of a Kind', 'Straight Flush'];
const TC_PAIRPLUS = [5 => 40, 4 => 30, 3 => 6, 2 => 4, 1 => 1];
const TC_ANTE_BONUS = [5 => 5, 4 => 4, 3 => 1];
function tc_cmp(array $a, array $b): int { return [$a[0], ...$a[1]] <=> [$b[0], ...$b[1]]; }
function threecard_act(): array {
    $p = require_playable(); $g = game_cfg('threecard');
    $pid = (int)$p['id']; $move = (string)($_POST['move'] ?? '');
    $ante = 0; $pp = 0;
    if ($move === 'deal') {
        $ante = clamp_bet($_POST['bet'] ?? '', $g);
        $ppRaw = trim((string)($_POST['pairplus'] ?? ''));
        $pp = $ppRaw === '' || $ppRaw === '0' ? 0 : clamp_bet($ppRaw, $g);
    }
    $r = tx(function () use ($pid, $move, $ante, $pp) {
        $r = round_active($pid, 'threecard');
        if ($move === 'deal') {
            if ($r) { throw new DomainException('Play or fold the hand you\'re holding first.'); }
            $d = shoe(1);
            return round_open($pid, 'threecard', $ante + $pp, ['player' => array_splice($d, 0, 3), 'dealer' => array_splice($d, 0, 3), 'ante' => $ante, 'pp' => $pp]);
        }
        if (!$r || !in_array($move, ['play', 'fold'], true)) { throw new DomainException('Deal a hand first.'); }
        $s = st($r);
        $pe = tc_eval($s['player']); $de = tc_eval($s['dealer']);
        $pay = 0; $notes = [];
        if ($s['pp'] && isset(TC_PAIRPLUS[$pe[0]])) { $pay += $s['pp'] * (TC_PAIRPLUS[$pe[0]] + 1); $notes[] = 'Pair Plus pays'; }
        if ($move === 'fold') {
            $s['folded'] = true;
            $outcome = 'fold';
        } else {
            $r = round_raise($r, (int)$s['ante'], 'play bet');
            $s['play'] = (int)$s['ante'];
            if (isset(TC_ANTE_BONUS[$pe[0]])) { $pay += $s['ante'] * TC_ANTE_BONUS[$pe[0]]; $notes[] = 'Ante bonus'; }
            $qual = $de[0] >= 1 || $de[1][0] >= 12;
            $s['qualified'] = $qual;
            if (!$qual) { $pay += $s['ante'] * 2 + $s['play']; $outcome = 'no_qualify'; }
            else {
                $cmp = tc_cmp($pe, $de);
                if ($cmp > 0) { $pay += ($s['ante'] + $s['play']) * 2; $outcome = 'win'; }
                elseif ($cmp === 0) { $pay += $s['ante'] + $s['play']; $outcome = 'push'; }
                else { $outcome = 'lose'; }
            }
        }
        $s['notes'] = $notes; $s['pe'] = $pe[0]; $s['de'] = $de[0];
        return round_close($r, $s, $pay, $outcome);
    });
    $s = st($r);
    $msg = match ($r['outcome']) {
        null => 'You have ' . strtolower(TC_NAMES[tc_eval($s['player'])[0]]) . '. Play or fold?',
        'fold' => 'Folded.', 'no_qualify' => 'Dealer doesn\'t qualify. Ante pays, play pushes.',
        'win' => 'You beat the dealer!', 'push' => 'Push.', 'lose' => 'Dealer takes it.', default => '',
    };
    if (!empty($s['notes'])) { $msg .= ' ' . implode(' + ', $s['notes']) . '!'; }
    return ['payout' => (int)$r['payout'], 'win' => (int)$r['payout'] > (int)$r['bet'], 'balance' => bal($pid), 'message' => $msg];
}

/* ── Tide Hi-Lo: infinite deck, 1% edge per call, ties count for you ── */
function hilo_draw(): array { return ['r' => random_int(1, 13), 's' => ['S', 'H', 'D', 'C'][random_int(0, 3)]]; }
function hilo_card(array $c): string { return [1 => 'A', 11 => 'J', 12 => 'Q', 13 => 'K'][$c['r']] ?? (string)$c['r']; }
function hilo_odds(int $rank): array { return ['hi' => (14 - $rank) / 13, 'lo' => $rank / 13]; }
function hilo_act(): array {
    $p = require_playable(); $g = game_cfg('hilo');
    $pid = (int)$p['id']; $move = (string)($_POST['move'] ?? '');
    $bet = $move === 'start' ? clamp_bet($_POST['bet'] ?? '', $g) : 0;
    $r = tx(function () use ($pid, $move, $bet) {
        $r = round_active($pid, 'hilo');
        if ($move === 'start') {
            if ($r) { throw new DomainException('You\'ve got a run going. Cash out or keep calling.'); }
            return round_open($pid, 'hilo', $bet, ['card' => hilo_draw(), 'mult' => 1.0, 'steps' => 0, 'trail' => []]);
        }
        if (!$r) { throw new DomainException('Start a run first.'); }
        $s = st($r);
        if ($move === 'skip') {
            if (($s['skips'] ?? 0) >= 5) { throw new DomainException('Out of skips this run.'); }
            $s['skips'] = ($s['skips'] ?? 0) + 1;
            $s['trail'][] = ['card' => $s['card'], 'call' => 'skip'];
            $s['card'] = hilo_draw();
            return round_save($r, $s);
        }
        if ($move === 'cashout') {
            if ($s['steps'] < 1) { throw new DomainException('Make at least one call before cashing out.'); }
            return round_close($r, $s, (int)floor($r['bet'] * $s['mult']), 'cashout');
        }
        if ($move !== 'hi' && $move !== 'lo') { throw new DomainException('Unknown move.'); }
        $pOdds = hilo_odds($s['card']['r'])[$move];
        $next = hilo_draw();
        $ok = $move === 'hi' ? $next['r'] >= $s['card']['r'] : $next['r'] <= $s['card']['r'];
        $s['trail'][] = ['card' => $s['card'], 'call' => $move, 'ok' => $ok];
        $s['card'] = $next;
        if (!$ok) { return round_close($r, $s, 0, 'wrong'); }
        $s['mult'] = min(5000, floor($s['mult'] * 0.99 / $pOdds * 10000) / 10000);
        $s['steps']++;
        if ($s['mult'] >= 5000) { return round_close($r, $s, (int)floor($r['bet'] * $s['mult']), 'max'); }
        return round_save($r, $s);
    });
    $s = st($r);
    $msg = $r['status'] === 'active' ? 'Run at ' . number_format($s['mult'], 2) . '× · worth ' . coins((int)floor($r['bet'] * $s['mult'])) . ' GC'
        : ($r['outcome'] === 'wrong' ? 'Wrong call. The tide took it.' : 'Cashed out at ' . number_format($s['mult'], 2) . '× · +' . coins((int)$r['payout']) . ' GC');
    return ['payout' => (int)$r['payout'], 'win' => (int)$r['payout'] > 0, 'balance' => bal($pid), 'message' => $msg];
}

/* ── Reef Mines: 5×5, you choose 1–24 urchins, 1% edge ── */
function mines_mult(int $n, int $k): float {
    $m = 0.99;
    for ($i = 0; $i < $k; $i++) { $m *= (25 - $i) / (25 - $n - $i); }
    return floor($m * 100) / 100;
}
function mines_act(): array {
    $p = require_playable(); $g = game_cfg('mines');
    $pid = (int)$p['id']; $move = (string)($_POST['move'] ?? '');
    $bet = $move === 'start' ? clamp_bet($_POST['bet'] ?? '', $g) : 0;
    $n = (int)($_POST['mines'] ?? 3);
    if ($move === 'start' && ($n < 1 || $n > 24)) { fail('Pick 1 to 24 urchins.'); }
    $r = tx(function () use ($pid, $move, $bet, $n) {
        $r = round_active($pid, 'mines');
        if ($move === 'start') {
            if ($r) { throw new DomainException('Finish the reef you\'re on first.'); }
            return round_open($pid, 'mines', $bet, ['n' => $n, 'mines' => array_slice(csprng_shuffle(range(0, 24)), 0, $n), 'open' => []]);
        }
        if (!$r) { throw new DomainException('Start a round first.'); }
        $s = st($r);
        if ($move === 'cashout') {
            if (!$s['open']) { throw new DomainException('Flip at least one tile first.'); }
            return round_close($r, $s, (int)floor($r['bet'] * mines_mult($s['n'], count($s['open']))), 'cashout');
        }
        $t = (int)($_POST['tile'] ?? -1);
        if ($move !== 'reveal' || $t < 0 || $t > 24 || in_array($t, $s['open'], true)) { throw new DomainException('Pick a covered tile.'); }
        if (in_array($t, $s['mines'], true)) { $s['boom'] = $t; return round_close($r, $s, 0, 'boom'); }
        $s['open'][] = $t;
        if (count($s['open']) === 25 - $s['n']) {
            return round_close($r, $s, (int)floor($r['bet'] * mines_mult($s['n'], count($s['open']))), 'cleared');
        }
        return round_save($r, $s);
    });
    $s = st($r);
    $k = count($s['open']);
    $msg = match ($r['outcome']) {
        null => $k ? $k . ' pearl' . ($k > 1 ? 's' : '') . ' · ' . number_format(mines_mult($s['n'], $k), 2) . '×. Keep going or cash out.' : 'Tap a tile.',
        'boom' => 'Urchin! Ouch.', default => 'Cashed ' . number_format(mines_mult($s['n'], $k), 2) . '× · +' . coins((int)$r['payout']) . ' GC',
    };
    return ['payout' => (int)$r['payout'], 'win' => (int)$r['payout'] > 0, 'boom' => $r['outcome'] === 'boom', 'balance' => bal($pid), 'message' => $msg];
}

/* ── Tide Crash ──
 * Crash point: P(crash ≥ m) = 0.99 / m, so any cash-out target returns 99%.
 * The multiplier grows as e^(0.08·t) on SERVER time; the client only draws it.
 */
const CRASH_K = 0.08;
function crash_point(): float {
    $u = random_int(1, 100000000) / 100000000;
    return max(1.0, min(1000.0, floor(99 / $u) / 100));
}
function crash_now(array $s): float { return floor(exp(CRASH_K * (microtime(true) - $s['start'])) * 100) / 100; }
/** Settle a running round if time has already decided it. Returns the (maybe closed) round. */
function crash_resolve(array $r, bool $cashout = false): array {
    $s = st($r);
    $m = crash_now($s);
    if ($s['auto'] > 0 && $s['auto'] <= $s['crash'] && $m >= $s['auto']) {
        $s['cashed'] = $s['auto'];
        return round_close($r, $s, (int)floor($r['bet'] * $s['auto']), 'cashout');
    }
    if ($m >= $s['crash']) { return round_close($r, $s, 0, 'crashed'); }
    if ($cashout) { $s['cashed'] = $m; return round_close($r, $s, (int)floor($r['bet'] * $m), 'cashout'); }
    return $r;
}
function crash_act(): array {
    $p = require_playable(); $g = game_cfg('crash');
    $pid = (int)$p['id']; $move = (string)($_POST['move'] ?? 'peek');
    $bet = 0; $auto = 0.0;
    if ($move === 'launch') {
        $bet = clamp_bet($_POST['bet'] ?? '', $g);
        $a = trim((string)($_POST['auto'] ?? ''));
        if ($a !== '') {
            if (!is_numeric($a) || (float)$a < 1.01 || (float)$a > 1000) { fail('Auto cash-out has to be between 1.01× and 1000×.'); }
            $auto = floor((float)$a * 100) / 100;
        }
    }
    $r = tx(function () use ($pid, $move, $bet, $auto) {
        $r = round_active($pid, 'crash');
        if ($r) { $r = crash_resolve($r, $move === 'cashout'); }
        if ($move === 'launch') {
            if ($r && $r['status'] === 'active') { throw new DomainException('Your wave is still rolling.'); }
            return round_open($pid, 'crash', $bet, ['start' => microtime(true), 'crash' => crash_point(), 'auto' => $auto]);
        }
        return $r ?? round_last($pid, 'crash');
    });
    if (!$r) { fail('Launch a wave first.'); }
    $s = st($r);
    $live = $r['status'] === 'active';
    $out = ['live' => $live, 'id' => (int)$r['id'], 'payout' => (int)$r['payout'], 'win' => (int)$r['payout'] > 0, 'balance' => bal($pid)];
    if ($live) {
        $out += ['elapsed' => microtime(true) - $s['start'], 'm' => crash_now($s), 'auto' => $s['auto'], 'k' => CRASH_K, 'message' => 'Riding the wave…'];
    } else {
        $out += ['crash' => $s['crash'], 'cashed' => $s['cashed'] ?? null,
            'message' => $r['outcome'] === 'crashed' ? 'Wave broke at ' . number_format($s['crash'], 2) . '×' : 'Cashed at ' . number_format($s['cashed'], 2) . '× · +' . coins((int)$r['payout']) . ' GC'];
    }
    return $out;
}

const GAME_ENGINES = [
    'dice' => 'dice_play', 'plinko' => 'plinko_play', 'keno' => 'keno_play', 'scratch' => 'scratch_play',
    'bigwheel' => 'bigwheel_play', 'sicbo' => 'sicbo_play', 'crabs' => 'crabs_play', 'baccarat' => 'baccarat_play',
    'videopoker' => 'videopoker_act', 'threecard' => 'threecard_act', 'hilo' => 'hilo_act', 'mines' => 'mines_act', 'crash' => 'crash_act',
    'roulette3d' => 'roulette3d_play', 'craps' => 'craps_act', 'pusher' => 'pusher_play',
    'abyss' => 'vs_play', 'tinfoil' => 'vs_play', 'blacksite' => 'vs_play', 'coderain' => 'vs_play', 'tiki' => 'vs_play', 'calavera' => 'vs_play',
];

function play_game(): never {
    csrf_check();
    $slug = (string)($_GET['g'] ?? '');
    $fn = GAME_ENGINES[$slug] ?? null;
    if (!$fn) { fail('No such game.', 404); }
    $r = $fn();
    if (wants_json()) { $r['html'] = game_panel($slug); ok($r); }
    flash(!empty($r['win']) ? 'ok' : 'info', $r['message'] ?? 'Done.');
    redirect(url($slug));
}

/* ═════════════════════════ SLOT HALL: themed 243-ways video slots ═════════════════════════
 * 5 reels × 3 rows, every cell drawn independently by weight (wild only on reels 2–4).
 * A win is a symbol on adjacent reels from the left; ways = product of matching cells per reel.
 * 3+ scatters anywhere pay and trigger free spins at a fixed multiplier (no retriggers).
 * Because cells are independent, RTP has a closed form:
 *   RTP = ways + scatter + Σ P(n scatters)·spins(n)·mult·(ways + scatter)
 * Each table below was solved to 95.0–95.8% and checked by simulation.
 */
const VSLOTS = [
    'tiki' => [
        'name' => 'Tiki Tides', 'blurb' => 'Laid-back luau. Frequent wins, volcano free spins at 2×.', 'sort' => 44,
        'w' => ['H1' => 40, 'H2' => 60, 'H3' => 80, 'H4' => 100, 'L1' => 160, 'L2' => 180, 'L3' => 200, 'L4' => 220, 'L5' => 240, 'W' => 64, 'S' => 40],
        'pays' => ['H1' => [1.8, 5.5, 18.3], 'H2' => [1.5, 3.7, 11], 'H3' => [1.1, 2.7, 7.3], 'H4' => [0.91, 2.2, 5.5], 'L1' => [0.37, 0.91, 2.7], 'L2' => [0.37, 0.73, 2.2], 'L3' => [0.27, 0.73, 1.8], 'L4' => [0.27, 0.55, 1.5], 'L5' => [0.18, 0.55, 1.1]],
        'fs' => [3 => 10, 4 => 15, 5 => 20], 'mult' => 2,
        'bonus' => ['type' => 'wheel', 'name' => 'Volcano Wheel'],
    ],
    'calavera' => [
        'name' => 'Calavera Fiesta', 'blurb' => 'Día de los Muertos under the marigolds. 12+ free spins at 2×.', 'sort' => 45,
        'w' => ['H1' => 40, 'H2' => 60, 'H3' => 80, 'H4' => 100, 'L1' => 160, 'L2' => 180, 'L3' => 200, 'L4' => 220, 'L5' => 240, 'W' => 52, 'S' => 40],
        'pays' => ['H1' => [2, 6.1, 20.2], 'H2' => [1.6, 4, 12.1], 'H3' => [1.2, 3, 8.1], 'H4' => [1, 2.4, 6.1], 'L1' => [0.4, 1, 3], 'L2' => [0.4, 0.81, 2.4], 'L3' => [0.3, 0.81, 2], 'L4' => [0.3, 0.61, 1.6], 'L5' => [0.2, 0.61, 1.2]],
        'fs' => [3 => 12, 4 => 16, 5 => 24], 'mult' => 2,
        'bonus' => ['type' => 'wheel', 'name' => 'Fiesta Wheel'],
    ],
    'abyss' => [
        'name' => 'Abyss Critters', 'blurb' => 'Glow-in-the-dark deep sea. Kraken wilds, pearl-clam free spins at 3×.', 'sort' => 40,
        'w' => ['H1' => 40, 'H2' => 60, 'H3' => 80, 'H4' => 100, 'L1' => 160, 'L2' => 180, 'L3' => 200, 'L4' => 220, 'L5' => 240, 'W' => 48, 'S' => 36],
        'pays' => ['H1' => [2.1, 6.3, 21], 'H2' => [1.7, 4.2, 12.6], 'H3' => [1.3, 3.1, 8.4], 'H4' => [1, 2.5, 6.3], 'L1' => [0.42, 1, 3.1], 'L2' => [0.42, 0.84, 2.5], 'L3' => [0.31, 0.84, 2.1], 'L4' => [0.31, 0.63, 1.7], 'L5' => [0.21, 0.63, 1.3]],
        'fs' => [3 => 10, 4 => 15, 5 => 25], 'mult' => 3,
        'bonus' => ['type' => 'pick', 'name' => 'Sunken Treasure', 'tile' => 'clam'],
    ],
    'tinfoil' => [
        'name' => 'Tinfoil Hat', 'blurb' => 'They don\'t want you to know about these free spins. UFO scatters, 3× bonus.', 'sort' => 41,
        'w' => ['H1' => 40, 'H2' => 60, 'H3' => 80, 'H4' => 100, 'L1' => 160, 'L2' => 180, 'L3' => 200, 'L4' => 220, 'L5' => 240, 'W' => 44, 'S' => 35],
        'pays' => ['H1' => [2.2, 6.7, 22.3], 'H2' => [1.8, 4.5, 13.4], 'H3' => [1.3, 3.3, 8.9], 'H4' => [1.1, 2.7, 6.7], 'L1' => [0.45, 1.1, 3.3], 'L2' => [0.45, 0.89, 2.7], 'L3' => [0.33, 0.89, 2.2], 'L4' => [0.33, 0.67, 1.8], 'L5' => [0.22, 0.67, 1.3]],
        'fs' => [3 => 10, 4 => 14, 5 => 20], 'mult' => 3,
        'bonus' => ['type' => 'pick', 'name' => 'Declassified', 'tile' => 'file'],
    ],
    'blacksite' => [
        'name' => 'Black Site Breach', 'blurb' => 'Crack the vault. Keycard wilds, classified-file free spins at 4×.', 'sort' => 42,
        'w' => ['H1' => 32, 'H2' => 52, 'H3' => 80, 'H4' => 100, 'L1' => 160, 'L2' => 180, 'L3' => 200, 'L4' => 220, 'L5' => 240, 'W' => 40, 'S' => 32],
        'pays' => ['H1' => [2.2, 6.6, 22], 'H2' => [1.8, 4.4, 13.2], 'H3' => [1.3, 3.3, 8.8], 'H4' => [1.1, 2.6, 6.6], 'L1' => [0.44, 1.1, 3.3], 'L2' => [0.44, 0.88, 2.6], 'L3' => [0.33, 0.88, 2.2], 'L4' => [0.33, 0.66, 1.8], 'L5' => [0.22, 0.66, 1.3]],
        'fs' => [3 => 10, 4 => 15, 5 => 20], 'mult' => 4,
        'bonus' => ['type' => 'pick', 'name' => 'Vault Cracker', 'tile' => 'safe'],
    ],
    'coderain' => [
        'name' => 'Code Rain', 'blurb' => 'Green code falls forever. Rare free spins at a massive 5×.', 'sort' => 43,
        'w' => ['H1' => 30, 'H2' => 50, 'H3' => 80, 'H4' => 100, 'L1' => 160, 'L2' => 180, 'L3' => 200, 'L4' => 220, 'L5' => 240, 'W' => 40, 'S' => 30],
        'pays' => ['H1' => [2.2, 6.7, 22.4], 'H2' => [1.8, 4.5, 13.4], 'H3' => [1.3, 3.4, 9], 'H4' => [1.1, 2.7, 6.7], 'L1' => [0.45, 1.1, 3.4], 'L2' => [0.45, 0.9, 2.7], 'L3' => [0.34, 0.9, 2.2], 'L4' => [0.34, 0.67, 1.8], 'L5' => [0.22, 0.67, 1.3]],
        'fs' => [3 => 8, 4 => 12, 5 => 16], 'mult' => 5,
        'bonus' => ['type' => 'pick', 'name' => 'Mainframe Hack', 'tile' => 'node'],
    ],
];
const VS_SYMS = ['H1', 'H2', 'H3', 'H4', 'L1', 'L2', 'L3', 'L4', 'L5'];
const VS_SCATTER_PAY = [3 => 2, 4 => 10, 5 => 50];
const VS_MAX_WIN = 5000; // × total bet, per spin including its free spins
/* Bonus game: a wild on each of reels 2, 3 and 4 in the base game.
 * P(trigger) = Π over reels 2–4 of 1 − (1 − p_wild)³, which runs from about 1 in 430 (Tiki) to 1 in 1,500 (Code Rain).
 * The pick bonus draws 3 prizes from VS_PICK (EV 6.76× each, 20.28× total). The wheel draws one stop from VS_WHEEL (EV 14.13×).
 * The bonus value is independent of the grid, so RTP = base + free spins + P(trigger)·E[bonus]. Each paytable was re-solved to 95–95.6%.
 */
const VS_PICK = [2 => 3000, 3 => 2500, 5 => 1800, 8 => 1200, 10 => 800, 15 => 400, 25 => 200, 75 => 70, 250 => 25, 1000 => 5];   // per 10,000
const VS_WHEEL = [5 => 220, 8 => 200, 10 => 170, 12 => 140, 15 => 110, 20 => 70, 25 => 50, 40 => 25, 75 => 10, 250 => 4, 1000 => 1]; // per 1,000
const VS_WHEEL_SEGS = [5, 20, 8, 1000, 10, 40, 12, 75, 5, 25, 8, 250, 10, 15, 12, 25];
const VS_JP = [25 => 'Mini', 75 => 'Minor', 250 => 'Major', 1000 => 'Grand'];
function vs_weighted(array $table): int {
    $roll = random_int(1, array_sum($table));
    foreach ($table as $v => $n) { if (($roll -= $n) <= 0) { return (int)$v; } }
    return (int)array_key_first($table);
}
function vs_bonus_hit(array $grid): bool {
    return in_array('W', $grid[1], true) && in_array('W', $grid[2], true) && in_array('W', $grid[3], true);
}
/** Draw a bonus outcome. 'x' is × total bet. */
function vs_bonus(array $t): array {
    $b = $t['bonus'];
    if ($b['type'] === 'wheel') {
        $v = vs_weighted(VS_WHEEL);
        $stops = array_keys(VS_WHEEL_SEGS, $v, true);
        return ['type' => 'wheel', 'name' => $b['name'], 'segments' => VS_WHEEL_SEGS, 'stop' => $stops[random_int(0, count($stops) - 1)], 'x' => $v];
    }
    $picks = [vs_weighted(VS_PICK), vs_weighted(VS_PICK), vs_weighted(VS_PICK)];
    $others = []; for ($i = 0; $i < 9; $i++) { $others[] = vs_weighted(VS_PICK); }
    return ['type' => 'pick', 'name' => $b['name'], 'tile' => $b['tile'] ?? '', 'picks' => $picks, 'others' => $others, 'x' => array_sum($picks)];
}

function vs_draw(array $w, int $reel): string {
    $pool = $w;
    if ($reel === 0 || $reel === 4) { unset($pool['W']); }
    $roll = random_int(1, array_sum($pool));
    foreach ($pool as $s => $n) { if (($roll -= $n) <= 0) { return $s; } }
    return 'L5';
}
function vs_grid(array $w): array {
    $g = [];
    for ($r = 0; $r < 5; $r++) { for ($y = 0; $y < 3; $y++) { $g[$r][$y] = vs_draw($w, $r); } }
    return $g;
}
/** Evaluate a grid: ways wins + scatter count. Returns multiples of total bet. */
function vs_eval(array $grid, array $pays): array {
    $wins = []; $total = 0.0;
    foreach (VS_SYMS as $s) {
        $ways = 1; $k = 0; $cells = [];
        for ($r = 0; $r < 5; $r++) {
            $c = 0;
            foreach ($grid[$r] as $y => $v) { if ($v === $s || $v === 'W') { $c++; $cells[] = [$r, $y]; } }
            if (!$c) { break; }
            $ways *= $c; $k++;
        }
        if ($k >= 3) {
            $cells = array_values(array_filter($cells, fn($x) => $x[0] < $k));
            $m = $pays[$s][$k - 3] * $ways;
            $total += $m;
            $wins[] = ['sym' => $s, 'k' => $k, 'ways' => $ways, 'x' => $m, 'cells' => $cells];
        }
    }
    $sc = [];
    foreach ($grid as $r => $col) { foreach ($col as $y => $v) { if ($v === 'S') { $sc[] = [$r, $y]; } } }
    $n = count($sc);
    if ($n >= 3) { $total += VS_SCATTER_PAY[min($n, 5)]; }
    usort($wins, fn($a, $b) => $b['x'] <=> $a['x']);
    return ['wins' => $wins, 'x' => $total, 'scatters' => $sc];
}

function vs_play(): array {
    $slug = (string)($_GET['g'] ?? '');
    $t = VSLOTS[$slug] ?? null;
    if (!$t) { fail('No such slot.', 404); }
    $p = require_playable(); $g = game_cfg($slug);
    $bet = clamp_bet($_POST['bet'] ?? '', $g);

    $base = vs_grid($t['w']);
    $ev = vs_eval($base, $t['pays']);
    $x = $ev['x'];
    $bonus = null;
    if (vs_bonus_hit($base)) { $bonus = vs_bonus($t); $x += $bonus['x']; $bonus['win'] = (int)floor($bet * $bonus['x']); }
    $fs = null;
    $n = count($ev['scatters']);
    if ($n >= 3) {
        $count = $t['fs'][min($n, 5)];
        $spins = []; $fx = 0.0;
        for ($i = 0; $i < $count; $i++) {
            $gr = vs_grid($t['w']);
            $e = vs_eval($gr, $t['pays']);
            $m = $e['x'] * $t['mult'];
            $fx += $m;
            $spins[] = ['grid' => $gr, 'wins' => $e['wins'], 'scatters' => $e['scatters'], 'win' => (int)floor($bet * $m)];
        }
        $x += $fx;
        $fs = ['count' => $count, 'mult' => $t['mult'], 'spins' => $spins, 'win' => (int)floor($bet * $fx)];
    }
    $capped = $x > VS_MAX_WIN;
    $x = min($x, VS_MAX_WIN);
    $payout = (int)floor($bet * $x);
    $baseWin = (int)floor($bet * $ev['x']);
    $pid = (int)$p['id'];
    tx(fn() => round_oneshot($pid, $slug, $bet, $payout, $bonus ? 'bonus ' . $bonus['x'] . 'x' : ($fs ? 'free spins' : ($payout ? round($x, 2) . 'x' : 'no win')),
        ['grid' => $base, 'x' => round($x, 4), 'fs' => $fs ? ['count' => $fs['count'], 'win' => $fs['win']] : null, 'bonus' => $bonus ? ['name' => $bonus['name'], 'x' => $bonus['x'], 'win' => $bonus['win']] : null]));
    $wm = $payout / max(1, $bet);
    $jp = $bonus ? array_values(array_filter($bonus['type'] === 'wheel' ? [$bonus['x']] : $bonus['picks'], fn($v) => isset(VS_JP[$v]))) : [];
    return ['grid' => $base, 'wins' => $ev['wins'], 'scatters' => $ev['scatters'], 'base_win' => $baseWin, 'fs' => $fs, 'bonus' => $bonus,
        'payout' => $payout, 'bet' => $bet, 'x' => round($x, 2), 'capped' => $capped, 'win' => $payout > $bet, 'balance' => bal($pid),
        'tier' => $wm >= 50 ? 'epic' : ($wm >= 20 ? 'mega' : ($wm >= 8 ? 'big' : '')),
        'message' => $bonus ? $bonus['name'] . ($jp ? ' ' . strtoupper(VS_JP[max($jp)]) . ' JACKPOT' : ' bonus') . '! Total +' . coins($payout) . ' GC'
            : ($fs ? $fs['count'] . ' free spins at ' . $t['mult'] . '×! Total +' . coins($payout) . ' GC'
            : ($payout ? 'Win +' . coins($payout) . ' GC' : 'No win. Spin again?'))];
}

const VS_ART = [
    'abyss' => [
        'W' => ['name' => 'Kraken', 'svg' => '<defs><radialGradient id="abyss-W-g1" cx="0.4" cy="0.3" r="0.75"><stop offset="0" stop-color="#f08cff"/><stop offset="0.55" stop-color="#b03ad8"/><stop offset="1" stop-color="#5a1484"/></radialGradient><linearGradient id="abyss-W-g2" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#fff0a0"/><stop offset="0.5" stop-color="#ffc83a"/><stop offset="1" stop-color="#c07a08"/></linearGradient><radialGradient id="abyss-W-g3"><stop offset="0" stop-color="#d45cff" stop-opacity="0.6"/><stop offset="1" stop-color="#d45cff" stop-opacity="0"/></radialGradient></defs><circle cx="32" cy="28" r="30" fill="url(#abyss-W-g3)"/><g fill="none" stroke-linecap="round"><path d="M18 34C8 36 3 44 8 50C12 54 17 50 14 46" stroke="#4a0f6e" stroke-width="8"/><path d="M46 34C56 36 61 44 56 50C52 54 47 50 50 46" stroke="#4a0f6e" stroke-width="8"/><path d="M18 34C8 36 3 44 8 50C12 54 17 50 14 46" stroke="#a62fd0" stroke-width="5"/><path d="M46 34C56 36 61 44 56 50C52 54 47 50 50 46" stroke="#a62fd0" stroke-width="5"/></g><path d="M13 32C13 14 21 6 32 6S51 14 51 32C51 41 43 44 32 44S13 41 13 32Z" fill="url(#abyss-W-g1)" stroke="#3a0a58" stroke-width="2"/><polygon points="22,9 25,1 29,7 32,0 35,7 39,1 42,9" fill="url(#abyss-W-g2)" stroke="#7a4a00" stroke-width="1.2" stroke-linejoin="round"/><circle cx="32" cy="4" r="1.6" fill="#5ff6ff"/><ellipse cx="22" cy="17" rx="5" ry="3" fill="#fff" opacity="0.4" transform="rotate(-35 22 17)"/><g fill="#ff7ad9"><circle cx="41" cy="15" r="2"/><circle cx="46" cy="21" r="1.4"/><circle cx="18" cy="26" r="1.4"/></g><circle cx="24.5" cy="29" r="6" fill="#fff"/><circle cx="39.5" cy="29" r="6" fill="#fff"/><circle cx="25" cy="29.5" r="4" fill="#00e5ff"/><circle cx="39" cy="29.5" r="4" fill="#00e5ff"/><circle cx="25" cy="29.5" r="2" fill="#001a2e"/><circle cx="39" cy="29.5" r="2" fill="#001a2e"/><circle cx="26.5" cy="27.5" r="1.3" fill="#fff"/><circle cx="40.5" cy="27.5" r="1.3" fill="#fff"/><path d="M22 22L28 24M42 22L36 24" stroke="#3a0a58" stroke-width="2" stroke-linecap="round"/><path d="M28 38Q32 41 36 38" fill="none" stroke="#3a0a58" stroke-width="2" stroke-linecap="round"/><rect x="9" y="46" width="46" height="15" rx="4" fill="url(#abyss-W-g2)" stroke="#6a3c00" stroke-width="1.6"/><text x="32" y="58" text-anchor="middle" font-family="Limelight" font-size="12" fill="#3a0a58">WILD</text>'],
        'S' => ['name' => 'Pearl Clam', 'svg' => '<defs><radialGradient id="abyss-S-g1"><stop offset="0.55" stop-color="#5ff6ff" stop-opacity="0.45"/><stop offset="1" stop-color="#5ff6ff" stop-opacity="0"/></radialGradient><radialGradient id="abyss-S-g2" cx="0.35" cy="0.35" r="0.7"><stop offset="0" stop-color="#ffffff"/><stop offset="0.6" stop-color="#e0f4ff"/><stop offset="1" stop-color="#8fc8ff"/></radialGradient><linearGradient id="abyss-S-g3" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffb3d1"/><stop offset="1" stop-color="#d84a86"/></linearGradient></defs><circle cx="32" cy="30" r="30" fill="url(#abyss-S-g1)"/><circle cx="32" cy="30" r="27" fill="none" stroke="#5ff6ff" stroke-width="2.5"/><path d="M9 33C9 15 20 7 32 7S55 15 55 33Z" fill="url(#abyss-S-g3)" stroke="#8a1f55" stroke-width="1.8" stroke-linejoin="round"/><g stroke="#a8306a" stroke-width="1.4" fill="none"><path d="M32 33L32 9M32 33L20 12M32 33L44 12M32 33L12 21M32 33L52 21"/></g><path d="M14 34C14 24 22 18 32 18S50 24 50 34Z" fill="#3a0c4a"/><circle cx="32" cy="28" r="13" fill="#bfefff" opacity="0.3"/><circle cx="32" cy="28" r="9.5" fill="url(#abyss-S-g2)" stroke="#6ab0e8" stroke-width="1"/><ellipse cx="29" cy="25" rx="3" ry="2" fill="#fff"/><path d="M6 35Q32 29 58 35Q54 50 32 51Q10 50 6 35Z" fill="#ec6fa0" stroke="#8a1f55" stroke-width="1.8" stroke-linejoin="round"/><g stroke="#b83a78" stroke-width="1.3" fill="none"><path d="M32 51L32 34M22 49L19 34M42 49L45 34M14 44L10 35M50 44L54 35"/></g><polygon points="8,49 14,48 13,56 16,62 8,58 4,61" fill="#0a8a9a"/><polygon points="56,49 50,48 51,56 48,62 56,58 60,61" fill="#0a8a9a"/><rect x="12" y="47" width="40" height="12" rx="2" fill="#11c6d8" stroke="#05606e" stroke-width="1.4"/><text x="32" y="56.5" text-anchor="middle" font-family="Figtree, sans-serif" font-weight="900" font-size="9" fill="#fff" letter-spacing="1">BONUS</text>'],
        'H1' => ['name' => 'Anglerfish', 'svg' => '<defs><radialGradient id="abyss-H1-g1" cx="0.45" cy="0.35" r="0.7"><stop offset="0" stop-color="#4f6aa8"/><stop offset="1" stop-color="#141e3c"/></radialGradient><radialGradient id="abyss-H1-g2"><stop offset="0" stop-color="#fffbd0" stop-opacity="0.95"/><stop offset="0.4" stop-color="#ffe14a" stop-opacity="0.6"/><stop offset="1" stop-color="#ffe14a" stop-opacity="0"/></radialGradient></defs><path d="M12 36L3 24L6 36L3 48Z" fill="#2f4378" stroke="#5ff6ff" stroke-width="1.4" stroke-linejoin="round"/><path d="M22 18L26 10L30 17L34 11L37 17Z" fill="#ff6fa8" stroke="#8a1f55" stroke-width="1" stroke-linejoin="round"/><path d="M9 36C9 21 21 14 35 15C48 16 58 26 58 37C58 49 46 57 33 57C19 57 9 49 9 36Z" fill="url(#abyss-H1-g1)" stroke="#5ff6ff" stroke-width="1.6"/><path d="M36 36Q48 31 58 33L58 43Q50 52 36 45Z" fill="#3b0a24" stroke="#1a0010" stroke-width="1"/><path d="M38 36L40 40L42 35L44 39L46 34L48 38L50 33L52 37L54 33L56 36L57 33" fill="#fff" stroke="#fff" stroke-width="0.8" stroke-linejoin="round"/><path d="M39 45L41 42L43 46L45 42L47 46L49 41L51 45L53 40L55 43" fill="#fff" stroke="#fff" stroke-width="0.8" stroke-linejoin="round"/><path d="M20 44Q16 52 24 52Q24 47 20 44Z" fill="#ff6fa8" stroke="#8a1f55" stroke-width="1"/><ellipse cx="22" cy="26" rx="6" ry="3.5" fill="#fff" opacity="0.2" transform="rotate(-25 22 26)"/><g fill="#5ff6ff"><circle cx="18" cy="38" r="1.2"/><circle cx="24" cy="46" r="1"/><circle cx="15" cy="30" r="1"/></g><circle cx="38" cy="27" r="5.5" fill="#fff" stroke="#0a1024" stroke-width="1"/><circle cx="39.5" cy="27.5" r="3" fill="#0a1024"/><circle cx="40.5" cy="26" r="1.1" fill="#fff"/><path d="M31 22L43 23" stroke="#0a1024" stroke-width="2" stroke-linecap="round"/><path d="M36 16C34 5 46 0 52 8" fill="none" stroke="#2f4378" stroke-width="2.6" stroke-linecap="round"/><circle cx="52" cy="11" r="10" fill="url(#abyss-H1-g2)"/><circle cx="52" cy="11" r="4.5" fill="#ffd21f" stroke="#b07a00" stroke-width="1"/><circle cx="50.5" cy="9.5" r="1.6" fill="#fff"/>'],
        'H2' => ['name' => 'Great White Shark', 'svg' => '<defs><linearGradient id="abyss-H2-g1" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#a9bfd4"/><stop offset="1" stop-color="#4e6a88"/></linearGradient></defs><path d="M27 22L33 5L40 22Z" fill="#5c7898" stroke="#1d2e44" stroke-width="1.6" stroke-linejoin="round"/><path d="M50 30L61 14L57 34L62 52L49 40Z" fill="#5c7898" stroke="#1d2e44" stroke-width="1.6" stroke-linejoin="round"/><path d="M3 36C10 22 30 17 46 26C50 29 52 33 52 35C52 38 50 41 46 43C32 52 12 50 3 36Z" fill="url(#abyss-H2-g1)" stroke="#1d2e44" stroke-width="1.8" stroke-linejoin="round"/><path d="M5 38C14 47 32 49 46 42C34 43 18 43 5 38Z" fill="#f4f8fb"/><path d="M26 42L20 56L34 44Z" fill="#5c7898" stroke="#1d2e44" stroke-width="1.6" stroke-linejoin="round"/><path d="M5 37Q12 44 22 39Q14 40 5 37Z" fill="#7a1030"/><path d="M7 38L9 40.5L11 39L13 41.5L15 40L17 42L19 40.2L21 40" fill="none" stroke="#fff" stroke-width="1.4" stroke-linejoin="round"/><g stroke="#2d4460" stroke-width="1.3" stroke-linecap="round"><path d="M27 29L25 36M30 29L28 36M33 29L31 36"/></g><ellipse cx="22" cy="24" rx="8" ry="2.5" fill="#fff" opacity="0.45" transform="rotate(-12 22 24)"/><circle cx="15" cy="31" r="3" fill="#fff"/><circle cx="15.5" cy="31" r="1.9" fill="#0a1024"/><circle cx="16" cy="30.3" r="0.7" fill="#fff"/><path d="M11 27L19 28.5" stroke="#1d2e44" stroke-width="1.8" stroke-linecap="round"/>'],
        'H3' => ['name' => 'Sea Turtle', 'svg' => '<defs><radialGradient id="abyss-H3-g1" cx="0.4" cy="0.35" r="0.7"><stop offset="0" stop-color="#6ccf6a"/><stop offset="1" stop-color="#1e6b3a"/></radialGradient></defs><g fill="#9ad67a" stroke="#2f5a26" stroke-width="1.5" stroke-linejoin="round"><path d="M18 26C8 18 3 20 4 26C8 30 14 32 20 32Z"/><path d="M46 26C56 18 61 20 60 26C56 30 50 32 44 32Z"/><path d="M21 46C14 50 12 57 16 58C20 56 24 52 25 48Z"/><path d="M43 46C50 50 52 57 48 58C44 56 40 52 39 48Z"/><path d="M29 52L32 60L35 52Z"/></g><ellipse cx="32" cy="10" rx="7.5" ry="7.5" fill="#9ad67a" stroke="#2f5a26" stroke-width="1.5"/><circle cx="28.5" cy="9" r="2" fill="#0a1024"/><circle cx="35.5" cy="9" r="2" fill="#0a1024"/><circle cx="29" cy="8.3" r="0.7" fill="#fff"/><circle cx="36" cy="8.3" r="0.7" fill="#fff"/><path d="M30 13Q32 14.5 34 13" fill="none" stroke="#2f5a26" stroke-width="1.2" stroke-linecap="round"/><ellipse cx="32" cy="35" rx="17" ry="19" fill="#c8a24a" stroke="#4a3510" stroke-width="1.8"/><ellipse cx="32" cy="35" rx="14.5" ry="16.5" fill="url(#abyss-H3-g1)"/><g fill="none" stroke="#b9ec8a" stroke-width="1.4" stroke-linejoin="round"><polygon points="32,28 38,32 38,39 32,43 26,39 26,32"/><path d="M32 28L32 19M38 32L45 27M38 39L45 44M32 43L32 51M26 39L19 44M26 32L19 27"/></g><ellipse cx="25" cy="25" rx="4" ry="2.5" fill="#fff" opacity="0.35" transform="rotate(-35 25 25)"/>'],
        'H4' => ['name' => 'Octopus', 'svg' => '<defs><radialGradient id="abyss-H4-g1" cx="0.4" cy="0.3" r="0.75"><stop offset="0" stop-color="#ffc26a"/><stop offset="0.6" stop-color="#ff7f1f"/><stop offset="1" stop-color="#c24a08"/></radialGradient></defs><g fill="none" stroke-linecap="round"><g stroke="#7a2e04" stroke-width="7.5"><path d="M20 36C12 42 6 44 5 52"/><path d="M26 40C24 48 18 52 20 58"/><path d="M38 40C40 48 46 52 44 58"/><path d="M44 36C52 42 58 44 59 52"/></g><g stroke="#ff8a2a" stroke-width="4.5"><path d="M20 36C12 42 6 44 5 52"/><path d="M26 40C24 48 18 52 20 58"/><path d="M38 40C40 48 46 52 44 58"/><path d="M44 36C52 42 58 44 59 52"/></g></g><g fill="#ffe0b0"><circle cx="10" cy="45" r="1.1"/><circle cx="54" cy="45" r="1.1"/><circle cx="22" cy="51" r="1.1"/><circle cx="42" cy="51" r="1.1"/></g><path d="M12 26C12 12 21 5 32 5S52 12 52 26C52 36 44 42 32 42S12 36 12 26Z" fill="url(#abyss-H4-g1)" stroke="#7a2e04" stroke-width="2"/><ellipse cx="23" cy="14" rx="5" ry="3" fill="#fff" opacity="0.45" transform="rotate(-30 23 14)"/><g fill="#e0620e"><circle cx="40" cy="12" r="2"/><circle cx="45" cy="18" r="1.4"/><circle cx="36" cy="9" r="1.2"/></g><circle cx="25" cy="27" r="4.5" fill="#fff"/><circle cx="39" cy="27" r="4.5" fill="#fff"/><circle cx="25.5" cy="28" r="2.6" fill="#1a0a00"/><circle cx="38.5" cy="28" r="2.6" fill="#1a0a00"/><circle cx="26.5" cy="26.8" r="1" fill="#fff"/><circle cx="39.5" cy="26.8" r="1" fill="#fff"/><ellipse cx="18" cy="33" rx="3" ry="1.6" fill="#ff5a6a" opacity="0.6"/><ellipse cx="46" cy="33" rx="3" ry="1.6" fill="#ff5a6a" opacity="0.6"/><path d="M29 34Q32 37 35 34" fill="none" stroke="#7a2e04" stroke-width="1.8" stroke-linecap="round"/>'],
        'L1' => ['name' => 'Jellyfish', 'svg' => '<defs><radialGradient id="abyss-L1-g1" cx="0.45" cy="0.3" r="0.8"><stop offset="0" stop-color="#ffd6f0"/><stop offset="1" stop-color="#ff5fb8"/></radialGradient></defs><circle cx="32" cy="24" r="20" fill="#ff7ac8" opacity="0.18"/><g fill="none" stroke="#ff9fd6" stroke-width="2.4" stroke-linecap="round" opacity="0.9"><path d="M18 32C15 40 21 46 17 56"/><path d="M26 33C24 42 29 48 26 58"/><path d="M38 33C40 42 35 48 38 58"/><path d="M46 32C49 40 43 46 47 56"/></g><g fill="none" stroke="#ffd0ec" stroke-width="3.5" stroke-linecap="round" opacity="0.8"><path d="M32 33C30 42 34 46 32 52"/></g><path d="M11 31C11 16 20 8 32 8S53 16 53 31Q48 35 43 31Q37.5 35 32 31Q26.5 35 21 31Q16 35 11 31Z" fill="url(#abyss-L1-g1)" stroke="#c2267e" stroke-width="1.8" stroke-linejoin="round" opacity="0.95"/><ellipse cx="22" cy="17" rx="5" ry="3" fill="#fff" opacity="0.6" transform="rotate(-30 22 17)"/><circle cx="27" cy="24" r="1.8" fill="#6a0a40"/><circle cx="37" cy="24" r="1.8" fill="#6a0a40"/>'],
        'L2' => ['name' => 'Seahorse', 'svg' => '<defs><linearGradient id="abyss-L2-g1" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#fff07a"/><stop offset="1" stop-color="#f0a800"/></linearGradient></defs><path d="M24 22L15 26L18 32L14 38L24 38Z" fill="#ff9a3a" stroke="#8a5a00" stroke-width="1.3" stroke-linejoin="round"/><path d="M32 18C22 26 25 34 32 38C39 43 38 52 31 55C26 56 24 50 29 49" fill="none" stroke="#8a5a00" stroke-width="12" stroke-linecap="round"/><path d="M32 18C22 26 25 34 32 38C39 43 38 52 31 55C26 56 24 50 29 49" fill="none" stroke="url(#abyss-L2-g1)" stroke-width="9" stroke-linecap="round"/><path d="M28 30L33 29M30 36L35 35M34 42L38 43M33 48L37 50" stroke="#c88400" stroke-width="1.3" stroke-linecap="round"/><path d="M36 12L50 14Q53 16 50 18L38 21Z" fill="#ffd21f" stroke="#8a5a00" stroke-width="1.5" stroke-linejoin="round"/><circle cx="32" cy="14" r="9" fill="url(#abyss-L2-g1)" stroke="#8a5a00" stroke-width="1.6"/><path d="M26 7L28 2L31 6L34 2L35 7" fill="#ff9a3a" stroke="#8a5a00" stroke-width="1.2" stroke-linejoin="round"/><circle cx="34" cy="13" r="2.4" fill="#fff"/><circle cx="34.6" cy="13" r="1.4" fill="#1a1000"/><ellipse cx="28" cy="10" rx="2.5" ry="1.5" fill="#fff" opacity="0.6"/>'],
        'L3' => ['name' => 'Pufferfish', 'svg' => '<defs><radialGradient id="abyss-L3-g1" cx="0.4" cy="0.35" r="0.7"><stop offset="0" stop-color="#eaffa0"/><stop offset="1" stop-color="#7cc41a"/></radialGradient></defs><path d="M50 34L61 25L59 34L61 43Z" fill="#a8e03a" stroke="#3d6a08" stroke-width="1.4" stroke-linejoin="round"/><polygon points="30.0,9.0 34.2,15.5 40.8,11.5 41.8,19.1 49.5,18.4 47.1,25.8 54.4,28.4 49.0,34.0 54.4,39.6 47.1,42.2 49.5,49.6 41.8,48.9 40.8,56.5 34.2,52.5 30.0,59.0 25.8,52.5 19.2,56.5 18.2,48.9 10.5,49.6 12.9,42.2 5.6,39.6 11.0,34.0 5.6,28.4 12.9,25.8 10.5,18.4 18.2,19.1 19.2,11.5 25.8,15.5" fill="#c8f060" stroke="#3d6a08" stroke-width="1.4" stroke-linejoin="round"/><circle cx="30" cy="34" r="19" fill="url(#abyss-L3-g1)" stroke="#3d6a08" stroke-width="1.8"/><path d="M14 40C18 50 36 54 46 44C38 48 22 48 14 40Z" fill="#fbffe0"/><ellipse cx="22" cy="24" rx="5" ry="3" fill="#fff" opacity="0.55" transform="rotate(-35 22 24)"/><circle cx="21" cy="31" r="4.5" fill="#fff" stroke="#3d6a08" stroke-width="1"/><circle cx="20" cy="31.5" r="2.4" fill="#102000"/><circle cx="19.3" cy="30.5" r="0.9" fill="#fff"/><ellipse cx="14" cy="40" rx="2.4" ry="2" fill="#ff7a8a"/><path d="M34 36Q40 34 40 40Q36 40 34 36Z" fill="#8fd02a" stroke="#3d6a08" stroke-width="1"/>'],
        'L4' => ['name' => 'Starfish', 'svg' => '<defs><radialGradient id="abyss-L4-g1" cx="0.45" cy="0.4" r="0.6"><stop offset="0" stop-color="#ffb08a"/><stop offset="1" stop-color="#e8323a"/></radialGradient></defs><polygon points="32.0,9.0 38.5,25.1 55.8,26.3 42.5,37.4 46.7,54.2 32.0,45.0 17.3,54.2 21.5,37.4 8.2,26.3 25.5,25.1" fill="#8a1018" stroke="#8a1018" stroke-width="8" stroke-linejoin="round"/><polygon points="32.0,9.0 38.5,25.1 55.8,26.3 42.5,37.4 46.7,54.2 32.0,45.0 17.3,54.2 21.5,37.4 8.2,26.3 25.5,25.1" fill="url(#abyss-L4-g1)" stroke="#ff5a4a" stroke-width="5" stroke-linejoin="round"/><g fill="#ffe0c8"><circle cx="32" cy="16" r="1.4"/><circle cx="32" cy="22" r="1.4"/><circle cx="48" cy="30" r="1.4"/><circle cx="42" cy="32" r="1.4"/><circle cx="16" cy="30" r="1.4"/><circle cx="22" cy="32" r="1.4"/><circle cx="42" cy="50" r="1.4"/><circle cx="22" cy="50" r="1.4"/></g><ellipse cx="27" cy="24" rx="3" ry="1.8" fill="#fff" opacity="0.5" transform="rotate(-50 27 24)"/><circle cx="28" cy="35" r="1.8" fill="#3a0008"/><circle cx="36" cy="35" r="1.8" fill="#3a0008"/><path d="M29.5 39Q32 41 34.5 39" fill="none" stroke="#3a0008" stroke-width="1.4" stroke-linecap="round"/>'],
        'L5' => ['name' => 'Clownfish', 'svg' => '<defs><radialGradient id="abyss-L5-g1" cx="0.4" cy="0.35" r="0.7"><stop offset="0" stop-color="#4fb4ff"/><stop offset="1" stop-color="#0b4fa8"/></radialGradient><clipPath id="abyss-L5-c1"><path d="M10 32C10 22 22 16 34 17C44 18 50 25 50 32C50 39 44 46 34 47C22 48 10 42 10 32Z"/></clipPath></defs><circle cx="32" cy="32" r="26" fill="url(#abyss-L5-g1)" stroke="#8fdcff" stroke-width="2"/><ellipse cx="22" cy="17" rx="7" ry="3.5" fill="#fff" opacity="0.3" transform="rotate(-30 22 17)"/><path d="M48 32L58 23L56 32L58 41Z" fill="#ff7a12" stroke="#1a0a00" stroke-width="1.5" stroke-linejoin="round"/><path d="M28 18L34 11L40 19Z" fill="#ff7a12" stroke="#1a0a00" stroke-width="1.5" stroke-linejoin="round"/><path d="M10 32C10 22 22 16 34 17C44 18 50 25 50 32C50 39 44 46 34 47C22 48 10 42 10 32Z" fill="#ff7a12"/><g clip-path="url(#abyss-L5-c1)" stroke="#1a0a00" stroke-width="1.2"><rect x="18" y="10" width="6" height="44" fill="#fff"/><rect x="32" y="10" width="6" height="44" fill="#fff"/><rect x="45" y="10" width="4" height="44" fill="#fff"/></g><path d="M10 32C10 22 22 16 34 17C44 18 50 25 50 32C50 39 44 46 34 47C22 48 10 42 10 32Z" fill="none" stroke="#1a0a00" stroke-width="1.8"/><path d="M26 40L30 46L33 40Z" fill="#ff7a12" stroke="#1a0a00" stroke-width="1.2" stroke-linejoin="round"/><circle cx="15" cy="29" r="2.8" fill="#fff"/><circle cx="14.6" cy="29.3" r="1.7" fill="#1a0a00"/><circle cx="14" cy="28.6" r="0.6" fill="#fff"/><path d="M11 36Q13 37 15 36" fill="none" stroke="#1a0a00" stroke-width="1.2" stroke-linecap="round"/>'],
    ],
    'tinfoil' => [
        'W' => ['name' => 'Tinfoil Hat', 'svg' => '<defs><radialGradient id="tinfoil-W-glow" cx="0.5" cy="0.5" r="0.5"><stop offset="0" stop-color="#7dff8a" stop-opacity="0.55"/><stop offset="1" stop-color="#7dff8a" stop-opacity="0"/></radialGradient><linearGradient id="tinfoil-W-foil" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#ffffff"/><stop offset="0.45" stop-color="#b9c0cc"/><stop offset="0.7" stop-color="#eef1f6"/><stop offset="1" stop-color="#7c8596"/></linearGradient><linearGradient id="tinfoil-W-gold" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffe27a"/><stop offset="1" stop-color="#e08a1e"/></linearGradient></defs><circle cx="32" cy="27" r="27" fill="url(#tinfoil-W-glow)"/><g transform="translate(32 26) scale(1.12) translate(-32 -26)"><line x1="32" y1="9" x2="32" y2="6" stroke="#cfd5de" stroke-width="1.6"/><circle cx="32" cy="6" r="2.4" fill="#7dff8a" stroke="#1d6b2a" stroke-width="0.8"/><polygon points="32,8 38,14 36,18 43,23 41,28 48,34 46,37 53,43 11,43 18,37 16,34 23,28 21,23 28,18 26,14" fill="url(#tinfoil-W-foil)" stroke="#4b5363" stroke-width="1.4" stroke-linejoin="round"/><polyline points="32,8 30,18 35,26 29,34 34,43" fill="none" stroke="#6d7688" stroke-width="1"/><polyline points="21,23 29,27 24,36 18,37" fill="none" stroke="#6d7688" stroke-width="0.9"/><polyline points="43,23 37,29 42,36 48,34" fill="none" stroke="#6d7688" stroke-width="0.9"/><polygon points="31,11 28,18 30,23" fill="#ffffff"/><polygon points="24,28 21,34 25,33" fill="#ffffff" opacity="0.9"/><polygon points="38,17 40,22 36,21" fill="#ffffff" opacity="0.8"/><ellipse cx="32" cy="43.5" rx="23" ry="3.6" fill="#9aa3b3" stroke="#4b5363" stroke-width="1.2"/></g><rect x="9" y="47" width="46" height="13" rx="3.5" fill="url(#tinfoil-W-gold)" stroke="#7a3f0a" stroke-width="1.2"/><text x="32" y="57.3" text-anchor="middle" font-family="Limelight" font-size="10.5" fill="#1b0f3a">WILD</text>'],
        'S' => ['name' => 'UFO', 'svg' => '<defs><radialGradient id="tinfoil-S-halo" cx="0.5" cy="0.5" r="0.5"><stop offset="0.6" stop-color="#5dffb0" stop-opacity="0"/><stop offset="0.85" stop-color="#5dffb0" stop-opacity="0.45"/><stop offset="1" stop-color="#5dffb0" stop-opacity="0"/></radialGradient><linearGradient id="tinfoil-S-beam" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#b6ff7a" stop-opacity="0.85"/><stop offset="1" stop-color="#b6ff7a" stop-opacity="0.1"/></linearGradient><linearGradient id="tinfoil-S-hull" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#f4f6fb"/><stop offset="0.5" stop-color="#aab2c2"/><stop offset="1" stop-color="#5a6275"/></linearGradient></defs><circle cx="32" cy="30" r="29" fill="url(#tinfoil-S-halo)"/><circle cx="32" cy="30" r="25" fill="none" stroke="#5dffb0" stroke-width="1.5" stroke-dasharray="3 3" opacity="0.8"/><polygon points="24,32 40,32 50,52 14,52" fill="url(#tinfoil-S-beam)"/><ellipse cx="32" cy="21" rx="10" ry="9" fill="#6ff0ff" stroke="#1b6a86" stroke-width="1.2"/><ellipse cx="29" cy="17.5" rx="3.5" ry="2.3" fill="#ffffff" opacity="0.85"/><ellipse cx="32" cy="27" rx="25" ry="7.5" fill="url(#tinfoil-S-hull)" stroke="#353b4a" stroke-width="1.4"/><ellipse cx="32" cy="25" rx="16" ry="2.2" fill="#ffffff" opacity="0.7"/><circle cx="15" cy="28.5" r="2" fill="#ffe14a"/><circle cx="24" cy="30.5" r="2" fill="#ff5ad6"/><circle cx="32" cy="31.2" r="2" fill="#ffe14a"/><circle cx="40" cy="30.5" r="2" fill="#ff5ad6"/><circle cx="49" cy="28.5" r="2" fill="#ffe14a"/><polygon points="6,46 12,46 12,58 6,58 9,52" fill="#8a1f7a"/><polygon points="58,46 52,46 52,58 58,58 55,52" fill="#8a1f7a"/><rect x="10" y="45" width="44" height="12" rx="2" fill="#e03aa8" stroke="#6a0f55" stroke-width="1"/><text x="32" y="54.5" text-anchor="middle" font-family="Figtree" font-weight="900" font-size="9.5" fill="#ffffff">BONUS</text>'],
        'H1' => ['name' => 'Grey Alien', 'svg' => '<defs><radialGradient id="tinfoil-H1-skin" cx="0.4" cy="0.3" r="0.8"><stop offset="0" stop-color="#d8ffd0"/><stop offset="0.55" stop-color="#8fdc8a"/><stop offset="1" stop-color="#3f8f55"/></radialGradient><radialGradient id="tinfoil-H1-glow" cx="0.5" cy="0.5" r="0.5"><stop offset="0.5" stop-color="#9dff6a" stop-opacity="0.45"/><stop offset="1" stop-color="#9dff6a" stop-opacity="0"/></radialGradient></defs><circle cx="32" cy="31" r="30" fill="url(#tinfoil-H1-glow)"/><path d="M32 5 C49 5 58 16 56 29 C54 42 41 56 32 59 C23 56 10 42 8 29 C6 16 15 5 32 5Z" fill="url(#tinfoil-H1-skin)" stroke="#1f5a33" stroke-width="1.8"/><path d="M11 28 C13 20 25 21 29 33 C27 38 14 38 11 28Z" fill="#101018"/><path d="M53 28 C51 20 39 21 35 33 C37 38 50 38 53 28Z" fill="#101018"/><ellipse cx="18" cy="27" rx="3.2" ry="2" fill="#ffffff" opacity="0.9" transform="rotate(20 18 27)"/><ellipse cx="46" cy="27" rx="3.2" ry="2" fill="#ffffff" opacity="0.9" transform="rotate(-20 46 27)"/><circle cx="23" cy="32" r="1" fill="#7dff8a"/><circle cx="41" cy="32" r="1" fill="#7dff8a"/><circle cx="30.5" cy="42" r="0.9" fill="#1f5a33"/><circle cx="33.5" cy="42" r="0.9" fill="#1f5a33"/><path d="M28 48 Q32 50.5 36 48" fill="none" stroke="#1f5a33" stroke-width="1.5" stroke-linecap="round"/><path d="M20 11 C25 8 31 8 35 9" fill="none" stroke="#ffffff" stroke-width="2.4" stroke-linecap="round" opacity="0.75"/>'],
        'H2' => ['name' => 'Bigfoot', 'svg' => '<defs><linearGradient id="tinfoil-H2-fur" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#a86a3a"/><stop offset="1" stop-color="#5a3318"/></linearGradient></defs><circle cx="44" cy="16" r="10" fill="#ff9a3c" opacity="0.35"/><path d="M26 40 L17 54 L20 56 L31 44Z" fill="#5a3318" stroke="#2e1a0b" stroke-width="1.2"/><path d="M37 42 L45 55 L49 53 L42 39Z" fill="#6e4020" stroke="#2e1a0b" stroke-width="1.2"/><ellipse cx="16" cy="56" rx="6" ry="2.6" fill="#2e1a0b"/><ellipse cx="49" cy="55.5" rx="6" ry="2.6" fill="#2e1a0b"/><path d="M22 24 C14 30 12 38 13 44 L18 44 C18 38 21 33 26 29Z" fill="#6e4020" stroke="#2e1a0b" stroke-width="1.2"/><path d="M42 24 C50 26 54 32 55 38 L50 40 C49 34 46 31 40 30Z" fill="#6e4020" stroke="#2e1a0b" stroke-width="1.2"/><path d="M20 26 C20 18 26 17 32 17 C38 17 45 18 45 27 C46 37 42 45 32 46 C22 45 19 36 20 26Z" fill="url(#tinfoil-H2-fur)" stroke="#2e1a0b" stroke-width="1.4"/><path d="M22 20 L20 17 L25 18 M40 19 L44 16 L43 21" fill="none" stroke="#2e1a0b" stroke-width="1"/><circle cx="33" cy="13" r="9.5" fill="url(#tinfoil-H2-fur)" stroke="#2e1a0b" stroke-width="1.4"/><path d="M27 5 L29 8 L31 3.5 L33 7 L36 4 L37 8" fill="#8a5530" stroke="#2e1a0b" stroke-width="1" stroke-linejoin="round"/><ellipse cx="33" cy="15" rx="6.5" ry="5.8" fill="#e2b07a"/><circle cx="30.5" cy="13.5" r="1.3" fill="#1a0f06"/><circle cx="35.5" cy="13.5" r="1.3" fill="#1a0f06"/><circle cx="30.9" cy="13.1" r="0.45" fill="#ffffff"/><circle cx="35.9" cy="13.1" r="0.45" fill="#ffffff"/><path d="M30 17.3 Q33 20 36 17.3" fill="none" stroke="#5a3318" stroke-width="1.2" stroke-linecap="round"/><ellipse cx="28" cy="27" rx="4" ry="6" fill="#c08450" opacity="0.6"/>'],
        'H3' => ['name' => 'Lizard Person', 'svg' => '<defs><linearGradient id="tinfoil-H3-skin" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#b6f04a"/><stop offset="1" stop-color="#3f9a2a"/></linearGradient></defs><path d="M8 59 C8 45 17 38 32 38 C47 38 56 45 56 59Z" fill="#23294a" stroke="#0e1128" stroke-width="1.4"/><polygon points="25,38 39,38 32,52" fill="#f4f4f4"/><polygon points="30,40 34,40 35,43 32,54 29,43" fill="#e0263a" stroke="#7a0f1c" stroke-width="0.8"/><polygon points="25,38 22,44 29,49 32,52" fill="#343c68"/><polygon points="39,38 42,44 35,49 32,52" fill="#343c68"/><path d="M13 50 L20 50" stroke="#ffffff" stroke-width="1.2" opacity="0.5"/><path d="M26 32 L38 32 L37 40 L27 40Z" fill="#4faa2e"/><path d="M14 22 C14 11 22 6 32 6 C42 6 50 11 50 22 C50 30 44 35 32 35 C20 35 14 30 14 22Z" fill="url(#tinfoil-H3-skin)" stroke="#1e5a14" stroke-width="1.6"/><path d="M20 26 Q32 34 44 26" fill="none" stroke="#1e5a14" stroke-width="1.6" stroke-linecap="round"/><path d="M24 27.5 L25.5 29.5 L27 28.5 M37 28.5 L38.5 29.5 L40 27.5" fill="none" stroke="#ffffff" stroke-width="1"/><circle cx="22" cy="15" r="6" fill="#ffd23a" stroke="#1e5a14" stroke-width="1.4"/><circle cx="42" cy="15" r="6" fill="#ffd23a" stroke="#1e5a14" stroke-width="1.4"/><ellipse cx="22" cy="15" rx="1.3" ry="4" fill="#111111"/><ellipse cx="42" cy="15" rx="1.3" ry="4" fill="#111111"/><circle cx="29" cy="22" r="0.9" fill="#1e5a14"/><circle cx="35" cy="22" r="0.9" fill="#1e5a14"/><circle cx="28" cy="9" r="1.6" fill="#7fcc34"/><circle cx="36" cy="10" r="1.3" fill="#7fcc34"/><circle cx="32" cy="8" r="1" fill="#7fcc34"/><path d="M18 11 C20 8 23 7 26 7" fill="none" stroke="#ffffff" stroke-width="1.6" stroke-linecap="round" opacity="0.7"/>'],
        'H4' => ['name' => 'All-Seeing Eye', 'svg' => '<defs><linearGradient id="tinfoil-H4-pyr" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#d690ff"/><stop offset="1" stop-color="#6a1fb8"/></linearGradient><radialGradient id="tinfoil-H4-iris" cx="0.5" cy="0.5" r="0.5"><stop offset="0" stop-color="#ffe98a"/><stop offset="1" stop-color="#e09a18"/></radialGradient></defs><g stroke="#ffd35a" stroke-width="2" stroke-linecap="round" opacity="0.8"><line x1="32" y1="6" x2="32" y2="1.5"/><line x1="20" y1="12" x2="15" y2="6"/><line x1="44" y1="12" x2="49" y2="6"/><line x1="12" y1="25" x2="5" y2="21"/><line x1="52" y1="25" x2="59" y2="21"/><line x1="8" y1="40" x2="2" y2="40"/><line x1="56" y1="40" x2="62" y2="40"/></g><polygon points="32,8 58,55 6,55" fill="url(#tinfoil-H4-pyr)" stroke="#ffd35a" stroke-width="2.4" stroke-linejoin="round"/><g stroke="#4a1285" stroke-width="1" opacity="0.7"><line x1="14" y1="47" x2="50" y2="47"/><line x1="10" y1="51" x2="54" y2="51"/><line x1="26" y1="47" x2="24" y2="51"/><line x1="40" y1="47" x2="42" y2="51"/><line x1="32" y1="51" x2="32" y2="55"/></g><path d="M16 36 Q32 20 48 36 Q32 50 16 36Z" fill="#ffffff" stroke="#2a0a52" stroke-width="1.6"/><circle cx="32" cy="36" r="7" fill="url(#tinfoil-H4-iris)" stroke="#7a4a08" stroke-width="1"/><circle cx="32" cy="36" r="3" fill="#1a0a2e"/><circle cx="29.5" cy="33.5" r="1.6" fill="#ffffff"/><polygon points="32,12 35,18 29,18" fill="#ffffff" opacity="0.5"/>'],
        'L1' => ['name' => 'Crop Circle', 'svg' => '<defs><linearGradient id="tinfoil-L1-field" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#ffe07a"/><stop offset="1" stop-color="#e0a02e"/></linearGradient></defs><rect x="7" y="7" width="50" height="50" rx="5" fill="url(#tinfoil-L1-field)" stroke="#7a4a10" stroke-width="1.6"/><g stroke="#b87a1e" stroke-width="1.1" opacity="0.75"><line x1="14" y1="9" x2="10" y2="55"/><line x1="19" y1="9" x2="15" y2="55"/><line x1="24" y1="9" x2="20" y2="55"/><line x1="29" y1="9" x2="25" y2="55"/><line x1="34" y1="9" x2="30" y2="55"/><line x1="39" y1="9" x2="35" y2="55"/><line x1="44" y1="9" x2="40" y2="55"/><line x1="49" y1="9" x2="45" y2="55"/><line x1="54" y1="9" x2="50" y2="55"/><line x1="59" y1="9" x2="55" y2="55"/></g><circle cx="32" cy="32" r="15" fill="none" stroke="#fff4c8" stroke-width="3.2"/><circle cx="32" cy="32" r="7" fill="#fff4c8"/><circle cx="32" cy="32" r="3" fill="#e0a02e"/><g fill="#fff4c8"><circle cx="32" cy="12.5" r="3.2"/><circle cx="32" cy="51.5" r="3.2"/><circle cx="12.5" cy="32" r="3.2"/><circle cx="51.5" cy="32" r="3.2"/></g><g stroke="#fff4c8" stroke-width="1.8"><line x1="32" y1="15" x2="32" y2="17"/><line x1="32" y1="47" x2="32" y2="49"/><line x1="15" y1="32" x2="17" y2="32"/><line x1="47" y1="32" x2="49" y2="32"/></g><g fill="#fff4c8"><circle cx="21" cy="21" r="1.8"/><circle cx="43" cy="21" r="1.8"/><circle cx="21" cy="43" r="1.8"/><circle cx="43" cy="43" r="1.8"/></g>'],
        'L2' => ['name' => 'Black Helicopter', 'svg' => '<defs><linearGradient id="tinfoil-L2-beam" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#fff38a" stop-opacity="0.9"/><stop offset="1" stop-color="#fff38a" stop-opacity="0.05"/></linearGradient></defs><polygon points="24,36 30,38 22,60 6,60" fill="url(#tinfoil-L2-beam)"/><rect x="6" y="11" width="52" height="3" rx="1.5" fill="#8a93a8"/><rect x="30" y="13" width="4" height="6" fill="#3a3f4c"/><path d="M16 30 C16 22 22 18 32 18 C40 18 44 22 45 26 L58 25 L58 30 L44 33 C42 38 36 40 28 40 C21 40 16 36 16 30Z" fill="#1c1f27" stroke="#8a93a8" stroke-width="1.4" stroke-linejoin="round"/><rect x="55" y="20" width="3" height="10" rx="1" fill="#1c1f27" stroke="#8a93a8" stroke-width="1"/><path d="M19 29 C19 24 22 21 27 21 L28 30Z" fill="#4a6a8a" stroke="#8a93a8" stroke-width="0.8"/><path d="M21 25 L24 22" stroke="#cfe4ff" stroke-width="1.2" stroke-linecap="round"/><circle cx="25" cy="37" r="2.4" fill="#fff38a"/><g stroke="#8a93a8" stroke-width="1.6" stroke-linecap="round"><line x1="22" y1="40" x2="20" y2="46"/><line x1="36" y1="40" x2="38" y2="46"/><line x1="16" y1="46" x2="44" y2="46"/></g>'],
        'L3' => ['name' => 'Moon Landing', 'svg' => '<defs><radialGradient id="tinfoil-L3-moon" cx="0.4" cy="0.35" r="0.7"><stop offset="0" stop-color="#ffffff"/><stop offset="1" stop-color="#a9b0c4"/></radialGradient></defs><circle cx="40" cy="24" r="18" fill="url(#tinfoil-L3-moon)" stroke="#5d647a" stroke-width="1.4"/><circle cx="34" cy="18" r="3" fill="#bcc2d3"/><circle cx="46" cy="30" r="4" fill="#bcc2d3"/><circle cx="47" cy="17" r="2" fill="#bcc2d3"/><line x1="44" y1="21" x2="44" y2="8" stroke="#5d647a" stroke-width="1.4"/><rect x="44" y="8" width="10" height="6.5" fill="#ffffff" stroke="#5d647a" stroke-width="0.8"/><rect x="44" y="8" width="4" height="3.2" fill="#3a5ad8"/><g stroke="#e0263a" stroke-width="0.9"><line x1="48" y1="9.5" x2="54" y2="9.5"/><line x1="44" y1="12" x2="54" y2="12"/><line x1="44" y1="14" x2="54" y2="14"/></g><g stroke="#2a2e3a" stroke-width="2" stroke-linecap="round"><line x1="20" y1="42" x2="12" y2="58"/><line x1="20" y1="42" x2="28" y2="58"/><line x1="20" y1="42" x2="20" y2="58"/></g><rect x="9" y="31" width="20" height="12" rx="2" fill="#2a2e3a" stroke="#0e1018" stroke-width="1"/><circle cx="13" cy="28" r="4" fill="#3c4150" stroke="#0e1018" stroke-width="1"/><circle cx="22" cy="28" r="4" fill="#3c4150" stroke="#0e1018" stroke-width="1"/><polygon points="29,34 36,31 36,43 29,40" fill="#3c4150" stroke="#0e1018" stroke-width="1"/><circle cx="14" cy="37" r="1.4" fill="#ff3a4a"/><rect x="18" y="35" width="8" height="2" fill="#6b7385"/>'],
        'L4' => ['name' => 'Bermuda Triangle', 'svg' => '<defs><linearGradient id="tinfoil-L4-sea" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#4cc8ff"/><stop offset="1" stop-color="#1640b0"/></linearGradient><clipPath id="tinfoil-L4-clip"><polygon points="32,7 58,54 6,54"/></clipPath></defs><polygon points="32,7 58,54 6,54" fill="url(#tinfoil-L4-sea)" stroke="#0a2466" stroke-width="2" stroke-linejoin="round"/><g clip-path="url(#tinfoil-L4-clip)" fill="none" stroke="#bff0ff" stroke-width="1.4" stroke-linecap="round" opacity="0.8"><path d="M4 26 Q10 23 16 26 T28 26 T40 26 T52 26 T64 26"/><path d="M4 49 Q10 46 16 49 T28 49 T40 49 T52 49 T64 49"/></g><path d="M32 42 a2 2 0 0 1 4 0 a4 4 0 0 1 -8 0 a6 6 0 0 1 12 0 a8 8 0 0 1 -16 0" fill="none" stroke="#ffffff" stroke-width="2.2" stroke-linecap="round"/><polygon points="41,30 49,30 47,33 43,33" fill="#6a3a1a"/><line x1="45" y1="30" x2="45" y2="23" stroke="#3a2010" stroke-width="1"/><polygon points="45,23 49,28 45,28" fill="#ffffff"/><path d="M28 14 L22 25" stroke="#ffffff" stroke-width="1.8" stroke-linecap="round" opacity="0.6"/>'],
        'L5' => ['name' => 'Blurry Evidence Photo', 'svg' => '<defs><linearGradient id="tinfoil-L5-sky" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#3a2a78"/><stop offset="0.65" stop-color="#ff8a3a"/><stop offset="1" stop-color="#c85a1c"/></linearGradient></defs><g transform="rotate(-8 32 32)"><rect x="11" y="7" width="42" height="50" rx="2" fill="#f6f2e6" stroke="#8a8270" stroke-width="1.4"/><rect x="15" y="11" width="34" height="32" fill="url(#tinfoil-L5-sky)"/><ellipse cx="30" cy="30" rx="6" ry="9" fill="#4a2a1a" opacity="0.4"/><ellipse cx="31" cy="29" rx="4.5" ry="7.5" fill="#4a2a1a" opacity="0.5"/><circle cx="31" cy="21" r="3.5" fill="#4a2a1a" opacity="0.55"/><path d="M15 38 L22 34 L28 37 L36 33 L49 38 L49 43 L15 43Z" fill="#7a3a14"/><rect x="18" y="47" width="22" height="1.6" fill="#b8b09a"/></g><path d="M38 26 C38 19 50 19 50 26 C50 31 44 31 44 36 L44 38" fill="none" stroke="#7a0f1c" stroke-width="6" stroke-linecap="round"/><path d="M38 26 C38 19 50 19 50 26 C50 31 44 31 44 36 L44 38" fill="none" stroke="#ff2a3a" stroke-width="3.6" stroke-linecap="round"/><circle cx="44" cy="45" r="3" fill="#ff2a3a" stroke="#7a0f1c" stroke-width="1.2"/>'],
    ],
    'blacksite' => [
        'W' => ['name' => 'Master Keycard', 'svg' => '<defs><linearGradient id="blacksite-W-g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#fff0a8"/><stop offset=".45" stop-color="#e6b422"/><stop offset="1" stop-color="#8a5a06"/></linearGradient><linearGradient id="blacksite-W-c" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#fff6c8"/><stop offset="1" stop-color="#c8911a"/></linearGradient></defs><g transform="rotate(-8 32 28)"><rect x="6" y="7" width="52" height="36" rx="5" fill="#3a2605"/><rect x="7" y="6" width="50" height="34" rx="5" fill="url(#blacksite-W-g)" stroke="#1a1204" stroke-width="1.5"/><rect x="7" y="12" width="50" height="7" fill="#111318"/><rect x="7" y="14.5" width="50" height="2" fill="#7ff4ff"/><rect x="7" y="14" width="50" height="3" fill="#39e6ff" opacity=".35"/><rect x="12" y="23" width="13" height="11" rx="2" fill="url(#blacksite-W-c)" stroke="#5a3a04" stroke-width="1"/><path d="M12 28.5h13M18.5 23v11M15 23v5.5M22 28.5v5.5" stroke="#5a3a04" stroke-width=".9"/><rect x="30" y="24" width="22" height="3" rx="1" fill="#1a1204" opacity=".7"/><rect x="30" y="30" width="15" height="2.5" rx="1" fill="#1a1204" opacity=".5"/><circle cx="51" cy="33" r="3" fill="#ff2a2a" stroke="#1a1204"/><path d="M11 9h30" stroke="#fffbe0" stroke-width="1.5" stroke-linecap="round" opacity=".8"/></g><rect x="8" y="44" width="48" height="15" rx="3" fill="#0b0c10" stroke="#e6b422" stroke-width="2"/><rect x="10" y="46" width="44" height="1" fill="#ff3030"/><text x="32" y="56.5" text-anchor="middle" font-family="Limelight" font-size="12" fill="#ffd54a" letter-spacing="1">WILD</text>'],
        'S' => ['name' => 'Classified Folder', 'svg' => '<defs><radialGradient id="blacksite-S-h"><stop offset=".55" stop-color="#ff3b30" stop-opacity="0"/><stop offset=".8" stop-color="#ff3b30" stop-opacity=".55"/><stop offset="1" stop-color="#ff3b30" stop-opacity="0"/></radialGradient><linearGradient id="blacksite-S-f" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#f3d58e"/><stop offset="1" stop-color="#c49a4a"/></linearGradient></defs><circle cx="32" cy="30" r="29" fill="url(#blacksite-S-h)"/><circle cx="32" cy="30" r="25" fill="none" stroke="#ffb020" stroke-width="1.5" stroke-dasharray="4 3"/><path d="M9 14h16l4 4h26v28H9z" fill="#8a6428"/><rect x="11" y="16" width="40" height="26" fill="#f5f2e8"/><path d="M8 21h48l-3 27H11z" fill="url(#blacksite-S-f)" stroke="#5c4012" stroke-width="1.5"/><path d="M11 24h42" stroke="#fff3cf" stroke-width="1.5" opacity=".8"/><g transform="rotate(-12 32 34)"><rect x="17" y="28" width="30" height="12" rx="1" fill="none" stroke="#d0141a" stroke-width="2.5"/><rect x="21" y="32" width="22" height="2" fill="#d0141a"/><rect x="24" y="35.5" width="16" height="1.8" fill="#d0141a"/></g><path d="M4 49h56l-4 5 4 5H4l4-5z" fill="#d0141a" stroke="#5a0508" stroke-width="1"/><text x="32" y="57.5" text-anchor="middle" font-family="Figtree" font-weight="900" font-size="8.5" fill="#fff" letter-spacing="1">BONUS</text>'],
        'H1' => ['name' => 'Vault Door', 'svg' => '<defs><radialGradient id="blacksite-H1-g" cx=".35" cy=".3"><stop offset="0" stop-color="#e8edf2"/><stop offset=".6" stop-color="#8b95a1"/><stop offset="1" stop-color="#3b424b"/></radialGradient><linearGradient id="blacksite-H1-r" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#5a636e"/><stop offset="1" stop-color="#1c2026"/></linearGradient></defs><circle cx="32" cy="33" r="27" fill="#0a0b0e"/><circle cx="32" cy="32" r="27" fill="url(#blacksite-H1-r)" stroke="#0a0b0e" stroke-width="1.5"/><g fill="#c9d1da" stroke="#2a2f36" stroke-width=".6"><circle cx="32" cy="8" r="2"/><circle cx="32" cy="56" r="2"/><circle cx="8" cy="32" r="2"/><circle cx="56" cy="32" r="2"/><circle cx="15" cy="15" r="2"/><circle cx="49" cy="15" r="2"/><circle cx="15" cy="49" r="2"/><circle cx="49" cy="49" r="2"/></g><circle cx="32" cy="32" r="20" fill="url(#blacksite-H1-g)" stroke="#2a2f36" stroke-width="1.5"/><circle cx="32" cy="32" r="15" fill="none" stroke="#5d6772" stroke-width="1.2"/><g stroke="#2a2f36" stroke-width="4.5" stroke-linecap="round"><path d="M32 16v32M18 24l28 16M18 40l28-16"/></g><g stroke="#ffc233" stroke-width="2.5" stroke-linecap="round"><path d="M32 16v32M18 24l28 16M18 40l28-16"/></g><circle cx="32" cy="32" r="6.5" fill="#1c2026" stroke="#ffc233" stroke-width="2"/><circle cx="32" cy="32" r="2.2" fill="#ff2a2a"/><path d="M17 22a18 18 0 0 1 12-9" stroke="#fff" stroke-width="2" fill="none" stroke-linecap="round" opacity=".7"/>'],
        'H2' => ['name' => 'Satellite', 'svg' => '<defs><linearGradient id="blacksite-H2-p" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#2a6cff"/><stop offset="1" stop-color="#0a1e5c"/></linearGradient><linearGradient id="blacksite-H2-b" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#ffe07a"/><stop offset="1" stop-color="#b87a10"/></linearGradient></defs><g transform="rotate(-30 32 32)"><path d="M4 32h56" stroke="#9aa4b0" stroke-width="2"/><g stroke="#0a0f24" stroke-width="1.2"><rect x="3" y="23" width="19" height="18" fill="url(#blacksite-H2-p)"/><rect x="42" y="23" width="19" height="18" fill="url(#blacksite-H2-p)"/></g><path d="M9.3 23v18M15.6 23v18M3 32h19M48.3 23v18M54.6 23v18M42 32h19" stroke="#6fe8ff" stroke-width=".8" opacity=".8"/><rect x="24" y="22" width="16" height="20" rx="2" fill="url(#blacksite-H2-b)" stroke="#3a2605" stroke-width="1.2"/><path d="M26 25h12M26 29h12" stroke="#fff3b0" stroke-width="1" opacity=".8"/><rect x="29" y="42" width="6" height="4" fill="#5a636e"/></g><g><path d="M33 47l9 9" stroke="#c9d1da" stroke-width="2"/><ellipse cx="44" cy="53" rx="8" ry="4" transform="rotate(-45 44 53)" fill="#dfe5ea" stroke="#3b424b" stroke-width="1.2"/><circle cx="46" cy="55" r="1.8" fill="#ff2a2a"/></g>'],
        'H3' => ['name' => 'Stealth Drone', 'svg' => '<defs><linearGradient id="blacksite-H3-b" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#5a616c"/><stop offset="1" stop-color="#15181d"/></linearGradient></defs><g stroke="#4a525c" stroke-width="4" stroke-linecap="round"><path d="M32 32L13 16M32 32L51 16M32 32L13 46M32 32L51 46"/></g><g fill="#8fe9ff" fill-opacity=".25" stroke="#b8c2cc" stroke-width="1.2"><ellipse cx="13" cy="16" rx="10" ry="3.5"/><ellipse cx="51" cy="16" rx="10" ry="3.5"/><ellipse cx="13" cy="46" rx="10" ry="3.5"/><ellipse cx="51" cy="46" rx="10" ry="3.5"/></g><g fill="#111"><circle cx="13" cy="16" r="2.3"/><circle cx="51" cy="16" r="2.3"/><circle cx="13" cy="46" r="2.3"/><circle cx="51" cy="46" r="2.3"/></g><path d="M32 14l18 16-7 16H21l-7-16z" fill="url(#blacksite-H3-b)" stroke="#ff3b30" stroke-width="1.5"/><path d="M32 14l-9 16h18z" fill="#3b424b"/><path d="M25 30h14l-3 7h-8z" fill="#0a0b0e"/><circle cx="32" cy="32.5" r="2.4" fill="#ff1f1f"/><circle cx="32" cy="32.5" r="4.5" fill="#ff1f1f" opacity=".3"/><circle cx="17" cy="30" r="1.8" fill="#ff3b30"/><circle cx="47" cy="30" r="1.8" fill="#ff3b30"/><path d="M27 21l5-4" stroke="#aeb7c2" stroke-width="1.2" stroke-linecap="round"/>'],
        'H4' => ['name' => 'Retina Scanner', 'svg' => '<defs><radialGradient id="blacksite-H4-i"><stop offset="0" stop-color="#b8fbff"/><stop offset=".55" stop-color="#18c8e8"/><stop offset="1" stop-color="#05506a"/></radialGradient></defs><g stroke="#39e6ff" stroke-width="2" fill="none"><path d="M6 14V7h8M58 14V7h-8M6 50v7h8M58 50v7h-8"/></g><path d="M5 32Q32 5 59 32Q32 59 5 32z" fill="#0c1a22" stroke="#0a0b0e" stroke-width="3"/><path d="M7 32Q32 9 57 32Q32 55 7 32z" fill="#e9f4f7"/><circle cx="32" cy="32" r="13" fill="url(#blacksite-H4-i)" stroke="#063646" stroke-width="1.5"/><circle cx="32" cy="32" r="5.5" fill="#05080c"/><circle cx="28" cy="27.5" r="2.5" fill="#fff"/><g stroke="#7ff4ff" stroke-width="1" opacity=".9"><circle cx="32" cy="32" r="17" fill="none" stroke-dasharray="3 3"/><path d="M32 12v6M32 46v6M12 32h6M46 32h6"/></g><rect x="4" y="38" width="56" height="2.4" fill="#39e6ff" opacity=".9"/><rect x="4" y="35" width="56" height="8" fill="#39e6ff" opacity=".2"/>'],
        'L1' => ['name' => 'Fingerprint', 'svg' => '<g fill="none" stroke="#ffb020" stroke-width="3" stroke-linecap="round"><path d="M17 20a19 19 0 0 1 30 0"/><path d="M13 32a19 19 0 0 1 38 0v4"/><path d="M19 48c-2-6-3-10-3-15a16 16 0 0 1 0 0a16 16 0 0 1 32 0"/><path d="M23 52c-1-6-2-12-1-17a10 10 0 0 1 20 0c0 5 0 9-1 13"/><path d="M29 55c-1-6-2-13-1-19a4 4 0 0 1 8 0c0 8-1 14-3 19"/><path d="M47 44c0 4-1 7-2 10"/></g><path d="M20 19a17 17 0 0 1 14-6" stroke="#fff1c2" stroke-width="1.5" fill="none" stroke-linecap="round"/>'],
        'L2' => ['name' => 'Padlock', 'svg' => '<defs><linearGradient id="blacksite-L2-g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ff5a4f"/><stop offset="1" stop-color="#a00c12"/></linearGradient></defs><path d="M20 30V20a12 12 0 0 1 24 0v10" fill="none" stroke="#8b95a1" stroke-width="6"/><path d="M20 30V20a12 12 0 0 1 24 0v10" fill="none" stroke="#c9d1da" stroke-width="2.5"/><rect x="12" y="28" width="40" height="30" rx="5" fill="url(#blacksite-L2-g)" stroke="#4a0508" stroke-width="2"/><circle cx="32" cy="40" r="4.5" fill="#2a0204"/><path d="M30 42h4l1 8h-6z" fill="#2a0204"/><path d="M16 32h26" stroke="#ffb0aa" stroke-width="2" stroke-linecap="round" opacity=".8"/>'],
        'L3' => ['name' => 'USB Drive', 'svg' => '<defs><linearGradient id="blacksite-L3-g" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#9ff8ff"/><stop offset=".5" stop-color="#18c8e8"/><stop offset="1" stop-color="#066a86"/></linearGradient></defs><g transform="rotate(35 32 32)"><rect x="24" y="4" width="16" height="15" fill="#c9d1da" stroke="#3b424b" stroke-width="1.5"/><rect x="27" y="8" width="3.5" height="3.5" fill="#3b424b"/><rect x="33.5" y="8" width="3.5" height="3.5" fill="#3b424b"/><rect x="18" y="19" width="28" height="4" fill="#2c3138"/><rect x="18" y="22" width="28" height="38" rx="5" fill="url(#blacksite-L3-g)" stroke="#043848" stroke-width="2"/><rect x="26" y="30" width="12" height="16" rx="2" fill="#043848" opacity=".45"/><circle cx="32" cy="53" r="2.5" fill="#fff"/><path d="M22 26v26" stroke="#e0feff" stroke-width="2" stroke-linecap="round" opacity=".8"/></g>'],
        'L4' => ['name' => 'Circuit Chip', 'svg' => '<g stroke="#9aa4b0" stroke-width="2.5"><path d="M20 6v8M28 6v8M36 6v8M44 6v8M20 50v8M28 50v8M36 50v8M44 50v8M6 20h8M6 28h8M6 36h8M6 44h8M50 20h8M50 28h8M50 36h8M50 44h8"/></g><rect x="13" y="13" width="38" height="38" rx="4" fill="#1e8f3e" stroke="#0a3a18" stroke-width="2"/><g stroke="#9dffb0" stroke-width="1.4" fill="none"><path d="M17 20h8l4 4M47 44h-8l-4-4M20 47v-6l4-4M44 17v6l-4 4"/></g><rect x="23" y="23" width="18" height="18" rx="2" fill="#0d3a1a" stroke="#4cff7a" stroke-width="1.5"/><rect x="27" y="27" width="10" height="10" fill="#2ee86a"/><path d="M16 16h14" stroke="#c8ffd4" stroke-width="1.5" stroke-linecap="round" opacity=".7"/>'],
        'L5' => ['name' => 'Laser Grid', 'svg' => '<rect x="7" y="7" width="50" height="50" rx="3" fill="#15181d" stroke="#6b7480" stroke-width="3"/><rect x="10" y="10" width="44" height="44" fill="#1f0a0c"/><g stroke="#ff2a2a" stroke-width="5" opacity=".35" stroke-linecap="round"><path d="M10 10l44 44M54 10L10 54M10 24l30 30M24 10l30 30M40 10l14 14"/></g><g stroke="#ff4a3d" stroke-width="2" stroke-linecap="round"><path d="M10 10l44 44M54 10L10 54M10 24l30 30M24 10l30 30"/></g><g stroke="#ffd0cc" stroke-width=".7"><path d="M10 10l44 44M54 10L10 54"/></g><g fill="#ff2a2a" stroke="#3a0406"><circle cx="10" cy="10" r="3"/><circle cx="54" cy="10" r="3"/><circle cx="10" cy="54" r="3"/><circle cx="54" cy="54" r="3"/></g>'],
    ],
    'coderain' => [
        'W' => ['name' => 'Glitch Core', 'svg' => '<defs><radialGradient id="coderain-W-glow" cx="0.5" cy="0.45" r="0.5"><stop offset="0" stop-color="#00ff66" stop-opacity="0.55"/><stop offset="1" stop-color="#00ff66" stop-opacity="0"/></radialGradient><linearGradient id="coderain-W-top" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#d9ffe6"/><stop offset="1" stop-color="#3dff8a"/></linearGradient></defs><circle cx="32" cy="27" r="28" fill="url(#coderain-W-glow)"/><polygon points="32,4 53,15 32,26 11,15" fill="url(#coderain-W-top)" stroke="#001a0a" stroke-width="1.5"/><polygon points="11,15 32,26 32,48 11,37" fill="#00c24e" stroke="#001a0a" stroke-width="1.5"/><polygon points="53,15 32,26 32,48 53,37" fill="#006b2b" stroke="#001a0a" stroke-width="1.5"/><g fill="#001a0a" opacity="0.55"><rect x="11" y="22" width="21" height="1.6"/><rect x="11" y="29" width="21" height="1.6"/><rect x="32" y="24" width="21" height="1.6"/><rect x="32" y="32" width="21" height="1.6"/></g><rect x="6" y="25" width="12" height="4" fill="#00ff66"/><rect x="45" y="30" width="13" height="3.5" fill="#9dffc2"/><rect x="36" y="19" width="7" height="3" fill="#ffffff"/><rect x="18" y="33" width="5" height="5" fill="#b8ffd4"/><rect x="41" y="38" width="5" height="4" fill="#00ff66"/><polyline points="20,10 26,14 23,18" fill="none" stroke="#ffffff" stroke-width="1.6"/><rect x="8" y="46" width="48" height="13" rx="3" fill="#001a0a" stroke="#00ff66" stroke-width="2"/><text x="32" y="56.5" text-anchor="middle" font-family="Limelight" font-size="11" fill="#b8ffd4" letter-spacing="1">WILD</text>'],
        'S' => ['name' => 'Twin Pills', 'svg' => '<defs><radialGradient id="coderain-S-halo" cx="0.5" cy="0.5" r="0.5"><stop offset="0.55" stop-color="#00ff66" stop-opacity="0"/><stop offset="0.8" stop-color="#00ff66" stop-opacity="0.45"/><stop offset="1" stop-color="#00ff66" stop-opacity="0"/></radialGradient><linearGradient id="coderain-S-r" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ff7a7a"/><stop offset="1" stop-color="#c8101e"/></linearGradient><linearGradient id="coderain-S-b" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#7ab8ff"/><stop offset="1" stop-color="#1a4fd6"/></linearGradient></defs><circle cx="32" cy="28" r="27" fill="url(#coderain-S-halo)"/><circle cx="32" cy="28" r="21" fill="#020805" stroke="#00ff66" stroke-width="2.5"/><circle cx="32" cy="28" r="24.5" fill="none" stroke="#9dffc2" stroke-width="0.8" stroke-dasharray="3 2"/><g transform="rotate(-45 32 28)"><rect x="12" y="21" width="40" height="14" rx="7" fill="url(#coderain-S-r)" stroke="#4a0008" stroke-width="1.5"/><rect x="32" y="21" width="20" height="14" rx="7" fill="#ffffff" opacity="0.18"/><rect x="16" y="23.5" width="14" height="3" rx="1.5" fill="#ffffff" opacity="0.6"/></g><g transform="rotate(45 32 28)"><rect x="12" y="21" width="40" height="14" rx="7" fill="url(#coderain-S-b)" stroke="#06164a" stroke-width="1.5"/><rect x="32" y="21" width="20" height="14" rx="7" fill="#ffffff" opacity="0.18"/><rect x="16" y="23.5" width="14" height="3" rx="1.5" fill="#ffffff" opacity="0.6"/></g><polygon points="7,47 57,47 53,53 57,59 7,59 11,53" fill="#00c24e" stroke="#001a0a" stroke-width="1.5"/><text x="32" y="56.5" text-anchor="middle" font-family="Figtree, sans-serif" font-weight="900" font-size="9" fill="#001a0a" letter-spacing="1">BONUS</text>'],
        'H1' => ['name' => 'Mirrorshades', 'svg' => '<circle cx="32" cy="34" r="26" fill="#00ff66" opacity="0.08"/><defs><linearGradient id="coderain-H1-l" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#0d3a1f"/><stop offset="1" stop-color="#000000"/></linearGradient><clipPath id="coderain-H1-c"><path d="M5,22 H29 L27,36 Q25,44 16,44 Q7,44 6,36 Z M35,22 H59 L58,36 Q57,44 48,44 Q39,44 37,36 Z"/></clipPath></defs><g transform="translate(0,-3) scale(1,1.2)"><path d="M2,20 H62 L61,25 H3 Z" fill="#1c2420" stroke="#00ff66" stroke-width="1"/><path d="M5,22 H29 L27,36 Q25,44 16,44 Q7,44 6,36 Z M35,22 H59 L58,36 Q57,44 48,44 Q39,44 37,36 Z" fill="url(#coderain-H1-l)" stroke="#00ff66" stroke-width="2"/><g clip-path="url(#coderain-H1-c)" fill="#00ff66"><rect x="9" y="22" width="2" height="12" opacity="0.9"/><rect x="14" y="26" width="2" height="16" opacity="0.5"/><rect x="19" y="22" width="2" height="8" opacity="0.8"/><rect x="24" y="28" width="2" height="12" opacity="0.4"/><rect x="40" y="24" width="2" height="14" opacity="0.8"/><rect x="45" y="22" width="2" height="9" opacity="0.5"/><rect x="50" y="27" width="2" height="15" opacity="0.9"/><rect x="55" y="22" width="2" height="10" opacity="0.5"/><polygon points="6,22 14,22 8,40 6,40" fill="#ffffff" opacity="0.25"/><polygon points="36,22 44,22 38,40 36,40" fill="#ffffff" opacity="0.25"/></g><path d="M29,25 Q32,22 35,25" fill="none" stroke="#1c2420" stroke-width="3"/><rect x="10" y="15" width="3" height="2" fill="#00ff66" opacity="0.6"/><rect x="50" y="12" width="3" height="2" fill="#00ff66" opacity="0.6"/><rect x="30" y="48" width="4" height="2" fill="#00ff66" opacity="0.5"/></g>'],
        'H2' => ['name' => 'Bent Spoon', 'svg' => '<defs><linearGradient id="coderain-H2-m" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#ffffff"/><stop offset="0.5" stop-color="#b9c6c0"/><stop offset="1" stop-color="#5c6b64"/></linearGradient><radialGradient id="coderain-H2-g" cx="0.5" cy="0.5" r="0.5"><stop offset="0" stop-color="#00ff66" stop-opacity="0.7"/><stop offset="1" stop-color="#00ff66" stop-opacity="0"/></radialGradient></defs><circle cx="33" cy="35" r="17" fill="url(#coderain-H2-g)"/><ellipse cx="20" cy="17" rx="10" ry="13" transform="rotate(-35 20 17)" fill="url(#coderain-H2-m)" stroke="#1c2420" stroke-width="2"/><ellipse cx="18" cy="15" rx="4" ry="7" transform="rotate(-35 18 15)" fill="#ffffff" opacity="0.75"/><path d="M26,26 L34,36 Q37,40 42,38 L54,52 L50,56 L39,43 Q33,45 30,39 L22,29 Z" fill="url(#coderain-H2-m)" stroke="#1c2420" stroke-width="2" stroke-linejoin="round"/><path d="M28,29 L33,35" stroke="#ffffff" stroke-width="1.4" opacity="0.8"/><g stroke="#00ff66" stroke-width="1.8" stroke-linecap="round"><line x1="41" y1="30" x2="46" y2="26"/><line x1="44" y1="36" x2="50" y2="35"/><line x1="26" y1="42" x2="22" y2="47"/></g>'],
        'H3' => ['name' => 'White Rabbit', 'svg' => '<defs><linearGradient id="coderain-H3-f" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffffff"/><stop offset="1" stop-color="#c9d9cf"/></linearGradient></defs><ellipse cx="32" cy="58" rx="20" ry="3" fill="#00ff66" opacity="0.3"/><path d="M22,26 Q16,6 20,3 Q26,4 28,24 Z" fill="url(#coderain-H3-f)" stroke="#6a8575" stroke-width="1.5"/><path d="M31,24 Q32,4 37,3 Q42,6 36,26 Z" fill="url(#coderain-H3-f)" stroke="#6a8575" stroke-width="1.5"/><path d="M21,23 Q18,11 21,7 Q24,10 25,22 Z" fill="#ffc7d6" opacity="0.7"/><ellipse cx="36" cy="46" rx="18" ry="12" fill="url(#coderain-H3-f)" stroke="#6a8575" stroke-width="1.5"/><circle cx="29" cy="31" r="10" fill="url(#coderain-H3-f)" stroke="#6a8575" stroke-width="1.5"/><circle cx="53" cy="44" r="4" fill="#ffffff" stroke="#6a8575" stroke-width="1.2"/><ellipse cx="24" cy="54" rx="6" ry="3" fill="#ffffff" stroke="#6a8575" stroke-width="1.2"/><circle cx="26" cy="29" r="3.5" fill="#001a0a" stroke="#00ff66" stroke-width="1.8"/><circle cx="25" cy="28" r="1" fill="#b8ffd4"/><circle cx="20" cy="34" r="1.3" fill="#ff8fa8"/><path d="M40,40 Q46,38 50,42" fill="none" stroke="#ffffff" stroke-width="2" opacity="0.8"/>'],
        'H4' => ['name' => 'Sentinel', 'svg' => '<defs><radialGradient id="coderain-H4-b" cx="0.4" cy="0.35" r="0.7"><stop offset="0" stop-color="#5c6f78"/><stop offset="1" stop-color="#141c20"/></radialGradient></defs><g fill="none" stroke="#56707a" stroke-width="3.8" stroke-linecap="round"><path d="M18,32 Q8,42 12,56"/><path d="M24,35 Q20,48 24,59"/><path d="M32,36 Q33,48 30,60"/><path d="M40,35 Q46,46 42,59"/><path d="M46,32 Q58,40 54,56"/></g><g fill="none" stroke="#00ff66" stroke-width="1.2" stroke-dasharray="2 3"><path d="M18,32 Q8,42 12,56"/><path d="M32,36 Q33,48 30,60"/><path d="M46,32 Q58,40 54,56"/></g><ellipse cx="32" cy="22" rx="19" ry="16" fill="url(#coderain-H4-b)" stroke="#000000" stroke-width="2"/><path d="M16,24 Q32,32 48,24 L47,30 Q32,38 17,30 Z" fill="#0b1114"/><g fill="#ff2a2a" stroke="#ff9a9a" stroke-width="0.6"><circle cx="21" cy="17" r="2.4"/><circle cx="27" cy="14" r="2.8"/><circle cx="34" cy="14" r="2.8"/><circle cx="41" cy="17" r="2.4"/><circle cx="31" cy="20" r="2"/><circle cx="44" cy="22" r="1.6"/><circle cx="18" cy="22" r="1.6"/></g><ellipse cx="25" cy="10" rx="6" ry="2.5" fill="#ffffff" opacity="0.25" transform="rotate(-20 25 10)"/>'],
        'L1' => ['name' => 'Glyph 7', 'svg' => '<defs><linearGradient id="coderain-L1-r" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#00ff66" stop-opacity="0"/><stop offset="1" stop-color="#00ff66" stop-opacity="0.45"/></linearGradient></defs><rect x="7" y="7" width="50" height="50" rx="9" fill="#031a0c" stroke="#00ff66" stroke-width="2.5"/><rect x="25" y="10" width="14" height="30" rx="2" fill="url(#coderain-L1-r)"/><rect x="47" y="11" width="3" height="16" fill="url(#coderain-L1-r)"/><rect x="13" y="20" width="3" height="22" fill="url(#coderain-L1-r)"/><text x="32" y="48" text-anchor="middle" font-family="Chivo Mono, monospace" font-weight="700" font-size="42" fill="#3dff8a" stroke="#b8ffd4" stroke-width="0.8">7</text>'],
        'L2' => ['name' => 'Glyph A', 'svg' => '<defs><linearGradient id="coderain-L2-r" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#1fb857" stop-opacity="0"/><stop offset="1" stop-color="#1fb857" stop-opacity="0.45"/></linearGradient></defs><rect x="7" y="7" width="50" height="50" rx="9" fill="#061208" stroke="#1f9e4a" stroke-width="2.5"/><rect x="25" y="10" width="14" height="30" rx="2" fill="url(#coderain-L2-r)"/><rect x="47" y="11" width="3" height="16" fill="url(#coderain-L2-r)"/><rect x="13" y="20" width="3" height="22" fill="url(#coderain-L2-r)"/><text x="32" y="47" text-anchor="middle" font-family="Chivo Mono, monospace" font-weight="700" font-size="38" fill="#1fb857">ア</text>'],
        'L3' => ['name' => 'Glyph Hash', 'svg' => '<defs><linearGradient id="coderain-L3-r" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#2ef0c8" stop-opacity="0"/><stop offset="1" stop-color="#2ef0c8" stop-opacity="0.45"/></linearGradient></defs><rect x="7" y="7" width="50" height="50" rx="9" fill="#021514" stroke="#1fd6b0" stroke-width="2.5"/><rect x="25" y="10" width="14" height="30" rx="2" fill="url(#coderain-L3-r)"/><rect x="47" y="11" width="3" height="16" fill="url(#coderain-L3-r)"/><rect x="13" y="20" width="3" height="22" fill="url(#coderain-L3-r)"/><text x="32" y="47" text-anchor="middle" font-family="Chivo Mono, monospace" font-weight="700" font-size="40" fill="#2ef0c8">#</text>'],
        'L4' => ['name' => 'Glyph 0', 'svg' => '<defs><linearGradient id="coderain-L4-r" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#c8ff2e" stop-opacity="0"/><stop offset="1" stop-color="#c8ff2e" stop-opacity="0.45"/></linearGradient></defs><rect x="7" y="7" width="50" height="50" rx="9" fill="#101a02" stroke="#b6f000" stroke-width="2.5"/><rect x="25" y="10" width="14" height="30" rx="2" fill="url(#coderain-L4-r)"/><rect x="47" y="11" width="3" height="16" fill="url(#coderain-L4-r)"/><rect x="13" y="20" width="3" height="22" fill="url(#coderain-L4-r)"/><text x="32" y="48" text-anchor="middle" font-family="Chivo Mono, monospace" font-weight="700" font-size="42" fill="#c8ff2e">0</text>'],
        'L5' => ['name' => 'Glyph Wo', 'svg' => '<defs><linearGradient id="coderain-L5-r" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#8fd6a4" stop-opacity="0"/><stop offset="1" stop-color="#8fd6a4" stop-opacity="0.45"/></linearGradient></defs><rect x="7" y="7" width="50" height="50" rx="9" fill="#040a06" stroke="#4d7a5c" stroke-width="2.5"/><rect x="25" y="10" width="14" height="30" rx="2" fill="url(#coderain-L5-r)"/><rect x="47" y="11" width="3" height="16" fill="url(#coderain-L5-r)"/><rect x="13" y="20" width="3" height="22" fill="url(#coderain-L5-r)"/><text x="32" y="47" text-anchor="middle" font-family="Chivo Mono, monospace" font-weight="700" font-size="38" fill="#e9fff0" stroke="#3f8a55" stroke-width="2.2" paint-order="stroke">ヲ</text>'],
    ],
    'tiki' => [
        'W' => ['name' => 'Tiki Idol', 'svg' => '<defs><linearGradient id="tiki-W-g1" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#b8743a"/><stop offset="1" stop-color="#5e2f12"/></linearGradient><linearGradient id="tiki-W-g2" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffe98a"/><stop offset="1" stop-color="#d98e14"/></linearGradient></defs><path d="M12 16 L16 2 L22 12 L27 1 L32 10 L37 1 L42 12 L48 2 L52 16Z" fill="#ff8a1e" stroke="#2a130a" stroke-width="1.5" stroke-linejoin="round"/><path d="M17 15 L22 6 L27 15Z M37 15 L42 6 L47 15Z" fill="#2fb59a"/><path d="M28 13 L32 5 L36 13Z" fill="#ffd34a"/><path d="M15 16 Q15 11 32 11 Q49 11 49 16 L49 45 Q49 52 32 52 Q15 52 15 45Z" fill="url(#tiki-W-g1)" stroke="#2a130a" stroke-width="2"/><rect x="15" y="15" width="34" height="4" fill="url(#tiki-W-g2)" stroke="#2a130a" stroke-width="1"/><circle cx="24" cy="27" r="6.5" fill="#fff4d6" stroke="#2a130a" stroke-width="2"/><circle cx="40" cy="27" r="6.5" fill="#fff4d6" stroke="#2a130a" stroke-width="2"/><circle cx="24" cy="27.5" r="3.2" fill="#2a130a"/><circle cx="40" cy="27.5" r="3.2" fill="#2a130a"/><circle cx="25.2" cy="26.2" r="1.1" fill="#fff"/><circle cx="41.2" cy="26.2" r="1.1" fill="#fff"/><path d="M29 30 L35 30 L38 37 L26 37Z" fill="#6b3414" stroke="#2a130a" stroke-width="1.2"/><rect x="19" y="38" width="26" height="9" rx="4" fill="#2a130a"/><path d="M21 40 H43 V45 H21Z" fill="#fff4d6"/><path d="M25 40 V45 M29 40 V45 M33 40 V45 M37 40 V45 M41 40 V45 M21 42.5 H43" stroke="#2a130a" stroke-width="1"/><circle cx="13" cy="32" r="3" fill="url(#tiki-W-g2)" stroke="#2a130a"/><circle cx="51" cy="32" r="3" fill="url(#tiki-W-g2)" stroke="#2a130a"/><path d="M18 20 Q17 30 19 38" stroke="#fff" stroke-width="2" stroke-opacity=".3" fill="none" stroke-linecap="round"/><rect x="9" y="49" width="46" height="13" rx="3" fill="url(#tiki-W-g2)" stroke="#6b2a0c" stroke-width="1.5"/><text x="32" y="59.5" text-anchor="middle" font-family="Limelight" font-size="11" fill="#5a1a06">WILD</text>'],
        'S' => ['name' => 'Volcano', 'svg' => '<defs><radialGradient id="tiki-S-g1" cx=".5" cy=".45" r=".5"><stop offset="0" stop-color="#ffcf5a" stop-opacity=".9"/><stop offset=".6" stop-color="#ff7a1a" stop-opacity=".45"/><stop offset="1" stop-color="#ff5a1a" stop-opacity="0"/></radialGradient><linearGradient id="tiki-S-g2" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#5a3526"/><stop offset="1" stop-color="#2e1a12"/></linearGradient></defs><circle cx="32" cy="28" r="28" fill="url(#tiki-S-g1)"/><circle cx="32" cy="28" r="24" fill="none" stroke="#ffd966" stroke-width="2.5" stroke-dasharray="4 3"/><path d="M4 52 L24 22 Q32 19 40 22 L60 52Z" fill="url(#tiki-S-g2)" stroke="#1a0a05" stroke-width="2" stroke-linejoin="round"/><path d="M24 22 L14 38 L20 36 L12 50" stroke="#7a4a36" stroke-width="2" fill="none"/><ellipse cx="32" cy="22" rx="8" ry="2.5" fill="#ffb13b"/><path d="M27 22 Q29 30 24 36 Q21 40 23 46 Q27 40 30 34 Q32 28 32 22Z M34 22 Q35 30 40 34 Q44 38 44 44 Q48 38 44 31 Q40 26 38 22Z" fill="#ff6a1a" stroke="#ffcf5a" stroke-width="1" stroke-linejoin="round"/><circle cx="32" cy="12" r="6" fill="#ff6a1a"/><circle cx="25" cy="8" r="4" fill="#ff9a2a"/><circle cx="39" cy="7" r="4.5" fill="#ff9a2a"/><circle cx="32" cy="4" r="3" fill="#ffd34a"/><circle cx="31" cy="12" r="2.5" fill="#ffe98a"/><path d="M2 50 H62 L58 55.5 L62 61 H2 L6 55.5Z" fill="#e8336b" stroke="#7a0f2e" stroke-width="1.5" stroke-linejoin="round"/><text x="32" y="59.2" text-anchor="middle" font-family="Limelight" font-size="9" fill="#fff4d6" letter-spacing="1">BONUS</text>'],
        'H1' => ['name' => 'Tiki Mug', 'svg' => '<defs><linearGradient id="tiki-H1-g1" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#3fd0bd"/><stop offset=".55" stop-color="#15907f"/><stop offset="1" stop-color="#0b5a52"/></linearGradient></defs><path d="M40 26 L50 4" stroke="#ffe066" stroke-width="3" stroke-linecap="round"/><path d="M40 26 L50 4" stroke="#e8336b" stroke-width="3" stroke-dasharray="3 3"/><path d="M30 24 L22 6" stroke="#8a5a2a" stroke-width="1.8" stroke-linecap="round"/><path d="M8 12 Q20 -2 36 8 Z" fill="#ff5a96" stroke="#7a0f2e" stroke-width="1.5" stroke-linejoin="round"/><path d="M8 12 L17 5 L22 6 L28 4.5 L36 8" fill="none" stroke="#7a0f2e" stroke-width="1"/><path d="M16 22 L48 22 L45 58 Q32 62 19 58Z" fill="url(#tiki-H1-g1)" stroke="#06312c" stroke-width="2" stroke-linejoin="round"/><ellipse cx="32" cy="22" rx="16" ry="3.5" fill="#ffb13b" stroke="#06312c" stroke-width="1.5"/><path d="M19 30 H45" stroke="#06312c" stroke-width="2"/><path d="M21 38 Q25 33 29 38 M35 38 Q39 33 43 38" stroke="#06312c" stroke-width="2.4" fill="none" stroke-linecap="round"/><circle cx="25" cy="38.5" r="1.8" fill="#06312c"/><circle cx="39" cy="38.5" r="1.8" fill="#06312c"/><path d="M30 38 L34 38 L35 44 L29 44Z" fill="#0b5a52"/><rect x="23" y="46" width="18" height="6" rx="2.5" fill="#06312c"/><path d="M25 47.5 H39 V50.5 H25Z" fill="#dff7f0"/><path d="M28 47.5 V50.5 M32 47.5 V50.5 M36 47.5 V50.5" stroke="#06312c" stroke-width=".8"/><path d="M20 26 Q20 42 22 55" stroke="#fff" stroke-width="2.5" stroke-opacity=".35" fill="none" stroke-linecap="round"/><path d="M16 30 Q9 32 10 40 Q11 46 18 46" stroke="#0b5a52" stroke-width="3.5" fill="none"/>'],
        'H2' => ['name' => 'Ukulele', 'svg' => '<defs><linearGradient id="tiki-H2-g1" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#ffb04a"/><stop offset="1" stop-color="#c2561a"/></linearGradient></defs><g transform="translate(32 32) scale(1.12) translate(-32 -32) rotate(35 32 32)"><rect x="29" y="3" width="6" height="30" fill="#4a2410" stroke="#1a0a05" stroke-width="1.2"/><path d="M27 2 H37 L36 10 H28Z" fill="#6b3414" stroke="#1a0a05" stroke-width="1.2"/><circle cx="26.5" cy="5" r="1.4" fill="#ffe066"/><circle cx="37.5" cy="5" r="1.4" fill="#ffe066"/><circle cx="26.5" cy="8" r="1.4" fill="#ffe066"/><circle cx="37.5" cy="8" r="1.4" fill="#ffe066"/><path d="M32 22 C21 22 20 30 23 35 C17 39 17 52 24 57 C28 60 36 60 40 57 C47 52 47 39 41 35 C44 30 43 22 32 22Z" fill="url(#tiki-H2-g1)" stroke="#5a2408" stroke-width="2"/><path d="M32 23.5 C23 24 22 30 25 35" stroke="#fff" stroke-width="2" stroke-opacity=".35" fill="none" stroke-linecap="round"/><circle cx="32" cy="38" r="5" fill="#2a130a" stroke="#7a3a10" stroke-width="1.5"/><circle cx="32" cy="38" r="7" fill="none" stroke="#2fb59a" stroke-width="1.2"/><rect x="26" y="50" width="12" height="3" rx="1" fill="#4a2410"/><path d="M30.5 6 V51 M31.5 6 V51 M32.5 6 V51 M33.5 6 V51" stroke="#fff4d6" stroke-width=".4"/></g><g transform="translate(14 48)"><circle r="5" fill="#ff4f8b"/><circle r="1.8" fill="#ffe066"/></g>'],
        'H3' => ['name' => 'Surfboard', 'svg' => '<defs><linearGradient id="tiki-H3-g1" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#fff8e4"/><stop offset="1" stop-color="#e8cf9a"/></linearGradient></defs><g transform="rotate(-30 32 32)"><path d="M32 1 Q46 16 44 40 Q42 60 32 63 Q22 60 20 40 Q18 16 32 1Z" fill="url(#tiki-H3-g1)" stroke="#3a1a08" stroke-width="2"/><path d="M29 4 Q28 30 29 62 L35 62 Q36 30 35 4 Q32 1 29 4Z" fill="#e0342b"/><path d="M26 10 Q23 30 25 58 M38 10 Q41 30 39 58" stroke="#16a08c" stroke-width="2.2" fill="none"/><ellipse cx="32" cy="28" rx="6" ry="6" fill="#ffd34a" stroke="#3a1a08" stroke-width="1.2"/><path d="M32 23.5 L33.3 26.7 L36.6 27 L34 29.1 L34.8 32.4 L32 30.6 L29.2 32.4 L30 29.1 L27.4 27 L30.7 26.7Z" fill="#e0342b"/><path d="M24 16 Q22 30 23 44" stroke="#fff" stroke-width="2" stroke-opacity=".7" fill="none" stroke-linecap="round"/></g>'],
        'H4' => ['name' => 'Tiki Torch', 'svg' => '<defs><linearGradient id="tiki-H4-g1" x1="0" y1="1" x2="0" y2="0"><stop offset="0" stop-color="#ff4a12"/><stop offset=".55" stop-color="#ff9a1e"/><stop offset="1" stop-color="#ffe066"/></linearGradient><linearGradient id="tiki-H4-g2" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#f2d08a"/><stop offset="1" stop-color="#b98a3e"/></linearGradient></defs><path d="M32 2 Q44 12 42 22 Q46 16 44 10 Q52 20 46 30 H18 Q12 20 20 12 Q19 18 22 22 Q20 12 32 2Z" fill="url(#tiki-H4-g1)" stroke="#a82a0a" stroke-width="1.5" stroke-linejoin="round"/><path d="M32 12 Q38 20 36 28 H28 Q26 20 32 12Z" fill="#fff4b0"/><path d="M17 28 H47 L42 40 H22Z" fill="#9a5a24" stroke="#3a1a08" stroke-width="2" stroke-linejoin="round"/><path d="M20 31 L44 37 M44 31 L20 37 M19 34 H45" stroke="#e2b46a" stroke-width="1.5"/><rect x="28" y="40" width="8" height="23" fill="url(#tiki-H4-g2)" stroke="#3a1a08" stroke-width="1.8"/><path d="M27.5 47 H36.5 M27.5 55 H36.5" stroke="#3a1a08" stroke-width="2"/><path d="M30 42 V62" stroke="#fff" stroke-width="1.2" stroke-opacity=".5"/>'],
        'L1' => ['name' => 'Hibiscus', 'svg' => '<g transform="translate(32 33)" stroke="#8a0f3a" stroke-width="1.5"><path d="M0 0 C-10 -8 -12 -24 0 -25 C12 -24 10 -8 0 0Z" fill="#ff4f8b"/><path d="M0 0 C-10 -8 -12 -24 0 -25 C12 -24 10 -8 0 0Z" fill="#ff4f8b" transform="rotate(72)"/><path d="M0 0 C-10 -8 -12 -24 0 -25 C12 -24 10 -8 0 0Z" fill="#ff4f8b" transform="rotate(144)"/><path d="M0 0 C-10 -8 -12 -24 0 -25 C12 -24 10 -8 0 0Z" fill="#ff4f8b" transform="rotate(216)"/><path d="M0 0 C-10 -8 -12 -24 0 -25 C12 -24 10 -8 0 0Z" fill="#ff4f8b" transform="rotate(288)"/><circle r="7" fill="#c21857" stroke="none"/><path d="M0 0 L9 -13" stroke="#ffe066" stroke-width="2"/><circle cx="9" cy="-13" r="2.2" fill="#ffd34a" stroke="#b36a00" stroke-width=".8"/><path d="M-4 -20 Q-6 -14 -3 -9" stroke="#fff" stroke-opacity=".6" stroke-width="2" fill="none" stroke-linecap="round"/></g>'],
        'L2' => ['name' => 'Pineapple', 'svg' => '<defs><clipPath id="tiki-L2-c"><ellipse cx="32" cy="43" rx="15" ry="18"/></clipPath></defs><path d="M32 30 L14 12 L26 20 L22 4 L30 16 L32 1 L34 16 L42 4 L38 20 L50 12Z" fill="#3cb04a" stroke="#14521e" stroke-width="1.5" stroke-linejoin="round"/><ellipse cx="32" cy="43" rx="15" ry="18" fill="#ffc92a" stroke="#8a5200" stroke-width="2"/><g clip-path="url(#tiki-L2-c)" stroke="#c77a00" stroke-width="1.6"><path d="M8 30 L40 62 M8 38 L32 62 M8 22 L48 62 M14 20 L52 58 M22 20 L56 54 M56 30 L24 62 M56 38 L32 62 M56 22 L16 62 M50 20 L12 58 M42 20 L8 54"/></g><path d="M22 36 Q20 44 23 52" stroke="#fff" stroke-width="2.5" stroke-opacity=".55" fill="none" stroke-linecap="round"/>'],
        'L3' => ['name' => 'Coconut', 'svg' => '<defs><radialGradient id="tiki-L3-g1" cx=".4" cy=".35" r=".7"><stop offset="0" stop-color="#9a5e30"/><stop offset="1" stop-color="#4a2410"/></radialGradient></defs><path d="M8 30 Q8 58 32 58 Q56 58 56 30Z" fill="url(#tiki-L3-g1)" stroke="#1f0d05" stroke-width="2"/><path d="M14 38 L18 42 M22 46 L25 50 M36 48 L40 45 M46 40 L50 36 M30 52 L33 55" stroke="#2a130a" stroke-width="1.5" stroke-linecap="round"/><ellipse cx="32" cy="30" rx="24" ry="10" fill="#fffaf0" stroke="#1f0d05" stroke-width="2"/><ellipse cx="32" cy="30.5" rx="18" ry="6.5" fill="#e9f3f0"/><ellipse cx="32" cy="31" rx="15" ry="4.8" fill="#cfe6e4"/><path d="M20 28 Q26 26 30 27" stroke="#fff" stroke-width="2" fill="none" stroke-linecap="round"/><path d="M14 44 Q14 50 20 53" stroke="#fff" stroke-width="2" stroke-opacity=".3" fill="none" stroke-linecap="round"/>'],
        'L4' => ['name' => 'Seashell', 'svg' => '<defs><linearGradient id="tiki-L4-g1" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#a8f4ee"/><stop offset="1" stop-color="#2aa9b8"/></linearGradient></defs><path d="M50 12 L58 4 L55 16 Q59 30 47 44 Q34 58 16 57 Q7 55 7 46 Q8 32 20 22 L24 14 L28 20 L33 11 L37 17 L43 9 L45 15Z" fill="url(#tiki-L4-g1)" stroke="#0c4a55" stroke-width="2" stroke-linejoin="round"/><path d="M50 12 Q46 18 49 24 M55 16 Q50 20 52 28 M45 15 Q40 24 44 32" stroke="#0c6a75" stroke-width="1.5" fill="none"/><path d="M11 49 Q12 32 28 27 Q40 24 45 33 Q38 50 21 55 Q13 56 11 49Z" fill="#ffb3c6" stroke="#0c4a55" stroke-width="1.5"/><path d="M18 46 Q22 36 32 33 Q38 32 40 35" stroke="#e8668a" stroke-width="2.2" fill="none" stroke-linecap="round"/><path d="M24 20 Q34 16 40 20" stroke="#fff" stroke-width="2" stroke-opacity=".7" fill="none" stroke-linecap="round"/>'],
        'L5' => ['name' => 'Palm Leaf', 'svg' => '<defs><linearGradient id="tiki-L5-g1" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#6ee06a"/><stop offset="1" stop-color="#1f8a3a"/></linearGradient></defs><path d="M32 63 V52" stroke="#1f6a2a" stroke-width="3" stroke-linecap="round"/><path d="M32 56 C14 50 5 36 7 22 C9 10 22 5 32 13 C42 5 55 10 57 22 C59 36 50 50 32 56Z" fill="url(#tiki-L5-g1)" stroke="#0e4a1e" stroke-width="2" stroke-linejoin="round"/><path d="M4 21 L22 26 L5 30Z M5 35 L23 36 L9 44Z M13 47 L26 42 L20 54Z M60 21 L42 26 L59 30Z M59 35 L41 36 L55 44Z M51 47 L38 42 L44 54Z" fill="#2a130a"/><ellipse cx="25" cy="32" rx="2.2" ry="3" fill="#2a130a"/><ellipse cx="39" cy="32" rx="2.2" ry="3" fill="#2a130a"/><path d="M32 13 V56 M32 24 L15 18 M32 32 L14 32 M32 40 L20 46 M32 24 L49 18 M32 32 L50 32 M32 40 L44 46" stroke="#0e4a1e" stroke-width="1.8" fill="none" stroke-linecap="round"/><path d="M14 12 Q10 16 9 22" stroke="#fff" stroke-width="2" stroke-opacity=".5" fill="none" stroke-linecap="round"/>'],
    ],
    'calavera' => [
        'W' => ['name' => 'Sugar Skull', 'svg' => '<defs><linearGradient id="calavera-W-plate" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffe680"/><stop offset="1" stop-color="#e0a100"/></linearGradient></defs><circle cx="32" cy="27" r="27" fill="#ff9f1c" opacity="0.22"/><circle cx="32" cy="27" r="28" fill="none" stroke="#ffd23f" stroke-width="2" stroke-dasharray="0.1 3.4" stroke-linecap="round"/><path d="M32 4C47 4 55 14 55 25C55 32 52 36 49 38L48 44C48 47 45 49 42 49H22C19 49 16 47 16 44L15 38C12 36 9 32 9 25C9 14 17 4 32 4Z" fill="#fff8ec" stroke="#2a0f3d" stroke-width="2.2"/><path d="M13 22C14 12 22 7 30 6C22 9 16 14 15 24Z" fill="#fff"/><circle cx="32" cy="14" r="3.5" fill="none" stroke="#ff9f1c" stroke-width="4" stroke-dasharray="0.1 2.6" stroke-linecap="round"/><circle cx="32" cy="14" r="2" fill="#ffd23f"/><circle cx="23" cy="10.5" r="1.2" fill="#1fd1c1"/><circle cx="41" cy="10.5" r="1.2" fill="#1fd1c1"/><circle cx="26" cy="8" r="1" fill="#a6e22e"/><circle cx="38" cy="8" r="1" fill="#a6e22e"/><circle cx="22" cy="26" r="6.5" fill="none" stroke="#ff2e88" stroke-width="4.5" stroke-dasharray="0.1 3.4" stroke-linecap="round"/><circle cx="42" cy="26" r="6.5" fill="none" stroke="#ff2e88" stroke-width="4.5" stroke-dasharray="0.1 3.4" stroke-linecap="round"/><circle cx="22" cy="26" r="5" fill="#1fd1c1"/><circle cx="42" cy="26" r="5" fill="#1fd1c1"/><circle cx="22" cy="26" r="2.6" fill="#2a0f3d"/><circle cx="42" cy="26" r="2.6" fill="#2a0f3d"/><path d="M32 38L28.5 33.5C28 31.5 30.5 31 32 32.5C33.5 31 36 31.5 35.5 33.5Z" fill="#2a0f3d"/><path d="M13 33Q15 36 13 38M51 33Q49 36 51 38" fill="none" stroke="#a6e22e" stroke-width="1.6" stroke-linecap="round"/><path d="M21 41H43M24 39V43M28 39V43M32 39V43M36 39V43M40 39V43" stroke="#2a0f3d" stroke-width="1.4"/><rect x="7" y="47" width="50" height="13" rx="3.5" fill="url(#calavera-W-plate)" stroke="#2a0f3d" stroke-width="1.8"/><text x="32" y="57.6" font-family="Limelight" font-size="11" fill="#3a1457" text-anchor="middle" letter-spacing="1.5">WILD</text>'],
        'S' => ['name' => 'Marigold', 'svg' => '<defs><radialGradient id="calavera-S-glow" cx="50%" cy="50%" r="50%"><stop offset="55%" stop-color="#ffb627" stop-opacity="0.7"/><stop offset="100%" stop-color="#ffb627" stop-opacity="0"/></radialGradient></defs><circle cx="32" cy="27" r="29" fill="url(#calavera-S-glow)"/><circle cx="32" cy="27" r="24" fill="none" stroke="#ffd23f" stroke-width="1.8" stroke-dasharray="1 2.4" stroke-linecap="round"/><circle cx="32" cy="27" r="18" fill="#c2410c"/><circle cx="32" cy="27" r="17" fill="none" stroke="#e8590c" stroke-width="8" stroke-dasharray="0.1 5" stroke-linecap="round"/><circle cx="32" cy="27" r="12.5" fill="none" stroke="#ff8c1a" stroke-width="7" stroke-dasharray="0.1 4.4" stroke-linecap="round"/><circle cx="32" cy="27" r="8" fill="none" stroke="#ffb627" stroke-width="6" stroke-dasharray="0.1 3.6" stroke-linecap="round"/><circle cx="32" cy="27" r="4.5" fill="#ffe066"/><circle cx="32" cy="27" r="2" fill="#c2410c"/><circle cx="26" cy="20" r="2" fill="#fff4c2" opacity="0.8"/><path d="M8 47L14 45V58L8 56L11 51.5Z" fill="#b3125e"/><path d="M56 47L50 45V58L56 56L53 51.5Z" fill="#b3125e"/><rect x="13" y="45" width="38" height="12" rx="2" fill="#ff2e88" stroke="#6b0f3a" stroke-width="1.2"/><text x="32" y="54.4" font-family="Figtree, sans-serif" font-weight="900" font-size="8.5" fill="#fff" text-anchor="middle" letter-spacing="1">BONUS</text>'],
        'H1' => ['name' => 'Catrina Hat', 'svg' => '<path d="M40 30C42 20 46 12 54 5C52 14 48 22 44 31Z" fill="#1fd1c1" stroke="#0b6e66" stroke-width="1"/><path d="M36 28C35 18 38 10 44 3C45 12 42 21 40 30Z" fill="#a6e22e" stroke="#4d7a0c" stroke-width="1"/><path d="M44 31C48 24 54 19 60 17C57 23 52 28 46 33Z" fill="#ff2e88" stroke="#8a1049" stroke-width="1"/><ellipse cx="32" cy="42" rx="28" ry="9" fill="#1a0829"/><ellipse cx="32" cy="41" rx="27" ry="8" fill="#5b1f7a" stroke="#2a0f3d" stroke-width="1.5"/><ellipse cx="32" cy="41" rx="24" ry="6" fill="none" stroke="#ffd23f" stroke-width="1.4" stroke-dasharray="0.1 2.6" stroke-linecap="round"/><path d="M17 40C17 25 22 17 32 17C42 17 47 25 47 40C42 43 22 43 17 40Z" fill="#3a1457" stroke="#1a0829" stroke-width="1.6"/><path d="M22 36C21 27 24 21 29 19C25 23 24 29 25 37Z" fill="#7a3aa0"/><path d="M17.5 32C22 35 42 35 46.5 32L47 38C42 41 22 41 17 38Z" fill="#ff2e88"/><circle cx="23" cy="34" r="5" fill="#e8590c"/><circle cx="23" cy="34" r="4" fill="none" stroke="#ffb627" stroke-width="3" stroke-dasharray="0.1 2.2" stroke-linecap="round"/><circle cx="23" cy="34" r="1.6" fill="#ffe066"/><circle cx="31.5" cy="35.5" r="4" fill="#1fd1c1" stroke="#0b6e66" stroke-width="1"/><circle cx="31.5" cy="35.5" r="1.5" fill="#fff8ec"/><circle cx="39" cy="34.5" r="4.4" fill="#d6006a"/><path d="M37 34.5a2 2 0 1 1 2 2M39 32.8a1.6 1.6 0 1 0 1.5 1.8" fill="none" stroke="#ff8ac0" stroke-width="1"/><path d="M28 39.5l-2 3.5 4-1zM35 39.5l2 3.5-4-1z" fill="#a6e22e"/><path d="M7 45Q10 49 13 47Q16 51 19 48Q22 52 26 49Q29 52 32 49Q35 52 38 49Q42 52 45 48Q48 51 51 47Q54 49 57 45" fill="none" stroke="#fff8ec" stroke-width="1.4" stroke-linecap="round"/>'],
        'H2' => ['name' => 'Guitar', 'svg' => '<g transform="translate(29 32) rotate(-38) scale(0.95) translate(-32 -32)"><rect x="29" y="-2" width="6" height="30" rx="1" fill="#4a2410" stroke="#1a0829" stroke-width="1.2"/><path d="M27 -6H37L36 3H28Z" fill="#6b3215" stroke="#1a0829" stroke-width="1.2"/><circle cx="26.5" cy="-3.5" r="1.3" fill="#ffd23f"/><circle cx="26.8" cy="0.5" r="1.3" fill="#ffd23f"/><circle cx="37.5" cy="-3.5" r="1.3" fill="#ffd23f"/><circle cx="37.2" cy="0.5" r="1.3" fill="#ffd23f"/><circle cx="32" cy="31" r="11.5" fill="#1a0829"/><circle cx="32" cy="48" r="15" fill="#1a0829"/><circle cx="32" cy="31" r="10" fill="#e0822a"/><circle cx="32" cy="48" r="13.5" fill="#e0822a"/><circle cx="32" cy="48" r="11" fill="#f2a041"/><path d="M24 28A10 10 0 0 1 32 22" fill="none" stroke="#ffd9a0" stroke-width="2" stroke-linecap="round"/><circle cx="32" cy="38" r="6.5" fill="none" stroke="#1fd1c1" stroke-width="3" stroke-dasharray="0.1 2.4" stroke-linecap="round"/><circle cx="32" cy="38" r="4.2" fill="#2a0f3d"/><circle cx="24" cy="51" r="3" fill="#ff2e88"/><circle cx="24" cy="51" r="1.2" fill="#ffe066"/><circle cx="40" cy="51" r="3" fill="#ff2e88"/><circle cx="40" cy="51" r="1.2" fill="#ffe066"/><circle cx="21" cy="45.5" r="1.3" fill="#a6e22e"/><circle cx="43" cy="45.5" r="1.3" fill="#a6e22e"/><circle cx="27" cy="57" r="1.3" fill="#1fd1c1"/><circle cx="37" cy="57" r="1.3" fill="#1fd1c1"/><rect x="26" y="50" width="12" height="3" rx="1" fill="#4a2410"/><path d="M30.5 1V51M32 1V51M33.5 1V51" stroke="#fff8ec" stroke-width="0.5"/></g>'],
        'H3' => ['name' => 'Papel Picado', 'svg' => '<path d="M3 9Q32 17 61 9" fill="none" stroke="#fff8ec" stroke-width="1.6"/><g transform="rotate(5 13 11)"><path d="M5 11H21V46Q18.3 51 15.7 46Q13 51 10.3 46Q7.7 51 5 46Z" fill="#ff2e88" stroke="#8a1049" stroke-width="1"/><circle cx="13" cy="25" r="4.5" fill="none" stroke="#1d0b2e" stroke-width="3" stroke-dasharray="0.1 2.8" stroke-linecap="round"/><circle cx="13" cy="25" r="1.8" fill="#1d0b2e"/><path d="M13 33L16 37L13 41L10 37Z" fill="#1d0b2e"/><path d="M8 15H18" stroke="#1d0b2e" stroke-width="1.4" stroke-dasharray="1.4 1.6"/></g><g><path d="M24 14H40V50Q37.3 55 34.7 50Q32 55 29.3 50Q26.7 55 24 50Z" fill="#ff9f1c" stroke="#a34a00" stroke-width="1"/><path d="M32 22C35 22 37 25 37 28C37 32 35 34 32 36C29 34 27 32 27 28C27 25 29 22 32 22Z" fill="#1d0b2e"/><circle cx="30" cy="27" r="1.4" fill="#ff9f1c"/><circle cx="34" cy="27" r="1.4" fill="#ff9f1c"/><path d="M32 29.5L31 31H33Z" fill="#ff9f1c"/><circle cx="28" cy="42" r="1.4" fill="#1d0b2e"/><circle cx="32" cy="43" r="1.4" fill="#1d0b2e"/><circle cx="36" cy="42" r="1.4" fill="#1d0b2e"/><path d="M27 18H37" stroke="#1d0b2e" stroke-width="1.4" stroke-dasharray="1.4 1.6"/></g><g transform="rotate(-5 51 11)"><path d="M43 11H59V46Q56.3 51 53.7 46Q51 51 48.3 46Q45.7 51 43 46Z" fill="#1fd1c1" stroke="#0b6e66" stroke-width="1"/><path d="M51 20L53 25L58 25L54 28L55.5 33L51 30L46.5 33L48 28L44 25L49 25Z" fill="#1d0b2e"/><path d="M48 37L51 41L54 37L51 41.5ZM47 40Q51 44 55 40" fill="none" stroke="#1d0b2e" stroke-width="1.6"/><path d="M46 15H56" stroke="#1d0b2e" stroke-width="1.4" stroke-dasharray="1.4 1.6"/></g><circle cx="22.5" cy="12" r="1.6" fill="#a6e22e"/><circle cx="41.5" cy="12" r="1.6" fill="#a6e22e"/>'],
        'H4' => ['name' => 'Ofrenda Candle', 'svg' => '<defs><radialGradient id="calavera-H4-glow" cx="50%" cy="50%" r="50%"><stop offset="0" stop-color="#ffd23f" stop-opacity="0.8"/><stop offset="1" stop-color="#ffd23f" stop-opacity="0"/></radialGradient><linearGradient id="calavera-H4-wax" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#e8d3a8"/><stop offset="0.4" stop-color="#fff6de"/><stop offset="1" stop-color="#d9bd86"/></linearGradient></defs><circle cx="32" cy="12" r="12" fill="url(#calavera-H4-glow)"/><path d="M32 3C36 8 37 12 35 16C34 18 30 18 29 16C27 12 29 8 32 3Z" fill="#ff8c1a"/><path d="M32 8C34 11 34 14 33 15.5C32 16.3 31 16 30.7 15C30.3 13 31 11 32 8Z" fill="#ffe066"/><path d="M32 16V20" stroke="#2a0f3d" stroke-width="1.2"/><rect x="21" y="19" width="22" height="34" rx="2" fill="url(#calavera-H4-wax)" stroke="#6b4a1a" stroke-width="1.4"/><path d="M21 21C23 24 25 20 27 23C29 26 31 21 33 24C36 27 38 21 43 22V20H21Z" fill="#fffaf0"/><circle cx="32" cy="34" r="6.2" fill="none" stroke="#ff2e88" stroke-width="4.2" stroke-dasharray="0.1 3.2" stroke-linecap="round"/><circle cx="32" cy="34" r="3.6" fill="#ff9f1c"/><circle cx="32" cy="34" r="1.6" fill="#ffd23f"/><path d="M26 42Q29 46 32 43Q35 46 38 42" fill="none" stroke="#1fd1c1" stroke-width="1.6" stroke-linecap="round"/><path d="M25 46L29 44L28 48ZM39 46L35 44L36 48Z" fill="#a6e22e"/><rect x="24" y="23" width="3" height="27" rx="1.5" fill="#fff" opacity="0.7"/><path d="M15 53H49L46 59H18Z" fill="#ffd23f" stroke="#8a6200" stroke-width="1.4"/><path d="M19 56H45" stroke="#8a6200" stroke-width="1" stroke-dasharray="1 2"/>'],
        'L1' => ['name' => 'Monarch Butterfly', 'svg' => '<path d="M31 30C26 16 16 8 8 10C3 12 5 22 10 27C15 31 24 32 31 31Z" fill="#ff7b00" stroke="#1a0a0a" stroke-width="2.5"/><path d="M33 30C38 16 48 8 56 10C61 12 59 22 54 27C49 31 40 32 33 31Z" fill="#ff7b00" stroke="#1a0a0a" stroke-width="2.5"/><path d="M31 33C24 33 15 36 13 44C12 50 19 53 24 49C28 46 30 40 31 34Z" fill="#ff9a1f" stroke="#1a0a0a" stroke-width="2.5"/><path d="M33 33C40 33 49 36 51 44C52 50 45 53 40 49C36 46 34 40 33 34Z" fill="#ff9a1f" stroke="#1a0a0a" stroke-width="2.5"/><path d="M30 30L12 16M30 30L10 24M30 30L20 12M31 35L17 45M31 35L23 49M34 30L52 16M34 30L54 24M34 30L44 12M33 35L47 45M33 35L41 49" stroke="#1a0a0a" stroke-width="1.3"/><circle cx="9" cy="15" r="1.1" fill="#fff"/><circle cx="7.5" cy="19" r="1.1" fill="#fff"/><circle cx="55" cy="15" r="1.1" fill="#fff"/><circle cx="56.5" cy="19" r="1.1" fill="#fff"/><circle cx="15" cy="48" r="1" fill="#fff"/><circle cx="49" cy="48" r="1" fill="#fff"/><ellipse cx="32" cy="33" rx="2.4" ry="11" fill="#1a0a0a"/><path d="M31 23Q28 16 25 14M33 23Q36 16 39 14" fill="none" stroke="#1a0a0a" stroke-width="1.3" stroke-linecap="round"/><path d="M14 14Q18 13 22 17" stroke="#ffd28a" stroke-width="1.6" fill="none" stroke-linecap="round"/>'],
        'L2' => ['name' => 'Maracas', 'svg' => '<g transform="translate(-5 1)"><path d="M26 34L13 57" stroke="#1a0829" stroke-width="6" stroke-linecap="round"/><path d="M26 34L13 57" stroke="#c98a3c" stroke-width="3.6" stroke-linecap="round"/><ellipse cx="30" cy="22" rx="11" ry="14" transform="rotate(28 30 22)" fill="#1fd1c1" stroke="#0b4f4a" stroke-width="1.8"/><path d="M20 23Q30 29 38 17" fill="none" stroke="#ffd23f" stroke-width="2.4"/><path d="M22 28Q31 33 37 24" fill="none" stroke="#ff2e88" stroke-width="1.8" stroke-dasharray="0.1 3" stroke-linecap="round"/><ellipse cx="27" cy="14" rx="3" ry="4.5" transform="rotate(28 27 14)" fill="#b8fff7"/></g><g transform="translate(5 1)"><path d="M38 34L51 57" stroke="#1a0829" stroke-width="6" stroke-linecap="round"/><path d="M38 34L51 57" stroke="#c98a3c" stroke-width="3.6" stroke-linecap="round"/><ellipse cx="36" cy="24" rx="11" ry="14" transform="rotate(-28 36 24)" fill="#ff2e88" stroke="#6b0f3a" stroke-width="1.8"/><path d="M28 21Q35 31 45 25" fill="none" stroke="#ffd23f" stroke-width="2.4"/><path d="M27 27Q34 35 43 30" fill="none" stroke="#1fd1c1" stroke-width="1.8" stroke-dasharray="0.1 3" stroke-linecap="round"/><ellipse cx="33" cy="15" rx="3" ry="4.5" transform="rotate(-28 33 15)" fill="#ffc2dd"/></g>'],
        'L3' => ['name' => 'Pan Dulce', 'svg' => '<defs><clipPath id="calavera-L3-top"><path d="M9 38C9 22 20 13 32 13C44 13 55 22 55 38Z"/></clipPath></defs><path d="M6 40C6 36 9 34 12 34H52C55 34 58 36 58 40C58 47 52 51 44 51H20C12 51 6 47 6 40Z" fill="#d9913a" stroke="#6b3a10" stroke-width="1.8"/><path d="M10 44C14 48 50 48 54 44" fill="none" stroke="#b36d20" stroke-width="1.4"/><path d="M9 38C9 22 20 13 32 13C44 13 55 22 55 38C48 41 16 41 9 38Z" fill="#ff8fc4" stroke="#a3265f" stroke-width="1.8"/><g clip-path="url(#calavera-L3-top)" fill="none" stroke="#d6508f" stroke-width="1.5"><path d="M32 38V13M32 38L20 15M32 38L44 15M32 38L11 24M32 38L53 24"/><path d="M14 36Q32 24 50 36M18 29Q32 18 46 29M24 21Q32 15 40 21"/></g><path d="M16 26Q20 18 28 16" fill="none" stroke="#ffd6ea" stroke-width="2.4" stroke-linecap="round"/>'],
        'L4' => ['name' => 'Chili Pepper', 'svg' => '<path d="M40 14C49 14 54 20 52 29C49 42 34 54 14 57C10 57.5 9 55 12 53C26 46 34 36 34 24C34 18 36 14 40 14Z" fill="#e3121b" stroke="#6b0508" stroke-width="2"/><path d="M40 19C44 19 47 22 46 27C44 35 36 44 26 49C33 42 38 33 38 25C38 22 38.5 20 40 19Z" fill="#ff5a4f"/><path d="M41 21Q44 22 44 26" stroke="#ffd0c8" stroke-width="2" fill="none" stroke-linecap="round"/><path d="M34 15C37 11 43 10 47 13C45 16 39 17 34 15Z" fill="#6cc417" stroke="#2f5e08" stroke-width="1.4"/><path d="M40 12C40 8 42 5 46 4" fill="none" stroke="#2f5e08" stroke-width="3" stroke-linecap="round"/><path d="M40 12C40 8 42 5 46 4" fill="none" stroke="#6cc417" stroke-width="1.6" stroke-linecap="round"/>'],
        'L5' => ['name' => 'Rose', 'svg' => '<path d="M32 36Q31 48 34 60" fill="none" stroke="#2f7a0c" stroke-width="3" stroke-linecap="round"/><path d="M33 47C26 42 18 44 14 50C21 53 28 52 33 47Z" fill="#8bd61f" stroke="#2f5e08" stroke-width="1.3"/><path d="M33 51C39 46 47 47 51 52C45 56 38 55 33 51Z" fill="#8bd61f" stroke="#2f5e08" stroke-width="1.3"/><path d="M14 23C13 13 22 6 32 6C42 6 51 13 50 23C49 33 41 39 32 39C23 39 15 33 14 23Z" fill="#c2005b" stroke="#5c0029" stroke-width="1.8"/><path d="M19 22C19 14 25 10 32 10C39 10 45 14 45 22C45 30 39 34 32 34C25 34 19 30 19 22Z" fill="#ff2e88"/><path d="M24 21C24 16 28 13 32 13C37 13 40 16 40 21C40 27 36 30 32 30C28 30 24 26 24 21Z" fill="#e0006e"/><path d="M27 21C27 18 30 16 33 16.5C36 17 37 20 36 22.5C35 25 31 26 29 24C27.5 22.5 28.5 20 31 20C32.5 20 33 21.5 32 22.5" fill="none" stroke="#5c0029" stroke-width="1.4" stroke-linecap="round"/><path d="M14 23C18 32 26 36 32 36C38 36 46 32 50 23" fill="none" stroke="#8a003f" stroke-width="1.4"/><path d="M20 15Q24 10 29 9" fill="none" stroke="#ffc2dd" stroke-width="2" stroke-linecap="round"/>'],
    ],
];

/* ═════════════════════════ 3D GAMES: engines ═════════════════════════
 * Same rule as everything else: the server decides, the 3D scene acts it out.
 */

/* ── Coronado Roulette 3D: same single-zero rules as the 2D table, chip-board bet keys ── */
function roulette3d_play(): array {
    $p = require_playable(); $g = game_cfg('roulette3d');
    [$bets, $total] = parse_bets($g, function (string $k) {
        if (!preg_match('/^(straight|red|black|odd|even|low|high|dozen|column):(0|[1-9]\d?)$/', $k, $m)) { return false; }   // exact spelling: no "017"
        $v = (int)$m[2];
        return match ($m[1]) { 'straight' => $v >= 0 && $v <= 36, 'dozen', 'column' => $v >= 1 && $v <= 3, default => $v === 0 };
    });
    $n = random_int(0, 36);
    $payout = 0; $wins = [];
    foreach ($bets as $k => $amt) {
        [$type, $v] = explode(':', $k);
        $x = roulette_wins($type, (int)$v, $n);
        if ($x) { $payout += $amt * $x; $wins[] = $k; }
    }
    $pid = (int)$p['id'];
    tx(fn() => round_oneshot($pid, 'roulette3d', $total, $payout, (string)$n, ['number' => $n, 'bets' => $bets]));
    $color = $n === 0 ? 'green' : (in_array($n, ROULETTE_RED, true) ? 'red' : 'black');
    return ['number' => $n, 'color' => $color, 'win_keys' => $wins, 'payout' => $payout, 'bet' => $total, 'win' => $payout > $total,
        'balance' => bal($pid), 'message' => "$n " . strtoupper($color) . ($payout ? ' · returned ' . coins($payout) . ' GC' : ' · house takes it')];
}

/* ── Harbor Craps: the full bubble-craps menu ──
 * Returns below include the stake unless noted. "Stays up" bets (place, buy, lay, big 6/8,
 * hardways) pay their profit and remain on the layout, and are OFF on the come-out roll.
 * House edge (standard): pass 1.41%, don't pass 1.36%, come 1.41%, don't come 1.36%, odds 0%,
 * place 6/8 1.52%, place 5/9 4.0%, place 4/10 6.67%, buy (5% on win) 1.67%, lay 4/10 2.44%,
 * big 6/8 9.09%, field 2.78%, hard 6/8 9.09%, hard 4/10 11.1%, 2/12 13.9%, 3/11 11.1%,
 * any craps 11.1%, horn 12.5%, C&E 11.1%, any seven 16.7%.
 */
const CRAPS_NUMS = [4, 5, 6, 8, 9, 10];
const CRAPS_ONE_ROLL = ['field', 'any7', 'anycraps', 'ace2', 'ace3', 'yo', 'twelve', 'horn', 'ce'];
const CRAPS_TRUE = [4 => [2, 1], 10 => [2, 1], 5 => [3, 2], 9 => [3, 2], 6 => [6, 5], 8 => [6, 5]];   // odds on the number
const CRAPS_PLACE = [4 => [9, 5], 10 => [9, 5], 5 => [7, 5], 9 => [7, 5], 6 => [7, 6], 8 => [7, 6]];
const CRAPS_ODDS_MAX = [4 => 3, 10 => 3, 5 => 4, 9 => 4, 6 => 5, 8 => 5];                          // 3-4-5× odds
function craps_label(string $k): string {
    static $L = ['pass' => 'Pass line', 'dontpass' => "Don't pass", 'passodds' => 'Pass odds', 'dpodds' => "Don't pass odds",
        'come' => 'Come', 'dontcome' => "Don't come", 'field' => 'Field', 'any7' => 'Any seven', 'anycraps' => 'Any craps',
        'ace2' => 'Aces (2)', 'ace3' => 'Ace-deuce (3)', 'yo' => 'Yo (11)', 'twelve' => 'Boxcars (12)', 'horn' => 'Horn', 'ce' => 'C & E',
        'big6' => 'Big 6', 'big8' => 'Big 8'];
    if (isset($L[$k])) { return $L[$k]; }
    if (preg_match('/^(hard|place|buy|lay|come|comeodds|dcome|dcomeodds)(\d+)$/', $k, $m)) {
        return ['hard' => 'Hard ', 'place' => 'Place ', 'buy' => 'Buy ', 'lay' => 'Lay ', 'come' => 'Come ', 'comeodds' => 'Come odds ', 'dcome' => "Don't come ", 'dcomeodds' => "Don't come odds "][$m[1]] . $m[2];
    }
    return $k;
}
/** Keys a player may add chips to directly (come points themselves are created by rolls). */
function craps_placeable(string $k): bool {
    if (in_array($k, ['pass', 'dontpass', 'passodds', 'dpodds', 'come', 'dontcome', 'big6', 'big8', ...CRAPS_ONE_ROLL], true)) { return true; }
    if (preg_match('/^hard(4|6|8|10)$/', $k)) { return true; }
    return (bool)preg_match('/^(place|buy|lay|comeodds|dcomeodds)(4|5|6|8|9|10)$/', $k);
}
function craps_removable(string $k): bool {
    return !in_array($k, ['pass', 'come'], true) && !preg_match('/^come\d+$/', $k) && !in_array($k, CRAPS_ONE_ROLL, true);
}
function craps_state(?array $r): array {
    $s = st($r);
    $bets = $s['bets'] ?? [];
    if (isset($bets['odds'])) { $bets['passodds'] = ($bets['passodds'] ?? 0) + $bets['odds']; unset($bets['odds']); }   // v1 name
    if (isset($bets['yo'])) { /* same key */ }
    // action / won: stakes actually decided so far and what they returned. Chips parked and taken back down never
    // enter either, so the stats and the leaderboard count rounds that were really played (paid also counts take-downs).
    return ['point' => (int)($s['point'] ?? 0), 'bets' => $bets, 'paid' => (int)($s['paid'] ?? 0), 'rolls' => $s['rolls'] ?? [],
        'action' => (int)($s['action'] ?? 0), 'won' => (int)($s['won'] ?? 0)];
}
/** Validate one chip placement against the current table state. Throws DomainException. */
function craps_check_add(array $s, string $k, int $amt, array $g): void {
    $b = $s['bets']; $pt = $s['point']; $cur = ($b[$k] ?? 0) + $amt; $max = (int)$g['max_bet'];
    $need = function (bool $ok, string $why) { if (!$ok) { throw new DomainException($why); } };
    switch (true) {
        case $k === 'pass' || $k === 'dontpass':
            $need(!$pt, 'Line bets go down on the come-out roll only.'); break;
        case $k === 'come' || $k === 'dontcome':
            $need((bool)$pt, 'Come and Don\'t Come need a point to be on.'); break;
        case $k === 'passodds':
            $need($pt && !empty($b['pass']), 'Pass odds need a pass line bet and a point.');
            $need($cur <= $b['pass'] * CRAPS_ODDS_MAX[$pt], 'Odds on ' . $pt . ' max out at ' . CRAPS_ODDS_MAX[$pt] . '× your pass line.'); return;
        case $k === 'dpodds':
            $need($pt && !empty($b['dontpass']), 'Lay odds need a don\'t pass bet and a point.');
            $need($cur <= $b['dontpass'] * 6, 'Lay odds max out at 6× your don\'t pass.'); return;
        case (bool)preg_match('/^comeodds(\d+)$/', $k, $m):
            $need(!empty($b['come' . $m[1]]), 'Come odds need a come bet sitting on ' . $m[1] . '.');
            $need($cur <= $b['come' . $m[1]] * CRAPS_ODDS_MAX[(int)$m[1]], 'Odds max out at ' . CRAPS_ODDS_MAX[(int)$m[1]] . '× the come bet.'); return;
        case (bool)preg_match('/^dcomeodds(\d+)$/', $k, $m):
            $need(!empty($b['dcome' . $m[1]]), 'Lay odds need a don\'t come bet on ' . $m[1] . '.');
            $need($cur <= $b['dcome' . $m[1]] * 6, 'Lay odds max out at 6× the don\'t come bet.'); return;
        case $k === 'horn':
            $need($amt % 4 === 0, 'Horn bets split four ways, so use a multiple of 4.'); break;
        case $k === 'ce':
            $need($amt % 2 === 0, 'C & E splits two ways, so use an even amount.'); break;
    }
    $need($cur <= $max, 'Table max on ' . craps_label($k) . ' is ' . coins($max) . ' GC.');
}

function craps_act(): array {
    $p = require_playable(); $g = game_cfg('craps');
    $pid = (int)$p['id'];
    $move = (string)($_POST['move'] ?? 'roll');
    $new = [];
    $raw = $_POST['bets'] ?? '';
    if ((is_string($raw) && $raw !== '' && $raw !== '[]') || !empty($_POST['bet_key'])) {
        [$new] = parse_bets($g, 'craps_placeable');
    }

    if ($move === 'takedown') {
        $keys = array_filter(explode(',', (string)($_POST['keys'] ?? '')), 'craps_removable');
        if (!$keys) { fail('Nothing to take down there.'); }
        $out = tx(function () use ($pid, $keys) {
            $r = round_active($pid, 'craps');
            if (!$r) { throw new DomainException('No bets on the table.'); }
            $s = craps_state($r); $back = 0;
            foreach ($keys as $k) { if (isset($s['bets'][$k])) { $back += $s['bets'][$k]; unset($s['bets'][$k]); } }
            if (!$back) { throw new DomainException('Nothing to take down there.'); }
            // chips coming back down were never decided, so this reverses the wager (a positive 'wager' row) instead of
            // paying out: "wagered today" and per-game RTP net it to zero rather than counting it as handle and a 100% return
            move_coins($pid, $back, 'wager', 'craps', 'took down ' . implode(', ', $keys));
            $s['paid'] += $back;
            if (!$s['bets']) {
                q("UPDATE rounds SET status = 'done', outcome = 'down', payout = ?, state = ?, updated_at = datetime('now') WHERE id = ?", [$s['paid'], json_encode($s), $r['id']]);
                if ($s['action'] > 0) { record_round($pid, $s['action'], $s['won']); }   // park-and-take-down is not a round played
            } else { round_save($r, $s); }
            return ['state' => $s, 'back' => $back];
        });
        return ['dice' => null, 'point' => $out['state']['point'], 'bets' => (object)$out['state']['bets'], 'events' => [], 'payout' => 0, 'win' => false,
            'balance' => bal($pid), 'message' => 'Took down ' . coins($out['back']) . ' GC.'];
    }

    $out = tx(function () use ($pid, $new, $g) {
        $r = round_active($pid, 'craps');
        $s = craps_state($r);
        foreach ($new as $k => $amt) { craps_check_add($s, $k, $amt, $g); $s['bets'][$k] = ($s['bets'][$k] ?? 0) + $amt; }
        $stake = array_sum($new);
        if (!$s['bets']) { throw new DomainException('Put some chips on the table first.'); }
        if ($stake) { $r = $r ? round_raise($r, $stake, 'craps chips') : round_open($pid, 'craps', $stake, []); }

        $d = [random_int(1, 6), random_int(1, 6)];
        $sum = $d[0] + $d[1]; $hard = $d[0] === $d[1]; $pt = $s['point']; $comeOut = !$pt;
        $pay = 0; $events = []; $act = 0; $won = 0;   // act / won: stakes decided on this roll and what they returned (stats only)
        $B = &$s['bets'];
        $credit = function (string $k, int $amt, string $what, bool $remove = true) use (&$B, &$pay, &$events, &$act, &$won) {
            // a stay-up win pays profit only and keeps the stake working: count that as stake returned and re-bet
            $act += $B[$k]; $won += $remove ? $amt : $amt + $B[$k];
            $pay += $amt; $events[] = ['key' => $k, 'win' => true, 'text' => craps_label($k) . ' ' . $what . ' +' . coins($amt)];
            if ($remove) { unset($B[$k]); }
        };
        $lose = function (string $k) use (&$B, &$events, &$act) { $act += $B[$k]; $events[] = ['key' => $k, 'win' => false, 'text' => craps_label($k) . ' loses']; unset($B[$k]); };
        $push = function (string $k, string $why) use (&$B, &$pay, &$events, &$act, &$won) { $act += $B[$k]; $won += $B[$k]; $pay += $B[$k]; $events[] = ['key' => $k, 'win' => null, 'text' => craps_label($k) . ' ' . $why]; unset($B[$k]); };
        $trueRet = fn(int $amt, int $n) => $amt + intdiv($amt * CRAPS_TRUE[$n][0], CRAPS_TRUE[$n][1]);
        $layRet = fn(int $amt, int $n) => $amt + intdiv($amt * CRAPS_TRUE[$n][1], CRAPS_TRUE[$n][0]);
        $vig = fn(int $win) => max(1, (int)floor($win * 0.05));

        // ── one-roll bets ──
        foreach (CRAPS_ONE_ROLL as $k) {
            if (!isset($B[$k])) { continue; }
            $a = $B[$k];
            $ret = match ($k) {
                'field' => $sum === 2 ? $a * 3 : ($sum === 12 ? $a * 4 : (in_array($sum, [3, 4, 9, 10, 11], true) ? $a * 2 : 0)),
                'any7' => $sum === 7 ? $a * 5 : 0,
                'anycraps' => in_array($sum, [2, 3, 12], true) ? $a * 8 : 0,
                'ace2' => $sum === 2 ? $a * 31 : 0,
                'twelve' => $sum === 12 ? $a * 31 : 0,
                'ace3' => $sum === 3 ? $a * 16 : 0,
                'yo' => $sum === 11 ? $a * 16 : 0,
                'horn' => in_array($sum, [2, 12], true) ? intdiv($a, 4) * 31 : (in_array($sum, [3, 11], true) ? intdiv($a, 4) * 16 : 0),
                'ce' => in_array($sum, [2, 3, 12], true) ? intdiv($a, 2) * 8 : ($sum === 11 ? intdiv($a, 2) * 16 : 0),
            };
            $ret ? $credit($k, $ret, 'hits') : $lose($k);
        }
        // ── stay-up bets: place, buy, lay, big 6/8, hardways (all OFF on the come-out) ──
        if (!$comeOut) {
            foreach (CRAPS_NUMS as $n) {
                if (isset($B["place$n"])) {
                    if ($sum === $n) { $a = $B["place$n"]; $credit("place$n", intdiv($a * CRAPS_PLACE[$n][0], CRAPS_PLACE[$n][1]), 'pays', false); }
                    elseif ($sum === 7) { $lose("place$n"); }
                }
                if (isset($B["buy$n"])) {
                    if ($sum === $n) { $a = $B["buy$n"]; $w = intdiv($a * CRAPS_TRUE[$n][0], CRAPS_TRUE[$n][1]); $credit("buy$n", $w - $vig($w), 'pays true odds (less 5%)', false); }
                    elseif ($sum === 7) { $lose("buy$n"); }
                }
                if (isset($B["lay$n"])) {
                    if ($sum === 7) { $a = $B["lay$n"]; $w = intdiv($a * CRAPS_TRUE[$n][1], CRAPS_TRUE[$n][0]); $credit("lay$n", $w - $vig($w), 'wins (less 5%)', false); }
                    elseif ($sum === $n) { $lose("lay$n"); }
                }
            }
            foreach ([6, 8] as $n) {
                if (!isset($B["big$n"])) { continue; }
                if ($sum === $n) { $credit("big$n", $B["big$n"], 'pays even money', false); } elseif ($sum === 7) { $lose("big$n"); }
            }
            foreach ([4, 6, 8, 10] as $n) {
                if (!isset($B["hard$n"])) { continue; }
                if ($sum === $n && $hard) { $credit("hard$n", $B["hard$n"] * ($n === 6 || $n === 8 ? 9 : 7), 'hits the hard way', false); }
                elseif ($sum === 7 || $sum === $n) { $lose("hard$n"); }
            }
        }
        // ── come points already on the numbers (come odds are off on the come-out, don't-come odds always work) ──
        foreach (CRAPS_NUMS as $n) {
            if (isset($B["come$n"])) {
                if ($sum === $n) {
                    $credit("come$n", $B["come$n"] * 2, 'hits');
                    if (isset($B["comeodds$n"])) { $comeOut ? $push("comeodds$n", 'returned (odds off on the come-out)') : $credit("comeodds$n", $trueRet($B["comeodds$n"], $n), 'pays true odds'); }
                } elseif ($sum === 7) {
                    $lose("come$n");
                    if (isset($B["comeodds$n"])) { $comeOut ? $push("comeodds$n", 'returned (odds off on the come-out)') : $lose("comeodds$n"); }
                }
            }
            if (isset($B["dcome$n"])) {
                if ($sum === 7) {
                    $credit("dcome$n", $B["dcome$n"] * 2, 'wins');
                    if (isset($B["dcomeodds$n"])) { $credit("dcomeodds$n", $layRet($B["dcomeodds$n"], $n), 'lay odds win'); }
                } elseif ($sum === $n) { $lose("dcome$n"); if (isset($B["dcomeodds$n"])) { $lose("dcomeodds$n"); } }
            }
        }
        // ── new come / don't come bets travel ──
        if (isset($B['come'])) {
            $a = $B['come'];
            if ($sum === 7 || $sum === 11) { $credit('come', $a * 2, 'wins'); }
            elseif (in_array($sum, [2, 3, 12], true)) { $lose('come'); }
            else { unset($B['come']); $B["come$sum"] = ($B["come$sum"] ?? 0) + $a; $events[] = ['key' => "come$sum", 'win' => null, 'text' => "Come bet moves to $sum"]; }
        }
        if (isset($B['dontcome'])) {
            $a = $B['dontcome'];
            if ($sum === 2 || $sum === 3) { $credit('dontcome', $a * 2, 'wins'); }
            elseif ($sum === 12) { $push('dontcome', 'pushes on 12'); }
            elseif ($sum === 7 || $sum === 11) { $lose('dontcome'); }
            else { unset($B['dontcome']); $B["dcome$sum"] = ($B["dcome$sum"] ?? 0) + $a; $events[] = ['key' => "dcome$sum", 'win' => null, 'text' => "Don't come moves behind $sum"]; }
        }
        // ── line bets ──
        if ($comeOut) {
            if ($sum === 7 || $sum === 11) {
                if (isset($B['pass'])) { $credit('pass', $B['pass'] * 2, 'natural'); }
                if (isset($B['dontpass'])) { $lose('dontpass'); }
            } elseif (in_array($sum, [2, 3, 12], true)) {
                if (isset($B['pass'])) { $lose('pass'); }
                if (isset($B['dontpass'])) { $sum === 12 ? $push('dontpass', 'pushes on 12') : $credit('dontpass', $B['dontpass'] * 2, 'wins'); }
            } else {
                $s['point'] = $sum;
                $events[] = ['key' => 'point', 'win' => null, 'text' => "Point is $sum"];
            }
        } elseif ($sum === $pt) {
            if (isset($B['pass'])) { $credit('pass', $B['pass'] * 2, 'hits the point'); }
            if (isset($B['passodds'])) { $credit('passodds', $trueRet($B['passodds'], $pt), 'pays true odds'); }
            if (isset($B['dontpass'])) { $lose('dontpass'); }
            if (isset($B['dpodds'])) { $lose('dpodds'); }
            $s['point'] = 0;
            $events[] = ['key' => 'point', 'win' => null, 'text' => 'Winner! Point made'];
        } elseif ($sum === 7) {
            foreach (['pass', 'passodds'] as $k) { if (isset($B[$k])) { $lose($k); } }
            if (isset($B['dontpass'])) { $credit('dontpass', $B['dontpass'] * 2, 'wins on seven-out'); }
            if (isset($B['dpodds'])) { $credit('dpodds', $layRet($B['dpodds'], $pt), 'lay odds win'); }
            $s['point'] = 0;
            $events[] = ['key' => 'point', 'win' => null, 'text' => 'Seven out'];
        }
        unset($B);
        if ($pay) { move_coins($pid, $pay, 'payout', 'craps', "roll $d[0]-$d[1]"); }
        $s['paid'] += $pay; $s['action'] += $act; $s['won'] += $won;
        $s['rolls'] = array_slice([...$s['rolls'], $d], -16);
        if (!$s['bets']) {
            $s['point'] = 0;
            q("UPDATE rounds SET status = 'done', outcome = ?, payout = ?, state = ?, updated_at = datetime('now') WHERE id = ?",
                ["$d[0]-$d[1]", $s['paid'], json_encode($s), $r['id']]);
            if ($s['action'] > 0) { record_round($pid, $s['action'], $s['won']); }   // only chips that were decided count as played
        } else {
            round_save($r, $s);
        }
        return ['dice' => $d, 'sum' => $sum, 'state' => $s, 'pay' => $pay, 'events' => $events];
    });
    $s = $out['state'];
    $wins = array_values(array_filter($out['events'], fn($e) => $e['win'] === true));
    $msg = $out['sum'] . ($out['dice'][0] === $out['dice'][1] ? ' (hard)' : '') . ' · '
        . ($out['events'] ? implode(' · ', array_map(fn($e) => $e['text'], array_slice($out['events'], 0, 5))) . (count($out['events']) > 5 ? ' …' : '') : 'no decision');
    return ['dice' => $out['dice'], 'sum' => $out['sum'], 'point' => $s['point'], 'bets' => (object)$s['bets'], 'events' => $out['events'],
        'rolls' => $s['rolls'], 'payout' => $out['pay'], 'win' => $out['pay'] > 0 && (bool)$wins, 'balance' => bal($pid), 'message' => $msg];
}

/* ── Pier Pusher ──
 * Each coin you drop costs your bet. How many coins spill over the edge is drawn from a
 * fixed table (returns × bet): EV = 0.95, about 46% of drops pay something.
 * Where you drop is just for fun: the push is decided when the coin leaves your hand.
 */
const PUSHER_TABLE = [1 => 27000, 2 => 10000, 3 => 5000, 5 => 2600, 10 => 800, 25 => 240, 100 => 60]; // per 100,000 drops; the rest spill nothing
function pusher_play(): array {
    $p = require_playable(); $g = game_cfg('pusher');
    $bet = clamp_bet($_POST['bet'] ?? '', $g);
    $lane = max(0, min(100, (int)($_POST['lane'] ?? 50)));
    $roll = random_int(1, 100000); $n = 0; $acc = 0;
    foreach (PUSHER_TABLE as $k => $w) { $acc += $w; if ($roll <= $acc) { $n = $k; break; } }
    $payout = $bet * $n;
    $pid = (int)$p['id'];
    tx(fn() => round_oneshot($pid, 'pusher', $bet, $payout, $n . ' coins', ['coins' => $n, 'lane' => $lane]));
    return ['coins' => $n, 'lane' => $lane, 'jackpot' => $n >= 25, 'payout' => $payout, 'bet' => $bet, 'win' => $payout > $bet, 'balance' => bal($pid),
        'message' => $n ? ($n >= 25 ? 'AVALANCHE! ' : '') . $n . ' coin' . ($n > 1 ? 's' : '') . ' spilled · +' . coins($payout) . ' GC' : 'Nothing fell this time.'];
}

/* ═════════════════════════ POKER ENGINE: no-limit Texas hold'em ═════════════════════════
 * Pure functions over a table state array (see REALTIME.md → "Poker engine API").
 * ws.php hosts the tables and owns persistence; nothing in here touches the database or the session.
 */
// [[REGION poker-engine]]
function pk_placeholder(): void {}
// [[/REGION poker-engine]]

/* ═════════════════════════ FREE COINS ═════════════════════════ */

function daily_status(array $p): array {
    $last = $p['last_daily_at'] ? strtotime($p['last_daily_at'] . ' UTC') : 0;
    $next = $last ? $last + 22 * 3600 : 0; // 22h so a daily habit can drift a little
    $streakAlive = $last && (time() - $last) <= 48 * 3600;
    $streak = $streakAlive ? min((int)$p['daily_streak'] + 1, isetting('daily_max_streak', 7)) : 1;
    $amount = isetting('daily_base', 1000) + isetting('daily_step', 250) * ($streak - 1);
    return ['ready' => time() >= $next, 'next_at' => $next ? gmdate('Y-m-d H:i:s', $next) : null,
        'wait' => max(0, $next - time()), 'streak' => $streak, 'amount' => $amount];
}

function refill_status(array $p): array {
    $last = $p['last_refill_at'] ? strtotime($p['last_refill_at'] . ' UTC') : 0;
    $next = $last + isetting('refill_hours', 4) * 3600;
    // "running low" counts chips on the table too, so parking take-down-able craps chips can't fake a low balance
    $low = ((int)$p['balance'] + coins_in_play((int)$p['id'])) < isetting('refill_below', 500);
    return ['ready' => $low && time() >= $next, 'low' => $low, 'wait' => max(0, $next - time()),
        'amount' => isetting('refill_amount', 2500)];
}

function claim_daily(): array {
    $p = require_playable();
    return tx(function () use ($p) {
        $p = row('SELECT * FROM players WHERE id = ?', [$p['id']]); // re-read inside the lock
        $s = daily_status($p);
        if (!$s['ready']) { throw new DomainException('Daily bonus is back in ' . human_wait($s['wait']) . '.'); }
        $bal = move_coins((int)$p['id'], $s['amount'], 'daily', null, 'streak day ' . $s['streak']);
        q("UPDATE players SET last_daily_at = datetime('now'), daily_streak = ? WHERE id = ?", [$s['streak'], $p['id']]);
        return ['amount' => $s['amount'], 'streak' => $s['streak'], 'balance' => $bal,
            'message' => '+' . coins($s['amount']) . ' GC · day ' . $s['streak'] . ' streak'];
    });
}

function claim_refill(): array {
    $p = require_playable();
    return tx(function () use ($p) {
        $p = row('SELECT * FROM players WHERE id = ?', [$p['id']]);
        $s = refill_status($p);
        if (!$s['low']) { throw new DomainException('Refills unlock when your balance plus chips on the table drops under ' . coins(isetting('refill_below', 500)) . ' GC.'); }
        if (!$s['ready']) { throw new DomainException('Next refill in ' . human_wait($s['wait']) . '.'); }
        $bal = move_coins((int)$p['id'], $s['amount'], 'refill');
        q("UPDATE players SET last_refill_at = datetime('now') WHERE id = ?", [$p['id']]);
        return ['amount' => $s['amount'], 'balance' => $bal, 'message' => 'Topped up +' . coins($s['amount']) . ' GC'];
    });
}

function redeem_promo(): array {
    $p = require_playable();
    $key = 'promo:' . $p['id'];
    if (!attempts_left($key)) { fail('Too many wrong codes. Try again in ' . ATTEMPT_WINDOW_MIN . ' minutes.', 429); }
    $code = strtoupper(trim((string)($_POST['code'] ?? '')));
    if (!preg_match('/^[A-Z0-9_-]{3,32}$/', $code)) { note_failed_attempt($key); fail('That code doesn\'t look right.'); }

    try {
        return tx(function () use ($p, $code) {
            $pc = row('SELECT * FROM promo_codes WHERE code = ?', [$code]);
            if (!$pc || !(int)$pc['active'] || ($pc['expires_at'] && $pc['expires_at'] < now())) {
                throw new InvalidArgumentException('Code not found or expired.');
            }
            if ((int)$pc['max_uses'] > 0 && (int)$pc['uses'] >= (int)$pc['max_uses']) { throw new DomainException('That code is all used up.'); }
            if (val('SELECT 1 FROM promo_redemptions WHERE promo_id = ? AND player_id = ?', [$pc['id'], $p['id']])) {
                throw new DomainException('You already redeemed that one.');
            }
            q('INSERT INTO promo_redemptions (promo_id, player_id, coins) VALUES (?,?,?)', [$pc['id'], $p['id'], $pc['coins']]);
            q("UPDATE promo_codes SET uses = uses + 1, updated_at = datetime('now') WHERE id = ?", [$pc['id']]);
            $bal = move_coins((int)$p['id'], (int)$pc['coins'], 'promo', null, $pc['code']);
            return ['amount' => (int)$pc['coins'], 'balance' => $bal, 'message' => 'Code accepted! +' . coins((int)$pc['coins']) . ' GC'];
        });
    } catch (InvalidArgumentException $e) {
        note_failed_attempt($key);
        fail($e->getMessage());
    }
}

function human_wait(int $s): string {
    if ($s >= 3600) { return intdiv($s, 3600) . 'h ' . intdiv($s % 3600, 60) . 'm'; }
    if ($s >= 60) { return intdiv($s, 60) . 'm'; }
    return max(1, $s) . 's';
}

/* ═════════════════════════ PLAYER ACCOUNTS ═════════════════════════ */

function do_register(): void {
    csrf_check();
    if (!isetting('registration_open', 1)) { fail('New signups are paused right now.'); }
    $ipKey = 'signup:' . client_ip();
    if (!attempts_left($ipKey)) { fail('Too many signups from this network. Try again later.', 429); }

    $u = trim((string)($_POST['username'] ?? ''));
    $e = trim((string)($_POST['email'] ?? ''));
    $pw = (string)($_POST['password'] ?? '');
    $errs = [];
    if (!preg_match('/^[A-Za-z0-9_]{3,24}$/', $u)) { $errs['username'] = '3–24 letters, numbers, or underscores.'; }
    elseif (val('SELECT 1 FROM players WHERE username = ?', [$u])) { $errs['username'] = 'That name is taken.'; }
    if ($e !== '' && !filter_var($e, FILTER_VALIDATE_EMAIL)) { $errs['email'] = 'That email doesn\'t look valid.'; }
    if (strlen($pw) < 8) { $errs['password'] = 'At least 8 characters.'; }
    elseif ($pw !== (string)($_POST['password2'] ?? '')) { $errs['password2'] = 'Passwords don\'t match.'; }
    if (empty($_POST['age_ok'])) { $errs['age_ok'] = 'You need to confirm your age.'; }
    if (empty($_POST['terms_ok'])) { $errs['terms_ok'] = 'Please accept the play-money terms.'; }
    if ($errs) {
        $_SESSION['form_errors'] = $errs;
        $_SESSION['form_old'] = ['username' => $u, 'email' => $e];
        redirect(url('register'));
    }

    note_failed_attempt($ipKey); // counts every signup, not just failures
    $start = isetting('starting_coins', 10000);
    $pid = tx(function () use ($u, $e, $pw, $start) {
        q('INSERT INTO players (username, email, pass_hash) VALUES (?,?,?)',
            [$u, $e !== '' ? $e : null, password_hash($pw, PASSWORD_BCRYPT, ['cost' => 12])]);
        $pid = (int)db()->lastInsertId();
        move_coins($pid, $start, 'signup', null, 'welcome coins');
        return $pid;
    });
    session_regenerate_id(true);
    $_SESSION['pid'] = $pid;
    q("UPDATE players SET last_login_at = datetime('now') WHERE id = ?", [$pid]);
    flash('ok', 'Welcome aboard! ' . coins($start) . ' Gold Coins are in your stack.');
    redirect(url());
}

function do_login(): void {
    csrf_check();
    $u = trim((string)($_POST['username'] ?? ''));
    $key = 'player:' . client_ip() . '|' . strtolower($u);
    if (!attempts_left($key)) { fail('Too many tries. Wait ' . ATTEMPT_WINDOW_MIN . ' minutes and try again.', 429); }
    $p = row('SELECT * FROM players WHERE username = ?', [$u]);
    // always run a bcrypt verify so response time doesn't reveal which usernames exist
    $ok = password_verify((string)($_POST['password'] ?? ''), $p['pass_hash'] ?? '$2y$12$EIHsUnF2la1bkL6j5/6aWuFAR70Axe0kWuYjn2srqaZG4o5UWPHFu');
    if (!$p || !$ok) {
        note_failed_attempt($key);
        $_SESSION['form_old'] = ['username' => $u];
        fail('Wrong username or password.');
    }
    if ($p['status'] !== 'active') { fail('This account is suspended. Reach out to the site team.'); }
    clear_attempts($key);
    session_regenerate_id(true);
    $_SESSION['pid'] = (int)$p['id'];
    if (password_needs_rehash($p['pass_hash'], PASSWORD_BCRYPT, ['cost' => 12])) {
        q('UPDATE players SET pass_hash = ? WHERE id = ?', [password_hash((string)$_POST['password'], PASSWORD_BCRYPT, ['cost' => 12]), $p['id']]);
    }
    q("UPDATE players SET last_login_at = datetime('now') WHERE id = ?", [$p['id']]);
    redirect(url());
}

function do_player_password(): void {
    csrf_check();
    $p = require_player();
    $new = (string)($_POST['new_password'] ?? '');
    if (!password_verify((string)($_POST['current_password'] ?? ''), $p['pass_hash'])) { fail('Current password is wrong.'); }
    if (strlen($new) < 8) { fail('New password needs at least 8 characters.'); }
    if ($new !== (string)($_POST['new_password2'] ?? '')) { fail('New passwords don\'t match.'); }
    q("UPDATE players SET pass_hash = ?, updated_at = datetime('now') WHERE id = ?",
        [password_hash($new, PASSWORD_BCRYPT, ['cost' => 12]), $p['id']]);
    session_regenerate_id(true);
    flash('ok', 'Password updated.');
    redirect(url('account'));
}

function do_take_break(): void {
    csrf_check();
    $p = require_player();
    $days = (int)($_POST['days'] ?? 0);
    if (!in_array($days, [1, 7, 30, 90], true)) { fail('Pick 1, 7, 30, or 90 days.'); }
    if (($_POST['confirm'] ?? '') !== 'BREAK') { fail('Type BREAK to confirm.'); }
    $until = gmdate('Y-m-d H:i:s', time() + $days * 86400);
    // a break can only be extended, never shortened, from the player side
    q("UPDATE players SET break_until = MAX(COALESCE(break_until, ''), ?), updated_at = datetime('now') WHERE id = ?", [$until, $p['id']]);
    flash('ok', "Break's on. Games unlock again after $until UTC. Proud of you for checking in with yourself.");
    redirect(url('account'));
}

/* ═════════════════════════ ADMIN: auth ═════════════════════════ */

const ADMIN_IDLE_SECONDS = 7200;

function current_admin(): ?array {
    $id = (int)($_SESSION['admin_id'] ?? 0);
    if (!$id) { return null; }
    if (time() - (int)($_SESSION['admin_seen'] ?? 0) > ADMIN_IDLE_SECONDS) {
        unset($_SESSION['admin_id'], $_SESSION['admin_seen']);
        return null;
    }
    $_SESSION['admin_seen'] = time();
    return row('SELECT id, username, last_login_at FROM admins WHERE id = ?', [$id]);
}

function require_admin(): array {
    $a = current_admin();
    if (!$a) {
        if (wants_json()) { json_out(['ok' => false, 'data' => null, 'error' => 'Admin login required.'], 401); }
        redirect(url('admin_login'));
    }
    return $a;
}

function do_admin_login(): void {
    csrf_check();
    $u = trim((string)($_POST['username'] ?? ''));
    $key = 'admin:' . client_ip() . '|' . strtolower($u);
    if (!attempts_left($key)) { fail('Locked out for ' . ATTEMPT_WINDOW_MIN . ' minutes after too many attempts.', 429); }
    $a = row('SELECT * FROM admins WHERE username = ?', [$u]);
    $ok = password_verify((string)($_POST['password'] ?? ''), $a['pass_hash'] ?? '$2y$12$EIHsUnF2la1bkL6j5/6aWuFAR70Axe0kWuYjn2srqaZG4o5UWPHFu');
    if (!$a || !$ok) {
        note_failed_attempt($key);
        audit($u !== '' ? $u : '?', 'admin_login_failed');
        fail('Wrong username or password. ' . attempts_left($key) . ' tries left.');
    }
    clear_attempts($key);
    session_regenerate_id(true);
    $_SESSION['admin_id'] = (int)$a['id'];
    $_SESSION['admin_seen'] = time();
    q("UPDATE admins SET last_login_at = datetime('now') WHERE id = ?", [$a['id']]);
    audit($a['username'], 'admin_login');
    redirect(url('admin'));
}

function do_admin_logout(): void {
    csrf_check();
    if ($a = current_admin()) { audit($a['username'], 'admin_logout'); }
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $c = session_get_cookie_params();
        setcookie(session_name(), '', ['expires' => time() - 42000, 'path' => $c['path'], 'secure' => $c['secure'],
            'httponly' => true, 'samesite' => 'Strict']);
    }
    session_destroy();
    redirect(url('admin_login'));
}

function do_admin_password(array $admin): void {
    csrf_check();
    $full = row('SELECT * FROM admins WHERE id = ?', [$admin['id']]);
    $new = (string)($_POST['new_password'] ?? '');
    $errs = [];
    if (!password_verify((string)($_POST['current_password'] ?? ''), $full['pass_hash'])) { $errs['current_password'] = 'That isn\'t your current password.'; }
    if (strlen($new) < 12) { $errs['new_password'] = 'Use at least 12 characters.'; }
    elseif ($new !== (string)($_POST['new_password2'] ?? '')) { $errs['new_password2'] = 'Doesn\'t match.'; }
    if ($errs) { $_SESSION['form_errors'] = $errs; redirect(url('admin_password')); }
    q("UPDATE admins SET pass_hash = ?, updated_at = datetime('now') WHERE id = ?", [password_hash($new, PASSWORD_BCRYPT, ['cost' => 12]), $admin['id']]);
    if (is_file(PW_FILE)) { @unlink(PW_FILE); }
    session_regenerate_id(true);
    audit($admin['username'], 'admin_password_changed', 'admins', (int)$admin['id']);
    flash('ok', 'Password changed' . (is_file(PW_FILE) ? '. Heads up: couldn\'t delete admin_password.txt, remove it by hand.' : ' and admin_password.txt wiped.'));
    redirect(url('admin'));
}

/* ═════════════════════════ ADMIN: entity registry ═════════════════════════
 * Every table the dashboard manages is described once here. The CRUD engine
 * below reads this, so adding a table = adding an entry. Column names only ever
 * come from this array, never from the request, which keeps dynamic SQL safe.
 * ops: c=create r=read u=update d=delete
 */
function entities(): array {
    static $e = null;
    return $e ??= [
        'players' => [
            'label' => 'Players', 'ops' => 'crud', 'title' => 'username',
            'list' => ['id', 'username', 'email', 'balance', 'status', 'rounds_played', 'biggest_win', 'last_login_at', 'created_at'],
            'search' => ['username', 'email'], 'filters' => ['status'],
            'fields' => [
                'username' => ['type' => 'text', 'required' => true, 'pattern' => '/^[A-Za-z0-9_]{3,24}$/', 'hint' => '3–24 letters, numbers, underscores'],
                'email' => ['type' => 'email'],
                'password' => ['type' => 'password', 'column' => 'pass_hash', 'min' => 8, 'hint' => 'Blank keeps the current one. 8+ chars.'],
                'balance' => ['type' => 'int', 'min' => 0, 'required' => true, 'default' => 10000, 'hint' => 'Changes are written to the ledger as an admin adjustment. The save is refused if the balance moved while this form was open'],
                'status' => ['type' => 'enum', 'options' => ['active', 'suspended'], 'default' => 'active'],
                'break_until' => ['type' => 'datetime', 'hint' => 'UTC. Blank means no break.'],
                'daily_streak' => ['type' => 'int', 'min' => 0, 'default' => 0],
            ],
        ],
        'games' => [
            'label' => 'Games', 'ops' => 'crud', 'title' => 'name', 'sort' => 'sort_order', 'dir' => 'asc',
            'list' => ['id', 'slug', 'name', 'enabled', 'min_bet', 'max_bet', 'sort_order', 'updated_at'],
            'search' => ['slug', 'name'], 'filters' => ['enabled'],
            'fields' => [
                'slug' => ['type' => 'enum', 'options' => array_keys(GAME_REGISTRY), 'required' => true, 'hint' => 'Which engine this table runs'],
                'name' => ['type' => 'text', 'required' => true, 'max' => 60],
                'blurb' => ['type' => 'textarea', 'max' => 300],
                'enabled' => ['type' => 'bool', 'default' => 1],
                'min_bet' => ['type' => 'int', 'min' => 1, 'required' => true, 'default' => 10],
                'max_bet' => ['type' => 'int', 'min' => 1, 'required' => true, 'default' => 5000],
                'sort_order' => ['type' => 'int', 'default' => 0],
            ],
        ],
        'promo_codes' => [
            'label' => 'Promo codes', 'ops' => 'crud', 'title' => 'code',
            'list' => ['id', 'code', 'coins', 'uses', 'max_uses', 'expires_at', 'active', 'note', 'created_at'],
            'search' => ['code', 'note'], 'filters' => ['active'],
            'fields' => [
                'code' => ['type' => 'text', 'required' => true, 'pattern' => '/^[A-Z0-9_-]{3,32}$/', 'upper' => true, 'hint' => 'Hand these out at events. A–Z, 0–9, _ or -'],
                'coins' => ['type' => 'int', 'min' => 1, 'required' => true, 'default' => 5000],
                'max_uses' => ['type' => 'int', 'min' => 0, 'default' => 0, 'hint' => '0 = unlimited (still once per player)'],
                'expires_at' => ['type' => 'datetime', 'hint' => 'UTC. Blank = never.'],
                'active' => ['type' => 'bool', 'default' => 1],
                'note' => ['type' => 'textarea', 'max' => 300, 'hint' => 'Internal: which event or partner this was for'],
            ],
        ],
        'promo_redemptions' => [
            'label' => 'Redemptions', 'ops' => 'crud',
            'list' => ['id', 'promo_id', 'player_id', 'coins', 'created_at'],
            'search' => [], 'filters' => [],
            'fields' => [
                'promo_id' => ['type' => 'fk', 'ref' => 'promo_codes', 'label_col' => 'code', 'required' => true],
                'player_id' => ['type' => 'fk', 'ref' => 'players', 'label_col' => 'username', 'required' => true],
                'coins' => ['type' => 'int', 'min' => 1, 'required' => true, 'hint' => 'Record only. Editing here doesn\'t move coins.'],
            ],
        ],
        'ledger' => [
            'label' => 'Coin ledger', 'ops' => 'crud',
            'list' => ['id', 'player_id', 'kind', 'game', 'amount', 'balance_after', 'detail', 'created_at'],
            'search' => ['detail', 'game'], 'filters' => ['kind'],
            'fields' => [
                'player_id' => ['type' => 'fk', 'ref' => 'players', 'label_col' => 'username', 'required' => true],
                'kind' => ['type' => 'enum', 'options' => ['signup', 'wager', 'payout', 'daily', 'refill', 'promo', 'admin'], 'required' => true],
                'game' => ['type' => 'text', 'max' => 20],
                'amount' => ['type' => 'int', 'required' => true],
                'balance_after' => ['type' => 'int', 'required' => true, 'hint' => 'Record only. To change a balance, edit the player.'],
                'detail' => ['type' => 'text', 'max' => 200],
            ],
        ],
        'bj_hands' => [
            'label' => 'Blackjack hands', 'ops' => 'crud',
            'list' => ['id', 'player_id', 'bet', 'status', 'outcome', 'payout', 'updated_at'],
            'search' => ['outcome'], 'filters' => ['status'],
            'fields' => [
                'player_id' => ['type' => 'fk', 'ref' => 'players', 'label_col' => 'username', 'required' => true],
                'bet' => ['type' => 'int', 'min' => 1, 'required' => true],
                'status' => ['type' => 'enum', 'options' => ['active', 'done', 'void'], 'default' => 'done', 'hint' => 'Setting an active hand to void refunds its bet. Done and void hands can\'t be reopened or voided again'],
                'outcome' => ['type' => 'text', 'max' => 30],
                'payout' => ['type' => 'int', 'min' => 0, 'default' => 0],
                'state' => ['type' => 'json', 'default' => '{}'],
            ],
        ],
        'rounds' => [
            'label' => 'Game rounds', 'ops' => 'crud',
            'list' => ['id', 'player_id', 'game', 'bet', 'status', 'outcome', 'payout', 'updated_at'],
            'search' => ['game', 'outcome'], 'filters' => ['status'],
            'fields' => [
                'player_id' => ['type' => 'fk', 'ref' => 'players', 'label_col' => 'username', 'required' => true],
                'game' => ['type' => 'text', 'required' => true, 'max' => 20],
                'bet' => ['type' => 'int', 'min' => 1, 'required' => true, 'hint' => 'Total staked this round (craps: every chip ever placed, including ones since paid or taken down)'],
                'status' => ['type' => 'enum', 'options' => ['active', 'done', 'void'], 'default' => 'done', 'hint' => 'Setting an active round to void refunds the chips still at risk on it (craps: what is on the layout now). Done and void rounds can\'t be reopened or voided again'],
                'outcome' => ['type' => 'text', 'max' => 30],
                'payout' => ['type' => 'int', 'min' => 0, 'default' => 0],
                'state' => ['type' => 'json', 'default' => '{}'],
            ],
        ],
        'fair_seeds' => [
            'label' => 'Fairness seeds', 'ops' => 'rd', 'hint' => 'Active server seeds are hidden everywhere until the player rotates them. Deleting an active seed just issues a new one.',
            'list' => ['id', 'player_id', 'game', 'server_hash', 'client_seed', 'nonce', 'status', 'revealed_at'],
            'search' => ['server_hash', 'client_seed'], 'filters' => ['status'],
            'fields' => [
                'player_id' => ['type' => 'fk', 'ref' => 'players', 'label_col' => 'username'],
                'game' => ['type' => 'text'], 'server_hash' => ['type' => 'text'], 'client_seed' => ['type' => 'text'],
                'nonce' => ['type' => 'int'], 'status' => ['type' => 'enum', 'options' => ['active', 'revealed']],
            ],
        ],
        'poker_tables' => [
            'label' => 'Poker tables', 'ops' => 'crud', 'title' => 'name', 'sort' => 'sort_order', 'dir' => 'asc',
            'hint' => 'ws.php re-reads this list every 30 s. Blind changes apply at the next hand; disabling a table cashes everyone out.',
            'list' => ['id', 'name', 'seats', 'small_blind', 'big_blind', 'min_buyin', 'max_buyin', 'bots', 'enabled', 'sort_order'],
            'search' => ['name'], 'filters' => ['enabled'],
            'fields' => [
                'name' => ['type' => 'text', 'required' => true, 'max' => 40],
                'seats' => ['type' => 'int', 'min' => 2, 'max' => 9, 'default' => 6, 'required' => true],
                'small_blind' => ['type' => 'int', 'min' => 1, 'default' => 10, 'required' => true],
                'big_blind' => ['type' => 'int', 'min' => 1, 'default' => 20, 'required' => true],
                'min_buyin' => ['type' => 'int', 'min' => 1, 'default' => 800, 'required' => true, 'hint' => 'Usually 40 big blinds'],
                'max_buyin' => ['type' => 'int', 'min' => 1, 'default' => 4000, 'required' => true, 'hint' => 'Usually 200 big blinds'],
                'bots' => ['type' => 'int', 'min' => 0, 'max' => 8, 'default' => 0, 'hint' => 'House players that keep the table alive. Always labelled as such.'],
                'enabled' => ['type' => 'bool', 'default' => 1],
                'sort_order' => ['type' => 'int', 'default' => 0],
            ],
        ],
        'poker_seats' => [
            'label' => 'Poker seats', 'ops' => 'rd', 'hint' => 'Chips currently at a table. ws.php refunds every row here when it restarts.',
            'list' => ['id', 'table_id', 'player_id', 'seat', 'stack', 'updated_at'],
            'search' => [], 'filters' => [],
            'fields' => [
                'table_id' => ['type' => 'fk', 'ref' => 'poker_tables', 'label_col' => 'name'],
                'player_id' => ['type' => 'fk', 'ref' => 'players', 'label_col' => 'username'],
                'seat' => ['type' => 'int'], 'stack' => ['type' => 'int'],
            ],
        ],
        'poker_hands' => [
            'label' => 'Poker hands', 'ops' => 'r', 'hint' => 'Full history of every hand, with the deck commitment.',
            'list' => ['id', 'table_id', 'hand_no', 'board', 'pot', 'started_at', 'ended_at'],
            'search' => ['deck_hash', 'board'], 'filters' => [],
            'fields' => [
                'table_id' => ['type' => 'fk', 'ref' => 'poker_tables', 'label_col' => 'name'],
                'hand_no' => ['type' => 'int'], 'deck_hash' => ['type' => 'text'], 'deck_salt' => ['type' => 'text'],
                'board' => ['type' => 'text'], 'pot' => ['type' => 'int'], 'record' => ['type' => 'json'],
            ],
        ],
        'settings' => [
            'label' => 'Site settings', 'ops' => 'crud', 'title' => 'key', 'sort' => 'key', 'dir' => 'asc',
            'list' => ['id', 'key', 'value', 'note', 'updated_at'],
            'search' => ['key', 'value', 'note'], 'filters' => [],
            'fields' => [
                'key' => ['type' => 'text', 'required' => true, 'pattern' => '/^[a-z0-9_]{2,40}$/'],
                'value' => ['type' => 'textarea', 'max' => 2000],
                'note' => ['type' => 'text', 'max' => 200],
            ],
        ],
        'admins' => [
            'label' => 'Admins', 'ops' => 'crud', 'title' => 'username',
            'list' => ['id', 'username', 'last_login_at', 'created_at'],
            'search' => ['username'], 'filters' => [],
            'fields' => [
                'username' => ['type' => 'text', 'required' => true, 'pattern' => '/^[A-Za-z0-9_.-]{3,32}$/'],
                'password' => ['type' => 'password', 'column' => 'pass_hash', 'min' => 12, 'hint' => 'Required for new admins. 12+ chars.'],
            ],
        ],
        'login_attempts' => [
            'label' => 'Login lockouts', 'ops' => 'rd',
            'list' => ['id', 'attempt_key', 'created_at'], 'search' => ['attempt_key'], 'filters' => [],
            'fields' => ['attempt_key' => ['type' => 'text']],
        ],
        'audit_log' => [
            'label' => 'Audit log', 'ops' => 'r', 'hint' => 'Append-only. The database refuses edits and deletes here.',
            'list' => ['id', 'actor', 'action', 'tbl', 'row_id', 'ip', 'created_at'],
            'search' => ['actor', 'action', 'tbl', 'ip'], 'filters' => [],
            'fields' => [
                'actor' => ['type' => 'text'], 'action' => ['type' => 'text'], 'tbl' => ['type' => 'text'], 'row_id' => ['type' => 'int'],
                'before_json' => ['type' => 'json'], 'after_json' => ['type' => 'json'], 'ip' => ['type' => 'text'],
            ],
        ],
    ];
}

function entity(string $t): array {
    $e = entities()[$t] ?? null;
    if (!$e) { error_page(404, 'No such table', 'That table isn\'t managed here.'); }
    return $e;
}
function can(array $e, string $op): bool { return str_contains($e['ops'], $op); }
function fk_label(string $ref, string $col, ?int $id): string {
    static $cache = [];
    if (!$id) { return ''; }
    $k = "$ref.$id";
    if (!array_key_exists($k, $cache)) {
        $refCfg = entities()[$ref];
        $safeCol = isset($refCfg['fields'][$col]) ? $col : 'id';
        $cache[$k] = (string)(val("SELECT $safeCol FROM $ref WHERE id = ?", [$id]) ?? "#$id (deleted)");
    }
    return $cache[$k];
}

function per_page(): int {
    $pp = (int)($_GET['per'] ?? ($_COOKIE['gt_rpp'] ?? 25));
    return in_array($pp, [25, 50, 100], true) ? $pp : 25;
}

/** Build the WHERE clause for list + export from ?q= and ?f_*= using only whitelisted columns. */
function list_where(array $e): array {
    $where = []; $args = [];
    $term = trim((string)($_GET['q'] ?? ''));
    if ($term !== '' && $e['search']) {
        $like = '%' . strtr($term, ['\\' => '\\\\', '%' => '\\%', '_' => '\\_']) . '%';
        $or = [];
        foreach ($e['search'] as $c) { $or[] = "CAST($c AS TEXT) LIKE ? ESCAPE '\\'"; $args[] = $like; }
        if (ctype_digit($term)) { $or[] = 'id = ?'; $args[] = (int)$term; }
        $where[] = '(' . implode(' OR ', $or) . ')';
    }
    foreach ($e['filters'] as $f) {
        $v = $_GET['f_' . $f] ?? '';
        if ($v === '' || !is_string($v)) { continue; }
        $fd = $e['fields'][$f];
        $allowed = $fd['type'] === 'bool' ? ['0', '1'] : ($fd['options'] ?? []);
        if (in_array($v, $allowed, true)) { $where[] = "$f = ?"; $args[] = $v; }
    }
    foreach ($e['fields'] as $name => $fd) {
        if ($fd['type'] === 'fk' && ctype_digit((string)($_GET[$name] ?? ''))) { $where[] = "$name = ?"; $args[] = (int)$_GET[$name]; }
    }
    // date range filter on created_at
    foreach (['from' => '>=', 'to' => '<='] as $k => $op) {
        $d = (string)($_GET[$k] ?? '');
        if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $d)) { $where[] = "date(created_at) $op ?"; $args[] = $d; }
    }
    return [$where ? 'WHERE ' . implode(' AND ', $where) : '', $args];
}

/* ═════════════════════════ ADMIN: validation + save ═════════════════════════ */

/** Fingerprint of a round / hand row as the edit form saw it; the save refuses to overwrite a row that moved since. */
function row_rev(array $r): string { return substr(hash('sha256', json_encode($r)), 0, 20); }

function validate_entity(string $t, array $e, array $in, ?array $existing): array {
    $data = []; $errs = [];
    foreach ($e['fields'] as $name => $f) {
        $raw = $in[$name] ?? null;
        $col = $f['column'] ?? $name;
        $label = ucwords(str_replace('_', ' ', $name));
        switch ($f['type']) {
            case 'password':
                $pw = is_string($raw) ? $raw : '';
                if ($pw === '') { if (!$existing) { $errs[$name] = "$label is required for new records."; } break; }
                if (strlen($pw) < ($f['min'] ?? 8)) { $errs[$name] = 'At least ' . ($f['min'] ?? 8) . ' characters.'; break; }
                $data[$col] = password_hash($pw, PASSWORD_BCRYPT, ['cost' => 12]);
                break;
            case 'bool':
                $data[$col] = !empty($raw) ? 1 : 0;
                break;
            case 'int':
            case 'fk':
                $s = is_string($raw) ? trim($raw) : '';
                if ($s === '') {
                    if (!empty($f['required'])) { $errs[$name] = "$label is required."; }
                    else { $data[$col] = $f['type'] === 'fk' ? null : (int)($f['default'] ?? 0); }
                    break;
                }
                if (!preg_match('/^-?\d{1,15}$/', $s)) { $errs[$name] = 'Whole numbers only.'; break; }
                $n = (int)$s;
                if (isset($f['min']) && $n < $f['min']) { $errs[$name] = "Minimum is {$f['min']}."; break; }
                if ($f['type'] === 'fk' && !val("SELECT 1 FROM {$f['ref']} WHERE id = ?", [$n])) { $errs[$name] = 'That record doesn\'t exist.'; break; }
                $data[$col] = $n;
                break;
            case 'enum':
                $s = is_string($raw) ? $raw : '';
                if (!in_array($s, $f['options'], true)) { $errs[$name] = 'Pick one of the options.'; break; }
                $data[$col] = $s;
                break;
            case 'datetime':
                $s = is_string($raw) ? trim($raw) : '';
                if ($s === '') { $data[$col] = null; break; }
                $ts = strtotime(str_replace('T', ' ', $s) . ' UTC');
                if ($ts === false) { $errs[$name] = 'Not a valid date/time.'; break; }
                $data[$col] = gmdate('Y-m-d H:i:s', $ts);
                break;
            case 'json':
                $s = is_string($raw) ? trim($raw) : '';
                if ($s === '') { $s = (string)($f['default'] ?? '{}'); }
                json_decode($s);
                if (json_last_error() !== JSON_ERROR_NONE) { $errs[$name] = 'Must be valid JSON.'; break; }
                $data[$col] = $s;
                break;
            case 'email':
                $s = is_string($raw) ? trim($raw) : '';
                if ($s === '') { $data[$col] = null; break; }
                if (!filter_var($s, FILTER_VALIDATE_EMAIL)) { $errs[$name] = 'Not a valid email.'; break; }
                $data[$col] = $s;
                break;
            default: // text, textarea
                $s = is_string($raw) ? trim(str_replace("\0", '', $raw)) : '';
                if (!empty($f['upper'])) { $s = strtoupper($s); }
                if ($s === '' && !empty($f['required'])) { $errs[$name] = "$label is required."; break; }
                if (isset($f['max']) && mb_strlen($s) > $f['max']) { $errs[$name] = "Keep it under {$f['max']} characters."; break; }
                if ($s !== '' && isset($f['pattern']) && !preg_match($f['pattern'], $s)) { $errs[$name] = $f['hint'] ?? 'Invalid format.'; break; }
                $data[$col] = $s;
        }
    }
    if ($t === 'games' && isset($data['min_bet'], $data['max_bet']) && $data['max_bet'] < $data['min_bet']) {
        $errs['max_bet'] = 'Max bet has to be at least the min bet.';
    }
    return [$data, $errs];
}

function do_admin_save(array $admin): void {
    csrf_check();
    $t = (string)($_POST['t'] ?? '');
    $e = entity($t);
    $id = (int)($_POST['id'] ?? 0);
    $existing = $id ? row("SELECT * FROM $t WHERE id = ?", [$id]) : null;
    if ($id && !$existing) { fail('That record is gone.'); }
    if (!can($e, $existing ? 'u' : 'c')) { fail('Not allowed on this table.', 403); }

    [$data, $errs] = validate_entity($t, $e, $_POST, $existing);
    if ($errs) {
        $_SESSION['form_errors'] = $errs;
        $_SESSION['form_old'] = array_map(fn($v) => is_string($v) ? $v : '', array_diff_key($_POST, ['csrf' => 1, 'password' => 1]));
        flash('err', 'Fix the highlighted fields.');
        redirect(url('admin_edit', ['t' => $t, 'id' => $id ?: null]));
    }

    try {
        $newId = tx(function () use ($t, $data, &$existing, $id, $admin) {
            if ($existing) {
                // re-read under the write lock: the form was built from a snapshot, and a roll, hit or cashout may have
                // landed since. Money-bearing rows also carry what the admin saw and refuse to save over a change.
                $existing = row("SELECT * FROM $t WHERE id = ?", [$id]);
                if (!$existing) { throw new DomainException('That record is gone.'); }
                if ($t === 'players' && isset($_POST['balance_was']) && (int)$_POST['balance_was'] !== (int)$existing['balance']) {
                    throw new DomainException('Balance changed to ' . coins((int)$existing['balance']) . ' GC while you were editing. Reload and try again.');
                }
                if (in_array($t, ['rounds', 'bj_hands'], true)) {
                    $what = $t === 'rounds' ? 'round' : 'hand';
                    if (isset($_POST['rev']) && (string)$_POST['rev'] !== row_rev($existing)) { throw new DomainException("This $what changed while you were editing (the player kept playing). Reload and try again."); }
                    // the only transitions are active → done and active → void: a settled or voided row never reopens or refunds twice
                    if ($data['status'] !== $existing['status'] && $existing['status'] !== 'active') { throw new DomainException("Settled or voided {$what}s can't be reopened or re-voided."); }
                }
                $sets = implode(', ', array_map(fn($c) => "$c = ?", array_keys($data)));
                q("UPDATE $t SET $sets, updated_at = datetime('now') WHERE id = ?", [...array_values($data), $id]);
                // side effects that keep the coin economy honest
                if ($t === 'players' && (int)$existing['balance'] !== (int)$data['balance']) {
                    $delta = (int)$data['balance'] - (int)$existing['balance'];
                    q('INSERT INTO ledger (player_id, kind, amount, balance_after, detail) VALUES (?,?,?,?,?)',
                        [$id, 'admin', $delta, $data['balance'], 'adjusted by ' . $admin['username']]);
                }
                if ($t === 'rounds' && $existing['status'] === 'active' && $data['status'] === 'void') {
                    // hand back only what is still on the table: chips already paid or taken down stayed with the player
                    $refund = round_at_risk($existing); $paid = (int)(st($existing)['paid'] ?? 0);
                    if ($refund > 0) { move_coins((int)$existing['player_id'], $refund, 'admin', $existing['game'], 'voided round #' . $id . ' refund'); }
                    q("UPDATE rounds SET outcome = 'void', payout = ? WHERE id = ?", [$paid + $refund, $id]);
                }
                if ($t === 'bj_hands' && $existing['status'] === 'active' && $data['status'] === 'void') {
                    move_coins((int)$existing['player_id'], (int)$existing['bet'], 'admin', 'blackjack', 'voided hand #' . $id . ' refund');
                    q("UPDATE bj_hands SET outcome = 'void', payout = bet WHERE id = ?", [$id]);
                }
                $after = row("SELECT * FROM $t WHERE id = ?", [$id]);
                audit($admin['username'], 'update', $t, $id, $existing, $after);
                return $id;
            }
            $cols = array_keys($data);
            q("INSERT INTO $t (" . implode(', ', $cols) . ') VALUES (' . implode(', ', array_fill(0, count($cols), '?')) . ')', array_values($data));
            $nid = (int)db()->lastInsertId();
            if ($t === 'players' && (int)($data['balance'] ?? 0) > 0) {
                q('INSERT INTO ledger (player_id, kind, amount, balance_after, detail) VALUES (?,?,?,?,?)',
                    [$nid, 'admin', $data['balance'], $data['balance'], 'created by ' . $admin['username']]);
            }
            audit($admin['username'], 'create', $t, $nid, null, row("SELECT * FROM $t WHERE id = ?", [$nid]));
            return $nid;
        });
    } catch (PDOException $ex) {
        $msg = $ex->getMessage();
        if (str_contains($msg, 'UNIQUE')) { $human = 'That value is already taken. Pick something unique.'; }
        elseif (str_contains($msg, 'CHECK')) { $human = 'One of the values breaks a table rule (e.g. negative balance or bad length).'; }
        elseif (str_contains($msg, 'FOREIGN KEY')) { $human = 'A linked record is missing.'; }
        else { throw $ex; }
        $_SESSION['form_old'] = array_map(fn($v) => is_string($v) ? $v : '', array_diff_key($_POST, ['csrf' => 1, 'password' => 1]));
        flash('err', $human);
        redirect(url('admin_edit', ['t' => $t, 'id' => $id ?: null]));
    } catch (DomainException $ex) {
        // a rule refused the save (balance moved, round already settled, overdraw): say so on a freshly loaded form
        flash('err', $ex->getMessage());
        redirect(url('admin_edit', ['t' => $t, 'id' => $id ?: null]));
    }
    flash('ok', ($existing ? 'Saved' : 'Created') . " #$newId.");
    redirect(url('admin_list', ['t' => $t]));
}

function guard_delete(string $t, array $ids, array $admin): void {
    if ($t === 'admins') {
        if (in_array((int)$admin['id'], $ids, true)) { fail('You can\'t delete yourself.'); }
        if ((int)val('SELECT COUNT(*) FROM admins') - count($ids) < 1) { fail('At least one admin has to remain.'); }
    }
}

function delete_rows(string $t, array $ids, array $admin): int {
    return tx(function () use ($t, $ids, $admin) {
        $n = 0;
        foreach ($ids as $id) {
            $before = row("SELECT * FROM $t WHERE id = ?", [$id]);
            if (!$before) { continue; }
            q("DELETE FROM $t WHERE id = ?", [$id]);
            audit($admin['username'], 'delete', $t, $id, $before, null);
            $n++;
        }
        return $n;
    });
}

function do_admin_delete(array $admin): void {
    csrf_check();
    $t = (string)($_POST['t'] ?? '');
    $e = entity($t);
    if (!can($e, 'd')) { fail('Deletes aren\'t allowed on this table.', 403); }
    if (($_POST['confirm'] ?? '') !== 'DELETE') { fail('Type DELETE to confirm.'); }
    $id = (int)($_POST['id'] ?? 0);
    guard_delete($t, [$id], $admin);
    $n = delete_rows($t, [$id], $admin);
    flash($n ? 'ok' : 'err', $n ? "Deleted #$id." : 'Nothing deleted.');
    redirect(url('admin_list', ['t' => $t]));
}

function do_admin_bulk(array $admin): void {
    csrf_check();
    $t = (string)($_POST['t'] ?? '');
    $e = entity($t);
    $ids = array_values(array_unique(array_filter(array_map('intval', (array)($_POST['ids'] ?? [])))));
    if (!$ids) { fail('Select some rows first.'); }
    if (count($ids) > 500) { fail('Max 500 rows per bulk action.'); }
    $op = (string)($_POST['op'] ?? '');

    if ($op === 'delete') {
        if (!can($e, 'd')) { fail('Deletes aren\'t allowed on this table.', 403); }
        if (($_POST['confirm'] ?? '') !== 'DELETE') { fail('Type DELETE in the box to confirm a bulk delete.'); }
        guard_delete($t, $ids, $admin);
        $n = delete_rows($t, $ids, $admin);
        flash('ok', "Deleted $n rows.");
    } elseif (preg_match('/^set:([a-z_]+):(.*)$/', $op, $m)) {
        if (!can($e, 'u')) { fail('Updates aren\'t allowed on this table.', 403); }
        [$field, $value] = [$m[1], $m[2]];
        $f = $e['fields'][$field] ?? null;
        $allowed = $f ? ($f['type'] === 'bool' ? ['0', '1'] : ($f['type'] === 'enum' ? $f['options'] : [])) : [];
        if (!in_array($value, $allowed, true) || (in_array($t, ['bj_hands', 'rounds'], true) && $field === 'status')) { fail('That bulk change isn\'t supported.'); }
        $n = tx(function () use ($t, $ids, $field, $value, $admin) {
            $n = 0;
            foreach ($ids as $id) {
                $before = row("SELECT * FROM $t WHERE id = ?", [$id]);
                if (!$before) { continue; }
                q("UPDATE $t SET $field = ?, updated_at = datetime('now') WHERE id = ?", [$value, $id]);
                audit($admin['username'], 'bulk_update', $t, $id, [$field => $before[$field]], [$field => $value]);
                $n++;
            }
            return $n;
        });
        flash('ok', "Updated $n rows.");
    } else {
        fail('Pick a bulk action.');
    }
    redirect($_SERVER['HTTP_REFERER'] ?? url('admin_list', ['t' => $t]));
}

function do_admin_export(array $admin): never {
    $t = (string)($_GET['t'] ?? '');
    $e = entity($t);
    [$where, $args] = list_where($e);
    $st = q("SELECT * FROM $t $where ORDER BY id", $args);
    audit($admin['username'], 'export', $t);
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $t . '-' . gmdate('Ymd-His') . '.csv"');
    header('Cache-Control: no-store');
    $out = fopen('php://output', 'w');
    $first = true;
    while ($r = $st->fetch()) {
        unset($r['pass_hash']);
        if (($r['status'] ?? '') === 'active' && isset($r['server_seed'])) { $r['server_seed'] = '(hidden)'; }
        if ($first) { fputcsv($out, array_keys($r), ',', '"', '\\'); $first = false; }
        // stop spreadsheet apps from treating cells as formulas
        $r = array_map(fn($v) => is_string($v) && $v !== '' && !is_numeric($v) && str_contains('=+-@', $v[0]) ? "'" . $v : $v, $r);
        fputcsv($out, $r, ',', '"', '\\');
    }
    if ($first) { fputcsv($out, ['(no rows)'], ',', '"', '\\'); }
    exit;
}

/* ═════════════════════════ VIEW HELPERS ═════════════════════════ */

const SYMBOL_SVG = [
    'cherry' => '<path d="M33 9C30 22 24 29 21 35" stroke="#3f8a3a" stroke-width="3.5" fill="none" stroke-linecap="round"/><path d="M33 9c4 12 9 19 11 24" stroke="#3f8a3a" stroke-width="3.5" fill="none" stroke-linecap="round"/><path d="M33 9c7-6 16-5 20 1-7 4-14 4-20-1z" fill="#5cb85c"/><circle cx="21" cy="44" r="12" fill="#e3243b"/><circle cx="44" cy="41" r="11" fill="#c41c32"/><circle cx="16.5" cy="39.5" r="3.2" fill="#fff" opacity=".55"/><circle cx="40" cy="36.5" r="2.8" fill="#fff" opacity=".5"/>',
    'lemon' => '<g transform="rotate(-24 32 34)"><ellipse cx="32" cy="34" rx="22" ry="15.5" fill="#ffd23f"/><path d="M9 34l-5-2 5-3zM55 34l5 2-5 3z" fill="#f2b705"/><ellipse cx="25" cy="28" rx="8" ry="3.5" fill="#fff" opacity=".45"/></g>',
    'shell' => '<path d="M32 55 9 27C15 11 49 11 55 27z" fill="#ffb3a1"/><path d="M32 55 18 18M32 55V13M32 55 46 18M32 55 10 27M32 55 54 27" stroke="#e0735f" stroke-width="2.5" fill="none"/><path d="M25 55h14l-3 5h-8z" fill="#e0735f"/>',
    'palm' => '<path d="M31 58c2-14 3-24 1-34" stroke="#8a5a2b" stroke-width="5" fill="none" stroke-linecap="round"/><path d="M32 22C24 10 12 12 6 20c10-3 18-2 26 2zM32 22c8-12 20-10 26-2-10-3-18-2-26 2zM32 22c-9-4-19 2-21 12 6-7 13-10 21-12zM32 22c9-4 19 2 21 12-6-7-13-10-21-12zM32 22c-3-9 1-16 6-19-2 6-4 12-6 19z" fill="#2fb36d"/><circle cx="28" cy="25" r="3" fill="#6b3f1d"/><circle cx="35" cy="25" r="3" fill="#6b3f1d"/>',
    'bell' => '<path d="M32 9c-12 0-17 11-17 22 0 9-4 13-9 15h52c-5-2-9-6-9-15 0-11-5-22-17-22z" fill="#f2b51d"/><path d="M21 22c2-6 6-9 11-9" stroke="#fff3c4" stroke-width="3" fill="none" stroke-linecap="round"/><rect x="6" y="45" width="52" height="5" rx="2.5" fill="#c98d0b"/><circle cx="32" cy="54" r="5" fill="#c98d0b"/><circle cx="32" cy="7" r="3" fill="#c98d0b"/>',
    'bar' => '<rect x="5" y="19" width="54" height="26" rx="5" fill="#1b1a2e" stroke="#e8b64c" stroke-width="3"/><text x="32" y="39.5" text-anchor="middle" font-family="Limelight, serif" font-size="17" fill="#e8b64c">BAR</text>',
    'seven' => '<text x="32" y="53" text-anchor="middle" font-family="Limelight, serif" font-size="56" fill="#ff5a45" stroke="#ffd98a" stroke-width="2.5">7</text>',
    'sun' => '<g fill="#ffb627"><circle cx="32" cy="32" r="13"/><path d="M32 2l4 12h-8zM32 62l-4-12h8zM2 32l12-4v8zM62 32l-12 4v-8zM11 11l11 6-5 5zM53 53l-11-6 5-5zM53 11l-6 11-5-5zM11 53l6-11 5 5z"/></g><circle cx="32" cy="32" r="9" fill="#ffe08a"/><path d="M27 34q5 5 10 0" stroke="#c46a00" stroke-width="2" fill="none" stroke-linecap="round"/><circle cx="28.5" cy="29.5" r="1.6" fill="#c46a00"/><circle cx="35.5" cy="29.5" r="1.6" fill="#c46a00"/>',
];
function sym(string $s): string {
    return '<svg viewBox="0 0 64 64" role="img" aria-label="' . h($s) . '">' . (SYMBOL_SVG[$s] ?? '') . '</svg>';
}

function coin_svg(int $size = 18): string {
    return '<svg class="coin" width="' . $size . '" height="' . $size . '" viewBox="0 0 32 32" aria-hidden="true"><circle cx="16" cy="16" r="15" fill="#e8b64c"/><circle cx="16" cy="16" r="11.5" fill="none" stroke="#b07d12" stroke-width="2"/><path d="M16 8.5l2.2 4.6 5 .7-3.6 3.5.9 5-4.5-2.4-4.5 2.4.9-5-3.6-3.5 5-.7z" fill="#fff3c4"/></svg>';
}

function field_error(string $name): string {
    $e = $_SESSION['form_errors'][$name] ?? null;
    return $e ? '<p class="ferr" id="err-' . h($name) . '">' . h($e) . '</p>' : '';
}
function old(string $name, string $default = ''): string { return (string)($_SESSION['form_old'][$name] ?? $default); }
function aria_err(string $name): string { return isset($_SESSION['form_errors'][$name]) ? ' aria-invalid="true" aria-describedby="err-' . h($name) . '"' : ''; }

function error_page(int $code, string $title, string $msg): never {
    http_response_code($code);
    layout("$code · $title", '<section class="panel narrow reveal"><p class="eyebrow">Error ' . $code . '</p><h1 class="display">' . h($title) . '</h1><p class="lead">' . h($msg) . '</p><p><a class="btn gold" href="' . h(url()) . '">Back to the lobby</a></p></section>', 'public');
    exit;
}

/* ═════════════════════════ LAYOUT ═════════════════════════ */

/** ?embed=1: the page is a machine screen inside the 3D floor. No header, footer, rules or rail. */
function is_embed(): bool { return (($_GET['embed'] ?? '') === '1'); }

function layout(string $title, string $body, string $mode = 'public'): void {
    send_security_headers();
    header('Content-Type: text/html; charset=utf-8');
    $site = setting('site_name', 'Gold Tide');
    $p = $mode === 'public' ? current_player() : null;
    $flashes = take_flashes();
    unset($_SESSION['form_errors'], $_SESSION['form_old']);
    $nonce = csp_nonce();
    $act = (string)($_GET['action'] ?? '');
    $nav = fn(string $a, string $label) => '<a href="' . h(url($a)) . '"' . ($act === $a ? ' aria-current="page"' : '') . '>' . $label . '</a>';
    $favicon = 'data:image/svg+xml,' . rawurlencode('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><circle cx="16" cy="16" r="15" fill="#e8b64c"/><circle cx="16" cy="16" r="11" fill="none" stroke="#b07d12" stroke-width="2"/><path d="M16 8.5l2.2 4.6 5 .7-3.6 3.5.9 5-4.5-2.4-4.5 2.4.9-5-3.6-3.5 5-.7z" fill="#fff3c4"/></svg>');
    ?><!doctype html>
<html lang="en" data-mode="<?= h($mode) ?>">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<meta name="csrf" content="<?= h(csrf_token()) ?>">
<meta name="g3d" content="?action=asset&amp;f=g3d&amp;v=<?= h(g3d_version()) ?>">
<meta name="robots" content="<?= $mode === 'admin' ? 'noindex, nofollow' : 'index, follow' ?>">
<title><?= h($title) ?> · <?= h($site) ?></title>
<link rel="icon" href="<?= h($favicon) ?>">
<script nonce="<?= h($nonce) ?>">try{var t=localStorage.getItem('gt_theme');if(t==='light'||t==='dark')document.documentElement.dataset.theme=t;var d=localStorage.getItem('gt_density');if(d==='compact')document.documentElement.dataset.density=d;}catch(e){}</script>
<link rel="stylesheet" href="?action=asset&amp;f=css&amp;v=<?= h(css_version()) ?>">
</head>
<body class="pg-<?= h($act === '' ? 'lobby' : preg_replace('/[^a-z0-9]/', '', $act)) ?><?= is_embed() ? ' embed' : '' ?>">
<a class="skip" href="#main">Skip to content</a>
<?php if ($mode === 'public' && setting('announcement') !== ''): ?>
<div class="announce" role="status"><?= h(setting('announcement')) ?></div>
<?php endif; ?>
<header class="top">
  <a class="brand" href="<?= h(url($mode === 'admin' ? 'admin' : '')) ?>">
    <span class="brand-mark"><?= coin_svg(30) ?></span>
    <span class="brand-name"><?= h($site) ?><?php if ($mode === 'admin'): ?> <small>back office</small><?php endif; ?></span>
  </a>
  <?php if ($mode === 'public'): ?>
  <nav class="nav" aria-label="Main">
    <?= $nav('', 'Lobby') ?>
    <?php foreach (GAME_CATEGORIES as $ck => [$cl]): $inCat = isset(GAME_REGISTRY[$act]) && GAME_REGISTRY[$act][1] === $ck; ?><a href="<?= h(url()) ?>#cat-<?= h($ck) ?>"<?= $inCat ? ' aria-current="page"' : '' ?>><?= h(['slots' => 'Slots', 'reels' => 'Keno', 'tables' => 'Tables', 'cards' => 'Cards', 'arcade' => 'Arcade', 'worlds' => '3D'][$ck] ?? $ck) ?></a><?php endforeach; ?>
    <?php if (isetting('floor_enabled', 1)): ?><?= $nav('floor', 'The Floor') ?><?php endif; ?>
    <?= $nav('leaderboard', 'Leaders') ?>
  </nav>
  <div class="me">
    <?php if ($p): ?>
      <a class="balance" href="<?= h(url('account')) ?>" title="Your Gold Coins (no cash value)"><?= coin_svg() ?><span data-balance="<?= (int)$p['balance'] ?>"><?= coins((int)$p['balance']) ?></span><em>GC</em></a>
      <a class="who" href="<?= h(url('account')) ?>"><?= h($p['username']) ?></a>
    <?php else: ?>
      <a class="btn ghost sm" href="<?= h(url('login')) ?>">Log in</a>
      <a class="btn gold sm" href="<?= h(url('register')) ?>">Play free</a>
    <?php endif; ?>
    <button class="icon-btn" type="button" data-sound-toggle aria-pressed="true" aria-label="Sound on" title="Sound"><svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path d="M4 9h4l5-4v14l-5-4H4z" fill="currentColor"/><path d="M16 8.5a5 5 0 0 1 0 7M18.5 6a8.5 8.5 0 0 1 0 12" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" data-waves/></svg></button>
    <button class="icon-btn" type="button" data-theme-toggle aria-label="Toggle light/dark theme"><svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path d="M12 3a9 9 0 1 0 9 9 7 7 0 0 1-9-9z" fill="currentColor"/></svg></button>
  </div>
  <?php elseif ($mode === 'admin' && current_admin()): ?>
  <nav class="nav" aria-label="Admin">
    <?= $nav('admin', 'Dashboard') ?>
    <a href="<?= h(url('admin_list', ['t' => 'players'])) ?>"<?= ($_GET['t'] ?? '') === 'players' ? ' aria-current="page"' : '' ?>>Players</a>
    <a href="<?= h(url('admin_list', ['t' => 'promo_codes'])) ?>"<?= ($_GET['t'] ?? '') === 'promo_codes' ? ' aria-current="page"' : '' ?>>Promos</a>
    <a href="<?= h(url('admin_list', ['t' => 'settings'])) ?>"<?= ($_GET['t'] ?? '') === 'settings' ? ' aria-current="page"' : '' ?>>Settings</a>
    <?= $nav('admin_password', 'Password') ?>
  </nav>
  <div class="me">
    <button class="icon-btn" type="button" data-ui-settings aria-haspopup="dialog" aria-label="Display settings"><svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="16" cy="6" r="2" fill="currentColor"/><circle cx="10" cy="12" r="2" fill="currentColor"/><circle cx="18" cy="18" r="2" fill="currentColor"/></svg></button>
    <form method="post" action="<?= h(url('admin_logout')) ?>"><?= csrf_field() ?><button class="btn ghost sm">Log out</button></form>
  </div>
  <?php else: ?>
  <div class="me"><button class="icon-btn" type="button" data-theme-toggle aria-label="Toggle light/dark theme"><svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path d="M12 3a9 9 0 1 0 9 9 7 7 0 0 1-9-9z" fill="currentColor"/></svg></button></div>
  <?php endif; ?>
</header>

<div class="toasts" aria-live="polite" aria-atomic="false">
<?php foreach ($flashes as [$type, $msg]): ?>
  <div class="toast <?= h($type) ?>" role="<?= $type === 'err' ? 'alert' : 'status' ?>"><?= h($msg) ?></div>
<?php endforeach; ?>
</div>

<main id="main" class="<?= $mode === 'admin' ? 'admin' : 'public' ?>">
<?= $body ?>
</main>

<?php if ($mode === 'public'): ?>
<footer class="foot">
  <p class="fine"><strong>Play money only.</strong> Gold Coins have no cash value. They can't be purchased, redeemed, exchanged, or transferred, and nothing here is gambling for money or prizes. For adults <?= isetting('min_age', 21) ?>+ for entertainment.</p>
  <p class="fine"><a href="<?= h(url('rules')) ?>">How it works &amp; responsible play</a> · Need to talk to someone? <a href="tel:18004262537">1-800-GAMBLER</a> is free and confidential, 24/7.</p>
  <?php if (setting('partner_name') !== ''): ?><p class="fine partner">Presented with <?= h(setting('partner_name')) ?></p><?php endif; ?>
</footer>
<?php endif; ?>

<?php if ($mode === 'admin'): ?>
<dialog class="ui-settings" id="ui-settings" aria-labelledby="ui-settings-title">
  <form method="dialog">
    <h2 id="ui-settings-title" class="display sm">Display</h2>
    <label>Theme <select data-pref="theme"><option value="auto">Match system</option><option value="dark">Night harbor</option><option value="light">Day at the pier</option></select></label>
    <label>Density <select data-pref="density"><option value="comfy">Comfortable</option><option value="compact">Compact</option></select></label>
    <label>Rows per page <select data-pref="rpp"><option>25</option><option>50</option><option>100</option></select></label>
    <button class="btn gold">Done</button>
  </form>
</dialog>
<?php endif; ?>

<script type="application/json" id="symbols"><?= json_encode(SYMBOL_SVG, JSON_HEX_TAG | JSON_HEX_AMP) ?></script>
<script nonce="<?= h($nonce) ?>"><?= app_js() ?></script>
</body>
</html>
<?php
}

/* ═════════════════════════ PUBLIC PAGES ═════════════════════════ */

function page_lobby(): void {
    $p = current_player();
    $games = q('SELECT * FROM games WHERE enabled = 1 ORDER BY sort_order, id')->fetchAll();
    $top = q("SELECT username, balance FROM players WHERE status = 'active' ORDER BY balance DESC, id LIMIT 5")->fetchAll();
    $art = ['slots' => sym('seven') . sym('sun') . sym('seven'), 'blackjack' => card_html('AS') . card_html('KH'), 'roulette' => mini_wheel(),
        'scratch' => sym('sun') . sym('bell') . sym('sun'), 'keno' => '<span class="art-balls"><b>7</b><b>19</b><b class="hot">23</b><b>31</b></span>',
        'baccarat' => card_html('9D') . card_html('QS'), 'sicbo' => die_svg(3) . die_svg(5) . die_svg(6), 'bigwheel' => mini_wheel(),
        'crabs' => crab_svg('#ff6f59') . crab_svg('#2bb3a3'), 'videopoker' => card_html('AH') . card_html('KH') . card_html('QH'),
        'threecard' => card_html('7C') . card_html('8C') . card_html('9C'), 'hilo' => card_html('JD') . '<span class="art-arrows">▲<br>▼</span>',
        'crash' => '<svg viewBox="0 0 120 80" class="art-wide"><path d="M4 76C40 74 80 56 112 8" stroke="#2bb3a3" stroke-width="5" fill="none" stroke-linecap="round"/><circle cx="112" cy="8" r="6" fill="#ff6f59"/><text x="8" y="30" font-family="Limelight,serif" font-size="22" fill="#ffd98a">4.20×</text></svg>',
        'abyss' => vs_sym('abyss', 'H1') . vs_sym('abyss', 'W') . vs_sym('abyss', 'S'), 'tinfoil' => vs_sym('tinfoil', 'H1') . vs_sym('tinfoil', 'W') . vs_sym('tinfoil', 'S'),
        'blacksite' => vs_sym('blacksite', 'H1') . vs_sym('blacksite', 'W') . vs_sym('blacksite', 'S'), 'coderain' => vs_sym('coderain', 'H1') . vs_sym('coderain', 'W') . vs_sym('coderain', 'S'),
        'tiki' => vs_sym('tiki', 'H1') . vs_sym('tiki', 'W') . vs_sym('tiki', 'S'), 'calavera' => vs_sym('calavera', 'H1') . vs_sym('calavera', 'W') . vs_sym('calavera', 'S'),
        'roulette3d' => mini_wheel() . '<span class="art-3d">3D</span>', 'craps' => die_svg(5) . die_svg(2) . '<span class="art-3d">3D</span>',
        'pusher' => game_icon('pusher') . game_icon('pusher') . '<span class="art-3d">3D</span>',
        'plinko' => game_icon('plinko'), 'mines' => game_icon('mines') . game_icon('mines'), 'dice' => die_svg(6) . die_svg(1)];
    ob_start(); ?>
<section class="hero">
  <div class="mesa" aria-hidden="true"><?= mesa_svg() ?></div>
  <div class="hero-copy">
    <p class="eyebrow reveal d1">Free-to-play social casino</p>
    <h1 class="display xl reveal d2"><?= h(setting('site_name', 'Gold Tide')) ?></h1>
    <p class="lead reveal d3"><?= h(setting('tagline')) ?></p>
    <?php if (!$p): ?>
      <p class="reveal d4"><a class="btn gold lg" href="<?= h(url('register')) ?>">Grab <?= coins(isetting('starting_coins', 10000)) ?> free Gold Coins</a>
      <a class="btn ghost lg" href="<?= h(url('login')) ?>">I have an account</a></p>
    <?php else: ?>
      <p class="reveal d4 welcome">Welcome back, <strong><?= h($p['username']) ?></strong>. You're holding <strong><?= coins((int)$p['balance']) ?></strong> Gold Coins.</p>
    <?php endif; ?>
    <p class="fine reveal d5">No purchases. No prizes. No cash value. Just the fun part.</p>
  </div>
</section>

<div class="weave" aria-hidden="true"></div>

<?php if ($p): echo bonus_strip($p); endif; ?>

<?php if (isetting('floor_enabled', 1)): ?>
<a class="featured floor-card reveal d4" href="<?= h(url('floor')) ?>">
  <div>
    <p class="eyebrow">New · walk the casino</p>
    <h2>The Floor</h2>
    <p>A first-person 3D casino. Walk the slot hall, the pit and the card room, sit down at any machine or table, and see everyone else who's playing.</p>
    <ul><li>Every game on the floor</li><li>Live players as avatars</li><li>Multiplayer hold'em</li><li>Works on phones</li></ul>
    <span class="btn gold lg">Step inside</span>
  </div>
  <div class="featured-art floor-art" aria-hidden="true"><?= floor_art() ?></div>
</a>
<?php endif; ?>
<?php $pdGame = array_values(array_filter($games, fn($x) => $x['slug'] === 'plinko'))[0] ?? null; if ($pdGame): ?>
<a class="featured reveal d4" href="<?= h(url('plinko')) ?>">
  <div>
    <p class="eyebrow">Featured · the house favorite</p>
    <h2><?= h($pdGame['name']) ?></h2>
    <p><?= h($pdGame['blurb']) ?></p>
    <ul><li>✦ Golden pegs ×2, stacking</li><li>Up to 20 pearls a drop</li><li>8–16 rows · 3 risk levels</li><li>Provably fair</li><li>Up to 1,000× base</li></ul>
    <span class="btn gold lg">Drop a pearl</span>
  </div>
  <div class="featured-art" aria-hidden="true"><?= pd_art() ?></div>
</a>
<?php endif; ?>
<?php $byCat = []; foreach ($games as $g) { $c = GAME_REGISTRY[$g['slug']][1] ?? 'arcade'; $byCat[$c][] = $g; } ?>
<?php foreach (GAME_CATEGORIES as $ck => [$cl, $cd]): if (empty($byCat[$ck])) { continue; } ?>
<section class="cat cat-<?= h($ck) ?> reveal d4" id="cat-<?= h($ck) ?>" aria-labelledby="cat-h-<?= h($ck) ?>">
  <header class="cat-head"><h2 class="display md" id="cat-h-<?= h($ck) ?>"><?= h($cl) ?></h2><p class="muted"><?= h($cd) ?></p></header>
  <div class="games">
  <?php foreach ($byCat[$ck] as $i => $g): ?>
  <a class="game-card g-<?= h($g['slug']) ?>" href="<?= h(url($g['slug'])) ?>">
    <div class="game-art" aria-hidden="true"><?= $art[$g['slug']] ?? game_icon($g['slug']) ?></div>
    <h3 class="display md"><?= h($g['name']) ?></h3>
    <p><?= h($g['blurb']) ?></p>
    <?php if ($g['slug'] === 'poker'): $lo = row('SELECT small_blind, big_blind FROM poker_tables WHERE enabled = 1 ORDER BY big_blind LIMIT 1'); ?>
    <p class="limits"><?= coin_svg(14) ?> blinds from <?= $lo ? coins((int)$lo['small_blind']) . '/' . coins((int)$lo['big_blind']) : '10/20' ?> · live tables</p>
    <?php else: ?>
    <p class="limits"><?= coin_svg(14) ?> <?= coins((int)$g['min_bet']) ?>–<?= coins((int)$g['max_bet']) ?> GC</p>
    <?php endif; ?>
    <span class="play">Play &rarr;</span>
  </a>
  <?php endforeach; ?>
  </div>
</section>
<?php endforeach; ?>
<?php if (!$games): ?><p class="panel">All tables are closed for maintenance. Check back soon.</p><?php endif; ?>

<section class="panel mini-leaders reveal d5">
  <h2 class="display md">High rollers</h2>
  <ol class="leader-list">
  <?php foreach ($top as $i => $t): ?>
    <li><span class="rank"><?= $i + 1 ?></span><span class="name"><?= h($t['username']) ?></span><span class="num"><?= coins((int)$t['balance']) ?></span></li>
  <?php endforeach; ?>
  <?php if (!$top): ?><li class="muted">Nobody yet. Be first.</li><?php endif; ?>
  </ol>
  <a class="more" href="<?= h(url('leaderboard')) ?>">Full leaderboard &rarr;</a>
</section>
<?php layout('Lobby', ob_get_clean());
}

/** Lobby horizon: layered ridgelines of the inland mountains east of San Diego at dusk. Purely scenic, no cultural symbols. */
function mesa_svg(): string {
    mt_srand(11);
    $stars = '';
    for ($i = 0; $i < 60; $i++) { $stars .= '<circle cx="' . mt_rand(0, 1440) . '" cy="' . mt_rand(6, 190) . '" r="' . (mt_rand(4, 14) / 10) . '"' . ($i % 7 === 0 ? ' class="tw"' : '') . '/>'; }
    mt_srand();
    return '<svg viewBox="0 0 1440 420" preserveAspectRatio="xMidYMax slice">'
        . '<defs><radialGradient id="mSun" cx="50%" cy="50%" r="50%"><stop offset="0" stop-color="var(--m-sun1)"/><stop offset=".62" stop-color="var(--m-sun2)"/><stop offset="1" stop-color="var(--m-sun2)" stop-opacity="0"/></radialGradient></defs>'
        . '<g class="m-stars">' . $stars . '</g>'
        . '<g transform="translate(0 64)"><circle cx="1060" cy="206" r="210" fill="url(#mSun)" class="m-glow"/><circle cx="1060" cy="206" r="78" class="m-sun"/>'
        . '<path class="m-r1" d="M0 262C110 236 190 204 300 222S470 176 560 204 720 160 830 192 990 148 1090 182 1270 166 1350 194 1440 188 1440 188V420H0Z"/>'
        . '<path class="m-r2" d="M0 300L80 276 150 288 250 250 330 272 420 238 510 266 600 252 690 284 780 256 880 276 980 240 1060 266 1150 250 1240 280 1330 262 1440 276V420H0Z"/>'
        . '<path class="m-r3" d="M0 344C150 322 260 336 380 320S620 312 760 330 1000 306 1140 322 1360 336 1440 318V420H0Z"/></g>'
        . '</svg>';
}

function pd_art(): string {
    $o = '<svg viewBox="0 0 320 240">';
    $gold = ['2:1' => 1, '4:3' => 1, '6:2' => 1];
    for ($r = 0; $r < 8; $r++) {
        for ($i = 0; $i < $r + 3; $i++) {
            $x = 160 + ($i - ($r + 2) / 2) * 30; $y = 20 + $r * 24;
            $o .= '<circle cx="' . $x . '" cy="' . $y . '" r="' . (isset($gold["$r:$i"]) ? 6 : 3.5) . '" class="' . (isset($gold["$r:$i"]) ? 'gpeg' : 'fpeg') . '"/>';
        }
    }
    $cols = ['#d6283f', '#ff6f59', '#ffb627', '#ffd23f', '#2bb3a3', '#ffd23f', '#ffb627', '#ff6f59', '#d6283f'];
    foreach ($cols as $k => $c) { $o .= '<rect x="' . (160 + ($k - 4) * 30 - 13) . '" y="212" width="26" height="18" rx="4" fill="' . $c . '"/>'; }
    return $o . '<circle class="fpearl" cx="160" cy="4" r="7" fill="#fff"/></svg>';
}

function bonus_strip(array $p): string {
    $d = daily_status($p); $r = refill_status($p);
    $brk = on_break($p);
    ob_start(); ?>
<section class="bonus-strip reveal d4" aria-label="Free coins">
  <?php if ($brk): ?>
    <div class="bonus-card"><h3>On a break</h3><p>Games and bonuses unlock after <?= h($brk) ?> UTC.</p></div>
  <?php else: ?>
  <form class="bonus-card" method="post" action="<?= h(url('claim_daily')) ?>" data-ajax>
    <?= csrf_field() ?>
    <h3>Daily bonus</h3>
    <p><strong><?= coins($d['amount']) ?> GC</strong> · streak day <?= $d['streak'] ?></p>
    <button class="btn gold" <?= $d['ready'] ? '' : 'disabled' ?> data-wait="<?= $d['wait'] ?>"><?= $d['ready'] ? 'Collect' : 'Back in ' . h(human_wait($d['wait'])) ?></button>
  </form>
  <form class="bonus-card" method="post" action="<?= h(url('claim_refill')) ?>" data-ajax>
    <?= csrf_field() ?>
    <h3>Running low?</h3>
    <p>Under <?= coins(isetting('refill_below', 500)) ?> GC (counting chips on the table) gets you <?= coins($r['amount']) ?> every <?= isetting('refill_hours', 4) ?>h.</p>
    <button class="btn ghost" <?= $r['ready'] ? '' : 'disabled' ?>><?= $r['ready'] ? 'Top me up' : ($r['low'] ? 'Back in ' . h(human_wait($r['wait'])) : 'You\'re good') ?></button>
  </form>
  <form class="bonus-card" method="post" action="<?= h(url('redeem')) ?>" data-ajax>
    <?= csrf_field() ?>
    <h3>Promo code</h3>
    <label class="sr" for="promo-code">Promo code</label>
    <div class="inline"><input id="promo-code" name="code" maxlength="32" autocomplete="off" placeholder="From an event?" required><button class="btn ghost">Redeem</button></div>
  </form>
  <?php endif; ?>
</section>
<?php return ob_get_clean();
}

function card_html(string $c, bool $down = false, int $i = 0): string {
    if ($down) { return '<div class="card down" style="--i:' . $i . '" aria-label="face-down card"></div>'; }
    $r = substr($c, 0, -1); $s = substr($c, -1);
    $glyph = ['S' => '♠', 'H' => '♥', 'D' => '♦', 'C' => '♣'][$s];
    $red = in_array($s, ['H', 'D'], true) ? ' red' : '';
    $name = ['S' => 'spades', 'H' => 'hearts', 'D' => 'diamonds', 'C' => 'clubs'][$s];
    return '<div class="card' . $red . '" style="--i:' . $i . '" aria-label="' . h("$r of $name") . '"><span class="r">' . h($r) . '</span><span class="s">' . $glyph . '</span><span class="r2">' . h($r) . $glyph . '</span></div>';
}

function mini_wheel(): string {
    return '<svg viewBox="0 0 100 100" class="mini-wheel"><circle cx="50" cy="50" r="48" fill="#6b3f1d"/><circle cx="50" cy="50" r="42" fill="none" stroke="#e8b64c" stroke-width="10" stroke-dasharray="3.5 3.5"/><circle cx="50" cy="50" r="42" fill="none" stroke="#c0263a" stroke-width="10" stroke-dasharray="3.5 3.5" stroke-dashoffset="3.5"/><circle cx="50" cy="50" r="30" fill="#0f4d45"/><circle cx="50" cy="50" r="8" fill="#e8b64c"/><circle cx="72" cy="30" r="3.5" fill="#fff"/></svg>';
}

function game_header(string $slug): array {
    $g = row('SELECT * FROM games WHERE slug = ?', [$slug]);
    if (!$g || !(int)$g['enabled']) { error_page(404, 'Table closed', 'That game is closed right now. Try another one from the lobby.'); }
    return $g;
}

function page_slots(): void {
    $g = game_header('slots');
    $p = current_player();
    $last = $_SESSION['last']['slots'] ?? null;
    unset($_SESSION['last']['slots']);
    $grid = $last['grid'] ?? [['seven', 'cherry', 'bell'], ['sun', 'seven', 'palm'], ['shell', 'seven', 'lemon']];
    $steps = array_values(array_filter([10, 25, 50, 100, 250, 500, 1000, 2500, 5000],
        fn($b) => $b >= (int)$g['min_bet'] && $b <= (int)$g['max_bet'] && $b % 5 === 0));
    if (!$steps) { $steps = [(int)ceil((int)$g['min_bet'] / 5) * 5]; }
    ob_start(); ?>
<section class="table-wrap slots-wrap<?= scene_open('slots') ?>">
  <header class="table-head reveal d1">
    <p class="eyebrow">Sunset Reels</p>
    <h1 class="display lg"><?= h($g['name']) ?></h1>
  </header>
  <div class="machine reveal d2" data-slots>
    <div class="marquee" aria-hidden="true"><span></span><span></span><span></span><span></span><span></span><span></span><span></span><span></span></div>
    <div class="reels" role="img" aria-label="Slot reels">
      <?php for ($r = 0; $r < 3; $r++): ?>
      <div class="reel" data-reel="<?= $r ?>"><div class="strip">
        <?php foreach ($grid[$r] as $s): ?><div class="cell"><?= sym($s) ?></div><?php endforeach; ?>
      </div></div>
      <?php endfor; ?>
      <svg class="paylines" viewBox="0 0 300 300" preserveAspectRatio="none" aria-hidden="true">
        <polyline data-line="0" points="10,150 150,150 290,150"/><polyline data-line="1" points="10,50 150,50 290,50"/>
        <polyline data-line="2" points="10,250 150,250 290,250"/><polyline data-line="3" points="10,40 150,150 290,260"/>
        <polyline data-line="4" points="10,260 150,150 290,40"/>
      </svg>
    </div>
    <p class="result" data-result aria-live="polite"><?= $last ? h($last['message']) : 'Five lines. Match three across any of them.' ?></p>
    <form class="controls" method="post" action="<?= h(url('play_slots')) ?>" data-game-form>
      <?= csrf_field() ?>
      <fieldset class="bet-pick">
        <legend>Total bet (split across 5 lines)</legend>
        <?php foreach ($steps as $i => $b): ?>
          <label class="chip-radio"><input type="radio" name="bet" value="<?= $b ?>" <?= $i === 0 ? 'checked' : '' ?>><span><?= coins($b) ?></span></label>
        <?php endforeach; ?>
      </fieldset>
      <?php if ($p): ?>
        <button class="btn gold xl spin-btn" data-spin>Spin</button>
      <?php else: ?>
        <a class="btn gold xl" href="<?= h(url('register')) ?>">Sign up free to spin</a>
      <?php endif; ?>
    </form>
  </div>
  <aside class="panel paytable reveal d3" aria-label="Paytable">
    <h2 class="display md">Paytable <small>× line bet</small></h2>
    <ul>
      <?php foreach (array_reverse(SLOT_PAY3, true) as $s => $m): ?>
        <li><span class="syms"><?= sym($s) . sym($s) . sym($s) ?></span><span class="num"><?= coins($m) ?>×</span></li>
      <?php endforeach; ?>
      <li><span class="syms"><?= sym('cherry') . sym('cherry') ?><i>any</i></span><span class="num"><?= SLOT_CHERRY2 ?>×</span></li>
    </ul>
    <p class="fine">Lines: middle, top, bottom, and both diagonals. Two cherries count from the left reel. Theoretical return ≈ 95%.</p>
  </aside>
</section>
<?= games_rail('slots') ?>
<?php layout($g['name'], ob_get_clean());
}

function page_blackjack(): void {
    $g = game_header('blackjack');
    $p = current_player();
    $hand = null;
    if ($p) {
        $raw = bj_active((int)$p['id']);
        $lastId = (int)($_SESSION['last']['blackjack']['hand']['id'] ?? 0);
        if (!$raw && $lastId) { $raw = row('SELECT * FROM bj_hands WHERE id = ? AND player_id = ?', [$lastId, $p['id']]); }
        unset($_SESSION['last']['blackjack']);
        $hand = bj_public($raw);
    }
    $live = $hand && $hand['status'] === 'active';
    ob_start(); ?>
<section class="table-wrap bj-wrap<?= scene_open('blackjack') ?>">
  <header class="table-head reveal d1">
    <p class="eyebrow">Harbor Blackjack</p>
    <h1 class="display lg"><?= h($g['name']) ?></h1>
  </header>
  <div class="felt reveal d2" data-bj data-state="<?= h(json_encode($hand)) ?>">
    <p class="felt-rule" aria-hidden="true">Blackjack pays 3 to 2 · Dealer stands on all 17s</p>
    <div class="hand dealer">
      <h2>Dealer <span class="total" data-dealer-total><?= $hand ? $hand['dealer_total'] . ($hand['dealer_hidden'] ? ' + ?' : '') : '' ?></span></h2>
      <div class="cards" data-dealer-cards>
        <?php if ($hand) { foreach ($hand['dealer'] as $i => $c) { echo card_html($c, false, $i); } for ($i = 0; $i < $hand['dealer_hidden']; $i++) { echo card_html('', true, 1); } } ?>
      </div>
    </div>
    <p class="result" data-result aria-live="polite"><?= $hand ? h($live ? 'Hit, stand, or double?' : (BJ_OUTCOME_TEXT[$hand['outcome']] ?? '')) : 'Place a bet to deal.' ?></p>
    <div class="hand player">
      <h2>You <span class="total" data-player-total><?= $hand ? $hand['player_total'] : '' ?></span> <span class="bet-tag" data-bet-tag><?= $hand ? coins($hand['bet']) . ' GC' : '' ?></span></h2>
      <div class="cards" data-player-cards>
        <?php if ($hand) { foreach ($hand['player'] as $i => $c) { echo card_html($c, false, $i); } } ?>
      </div>
    </div>
    <?php if ($p): ?>
    <form class="controls" method="post" action="<?= h(url('play_blackjack')) ?>" data-game-form>
      <?= csrf_field() ?>
      <div class="bj-bet" data-when="idle" <?= $live ? 'hidden' : '' ?>>
        <label for="bj-bet">Bet</label>
        <input id="bj-bet" type="number" name="bet" min="<?= (int)$g['min_bet'] ?>" max="<?= (int)$g['max_bet'] ?>" step="1" value="<?= max((int)$g['min_bet'], min(100, (int)$g['max_bet'])) ?>" inputmode="numeric">
        <div class="quick" role="group" aria-label="Quick bets">
          <?php foreach ([25, 100, 500, 1000] as $q): if ($q >= (int)$g['min_bet'] && $q <= (int)$g['max_bet']): ?><button type="button" class="chip c<?= $q ?>" data-quick="<?= $q ?>"><?= coins($q) ?></button><?php endif; endforeach; ?>
        </div>
        <button class="btn gold lg" name="move" value="deal">Deal</button>
      </div>
      <div class="bj-moves" data-when="live" <?= $live ? '' : 'hidden' ?>>
        <button class="btn gold lg" name="move" value="hit">Hit</button>
        <button class="btn ghost lg" name="move" value="stand">Stand</button>
        <button class="btn coral lg" name="move" value="double" data-double <?= $hand && $hand['can_double'] ? '' : 'disabled' ?>>Double</button>
      </div>
    </form>
    <?php else: ?>
      <p class="controls"><a class="btn gold lg" href="<?= h(url('register')) ?>">Sign up free to take a seat</a></p>
    <?php endif; ?>
  </div>
  <aside class="panel reveal d3 house-rules">
    <h2 class="display md">House rules</h2>
    <ul class="ticks">
      <li>Six-deck shoe, reshuffled every hand.</li><li>Dealer peeks for blackjack and stands on all 17s.</li>
      <li>Blackjack pays 3:2. Wins pay 1:1. Ties push.</li><li>Double down on any first two cards (one more card).</li>
      <li>No splits or insurance at this table.</li>
    </ul>
  </aside>
</section>
<?= games_rail('blackjack') ?>
<?php layout($g['name'], ob_get_clean());
}

function page_roulette(): void {
    $g = game_header('roulette');
    $p = current_player();
    $last = $_SESSION['last']['roulette'] ?? null;
    unset($_SESSION['last']['roulette']);
    ob_start(); ?>
<section data-roulette data-min="<?= (int)$g['min_bet'] ?>" data-max="<?= (int)$g['max_bet'] ?>" class="table-wrap rl-wrap<?= scene_open('roulette') ?>">
  <header class="table-head reveal d1">
    <p class="eyebrow">Coronado Roulette</p>
    <h1 class="display lg"><?= h($g['name']) ?></h1>
  </header>
  <div class="rl-top reveal d2">
    <div class="wheel-box">
      <div class="pointer" aria-hidden="true"></div>
      <svg class="wheel" data-wheel viewBox="-110 -110 220 220" aria-hidden="true"></svg>
      <div class="landed" data-landed aria-live="polite"><?= $last ? '<b class="n ' . h($last['color']) . '">' . (int)$last['number'] . '</b>' : '' ?></div>
    </div>
    <div class="rl-side">
      <p class="result" data-result aria-live="polite"><?= $last ? h($last['message']) : 'Pick a chip, tap the board, spin.' ?></p>
      <div class="chips" role="radiogroup" aria-label="Chip value" data-chips>
        <?php $first = true; foreach ([10, 50, 100, 500, 1000] as $c): if ($c >= (int)$g['min_bet'] && $c <= (int)$g['max_bet']): ?>
          <button type="button" class="chip c<?= $c ?>" role="radio" aria-checked="<?= $first ? 'true' : 'false' ?>" data-chip="<?= $c ?>"><?= $c >= 1000 ? ($c / 1000) . 'K' : $c ?></button>
        <?php $first = false; endif; endforeach; ?>
      </div>
      <p class="staked">On the table: <strong data-staked>0</strong> GC</p>
      <div class="rl-actions">
        <?php if ($p): ?>
        <button type="button" class="btn gold lg" data-rl-spin disabled>Spin</button>
        <button type="button" class="btn ghost" data-rl-undo disabled>Undo</button>
        <button type="button" class="btn ghost" data-rl-clear disabled>Clear</button>
        <button type="button" class="btn ghost" data-rl-rebet hidden>Rebet</button>
        <?php else: ?><a class="btn gold lg" href="<?= h(url('register')) ?>">Sign up free to play</a><?php endif; ?>
      </div>
      <ol class="history" data-history aria-label="Recent numbers"></ol>
    </div>
  </div>
  <div class="board-scroll reveal d3">
  <div class="board" data-board role="group" aria-label="Betting board">
    <button type="button" class="b-zero green" data-bet="straight:0">0</button>
    <?php for ($col = 0; $col < 12; $col++): for ($row = 2; $row >= 0; $row--): $n = $col * 3 + $row + 1; ?>
      <button type="button" class="num <?= in_array($n, ROULETTE_RED, true) ? 'red' : 'black' ?>" style="grid-column:<?= $col + 2 ?>;grid-row:<?= 3 - $row ?>" data-bet="straight:<?= $n ?>"><?= $n ?></button>
    <?php endfor; endfor; ?>
    <?php for ($c = 3; $c >= 1; $c--): ?><button type="button" class="out col" style="grid-column:14;grid-row:<?= 4 - $c ?>" data-bet="column:<?= $c ?>" aria-label="Column <?= $c ?>">2:1</button><?php endfor; ?>
    <?php for ($d = 1; $d <= 3; $d++): ?><button type="button" class="out dozen" style="grid-column:<?= ($d - 1) * 4 + 2 ?> / span 4;grid-row:4" data-bet="dozen:<?= $d ?>"><?= ['1st', '2nd', '3rd'][$d - 1] ?> 12</button><?php endfor; ?>
    <?php foreach ([['low', '1–18'], ['even', 'Even'], ['red', '◆'], ['black', '◆'], ['odd', 'Odd'], ['high', '19–36']] as $i => [$t, $l]): ?>
      <button type="button" class="out even-money <?= $t ?>" style="grid-column:<?= $i * 2 + 2 ?> / span 2;grid-row:5" data-bet="<?= $t ?>:0" aria-label="<?= ucfirst($t) ?>"><?= $l ?></button>
    <?php endforeach; ?>
  </div>
  </div>
  <?php if ($p): ?>
  <noscript>
    <form class="panel" method="post" action="<?= h(url('play_roulette')) ?>">
      <?= csrf_field() ?>
      <h2 class="display md">Quick bet</h2>
      <label>Bet on <select name="bet_type"><?php foreach (['red', 'black', 'odd', 'even', 'low', 'high', 'dozen', 'column', 'straight'] as $t): ?><option><?= $t ?></option><?php endforeach; ?></select></label>
      <label>Number / dozen / column <input type="number" name="bet_value" min="0" max="36" value="0"></label>
      <label>Amount <input type="number" name="amount" min="<?= (int)$g['min_bet'] ?>" max="<?= (int)$g['max_bet'] ?>" value="<?= (int)$g['min_bet'] ?>"></label>
      <button class="btn gold">Spin</button>
    </form>
  </noscript>
  <?php endif; ?>
  <aside class="panel reveal d4">
    <h2 class="display md">Payouts</h2>
    <ul class="ticks cols">
      <li>Single number 35:1</li><li>Dozen or column 2:1</li><li>Red/black, odd/even, 1–18/19–36 1:1</li><li>Zero loses outside bets</li>
      <li>Up to <?= coins((int)$g['max_bet']) ?> GC on any one spot, <?= coins((int)$g['max_bet'] * 10) ?> GC per spin</li>
    </ul>
    <p class="fine">Right-click (or long-press) a spot to pull chips back off it.</p>
  </aside>
</section>
<?= games_rail('roulette') ?>
<?php layout($g['name'], ob_get_clean());
}

function page_leaderboard(): void {
    $by = (string)($_GET['by'] ?? 'balance');
    $boards = [
        'balance' => ['Biggest stacks', 'balance', 'Gold Coins'],
        'bigwin' => ['Biggest single win', 'biggest_win', 'Net win'],
        'rounds' => ['Most rounds played', 'rounds_played', 'Rounds'],
    ];
    if (!isset($boards[$by])) { $by = 'balance'; }
    [$title, $col, $unit] = $boards[$by];
    $rows = q("SELECT id, username, $col AS v FROM players WHERE status = 'active' AND $col > 0 ORDER BY $col DESC, id LIMIT 50")->fetchAll();
    $me = current_player();
    ob_start(); ?>
<section class="panel wide reveal d1">
  <p class="eyebrow">Leaderboard</p>
  <h1 class="display lg"><?= h($title) ?></h1>
  <nav class="tabs" aria-label="Leaderboard type">
    <?php foreach ($boards as $k => [$t]): ?><a href="<?= h(url('leaderboard', ['by' => $k])) ?>"<?= $k === $by ? ' aria-current="page"' : '' ?>><?= h($t) ?></a><?php endforeach; ?>
  </nav>
  <ol class="leader-list big">
    <?php foreach ($rows as $i => $r): ?>
      <li class="reveal d<?= min(6, 2 + intdiv($i, 3)) ?><?= $me && (int)$me['id'] === (int)$r['id'] ? ' me' : '' ?>">
        <span class="rank<?= $i < 3 ? ' podium p' . ($i + 1) : '' ?>"><?= $i + 1 ?></span>
        <span class="name"><?= h($r['username']) ?></span>
        <span class="num"><?= coins((int)$r['v']) ?> <small><?= h($unit) ?></small></span>
      </li>
    <?php endforeach; ?>
    <?php if (!$rows): ?><li class="muted">No one on the board yet.</li><?php endif; ?>
  </ol>
</section>
<?php layout('Leaderboard', ob_get_clean());
}

function page_account(): void {
    $p = require_player();
    $ledger = q('SELECT * FROM ledger WHERE player_id = ? ORDER BY id DESC LIMIT 30', [$p['id']])->fetchAll();
    $net = (int)$p['total_won'] - (int)$p['total_wagered'];
    ob_start(); ?>
<section class="acct">
  <header class="table-head reveal d1">
    <p class="eyebrow">Your account</p>
    <h1 class="display lg"><?= h($p['username']) ?></h1>
  </header>
  <div class="tiles reveal d2">
    <div class="tile"><span>Balance</span><strong data-balance="<?= (int)$p['balance'] ?>"><?= coins((int)$p['balance']) ?></strong></div>
    <div class="tile"><span>Rounds</span><strong><?= coins((int)$p['rounds_played']) ?></strong></div>
    <div class="tile"><span>Biggest win</span><strong><?= coins((int)$p['biggest_win']) ?></strong></div>
    <div class="tile"><span>Lifetime net</span><strong class="<?= $net >= 0 ? 'pos' : 'neg' ?>"><?= ($net >= 0 ? '+' : '') . coins($net) ?></strong></div>
  </div>
  <?= bonus_strip($p) ?>
  <div class="acct-grid">
    <section class="panel reveal d3">
      <h2 class="display md">Recent coin activity</h2>
      <div class="scroll-x"><table class="data compact">
        <thead><tr><th>When (UTC)</th><th>What</th><th class="n">Coins</th><th class="n">Balance</th></tr></thead>
        <tbody>
        <?php foreach ($ledger as $l): ?>
          <tr><td><?= h(substr($l['created_at'], 5, 11)) ?></td><td><?= $l['kind'] === 'wager' && (int)$l['amount'] > 0 ? 'Chips back' : h(ucfirst($l['kind'])) ?><?= $l['game'] ? ' · ' . h($l['game']) : '' ?></td>
            <td class="n <?= (int)$l['amount'] >= 0 ? 'pos' : 'neg' ?>"><?= ((int)$l['amount'] >= 0 ? '+' : '') . coins((int)$l['amount']) ?></td><td class="n"><?= coins((int)$l['balance_after']) ?></td></tr>
        <?php endforeach; ?>
        </tbody>
      </table></div>
    </section>
    <div class="stack">
      <section class="panel reveal d4">
        <h2 class="display md">Change password</h2>
        <form method="post" action="<?= h(url('player_password')) ?>" class="form">
          <?= csrf_field() ?>
          <label>Current password <input type="password" name="current_password" autocomplete="current-password" required></label>
          <label>New password <input type="password" name="new_password" minlength="8" autocomplete="new-password" required></label>
          <label>New password again <input type="password" name="new_password2" minlength="8" autocomplete="new-password" required></label>
          <button class="btn ghost">Update password</button>
        </form>
      </section>
      <section class="panel reveal d5 break-panel">
        <h2 class="display md">Take a break</h2>
        <?php if ($until = on_break($p)): ?>
          <p>You're on a break until <strong><?= h($until) ?> UTC</strong>. Games and bonuses stay locked until then. You can extend it below.</p>
        <?php else: ?>
          <p>Even with play money, it's healthy to step away. This locks games and bonuses for the time you pick, and it can't be shortened.</p>
        <?php endif; ?>
        <form method="post" action="<?= h(url('take_break')) ?>" class="form">
          <?= csrf_field() ?>
          <label>How long <select name="days"><option value="1">1 day</option><option value="7">7 days</option><option value="30">30 days</option><option value="90">90 days</option></select></label>
          <label>Type <b>BREAK</b> to confirm <input name="confirm" pattern="BREAK" required autocomplete="off"></label>
          <button class="btn coral">Start my break</button>
        </form>
      </section>
      <form method="post" action="<?= h(url('logout')) ?>" class="reveal d6"><?= csrf_field() ?><button class="btn ghost wide">Log out</button></form>
    </div>
  </div>
</section>
<?php layout('Account', ob_get_clean());
}

function page_login(): void {
    if (current_player()) { redirect(url()); }
    ob_start(); ?>
<section class="panel narrow auth reveal d1">
  <p class="eyebrow">Welcome back</p>
  <h1 class="display lg">Log in</h1>
  <form method="post" action="<?= h(url('login')) ?>" class="form">
    <?= csrf_field() ?>
    <label>Username <input name="username" value="<?= h(old('username')) ?>" autocomplete="username" required autofocus></label>
    <label>Password <input type="password" name="password" autocomplete="current-password" required></label>
    <button class="btn gold lg wide">Log in</button>
  </form>
  <p class="muted">New here? <a href="<?= h(url('register')) ?>">Make a free account</a>.</p>
</section>
<?php layout('Log in', ob_get_clean());
}

function page_register(): void {
    if (current_player()) { redirect(url()); }
    $open = isetting('registration_open', 1);
    $age = isetting('min_age', 21);
    ob_start(); ?>
<section class="panel narrow auth reveal d1">
  <p class="eyebrow">Free account · <?= coins(isetting('starting_coins', 10000)) ?> GC to start</p>
  <h1 class="display lg">Pull up a chair</h1>
  <?php if (!$open): ?>
    <p class="lead">Signups are paused right now. Check back soon.</p>
  <?php else: ?>
  <form method="post" action="<?= h(url('register')) ?>" class="form" novalidate>
    <?= csrf_field() ?>
    <label>Username <input name="username" value="<?= h(old('username')) ?>" pattern="[A-Za-z0-9_]{3,24}" maxlength="24" autocomplete="username" required<?= aria_err('username') ?>></label><?= field_error('username') ?>
    <label>Email <small>(optional, only used for account recovery)</small> <input type="email" name="email" value="<?= h(old('email')) ?>" autocomplete="email"<?= aria_err('email') ?>></label><?= field_error('email') ?>
    <label>Password <input type="password" name="password" minlength="8" autocomplete="new-password" required<?= aria_err('password') ?>></label><?= field_error('password') ?>
    <label>Password again <input type="password" name="password2" minlength="8" autocomplete="new-password" required<?= aria_err('password2') ?>></label><?= field_error('password2') ?>
    <label class="check"><input type="checkbox" name="age_ok" value="1" required<?= aria_err('age_ok') ?>> I'm <?= $age ?> or older.</label><?= field_error('age_ok') ?>
    <label class="check"><input type="checkbox" name="terms_ok" value="1" required<?= aria_err('terms_ok') ?>> I get it: Gold Coins are play money with no cash value, and can't be bought, redeemed, or traded. <a href="<?= h(url('rules')) ?>">Details</a></label><?= field_error('terms_ok') ?>
    <button class="btn gold lg wide">Create account</button>
  </form>
  <?php endif; ?>
  <p class="muted">Already playing? <a href="<?= h(url('login')) ?>">Log in</a>.</p>
</section>
<?php layout('Sign up', ob_get_clean());
}

function page_rules(): void {
    $site = setting('site_name', 'Gold Tide');
    ob_start(); ?>
<section class="panel narrow prose reveal d1">
  <p class="eyebrow">The fine print, in plain English</p>
  <h1 class="display lg">How <?= h($site) ?> works</h1>
  <h2>Gold Coins are play money</h2>
  <p>Every account starts with <?= coins(isetting('starting_coins', 10000)) ?> Gold Coins (GC). You earn more from the daily bonus, the low-balance refill, and promo codes handed out at events. That's it.</p>
  <ul class="ticks">
    <li>You can't buy Gold Coins. There's no store.</li>
    <li>You can't cash out, redeem, or trade Gold Coins for money, prizes, or anything else of value.</li>
    <li>Winning or losing here has no effect outside this site.</li>
  </ul>
  <h2>Fair games</h2>
  <p>Every spin, card, and roll is decided on our server with a cryptographically secure random number generator, then shown to you. Slots return about 95% over time, blackjack follows the house rules on the table, and roulette uses a single-zero wheel.</p>
  <h2>Play money is still practice for real habits</h2>
  <p>Social casino games can feel a lot like the real thing. If you notice you're chasing losses, playing longer than you meant to, or it stops being fun, take a break. You can lock your own account from <a href="<?= h(url('account')) ?>">your account page</a> for 1 to 90 days.</p>
  <p>If gambling (real or not) is causing trouble for you or someone you love, call or text <a href="tel:18004262537">1-800-GAMBLER</a>. It's free, confidential, and open around the clock. California residents can also reach the Office of Problem Gambling's free treatment program.</p>
  <h2>Who can play</h2>
  <p>Adults <?= isetting('min_age', 21) ?> and older, one account per person. Accounts that game the system (multiple accounts, automation) can be suspended.</p>
</section>
<?php layout('How it works', ob_get_clean());
}

/* ═════════════════════════ GAME PANELS ═════════════════════════
 * Each panel is rendered by the server from the round in the database, so the
 * page works with no JS at all. With JS, the play endpoint hands back the fresh
 * panel HTML and the script just swaps it in and animates.
 */
const GAME_RULES = [
    'poker' => ['No-limit Texas hold\'em, real players at the table (house players fill empty seats and are labelled). Blinds and buy-in range are set per table.', 'Buy in from your Gold Coins. Your stack lives at the table until you stand up, then it goes straight back to your balance.', 'Fold, check, call, raise or shove. Minimum raise is the size of the last raise. Side pots are handled like a live room and odd chips go to the first seat left of the button.', 'The clock gives you ' . 20 . ' seconds an action; two timeouts and you sit out. Leave any time; if you\'re in a hand, you\'re folded and paid when it ends.', 'Every deal is committed to before a card moves: the table shows a SHA-256 of the shuffled deck, and reveals the deck and salt after the hand. Open any hand history to verify it.'],
    'roulette3d' => ['Tap a chip, tap the board, hit Spin. Same single-zero payouts as the 2D table (35:1 straight up).', 'The wheel you watch is the real result: the server picks the pocket, then the ball is steered into it.', 'Right-click or long-press a spot to pull chips back.'],
    'craps' => ['Come-out roll: Pass or Don\'t Pass. 7 or 11 wins Pass, 2, 3 or 12 loses it (12 pushes Don\'t Pass). Any other number becomes the point; hit it again before a 7 to win.', 'Come and Don\'t Come work the same way on any roll after the point is set, and travel to their own number. Back line and come bets with odds (3-4-5× behind Pass and Come, 6× laying): odds pay true odds with zero house edge.', 'Every number has Place (6/8 pay 7:6, 5/9 pay 7:5, 4/10 pay 9:5), Buy (true odds, 5% on wins) and Lay (bet the 7 beats it). Big 6 and Big 8 pay even money. These stay up until they lose and are OFF on the come-out roll.', 'Field, Any 7, Any craps, Aces, Ace-deuce, Yo, Boxcars, Horn and C & E are one-roll bets. Hardways stay up until the pair hits, a 7 rolls, or the number comes easy.', 'Use Take bets down to pull place, buy, lay, odds, hardways, Big 6/8 and don\'t bets back. Pass and come bets are contract bets and ride until they\'re decided. Right-click or long-press pulls back chips you haven\'t rolled yet.', 'Chips you take back down were never in play: they don\'t count toward your rounds, wagered or won totals. Each spot takes up to the table max (chips already working included), and each roll up to 10× the table max in new chips.'],
    'pusher' => ['Each coin you drop costs your coin value. Coins that spill over the front edge are yours.', 'Tap the machine or use the slider to aim. Aiming is just for fun: how many coins fall is decided the moment you drop.', 'About 46% of drops spill something, and rare avalanches pay 25× or 100×. Return to player is 95%.'],
    'scratch' => ['Buy a ticket, scratch all nine spots.', 'Three matching prizes wins that prize. Only one triple per ticket.', 'Top prize is 1,000× the ticket. About 1 in 4 tickets wins something.'],
    'keno' => ['Pick 1 to 10 numbers from 40.', 'Ten numbers are drawn. The more you catch, the more you win.', 'The paytable changes with how many you pick. Big picks, big jackpots.'],
    'baccarat' => ['Bet on Player, Banker, or Tie. Closest to 9 wins.', 'Cards are worth face value, tens and faces are 0, aces are 1. Only the last digit counts.', 'Player pays 1:1, Banker pays 0.95:1, Tie pays 8:1 (and Player/Banker bets push on a tie).', 'Third cards follow the standard tableau. No decisions needed.'],
    'sicbo' => ['Three dice are shaken. Bet on what they show.', 'Small (4–10) and Big (11–17) pay 1:1 but lose on any triple.', 'Totals pay 6:1 up to 60:1, doubles 10:1, any triple 30:1, a specific triple 180:1.', 'Single numbers pay 1:1 per die that shows it.'],
    'bigwheel' => ['Put chips on the symbols you like, then spin.', '54 stops: 24×1, 15×2, 7×5, 4×10, 2×20, one anchor, one sun.', 'Numbers pay their face value to 1. The anchor and sun pay 45 to 1.'],
    'crabs' => ['Back one crab or several.', 'Odds are fixed. Favorites win more often, longshots pay more.', 'Payout is your chip times the odds shown (it includes your chip).'],
    'videopoker' => ['Deal five cards, tap the ones to hold, then draw.', 'Win on a pair of Jacks or better. Full paytable is on the machine.', 'With perfect holds this 9/6 paytable returns about 99.5%.'],
    'threecard' => ['Place an Ante (and an optional Pair Plus), get three cards.', 'Play (matching your Ante) or fold. Dealer needs Queen-high to qualify.', 'Ante bonus pays on a straight or better no matter what the dealer has.', 'Pair Plus pays on your hand alone: pair 1:1 up to straight flush 40:1.'],
    'hilo' => ['Call whether the next card is higher or lower.', 'Ties count as a win either way. Aces are low.', 'Every right call multiplies your run. Cash out any time after your first call.', 'Up to five skips per run if you don\'t like a card.'],
    'crash' => ['Launch your wave. The multiplier climbs from 1.00×.', 'Cash out any time before the wave breaks to lock in that multiplier.', 'Set an auto cash-out so the server grabs it for you, even if your connection hiccups.', 'Any cash-out target returns 99% over time.'],
    'plinko' => ['Pick 8–16 rows, a risk level, and how many pearls to drop at once (1–20). Your bet is per pearl.',
        'Every drop, 3 golden pegs light up. Each golden peg a pearl touches doubles that pearl\'s multiplier, and they stack: ×2, ×4, ×8.',
        'Every row count and risk level returns 98.5–99% over time, with the golden peg bonus included.',
        'Provably fair: your drops come from a server seed that\'s locked in (and fingerprinted) before you play. Rotate it any time to reveal it and verify every drop right on this page.',
        'Autoplay can stop itself on a big hit, a profit target, or a loss limit. Space bar drops too.'],
    'mines' => ['Choose how many urchins hide in the reef (1–24).', 'Flip tiles. Every pearl raises the multiplier, an urchin ends the round.', 'Cash out whenever you want. More urchins, faster growth.'],
    'dice' => ['Slide to set your target, pick roll over or under.', 'The roll is 0.00–99.99. Lower chance, higher payout.', 'Multiplier = 99 ÷ win chance, so every setting has the same 1% edge.'],
];

function game_panel(string $slug): string {
    $p = current_player();
    $g = row('SELECT * FROM games WHERE slug = ?', [$slug]);
    if (!$p || !$g) { return ''; }
    $fresh = row('SELECT * FROM players WHERE id = ?', [$p['id']]);
    if (isset(VSLOTS[$slug])) { return panel_videoslot($slug, $fresh, $g); }
    try { return ('panel_' . $slug)($fresh, $g); }
    catch (Throwable $e) {
        // a hand-edited or legacy round shouldn't take the whole table down: log it, render a fresh table
        error_log('[' . date('c') . "] panel $slug: " . $e->getMessage());
        $GLOBALS['gt_skip_last'] = true;
        try { return ('panel_' . $slug)($fresh, $g); } finally { unset($GLOBALS['gt_skip_last']); }
    }
}

function play_url(string $slug): string { return url('play', ['g' => $slug]); }
function play_form_open(string $slug, string $class = ''): string {
    return '<form method="post" action="' . h(play_url($slug)) . '" data-play class="' . h($class) . '">' . csrf_field();
}
function bet_box(array $g, int $default, string $name = 'bet', string $label = 'Bet'): string {
    $d = max((int)$g['min_bet'], min((int)$g['max_bet'], $default ?: 100));
    return '<div class="betbox"><label>' . h($label) . ' <input type="number" name="' . h($name) . '" min="' . (int)$g['min_bet'] . '" max="' . (int)$g['max_bet']
        . '" step="1" value="' . $d . '" inputmode="numeric" required></label><div class="bet-quick" role="group" aria-label="Adjust bet">'
        . '<button type="button" data-adj="half">½</button><button type="button" data-adj="double">2×</button>'
        . '<button type="button" data-adj="min">min</button><button type="button" data-adj="max">max</button></div></div>';
}
function result_line(string $msg, bool $win = false): string {
    return '<p class="result after' . ($win ? ' win' : '') . '" aria-live="polite">' . h($msg) . '</p>';
}
function die_svg(int $n, string $cls = ''): string {
    $pips = [1 => [[50, 50]], 2 => [[28, 28], [72, 72]], 3 => [[26, 26], [50, 50], [74, 74]], 4 => [[28, 28], [72, 28], [28, 72], [72, 72]],
        5 => [[26, 26], [74, 26], [50, 50], [26, 74], [74, 74]], 6 => [[28, 24], [72, 24], [28, 50], [72, 50], [28, 76], [72, 76]]][$n] ?? [];
    $s = '<svg class="die ' . h($cls) . '" viewBox="0 0 100 100" role="img" aria-label="die showing ' . $n . '"><rect x="4" y="4" width="92" height="92" rx="20" fill="#fffaf0" stroke="#e8b64c" stroke-width="4"/>';
    foreach ($pips as [$x, $y]) { $s .= '<circle cx="' . $x . '" cy="' . $y . '" r="9" fill="' . ($n === 1 ? '#d6283f' : '#1b1a2e') . '"/>'; }
    return $s . '</svg>';
}
function crab_svg(string $color): string {
    return '<svg class="crab" viewBox="0 0 64 44" aria-hidden="true"><g fill="' . h($color) . '"><ellipse cx="32" cy="27" rx="17" ry="11"/>'
        . '<path d="M14 22c-8-2-11-9-8-14 3 3 7 3 9 0 2 5 1 10-1 14zM50 22c8-2 11-9 8-14-3 3-7 3-9 0-2 5-1 10 1 14z"/>'
        . '<path d="M17 31l-9 5M17 34l-7 8M47 31l9 5M47 34l7 8" stroke="' . h($color) . '" stroke-width="3" stroke-linecap="round"/></g>'
        . '<circle cx="26" cy="16" r="4" fill="#fff"/><circle cx="38" cy="16" r="4" fill="#fff"/><circle cx="26.5" cy="16.5" r="2" fill="#111"/><circle cx="38.5" cy="16.5" r="2" fill="#111"/>'
        . '<path d="M27 30q5 4 10 0" stroke="#111" stroke-width="2" fill="none" stroke-linecap="round"/></svg>';
}

/** Shared chip-board UI for multi-bet table games. $spots = [key => html label]. */
function chipboard(string $slug, array $g, string $boardHtml, array $spots, string $go = 'Spin'): string {
    $chips = '';
    $first = true;
    foreach ([10, 50, 100, 500, 1000] as $c) {
        if ($c < (int)$g['min_bet'] || $c > (int)$g['max_bet']) { continue; }
        $chips .= '<button type="button" class="chip c' . $c . '" role="radio" aria-checked="' . ($first ? 'true' : 'false') . '" data-chip="' . $c . '">' . ($c >= 1000 ? ($c / 1000) . 'K' : $c) . '</button>';
        $first = false;
    }
    $opts = '';
    foreach ($spots as $k => $l) { $opts .= '<option value="' . h($k) . '">' . h(strip_tags($l)) . '</option>'; }
    return '<div class="cb" data-chipboard="' . h($slug) . '" data-min="' . (int)$g['min_bet'] . '" data-max="' . (int)$g['max_bet'] . '">'
        . '<div class="cb-bar"><div class="chips" role="radiogroup" aria-label="Chip value">' . $chips . '</div>'
        . '<p class="staked">On the table: <strong data-staked>0</strong> GC</p>'
        . '<div class="rl-actions"><button type="button" class="btn gold lg" data-cb-go disabled>' . h($go) . '</button>'
        . '<button type="button" class="btn ghost" data-cb-undo disabled>Undo</button><button type="button" class="btn ghost" data-cb-clear disabled>Clear</button>'
        . '<button type="button" class="btn ghost" data-cb-rebet hidden>Rebet</button></div></div>'
        . $boardHtml
        . '<noscript>' . play_form_open($slug, 'panel form') . '<label>Bet on <select name="bet_key">' . $opts . '</select></label>'
        . '<label>Amount <input type="number" name="amount" min="' . (int)$g['min_bet'] . '" max="' . (int)$g['max_bet'] . '" value="' . (int)$g['min_bet'] . '"></label>'
        . '<button class="btn gold">' . h($go) . '</button></form></noscript></div>';
}

/* ── dice ── */
function panel_dice(array $p, array $g): string {
    $last = round_last((int)$p['id'], 'dice'); $s = st($last);
    $target = $s['target'] ?? 50; $dir = $s['dir'] ?? 'under';
    ob_start(); ?>
<div class="dice-stage">
  <div class="dice-readout after"><?php if ($last): ?><span class="big-num <?= $last['payout'] > 0 ? 'pos' : 'neg' ?>" data-roll="<?= h($s['roll']) ?>"><?= number_format($s['roll'], 2) ?></span><?php else: ?><span class="big-num">–</span><?php endif; ?></div>
  <div class="dice-track <?= h($dir) ?>" style="--t:<?= (float)$target ?>%" data-track>
    <div class="dice-zone"></div>
    <?php if ($last): ?><div class="dice-marker after <?= $last['payout'] > 0 ? 'win' : 'lose' ?>" style="--r:<?= (float)$s['roll'] ?>%"><span><?= number_format($s['roll'], 2) ?></span></div><?php endif; ?>
    <div class="dice-scale"><span>0</span><span>25</span><span>50</span><span>75</span><span>100</span></div>
  </div>
  <?= $last ? result_line(sprintf('Rolled %.2f · ', $s['roll']) . ($last['payout'] ? 'won ' . coins((int)$last['payout']) . ' GC' : 'miss'), $last['payout'] > 0) : '<p class="result">Set your odds and roll.</p>' ?>
</div>
<?= play_form_open('dice', 'controls stacked') ?>
  <label class="slider">Target <input type="range" name="target" min="2" max="98" step="0.5" value="<?= h($target) ?>" data-dice-target></label>
  <div class="seg" role="radiogroup" aria-label="Direction">
    <label><input type="radio" name="dir" value="under" <?= $dir === 'under' ? 'checked' : '' ?> data-dice-dir> Roll under</label>
    <label><input type="radio" name="dir" value="over" <?= $dir === 'over' ? 'checked' : '' ?> data-dice-dir> Roll over</label>
  </div>
  <div class="stat-row"><span>Win chance <b data-dice-chance>–</b></span><span>Pays <b data-dice-mult>–</b></span></div>
  <?= bet_box($g, (int)($last['bet'] ?? 100)) ?>
  <button class="btn gold xl">Roll</button>
</form>
<?php return ob_get_clean();
}

/* ── Pearl Drop panel ── */
function panel_plinko(array $p, array $g): string {
    $pid = (int)$p['id'];
    $last = round_last($pid, 'plinko'); $s = st($last);
    if (!isset($s['balls'])) { $s = []; } // rounds from the old 12-row version don't carry per-ball data
    $rows = (int)($s['rows'] ?? 12); $risk = (string)($s['risk'] ?? 'med');
    $balls = count($s['balls'] ?? [1]); $per = (int)($s['per'] ?? max((int)$g['min_bet'], 100));
    $seed = tx(fn() => fair_active($pid, 'plinko'));
    $revealed = q("SELECT server_seed, server_hash, client_seed, nonce, revealed_at FROM fair_seeds WHERE player_id = ? AND game = 'plinko' AND status = 'revealed' ORDER BY id DESC LIMIT 5", [$pid])->fetchAll();
    $recent = q("SELECT state, bet, payout FROM rounds WHERE player_id = ? AND game = 'plinko' AND status = 'done' ORDER BY id DESC LIMIT 8", [$pid])->fetchAll();
    $cfg = ['tables' => PD_TABLES, 'gold' => PD_GOLD, 'min' => (int)$g['min_bet'], 'max' => (int)$g['max_bet']];
    $seg = function (string $name, array $opts, $cur) {
        $o = '<div class="seg" role="radiogroup" aria-label="' . h(ucfirst($name)) . '">';
        foreach ($opts as $v => $l) { $o .= '<label><input type="radio" name="' . h($name) . '" value="' . h($v) . '"' . ((string)$v === (string)$cur ? ' checked' : '') . '> ' . h($l) . '</label>'; }
        return $o . '</div>';
    };
    ob_start(); ?>
<div class="pd" data-pearldrop data-cfg="<?= h(json_encode($cfg)) ?>">
  <div class="pd-top">
    <ol class="pd-hist" data-pd-hist aria-label="Recent pearls"></ol>
    <div class="pd-tools">
      <button type="button" class="icon-btn" data-pd-sound aria-pressed="true" aria-label="Sound on" title="Sound"><svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path d="M4 9h4l5-4v14l-5-4H4z" fill="currentColor"/><path d="M16 8.5a5 5 0 0 1 0 7M18.5 6a8.5 8.5 0 0 1 0 12" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" data-waves/></svg></button>
      <a class="fair-badge" href="#pd-fair" data-pd-fair-open><svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5z" fill="currentColor"/><path d="m8.5 12 2.5 2.5 4.5-5" stroke="#0b1a33" stroke-width="2.2" fill="none" stroke-linecap="round"/></svg> Provably fair</a>
    </div>
  </div>
  <div class="pd-board" data-pd-board>
    <canvas data-pd-canvas aria-label="Pearl Drop board" role="img"></canvas>
    <div class="pd-banner" data-pd-banner aria-hidden="true"></div>
  </div>
  <p class="result pd-result" data-pd-result aria-live="polite"><?php
    if ($s) { echo h(count($s['balls']) . ' pearl' . (count($s['balls']) > 1 ? 's' : '') . ' · ' . ((int)$last['payout'] ? coins((int)$last['payout']) . ' GC back' : 'nothing back')); }
    else { echo '3 golden pegs light up every drop. Each one a pearl touches doubles it.'; } ?></p>
  <?php if ($s): ?><noscript><p class="muted center">Last drop: <?= h(implode(' · ', array_map(fn($b) => $b['mult'] . '×' . ($b['hits'] ? ' (' . count($b['hits']) . ' gold)' : ''), $s['balls']))) ?></p></noscript><?php endif; ?>

  <form class="pd-controls" method="post" action="<?= h(play_url('plinko')) ?>" data-pd-form>
    <?= csrf_field() ?>
    <div class="pd-row">
      <div class="pd-field"><span>Rows</span><?= $seg('rows', array_combine(PD_ROWS, PD_ROWS), $rows) ?></div>
      <div class="pd-field"><span>Risk</span><?= $seg('risk', ['low' => 'Low', 'med' => 'Medium', 'high' => 'High'], $risk) ?></div>
      <div class="pd-field"><span>Pearls per drop</span><?= $seg('balls', array_combine(PD_BALLS, PD_BALLS), $balls) ?></div>
    </div>
    <div class="pd-row main">
      <?= bet_box($g, $per, 'bet', 'Bet per pearl') ?>
      <p class="pd-total">Drop costs <b data-pd-cost><?= coins($per * $balls) ?></b> GC</p>
      <button class="btn gold xl pd-drop" data-pd-drop>Drop</button>
    </div>
    <details class="pd-auto">
      <summary>Autoplay &amp; turbo</summary>
      <div class="pd-row">
        <label>Drops <select data-pd-auto-n><option>10</option><option selected>25</option><option>50</option><option>100</option><option value="0">Until I stop</option></select></label>
        <label>Stop on a pearl ≥ <input type="number" min="0" step="1" placeholder="off" data-pd-stop-mult inputmode="numeric"> ×</label>
        <label>Stop at profit <input type="number" min="0" step="1" placeholder="off" data-pd-stop-win inputmode="numeric"></label>
        <label>Stop at loss <input type="number" min="0" step="1" placeholder="off" data-pd-stop-loss inputmode="numeric"></label>
        <label class="check"><input type="checkbox" data-pd-turbo> Turbo</label>
        <button type="button" class="btn ghost" data-pd-auto>Start autoplay</button>
      </div>
    </details>
  </form>

  <div class="pd-stats" data-pd-stats>
    <div><span>Drops</span><b data-st="drops">0</b></div><div><span>Pearls</span><b data-st="balls">0</b></div>
    <div><span>Wagered</span><b data-st="wagered">0</b></div><div><span>Won</span><b data-st="won">0</b></div>
    <div><span>Net</span><b data-st="net">0</b></div><div><span>Best</span><b data-st="best">–</b></div>
    <button type="button" class="btn ghost sm" data-pd-reset>Reset session</button>
  </div>

  <details class="pd-fair" id="pd-fair">
    <summary>Provably fair: check any drop yourself</summary>
    <div class="fair-grid">
      <section>
        <h3>Your live seed pair</h3>
        <dl class="fair-dl">
          <dt>Server seed hash</dt><dd><code data-fair-hash><?= h($seed['server_hash']) ?></code></dd>
          <dt>Client seed</dt><dd><code data-fair-client><?= h($seed['client_seed']) ?></code></dd>
          <dt>Next nonce</dt><dd><code data-fair-nonce><?= (int)$seed['nonce'] ?></code></dd>
        </dl>
        <p class="hint">We lock in the server seed before you play and show you its SHA-256 fingerprint. Every drop is HMAC-SHA256(server seed, "client:nonce:ball:N"). Rotate to reveal the seed and check every drop you made with it.</p>
        <form method="post" action="<?= h(url('fair', ['g' => 'plinko'])) ?>" class="form" data-fair-rotate>
          <?= csrf_field() ?>
          <label>New client seed <small>(optional)</small> <input name="client_seed" maxlength="64" pattern="[A-Za-z0-9_\-]{1,64}" placeholder="anything you like"></label>
          <button class="btn ghost">Reveal &amp; rotate seed</button>
        </form>
      </section>
      <section>
        <h3>Revealed seeds</h3>
        <ul class="fair-list" data-fair-revealed>
          <?php foreach ($revealed as $r): ?>
            <li><button type="button" class="linkish" data-fair-use="<?= h(json_encode(['seed' => $r['server_seed'], 'client' => $r['client_seed'], 'n' => (int)$r['nonce']])) ?>"><code><?= h(substr($r['server_seed'], 0, 16)) ?>…</code> · <?= (int)$r['nonce'] ?> drops</button></li>
          <?php endforeach; ?>
          <?php if (!$revealed): ?><li class="muted">Rotate your seed to reveal one.</li><?php endif; ?>
        </ul>
        <h3>Recent drops</h3>
        <ul class="fair-list">
          <?php foreach ($recent as $rr): $x = json_decode($rr['state'], true); if (!isset($x['balls'])) { continue; } ?>
            <li>nonce <b><?= (int)$x['nonce'] ?></b> · <?= (int)$x['rows'] ?> rows · <?= count($x['balls']) ?>× · <?= coins((int)$rr['payout']) ?> GC <small class="muted"><?= h(substr($x['hash'], 0, 8)) ?></small></li>
          <?php endforeach; ?>
        </ul>
      </section>
      <section>
        <h3>Verify a drop</h3>
        <div class="form" data-fair-verify>
          <label>Server seed <input data-v="seed" spellcheck="false" autocomplete="off"></label>
          <label>Client seed <input data-v="client" spellcheck="false" autocomplete="off"></label>
          <div class="inline"><label>Nonce <input type="number" min="0" value="0" data-v="nonce"></label><label>Rows <select data-v="rows"><?php foreach (PD_ROWS as $r): ?><option<?= $r === 12 ? ' selected' : '' ?>><?= $r ?></option><?php endforeach; ?></select></label><label>Pearl # <input type="number" min="1" max="20" value="1" data-v="ball"></label></div>
          <button type="button" class="btn gold" data-fair-check>Recompute</button>
          <pre class="fair-out" data-fair-out aria-live="polite">Paste a revealed seed and press recompute.</pre>
        </div>
      </section>
    </div>
  </details>
</div>
<?php return ob_get_clean();
}

/* ── keno ── */
function panel_keno(array $p, array $g): string {
    $last = round_last((int)$p['id'], 'keno'); $s = st($last);
    $picks = $s['picks'] ?? []; $drawn = $s['drawn'] ?? []; $hits = $s['hits'] ?? [];
    ob_start(); ?>
<?= play_form_open('keno', 'keno-form') ?>
<div class="keno-grid" data-keno>
  <?php for ($n = 1; $n <= 40; $n++): $di = array_search($n, $drawn, true); ?>
    <label class="kt<?= $di !== false ? ' drawn' : '' ?><?= in_array($n, $hits, true) ? ' hit' : '' ?>"<?= $di !== false ? ' style="--i:' . $di . '"' : '' ?>><input type="checkbox" name="picks[]" value="<?= $n ?>" <?= in_array($n, $picks, true) ? 'checked' : '' ?>><span><?= $n ?></span></label>
  <?php endfor; ?>
</div>
<div class="keno-side">
  <?= $last ? result_line(count($hits) . ' of ' . count($picks) . ' caught · ' . ($last['payout'] ? '+' . coins((int)$last['payout']) . ' GC' : 'no prize'), $last['payout'] > $last['bet']) : '<p class="result">Pick up to 10 numbers.</p>' ?>
  <table class="data compact keno-pay" data-keno-pay="<?= h(json_encode(KENO_PAY)) ?>"><thead><tr><th>Catch</th><th class="n">Pays</th></tr></thead><tbody></tbody></table>
  <div class="controls">
    <button type="button" class="btn ghost sm" data-keno-quick>Quick pick</button>
    <button type="button" class="btn ghost sm" data-keno-clear>Clear</button>
  </div>
  <?= bet_box($g, (int)($last['bet'] ?? 100)) ?>
  <button class="btn gold xl wide">Draw</button>
</div>
</form>
<?php return ob_get_clean();
}

/* ── scratchers ── */
function panel_scratch(array $p, array $g): string {
    $last = round_last((int)$p['id'], 'scratch'); $s = st($last);
    $tickets = array_values(array_filter([10, 50, 100, 500, 1000, 5000], fn($t) => $t >= (int)$g['min_bet'] && $t <= (int)$g['max_bet']));
    ob_start(); ?>
<div class="ticket" data-ticket>
  <div class="ticket-head"><span class="display md">Sunset Scratchers</span><span class="price"><?= $last ? coins((int)$last['bet']) . ' GC ticket' : 'Pick a ticket' ?></span></div>
  <div class="spots">
    <?php if ($last): foreach ($s['spots'] as $i => $v): ?>
      <div class="spot<?= $s['win'] && $v === $s['win'] ? ' match' : '' ?>" data-spot="<?= $i ?>"><span class="prize"><?= coins((int)$last['bet'] * $v) ?></span><small>GC</small></div>
    <?php endforeach; else: for ($i = 0; $i < 9; $i++): ?><div class="spot blank"><span class="prize">?</span></div><?php endfor; endif; ?>
  </div>
  <p class="ticket-foot">Match 3 like prizes to win that prize.</p>
</div>
<?= $last ? result_line($s['win'] ? 'Winner! ' . coins((int)$last['payout']) . ' GC' : 'No match this time.', $s['win'] > 0) : '<p class="result">Grab a ticket.</p>' ?>
<?= play_form_open('scratch', 'controls') ?>
  <?php foreach ($tickets as $t): ?><button class="btn <?= $t === ($last['bet'] ?? $tickets[0]) ? 'gold' : 'ghost' ?>" name="bet" value="<?= $t ?>"><?= coins($t) ?> GC ticket</button><?php endforeach; ?>
</form>
<button type="button" class="btn ghost sm reveal-all" data-reveal-all hidden>Reveal all</button>
<?php return ob_get_clean();
}

/* ── big six ── */
function panel_bigwheel(array $p, array $g): string {
    $last = round_last((int)$p['id'], 'bigwheel'); $s = st($last);
    $labels = ['1' => '1', '2' => '2', '5' => '5', '10' => '10', '20' => '20', 'anchor' => '⚓', 'sun' => '☀'];
    $board = '<div class="bw-board" data-board>';
    $spots = [];
    foreach (BIGSIX as $k => [$n, $pay]) {
        $k = (string)$k;
        $board .= '<button type="button" class="bw-spot s-' . h($k) . ($last && $s['hit'] === $k ? ' win' : '') . '" data-bet="' . h($k) . '"><b>' . $labels[$k] . '</b><small>' . $pay . ' to 1</small></button>';
        $spots[$k] = $labels[$k] . " ($pay to 1)";
    }
    $board .= '</div>';
    ob_start(); ?>
<div class="bw-stage">
  <div class="wheel-box bw">
    <div class="pointer" aria-hidden="true"></div>
    <svg class="wheel" viewBox="-110 -110 220 220" data-bigwheel="<?= h(json_encode(bigsix_wheel())) ?>" <?= $last ? 'data-index="' . (int)$s['index'] . '"' : '' ?> aria-hidden="true"></svg>
  </div>
  <?= $last ? result_line('Landed on ' . $labels[$s['hit']] . ($last['payout'] ? ' · +' . coins((int)$last['payout']) . ' GC' : ''), $last['payout'] > 0) : '<p class="result">Chips on a symbol, then spin.</p>' ?>
</div>
<?= chipboard('bigwheel', $g, $board, $spots) ?>
<?php return ob_get_clean();
}

/* ── sic bo ── */
function panel_sicbo(array $p, array $g): string {
    $last = round_last((int)$p['id'], 'sicbo'); $s = st($last);
    $wins = $s['wins'] ?? [];
    $spots = []; $b = '<div class="sb-board" data-board>';
    $btn = function (string $k, string $label, string $cls = '') use (&$spots, $wins) {
        $spots[$k] = $label;
        return '<button type="button" class="sb ' . $cls . (in_array($k, $wins, true) ? ' win' : '') . '" data-bet="' . h($k) . '">' . $label . '</button>';
    };
    $b .= '<div class="sb-row sb-top">' . $btn('small', '<b>SMALL</b><small>4–10 · 1:1</small>', 'wide') . $btn('any_triple', '<b>ANY TRIPLE</b><small>30:1</small>', 'wide') . $btn('big', '<b>BIG</b><small>11–17 · 1:1</small>', 'wide') . '</div>';
    $b .= '<div class="sb-row totals">';
    foreach (SICBO_TOTALS as $t => $pay) { $b .= $btn("total:$t", '<b>' . $t . '</b><small>' . $pay . ':1</small>'); }
    $b .= '</div><div class="sb-row faces">';
    for ($n = 1; $n <= 6; $n++) { $b .= $btn("double:$n", die_svg($n, 'mini') . die_svg($n, 'mini') . '<small>10:1</small>'); }
    for ($n = 1; $n <= 6; $n++) { $b .= $btn("triple:$n", die_svg($n, 'mini') . die_svg($n, 'mini') . die_svg($n, 'mini') . '<small>180:1</small>'); }
    $b .= '</div><div class="sb-row singles">';
    for ($n = 1; $n <= 6; $n++) { $b .= $btn("single:$n", die_svg($n, 'mid') . '<small>1:1 per die</small>'); }
    $b .= '</div></div>';
    ob_start(); ?>
<div class="sb-stage">
  <div class="dice-cup" data-dice>
    <?php foreach ($s['dice'] ?? [3, 5, 6] as $i => $d): ?><?= die_svg((int)$d, 'big' . ($last ? ' tumble' : '')) ?><?php endforeach; ?>
  </div>
  <?= $last ? result_line(implode(' · ', $s['dice']) . ' = ' . array_sum($s['dice']) . ($last['payout'] ? ' · returned ' . coins((int)$last['payout']) . ' GC' : ''), $last['payout'] > $last['bet']) : '<p class="result">Place your bets, shake the dice.</p>' ?>
</div>
<?= chipboard('sicbo', $g, $b, $spots, 'Shake') ?>
<?php return ob_get_clean();
}

/* ── crab derby ── */
function panel_crabs(array $p, array $g): string {
    $last = round_last((int)$p['id'], 'crabs'); $s = st($last);
    $order = $s['order'] ?? null;
    $spots = []; $track = '<div class="derby" data-derby' . ($order ? ' data-order="' . h(json_encode($order)) . '"' : '') . '>';
    foreach (CRABS as $i => [$name, $odds, $color]) {
        $place = $order ? array_search($i, $order, true) : null;
        $pos = $order ? 100 - $place * 9 : 0;
        $track .= '<div class="lane"><span class="lane-name">' . h($name) . '</span><div class="lane-track"><div class="runner" data-runner="' . $i . '" style="--x:' . $pos . '%">' . crab_svg($color)
            . ($place === 0 ? '<span class="rosette">1st</span>' : '') . '</div></div></div>';
    }
    $track .= '<div class="finish" aria-hidden="true"></div></div>';
    $board = '<div class="crab-board" data-board>';
    foreach (CRABS as $i => [$name, $odds, $color]) {
        $board .= '<button type="button" class="crab-spot' . ($order && $order[0] === $i ? ' win' : '') . '" data-bet="crab:' . $i . '" style="--c:' . h($color) . '">' . crab_svg($color) . '<b>' . h($name) . '</b><small>pays ' . $odds . '×</small></button>';
        $spots["crab:$i"] = "$name ({$odds}×)";
    }
    $board .= '</div>';
    ob_start(); ?>
<?= $track ?>
<?= $last ? result_line(CRABS[$order[0]][0] . ' wins!' . ($last['payout'] ? ' +' . coins((int)$last['payout']) . ' GC' : ''), $last['payout'] > 0) : '<p class="result">Back a crab and start the race.</p>' ?>
<?= chipboard('crabs', $g, $board, $spots, 'Race') ?>
<?php return ob_get_clean();
}

/* ── baccarat ── */
function panel_baccarat(array $p, array $g): string {
    $last = round_last((int)$p['id'], 'baccarat'); $s = st($last);
    $res = $s['result'] ?? null;
    $seq = function (string $side) use ($s) {
        $out = ''; $n = 0; $pi = 0; $bi = 0;
        foreach ($s['order'] ?? [] as $step => $who) {
            if ($who === 'P') { if ($side === 'P') { $out .= card_html($s['player'][$pi], false, $step); } $pi++; }
            else { if ($side === 'B') { $out .= card_html($s['banker'][$bi], false, $step); } $bi++; }
        }
        return $out;
    };
    $board = '<div class="bac-board" data-board>'
        . '<button type="button" class="bac player' . ($res === 'player' ? ' win' : '') . '" data-bet="player"><b>PLAYER</b><small>1 to 1</small></button>'
        . '<button type="button" class="bac tie' . ($res === 'tie' ? ' win' : '') . '" data-bet="tie"><b>TIE</b><small>8 to 1</small></button>'
        . '<button type="button" class="bac banker' . ($res === 'banker' ? ' win' : '') . '" data-bet="banker"><b>BANKER</b><small>0.95 to 1</small></button></div>';
    ob_start(); ?>
<div class="felt bac-felt slow-deal">
  <div class="bac-hands">
    <div class="hand"><h2>Player <span class="total after"><?= $last ? (int)$s['pv'] : '' ?></span></h2><div class="cards"><?= $last ? $seq('P') : '' ?></div></div>
    <div class="hand"><h2>Banker <span class="total after"><?= $last ? (int)$s['bv'] : '' ?></span></h2><div class="cards"><?= $last ? $seq('B') : '' ?></div></div>
  </div>
  <?= $last ? result_line(($res === 'tie' ? 'Tie' : ucfirst($res) . ' wins') . ' ' . $s['pv'] . '–' . $s['bv'] . ($last['payout'] ? ' · returned ' . coins((int)$last['payout']) . ' GC' : ''), $last['payout'] > $last['bet']) : '<p class="result">Bet Player, Banker, or Tie.</p>' ?>
</div>
<?= chipboard('baccarat', $g, $board, ['player' => 'Player', 'banker' => 'Banker', 'tie' => 'Tie'], 'Deal') ?>
<?php return ob_get_clean();
}

/* ── video poker ── */
function panel_videopoker(array $p, array $g): string {
    $act = round_active((int)$p['id'], 'videopoker');
    $r = $act ?? round_last((int)$p['id'], 'videopoker'); $s = st($r);
    $live = (bool)$act;
    $hitRow = !$live ? ($s['result'] ?? null) : null;
    $mult = $r ? (int)$r['bet'] : max((int)$g['min_bet'], 100);
    ob_start(); ?>
<div class="vp-machine">
  <table class="vp-pay"><tbody>
    <?php foreach (VP_PAY as $k => $x): ?><tr class="<?= $hitRow === $k ? 'hit' : '' ?>"><td><?= h(VP_NAMES[$k]) ?></td><td class="n"><?= $x ?>×</td><td class="n"><?= coins($x * $mult) ?></td></tr><?php endforeach; ?>
  </tbody></table>
  <?= play_form_open('videopoker') ?>
  <div class="vp-cards">
    <?php if ($r): foreach ($s['hand'] as $i => $c): ?>
      <label class="vp-card<?= !$live && in_array($i, $s['held'] ?? [], true) ? ' was-held' : '' ?>">
        <?= card_html($c, false, $i) ?>
        <?php if ($live): ?><input type="checkbox" name="hold[]" value="<?= $i ?>"><span class="hold-tag">HOLD</span><?php endif; ?>
      </label>
    <?php endforeach; else: for ($i = 0; $i < 5; $i++): ?><div class="vp-card"><?= card_html('', true, $i) ?></div><?php endfor; endif; ?>
  </div>
  <?php if ($live): ?>
    <p class="result"><?= ($h = vp_eval($s['hand'])) ? 'Dealt: ' . h(VP_NAMES[$h]) . '. Pick holds.' : 'Tap cards to hold, then draw.' ?></p>
    <div class="controls"><button class="btn gold xl" name="move" value="draw">Draw</button></div>
  <?php else: ?>
    <?= $r ? result_line(($s['result'] ? VP_NAMES[$s['result']] : 'No win') . ((int)$r['payout'] ? ' · +' . coins((int)$r['payout']) . ' GC' : ''), (int)$r['payout'] > 0) : '<p class="result">Place a bet and deal.</p>' ?>
    <div class="controls"><?= bet_box($g, (int)($r['bet'] ?? 100)) ?><button class="btn gold xl" name="move" value="deal">Deal</button></div>
  <?php endif; ?>
  </form>
</div>
<?php return ob_get_clean();
}

/* ── three card poker ── */
function panel_threecard(array $p, array $g): string {
    $act = round_active((int)$p['id'], 'threecard');
    $r = $act ?? round_last((int)$p['id'], 'threecard'); $s = st($r);
    $live = (bool)$act;
    ob_start(); ?>
<div class="felt tc-felt">
  <p class="felt-rule" aria-hidden="true">Dealer qualifies with Queen high</p>
  <div class="hand dealer"><h2>Dealer <?php if ($r && !$live): ?><span class="total"><?= h(TC_NAMES[$s['de']]) ?></span><?php endif; ?></h2>
    <div class="cards"><?php if ($r) { foreach ($s['dealer'] as $i => $c) { echo card_html($c, $live, $i + 3); } } ?></div></div>
  <?php if ($r && !$live): ?>
    <?= result_line(threecard_summary($r, $s), (int)$r['payout'] > (int)$r['bet']) ?>
  <?php else: ?><p class="result"><?= $live ? 'You have ' . h(strtolower(TC_NAMES[tc_eval($s['player'])[0]])) . '. Play or fold?' : 'Ante up to deal.' ?></p><?php endif; ?>
  <div class="hand player"><h2>You <?php if ($r): ?><span class="total"><?= h(TC_NAMES[tc_eval($s['player'])[0]]) ?></span><span class="bet-tag">Ante <?= coins((int)$s['ante']) ?><?= $s['pp'] ? ' · PP ' . coins((int)$s['pp']) : '' ?></span><?php endif; ?></h2>
    <div class="cards"><?php if ($r) { foreach ($s['player'] as $i => $c) { echo card_html($c, false, $i); } } ?></div></div>
  <?= play_form_open('threecard', 'controls') ?>
  <?php if ($live): ?>
    <button class="btn gold lg" name="move" value="play">Play (+<?= coins((int)$s['ante']) ?>)</button>
    <button class="btn ghost lg" name="move" value="fold">Fold</button>
  <?php else: ?>
    <?= bet_box($g, (int)($s['ante'] ?? 100), 'bet', 'Ante') ?>
    <label class="pp">Pair Plus <input type="number" name="pairplus" min="0" max="<?= (int)$g['max_bet'] ?>" step="1" value="<?= (int)($s['pp'] ?? 0) ?>" inputmode="numeric"></label>
    <button class="btn gold lg" name="move" value="deal">Deal</button>
  <?php endif; ?>
  </form>
</div>
<?php return ob_get_clean();
}
function threecard_summary(array $r, array $s): string {
    $m = match ($r['outcome']) {
        'fold' => 'Folded.', 'no_qualify' => 'Dealer didn\'t qualify. Ante paid.', 'win' => 'You beat the dealer!', 'push' => 'Push.', 'lose' => 'Dealer wins.', default => '',
    };
    if (!empty($s['notes'])) { $m .= ' ' . implode(' + ', $s['notes']) . '!'; }
    return $m . ((int)$r['payout'] ? ' Returned ' . coins((int)$r['payout']) . ' GC.' : '');
}

/* ── hi-lo ── */
function panel_hilo(array $p, array $g): string {
    $act = round_active((int)$p['id'], 'hilo');
    $r = $act ?? round_last((int)$p['id'], 'hilo'); $s = st($r);
    $live = (bool)$act;
    $cardCode = fn(array $c) => hilo_card($c) . $c['s'];
    ob_start(); ?>
<div class="hilo-stage">
  <div class="trail" aria-label="Previous cards">
    <?php foreach (array_slice($s['trail'] ?? [], -8) as $t): ?>
      <div class="trail-card <?= $t['call'] === 'skip' ? 'skipped' : (($t['ok'] ?? false) ? 'ok' : 'bad') ?>"><?= card_html($cardCode($t['card'])) ?><span><?= $t['call'] === 'skip' ? 'skip' : ($t['call'] === 'hi' ? '▲' : '▼') ?></span></div>
    <?php endforeach; ?>
  </div>
  <div class="hilo-main"><?= $r ? card_html($cardCode($s['card'])) : card_html('', true) ?></div>
  <?php if ($live): $o = hilo_odds($s['card']['r']); ?>
    <p class="result">Run: <b><?= number_format($s['mult'], 2) ?>×</b> · worth <?= coins((int)floor($r['bet'] * $s['mult'])) ?> GC</p>
    <?= play_form_open('hilo', 'controls') ?>
      <button class="btn gold lg" name="move" value="hi">▲ Higher or same <small><?= round($o['hi'] * 100) ?>% · <?= number_format(0.99 / $o['hi'], 2) ?>×</small></button>
      <button class="btn gold lg" name="move" value="lo">▼ Lower or same <small><?= round($o['lo'] * 100) ?>% · <?= number_format(0.99 / $o['lo'], 2) ?>×</small></button>
      <button class="btn ghost" name="move" value="skip" <?= ($s['skips'] ?? 0) >= 5 ? 'disabled' : '' ?>>Skip (<?= 5 - ($s['skips'] ?? 0) ?>)</button>
      <button class="btn coral lg" name="move" value="cashout" <?= $s['steps'] < 1 ? 'disabled' : '' ?>>Cash out</button>
    </form>
  <?php else: ?>
    <?= $r ? result_line($r['outcome'] === 'wrong' ? 'Wrong call after ' . $s['steps'] . ' right. The tide took it.' : 'Cashed ' . number_format($s['mult'], 2) . '× · +' . coins((int)$r['payout']) . ' GC', (int)$r['payout'] > 0) : '<p class="result">Start a run.</p>' ?>
    <?= play_form_open('hilo', 'controls') ?><?= bet_box($g, (int)($r['bet'] ?? 100)) ?><button class="btn gold xl" name="move" value="start">Start</button></form>
  <?php endif; ?>
</div>
<?php return ob_get_clean();
}

/* ── mines ── */
function panel_mines(array $p, array $g): string {
    $act = round_active((int)$p['id'], 'mines');
    $r = $act ?? round_last((int)$p['id'], 'mines'); $s = st($r);
    $live = (bool)$act;
    $open = $s['open'] ?? []; $n = (int)($s['n'] ?? 3);
    ob_start(); ?>
<div class="mines-stage">
  <?= play_form_open('mines', 'reef') ?>
  <input type="hidden" name="move" value="reveal">
  <?php for ($i = 0; $i < 25; $i++):
      $isOpen = in_array($i, $open, true);
      $isMine = !$live && $r && in_array($i, $s['mines'] ?? [], true);
      $cls = $isOpen ? 'pearl' : ($isMine ? 'urchin' . (($s['boom'] ?? -1) === $i ? ' boom' : ' ghost') : ''); ?>
    <button class="reef-tile <?= $cls ?>" name="tile" value="<?= $i ?>" <?= !$live || $isOpen ? 'disabled' : '' ?> aria-label="Tile <?= $i + 1 ?><?= $isOpen ? ', pearl' : ($isMine ? ', urchin' : '') ?>"><?php if ($isOpen): ?><svg viewBox="0 0 40 40"><circle cx="20" cy="20" r="12" fill="url(#pearl)"/></svg><?php elseif ($isMine): ?><svg viewBox="0 0 40 40"><g stroke="#2a1640" stroke-width="3" stroke-linecap="round"><path d="M20 3v34M3 20h34M8 8l24 24M32 8 8 32"/></g><circle cx="20" cy="20" r="10" fill="#4a2670"/></svg><?php endif; ?></button>
  <?php endfor; ?>
  <svg width="0" height="0" aria-hidden="true"><defs><radialGradient id="pearl" cx=".35" cy=".35"><stop offset="0" stop-color="#fff"/><stop offset=".6" stop-color="#f3e9ff"/><stop offset="1" stop-color="#c9b8e8"/></radialGradient></defs></svg>
  </form>
  <div class="mines-side">
  <?php if ($live): $k = count($open); ?>
    <p class="result">Pearls <?= $k ?> / <?= 25 - $n ?> · <b><?= number_format($k ? mines_mult($n, $k) : 1, 2) ?>×</b></p>
    <p class="muted">Next pearl: <?= number_format(mines_mult($n, $k + 1), 2) ?>×</p>
    <?= play_form_open('mines', 'controls') ?><button class="btn coral xl" name="move" value="cashout" <?= $k ? '' : 'disabled' ?>>Cash out <?= $k ? coins((int)floor($r['bet'] * mines_mult($n, $k))) : '' ?></button></form>
  <?php else: ?>
    <?= $r ? result_line($r['outcome'] === 'boom' ? 'Urchin! Round over.' : 'Cashed ' . number_format(mines_mult($n, count($open)), 2) . '× · +' . coins((int)$r['payout']) . ' GC', (int)$r['payout'] > 0) : '<p class="result">Pick your danger level.</p>' ?>
    <?= play_form_open('mines', 'controls stacked') ?>
      <label>Urchins <select name="mines"><?php foreach ([1, 2, 3, 5, 8, 10, 15, 20, 24] as $m): ?><option<?= $m === $n ? ' selected' : '' ?>><?= $m ?></option><?php endforeach; ?></select></label>
      <?= bet_box($g, (int)($r['bet'] ?? 100)) ?>
      <button class="btn gold xl" name="move" value="start">Dive in</button>
    </form>
  <?php endif; ?>
  </div>
</div>
<?php return ob_get_clean();
}

/* ── crash ── */
function panel_crash(array $p, array $g): string {
    $act = round_active((int)$p['id'], 'crash');
    if ($act) { $act = tx(fn() => crash_resolve($act)); if ($act['status'] !== 'active') { $act = null; } }
    $r = $act ?? round_last((int)$p['id'], 'crash'); $s = st($r);
    $live = (bool)$act;
    $hist = q("SELECT state FROM rounds WHERE player_id = ? AND game = 'crash' AND status = 'done' ORDER BY id DESC LIMIT 12", [$p['id']])->fetchAll();
    ob_start(); ?>
<div class="crash-stage" data-crash <?= $live ? 'data-live="1" data-elapsed="' . h(microtime(true) - $s['start']) . '" data-auto="' . h($s['auto']) . '" data-bet="' . (int)$r['bet'] . '" data-k="' . CRASH_K . '"' : '' ?>>
  <div class="crash-hist">
    <?php foreach ($hist as $h): $c = (json_decode($h['state'], true)['crash'] ?? 1); ?><span class="<?= $c >= 2 ? 'hi' : 'lo' ?>"><?= number_format($c, 2) ?>×</span><?php endforeach; ?>
  </div>
  <svg class="crash-graph" viewBox="0 0 600 300" preserveAspectRatio="none" aria-hidden="true">
    <defs><linearGradient id="waveg" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="#2bb3a3" stop-opacity=".55"/><stop offset="1" stop-color="#2bb3a3" stop-opacity="0"/></linearGradient></defs>
    <path class="wave-fill" d="M0,300 L0,300 Z" fill="url(#waveg)" data-wave-fill/>
    <path class="wave" d="M0,300" data-wave/>
  </svg>
  <div class="crash-mult <?= !$live && $r ? ($r['outcome'] === 'crashed' ? 'broke' : 'cashed') : '' ?>" data-mult>
    <?php if ($live): ?>1.00×<?php elseif ($r): ?><?= number_format($s['crash'], 2) ?>×<?php else: ?>1.00×<?php endif; ?>
  </div>
  <?php if ($r && !$live): ?><?= result_line($r['outcome'] === 'crashed' ? 'Wave broke at ' . number_format($s['crash'], 2) . '×' . (isset($s['cashed']) ? '' : '') : 'You cashed at ' . number_format($s['cashed'], 2) . '× · +' . coins((int)$r['payout']) . ' GC · it broke at ' . number_format($s['crash'], 2) . '×', (int)$r['payout'] > 0) ?>
  <?php else: ?><p class="result"><?= $live ? 'Riding the wave…' : 'Launch a wave.' ?></p><?php endif; ?>
</div>
<?= play_form_open('crash', 'controls') ?>
<?php if ($live): ?>
  <button class="btn coral xl" name="move" value="cashout" data-cashout>Cash out</button>
  <button class="btn ghost" name="move" value="peek">Check wave</button>
<?php else: ?>
  <?= bet_box($g, (int)($r['bet'] ?? 100)) ?>
  <label class="auto">Auto cash-out <input type="number" name="auto" min="1.01" max="1000" step="0.01" placeholder="off" value="<?= !empty($s['auto']) ? h($s['auto']) : '' ?>"></label>
  <button class="btn gold xl" name="move" value="launch">Launch</button>
<?php endif; ?>
</form>
<?php return ob_get_clean();
}

/* ── Slot Hall panel ── */
function vs_sym(string $slug, string $s): string {
    return '<svg viewBox="0 0 64 64" role="img" aria-label="' . h(VS_ART[$slug][$s]['name'] ?? $s) . '">' . (VS_ART[$slug][$s]['svg'] ?? '') . '</svg>';
}
function panel_videoslot(string $slug, array $p, array $g): string {
    $t = VSLOTS[$slug];
    $last = round_last((int)$p['id'], $slug); $s = st($last);
    $grid = $s['grid'] ?? null;
    if (!$grid) { $grid = [['H1', 'L1', 'L3'], ['L2', 'W', 'H2'], ['H3', 'S', 'L4'], ['L5', 'H1', 'L1'], ['H4', 'L2', 'S']]; }
    $art = [];
    foreach (VS_ART[$slug] as $k => $a) { $art[$k] = $a['svg']; }
    $names = array_map(fn($a) => $a['name'], VS_ART[$slug]);
    $cfg = ['slug' => $slug, 'art' => $art, 'names' => $names, 'pays' => $t['pays'], 'fs' => $t['fs'], 'mult' => $t['mult'], 'scat' => VS_SCATTER_PAY];
    $bet = (int)($last['bet'] ?? max((int)$g['min_bet'], 50));
    ob_start(); ?>
<div class="vs vs-<?= h($slug) ?>" data-vslot="<?= h($slug) ?>" data-cfg="<?= h(json_encode($cfg, JSON_UNESCAPED_UNICODE)) ?>">
  <canvas class="vs-fx" data-vs-fx aria-hidden="true"></canvas>
  <div class="vs-deco" aria-hidden="true"></div>
  <div class="vs-machine">
    <div class="vs-marquee">
      <span class="vs-title"><?= h($g['name']) ?></span>
      <span class="vs-badges"><b>243 WAYS</b><b><?= $t['fs'][3] ?>+ FREE SPINS ×<?= (int)$t['mult'] ?></b><b><?= h(strtoupper($t['bonus']['name'])) ?> BONUS</b></span>
      <button type="button" class="icon-btn vs-snd" data-vs-sound aria-pressed="true" aria-label="Sound on"><svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path d="M4 9h4l5-4v14l-5-4H4z" fill="currentColor"/><path d="M16 8.5a5 5 0 0 1 0 7M18.5 6a8.5 8.5 0 0 1 0 12" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" data-waves/></svg></button>
    </div>
    <div class="vs-jp" aria-label="Bonus jackpots at your current bet"><?php foreach (VS_JP as $jx => $jn): ?><span class="jp-<?= strtolower($jn) ?>"><?= strtoupper($jn) ?> <b data-jp="<?= $jx ?>"><?= coins($jx * $bet) ?></b></span><?php endforeach; ?></div>
    <div class="vs-bonus" data-vs-bonus hidden></div>
    <div class="vs-fsbar" data-vs-fsbar hidden><span>FREE SPINS</span><b data-fs-left>0</b><span>left · ×<?= (int)$t['mult'] ?> · won</span><b data-fs-won>0</b></div>
    <div class="vs-window">
      <div class="vs-reels" data-vs-reels role="img" aria-label="Slot reels">
        <?php for ($r = 0; $r < 5; $r++): ?>
        <div class="vs-reel" data-reel="<?= $r ?>"><div class="vs-strip">
          <?php foreach ($grid[$r] as $sy): ?><div class="vs-cell" data-s="<?= h($sy) ?>"><?= vs_sym($slug, $sy) ?></div><?php endforeach; ?>
        </div></div>
        <?php endfor; ?>
      </div>
      <div class="vs-banner" data-vs-banner aria-hidden="true"></div>
    </div>
    <div class="vs-winbar">
      <span class="vs-winlabel">WIN</span><b class="vs-winamt" data-vs-win><?= $last ? coins((int)$last['payout']) : 0 ?></b>
      <span class="vs-msg" data-vs-msg aria-live="polite"><?= $last ? h(($s['fs'] ?? null) ? 'Free spins paid ' . coins((int)$s['fs']['win']) . ' GC' : ((int)$last['payout'] ? 'Last spin won ' . coins((int)$last['payout']) . ' GC' : 'Good luck!')) : 'Match 3+ symbols on adjacent reels from the left.' ?></span>
    </div>
  </div>
  <form class="vs-controls" method="post" action="<?= h(play_url($slug)) ?>" data-vs-form>
    <?= csrf_field() ?>
    <?= bet_box($g, $bet, 'bet', 'Total bet') ?>
    <button class="btn gold xl vs-spin" data-vs-spin>Spin</button>
    <div class="vs-auto">
      <label>Autospin <select data-vs-auto-n><option value="10">10</option><option value="25" selected>25</option><option value="50">50</option><option value="100">100</option></select></label>
      <label class="check"><input type="checkbox" data-vs-stopfs checked> Stop on free spins &amp; bonus</label>
      <label class="check"><input type="checkbox" data-vs-turbo> Turbo</label>
      <button type="button" class="btn ghost" data-vs-auto>Start</button>
      <button type="button" class="btn ghost" data-vs-3d hidden>3D cabinet</button>
    </div>
  </form>
  <details class="vs-pay">
    <summary>Paytable &amp; rules</summary>
    <div class="vs-paygrid" data-vs-paygrid>
      <?php foreach (['W', 'S', ...VS_SYMS] as $sy): ?>
        <div class="vs-payrow" data-sym="<?= h($sy) ?>"><div class="vs-payicon"><?= vs_sym($slug, $sy) ?></div><div>
          <b><?= h($names[$sy]) ?></b>
          <?php if ($sy === 'W'): ?><small>Wild on reels 2–4. Stands in for everything except the scatter. A wild on each of reels 2, 3 and 4 starts the <?= h($t['bonus']['name']) ?> bonus.</small>
          <?php elseif ($sy === 'S'): ?><small>3 / 4 / 5 anywhere: <?= VS_SCATTER_PAY[3] ?>× / <?= VS_SCATTER_PAY[4] ?>× / <?= VS_SCATTER_PAY[5] ?>× bet and <?= $t['fs'][3] ?> / <?= $t['fs'][4] ?> / <?= $t['fs'][5] ?> free spins at ×<?= (int)$t['mult'] ?></small>
          <?php else: ?><small class="mono">5× <span data-pay="2"><?= $t['pays'][$sy][2] ?></span> · 4× <span data-pay="1"><?= $t['pays'][$sy][1] ?></span> · 3× <span data-pay="0"><?= $t['pays'][$sy][0] ?></span></small><?php endif; ?>
        </div></div>
      <?php endforeach; ?>
    </div>
    <p class="fine">Pays shown are × your total bet, per way. 243 ways: a symbol pays when it lands anywhere on reels 1, 2, 3 (and 4, 5) in a row, and the win multiplies by how many times it shows on each reel. Free spins play automatically, can't retrigger, and every free-spin win is multiplied. <?= $t['bonus']['type'] === 'pick'
    ? h($t['bonus']['name']) . ' bonus: pick 3 of 12 tiles. Each tile hides 2×–1,000× your bet: 2× (30%), 3× (25%), 5× (18%), 8× (12%), 10× (8%), 15× (4%), Mini 25× (2%), Minor 75× (0.7%), Major 250× (0.25%), Grand 1,000× (0.05%).'
    : h($t['bonus']['name']) . ' bonus: one spin of the wheel, 5×–1,000× your bet. The stops aren\'t equally likely: 5× (22%), 8× (20%), 10× (17%), 12× (14%), 15× (11%), 20× (7%), Mini 25× (5%), 40× (2.5%), Minor 75× (1%), Major 250× (0.4%), Grand 1,000× (0.1%).' ?>
    Wins cap at <?= coins(VS_MAX_WIN) ?>× bet per spin. Return to player ≈ 95%, bonus included.</p>
  </details>
</div>
<?php return ob_get_clean();
}

/* ── 3D game panels ── */
function g3d_stage(string $kind, string $extra = ''): string {
    return '<div class="g3d" data-g3d="' . h($kind) . '"' . $extra . '><canvas aria-hidden="true"></canvas>'
        . '<div class="g3d-loading" aria-hidden="true"><span></span>Loading 3D table…</div>'
        . '<noscript><p class="g3d-nojs">3D view needs JavaScript. The bets below still work.</p></noscript></div>';
}
function roulette_board(): string {
    $o = '<div class="board-scroll"><div class="board" data-board role="group" aria-label="Betting board"><button type="button" class="b-zero green" data-bet="straight:0">0</button>';
    for ($col = 0; $col < 12; $col++) { for ($row = 2; $row >= 0; $row--) { $n = $col * 3 + $row + 1;
        $o .= '<button type="button" class="num ' . (in_array($n, ROULETTE_RED, true) ? 'red' : 'black') . '" style="grid-column:' . ($col + 2) . ';grid-row:' . (3 - $row) . '" data-bet="straight:' . $n . '">' . $n . '</button>'; } }
    for ($c = 3; $c >= 1; $c--) { $o .= '<button type="button" class="out col" style="grid-column:14;grid-row:' . (4 - $c) . '" data-bet="column:' . $c . '" aria-label="Column ' . $c . '">2:1</button>'; }
    for ($d = 1; $d <= 3; $d++) { $o .= '<button type="button" class="out dozen" style="grid-column:' . (($d - 1) * 4 + 2) . ' / span 4;grid-row:4" data-bet="dozen:' . $d . '">' . ['1st', '2nd', '3rd'][$d - 1] . ' 12</button>'; }
    foreach ([['low', '1–18'], ['even', 'Even'], ['red', '◆'], ['black', '◆'], ['odd', 'Odd'], ['high', '19–36']] as $i => [$t, $l]) {
        $o .= '<button type="button" class="out even-money ' . $t . '" style="grid-column:' . ($i * 2 + 2) . ' / span 2;grid-row:5" data-bet="' . $t . ':0" aria-label="' . ucfirst($t) . '">' . $l . '</button>';
    }
    return $o . '</div></div>';
}
function panel_roulette3d(array $p, array $g): string {
    $recent = q("SELECT outcome FROM rounds WHERE player_id = ? AND game = 'roulette3d' AND status = 'done' ORDER BY id DESC LIMIT 14", [$p['id']])->fetchAll();
    $spots = ['red:0' => 'Red', 'black:0' => 'Black', 'odd:0' => 'Odd', 'even:0' => 'Even', 'low:0' => '1–18', 'high:0' => '19–36',
        'dozen:1' => '1st 12', 'dozen:2' => '2nd 12', 'dozen:3' => '3rd 12', 'column:1' => 'Column 1', 'column:2' => 'Column 2', 'column:3' => 'Column 3'];
    for ($n = 0; $n <= 36; $n++) { $spots["straight:$n"] = "Number $n"; }
    ob_start(); ?>
<div class="g3d-wrap">
  <?= g3d_stage('roulette') ?>
  <div class="g3d-bar">
    <p class="result" data-g3d-msg aria-live="polite">Chips on the board, then spin.</p>
    <ol class="history" data-g3d-hist aria-label="Recent numbers">
      <?php foreach ($recent as $r): $n = (int)$r['outcome']; $c = $n === 0 ? 'green' : (in_array($n, ROULETTE_RED, true) ? 'red' : 'black'); ?><li class="<?= $c ?>"><?= $n ?></li><?php endforeach; ?>
    </ol>
  </div>
</div>
<?= chipboard('roulette3d', $g, roulette_board(), $spots, 'Spin') ?>
<?php return ob_get_clean();
}

function panel_craps(array $p, array $g): string {
    $r = round_active((int)$p['id'], 'craps');
    $s = craps_state($r);
    $spot = fn(string $k, string $label, string $sub = '', string $cls = '', string $art = '') => '<button type="button" class="cr-spot ' . $cls . '" data-bet="' . h($k) . '">'
        . ($art !== '' ? '<i class="cr-art" aria-hidden="true">' . $art . '</i>' : '') . '<b>' . h($label) . '</b>' . ($sub !== '' ? '<small>' . h($sub) . '</small>' : '') . '</button>';
    $dice = fn(int $a, int $b) => die_svg($a) . die_svg($b);
    $chips = '';
    $first = true;
    foreach ([10, 25, 50, 100, 500, 1000] as $c) {
        if ($c < (int)$g['min_bet'] || $c > (int)$g['max_bet']) { continue; }
        $chips .= '<button type="button" class="chip c' . $c . '" role="radio" aria-checked="' . ($first ? 'true' : 'false') . '" data-chip="' . $c . '">' . ($c >= 1000 ? ($c / 1000) . 'K' : $c) . '</button>';
        $first = false;
    }
    $cols = '';
    foreach (CRAPS_NUMS as $n) {
        [$pa, $pb] = CRAPS_PLACE[$n]; [$ta, $tb] = CRAPS_TRUE[$n];
        $cols .= '<div class="cr-col' . ($s['point'] === $n ? ' pt' : '') . '" data-cr-num="' . $n . '" role="group" aria-label="Number ' . $n . '">'
            . $spot("lay$n", 'Lay', "$tb:$ta · 5% on win", 'mini lay')
            . '<div class="cr-num"><span class="cr-puck" aria-hidden="true">ON</span><b>' . ($n === 6 ? 'SIX' : ($n === 9 ? 'NINE' : $n)) . '</b><div class="cr-cp" data-cr-cp="' . $n . '"></div></div>'
            . $spot("place$n", 'Place', "$pa:$pb", 'mini place')
            . $spot("buy$n", 'Buy', "$ta:$tb · 5% on win", 'mini')
            . $spot("comeodds$n", 'Come odds', "$ta:$tb true", 'mini odds')
            . $spot("dcomeodds$n", 'DC odds', "$tb:$ta true", 'mini odds')
            . '</div>';
    }
    $hist = '';
    foreach (array_reverse($s['rolls']) as $d) { $t = $d[0] + $d[1]; $hist .= '<li class="' . ($t === 7 ? 'seven' : '') . '">' . $t . '</li>'; }
    $placeable = ['pass', 'dontpass', 'passodds', 'dpodds', 'come', 'dontcome', 'field', 'big6', 'big8', 'hard4', 'hard6', 'hard8', 'hard10',
        'any7', 'anycraps', 'ace2', 'ace3', 'yo', 'twelve', 'horn', 'ce'];
    foreach (CRAPS_NUMS as $n) { array_push($placeable, "place$n", "buy$n", "lay$n", "comeodds$n", "dcomeodds$n"); }
    ob_start(); ?>
<div class="craps" data-craps data-state="<?= h(json_encode(['point' => $s['point'], 'bets' => (object)$s['bets']])) ?>" data-max="<?= (int)$g['max_bet'] ?>" data-min="<?= (int)$g['min_bet'] ?>">
  <div class="g3d-wrap">
    <?= g3d_stage('craps') ?>
    <div class="g3d-bar">
      <p class="result" data-cr-msg aria-live="polite"><?= $s['point'] ? 'Point is ' . $s['point'] . '. Roll again.' : 'Come-out roll. Put chips on the line.' ?></p>
      <div class="cr-bar-r">
        <button type="button" class="btn ghost sm" data-cr-mode hidden>Bubble view</button>
        <div class="cr-point<?= $s['point'] ? ' on' : '' ?>" data-cr-point><?= $s['point'] ? 'POINT ' . $s['point'] : 'COME-OUT' ?></div>
      </div>
    </div>
    <ol class="history cr-hist" data-cr-hist aria-label="Last rolls"><?= $hist ?></ol>
  </div>
  <div class="cr-controls">
    <div class="chips" role="radiogroup" aria-label="Chip value" data-cr-chips><?= $chips ?></div>
    <p class="staked">Adding <strong data-cr-new>0</strong> GC · on the table <strong data-cr-working><?= coins(array_sum($s['bets'])) ?></strong> GC</p>
    <div class="rl-actions">
      <button type="button" class="btn gold lg" data-cr-roll>Roll the dice</button>
      <button type="button" class="btn ghost" data-cr-clear>Clear new chips</button>
      <button type="button" class="btn ghost" data-cr-td aria-pressed="false">Take bets down</button>
      <button type="button" class="btn coral" data-cr-td-go hidden>Return 0 GC</button>
    </div>
    <p class="cr-hint" data-cr-hint>Tap a spot to add your chip. Right-click or long-press to pull back chips you haven't rolled yet.</p>
    <ul class="cr-log" data-cr-log aria-live="polite"></ul>
  </div>
  <div class="cr-board" data-cr-board>
    <div class="cr-nums">
      <div class="cr-dcbar"><?= $spot('dontcome', "Don't come", 'bar 12 · 1:1', 'dark tall') ?></div>
      <?= $cols ?>
    </div>
    <div class="cr-row cr-come"><?= $spot('come', 'Come', '7 or 11 wins · 2, 3, 12 lose · else moves to the number', 'wide') ?></div>
    <div class="cr-row cr-field">
      <?= $spot('big6', 'Big 6', 'stays up · 1:1', 'big') ?>
      <?= $spot('field', 'Field', '3 · 4 · 9 · 10 · 11 pay 1:1 · 2 pays 2:1 · 12 pays 3:1', 'wide') ?>
      <?= $spot('big8', 'Big 8', 'stays up · 1:1', 'big') ?>
    </div>
    <div class="cr-row cr-line">
      <?= $spot('dontpass', "Don't pass bar", 'come-out · 12 pushes', 'dark') ?>
      <?= $spot('dpodds', 'Lay odds', 'behind don\'t pass · 6×', 'odds') ?>
      <?= $spot('pass', 'Pass line', 'come-out · 1:1', 'wide gold') ?>
      <?= $spot('passodds', 'Pass odds', 'true odds · 3-4-5×', 'odds') ?>
    </div>
    <div class="cr-props" role="group" aria-label="Proposition bets">
      <?= $spot('any7', 'Any seven', 'one roll · 4:1', 'red wide') ?>
      <?= $spot('hard6', 'Hard 6', '9:1', 'hard', $dice(3, 3)) ?>
      <?= $spot('hard10', 'Hard 10', '7:1', 'hard', $dice(5, 5)) ?>
      <?= $spot('hard8', 'Hard 8', '9:1', 'hard', $dice(4, 4)) ?>
      <?= $spot('hard4', 'Hard 4', '7:1', 'hard', $dice(2, 2)) ?>
      <?= $spot('ace3', 'Ace-deuce', '15:1', '', $dice(1, 2)) ?>
      <?= $spot('ace2', 'Aces', '30:1', '', $dice(1, 1)) ?>
      <?= $spot('twelve', 'Boxcars', '30:1', '', $dice(6, 6)) ?>
      <?= $spot('yo', 'Yo 11', '15:1', '', $dice(5, 6)) ?>
      <?= $spot('horn', 'Horn', '2 · 3 · 11 · 12 · ×4 chips', 'wide') ?>
      <?= $spot('ce', 'C & E', 'craps 3:1 · eleven 7:1', 'wide') ?>
      <?= $spot('anycraps', 'Any craps', 'one roll · 7:1', 'red wide') ?>
    </div>
  </div>
  <noscript>
    <form class="panel form" method="post" action="<?= h(play_url('craps')) ?>">
      <?= csrf_field() ?>
      <label>Add a bet (optional) <select name="bet_key"><option value="">none, just roll</option><?php foreach ($placeable as $k): ?><option value="<?= h($k) ?>"><?= h(craps_label($k)) ?></option><?php endforeach; ?></select></label>
      <label>Amount <input type="number" name="amount" min="<?= (int)$g['min_bet'] ?>" max="<?= (int)$g['max_bet'] ?>" value="<?= (int)$g['min_bet'] ?>"></label>
      <button class="btn gold">Roll</button>
    </form>
  </noscript>
</div>
<?php return ob_get_clean();
}

function panel_pusher(array $p, array $g): string {
    $last = round_last((int)$p['id'], 'pusher'); $s = st($last);
    ob_start(); ?>
<div class="pusher" data-pusher>
  <div class="g3d-wrap">
    <?= g3d_stage('pusher', ' title="Tap the machine to aim your drop"') ?>
    <div class="g3d-bar"><p class="result" data-pu-msg aria-live="polite"><?= $last ? h(($s['coins'] ?? 0) ? $s['coins'] . ' coins spilled last drop' : 'Nothing fell last drop') : 'Tap the machine to aim, then drop a coin.' ?></p>
      <p class="pu-tally">Session: <b data-pu-drops>0</b> drops · <b data-pu-won>0</b> GC won</p></div>
  </div>
  <form class="controls" method="post" action="<?= h(play_url('pusher')) ?>" data-pu-form>
    <?= csrf_field() ?>
    <?= bet_box($g, (int)($last['bet'] ?? 25), 'bet', 'Coin value') ?>
    <label class="slider pu-lane">Aim <input type="range" name="lane" min="0" max="100" value="<?= (int)($s['lane'] ?? 50) ?>" data-pu-lane></label>
    <button class="btn gold xl" data-pu-drop>Drop coin</button>
    <div class="vs-auto"><label>Auto <select data-pu-auto-n><option>10</option><option selected>25</option><option>50</option></select></label><button type="button" class="btn ghost" data-pu-auto>Start</button></div>
  </form>
</div>
<?php return ob_get_clean();
}

/* ═════════════════════════ GAME PAGES ═════════════════════════ */

function games_rail(string $current): string {
    $gs = q('SELECT slug, name FROM games WHERE enabled = 1 ORDER BY sort_order, id')->fetchAll();
    $o = '<nav class="rail reveal d4" aria-label="More games"><span class="eyebrow">More games</span><div class="rail-list">';
    foreach ($gs as $x) {
        if (!isset(GAME_REGISTRY[$x['slug']])) { continue; }
        $o .= '<a href="' . h(url($x['slug'])) . '"' . ($x['slug'] === $current ? ' aria-current="page"' : '') . '>' . game_icon($x['slug']) . '<span>' . h($x['name']) . '</span></a>';
    }
    return $o . '</div></nav>';
}

function game_icon(string $slug): string {
    return match ($slug) {
        'slots' => sym('seven'), 'scratch' => sym('sun'), 'keno' => sym('shell'), 'roulette' => mini_wheel(),
        'baccarat' => '<span class="ico-card">B</span>', 'sicbo' => die_svg(5), 'bigwheel' => mini_wheel(), 'crabs' => crab_svg('#ff6f59'),
        'blackjack' => '<span class="ico-card">A♠</span>', 'videopoker' => '<span class="ico-card red">K♥</span>', 'threecard' => '<span class="ico-card">3</span>',
        'hilo' => '<span class="ico-card">▲▼</span>', 'crash' => '<svg viewBox="0 0 40 40"><path d="M3 34C14 33 24 26 36 6" stroke="#2bb3a3" stroke-width="4" fill="none" stroke-linecap="round"/><circle cx="36" cy="6" r="4" fill="#ff6f59"/></svg>',
        'plinko' => '<svg viewBox="0 0 40 40"><g fill="#e8b64c"><circle cx="20" cy="8" r="2.5"/><circle cx="14" cy="16" r="2.5"/><circle cx="26" cy="16" r="2.5"/><circle cx="8" cy="24" r="2.5"/><circle cx="20" cy="24" r="2.5"/><circle cx="32" cy="24" r="2.5"/></g><circle cx="17" cy="33" r="4.5" fill="#fff"/></svg>',
        'mines' => '<svg viewBox="0 0 40 40"><circle cx="20" cy="20" r="11" fill="#f3e9ff" stroke="#c9b8e8" stroke-width="2"/><circle cx="16" cy="16" r="3" fill="#fff"/></svg>',
        'dice' => die_svg(6), 'craps' => die_svg(6) , 'roulette3d' => mini_wheel(),
        'poker' => '<span class="ico-card">A♠</span><span class="ico-card red">A♥</span>',
        'pusher' => '<svg viewBox="0 0 40 40"><g fill="#e8b64c" stroke="#b07d12"><ellipse cx="14" cy="28" rx="9" ry="4"/><ellipse cx="24" cy="24" rx="9" ry="4"/><ellipse cx="18" cy="18" rx="9" ry="4"/></g></svg>',
        default => isset(VS_ART[$slug]) ? '<svg viewBox="0 0 64 64">' . VS_ART[$slug]['W']['svg'] . '</svg>' : '',
    };
}

function page_game(string $slug): void {
    $g = game_header($slug);
    $p = current_player();
    [$name, $cat, $blurb] = GAME_REGISTRY[$slug];
    ob_start(); ?>
<section class="table-wrap g-page g-<?= h($slug) ?><?= isset(VSLOTS[$slug]) ? ' g-vslot' : '' ?><?= (GAME_REGISTRY[$slug][1] ?? '') === 'worlds' ? ' g-3d' : '' ?><?= scene_open($slug) ?>">
  <header class="table-head reveal d1">
    <p class="eyebrow"><a href="<?= h(url()) ?>#cat-<?= h($cat) ?>"><?= h(GAME_CATEGORIES[$cat][0]) ?></a></p>
    <h1 class="display lg"><?= h($g['name']) ?></h1>
    <p class="muted"><?= h($g['blurb']) ?> <span class="limits-inline"><?= coins((int)$g['min_bet']) ?>–<?= coins((int)$g['max_bet']) ?> GC</span></p>
  </header>
  <div class="game-stage reveal d2" data-panel="<?= h($slug) ?>">
    <?php if ($p): ?><?= game_panel($slug) ?>
    <?php else: ?><div class="gate"><div class="gate-art"><?= game_icon($slug) ?></div><p class="lead">Free account, <?= coins(isetting('starting_coins', 10000)) ?> Gold Coins, no card needed.</p><a class="btn gold lg" href="<?= h(url('register')) ?>">Sign up free to play</a> <a class="btn ghost lg" href="<?= h(url('login')) ?>">Log in</a></div><?php endif; ?>
  </div>
  <aside class="panel reveal d3 house-rules">
    <h2 class="display md">How to play</h2>
    <ul class="ticks"><?php foreach (GAME_RULES[$slug] ?? (isset(VSLOTS[$slug]) ? [
        '5 reels, 3 rows, 243 ways: symbols pay left to right on adjacent reels, anywhere in each column. More copies on a reel = more ways.',
        'The wild shows up on reels 2, 3 and 4 and stands in for every symbol except the bonus.',
        '3, 4 or 5 bonus symbols anywhere pay ' . VS_SCATTER_PAY[3] . '×, ' . VS_SCATTER_PAY[4] . '× or ' . VS_SCATTER_PAY[5] . '× your bet and award ' . implode(' / ', VSLOTS[$slug]['fs']) . ' free spins where every win is ×' . VSLOTS[$slug]['mult'] . '.',
        'Watch for the slow-down: once two bonus symbols land, the remaining reels tease.',
        'Return to player ≈ 95%, checked with exact math and a million-plus simulated spins.',
    ] : []) as $line): ?><li><?= h($line) ?></li><?php endforeach; ?></ul>
  </aside>
</section>
<?= games_rail($slug) ?>
<?php layout($g['name'], ob_get_clean());
}

/* ═════════════════════════ THE FLOOR + POKER PAGES ═════════════════════════ */

/** Lobby card art for the floor: a little isometric casino. */
function floor_art(): string {
    return '<svg viewBox="0 0 200 140" class="art-wide" aria-hidden="true"><defs><linearGradient id="fa-g" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="#ffd98a"/><stop offset="1" stop-color="#b07d12"/></linearGradient></defs>'
        . '<path d="M10 90 L100 40 L190 90 L100 140 Z" fill="#1d1a2b" stroke="#e8b64c" stroke-width="1.5"/>'
        . '<path d="M40 88 L100 56 L160 88 L100 120 Z" fill="#3b1f1a" opacity=".9"/>'
        . '<g fill="url(#fa-g)"><rect x="56" y="62" width="10" height="16" rx="1"/><rect x="70" y="56" width="10" height="16" rx="1"/><rect x="84" y="50" width="10" height="16" rx="1"/></g>'
        . '<ellipse cx="128" cy="92" rx="22" ry="11" fill="#0e4a43" stroke="#ffd98a" stroke-width="1.5"/>'
        . '<ellipse cx="84" cy="104" rx="16" ry="8" fill="#5a1d1d" stroke="#ffd98a" stroke-width="1.5"/>'
        . '<circle cx="128" cy="92" r="3" fill="#ffd98a"/><circle cx="84" cy="104" r="2.5" fill="#fff"/>'
        . '<g fill="#ffd98a"><circle cx="150" cy="60" r="2"/><circle cx="60" cy="40" r="1.6"/><circle cx="100" cy="28" r="2.2"/></g></svg>';
}

/** What the floor and poker modules need from the server. Rendered as JSON in the page. */
function rt_page_config(): array {
    $p = current_player();
    $games = [];
    foreach (q('SELECT slug, name, min_bet, max_bet FROM games WHERE enabled = 1 ORDER BY sort_order, id')->fetchAll() as $g) {
        if (!isset(GAME_REGISTRY[$g['slug']])) { continue; }
        $games[$g['slug']] = ['name' => $g['name'], 'cat' => GAME_REGISTRY[$g['slug']][1], 'min' => (int)$g['min_bet'], 'max' => (int)$g['max_bet']];
    }
    $tables = q('SELECT id, name, seats, small_blind AS sb, big_blind AS bb, min_buyin AS min_buy, max_buyin AS max_buy, bots FROM poker_tables WHERE enabled = 1 ORDER BY sort_order, id')->fetchAll();
    foreach ($tables as &$t) { foreach ($t as $k => $v) { if ($k !== 'name') { $t[$k] = (int)$v; } } } unset($t);
    return [
        'ws' => rt_ws_url(), 'ticket' => url('rt_ticket'),
        'me' => $p ? ['uid' => 'p' . (int)$p['id'], 'name' => $p['username'], 'balance' => (int)$p['balance'], 'brk' => on_break($p) !== null] : null,
        'games' => $games, 'tables' => $tables,
        'glb' => is_file(DATA_DIR . '/floor.glb') ? '?action=asset&f=glb&v=' . substr(md5((string)filemtime(DATA_DIR . '/floor.glb')), 0, 8) : null,
        'site' => setting('site_name', 'Gold Tide'), 'act_secs' => isetting('poker_action_seconds', 20),
        'register' => url('register'), 'login' => url('login'), 'lobby' => url(),
    ];
}

// [[REGION floor-page]]
function page_floor(): void {
    if (!isetting('floor_enabled', 1)) { error_page(404, 'The floor is closed', 'The 3D casino floor is turned off right now.'); }
    $cfg = rt_page_config();
    ob_start(); ?>
<section class="floor-shell" data-floor>
  <script type="application/json" id="floor-cfg"><?= json_encode($cfg, JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_SLASHES) ?></script>
  <div class="floor-css3d" aria-hidden="true"></div>
  <canvas class="floor-gl" aria-label="The casino floor"></canvas>
  <div class="floor-hud" hidden></div>
  <div class="floor-loading"><span></span>Opening the doors…</div>
  <noscript><p class="panel">The floor needs JavaScript and WebGL. Every game still plays from the <a href="<?= h(url()) ?>">lobby</a>.</p></noscript>
</section>
<script type="module" nonce="<?= h(csp_nonce()) ?>" src="?action=asset&amp;f=floor&amp;v=<?= h(floor_version()) ?>"></script>
<?php layout('The Floor', ob_get_clean());
}
// [[/REGION floor-page]]

// [[REGION poker-page]]
function page_poker(): void {
    $g = game_header('poker');
    $p = current_player();
    $cfg = rt_page_config();
    $tid = (int)($_GET['t'] ?? 0);
    ob_start(); ?>
<section class="table-wrap g-page g-poker">
  <header class="table-head reveal d1">
    <p class="eyebrow"><a href="<?= h(url()) ?>#cat-cards"><?= h(GAME_CATEGORIES['cards'][0]) ?></a></p>
    <h1 class="display lg"><?= h($g['name']) ?></h1>
    <p class="muted"><?= h($g['blurb']) ?></p>
  </header>
  <div class="game-stage reveal d2" data-panel="poker">
    <?php if ($p): ?>
    <div class="poker-room" data-poker-room data-table="<?= $tid ?>">
      <script type="application/json" id="poker-cfg"><?= json_encode($cfg, JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_SLASHES) ?></script>
      <div class="poker-loading"><span></span>Connecting to the card room…</div>
      <noscript><p class="panel">Live poker needs JavaScript.</p></noscript>
    </div>
    <script type="module" nonce="<?= h(csp_nonce()) ?>" src="?action=asset&amp;f=poker&amp;v=<?= h(poker_version()) ?>"></script>
    <?php else: ?><div class="gate"><div class="gate-art"><?= game_icon('poker') ?></div><p class="lead">Free account, <?= coins(isetting('starting_coins', 10000)) ?> Gold Coins, no card needed.</p><a class="btn gold lg" href="<?= h(url('register')) ?>">Sign up free to play</a> <a class="btn ghost lg" href="<?= h(url('login')) ?>">Log in</a></div><?php endif; ?>
  </div>
  <aside class="panel reveal d3 house-rules">
    <h2 class="display md">How to play</h2>
    <ul class="ticks"><?php foreach (GAME_RULES['poker'] as $line): ?><li><?= h($line) ?></li><?php endforeach; ?></ul>
  </aside>
</section>
<?= games_rail('poker') ?>
<?php layout($g['name'], ob_get_clean());
}

/** ?action=poker_hand&id=N: a hand history with the deck-commitment check. */
function page_poker_hand(): void {
    $id = (int)($_GET['id'] ?? 0);
    $hand = $id ? row('SELECT h.*, t.name AS table_name FROM poker_hands h JOIN poker_tables t ON t.id = h.table_id WHERE h.id = ?', [$id]) : null;
    if (!$hand) { error_page(404, 'No such hand', 'That hand history isn\'t here.'); }
    $rec = json_decode((string)$hand['record'], true) ?: [];
    $deck = $rec['deck'] ?? [];
    $check = $deck && $hand['deck_salt'] !== '' ? hash('sha256', implode(' ', $deck) . '|' . $hand['deck_salt']) === $hand['deck_hash'] : null;
    ob_start(); ?>
<section class="panel wide reveal d1 poker-history">
  <p class="eyebrow"><a href="<?= h(url('poker', ['t' => (int)$hand['table_id']])) ?>"><?= h($hand['table_name']) ?></a></p>
  <h1 class="display lg">Hand #<?= (int)$hand['hand_no'] ?></h1>
  <p class="muted">Started <?= h($hand['started_at']) ?> UTC<?= $hand['ended_at'] ? ', ended ' . h($hand['ended_at']) . ' UTC' : '' ?>. Pot <?= coins((int)$hand['pot']) ?> GC.</p>
  <div class="ph-check <?= $check === null ? 'pending' : ($check ? 'ok' : 'bad') ?>">
    <strong><?= $check === null ? 'Deck not revealed yet' : ($check ? 'Deck commitment verified' : 'Deck commitment FAILED') ?></strong>
    <p class="fine">deck_hash = SHA-256(deck in deal order + "|" + salt)</p>
    <p class="fine mono">hash: <?= h($hand['deck_hash']) ?></p>
    <?php if ($hand['deck_salt'] !== ''): ?><p class="fine mono">salt: <?= h($hand['deck_salt']) ?></p><?php endif; ?>
    <?php if ($deck): ?><p class="fine mono">deck: <?= h(implode(' ', $deck)) ?></p><?php endif; ?>
  </div>
  <script type="application/json" id="hand-record"><?= json_encode($rec, JSON_HEX_TAG | JSON_HEX_AMP) ?></script>
  <div class="ph-body" data-poker-hand></div>
  <details><summary>Raw record</summary><pre class="mono"><?= h(json_encode($rec, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) ?></pre></details>
</section>
<script type="module" nonce="<?= h(csp_nonce()) ?>" src="?action=asset&amp;f=poker&amp;v=<?= h(poker_version()) ?>"></script>
<?php layout('Hand #' . (int)$hand['hand_no'], ob_get_clean());
}
// [[/REGION poker-page]]

/* ═════════════════════════ ADMIN PAGES ═════════════════════════ */

function page_admin_login(): void {
    if (current_admin()) { redirect(url('admin')); }
    $pwFile = is_file(PW_FILE);
    ob_start(); ?>
<section class="panel narrow auth reveal d1">
  <p class="eyebrow">Staff only</p>
  <h1 class="display lg">Back office</h1>
  <?php if ($pwFile): ?><p class="note">First time? Your login is in <code>admin_password.txt</code> next to <code>index.php</code>. Change the password after you log in and the file wipes itself.</p><?php endif; ?>
  <form method="post" action="<?= h(url('admin_login')) ?>" class="form">
    <?= csrf_field() ?>
    <label>Username <input name="username" autocomplete="username" required autofocus></label>
    <label>Password <input type="password" name="password" autocomplete="current-password" required></label>
    <button class="btn gold lg wide">Log in</button>
  </form>
</section>
<?php layout('Admin login', ob_get_clean(), 'admin');
}

function page_admin_dash(array $admin): void {
    $counts = [];
    foreach (entities() as $t => $e) { $counts[$t] = (int)val("SELECT COUNT(*) FROM $t"); }
    $stats = [
        'Players' => coins($counts['players']),
        'Active 24h' => coins((int)val("SELECT COUNT(*) FROM players WHERE last_login_at >= datetime('now','-1 day')")),
        'New today' => coins((int)val("SELECT COUNT(*) FROM players WHERE date(created_at) = date('now')")),
        'Coins in play' => coins((int)val('SELECT COALESCE(SUM(balance),0) FROM players')),
        'Wagered today' => coins(-(int)val("SELECT COALESCE(SUM(amount),0) FROM ledger WHERE kind='wager' AND date(created_at) = date('now')")),
        'House hold today' => coins(-(int)val("SELECT COALESCE(SUM(amount),0) FROM ledger WHERE kind IN ('wager','payout') AND date(created_at) = date('now')")),
    ];
    $byGame = q("SELECT game, -SUM(CASE WHEN kind='wager' THEN amount ELSE 0 END) AS wagered, SUM(CASE WHEN kind='payout' THEN amount ELSE 0 END) AS paid
                 FROM ledger WHERE game IS NOT NULL AND kind IN ('wager','payout') AND created_at >= datetime('now','-7 day') GROUP BY game")->fetchAll();
    $audit = q('SELECT * FROM audit_log ORDER BY id DESC LIMIT 12')->fetchAll();
    $ledger = q('SELECT l.*, p.username FROM ledger l JOIN players p ON p.id = l.player_id ORDER BY l.id DESC LIMIT 12')->fetchAll();
    ob_start(); ?>
<header class="table-head reveal d1">
  <p class="eyebrow">Signed in as <?= h($admin['username']) ?></p>
  <h1 class="display lg">Dashboard</h1>
</header>
<?php if (is_file(PW_FILE)): ?>
  <p class="note warn reveal d1"><strong>admin_password.txt still exists.</strong> Save your password somewhere safe, then <a href="<?= h(url('admin_password')) ?>">change it</a> to wipe the file.</p>
<?php endif; ?>
<div class="tiles reveal d2">
  <?php foreach ($stats as $k => $v): ?><div class="tile"><span><?= h($k) ?></span><strong><?= $v ?></strong></div><?php endforeach; ?>
</div>
<div class="dash-grid">
  <section class="panel reveal d3">
    <h2 class="display md">Tables</h2>
    <ul class="table-links">
      <?php foreach (entities() as $t => $e): ?>
        <li><a href="<?= h(url('admin_list', ['t' => $t])) ?>"><span><?= h($e['label']) ?></span><b><?= coins($counts[$t]) ?></b></a></li>
      <?php endforeach; ?>
    </ul>
  </section>
  <section class="panel reveal d3">
    <h2 class="display md">Last 7 days by game</h2>
    <div class="scroll-x"><table class="data compact"><thead><tr><th>Game</th><th class="n">Wagered</th><th class="n">Paid out</th><th class="n">RTP</th></tr></thead><tbody>
    <?php foreach ($byGame as $b): ?>
      <tr><td><?= h($b['game']) ?></td><td class="n"><?= coins((int)$b['wagered']) ?></td><td class="n"><?= coins((int)$b['paid']) ?></td>
      <td class="n"><?= (int)$b['wagered'] ? number_format((int)$b['paid'] / (int)$b['wagered'] * 100, 1) . '%' : '–' ?></td></tr>
    <?php endforeach; ?>
    <?php if (!$byGame): ?><tr><td colspan="4" class="muted">No play yet.</td></tr><?php endif; ?>
    </tbody></table></div>
  </section>
  <section class="panel reveal d4">
    <h2 class="display md">Admin activity</h2>
    <ul class="feed">
      <?php foreach ($audit as $a): ?>
        <li><time><?= h(substr($a['created_at'], 5, 11)) ?></time> <b><?= h($a['actor']) ?></b> <?= h(str_replace('_', ' ', $a['action'])) ?><?= $a['tbl'] ? ' <a href="' . h(url('admin_view', ['t' => $a['tbl'], 'id' => $a['row_id']])) . '">' . h($a['tbl']) . ($a['row_id'] ? ' #' . (int)$a['row_id'] : '') . '</a>' : '' ?></li>
      <?php endforeach; ?>
      <?php if (!$audit): ?><li class="muted">Nothing yet.</li><?php endif; ?>
    </ul>
    <a class="more" href="<?= h(url('admin_list', ['t' => 'audit_log'])) ?>">Full audit log &rarr;</a>
  </section>
  <section class="panel reveal d4">
    <h2 class="display md">Coin flow</h2>
    <ul class="feed">
      <?php foreach ($ledger as $l): ?>
        <li><time><?= h(substr($l['created_at'], 5, 11)) ?></time> <b><?= h($l['username']) ?></b> <?= h($l['kind']) ?><?= $l['game'] ? ' · ' . h($l['game']) : '' ?> <span class="<?= (int)$l['amount'] >= 0 ? 'pos' : 'neg' ?>"><?= ((int)$l['amount'] >= 0 ? '+' : '') . coins((int)$l['amount']) ?></span></li>
      <?php endforeach; ?>
      <?php if (!$ledger): ?><li class="muted">No coins have moved yet.</li><?php endif; ?>
    </ul>
    <a class="more" href="<?= h(url('admin_list', ['t' => 'ledger'])) ?>">Full ledger &rarr;</a>
  </section>
</div>
<?php layout('Dashboard', ob_get_clean(), 'admin');
}

function fmt_cell(array $e, string $col, mixed $v): string {
    $f = $e['fields'][$col] ?? null;
    if ($v === null || $v === '') { return '<span class="muted">–</span>'; }
    if ($f && $f['type'] === 'bool') { return (int)$v ? '<span class="pill ok">yes</span>' : '<span class="pill">no</span>'; }
    if ($f && $f['type'] === 'enum') { return '<span class="pill s-' . h($v) . '">' . h($v) . '</span>'; }
    if ($f && $f['type'] === 'fk') {
        return '<a href="' . h(url('admin_view', ['t' => $f['ref'], 'id' => $v])) . '">' . h(fk_label($f['ref'], $f['label_col'], (int)$v)) . '</a>';
    }
    if (in_array($col, ['amount'], true)) { return '<span class="' . ((int)$v >= 0 ? 'pos' : 'neg') . '">' . ((int)$v >= 0 ? '+' : '') . coins((int)$v) . '</span>'; }
    if (is_int($v) || (is_string($v) && preg_match('/^-?\d+$/', $v) && $col !== 'id' && $col !== 'row_id' && !str_ends_with($col, '_key'))) { return coins((int)$v); }
    $s = (string)$v;
    return mb_strlen($s) > 60 ? '<span title="' . h($s) . '">' . h(mb_substr($s, 0, 60)) . '…</span>' : h($s);
}

function page_admin_list(array $admin): void {
    $t = (string)($_GET['t'] ?? '');
    $e = entity($t);
    [$where, $args] = list_where($e);
    $sort = in_array($_GET['sort'] ?? '', $e['list'], true) ? $_GET['sort'] : ($e['sort'] ?? 'id');
    $dir = ($_GET['dir'] ?? ($e['dir'] ?? 'desc')) === 'asc' ? 'ASC' : 'DESC';
    $per = per_page();
    $total = (int)val("SELECT COUNT(*) FROM $t $where", $args);
    $pages = max(1, (int)ceil($total / $per));
    $page = min($pages, max(1, (int)($_GET['page'] ?? 1)));
    $rows = q("SELECT * FROM $t $where ORDER BY $sort $dir, id DESC LIMIT $per OFFSET " . (($page - 1) * $per), $args)->fetchAll();
    $fkNames = array_keys(array_filter($e['fields'], fn($f) => $f['type'] === 'fk'));
    $keep = array_filter(array_intersect_key($_GET, array_flip(['t', 'q', 'from', 'to', 'per', 'sort', 'dir', ...$fkNames, ...array_map(fn($f) => "f_$f", $e['filters'])])), fn($v) => is_string($v) && $v !== '');
    $bulkSets = [];
    foreach ($e['fields'] as $n => $f) {
        if (!can($e, 'u') || (in_array($t, ['bj_hands', 'rounds'], true) && $n === 'status')) { continue; }
        if ($f['type'] === 'enum') { foreach ($f['options'] as $o) { $bulkSets["set:$n:$o"] = "Set $n → $o"; } }
        if ($f['type'] === 'bool') { $bulkSets["set:$n:1"] = "Set $n → yes"; $bulkSets["set:$n:0"] = "Set $n → no"; }
    }
    ob_start(); ?>
<header class="table-head row reveal d1">
  <div>
    <p class="eyebrow"><a href="<?= h(url('admin')) ?>">Dashboard</a> / table</p>
    <h1 class="display lg"><?= h($e['label']) ?> <small><?= coins($total) ?></small></h1>
    <?php if (!empty($e['hint'])): ?><p class="muted"><?= h($e['hint']) ?></p><?php endif; ?>
  </div>
  <div class="head-actions">
    <a class="btn ghost" href="<?= h(url('admin_export', array_diff_key($keep, ['per' => 1, 'sort' => 1, 'dir' => 1]))) ?>">Export CSV</a>
    <?php if (can($e, 'c')): ?><a class="btn gold" href="<?= h(url('admin_edit', ['t' => $t])) ?>">+ New</a><?php endif; ?>
  </div>
</header>

<form class="filters panel reveal d2" method="get" data-live-filter>
  <input type="hidden" name="action" value="admin_list"><input type="hidden" name="t" value="<?= h($t) ?>">
  <?php foreach ($fkNames as $fk): if (ctype_digit((string)($_GET[$fk] ?? ''))): ?>
    <span class="pill">only <?= h(str_replace('_id', '', $fk)) ?>: <?= h(fk_label($e['fields'][$fk]['ref'], $e['fields'][$fk]['label_col'], (int)$_GET[$fk])) ?> <a href="<?= h(url('admin_list', array_diff_key($keep, [$fk => 1]))) ?>" aria-label="Remove filter">×</a></span>
    <input type="hidden" name="<?= h($fk) ?>" value="<?= (int)$_GET[$fk] ?>">
  <?php endif; endforeach; ?>
  <?php if ($e['search']): ?><label class="grow">Search <input type="search" name="q" value="<?= h($_GET['q'] ?? '') ?>" placeholder="<?= h(implode(', ', $e['search'])) ?> or id" data-live></label><?php endif; ?>
  <?php foreach ($e['filters'] as $fName): $fd = $e['fields'][$fName]; $opts = $fd['type'] === 'bool' ? ['1' => 'yes', '0' => 'no'] : array_combine($fd['options'], $fd['options']); ?>
    <label><?= h(ucwords(str_replace('_', ' ', $fName))) ?> <select name="f_<?= h($fName) ?>" data-live><option value="">All</option>
      <?php foreach ($opts as $v => $l): ?><option value="<?= h($v) ?>"<?= ($_GET['f_' . $fName] ?? '') === (string)$v ? ' selected' : '' ?>><?= h($l) ?></option><?php endforeach; ?>
    </select></label>
  <?php endforeach; ?>
  <label>From <input type="date" name="from" value="<?= h($_GET['from'] ?? '') ?>" data-live></label>
  <label>To <input type="date" name="to" value="<?= h($_GET['to'] ?? '') ?>" data-live></label>
  <label>Rows <select name="per" data-live><?php foreach ([25, 50, 100] as $n): ?><option<?= $n === $per ? ' selected' : '' ?>><?= $n ?></option><?php endforeach; ?></select></label>
  <button class="btn ghost">Apply</button>
</form>

<div id="list-region" class="reveal d3">
<?php if ($bulkSets || can($e, 'd')): ?>
<form id="bulkform" class="bulkbar" method="post" action="<?= h(url('admin_bulk')) ?>" data-bulk hidden>
  <?= csrf_field() ?><input type="hidden" name="t" value="<?= h($t) ?>">
  <span data-bulk-count>0 selected</span>
  <select name="op" required><option value="">Bulk action…</option>
    <?php foreach ($bulkSets as $k => $l): ?><option value="<?= h($k) ?>"><?= h($l) ?></option><?php endforeach; ?>
    <?php if (can($e, 'd')): ?><option value="delete">Delete selected</option><?php endif; ?>
  </select>
  <input name="confirm" placeholder="type DELETE for deletes" autocomplete="off" aria-label="Type DELETE to confirm bulk delete">
  <button class="btn coral sm">Apply</button>
</form>
<?php endif; ?>
<div class="scroll-x panel flush">
<table class="data">
  <thead><tr>
    <?php if ($bulkSets || can($e, 'd')): ?><th class="cb"><input type="checkbox" data-check-all aria-label="Select all on this page"></th><?php endif; ?>
    <?php foreach ($e['list'] as $c):
        $nd = $sort === $c && $dir === 'ASC' ? 'desc' : 'asc';
        $arrow = $sort === $c ? ($dir === 'ASC' ? ' ↑' : ' ↓') : ''; ?>
      <th<?= $sort === $c ? ' aria-sort="' . ($dir === 'ASC' ? 'ascending' : 'descending') . '"' : '' ?>><a href="<?= h(url('admin_list', ['sort' => $c, 'dir' => $nd, 'page' => null] + $keep)) ?>"><?= h(str_replace('_', ' ', $c)) . $arrow ?></a></th>
    <?php endforeach; ?>
    <th class="actions"><span class="sr">Actions</span></th>
  </tr></thead>
  <tbody>
  <?php foreach ($rows as $r): ?>
    <tr>
      <?php if ($bulkSets || can($e, 'd')): ?><td class="cb"><input type="checkbox" name="ids[]" value="<?= (int)$r['id'] ?>" form="bulkform" aria-label="Select #<?= (int)$r['id'] ?>"></td><?php endif; ?>
      <?php foreach ($e['list'] as $c): ?><td<?= is_numeric($r[$c]) && $c !== 'id' ? ' class="n"' : '' ?>><?= $c === 'id' ? '<a href="' . h(url('admin_view', ['t' => $t, 'id' => $r['id']])) . '">#' . (int)$r['id'] . '</a>' : fmt_cell($e, $c, $r[$c]) ?></td><?php endforeach; ?>
      <td class="actions">
        <a href="<?= h(url('admin_view', ['t' => $t, 'id' => $r['id']])) ?>">View</a>
        <?php if (can($e, 'u')): ?><a href="<?= h(url('admin_edit', ['t' => $t, 'id' => $r['id']])) ?>">Edit</a><?php endif; ?>
        <?php if (can($e, 'd')): ?><?= delete_form($t, (int)$r['id']) ?><?php endif; ?>
      </td>
    </tr>
  <?php endforeach; ?>
  <?php if (!$rows): ?><tr><td colspan="<?= count($e['list']) + 2 ?>" class="empty">Nothing matches. Try loosening the filters.</td></tr><?php endif; ?>
  </tbody>
</table>
</div>
<nav class="pager" aria-label="Pages">
  <span class="muted">Page <?= $page ?> of <?= $pages ?></span>
  <?php if ($page > 1): ?><a class="btn ghost sm" href="<?= h(url('admin_list', ['page' => $page - 1] + $keep)) ?>">&larr; Prev</a><?php endif; ?>
  <?php if ($page < $pages): ?><a class="btn ghost sm" href="<?= h(url('admin_list', ['page' => $page + 1] + $keep)) ?>">Next &rarr;</a><?php endif; ?>
</nav>
</div>
<?php layout($e['label'], ob_get_clean(), 'admin');
}

function delete_form(string $t, int $id): string {
    return '<details class="del"><summary>Delete</summary><form method="post" action="' . h(url('admin_delete')) . '">' . csrf_field()
        . '<input type="hidden" name="t" value="' . h($t) . '"><input type="hidden" name="id" value="' . $id . '">'
        . '<label>Type DELETE <input name="confirm" pattern="DELETE" required autocomplete="off"></label><button class="btn coral sm">Delete #' . $id . '</button></form></details>';
}

function page_admin_view(array $admin): void {
    $t = (string)($_GET['t'] ?? '');
    $e = entity($t);
    $id = (int)($_GET['id'] ?? 0);
    $r = row("SELECT * FROM $t WHERE id = ?", [$id]);
    if (!$r) { error_page(404, 'Not found', "There's no $t #$id."); }
    unset($r['pass_hash']);
    if ($t === 'fair_seeds' && $r['status'] === 'active') { $r['server_seed'] = '(hidden until the player rotates)'; }
    ob_start(); ?>
<header class="table-head row reveal d1">
  <div>
    <p class="eyebrow"><a href="<?= h(url('admin_list', ['t' => $t])) ?>"><?= h($e['label']) ?></a> / #<?= $id ?></p>
    <h1 class="display lg"><?= h(isset($e['title']) ? (string)$r[$e['title']] : $e['label'] . ' #' . $id) ?></h1>
  </div>
  <div class="head-actions">
    <?php if (can($e, 'u')): ?><a class="btn gold" href="<?= h(url('admin_edit', ['t' => $t, 'id' => $id])) ?>">Edit</a><?php endif; ?>
    <?php if (can($e, 'd')): ?><?= delete_form($t, $id) ?><?php endif; ?>
  </div>
</header>
<section class="panel reveal d2">
  <dl class="detail">
  <?php foreach ($r as $k => $v): $f = $e['fields'][$k] ?? null; ?>
    <dt><?= h(str_replace('_', ' ', $k)) ?></dt>
    <dd><?php if (($f['type'] ?? '') === 'json' || str_ends_with($k, '_json')): $d = json_decode((string)$v, true); ?><pre><?= h($d === null ? (string)$v : json_encode($d, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) ?></pre>
    <?php else: ?><?= fmt_cell($e, $k, $v) ?><?php endif; ?></dd>
  <?php endforeach; ?>
  </dl>
</section>
<?php if ($t === 'players'): $l = q('SELECT * FROM ledger WHERE player_id = ? ORDER BY id DESC LIMIT 15', [$id])->fetchAll(); ?>
<section class="panel reveal d3">
  <h2 class="display md">Recent ledger</h2>
  <table class="data compact"><thead><tr><th>When</th><th>Kind</th><th>Game</th><th class="n">Amount</th><th class="n">After</th><th>Detail</th></tr></thead><tbody>
  <?php foreach ($l as $x): ?><tr><td><?= h($x['created_at']) ?></td><td><?= h($x['kind']) ?></td><td><?= h($x['game']) ?></td><td class="n"><?= fmt_cell(entities()['ledger'], 'amount', $x['amount']) ?></td><td class="n"><?= coins((int)$x['balance_after']) ?></td><td><?= h($x['detail']) ?></td></tr><?php endforeach; ?>
  </tbody></table>
  <a class="more" href="<?= h(url('admin_list', ['t' => 'ledger', 'player_id' => $id])) ?>">All ledger rows &rarr;</a>
</section>
<?php endif; ?>
<?php layout($e['label'] . ' #' . $id, ob_get_clean(), 'admin');
}

function page_admin_edit(array $admin): void {
    $t = (string)($_GET['t'] ?? '');
    $e = entity($t);
    $id = (int)($_GET['id'] ?? 0);
    $r = $id ? row("SELECT * FROM $t WHERE id = ?", [$id]) : null;
    if ($id && !$r) { error_page(404, 'Not found', "There's no $t #$id."); }
    if (!can($e, $r ? 'u' : 'c')) { error_page(403, 'Read-only', 'This table can\'t be edited from the dashboard.'); }
    $hasOld = isset($_SESSION['form_old']);
    ob_start(); ?>
<header class="table-head reveal d1">
  <p class="eyebrow"><a href="<?= h(url('admin_list', ['t' => $t])) ?>"><?= h($e['label']) ?></a> / <?= $r ? "edit #$id" : 'new' ?></p>
  <h1 class="display lg"><?= $r ? 'Edit' : 'New' ?> <?= h(rtrim($e['label'], 's')) ?></h1>
</header>
<form class="panel form edit-form reveal d2" method="post" action="<?= h(url('admin_save')) ?>" novalidate>
  <?= csrf_field() ?><input type="hidden" name="t" value="<?= h($t) ?>"><input type="hidden" name="id" value="<?= $id ?>">
  <?php // what the admin saw: the save refuses to overwrite a balance or a live round/hand that moved meanwhile
  if ($r && $t === 'players'): ?><input type="hidden" name="balance_was" value="<?= h($hasOld ? old('balance_was', (string)(int)$r['balance']) : (int)$r['balance']) ?>">
  <?php elseif ($r && in_array($t, ['rounds', 'bj_hands'], true)): ?><input type="hidden" name="rev" value="<?= h($hasOld ? old('rev', row_rev($r)) : row_rev($r)) ?>">
  <?php endif; ?>
  <?php foreach ($e['fields'] as $name => $f):
      $col = $f['column'] ?? $name;
      $cur = $hasOld ? old($name) : ($r ? (string)($r[$col] ?? '') : (string)($f['default'] ?? ''));
      if ($f['type'] === 'password') { $cur = ''; }
      $req = !empty($f['required']) || ($f['type'] === 'password' && !$r);
      $label = h(ucwords(str_replace('_', ' ', $name))) . ($req ? ' <abbr title="required">*</abbr>' : '');
      $a = ' name="' . h($name) . '" id="f-' . h($name) . '"' . ($req ? ' required' : '') . aria_err($name); ?>
    <div class="field f-<?= h($f['type']) ?>">
    <?php switch ($f['type']):
        case 'bool': ?>
          <label class="check"><input type="checkbox" value="1"<?= $a ?><?= ($hasOld ? isset($_SESSION['form_old'][$name]) : (int)$cur === 1) ? ' checked' : '' ?>> <?= $label ?></label>
        <?php break; case 'enum': ?>
          <label for="f-<?= h($name) ?>"><?= $label ?></label>
          <select<?= $a ?>><?php foreach ($f['options'] as $o): ?><option<?= $cur === $o ? ' selected' : '' ?>><?= h($o) ?></option><?php endforeach; ?></select>
        <?php break; case 'fk':
            $n = (int)val("SELECT COUNT(*) FROM {$f['ref']}"); ?>
          <label for="f-<?= h($name) ?>"><?= $label ?></label>
          <?php if ($n <= 500): $opts = q("SELECT id, {$f['label_col']} AS l FROM {$f['ref']} ORDER BY {$f['label_col']}")->fetchAll(); ?>
            <select<?= $a ?>><option value="">Choose…</option><?php foreach ($opts as $o): ?><option value="<?= (int)$o['id'] ?>"<?= $cur === (string)$o['id'] ? ' selected' : '' ?>><?= h($o['l']) ?> (#<?= (int)$o['id'] ?>)</option><?php endforeach; ?></select>
          <?php else: ?><input type="number" min="1" value="<?= h($cur) ?>"<?= $a ?> placeholder="<?= h($f['ref']) ?> id"><?php endif; ?>
        <?php break; case 'textarea': case 'json': ?>
          <label for="f-<?= h($name) ?>"><?= $label ?></label>
          <textarea rows="<?= $f['type'] === 'json' ? 10 : 4 ?>"<?= $a ?><?= $f['type'] === 'json' ? ' class="mono" spellcheck="false"' : '' ?>><?= h($f['type'] === 'json' && $cur !== '' && json_decode($cur) !== null ? json_encode(json_decode($cur), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) : $cur) ?></textarea>
        <?php break; case 'datetime': ?>
          <label for="f-<?= h($name) ?>"><?= $label ?></label>
          <input type="datetime-local" step="1" value="<?= h($cur !== '' ? str_replace(' ', 'T', $cur) : '') ?>"<?= $a ?>>
        <?php break; case 'int': ?>
          <label for="f-<?= h($name) ?>"><?= $label ?></label>
          <input type="number" step="1"<?= isset($f['min']) ? ' min="' . (int)$f['min'] . '"' : '' ?> value="<?= h($cur) ?>"<?= $a ?> inputmode="numeric">
        <?php break; case 'password': ?>
          <label for="f-<?= h($name) ?>"><?= $label ?></label>
          <input type="password" minlength="<?= (int)($f['min'] ?? 8) ?>" autocomplete="new-password"<?= $a ?>>
        <?php break; default: ?>
          <label for="f-<?= h($name) ?>"><?= $label ?></label>
          <input type="<?= $f['type'] === 'email' ? 'email' : 'text' ?>" value="<?= h($cur) ?>"<?= isset($f['max']) ? ' maxlength="' . (int)$f['max'] . '"' : '' ?><?= $a ?>>
    <?php endswitch; ?>
    <?php if (!empty($f['hint'])): ?><p class="hint"><?= h($f['hint']) ?></p><?php endif; ?>
    <?= field_error($name) ?>
    </div>
  <?php endforeach; ?>
  <div class="form-actions">
    <button class="btn gold lg"><?= $r ? 'Save changes' : 'Create' ?></button>
    <a class="btn ghost lg" href="<?= h(url('admin_list', ['t' => $t])) ?>">Cancel</a>
  </div>
</form>
<?php layout(($r ? 'Edit ' : 'New ') . $e['label'], ob_get_clean(), 'admin');
}

function page_admin_password(array $admin): void {
    ob_start(); ?>
<section class="panel narrow reveal d1">
  <p class="eyebrow">Security</p>
  <h1 class="display lg">Change password</h1>
  <p class="muted">12 characters minimum. A long passphrase beats a short clever one. Saving wipes <code>admin_password.txt</code>.</p>
  <form method="post" action="<?= h(url('admin_password')) ?>" class="form">
    <?= csrf_field() ?>
    <label>Current password <input type="password" name="current_password" autocomplete="current-password" required<?= aria_err('current_password') ?>></label><?= field_error('current_password') ?>
    <label>New password <input type="password" name="new_password" minlength="12" autocomplete="new-password" required<?= aria_err('new_password') ?>></label><?= field_error('new_password') ?>
    <label>New password again <input type="password" name="new_password2" minlength="12" autocomplete="new-password" required<?= aria_err('new_password2') ?>></label><?= field_error('new_password2') ?>
    <button class="btn gold lg">Change password</button>
  </form>
</section>
<?php layout('Change password', ob_get_clean(), 'admin');
}


/* ═════════════════════════ STATIC ASSETS (3D) ═════════════════════════
 * three.js r170 (MIT, (c) 2010-2024 three.js authors; license header kept inside)
 * is stored gzip+base64 and served with long cache headers; the 3D game module too.
 */
function three_gz(): string {
    return base64_decode(<<<'B64'
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
B64);
}
function g3d_js(): string {
    return <<<'JS'
/* Gold Tide 3D games (ES module). Loaded on demand; three.js is served by index.php too.
 * Every scene here only ACTS OUT an outcome the server already decided.
 */
const T = await import(new URL('?action=asset&f=three&v=170', import.meta.url).href);
try { await Promise.all(['400 60px Limelight', '600 40px Figtree', '500 40px "Chivo Mono"'].map(f => document.fonts.load(f))); } catch (e) {}
const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const fmt = n => Number(n).toLocaleString('en-US');
const sleep = ms => new Promise(r => setTimeout(r, ms));
const clamp = (x, a, b) => Math.max(a, Math.min(b, x));
const lerp = (a, b, t) => a + (b - a) * t;
const easeOut = t => 1 - Math.pow(1 - t, 3);
const easeOutQuart = t => 1 - Math.pow(1 - t, 4);
const easeInOut = t => t < .5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;

/* ───────── shared stage ───────── */
function stage(host, o = {}) {
  const canvas = $('canvas', host);
  const renderer = new T.WebGLRenderer({ canvas, antialias: true, powerPreference: 'high-performance' });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, o.maxDpr || 2));
  renderer.shadowMap.enabled = true; renderer.shadowMap.type = T.PCFSoftShadowMap;
  renderer.toneMapping = T.ACESFilmicToneMapping; renderer.toneMappingExposure = o.exposure || 1.05;
  renderer.outputColorSpace = T.SRGBColorSpace;
  const scene = new T.Scene();
  scene.background = new T.Color(o.bg ?? 0x0a1020);
  if (o.fog) scene.fog = new T.Fog(o.bg ?? 0x0a1020, o.fog[0], o.fog[1]);
  const camera = new T.PerspectiveCamera(o.fov || 40, 1, 0.1, 200);
  const ticks = new Set(), tweens = new Set();
  let last = performance.now();
  const size = () => {
    const w = Math.max(1, host.clientWidth), h = Math.max(1, host.clientHeight);
    renderer.setSize(w, h, false); camera.aspect = w / h; camera.updateProjectionMatrix();
    if (o.onResize) o.onResize(w, h);
  };
  if ('ResizeObserver' in window) new ResizeObserver(size).observe(host);
  size();
  const loop = now => {
    if (!host.isConnected) { renderer.dispose(); return; }
    const dt = Math.min(.05, (now - last) / 1000); last = now;
    for (const tw of [...tweens]) { const u = clamp((now - tw.t0) / tw.dur, 0, 1); tw.fn(u); if (u >= 1) { tweens.delete(tw); tw.done(); } }
    for (const f of ticks) f(dt, now / 1000);
    renderer.render(scene, camera);
    requestAnimationFrame(loop);
  };
  requestAnimationFrame(loop);
  const tween = (dur, fn) => new Promise(done => { if (reduce || dur <= 0) { fn(1); done(); return; } tweens.add({ t0: performance.now(), dur, fn, done }); });
  return { renderer, scene, camera, tick: f => ticks.add(f), untick: f => ticks.delete(f), tween, size };
}
function canvasTex(w, h, draw, repeat) {
  const c = document.createElement('canvas'); c.width = w; c.height = h;
  draw(c.getContext('2d'), w, h);
  const t = new T.CanvasTexture(c); t.colorSpace = T.SRGBColorSpace; t.anisotropy = 8;
  if (repeat) { t.wrapS = t.wrapT = T.RepeatWrapping; t.repeat.set(...repeat); }
  t.userData.canvas = c;
  return t;
}
function woodTex(base = '#5a2a12', dark = '#3a1808') {
  return canvasTex(512, 512, (x, w, h) => {
    x.fillStyle = base; x.fillRect(0, 0, w, h);
    for (let i = 0; i < 90; i++) {
      x.strokeStyle = `rgba(0,0,0,${Math.random() * .18})`; x.lineWidth = Math.random() * 3 + .5;
      x.beginPath(); const y = Math.random() * h; x.moveTo(0, y);
      for (let k = 0; k <= 8; k++) x.lineTo(k * w / 8, y + Math.sin(k + i) * 6 + (Math.random() - .5) * 4); x.stroke();
    }
    x.fillStyle = dark; x.globalAlpha = .15; x.fillRect(0, 0, w, h);
  }, [2, 2]);
}
function feltTex(color = '#0f5a4c', draw) {
  return canvasTex(2048, 1024, (x, w, h) => {
    x.fillStyle = color; x.fillRect(0, 0, w, h);
    const img = x.getImageData(0, 0, w, h), d = img.data;
    for (let i = 0; i < d.length; i += 4) { const n = (Math.random() - .5) * 14; d[i] += n; d[i + 1] += n; d[i + 2] += n; }
    x.putImageData(img, 0, 0);
    if (draw) draw(x, w, h);
  });
}
function lights(scene, o = {}) {
  scene.add(new T.HemisphereLight(o.sky ?? 0xfff1d6, o.ground ?? 0x1a1030, o.hemi ?? .55));
  const key = new T.SpotLight(o.key ?? 0xfff3e0, o.keyI ?? 900, 60, Math.PI / 5, .45, 1.6);
  key.position.set(...(o.keyPos || [3, 18, 6])); key.castShadow = true; key.shadow.mapSize.set(2048, 2048); key.shadow.bias = -.0004;
  key.target.position.set(0, 0, 0); scene.add(key, key.target);
  const rim = new T.PointLight(o.rim ?? 0x5fe0cf, o.rimI ?? 60, 40); rim.position.set(...(o.rimPos || [-10, 6, -8])); scene.add(rim);
  return { key, rim };
}
function burstAt(host, n = 16) { if (window.goldTideBurst) window.goldTideBurst(host, n); }
function hud(host, text, cls = '') {
  let b = $('.g3d-banner', host);
  if (!b) { b = document.createElement('div'); b.className = 'g3d-banner'; host.appendChild(b); }
  b.className = 'g3d-banner ' + cls; b.innerHTML = text; void b.offsetWidth; b.classList.add('show');
}
async function post(url, fd) {
  if (!fd.has('csrf')) fd.append('csrf', $('meta[name="csrf"]').content);
  const res = await fetch(url, { method: 'POST', body: fd, credentials: 'same-origin', headers: { 'X-Requested-With': 'fetch', 'Accept': 'application/json' } });
  let j; try { j = await res.json(); } catch (e) { throw new Error('Network hiccup. Try again.'); }
  if (!j.ok) throw new Error(j.error || 'Something went wrong.');
  return j.data;
}
const api = () => window.goldTide || {};

/* ═════════════════════════ ROULETTE ═════════════════════════ */
const ORDER = [0, 32, 15, 19, 4, 21, 2, 25, 17, 34, 6, 27, 13, 36, 11, 30, 8, 23, 10, 5, 24, 16, 33, 1, 20, 14, 31, 9, 22, 18, 29, 7, 28, 12, 35, 3, 26];
const RED = new Set([1, 3, 5, 7, 9, 12, 14, 16, 18, 19, 21, 23, 25, 27, 30, 32, 34, 36]);
export function roulette(host) {
  const S = stage(host, { bg: 0x07121f, fog: [22, 50], fov: 38 });
  const { scene, camera } = S;
  lights(scene, { keyPos: [2, 16, 4], keyI: 1100, rim: 0xffb45a, rimI: 50 });
  const STEP = Math.PI * 2 / 37;
  // table
  const table = new T.Mesh(new T.CircleGeometry(20, 64), new T.MeshStandardMaterial({ map: feltTex('#0e4a43'), roughness: .95 }));
  table.rotation.x = -Math.PI / 2; table.position.y = -.35; table.receiveShadow = true; scene.add(table);
  // bowl (lathe): outer rim, ball track, sloped apron down to the rotor
  const prof = [[5.9, -.35], [6.0, .55], [5.75, .75], [5.3, .72], [4.95, .62], [4.6, .45], [4.1, .28], [3.75, .2], [3.7, -.1]].map(([r, y]) => new T.Vector2(r, y));
  const bowl = new T.Mesh(new T.LatheGeometry(prof, 128), new T.MeshStandardMaterial({ map: woodTex('#6b2f12'), roughness: .35, metalness: .1 }));
  bowl.castShadow = bowl.receiveShadow = true; scene.add(bowl);
  const track = new T.Mesh(new T.TorusGeometry(5.05, .05, 8, 128), new T.MeshStandardMaterial({ color: 0xd9b25a, metalness: .9, roughness: .25 }));
  track.rotation.x = Math.PI / 2; track.position.y = .66; scene.add(track);
  // deflector diamonds
  for (let i = 0; i < 8; i++) {
    const d = new T.Mesh(new T.OctahedronGeometry(.16), new T.MeshStandardMaterial({ color: 0xe8d9a8, metalness: .9, roughness: .2 }));
    const a = i * Math.PI / 4 + Math.PI / 8; d.position.set(Math.cos(a) * 4.4, .42, Math.sin(a) * 4.4); d.scale.set(1, .5, 2); d.rotation.y = -a; d.castShadow = true; scene.add(d);
  }
  // rotor
  const rotor = new T.Group(); scene.add(rotor);
  const rotorTex = canvasTex(2048, 2048, (x, w, h) => {
    const c = w / 2, R = w / 2;
    x.fillStyle = '#3a1a0a'; x.beginPath(); x.arc(c, c, R, 0, 7); x.fill();
    ORDER.forEach((n, i) => {
      const a0 = -Math.PI / 2 + (i - .5) * STEP, a1 = a0 + STEP;
      const col = n === 0 ? '#138a4f' : RED.has(n) ? '#c0142b' : '#15151c';
      x.fillStyle = col; x.beginPath(); x.arc(c, c, R * .99, a0, a1); x.arc(c, c, R * .8, a1, a0, true); x.fill();   // number band
      x.fillStyle = n === 0 ? '#0d5e36' : RED.has(n) ? '#8e0f21' : '#0c0c11';
      x.beginPath(); x.arc(c, c, R * .8, a0, a1); x.arc(c, c, R * .6, a1, a0, true); x.fill();                   // pocket floor
      x.save(); x.translate(c, c); x.rotate(-Math.PI / 2 + i * STEP + Math.PI / 2);
      x.fillStyle = '#fff'; x.font = `600 ${R * .085}px Limelight, serif`; x.textAlign = 'center'; x.textBaseline = 'middle';
      x.fillText(String(n), 0, -R * .895); x.restore();
    });
    const g = x.createRadialGradient(c, c, 0, c, c, R * .6); g.addColorStop(0, '#d9b25a'); g.addColorStop(.35, '#8a5a18'); g.addColorStop(.36, '#6b2f12'); g.addColorStop(1, '#4a1f0a');
    x.fillStyle = g; x.beginPath(); x.arc(c, c, R * .6, 0, 7); x.fill();
    for (let k = 0; k < 4; k++) { x.strokeStyle = 'rgba(217,178,90,.8)'; x.lineWidth = 6; x.beginPath(); x.arc(c, c, R * (.6 - k * .002), 0, 7); x.stroke(); }
  });
  const rotorTop = new T.Mesh(new T.CircleGeometry(3.7, 128), new T.MeshStandardMaterial({ map: rotorTex, roughness: .4, metalness: .05 }));
  rotorTop.rotation.x = -Math.PI / 2; rotorTop.rotation.z = 0; rotorTop.position.y = .02; rotorTop.receiveShadow = true; rotor.add(rotorTop);
  const rotorSide = new T.Mesh(new T.CylinderGeometry(3.7, 3.7, .35, 128, 1, true), new T.MeshStandardMaterial({ color: 0x4a1f0a, roughness: .5 }));
  rotorSide.position.y = -.15; rotor.add(rotorSide);
  const fretMat = new T.MeshStandardMaterial({ color: 0xd9b25a, metalness: .95, roughness: .2 });
  for (let i = 0; i < 37; i++) {
    const a = (i - .5) * STEP;
    const f = new T.Mesh(new T.BoxGeometry(.05, .2, .8), fretMat);
    const r = 3.7 * .7;   // pocket band centre
    f.position.set(Math.sin(a) * r, .12, -Math.cos(a) * r); f.rotation.y = -a; f.castShadow = true; rotor.add(f);
  }
  const ring = new T.Mesh(new T.TorusGeometry(3.7 * .8, .035, 6, 128), fretMat); ring.rotation.x = Math.PI / 2; ring.position.y = .1; rotor.add(ring);
  const ring2 = ring.clone(); ring2.scale.setScalar(.6 / .8); rotor.add(ring2);
  // turret
  const turret = new T.Group(); rotor.add(turret);
  const cone = new T.Mesh(new T.ConeGeometry(.55, 1.1, 48), fretMat); cone.position.y = .6; cone.castShadow = true; turret.add(cone);
  for (let k = 0; k < 4; k++) {
    const arm = new T.Mesh(new T.CylinderGeometry(.05, .05, 1.5, 12), fretMat); arm.rotation.z = Math.PI / 2; arm.position.y = .75; arm.rotation.y = k * Math.PI / 2; turret.add(arm);
    const knob = new T.Mesh(new T.SphereGeometry(.11, 16, 12), fretMat); knob.position.set(Math.cos(k * Math.PI / 2) * .75, .75, Math.sin(k * Math.PI / 2) * .75); turret.add(knob);
  }
  // ball
  const ball = new T.Mesh(new T.SphereGeometry(.14, 32, 24), new T.MeshPhysicalMaterial({ color: 0xffffff, roughness: .08, clearcoat: 1 }));
  ball.castShadow = true; scene.add(ball);
  // pocket angle in rotor frame: pocket i sits at angle i*STEP measured clockwise from -z, i.e. world pos (sin a, -cos a)
  let rot = 0, spinBoost = 0, ballMode = 'rest', ballPsi = 0, ballR = 2.6, ballY = .12, ballAbs = 0;
  const pos = (psiWorld, r, y) => ball.position.set(Math.sin(psiWorld) * r, y, -Math.cos(psiWorld) * r);
  const bowlY = r => r > 4.6 ? .66 : r > 3.75 ? lerp(.2, .45, (r - 3.75) / .85) : .12;
  const zoom = () => Math.max(1, 1.5 / camera.aspect);
  const camHome = { copy: v => v.set(0, 11.5 * zoom(), 10.5 * zoom()), clone() { return this.copy(new T.Vector3()); } };
  const look = new T.Vector3(0, 0, 0);
  camHome.copy(camera.position); camera.lookAt(look);
  let camTarget = camHome.clone(), lookTarget = look.clone();
  S.tick((dt, t) => {
    rot += (0.32 + spinBoost) * dt; rotor.rotation.y = -rot;
    if (ballMode === 'rest') pos(ballPsi + rot, ballR, ballY);
    camera.position.lerp(camTarget, 1 - Math.pow(.02, dt)); look.lerp(lookTarget, 1 - Math.pow(.02, dt)); camera.lookAt(look);
  });
  ballMode = 'rest'; ballPsi = 0; ballR = 2.6; ballY = .14;

  async function spin(number) {
    const idx = ORDER.indexOf(number), dur = reduce ? 1 : 6800;
    spinBoost = 2.2;
    const boostDecay = S.tween(dur + 1500, u => { spinBoost = 2.2 * (1 - easeOut(u)); });
    ballMode = 'fly';
    const psi0 = Math.random() * Math.PI * 2, target = idx * STEP;
    let delta = ((target - psi0) % (Math.PI * 2) + Math.PI * 2) % (Math.PI * 2) - Math.PI * 2 * 9; // 9 turns against the rotor
    let lastTick = 0;
    await S.tween(dur, u => {
      const psi = psi0 + delta * easeOutQuart(u);
      const wob = u > .55 && u < .96 ? Math.sin(u * 70) * .16 * Math.pow(1 - (u - .55) / .41, 2) : 0;
      let r, y;
      if (u < .52) { r = 5.05; y = .78; }
      else if (u < .8) { const v = (u - .52) / .28; r = lerp(5.05, 2.6, easeInOut(v)); y = bowlY(r) + .14 + Math.abs(Math.sin(v * Math.PI * 4)) * .35 * (1 - v); }
      else { const v = (u - .8) / .2; r = 2.6 + Math.sin(v * Math.PI * 3) * .12 * (1 - v); y = .14 + Math.abs(Math.sin(v * Math.PI * 5)) * .18 * (1 - v); }
      pos(psi + wob + rot, r, y);
      if (u > .52) {
        const bp = ball.position;
        camTarget.set(bp.x * 1.25, 5.2 * zoom(), bp.z * 1.25 + 3.4 * zoom()); lookTarget.set(bp.x * .6, 0, bp.z * .6);
        if (u - lastTick > .03 && u < .95) { lastTick = u; api().tink && api().tink(); }
      }
    });
    ballMode = 'rest'; ballPsi = target; ballR = 2.6; ballY = .14;
    await sleep(900);
    camHome.copy(camTarget); lookTarget.set(0, 0, 0);
    boostDecay.then(() => {});
  }

  host._g3d = {
    async play(fd) {
      const d = await post(playUrl('roulette3d'), fd);
      host.classList.add('spinning');
      const msg = $('[data-g3d-msg]', host.parentElement); if (msg) msg.textContent = 'No more bets…';
      await spin(d.number);
      host.classList.remove('spinning');
      const col = d.color;
      hud(host, `<b class="n ${col}">${d.number}</b>`, 'num');
      if (msg) msg.textContent = d.message;
      const hist = $('[data-g3d-hist]', host.parentElement);
      if (hist) { hist.insertAdjacentHTML('afterbegin', `<li class="${col}">${d.number}</li>`); while (hist.children.length > 14) hist.lastElementChild.remove(); }
      if (d.payout > 0) burstAt(host, 20);
      api().setBalance && api().setBalance(d.balance);
      return d;
    },
  };
  host.classList.add('ready');
}
const playUrl = slug => '?action=play&g=' + encodeURIComponent(slug);

/* ═════════════════════════ DICE (craps) ═════════════════════════ */
function pipTex(v, color = '#c8102e') {
  return canvasTex(256, 256, (x, w) => {
    x.fillStyle = color; x.fillRect(0, 0, w, w);
    const g = x.createRadialGradient(w * .3, w * .3, 0, w * .5, w * .5, w * .8); g.addColorStop(0, 'rgba(255,255,255,.25)'); g.addColorStop(1, 'rgba(0,0,0,.25)');
    x.fillStyle = g; x.fillRect(0, 0, w, w);
    const P = { 1: [[.5, .5]], 2: [[.27, .27], [.73, .73]], 3: [[.25, .25], [.5, .5], [.75, .75]], 4: [[.27, .27], [.73, .27], [.27, .73], [.73, .73]], 5: [[.25, .25], [.75, .25], [.5, .5], [.25, .75], [.75, .75]], 6: [[.28, .22], [.72, .22], [.28, .5], [.72, .5], [.28, .78], [.72, .78]] }[v];
    P.forEach(([a, b]) => { x.fillStyle = '#fff'; x.beginPath(); x.arc(a * w, b * w, w * .085, 0, 7); x.fill(); x.fillStyle = 'rgba(0,0,0,.25)'; x.beginPath(); x.arc(a * w + 3, b * w + 3, w * .085, 0, 7); x.fill(); x.fillStyle = '#f7f3ea'; x.beginPath(); x.arc(a * w, b * w, w * .08, 0, 7); x.fill(); });
  });
}
// BoxGeometry material order: +x, -x, +y, -y, +z, -z. Opposite faces add to 7.
const FACE_VALUES = [2, 5, 1, 6, 3, 4];
const FACE_UP = {
  1: new T.Quaternion(),
  6: new T.Quaternion().setFromAxisAngle(new T.Vector3(1, 0, 0), Math.PI),
  2: new T.Quaternion().setFromAxisAngle(new T.Vector3(0, 0, 1), Math.PI / 2),
  5: new T.Quaternion().setFromAxisAngle(new T.Vector3(0, 0, 1), -Math.PI / 2),
  3: new T.Quaternion().setFromAxisAngle(new T.Vector3(1, 0, 0), -Math.PI / 2),
  4: new T.Quaternion().setFromAxisAngle(new T.Vector3(1, 0, 0), Math.PI / 2),
};
function makeDie(color) {
  const mats = FACE_VALUES.map(v => new T.MeshPhysicalMaterial({ map: pipTex(v, color), roughness: .18, clearcoat: .8, clearcoatRoughness: .1 }));
  const m = new T.Mesh(new T.BoxGeometry(.62, .62, .62, 2, 2, 2), mats); m.castShadow = true; return m;
}

// Felt coordinates: x runs across the table (-8..8), z toward the player (-4..4).
const CR_COLX = { 4: -6.25, 5: -4.95, 6: -3.65, 8: -2.35, 9: -1.05, 10: .25 };
const CRAPS_SPOTS = {
  dontcome: [-7.4, -2.6], come: [-3, -.82], field: [-3, .42], big6: [-7.4, 0], big8: [-7.4, .66],
  dontpass: [-5.6, 1.3], pass: [-3.2, 2.05], passodds: [-3.2, 2.9], dpodds: [-5.46, 1.18, 'dontpass'],
  any7: [3.3, -3.65], hard6: [2.35, -3], hard10: [4.25, -3], hard8: [2.35, -2.3], hard4: [4.25, -2.3],
  ace3: [1.875, -1.52], ace2: [2.825, -1.52], twelve: [3.775, -1.52], yo: [4.725, -1.52], horn: [2.35, -.75], ce: [4.25, -.75], anycraps: [3.3, -.1],
};
for (const [n, x] of Object.entries(CR_COLX)) {
  CRAPS_SPOTS['lay' + n] = [x, -3.7]; CRAPS_SPOTS['place' + n] = [x, -2.0]; CRAPS_SPOTS['buy' + n] = [x, -1.52];
  CRAPS_SPOTS['come' + n] = [x - .34, -2.6]; CRAPS_SPOTS['dcome' + n] = [x + .34, -2.6];
  CRAPS_SPOTS['comeodds' + n] = [x - .22, -2.72, 'come' + n]; CRAPS_SPOTS['dcomeodds' + n] = [x + .46, -2.72, 'dcome' + n];
}
export function craps(host) {
  const S = stage(host, { bg: 0x0a0d18, fog: [24, 50], fov: 36 });
  const { scene, camera } = S;
  lights(scene, { keyPos: [-1, 15, 5], keyI: 1300, rim: 0xffcf7a, rimI: 40, rimPos: [8, 6, 8] });
  // felt with a printed bubble-style layout
  const felt = feltTex('#0f5a45', (x, w, h) => {
    const X = v => (v + 8) / 16 * w, Z = v => (v + 4) / 8 * h, INK = '#f5ecd7';
    x.strokeStyle = INK; x.fillStyle = INK; x.lineWidth = 5; x.textAlign = 'center'; x.textBaseline = 'middle';
    const text = (s, cx, cz, size, font = 'Figtree, sans-serif', weight = 600, color = INK) => { x.fillStyle = color; x.font = `${weight} ${size}px ${font}`; x.fillText(s, X(cx), Z(cz)); x.fillStyle = INK; };
    const box = (x0, z0, x1, z1, label, size = 40, font, color, fill) => {
      if (fill) { x.fillStyle = fill; x.fillRect(X(x0), Z(z0), X(x1) - X(x0), Z(z1) - Z(z0)); x.fillStyle = INK; }
      x.strokeRect(X(x0), Z(z0), X(x1) - X(x0), Z(z1) - Z(z0));
      if (label) text(label, (x0 + x1) / 2, (z0 + z1) / 2, size, font, 600, color);
    };
    // numbers: lay strip / number / place / buy
    for (const [n, cx] of Object.entries(CR_COLX)) {
      const x0 = cx - .65, x1 = cx + .65;
      box(x0, -3.95, x1, -3.45, 'LAY', 26, undefined, INK, 'rgba(0,0,0,.18)');
      box(x0, -3.45, x1, -2.25, n === '6' ? 'SIX' : n === '9' ? 'NINE' : n, 78, 'Limelight, serif', '#ffe7b0');
      box(x0, -2.25, x1, -1.75, 'PLACE', 26, undefined, INK, 'rgba(255,217,138,.1)');
      box(x0, -1.75, x1, -1.3, 'BUY', 24);
    }
    box(-7.9, -3.95, -6.9, -1.3, '');
    x.save(); x.translate(X(-7.4), Z(-2.62)); x.rotate(-Math.PI / 2); x.font = '600 40px Limelight, serif'; x.fillText("DON'T COME BAR", 0, 0); x.restore();
    box(-7.9, -1.3, .9, -.35, 'COME', 70, 'Limelight, serif');
    box(-6.9, -.35, .9, 1.0, '');
    text('FIELD', -3, -.08, 58, 'Limelight, serif', 400);
    text('2 · 3 · 4 · 9 · 10 · 11 · 12', -3, .38, 40, '"Chivo Mono", monospace', 500);
    text('2 PAYS DOUBLE  ·  12 PAYS TRIPLE', -3, .78, 24);
    box(-7.9, -.35, -6.9, .33, 'BIG 6', 30, 'Limelight, serif', '#ff9a9a');
    box(-7.9, .33, -6.9, 1.0, 'BIG 8', 30, 'Limelight, serif', '#ff9a9a');
    box(-7.9, 1.0, .9, 1.6, "DON'T PASS BAR  ⚀⚀", 38);
    box(-7.9, 1.6, .9, 2.5, 'PASS LINE', 64, 'Limelight, serif');
    box(-4.2, 2.5, -2.2, 3.3, 'ODDS', 30);
    // props
    const P0 = 1.4, P1 = 5.2, PM = 3.3;
    box(P0, -3.95, P1, -3.35, 'SEVEN  4 TO 1', 34, 'Limelight, serif', '#ff8a8a', 'rgba(0,0,0,.15)');
    box(P0, -3.35, PM, -2.65, 'HARD 6  9:1', 28); box(PM, -3.35, P1, -2.65, 'HARD 10  7:1', 28);
    box(P0, -2.65, PM, -1.95, 'HARD 8  9:1', 28); box(PM, -2.65, P1, -1.95, 'HARD 4  7:1', 28);
    [['1·2', '15:1'], ['1·1', '30:1'], ['6·6', '30:1'], ['5·6', '15:1']].forEach(([a, b], i) => { const x0 = P0 + i * .95; box(x0, -1.95, x0 + .95, -1.1, ''); text(a, x0 + .475, -1.66, 30, '"Chivo Mono", monospace', 500); text(b, x0 + .475, -1.33, 24); });
    box(P0, -1.1, PM, -.4, 'HORN', 30); box(PM, -1.1, P1, -.4, 'C & E', 30);
    box(P0, -.4, P1, .2, 'ANY CRAPS  7 TO 1', 30, 'Limelight, serif', '#ff8a8a', 'rgba(0,0,0,.15)');
    x.font = '400 72px Limelight, serif'; x.fillStyle = 'rgba(245,236,215,.14)'; x.fillText('HARBOR', X(PM), Z(1.0)); x.fillText('CRAPS', X(PM), Z(1.75));
  });
  const table = new T.Mesh(new T.PlaneGeometry(16, 8), new T.MeshStandardMaterial({ map: felt, roughness: .92 }));
  table.rotation.x = -Math.PI / 2; table.receiveShadow = true; scene.add(table);
  const railMat = new T.MeshStandardMaterial({ map: woodTex('#4a2410'), roughness: .35 });
  const rail = (w, d, x, z, h = .6) => { const m = new T.Mesh(new T.BoxGeometry(w, h, d), railMat); m.position.set(x, h / 2 - .05, z); m.castShadow = m.receiveShadow = true; scene.add(m); return m; };
  rail(16.8, .4, 0, -4.2); rail(16.8, .4, 0, 4.2); rail(.4, 8.8, -8.2, 0); rail(.4, 8.8, 8.2, 0);
  // diamond-studded back wall (the dice bounce here)
  const wallTex = canvasTex(1024, 128, (x, w, h) => { x.fillStyle = '#2a2a33'; x.fillRect(0, 0, w, h); for (let i = 0; i < 64; i++) for (let j = 0; j < 4; j++) { const cx = i * 16 + (j % 2) * 8, cy = j * 32 + 16; x.fillStyle = '#50505e'; x.beginPath(); x.moveTo(cx, cy - 10); x.lineTo(cx + 8, cy); x.lineTo(cx, cy + 10); x.lineTo(cx - 8, cy); x.fill(); } });
  const wall = new T.Mesh(new T.BoxGeometry(.3, .9, 8), new T.MeshStandardMaterial({ map: wallTex, roughness: .6 })); wall.position.set(7.85, .45, 0); scene.add(wall);
  // puck
  const puckTex = on => canvasTex(256, 256, (x, w) => { x.fillStyle = on ? '#f5f1e8' : '#16161c'; x.beginPath(); x.arc(w / 2, w / 2, w / 2, 0, 7); x.fill(); x.fillStyle = on ? '#16161c' : '#f5f1e8'; x.font = '700 90px Figtree, sans-serif'; x.textAlign = 'center'; x.textBaseline = 'middle'; x.fillText(on ? 'ON' : 'OFF', w / 2, w / 2 + 4); });
  const puckOn = new T.MeshStandardMaterial({ map: puckTex(true), roughness: .4 }), puckOff = new T.MeshStandardMaterial({ map: puckTex(false), roughness: .4 });
  const puck = new T.Mesh(new T.CylinderGeometry(.3, .3, .1, 40), [new T.MeshStandardMaterial({ color: 0x999999 }), puckOff, puckOff]);
  puck.castShadow = true; scene.add(puck);
  let puckAt = -1;
  const setPuck = (point, animate = true) => {
    if (point === puckAt) return Promise.resolve();
    puckAt = point;
    const to = point ? new T.Vector3(CR_COLX[point], .07, -3.12) : new T.Vector3(-7.4, .07, -3.6);
    puck.material[1] = point ? puckOn : puckOff;
    if (!animate) { puck.position.copy(to); return Promise.resolve(); }
    const from = puck.position.clone();
    return S.tween(600, u => { puck.position.lerpVectors(from, to, easeInOut(u)); puck.position.y = .07 + Math.sin(u * Math.PI) * .8; });
  };
  // chip stacks for every bet on the layout (odds ride on top of their base bet, offset a little)
  const chipMat = [0x6c7bd6, 0x1b8a5a, 0xd6283f, 0x1c1c24, 0x7b3fb3, 0xd19a1a].map(c => new T.MeshStandardMaterial({ color: c, roughness: .45, metalness: .05 }));
  const chipGeo = new T.CylinderGeometry(.22, .22, .06, 28);
  const stacks = {};
  const chipsFor = amt => Math.min(10, Math.max(1, Math.round(Math.log10(Math.max(1, amt)) * 2.5)));
  let lastSig = '';
  function setStacks(bets) {
    const sig = JSON.stringify(bets || {}); if (sig === lastSig) return; lastSig = sig;
    for (const k in stacks) { scene.remove(stacks[k]); delete stacks[k]; }
    const entries = Object.entries(bets || {}).sort((a, b) => !!(CRAPS_SPOTS[a[0]] || [])[2] - !!(CRAPS_SPOTS[b[0]] || [])[2]);
    for (const [k, amt] of entries) {
      const spot = CRAPS_SPOTS[k]; if (!spot || !amt) continue;
      const g = new T.Group(), n = chipsFor(amt);
      for (let i = 0; i < n; i++) { const c = new T.Mesh(chipGeo, chipMat[(i + k.length) % chipMat.length]); c.position.y = .035 + i * .062; c.rotation.y = i * .7; c.castShadow = true; g.add(c); }
      const base = spot[2] && bets[spot[2]] ? chipsFor(bets[spot[2]]) * .062 : 0;
      g.position.set(spot[0], base, spot[1]); scene.add(g); stacks[k] = g;
    }
  }
  const d1 = makeDie('#c8102e'), d2 = makeDie('#c8102e');
  d1.position.set(-6, .31, 3.2); d2.position.set(-5.3, .31, 3.4); scene.add(d1, d2);

  /* ── the bubble: a glass dome on a chrome pedestal behind the table ── */
  const BUB = new T.Vector3(0, 0, -12), FLOOR = 1.02;
  const bubble = new T.Group(); bubble.position.copy(BUB); scene.add(bubble);
  const chrome = new T.MeshStandardMaterial({ color: 0xd9d4c7, metalness: .9, roughness: .22 });
  const ped = new T.Mesh(new T.CylinderGeometry(2.3, 2.7, 1, 64), new T.MeshStandardMaterial({ color: 0x1b1f2e, metalness: .5, roughness: .35 }));
  ped.position.y = .5; ped.receiveShadow = true; bubble.add(ped);
  const deck = new T.Mesh(new T.CylinderGeometry(2.05, 2.05, .04, 64), new T.MeshStandardMaterial({ map: feltTex('#0f5a45', (x, w, h) => {
    x.strokeStyle = '#f5ecd7'; x.lineWidth = 10; x.beginPath(); x.ellipse(w / 2, h / 2, w * .42, h * .42, 0, 0, 7); x.stroke();
  }), roughness: .9 }));
  deck.position.y = 1; deck.receiveShadow = true; bubble.add(deck);
  const ring = new T.Mesh(new T.TorusGeometry(2.08, .07, 16, 96), chrome); ring.rotation.x = Math.PI / 2; ring.position.y = 1.02; bubble.add(ring);
  const bulbs = [];
  for (let i = 0; i < 28; i++) {
    const a = i / 28 * Math.PI * 2, m = new T.Mesh(new T.SphereGeometry(.07, 12, 8), new T.MeshStandardMaterial({ color: 0xffd98a, emissive: 0xffb627, emissiveIntensity: 1 }));
    m.position.set(Math.cos(a) * 2.52, .55, Math.sin(a) * 2.52); bubble.add(m); bulbs.push(m);
  }
  const glass = new T.Mesh(new T.SphereGeometry(2.02, 64, 32, 0, Math.PI * 2, 0, Math.PI / 2),
    new T.MeshPhysicalMaterial({ color: 0xdff4ff, transparent: true, opacity: .16, roughness: .02, metalness: 0, clearcoat: 1, side: T.DoubleSide, depthWrite: false }));
  glass.position.y = 1.02; bubble.add(glass);
  const glint = new T.PointLight(0x9fe8ff, 30, 12); glint.position.set(-2.5, 4.5, 2.5); bubble.add(glint);
  const b1 = makeDie('#c8102e'), b2 = makeDie('#c8102e');
  b1.position.set(-.45, FLOOR + .31, .2); b2.position.set(.45, FLOOR + .31, -.2); bubble.add(b1, b2);
  // air bubbles that rise while the dice are popping
  const airMat = new T.MeshPhysicalMaterial({ color: 0xffffff, transparent: true, opacity: .35, roughness: 0, clearcoat: 1, depthWrite: false });
  const air = Array.from({ length: 26 }, () => { const m = new T.Mesh(new T.SphereGeometry(.05 + Math.random() * .07, 10, 8), airMat); m.visible = false; bubble.add(m); return m; });
  let airOn = 0;
  S.tick((dt, t) => {
    bulbs.forEach((b, i) => { b.material.emissiveIntensity = .4 + .6 * (Math.sin(t * (airOn ? 12 : 2.5) - i * .7) * .5 + .5); });
    air.forEach(m => {
      if (!m.visible) { if (airOn && Math.random() < .12) { const a = Math.random() * 7, r = Math.random() * 1.6; m.position.set(Math.cos(a) * r, FLOOR + .05, Math.sin(a) * r); m.visible = true; } return; }
      m.position.y += dt * (2.2 + m.geometry.parameters.radius * 10);
      if (m.position.y > FLOOR + Math.sqrt(Math.max(0, 4 - m.position.x * m.position.x - m.position.z * m.position.z)) - .1) m.visible = false;
    });
  });

  // cameras: back off on tall/narrow screens so the whole table stays in frame
  const zoom = () => Math.max(1, 1.7 / camera.aspect);
  let mode = 'table';
  const homes = {
    table: { pos: () => new T.Vector3(-1.2 * zoom(), 10.8 * zoom(), 9.6 * zoom()), look: () => new T.Vector3(-.8, 0, -.2) },
    bubble: { pos: () => new T.Vector3(BUB.x, 4.1 + zoom() * 1.3, BUB.z + 5.4 * zoom()), look: () => new T.Vector3(BUB.x, 1.35, BUB.z) },
  };
  let camTarget = homes.table.pos(), lookTarget = homes.table.look();
  const look = lookTarget.clone();
  camera.position.copy(camTarget); camera.lookAt(look);
  const goHome = () => { camTarget = homes[mode].pos(); lookTarget = homes[mode].look(); };
  S.tick(dt => { camera.position.lerp(camTarget, 1 - Math.pow(.05, dt)); look.lerp(lookTarget, 1 - Math.pow(.05, dt)); camera.lookAt(look); });

  function throwDie(die, value, lane) {
    const rest = new T.Vector3(5.7 + Math.random() * 1.4, .31, lane * 1.6 + (Math.random() - .5) * 1.2);
    const start = new T.Vector3(-6.5, 1.6, 2.8 + lane * .3);
    const hit1 = new T.Vector3(1.2 + Math.random() * 1.6, .31, lane * 1.1 + (Math.random() - .5));
    const wallHit = new T.Vector3(7.4, .55, lane * 1.3 + (Math.random() - .5) * 1.5);
    const b2 = new T.Vector3(lerp(wallHit.x, rest.x, .55), .31, lerp(wallHit.z, rest.z, .5));
    const legs = [[start, hit1, 1.9, .34], [hit1, wallHit, 1.1, .28], [wallHit, b2, .55, .2], [b2, rest, .22, .18]];
    return animateDie(die, value, legs, rest, 2200);
  }
  function popDie(die, value, side) {
    // hop around inside the dome, then drop to the deck
    const pt = (y0, y1) => { const a = Math.random() * Math.PI * 2, r = Math.random() * 1.15; return new T.Vector3(Math.cos(a) * r, FLOOR + y0 + Math.random() * (y1 - y0), Math.sin(a) * r); };
    const rest = new T.Vector3(side * (.35 + Math.random() * .5), FLOOR + .31, (Math.random() - .5) * 1.1);
    const pts = [die.position.clone(), pt(1.2, 2.2), pt(.4, 1.9), pt(1, 2.3), pt(.3, 1.6), pt(.6, 1.4), rest];
    const legs = []; for (let i = 0; i < pts.length - 1; i++) legs.push([pts[i], pts[i + 1], i === pts.length - 2 ? .5 : .25, i === pts.length - 2 ? .3 : .16]);
    return animateDie(die, value, legs, rest, 2300);
  }
  function animateDie(die, value, legs, rest, dur) {
    const fin = new T.Quaternion().setFromAxisAngle(new T.Vector3(0, 1, 0), Math.random() * Math.PI * 2).multiply(FACE_UP[value]);
    const axis = new T.Vector3(Math.random() - .5, Math.random() - .5, Math.random() - .5).normalize();
    const total = legs.reduce((a, l) => a + l[3], 0);
    return S.tween(reduce ? 1 : dur, u => {
      let tAcc = 0; const t = u * total;
      for (let i = 0; i < legs.length; i++) {
        const [a, b, h, d] = legs[i];
        if (t <= tAcc + d || i === legs.length - 1) {
          const v = clamp((t - tAcc) / d, 0, 1);
          die.position.set(lerp(a.x, b.x, v), lerp(a.y, b.y, v) + Math.sin(v * Math.PI) * h, lerp(a.z, b.z, v));
          break;
        }
        tAcc += d;
      }
      const spin = new T.Quaternion().setFromAxisAngle(axis, (1 - easeOut(u)) * Math.PI * 14);
      die.quaternion.copy(spin.multiply(fin));
      if (u >= 1) { die.position.copy(rest); die.quaternion.copy(fin); }
    });
  }
  const NORMALS = [[1, 0, 0], [-1, 0, 0], [0, 1, 0], [0, -1, 0], [0, 0, 1], [0, 0, -1]].map(v => new T.Vector3(...v));
  const topFace = die => { let best = -2, val = 0; NORMALS.forEach((n, i) => { const y = n.clone().applyQuaternion(die.quaternion).y; if (y > best) { best = y; val = FACE_VALUES[i]; } }); return val; };
  host._g3d = {
    tops: () => mode === 'bubble' ? [topFace(b1), topFace(b2)] : [topFace(d1), topFace(d2)],   // read-only, for tests
    setState(st) { setStacks(st.bets); setPuck(st.point || 0, puckAt !== -1); },
    setMode(m, animate = true) {
      mode = m === 'bubble' ? 'bubble' : 'table'; goHome();
      if (!animate) { camera.position.copy(camTarget); look.copy(lookTarget); }
    },
    async roll(d) {
      api().rattle && api().rattle();
      if (mode === 'bubble') {
        airOn = 1;
        await Promise.all([popDie(b1, d.dice[0], -1), popDie(b2, d.dice[1], 1)]);
        airOn = 0;
      } else {
        camTarget.set(2 * zoom(), 7.5 * zoom(), 7.5 * zoom()); lookTarget.set(5, 0, 0);
        await Promise.all([throwDie(d1, d.dice[0], -.5), throwDie(d2, d.dice[1], .5)]);
      }
      api().thud && api().thud();
      await sleep(350);
      setStacks(d.bets);
      await setPuck(d.point || 0);
      goHome();
    },
  };
  host.classList.add('ready');
}

/* ═════════════════════════ PIER PUSHER ═════════════════════════ */
export function pusher(host) {
  const S = stage(host, { bg: 0x120a1e, fog: [16, 40], fov: 42, maxDpr: 1.75 });
  const { scene, camera } = S;
  lights(scene, { keyPos: [0, 12, 6], keyI: 520, rim: 0xff6fb0, rimI: 70, rimPos: [0, 5, -6], hemi: .45 });
  // stamped coin face: rim, beaded ring and a star, like the Gold Tide logo coin
  const faceTex = canvasTex(256, 256, (x, w) => {
    const c = w / 2, g = x.createRadialGradient(c * .7, c * .6, 10, c, c, c); g.addColorStop(0, '#ffe38a'); g.addColorStop(.7, '#e0a526'); g.addColorStop(1, '#a86f08');
    x.fillStyle = g; x.beginPath(); x.arc(c, c, c, 0, 7); x.fill();
    x.strokeStyle = '#8a5a00'; x.lineWidth = 10; x.beginPath(); x.arc(c, c, c * .82, 0, 7); x.stroke();
    for (let i = 0; i < 36; i++) { const a = i / 36 * Math.PI * 2; x.fillStyle = '#fff1b8'; x.beginPath(); x.arc(c + Math.cos(a) * c * .92, c + Math.sin(a) * c * .92, 4, 0, 7); x.fill(); }
    x.fillStyle = '#fff3c4'; x.beginPath(); for (let i = 0; i < 10; i++) { const a = -Math.PI / 2 + i * Math.PI / 5, r = i % 2 ? c * .22 : c * .5; x.lineTo(c + Math.cos(a) * r, c + Math.sin(a) * r); } x.fill();
  });
  const coinMat = [new T.MeshStandardMaterial({ color: 0xc88a12, metalness: .8, roughness: .35 }),
    new T.MeshStandardMaterial({ map: faceTex, metalness: .45, roughness: .4 }), new T.MeshStandardMaterial({ map: faceTex, metalness: .45, roughness: .4 })];
  const coinGeo = new T.CylinderGeometry(.34, .34, .07, 28);
  // cabinet
  const neon = c => new T.MeshStandardMaterial({ color: c, emissive: c, emissiveIntensity: 1.6 });
  const back = new T.Mesh(new T.BoxGeometry(7, 6, .3), new T.MeshStandardMaterial({ map: canvasTex(512, 512, (x, w, h) => {
    const g = x.createLinearGradient(0, 0, 0, h); g.addColorStop(0, '#2b0f44'); g.addColorStop(1, '#0d1b3a'); x.fillStyle = g; x.fillRect(0, 0, w, h);
    x.fillStyle = '#ffd98a'; x.font = '400 64px Limelight, serif'; x.textAlign = 'center'; x.fillText('PIER PUSHER', w / 2, 90);
    for (let i = 0; i < 40; i++) { x.fillStyle = `rgba(255,255,255,${Math.random() * .5})`; x.fillRect(Math.random() * w, 120 + Math.random() * 380, 2, 2); }
  }), roughness: .6 }));
  back.position.set(0, 3, -3.4); scene.add(back);
  // peg field on the back wall
  const pegMat = new T.MeshStandardMaterial({ color: 0xd9dde8, metalness: .9, roughness: .2 });
  const pegs = [];
  for (let r = 0; r < 5; r++) for (let i = 0; i < 9 - (r % 2); i++) { const p = new T.Mesh(new T.CylinderGeometry(.06, .06, .5, 10), pegMat); p.rotation.x = Math.PI / 2; p.position.set(-2.8 + i * .7 + (r % 2) * .35, 4.6 - r * .55, -3.05); scene.add(p); pegs.push(p); }
  // shelf
  const shelf = new T.Mesh(new T.BoxGeometry(6.4, .3, 5), new T.MeshStandardMaterial({ color: 0x9fb4c8, metalness: .6, roughness: .35 }));
  shelf.position.set(0, -.15, -.3); shelf.receiveShadow = true; scene.add(shelf);
  const lipL = new T.Mesh(new T.BoxGeometry(.25, 1.2, 5.4), new T.MeshStandardMaterial({ color: 0x2b0f44, roughness: .4 })); lipL.position.set(-3.3, .4, -.3); scene.add(lipL);
  const lipR = lipL.clone(); lipR.position.x = 3.3; scene.add(lipR);
  [-3.3, 3.3].forEach(x => { const n = new T.Mesh(new T.BoxGeometry(.06, .06, 5.4), neon(0xff4fa3)); n.position.set(x, 1.02, -.3); scene.add(n); });
  const edge = new T.Mesh(new T.BoxGeometry(6.4, .05, .05), neon(0x5fe0cf)); edge.position.set(0, .02, 2.2); scene.add(edge);
  // pusher block
  const pusherMesh = new T.Mesh(new T.BoxGeometry(6.3, .55, 2), new T.MeshStandardMaterial({ color: 0xc8d2e0, metalness: .75, roughness: .25 }));
  pusherMesh.castShadow = true; pusherMesh.receiveShadow = true; scene.add(pusherMesh);
  const pushTop = new T.Mesh(new T.BoxGeometry(6.3, .02, 2), new T.MeshStandardMaterial({ map: canvasTex(512, 160, (x, w, h) => { x.fillStyle = '#1a2440'; x.fillRect(0, 0, w, h); x.fillStyle = '#5fe0cf'; x.font = '600 40px Figtree'; x.textAlign = 'center'; x.fillText('← DROP ZONE →', w / 2, h / 2 + 14); }) }));
  scene.add(pushTop);
  // tray
  const tray = new T.Mesh(new T.BoxGeometry(6.6, .2, 1.4), new T.MeshStandardMaterial({ color: 0x1a1030, roughness: .5 })); tray.position.set(0, -1.6, 3.1); tray.receiveShadow = true; scene.add(tray);
  // coins: instanced
  const MAX = 260;
  const inst = new T.InstancedMesh(coinGeo, coinMat, MAX); inst.castShadow = true; inst.receiveShadow = true; inst.instanceMatrix.setUsage(T.DynamicDrawUsage); scene.add(inst);
  const coins = [];
  const dummy = new T.Object3D();
  const addCoin = (x, z, y = .035, extra = {}) => { if (coins.length >= MAX) return null; const c = { x, y, z, rx: 0, ry: Math.random() * 6, rz: 0, mode: 'pile', ...extra }; coins.push(c); return c; };
  let pz = 0;   // pusher front z
  const PUSH_BACK = -2.2, PUSH_FWD = -1.1, EDGE = 2.2;
  for (let i = 0; i < 110; i++) addCoin(-2.8 + Math.random() * 5.6, lerp(PUSH_FWD, EDGE - .35, Math.random()), .035 + (Math.random() < .25 ? .07 : 0));
  const aimCam = () => { const k = Math.max(1, 1.2 / camera.aspect); camera.position.set(0, 6.2 * k, 7.0 * k); camera.lookAt(0, .5, -.5); };
  aimCam(); if ('ResizeObserver' in window) new ResizeObserver(aimCam).observe(host);
  let t0 = 0;
  S.tick((dt, t) => {
    t0 = t;
    pz = lerp(PUSH_BACK, PUSH_FWD, .5 + .5 * Math.sin(t * 1.3));
    pusherMesh.position.set(0, .28, pz - 1); pushTop.position.set(0, .56, pz - 1);
    for (const c of coins) {
      if (c.mode === 'pile' && c.z < pz + .34) c.z = pz + .34;   // shove
    }
    coins.forEach((c, i) => { dummy.position.set(c.x, c.y, c.z); dummy.rotation.set(c.rx, c.ry, c.rz); dummy.updateMatrix(); inst.setMatrixAt(i, dummy.matrix); });
    inst.count = coins.length; inst.instanceMatrix.needsUpdate = true;
  });
  // animations
  async function dropCoin(lane) {
    const x = lerp(-2.6, 2.6, lane / 100);
    const c = addCoin(x, -3.0, 5.3, { mode: 'fly', rx: Math.PI / 2 });
    let px = x;
    await S.tween(reduce ? 1 : 1100, u => {
      c.y = lerp(5.3, 1.8, u); c.x = px + Math.sin(u * Math.PI * 5) * .25 * (1 - u); c.z = -3.0; c.ry += .3;
      if (Math.floor(u * 5) !== Math.floor((u - .02) * 5)) api().tink && api().tink();
    });
    const lz = lerp(pz + .6, .4, Math.random());
    await S.tween(reduce ? 1 : 420, u => { c.y = lerp(1.8, .6, u) + Math.sin(u * Math.PI) * .3; c.z = lerp(-3, lz, u); c.rx = lerp(Math.PI / 2, 0, u); });
    c.y = .105; c.rx = 0; c.mode = 'pile';
    api().clink && api().clink();
  }
  async function spill(n) {
    if (!n) return;
    // pick the coins nearest the edge; top up the front if the pile is thin
    let front = coins.filter(c => c.mode === 'pile').sort((a, b) => b.z - a.z).slice(0, n);
    while (front.length < n) front.push(addCoin(-2.6 + Math.random() * 5.2, EDGE - .3 - Math.random() * .4));
    front.forEach(c => { c.mode = 'fall'; });
    await Promise.all(front.map((c, i) => sleep(reduce ? 0 : Math.min(2200, i * (n > 20 ? 40 : 110))).then(() => {
      const z0 = c.z, x0 = c.x, spinX = (Math.random() - .5) * 8;
      return S.tween(reduce ? 1 : 900, u => {
        if (u < .3) { c.z = lerp(z0, EDGE + .2, u / .3); }
        else { const v = (u - .3) / .7; c.z = EDGE + .2 + v * .9; c.y = .035 - v * v * 1.55; c.rx = spinX * v; c.x = x0 + v * (Math.random() - .5) * .1; }
      }).then(() => { const k = coins.indexOf(c); if (k >= 0) coins.splice(k, 1); api().clink && api().clink(); });
    })));
    // refill the back so the pile never runs dry
    for (let i = 0; i < n; i++) addCoin(-2.8 + Math.random() * 5.6, lerp(PUSH_FWD, 0, Math.random()), .035 + (Math.random() < .3 ? .07 : 0));
  }
  host._g3d = {
    lane: 50,
    async play(fd) {
      const d = await post(playUrl('pusher'), fd);
      await dropCoin(d.lane);
      await sleep(reduce ? 0 : 500);
      await spill(d.coins);
      if (d.jackpot) { hud(host, `<b>AVALANCHE!</b><span>${d.coins} coins</span>`, 'big'); burstAt(host, 30); }
      else if (d.coins) burstAt(host, Math.min(18, 4 + d.coins * 2));
      return d;
    },
  };
  // click the board to aim
  host.addEventListener('pointerdown', e => {
    const r = host.getBoundingClientRect(), lane = clamp(Math.round((e.clientX - r.left) / r.width * 100), 0, 100);
    host.dispatchEvent(new CustomEvent('lane', { detail: lane }));
  });
  host.classList.add('ready');
}

/* ═════════════════════════ 3D SLOT CABINET ═════════════════════════ */
function svgImage(svg, size = 192) {
  return new Promise(res => {
    const img = new Image(); img.width = img.height = size;
    img.onload = () => res(img); img.onerror = () => res(null);
    img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="${size}" height="${size}">${svg}</svg>`);
  });
}
export async function slotCabinet(el) {
  const cfg = el._vs.cfg;
  const win = $('.vs-window', el);
  let host = $('.vs-3d', win);
  if (!host) { host = document.createElement('div'); host.className = 'vs-3d'; host.innerHTML = '<canvas></canvas>'; win.appendChild(host); }
  const cs = getComputedStyle(el);
  const tile = cs.getPropertyValue('--vs-tile').trim() || '#101a33', accent = cs.getPropertyValue('--vs-accent').trim() || '#ffd98a';
  const frame = cs.getPropertyValue('--vs-frame').trim() || '#e8b64c';
  const S = stage(host, { bg: new T.Color(cs.getPropertyValue('--vs-bg1').trim() || '#0b1020').getHex(), fov: 30 });
  const { scene, camera, renderer } = S;
  renderer.toneMapping = T.NoToneMapping;
  scene.add(new T.AmbientLight(0xffffff, 1.35));
  const key = new T.DirectionalLight(0xffffff, 1.6); key.position.set(0, 2.5, 8); scene.add(key);
  const glow = new T.PointLight(new T.Color(accent), 6, 12); glow.position.set(0, 3, 3); scene.add(glow);
  const imgs = {};
  await Promise.all(Object.entries(cfg.art).map(async ([k, svg]) => { imgs[k] = await svgImage(svg); }));
  const SLOTS = 12, PX = 192, syms = Object.keys(cfg.art);
  const R = 2.05, STEP = Math.PI * 2 / SLOTS, W = 1.02, EDGE = R * Math.sin(1.5 * STEP) + .06;
  const reels = [];
  for (let i = 0; i < 5; i++) {
    const cvs = document.createElement('canvas'); cvs.width = PX * SLOTS; cvs.height = PX;
    const tex = new T.CanvasTexture(cvs); tex.colorSpace = T.SRGBColorSpace; tex.anisotropy = 8;
    const strip = Array.from({ length: SLOTS }, () => syms[Math.floor(Math.random() * syms.length)]);
    const mat = new T.MeshStandardMaterial({ map: tex, roughness: .55, metalness: 0 });
    const mesh = new T.Mesh(new T.CylinderGeometry(R, R, W * .94, 96, 1, true), mat);
    mesh.rotation.z = Math.PI / 2;           // axis along x
    const g = new T.Group(); g.add(mesh); g.position.set((i - 2) * W, 0, -R + .9); scene.add(g);
    const reel = { cvs, tex, strip, mat, g, angle: 0, hi: new Set() };
    paint(reel); reels.push(reel);
  }
  function paint(reel) {
    const x = reel.cvs.getContext('2d');
    for (let s = 0; s < SLOTS; s++) {
      x.fillStyle = s % 2 ? tile : shade(tile, 8); x.fillRect(s * PX, 0, PX, PX);
      // canvas x wraps around the cylinder (shows as screen-up), canvas y runs along the axis (screen-right): draw rotated 90°
      const im = imgs[reel.strip[s]];
      if (im) { x.save(); x.translate(s * PX + PX / 2, PX / 2); x.rotate(Math.PI / 2); x.drawImage(im, -PX * .42, -PX * .42, PX * .84, PX * .84); x.restore(); }
      if (reel.hi.has(s)) { x.strokeStyle = accent; x.lineWidth = 10; x.strokeRect(s * PX + 6, 6, PX - 12, PX - 12); }
    }
    reel.tex.needsUpdate = true;
  }
  function shade(hex, amt) { const c = new T.Color(hex); c.offsetHSL(0, 0, amt / 100); return '#' + c.getHexString(); }
  // cylinder u runs around the circumference; slot s is centred at angle theta_s. Find which slot faces the camera.
  // slot s is centred at theta=(s+.5)·STEP; after rotating the mesh by angle a the slot at theta=a faces the camera,
  // and larger theta sits higher on screen (so row 0 = slot+1, row 1 = slot, row 2 = slot-1)
  const frontSlot = reel => ((Math.round(reel.angle / STEP - .5) % SLOTS) + SLOTS) % SLOTS;
  // chrome frame + bulbs
  const chrome = new T.MeshStandardMaterial({ color: new T.Color(frame), metalness: .9, roughness: .25 });
  const bar = (w, h, x, y) => { const m = new T.Mesh(new T.BoxGeometry(w, h, .3), chrome); m.position.set(x, y, 1.05); scene.add(m); };
  const HW = W * 2.5 + .08;
  bar(HW * 2 + .1, .14, 0, EDGE); bar(HW * 2 + .1, .14, 0, -EDGE); bar(.14, EDGE * 2 + .1, -HW, 0); bar(.14, EDGE * 2 + .1, HW, 0);
  for (let i = 1; i < 5; i++) bar(.05, EDGE * 2, -W * 2.5 + i * W, 0);
  const bulbs = [];
  for (let i = 0; i < 22; i++) { const m = new T.Mesh(new T.SphereGeometry(.06, 12, 10), new T.MeshStandardMaterial({ color: new T.Color(accent), emissive: new T.Color(accent), emissiveIntensity: 1 })); m.position.set(-HW + i * (HW * 2 / 21), EDGE + .16, 1.1); scene.add(m); bulbs.push(m); const m2 = m.clone(); m2.material = m.material.clone(); m2.position.y = -EDGE - .16; scene.add(m2); bulbs.push(m2); }
  let party = 0;
  S.tick((dt, t) => {
    reels.forEach(r => { r.g.children[0].rotation.x = r.angle; });
    bulbs.forEach((b, i) => { b.material.emissiveIntensity = party > 0 ? (Math.sin(t * 16 + i) > 0 ? 3 : .2) : (Math.floor(t * 6 + i / 2) % 4 === 0 ? 2.5 : .6); });
    if (party > 0) party -= dt;
    camera.position.x = Math.sin(t * .4) * .08; camera.position.y = Math.sin(t * .3) * .04;
    camera.lookAt(0, 0, 0);
  });
  camera.position.set(0, 0, 7.4); camera.lookAt(0, 0, 0);
  // frame the 5-reel window to fill the canvas whatever its aspect
  const fit = () => { const a = host.clientWidth / Math.max(1, host.clientHeight), vH = Math.max((EDGE + .35) * 2, (HW + .25) * 2 / a); camera.position.z = 1.05 + vH / 2 / Math.tan(15 * Math.PI / 180); };
  new ResizeObserver(fit).observe(host); fit();

  el._v3d = {
    async spin(grid, teases, turbo) {
      reels.forEach(r => { r.hi.clear(); });
      await Promise.all(reels.map((r, i) => {
        // write the result onto the back of the cylinder, then rotate it round to the front
        const f = frontSlot(r), k = (f + SLOTS / 2) % SLOTS;
        r.strip[(k + 1) % SLOTS] = grid[i][0]; r.strip[k] = grid[i][1]; r.strip[(k + SLOTS - 1) % SLOTS] = grid[i][2];
        paint(r);
        const from = r.angle, want = (k + .5) * STEP, TAU = Math.PI * 2;
        const to = from + (((want - from) % TAU) + TAU) % TAU + TAU * (2 + Math.floor(i / 2) + (turbo ? 0 : 1) + (teases[i] ? 1 : 0));
        const dur = (turbo ? 700 : 1300) + i * (turbo ? 120 : 260) + (teases[i] || 0);
        return S.tween(dur, u => { r.angle = lerp(from, to, easeOutQuart(u)) + (u > .85 ? Math.sin((u - .85) / .15 * Math.PI) * .05 : 0); }).then(() => { r.angle = to; });
      }));
    },
    highlight(cells) {
      reels.forEach(r => r.hi.clear());
      cells.forEach(([ri, y]) => { const r = reels[ri]; const k = frontSlot(r); r.hi.add((k + 1 - y + SLOTS) % SLOTS); });
      reels.forEach(paint);
      if (cells.length) party = 1.2;
    },
    party() { party = 3; },
  };
  host.classList.add('ready');
  el.classList.add('cab3d');
}

JS;
}
/* ═════════════════════════ THE FLOOR: first-person 3D casino (ES module) ═════════════════════════ */
// [[REGION floor-js]]
function floor_js(): string {
    return <<<'JS'
/* Gold Tide: The Floor. Placeholder until the floor module lands. */
const shell = document.querySelector('[data-floor]');
if (shell) { const l = shell.querySelector('.floor-loading'); if (l) l.textContent = 'The floor is being built. Check back soon.'; }
JS;
}
// [[/REGION floor-js]]

/* ═════════════════════════ POKER CLIENT (ES module, shared by the poker page and the floor HUD) ═════════════════════════ */
// [[REGION poker-js]]
function poker_js(): string {
    return <<<'JS'
/* Gold Tide: poker client. Placeholder until the poker client lands. */
const room = document.querySelector('[data-poker-room]');
if (room) { const l = room.querySelector('.poker-loading'); if (l) l.textContent = 'The card room is being built. Check back soon.'; }
JS;
}
// [[/REGION poker-js]]

function g3d_version(): string { static $v = null; return $v ??= substr(md5(g3d_js()), 0, 10); }
function css_version(): string { static $v = null; return $v ??= substr(md5(app_css()), 0, 10); }
function floor_version(): string { static $v = null; return $v ??= substr(md5(floor_js()), 0, 10); }
function poker_version(): string { static $v = null; return $v ??= substr(md5(poker_js()), 0, 10); }
function serve_asset(string $f): never {
    header('X-Content-Type-Options: nosniff');
    header('Content-Type: text/javascript; charset=utf-8');
    header('Cache-Control: ' . (isset($_GET['v']) ? 'public, max-age=31536000, immutable' : 'no-cache'));
    header('Vary: Accept-Encoding');
    if ($f === 'css') { header('Content-Type: text/css; charset=utf-8'); echo app_css(); exit; }
    if ($f === 'floor') { echo floor_js(); exit; }
    if ($f === 'poker') { echo poker_js(); exit; }
    if ($f === 'glb') {
        // optional hand-made floor (e.g. exported from Blender) dropped in data/floor.glb replaces the procedural room
        $file = DATA_DIR . '/floor.glb';
        if (!is_file($file)) { http_response_code(404); echo '// no floor.glb'; exit; }
        header('Content-Type: model/gltf-binary'); header('Content-Length: ' . filesize($file)); readfile($file); exit;
    }
    if ($f === 'three') {
        $gz = three_gz();
        if (str_contains($_SERVER['HTTP_ACCEPT_ENCODING'] ?? '', 'gzip') && !ini_get('zlib.output_compression')) {
            header('Content-Encoding: gzip'); header('Content-Length: ' . strlen($gz)); echo $gz;
        } else { echo gzdecode($gz); }
        exit;
    }
    if ($f === 'g3d') { echo g3d_js(); exit; }
    http_response_code(404); echo '// not found'; exit;
}

/* ═════════════════════════ ROUTER ═════════════════════════ */

function play(callable $fn, string $page): never {
    csrf_check();
    $r = $fn();
    if (wants_json()) { ok($r); }
    $_SESSION['last'][$page] = $r;
    flash(!empty($r['payout']) || !empty($r['amount']) ? 'ok' : 'info', $r['message'] ?? 'Done.');
    redirect($page !== '' ? url($page) : ($_SERVER['HTTP_REFERER'] ?? url()));
}

function route(): void {
    if (($_GET['action'] ?? '') === 'asset') { serve_asset((string)($_GET['f'] ?? '')); }
    start_session();
    db();
    $action = (string)($_GET['action'] ?? '');
    $post = method() === 'POST';

    $postRoutes = [
        'register' => fn() => do_register(),
        'login' => fn() => do_login(),
        'logout' => function () { csrf_check(); unset($_SESSION['pid'], $_SESSION['last']); session_regenerate_id(true); redirect(url()); },
        'play_slots' => fn() => play('slots_spin', 'slots'),
        'play_blackjack' => fn() => play('blackjack_act', 'blackjack'),
        'play_roulette' => fn() => play('roulette_spin', 'roulette'),
        'play' => fn() => play_game(),
        'fair' => fn() => fair_rotate(),
        'rt_ticket' => fn() => do_rt_ticket(),
        'claim_daily' => fn() => play('claim_daily', ''),
        'claim_refill' => fn() => play('claim_refill', ''),
        'redeem' => fn() => play('redeem_promo', ''),
        'player_password' => fn() => do_player_password(),
        'take_break' => fn() => do_take_break(),
        'admin_login' => fn() => do_admin_login(),
        'admin_logout' => fn() => do_admin_logout(),
        'admin_save' => fn() => do_admin_save(require_admin()),
        'admin_delete' => fn() => do_admin_delete(require_admin()),
        'admin_bulk' => fn() => do_admin_bulk(require_admin()),
        'admin_password' => fn() => do_admin_password(require_admin()),
    ];
    $getRoutes = [
        '' => fn() => page_lobby(),
        'slots' => fn() => page_slots(),
        'blackjack' => fn() => page_blackjack(),
        'roulette' => fn() => page_roulette(),
        'leaderboard' => fn() => page_leaderboard(),
        'account' => fn() => page_account(),
        'login' => fn() => page_login(),
        'register' => fn() => page_register(),
        'rules' => fn() => page_rules(),
        'floor' => fn() => page_floor(),
        'poker' => fn() => page_poker(),
        'poker_hand' => fn() => page_poker_hand(),
        'api_me' => function () {
            $p = current_player();
            ok($p ? ['username' => $p['username'], 'balance' => (int)$p['balance'], 'daily' => daily_status($p), 'refill' => refill_status($p), 'on_break' => on_break($p)] : null);
        },
        'admin_login' => fn() => page_admin_login(),
        'admin' => fn() => page_admin_dash(require_admin()),
        'admin_list' => fn() => page_admin_list(require_admin()),
        'admin_view' => fn() => page_admin_view(require_admin()),
        'admin_edit' => fn() => page_admin_edit(require_admin()),
        'admin_password' => fn() => page_admin_password(require_admin()),
        'admin_export' => fn() => do_admin_export(require_admin()),
    ];

    foreach (array_keys(GAME_ENGINES) as $slug) { $getRoutes[$slug] = fn() => page_game($slug); }
    if ($post && isset($postRoutes[$action])) { $postRoutes[$action](); return; }
    if (!$post && isset($getRoutes[$action])) { $getRoutes[$action](); return; }
    if (isset($postRoutes[$action]) || isset($getRoutes[$action])) {
        header('Allow: ' . ($post ? 'GET' : 'POST'));
        error_page(405, 'Wrong door', 'That page doesn\'t take that kind of request.');
    }
    error_page(404, 'Nothing here', 'That page wandered off. The lobby is always open though.');
}

/* ═════════════════════════ STYLES ═════════════════════════
 * "Pacific deco": art-deco casino gold over a San Diego sunset harbor.
 * Fonts are embedded (Limelight display, Figtree body, Chivo Mono numbers; all OFL).
 */
function app_css(): string {
    return <<<'CSS'
@font-face{font-family:"Limelight";font-weight:400;font-display:swap;src:url(data:font/woff2;base64,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) format("woff2")}
@font-face{font-family:"Figtree";font-weight:300 900;font-display:swap;src:url(data:font/woff2;base64,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) format("woff2")}
@font-face{font-family:"Chivo Mono";font-weight:500;font-display:swap;src:url(data:font/woff2;base64,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) format("woff2")}

:root{
  --bg:#0a0f1f;--bg2:#111a33;--bg3:#18244a;--ink:#f5ecd7;--muted:#a9a18c;--line:rgba(232,182,76,.22);
  --gold:#e8b64c;--gold2:#ffd98a;--gold-ink:#1a1204;--coral:#ff6f59;--sea:#2bb3a3;--felt:#0e4a43;--felt2:#0a3934;
  --red:#d6283f;--black:#1c1c24;--green:#1b8a5a;--pos:#55d69a;--neg:#ff7d6b;
  --link:#ffd98a;--gold-text:#ffd98a;--card:rgba(17,26,51,.72);--card-solid:#121b36;--shadow:0 18px 50px -20px rgba(0,0,0,.7);
  --glow1:rgba(255,111,89,.35);--glow2:rgba(232,182,76,.28);--glow3:rgba(43,179,163,.18);
  --radius:18px;--pad:clamp(16px,2.4vw,28px);--gap:clamp(14px,2vw,24px);
  --f-display:"Limelight","Didot","Bodoni 72",Georgia,serif;
  --f-body:"Figtree","Avenir Next","Segoe UI Variable","Helvetica Neue",sans-serif;
  --f-mono:"Chivo Mono","SF Mono",Menlo,Consolas,monospace;
  color-scheme:dark;
}
@media (prefers-color-scheme:light){:root:not([data-theme="dark"]){
  --bg:#f6eedb;--bg2:#efe2c4;--bg3:#e5d3ab;--ink:#1b1a2e;--muted:#6d6450;--line:rgba(120,84,18,.22);
  --gold:#a8740c;--gold2:#c9901d;--gold-ink:#fff8e6;--coral:#d4452c;--sea:#127a6e;--felt:#1b6b5e;--felt2:#15574c;
  --link:#7a4d00;--gold-text:#855700;--pos:#12825a;--neg:#c73b27;--card:rgba(255,252,243,.78);--card-solid:#fffaf0;--shadow:0 18px 40px -22px rgba(80,50,10,.45);
  --glow1:rgba(255,120,90,.28);--glow2:rgba(232,182,76,.35);--glow3:rgba(43,179,163,.15);color-scheme:light}}
:root[data-theme="light"]{
  --bg:#f6eedb;--bg2:#efe2c4;--bg3:#e5d3ab;--ink:#1b1a2e;--muted:#6d6450;--line:rgba(120,84,18,.22);
  --gold:#a8740c;--gold2:#c9901d;--gold-ink:#fff8e6;--coral:#d4452c;--sea:#127a6e;--felt:#1b6b5e;--felt2:#15574c;
  --link:#7a4d00;--gold-text:#855700;--pos:#12825a;--neg:#c73b27;--card:rgba(255,252,243,.78);--card-solid:#fffaf0;--shadow:0 18px 40px -22px rgba(80,50,10,.45);
  --glow1:rgba(255,120,90,.28);--glow2:rgba(232,182,76,.35);--glow3:rgba(43,179,163,.15);color-scheme:light}
:root[data-density="compact"]{--pad:14px;--gap:12px}

*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;min-height:100vh;font:400 16px/1.55 var(--f-body);color:var(--ink);background:var(--bg);
  background-image:
    radial-gradient(1200px 520px at 78% -8%,var(--glow1),transparent 60%),
    radial-gradient(900px 500px at 8% 4%,var(--glow2),transparent 62%),
    radial-gradient(1000px 700px at 50% 110%,var(--glow3),transparent 60%),
    repeating-linear-gradient(135deg,transparent 0 22px,rgba(232,182,76,.025) 22px 23px);
  background-attachment:fixed;overflow-x:hidden;isolation:isolate}
body::before{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;background:inherit;background-attachment:scroll}
body::after{content:"";position:fixed;inset:0;pointer-events:none;z-index:100;opacity:.07;mix-blend-mode:overlay;
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='180' height='180'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.85' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E")}
a{color:var(--link)}a:hover{color:var(--coral)}
img,svg{max-width:100%}
:focus-visible{outline:3px solid var(--gold2);outline-offset:3px;border-radius:6px}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.skip{position:absolute;left:-999px;top:8px;background:var(--gold);color:var(--gold-ink);padding:8px 14px;border-radius:8px;z-index:200}
.skip:focus{left:12px}
code{font-family:var(--f-mono);font-size:.9em;background:var(--bg3);padding:.1em .4em;border-radius:5px}
small{font-size:.75em;color:var(--muted)}
.muted{color:var(--muted)}.pos{color:var(--pos)}.neg{color:var(--neg)}
.fine{font-size:.85rem;color:var(--muted);margin:.4em 0}

/* type */
.display{font-family:var(--f-display);font-weight:400;letter-spacing:.01em;line-height:1.02;margin:.1em 0 .25em}
.display.xl{font-size:clamp(3rem,9vw,7.2rem);background:linear-gradient(180deg,var(--gold2),var(--gold) 55%,var(--coral));-webkit-background-clip:text;background-clip:text;color:transparent;text-shadow:0 0 60px rgba(232,182,76,.15)}
.display.lg{font-size:clamp(2.1rem,5vw,3.4rem)}
.display.md{font-size:1.45rem;color:var(--gold-text)}
.display.sm{font-size:1.2rem}
.display small{font-family:var(--f-body);font-size:.45em;letter-spacing:.08em;text-transform:uppercase}
.eyebrow{font:700 .72rem/1 var(--f-body);letter-spacing:.28em;text-transform:uppercase;color:var(--coral);margin:0 0 .6em}
.eyebrow a{color:inherit;text-decoration:none}
.lead{font-size:clamp(1.05rem,2vw,1.3rem);color:var(--muted);max-width:40ch}

/* header */
.announce{background:linear-gradient(90deg,var(--coral),var(--gold));color:#1a0e04;text-align:center;font-weight:700;padding:8px 16px;font-size:.92rem}
.top{position:sticky;top:0;z-index:50;display:flex;align-items:center;gap:18px;padding:12px clamp(16px,3vw,40px);
  background:color-mix(in srgb,var(--bg) 78%,transparent);backdrop-filter:blur(14px) saturate(1.3);-webkit-backdrop-filter:blur(14px);border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:10px;text-decoration:none;color:var(--ink)!important;flex-shrink:0}
.brand-mark .coin{filter:drop-shadow(0 0 10px rgba(232,182,76,.5));transition:transform .6s cubic-bezier(.2,.8,.2,1)}
.brand:hover .coin{transform:rotateY(180deg) scale(1.08)}
.brand-name{font:400 1.45rem/1 var(--f-display);color:var(--gold-text)}
.brand-name small{font:600 .62rem var(--f-body);letter-spacing:.2em;text-transform:uppercase;color:var(--coral);margin-left:4px}
.nav{display:flex;gap:4px;flex:1;overflow-x:auto;scrollbar-width:none}
.nav a{padding:8px 12px;border-radius:999px;text-decoration:none;color:var(--muted)!important;font-weight:600;font-size:.93rem;white-space:nowrap;transition:color .2s,background .2s}
.nav a:hover{color:var(--ink)!important;background:var(--bg3)}
.nav a[aria-current="page"]{color:var(--gold-ink)!important;background:var(--gold)}
.me{display:flex;align-items:center;gap:10px;margin-left:auto}
.me form{margin:0}
.balance{display:flex;align-items:center;gap:6px;padding:6px 12px 6px 8px;border:1px solid var(--line);border-radius:999px;background:var(--card);text-decoration:none;color:var(--ink)!important;font:500 .98rem var(--f-mono)}
.balance em{font-style:normal;color:var(--muted);font-size:.72rem}
.balance.bump{animation:bump .6s cubic-bezier(.2,.9,.3,1.4)}
@keyframes bump{40%{transform:scale(1.12);box-shadow:0 0 0 6px rgba(232,182,76,.2)}}
.who{font-weight:700;color:var(--ink)!important;text-decoration:none;max-width:12ch;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.icon-btn{display:grid;place-items:center;width:38px;height:38px;border-radius:50%;border:1px solid var(--line);background:var(--card);color:var(--ink);cursor:pointer;transition:transform .3s}
.icon-btn:hover{transform:rotate(-20deg)}

/* buttons */
.btn{--b:var(--bg3);--c:var(--ink);display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:11px 20px;border-radius:999px;border:1px solid transparent;
  background:var(--b);color:var(--c)!important;font:700 .95rem var(--f-body);letter-spacing:.02em;text-decoration:none;cursor:pointer;
  transition:transform .18s cubic-bezier(.2,.8,.2,1),box-shadow .2s,filter .2s;position:relative;overflow:hidden}
.btn:hover:not(:disabled){transform:translateY(-2px);box-shadow:0 10px 24px -10px rgba(0,0,0,.6)}
.btn:active:not(:disabled){transform:translateY(1px) scale(.98)}
.btn:disabled{opacity:.45;cursor:not-allowed}
.btn.gold{--b:linear-gradient(180deg,var(--gold2),var(--gold));--c:var(--gold-ink);background:linear-gradient(180deg,var(--gold2),var(--gold));box-shadow:inset 0 1px 0 rgba(255,255,255,.5),0 6px 20px -8px rgba(232,182,76,.7)}
.btn.gold::after{content:"";position:absolute;inset:0;background:linear-gradient(110deg,transparent 30%,rgba(255,255,255,.45) 50%,transparent 70%);transform:translateX(-120%);transition:transform .7s}
.btn.gold:hover::after{transform:translateX(120%)}
.btn.ghost{background:transparent;border-color:var(--line);--c:var(--ink)}
.btn.ghost:hover:not(:disabled){border-color:var(--gold)}
.btn.coral{background:var(--coral);--c:#1d0703}
.btn.sm{padding:7px 14px;font-size:.85rem}.btn.lg{padding:14px 26px;font-size:1.02rem}.btn.xl{padding:18px 44px;font-size:1.25rem;letter-spacing:.12em;text-transform:uppercase}
.btn.wide{width:100%}

/* layout */
main{padding:clamp(18px,4vw,48px) clamp(16px,4vw,48px) 60px;max-width:1280px;margin:0 auto}
.panel{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:var(--pad);box-shadow:var(--shadow);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);margin-bottom:var(--gap)}
.panel.narrow{max-width:520px;margin-inline:auto}
.panel.wide{max-width:860px;margin-inline:auto}
.panel.flush{padding:0;overflow:hidden}
.more{display:inline-block;margin-top:10px;font-weight:700;text-decoration:none}
.note{border-left:3px solid var(--gold);background:var(--bg3);padding:10px 14px;border-radius:8px;font-size:.92rem}
.note.warn{border-color:var(--coral)}
.table-head{margin-bottom:var(--gap)}
.table-head.row{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;flex-wrap:wrap}
.head-actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.scroll-x{overflow-x:auto}

/* reveal choreography */
.reveal{opacity:0;transform:translateY(18px);animation:rise .8s cubic-bezier(.2,.8,.2,1) forwards}
.d1{animation-delay:.05s}.d2{animation-delay:.15s}.d3{animation-delay:.27s}.d4{animation-delay:.4s}.d5{animation-delay:.55s}.d6{animation-delay:.7s}
@keyframes rise{to{opacity:1;transform:none}}

/* hero */
.hero{position:relative;overflow-x:clip;display:grid;min-height:min(46vh,440px);align-items:center;padding:clamp(24px,5vw,60px) 0;margin-bottom:var(--gap);isolation:isolate}
.sunburst{position:absolute;z-index:-1;right:-12%;top:50%;width:min(900px,120vw);aspect-ratio:1;transform:translateY(-50%);border-radius:50%;
  background:repeating-conic-gradient(from 0deg,rgba(232,182,76,.16) 0 6deg,transparent 6deg 12deg);
  -webkit-mask:radial-gradient(circle,#000 18%,transparent 68%);mask:radial-gradient(circle,#000 18%,transparent 68%);animation:turn 120s linear infinite}
.sunburst::after{content:"";position:absolute;inset:36%;border-radius:50%;background:radial-gradient(circle at 50% 60%,var(--coral),var(--gold) 55%,transparent 72%);filter:blur(6px);opacity:.75}
@keyframes turn{to{transform:translateY(-50%) rotate(360deg)}}
.hero-copy{max-width:640px}
.welcome{font-size:1.15rem}

/* ═════ LOBBY: desert dusk ═════
 * Earth tones of the inland San Diego backcountry: canyon brown, terracotta, turquoise, sandstone, sage, ochre.
 * The woven band is a generic geometric pattern. Partner motif slot: when a partner nation supplies and approves
 * its own artwork, replace --weave (and the mesa_svg() ridgelines) with it. Nothing here copies a specific nation's designs.
 */
body.pg-lobby{
  --bg:#1a0f0b;--bg2:#2a1811;--bg3:#3a2216;--ink:#f3e6d0;--muted:#bba58b;--line:rgba(217,164,65,.24);
  --gold:#d9a441;--gold2:#f0c46a;--gold-ink:#1f1208;--coral:#c8553d;--sea:#3fb8a9;--link:#f0c46a;--gold-text:#f0c46a;
  --card:rgba(46,26,18,.74);--card-solid:#2c1a12;--sage:#8fa37a;--clay:#a8432f;
  --glow1:rgba(200,85,61,.30);--glow2:rgba(217,164,65,.22);--glow3:rgba(63,184,169,.14);
  --m-sky1:#140d24;--m-sky2:#3a1b33;--m-sky3:#7a3526;--m-sun1:#ffd98a;--m-sun2:#e0703f;--m-r1:#5a3550;--m-r2:#3d2233;--m-r3:#1a0f0b;--m-star:#f3e6d0;
  --weave:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='64' height='18' viewBox='0 0 64 18'%3E%3Crect width='64' height='18' fill='%232a1811'/%3E%3Crect y='1' width='64' height='1.5' fill='%23d9a441'/%3E%3Crect y='15.5' width='64' height='1.5' fill='%23d9a441'/%3E%3Cpath d='M16 4l5 5-5 5-5-5z' fill='%233fb8a9'/%3E%3Cpath d='M16 7l2 2-2 2-2-2z' fill='%232a1811'/%3E%3Cpath d='M48 4l5 5-5 5-5-5z' fill='%23c8553d'/%3E%3Cpath d='M48 7l2 2-2 2-2-2z' fill='%23f3e6d0'/%3E%3Cpath d='M21 9l3.5-3 3.5 3 3.5 3 3.5-3 3.5-3 3.5 3M53 9l3.5-3 3.5 3 3.5 3M-3 12l3.5-3 3.5-3 3.5 3' stroke='%23f3e6d0' stroke-width='1.3' fill='none'/%3E%3C/svg%3E");
  background-image:radial-gradient(1000px 600px at 70% 30%,var(--glow1),transparent 60%),radial-gradient(900px 600px at 10% 90%,var(--glow3),transparent 60%),
    repeating-linear-gradient(90deg,transparent 0 3px,rgba(243,230,208,.012) 3px 4px);
}
@media (prefers-color-scheme:light){:root:not([data-theme="dark"]) body.pg-lobby{
  --bg:#f3e4cc;--bg2:#ead3b0;--bg3:#e2c49a;--ink:#2b1a12;--muted:#6e5642;--line:rgba(140,70,30,.24);
  --gold:#a8651a;--gold2:#c47f2a;--gold-ink:#fff7ea;--coral:#b4452c;--sea:#1d8a80;--link:#8a4a12;--gold-text:#8a4a12;
  --card:rgba(255,248,236,.82);--card-solid:#fff7ea;--sage:#5f7a4e;--clay:#9c3b27;
  --glow1:rgba(224,112,63,.22);--glow2:rgba(217,164,65,.25);--glow3:rgba(29,138,128,.12);
  --m-sky1:#f7d9b0;--m-sky2:#f2b98a;--m-sky3:#e8946a;--m-sun1:#fff3c4;--m-sun2:#f0a04b;--m-r1:#b98a9a;--m-r2:#8f6a6e;--m-r3:#f3e4cc;--m-star:transparent}}
:root[data-theme="light"] body.pg-lobby{
  --bg:#f3e4cc;--bg2:#ead3b0;--bg3:#e2c49a;--ink:#2b1a12;--muted:#6e5642;--line:rgba(140,70,30,.24);
  --gold:#a8651a;--gold2:#c47f2a;--gold-ink:#fff7ea;--coral:#b4452c;--sea:#1d8a80;--link:#8a4a12;--gold-text:#8a4a12;
  --card:rgba(255,248,236,.82);--card-solid:#fff7ea;--sage:#5f7a4e;--clay:#9c3b27;
  --glow1:rgba(224,112,63,.22);--glow2:rgba(217,164,65,.25);--glow3:rgba(29,138,128,.12);
  --m-sky1:#f7d9b0;--m-sky2:#f2b98a;--m-sky3:#e8946a;--m-sun1:#fff3c4;--m-sun2:#f0a04b;--m-r1:#b98a9a;--m-r2:#8f6a6e;--m-r3:#f3e4cc;--m-star:transparent}
.pg-lobby .hero{overflow-x:visible;min-height:min(60vh,560px);align-items:start;padding-bottom:clamp(130px,17vw,210px)}
.mesa{position:absolute;z-index:-1;inset:-140px auto 0 50%;width:100vw;transform:translateX(-50%);background:linear-gradient(180deg,var(--m-sky1),var(--m-sky2) 45%,var(--m-sky3) 80%,var(--bg))}
.mesa svg{position:absolute;inset:0;width:100%;height:100%}
.m-stars circle{fill:var(--m-star);opacity:.7}.m-stars .tw{animation:twinkle 3.5s ease-in-out infinite}
@keyframes twinkle{50%{opacity:.15}}
.m-sun{fill:var(--m-sun1);filter:drop-shadow(0 0 30px var(--m-sun2))}.m-glow{opacity:.85}
.m-r1{fill:var(--m-r1)}.m-r2{fill:var(--m-r2)}.m-r3{fill:var(--m-r3)}
.pg-lobby .hero .display{color:#fff3e0;text-shadow:0 4px 30px rgba(0,0,0,.45)}
.pg-lobby .hero .lead,.pg-lobby .hero .welcome,.pg-lobby .hero .fine{color:#f3e6d0;text-shadow:0 1px 10px rgba(0,0,0,.5)}
.pg-lobby .hero .eyebrow{color:#f0c46a}
:root[data-theme="light"] .pg-lobby .hero .display{color:#3a1d12;text-shadow:0 2px 20px rgba(255,240,210,.7)}
:root[data-theme="light"] .pg-lobby .hero .lead,:root[data-theme="light"] .pg-lobby .hero .welcome,:root[data-theme="light"] .pg-lobby .hero .fine{color:#3a2418;text-shadow:none}
:root[data-theme="light"] .pg-lobby .hero .eyebrow{color:#8a3a1a}
@media (prefers-color-scheme:light){:root:not([data-theme="dark"]) .pg-lobby .hero .display{color:#3a1d12;text-shadow:0 2px 20px rgba(255,240,210,.7)}
  :root:not([data-theme="dark"]) .pg-lobby .hero .lead,:root:not([data-theme="dark"]) .pg-lobby .hero .welcome,:root:not([data-theme="dark"]) .pg-lobby .hero .fine{color:#3a2418;text-shadow:none}
  :root:not([data-theme="dark"]) .pg-lobby .hero .eyebrow{color:#8a3a1a}}
.weave{height:18px;margin:-18px 0 calc(var(--gap)*1.4);position:relative;left:50%;width:100vw;transform:translateX(-50%);background:var(--weave) repeat-x center/auto 18px;box-shadow:0 6px 20px rgba(0,0,0,.35)}
.pg-lobby .cat-slots{--acc:#c8553d}.pg-lobby .cat-worlds{--acc:#3fb8a9}.pg-lobby .cat-reels{--acc:var(--sage)}
.pg-lobby .cat-tables{--acc:#d9a441}.pg-lobby .cat-cards{--acc:var(--clay)}.pg-lobby .cat-arcade{--acc:#5fc6b8}
.pg-lobby .cat-head{border-bottom:0;padding-bottom:16px;background:var(--weave) left bottom/auto 8px repeat-x;position:relative}
.pg-lobby .cat-head h2{color:var(--gold-text)}
.pg-lobby .cat-head h2::before{content:"";display:inline-block;width:.55em;height:.55em;margin-right:.45em;vertical-align:.12em;background:var(--acc);transform:rotate(45deg);box-shadow:0 0 0 3px var(--bg),0 0 0 5px var(--acc)}
.pg-lobby .game-card{border-radius:22px 22px 22px 6px;background:linear-gradient(170deg,var(--card-solid),var(--card));border-color:color-mix(in srgb,var(--acc,var(--gold)) 32%,transparent);padding-top:28px}
.pg-lobby .game-card::before{background:radial-gradient(circle at 88% 0%,color-mix(in srgb,var(--acc,var(--gold)) 34%,transparent),transparent 62%)}
.pg-lobby .game-card::after{content:"";position:absolute;left:0;right:0;top:0;height:8px;background:var(--weave) left center/auto 8px repeat-x;opacity:.9}
.pg-lobby .game-card:hover{border-color:var(--acc,var(--gold));box-shadow:0 20px 50px -22px color-mix(in srgb,var(--acc,var(--gold)) 70%,transparent)}
.pg-lobby .game-card .play{color:var(--acc,var(--gold))}
.pg-lobby .featured{background:radial-gradient(120% 100% at 85% 0%,#8a3f2a,#4a2233 45%,#1c1230);box-shadow:inset 0 0 0 2px rgba(217,164,65,.45),var(--shadow)}
.pg-lobby .featured::after{content:"";position:absolute;left:0;right:0;bottom:0;height:10px;background:var(--weave) left center/auto 10px repeat-x}
.pg-lobby .bonus-card{border-radius:18px 18px 18px 6px}
@media (max-width:720px){.pg-lobby .hero{min-height:0;padding-bottom:170px}.mesa svg{height:100%}}

/* bonus */
.bonus-strip{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:var(--gap);margin-bottom:calc(var(--gap)*1.5)}
.bonus-card{background:linear-gradient(160deg,var(--bg3),var(--card-solid));border:1px solid var(--line);border-radius:var(--radius);padding:18px 20px;display:flex;flex-direction:column;gap:8px;position:relative;overflow:hidden}
.bonus-card::before{content:"";position:absolute;inset:auto -30px -30px auto;width:110px;height:110px;border-radius:50%;background:radial-gradient(circle,var(--glow2),transparent 70%)}
.bonus-card h3{margin:0;font:400 1.15rem var(--f-display);color:var(--gold-text)}
.bonus-card p{margin:0;color:var(--muted)}
.bonus-card .btn{align-self:flex-start;margin-top:auto}
.inline{display:flex;gap:8px}.inline input{flex:1;min-width:0}

/* game cards */
.games{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:var(--gap);margin-bottom:calc(var(--gap)*1.5)}
.game-card{position:relative;display:flex;flex-direction:column;padding:22px;border-radius:24px;text-decoration:none;color:var(--ink)!important;overflow:hidden;
  border:1px solid var(--line);background:var(--card);box-shadow:var(--shadow);transition:transform .35s cubic-bezier(.2,.8,.2,1),border-color .3s}
.game-card::before{content:"";position:absolute;inset:0;z-index:-1;opacity:.9}
.g-slots::before{background:radial-gradient(circle at 80% 0%,rgba(255,111,89,.35),transparent 60%)}
.g-blackjack::before{background:radial-gradient(circle at 80% 0%,rgba(43,179,163,.35),transparent 60%)}
.g-roulette::before{background:radial-gradient(circle at 80% 0%,rgba(214,40,63,.35),transparent 60%)}
.game-card:hover{transform:translateY(-6px) rotate(-.4deg);border-color:var(--gold)}
.game-card h2{margin:.3em 0 .2em}.game-card p{margin:0 0 .4em;color:var(--muted)}
.game-art{height:120px;display:flex;align-items:center;gap:6px}
.game-art svg{width:74px;height:74px;transition:transform .5s cubic-bezier(.2,.8,.2,1.4)}
.game-card:hover .game-art svg:nth-child(2){transform:translateY(-10px) rotate(8deg)}
.game-art .card{--w:62px;transform:rotate(-8deg)}.game-art .card+.card{transform:rotate(8deg) translate(-18px,6px)}
.game-card:hover .game-art .card+.card{transform:rotate(14deg) translate(-4px,0)}
.mini-wheel{width:110px!important;height:110px!important;animation:turn2 14s linear infinite}
@keyframes turn2{to{transform:rotate(360deg)}}
.limits{display:flex;align-items:center;gap:6px;font:500 .85rem var(--f-mono);color:var(--muted)!important}
.play{margin-top:auto;padding-top:10px;font-weight:800;color:var(--gold-text);letter-spacing:.06em}

/* leaderboard */
.leader-list{list-style:none;margin:0;padding:0}
.leader-list li{display:grid;grid-template-columns:2.4em 1fr auto;align-items:center;gap:12px;padding:10px 6px;border-bottom:1px dashed var(--line)}
.leader-list li.me{background:var(--bg3);border-radius:10px}
.leader-list .rank{font:500 .9rem var(--f-mono);color:var(--muted);text-align:center}
.leader-list .name{font-weight:700;overflow:hidden;text-overflow:ellipsis}
.leader-list .num{font:500 1rem var(--f-mono)}
.leader-list.big li{padding:14px 8px;font-size:1.08rem}
.podium{display:grid;place-items:center;width:2em;height:2em;border-radius:50%;color:#1a1204!important;font-weight:700}
.p1{background:linear-gradient(180deg,#ffe49a,#e8b64c)}.p2{background:linear-gradient(180deg,#eef0f4,#aab0bd)}.p3{background:linear-gradient(180deg,#f3c49b,#c07a45)}
.tabs{display:flex;gap:6px;flex-wrap:wrap;margin:10px 0 16px}
.tabs a{padding:8px 14px;border:1px solid var(--line);border-radius:999px;text-decoration:none;font-weight:600;color:var(--muted)!important}
.tabs a[aria-current="page"]{background:var(--gold);color:var(--gold-ink)!important;border-color:transparent}
.mini-leaders{max-width:520px}

/* forms */
.form{display:grid;gap:14px}
.form label,.filters label,.ui-settings label{display:grid;gap:6px;font-weight:600;font-size:.9rem}
.form label.check{display:flex;gap:10px;align-items:flex-start;font-weight:500}
input,select,textarea{font:inherit;font-weight:500;color:var(--ink);background:var(--bg2);border:1px solid var(--line);border-radius:12px;padding:11px 13px;width:100%;transition:border-color .2s,box-shadow .2s}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--gold);box-shadow:0 0 0 4px rgba(232,182,76,.18)}
input[type=checkbox],input[type=radio]{width:auto;accent-color:var(--gold);transform:scale(1.2);margin-top:4px}
input[aria-invalid="true"]{border-color:var(--neg)}
textarea.mono{font:.85rem/1.5 var(--f-mono)}
.ferr{color:var(--neg);font-size:.85rem;margin:-8px 0 0;font-weight:600}
.hint{color:var(--muted);font-size:.8rem;margin:4px 0 0}
.auth{margin-top:4vh}

/* toasts */
.toasts{position:fixed;right:16px;bottom:16px;z-index:120;display:grid;gap:10px;max-width:min(380px,calc(100vw - 32px))}
.toast{padding:12px 16px;border-radius:14px;background:var(--card-solid);border:1px solid var(--line);box-shadow:var(--shadow);font-weight:600;animation:toast-in .5s cubic-bezier(.2,.8,.2,1.2)}
.toast.ok{border-color:var(--pos);border-left:5px solid var(--pos)}.toast.err{border-left:5px solid var(--neg)}.toast.info{border-left:5px solid var(--gold)}
.toast.out{animation:toast-out .4s forwards}
@keyframes toast-in{from{opacity:0;transform:translateY(20px) scale(.95)}}
@keyframes toast-out{to{opacity:0;transform:translateX(30px)}}

/* game tables shared */
.table-wrap{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:var(--gap);align-items:start}
.table-wrap>.table-head{grid-column:1/-1;margin:0}
.result{text-align:center;font:400 1.35rem var(--f-display);color:var(--gold-text);min-height:1.6em;margin:12px 0}
.result.win{animation:glow 1.2s ease 2}
@keyframes glow{50%{text-shadow:0 0 24px var(--gold),0 0 4px #fff}}
.controls{display:flex;flex-wrap:wrap;gap:14px;align-items:center;justify-content:center;margin:0}
.ticks{padding-left:0;list-style:none}.ticks li{padding-left:1.4em;position:relative;margin:.4em 0}
.ticks li::before{content:"◆";position:absolute;left:0;color:var(--gold);font-size:.7em;top:.35em}
.chip-radio input{position:absolute;opacity:0;pointer-events:none}
.chip-radio span{display:inline-grid;place-items:center;min-width:58px;height:40px;padding:0 12px;border-radius:999px;border:2px dashed var(--line);font:500 .9rem var(--f-mono);cursor:pointer;transition:all .2s}
.chip-radio input:checked+span{background:var(--gold);color:var(--gold-ink);border:2px solid var(--gold2);transform:translateY(-2px)}
.chip-radio input:focus-visible+span{outline:3px solid var(--gold2);outline-offset:2px}
.bet-pick{border:0;padding:0;margin:0;display:flex;flex-wrap:wrap;gap:8px;justify-content:center}
.bet-pick legend{width:100%;text-align:center;font-size:.8rem;color:var(--muted);letter-spacing:.14em;text-transform:uppercase;margin-bottom:8px}

/* slots */
.machine{position:relative;padding:28px clamp(14px,3vw,34px) 30px;border-radius:32px;
  background:linear-gradient(180deg,#3a1d2e,#1a0f24 40%,#0f1330);border:3px solid var(--gold);
  box-shadow:0 0 0 6px rgba(232,182,76,.12),0 0 60px -10px var(--glow1),var(--shadow)}
:root[data-theme="light"] .machine{background:linear-gradient(180deg,#5b2a3a,#2a1535 45%,#1d2350)}
.marquee{display:flex;justify-content:space-between;margin:-8px 10px 14px}
.marquee span{width:12px;height:12px;border-radius:50%;background:var(--gold2);box-shadow:0 0 10px var(--gold);animation:blink 1.4s infinite}
.marquee span:nth-child(odd){animation-delay:.7s}
.machine.spinning .marquee span{animation-duration:.25s}
@keyframes blink{50%{opacity:.25;box-shadow:none}}
.reels{position:relative;display:grid;grid-template-columns:repeat(3,1fr);gap:10px;padding:12px;border-radius:18px;background:#0b0816;box-shadow:inset 0 8px 30px rgba(0,0,0,.8)}
.reel{--cell:clamp(78px,15vw,124px);height:calc(var(--cell)*3);overflow:hidden;border-radius:12px;background:linear-gradient(180deg,#e9e1cf,#fffaf0 30%,#fffaf0 70%,#e9e1cf);position:relative}
.reel::after{content:"";position:absolute;inset:0;pointer-events:none;background:linear-gradient(180deg,rgba(0,0,0,.35),transparent 22%,transparent 78%,rgba(0,0,0,.35))}
.strip{will-change:transform}
.cell{height:var(--cell);display:grid;place-items:center;padding:14%}
.cell svg{width:100%;height:100%}
.cell.hit{animation:hit .5s ease-in-out 3 alternate}
@keyframes hit{to{transform:scale(1.14);filter:drop-shadow(0 0 10px #ffb627)}}
.reel.blur .strip{filter:blur(1.6px)}
.paylines{position:absolute;inset:12px;width:calc(100% - 24px);height:calc(100% - 24px);pointer-events:none}
.paylines polyline{fill:none;stroke:var(--coral);stroke-width:5;stroke-linecap:round;stroke-linejoin:round;opacity:0;vector-effect:non-scaling-stroke;filter:drop-shadow(0 0 6px var(--coral))}
.paylines polyline.on{opacity:.9;stroke-dasharray:600;stroke-dashoffset:600;animation:draw .7s forwards}
@keyframes draw{to{stroke-dashoffset:0}}
.machine .result{color:#ffd98a}
.machine .bet-pick legend{color:#cbbfa4}
.machine .chip-radio span{color:#f5ecd7;border-color:rgba(232,182,76,.35)}
.machine .chip-radio input:checked+span{color:#1a1204}
.spin-btn{border-radius:22px!important}
.paytable ul{list-style:none;padding:0;margin:0}
.paytable li{display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px dashed var(--line)}
.paytable .syms{display:flex;align-items:center;gap:2px}.paytable .syms svg{width:30px;height:30px}
.paytable .syms i{font-size:.75rem;color:var(--muted);margin-left:6px}
.paytable .num{font:500 1rem var(--f-mono);color:var(--gold-text)}

/* blackjack */
.felt{position:relative;border-radius:180px 180px 28px 28px/120px 120px 28px 28px;padding:36px clamp(16px,4vw,48px) 30px;
  background:radial-gradient(ellipse at 50% 0%,#17705f,var(--felt) 45%,var(--felt2));border:10px solid #5a3a1c;
  box-shadow:inset 0 0 0 2px rgba(232,182,76,.5),inset 0 20px 60px rgba(0,0,0,.45),var(--shadow);color:#f5ecd7}
.felt-rule{text-align:center;font:400 .95rem var(--f-display);letter-spacing:.14em;color:rgba(255,217,138,.55);margin:0 0 10px;text-transform:uppercase}
.hand h2{font:700 .8rem var(--f-body);letter-spacing:.2em;text-transform:uppercase;color:rgba(245,236,215,.75);margin:0 0 10px;display:flex;align-items:center;gap:10px;justify-content:center}
.total{font:500 1rem var(--f-mono);background:rgba(0,0,0,.35);padding:2px 10px;border-radius:999px;color:#ffd98a;letter-spacing:0}
.total:empty,.bet-tag:empty{display:none}
.bet-tag{font:500 .85rem var(--f-mono);background:var(--gold);color:#1a1204;padding:2px 10px;border-radius:999px;letter-spacing:0}
.cards{display:flex;justify-content:center;min-height:140px;padding:4px}
.card{--w:clamp(70px,11vw,96px);width:var(--w);height:calc(var(--w)*1.4);border-radius:10px;background:#fffdf7;color:#1c1c24;position:relative;
  box-shadow:0 8px 18px rgba(0,0,0,.4);margin-left:calc(var(--w)*-.28);font-family:var(--f-display);flex-shrink:0;
  animation:deal .45s cubic-bezier(.2,.8,.2,1) backwards;animation-delay:calc(var(--i,0)*.12s)}
.card:first-child{margin-left:0}
.card.red{color:#c41c32}
.card .r{position:absolute;top:6px;left:8px;font-size:calc(var(--w)*.26);line-height:1}
.card .s{position:absolute;inset:0;display:grid;place-items:center;font-size:calc(var(--w)*.5);font-family:serif}
.card .r2{position:absolute;bottom:6px;right:8px;font-size:calc(var(--w)*.18);transform:rotate(180deg)}
.card.down{background:repeating-linear-gradient(45deg,#8e2336 0 6px,#a12b40 6px 12px);border:4px solid #fffdf7}
.card.down::after{content:"";position:absolute;inset:8px;border:2px solid rgba(255,217,138,.6);border-radius:6px}
@keyframes deal{from{opacity:0;transform:translate(120px,-160px) rotate(-25deg)}}
.felt .result{color:#ffd98a}
.felt .btn.ghost{--c:#f5ecd7;border-color:rgba(255,217,138,.45)}
.bj-bet,.bj-moves{display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:center;width:100%}
.bj-bet label{font-weight:700;color:#f5ecd7}
.bj-bet input{width:130px;background:rgba(0,0,0,.35);color:#fff;border-color:rgba(232,182,76,.4);font-family:var(--f-mono)}
.quick{display:flex;gap:6px}
[hidden]{display:none!important}

/* chips */
.chip{--c1:#e8e2d0;--c2:#b9b2a0;--t:#1b1a2e;width:48px;height:48px;border-radius:50%;border:0;cursor:pointer;font:500 .78rem var(--f-mono);color:var(--t);
  background:radial-gradient(circle,var(--c1) 52%,transparent 53%),repeating-conic-gradient(var(--c1) 0 30deg,var(--c2) 30deg 60deg);
  box-shadow:0 4px 10px rgba(0,0,0,.4),inset 0 0 0 3px rgba(255,255,255,.35);transition:transform .2s}
.chip:hover{transform:translateY(-3px) rotate(-12deg)}
.chip[aria-checked="true"]{transform:translateY(-6px) scale(1.08);box-shadow:0 0 0 3px var(--gold2),0 10px 20px rgba(0,0,0,.5)}
.chip.c10{--c1:#eef1f5;--c2:#6c7bd6}.chip.c25{--c1:#e6f5ec;--c2:#1b8a5a}.chip.c50{--c1:#fbe6e8;--c2:#d6283f}.chip.c100{--c1:#e9e9ef;--c2:#1c1c24}
.chip.c500{--c1:#f2e6fb;--c2:#7b3fb3}.chip.c1000{--c1:#fff3cf;--c2:#d19a1a}

/* roulette */
.rl-wrap{grid-template-columns:1fr}
.rl-top{display:grid;grid-template-columns:minmax(260px,420px) 1fr;gap:var(--gap);align-items:center}
.wheel-box{position:relative;aspect-ratio:1;width:100%;max-width:420px;margin-inline:auto}
.wheel{width:100%;height:100%;transition:transform 5s cubic-bezier(.12,.72,.12,1);filter:drop-shadow(0 20px 40px rgba(0,0,0,.6))}
.pointer{position:absolute;left:50%;top:-4px;transform:translateX(-50%);width:0;height:0;border-left:13px solid transparent;border-right:13px solid transparent;border-top:26px solid var(--gold2);z-index:2;filter:drop-shadow(0 3px 4px rgba(0,0,0,.5))}
.landed{position:absolute;inset:0;display:grid;place-items:center;pointer-events:none}
.landed .n{display:grid;place-items:center;width:25%;aspect-ratio:1;border-radius:50%;font:400 clamp(1.6rem,4vw,2.6rem) var(--f-display);color:#fff;border:3px solid var(--gold2);animation:pop .5s cubic-bezier(.2,.9,.3,1.5)}
.n.red{background:var(--red)}.n.black{background:var(--black)}.n.green{background:var(--green)}
@keyframes pop{from{transform:scale(0)}}
.rl-side{display:grid;gap:14px;justify-items:center;text-align:center}
.chips{display:flex;gap:10px;flex-wrap:wrap;justify-content:center}
.staked{margin:0;font-size:1.05rem}.staked strong{font-family:var(--f-mono)}
.rl-actions{display:flex;gap:10px;flex-wrap:wrap;justify-content:center}
.history{list-style:none;display:flex;gap:6px;padding:0;margin:0;flex-wrap:wrap;justify-content:center}
.history li{display:grid;place-items:center;width:34px;height:34px;border-radius:50%;font:500 .82rem var(--f-mono);color:#fff;animation:pop .4s}
.history li.red{background:var(--red)}.history li.black{background:var(--black);border:1px solid #444}.history li.green{background:var(--green)}
.board-scroll{overflow-x:auto;padding:10px 0 4px;margin-bottom:var(--gap)}
.board{display:grid;grid-template-columns:56px repeat(12,minmax(44px,1fr)) 56px;grid-template-rows:repeat(3,54px) 46px 46px;gap:4px;min-width:720px;
  padding:14px;border-radius:18px;background:radial-gradient(ellipse at 50% 0%,#17705f,var(--felt) 60%,var(--felt2));border:8px solid #5a3a1c}
.board button{position:relative;border:1px solid rgba(255,255,255,.35);border-radius:6px;color:#fff;font:400 1.05rem var(--f-display);cursor:pointer;background:transparent;transition:transform .12s,box-shadow .15s}
.board button:hover{box-shadow:inset 0 0 0 2px var(--gold2);transform:translateY(-1px)}
.board .num.red{background:var(--red)}.board .num.black{background:var(--black)}
.b-zero{grid-row:1/4;grid-column:1;background:var(--green)!important;border-radius:28px 6px 6px 28px!important}
.board .out{font-family:var(--f-body);font-weight:700;font-size:.85rem;background:rgba(0,0,0,.15)}
.board .even-money.red{color:var(--red);font-size:1.5rem;text-shadow:0 0 2px #fff}.board .even-money.black{color:#000;font-size:1.5rem;text-shadow:0 0 2px #fff}
.board .win{animation:winpulse .6s ease 4 alternate}
@keyframes winpulse{to{box-shadow:0 0 0 3px var(--gold2),0 0 24px var(--gold)}}
.stake{position:absolute;right:-6px;top:-8px;min-width:28px;height:28px;padding:0 5px;border-radius:999px;display:grid;place-items:center;font:500 .7rem var(--f-mono);
  background:radial-gradient(circle,#fff3cf 55%,#d19a1a 56%);color:#1a1204;box-shadow:0 3px 6px rgba(0,0,0,.5);z-index:2;animation:pop .25s}

/* account + admin */
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:var(--gap);margin-bottom:var(--gap)}
.tile{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px 18px;display:grid;gap:4px;position:relative;overflow:hidden}
.tile::after{content:"";position:absolute;right:-28px;top:-28px;width:64px;height:64px;border-radius:50%;border:8px solid var(--line);opacity:.6}
.tile span{font-size:.72rem;letter-spacing:.18em;text-transform:uppercase;color:var(--muted);font-weight:700}
.tile strong{font:500 clamp(1.3rem,2.6vw,1.8rem) var(--f-mono)}
.acct-grid,.dash-grid{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(0,1fr);gap:var(--gap)}
.dash-grid{grid-template-columns:repeat(auto-fit,minmax(320px,1fr))}
.stack{display:grid;gap:0;align-content:start}
.break-panel{border-color:rgba(255,111,89,.4)}
.prose h2{font:400 1.35rem var(--f-display);color:var(--gold-text);margin:1.4em 0 .3em}
.prose p,.prose li{color:var(--ink);opacity:.92}
table.data{width:100%;border-collapse:collapse;font-size:.92rem}
table.data th,table.data td{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:middle}
table.data.compact th,table.data.compact td{padding:7px 8px}
:root[data-density="compact"] table.data th,:root[data-density="compact"] table.data td{padding:6px 8px}
table.data th{font-size:.72rem;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);white-space:nowrap;position:sticky;top:0;background:var(--card-solid)}
table.data th a{color:inherit!important;text-decoration:none}
table.data th[aria-sort] a{color:var(--gold-text)!important}
table.data tbody tr{transition:background .15s}
table.data tbody tr:hover{background:var(--bg3)}
table.data .n{text-align:right;font-family:var(--f-mono);font-size:.88rem}
table.data td.cb,table.data th.cb{width:36px}
table.data td.actions{white-space:nowrap;text-align:right}
table.data td.actions a{margin-left:10px;font-weight:600;font-size:.85rem}
table.data .empty{text-align:center;padding:40px;color:var(--muted)}
.pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:.75rem;font-weight:700;background:var(--bg3);color:var(--muted)}
.pill a{text-decoration:none;margin-left:4px}
.pill.ok,.pill.s-active,.pill.s-done{background:rgba(85,214,154,.15);color:var(--pos)}
.pill.s-suspended,.pill.s-void{background:rgba(255,125,107,.15);color:var(--neg)}
.pill.s-wager{color:var(--neg)}.pill.s-payout,.pill.s-daily,.pill.s-promo,.pill.s-refill,.pill.s-signup{color:var(--pos)}.pill.s-admin{color:var(--gold-text)}
.filters{display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end}
.filters label{min-width:120px}.filters .grow{flex:1;min-width:220px}
.filters input,.filters select{padding:8px 10px}
.bulkbar{position:sticky;top:70px;z-index:10;display:flex;flex-wrap:wrap;gap:10px;align-items:center;padding:10px 14px;margin-bottom:10px;border-radius:14px;background:var(--gold);color:var(--gold-ink)}
.bulkbar select,.bulkbar input{width:auto;padding:6px 10px;background:var(--card-solid)}
.bulkbar span{font-weight:800}
.pager{display:flex;gap:10px;align-items:center;justify-content:flex-end}
details.del{display:inline-block;margin-left:10px;position:relative}
details.del summary{cursor:pointer;color:var(--neg);font-weight:600;font-size:.85rem;list-style:none}
details.del summary::-webkit-details-marker{display:none}
details.del[open] form{position:absolute;right:0;top:1.8em;z-index:20;display:grid;gap:8px;padding:12px;min-width:220px;background:var(--card-solid);border:1px solid var(--neg);border-radius:12px;box-shadow:var(--shadow);text-align:left}
details.del label{font-size:.8rem;font-weight:700;display:grid;gap:4px}
.head-actions details.del[open] form{top:2.2em}
.table-links{list-style:none;padding:0;margin:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px}
.table-links a{display:flex;justify-content:space-between;padding:10px 12px;border-radius:10px;background:var(--bg2);text-decoration:none;color:var(--ink)!important;font-weight:600;transition:transform .2s,background .2s}
.table-links a:hover{transform:translateX(4px);background:var(--bg3)}
.table-links b{font-family:var(--f-mono);font-weight:500;color:var(--gold-text)}
.feed{list-style:none;padding:0;margin:0;font-size:.9rem}
.feed li{padding:7px 0;border-bottom:1px dashed var(--line)}
.feed time{font:.78rem var(--f-mono);color:var(--muted);margin-right:6px}
dl.detail{display:grid;grid-template-columns:minmax(120px,200px) 1fr;gap:0;margin:0}
dl.detail dt{padding:10px 0;color:var(--muted);font-size:.8rem;letter-spacing:.1em;text-transform:uppercase;font-weight:700;border-bottom:1px solid var(--line)}
dl.detail dd{margin:0;padding:10px 0;border-bottom:1px solid var(--line);word-break:break-word}
dl.detail pre{margin:0;font:.8rem/1.5 var(--f-mono);white-space:pre-wrap;max-height:360px;overflow:auto;background:var(--bg2);padding:10px;border-radius:10px}
.edit-form{max-width:760px}
.form-actions{display:flex;gap:10px;margin-top:6px}
.ui-settings{border:1px solid var(--line);border-radius:var(--radius);background:var(--card-solid);color:var(--ink);padding:24px;width:min(360px,calc(100vw - 32px))}
.ui-settings form{display:grid;gap:14px}
.ui-settings::backdrop{background:rgba(5,8,18,.6);backdrop-filter:blur(3px)}

/* footer */
.foot{border-top:1px solid var(--line);padding:26px clamp(16px,4vw,48px) 40px;max-width:1280px;margin:0 auto;text-align:center}
.foot .partner{font-family:var(--f-display);color:var(--gold-text);font-size:1rem}

/* ═════ lobby categories + rail ═════ */
.cat{margin-bottom:calc(var(--gap)*1.6);scroll-margin-top:90px}
.cat-head{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap;margin-bottom:12px;border-bottom:1px solid var(--line);padding-bottom:8px}
.cat-head h2{margin:0;font-size:1.8rem}.cat-head p{margin:0}
.games{grid-template-columns:repeat(auto-fill,minmax(250px,1fr))}
.game-card h3{margin:.3em 0 .2em;font-size:1.35rem;color:var(--gold-text)}
.game-art .die{width:52px;height:52px}.game-art .die+.die{transform:rotate(12deg)}
.game-art .crab{width:80px;height:56px}.game-art .crab+.crab{transform:scaleX(-1) translateY(10px)}
.art-wide{width:140px!important;height:90px!important}
.art-balls{display:flex;gap:6px}.art-balls b{display:grid;place-items:center;width:40px;height:40px;border-radius:50%;background:radial-gradient(circle at 35% 30%,#fff,#e9e1cf);color:#1b1a2e;font:500 .95rem var(--f-mono);box-shadow:0 4px 10px rgba(0,0,0,.35)}
.art-balls b.hot{background:radial-gradient(circle at 35% 30%,#ffe49a,#e8b64c)}
.art-arrows{font-size:1.6rem;line-height:1.1;color:var(--coral);margin-left:10px}
.ico-card{display:inline-grid;place-items:center;width:30px;height:40px;border-radius:5px;background:#fffdf7;color:#1c1c24;font:400 .8rem var(--f-display);box-shadow:0 2px 6px rgba(0,0,0,.35)}
.ico-card.red{color:#c41c32}
.rail{margin-top:calc(var(--gap)*1.5)}
.rail-list{display:flex;gap:8px;overflow-x:auto;padding:6px 2px 10px;scrollbar-width:thin}
.rail-list a{display:flex;align-items:center;gap:8px;flex-shrink:0;padding:6px 14px 6px 6px;border:1px solid var(--line);border-radius:999px;background:var(--card);text-decoration:none;color:var(--ink)!important;font-weight:600;font-size:.88rem;transition:transform .2s,border-color .2s}
.rail-list a:hover{transform:translateY(-2px);border-color:var(--gold)}
.rail-list a[aria-current="page"]{background:var(--gold);color:var(--gold-ink)!important}
.rail-list svg,.rail-list .ico-card{width:30px;height:30px;flex-shrink:0}.rail-list .ico-card{height:34px;width:26px;font-size:.62rem}
.rail-list .mini-wheel{width:30px!important;height:30px!important}
.limits-inline{font:500 .8rem var(--f-mono);border:1px solid var(--line);border-radius:999px;padding:1px 8px;margin-left:6px;white-space:nowrap}

/* ═════ shared game stage ═════ */
.game-stage{position:relative;padding:var(--pad);border-radius:28px;border:1px solid var(--line);background:
  radial-gradient(600px 300px at 50% 0%,rgba(43,179,163,.14),transparent 70%),linear-gradient(180deg,var(--card-solid),var(--bg2));box-shadow:var(--shadow);min-width:0}
.game-stage.busy form button:not([type=button]){pointer-events:none}
.pending .after,.pending .stake{visibility:hidden}
.pending .spot.match{box-shadow:none}
.gate{display:grid;justify-items:center;gap:14px;text-align:center;padding:40px 10px}
.gate-art svg,.gate-art .ico-card{width:110px;height:110px}.gate-art .ico-card{width:80px;font-size:1.6rem}
.controls.stacked{flex-direction:column;align-items:stretch;max-width:420px;margin-inline:auto}
.betbox{display:flex;align-items:flex-end;gap:8px;flex-wrap:wrap;justify-content:center}
.betbox label{display:grid;gap:4px;font-weight:700;font-size:.8rem;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
.betbox input{width:140px;font:500 1.05rem var(--f-mono);text-align:center}
.bet-quick{display:flex;border:1px solid var(--line);border-radius:12px;overflow:hidden}
.bet-quick button{background:var(--bg2);color:var(--ink);border:0;border-right:1px solid var(--line);padding:10px 11px;font:600 .8rem var(--f-body);cursor:pointer}
.bet-quick button:last-child{border-right:0}.bet-quick button:hover{background:var(--bg3)}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:999px;padding:3px;background:var(--bg2);gap:2px;align-self:center}
.seg label{position:relative;padding:8px 16px;border-radius:999px;cursor:pointer;font-weight:700;font-size:.88rem;display:block}
.seg input{position:absolute;opacity:0;pointer-events:none}
.seg label:has(input:checked){background:var(--gold);color:var(--gold-ink)}
.seg label:has(input:focus-visible){outline:3px solid var(--gold2)}
.stat-row{display:flex;gap:18px;justify-content:center;font-size:.9rem;color:var(--muted)}.stat-row b{font:500 1rem var(--f-mono);color:var(--ink)}
.big-num{font:400 clamp(3rem,9vw,5.4rem)/1 var(--f-display);letter-spacing:.02em}
.cb{margin-top:var(--gap)}
.cb-bar{display:grid;gap:12px;justify-items:center;margin-bottom:14px}
.btn small{font:500 .72rem var(--f-mono);opacity:.75;margin-left:4px}

/* ═════ dice ═════ */
.dice-stage{display:grid;justify-items:center;gap:14px;margin-bottom:10px}
.dice-track{--t:50%;position:relative;width:100%;height:18px;border-radius:999px;margin:30px 0 26px;background:var(--bg3)}
.dice-zone{position:absolute;inset:0;border-radius:999px}
.dice-track.under .dice-zone{background:linear-gradient(90deg,var(--sea),var(--gold)) 0/var(--t) 100% no-repeat}
.dice-track.over .dice-zone{background:linear-gradient(90deg,var(--gold),var(--coral)) right/calc(100% - var(--t)) 100% no-repeat}
.dice-track::after{content:"";position:absolute;left:var(--t);top:-8px;width:4px;height:34px;margin-left:-2px;background:var(--ink);border-radius:2px}
.dice-marker{position:absolute;left:var(--r);top:50%;transform:translate(-50%,-50%);width:26px;height:26px;border-radius:7px;background:#fffaf0;border:3px solid var(--gold);box-shadow:0 6px 14px rgba(0,0,0,.4);z-index:2}
.dice-marker.win{border-color:var(--pos)}.dice-marker.lose{border-color:var(--neg)}
.dice-marker span{position:absolute;bottom:130%;left:50%;transform:translateX(-50%);font:500 .8rem var(--f-mono);background:var(--card-solid);padding:2px 6px;border-radius:6px;white-space:nowrap}
.dice-scale{position:absolute;top:26px;left:0;right:0;display:flex;justify-content:space-between;font:500 .72rem var(--f-mono);color:var(--muted)}
.slider{display:grid;gap:6px;font-weight:700}
input[type=range]{padding:0;height:8px;accent-color:var(--gold);background:transparent;border:0}

/* ═════ keno ═════ */
.keno-form{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(220px,1fr);gap:var(--gap);align-items:start}
.keno-grid{display:grid;grid-template-columns:repeat(8,1fr);gap:6px}
.kt{position:relative;cursor:pointer}
.kt input{position:absolute;opacity:0}
.kt span{display:grid;place-items:center;aspect-ratio:1;border-radius:50%;font:500 clamp(.8rem,1.8vw,1rem) var(--f-mono);background:var(--bg2);border:2px solid var(--line);transition:transform .15s,background .2s}
.kt:hover span{transform:scale(1.06)}
.kt input:checked+span{background:linear-gradient(180deg,var(--gold2),var(--gold));color:var(--gold-ink);border-color:var(--gold2)}
.kt input:focus-visible+span{outline:3px solid var(--gold2)}
.kt.drawn span{animation:ball-in .4s cubic-bezier(.2,.9,.3,1.5) backwards;animation-delay:calc(var(--i)*.18s);background:var(--sea);color:#fff;border-color:#8ee8dc}
.kt.drawn.hit span{background:radial-gradient(circle at 35% 30%,#fff3cf,#e8b64c);color:#1a1204;border-color:#fff;box-shadow:0 0 16px var(--gold)}
@keyframes ball-in{from{transform:scale(0) rotate(-90deg)}}
.keno-side{display:grid;gap:12px}
.keno-pay td{padding:4px 8px!important}

/* ═════ scratchers ═════ */
.ticket{max-width:460px;margin:0 auto;padding:18px;border-radius:18px;background:linear-gradient(160deg,#ff9a6b,#ff6f59 40%,#c0263a);box-shadow:var(--shadow),inset 0 0 0 3px rgba(255,255,255,.25);position:relative;overflow:hidden}
.ticket::before{content:"";position:absolute;inset:-40%;background:repeating-conic-gradient(rgba(255,217,138,.18) 0 8deg,transparent 8deg 16deg);animation:turn2 60s linear infinite}
.ticket>*{position:relative}
.ticket-head{display:flex;justify-content:space-between;align-items:center;color:#fff}
.ticket-head .display{color:#fff3cf}
.ticket-head .price{font:500 .8rem var(--f-mono);background:rgba(0,0,0,.25);padding:3px 10px;border-radius:999px}
.spots{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:14px 0}
.spot{position:relative;aspect-ratio:1.2;border-radius:12px;background:#fffaf0;display:grid;place-content:center;text-align:center;color:#1b1a2e;overflow:hidden}
.spot .prize{font:400 clamp(1rem,3.5vw,1.45rem) var(--f-display)}.spot small{color:#6d6450}
.spot.match{box-shadow:0 0 0 4px #ffd98a,0 0 20px #ffd98a;animation:hit .5s ease-in-out 3 alternate}
.spot.blank .prize{opacity:.3}
.foil{position:absolute;inset:0;width:100%;height:100%;cursor:crosshair;touch-action:none;border-radius:12px}
.ticket-foot{margin:0;text-align:center;color:#fff3cf;font-weight:700;font-size:.85rem}
.reveal-all{display:block;margin:10px auto 0}

/* ═════ big six ═════ */
.bw-stage{display:grid;justify-items:center;gap:6px}
.wheel-box.bw{max-width:380px}
.bw-board{display:grid;grid-template-columns:repeat(7,1fr);gap:8px}
.bw-spot{position:relative;display:grid;gap:2px;justify-items:center;padding:14px 4px;border-radius:12px;border:2px solid rgba(255,255,255,.25);cursor:pointer;color:#1b1a2e;transition:transform .15s}
.bw-spot b{font:400 1.5rem var(--f-display)}.bw-spot small{font:600 .7rem var(--f-body);opacity:.8}
.bw-spot:hover{transform:translateY(-3px)}
.s-1{background:#efe6d2}.s-2{background:#ffd23f}.s-5{background:#2bb3a3;color:#fff}.s-10{background:#ff6f59;color:#fff}.s-20{background:#8c7ae6;color:#fff}.s-anchor{background:#1b1a2e;color:#ffd98a}.s-sun{background:#ffb627}
.win{animation:winpulse .6s ease 4 alternate}

/* ═════ sic bo ═════ */
.sb-stage{display:grid;justify-items:center}
.dice-cup{display:flex;gap:16px;padding:18px 26px;border-radius:999px;background:radial-gradient(ellipse,#17705f,var(--felt2));border:6px solid #5a3a1c;box-shadow:inset 0 10px 30px rgba(0,0,0,.5)}
.die.big{width:clamp(56px,11vw,84px);height:auto;filter:drop-shadow(0 8px 10px rgba(0,0,0,.45))}
.die.tumble{animation:tumble .9s cubic-bezier(.2,.7,.3,1) backwards}
.die.tumble:nth-child(2){animation-delay:.08s}.die.tumble:nth-child(3){animation-delay:.16s}
@keyframes tumble{0%{transform:translateY(-60px) rotate(-340deg) scale(.6);opacity:0}60%{transform:translateY(6px) rotate(20deg)}80%{transform:translateY(-4px) rotate(-6deg)}}
.sb-board{display:grid;gap:6px;padding:12px;border-radius:18px;background:radial-gradient(ellipse at 50% 0%,#17705f,var(--felt) 60%,var(--felt2));border:8px solid #5a3a1c}
.sb-row{display:grid;gap:6px}
.sb-row.sb-top{grid-template-columns:repeat(3,1fr)}.sb-row.totals{grid-template-columns:repeat(7,1fr)}.sb-row.faces{grid-template-columns:repeat(6,1fr)}.sb-row.singles{grid-template-columns:repeat(6,1fr)}
.sb{position:relative;display:flex;flex-wrap:wrap;gap:2px;align-items:center;justify-content:center;flex-direction:column;padding:8px 4px;min-height:54px;border:1px solid rgba(255,255,255,.35);border-radius:8px;background:rgba(0,0,0,.18);color:#fff;cursor:pointer}
.sb b{font:400 1.05rem var(--f-display)}.sb small{font:600 .66rem var(--f-body);opacity:.8}
.sb:hover{box-shadow:inset 0 0 0 2px var(--gold2)}
.sb .die.mini{width:18px;height:18px;display:inline}.sb .die.mid{width:30px;height:30px}
.sb-row.faces .sb{flex-direction:row}
.sb-row.faces .sb small{width:100%;text-align:center}

/* ═════ crab derby ═════ */
.derby{position:relative;display:grid;gap:6px;padding:14px 16px;border-radius:18px;background:linear-gradient(180deg,#f1d9a8,#e7c486);box-shadow:inset 0 0 0 4px rgba(90,58,28,.3),var(--shadow);overflow:hidden}
.derby::before{content:"";position:absolute;inset:0;background:repeating-linear-gradient(90deg,transparent 0 60px,rgba(255,255,255,.18) 60px 62px)}
.lane{position:relative;display:grid;grid-template-columns:110px 1fr;align-items:center;min-height:46px;border-bottom:2px dashed rgba(90,58,28,.25)}
.lane-name{font:700 .8rem var(--f-body);color:#5a3a1c}
.lane-track{position:relative;height:44px}
.runner{position:absolute;left:calc(var(--x) * .86);top:0;width:60px}
.runner .crab{width:60px;height:42px}
.runner.running .crab{animation:scuttle .18s steps(2) infinite}
@keyframes scuttle{50%{transform:translateY(-3px) rotate(4deg)}}
.rosette{position:absolute;right:-18px;top:-6px;background:var(--coral);color:#fff;font:800 .62rem var(--f-body);padding:3px 6px;border-radius:999px}
.pending .rosette{visibility:hidden}
.finish{position:absolute;right:calc(14% - 26px);top:0;bottom:0;width:10px;background:repeating-linear-gradient(0deg,#1b1a2e 0 10px,#fff 10px 20px)}
.crab-board{display:grid;grid-template-columns:repeat(6,1fr);gap:8px}
.crab-spot{position:relative;display:grid;justify-items:center;gap:2px;padding:10px 4px;border-radius:14px;border:2px solid var(--c);background:var(--card-solid);color:var(--ink);cursor:pointer;transition:transform .15s}
.crab-spot:hover{transform:translateY(-3px)}.crab-spot .crab{width:48px;height:34px}
.crab-spot b{font-size:.82rem}.crab-spot small{font:500 .75rem var(--f-mono);color:var(--muted)}

/* ═════ baccarat ═════ */
.bac-hands{display:grid;grid-template-columns:1fr 1fr;gap:20px}
.slow-deal .card{animation-delay:calc(var(--i)*.5s)}
.bac-board{display:grid;grid-template-columns:1fr .7fr 1fr;gap:10px}
.bac{position:relative;display:grid;justify-items:center;padding:20px 8px;border-radius:16px;border:2px solid rgba(255,255,255,.3);cursor:pointer;color:#fff}
.bac b{font:400 1.4rem var(--f-display);letter-spacing:.06em}.bac small{opacity:.8;font-weight:600}
.bac.player{background:#1f4fa3}.bac.banker{background:#b3263a}.bac.tie{background:var(--green)}
.bac:hover{box-shadow:inset 0 0 0 3px var(--gold2)}

/* ═════ video poker ═════ */
.vp-machine{padding:18px;border-radius:24px;background:linear-gradient(180deg,#1d2350,#0f1330);border:3px solid var(--gold);color:#f5ecd7}
.vp-pay{width:100%;max-width:520px;margin:0 auto 14px;border-collapse:collapse;font:500 .82rem var(--f-mono);color:#ffd98a}
.vp-pay td{padding:3px 10px;border-bottom:1px solid rgba(232,182,76,.15)}.vp-pay td.n{text-align:right}
.vp-pay td:first-child{font-family:var(--f-body);font-weight:700;color:#f5ecd7}
.vp-pay tr.hit{background:var(--coral);color:#fff}.vp-pay tr.hit td{color:#fff}
.vp-cards{display:flex;justify-content:center;gap:clamp(6px,1.4vw,14px);margin:6px 0 4px}
.vp-card{position:relative;display:grid;justify-items:center;gap:6px;cursor:pointer}
.vp-card .card{margin-left:0!important;transition:transform .2s}
.vp-card input{position:absolute;opacity:0}
.hold-tag{font:800 .72rem var(--f-body);letter-spacing:.2em;padding:3px 8px;border-radius:6px;background:rgba(255,255,255,.08);color:transparent}
.vp-card:has(input:checked) .card{transform:translateY(-12px)}
.vp-card input:checked~.hold-tag{background:var(--gold);color:#1a1204}
.vp-card input:focus-visible~.hold-tag{outline:3px solid var(--gold2)}
.vp-card.was-held .card{box-shadow:0 0 0 3px var(--gold)}
.vp-machine .result{color:#ffd98a}
.vp-machine .betbox label{color:#cbbfa4}

/* ═════ three card ═════ */
.tc-felt .controls{margin-top:10px}
.pp{display:grid;gap:4px;font-weight:700;font-size:.8rem;letter-spacing:.08em;text-transform:uppercase;color:#cbbfa4}
.pp input{width:120px;font-family:var(--f-mono);text-align:center;background:rgba(0,0,0,.35);color:#fff;border-color:rgba(232,182,76,.4)}
.felt .betbox label{color:#cbbfa4}.felt .betbox input{background:rgba(0,0,0,.35);color:#fff;border-color:rgba(232,182,76,.4)}

/* ═════ hi-lo ═════ */
.hilo-stage{display:grid;justify-items:center;gap:12px}
.hilo-main .card{--w:clamp(110px,20vw,150px);margin:0}
.trail{display:flex;gap:6px;min-height:70px;flex-wrap:wrap;justify-content:center}
.trail-card{display:grid;justify-items:center;gap:2px;font:700 .75rem var(--f-body)}
.trail-card .card{--w:44px;margin:0;animation:none}
.trail-card.ok>span{color:var(--pos)}.trail-card.bad>span{color:var(--neg)}.trail-card.skipped{opacity:.55}
.hilo-stage .btn.lg{flex-direction:column;gap:2px}

/* ═════ mines ═════ */
.mines-stage{display:grid;grid-template-columns:minmax(0,1.3fr) minmax(220px,1fr);gap:var(--gap);align-items:center}
.reef{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;padding:12px;border-radius:18px;background:radial-gradient(ellipse at 50% 30%,#1b6b8a,#0b2e4a);box-shadow:inset 0 10px 40px rgba(0,0,0,.5)}
.reef-tile{aspect-ratio:1;border-radius:12px;border:0;cursor:pointer;background:linear-gradient(160deg,#3fa7b8,#1d6a86);box-shadow:inset 0 -5px 0 rgba(0,0,0,.25),0 4px 10px rgba(0,0,0,.3);transition:transform .15s,filter .15s;padding:12%}
.reef-tile:not(:disabled):hover{transform:translateY(-3px);filter:brightness(1.15)}
.reef-tile:disabled{cursor:default}
.reef-tile svg{width:100%;height:100%}
.reef-tile.pearl{background:linear-gradient(160deg,#fff3cf,#e8b64c);animation:flip .4s cubic-bezier(.2,.9,.3,1.4)}
.reef-tile.urchin{background:linear-gradient(160deg,#ff9fb2,#8e2336)}.reef-tile.urchin.ghost{opacity:.55}
.reef-tile.boom{animation:boom .5s ease;box-shadow:0 0 0 4px #ff4d4d,0 0 30px #ff4d4d}
@keyframes flip{from{transform:rotateY(90deg)}}
@keyframes boom{30%{transform:scale(1.25)}}
.mines-side{display:grid;gap:10px;justify-items:center;text-align:center}

/* ═════ crash ═════ */
.crash-stage{position:relative;height:clamp(260px,42vw,380px);border-radius:20px;overflow:hidden;background:linear-gradient(180deg,#0b1a33,#0e2b44 60%,#0f4d45);border:1px solid var(--line);margin-bottom:14px}
.crash-graph{position:absolute;inset:36px 0 0 0;width:100%;height:calc(100% - 36px)}
.wave{fill:none;stroke:#5fe0cf;stroke-width:4;stroke-linecap:round;vector-effect:non-scaling-stroke;filter:drop-shadow(0 0 8px #2bb3a3)}
.crash-stage.broke .wave{stroke:var(--coral);filter:drop-shadow(0 0 8px var(--coral))}
.crash-mult{position:absolute;inset:0;display:grid;place-items:center;font:400 clamp(3rem,10vw,6rem) var(--f-display);color:#fff3cf;text-shadow:0 0 30px rgba(255,217,138,.5);pointer-events:none}
.crash-mult.broke{color:var(--coral)}.crash-mult.cashed{color:#5fe0cf}
.crash-stage .result{position:absolute;left:0;right:0;bottom:8px;color:#ffd98a}
.crash-hist{position:absolute;top:8px;left:10px;right:10px;display:flex;gap:6px;overflow:hidden;z-index:2}
.crash-hist span{font:500 .72rem var(--f-mono);padding:2px 8px;border-radius:999px;background:rgba(255,255,255,.08);color:#f5ecd7;flex-shrink:0}
.crash-hist span.hi{color:#5fe0cf}.crash-hist span.lo{color:#ff9f8f}
.auto{display:grid;gap:4px;font-weight:700;font-size:.8rem;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
.auto input{width:130px;font-family:var(--f-mono);text-align:center}

@media (max-width:980px){
  .keno-form,.mines-stage{grid-template-columns:1fr}
}
@media (max-width:720px){
  .bw-board{grid-template-columns:repeat(4,1fr)}
  .crab-board{grid-template-columns:repeat(3,1fr)}
  .sb-row.totals{grid-template-columns:repeat(5,1fr)}.sb-row.faces{grid-template-columns:repeat(3,1fr)}.sb-row.singles{grid-template-columns:repeat(3,1fr)}
  .lane{grid-template-columns:70px 1fr}.lane-name{font-size:.68rem}
  .bac-hands{grid-template-columns:1fr}
  .vp-card .card{--w:clamp(52px,16vw,80px)}
  .bet-quick button{padding:10px 8px}
}

/* ═════ Pearl Drop ═════ */
.g-plinko{grid-template-columns:minmax(0,1fr)}
.g-plinko .house-rules{max-width:none}
.pd{display:grid;gap:14px}
.pd-top{display:flex;align-items:center;gap:12px;justify-content:space-between}
.pd-hist{list-style:none;display:flex;gap:5px;margin:0;padding:0;overflow:hidden;flex:1;min-height:26px;mask-image:linear-gradient(90deg,#000 80%,transparent);-webkit-mask-image:linear-gradient(90deg,#000 80%,transparent)}
.pd-hist li{flex-shrink:0;font:600 .72rem var(--f-mono);padding:4px 8px;border-radius:999px;animation:pop .3s}
.pd-hist .lo{background:#12686e;color:#e8fff9}.pd-hist .mid{background:#ffd23f;color:#1a1204}
.pd-hist .hi{background:#ff9146;color:#1a1204}.pd-hist .top{background:linear-gradient(90deg,#ff5a45,#d6283f);color:#fff;box-shadow:0 0 12px rgba(255,90,69,.6)}
.pd-tools{display:flex;gap:8px;align-items:center}
.icon-btn.muted{opacity:.5}.icon-btn.muted [data-waves]{display:none}
.fair-badge{display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:999px;background:rgba(95,224,207,.12);border:1px solid rgba(95,224,207,.4);color:#5fe0cf!important;font:700 .75rem var(--f-body);letter-spacing:.06em;text-decoration:none;text-transform:uppercase}
:root[data-theme="light"] .fair-badge{color:#0d6b60!important}
.pd-board{position:relative;border-radius:24px;padding:14px 10px 6px;overflow:hidden;
  background:radial-gradient(120% 70% at 50% 0%,#1c5d7d 0%,#0e2f4f 45%,#0a1a33 100%);
  box-shadow:inset 0 0 0 2px rgba(232,182,76,.35),inset 0 -30px 60px rgba(0,0,0,.35),var(--shadow)}
.pd-board::before{content:"";position:absolute;inset:0;pointer-events:none;opacity:.35;mix-blend-mode:screen;
  background:repeating-radial-gradient(circle at 30% -20%,transparent 0 28px,rgba(120,220,255,.07) 30px 32px),repeating-radial-gradient(circle at 80% -10%,transparent 0 40px,rgba(120,220,255,.05) 42px 44px);
  animation:caustic 14s linear infinite alternate}
@keyframes caustic{to{background-position:40px 30px,-30px 20px}}
.pd-board canvas{display:block;width:100%;max-width:min(760px,100%,calc((100vh - 170px) * 1.05));margin:0 auto;position:relative}
.pd-banner{position:absolute;left:50%;top:38%;transform:translate(-50%,-50%) scale(.6);opacity:0;pointer-events:none;text-align:center;display:grid;gap:2px}
.pd-banner b{font:400 clamp(1.8rem,6vw,3.4rem) var(--f-display);color:#ffd98a;text-shadow:0 0 30px rgba(255,182,39,.8),0 4px 0 #8a5a00;letter-spacing:.04em}
.pd-banner span{font:500 clamp(1.2rem,4vw,2rem) var(--f-mono);color:#fff}
.pd-banner.show{animation:banner 2.2s cubic-bezier(.2,.9,.3,1.3) forwards}
@keyframes banner{0%{opacity:0;transform:translate(-50%,-50%) scale(.4) rotate(-6deg)}15%{opacity:1;transform:translate(-50%,-50%) scale(1.08) rotate(2deg)}25%{transform:translate(-50%,-50%) scale(1) rotate(0)}80%{opacity:1}100%{opacity:0;transform:translate(-50%,-60%) scale(1)}}
.pd-result{margin:0}
.center{text-align:center}
.pd-controls{display:grid;gap:14px;padding:16px;border-radius:20px;background:var(--bg2);border:1px solid var(--line)}
.pd-row{display:flex;flex-wrap:wrap;gap:14px;align-items:flex-end;justify-content:center}
.pd-row.main{gap:18px}
.pd-field{display:grid;gap:6px;justify-items:center}
.pd-field>span{font:700 .72rem var(--f-body);letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
.pd-field .seg label{padding:7px 12px}
.seg input:disabled+*,.seg label:has(input:disabled){opacity:.5;cursor:not-allowed}
.pd-total{margin:0;color:var(--muted);font-size:.9rem;align-self:center}.pd-total b{font-family:var(--f-mono);color:var(--ink)}
.pd-drop{min-width:200px}
.pd-auto summary{cursor:pointer;font-weight:700;color:var(--gold-text);text-align:center;list-style:none}
.pd-auto summary::-webkit-details-marker{display:none}
.pd-auto summary::after{content:" ▾"}.pd-auto[open] summary::after{content:" ▴"}
.pd-auto .pd-row{margin-top:12px}
.pd-auto label{display:grid;gap:4px;font-weight:700;font-size:.78rem;color:var(--muted)}
.pd-auto label.check{display:flex;align-items:center;gap:8px;font-size:.9rem;color:var(--ink)}
.pd-auto input[type=number]{width:110px;padding:8px 10px;font-family:var(--f-mono)}
.pd-auto select{padding:8px 10px}
.pd-stats{display:grid;grid-template-columns:repeat(6,1fr) auto;gap:8px;align-items:center}
.pd-stats div{display:grid;gap:2px;padding:8px 10px;border-radius:12px;background:var(--bg2);border:1px solid var(--line)}
.pd-stats span{font:700 .64rem var(--f-body);letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
.pd-stats b{font:500 .95rem var(--f-mono)}
.pd-fair{border:1px solid rgba(95,224,207,.35);border-radius:18px;padding:12px 16px;background:linear-gradient(180deg,rgba(95,224,207,.06),transparent)}
.pd-fair>summary{cursor:pointer;font:400 1.1rem var(--f-display);color:var(--gold-text)}
.fair-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:18px;margin-top:12px}
.fair-grid h3{margin:.2em 0 .5em;font:700 .78rem var(--f-body);letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
.fair-dl{margin:0;display:grid;gap:4px}.fair-dl dt{font-size:.78rem;color:var(--muted)}.fair-dl dd{margin:0 0 6px}
.fair-dl code,.fair-list code{word-break:break-all;font-size:.78rem}
.fair-list{list-style:none;padding:0;margin:0 0 14px;display:grid;gap:4px;font-size:.85rem}
.linkish{background:none;border:0;padding:0;color:var(--link);cursor:pointer;font:inherit;text-align:left;text-decoration:underline}
.fair-out{margin:0;white-space:pre-wrap;font:.78rem/1.55 var(--f-mono);background:var(--bg2);border:1px solid var(--line);border-radius:10px;padding:10px;min-height:120px}
[data-fair-verify] .inline{gap:8px}[data-fair-verify] .inline label{flex:1;min-width:0}
.featured{position:relative;display:grid;grid-template-columns:1.2fr 1fr;gap:var(--gap);align-items:center;margin-bottom:calc(var(--gap)*1.6);padding:clamp(18px,3vw,32px);border-radius:28px;text-decoration:none;color:#f5ecd7!important;overflow:hidden;
  background:radial-gradient(120% 90% at 80% 0%,#1c5d7d,#0e2f4f 50%,#0a1a33);box-shadow:inset 0 0 0 2px rgba(232,182,76,.4),var(--shadow);transition:transform .35s cubic-bezier(.2,.8,.2,1)}
.featured:hover{transform:translateY(-4px)}
.featured .eyebrow{color:#ffd98a}
.featured h2{font:400 clamp(2.2rem,6vw,3.8rem)/1 var(--f-display);margin:.1em 0 .2em;background:linear-gradient(180deg,#fff3cf,#e8b64c);-webkit-background-clip:text;background-clip:text;color:transparent}
.featured ul{list-style:none;padding:0;margin:10px 0 16px;display:flex;flex-wrap:wrap;gap:8px}
.featured li{font:700 .78rem var(--f-body);padding:5px 11px;border-radius:999px;background:rgba(255,255,255,.08);border:1px solid rgba(255,217,138,.3)}
.featured-art svg{width:100%;height:auto;max-height:260px}
.featured-art .fpeg{fill:#f5ecd7;opacity:.75}.featured-art .gpeg{fill:#ffd98a;filter:drop-shadow(0 0 6px #ffb627)}
.featured-art .fpearl{animation:fall 2.6s cubic-bezier(.5,0,.7,1) infinite}
@keyframes fall{0%{transform:translate(0,-10px)}20%{transform:translate(-12px,40px)}40%{transform:translate(0,80px)}60%{transform:translate(12px,120px)}80%{transform:translate(24px,160px)}100%{transform:translate(12px,190px);opacity:0}}
@media (max-width:720px){
  .pd-stats{grid-template-columns:repeat(3,1fr)}
  .pd-field .seg label{padding:6px 9px;font-size:.8rem}
  .featured{grid-template-columns:1fr}
  .featured-art{display:none}
  .pd-drop{width:100%}
}

/* ═════ Slot Hall ═════ */
.g-vslot{grid-template-columns:minmax(0,1fr)}
.g-vslot .game-stage{padding:0;background:none;border:0;box-shadow:none}
.vs{--vs-bg1:#0b1020;--vs-bg2:#111a33;--vs-frame:#e8b64c;--vs-frame2:#8a5a00;--vs-tile:#101a33;--vs-tile2:#0b1224;--vs-accent:#ffd98a;--vs-glow:rgba(232,182,76,.55);--vs-text:#f5ecd7;--vs-font:var(--f-display);
  position:relative;display:grid;gap:14px;padding:clamp(14px,2.4vw,26px);border-radius:28px;overflow:hidden;isolation:isolate;color:var(--vs-text);
  background:radial-gradient(120% 80% at 50% 0%,var(--vs-bg2),var(--vs-bg1));box-shadow:var(--shadow),inset 0 0 0 1px rgba(255,255,255,.06)}
.vs-fx{position:absolute;inset:0;width:100%;height:100%;z-index:-1;pointer-events:none}
.vs-deco{position:absolute;inset:0;z-index:-1;pointer-events:none}
.vs-machine{position:relative;max-width:900px;width:100%;margin:0 auto;padding:14px 14px 12px;border-radius:26px;
  background:linear-gradient(180deg,color-mix(in srgb,var(--vs-frame) 40%,#000) 0%,color-mix(in srgb,var(--vs-frame2) 60%,#000) 100%);
  box-shadow:0 0 0 3px var(--vs-frame),0 0 50px -8px var(--vs-glow),0 30px 60px -20px rgba(0,0,0,.8),inset 0 2px 0 rgba(255,255,255,.25)}
.vs-marquee{display:flex;align-items:center;gap:12px;justify-content:space-between;padding:4px 8px 10px;flex-wrap:wrap}
.vs-title{font:400 clamp(1.4rem,3.6vw,2.2rem)/1 var(--vs-font);color:var(--vs-accent);text-shadow:0 0 18px var(--vs-glow),0 2px 0 rgba(0,0,0,.5);letter-spacing:.02em}
.vs-badges{display:flex;gap:6px;flex-wrap:wrap}
.vs-badges b{font:700 .66rem var(--f-body);letter-spacing:.14em;padding:4px 9px;border-radius:999px;background:rgba(0,0,0,.35);border:1px solid color-mix(in srgb,var(--vs-accent) 50%,transparent);color:var(--vs-accent)}
.vs-snd{background:rgba(0,0,0,.3);color:var(--vs-accent);border-color:color-mix(in srgb,var(--vs-accent) 40%,transparent)}
.vs-fsbar{display:flex;justify-content:center;align-items:baseline;gap:8px;margin:-2px 0 8px;padding:6px 12px;border-radius:12px;background:linear-gradient(90deg,transparent,color-mix(in srgb,var(--vs-accent) 30%,transparent),transparent);font:700 .8rem var(--f-body);letter-spacing:.12em;animation:fspulse 1.2s ease-in-out infinite alternate}
.vs-fsbar b{font:500 1.2rem var(--f-mono);color:var(--vs-accent)}
@keyframes fspulse{to{filter:brightness(1.35)}}
.vs-window{position:relative;border-radius:18px;padding:8px;background:rgba(0,0,0,.55);box-shadow:inset 0 6px 24px rgba(0,0,0,.8)}
.vs-reels{display:grid;grid-template-columns:repeat(5,1fr);gap:6px}
.vs-reel{--cell:clamp(58px,14.5vw,150px);height:calc(var(--cell)*3);overflow:hidden;border-radius:12px;position:relative;
  background:linear-gradient(180deg,var(--vs-tile2),var(--vs-tile) 25%,var(--vs-tile) 75%,var(--vs-tile2))}
.vs-reel::after{content:"";position:absolute;inset:0;pointer-events:none;background:linear-gradient(180deg,rgba(0,0,0,.45),transparent 18%,transparent 82%,rgba(0,0,0,.45))}
.vs-reel.spinning .vs-strip{filter:blur(1.2px) saturate(1.2)}
.vs-reel.tease{box-shadow:0 0 0 3px var(--vs-accent),0 0 30px var(--vs-glow);animation:tease .35s ease-in-out infinite alternate}
@keyframes tease{to{box-shadow:0 0 0 3px #fff,0 0 44px var(--vs-glow)}}
.vs-strip{will-change:transform}
.vs-cell{height:var(--cell);display:grid;place-items:center;padding:9%;transition:opacity .25s,filter .25s,transform .25s}
.vs-cell svg{width:100%;height:100%;filter:drop-shadow(0 4px 6px rgba(0,0,0,.45))}
.vs-cell.dim{opacity:.28;filter:grayscale(.6)}
.vs-cell.hit{animation:vshit .55s ease-in-out infinite alternate;position:relative;z-index:1}
.vs-cell.hit svg{filter:drop-shadow(0 0 12px var(--vs-accent)) drop-shadow(0 4px 6px rgba(0,0,0,.45))}
.vs-cell.scat{animation:vsscat .45s ease-in-out infinite alternate}
@keyframes vshit{to{transform:scale(1.1)}}
@keyframes vsscat{to{transform:scale(1.16) rotate(4deg);filter:brightness(1.4)}}
.vs-banner{position:absolute;inset:0;display:grid;place-content:center;text-align:center;pointer-events:none;opacity:0;z-index:5;border-radius:18px}
.vs-banner b{font:400 clamp(2rem,7vw,4.4rem)/1 var(--vs-font);color:var(--vs-accent);text-shadow:0 0 30px var(--vs-glow),0 4px 0 rgba(0,0,0,.6);letter-spacing:.04em}
.vs-banner span{font:600 clamp(1rem,2.6vw,1.5rem) var(--f-mono);color:#fff;margin-top:8px}
.vs-banner.show{animation:vsbanner var(--dur,2.4s) cubic-bezier(.2,.9,.3,1.2) forwards;background:radial-gradient(circle,rgba(0,0,0,.72),rgba(0,0,0,.35) 70%)}
.vs-banner.tier.epic b{font-size:clamp(2.6rem,9vw,5.6rem);background:linear-gradient(180deg,#fff,var(--vs-accent),#ff6f59);-webkit-background-clip:text;background-clip:text;color:transparent}
@keyframes vsbanner{0%{opacity:0;transform:scale(.5)}12%{opacity:1;transform:scale(1.08)}20%{transform:scale(1)}85%{opacity:1}100%{opacity:0}}
.vs-winbar{display:flex;align-items:center;gap:12px;padding:10px 8px 2px;flex-wrap:wrap}
.vs-winlabel{font:700 .7rem var(--f-body);letter-spacing:.2em;color:color-mix(in srgb,var(--vs-text) 60%,transparent)}
.vs-winamt{font:500 clamp(1.3rem,3vw,1.8rem) var(--f-mono);color:var(--vs-accent);min-width:5ch;text-shadow:0 0 14px var(--vs-glow)}
.vs-msg{flex:1;text-align:right;font-size:.88rem;color:color-mix(in srgb,var(--vs-text) 80%,transparent);min-width:180px}
.vs-controls{display:flex;flex-wrap:wrap;gap:14px;align-items:flex-end;justify-content:center;max-width:900px;margin:0 auto;width:100%}
.vs-controls .betbox label{color:color-mix(in srgb,var(--vs-text) 70%,transparent)}
.vs-controls .betbox input{background:rgba(0,0,0,.35);color:#fff;border-color:color-mix(in srgb,var(--vs-accent) 40%,transparent)}
.vs-controls .bet-quick button{background:rgba(0,0,0,.35);color:var(--vs-text);border-color:rgba(255,255,255,.1)}
.vs-spin{min-width:190px;border-radius:999px!important;background:linear-gradient(180deg,#fff,var(--vs-accent) 40%,color-mix(in srgb,var(--vs-accent) 60%,#000))!important;color:#140d02!important;box-shadow:0 0 30px -4px var(--vs-glow),inset 0 1px 0 #fff!important}
.vs.spinning .vs-spin{filter:saturate(.6) brightness(.8)}
.vs-auto{display:flex;flex-wrap:wrap;gap:10px;align-items:center}
.vs-auto label{display:flex;gap:6px;align-items:center;font-size:.85rem;font-weight:600;color:color-mix(in srgb,var(--vs-text) 80%,transparent)}
.vs-auto select{width:auto;padding:6px 8px;background:rgba(0,0,0,.35);color:#fff}
.vs .btn.ghost{color:var(--vs-text)!important;border-color:color-mix(in srgb,var(--vs-accent) 35%,transparent)}
.vs-pay{max-width:900px;width:100%;margin:0 auto;padding:10px 14px;border-radius:16px;background:rgba(0,0,0,.35);border:1px solid rgba(255,255,255,.08)}
.vs-pay summary{cursor:pointer;font:400 1.05rem var(--vs-font);color:var(--vs-accent)}
.vs-paygrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:10px;margin:12px 0}
.vs-payrow{display:flex;gap:10px;align-items:center;padding:6px;border-radius:12px;background:rgba(255,255,255,.04)}
.vs-payicon{width:54px;height:54px;flex-shrink:0;border-radius:10px;background:var(--vs-tile);padding:3px}
.vs-payicon svg{width:100%;height:100%}
.vs-payrow b{display:block;font-size:.9rem}.vs-payrow small{font-size:.76rem;color:color-mix(in srgb,var(--vs-text) 75%,transparent)}
.vs-payrow small.mono{font-family:var(--f-mono)}
.vs .fine{color:color-mix(in srgb,var(--vs-text) 65%,transparent)}
.vs.freespins .vs-machine{box-shadow:0 0 0 3px var(--vs-accent),0 0 80px 0 var(--vs-glow),0 30px 60px -20px rgba(0,0,0,.8)}

/* per-theme looks */
.vs-abyss{--vs-bg1:#020b1a;--vs-bg2:#0a3a5c;--vs-frame:#3fe0d0;--vs-frame2:#0b4d6b;--vs-tile:#06213a;--vs-tile2:#031426;--vs-accent:#7ff9e6;--vs-glow:rgba(63,224,208,.55);--vs-text:#e2fbff}
.vs-abyss .vs-deco{background:radial-gradient(60% 40% at 50% 115%,rgba(255,111,160,.18),transparent),linear-gradient(0deg,rgba(0,0,0,.4),transparent 30%)}
.vs-tinfoil{--vs-bg1:#07061a;--vs-bg2:#241a4d;--vs-frame:#c7cde0;--vs-frame2:#4b4f66;--vs-tile:#171336;--vs-tile2:#0c0a22;--vs-accent:#9dff9a;--vs-glow:rgba(120,255,140,.45);--vs-text:#eef0ff}
.vs-tinfoil .vs-deco{background:linear-gradient(0deg,#2b1406 0%,#6b3310 8%,transparent 22%)}
.vs-tinfoil .vs-machine{background:repeating-linear-gradient(115deg,#8d94aa 0 6px,#d8dcec 6px 9px,#6d738a 9px 16px)}
.vs-blacksite{--vs-bg1:#050608;--vs-bg2:#141a22;--vs-frame:#ff2d44;--vs-frame2:#2a2f38;--vs-tile:#0f1319;--vs-tile2:#07090c;--vs-accent:#5fe6ff;--vs-glow:rgba(255,45,68,.45);--vs-text:#dfe9f2;--vs-font:var(--f-mono)}
.vs-blacksite .vs-machine{background:repeating-linear-gradient(135deg,#1a1f27 0 14px,#232a34 14px 28px);box-shadow:0 0 0 2px #ff2d44,0 0 0 6px #111,0 0 0 8px #ffb000,0 0 50px -8px var(--vs-glow),0 30px 60px -20px rgba(0,0,0,.8)}
.vs-blacksite .vs-title{text-transform:uppercase;letter-spacing:.12em;font-weight:500}
.vs-coderain{--vs-bg1:#000;--vs-bg2:#021a0c;--vs-frame:#00ff66;--vs-frame2:#003318;--vs-tile:#010c05;--vs-tile2:#000;--vs-accent:#39ff88;--vs-glow:rgba(0,255,102,.5);--vs-text:#c8ffd9;--vs-font:var(--f-mono)}
.vs-coderain .vs-machine{background:#010904;box-shadow:0 0 0 2px #00ff66,0 0 40px -6px var(--vs-glow),inset 0 0 40px rgba(0,255,102,.12)}
.vs-coderain .vs-title{letter-spacing:.2em;text-transform:uppercase}
.vs-tiki{--vs-bg1:#1a0903;--vs-bg2:#6b2a0c;--vs-frame:#e7a24a;--vs-frame2:#5a2c10;--vs-tile:#3a1a0c;--vs-tile2:#220e05;--vs-accent:#ffcf5c;--vs-glow:rgba(255,140,40,.55);--vs-text:#fff1dc}
.vs-tiki .vs-machine{background:repeating-linear-gradient(90deg,#6a3b16 0 22px,#7c4a1d 22px 26px,#5a3010 26px 48px);box-shadow:0 0 0 4px #c8893f,0 0 0 7px #3a1a0a,0 0 50px -8px var(--vs-glow),0 30px 60px -20px rgba(0,0,0,.8)}
.vs-tiki .vs-deco{background:radial-gradient(80% 50% at 50% 120%,rgba(255,110,40,.35),transparent),radial-gradient(40% 25% at 50% -5%,rgba(255,200,120,.25),transparent)}
.vs-calavera{--vs-bg1:#12051f;--vs-bg2:#3a0e52;--vs-frame:#ff9f1c;--vs-frame2:#7a1f6b;--vs-tile:#260b3a;--vs-tile2:#170626;--vs-accent:#ffc93c;--vs-glow:rgba(255,79,163,.5);--vs-text:#fff0fa}
.vs-calavera .vs-deco{background:
  linear-gradient(90deg,#ff4fa3 0 16.6%,#ff9f1c 16.6% 33.3%,#3fe0d0 33.3% 50%,#e8ff5a 50% 66.6%,#b04bff 66.6% 83.3%,#ff4fa3 83.3%) top/100% 22px no-repeat}
.vs-calavera .vs-deco::after{content:"";position:absolute;left:0;right:0;top:22px;height:14px;background:radial-gradient(circle at 8px 0,transparent 7px,var(--vs-bg2) 8px) 0 0/16px 14px repeat-x}
.vs-calavera .vs-machine{margin-top:18px}
.vs-tinfoil .vs-marquee,.vs-tinfoil .vs-winbar,.vs-tiki .vs-marquee,.vs-tiki .vs-winbar{background:rgba(8,6,20,.72);border-radius:14px;padding:8px 12px;margin-bottom:8px}
.vs-tinfoil .vs-winbar,.vs-tiki .vs-winbar{margin:8px 0 0}
@media (max-width:720px){
  .vs-msg{text-align:left}
  .vs-spin{width:100%}
  .vs-reels{gap:3px}.vs-window{padding:4px}
}

/* ═════ embed mode: a game page shown on a machine screen inside the floor ═════ */
.embed .top,.embed .foot,.embed .rail,.embed .house-rules,.embed .table-head,.embed .announce,.embed .skip{display:none!important}
.embed main{padding:10px;max-width:none}
.embed .table-wrap{grid-template-columns:minmax(0,1fr)}
.embed .game-stage{border-radius:14px;padding:12px}
.embed .g3d{max-height:none}
/* ═════ the floor shell ═════ */
/* [[REGION floor-css]] */
.pg-floor main{padding:0;max-width:none}
.pg-floor .foot{display:none}
.pg-floor .top{position:fixed;left:0;right:0;top:0;background:rgba(6,8,16,.72);backdrop-filter:blur(10px)}
.floor-shell{position:fixed;inset:0;background:#05070d;overflow:hidden;touch-action:none}
.floor-css3d,.floor-gl{position:absolute;inset:0;width:100%;height:100%}
.floor-css3d{overflow:hidden;pointer-events:none}
.floor-gl{display:block;touch-action:none}
.floor-loading{position:absolute;inset:0;display:grid;place-content:center;justify-items:center;gap:12px;color:#cbd8e6;font-weight:600;text-align:center;padding:20px}
.floor-loading span{width:38px;height:38px;border-radius:50%;border:4px solid rgba(255,255,255,.15);border-top-color:#ffd98a;animation:spin3d 1s linear infinite}
.floor-card .floor-art svg{width:min(100%,320px);height:auto}
/* [[/REGION floor-css]] */
/* ═════ poker room ═════ */
/* [[REGION poker-css]] */
.poker-room{position:relative;min-height:320px}
.poker-loading{display:grid;place-content:center;justify-items:center;gap:12px;color:var(--muted);font-weight:600;min-height:280px}
.poker-loading span{width:38px;height:38px;border-radius:50%;border:4px solid rgba(255,255,255,.15);border-top-color:#ffd98a;animation:spin3d 1s linear infinite}
.ph-check{padding:14px 16px;border-radius:14px;border:1px solid var(--line);margin:14px 0}
.ph-check.ok{border-color:#4fe0a0;background:rgba(27,138,90,.15)}.ph-check.bad{border-color:#ff7d6b;background:rgba(214,40,63,.15)}
.mono{font-family:var(--f-mono);word-break:break-all}
/* [[/REGION poker-css]] */
/* ═════ 3D games ═════ */
.g-3d{grid-template-columns:minmax(0,1fr)}
.g3d-wrap{position:relative;display:grid;gap:10px;margin-bottom:12px}
.g3d{position:relative;width:100%;aspect-ratio:16/9;min-height:300px;max-height:72vh;border-radius:24px;overflow:hidden;background:radial-gradient(120% 90% at 50% 0%,#15304a,#07121f);box-shadow:var(--shadow),inset 0 0 0 1px rgba(255,255,255,.08);touch-action:manipulation}
.g3d canvas{position:absolute;inset:0;width:100%;height:100%;display:block;opacity:0;transition:opacity .6s}
.g3d.ready canvas{opacity:1}
.g3d-loading{position:absolute;inset:0;display:grid;place-content:center;justify-items:center;gap:12px;color:#cbd8e6;font-weight:600;text-align:center;padding:20px;transition:opacity .4s}
.g3d-loading span{width:38px;height:38px;border-radius:50%;border:4px solid rgba(255,255,255,.15);border-top-color:#ffd98a;animation:spin3d 1s linear infinite}
.g3d.nogl .g3d-loading span{display:none}
.g3d.ready .g3d-loading{opacity:0;pointer-events:none}
@keyframes spin3d{to{transform:rotate(360deg)}}
.g3d-nojs{position:absolute;inset:auto 0 0;padding:10px;text-align:center;color:#fff;background:rgba(0,0,0,.5);margin:0}
.g3d-banner{position:absolute;left:50%;top:40%;transform:translate(-50%,-50%);pointer-events:none;opacity:0;text-align:center;display:grid;gap:4px;z-index:3}
.g3d-banner.show{animation:banner 2.4s cubic-bezier(.2,.9,.3,1.3) forwards}
.g3d-banner b{font:400 clamp(2rem,6vw,3.6rem) var(--f-display);color:#ffd98a;text-shadow:0 0 30px rgba(255,182,39,.8),0 4px 0 #6a4300}
.g3d-banner span{font:600 1.2rem var(--f-mono);color:#fff}
.g3d-banner.num .n{display:grid;place-items:center;width:clamp(80px,14vw,120px);aspect-ratio:1;border-radius:50%;font:400 clamp(2.4rem,6vw,3.6rem) var(--f-display);color:#fff;border:4px solid #ffd98a;box-shadow:0 10px 30px rgba(0,0,0,.6)}
.g3d-banner.num.show{animation:numpop 3.2s cubic-bezier(.2,.9,.3,1.3) forwards}
@keyframes numpop{0%{opacity:0;transform:translate(-50%,-50%) scale(.3)}12%{opacity:1;transform:translate(-50%,-50%) scale(1.1)}20%{transform:translate(-50%,-50%) scale(1)}80%{opacity:1}100%{opacity:0}}
.g3d-bar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.g3d-bar .result{margin:0;text-align:left}
.g3d-bar .history{justify-content:flex-end}
/* craps */
.cr-controls{display:grid;gap:10px;justify-items:center;margin:6px 0 12px}
.cr-bar-r{display:flex;align-items:center;gap:8px}
.cr-point{font:700 .8rem var(--f-body);letter-spacing:.16em;padding:8px 14px;border-radius:999px;background:#16161c;color:#f5f1e8;border:2px solid #555}
.cr-point.on{background:#f5f1e8;color:#16161c;border-color:#ffd98a;box-shadow:0 0 16px rgba(255,217,138,.6)}
.cr-hist{justify-content:flex-start}.cr-hist li{background:#1d3b33;border:1px solid rgba(255,255,255,.2);width:30px;height:30px}.cr-hist li.seven{background:var(--red)}
.cr-hint{margin:0;font-size:.8rem;color:var(--muted);text-align:center}
.cr-log{list-style:none;margin:0;padding:0;display:flex;flex-wrap:wrap;gap:6px;justify-content:center;min-height:6px}
.cr-log li{font:600 .75rem var(--f-body);padding:4px 10px;border-radius:999px;background:var(--card2,rgba(255,255,255,.08));border:1px solid rgba(255,255,255,.15);animation:pop .3s}
.cr-log li.w{background:#1b8a5a;color:#fff;border-color:#4fe0a0}.cr-log li.l{opacity:.65;text-decoration:line-through}
.cr-board{display:grid;gap:8px;padding:12px;border-radius:18px;background:radial-gradient(ellipse at 50% 0%,#17705f,var(--felt) 60%,var(--felt2));border:8px solid #5a3a1c;color:#fff}
.cr-nums{display:grid;grid-template-columns:minmax(64px,.7fr) repeat(6,minmax(0,1fr));gap:6px}
.cr-dcbar{display:grid}
.cr-col{display:grid;gap:4px;grid-template-rows:auto auto auto auto auto auto;align-content:start;padding:4px;border-radius:12px;border:1px solid rgba(255,255,255,.25);background:rgba(0,0,0,.12)}
.cr-col.pt{box-shadow:inset 0 0 0 2px #ffd98a,0 0 14px rgba(255,217,138,.35)}
.cr-num{position:relative;display:grid;place-items:center;min-height:74px;padding:6px 2px;border-radius:10px;background:rgba(255,255,255,.06)}
.cr-num>b{font:400 clamp(1.3rem,3vw,2rem) var(--f-display);color:#ffe7b0;text-shadow:0 2px 0 rgba(0,0,0,.4)}
.cr-puck{position:absolute;left:4px;top:4px;display:none;width:26px;height:26px;border-radius:50%;background:#f5f1e8;color:#16161c;font:800 .55rem var(--f-body);place-items:center;box-shadow:0 2px 6px rgba(0,0,0,.5)}
.cr-col.pt .cr-puck{display:grid}
.cr-cp{display:flex;flex-wrap:wrap;gap:3px;justify-content:center;min-height:4px}
.cr-tok{font:600 .64rem var(--f-mono);padding:3px 6px;border-radius:999px;border:0;background:radial-gradient(circle,#fff3cf 55%,#d19a1a 56%);color:#1a1204;cursor:default}
.cr-tok.dc{background:radial-gradient(circle,#e8e8f0 55%,#1c1c24 56%);color:#16161c}
.cr-tok.win,.cr-num.win{animation:winpulse .6s ease 4 alternate}
.cr-spot{position:relative;display:grid;gap:2px;justify-items:center;align-content:center;padding:12px 6px;border-radius:12px;border:1px solid rgba(255,255,255,.35);background:rgba(0,0,0,.18);color:#fff;cursor:pointer;transition:transform .12s,box-shadow .15s,opacity .15s;font:inherit}
.cr-spot b{font:400 1.05rem var(--f-display);line-height:1.1}.cr-spot small{font-size:.68rem;opacity:.8;text-align:center;line-height:1.2}
.cr-spot.mini{padding:6px 2px;border-radius:8px}.cr-spot.mini b{font:700 .72rem var(--f-body);letter-spacing:.04em;text-transform:uppercase}.cr-spot.mini small{font-size:.6rem}
.cr-spot.lay{background:rgba(0,0,0,.35)}.cr-spot.place{background:rgba(255,217,138,.12)}
.cr-spot.odds{background:rgba(255,255,255,.05);border-style:dashed}
.cr-spot.dark{background:rgba(0,0,0,.4)}.cr-spot.tall{height:100%}
.cr-spot.gold{background:linear-gradient(180deg,rgba(255,217,138,.22),rgba(255,217,138,.06));border-color:#ffd98a}
.cr-spot.red b{color:#ff9a9a}
.cr-spot.big b{font-size:1.25rem;color:#ff9a9a}
.cr-spot:hover:not(:disabled){box-shadow:inset 0 0 0 2px var(--gold2);transform:translateY(-1px)}
.cr-spot:disabled{opacity:.45;cursor:not-allowed}
.cr-spot.working{box-shadow:inset 0 0 0 2px rgba(255,217,138,.6)}
.cr-spot.off::after{content:'OFF';position:absolute;left:4px;top:4px;font:800 .55rem var(--f-body);padding:2px 5px;border-radius:999px;background:#16161c;color:#f5f1e8;border:1px solid #777}
.cr-spot.sel{box-shadow:inset 0 0 0 3px var(--coral),0 0 16px rgba(255,111,89,.55)}
.cr-spot.win{animation:winpulse .6s ease 4 alternate}
.cr-spot .stake{right:-4px;top:-10px;min-width:40px;height:26px;padding:0 8px;font-size:.66rem}
.cr-spot.mini .stake{right:-2px;top:-8px;min-width:30px;height:22px;padding:0 5px;font-size:.6rem}
.cr-spot .stake.add{background:radial-gradient(circle,#e6f5ec 55%,#1b8a5a 56%)}
.cr-art{display:flex;gap:3px}.cr-art .die{width:20px;height:20px}
.cr-row{display:grid;gap:8px}
.cr-come{grid-template-columns:1fr}
.cr-field{grid-template-columns:minmax(80px,.6fr) 3fr minmax(80px,.6fr)}
.cr-line{grid-template-columns:1.1fr .8fr 2fr .8fr}
.cr-props{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:6px;padding:8px;border-radius:14px;background:rgba(0,0,0,.22);border:1px solid rgba(255,255,255,.2)}
.cr-props .wide{grid-column:span 2}
.cr-board.takedown{outline:3px dashed var(--coral);outline-offset:2px}
@media (max-width:720px){
  .cr-nums{grid-template-columns:repeat(3,minmax(0,1fr))}
  .cr-dcbar{grid-column:1/-1}.cr-spot.tall{height:auto}
  .cr-field{grid-template-columns:1fr 1fr}.cr-field .wide{grid-column:1/-1;order:-1}
  .cr-line{grid-template-columns:1fr 1fr}.cr-line .wide{grid-column:1/-1;order:-1}
  .cr-props{grid-template-columns:repeat(2,minmax(0,1fr))}
  .cr-spot.mini b{font-size:.62rem;letter-spacing:0}
}
/* pusher */
.pusher .g3d{cursor:crosshair;aspect-ratio:4/3;max-height:70vh}
.pu-tally{margin:0;font-size:.9rem;color:var(--muted)}.pu-tally b{font-family:var(--f-mono);color:var(--ink)}
.pu-lane input{width:180px}
/* 3D cabinet */
.vs-jp{display:grid;grid-template-columns:repeat(4,1fr);gap:6px;margin:0 0 8px}
.vs-jp span{display:grid;justify-items:center;padding:4px 6px;border-radius:10px;font:800 .62rem var(--f-body);letter-spacing:.16em;color:var(--vs-text);background:rgba(0,0,0,.4);border:1px solid color-mix(in srgb,var(--vs-accent) 35%,transparent)}
.vs-jp b{font:600 .9rem var(--f-mono);letter-spacing:0;color:var(--vs-accent)}
.vs-jp .jp-grand{border-color:var(--vs-accent);box-shadow:0 0 14px var(--vs-glow)}.vs-jp .jp-grand b{color:#fff;text-shadow:0 0 10px var(--vs-glow)}
.vs-bonus{position:absolute;inset:0;z-index:6;border-radius:26px;display:grid;grid-template-rows:auto 1fr;gap:10px;padding:14px;background:radial-gradient(circle at 50% 40%,color-mix(in srgb,var(--vs-bg2) 88%,transparent),rgba(0,0,0,.92));backdrop-filter:blur(4px);animation:pop .35s}
.vs-bonus[hidden]{display:none}
.vb-head{display:flex;justify-content:space-between;align-items:baseline;gap:10px;flex-wrap:wrap;color:var(--vs-text)}
.vb-head>b{font:400 clamp(1.3rem,4vw,2.2rem) var(--vs-font);color:var(--vs-accent);text-shadow:0 0 18px var(--vs-glow)}
.vb-head span{font:600 .9rem var(--f-body)}.vb-head span b{font-family:var(--f-mono);color:var(--vs-accent)}
.vb-grid{display:grid;grid-template-columns:repeat(4,1fr);grid-auto-rows:1fr;gap:8px;min-height:0}
.vb-tile{display:grid;place-items:center;align-content:center;gap:2px;border-radius:14px;border:2px solid color-mix(in srgb,var(--vs-accent) 55%,transparent);background:linear-gradient(160deg,var(--vs-tile),var(--vs-tile2));color:var(--vs-text);cursor:pointer;padding:4px;min-height:0;transition:transform .15s,box-shadow .15s}
.vb-tile svg{width:min(56px,70%);height:auto;max-height:100%}
.vb-tile:hover:not(.open){transform:translateY(-2px) scale(1.03);box-shadow:0 0 18px var(--vs-glow)}
.vb-tile.open{cursor:default;animation:vbflip .45s ease}
.vb-tile.open b{font:400 clamp(1.1rem,3.4vw,1.9rem) var(--vs-font);color:var(--vs-accent)}.vb-tile.open small{font:500 .72rem var(--f-mono)}
.vb-tile.jp{background:radial-gradient(circle,#fff3c4,var(--vs-accent) 60%,#8a5a00);color:#1a1204;box-shadow:0 0 26px var(--vs-glow)}.vb-tile.jp b{color:#1a1204}
.vb-tile.miss{opacity:.4;animation:none}
@keyframes vbflip{0%{transform:rotateY(90deg)}100%{transform:rotateY(0)}}
.vb-wheel{position:relative;display:grid;place-items:center;min-height:0}
.vb-svg{height:100%;max-height:min(440px,64vh);width:auto;max-width:100%;aspect-ratio:208/218;overflow:visible;filter:drop-shadow(0 10px 30px rgba(0,0,0,.6))}
.vb-disc{transform-box:fill-box;transform-origin:center}
.vb-rim{fill:var(--vs-frame2);stroke:var(--vs-frame);stroke-width:3}
.vb-seg{stroke:rgba(0,0,0,.45);stroke-width:.8}.vb-seg.s0{fill:var(--vs-tile)}.vb-seg.s1{fill:color-mix(in srgb,var(--vs-accent) 30%,var(--vs-tile2))}
.vb-seg.jp{fill:#d19a1a}.vb-seg.jp1000{fill:#ff6f59}.vb-seg.jp250{fill:#7b3fb3}
.vb-seg.hit{fill:#fff;animation:winpulse .5s ease 5 alternate}
.vb-lbl{font:700 10px var(--f-body);letter-spacing:.04em;fill:#fff;text-anchor:middle;dominant-baseline:middle;paint-order:stroke;stroke:rgba(0,0,0,.6);stroke-width:2px}
.vb-hub{fill:var(--vs-frame);stroke:#fff;stroke-width:2}
.vb-ptr{fill:#fff;stroke:var(--vs-frame2);stroke-width:1.5}.vb-lbl.j{font-size:9px}
.vb-go{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);border-radius:999px;padding:12px 18px}
.vb-go:disabled{opacity:0;pointer-events:none}
.vs-3d{position:absolute;inset:0;border-radius:18px;overflow:hidden;display:none;z-index:2}
.vs-3d canvas{width:100%;height:100%;display:block;opacity:0;transition:opacity .5s}
.vs-3d.ready canvas{opacity:1}
.vs.cab3d .vs-3d{display:block}
.vs.cab3d .vs-reels{visibility:hidden}
@media (max-width:720px){.g3d{aspect-ratio:4/3}}
.art-3d{font:800 .8rem var(--f-body);letter-spacing:.1em;padding:3px 8px;border-radius:6px;background:linear-gradient(90deg,#5fe0cf,#8c7ae6);color:#0b1020;align-self:flex-start}

/* ═════ rooms: every classic game gets a night-time scene ═════ */
.scene{position:relative;isolation:isolate;padding:clamp(16px,2.6vw,30px);border-radius:32px;overflow:hidden;
  color-scheme:dark;--ink:#f5ecd7;--muted:#b3ab96;--bg2:#101830;--bg3:#1a2548;--card:rgba(12,18,38,.62);--card-solid:#121b36;--line:rgba(232,182,76,.24);--gold-text:#ffd98a;--link:#ffd98a;--pos:#55d69a;--neg:#ff7d6b;
  color:var(--ink);box-shadow:var(--shadow),inset 0 0 0 1px rgba(255,255,255,.06)}
.scene>.scene-fx{position:absolute;inset:0;width:100%;height:100%;z-index:-1;pointer-events:none}
.scene .game-stage{background:linear-gradient(180deg,rgba(8,12,26,.5),rgba(8,12,26,.3));border-color:rgba(255,255,255,.1);backdrop-filter:blur(3px);-webkit-backdrop-filter:blur(3px)}
.scene .panel{background:rgba(8,12,26,.55);border-color:rgba(255,255,255,.1)}
.scene .table-head .display{text-shadow:0 2px 20px rgba(0,0,0,.5)}
.scene .table-head .muted,.scene .table-head p{color:#d8cfbb}
.scene-slots{background:linear-gradient(180deg,#120a24 0%,#3d1b3e 45%,#8a3a2c 85%,#c45a2c 100%)}
.scene-scratch{background:radial-gradient(90% 70% at 50% 0%,#4a1a4a,#1a0f2e 70%)}
.scene-keno{background:linear-gradient(180deg,#04263a 0%,#063b3a 60%,#0a4a2c 100%)}
.scene-roulette{background:radial-gradient(90% 70% at 50% 10%,#3e2210,#170b05 75%)}
.scene-baccarat{background:radial-gradient(90% 70% at 50% 0%,#4a0d1c,#16040a 75%),#16040a}
.scene-baccarat::after{content:"";position:absolute;inset:0;z-index:-1;pointer-events:none;background:repeating-linear-gradient(90deg,transparent 0 60px,rgba(232,182,76,.06) 60px 62px)}
.scene-sicbo{background:linear-gradient(180deg,#0b1d3a 0%,#0e3a5a 60%,#11606a 100%)}
.scene-bigwheel{background:radial-gradient(90% 80% at 30% 20%,#3a1150,#120621 70%)}
.scene-crabs{background:linear-gradient(180deg,#0f4a55 0%,#3b5b4a 18%,#8a6a3e 40%,#5a4228 100%)}
.scene-blackjack{background:linear-gradient(180deg,#07122a 0%,#0b1f3d 62%,#082a3a 100%)}
.scene-videopoker{background:linear-gradient(180deg,#0d0620 0%,#2a0c3a 45%,#0d0620 46%,#12072a 100%)}
.scene-threecard{background:linear-gradient(180deg,#0a0c24 0%,#241a44 55%,#4a2a3a 100%)}
.scene-hilo{background:radial-gradient(80% 70% at 50% 60%,#0f4a5a,#06202e 75%)}
.scene-crash{background:linear-gradient(180deg,#040816 0%,#0a1a33 60%,#0b2e3e 100%)}
.scene-mines{background:linear-gradient(180deg,#05324a 0%,#0a4a5a 50%,#123a3a 100%)}
.scene-dice{background:linear-gradient(180deg,#0a1122 0%,#152238 60%,#1f2c3c 100%)}
.tier-banner{position:absolute;left:50%;top:42%;transform:translate(-50%,-50%);z-index:6;pointer-events:none;opacity:0;text-align:center;display:grid;gap:4px}
.tier-banner.show{animation:banner 2.6s cubic-bezier(.2,.9,.3,1.3) forwards}
.tier-banner b{font:400 clamp(2.2rem,7vw,4rem) var(--f-display);color:#ffd98a;text-shadow:0 0 34px rgba(255,182,39,.85),0 4px 0 #6a4300;white-space:nowrap}
.tier-banner span{font:600 1.1rem var(--f-mono);color:#fff;text-shadow:0 2px 8px rgba(0,0,0,.6)}
.game-stage,.machine,.felt{position:relative}

/* responsive */
@media (max-width:980px){
  .table-wrap,.acct-grid,.rl-top{grid-template-columns:1fr}
  .paytable,.house-rules{order:3}
}
@media (max-width:720px){
  .top{flex-wrap:wrap;gap:10px}
  .nav{order:3;width:100%;flex:none}
  .who{display:none}
  .felt{border-radius:80px 80px 20px 20px/50px 50px 20px 20px;border-width:6px}
  dl.detail{grid-template-columns:1fr}dl.detail dt{border:0;padding-bottom:0}
  .reel{--cell:clamp(64px,22vw,110px)}
}
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{animation-duration:.001ms!important;animation-iteration-count:1!important;transition-duration:.001ms!important;scroll-behavior:auto!important}
  .reveal{opacity:1;transform:none}
  .wheel{transition-duration:.6s!important}
}
CSS;
}

/* ═════════════════════════ SCRIPT ═════════════════════════
 * Vanilla JS, progressive enhancement only. Every form here works without it.
 * The browser never decides an outcome: it posts, the server rolls, JS animates.
 */
function app_js(): string {
    return <<<'JS'
(() => {
'use strict';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const CSRF = $('meta[name="csrf"]').content;
const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
const SYMS = JSON.parse(($('#symbols') || {}).textContent || '{}');
const fmt = n => Number(n).toLocaleString('en-US');
const sleep = ms => new Promise(r => setTimeout(r, reduce ? 0 : ms));
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

/* ── theme ── */
$$('[data-theme-toggle]').forEach(b => b.addEventListener('click', () => {
  const root = document.documentElement;
  const cur = root.dataset.theme || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  const next = cur === 'light' ? 'dark' : 'light';
  root.dataset.theme = next;
  try { localStorage.setItem('gt_theme', next); } catch (e) {}
}));

/* ── toasts ── */
const toastBox = $('.toasts');
function dismiss(t) { t.classList.add('out'); setTimeout(() => t.remove(), 450); }
function toast(msg, type = 'info') {
  const t = document.createElement('div');
  t.className = 'toast ' + type;
  t.setAttribute('role', type === 'err' ? 'alert' : 'status');
  t.textContent = msg;
  toastBox.appendChild(t);
  setTimeout(() => dismiss(t), 4800);
}
$$('.toast').forEach(t => setTimeout(() => dismiss(t), 5200));

/* ── api ── */
async function post(url, data) {
  const fd = data instanceof FormData ? data : new FormData();
  if (!(data instanceof FormData)) for (const [k, v] of Object.entries(data || {})) fd.append(k, v);
  if (!fd.has('csrf')) fd.append('csrf', CSRF);
  let res, j;
  try {
    res = await fetch(url, { method: 'POST', body: fd, credentials: 'same-origin',
      headers: { 'X-Requested-With': 'fetch', 'Accept': 'application/json' } });
    j = await res.json();
  } catch (e) { throw new Error('Network hiccup. Check your connection and try again.'); }
  if (!j.ok) {
    if (res.status === 401) setTimeout(() => { location.href = '?action=login'; }, 900);
    throw new Error(j.error || 'Something went wrong.');
  }
  return j.data;
}

/* ── balance ── */
function countUp(el, from, to) {
  if (reduce || from === to) { el.textContent = fmt(to); return; }
  const t0 = performance.now(), d = 700;
  const step = t => {
    const k = Math.min(1, (t - t0) / d), e = 1 - Math.pow(1 - k, 3);
    el.textContent = fmt(Math.round(from + (to - from) * e));
    if (k < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}
const EMBED = document.body.classList.contains('embed');
function setBalance(n) {
  $$('[data-balance]').forEach(el => { countUp(el, +el.dataset.balance || 0, n); el.dataset.balance = n; });
  if (EMBED && window.parent !== window) { try { window.parent.postMessage({ t: 'gt_balance', balance: n }, location.origin); } catch (e) {} }
  const pill = $('.balance');
  if (pill) { pill.classList.remove('bump'); void pill.offsetWidth; pill.classList.add('bump'); }
}

/* ── coin burst: little celebration, pure decoration ── */
function burst(fromEl, count = 14) {
  if (reduce || !fromEl) return;
  const r = fromEl.getBoundingClientRect();
  const coinSvg = '<svg width="20" height="20" viewBox="0 0 32 32"><circle cx="16" cy="16" r="15" fill="#e8b64c"/><circle cx="16" cy="16" r="11" fill="none" stroke="#b07d12" stroke-width="2"/></svg>';
  for (let i = 0; i < count; i++) {
    const c = document.createElement('span');
    c.innerHTML = coinSvg;
    Object.assign(c.style, { position: 'fixed', left: (r.left + r.width / 2) + 'px', top: (r.top + r.height / 2) + 'px', zIndex: 150, pointerEvents: 'none' });
    document.body.appendChild(c);
    const a = (Math.random() * Math.PI) + Math.PI, dist = 80 + Math.random() * 140;
    c.animate([
      { transform: 'translate(-50%,-50%) scale(.6)', opacity: 1 },
      { transform: `translate(${Math.cos(a) * dist}px,${Math.sin(a) * dist}px) rotateY(720deg) scale(1)`, opacity: 1, offset: .6 },
      { transform: `translate(${Math.cos(a) * dist}px,${Math.sin(a) * dist + 120}px) scale(.8)`, opacity: 0 },
    ], { duration: 1100 + Math.random() * 500, easing: 'cubic-bezier(.2,.7,.3,1)' }).finished.then(() => c.remove());
  }
}

/* ── bonus forms (daily, refill, promo) ── */
$$('form[data-ajax]').forEach(f => f.addEventListener('submit', async e => {
  e.preventDefault();
  const btn = $('button', f);
  btn.disabled = true;
  try {
    const d = await post(f.action, new FormData(f));
    toast(d.message, 'ok');
    setBalance(d.balance);
    burst(btn);
    if (f.querySelector('input[name="code"]')) { f.reset(); btn.disabled = false; }
    else { btn.textContent = 'Collected ✓'; }
  } catch (err) { toast(err.message, 'err'); btn.disabled = false; }
}));

/* countdowns on disabled bonus buttons */
$$('button[data-wait]').forEach(b => {
  let left = +b.dataset.wait;
  if (!left) return;
  const tick = () => {
    left -= 30;
    if (left <= 0) { b.disabled = false; b.textContent = 'Collect'; return; }
    const h = Math.floor(left / 3600), m = Math.floor(left % 3600 / 60);
    b.textContent = 'Back in ' + (h ? h + 'h ' + m + 'm' : Math.max(1, m) + 'm');
    setTimeout(tick, 30000);
  };
  setTimeout(tick, 30000);
});

/* ═════ SLOTS ═════ */
const machine = $('[data-slots]');
if (machine) {
  const LINES = [[1,1,1],[0,0,0],[2,2,2],[0,1,2],[2,1,0]];
  const names = Object.keys(SYMS);
  const form = $('form', machine), res = $('[data-result]', machine);
  const reels = $$('.reel', machine), lines = $$('.paylines polyline', machine);
  const btn = $('[data-spin]', machine);
  const cellHtml = s => `<div class="cell"><svg viewBox="0 0 64 64" role="img" aria-label="${esc(s)}">${SYMS[s] || ''}</svg></div>`;
  const rand = () => names[Math.floor(Math.random() * names.length)];
  let busy = false;

  function land(reel, final, i) {
    const strip = $('.strip', reel);
    const cell = reel.clientHeight / 3;
    const current = $$('.cell', strip).map(c => c.querySelector('svg').getAttribute('aria-label'));
    const n = 16 + i * 6;
    const filler = Array.from({ length: n - 3 }, rand);
    // visually: new symbols drop in from above, old ones fall out the bottom
    strip.innerHTML = [...final, ...filler, ...current].map(cellHtml).join('');
    reel.classList.add('blur');
    const anim = strip.animate(
      [{ transform: `translateY(${-(n) * cell}px)` }, { transform: 'translateY(0)' }],
      { duration: reduce ? 1 : 850 + i * 380, easing: 'cubic-bezier(.2,.6,.25,1.08)', fill: 'forwards' });
    setTimeout(() => reel.classList.remove('blur'), reduce ? 0 : 500 + i * 380);
    return anim.finished.then(() => {
      strip.innerHTML = final.map(cellHtml).join('');
      anim.cancel();
      sfx.stop('classic', i);
    });
  }

  form.addEventListener('submit', async e => {
    e.preventDefault();
    if (busy || !btn) return;
    busy = true; btn.disabled = true;
    lines.forEach(l => l.classList.remove('on'));
    res.classList.remove('win');
    res.textContent = 'Spinning…';
    machine.classList.add('spinning');
    const bet = $('input[name="bet"]:checked', form).value;
    try {
      const d = await post(form.action, { bet });
      await Promise.all(reels.map((r, i) => land(r, d.grid[i], i)));
      d.wins.forEach((w, k) => {
        setTimeout(() => {
          lines[w.line].classList.add('on');
          LINES[w.line].slice(0, w.count).forEach((row, reel) => $$('.cell', reels[reel])[row].classList.add('hit'));
        }, k * 250);
      });
      res.textContent = d.message;
      if (d.payout > 0) { res.classList.add('win'); burst(res, Math.min(30, 8 + Math.round(d.payout / d.bet) * 2)); sfx.win('classic', Math.min(4, 1 + d.wins.length)); }
      setBalance(d.balance);
    } catch (err) {
      res.textContent = err.message;
      toast(err.message, 'err');
    } finally {
      machine.classList.remove('spinning');
      busy = false; btn.disabled = false;
    }
  });
  document.addEventListener('keydown', e => {
    if (e.code === 'Space' && e.target === document.body) { e.preventDefault(); form.requestSubmit(); }
  });
}

/* ═════ BLACKJACK ═════ */
const felt = $('[data-bj]');
if (felt) {
  const form = $('form', felt), res = $('[data-result]', felt);
  const dBox = $('[data-dealer-cards]', felt), pBox = $('[data-player-cards]', felt);
  const dTot = $('[data-dealer-total]', felt), pTot = $('[data-player-total]', felt), betTag = $('[data-bet-tag]', felt);
  const idle = $('[data-when="idle"]', felt), live = $('[data-when="live"]', felt), dbl = $('[data-double]', felt);
  const SUIT = { S: '♠', H: '♥', D: '♦', C: '♣' }, SNAME = { S: 'spades', H: 'hearts', D: 'diamonds', C: 'clubs' };
  let handId = (JSON.parse(felt.dataset.state || 'null') || {}).id || null;
  let busy = false;

  const cardHtml = (c, i) => {
    const r = c.slice(0, -1), s = c.slice(-1);
    return `<div class="card${s === 'H' || s === 'D' ? ' red' : ''}" style="--i:${i}" aria-label="${esc(r + ' of ' + SNAME[s])}"><span class="r">${esc(r)}</span><span class="s">${SUIT[s]}</span><span class="r2">${esc(r)}${SUIT[s]}</span></div>`;
  };
  function paint(box, cards, hidden, fresh) {
    if (fresh) box.innerHTML = '';
    $$('.card.down', box).forEach(x => x.remove());
    const have = $$('.card', box).length;
    cards.slice(have).forEach((c, k) => box.insertAdjacentHTML('beforeend', cardHtml(c, k)));
    for (let i = 0; i < hidden; i++) box.insertAdjacentHTML('beforeend', `<div class="card down" style="--i:${cards.length}" aria-label="face-down card"></div>`);
  }
  function render(h, fresh) {
    paint(pBox, h.player, 0, fresh);
    paint(dBox, h.dealer, h.dealer_hidden, fresh);
    pTot.textContent = h.player_total;
    dTot.textContent = h.dealer_total + (h.dealer_hidden ? ' + ?' : '');
    betTag.textContent = fmt(h.bet) + ' GC';
    const on = h.status === 'active';
    idle.hidden = on; live.hidden = !on;
    if (dbl) dbl.disabled = !h.can_double;
  }

  $$('[data-quick]', felt).forEach(b => b.addEventListener('click', () => { $('#bj-bet').value = b.dataset.quick; }));

  form.addEventListener('submit', async e => {
    e.preventDefault();
    if (busy) return;
    const move = e.submitter ? e.submitter.value : 'deal';
    busy = true;
    $$('button', form).forEach(b => b.disabled = true);
    res.classList.remove('win');
    const fd = new FormData(form);
    fd.set('move', move);
    try {
      const d = await post(form.action, fd);
      const h = d.hand;
      const fresh = h.id !== handId;
      handId = h.id;
      const before = $$('.card', felt).length;
      render(h, fresh);
      $$('.card', felt).slice(fresh ? 0 : before).forEach((c, k) => sfx.flip(k * .12));
      if (h.status === 'done') setTimeout(() => h.payout > h.bet ? sfx.win('lounge', h.outcome === 'blackjack' ? 4 : 2) : h.payout ? sfx.chime('lounge', 2) : sfx.lose('lounge'), 400);
      if (h.status === 'done') await sleep(350);
      res.textContent = d.message;
      if (h.status === 'done' && h.payout > h.bet) { res.classList.add('win'); burst(res, h.outcome === 'blackjack' ? 26 : 14); }
      setBalance(d.balance);
    } catch (err) { toast(err.message, 'err'); res.textContent = err.message; }
    finally {
      busy = false;
      $$('button', form).forEach(b => { if (b !== dbl) b.disabled = false; });
    }
  });
}

/* ═════ ROULETTE ═════ */
const rl = $('[data-roulette]');
if (rl) {
  const ORDER = [0,32,15,19,4,21,2,25,17,34,6,27,13,36,11,30,8,23,10,5,24,16,33,1,20,14,31,9,22,18,29,7,28,12,35,3,26];
  const RED = new Set([1,3,5,7,9,12,14,16,18,19,21,23,25,27,30,32,34,36]);
  const colorOf = n => n === 0 ? 'green' : RED.has(n) ? 'red' : 'black';
  const MIN = +rl.dataset.min, MAX = +rl.dataset.max, TABLE = MAX * 10;
  const wheel = $('[data-wheel]', rl), landed = $('[data-landed]', rl), res = $('[data-result]', rl);
  const stakedEl = $('[data-staked]', rl), hist = $('[data-history]', rl);
  const spinBtn = $('[data-rl-spin]', rl), undoBtn = $('[data-rl-undo]', rl), clearBtn = $('[data-rl-clear]', rl), rebetBtn = $('[data-rl-rebet]', rl);
  const board = $('[data-board]', rl);
  const step = 360 / 37;
  let rot = 0, chip = +(($('[data-chip][aria-checked="true"]', rl) || {}).dataset || {}).chip || MIN;
  let bets = new Map(), stack = [], lastBets = null, busy = false;

  // draw the wheel
  const NS = 'http://www.w3.org/2000/svg';
  const pol = (r, deg) => { const a = (deg - 90) * Math.PI / 180; return [r * Math.cos(a), r * Math.sin(a)]; };
  let svg = '<circle r="108" fill="#5a3a1c"/><circle r="103" fill="#2b1a0c"/>';
  ORDER.forEach((n, i) => {
    const a0 = i * step - step / 2, a1 = a0 + step;
    const [x0, y0] = pol(100, a0), [x1, y1] = pol(100, a1), [x2, y2] = pol(68, a1), [x3, y3] = pol(68, a0);
    const fill = n === 0 ? '#1b8a5a' : RED.has(n) ? '#c0263a' : '#16161d';
    svg += `<path d="M${x0},${y0} A100,100 0 0 1 ${x1},${y1} L${x2},${y2} A68,68 0 0 0 ${x3},${y3}Z" fill="${fill}" stroke="#e8b64c" stroke-width=".6"/>`;
    const [tx, ty] = pol(88, i * step);
    svg += `<text x="${tx}" y="${ty}" fill="#fff" font-size="8.5" font-family="Limelight,serif" text-anchor="middle" dominant-baseline="central" transform="rotate(${i * step} ${tx} ${ty})">${n}</text>`;
  });
  svg += '<circle r="68" fill="#0e4a43" stroke="#e8b64c" stroke-width="1.5"/><circle r="52" fill="none" stroke="rgba(232,182,76,.35)" stroke-width="1"/>';
  for (let i = 0; i < 8; i++) { const [x, y] = pol(46, i * 45); svg += `<line x1="0" y1="0" x2="${x}" y2="${y}" stroke="#e8b64c" stroke-width="3" stroke-linecap="round"/>`; }
  svg += '<circle r="12" fill="#e8b64c"/><circle r="5" fill="#fff3c4"/>';
  wheel.innerHTML = svg;

  function refresh() {
    let total = 0;
    $$('.stake', board).forEach(s => s.remove());
    for (const [key, amt] of bets) {
      total += amt;
      const b = board.querySelector(`[data-bet="${key}"]`);
      if (b) b.insertAdjacentHTML('beforeend', `<span class="stake">${amt >= 1000 ? (amt / 1000).toFixed(amt % 1000 ? 1 : 0) + 'K' : amt}</span>`);
    }
    stakedEl.textContent = fmt(total);
    const has = bets.size > 0;
    if (spinBtn) spinBtn.disabled = !has || busy;
    if (undoBtn) undoBtn.disabled = !stack.length || busy;
    if (clearBtn) clearBtn.disabled = !has || busy;
    if (rebetBtn) rebetBtn.hidden = !lastBets || has;
    return total;
  }
  const total = () => [...bets.values()].reduce((a, b) => a + b, 0);

  $$('[data-chip]', rl).forEach(c => c.addEventListener('click', () => {
    $$('[data-chip]', rl).forEach(x => x.setAttribute('aria-checked', 'false'));
    c.setAttribute('aria-checked', 'true');
    chip = +c.dataset.chip;
  }));

  board.addEventListener('click', e => {
    const b = e.target.closest('[data-bet]');
    if (!b || busy || !spinBtn) return;
    $$('.win', board).forEach(x => x.classList.remove('win'));
    const key = b.dataset.bet, cur = bets.get(key) || 0;
    if (cur + chip > MAX) { toast(`Max ${fmt(MAX)} GC on one spot.`, 'err'); return; }
    if (total() + chip > TABLE) { toast(`Table limit is ${fmt(TABLE)} GC per spin.`, 'err'); return; }
    if (bets.size >= 40 && !bets.has(key)) { toast('That\'s a lot of spots. Max 40 per spin.', 'err'); return; }
    bets.set(key, cur + chip); stack.push([key, chip]);
    refresh();
  });
  const pull = b => { const key = b.dataset.bet; if (!bets.has(key) || busy) return; bets.delete(key); stack = stack.filter(([k]) => k !== key); refresh(); };
  board.addEventListener('contextmenu', e => { const b = e.target.closest('[data-bet]'); if (b) { e.preventDefault(); pull(b); } });
  let press;
  board.addEventListener('pointerdown', e => { const b = e.target.closest('[data-bet]'); if (b && e.pointerType === 'touch') press = setTimeout(() => pull(b), 550); });
  ['pointerup', 'pointerleave', 'pointercancel'].forEach(t => board.addEventListener(t, () => clearTimeout(press)));

  if (undoBtn) undoBtn.addEventListener('click', () => {
    const last = stack.pop(); if (!last) return;
    const [k, amt] = last, left = (bets.get(k) || 0) - amt;
    left > 0 ? bets.set(k, left) : bets.delete(k);
    refresh();
  });
  if (clearBtn) clearBtn.addEventListener('click', () => { bets.clear(); stack = []; refresh(); });
  if (rebetBtn) rebetBtn.addEventListener('click', () => { bets = new Map(lastBets); stack = [...bets].map(([k, v]) => [k, v]); refresh(); });

  function spinTo(n) {
    const idx = ORDER.indexOf(n);
    const target = -idx * step;
    const cur = ((rot % 360) + 360) % 360;
    let delta = ((target - cur) % 360 + 360) % 360;
    rot = rot + delta + 360 * (reduce ? 0 : 5);
    wheel.style.transform = `rotate(${rot}deg)`;
    return sleep(5100);
  }

  if (spinBtn) spinBtn.addEventListener('click', async () => {
    if (busy || !bets.size) return;
    busy = true; refresh();
    landed.innerHTML = '';
    res.classList.remove('win');
    res.textContent = 'No more bets…';
    const list = [...bets].map(([k, amount]) => { const [type, value] = k.split(':'); return { type, value: +value, amount }; });
    try {
      const d = await post('?action=play_roulette', { bets: JSON.stringify(list) });
      const tk = setInterval(() => sfx.tick('lounge'), 120); setTimeout(() => clearInterval(tk), 4600);
      await spinTo(d.number);
      d.payout > 0 ? sfx.win('lounge', 3) : sfx.lose('lounge');
      landed.innerHTML = `<b class="n ${d.color}">${d.number}</b>`;
      res.textContent = d.message;
      d.bets.filter(b => b.returned > 0).forEach(b => {
        const el = board.querySelector(`[data-bet="${b.type}:${b.value}"]`); if (el) el.classList.add('win');
      });
      hist.insertAdjacentHTML('afterbegin', `<li class="${d.color}">${d.number}</li>`);
      while (hist.children.length > 12) hist.lastElementChild.remove();
      if (d.payout > 0) { res.classList.add('win'); burst(landed, 18); }
      setBalance(d.balance);
      lastBets = new Map(bets);
      bets.clear(); stack = [];
    } catch (err) { toast(err.message, 'err'); res.textContent = err.message; }
    finally { busy = false; refresh(); }
  });
  refresh();
}

/* ═════ GAME PANELS (shared) ═════
 * Forms marked data-play post to ?action=play&g=slug. The server answers with the
 * outcome plus the freshly rendered panel; we swap it in, run the game's animation
 * hook, and only then reveal the result and update the balance.
 */
const hooks = {};
const playUrl = slug => '?action=play&g=' + encodeURIComponent(slug);
function enhance(root) {
  initChipboards(root); initDice(root); initPearlDrop(root); initVideoSlot(root); init3d(root); initScenes(root); initKeno(root); initBigWheel(root); initCrash(root);
}
async function runPlay(panel, url, fd) {
  if (panel.dataset.busy) return null;
  panel.dataset.busy = '1'; panel.classList.add('busy');
  const slug = panel.dataset.panel, snd = GAME_SFX[slug] || 'classic';
  let stake = +(fd.get('bet') || 0);
  if (!stake) { try { stake = JSON.parse(fd.get('bets') || '[]').reduce((a, b) => a + (+b.amount || 0), 0); } catch (e) { stake = 0; } }
  sfx.unlock();
  if (slug === 'sicbo' || slug === 'dice') sfx.rattle(); else sfx.tick(snd);
  try {
    const d = await post(url, fd);
    const h = hooks[panel.dataset.panel] || {};
    panel.innerHTML = d.html;
    panel.classList.add('pending');
    enhance(panel);
    // a soft card-flip for every card as its deal animation lands
    const slow = !!panel.querySelector('.slow-deal');
    $$('.card', panel).forEach(c => { const i = +(c.style.getPropertyValue('--i') || 0); sfx.flip((slow ? .5 : .12) * i + .1); });
    if (h.after && !reduce) await h.after(d, panel);
    panel.classList.remove('pending');
    if (d.win) sfx.win(snd, stake && d.payout >= stake * 5 ? 4 : 2); else if (d.payout === 0 && !/Pick|Tap|Hit|Play or fold|Run at|pearl/.test(d.message || '')) sfx.lose(snd);
    if (stake && d.payout >= stake * 10) {
      const x = d.payout / stake, tier = x >= 100 ? 'EPIC WIN' : x >= 25 ? 'MEGA WIN' : 'BIG WIN';
      const b = document.createElement('div'); b.className = 'tier-banner'; b.innerHTML = `<b>${tier}</b><span>+${fmt(d.payout)} GC · ${x.toFixed(1)}×</span>`;
      panel.appendChild(b); void b.offsetWidth; b.classList.add('show'); sfx.big(snd); burst(b, x >= 25 ? 30 : 20);
      setTimeout(() => b.remove(), 2800);
    }
    if (d.boom) panel.animate([{ transform: 'translateX(0)' }, { transform: 'translateX(-10px)' }, { transform: 'translateX(10px)' }, { transform: 'translateX(0)' }], { duration: 320, iterations: 2 });
    if (d.win) burst(panel.querySelector('.result') || panel, Math.min(28, 10 + Math.round((d.payout || 0) / 500)));
    setBalance(d.balance);
    return d;
  } catch (err) { toast(err.message, 'err'); return null; }
  finally { delete panel.dataset.busy; panel.classList.remove('busy'); }
}
document.addEventListener('submit', e => {
  const f = e.target.closest('form[data-play]');
  const panel = f && f.closest('[data-panel]');
  if (!panel) return;
  e.preventDefault();
  const fd = new FormData(f);
  if (e.submitter && e.submitter.name) fd.set(e.submitter.name, e.submitter.value);
  runPlay(panel, f.action, fd);
});
document.addEventListener('click', e => {
  const b = e.target.closest('[data-adj]');
  if (!b) return;
  const inp = b.closest('.betbox').querySelector('input');
  const min = +inp.min, max = +inp.max, v = +inp.value || min;
  inp.value = Math.max(min, Math.min(max, { half: Math.floor(v / 2), double: v * 2, min, max }[b.dataset.adj]));
});

/* ── chip board: shared by sic bo, big six, crabs, baccarat ── */
const cbMem = {};
function initChipboards(root) {
  $$('[data-chipboard]', root).forEach(cb => {
    if (cb.dataset.ready) return;
    cb.dataset.ready = '1';
    const slug = cb.dataset.chipboard, MAX = +cb.dataset.max, TABLE = MAX * 10;
    const board = $('[data-board]', cb), go = $('[data-cb-go]', cb), undo = $('[data-cb-undo]', cb),
      clear = $('[data-cb-clear]', cb), rebet = $('[data-cb-rebet]', cb), staked = $('[data-staked]', cb);
    let chip = +((($('[data-chip][aria-checked="true"]', cb) || {}).dataset || {}).chip || cb.dataset.min);
    let bets = new Map(), stack = [];
    const total = () => [...bets.values()].reduce((a, b) => a + b, 0);
    const refresh = () => {
      $$('.stake', board).forEach(s => s.remove());
      for (const [k, amt] of bets) {
        const el = board.querySelector(`[data-bet="${CSS.escape(k)}"]`);
        if (el) el.insertAdjacentHTML('beforeend', `<span class="stake">${amt >= 1000 ? (amt / 1000).toFixed(amt % 1000 ? 1 : 0) + 'K' : amt}</span>`);
      }
      staked.textContent = fmt(total());
      go.disabled = !bets.size; undo.disabled = !stack.length; clear.disabled = !bets.size;
      rebet.hidden = !cbMem[slug] || bets.size > 0;
    };
    $$('[data-chip]', cb).forEach(c => c.addEventListener('click', () => {
      $$('[data-chip]', cb).forEach(x => x.setAttribute('aria-checked', 'false'));
      c.setAttribute('aria-checked', 'true'); chip = +c.dataset.chip;
    }));
    board.addEventListener('click', e => {
      const b = e.target.closest('[data-bet]'); if (!b) return;
      $$('.win', board).forEach(x => x.classList.remove('win'));
      const k = b.dataset.bet, cur = bets.get(k) || 0;
      if (cur + chip > MAX) return toast(`Max ${fmt(MAX)} GC on one spot.`, 'err');
      if (total() + chip > TABLE) return toast(`Table limit is ${fmt(TABLE)} GC per round.`, 'err');
      bets.set(k, cur + chip); stack.push([k, chip]); refresh();
    });
    const pull = b => { const k = b.dataset.bet; if (!bets.has(k)) return; bets.delete(k); stack = stack.filter(([x]) => x !== k); refresh(); };
    board.addEventListener('contextmenu', e => { const b = e.target.closest('[data-bet]'); if (b) { e.preventDefault(); pull(b); } });
    let press;
    board.addEventListener('pointerdown', e => { const b = e.target.closest('[data-bet]'); if (b && e.pointerType === 'touch') press = setTimeout(() => pull(b), 550); });
    ['pointerup', 'pointerleave', 'pointercancel'].forEach(t => board.addEventListener(t, () => clearTimeout(press)));
    undo.addEventListener('click', () => { const l = stack.pop(); if (!l) return; const left = (bets.get(l[0]) || 0) - l[1]; left > 0 ? bets.set(l[0], left) : bets.delete(l[0]); refresh(); });
    clear.addEventListener('click', () => { bets.clear(); stack = []; refresh(); });
    rebet.addEventListener('click', () => { bets = new Map(cbMem[slug]); stack = [...bets]; refresh(); });
    go.addEventListener('click', async () => {
      if (!bets.size) return;
      go.disabled = true;
      const fd = new FormData();
      fd.append('bets', JSON.stringify([...bets].map(([key, amount]) => ({ key, amount }))));
      const snapshot = new Map(bets);
      const panel = cb.closest('[data-panel]'), host = panel && $('[data-g3d]', panel);
      if (host && host._g3d && host._g3d.play) {
        // 3D table: keep the scene alive, play the result in place instead of swapping the panel
        try {
          const d = await host._g3d.play(fd);
          cbMem[slug] = snapshot; bets.clear(); stack = []; refresh();
          (d.win_keys || []).forEach(k => { const b = board.querySelector(`[data-bet="${CSS.escape(k)}"]`); if (b) b.classList.add('win'); });
        } catch (err) { toast(err.message, 'err'); refresh(); }
        return;
      }
      const d = await runPlay(panel, playUrl(slug), fd);
      if (d) cbMem[slug] = snapshot; else refresh();
    });
    refresh();
  });
}

/* ── wheel drawing, shared by big six ── */
function wedges(labels, colorOf, textOf, inner) {
  const step = 360 / labels.length;
  const pol = (r, deg) => { const a = (deg - 90) * Math.PI / 180; return [r * Math.cos(a), r * Math.sin(a)]; };
  let svg = '<circle r="108" fill="#5a3a1c"/><circle r="103" fill="#2b1a0c"/>';
  labels.forEach((l, i) => {
    const a0 = i * step - step / 2, a1 = a0 + step;
    const [x0, y0] = pol(100, a0), [x1, y1] = pol(100, a1), [x2, y2] = pol(inner, a1), [x3, y3] = pol(inner, a0);
    const [fill, ink] = colorOf(l);
    svg += `<path d="M${x0},${y0} A100,100 0 0 1 ${x1},${y1} L${x2},${y2} A${inner},${inner} 0 0 0 ${x3},${y3}Z" fill="${fill}" stroke="#e8b64c" stroke-width=".6"/>`;
    const [tx, ty] = pol((100 + inner) / 2, i * step);
    svg += `<text x="${tx}" y="${ty}" fill="${ink}" font-size="${labels.length > 40 ? 7.5 : 8.5}" font-family="Limelight,serif" text-anchor="middle" dominant-baseline="central" transform="rotate(${i * step} ${tx} ${ty})">${textOf(l)}</text>`;
  });
  svg += `<circle r="${inner}" fill="#0e4a43" stroke="#e8b64c" stroke-width="1.5"/>`;
  for (let i = 0; i < 12; i++) { const [x, y] = pol(inner - 12, i * 30); svg += `<line x1="0" y1="0" x2="${x}" y2="${y}" stroke="#e8b64c" stroke-width="2.5" stroke-linecap="round"/>`; }
  return svg + '<circle r="11" fill="#e8b64c"/><circle r="4.5" fill="#fff3c4"/>';
}

/* ── Big Six ── */
const B6 = { '1': ['#efe6d2', '#1b1a2e'], '2': ['#ffd23f', '#1b1a2e'], '5': ['#2bb3a3', '#fff'], '10': ['#ff6f59', '#fff'], '20': ['#8c7ae6', '#fff'], anchor: ['#1b1a2e', '#ffd98a'], sun: ['#ffb627', '#1b1a2e'] };
function initBigWheel(root) {
  const w = $('[data-bigwheel]', root);
  if (!w || w.dataset.ready) return;
  w.dataset.ready = '1';
  const labels = JSON.parse(w.dataset.bigwheel);
  w.innerHTML = wedges(labels, l => B6[l], l => ({ anchor: '⚓', sun: '☀' }[l] || l), 64);
  if (w.dataset.index) { w.style.transition = 'none'; w.style.transform = `rotate(${-(+w.dataset.index) * 360 / 54}deg)`; }
}
hooks.bigwheel = {
  after: async (d, panel) => {
    const w = $('[data-bigwheel]', panel);
    const target = -d.index * 360 / 54 - 360 * 4;
    w.style.transition = 'none'; w.style.transform = 'rotate(0deg)';
    void w.getBoundingClientRect();
    w.style.transition = 'transform 4.2s cubic-bezier(.15,.7,.15,1)';
    w.style.transform = `rotate(${target}deg)`;
    const clicks = setInterval(() => { sfx.tick('carnival'); const p = $('.pointer', panel); if (p) p.animate([{ transform: 'translateX(-50%) rotate(0)' }, { transform: 'translateX(-50%) rotate(-18deg)' }, { transform: 'translateX(-50%) rotate(0)' }], { duration: 120 }); }, 140);
    await sleep(4300); clearInterval(clicks);
    $$('.bw-spot', panel).forEach(b => b.classList.toggle('win', b.dataset.bet === d.hit));
  },
};

/* ── dice ── */
function initDice(root) {
  const t = $('[data-dice-target]', root);
  if (!t || t.dataset.ready) return;
  t.dataset.ready = '1';
  const f = t.form, track = $('[data-track]', root);
  const upd = () => {
    const v = +f.target.value, dir = f.dir.value, ch = dir === 'under' ? v : 100 - v, ok = ch >= 2 && ch <= 95;
    $('[data-dice-chance]', root).textContent = ch.toFixed(1) + '%';
    $('[data-dice-mult]', root).textContent = ok ? (Math.floor(99 / ch * 10000) / 10000).toFixed(4) + '×' : 'out of range';
    track.style.setProperty('--t', v + '%');
    track.classList.toggle('over', dir === 'over'); track.classList.toggle('under', dir === 'under');
  };
  f.addEventListener('input', upd); upd();
}
hooks.dice = {
  after: async (d, panel) => {
    panel.classList.remove('pending');
    const m = $('.dice-marker', panel), num = $('.big-num', panel), res = $('.result', panel);
    if (res) res.style.visibility = 'hidden';
    if (m) m.animate([{ left: '50%' }, { left: d.roll + '%' }], { duration: 700, easing: 'cubic-bezier(.2,.8,.2,1.15)' });
    if (num) await new Promise(ok => {
      const t0 = performance.now();
      const step = t => { const k = (t - t0) / 700; if (k < 1) { num.textContent = (Math.random() * 100).toFixed(2); requestAnimationFrame(step); } else { num.textContent = d.roll.toFixed(2); ok(); } };
      requestAnimationFrame(step);
    });
    if (res) res.style.visibility = '';
  },
};

/* ── keno ── */
function initKeno(root) {
  const grid = $('[data-keno]', root);
  if (!grid || grid.dataset.ready) return;
  grid.dataset.ready = '1';
  const pay = JSON.parse($('[data-keno-pay]', root).dataset.kenoPay);
  const boxes = $$('input[type=checkbox]', grid);
  const table = $('[data-keno-pay] tbody', root);
  const paint = () => {
    const n = boxes.filter(b => b.checked).length;
    table.innerHTML = n ? pay[n].map((x, h) => x ? `<tr><td>${h} of ${n}</td><td class="n">${x}×</td></tr>` : '').reverse().join('') : '<tr><td colspan="2" class="muted">Pick numbers to see payouts</td></tr>';
  };
  grid.addEventListener('change', e => {
    if (boxes.filter(b => b.checked).length > 10) { e.target.checked = false; toast('Ten numbers max.', 'err'); }
    $$('.kt', grid).forEach(k => k.classList.remove('drawn', 'hit'));
    paint();
  });
  $('[data-keno-quick]', root).addEventListener('click', () => {
    const want = boxes.filter(b => b.checked).length || 6;
    boxes.forEach(b => { b.checked = false; });
    const pool = boxes.slice();
    for (let i = 0; i < want; i++) pool.splice(Math.floor(Math.random() * pool.length), 1)[0].checked = true;
    $$('.kt', grid).forEach(k => k.classList.remove('drawn', 'hit'));
    paint();
  });
  $('[data-keno-clear]', root).addEventListener('click', () => { boxes.forEach(b => { b.checked = false; }); $$('.kt', grid).forEach(k => k.classList.remove('drawn', 'hit')); paint(); });
  paint();
}
hooks.keno = { after: (d, panel) => { $$('.kt.drawn', panel).forEach(k => { const i = +k.style.getPropertyValue('--i') || 0; sfx.chime('ocean', k.classList.contains('hit') ? 5 : i, i * .18); }); return sleep(10 * 180 + 350); } };

/* ── scratchers ── */
hooks.scratch = {
  after: (d, panel) => new Promise(done => {
    panel.classList.add('scratching');
    const spots = $$('.spot', panel);
    const all = $('[data-reveal-all]', panel);
    let left = spots.length;
    const finish = () => { if (--left === 0) { all.hidden = true; panel.classList.remove('scratching'); done(); } };
    spots.forEach(spot => {
      const c = document.createElement('canvas');
      c.className = 'foil';
      spot.appendChild(c);
      const r = spot.getBoundingClientRect(), dpr = window.devicePixelRatio || 1;
      c.width = r.width * dpr; c.height = r.height * dpr;
      const x = c.getContext('2d');
      x.scale(dpr, dpr);
      const gr = x.createLinearGradient(0, 0, r.width, r.height);
      gr.addColorStop(0, '#ffe49a'); gr.addColorStop(.5, '#d19a1a'); gr.addColorStop(1, '#ffd98a');
      x.fillStyle = gr; x.fillRect(0, 0, r.width, r.height);
      x.fillStyle = 'rgba(90,58,28,.55)'; x.font = '600 12px Figtree, sans-serif'; x.textAlign = 'center';
      x.fillText('SCRATCH', r.width / 2, r.height / 2 + 4);
      x.globalCompositeOperation = 'destination-out';
      let down = false, moves = 0, gone = false;
      const clearIt = () => { if (gone) return; gone = true; c.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 250 }).finished.then(() => c.remove()); finish(); };
      const scratch = e => {
        if (!down || gone) return;
        const b = c.getBoundingClientRect();
        x.beginPath(); x.arc(e.clientX - b.left, e.clientY - b.top, 16, 0, Math.PI * 2); x.fill();
        if (++moves % 6 === 0) {
          const px = x.getImageData(0, 0, c.width, c.height).data; let clear = 0;
          for (let i = 3; i < px.length; i += 64) if (px[i] === 0) clear++;
          if (clear / (px.length / 64) > .5) clearIt();
        }
      };
      c.addEventListener('pointerdown', e => { down = true; c.setPointerCapture(e.pointerId); scratch(e); });
      c.addEventListener('pointermove', scratch);
      c.addEventListener('pointerup', () => { down = false; });
      c.addEventListener('dblclick', clearIt);
      c.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); clearIt(); } });
      c.tabIndex = 0; c.setAttribute('role', 'button'); c.setAttribute('aria-label', 'Scratch this spot');
      spot._clear = clearIt;
    });
    all.hidden = false;
    all.addEventListener('click', () => spots.forEach(s => s._clear && s._clear()));
  }),
};

/* ── sic bo, baccarat: CSS does the motion, we just wait for it ── */
hooks.sicbo = { after: () => sleep(1000) };
hooks.baccarat = { after: d => sleep(d.cards * 500 + 450) };

/* ── crab derby ── */
hooks.crabs = {
  after: async (d, panel) => {
    const runners = $$('[data-runner]', panel);
    const scuttle = setInterval(() => sfx.tick('carnival'), 110); setTimeout(() => clearInterval(scuttle), 4200);
    const anims = runners.map(r => {
      const i = +r.dataset.runner, place = d.order.indexOf(i), end = 100 - place * 9;
      const kf = [{ left: '0%' }]; let pos = 0;
      for (let k = 1; k < 8; k++) { pos = Math.min(end - 2, pos + (end / 8) * (0.5 + Math.random())); kf.push({ left: `calc(${pos}% * .86)` }); }
      kf.push({ left: `calc(${end}% * .86)` });
      r.classList.add('running');
      return r.animate(kf, { duration: 4200, easing: 'linear' }).finished.then(() => r.classList.remove('running'));
    });
    await Promise.all(anims);
  },
};

/* ── tide crash: draws the curve from server time, polls the server for the break ── */
function crashPath(k, tEnd, broke) {
  const T = Math.max(8, tEnd * 1.08), M = Math.max(2, Math.exp(k * tEnd) * 1.15);
  const X = t => t / T * 600, Y = m => 295 - (m - 1) / (M - 1) * 270;
  let dPath = 'M0,295';
  for (let i = 1; i <= 48; i++) { const t = tEnd * i / 48; dPath += ` L${X(t).toFixed(1)},${Y(Math.exp(k * t)).toFixed(1)}`; }
  return [dPath, dPath + ` L${X(tEnd).toFixed(1)},300 L0,300 Z`];
}
function initCrash(root) {
  const el = $('[data-crash]', root);
  if (!el || el.dataset.ready) return;
  el.dataset.ready = '1';
  const wave = $('[data-wave]', el), fill = $('[data-wave-fill]', el), multEl = $('[data-mult]', el);
  const K = 0.08;
  if (!el.dataset.live) {
    const m = parseFloat(multEl.textContent) || 1;
    if (m > 1) { const [p, f] = crashPath(K, Math.log(m) / K); wave.setAttribute('d', p); fill.setAttribute('d', f); }
    el.classList.toggle('broke', multEl.classList.contains('broke'));
    return;
  }
  const k = +el.dataset.k, auto = +el.dataset.auto || 0, bet = +el.dataset.bet;
  const t0 = performance.now() - (+el.dataset.elapsed) * 1000;
  const panel = el.closest('[data-panel]'), cash = root.querySelector('[data-cashout]');
  let lastPeek = 0, inflight = false, done = false;
  const peek = async () => {
    if (inflight || done) return;
    inflight = true;
    try {
      const fd = new FormData(); fd.append('move', 'peek');
      const d = await post(playUrl('crash'), fd);
      if (!d.live && !done && el.isConnected) {
        done = true;
        panel.innerHTML = d.html; enhance(panel);
        if (d.win) burst(panel.querySelector('.result') || panel, 16);
        else panel.animate([{ transform: 'translateY(0)' }, { transform: 'translateY(6px)' }, { transform: 'translateY(0)' }], { duration: 300 });
        setBalance(d.balance);
      }
    } catch (e) {}
    inflight = false;
  };
  const frame = now => {
    if (done || !el.isConnected) return;
    const t = (now - t0) / 1000, m = Math.floor(Math.exp(k * t) * 100) / 100;
    multEl.textContent = m.toFixed(2) + '×';
    if (cash) cash.textContent = 'Cash out ' + fmt(Math.floor(bet * m));
    const [p, f] = crashPath(k, t); wave.setAttribute('d', p); fill.setAttribute('d', f);
    if (now - lastPeek > 600 || (auto && m >= auto)) { lastPeek = now; peek(); }
    requestAnimationFrame(frame);
  };
  requestAnimationFrame(frame);
}

/* ═════ PEARL DROP (flagship plinko) ═════
 * Canvas board, concurrent pearls, golden pegs, synth audio, autoplay, session stats,
 * and an in-browser provably-fair verifier. The server has already decided every path;
 * this only animates it and never changes an outcome.
 */
const pdAudio = (() => {
  let ac = null, lastTink = 0;
  let on = true;
  try { on = localStorage.getItem('gt_sound') !== 'off'; } catch (e) {}
  const unlock = () => {
    if (!on) return;
    if (!ac) { try { ac = new (window.AudioContext || window.webkitAudioContext)(); } catch (e) { return; } }
    if (ac.state === 'suspended') ac.resume();
  };
  const tone = (f, dur, type = 'sine', vol = .05, when = 0) => {
    if (!on || !ac) return;
    const t = ac.currentTime + when, o = ac.createOscillator(), g = ac.createGain();
    o.type = type; o.frequency.setValueAtTime(f, t);
    g.gain.setValueAtTime(vol, t); g.gain.exponentialRampToValueAtTime(0.0001, t + dur);
    o.connect(g).connect(ac.destination); o.start(t); o.stop(t + dur + .02);
  };
  return {
    unlock, get on() { return on; },
    set(v) { on = v; try { localStorage.setItem('gt_sound', v ? 'on' : 'off'); } catch (e) {} if (v) unlock(); },
    tink(r) { const n = performance.now(); if (n - lastTink < 22) return; lastTink = n; tone(1250 - r * 28 + Math.random() * 80, .05, 'triangle', .022); },
    gold() { tone(1319, .22, 'sine', .06); tone(1760, .32, 'sine', .05, .07); tone(2637, .4, 'sine', .025, .14); },
    land(m) { const f = m >= 10 ? 880 : m >= 1 ? 523 : 247; tone(f, .16, 'sine', .055); if (m >= 10) { tone(f * 1.26, .2, 'sine', .045, .09); tone(f * 1.5, .3, 'sine', .045, .18); } },
    big() { [523, 659, 784, 1047, 1319].forEach((f, i) => tone(f, .35, 'triangle', .06, i * .08)); },
  };
})();

function initPearlDrop(root) {
  const el = $('[data-pearldrop]', root);
  if (!el || el.dataset.ready) return;
  el.dataset.ready = '1';
  const cfg = JSON.parse(el.dataset.cfg);
  const cv = $('[data-pd-canvas]', el), ctx = cv.getContext('2d');
  const form = $('[data-pd-form]', el), dropBtn = $('[data-pd-drop]', el);
  const resEl = $('[data-pd-result]', el), banner = $('[data-pd-banner]', el), hist = $('[data-pd-hist]', el);
  const autoBtn = $('[data-pd-auto]', el), costEl = $('[data-pd-cost]', el);
  const pick = n => (form.querySelector(`input[name="${n}"]:checked`) || {}).value;
  const turbo = () => $('[data-pd-turbo]', el).checked;
  let rows = +pick('rows'), risk = pick('risk');
  let G = {};
  const balls = [], sparks = [], floats = [], drops = [], flashes = new Map(), pulses = new Map();
  let heat = [], raf = 0, inflight = 0, seq = 0, applied = 0, auto = false;

  /* ── geometry ── */
  function layout() {
    const w = cv.clientWidth || 600, dpr = Math.min(2, window.devicePixelRatio || 1);
    const sx = w / (rows + 3), sy = sx * 0.9, top = sy * 1.15;
    const bucketY = top + (rows - 1) * sy + sy * 0.8, bucketH = Math.max(24, Math.min(40, sx * 0.62));
    const h = bucketY + bucketH + 18;
    cv.style.height = h + 'px'; cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    G = { w, h, sx, sy, top, bucketY, bucketH, cx: w / 2, pegR: Math.max(2.2, sx * 0.08), ballR: Math.max(4, Math.min(11, sx * 0.19)) };
    if (heat.length !== rows + 1) heat = new Array(rows + 1).fill(0);
    draw(performance.now());
  }
  const pegX = (r, i) => G.cx + (i - (r + 2) / 2) * G.sx;
  const pegY = r => G.top + r * G.sy;
  const slotX = k => G.cx + (k - rows / 2) * G.sx;
  const table = () => cfg.tables[rows][risk];

  /* ── colors ── */
  const mix = (a, b, t) => a.map((v, i) => Math.round(v + (b[i] - v) * t));
  const stops = [[18, 104, 110], [43, 179, 163], [255, 210, 63], [255, 111, 89], [214, 40, 63]];
  function bucketColor(m, max) {
    const t = Math.max(0, Math.min(1, Math.log(Math.max(m, .1) / .1) / Math.log(max / .1)));
    const s = t * (stops.length - 1), i = Math.min(stops.length - 2, Math.floor(s));
    const c = mix(stops[i], stops[i + 1], s - i);
    return `rgb(${c[0]},${c[1]},${c[2]})`;
  }

  /* ── drawing ── */
  function activeGold(now) {
    const set = new Map();
    drops.forEach(d => { if (now < d.goldUntil) d.gold.forEach(([r, i]) => set.set(r + ':' + i, d)); });
    return set;
  }
  function draw(now) {
    const { w, h, sx, pegR, ballR, bucketY, bucketH } = G;
    ctx.clearRect(0, 0, w, h);
    const gold = activeGold(now);
    // pegs
    for (let r = 0; r < rows; r++) {
      for (let i = 0; i < r + 3; i++) {
        const x = pegX(r, i), y = pegY(r), k = r + ':' + i;
        const f = flashes.get(k), age = f ? now - f.t : 1e9;
        if (gold.has(k)) {
          const pulse = 1 + Math.sin(now / 160) * .18;
          const g = ctx.createRadialGradient(x, y, 0, x, y, pegR * 5 * pulse);
          g.addColorStop(0, 'rgba(255,217,138,.85)'); g.addColorStop(1, 'rgba(255,182,39,0)');
          ctx.fillStyle = g; ctx.beginPath(); ctx.arc(x, y, pegR * 5 * pulse, 0, 7); ctx.fill();
          ctx.fillStyle = '#ffd98a'; ctx.beginPath(); ctx.arc(x, y, pegR * 1.8, 0, 7); ctx.fill();
          ctx.strokeStyle = '#fff3cf'; ctx.lineWidth = 1.2; ctx.stroke();
        } else {
          ctx.fillStyle = age < 220 ? `rgba(255,255,255,${1 - age / 400})` : 'rgba(245,236,215,.72)';
          ctx.beginPath(); ctx.arc(x, y, pegR * (age < 220 ? 1.5 : 1), 0, 7); ctx.fill();
        }
        if (age < 360) {
          ctx.strokeStyle = f.gold ? `rgba(255,217,138,${1 - age / 360})` : `rgba(255,255,255,${.5 - age / 720})`;
          ctx.lineWidth = f.gold ? 3 : 1.5;
          ctx.beginPath(); ctx.arc(x, y, pegR + age / 360 * sx * (f.gold ? .7 : .35), 0, 7); ctx.stroke();
        }
      }
    }
    // heat bars + buckets
    const tb = table(), max = Math.max(...tb), hmax = Math.max(1, ...heat);
    ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    const fs = Math.max(8, Math.min(13, sx * 0.27));
    ctx.font = `600 ${fs}px "Chivo Mono", monospace`;
    for (let k = 0; k <= rows; k++) {
      const x = slotX(k), p = pulses.get(k), age = p ? now - p : 1e9;
      const bounce = age < 320 ? Math.sin(age / 320 * Math.PI) * 7 : 0;
      const bw = sx * 0.9, y = bucketY + bounce;
      if (heat[k]) { ctx.fillStyle = 'rgba(255,243,207,.22)'; ctx.fillRect(x - bw / 2, bucketY - 4 - heat[k] / hmax * 14, bw, heat[k] / hmax * 14); }
      ctx.fillStyle = bucketColor(tb[k], max);
      roundRect(x - bw / 2, y, bw, bucketH, 6); ctx.fill();
      if (age < 500) { ctx.fillStyle = `rgba(255,255,255,${.55 - age / 900})`; roundRect(x - bw / 2, y, bw, bucketH, 6); ctx.fill(); }
      ctx.fillStyle = tb[k] >= 1 && tb[k] < max * .02 ? '#1a1204' : (tb[k] < 1 ? '#e8fff9' : '#1a1204');
      ctx.fillText(fmtMult(tb[k]), x, y + bucketH / 2 + 1);
    }
    // sparks
    for (const s of sparks) { ctx.fillStyle = `rgba(255,217,138,${s.life})`; ctx.beginPath(); ctx.arc(s.x, s.y, 2.2 * s.life + .5, 0, 7); ctx.fill(); }
    // balls
    for (const b of balls) {
      if (!b.pos) continue;
      b.trail.forEach((t, i) => { ctx.fillStyle = b.goldHits ? `rgba(255,217,138,${i / 18})` : `rgba(255,255,255,${i / 26})`; ctx.beginPath(); ctx.arc(t[0], t[1], ballR * (.4 + i / 12), 0, 7); ctx.fill(); });
      const [x, y] = b.pos;
      const g = ctx.createRadialGradient(x - ballR * .35, y - ballR * .35, ballR * .1, x, y, ballR);
      if (b.goldHits) { g.addColorStop(0, '#fffbe8'); g.addColorStop(.5, '#ffd98a'); g.addColorStop(1, '#d19a1a'); }
      else { g.addColorStop(0, '#ffffff'); g.addColorStop(.6, '#f3e9ff'); g.addColorStop(1, '#b9a6dc'); }
      ctx.fillStyle = g; ctx.beginPath(); ctx.arc(x, y, ballR, 0, 7); ctx.fill();
      if (b.goldHits > 1) { ctx.fillStyle = '#1a1204'; ctx.font = `800 ${ballR}px Figtree, sans-serif`; ctx.fillText('×' + (2 ** b.goldHits), x, y + .5); }
    }
    // floats
    for (const f of floats) {
      const age = (now - f.t) / f.dur; if (age < 0) continue;
      ctx.globalAlpha = Math.max(0, 1 - age);
      ctx.fillStyle = f.color; ctx.font = `${f.weight} ${f.size}px ${f.font}`;
      ctx.fillText(f.text, f.x, f.y - age * f.rise);
      ctx.globalAlpha = 1;
    }
  }
  function roundRect(x, y, w, h, r) { ctx.beginPath(); ctx.moveTo(x + r, y); ctx.arcTo(x + w, y, x + w, y + h, r); ctx.arcTo(x + w, y + h, x, y + h, r); ctx.arcTo(x, y + h, x, y, r); ctx.arcTo(x, y, x + w, y, r); ctx.closePath(); }
  const fmtMult = m => (m >= 100 ? Math.round(m) : +m.toFixed(2)) + '×';
  function float(text, x, y, o = {}) { floats.push({ text, x, y, t: performance.now(), dur: o.dur || 900, rise: o.rise || 26, color: o.color || '#fff3cf', size: o.size || 13, weight: o.weight || 700, font: o.font || 'Figtree, sans-serif' }); }

  /* ── pearls ── */
  function makeBall(b, drop, t0) {
    const bits = b.path.split('').map(Number), ks = [0];
    bits.forEach((d, r) => ks.push(ks[r] + d));
    return { ...b, bits, ks, hitSet: new Set(b.hits), drop, t0, row: -1, goldHits: 0, pos: null, trail: [], done: false };
  }
  const contact = (b, r) => [G.cx + (b.ks[r] - r / 2) * G.sx, pegY(r) - G.pegR - G.ballR * .9];
  function step(b, now) {
    const D = turbo() ? 62 : 118, e = now - b.t0;
    if (e < 0) return;
    const start = [G.cx, G.top - G.sy * 1.05];
    let P, Q, u, hop = G.sy * .26;
    if (e < D) { P = start; Q = contact(b, 0); u = e / D; b.pos = [P[0], P[1] + (Q[1] - P[1]) * u * u]; }
    else {
      const e2 = e - D, r = Math.floor(e2 / D);
      while (b.row < Math.min(r, rows - 1)) { b.row++; hitPeg(b, b.row, now); }
      if (r >= rows - 1) {
        P = contact(b, rows - 1); Q = [slotX(b.slot), G.bucketY + G.bucketH * .3]; u = (e2 - (rows - 1) * D) / (D * 1.25);
        if (u >= 1) { land(b, now); return; }
        hop = G.sy * .18;
      } else { P = contact(b, r); Q = contact(b, r + 1); u = (e2 - r * D) / D; }
      const eo = 1 - (1 - u) * (1 - u);
      b.pos = [P[0] + (Q[0] - P[0]) * eo, P[1] + (Q[1] - P[1]) * u * u - hop * Math.sin(Math.PI * u)];
    }
    b.trail.push(b.pos); if (b.trail.length > 7) b.trail.shift();
  }
  function hitPeg(b, r, now) {
    const i = 1 + b.ks[r], k = r + ':' + i, x = pegX(r, i), y = pegY(r);
    const isGold = b.hitSet.has(r);
    flashes.set(k, { t: now, gold: isGold });
    if (isGold) {
      b.goldHits++;
      for (let n = 0; n < 16; n++) { const a = Math.random() * 7, v = 1 + Math.random() * 2.4; sparks.push({ x, y, vx: Math.cos(a) * v, vy: Math.sin(a) * v - 1, life: 1 }); }
      float('×' + (2 ** b.goldHits), x, y - 12, { color: '#ffd98a', size: 16, weight: 800, font: 'Limelight, serif' });
      pdAudio.gold();
    } else pdAudio.tink(r);
  }
  function land(b, now) {
    b.done = true; b.pos = null;
    pulses.set(b.slot, now); heat[b.slot]++;
    const x = slotX(b.slot), y = G.bucketY - 10;
    float(fmtMult(b.mult), x, y, { color: b.mult >= 10 ? '#ff9f8f' : b.mult >= 1 ? '#fff3cf' : '#9fd6cf', size: b.mult >= 10 ? 18 : 13, weight: 800, rise: b.mult >= 10 ? 60 : 30, dur: b.mult >= 10 ? 1500 : 900, font: b.mult >= 10 ? 'Limelight, serif' : 'Figtree, sans-serif' });
    pdAudio.land(b.mult);
    pushHist(b);
    stats.balls++; stats.best = Math.max(stats.best, b.mult);
    if (--b.drop.left === 0) finishDrop(b.drop, now);
  }

  /* ── loop ── */
  function frame(now) {
    for (const b of balls) if (!b.done) step(b, now);
    for (let i = balls.length - 1; i >= 0; i--) if (balls[i].done) balls.splice(i, 1);
    for (const s of sparks) { s.x += s.vx; s.y += s.vy; s.vy += .08; s.life -= .03; }
    for (let i = sparks.length - 1; i >= 0; i--) if (sparks[i].life <= 0) sparks.splice(i, 1);
    for (let i = floats.length - 1; i >= 0; i--) if (now - floats[i].t > floats[i].dur) floats.splice(i, 1);
    for (let i = drops.length - 1; i >= 0; i--) if (drops[i].left === 0 && now > drops[i].goldUntil + 200) drops.splice(i, 1);
    draw(now);
    const busy = balls.length || sparks.length || floats.length || drops.length || [...flashes.values()].some(f => now - f.t < 400) || [...pulses.values()].some(p => now - p < 500);
    raf = busy ? requestAnimationFrame(frame) : 0;
  }
  const kick = () => { if (!raf) raf = requestAnimationFrame(frame); };

  /* ── session stats + history ── */
  let stats = { drops: 0, balls: 0, wagered: 0, won: 0, best: 0 };
  try { stats = Object.assign(stats, JSON.parse(sessionStorage.getItem('pd_stats') || '{}')); } catch (e) {}
  function paintStats() {
    const set = (k, v) => { const e = el.querySelector(`[data-st="${k}"]`); if (e) e.textContent = v; };
    set('drops', fmt(stats.drops)); set('balls', fmt(stats.balls)); set('wagered', fmt(stats.wagered)); set('won', fmt(stats.won));
    const net = stats.won - stats.wagered; set('net', (net >= 0 ? '+' : '') + fmt(net));
    const ne = el.querySelector('[data-st="net"]'); if (ne) ne.className = net >= 0 ? 'pos' : 'neg';
    set('best', stats.best ? fmtMult(stats.best) : '–');
    try { sessionStorage.setItem('pd_stats', JSON.stringify(stats)); } catch (e) {}
  }
  $('[data-pd-reset]', el).addEventListener('click', () => { stats = { drops: 0, balls: 0, wagered: 0, won: 0, best: 0 }; heat = new Array(rows + 1).fill(0); paintStats(); draw(performance.now()); });
  function pushHist(b) {
    const li = document.createElement('li');
    li.className = b.mult >= 10 ? 'top' : b.mult >= 2 ? 'hi' : b.mult >= 1 ? 'mid' : 'lo';
    li.textContent = fmtMult(b.mult) + (b.hits.length ? ' ✦' : '');
    hist.prepend(li);
    while (hist.children.length > 18) hist.lastElementChild.remove();
  }
  paintStats();

  /* ── controls ── */
  const updCost = () => { costEl.textContent = fmt((+form.bet.value || 0) * (+pick('balls') || 1)); };
  form.addEventListener('input', updCost);
  form.addEventListener('change', e => {
    if (e.target.name === 'rows' || e.target.name === 'risk') {
      if (balls.length) { e.preventDefault(); return; }
      rows = +pick('rows'); risk = pick('risk'); heat = new Array(rows + 1).fill(0); layout();
    }
    updCost();
  });
  const lockGeometry = on => $$('input[name="rows"], input[name="risk"]', form).forEach(i => { i.disabled = on; });

  function finishDrop(drop, now) {
    drop.goldUntil = now + 1100;
    const d = drop.d;
    stats.drops++; stats.wagered += d.bet; stats.won += d.payout; paintStats();
    if (drop.seq >= applied) { applied = drop.seq; setBalance(d.balance); }
    resEl.textContent = d.message;
    resEl.classList.toggle('win', d.payout > d.bet);
    const best = Math.max(...d.balls.map(b => b.mult));
    if (best >= 10) {
      const tier = best >= 1000 ? 'LEGENDARY' : best >= 100 ? 'MEGA WIN' : 'BIG WIN';
      banner.innerHTML = `<b>${tier}</b><span>${fmtMult(best)}</span>`;
      banner.classList.remove('show'); void banner.offsetWidth; banner.classList.add('show');
      burst(banner, best >= 100 ? 30 : 18); pdAudio.big();
      if (!reduce) el.querySelector('.pd-board').animate([{ transform: 'translate(0,0)' }, { transform: 'translate(-4px,2px)' }, { transform: 'translate(4px,-2px)' }, { transform: 'translate(0,0)' }], { duration: 220, iterations: 2 });
    } else if (d.payout > d.bet) burst(resEl, 8);
    if (!balls.some(b => !b.done)) lockGeometry(false);
    drop.resolve && drop.resolve(d);
  }

  async function drop() {
    if (inflight >= 2) return null;
    pdAudio.unlock();
    const fd = new FormData(form);
    const cost = (+form.bet.value || 0) * (+pick('balls') || 1);
    const balEl = document.querySelector('[data-balance]');
    const before = balEl ? +balEl.dataset.balance : null;
    if (before !== null && cost > before) { toast('Not enough Gold Coins for that drop.', 'err'); return null; }
    inflight++; const my = ++seq;
    lockGeometry(true);
    if (before !== null) setBalance(before - cost);
    let d;
    try { d = await post(playUrl('plinko'), fd); }
    catch (err) {
      inflight--; toast(err.message, 'err');
      if (before !== null) setBalance(before);
      if (!balls.length) lockGeometry(false);
      return null;
    }
    inflight--;
    const now = performance.now(), gap = turbo() ? 55 : 105;
    const dropObj = { d, gold: d.gold, left: d.balls.length, seq: my, goldUntil: Infinity };
    drops.push(dropObj);
    d.balls.forEach((b, i) => balls.push(makeBall(b, dropObj, now + i * gap)));
    const nonceEl = document.querySelector('[data-fair-nonce]'); if (nonceEl) nonceEl.textContent = d.next_nonce;
    kick();
    if (reduce) { // no motion: settle instantly
      balls.forEach(b => { if (b.drop === dropObj) { for (let r = 0; r < rows; r++) hitPeg(b, r, now); land(b, now); } });
    }
    return new Promise(res => { dropObj.resolve = res; if (dropObj.left === 0) res(d); });
  }
  form.addEventListener('submit', e => { e.preventDefault(); drop(); });
  document.addEventListener('keydown', e => {
    if (e.code === 'Space' && e.target === document.body && el.isConnected) { e.preventDefault(); drop(); }
  });

  autoBtn.addEventListener('click', async () => {
    if (auto) { auto = false; return; }
    auto = true;
    const n = +$('[data-pd-auto-n]', el).value;
    const sm = +$('[data-pd-stop-mult]', el).value || 0, sw = +$('[data-pd-stop-win]', el).value || 0, sl = +$('[data-pd-stop-loss]', el).value || 0;
    const startNet = stats.won - stats.wagered;
    let count = 0;
    autoBtn.classList.add('coral');
    while (auto && (n === 0 || count < n)) {
      autoBtn.textContent = `Stop autoplay (${count}${n ? '/' + n : ''})`;
      const d = await drop();
      if (!d) break;
      count++;
      const net = stats.won - stats.wagered - startNet;
      if (sm && d.balls.some(b => b.mult >= sm)) { toast(`Autoplay stopped: hit ${fmtMult(Math.max(...d.balls.map(b => b.mult)))}`, 'ok'); break; }
      if (sw && net >= sw) { toast('Autoplay stopped: profit target reached.', 'ok'); break; }
      if (sl && -net >= sl) { toast('Autoplay stopped: loss limit reached.', 'info'); break; }
      await sleep(turbo() ? 60 : 220);
    }
    auto = false;
    autoBtn.classList.remove('coral');
    autoBtn.textContent = 'Start autoplay';
  });

  const snd = $('[data-pd-sound]', el);
  const paintSnd = () => { snd.setAttribute('aria-pressed', pdAudio.on ? 'true' : 'false'); snd.setAttribute('aria-label', pdAudio.on ? 'Sound on' : 'Sound off'); snd.classList.toggle('muted', !pdAudio.on); };
  snd.addEventListener('click', () => { pdAudio.set(!pdAudio.on); paintSnd(); });
  paintSnd();

  $('[data-pd-fair-open]', el).addEventListener('click', e => { e.preventDefault(); const f = $('#pd-fair'); f.open = true; f.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' }); });

  /* ── provably fair ── */
  const vIn = k => $(`[data-v="${k}"]`, el), out = $('[data-fair-out]', el);
  const fillVerify = o => { vIn('seed').value = o.seed; vIn('client').value = o.client; vIn('nonce').value = Math.max(0, (o.n || 1) - 1); };
  el.addEventListener('click', e => { const b = e.target.closest('[data-fair-use]'); if (b) fillVerify(JSON.parse(b.dataset.fairUse)); });
  $('[data-fair-rotate]', el).addEventListener('submit', async e => {
    e.preventDefault();
    try {
      const d = await post(e.target.action, new FormData(e.target));
      $('[data-fair-hash]', el).textContent = d.active.server_hash;
      $('[data-fair-client]', el).textContent = d.active.client_seed;
      $('[data-fair-nonce]', el).textContent = '0';
      const list = $('[data-fair-revealed]', el), r = d.revealed;
      const li = document.createElement('li');
      li.innerHTML = `<button type="button" class="linkish"><code>${esc(r.server_seed.slice(0, 16))}…</code> · ${r.nonces} drops</button>`;
      li.firstChild.dataset.fairUse = JSON.stringify({ seed: r.server_seed, client: r.client_seed, n: r.nonces });
      const empty = list.querySelector('.muted'); if (empty) empty.remove();
      list.prepend(li);
      fillVerify({ seed: r.server_seed, client: r.client_seed, n: r.nonces });
      e.target.reset();
      toast(d.message, 'ok');
    } catch (err) { toast(err.message, 'err'); }
  });
  $('[data-fair-check]', el).addEventListener('click', async () => {
    if (!(window.crypto && crypto.subtle)) { out.textContent = 'Your browser only allows this check over HTTPS.'; return; }
    const seed = vIn('seed').value.trim(), client = vIn('client').value.trim(), nonce = +vIn('nonce').value, vr = +vIn('rows').value, ball = Math.max(1, +vIn('ball').value) - 1;
    if (!seed || !client) { out.textContent = 'Need both a server seed and a client seed.'; return; }
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(seed), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const hm = async m => new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(m)));
    const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(seed)))].map(x => x.toString(16).padStart(2, '0')).join('');
    const pb = await hm(`${client}:${nonce}:ball:${ball}`);
    const bits = []; for (let r = 0; r < vr; r++) bits.push(pb[r] >= 128 ? 1 : 0);
    const slot = bits.reduce((a, b) => a + b, 0);
    const pegs = []; for (let r = 0; r < vr; r++) for (let i = 1; i <= r + 1; i++) pegs.push([r, i]);
    const gb = await hm(`${client}:${nonce}:gold`), gold = [];
    for (let j = 0; j < cfg.gold; j++) {
      const u = ((gb[j * 4] << 24 | gb[j * 4 + 1] << 16 | gb[j * 4 + 2] << 8 | gb[j * 4 + 3]) >>> 0) % (pegs.length - j);
      [pegs[j], pegs[j + u]] = [pegs[j + u], pegs[j]]; gold.push(pegs[j]);
    }
    let k = 0, hits = 0;
    const gs = new Set(gold.map(([r, i]) => r + ':' + i));
    bits.forEach((d, r) => { if (gs.has(r + ':' + (1 + k))) hits++; k += d; });
    const m = rk => +(cfg.tables[vr][rk][slot] * 2 ** hits).toFixed(2);
    out.textContent = [
      `sha256(server seed) = ${hash}`,
      `path (pearl #${ball + 1}): ${bits.map(b => b ? 'R' : 'L').join(' ')}`,
      `lands in bucket ${slot} of 0–${vr}`,
      `golden pegs: ${gold.map(([r, i]) => `row ${r + 1} peg ${i}`).join(', ')}`,
      `golden pegs touched: ${hits}  →  ×${2 ** hits}`,
      `multiplier: low ${m('low')}× · medium ${m('med')}× · high ${m('high')}×`,
    ].join('\n');
  });

  if ('ResizeObserver' in window) new ResizeObserver(() => { if (Math.abs((cv.clientWidth || 0) - G.w) > 1) layout(); }).observe(cv);
  layout(); updCost();
}

/* ═════ SLOT HALL (themed video slots) ═════
 * The server returns the whole outcome (base grid + every free spin). This plays it
 * back: reel spin with scatter anticipation, win highlights, free-spin mode, tier banners.
 */
const sfx = (() => {
  let ac = null, on = true;
  try { on = localStorage.getItem('gt_sound') !== 'off'; } catch (e) {}
  const unlock = () => { if (!on) return; if (!ac) { try { ac = new (window.AudioContext || window.webkitAudioContext)(); } catch (e) { return; } } if (ac.state === 'suspended') ac.resume(); };
  const tone = (f, dur, o = {}) => {
    if (!on || !ac) return;
    const t = ac.currentTime + (o.when || 0), osc = ac.createOscillator(), g = ac.createGain();
    osc.type = o.type || 'sine'; osc.frequency.setValueAtTime(f, t);
    if (o.glide) osc.frequency.exponentialRampToValueAtTime(o.glide, t + dur);
    if (o.vib) { const l = ac.createOscillator(), lg = ac.createGain(); l.frequency.value = o.vib; lg.gain.value = f * .03; l.connect(lg).connect(osc.frequency); l.start(t); l.stop(t + dur + .05); }
    g.gain.setValueAtTime(o.vol || .05, t); g.gain.exponentialRampToValueAtTime(0.0001, t + dur);
    osc.connect(g).connect(ac.destination); osc.start(t); osc.stop(t + dur + .05);
  };
  // each theme gets its own instrument + scale for stops and win jingles
  const T = {
    abyss:    { type: 'sine', scale: [262, 311, 392, 466, 523, 622], glide: 1.5 },
    tinfoil:  { type: 'sine', scale: [330, 415, 494, 622, 740, 988], vib: 6 },
    blacksite:{ type: 'square', scale: [220, 262, 330, 392, 440, 523], vol: .025 },
    coderain: { type: 'square', scale: [392, 494, 587, 740, 880, 1175], vol: .02 },
    tiki:     { type: 'triangle', scale: [392, 440, 494, 587, 659, 784] },
    calavera: { type: 'sawtooth', scale: [349, 440, 523, 587, 698, 880], vol: .025 },
    classic:  { type: 'triangle', scale: [523, 587, 659, 784, 880, 1047] },
    lounge:   { type: 'sine', scale: [262, 330, 392, 494, 587, 659], vib: 4 },
    carnival: { type: 'square', scale: [523, 659, 784, 880, 1047, 1319], vol: .018 },
    ocean:    { type: 'sine', scale: [294, 349, 440, 523, 587, 698] },
    arcade:   { type: 'square', scale: [440, 554, 659, 880, 1109, 1319], vol: .02 },
  };
  let noiseBuf = null;
  const noise = (dur, freq, vol, when = 0) => {
    if (!on || !ac) return;
    if (!noiseBuf) { noiseBuf = ac.createBuffer(1, ac.sampleRate * .3, ac.sampleRate); const d = noiseBuf.getChannelData(0); for (let i = 0; i < d.length; i++) d[i] = Math.random() * 2 - 1; }
    const t = ac.currentTime + when, src = ac.createBufferSource(), f = ac.createBiquadFilter(), g = ac.createGain();
    src.buffer = noiseBuf; f.type = 'bandpass'; f.frequency.value = freq; f.Q.value = 1.2;
    g.gain.setValueAtTime(vol, t); g.gain.exponentialRampToValueAtTime(0.0001, t + dur);
    src.connect(f).connect(g).connect(ac.destination); src.start(t); src.stop(t + dur + .02);
  };
  const th = k => T[k] || T.classic;
  return {
    unlock, get on() { return on; },
    set(v) { on = v; try { localStorage.setItem('gt_sound', v ? 'on' : 'off'); } catch (e) {} if (v) unlock(); },
    stop(k, i) { const t = th(k); tone(t.scale[i % t.scale.length] / 2, .12, { type: t.type, vol: (t.vol || .05) * 1.2 }); },
    tick(k) { const t = th(k); tone(t.scale[0] * 2, .03, { type: 'square', vol: .008 }); },
    tease(k) { const t = th(k); tone(t.scale[2], .5, { type: t.type, vol: t.vol || .04, glide: t.scale[5] }); },
    win(k, size) { const t = th(k), n = Math.min(6, 2 + size); for (let i = 0; i < n; i++) tone(t.scale[i], .22, { type: t.type, vol: t.vol || .05, when: i * .08, vib: t.vib }); },
    scatter(k) { const t = th(k); [0, 2, 4, 5, 4, 5].forEach((s, i) => tone(t.scale[s] * 2, .3, { type: t.type, vol: t.vol || .05, when: i * .1, vib: t.vib })); },
    flip(when = 0) { noise(.07, 2600, .09, when); noise(.05, 900, .05, when + .02); },
    rattle() { for (let i = 0; i < 7; i++) noise(.04, 1400 + Math.random() * 1600, .07, i * .05 + Math.random() * .02); },
    chime(k, i = 0, when = 0) { const t = th(k); tone(t.scale[i % t.scale.length] * 2, .25, { type: 'sine', vol: .035, when }); },
    lose(k) { const t = th(k); tone(t.scale[1] / 2, .22, { type: t.type, vol: (t.vol || .04) * .8, glide: t.scale[0] / 3 }); },
    big(k) { const t = th(k); [0, 1, 2, 3, 4, 5, 5].forEach((s, i) => tone(t.scale[s] * (i > 5 ? 2 : 1), .45, { type: t.type, vol: (t.vol || .05) * 1.3, when: i * .11, vib: t.vib })); },
  };
})();

/* theme backdrops: one small particle system per slot, drawn behind the machine */
function vsFX(canvas, theme) {
  const ctx = canvas.getContext('2d');
  let w = 0, h = 0, parts = [], t0 = performance.now(), raf = 0;
  const R = (a, b) => a + Math.random() * (b - a);
  const GLY = '01アイウエオカキクケコサシスセソタチツテト7#$%ヲン';
  function size() {
    const r = canvas.getBoundingClientRect(), dpr = Math.min(2, devicePixelRatio || 1);
    w = r.width; h = r.height; canvas.width = w * dpr; canvas.height = h * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const n = { abyss: 60, tinfoil: 110, blacksite: 7, coderain: Math.floor(w / 16), tiki: 55, calavera: 45 }[theme] || 30;
    parts = Array.from({ length: n }, (_, i) => spawn(i, true));
  }
  function spawn(i, init) {
    switch (theme) {
      case 'abyss': return { x: R(0, w), y: init ? R(0, h) : h + 10, r: R(1.5, 6), v: R(.2, .9), wob: R(0, 6), glow: Math.random() < .3 };
      case 'tinfoil': return { x: R(0, w), y: R(0, h * .75), r: R(.5, 1.8), tw: R(0, 6) };
      case 'blacksite': return { a: R(0, Math.PI), v: R(-.004, .004) || .002, y: R(.1, .9), s: R(0, 1) };
      case 'coderain': return { x: i * 16 + 4, y: init ? R(-h, h) : R(-200, 0), v: R(2, 6), len: Math.floor(R(8, 24)) };
      case 'tiki': return { x: R(0, w), y: init ? R(0, h) : h + 5, v: R(.4, 1.4), r: R(1, 2.6), life: R(.4, 1) };
      case 'calavera': return { x: R(0, w), y: init ? R(0, h) : -10, v: R(.4, 1.2), rot: R(0, 6), vr: R(-.03, .03), r: R(4, 9), c: ['#ff9f1c', '#ffbf00', '#ff4fa3', '#e8ff5a'][i % 4] };
      default: return {};
    }
  }
  function frame(now) {
    const t = (now - t0) / 1000;
    ctx.clearRect(0, 0, w, h);
    if (theme === 'abyss') {
      for (let k = 0; k < 4; k++) { const x = w * (.15 + k * .25) + Math.sin(t * .3 + k) * 40; const g = ctx.createLinearGradient(x, 0, x + 60, h); g.addColorStop(0, 'rgba(120,220,255,.08)'); g.addColorStop(1, 'rgba(120,220,255,0)'); ctx.fillStyle = g; ctx.beginPath(); ctx.moveTo(x - 30, 0); ctx.lineTo(x + 30, 0); ctx.lineTo(x + 160, h); ctx.lineTo(x + 40, h); ctx.fill(); }
      parts.forEach((p, i) => { p.y -= p.v; p.x += Math.sin(t * 1.5 + p.wob) * .3; if (p.y < -10) parts[i] = spawn(i);
        ctx.strokeStyle = p.glow ? 'rgba(95,255,220,.7)' : 'rgba(200,240,255,.35)'; ctx.fillStyle = p.glow ? 'rgba(95,255,220,.25)' : 'rgba(200,240,255,.06)';
        ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, 7); ctx.fill(); ctx.stroke(); });
    } else if (theme === 'tinfoil') {
      parts.forEach(p => { ctx.fillStyle = `rgba(255,255,240,${.4 + .6 * Math.abs(Math.sin(t * 1.3 + p.tw))})`; ctx.fillRect(p.x, p.y, p.r, p.r); });
      const ux = ((t * 60) % (w + 300)) - 150, uy = h * .18 + Math.sin(t * 2) * 12;
      ctx.fillStyle = 'rgba(150,255,170,.12)'; ctx.beginPath(); ctx.moveTo(ux - 8, uy + 6); ctx.lineTo(ux + 8, uy + 6); ctx.lineTo(ux + 50, h); ctx.lineTo(ux - 50, h); ctx.fill();
      ctx.fillStyle = '#b8c0d8'; ctx.beginPath(); ctx.ellipse(ux, uy, 26, 7, 0, 0, 7); ctx.fill(); ctx.fillStyle = '#8fffa8'; ctx.beginPath(); ctx.ellipse(ux, uy - 5, 10, 7, 0, Math.PI, 0); ctx.fill();
      for (let k = 0; k < 2; k++) { const a = Math.sin(t * .6 + k * 2) * .6 - Math.PI / 2; const x0 = k ? w * .9 : w * .1; const g = ctx.createRadialGradient(x0, h, 0, x0, h, h * 1.2); g.addColorStop(0, 'rgba(255,255,200,.10)'); g.addColorStop(1, 'rgba(255,255,200,0)'); ctx.fillStyle = g; ctx.beginPath(); ctx.moveTo(x0, h); ctx.arc(x0, h, h * 1.2, a - .12, a + .12); ctx.fill(); }
    } else if (theme === 'blacksite') {
      ctx.strokeStyle = 'rgba(95,230,255,.06)'; ctx.lineWidth = 1;
      for (let x = 0; x < w; x += 28) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke(); }
      for (let y = 0; y < h; y += 28) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke(); }
      parts.forEach(p => { p.a += p.v; const cy = h * p.y, dx = Math.cos(p.a) * w, dy = Math.sin(p.a) * w * .3;
        ctx.strokeStyle = 'rgba(255,40,60,.55)'; ctx.lineWidth = 1.5; ctx.shadowColor = '#ff2840'; ctx.shadowBlur = 8;
        ctx.beginPath(); ctx.moveTo(w / 2 - dx, cy - dy); ctx.lineTo(w / 2 + dx, cy + dy); ctx.stroke(); ctx.shadowBlur = 0; });
      const sy = (t * 90) % h; const g = ctx.createLinearGradient(0, sy - 30, 0, sy); g.addColorStop(0, 'rgba(95,230,255,0)'); g.addColorStop(1, 'rgba(95,230,255,.12)'); ctx.fillStyle = g; ctx.fillRect(0, sy - 30, w, 30);
    } else if (theme === 'coderain') {
      ctx.font = '14px "Chivo Mono", monospace';
      parts.forEach((p, i) => { p.y += p.v; if (p.y - p.len * 16 > h) parts[i] = spawn(i);
        for (let j = 0; j < p.len; j++) { const y = p.y - j * 16; if (y < -16 || y > h + 16) continue;
          ctx.fillStyle = j === 0 ? 'rgba(220,255,230,.95)' : `rgba(0,255,102,${.55 * (1 - j / p.len)})`;
          ctx.fillText(GLY[(Math.floor(t * 8) + i * 7 + j * 3) % GLY.length], p.x, y); } });
    } else if (theme === 'tiki') {
      const g = ctx.createLinearGradient(0, h, 0, h * .4); g.addColorStop(0, 'rgba(255,120,30,.22)'); g.addColorStop(1, 'rgba(255,120,30,0)'); ctx.fillStyle = g; ctx.fillRect(0, 0, w, h);
      parts.forEach((p, i) => { p.y -= p.v; p.x += Math.sin(t * 2 + i) * .5; p.life -= .004; if (p.y < 0 || p.life <= 0) parts[i] = spawn(i);
        ctx.fillStyle = `rgba(255,${150 + Math.floor(p.life * 90)},60,${p.life})`; ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, 7); ctx.fill(); });
    } else if (theme === 'calavera') {
      parts.forEach((p, i) => { p.y += p.v; p.x += Math.sin(t + i) * .4; p.rot += p.vr; if (p.y > h + 10) parts[i] = spawn(i);
        ctx.save(); ctx.translate(p.x, p.y); ctx.rotate(p.rot); ctx.fillStyle = p.c; ctx.beginPath(); ctx.ellipse(0, 0, p.r, p.r * .55, 0, 0, 7); ctx.fill(); ctx.restore(); });
    }
    raf = canvas.isConnected && !reduce ? requestAnimationFrame(frame) : 0;
  }
  size();
  if ('ResizeObserver' in window) new ResizeObserver(size).observe(canvas);
  if (reduce) frame(performance.now()); else raf = requestAnimationFrame(frame);
}

function initVideoSlot(root) {
  const el = $('[data-vslot]', root);
  if (!el || el.dataset.ready) return;
  el.dataset.ready = '1';
  const cfg = JSON.parse(el.dataset.cfg), K = cfg.slug;
  vsFX($('[data-vs-fx]', el), K);
  const reels = $$('.vs-reel', el), form = $('[data-vs-form]', el), spinBtn = $('[data-vs-spin]', el);
  const winEl = $('[data-vs-win]', el), msgEl = $('[data-vs-msg]', el), banner = $('[data-vs-banner]', el);
  const fsbar = $('[data-vs-fsbar]', el), autoBtn = $('[data-vs-auto]', el);
  const turbo = () => $('[data-vs-turbo]', el).checked;
  const syms = Object.keys(cfg.art).filter(s => s !== 'S' && s !== 'W');
  const cellHtml = s => `<div class="vs-cell" data-s="${s}"><svg viewBox="0 0 64 64" role="img" aria-label="${esc(cfg.names[s] || s)}">${cfg.art[s]}</svg></div>`;
  let busy = false, auto = false;

  const paytable = () => { const b = +form.bet.value || 0; $$('[data-vs-paygrid] [data-pay]', el).forEach(x => { const s = x.closest('[data-sym]').dataset.sym; x.textContent = fmt(Math.floor(cfg.pays[s][+x.dataset.pay] * b)); }); $$('[data-jp]', el).forEach(x => { x.textContent = fmt(+x.dataset.jp * b); }); };
  form.addEventListener('input', paytable); paytable();

  function spinReel(reel, final, i, teaseMs) {
    const strip = $('.vs-strip', reel), cell = reel.clientHeight / 3;
    const current = $$('.vs-cell', strip).map(c => c.dataset.s);
    const base = turbo() ? 380 : 700, n = 14 + i * 4 + Math.round(teaseMs / 60);
    const filler = Array.from({ length: n - 3 }, () => Math.random() < .06 ? (Math.random() < .5 ? 'W' : 'S') : syms[Math.floor(Math.random() * syms.length)]);
    strip.innerHTML = [...final, ...filler, ...current].map(cellHtml).join('');
    reel.classList.add('spinning');
    if (teaseMs) reel.classList.add('tease');
    const dur = base + i * (turbo() ? 110 : 190) + teaseMs;
    const a = strip.animate([{ transform: `translateY(${-n * cell}px)` }, { transform: 'translateY(8px)', offset: .92 }, { transform: 'translateY(0)' }],
      { duration: reduce ? 1 : dur, easing: 'cubic-bezier(.25,.65,.3,1)', fill: 'forwards' });
    let ticks = setInterval(() => sfx.tick(K), 90);
    return a.finished.then(() => { clearInterval(ticks); strip.innerHTML = final.map(cellHtml).join(''); a.cancel(); reel.classList.remove('spinning', 'tease'); sfx.stop(K, i); });
  }
  async function showGrid(grid) {
    // anticipation: once 2 scatters are showing, the remaining reels slow down and glow
    let seen = 0;
    const teases = [];
    for (let r = 0; r < 5; r++) { teases.push(seen >= 2 && !reduce ? (turbo() ? 500 : 1100) * (r - 1) / 3 : 0); seen += grid[r].filter(s => s === 'S').length; }
    if (teases.some(Boolean)) sfx.tease(K);
    if (el._v3d && el.classList.contains('cab3d')) {
      reels.forEach((reel, r) => { $('.vs-strip', reel).innerHTML = grid[r].map(cellHtml).join(''); });
      const ticks = setInterval(() => sfx.tick(K), 90);
      await el._v3d.spin(grid, teases, turbo());
      clearInterval(ticks); sfx.stop(K, 4);
      return;
    }
    await Promise.all(teases.map((t, r) => spinReel(reels[r], grid[r], r, t)));
  }
  const cellAt = (r, y) => $$('.vs-cell', reels[r])[y];
  function clearHi() { $$('.vs-cell', el).forEach(c => c.classList.remove('hit', 'dim', 'scat')); }
  async function presentWins(wins, scatters, win, label) {
    clearHi();
    if (scatters.length >= 3) { scatters.forEach(([r, y]) => cellAt(r, y).classList.add('scat')); }
    if (el._v3d) el._v3d.highlight([...wins.flatMap(w => w.cells), ...(scatters.length >= 3 ? scatters : [])]);
    if (!wins.length) { if (win) countTo(win); return; }
    $$('.vs-cell', el).forEach(c => c.classList.add('dim'));
    wins.forEach(w => w.cells.forEach(([r, y]) => { const c = cellAt(r, y); c.classList.remove('dim'); c.classList.add('hit'); }));
    sfx.win(K, Math.min(4, wins.length));
    countTo(win);
    msgEl.textContent = (label ? label + ' · ' : '') + wins.slice(0, 3).map(w => `${w.k}× ${cfg.names[w.sym]}${w.ways > 1 ? ' · ' + w.ways + ' ways' : ''}`).join('  |  ');
    await sleep(turbo() ? 450 : 1000);
  }
  let shown = 0;
  function countTo(v) {
    const from = shown; shown = v;
    if (reduce || v === from) { winEl.textContent = fmt(v); return; }
    const t0 = performance.now(), d = Math.min(1600, 400 + (v - from) / 4);
    const step = t => { const k = Math.min(1, (t - t0) / d); winEl.textContent = fmt(Math.round(from + (v - from) * k)); if (k < 1) requestAnimationFrame(step); };
    requestAnimationFrame(step);
  }
  function showBanner(html, cls, ms) {
    banner.className = 'vs-banner ' + cls; banner.style.setProperty('--dur', ms + 'ms'); banner.innerHTML = html; void banner.offsetWidth; banner.classList.add('show');
    return sleep(ms);
  }

  const JP = { 25: 'MINI', 75: 'MINOR', 250: 'MAJOR', 1000: 'GRAND' };
  // the bonus outcome is already decided by the server; this only lets the player reveal it
  async function playBonus(b, bet) {
    const box = $('[data-vs-bonus]', el);
    const val = v => `<b>${JP[v] || v + '×'}</b><small>${fmt(Math.floor(v * bet))}</small>`;
    box.className = 'vs-bonus ' + b.type; box.hidden = false;
    sfx.scatter(K);
    if (b.type === 'pick') {
      box.innerHTML = `<div class="vb-head"><b>${esc(b.name)}</b><span>Pick <b data-vb-left>3</b> · won <b data-vb-won>0</b> GC</span></div>
        <div class="vb-grid">${Array.from({ length: 12 }, (_, i) => `<button type="button" class="vb-tile" aria-label="Tile ${i + 1}"><svg viewBox="0 0 64 64" aria-hidden="true">${cfg.art.W}</svg></button>`).join('')}</div>`;
      await new Promise(done => {
        let n = 0, got = 0, timer = 0;
        const arm = () => { timer = setTimeout(() => { const c = $$('.vb-tile:not(.open)', box); pick(c[Math.floor(Math.random() * c.length)]); }, auto ? (turbo() ? 350 : 800) : 15000); };
        const pick = t => {
          if (!t || n >= 3 || t.classList.contains('open')) return;
          clearTimeout(timer);
          const v = b.picks[n++]; got += v;
          t.classList.add('open'); if (JP[v]) t.classList.add('jp'); t.innerHTML = val(v);
          sfx.win(K, JP[v] ? 4 : 1); if (JP[v]) burst(t, 16);
          $('[data-vb-left]', box).textContent = 3 - n; $('[data-vb-won]', box).textContent = fmt(Math.floor(got * bet));
          if (n < 3) { arm(); return; }
          setTimeout(() => {
            let k = 0; $$('.vb-tile:not(.open)', box).forEach(x => { x.classList.add('open', 'miss'); x.innerHTML = val(b.others[k++]); });
            setTimeout(done, turbo() ? 900 : 1900);
          }, turbo() ? 250 : 600);
        };
        box.addEventListener('click', e => pick(e.target.closest('.vb-tile')));
        arm();
      });
    } else {
      const N = b.segments.length, seg = 360 / N, R = 96, pt = (a, r) => `${(Math.sin(a * Math.PI / 180) * r).toFixed(2)} ${(-Math.cos(a * Math.PI / 180) * r).toFixed(2)}`;
      const wedges = b.segments.map((v, i) => { const a0 = i * seg - seg / 2, a1 = a0 + seg;
        return `<path class="vb-seg ${JP[v] ? 'jp jp' + v : i % 2 ? 's1' : 's0'}" data-i="${i}" d="M0 0 L${pt(a0, R)} A${R} ${R} 0 0 1 ${pt(a1, R)} Z"/>`
          + `<text transform="rotate(${i * seg}) translate(0 -60) rotate(-90)" class="vb-lbl${JP[v] ? ' j' : ''}">${JP[v] || v + '×'}</text>`; }).join('');
      box.innerHTML = `<div class="vb-head"><b>${esc(b.name)}</b><span>Spin for up to the GRAND · ${fmt(1000 * bet)} GC</span></div>
        <div class="vb-wheel"><svg class="vb-svg" viewBox="-104 -114 208 218" aria-hidden="true"><g class="vb-disc"><circle r="99" class="vb-rim"/>${wedges}</g><circle r="20" class="vb-hub"/><path class="vb-ptr" d="M-10 -112 L10 -112 L0 -86 Z"/></svg>
        <button type="button" class="btn gold vb-go" data-vb-go>SPIN</button></div>`;
      const go = $('[data-vb-go]', box);
      await new Promise(r => { const t = setTimeout(() => go.click(), auto ? 600 : 15000); go.addEventListener('click', () => { clearTimeout(t); go.disabled = true; r(); }, { once: true }); });
      const disc = $('.vb-disc', box), target = 360 * 6 - b.stop * seg + (Math.random() - .5) * seg * .6, dur = reduce ? 1 : (turbo() ? 2600 : 5000);
      const t0 = performance.now(); let lastSeg = -1;
      const tk = setInterval(() => { const u = Math.min(1, (performance.now() - t0) / dur), ang = target * (1 - Math.pow(1 - u, 3.2)), s = Math.floor((ang + seg / 2) / seg); if (s !== lastSeg) { lastSeg = s; sfx.tick(K); } }, 30);
      await disc.animate([{ transform: 'rotate(0deg)' }, { transform: `rotate(${target}deg)` }], { duration: dur, easing: 'cubic-bezier(.15,.55,.12,1)', fill: 'forwards' }).finished;
      clearInterval(tk);
      const hit = $(`.vb-seg[data-i="${b.stop}"]`, box); if (hit) hit.classList.add('hit');
      sfx.win(K, JP[b.x] ? 4 : 2); if (JP[b.x]) burst(disc, 24);
      await sleep(turbo() ? 700 : 1400);
    }
    box.hidden = true; box.innerHTML = '';
    const top = Math.max(...(b.type === 'pick' ? b.picks : [b.x]).filter(v => JP[v]), 0);
    if (top) sfx.big(K);
    await showBanner(`<b>${top ? JP[top] + ' JACKPOT' : 'BONUS WIN'}</b><span>${fmt(b.win)} GC · ${b.x}×</span>`, top ? 'tier epic' : 'fs', turbo() ? 1300 : 2400);
  }

  async function spin() {
    if (busy) return null;
    sfx.unlock();
    const bet = +form.bet.value || 0;
    const balEl = document.querySelector('[data-balance]');
    const before = balEl ? +balEl.dataset.balance : null;
    if (before !== null && bet > before) { toast('Not enough Gold Coins for that bet.', 'err'); return null; }
    busy = true; spinBtn.disabled = true; el.classList.add('spinning');
    clearHi(); shown = 0; winEl.textContent = '0'; msgEl.textContent = 'Good luck…';
    if (before !== null) setBalance(before - bet);
    let d;
    try { d = await post(form.action, new FormData(form)); }
    catch (err) { toast(err.message, 'err'); if (before !== null) setBalance(before); busy = false; spinBtn.disabled = false; el.classList.remove('spinning'); return null; }
    await showGrid(d.grid);
    await presentWins(d.wins, d.scatters, d.base_win);
    let running = d.base_win;
    if (d.bonus) {
      el.classList.add('bonusing');
      await showBanner(`<b>BONUS!</b><span>${esc(d.bonus.name)}</span>`, 'fs', turbo() ? 1000 : 1900);
      await playBonus(d.bonus, bet);
      running += d.bonus.win; countTo(running);
      el.classList.remove('bonusing');
    }
    if (d.fs) {
      sfx.scatter(K);
      el.classList.add('freespins');
      await showBanner(`<b>FREE SPINS</b><span>${d.fs.count} spins · every win ×${d.fs.mult}</span>`, 'fs', turbo() ? 1400 : 2600);
      fsbar.hidden = false;
      let won = running;
      for (let i = 0; i < d.fs.spins.length; i++) {
        const s = d.fs.spins[i];
        $('[data-fs-left]', el).textContent = d.fs.spins.length - i - 1;
        clearHi();
        await showGrid(s.grid);
        won += s.win;
        if (s.win) await presentWins(s.wins, s.scatters, won, `free spin ${i + 1}: +${fmt(s.win)}`);
        else await sleep(turbo() ? 120 : 300);
        $('[data-fs-won]', el).textContent = fmt(won - running);
      }
      countTo(d.payout);
      await showBanner(`<b>FREE SPINS WON</b><span>${fmt(d.fs.win)} GC</span>`, 'fs', turbo() ? 1200 : 2200);
      fsbar.hidden = true; el.classList.remove('freespins');
    }
    if (d.tier) {
      const name = { big: 'BIG WIN', mega: 'MEGA WIN', epic: 'EPIC WIN' }[d.tier];
      sfx.big(K); burst(banner, d.tier === 'epic' ? 34 : 22);
      await showBanner(`<b>${name}</b><span>${fmt(d.payout)} GC · ${d.x}×</span>`, 'tier ' + d.tier, turbo() ? 1400 : 2600);
    } else if (d.payout > bet) burst(winEl, 10);
    countTo(d.payout);
    msgEl.textContent = d.message;
    setBalance(d.balance);
    busy = false; spinBtn.disabled = false; el.classList.remove('spinning');
    return d;
  }
  form.addEventListener('submit', e => { e.preventDefault(); spin(); });
  document.addEventListener('keydown', e => { if (e.code === 'Space' && e.target === document.body && el.isConnected) { e.preventDefault(); spin(); } });
  autoBtn.addEventListener('click', async () => {
    if (auto) { auto = false; return; }
    auto = true; autoBtn.classList.add('coral');
    const n = +$('[data-vs-auto-n]', el).value, stopFs = $('[data-vs-stopfs]', el).checked;
    for (let i = 0; i < n && auto; i++) {
      autoBtn.textContent = `Stop (${n - i})`;
      const d = await spin();
      if (!d) break;
      if (stopFs && (d.fs || d.bonus)) { toast(d.bonus ? 'Autospin stopped: bonus!' : 'Autospin stopped: free spins!', 'ok'); break; }
      await sleep(turbo() ? 80 : 350);
    }
    auto = false; autoBtn.classList.remove('coral'); autoBtn.textContent = 'Start';
  });
  const snd = $('[data-vs-sound]', el);
  const paintSnd = () => { snd.setAttribute('aria-pressed', sfx.on ? 'true' : 'false'); snd.setAttribute('aria-label', sfx.on ? 'Sound on' : 'Sound off'); snd.classList.toggle('muted', !sfx.on); };
  snd.addEventListener('click', () => { sfx.set(!sfx.on); paintSnd(); }); paintSnd();
  el._vs = { spin, cfg };
}

/* ═════ 3D GLUE ═════
 * The 3D scenes live in a separate ES module (and three.js), both served by index.php
 * and only fetched on pages that need them. Without WebGL the 2D controls still play.
 */
const hasGL = (() => { try { const c = document.createElement('canvas'); return !!(c.getContext('webgl2') || c.getContext('webgl')); } catch (e) { return false; } })();
let g3dMod = null;
const load3d = () => g3dMod || (g3dMod = import(new URL(($('meta[name="g3d"]') || {}).content || '?action=asset&f=g3d', location.href).href));
window.goldTide = {
  setBalance,
  tink: () => pdAudio.tink(8),
  clink: () => pdAudio.tink(0),
  thud: () => pdAudio.land(.5),
  rattle: () => { for (let i = 0; i < 6; i++) setTimeout(() => pdAudio.tink(4 + i), i * 45); },
};
window.goldTideBurst = burst;

function init3d(root) {
  $$('[data-g3d]', root).forEach(host => {
    if (host.dataset.ready3d) return;
    host.dataset.ready3d = '1';
    const loading = $('.g3d-loading', host);
    if (!hasGL) { host.classList.add('nogl'); if (loading) loading.textContent = 'Your browser has 3D graphics turned off. The game still plays with the controls below.'; return; }
    pdAudio.unlock && document.addEventListener('pointerdown', () => pdAudio.unlock(), { once: true });
    load3d().then(m => m[host.dataset.g3d](host)).then(() => {
      host.dispatchEvent(new CustomEvent('g3d-ready'));
    }).catch(err => {
      console.error(err);
      host.classList.add('nogl');
      if (loading) loading.textContent = 'Couldn\'t start the 3D table. The game still plays with the controls below.';
    });
  });
  initCraps(root); initPusher(root); initCabinetToggle(root);
}

/* ── craps: its own chip rack, because most bets stay up between rolls ── */
function initCraps(root) {
  const el = $('[data-craps]', root);
  if (!el || el.dataset.ready) return;
  el.dataset.ready = '1';
  let st = JSON.parse(el.dataset.state || '{"point":0,"bets":{}}');
  if (!st.bets || Array.isArray(st.bets)) st.bets = {};
  const MAX = +el.dataset.max, MIN = +el.dataset.min || 1, host = $('[data-g3d]', el), board = $('[data-cr-board]', el);
  const rollBtn = $('[data-cr-roll]', el), msg = $('[data-cr-msg]', el), pointEl = $('[data-cr-point]', el);
  const tdBtn = $('[data-cr-td]', el), tdGo = $('[data-cr-td-go]', el), hint = $('[data-cr-hint]', el), log = $('[data-cr-log]', el);
  const modeBtn = $('[data-cr-mode]', el), hist = $('[data-cr-hist]', el);
  const NUMS = [4, 5, 6, 8, 9, 10], ODDSX = { 4: 3, 5: 4, 6: 5, 8: 5, 9: 4, 10: 3 };
  const ONE = ['field', 'any7', 'anycraps', 'ace2', 'ace3', 'yo', 'twelve', 'horn', 'ce'];
  let chip = +(($('[data-chip][aria-checked="true"]', el) || {}).dataset || {}).chip || 10;
  const pending = new Map(), sel = new Set();
  let busy = false, td = false;
  const g3 = () => host && host._g3d;
  const label = k => { const b = board.querySelector(`.cr-spot[data-bet="${k}"] b`); const m = /^(d?come)(\d+)$/.exec(k); return b ? b.textContent : m ? (m[1] === 'come' ? 'Come ' : "Don't come ") + m[2] : k; };
  const removable = k => !(k === 'pass' || k === 'come' || /^come\d+$/.test(k) || ONE.includes(k));
  const offOnComeOut = k => /^(place|buy|lay|hard|comeodds)\d+$/.test(k) || k === 'big6' || k === 'big8';
  const unit = k => k === 'horn' ? 4 : k === 'ce' ? 2 : 1;
  // why a spot can't take chips right now ('' means it can)
  function blocked(k) {
    const b = st.bets, pt = st.point; let m;
    if (k === 'pass' || k === 'dontpass') return pt ? 'Line bets go down on the come-out roll only.' : '';
    if (k === 'come' || k === 'dontcome') return pt ? '' : 'Come and Don\'t Come need a point to be on.';
    if (k === 'passodds') return pt && b.pass ? '' : 'Pass odds need a pass line bet (already rolled) and a point.';
    if (k === 'dpodds') return pt && b.dontpass ? '' : 'Lay odds need a don\'t pass bet (already rolled) and a point.';
    if ((m = /^comeodds(\d+)$/.exec(k))) return b['come' + m[1]] ? '' : `Come odds need a come bet sitting on ${m[1]}.`;
    if ((m = /^dcomeodds(\d+)$/.exec(k))) return b['dcome' + m[1]] ? '' : `Lay odds need a don't come bet on ${m[1]}.`;
    return '';
  }
  function cap(k) {
    const b = st.bets; let m;
    if (k === 'passodds') return Math.min(MAX * 10, (b.pass || 0) * ODDSX[st.point]);
    if (k === 'dpodds') return Math.min(MAX * 10, (b.dontpass || 0) * 6);
    if ((m = /^comeodds(\d+)$/.exec(k))) return Math.min(MAX * 10, (b['come' + m[1]] || 0) * ODDSX[m[1]]);
    if ((m = /^dcomeodds(\d+)$/.exec(k))) return Math.min(MAX * 10, (b['dcome' + m[1]] || 0) * 6);
    return MAX;
  }
  const merged = () => { const o = { ...st.bets }; pending.forEach((v, k) => { o[k] = (o[k] || 0) + v; }); return o; };
  const selTotal = () => [...sel].reduce((a, k) => a + (st.bets[k] || 0), 0);
  function paint() {
    $$('.cr-spot', board).forEach(b => {
      const k = b.dataset.bet, w = st.bets[k] || 0, p = pending.get(k) || 0;
      b.disabled = busy || (td ? !(w && removable(k)) : (!!blocked(k) && !w && !p));
      b.classList.toggle('working', !!w);
      b.classList.toggle('off', !st.point && !!w && offOnComeOut(k));
      b.classList.toggle('sel', td && sel.has(k));
      const badge = $('.stake', b); if (badge) badge.remove();
      if (w || p) b.insertAdjacentHTML('beforeend', `<span class="stake${p ? ' add' : ''}">${fmt(w)}${p ? ' +' + fmt(p) : ''}</span>`);
    });
    NUMS.forEach(n => {
      const col = board.querySelector(`[data-cr-num="${n}"]`);
      col.classList.toggle('pt', st.point === n);
      const toks = [];
      if (st.bets['come' + n]) toks.push(`<span class="cr-tok" data-tok="come${n}" title="Come bet on ${n}${st.bets['comeodds' + n] ? ' with odds' : ''}">C ${fmt(st.bets['come' + n])}</span>`);
      if (st.bets['dcome' + n]) toks.push(`<span class="cr-tok dc" data-tok="dcome${n}" title="Don't come behind ${n}">DC ${fmt(st.bets['dcome' + n])}</span>`);
      $('[data-cr-cp]', col).innerHTML = toks.join('');
    });
    $('[data-cr-new]', el).textContent = fmt([...pending.values()].reduce((a, b) => a + b, 0));
    $('[data-cr-working]', el).textContent = fmt(Object.values(st.bets).reduce((a, b) => a + b, 0));
    pointEl.textContent = st.point ? 'POINT ' + st.point : 'COME-OUT';
    pointEl.classList.toggle('on', !!st.point);
    rollBtn.disabled = busy || td || (!pending.size && !Object.keys(st.bets).length);
    board.classList.toggle('takedown', td);
    tdBtn.setAttribute('aria-pressed', td ? 'true' : 'false');
    tdBtn.textContent = td ? 'Cancel' : 'Take bets down';
    tdBtn.disabled = busy || (!td && !Object.keys(st.bets).some(removable));
    tdGo.hidden = !td; tdGo.disabled = busy || !sel.size;
    tdGo.textContent = `Return ${fmt(selTotal())} GC`;
    hint.textContent = td ? 'Tap the bets you want back, then press Return. Pass line and come bets are contract bets and have to ride.'
      : 'Tap a spot to add your chip. Right-click or long-press to pull back chips you haven\'t rolled yet.';
    if (g3()) g3().setState({ point: st.point, bets: merged() });
  }
  $$('[data-chip]', el).forEach(c => c.addEventListener('click', () => { $$('[data-chip]', el).forEach(x => x.setAttribute('aria-checked', 'false')); c.setAttribute('aria-checked', 'true'); chip = +c.dataset.chip; }));
  board.addEventListener('click', e => {
    const b = e.target.closest('.cr-spot'); if (!b || busy) return;
    const k = b.dataset.bet;
    if (td) {
      if (!st.bets[k] || !removable(k)) return;
      const pair = k === 'dontpass' ? 'dpodds' : /^dcome\d+$/.test(k) ? 'dcomeodds' + k.slice(5) : null;
      if (sel.has(k)) sel.delete(k); else { sel.add(k); if (pair && st.bets[pair]) sel.add(pair); }
      paint(); return;
    }
    const why = blocked(k); if (why) { toast(why, 'err'); return; }
    const u = unit(k), cur = (pending.get(k) || 0) + (st.bets[k] || 0), c = cap(k);
    let amt = Math.ceil(chip / u) * u;
    if (cur + amt > c) amt = Math.floor((c - cur) / u) * u;   // odds: fill up to the max
    if (amt < MIN || amt <= 0) { toast(`${label(k)} is maxed at ${fmt(c)} GC.`, 'err'); return; }
    if ([...pending.values()].reduce((a, v) => a + v, 0) + amt > MAX * 10) { toast(`Table limit is ${fmt(MAX * 10)} GC of new chips per roll.`, 'err'); return; }
    pending.set(k, (pending.get(k) || 0) + amt);
    if (amt !== chip && u > 1) toast(`${label(k)} is split ${u} ways, so that's ${fmt(amt)} GC.`);
    paint();
  });
  board.addEventListener('contextmenu', e => { const b = e.target.closest('[data-bet]'); if (b) { e.preventDefault(); pending.delete(b.dataset.bet); paint(); } });
  $('[data-cr-clear]', el).addEventListener('click', () => { pending.clear(); paint(); });
  tdBtn.addEventListener('click', () => { td = !td; sel.clear(); if (td) pending.clear(); paint(); });
  const flash = key => {
    let t = board.querySelector(`.cr-spot[data-bet="${key}"]`);
    const m = /^(d?come)(\d+)$/.exec(key);
    if (!t && m) t = board.querySelector(`[data-cr-num="${m[2]}"] .cr-num`);
    if (t) { t.classList.remove('win'); void t.offsetWidth; t.classList.add('win'); }
  };
  function showLog(events) {
    log.innerHTML = events.map(ev => `<li class="${ev.win === true ? 'w' : ev.win === false ? 'l' : ''}">${ev.text.replace(/[<>&]/g, '')}</li>`).join('');
  }
  async function roll() {
    busy = true; paint(); msg.textContent = 'Dice are out…'; log.innerHTML = '';
    const fd = new FormData();
    fd.append('bets', JSON.stringify([...pending].map(([key, amount]) => ({ key, amount }))));
    const balEl = document.querySelector('[data-balance]'), before = balEl ? +balEl.dataset.balance : null;
    const adding = [...pending.values()].reduce((a, b) => a + b, 0);
    try {
      const d = await post(playUrl('craps'), fd);
      if (before !== null && adding) setBalance(Math.max(0, before - adding));
      pending.clear();
      if (g3()) await g3().roll(d);
      st = { point: d.point, bets: d.bets || {} };
      msg.textContent = d.message;
      showLog(d.events);
      d.events.filter(ev => ev.win).forEach(ev => flash(ev.key));
      if (hist && d.dice) {
        const t = d.dice[0] + d.dice[1];
        hist.insertAdjacentHTML('afterbegin', `<li class="${t === 7 ? 'seven' : ''}" title="${d.dice[0]}-${d.dice[1]}">${t}</li>`);
        while (hist.children.length > 16) hist.lastElementChild.remove();
      }
      if (d.payout) burst(msg, Math.min(24, 8 + Math.round(d.payout / 100)));
      setBalance(d.balance);
    } catch (err) { toast(err.message, 'err'); msg.textContent = err.message; }
    busy = false; paint();
  }
  rollBtn.addEventListener('click', () => { if (!busy) roll(); });
  tdGo.addEventListener('click', async () => {
    if (busy || !sel.size) return;
    busy = true; paint();
    const fd = new FormData(); fd.append('move', 'takedown'); fd.append('keys', [...sel].join(','));
    try {
      const d = await post(playUrl('craps'), fd);
      st = { point: d.point, bets: d.bets || {} };
      msg.textContent = d.message; setBalance(d.balance);
      sel.clear(); td = false;
    } catch (err) { toast(err.message, 'err'); }
    busy = false; paint();
  });
  // Table / Bubble camera
  let mode = 'table'; try { mode = localStorage.getItem('gt_crmode') === 'bubble' ? 'bubble' : 'table'; } catch (e) {}
  const paintMode = () => { modeBtn.textContent = mode === 'bubble' ? 'Table view' : 'Bubble view'; modeBtn.setAttribute('aria-label', 'Switch to ' + modeBtn.textContent); };
  modeBtn.addEventListener('click', () => {
    if (busy || !g3()) return;
    mode = mode === 'bubble' ? 'table' : 'bubble';
    try { localStorage.setItem('gt_crmode', mode); } catch (e) {}
    g3().setMode(mode); paintMode();
  });
  host.addEventListener('g3d-ready', () => {
    if (!g3()) return;
    g3().setMode(mode, false); modeBtn.hidden = false; paintMode(); paint();
  });
  document.addEventListener('keydown', e => {
    if (e.code !== 'Space' || !el.isConnected || /INPUT|TEXTAREA|SELECT|BUTTON/.test(document.activeElement.tagName)) return;
    e.preventDefault(); if (!rollBtn.disabled) roll();
  });
  paint();
}

/* ── pier pusher ── */
function initPusher(root) {
  const el = $('[data-pusher]', root);
  if (!el || el.dataset.ready) return;
  el.dataset.ready = '1';
  const host = $('[data-g3d]', el), form = $('[data-pu-form]', el), lane = $('[data-pu-lane]', el), msg = $('[data-pu-msg]', el), autoBtn = $('[data-pu-auto]', el);
  let busy = false, auto = false, tally = { drops: 0, won: 0 };
  try { tally = Object.assign(tally, JSON.parse(sessionStorage.getItem('pu_tally') || '{}')); } catch (e) {}
  const paintTally = () => { $('[data-pu-drops]', el).textContent = fmt(tally.drops); $('[data-pu-won]', el).textContent = fmt(tally.won); try { sessionStorage.setItem('pu_tally', JSON.stringify(tally)); } catch (e) {} };
  host.addEventListener('lane', e => { lane.value = e.detail; });
  async function drop() {
    if (busy) return null;
    busy = true; $('[data-pu-drop]', el).disabled = true;
    const fd = new FormData(form);
    const balEl = document.querySelector('[data-balance]'), before = balEl ? +balEl.dataset.balance : null, cost = +form.bet.value || 0;
    if (before !== null) setBalance(Math.max(0, before - cost));
    let d = null;
    try {
      d = host._g3d ? await host._g3d.play(fd) : await post(playUrl('pusher'), fd);
      msg.textContent = d.message;
      tally.drops++; tally.won += d.payout; paintTally();
      setBalance(d.balance);
    } catch (err) { toast(err.message, 'err'); if (before !== null) setBalance(before); }
    busy = false; $('[data-pu-drop]', el).disabled = false;
    return d;
  }
  form.addEventListener('submit', e => { e.preventDefault(); drop(); });
  autoBtn.addEventListener('click', async () => {
    if (auto) { auto = false; return; }
    auto = true; autoBtn.classList.add('coral');
    const n = +$('[data-pu-auto-n]', el).value;
    for (let i = 0; i < n && auto; i++) { autoBtn.textContent = `Stop (${n - i})`; lane.value = Math.round(Math.random() * 100); if (!await drop()) break; await sleep(200); }
    auto = false; autoBtn.classList.remove('coral'); autoBtn.textContent = 'Start';
  });
  paintTally();
}

/* ── 3D cabinet view for the themed slots ── */
function initCabinetToggle(root) {
  $$('[data-vslot]', root).forEach(el => {
    const b = $('[data-vs-3d]', el);
    if (!b || !hasGL || b.dataset.ready) return;
    b.dataset.ready = '1'; b.hidden = false;
    const setLabel = () => { b.textContent = el.classList.contains('cab3d') ? '2D reels' : '3D cabinet'; };
    const on = async () => {
      b.disabled = true; b.textContent = 'Loading 3D…';
      try { if (!el._v3d) { const m = await load3d(); await m.slotCabinet(el); } else el.classList.add('cab3d'); }
      catch (err) { console.error(err); toast('Couldn\'t start the 3D cabinet.', 'err'); }
      b.disabled = false; setLabel();
    };
    b.addEventListener('click', () => {
      if (el.classList.contains('cab3d')) { el.classList.remove('cab3d'); try { localStorage.setItem('gt_cab3d', '0'); } catch (e) {} setLabel(); }
      else { try { localStorage.setItem('gt_cab3d', '1'); } catch (e) {} on(); }
    });
    let pref = null; try { pref = localStorage.getItem('gt_cab3d'); } catch (e) {}
    if (pref === '1') on();
  });
}

/* ═════ SCENES: an ambient backdrop per game room ═════ */
const GAME_SFX = { slots: 'classic', scratch: 'carnival', keno: 'ocean', roulette: 'lounge', baccarat: 'lounge', sicbo: 'ocean', bigwheel: 'carnival',
  crabs: 'carnival', blackjack: 'lounge', videopoker: 'arcade', threecard: 'lounge', hilo: 'arcade', crash: 'ocean', mines: 'ocean', dice: 'arcade', plinko: 'ocean' };
function sceneFX(canvas, kind) {
  const ctx = canvas.getContext('2d');
  let w = 0, h = 0, P = [], t0 = performance.now();
  const R = (a, b) => a + Math.random() * (b - a);
  const counts = { sunset: 7, sparkle: 50, kelp: 34, chandelier: 26, surf: 40, carnival: 0, beach: 50, harbor: 26, synth: 0, dusk: 90, tidepool: 0, moon: 110, reef: 9, beam: 16 };
  function size() {
    const r = canvas.getBoundingClientRect(), dpr = Math.min(2, devicePixelRatio || 1);
    w = r.width; h = r.height; canvas.width = w * dpr; canvas.height = h * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    P = Array.from({ length: counts[kind] || 0 }, (_, i) => spawn(i, true));
  }
  function spawn(i, init) {
    switch (kind) {
      case 'sunset': return { x: init ? R(0, w) : -40, y: R(h * .05, h * .35), v: R(.3, .8), s: R(6, 12), f: R(0, 6) };
      case 'sparkle': return { x: R(0, w), y: R(0, h), p: R(0, 6), s: R(1, 3) };
      case 'kelp': return i < 14 ? { kelp: true, x: (i + .5) / 14 * w + R(-20, 20), hgt: R(.35, .75) * h, ph: R(0, 6), c: ['#1f6b3a', '#2e8b4a', '#175a30'][i % 3] } : { x: R(0, w), y: init ? R(0, h) : h + 5, r: R(1.5, 4), v: R(.3, .9) };
      case 'chandelier': return { x: R(0, w), y: R(0, h), r: R(10, 38), v: R(-.15, .15), a: R(.04, .12), hue: R(35, 48) };
      case 'surf': return { x: R(0, w), y: h - R(0, h * .18), r: R(1, 3), v: R(.2, .6) };
      case 'beach': return { x: R(0, w), y: R(h * .2, h), r: R(.6, 1.6) };
      case 'harbor': return { x: R(0, w), y: h * .72 + R(0, h * .28), l: R(10, 50), p: R(0, 6) };
      case 'dusk': case 'moon': return { x: R(0, w), y: R(0, h * .7), s: R(.5, 1.8), p: R(0, 6) };
      case 'reef': return { x: init ? R(0, w) : (i % 2 ? w + 40 : -40), y: R(h * .15, h * .85), v: (i % 2 ? -1 : 1) * R(.4, 1.1), s: R(8, 18), c: ['#ff9f43', '#5fe0cf', '#ffd23f', '#ff6fb0'][i % 4] };
      case 'beam': return { x: R(0, w), y: R(h * .4, h), r: R(40, 120), v: R(.1, .35), a: R(.03, .07) };
      default: return {};
    }
  }
  let ripples = [], star = null;
  function frame(now) {
    const t = (now - t0) / 1000;
    ctx.clearRect(0, 0, w, h);
    switch (kind) {
      case 'sunset': {
        const sx = w * .78, sy = h * .82;
        const g = ctx.createRadialGradient(sx, sy, 0, sx, sy, h * .7); g.addColorStop(0, 'rgba(255,200,90,.55)'); g.addColorStop(.25, 'rgba(255,111,89,.25)'); g.addColorStop(1, 'rgba(255,111,89,0)');
        ctx.fillStyle = g; ctx.fillRect(0, 0, w, h);
        ctx.fillStyle = 'rgba(255,214,120,.9)'; ctx.beginPath(); ctx.arc(sx, sy, h * .09, 0, 7); ctx.fill();
        for (let k = 0; k < 5; k++) { ctx.fillStyle = `rgba(255,170,90,${.18 - k * .03})`; ctx.fillRect(0, sy + h * .02 + k * 9 + Math.sin(t + k) * 2, w, 3); }
        ctx.strokeStyle = 'rgba(40,20,40,.55)'; ctx.lineWidth = 2;
        P.forEach((b, i) => { b.x += b.v; if (b.x > w + 40) P[i] = spawn(i); const fl = Math.sin(t * 6 + b.f) * b.s * .35;
          ctx.beginPath(); ctx.moveTo(b.x - b.s, b.y - fl); ctx.quadraticCurveTo(b.x - b.s / 2, b.y - b.s * .4, b.x, b.y); ctx.quadraticCurveTo(b.x + b.s / 2, b.y - b.s * .4, b.x + b.s, b.y - fl); ctx.stroke(); });
        break;
      }
      case 'sparkle':
        P.forEach(p => { const a = Math.max(0, Math.sin(t * 2 + p.p)); ctx.fillStyle = `rgba(255,230,150,${a * .8})`; ctx.save(); ctx.translate(p.x, p.y); ctx.rotate(t * .5);
          ctx.beginPath(); for (let k = 0; k < 8; k++) { const r = k % 2 ? p.s * .6 : p.s * 3 * a; ctx.lineTo(Math.cos(k * Math.PI / 4) * r, Math.sin(k * Math.PI / 4) * r); } ctx.fill(); ctx.restore(); });
        break;
      case 'kelp':
        P.forEach((k, i) => {
          if (k.kelp) { ctx.strokeStyle = k.c; ctx.lineWidth = 9; ctx.lineCap = 'round'; ctx.globalAlpha = .55; ctx.beginPath(); ctx.moveTo(k.x, h + 10);
            for (let s = 1; s <= 8; s++) { const y = h - k.hgt * s / 8; ctx.lineTo(k.x + Math.sin(t * .9 + k.ph + s * .6) * s * 3, y); } ctx.stroke(); ctx.globalAlpha = 1; }
          else { k.y -= k.v; if (k.y < -5) P[i] = spawn(i); ctx.strokeStyle = 'rgba(200,245,255,.4)'; ctx.lineWidth = 1; ctx.beginPath(); ctx.arc(k.x + Math.sin(t + i) * 3, k.y, k.r, 0, 7); ctx.stroke(); }
        });
        break;
      case 'chandelier':
        P.forEach(p => { p.y += p.v; if (p.y < -40) p.y = h + 40; if (p.y > h + 40) p.y = -40;
          const g = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.r); g.addColorStop(0, `hsla(${p.hue},90%,70%,${p.a * (1 + Math.sin(t + p.x) * .3)})`); g.addColorStop(1, `hsla(${p.hue},90%,60%,0)`);
          ctx.fillStyle = g; ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, 7); ctx.fill(); });
        break;
      case 'surf':
        for (let k = 0; k < 4; k++) { ctx.fillStyle = `rgba(${40 + k * 30},${170 + k * 15},${190 + k * 10},${.16 + k * .06})`; ctx.beginPath(); ctx.moveTo(0, h);
          for (let x = 0; x <= w; x += 16) ctx.lineTo(x, h - (60 - k * 13) - Math.sin(x / 70 + t * (1 + k * .3) + k) * 8); ctx.lineTo(w, h); ctx.fill(); }
        P.forEach((p, i) => { p.x += p.v; if (p.x > w) p.x = 0; ctx.fillStyle = 'rgba(255,255,255,.55)'; ctx.beginPath(); ctx.arc(p.x, p.y + Math.sin(t * 2 + i) * 3, p.r, 0, 7); ctx.fill(); });
        break;
      case 'carnival': {
        const n = Math.floor((w + h) * 2 / 34);
        for (let i = 0; i < n; i++) { const d = i / n * (w + h) * 2; let x, y; if (d < w) { x = d; y = 8; } else if (d < w + h) { x = w - 8; y = d - w; } else if (d < 2 * w + h) { x = w - (d - w - h); y = h - 8; } else { x = 8; y = h - (d - 2 * w - h); }
          const on = Math.floor(t * 6 - i / 2) % 3 === 0; ctx.fillStyle = on ? '#ffd98a' : 'rgba(255,217,138,.25)'; if (on) { ctx.shadowColor = '#ffb627'; ctx.shadowBlur = 12; } ctx.beginPath(); ctx.arc(x, y, 4, 0, 7); ctx.fill(); ctx.shadowBlur = 0; }
        const cx = w * .85, cy = h * .45, R0 = Math.min(w, h) * .35; ctx.strokeStyle = 'rgba(255,255,255,.08)'; ctx.lineWidth = 3;
        ctx.beginPath(); ctx.arc(cx, cy, R0, 0, 7); ctx.stroke();
        for (let k = 0; k < 12; k++) { const a = t * .15 + k * Math.PI / 6; ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(cx + Math.cos(a) * R0, cy + Math.sin(a) * R0); ctx.stroke(); ctx.fillStyle = `hsla(${k * 30},80%,60%,.18)`; ctx.fillRect(cx + Math.cos(a) * R0 - 8, cy + Math.sin(a) * R0, 16, 12); }
        break;
      }
      case 'beach':
        ctx.fillStyle = 'rgba(255,240,200,.07)'; P.forEach(p => { ctx.fillRect(p.x, p.y, p.r, p.r); });
        { const reach = h * .12 + Math.sin(t * .6) * h * .05; const g = ctx.createLinearGradient(0, 0, 0, reach + 20); g.addColorStop(0, 'rgba(43,179,163,.35)'); g.addColorStop(1, 'rgba(43,179,163,0)');
          ctx.fillStyle = g; ctx.fillRect(0, 0, w, reach + 20); ctx.strokeStyle = 'rgba(255,255,255,.5)'; ctx.lineWidth = 2; ctx.beginPath();
          for (let x = 0; x <= w; x += 12) ctx.lineTo(x, reach + Math.sin(x / 40 + t * 2) * 4); ctx.stroke(); }
        break;
      case 'harbor': {
        const mx = w * .64, my = h * .12; const g = ctx.createRadialGradient(mx, my, 0, mx, my, h * .3); g.addColorStop(0, 'rgba(255,250,230,.35)'); g.addColorStop(1, 'rgba(255,250,230,0)');
        ctx.fillStyle = g; ctx.fillRect(0, 0, w, h); ctx.fillStyle = 'rgba(255,250,230,.85)'; ctx.beginPath(); ctx.arc(mx, my, h * .045, 0, 7); ctx.fill();
        P.forEach(p => { ctx.fillStyle = `rgba(255,240,200,${.1 + .12 * Math.sin(t * 2 + p.p)})`; ctx.fillRect(p.x + Math.sin(t + p.p) * 6, p.y, p.l, 2); });
        const a = Math.sin(t * .5) * .7 - Math.PI / 2, lx = w * .92, ly = h * .6; ctx.fillStyle = 'rgba(255,245,200,.07)'; ctx.beginPath(); ctx.moveTo(lx, ly); ctx.arc(lx, ly, w * .9, a - .08, a + .08); ctx.fill();
        break;
      }
      case 'synth': {
        const hz = h * .45; ctx.strokeStyle = 'rgba(255,79,163,.35)'; ctx.lineWidth = 1.5;
        for (let i = -12; i <= 12; i++) { ctx.beginPath(); ctx.moveTo(w / 2 + i * 30, hz); ctx.lineTo(w / 2 + i * 260, h); ctx.stroke(); }
        for (let k = 0; k < 12; k++) { const u = ((k + (t * .6) % 1) / 12); const y = hz + Math.pow(u, 2.2) * (h - hz); ctx.globalAlpha = u; ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke(); ctx.globalAlpha = 1; }
        const g = ctx.createLinearGradient(0, hz - 120, 0, hz); g.addColorStop(0, '#ffd23f'); g.addColorStop(1, '#ff4fa3'); ctx.fillStyle = g; ctx.globalAlpha = .45;
        ctx.beginPath(); ctx.arc(w / 2, hz, 110, Math.PI, 0); ctx.fill(); ctx.globalAlpha = 1;
        for (let k = 0; k < 5; k++) { ctx.clearRect(w / 2 - 120, hz - 20 - k * 18, 240, 3 + k); }
        break;
      }
      case 'dusk': case 'moon':
        P.forEach(p => { ctx.fillStyle = `rgba(255,255,240,${.35 + .5 * Math.abs(Math.sin(t + p.p))})`; ctx.fillRect(p.x, p.y, p.s, p.s); });
        if (kind === 'moon') { const g = ctx.createRadialGradient(w * .85, h * .15, 0, w * .85, h * .15, h * .25); g.addColorStop(0, 'rgba(230,240,255,.4)'); g.addColorStop(1, 'rgba(230,240,255,0)'); ctx.fillStyle = g; ctx.fillRect(0, 0, w, h); ctx.fillStyle = '#eef3ff'; ctx.beginPath(); ctx.arc(w * .85, h * .15, h * .04, 0, 7); ctx.fill(); }
        else { if (!star && Math.random() < .004) star = { x: R(0, w * .6), y: R(0, h * .3), t: t }; if (star) { const u = (t - star.t) / .8; if (u > 1) star = null; else { ctx.strokeStyle = `rgba(255,255,255,${1 - u})`; ctx.lineWidth = 2; ctx.beginPath(); ctx.moveTo(star.x + u * 200, star.y + u * 80); ctx.lineTo(star.x + u * 200 - 60, star.y + u * 80 - 24); ctx.stroke(); } } }
        break;
      case 'tidepool':
        if (Math.random() < .03) ripples.push({ x: R(0, w), y: R(0, h), t });
        ripples = ripples.filter(r => t - r.t < 3);
        ripples.forEach(r => { const u = (t - r.t) / 3; ctx.strokeStyle = `rgba(160,230,255,${.35 * (1 - u)})`; ctx.lineWidth = 1.5; for (let k = 0; k < 3; k++) { ctx.beginPath(); ctx.ellipse(r.x, r.y, (u * 90 - k * 12) > 0 ? u * 90 - k * 12 : 0, (u * 40 - k * 5) > 0 ? u * 40 - k * 5 : 0, 0, 0, 7); ctx.stroke(); } });
        break;
      case 'reef':
        P.forEach((f, i) => { f.x += f.v; f.y += Math.sin(t * 2 + i) * .3; if (f.x > w + 50 || f.x < -50) P[i] = spawn(i);
          ctx.fillStyle = f.c; ctx.globalAlpha = .35; ctx.save(); ctx.translate(f.x, f.y); ctx.scale(f.v > 0 ? 1 : -1, 1);
          ctx.beginPath(); ctx.ellipse(0, 0, f.s, f.s * .5, 0, 0, 7); ctx.fill(); ctx.beginPath(); ctx.moveTo(-f.s * .8, 0); ctx.lineTo(-f.s * 1.5, -f.s * .5 + Math.sin(t * 10 + i) * 2); ctx.lineTo(-f.s * 1.5, f.s * .5 + Math.sin(t * 10 + i) * 2); ctx.fill(); ctx.restore(); ctx.globalAlpha = 1; });
        break;
      case 'beam': {
        const a = t * .6, lx = w * .08, ly = h * .12;
        const g = ctx.createRadialGradient(lx, ly, 0, lx, ly, w * 1.1); g.addColorStop(0, 'rgba(255,245,200,.22)'); g.addColorStop(1, 'rgba(255,245,200,0)');
        ctx.fillStyle = g; ctx.beginPath(); ctx.moveTo(lx, ly); ctx.arc(lx, ly, w * 1.1, Math.sin(a) * .5 + .4, Math.sin(a) * .5 + .52); ctx.fill();
        P.forEach(p => { p.x += p.v; if (p.x - p.r > w) p.x = -p.r; const g2 = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.r); g2.addColorStop(0, `rgba(200,210,230,${p.a})`); g2.addColorStop(1, 'rgba(200,210,230,0)'); ctx.fillStyle = g2; ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, 7); ctx.fill(); });
        ctx.fillStyle = 'rgba(245,236,215,.5)'; ctx.fillRect(lx - 3, ly, 6, h * .1);
        break;
      }
    }
    if (canvas.isConnected && !reduce && !document.hidden) requestAnimationFrame(frame);
    else if (canvas.isConnected && !reduce) document.addEventListener('visibilitychange', () => requestAnimationFrame(frame), { once: true });
  }
  size();
  if ('ResizeObserver' in window) new ResizeObserver(size).observe(canvas);
  requestAnimationFrame(frame);
}
function initScenes(root) { $$('canvas[data-scene]', root).forEach(c => { if (c.dataset.ready) return; c.dataset.ready = '1'; sceneFX(c, c.dataset.scene); }); }

/* global sound toggle in the header: flips every game's sound at once */
$$('[data-sound-toggle]').forEach(b => {
  const paint = () => { b.setAttribute('aria-pressed', sfx.on ? 'true' : 'false'); b.setAttribute('aria-label', sfx.on ? 'Sound on' : 'Sound off'); b.classList.toggle('muted', !sfx.on); };
  b.addEventListener('click', () => { const v = !sfx.on; sfx.set(v); pdAudio.set(v); paint(); $$('[data-vs-sound],[data-pd-sound]').forEach(x => x.classList.toggle('muted', !v)); });
  paint();
});
document.addEventListener('pointerdown', () => { sfx.unlock(); pdAudio.unlock(); }, { once: true });

enhance(document);

/* ═════ ADMIN ═════ */
if (document.documentElement.dataset.mode === 'admin') {
  // live filtering: fetch the same page, swap the list region
  const ff = $('[data-live-filter]');
  if (ff) {
    let timer, ctrl;
    const run = async () => {
      const qs = new URLSearchParams(new FormData(ff));
      [...qs.keys()].forEach(k => { if (qs.get(k) === '') qs.delete(k); });
      const url = '?' + qs.toString();
      if (ctrl) ctrl.abort();
      ctrl = new AbortController();
      try {
        const html = await (await fetch(url, { signal: ctrl.signal, credentials: 'same-origin' })).text();
        const doc = new DOMParser().parseFromString(html, 'text/html');
        const fresh = doc.getElementById('list-region');
        if (fresh) { $('#list-region').innerHTML = fresh.innerHTML; history.replaceState(null, '', url); syncBulk(); }
      } catch (e) { if (e.name !== 'AbortError') toast('Couldn\'t refresh the list.', 'err'); }
    };
    ff.addEventListener('input', e => { if (e.target.matches('[data-live]')) { clearTimeout(timer); timer = setTimeout(run, 320); } });
    ff.addEventListener('submit', e => { e.preventDefault(); run(); });
  }

  function syncBulk() {
    const bar = $('[data-bulk]');
    if (!bar) return;
    const n = $$('input[name="ids[]"]:checked').length;
    bar.hidden = n === 0;
    $('[data-bulk-count]', bar).textContent = n + ' selected';
  }
  document.addEventListener('change', e => {
    if (e.target.matches('[data-check-all]')) $$('input[name="ids[]"]').forEach(c => { c.checked = e.target.checked; });
    if (e.target.matches('[data-check-all], input[name="ids[]"]')) syncBulk();
  });
  document.addEventListener('submit', e => {
    const f = e.target;
    if (f.matches('[data-bulk]') && f.op.value === 'delete' && f.confirm.value !== 'DELETE') {
      e.preventDefault(); toast('Type DELETE in the box to confirm a bulk delete.', 'err'); f.confirm.focus();
    }
  });

  // display settings: theme / density / rows per page
  const dlg = $('#ui-settings'), open = $('[data-ui-settings]');
  if (dlg && open) {
    const get = k => { try { return localStorage.getItem(k); } catch (e) { return null; } };
    const set = (k, v) => { try { v == null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch (e) {} };
    open.addEventListener('click', () => {
      $('[data-pref="theme"]', dlg).value = get('gt_theme') || 'auto';
      $('[data-pref="density"]', dlg).value = get('gt_density') || 'comfy';
      $('[data-pref="rpp"]', dlg).value = (document.cookie.match(/(?:^|; )gt_rpp=(\d+)/) || [])[1] || '25';
      dlg.showModal();
    });
    dlg.addEventListener('change', e => {
      const k = e.target.dataset.pref, v = e.target.value, root = document.documentElement;
      if (k === 'theme') { if (v === 'auto') { delete root.dataset.theme; set('gt_theme', null); } else { root.dataset.theme = v; set('gt_theme', v); } }
      if (k === 'density') { v === 'compact' ? root.dataset.density = 'compact' : delete root.dataset.density; set('gt_density', v); }
      if (k === 'rpp') {
        document.cookie = 'gt_rpp=' + encodeURIComponent(v) + '; path=/; max-age=31536000; samesite=strict';
        if (new URLSearchParams(location.search).get('action') === 'admin_list') {
          const u = new URL(location.href); u.searchParams.delete('per'); u.searchParams.delete('page'); location.href = u;
        }
      }
    });
  }
}
})();
JS;
}

/* ═════════════════════════ GO ═════════════════════════ */
if (!defined('GT_NO_ROUTE')) { route(); }
