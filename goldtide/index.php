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
const SCHEMA_VERSION = 1;
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

function client_ip(): string {
    // cloudflare tunnel puts the real visitor here; everything else gets REMOTE_ADDR
    $cf = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? '';
    if ($cf !== '' && filter_var($cf, FILTER_VALIDATE_IP)) { return $cf; }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function csp_nonce(): string {
    static $n = null;
    return $n ??= base64_encode(random_bytes(16));
}

function send_security_headers(): void {
    if (headers_sent()) { return; }
    $n = csp_nonce();
    header("Content-Security-Policy: default-src 'self'; script-src 'nonce-$n'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'");
    header('X-Frame-Options: DENY');
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
        ['refill_below', '500', 'Refill unlocks when balance is below this'],
        ['refill_hours', '4', 'Hours between refills'],
        ['min_age', '21', 'Age players must confirm at signup'],
        ['registration_open', '1', '1 = new signups allowed, 0 = closed'],
    ] as $s) { $seed->execute($s); }

    $g = $pdo->prepare('INSERT OR IGNORE INTO games (slug, name, blurb, min_bet, max_bet, sort_order) VALUES (?,?,?,?,?,?)');
    $g->execute(['slots', 'Sunset Reels', 'Three reels, five paylines, one very shiny sun.', 10, 5000, 1]);
    $g->execute(['blackjack', 'Harbor Blackjack', 'Six decks, dealer stands on all 17s, blackjack pays 3:2.', 10, 5000, 2]);
    $g->execute(['roulette', 'Coronado Roulette', 'Single-zero European wheel. Spread your chips.', 10, 5000, 3]);

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
    if ($pay > 0) { move_coins($pid, $pay, 'payout', 'blackjack', 'hand #' . $hand['id'] . ' ' . $outcome); }
    record_round($pid, $bet, $pay);
    unset($st['shoe']); // no reason to keep 300 cards around once it's over
    q("UPDATE bj_hands SET status = 'done', outcome = ?, payout = ?, state = ?, updated_at = datetime('now') WHERE id = ?",
        [$outcome, $pay, json_encode($st), $hand['id']]);
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

    $clean = []; $total = 0;
    foreach ($bets as $b) {
        $type = is_array($b) ? (string)($b['type'] ?? '') : '';
        $v = (int)($b['value'] ?? 0);
        $ok = match ($type) {
            'straight' => $v >= 0 && $v <= 36,
            'dozen', 'column' => $v >= 1 && $v <= 3,
            'red', 'black', 'odd', 'even', 'low', 'high' => true,
            default => false,
        };
        if (!$ok) { fail('That bet isn\'t on the table.'); }
        $amt = clamp_bet($b['amount'] ?? '', $g);
        if (!in_array($type, ['straight', 'dozen', 'column'], true)) { $v = 0; }
        $clean[] = ['type' => $type, 'value' => $v, 'amount' => $amt];
        $total += $amt;
    }
    if ($total > (int)$g['max_bet'] * 10) { fail('Table limit is ' . coins((int)$g['max_bet'] * 10) . ' GC per spin.'); }

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
    $low = (int)$p['balance'] < isetting('refill_below', 500);
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
        if (!$s['low']) { throw new DomainException('Refills unlock when you drop under ' . coins(isetting('refill_below', 500)) . ' GC.'); }
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
                'balance' => ['type' => 'int', 'min' => 0, 'required' => true, 'default' => 10000, 'hint' => 'Changes are written to the ledger as an admin adjustment'],
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
                'slug' => ['type' => 'enum', 'options' => ['slots', 'blackjack', 'roulette'], 'required' => true, 'hint' => 'Which engine this table runs'],
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
                'status' => ['type' => 'enum', 'options' => ['active', 'done', 'void'], 'default' => 'done', 'hint' => 'Setting an active hand to void refunds its bet'],
                'outcome' => ['type' => 'text', 'max' => 30],
                'payout' => ['type' => 'int', 'min' => 0, 'default' => 0],
                'state' => ['type' => 'json', 'default' => '{}'],
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
        $newId = tx(function () use ($t, $data, $existing, $id, $admin) {
            if ($existing) {
                $sets = implode(', ', array_map(fn($c) => "$c = ?", array_keys($data)));
                q("UPDATE $t SET $sets, updated_at = datetime('now') WHERE id = ?", [...array_values($data), $id]);
                // side effects that keep the coin economy honest
                if ($t === 'players' && (int)$existing['balance'] !== (int)$data['balance']) {
                    $delta = (int)$data['balance'] - (int)$existing['balance'];
                    q('INSERT INTO ledger (player_id, kind, amount, balance_after, detail) VALUES (?,?,?,?,?)',
                        [$id, 'admin', $delta, $data['balance'], 'adjusted by ' . $admin['username']]);
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
        if (!in_array($value, $allowed, true) || ($t === 'bj_hands' && $field === 'status')) { fail('That bulk change isn\'t supported.'); }
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
<meta name="robots" content="<?= $mode === 'admin' ? 'noindex, nofollow' : 'index, follow' ?>">
<title><?= h($title) ?> · <?= h($site) ?></title>
<link rel="icon" href="<?= h($favicon) ?>">
<script nonce="<?= h($nonce) ?>">try{var t=localStorage.getItem('gt_theme');if(t==='light'||t==='dark')document.documentElement.dataset.theme=t;var d=localStorage.getItem('gt_density');if(d==='compact')document.documentElement.dataset.density=d;}catch(e){}</script>
<style><?= app_css() ?></style>
</head>
<body>
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
    <?= $nav('', 'Lobby') ?><?= $nav('slots', 'Slots') ?><?= $nav('blackjack', 'Blackjack') ?><?= $nav('roulette', 'Roulette') ?><?= $nav('leaderboard', 'Leaders') ?>
  </nav>
  <div class="me">
    <?php if ($p): ?>
      <a class="balance" href="<?= h(url('account')) ?>" title="Your Gold Coins (no cash value)"><?= coin_svg() ?><span data-balance="<?= (int)$p['balance'] ?>"><?= coins((int)$p['balance']) ?></span><em>GC</em></a>
      <a class="who" href="<?= h(url('account')) ?>"><?= h($p['username']) ?></a>
    <?php else: ?>
      <a class="btn ghost sm" href="<?= h(url('login')) ?>">Log in</a>
      <a class="btn gold sm" href="<?= h(url('register')) ?>">Play free</a>
    <?php endif; ?>
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
    $art = ['slots' => sym('seven') . sym('sun') . sym('seven'), 'blackjack' => card_html('AS') . card_html('KH'), 'roulette' => mini_wheel()];
    ob_start(); ?>
<section class="hero">
  <div class="sunburst" aria-hidden="true"></div>
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

<?php if ($p): echo bonus_strip($p); endif; ?>

<section class="games" aria-label="Games">
  <?php foreach ($games as $i => $g): ?>
  <a class="game-card reveal d<?= min(6, $i + 2) ?> g-<?= h($g['slug']) ?>" href="<?= h(url($g['slug'])) ?>">
    <div class="game-art" aria-hidden="true"><?= $art[$g['slug']] ?? '' ?></div>
    <h2 class="display md"><?= h($g['name']) ?></h2>
    <p><?= h($g['blurb']) ?></p>
    <p class="limits"><?= coin_svg(14) ?> <?= coins((int)$g['min_bet']) ?>–<?= coins((int)$g['max_bet']) ?> GC</p>
    <span class="play">Play &rarr;</span>
  </a>
  <?php endforeach; ?>
  <?php if (!$games): ?><p class="panel">All tables are closed for maintenance. Check back soon.</p><?php endif; ?>
</section>

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
    <p>Under <?= coins(isetting('refill_below', 500)) ?> GC gets you <?= coins($r['amount']) ?> every <?= isetting('refill_hours', 4) ?>h.</p>
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
<section class="table-wrap slots-wrap">
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
<section class="table-wrap bj-wrap">
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
<?php layout($g['name'], ob_get_clean());
}

function page_roulette(): void {
    $g = game_header('roulette');
    $p = current_player();
    $last = $_SESSION['last']['roulette'] ?? null;
    unset($_SESSION['last']['roulette']);
    ob_start(); ?>
<section class="table-wrap rl-wrap" data-roulette data-min="<?= (int)$g['min_bet'] ?>" data-max="<?= (int)$g['max_bet'] ?>">
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
    </ul>
    <p class="fine">Right-click (or long-press) a spot to pull chips back off it.</p>
  </aside>
</section>
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
          <tr><td><?= h(substr($l['created_at'], 5, 11)) ?></td><td><?= h(ucfirst($l['kind'])) ?><?= $l['game'] ? ' · ' . h($l['game']) : '' ?></td>
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
        if (!can($e, 'u') || ($t === 'bj_hands' && $n === 'status')) { continue; }
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
.hero{position:relative;display:grid;min-height:min(46vh,440px);align-items:center;padding:clamp(24px,5vw,60px) 0;margin-bottom:var(--gap);isolation:isolate}
.sunburst{position:absolute;z-index:-1;right:-12%;top:50%;width:min(900px,120vw);aspect-ratio:1;transform:translateY(-50%);border-radius:50%;
  background:repeating-conic-gradient(from 0deg,rgba(232,182,76,.16) 0 6deg,transparent 6deg 12deg);
  -webkit-mask:radial-gradient(circle,#000 18%,transparent 68%);mask:radial-gradient(circle,#000 18%,transparent 68%);animation:turn 120s linear infinite}
.sunburst::after{content:"";position:absolute;inset:36%;border-radius:50%;background:radial-gradient(circle at 50% 60%,var(--coral),var(--gold) 55%,transparent 72%);filter:blur(6px);opacity:.75}
@keyframes turn{to{transform:translateY(-50%) rotate(360deg)}}
.hero-copy{max-width:640px}
.welcome{font-size:1.15rem}

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
function setBalance(n) {
  $$('[data-balance]').forEach(el => { countUp(el, +el.dataset.balance || 0, n); el.dataset.balance = n; });
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
      if (d.payout > 0) { res.classList.add('win'); burst(res, Math.min(30, 8 + Math.round(d.payout / d.bet) * 2)); }
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
      render(h, fresh);
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
      await spinTo(d.number);
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
route();
