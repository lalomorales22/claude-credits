<?php
/**
 * Regression tests for the "core" audit group:
 *   - admin void refunds only the chips still at risk (craps), records payout = paid so far + refund
 *   - void is idempotent and re-read inside the tx; settled/void rounds and hands never reopen or refund twice
 *   - client_ip() trusts CF-Connecting-IP only behind loopback or the trusted_proxies setting
 *   - the "running low" refill counts chips on the table
 *   - craps park-and-take-down counts for nothing in rounds / wagered / won and nets out of the ledger
 *   - every chip board: exact keys, duplicates merged, max_bet per spot, 10 × max_bet per spin/round (2D roulette too)
 *   - admin player edit refuses to save over a balance that moved (balance_was); round/hand edits carry a rev
 *
 * Runs against a scratch copy of ../index.php in the system temp dir, so goldtide/data is never touched.
 * Anything that ends in fail() / redirect() / exit runs in a child php process (this same file in "child" mode)
 * that prints one JSON line the parent reads. Exit code 0 = all green.
 *
 *     php goldtide/tests/audit_core_test.php
 */
declare(strict_types=1);

/* ───────── child mode: one request against the scratch app, result as a JSON line ───────── */
if (($argv[1] ?? '') === 'child') {
    [, , $scenario, $argsJson, $scratch] = $argv;
    $A = json_decode($argsJson, true) ?: [];
    define('GT_NO_ROUTE', 1);
    $_SERVER['REMOTE_ADDR'] = $A['remote'] ?? '127.0.0.1';
    $_SERVER['HTTP_X_REQUESTED_WITH'] = 'fetch';   // fail() prints JSON instead of redirecting
    if (isset($A['cf'])) { $_SERVER['HTTP_CF_CONNECTING_IP'] = $A['cf']; }
    require $scratch . '/index.php';
    $_SESSION = ['csrf' => 'tok', 'pid' => (int)($A['pid'] ?? 0)];
    $_POST = array_map(fn($v) => is_array($v) ? $v : (string)$v, ($A['post'] ?? []) + ['csrf' => 'tok']);
    register_shutdown_function(function () {   // redirect() paths (admin save, login) end here: report the flash
        if (empty($GLOBALS['gt_done'])) { echo "\n" . json_encode(['ok' => true, 'flash' => $_SESSION['flash'] ?? [], 'data' => null]) . "\n"; }
    });
    $out = match ($scenario) {
        'engine' => $A['game'] === 'blackjack' ? blackjack_act() : (GAME_ENGINES[$A['game']])(),
        'roulette' => roulette_spin(),
        'refill' => claim_refill(),
        'ip' => ['ip' => client_ip()],
        'login' => do_login(),
        'admin_save' => do_admin_save(['id' => 1, 'username' => 'tester']),
    };
    $GLOBALS['gt_done'] = true;
    echo "\n" . json_encode(['ok' => true, 'data' => $out]) . "\n";
    exit;
}

/* ───────── parent: scratch app + helpers ───────── */
$t0 = microtime(true);
$src = dirname(__DIR__) . '/index.php';
$scratch = rtrim(sys_get_temp_dir(), '/') . '/gt_audit_core_' . getmypid();
@mkdir($scratch, 0700, true);
if (!copy($src, $scratch . '/index.php')) { fwrite(STDERR, "cannot copy $src to $scratch\n"); exit(2); }
define('GT_NO_ROUTE', 1);
$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
require $scratch . '/index.php';
ini_set('display_errors', '1');
$_SESSION = [];
db();

$fails = 0; $checks = 0;
function check(string $name, bool $ok, string $detail = ''): void {
    global $fails, $checks; $checks++;
    if (!$ok) { $fails++; }
    echo ($ok ? 'PASS' : 'FAIL') . '  ' . $name . ($detail !== '' && !$ok ? "  [$detail]" : '') . "\n";
}
function child(string $scenario, array $args): array {
    global $scratch;
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__FILE__) . ' child ' . escapeshellarg($scenario) . ' '
        . escapeshellarg(json_encode($args)) . ' ' . escapeshellarg($scratch) . ' 2>&1';
    exec($cmd, $lines, $code);
    foreach ($lines as $l) {
        $j = json_decode(trim($l), true);
        if (is_array($j) && array_key_exists('ok', $j)) { $j['raw'] = implode(' | ', $lines); return $j; }
    }
    return ['ok' => false, 'error' => "no json from child (exit $code): " . implode(' | ', $lines), 'raw' => implode(' | ', $lines)];
}
function err(array $o): string { return (string)($o['error'] ?? ''); }
function flash_of(array $o): string { return implode(' ', array_map(fn($f) => $f[0] . ':' . $f[1], $o['flash'] ?? [])); }
function mk_player(string $u, int $bal): int {
    return tx(function () use ($u, $bal) {
        q('INSERT INTO players (username, pass_hash) VALUES (?,?)', [$u, password_hash('password123', PASSWORD_BCRYPT, ['cost' => 4])]);
        $pid = (int)db()->lastInsertId();
        if ($bal > 0) { move_coins($pid, $bal, 'signup', null, 'test seed'); }
        return $pid;
    });
}
function bal_of(int $pid): int { return (int)val('SELECT balance FROM players WHERE id = ?', [$pid]); }
function prow(int $pid): array { return row('SELECT * FROM players WHERE id = ?', [$pid]); }
function rrow(int $id): array { return row('SELECT * FROM rounds WHERE id = ?', [$id]); }
function ledger(int $pid, string $kind, string $like = '%'): array {
    return q('SELECT * FROM ledger WHERE player_id = ? AND kind = ? AND detail LIKE ? ORDER BY id', [$pid, $kind, $like])->fetchAll();
}
/** A live craps round built directly: $bet was wagered, $paid already came back (a field hit, say). */
function seed_craps(int $pid, int $bet, array $bets, int $point, int $paid = 0): array {
    return tx(function () use ($pid, $bet, $bets, $point, $paid) {
        $r = round_open($pid, 'craps', $bet, ['point' => $point, 'bets' => $bets, 'paid' => $paid, 'rolls' => []]);
        if ($paid > 0) { move_coins($pid, $paid, 'payout', 'craps', 'test: earlier payout'); }
        return $r;
    });
}
/** Exactly the fields the admin edit form posts for a row, plus the concurrency tokens it now carries. */
function form_post(string $t, array $r, array $over = []): array {
    $post = ['t' => $t, 'id' => (string)$r['id']];
    foreach (entities()[$t]['fields'] as $name => $f) { $post[$name] = $f['type'] === 'password' ? '' : (string)($r[$f['column'] ?? $name] ?? ''); }
    if ($t === 'players') { $post['balance_was'] = (string)$r['balance']; }
    if (in_array($t, ['rounds', 'bj_hands'], true)) { $post['rev'] = row_rev($r); }
    foreach ($over as $k => $v) { $post[$k] = (string)$v; }
    return $post;
}
function set_setting(string $k, string $v): void {
    q("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')", [$k, $v]);
}
$bets = fn(array $kv) => json_encode(array_map(fn($k, $a) => ['key' => $k, 'amount' => $a], array_keys($kv), $kv));

/* ═════════ 1. void refunds only chips at risk ═════════ */
echo "── void refund (craps at-risk) ──\n";
$p = mk_player('void_a', 10000);
$r = seed_craps($p, 5100, ['pass' => 100, 'place6' => 5000], 4);
$o = child('engine', ['pid' => $p, 'game' => 'craps', 'post' => ['move' => 'takedown', 'keys' => 'place6']]);
check('craps take-down returns the 5,000 place chip', $o['ok'] && bal_of($p) === 9900, err($o) . ' bal=' . bal_of($p));
$r = rrow((int)$r['id']);
check('round stays active with 100 at risk while rounds.bet is still 5,100', $r['status'] === 'active' && round_at_risk($r) === 100 && (int)$r['bet'] === 5100);
$o = child('admin_save', ['post' => form_post('rounds', $r, ['status' => 'void'])]);
check('admin void refunds exactly the 100 still live (balance back to 10,000)', bal_of($p) === 10000, flash_of($o) . ' bal=' . bal_of($p));
$r = rrow((int)$r['id']);
check('voided round records payout = 5,000 taken down + 100 refunded', $r['status'] === 'void' && $r['outcome'] === 'void' && (int)$r['payout'] === 5100, json_encode([$r['status'], $r['outcome'], $r['payout']]));
$l = ledger($p, 'admin', 'voided round #%');
check('one admin ledger row, +100', count($l) === 1 && (int)$l[0]['amount'] === 100);

$p = mk_player('void_b', 10000);
$r = seed_craps($p, 600, ['pass' => 100], 9, 1000);   // pass 100 + field 500; the field hit paid 1,000 and left
check('setup: field paid, balance 10,400 with 100 live', bal_of($p) === 10400 && round_at_risk($r) === 100);
$o = child('admin_save', ['post' => form_post('rounds', $r, ['status' => 'void'])]);
check('void after a one-roll payout refunds 100, not rounds.bet 600', bal_of($p) === 10500 && (int)rrow((int)$r['id'])['payout'] === 1100, flash_of($o) . ' bal=' . bal_of($p));

/* ═════════ 2. void idempotency + state machine + in-tx re-read ═════════ */
echo "── void idempotency / state machine ──\n";
$p = mk_player('void_c', 10000);
$o = child('engine', ['pid' => $p, 'game' => 'hilo', 'post' => ['move' => 'start', 'bet' => 1000]]);
$r = round_active($p, 'hilo');
check('hilo run open, 1,000 staked', $o['ok'] && $r && bal_of($p) === 9000, err($o));
$o = child('admin_save', ['post' => form_post('rounds', $r, ['status' => 'void'])]);
check('first void refunds the stake', str_contains(flash_of($o), 'ok:') && bal_of($p) === 10000, flash_of($o));
$r = rrow((int)$r['id']);
$o = child('admin_save', ['post' => form_post('rounds', $r, ['status' => 'void'])]);
check('saving a void round as void again moves no coins', bal_of($p) === 10000 && count(ledger($p, 'admin')) === 1, flash_of($o) . ' bal=' . bal_of($p));
$r = rrow((int)$r['id']);
$o = child('admin_save', ['post' => form_post('rounds', $r, ['status' => 'active'])]);
check('void → active is refused', str_contains(flash_of($o), "can't be reopened") && rrow((int)$r['id'])['status'] === 'void', flash_of($o));
$o = child('engine', ['pid' => $p, 'game' => 'dice', 'post' => ['bet' => 100, 'dir' => 'under', 'target' => '50']]);
$r = row("SELECT * FROM rounds WHERE player_id = ? AND game = 'dice' ORDER BY id DESC LIMIT 1", [$p]);
$before = bal_of($p);
$o = child('admin_save', ['post' => form_post('rounds', $r, ['status' => 'void'])]);
check('done → void is refused and pays nothing', str_contains(flash_of($o), "can't be reopened") && bal_of($p) === $before && rrow((int)$r['id'])['status'] === 'done', flash_of($o));
$o = child('admin_save', ['post' => form_post('rounds', $r, ['status' => 'active'])]);
check('done → active is refused (no replaying a settled round)', str_contains(flash_of($o), "can't be reopened") && rrow((int)$r['id'])['status'] === 'done', flash_of($o));
try { tx(fn() => round_close($r, [], 5000, 'again')); $again = 'no exception'; } catch (DomainException $e) { $again = $e->getMessage(); }
check('round_close() on a settled round throws instead of paying', str_contains($again, 'already settled') && bal_of($p) === $before, $again);
// stale form: the player keeps playing between form load and save
$o = child('engine', ['pid' => $p, 'game' => 'hilo', 'post' => ['move' => 'start', 'bet' => 500]]);
$r = round_active($p, 'hilo'); $stale = form_post('rounds', $r, ['status' => 'void']);
$o = child('engine', ['pid' => $p, 'game' => 'hilo', 'post' => ['move' => 'skip']]);
$before = bal_of($p);
$o = child('admin_save', ['post' => $stale]);
check('round edit with a stale rev is refused, nothing refunded', str_contains(flash_of($o), 'changed while you were editing') && bal_of($p) === $before && round_active($p, 'hilo'), flash_of($o));
$o = child('admin_save', ['post' => form_post('rounds', round_active($p, 'hilo'), ['status' => 'void'])]);
check('fresh rev voids it and refunds the 500', bal_of($p) === $before + 500, flash_of($o));
// blackjack hands: same in-tx re-read and one-way status
$p = mk_player('void_bj', 10000);
for ($i = 0; $i < 12 && !bj_active($p); $i++) { child('engine', ['pid' => $p, 'game' => 'blackjack', 'post' => ['move' => 'deal', 'bet' => 500]]); }
$h = bj_active($p); $before = bal_of($p);
check('blackjack hand dealt and live', $h !== null);
$o = child('admin_save', ['post' => form_post('bj_hands', $h, ['status' => 'void'])]);
check('voiding the hand refunds 500 once', bal_of($p) === $before + 500, flash_of($o));
$h = row('SELECT * FROM bj_hands WHERE id = ?', [$h['id']]);
$o = child('admin_save', ['post' => form_post('bj_hands', $h, ['status' => 'void'])]);
$o2 = child('admin_save', ['post' => form_post('bj_hands', row('SELECT * FROM bj_hands WHERE id = ?', [$h['id']]), ['status' => 'active'])]);
check('re-void moves nothing; void → active refused', bal_of($p) === $before + 500 && str_contains(flash_of($o2), "can't be reopened"), flash_of($o) . ' / ' . flash_of($o2));

/* ═════════ 3. client_ip() trust ═════════ */
echo "── client_ip / trusted_proxies ──\n";
check('trusted_proxies setting is seeded', (int)val("SELECT COUNT(*) FROM settings WHERE key = 'trusted_proxies'") === 1);
check('ip_in_cidr: v4 inside / outside / bare / v6 / cross-family / garbage',
    ip_in_cidr('104.16.1.1', '104.16.0.0/13') && !ip_in_cidr('104.24.0.1', '104.16.0.0/13') && ip_in_cidr('1.2.3.4', '1.2.3.4') && !ip_in_cidr('1.2.3.5', '1.2.3.4')
    && ip_in_cidr('2a06:98c7::1', '2a06:98c0::/29') && !ip_in_cidr('2a06:98c8::1', '2a06:98c0::/29') && !ip_in_cidr('104.16.1.1', '2606:4700::/32')
    && !ip_in_cidr('nope', '10.0.0.0/8') && !ip_in_cidr('10.0.0.1', '10.0.0.0/99') && ip_in_cidr('::ffff:1.2.3.4', '::/0'));
$ip = fn(string $remote, string $cf, string $setting) => (function () use ($remote, $cf, $setting) { set_setting('trusted_proxies', $setting); return child('ip', ['remote' => $remote, 'cf' => $cf])['data']['ip'] ?? '?'; })();
check('direct visitor: spoofed CF-Connecting-IP ignored (setting blank)', $ip('203.0.113.9', '8.8.8.8', '') === '203.0.113.9');
check('loopback peer (cloudflared tunnel): header honoured', $ip('127.0.0.1', '8.8.8.8', '') === '8.8.8.8');
check('setting "cloudflare": header ignored from a non-Cloudflare peer', $ip('203.0.113.9', '8.8.8.8', 'cloudflare') === '203.0.113.9');
check('setting "cloudflare": header honoured from a Cloudflare IPv4 edge', $ip('104.16.1.1', '8.8.8.8', 'cloudflare') === '8.8.8.8');
check('setting "cloudflare": header honoured from a Cloudflare IPv6 edge', $ip('2606:4700::1234', '8.8.8.8', 'cloudflare') === '8.8.8.8');
check('CIDR list: 10.0.0.5 trusted via 10.0.0.0/8', $ip('10.0.0.5', '8.8.8.8', '10.0.0.0/8, 192.168.1.7') === '8.8.8.8');
check('CIDR list: bare IP entry trusted, garbage header falls back to peer', $ip('192.168.1.7', '8.8.8.8', '10.0.0.0/8, 192.168.1.7') === '8.8.8.8' && $ip('10.0.0.5', 'not-an-ip', '10.0.0.0/8') === '10.0.0.5');
check('CIDR list: untrusted peer keeps its own address', $ip('172.16.0.9', '8.8.8.8', '10.0.0.0/8, 192.168.1.7') === '172.16.0.9');
set_setting('trusted_proxies', '');
mk_player('lock_me', 100);
$last = '';
for ($i = 1; $i <= 6; $i++) { $last = err(child('login', ['remote' => '203.0.113.9', 'cf' => "198.51.100.$i", 'post' => ['username' => 'lock_me', 'password' => 'wrong-' . $i]])); }
check('6th bad login from one peer with 6 spoofed headers hits the lockout', str_contains($last, 'Too many tries'), $last);
q('DELETE FROM login_attempts');
for ($i = 1; $i <= 6; $i++) { $last = err(child('login', ['remote' => '127.0.0.1', 'cf' => "198.51.100.$i", 'post' => ['username' => 'lock_me', 'password' => 'wrong-' . $i]])); }
check('behind the tunnel the header is the key: 6 different visitors, no lockout', str_contains($last, 'Wrong username'), $last);
q('DELETE FROM login_attempts');

/* ═════════ 4. refill counts chips on the table ═════════ */
echo "── refill gate ──\n";
$p = mk_player('refill_a', 10000);
$o = child('engine', ['pid' => $p, 'game' => 'craps', 'post' => ['bets' => $bets(['place6' => 5000, 'place8' => 4600])]]);
check('park 9,600 of place chips (off on the come-out), balance 400', $o['ok'] && bal_of($p) === 400, err($o) . ' bal=' . bal_of($p));
check('refill_status: not low with 9,600 on the table', refill_status(prow($p))['low'] === false && coins_in_play($p) === 9600);
$o = child('refill', ['pid' => $p]);
check('claim_refill refused while the chips are parked', !$o['ok'] && str_contains(err($o), 'chips on the table'), err($o));
$o = child('engine', ['pid' => $p, 'game' => 'craps', 'post' => ['move' => 'takedown', 'keys' => 'place6,place8']]);
check('take-down brings the 9,600 back, still not low', $o['ok'] && bal_of($p) === 10000 && refill_status(prow($p))['low'] === false, err($o));
tx(fn() => move_coins($p, -9600, 'wager', 'dice', 'test: real loss'));
check('a genuine 400 balance is low', refill_status(prow($p))['low'] === true);
$o = child('refill', ['pid' => $p]);
check('claim_refill then pays 2,500', $o['ok'] && bal_of($p) === 2900, err($o) . ' bal=' . bal_of($p));
$p2 = mk_player('refill_bj', 400);
q("INSERT INTO bj_hands (player_id, bet, state) VALUES (?, 9600, '{}')", [$p2]);
check('an active blackjack hand counts as chips in play', refill_status(prow($p2))['low'] === false);
$p3 = mk_player('refill_pk', 400);
q('INSERT INTO poker_seats (table_id, player_id, seat, stack) VALUES (1, ?, 0, 9600)', [$p3]);
check('a seated poker stack counts as chips in play', refill_status(prow($p3))['low'] === false);

/* ═════════ 5. zero-risk craps: stats count only decided chips ═════════ */
echo "── craps stats ──\n";
$pr = prow($p);
check('park + take-down recorded 0 rounds / 0 wagered / 0 won', (int)$pr['rounds_played'] === 0 && (int)$pr['total_wagered'] === 0 && (int)$pr['total_won'] === 0, json_encode([$pr['rounds_played'], $pr['total_wagered'], $pr['total_won']]));
$net = (int)val("SELECT -SUM(CASE WHEN kind='wager' THEN amount ELSE 0 END) FROM ledger WHERE player_id = ? AND game = 'craps'", [$p]);
$paid = (int)val("SELECT COALESCE(SUM(CASE WHEN kind='payout' THEN amount ELSE 0 END),0) FROM ledger WHERE player_id = ? AND game = 'craps'", [$p]);
check('take-down is a wager reversal: dashboard wagered nets to 0 and paid stays 0', $net === 0 && $paid === 0 && count(ledger($p, 'wager', 'took down%')) === 1, "net=$net paid=$paid");
$p = mk_player('craps_res', 10000);
seed_craps($p, 1000, ['pass' => 1000], 5);
for ($i = 0; $i < 80 && round_active($p, 'craps'); $i++) { $o = child('engine', ['pid' => $p, 'game' => 'craps', 'post' => []]); if (!$o['ok']) { break; } }
$pr = prow($p); $won = bal_of($p) === 11000;
check('a pass-line decision records 1 round, 1,000 wagered, won = 2,000 or 0', !round_active($p, 'craps') && (int)$pr['rounds_played'] === 1 && (int)$pr['total_wagered'] === 1000 && (int)$pr['total_won'] === ($won ? 2000 : 0) && (int)$pr['biggest_win'] === ($won ? 1000 : 0), json_encode([$pr['rounds_played'], $pr['total_wagered'], $pr['total_won'], bal_of($p)]));
$p = mk_player('craps_mix', 10000);
seed_craps($p, 6000, ['pass' => 1000, 'place6' => 5000], 5);
child('engine', ['pid' => $p, 'game' => 'craps', 'post' => ['move' => 'takedown', 'keys' => 'place6']]);
for ($i = 0; $i < 80 && round_active($p, 'craps'); $i++) { $o = child('engine', ['pid' => $p, 'game' => 'craps', 'post' => []]); if (!$o['ok']) { break; } }
$pr = prow($p);
check('a place chip taken down mid-round never enters wagered (1,000, not 6,000)', !round_active($p, 'craps') && (int)$pr['rounds_played'] === 1 && (int)$pr['total_wagered'] === 1000, json_encode([$pr['rounds_played'], $pr['total_wagered']]));

/* ═════════ 6. chip boards: exact keys, merged duplicates, uniform caps ═════════ */
echo "── chip boards ──\n";
$p = mk_player('chips', 300000);
$rl = fn(array $list) => child('roulette', ['pid' => $p, 'post' => ['bets' => json_encode($list)]]);
$st = fn(int $n, $v, int $amt) => array_fill(0, $n, ['type' => 'straight', 'value' => $v, 'amount' => $amt]);
check('2D roulette: 40 × 1,250 on 17 → per-spot cap', err($rl($st(40, 17, 1250))) === 'Max 5,000 GC on one spot.');
check('2D roulette: 2 × 5,000 on 17 → per-spot cap', err($rl($st(2, 17, 5000))) === 'Max 5,000 GC on one spot.');
check('2D roulette: value "017" is the same spot as 17', err($rl([['type' => 'straight', 'value' => '017', 'amount' => 3000], ['type' => 'straight', 'value' => 17, 'amount' => 3000]])) === 'Max 5,000 GC on one spot.');
$o = $rl($st(4, 17, 1250));
check('2D roulette: 4 × 1,250 on 17 accepted as one 5,000 stack', $o['ok'] && (int)$o['data']['wagered'] === 5000 && count($o['data']['bets']) === 1 && (int)$o['data']['bets'][0]['amount'] === 5000, err($o));
$ten = []; foreach (range(1, 10) as $n) { $ten[] = ['type' => 'straight', 'value' => $n, 'amount' => 5000]; }
$o = $rl($ten);
check('2D roulette: 10 numbers × 5,000 = table limit, accepted', $o['ok'] && (int)$o['data']['wagered'] === 50000, err($o));
$ten[] = ['type' => 'straight', 'value' => 11, 'amount' => 5000];
check('2D roulette: an 11th 5,000 spot → 50,000 per spin limit', err($rl($ten)) === 'Table limit is 50,000 GC per spin.');
check('2D roulette: a 0-coin chip is rejected', err($rl([['type' => 'red', 'value' => 0, 'amount' => 0]])) === 'Bet must be a whole number of coins.');
$cb = fn(string $g, $list) => child('engine', ['pid' => $p, 'game' => $g, 'post' => ['bets' => is_string($list) ? $list : json_encode($list)]]);
check('sic bo: "single:01" is not a second spot beside "single:1"', err($cb('sicbo', $bets(['single:1' => 5000, 'single:01' => 5000]))) === 'That bet isn\'t on this table.');
check('sic bo: duplicate keys merge before the per-spot cap', err($cb('sicbo', [['key' => 'single:1', 'amount' => 3000], ['key' => 'single:1', 'amount' => 3000]])) === 'Max 5,000 GC on one spot.');
check('sic bo: whitespace / case aliases rejected', err($cb('sicbo', $bets([' small' => 100]))) === 'That bet isn\'t on this table.' && err($cb('sicbo', $bets(['SMALL' => 100]))) === 'That bet isn\'t on this table.');
$eleven = []; foreach ([4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14] as $n) { $eleven["total:$n"] = 5000; }
check('sic bo: 11 spots × 5,000 → 50,000 per round limit', err($cb('sicbo', $bets($eleven))) === 'Table limit is 50,000 GC per round.');
$o = $cb('sicbo', [['key' => 'small', 'amount' => 2500], ['key' => 'small', 'amount' => 2500]]);
check('sic bo: two 2,500 chips on small play as one 5,000 stack', $o['ok'], err($o));
check('3D roulette: "straight:017" rejected, duplicates capped', err($cb('roulette3d', $bets(['straight:017' => 100]))) === 'That bet isn\'t on this table.' && err($cb('roulette3d', [['key' => 'straight:17', 'amount' => 3000], ['key' => 'straight:17', 'amount' => 3000]])) === 'Max 5,000 GC on one spot.');
check('big six: "01" rejected, duplicates on "1" capped', err($cb('bigwheel', $bets(['01' => 100]))) === 'That bet isn\'t on this table.' && err($cb('bigwheel', [['key' => '1', 'amount' => 3000], ['key' => '1', 'amount' => 3000]])) === 'Max 5,000 GC on one spot.');
check('crabs: "crab:00" rejected, duplicates capped', err($cb('crabs', $bets(['crab:00' => 100]))) === 'That bet isn\'t on this table.' && err($cb('crabs', [['key' => 'crab:0', 'amount' => 3000], ['key' => 'crab:0', 'amount' => 3000]])) === 'Max 5,000 GC on one spot.');
check('baccarat: "Player" rejected, duplicates capped', err($cb('baccarat', $bets(['Player' => 100]))) === 'That bet isn\'t on this table.' && err($cb('baccarat', [['key' => 'player', 'amount' => 3000], ['key' => 'player', 'amount' => 3000]])) === 'Max 5,000 GC on one spot.');
check('craps: "place06" rejected, duplicate pass chips capped', err($cb('craps', $bets(['place06' => 100]))) === 'That bet isn\'t on this table.' && err($cb('craps', [['key' => 'pass', 'amount' => 3000], ['key' => 'pass', 'amount' => 3000]])) === 'Max 5,000 GC on one spot.');
$eleven = []; foreach (['pass', 'dontpass', 'field', 'any7', 'anycraps', 'ace2', 'ace3', 'yo', 'twelve', 'big6', 'big8'] as $k) { $eleven[$k] = 5000; }
check('craps: 11 spots × 5,000 of new chips → 50,000 per roll limit', err($cb('craps', $bets($eleven))) === 'Table limit is 50,000 GC per round.');
seed_craps($p, 4000, ['pass' => 4000], 0);
check('craps: per-spot max counts chips already working', str_contains(err($cb('craps', $bets(['pass' => 2000]))), 'Table max on Pass line'));

/* ═════════ 7. admin player edit: stale balance refused ═════════ */
echo "── admin balance edit ──\n";
$p = mk_player('gina2', 14060);
$form = prow($p);
tx(fn() => move_coins($p, -1000, 'wager', 'dice', 'test: player lost 1,000'));
$o = child('admin_save', ['post' => form_post('players', $form)]);   // unchanged form, loaded at 14,060
check('unchanged form saved after the player lost 1,000 is refused', str_contains(flash_of($o), 'Balance changed to 13,060 GC while you were editing'), flash_of($o));
check('balance stays 13,060 and no admin ledger row was written', bal_of($p) === 13060 && count(ledger($p, 'admin')) === 0);
$o = child('admin_save', ['post' => form_post('players', prow($p))]);
check('fresh form saves cleanly with no adjustment', str_contains(flash_of($o), 'ok:Saved') && count(ledger($p, 'admin')) === 0, flash_of($o));
$o = child('admin_save', ['post' => form_post('players', prow($p), ['balance' => 15000])]);
$l = ledger($p, 'admin');
check('deliberate change writes one +1,940 admin row', bal_of($p) === 15000 && count($l) === 1 && (int)$l[0]['amount'] === 1940, flash_of($o));

/* ═════════ wrap up ═════════ */
$log = @file_get_contents($scratch . '/data/error.log') ?: '';
check('no PHP errors logged by the scratch app', trim($log) === '', substr($log, 0, 400));
foreach (['/data/app.sqlite', '/data/app.sqlite-wal', '/data/app.sqlite-shm', '/data/error.log', '/data/.htaccess', '/.htaccess', '/admin_password.txt', '/index.php'] as $f) { @unlink($scratch . $f); }
@rmdir($scratch . '/data'); @rmdir($scratch);
printf("%s: %d/%d checks passed in %.1fs\n", $fails ? 'FAILED' : 'OK', $checks - $fails, $checks, microtime(true) - $t0);
exit($fails ? 1 : 0);
