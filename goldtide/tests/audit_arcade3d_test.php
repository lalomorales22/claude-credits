<?php
/**
 * Regression tests for the arcade / 3D audit group. Run: php goldtide/tests/audit_arcade3d_test.php   (exit 0 = green)
 *
 * Runs against a scratch COPY of index.php (its data/ lives next to the copy), so the real goldtide/data is never touched.
 * Pure functions are checked in-process; actions that end in ok()/fail()/redirect (plinko_play, fair_rotate,
 * mines_act, do_take_break, ...) run in a child php process against the same scratch copy and are read back as JSON.
 *
 * One or more checks per audit finding: craps buy vig (5% of the buy, on the win) and the per-number edges, craps chip
 * increments and exact place / odds / lay payouts at every legal amount, integer multiplier payouts (pay_mult), crash
 * ties (inclusive for manual and auto), dice over/under boundary, keno 94–96% per pick count, Pearl Drop RTP claim and
 * per-drop cap (plus an exhaustive RTP sweep over every stake), pre-committed next server seed, the Reef Mines 5,000× cap,
 * settling a live crash wave on a break, and the verifier's follow-up: hi-lo and video-slot payouts in integer math.
 */
declare(strict_types=1);
error_reporting(E_ALL);

$SRC = dirname(__DIR__) . '/index.php';
$DIR = sys_get_temp_dir() . '/gt_audit_arcade3d_' . getmypid();
@mkdir($DIR, 0700, true);
copy($SRC, "$DIR/index.php") || exit("cannot copy index.php to $DIR\n");
register_shutdown_function(function () use ($DIR) {   // scandir, not glob: data/ holds a .htaccess that glob('*') skips
    $wipe = function (string $d) { foreach (array_diff(scandir($d) ?: [], ['.', '..']) as $f) { @unlink("$d/$f"); } @rmdir($d); };
    if (is_dir("$DIR/data")) { $wipe("$DIR/data"); } $wipe($DIR);
});
// child runner: php child.php <pid> <function> <json POST>  → the JSON the action printed, or the return value / flash
file_put_contents("$DIR/child.php", <<<'PHP'
<?php
define('GT_NO_ROUTE', 1); require __DIR__ . '/index.php';
[, $pid, $fn, $post] = $argv;
$_SESSION['pid'] = (int)$pid; $_SERVER['HTTP_X_REQUESTED_WITH'] = 'fetch';
$_POST = json_decode($post, true) ?: []; $_GET = $_POST['_get'] ?? []; unset($_POST['_get']); $_POST['csrf'] = csrf_token();
ob_start();
register_shutdown_function(function () { $o = ob_get_clean(); echo $o !== '' ? $o : json_encode(['ok' => true, 'data' => null, 'flash' => $_SESSION['flash'] ?? []]); });
echo json_encode(['ok' => true, 'data' => $fn()]);
PHP);

define('GT_NO_ROUTE', 1);
require "$DIR/index.php";
if (!str_starts_with(DB_FILE, $DIR)) { exit("scratch copy is not using its own data dir: " . DB_FILE . "\n"); }

$PASS = 0; $FAIL = 0;
function check(bool $ok, string $msg): void { global $PASS, $FAIL; $ok ? $PASS++ : $FAIL++; echo ($ok ? 'ok   ' : 'FAIL ') . $msg . "\n"; }
function child(int $pid, string $fn, array $post = []): array {
    global $DIR;
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg("$DIR/child.php") . " $pid " . escapeshellarg($fn) . ' ' . escapeshellarg(json_encode($post)) . ' 2>&1';
    $out = (string)shell_exec($cmd);
    $j = json_decode($out, true);
    return is_array($j) ? $j : ['ok' => false, 'error' => 'no json: ' . substr($out, 0, 300)];
}
function mkplayer(string $name, int $bal = 10000000): int {
    q('INSERT INTO players (username, email, pass_hash, balance) VALUES (?,?,?,?)', [$name, null, password_hash('x', PASSWORD_BCRYPT, ['cost' => 4]), $bal]);
    return (int)db()->lastInsertId();
}
function choose(int $n, int $k): float { if ($k < 0 || $k > $n) { return 0.0; } $r = 1.0; for ($i = 1; $i <= $k; $i++) { $r = $r * ($n - $k + $i) / $i; } return $r; }
db();   // provisions the scratch schema
$P1 = mkplayer('audit_a3d_one'); $P2 = mkplayer('audit_a3d_two');
$T0 = microtime(true);

/* ── Finding 0 + 2: craps commission and increments ── */
$ways = [4 => 3, 10 => 3, 5 => 4, 9 => 4, 6 => 5, 8 => 5];
$edge = [4 => 1 / 60, 10 => 1 / 60, 5 => 0.02, 9 => 0.02, 6 => 0.25 / 11, 8 => 0.25 / 11];   // 1.67% / 2.00% / 2.27%
$g = game_cfg('craps'); $max = (int)$g['max_bet'];
check(craps_buy_win(4, 20) === 39 && craps_buy_win(6, 20) === 23, 'buy 4 for 20 pays 40 − 1 vig = 39; buy 6 for 20 pays 24 − 1 = 23 (5% of the BUY, on the win)');
check(craps_vig(20) === 1 && craps_vig(30) === 2 && craps_vig(29) === 1, 'vig is 5% rounded to the nearest coin');
foreach (['buy' => 'craps_buy_win', 'lay' => 'craps_lay_win'] as $kind => $fn) {
    $worst = 0.0; $cnt = 0;
    foreach (CRAPS_NUMS as $n) {
        $u = CRAPS_UNIT[$kind][$n]; $w = $ways[$n];
        for ($a = $u; $a <= $max; $a += $u) {
            $win = $fn($n, $a);
            $ev = $kind === 'buy' ? ($w * $win - 6 * $a) / ($w + 6) : (6 * $win - $w * $a) / ($w + 6);
            $worst = max($worst, abs(-$ev / $a - $edge[$n])); $cnt++;
        }
    }
    check($worst < 1e-12, "$kind bets: house edge is exactly 1.67% (4/10), 2.00% (5/9), 2.27% (6/8) at all $cnt legal amounts (worst dev " . sprintf('%.1e', $worst) . ')');
}
$bad = 0; $cnt = 0;
foreach (CRAPS_NUMS as $n) {
    [$x, $y] = CRAPS_PLACE[$n]; [$tx_, $ty] = CRAPS_TRUE[$n];
    for ($a = CRAPS_UNIT['place'][$n]; $a <= $max; $a += CRAPS_UNIT['place'][$n]) { $cnt++; if (craps_place_win($n, $a) * $y !== $a * $x) { $bad++; } }
    for ($a = CRAPS_UNIT['odds'][$n]; $a <= $max * 5; $a += CRAPS_UNIT['odds'][$n]) { $cnt++; if ((craps_odds_ret($a, $n) - $a) * $ty !== $a * $tx_) { $bad++; } }
    for ($a = CRAPS_UNIT['layodds'][$n]; $a <= $max * 6; $a += CRAPS_UNIT['layodds'][$n]) { $cnt++; if ((craps_lay_odds_ret($a, $n) - $a) * $tx_ !== $a * $ty) { $bad++; } }
}
check($bad === 0, "place pays exactly 7:6 / 7:5 / 9:5 and odds exactly true odds at every legal amount ($cnt amounts, $bad off)");
$s0 = craps_state(null);
$rej = function (array $s, string $k, int $amt) use ($g): string { try { craps_check_add($s, $k, $amt, $g); return ''; } catch (DomainException $e) { return $e->getMessage(); } };
check(str_contains($rej($s0, 'place6', 10), 'multiples of 6'), 'place 6 for 10 GC is refused naming the multiple: ' . $rej($s0, 'place6', 10));
check($rej($s0, 'place6', 12) === '' && $rej($s0, 'place5', 10) === '' && $rej($s0, 'place4', 25) === '', 'place 6 for 12, place 5 for 10, place 4 for 25 are accepted');
check(str_contains($rej($s0, 'place5', 12), 'multiples of 5') && str_contains($rej($s0, 'buy4', 10), 'multiples of 20') && str_contains($rej($s0, 'lay6', 20), 'multiples of 24'), 'place 5 / buy 4 / lay 6 wrong amounts are refused with the right multiple');
$sp = ['point' => 6, 'bets' => ['pass' => 100], 'paid' => 0, 'rolls' => []];
check(str_contains($rej($sp, 'passodds', 12), 'multiples of 5') && $rej($sp, 'passodds', 15) === '', 'pass odds on 6: 12 GC refused, 15 GC accepted');
$sp['bets'] = ['place6' => 12];
check(str_contains($rej($sp, 'place6', 10), 'multiples of 6') && $rej($sp, 'place6', 6) === '', 'the running total on a spot must sit on the unit (12 + 10 refused, 12 + 6 accepted)');

/* ── Finding 1: integer multiplier payouts ── */
check(pay_mult(100, 0.29) === 29 && (int)floor(100 * 0.29) === 28, 'pay_mult(100, 0.29) = 29 where floor(100 * 0.29) gave 28');
check(pay_mult(10, 0.23) === 2 && pay_mult(10, 0.37) === 4 && pay_mult(10, 0.25) === 3, 'nearest coin: 10 × 0.23 = 2, 10 × 0.37 = 4, 10 × 0.25 = 3');
$bad = 0; $cnt = 0;
foreach ([10, 13, 25, 100, 999, 5000] as $bet) { for ($c = 1; $c <= 100000; $c += 7) { $cnt++; if (pay_mult($bet, $c / 100) !== intdiv($bet * $c + 50, 100)) { $bad++; } } }
check($bad === 0, "pay_mult equals intdiv(bet × m100 + 50, 100) across $cnt (bet, multiplier) pairs");
check(pay_mult(100, 1.0421, 4) === 104 && pay_mult(5000, 1.0421, 4) === 5211, 'dice 4-dp multipliers pay exactly (100 × 1.0421 = 104, 5000 × 1.0421 = 5211)');

/* ── Finding 4: dice boundary ── */
$bad = 0;
foreach ([2.0, 5.0, 33.33, 50.0, 66.67, 95.0, 98.0] as $t) {
    foreach (['under', 'over'] as $dir) {
        $chance = $dir === 'under' ? $t : 100 - $t; if ($chance < 2 || $chance > 95) { continue; }
        $w = 0; for ($k = 0; $k < 10000; $k++) { if (dice_win($k / 100, $dir, $t)) { $w++; } }
        if ($w !== (int)round($chance * 100)) { $bad++; echo "  dice $dir $t wins $w, want " . (int)round($chance * 100) . "\n"; }
    }
}
check($bad === 0, 'dice: over T wins on exactly 100·(100−T) outcomes and under T on 100·T, for 7 targets each way');
$rtp = []; foreach ([['under', 50.0], ['over', 2.0], ['over', 5.0], ['under', 95.0]] as [$dir, $t]) { $chance = $dir === 'under' ? $t : 100 - $t; $m = floor(99 / $chance * 10000) / 10000; $w = 0; for ($k = 0; $k < 10000; $k++) { $w += dice_win($k / 100, $dir, $t) ? 1 : 0; } $rtp[] = $w / 10000 * $m; }
check(min($rtp) > 0.9899 && max($rtp) <= 0.99, 'dice RTP is 99% (−4-dp truncation) at the extreme "over" setting too: ' . implode(', ', array_map(fn($x) => sprintf('%.5f', $x), $rtp)));
$d = child($P1, 'dice_play', ['bet' => 100, 'target' => 50, 'dir' => 'over']);
check(($d['ok'] ?? false) && ($d['data']['win'] === ($d['data']['roll'] >= 50)), 'dice_play over 50: win iff roll ≥ 50 (roll ' . ($d['data']['roll'] ?? '?') . ')');

/* ── Finding 5: keno ── */
$rtps = [];
foreach (KENO_PAY as $p => $pay) { $r = 0.0; foreach ($pay as $k => $m) { $r += choose($p, $k) * choose(40 - $p, 10 - $k) / choose(40, 10) * $m; } $rtps[$p] = $r * 100; }
check(min($rtps) >= 94 && max($rtps) <= 96, 'keno: every pick count returns 94–96% (' . sprintf('%.2f–%.2f', min($rtps), max($rtps)) . ')');
$rules = implode(' ', GAME_RULES['keno']);
check(str_contains($rules, sprintf('3: %.1f%%', $rtps[3])) && str_contains($rules, sprintf('6: %.1f%%', $rtps[6])) && str_contains($rules, sprintf('8: %.1f%%', $rtps[8])) && str_contains($rules, sprintf('10: %.1f%%', $rtps[10])), 'keno rules text quotes the solved per-pick RTPs');
$d = child($P1, 'keno_play', ['bet' => 100, 'picks' => '1,2,3,4,5,6']);
check(($d['ok'] ?? false) && $d['data']['payout'] === pay_mult(100, KENO_PAY[6][count($d['data']['hits'])]), 'keno_play pays pay_mult(bet, KENO_PAY[picks][hits])');

/* ── Finding 6 + 9: Pearl Drop RTP claim and per-drop cap ── */
$exactR = []; $minR = []; $bet100R = [];
foreach (PD_TABLES as $R => $risks) { foreach ($risks as $risk => $tab) {
    $P = $R * ($R + 1) / 2; $hitp = []; for ($h = 0; $h <= 3; $h++) { $hitp[$h] = choose($R, $h) * choose($P - $R, 3 - $h) / choose($P, 3); }
    $ex = 0.0; $p10 = 0.0; $p100 = 0.0;
    foreach ($tab as $slot => $m0) { $ps = choose($R, $slot) / 2 ** $R; foreach ($hitp as $h => $ph) { $m = round($m0 * 2 ** $h, 2); $ex += $ps * $ph * $m; $p10 += $ps * $ph * pay_mult(10, $m) / 10; $p100 += $ps * $ph * pay_mult(100, $m) / 100; } }
    $exactR[] = $ex * 100; $minR[] = $p10 * 100; $bet100R[] = $p100 * 100;
} }
check(round(min($exactR), 1) >= 98.5 && round(max($exactR), 1) <= 98.9, 'Pearl Drop exact RTP is 98.5–98.9% (to 0.1) for all 15 tables (' . sprintf('%.2f–%.2f', min($exactR), max($exactR)) . ')');
check(max(array_map(fn($a, $b) => abs($a - $b), $exactR, $bet100R)) < 1e-9, 'Pearl Drop pays the exact RTP at 100 GC per pearl');
check(round(min($minR), 1) >= 97.5 && round(max($minR), 1) <= 99.4, 'Pearl Drop RTP at the 10 GC minimum is the claimed 97.5–99.4% (to 0.1) (' . sprintf('%.2f–%.2f', min($minR), max($minR)) . ')');
check(str_contains(implode(' ', GAME_RULES['plinko']), '97.5–99.4%') && str_contains(implode(' ', GAME_RULES['plinko']), '98.5–98.9%'), 'Pearl Drop rules text carries both RTP figures');
// exhaustive: every stake 10..5000 GC per pearl, all 15 tables (the swing comes from odd stakes under 100 GC, e.g. 12 GC)
$all = [1e9, 0]; $from100 = [1e9, 0];
foreach (PD_TABLES as $R => $risks) { foreach ($risks as $risk => $tab) {
    $P = $R * ($R + 1) / 2; $cells = [];
    foreach ($tab as $slot => $m0) { $ps = choose($R, $slot) / 2 ** $R; for ($h = 0; $h <= 3; $h++) { $cells[] = [$ps * choose($R, $h) * choose($P - $R, 3 - $h) / choose($P, 3), round($m0 * 2 ** $h, 2)]; } }
    for ($b = 10; $b <= 5000; $b++) {
        $r = 0.0; foreach ($cells as [$pr, $m]) { $r += $pr * pay_mult($b, $m); } $r = $r / $b * 100;
        $all = [min($all[0], $r), max($all[1], $r)]; if ($b >= 100) { $from100 = [min($from100[0], $r), max($from100[1], $r)]; }
    }
} }
check(round($all[0], 1) >= 96.8 && round($all[1], 1) <= 100.3 && round($from100[0], 1) >= 98.3 && round($from100[1], 1) <= 99.1, sprintf('Pearl Drop RTP over every stake 10–5,000 GC is the stated 96.8–100.3%% (%.2f–%.2f) and 98.3–99.1%% from 100 GC up (%.2f–%.2f)', $all[0], $all[1], $from100[0], $from100[1]));
$pr = implode(' ', GAME_RULES['plinko']);
check(str_contains($pr, '96.8–100.3%') && str_contains($pr, '98.3–99.1%') && str_contains($pr, 'every stake from 10 to 5,000 GC'), 'Pearl Drop rules text quotes the exhaustive range, not just the 10 GC and 100-GC-multiple figures');
$g = game_cfg('plinko'); $cap = (int)$g['max_bet'] * 10;
$d = child($P1, 'plinko_play', ['bet' => (int)$g['max_bet'], 'balls' => 20, 'rows' => 8, 'risk' => 'med']);
check(!($d['ok'] ?? true) && str_contains((string)($d['error'] ?? ''), 'Drop limit'), 'a drop wagering max_bet × 20 is refused: ' . ($d['error'] ?? ''));
$d = child($P1, 'plinko_play', ['bet' => (int)$g['max_bet'], 'balls' => 10, 'rows' => 8, 'risk' => 'med']);
check(($d['ok'] ?? false) && count($d['data']['balls']) === 10, 'a drop wagering exactly max_bet × 10 is accepted');
$d = child($P1, 'plinko_play', ['bet' => 10, 'balls' => 20, 'rows' => 8, 'risk' => 'med']);
$sum = 0; $okb = true; foreach ($d['data']['balls'] ?? [] as $b) { $sum += $b['win']; if ($b['win'] !== pay_mult(10, (float)$b['mult'])) { $okb = false; } }
check(($d['ok'] ?? false) && $okb && $sum === $d['data']['payout'], '20 pearls at 10 GC: each pearl pays pay_mult(10, mult) and the payout is their sum');

/* ── Finding 7: pre-committed next server seed ── */
$seed = tx(fn() => fair_active($P1, 'plinko'));
$N1 = hash('sha256', (string)$seed['next_server_seed']);
check(strlen((string)$seed['next_server_seed']) === 64, 'a fresh seed pair carries a next server seed');
$r1 = child($P1, 'fair_rotate', ['client_seed' => 'abc']);
check(($r1['ok'] ?? false) && $r1['data']['active']['server_hash'] === $N1 && $r1['data']['active']['client_seed'] === 'abc', 'rotating with a chosen client seed promotes the seed whose hash was already shown');
$r2 = child($P1, 'fair_rotate', ['client_seed' => 'def']);
check(($r2['ok'] ?? false) && $r2['data']['revealed']['server_hash'] === $N1 && hash('sha256', $r2['data']['revealed']['server_seed']) === $N1
    && $r2['data']['active']['server_hash'] === $r1['data']['active']['next_server_hash'], 'the next rotation reveals that seed (sha256 matches the pre-committed hash) and promotes the next one');
check(val("SELECT COUNT(*) FROM fair_seeds WHERE player_id = ? AND next_server_seed IS NULL", [$P1]) === 0, 'every seed row holds a committed next seed');

/* ── Finding 8: Reef Mines cap ── */
check(mines_mult(12, 13) === 5000.0 && mines_mult(1, 24) === 24.75, 'mines_mult is capped at 5000× (12 urchins cleared) and untouched below the cap');
$kcap = 1; while (mines_mult(12, $kcap) < MINES_MAX_WIN) { $kcap++; }
tx(fn() => round_open($P2, 'mines', 100, ['n' => 12, 'mines' => range(13, 24), 'open' => []]));
$bal0 = bal($P2); $last = null;
for ($t = 0; $t < 13; $t++) { $last = child($P2, 'mines_act', ['move' => 'reveal', 'tile' => $t]); if (!($last['ok'] ?? false) || $last['data']['payout'] > 0 || $last['data']['boom']) { break; } }
check(($last['ok'] ?? false) && $t + 1 === $kcap && $last['data']['payout'] === 5000 * 100 && bal($P2) === $bal0 + 500000, "mines auto-cashes at pearl $kcap when the ladder reaches 5,000× and pays 5,000 × bet: " . ($last['data']['message'] ?? $last['error'] ?? ''));
check(str_contains(implode(' ', GAME_RULES['mines']), '5,000×'), 'mines rules text states the cap');

/* ── Verifier follow-up: hi-lo and the video-slot engine pay bet × multiplier in integer math too ── */
check(floor(100 * 1.15) === 114.0 && pay_mult(100, 1.15, 4) === 115, 'premise: floor(100 * 1.15) on doubles is 114, pay_mult pays 115');
$r = tx(fn() => round_open($P2, 'hilo', 100, ['card' => ['r' => 7, 's' => 'H'], 'mult' => 1.15, 'steps' => 1, 'trail' => []]));
$d = child($P2, 'hilo_act', ['move' => 'cashout']);
check(($d['ok'] ?? false) && $d['data']['payout'] === 115 && str_contains($d['data']['message'], '+115 GC'), 'hilo cash-out at 1.15× on 100 GC pays 115, not floor()\'s 114: ' . ($d['data']['message'] ?? $d['error'] ?? ''));
$r = tx(fn() => round_open($P2, 'hilo', 100, ['card' => ['r' => 7, 's' => 'H'], 'mult' => 4999.9999, 'steps' => 9, 'trail' => []]));
$d = child($P2, 'hilo_act', ['move' => 'cashout']);
check(($d['ok'] ?? false) && $d['data']['payout'] === 500000, 'hilo pays 4,999.9999× on 100 GC as 500,000 (nearest coin, 4-dp multiplier)');
$slug = array_key_first(VSLOTS); $bad = []; $paid = 0; $bal0 = bal($P2);
for ($i = 0; $i < 60; $i++) {
    $d = child($P2, 'vs_play', ['bet' => 100, '_get' => ['g' => $slug]]);
    if (!($d['ok'] ?? false)) { $bad[] = $d['error'] ?? '?'; break; }
    $x = $d['data']; $paid += $x['payout'];
    if ($x['payout'] !== pay_mult(100, (float)$x['x']) || $x['base_win'] !== pay_mult(100, array_sum(array_column($x['wins'], 'x')) + (VS_SCATTER_PAY[min(5, count($x['scatters']))] ?? 0))) { $bad[] = json_encode([$x['x'], $x['payout'], $x['base_win']]); }
}
check(!$bad && bal($P2) === $bal0 - 6000 + $paid, "vs_play ($slug) pays pay_mult(bet, x) on every spin and the base win matches its ways + scatter total: " . implode('; ', array_slice($bad, 0, 3)));
$fs = VSLOTS[$slug]['pays']['L5'][0] * 2;   // two ways of the smallest 3-of-a-kind, e.g. 0.36 × 100 = 36.00000000000001 or 35.99…
check(pay_mult(100, $fs) === (int)round($fs * 100), 'a fractional ways total pays its nearest coin');

/* ── Finding 3: crash ties ── */
$mk = fn(int $pid, float $crash, float $auto, float $at) => tx(fn() => round_open($pid, 'crash', 100, ['start' => microtime(true) - log($at) / CRASH_K, 'crash' => $crash, 'auto' => $auto]));
$tie = null; $auto = null; $above = null;
for ($try = 0; $try < 5 && !$tie; $try++) { $r = $mk($P1, 1.01, 0.0, 1.0102); if (crash_now(st($r)) !== 1.01) { tx(fn() => round_close($r, st($r), 0, 'void')); continue; } $x = tx(fn() => crash_resolve($r, true)); if (crash_now(st($r)) === 1.01) { $tie = $x; } }
check($tie && $tie['outcome'] === 'cashout' && (int)$tie['payout'] === 101, 'manual cash-out at exactly the break multiplier (1.01 = 1.01) wins and pays 101');
for ($try = 0; $try < 5 && !$auto; $try++) { $r = $mk($P1, 1.01, 1.01, 1.0102); if (crash_now(st($r)) !== 1.01) { tx(fn() => round_close($r, st($r), 0, 'void')); continue; } $x = tx(fn() => crash_resolve($r, false)); if (crash_now(st($r)) === 1.01) { $auto = $x; } }
check($auto && $auto['outcome'] === 'cashout' && (int)$auto['payout'] === 101, 'auto cash-out at exactly the break multiplier wins the same way');
$r = $mk($P1, 1.5, 0.0, 2.0); $above = tx(fn() => crash_resolve($r, true));
check($above['outcome'] === 'crashed' && (int)$above['payout'] === 0, 'a cash-out after the wave broke (2.00 > 1.50) still loses');
$r = $mk($P1, 1.5, 1.4, 2.0); $x = tx(fn() => crash_resolve($r, true));
check($x['outcome'] === 'cashout' && (int)$x['payout'] === 140, 'a reached auto target (1.40 ≤ 1.50) is paid even when the click comes late');
check(str_contains(implode(' ', GAME_RULES['crash']), 'exactly the multiplier the wave breaks on still wins'), 'crash rules text states the inclusive tie rule');

/* ── Finding 10: a break settles a live crash wave ── */
$r = $mk($P1, 50.0, 0.0, 1.20); $bal0 = bal($P1);
$b = child($P1, 'do_take_break', ['days' => 1, 'confirm' => 'BREAK']);
$row = row('SELECT * FROM rounds WHERE id = ?', [$r['id']]); $pl = row('SELECT break_until FROM players WHERE id = ?', [$P1]);
$fl = implode(' ', array_map(fn($f) => $f[1], $b['flash'] ?? []));
check($row['status'] === 'done' && $row['outcome'] === 'cashout' && (int)$row['payout'] >= 120 && bal($P1) === $bal0 + (int)$row['payout'] && $pl['break_until'] !== null && str_contains($fl, 'cashed out'), 'starting a break cashes out the live wave inside the same tx and says so: ' . $fl);
check(round_active($P1, 'crash') === null && !(child($P1, 'crash_act', ['move' => 'peek'])['ok'] ?? true), 'no crash round stays active and play is refused while on break');
$r = $mk($P2, 1.5, 0.0, 3.0);
$b = child($P2, 'do_take_break', ['days' => 1, 'confirm' => 'BREAK']);
$row = row('SELECT * FROM rounds WHERE id = ?', [$r['id']]); $fl = implode(' ', array_map(fn($f) => $f[1], $b['flash'] ?? []));
check($row['status'] === 'done' && $row['outcome'] === 'crashed' && (int)$row['payout'] === 0 && str_contains($fl, 'already broken'), 'a wave that had already broken is settled as lost when the break starts: ' . $fl);

printf("\n%d passed, %d failed in %.1fs\n", $PASS, $FAIL, microtime(true) - $T0);
exit($FAIL ? 1 : 0);
