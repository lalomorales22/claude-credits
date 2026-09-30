<?php
/**
 * Regression checks for the slots audit: integer win math with one floor per spin, the 50 GC minimum, the
 * running-total max-win cap, the real pick bonus (hidden board, move=pick, auto-settle), and the rules/README claims.
 *
 * Runs against a scratch copy of index.php (its own data/ directory), so the shared checkout's database is never touched.
 *   php goldtide/tests/audit_slots_test.php            GT_SIM_N=<spins per slot> (default 300000) scales the RTP simulation.
 * Prints one line per check and exits 1 if any failed.
 */
declare(strict_types=1);
$t0 = microtime(true);
$src = dirname(__DIR__) . '/index.php';
$dir = sys_get_temp_dir() . '/gt_audit_slots_' . getmypid();
if (!is_dir($dir)) { mkdir($dir, 0700, true); }
copy($src, $dir . '/index.php');
register_shutdown_function(function () use ($dir) {
    foreach (array_merge(glob($dir . '/data/{,.}*', GLOB_BRACE) ?: [], glob($dir . '/{,.}*', GLOB_BRACE) ?: []) as $f) { if (is_file($f)) { @unlink($f); } }
    @rmdir($dir . '/data'); @rmdir($dir);
});
define('GT_NO_ROUTE', 1);
$_SERVER['REMOTE_ADDR'] = '127.0.0.1'; $_SERVER['REQUEST_METHOD'] = 'POST'; $_SERVER['HTTP_X_REQUESTED_WITH'] = 'fetch';
require $dir . '/index.php';

$fails = 0;
function t_check(string $name, bool $ok, string $detail = ''): void {
    global $fails; if (!$ok) { $fails++; }
    printf("%s  %s%s\n", $ok ? 'PASS' : 'FAIL', $name, $detail !== '' ? '  [' . $detail . ']' : '');
}
/** A play request in a child process, so fail() paths (which exit) can be observed as JSON. */
function t_child(string $dir, int $pid, string $g, array $post): array {
    $script = $dir . '/child.php';
    if (!is_file($script)) {
        file_put_contents($script, '<?php define("GT_NO_ROUTE", 1); $_SERVER["REMOTE_ADDR"] = "127.0.0.1"; $_SERVER["REQUEST_METHOD"] = "POST"; $_SERVER["HTTP_X_REQUESTED_WITH"] = "fetch";'
            . ' require __DIR__ . "/index.php"; $a = json_decode($argv[1], true); $_SESSION = ["pid" => $a["pid"], "csrf" => "tok"]; $_GET = ["g" => $a["g"]]; $_POST = $a["post"];'
            . ' try { echo json_encode(["ok" => true, "data" => vs_play()]); } catch (DomainException $e) { echo json_encode(["ok" => false, "error" => $e->getMessage()]); }');
    }
    exec(PHP_BINARY . ' ' . escapeshellarg($script) . ' ' . escapeshellarg(json_encode(['pid' => $pid, 'g' => $g, 'post' => $post])) . ' 2>&1', $out);
    return json_decode(implode('', $out), true) ?: ['ok' => false, 'error' => 'no json: ' . implode('', $out)];
}
function t_play(int $pid, string $g, array $post): array { $_SESSION = ['pid' => $pid, 'csrf' => 'tok']; $_GET = ['g' => $g]; $_POST = $post; return vs_play(); }
function t_parts(array $d): int { return $d['base_win'] + ($d['fs']['win'] ?? 0) + ($d['bonus']['win'] ?? 0); }
/** Closed-form RTP (same derivation as the engine comment): ways + scatter + free spins + P(trigger)·E[bonus]. */
function t_closed(array $t): float {
    $binom = function (int $n, int $k): float { $r = 1; for ($i = 1; $i <= $k; $i++) { $r = $r * ($n - $k + $i) / $i; } return $r; };
    $bdist = function (int $n, float $p) use ($binom): array { $d = []; for ($k = 0; $k <= $n; $k++) { $d[$k] = $binom($n, $k) * $p ** $k * (1 - $p) ** ($n - $k); } return $d; };
    $w = $t['w']; $tot2 = array_sum($w); $tot1 = $tot2 - $w['W']; $ways = 0.0;
    foreach (VS_SYMS as $s) {
        $q = [$w[$s] / $tot1, ($w[$s] + $w['W']) / $tot2, ($w[$s] + $w['W']) / $tot2, ($w[$s] + $w['W']) / $tot2, $w[$s] / $tot1];
        for ($k = 3; $k <= 5; $k++) { $e = $t['pays'][$s][$k - 3]; for ($r = 0; $r < $k; $r++) { $e *= 3 * $q[$r]; } if ($k < 5) { $e *= (1 - $q[$k]) ** 3; } $ways += $e; }
    }
    $a = $bdist(6, $w['S'] / $tot1); $b = $bdist(9, $w['S'] / $tot2); $pn = array_fill(0, 16, 0.0);
    foreach ($a as $i => $pa) { foreach ($b as $j => $pb) { $pn[$i + $j] += $pa * $pb; } }
    $scat = 0.0; $spins = 0.0;
    for ($n = 3; $n <= 15; $n++) { $scat += $pn[$n] * VS_SCATTER_PAY[min($n, 5)]; $spins += $pn[$n] * $t['fs'][min($n, 5)]; }
    $base = $ways + $scat; $pW = $w['W'] / $tot2;
    return 100 * ($base + $spins * $t['mult'] * $base + (1 - (1 - $pW) ** 3) ** 3 * t_bonus_ev($t));
}
function t_bonus_ev(array $t): float {
    $tab = $t['bonus']['type'] === 'wheel' ? VS_WHEEL : VS_PICK; $ev = 0.0;
    foreach ($tab as $v => $n) { $ev += $v * $n / array_sum($tab); }
    return $t['bonus']['type'] === 'wheel' ? $ev : 3 * $ev;
}

/* ── 0. fresh install: the six slots seed at VS_MIN_BET, everything else at 10 ── */
db();
$mins = array_column(q('SELECT slug, min_bet FROM games')->fetchAll(), 'min_bet', 'slug');
t_check('seed: video slots start at VS_MIN_BET (' . VS_MIN_BET . ')', count(array_filter(array_keys(VSLOTS), fn($s) => (int)$mins[$s] === VS_MIN_BET)) === 6 && (int)$mins['dice'] === 10, json_encode(array_intersect_key($mins, VSLOTS + ['dice' => 1])));
q("UPDATE games SET min_bet = 10 WHERE slug = 'tiki'");
$g10 = row("SELECT * FROM games WHERE slug = 'tiki'"); $gf = vs_game($g10);
t_check('vs_game(): a legacy 10 GC row is floored to VS_MIN_BET in memory and in the table', (int)$gf['min_bet'] === VS_MIN_BET && (int)$gf['max_bet'] === 5000 && (int)val("SELECT min_bet FROM games WHERE slug = 'tiki'") === VS_MIN_BET);
$g75 = vs_game(['slug' => 'tiki', 'min_bet' => 75, 'max_bet' => 5000]);
t_check('vs_game(): a staff-set minimum of 75 rounds up to the 10 GC step (80) in memory, table untouched', (int)$g75['min_bet'] === 80 && (int)val("SELECT min_bet FROM games WHERE slug = 'tiki'") === VS_MIN_BET);

/* ── 1. rules text and README say what the code does ── */
$php = file_get_contents($src); $readme = file_get_contents(dirname(__DIR__) . '/README.md');
t_check('rules: wild row says the bonus starts on a base-game spin only', substr_count($php, 'in a base-game spin starts the') >= 2 && str_contains($php, "can't retrigger or start the bonus game"));
t_check('rules: wheel copy says the server already drew the result', str_contains($php, 'The wheel shows a result the server already drew'));
t_check('rules: pick copy describes a real pick with 12 face-down tiles', str_contains($php, '12 tiles are dealt face down') && !str_contains($php, 'pick 3 of 12 tiles. Each tile hides'));
t_check('rules: minimum bet, bet step and once-per-spin rounding are disclosed', str_contains($php, 'rounded down to a whole coin once') && str_contains($php, 'Bets run from <?= coins(VS_MIN_BET) ?> GC in steps of <?= VS_BET_STEP ?>'));
t_check('README: base-game trigger, 50 GC minimum in steps of 10, real pick, server-drawn wheel', str_contains($readme, 'in the base game (not during free spins)') && str_contains($readme, '**50 GC minimum, in steps of 10 GC**') && str_contains($readme, 'real pick-3-of-12') && str_contains($readme, 'server already drew'));
foreach (VSLOTS as $slug => $t) {
    $cf = t_closed($t);
    t_check("closed-form RTP $slug = " . number_format($cf, 3) . '% matches the advertised ' . $t['rtp'] . '%', abs($cf - $t['rtp']) <= 0.06);
}

/* ── 2. integer pay math: exact floor of bet × pay, no float, one floor per spin ── */
$gridH1x4 = [['H1', 'L1', 'L2'], ['H1', 'L3', 'L4'], ['H1', 'L5', 'H2'], ['H1', 'H3', 'H4'], ['L1', 'L2', 'L3']];
$ev = vs_eval($gridH1x4, VSLOTS['calavera']['pays']);
t_check('vs_eval: Calavera H1 ×4 single way is exactly 610 hundredths', $ev['c'] === 610 && count($ev['wins']) === 1 && $ev['wins'][0]['c'] === 610);
$sp = vs_spin(VSLOTS['calavera'], 330, fn() => $gridH1x4);
t_check('vs_spin: 6.1× at bet 330 pays 2013 (float floor paid 2012)', $sp['base_win'] === 2013 && $sp['payout'] === 2013 && (int)floor(330 * 6.1) === 2012);
$gridL5x2 = [['L5', 'L5', 'H1'], ['L5', 'H2', 'H3'], ['L5', 'H4', 'L1'], ['L2', 'L3', 'L4'], ['H1', 'H2', 'H3']];
$sp = vs_spin(VSLOTS['tiki'], 55, fn() => $gridL5x2);
t_check('vs_spin: Tiki L5 ×3 on 2 ways at bet 55 = floor(19.8) = 19 in one floor', $sp['base_win'] === 19 && $sp['wins'][0]['ways'] === 2 && $sp['wins'][0]['c'] === 36);
$bad = 0; $floatWrong = 0; $n = 0;
foreach (VSLOTS as $t) { foreach (VS_SYMS as $s) { for ($k = 0; $k < 3; $k++) { foreach ([1, 2, 3, 4, 6, 9, 27] as $ways) { foreach ([50, 55, 73, 100, 330, 650, 999, 1300, 2570, 5000] as $bet) {
    $c = (int)round($t['pays'][$s][$k] * 100) * $ways; $q = vs_coins($bet, $c); $n++;
    if ($q * 100 > $bet * $c || ($q + 1) * 100 <= $bet * $c) { $bad++; }
    if ((int)floor($bet * $t['pays'][$s][$k] * $ways) !== $q) { $floatWrong++; }
} } } } }
t_check("vs_coins: exact rational floor for all $n (slot, pay, ways, bet) combos", $bad === 0, "float formula disagreed on $floatWrong of them");

/* ── 3. every displayed part adds up to the payout, at an odd bet, on every slot ── */
foreach (VSLOTS as $slug => $t) {
    $mism = 0; $fsRounds = 0; $neg = 0;
    for ($i = 0; $i < 20000; $i++) {
        $sp = vs_spin($t, 55);
        if ($sp['payout'] !== $sp['base_win'] + ($sp['fs']['win'] ?? 0) || $sp['payout'] !== vs_coins(55, $sp['c'])) { $mism++; }
        if ($sp['fs']) { $fsRounds++; if ($sp['fs']['win'] !== array_sum(array_column($sp['fs']['spins'], 'win')) || $sp['fs']['played'] !== $sp['fs']['count']) { $mism++; } foreach ($sp['fs']['spins'] as $x) { if ($x['win'] < 0) { $neg++; } } }
    }
    t_check("reconcile $slug: base_win + fs.win == payout == floor(bet·c) and fs.win == Σ spins[].win over 20k spins at bet 55", $mism === 0 && $neg === 0, "$fsRounds free-spin rounds");
}

/* ── 4. max-win cap as a running total: parts still add up, free spins stop at the cap ── */
$capGrid = [['H1', 'H1', 'H1'], ['W', 'W', 'W'], ['W', 'W', 'W'], ['W', 'W', 'S'], ['S', 'S', 'H1']];
$sp = vs_spin(VSLOTS['coderain'], 50, fn() => $capGrid);
t_check('cap: Code Rain forced grid pays exactly 5,000× with base_win + fs.win == payout', $sp['capped'] && $sp['payout'] === VS_MAX_WIN * 50 && $sp['base_win'] + $sp['fs']['win'] === $sp['payout'] && $sp['fs']['win'] === array_sum(array_column($sp['fs']['spins'], 'win')),
    'base ' . $sp['base_win'] . ' fs ' . $sp['fs']['win'] . ' played ' . $sp['fs']['played'] . '/' . $sp['fs']['count']);
t_check('cap: free spins end at the spin that reaches the cap', $sp['fs']['played'] < $sp['fs']['count'] && $sp['fs']['played'] >= 1);
// 72 ways of H1 (1,317.6×) + 3 scatters (2×) = 1,319.6× base; free spins at 2× add 2,639.2× each, so the 2nd free spin crosses 5,000×
$wheelGrid = [['H1', 'H1', 'S'], ['W', 'W', 'W'], ['W', 'W', 'W'], ['W', 'W', 'S'], ['H1', 'H1', 'S']];
$sp = vs_spin(VSLOTS['tiki'], 50, fn() => $wheelGrid);
t_check('cap: Tiki 1,319.6× base + 2× free spins crosses the cap on free spin 2; parts add up to 5,000×', $sp['capped'] && $sp['payout'] === VS_MAX_WIN * 50 && $sp['fs']['played'] === 2 && $sp['base_win'] === 65980 && $sp['fs']['win'] === 250000 - 65980 && $sp['fs']['spins'][0]['win'] === 131960 && $sp['fs']['spins'][1]['win'] === 250000 - 65980 - 131960,
    'base ' . $sp['base_win'] . ' fs ' . ($sp['fs']['win'] ?? 'none') . ' played ' . ($sp['fs']['played'] ?? 0));

/* ── 5. the real pick bonus through vs_play(), against the scratch database ── */
q('INSERT INTO players (username, pass_hash, balance) VALUES (?,?,?)', ['audit_slots', password_hash('x', PASSWORD_BCRYPT, ['cost' => 4]), 50000000]);
$pid = (int)db()->lastInsertId();
$bet = 50; $bal = bal($pid); $spins = 0; $d = null; $settledOk = 0; $settledBad = 0;
for ($i = 0; $i < 20000; $i++) {
    $d = t_play($pid, 'abyss', ['bet' => (string)$bet]); $spins++;
    if (!empty($d['pending'])) { break; }
    $last = round_last($pid, 'abyss');
    if ($d['payout'] === t_parts($d) && (int)$last['payout'] === $d['payout'] && $d['balance'] === $bal - $bet + $d['payout'] && $last['status'] === 'done') { $settledOk++; } else { $settledBad++; }
    $bal = $d['balance'];
}
t_check("settled spins: response parts == payout == rounds.payout and balance moves by payout - bet ($settledOk spins)", $settledBad === 0 && $settledOk > 0);
t_check('pick trigger reached on Abyss (P ≈ 1/945)', !empty($d['pending']), "after $spins spins");
if (!empty($d['pending'])) {
    $r = round_active($pid, 'abyss'); $s = st($r);
    t_check('pending reply exposes the tile count only: bonus = {type, name, tile, tiles: 12}', $d['bonus'] === ['type' => 'pick', 'name' => 'Sunken Treasure', 'tile' => 'clam', 'tiles' => 12], json_encode($d['bonus']));
    t_check('pending reply carries no board/picks/values/x/win anywhere', !preg_match('/"(board|picks|values|others)"/', json_encode($d)));
    t_check('nothing is credited before the pick: balance == before − bet, one wager ledger row, round active with spin win parked', $d['balance'] === $bal - $bet && $r && (int)$s['spin'] === $d['payout'] && $d['payout'] === $d['base_win'] + ($d['fs']['win'] ?? 0)
        && (int)val('SELECT amount FROM ledger WHERE player_id = ? ORDER BY id DESC LIMIT 1', [$pid]) === -$bet);
    $board = $s['bonus']['board'];
    t_check('stored board: 12 prizes, every one a VS_PICK value', count($board) === 12 && !array_diff($board, array_keys(VS_PICK)));
    $html = panel_videoslot('abyss', row('SELECT * FROM players WHERE id = ?', [$pid]), row("SELECT * FROM games WHERE slug = 'abyss'"));
    t_check('panel on reload: shows the pending pick (tiles: 12, min bet 50, step 10) without the board values', str_contains($html, 'Bonus waiting') && str_contains($html, '&quot;tiles&quot;:12') && !str_contains($html, 'board') && str_contains($html, 'min="' . VS_MIN_BET . '"') && str_contains($html, 'step="' . VS_BET_STEP . '"'));
    foreach (['[0,0,1]', '[0,1,12]', '[0,1]', 'abc', '[1,2,3,4]', '[-1,2,3]'] as $tiles) {
        $c = t_child($dir, $pid, 'abyss', ['move' => 'pick', 'tiles' => $tiles]);
        t_check("pick rejects tiles=$tiles", !$c['ok'] && str_contains($c['error'] ?? '', 'Pick 3 different tiles'), json_encode($c));
    }
    t_check('round still active after the rejected picks', (bool)round_active($pid, 'abyss'));
    $before = $bal - $bet; $spinWin = $d['payout']; $played = (int)val('SELECT rounds_played FROM players WHERE id = ?', [$pid]); $won = (int)val('SELECT total_won FROM players WHERE id = ?', [$pid]);
    $p = t_play($pid, 'abyss', ['move' => 'pick', 'tiles' => '[3,7,11]']);
    $b = $p['bonus']; $x = $board[3] + $board[7] + $board[11];
    t_check('pick reply: picks [3,7,11] reveal the stored values, x = their sum, win = bet × x', $b['picks'] === [3, 7, 11] && $b['values'] === [$board[3], $board[7], $board[11]] && $b['x'] === $x && $b['win'] === $bet * $x && $b['board'] === $board && $b['auto'] === false);
    t_check('pick reply: payout = parked spin win + bonus win, balance credited once, tier/x from the total', $p['payout'] === $spinWin + $bet * $x && $p['spin_win'] === $spinWin && $p['balance'] === $before + $p['payout'] && $p['x'] == round($p['payout'] / $bet, 2) && $p['tier'] === vs_tier($p['payout'], $bet) && $p['pending'] === false);
    $r2 = row('SELECT * FROM rounds WHERE id = ?', [$r['id']]); $s2 = st($r2);
    t_check('round closed: rounds.payout == payout, one payout ledger row, stats bumped once', $r2['status'] === 'done' && (int)$r2['payout'] === $p['payout'] && $s2['bonus']['picks'] === [3, 7, 11] && empty($s2['bonus']['pending'])
        && (int)val("SELECT amount FROM ledger WHERE player_id = ? AND kind = 'payout' ORDER BY id DESC LIMIT 1", [$pid]) === $p['payout']
        && (int)val('SELECT rounds_played FROM players WHERE id = ?', [$pid]) === $played + 1 && (int)val('SELECT total_won FROM players WHERE id = ?', [$pid]) === $won + $p['payout']);
    try { t_play($pid, 'abyss', ['move' => 'pick', 'tiles' => '[0,1,2]']); t_check('second pick refused', false); }
    catch (DomainException $e) { t_check('second pick refused', $e->getMessage() === 'No bonus in progress.', $e->getMessage()); }
    $bal = $p['balance'];

    // abandoned pick: the next spin settles it with 3 random tiles and reports it
    $d = null;
    for ($i = 0; $i < 20000; $i++) { $d = t_play($pid, 'abyss', ['bet' => (string)$bet]); if (!empty($d['pending'])) { break; } $bal = $d['balance']; }
    t_check('second pick trigger reached', !empty($d['pending']));
    if (!empty($d['pending'])) {
        $old = round_active($pid, 'abyss'); $os = st($old); $parked = (int)$os['spin']; $balPending = $d['balance'];
        $d2 = t_play($pid, 'abyss', ['bet' => (string)$bet]);
        $res = $d2['bonus_resolved'] ?? null;
        t_check('next spin auto-settles the abandoned pick and reports it (bonus_resolved)', $res && $res['auto'] === true && count(array_unique($res['picks'])) === 3 && min($res['picks']) >= 0 && max($res['picks']) <= 11
            && $res['values'] === array_map(fn($i) => $os['bonus']['board'][$i], $res['picks']) && $res['win'] === $bet * array_sum($res['values']) && $res['payout'] === $parked + $res['win'], json_encode($res));
        $oldRow = row('SELECT * FROM rounds WHERE id = ?', [$old['id']]);
        $expect = $balPending + $res['payout'] - $bet + (empty($d2['pending']) ? $d2['payout'] : 0);
        t_check('auto-settled round closed and paid; new spin wagered after it', $oldRow['status'] === 'done' && (int)$oldRow['payout'] === $res['payout'] && $d2['balance'] === $expect && str_contains($oldRow['outcome'], 'auto'));
        if (!empty($d2['pending'])) { t_play($pid, 'abyss', ['move' => 'pick', 'tiles' => '[0,1,2]']); }
        try { t_play($pid, 'abyss', ['move' => 'pick', 'tiles' => '[0,1,2]']); t_check('stale pick after the auto-settle is refused with an explanation', false); }
        catch (DomainException $e) { t_check('stale pick after the auto-settle is refused with an explanation', str_contains($e->getMessage(), empty($d2['pending']) ? 'already settled' : 'No bonus'), $e->getMessage()); }
    }
}

/* ── 6. the wheel stays a server-decided one-shot: stop + win settled with the spin ── */
$d = null; $bal = bal($pid);
for ($i = 0; $i < 20000; $i++) { $d = t_play($pid, 'tiki', ['bet' => (string)$bet]); if ($d['bonus']) { break; } $bal = $d['balance']; }
t_check('wheel trigger reached on Tiki (P ≈ 1/431)', (bool)($d['bonus'] ?? null));
if ($d['bonus']) {
    $b = $d['bonus']; $last = round_last($pid, 'tiki');
    t_check('wheel reply: stop indexes a segment worth x, win = bet × x, settled in the same round', $b['type'] === 'wheel' && VS_WHEEL_SEGS[$b['stop']] === $b['x'] && $b['win'] === $bet * $b['x'] && $d['payout'] === t_parts($d)
        && $last['status'] === 'done' && (int)$last['payout'] === $d['payout'] && $d['balance'] === $bal - $bet + $d['payout'] && empty($d['pending']));
}

/* ── 7. cap on the bonus side, inside tx(): a pick with no room left pays only the room ── */
$r = tx(fn() => round_open($pid, 'blacksite', 50, ['grid' => [], 'x' => 0, 'capped' => false, 'fs' => null, 'spin' => VS_MAX_WIN * 50 - 100, 'bonus' => ['type' => 'pick', 'name' => 'Vault Cracker', 'board' => array_fill(0, 12, 1000), 'pending' => true]]));
$balBefore = bal($pid);
$p = t_play($pid, 'blacksite', ['move' => 'pick', 'tiles' => '[0,1,2]']);
t_check('pick cap: 3,000× of bonus with 100 GC of room pays 100 and flags capped; total is exactly 5,000× bet', $p['bonus']['win'] === 100 && $p['bonus']['x'] === 3000 && $p['capped'] === true && $p['payout'] === VS_MAX_WIN * 50 && $p['balance'] === $balBefore + VS_MAX_WIN * 50 && str_starts_with($p['message'], 'MAX WIN'));

/* ── 7b. staff void of a pending pick pays the stake AND the parked base/free-spin win; a plain active round refunds just the stake ── */
$r = tx(fn() => round_open($pid, 'coderain', 60, ['grid' => [], 'x' => 0, 'capped' => false, 'fs' => null, 'spin' => 1234, 'bonus' => ['type' => 'pick', 'name' => 'Mainframe Hack', 'board' => array_fill(0, 12, 2), 'pending' => true]]));
$balBefore = bal($pid); $ledgerBefore = (int)val('SELECT COUNT(*) FROM ledger WHERE player_id = ?', [$pid]);
$v = tx(fn() => round_void($r));
t_check('void of a pending pick: rounds.payout = bet + parked win, status void, balance up by 60 + 1,234 in two admin ledger rows', $v['status'] === 'void' && $v['outcome'] === 'void' && (int)$v['payout'] === 60 + 1234 && bal($pid) === $balBefore + 60 + 1234
    && (int)val('SELECT COUNT(*) FROM ledger WHERE player_id = ?', [$pid]) === $ledgerBefore + 2 && (int)val("SELECT COUNT(*) FROM ledger WHERE player_id = ? AND kind = 'admin' AND amount = 1234", [$pid]) === 1);
t_check('voided round is skipped by round_last and round_active, so the panel does not resume it', !round_active($pid, 'coderain') && (round_last($pid, 'coderain')['id'] ?? 0) !== (int)$r['id']);
try { t_play($pid, 'coderain', ['move' => 'pick', 'tiles' => '[0,1,2]']); t_check('pick after a void is refused', false); }
catch (DomainException $e) { t_check('pick after a void is refused', $e->getMessage() === 'No bonus in progress.', $e->getMessage()); }
$r = tx(fn() => round_open($pid, 'dice', 25, ['n' => 3])); $balBefore = bal($pid);
$v = tx(fn() => round_void($r));
t_check('void of an ordinary active round (no parked win) refunds exactly the stake', (int)$v['payout'] === 25 && bal($pid) === $balBefore + 25);
t_check('admin save routes an active→void rounds edit through round_void()', str_contains($php, "\$data['status'] === 'void') { round_void(\$existing); }"));
t_check('bet-adjust JS: the max button snaps to the largest bet on the step', str_contains($php, 'Math.floor(max / step) * step') && str_contains($php, 'min, max: top }'));

/* ── 8. min bet and step: 10 and 49 are refused with the real limits, 55 with the step, 50 and 60 play ── */
foreach ([10 => 'limits', 49 => 'limits', 55 => 'step', 50 => 'ok', 60 => 'ok'] as $b => $want) {
    $c = t_child($dir, $pid, 'calavera', ['bet' => (string)$b]);
    $ok = $want === 'ok' ? $c['ok'] === true : (!$c['ok'] && str_contains($c['error'] ?? '', $want === 'step' ? 'steps of ' . VS_BET_STEP : coins(VS_MIN_BET) . '–5,000'));
    t_check("bet $b on Calavera " . ['limits' => 'is refused with the 50–5,000 limits', 'step' => 'is refused: steps of 10', 'ok' => 'is accepted'][$want], $ok, $c['error'] ?? 'ok');
}

/* ── 9. pick EV: any 3 of 12 i.i.d. tiles = 3 draws = 20.28× ── */
$sumTile = 0; $sumPick = 0; $NB = 100000;
for ($i = 0; $i < $NB; $i++) { $b = vs_bonus(VSLOTS['abyss']); $sumTile += array_sum($b['board']); $pk = vs_random_tiles(); $sumPick += $b['board'][$pk[0]] + $b['board'][$pk[1]] + $b['board'][$pk[2]]; }
t_check('pick EV: mean tile ' . number_format($sumTile / (12 * $NB), 3) . ' ≈ 6.76 and 3 random picks ' . number_format($sumPick / $NB, 2) . ' ≈ 20.28', abs($sumTile / (12 * $NB) - 6.76) < 0.1 && abs($sumPick / $NB - 20.28) < 0.6);

/* ── 10. RTP by simulation: the single floor costs < 0.4 points from 50 GC up (paired exact-vs-floored, so the loss is near-deterministic) ── */
$N = (int)(getenv('GT_SIM_N') ?: 300000); $bets = [10, 20, 51, 50, 60, 70, 90, 100]; // 10/20/51 are no longer accepted: shown to document why
$noise = 2.5 * sqrt(300000 / $N); // sim-vs-closed-form band: about 4 standard errors at 300k spins (jackpots make the per-spin variance large)
foreach (VSLOTS as $slug => $t) {
    $sumC = 0; $hits = 0; $paid = array_fill_keys($bets, 0); $fsTot = 0;
    for ($i = 0; $i < $N; $i++) {
        $sp = vs_spin($t, 100); $sumC += $sp['c']; if ($sp['bonus_hit']) { $hits++; }
        foreach ($bets as $b) { $paid[$b] += vs_coins($b, $sp['c']); }
    }
    $bonusPart = 100 * $hits / $N * t_bonus_ev($t); // bonus wins are integer multiples of the bet: no rounding loss
    $exact = 100 * $sumC / (100 * $N) + $bonusPart; $cf = t_closed($t);
    $loss = []; foreach ($bets as $b) { $loss[$b] = $exact - (100 * $paid[$b] / ($b * $N) + $bonusPart); }
    $line = implode(' ', array_map(fn($b) => "b$b:" . number_format($loss[$b], 2), $bets));
    t_check("RTP $slug: sim exact " . number_format($exact, 2) . "% (closed form " . number_format($cf, 2) . "%), floor loss in points $line", abs($exact - $cf) < $noise && $loss[50] < 0.15 && $loss[60] < 0.4 && $loss[70] < 0.4 && $loss[90] < 0.4 && abs($loss[100]) < 1e-9, "$N spins");
    t_check("RTP $slug at the 50 GC minimum: closed form − floor loss = " . number_format($cf - $loss[50], 2) . '% is within 0.4 of the advertised ' . $t['rtp'] . '%', abs($cf - $loss[50] - $t['rtp']) <= 0.4);
}

printf("%s: %d failure(s) in %.1fs\n", $fails ? 'FAILED' : 'ALL GREEN', $fails, microtime(true) - $t0);
exit($fails ? 1 : 0);
