<?php
/**
 * Gold Tide table-games audit regressions. Run: php goldtide/tests/audit_tables_test.php   (exit 0 = all green, < 60 s)
 *
 * Covers the "tables" audit group: Coastline 3-Card hand ordering (exhaustive, against a brute-force reference), Harbor
 * Blackjack rules (split once, DAS, split aces, late surrender, peek, 3:2 and surrender rounding, multi-hand DB flow) and its
 * house edge with basic strategy, Bayfront Baccarat banker rounding, Surf Sic Bo's 50 spots and exact returns, and the exact
 * bet-key spellings of Sic Bo and 3D roulette. No framework, no network: the engine is loaded through the CLI harness
 * (GT_NO_ROUTE) from a scratch copy of index.php, so the database it creates lives next to the copy and never touches data/.
 *
 * Knobs: GT_BJ_HANDS=3000000 for a long blackjack measurement, GT_TC_HANDS for three-card, GT_ONLY=bj|tc|bac|sicbo|rl to run one
 * section, GT_TEST_TMP=/dir to choose where the scratch copy goes.
 */
declare(strict_types=1);
error_reporting(E_ALL);
ini_set('display_errors', '1');
set_error_handler(fn($no, $str, $file, $line) => throw new ErrorException($str, 0, $no, $file, $line));
set_exception_handler(function (Throwable $e) {
    fwrite(STDERR, "\nUNCAUGHT " . get_class($e) . ': ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine() . "\n" . $e->getTraceAsString() . "\n");
    exit(1);
});
$T0 = microtime(true);

/* ───────── scratch copy of the app: its data/ is ours to trash ───────── */
$SCRATCH = rtrim(getenv('GT_TEST_TMP') ?: sys_get_temp_dir(), '/') . '/gt_audit_tables_' . getmypid();
if (!is_dir($SCRATCH) && !mkdir($SCRATCH, 0700, true)) { fwrite(STDERR, "cannot create $SCRATCH\n"); exit(1); }
copy(dirname(__DIR__) . '/index.php', $SCRATCH . '/index.php');
define('GT_NO_ROUTE', 1);
require $SCRATCH . '/index.php';
// index.php installs its own handlers (they render an HTML error page); put the test's back so a failure prints a trace
ini_set('display_errors', '1');
set_error_handler(fn($no, $str, $file, $line) => throw new ErrorException($str, 0, $no, $file, $line));
set_exception_handler(function (Throwable $e) {
    fwrite(STDERR, "\nUNCAUGHT " . get_class($e) . ': ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine() . "\n" . $e->getTraceAsString() . "\n");
    exit(1);
});
register_shutdown_function(function () use ($SCRATCH) {
    $rm = function (string $d) use (&$rm) { foreach (scandir($d) ?: [] as $f) { if ($f === '.' || $f === '..') { continue; } is_dir("$d/$f") ? $rm("$d/$f") : @unlink("$d/$f"); } @rmdir($d); };
    $rm($SCRATCH);
});

$PASS = 0; $FAIL = 0; $SECTION = ''; $FAILS = [];
function section(string $n): void { global $SECTION; $SECTION = $n; echo "\n== $n ==\n"; }
function yes(bool $c, string $msg): void { global $PASS, $FAIL, $SECTION, $FAILS; if ($c) { $PASS++; echo "  ok   $msg\n"; return; } $FAIL++; $FAILS[] = "[$SECTION] $msg"; echo "  FAIL $msg\n"; }
function eq(mixed $a, mixed $b, string $msg): void { yes($a === $b, $msg . ' (got ' . json_encode($a) . ', want ' . json_encode($b) . ')'); }
function near(float $a, float $b, float $tol, string $msg): void { yes(abs($a - $b) <= $tol, sprintf('%s (got %.3f, want %.3f ± %.3f)', $msg, $a, $b, $tol)); }
function throws(callable $fn, string $needle, string $msg): void {
    try { $fn(); yes(false, "$msg: no exception"); }
    catch (DomainException $e) { yes(str_contains($e->getMessage(), $needle), "$msg: " . $e->getMessage()); }
}
$ONLY = getenv('GT_ONLY') ?: '';
$run = fn(string $k) => $ONLY === '' || $ONLY === $k;

/* ───────── a player in the scratch database, "logged in" through the harness ───────── */
db();
q("INSERT INTO players (username, email, pass_hash, balance) VALUES ('audit_tables', 'audit@example.test', 'x', 1000000)");
$PID = (int)db()->lastInsertId();
$_SESSION = ['pid' => $PID];
$_SERVER['REQUEST_METHOD'] = 'POST';
function balance(): int { global $PID; return bal($PID); }
/** Ledger must always reconstruct the balance: every coin movement is one row. */
function ledger_ok(): bool { global $PID; return (int)val('SELECT COALESCE(SUM(amount),0) FROM ledger WHERE player_id = ?', [$PID]) + 1000000 === balance(); }
/**
 * fail() ends the request with exit, so the paths that reject a bet are exercised in a child php: it loads the same scratch copy,
 * fakes the session and POST, calls the engine and prints the JSON that fail()/the engine would send. Returns the decoded JSON.
 */
function probe(string $engine, array $post): array {
    global $SCRATCH, $PID;
    $code = 'define("GT_NO_ROUTE",1); require ' . var_export($SCRATCH . '/index.php', true) . '; $_SESSION=["pid"=>' . $PID . ']; $_SERVER["REQUEST_METHOD"]="POST"; $_SERVER["HTTP_X_REQUESTED_WITH"]="fetch"; $_POST=' . var_export($post, true) . '; try { ok(' . $engine . '()); } catch (Throwable $e) { json_out(["ok"=>false,"error"=>$e->getMessage()]); }';
    $out = shell_exec(PHP_BINARY . ' -d display_errors=0 -r ' . escapeshellarg($code) . ' 2>/dev/null');
    return json_decode((string)$out, true) ?: ['ok' => false, 'error' => 'no json: ' . substr((string)$out, 0, 200)];
}
/** Deal a fixed sequence into a blackjack shoe: cards are popped from the end, so the first card listed is dealt first. */
function rig(array $cards): array { return array_reverse($cards); }
/** Render a page function to a string. layout() sends headers, which the test's own output already made impossible: ignore just that warning. */
function render(callable $page): string {
    set_error_handler(function ($no, $str, $file, $line) { if (str_contains($str, 'header')) { return true; } throw new ErrorException($str, 0, $no, $file, $line); });
    ob_start();
    try { $page(); } finally { $html = (string)ob_get_clean(); restore_error_handler(); }
    return $html;
}

/* ═════════════════ 1. Coastline 3-Card: hand ranking ═════════════════ */
if ($run('tc')) {
    section('three-card: exhaustive ranking against a brute-force reference');
    // independent reference: category, then the ranks that decide ties, written from the rules rather than from tc_eval()
    $RANKS = ['2' => 2, '3' => 3, '4' => 4, '5' => 5, '6' => 6, '7' => 7, '8' => 8, '9' => 9, '10' => 10, 'J' => 11, 'Q' => 12, 'K' => 13, 'A' => 14];
    $ref = function (array $cards) use ($RANKS): array {
        $r = []; $suits = [];
        foreach ($cards as $c) { $r[] = $RANKS[substr($c, 0, -1)]; $suits[] = substr($c, -1); }
        rsort($r);
        $flush = count(array_unique($suits)) === 1;
        $distinct = count(array_unique($r)) === 3;
        $straight = $distinct && ($r[0] - $r[2] === 2 || $r === [14, 3, 2]);
        if ($r === [14, 3, 2] && $straight) { $r = [3, 2, 1]; }   // the wheel is the lowest straight
        if ($straight && $flush) { return [5, $r]; }
        if ($r[0] === $r[2]) { return [4, $r]; }
        if ($straight) { return [3, $r]; }
        if ($flush) { return [2, $r]; }
        if (!$distinct) { $pair = $r[0] === $r[1] ? $r[0] : $r[1]; $kick = $r[0] === $r[1] ? $r[2] : $r[0]; return [1, [$pair, $pair, $kick]]; }
        return [0, $r];
    };
    $refcmp = fn(array $a, array $b): int => $a[0] !== $b[0] ? ($a[0] <=> $b[0]) : ($a[1] <=> $b[1]);
    $deck = [];
    foreach (['S', 'H', 'D', 'C'] as $s) { foreach (array_keys($RANKS) as $rk) { $deck[] = $rk . $s; } }
    $catCount = array_fill(0, 6, 0); $mismatch = 0; $keys = []; $refKeys = []; $n = 0; $ppReturn = 0;
    for ($i = 0; $i < 52; $i++) { for ($j = $i + 1; $j < 52; $j++) { for ($k = $j + 1; $k < 52; $k++) {
        $hand = [$deck[$i], $deck[$j], $deck[$k]]; $n++;
        $e = tc_eval($hand); $r = $ref($hand);
        $catCount[$e[0]]++;
        if ($e[0] !== $r[0]) { $mismatch++; }
        $id = $e[0] . ':' . implode(',', $e[1]);
        if (!isset($keys[$id])) { $keys[$id] = $e; $refKeys[$id] = $r; }
        elseif ($refKeys[$id] !== $r) { $mismatch++; }   // two hands with the same engine key must be equal for the reference too
        $ppReturn += isset(TC_PAIRPLUS[$e[0]]) ? TC_PAIRPLUS[$e[0]] + 1 : 0;
    } } }
    eq($n, 22100, 'enumerated all C(52,3) hands');
    eq($catCount, [16440, 3744, 1096, 720, 52, 48], 'category counts match the textbook (high card, pair, flush, straight, trips, straight flush)');
    eq($mismatch, 0, 'tc_eval category and tie ranks agree with the reference on every hand');
    eq(count($keys), 741, 'distinct hand strengths');
    $ids = array_keys($keys); $bad = 0; $asym = 0; $selfBad = 0; $catBad = 0; $pairVsHigh = 0;
    foreach ($ids as $a) {
        if (tc_cmp($keys[$a], $keys[$a]) !== 0) { $selfBad++; }
        foreach ($ids as $b) {
            $c = tc_cmp($keys[$a], $keys[$b]);
            $want = $refcmp($refKeys[$a], $refKeys[$b]);
            if (($c <=> 0) !== $want) { $bad++; }
            if ($c !== -tc_cmp($keys[$b], $keys[$a])) { $asym++; }
            if ($keys[$a][0] > $keys[$b][0] && $c <= 0) { $catBad++; }
            if ($keys[$a][0] === 1 && $keys[$b][0] === 0 && $c <= 0) { $pairVsHigh++; }
        }
    }
    eq($selfBad, 0, 'every strength compares equal to itself');
    eq($bad, 0, 'all ' . (count($ids) ** 2) . ' pairwise comparisons agree with the reference ordering');
    eq($asym, 0, 'tc_cmp is antisymmetric');
    eq($catBad, 0, 'a higher category always beats a lower one');
    eq($pairVsHigh, 0, 'every pair beats every high card (the audit bug: PHP <=> ordered the shorter pair key below every 3-rank key)');
    eq(tc_cmp(tc_eval(['9S', '9H', '4D']), tc_eval(['QS', '7H', '2D'])), 1, 'pair of 9s beats Q-7-2');
    eq(tc_cmp(tc_eval(['2S', '2H', '3D']), tc_eval(['AS', 'KH', 'JD'])), 1, 'pair of 2s beats A-K-J');
    eq(tc_cmp(tc_eval(['2S', '2H', '3D']), tc_eval(['AS', 'KH', 'QD'])), -1, 'pair of 2s loses to the A-K-Q straight (the audit\'s own vector was a straight)');
    eq(tc_cmp(tc_eval(['QS', '6H', '4D']), tc_eval(['QC', '6D', '3S'])), 1, 'kickers decide within high card');
    eq(tc_cmp(tc_eval(['3S', '2H', 'AD']), tc_eval(['4S', '3H', '2D'])), -1, 'A-2-3 is the lowest straight');
    eq(tc_cmp(tc_eval(['9S', '9H', 'AD']), tc_eval(['9C', '9D', 'KD'])), 1, 'pair vs pair: kicker decides');
    eq(tc_cmp(tc_eval(['9S', '9H', '2D']), tc_eval(['8C', '8D', 'AD'])), 1, 'pair vs pair: pair rank first');
    eq($ppReturn, 21588, 'Pair Plus 1-4-6-30-40 returns 21,588 of 22,100 units = 97.68% exactly');

    section('three-card: ante/play house edge through the engine\'s evaluator');
    // fast dealer: partial Fisher-Yates over the top six cards with mt_rand (the game itself deals with random_int; only the math is under test)
    $hands = (int)(getenv('GT_TC_HANDS') ?: 600000);
    $q64 = tc_eval(['QS', '6H', '4D']);
    $res = ['always' => 0.0, 'q64' => 0.0];
    mt_srand(20260930);
    $d = $deck;
    for ($h = 0; $h < $hands; $h++) {
        for ($i = 51; $i >= 46; $i--) { $j = mt_rand(0, $i); [$d[$i], $d[$j]] = [$d[$j], $d[$i]]; }
        $pe = tc_eval([$d[51], $d[50], $d[49]]); $de = tc_eval([$d[48], $d[47], $d[46]]);
        $bonus = TC_ANTE_BONUS[$pe[0]] ?? 0;
        $qual = $de[0] >= 1 || $de[1][0] >= 12;
        $cmp = tc_cmp($pe, $de);
        $play = $bonus + (!$qual ? 1 : ($cmp > 0 ? 2 : ($cmp === 0 ? 0 : -2)));   // profit in antes when playing (ante + play bet at stake)
        $res['always'] += $play;
        $res['q64'] += tc_cmp($pe, $q64) >= 0 ? $play : -1;
    }
    $always = 100 * $res['always'] / $hands; $edgeQ64 = 100 * $res['q64'] / $hands;
    near($always, -7.65, 0.9, "always play: house edge per ante over $hands hands (textbook 7.65%)");
    near($edgeQ64, -3.37, 0.9, "Q-6-4 strategy: house edge per ante (textbook 3.37%)");
    yes($edgeQ64 < 0 && $always < 0, 'both strategies lose to the house (the audit found always-play at +12.9% for the player)');
}

/* ═════════════════ 2. Harbor Blackjack ═════════════════ */
if ($run('bj')) {
    section('blackjack: rules on scripted shoes');
    $st = bj_new(25, rig(['AS', '9D', 'KH', '7C']));
    yes($st['over'] && $st['hands'][0]['outcome'] === 'blackjack', 'player natural settles at the deal');
    eq($st['payout'], 63, '25 GC blackjack pays 3:2 rounded half up: 25 + 38');
    eq(count($st['dealer']), 2, 'the dealer does not draw against a lone natural');
    eq(bj_new(15, rig(['AS', '9D', 'KH', '7C']))['payout'], 38, '15 GC blackjack returns 38 (22.5 rounds up)');
    eq(bj_new(10, rig(['AS', '9D', 'KH', '7C']))['payout'], 25, '10 GC blackjack returns 25');
    $st = bj_new(10, rig(['KS', 'AD', 'QH', 'KC']));
    yes($st['over'] && $st['hands'][0]['outcome'] === 'dealer_blackjack' && $st['payout'] === 0, 'dealer peeks: a natural behind the Ace ends the hand before any action');
    $st = bj_new(10, rig(['KS', 'KD', 'QH', 'AC']));
    yes($st['over'] && $st['hands'][0]['outcome'] === 'dealer_blackjack', 'dealer peeks behind a ten too');
    $st = bj_new(10, rig(['AS', 'AD', 'KH', 'KC']));
    yes($st['over'] && $st['hands'][0]['outcome'] === 'push' && $st['payout'] === 10, 'two naturals push');
    $st = bj_new(10, rig(['9S', '6D', '7H', '9C', '2S', '8D']));
    eq(bj_legal($st), ['hit' => true, 'stand' => true, 'double' => true, 'split' => false, 'surrender' => true], 'first two cards: hit, stand, double, surrender (no pair, no split)');
    $st = bj_step($st, 'hit');
    eq(bj_legal($st), ['hit' => true, 'stand' => true, 'double' => false, 'split' => false, 'surrender' => false], 'after a hit only hit/stand remain');
    eq(bj_message($st), 'Hit or stand?', 'result strip names the legal moves');
    $st = bj_step($st, 'stand');
    yes($st['over'] && $st['hands'][0]['outcome'] === 'dealer_bust' && $st['payout'] === 20 && $st['dealer'] === ['6D', '9C', '8D'], 'dealer 15 draws an 8 and busts: pays 1:1');
    $st = bj_step(bj_new(10, rig(['9S', '6D', '7H', '9C', '2S', '2D'])), 'hit');
    $st = bj_step($st, 'stand');
    yes($st['over'] && $st['hands'][0]['outcome'] === 'win' && $st['dealer'] === ['6D', '9C', '2D'], 'dealer draws to 17 and stands (S17), loses to 18');
    $st = bj_step(bj_new(10, rig(['9S', '6D', '7H', '9C', '5S', '2D'])), 'hit');
    yes($st['over'] && $st['hands'][0]['outcome'] === 'win', 'hitting to 21 stands automatically');
    $st = bj_step(bj_new(10, rig(['9S', '6D', '7H', '9C', '9D', '8D'])), 'hit');
    yes($st['over'] && $st['hands'][0]['outcome'] === 'bust' && count($st['dealer']) === 2, 'bust ends the hand and the dealer does not draw');
    $st = bj_step(bj_new(25, rig(['10S', '9D', '6H', '7C', '2S'])), 'surrender');
    yes($st['over'] && $st['hands'][0]['outcome'] === 'surrender', 'late surrender on the first two cards');
    eq($st['payout'], 13, 'surrendering 25 returns 13 (12.5 rounds half up)');
    eq(bj_step(bj_new(10, rig(['10S', '9D', '6H', '7C', '2S'])), 'surrender')['payout'], 5, 'surrendering 10 returns 5');
    $st = bj_step(bj_new(10, rig(['5S', '6D', '6H', '10C', 'KS', 'AD'])), 'double');
    yes($st['over'] && $st['hands'][0]['doubled'] && $st['hands'][0]['bet'] === 20 && $st['hands'][0]['outcome'] === 'win' && $st['payout'] === 40 && $st['dealer'] === ['6D', '10C', 'AD'], 'double: one card, stake doubles, 21 beats the dealer\'s 17 for 40');
    $st = bj_step(bj_new(10, rig(['AS', '10D', '5H', '7C', '5S'])), 'double');
    yes($st['over'] && $st['hands'][0]['outcome'] === 'win' && $st['payout'] === 40, 'A-5 doubled into 21 beats a dealer 17 at 1:1 on the doubled bet (not a blackjack)');
    $st = bj_new(25, rig(['8S', '6D', '8H', '10C', '3S', '9H', '2C', 'KD']));
    eq(bj_legal($st)['split'], true, '8-8 can be split');
    $st = bj_step($st, 'split');
    yes($st['split'] && count($st['hands']) === 2 && $st['hands'][0]['cards'] === ['8S', '3S'] && $st['hands'][1]['cards'] === ['8H', '9H'], 'split deals one card to each hand');
    eq(array_column($st['hands'], 'bet'), [25, 25], 'the second hand carries the same bet');
    eq($st['active'], 0, 'first hand decides first');
    eq(bj_legal($st), ['hit' => true, 'stand' => true, 'double' => true, 'split' => false, 'surrender' => false], 'after the split: double after split allowed, no resplit, no surrender');
    throws(fn() => bj_step($st, 'split'), 'only once', 'resplit refused');
    throws(fn() => bj_step($st, 'surrender'), 'first two cards', 'surrender refused after a split');
    $st = bj_step($st, 'double');
    yes($st['hands'][0]['done'] && $st['hands'][0]['bet'] === 50 && $st['active'] === 1, 'double after split closes hand 1 and moves to hand 2');
    eq(bj_message($st), 'Hand 2: Hit, stand or double?', 'strip says which hand is deciding');
    $st = bj_step($st, 'stand');
    yes($st['over'] && $st['dealer'] === ['6D', '10C', 'KD'] && array_column($st['hands'], 'outcome') === ['dealer_bust', 'dealer_bust'], 'dealer busts against both split hands');
    eq($st['payout'], 150, 'payout sums both hands: 100 on the doubled hand, 50 on the other');
    eq(bj_message($st), 'Hand 1: Dealer busts. You win · Hand 2: Dealer busts. You win.', 'one verdict per hand');
    $st = bj_step(bj_new(10, rig(['AS', '6D', 'AH', '10C', 'KS', '9H', '5C', '4D'])), 'split');
    yes($st['over'] && count($st['hands'][0]['cards']) === 2 && count($st['hands'][1]['cards']) === 2, 'split aces get exactly one card each and the round resolves');
    eq($st['dealer'], ['6D', '10C', '5C'], 'dealer draws to 21 against the split hands');
    eq(array_column($st['hands'], 'outcome'), ['push', 'lose'], 'A-K after a split is 21, not blackjack: it only pushes the dealer 21; A-9 = 20 loses');
    eq($st['payout'], 10, 'split aces: the pushed hand returns its 10, the other is gone');
    $st = bj_step(bj_new(10, rig(['KS', '6D', 'QH', '9C', 'JS', 'AD', '5S', '2C'])), 'split');
    yes(!$st['over'] && $st['active'] === 0, 'a 20 after splitting tens still asks (not 21)');
    $st = bj_step(bj_new(10, rig(['KS', '6D', 'QH', '9C', 'AS', '5D', '2S', '3C'])), 'split');
    yes($st['hands'][0]['done'] && $st['active'] === 1 && $st['hands'][0]['cards'] === ['KS', 'AS'], 'K-A after a split is 21: it stands on its own and is not a blackjack');
    eq(bj_legal(bj_new(10, rig(['KS', '6D', 'QH', '9C'])))['split'], true, 'K-Q is a splittable ten pair');
    eq(bj_legal(bj_new(10, rig(['5S', '6D', '5H', '9C'])))['split'], true, '5-5 may be split (basic strategy just never does)');
    eq(bj_legal(bj_new(10, rig(['5S', '6D', '6H', '9C'])))['split'], false, '5-6 is not a pair');
    throws(fn() => bj_step(bj_new(10, rig(['5S', '6D', '6H', '9C'])), 'split'), 'matching pair', 'splitting a non-pair refused');
    throws(fn() => bj_step(bj_new(10, rig(['KS', 'AD', 'QH', 'KC'])), 'hit'), 'No hand in play', 'no moves on a finished hand');
    throws(fn() => bj_step(bj_new(10, rig(['5S', '6D', '6H', '9C'])), 'insurance'), 'Unknown move', 'unknown move refused');

    section('blackjack: coins and persistence through blackjack_act()');
    $b0 = balance();
    $_POST = ['move' => 'deal', 'bet' => 25];
    $r = blackjack_act();
    $h = $r['hand'];
    yes(in_array($h['status'], ['active', 'done'], true) && count($h['hands']) === 1 && $h['bet'] === 25, 'deal opens a hand with one 25 GC seat');
    if ($h['status'] === 'active') {
        yes($h['dealer_hidden'] === 1 && count($h['dealer']) === 1, 'hole card stays hidden while the hand is live');
        yes(isset($h['can']['hit']) && $h['can']['hit'] && $h['can']['surrender'], 'legal moves are published for the deciding hand');
        throws(fn() => blackjack_act(), 'Finish the hand', 'one active hand per player');   // $_POST is still the deal
        $_POST = ['move' => 'stand']; $r = blackjack_act(); $h = $r['hand'];
    }
    eq($h['status'], 'done', 'hand finishes');
    yes($h['dealer_hidden'] === 0 && count($h['dealer']) >= 2, 'dealer cards revealed at the end');
    eq(balance() - $b0, $h['payout'] - 25, 'balance moved by payout minus stake');
    yes(ledger_ok(), 'ledger reconstructs the balance');
    // a rigged active hand written the way the engine stores it: 8-8 vs dealer 6, split cards 3 and 9, then 2 for the double, dealer draws K
    $rigged = bj_new(40, rig(['8S', '6D', '8H', '10C', '3S', '9H', '2C', 'KD', '4S', '5S', '7S', '7D']));
    q('INSERT INTO bj_hands (player_id, bet, state) VALUES (?,?,?)', [$PID, 40, json_encode($rigged)]);
    $b0 = balance();
    $_POST = ['move' => 'split']; $r = blackjack_act(); $h = $r['hand'];
    eq(balance() - $b0, -40, 'split charges a second 40 GC bet');
    eq($h['bet'], 80, 'the row bet is the whole stake (what an admin void would refund)');
    eq(count($h['hands']), 2, 'two hands published');
    eq($h['active'], 0, 'hand 1 deciding');
    yes(!$h['can']['split'] && $h['can']['double'] && !$h['can']['surrender'], 'after the split: DAS yes, resplit no, surrender no');
    $_POST = ['move' => 'double']; $r = blackjack_act(); $h = $r['hand'];
    eq(balance() - $b0, -80, 'double after split charges another 40 GC');
    eq($h['bet'], 120, 'stake is now 120');
    eq($h['active'], 1, 'hand 2 deciding');
    eq($h['hands'][0]['cards'], ['8S', '3S', '2C'], 'doubled hand shows its third card');
    $_POST = ['move' => 'stand']; $r = blackjack_act(); $h = $r['hand'];
    eq($h['status'], 'done', 'round over after the last hand stands');
    eq($h['payout'], 240, 'dealer 6-10-K busts: 160 on the doubled hand + 80');
    eq(balance() - $b0, 160, 'net +160 GC');
    eq($h['outcome'], 'win', 'row outcome summarises a split round by its net');
    eq(array_column($h['hands'], 'outcome'), ['dealer_bust', 'dealer_bust'], 'per-hand outcomes published');
    eq(row('SELECT bet, payout, status FROM bj_hands WHERE id = ?', [$h['id']]), ['bet' => 120, 'payout' => 240, 'status' => 'done'], 'row persisted with the full stake and payout');
    yes(!str_contains((string)val('SELECT state FROM bj_hands WHERE id = ?', [$h['id']]), '"shoe"'), 'shoe dropped from the stored state once over');
    yes(ledger_ok(), 'ledger reconstructs the balance after split + double');
    $r = record_round_probe($PID);
    yes($r['total_wagered'] >= 120 && $r['rounds_played'] >= 2, 'record_round counted the whole stake');
    // surrender through the DB path
    $rigged = bj_new(25, rig(['10S', '9D', '6H', '7C', '2S']));
    q('INSERT INTO bj_hands (player_id, bet, state) VALUES (?,?,?)', [$PID, 25, json_encode($rigged)]);
    $b0 = balance();
    $_POST = ['move' => 'surrender']; $r = blackjack_act(); $h = $r['hand'];
    yes($h['status'] === 'done' && $h['outcome'] === 'surrender' && $h['payout'] === 13 && balance() - $b0 === 13, 'surrender pays 13 of 25 back through the ledger');
    eq($r['message'], BJ_OUTCOME_TEXT['surrender'], 'surrender message');
    // not enough coins for the split: the whole move rolls back and the hand stays playable
    $poor = bj_new(10, rig(['8S', '6D', '8H', '10C', '3S', '9H', '2C', 'KD']));
    q('UPDATE players SET balance = 5 WHERE id = ?', [$PID]);
    q('INSERT INTO bj_hands (player_id, bet, state) VALUES (?,?,?)', [$PID, 10, json_encode($poor)]);
    $hid = (int)db()->lastInsertId();
    $_POST = ['move' => 'split'];
    throws(fn() => blackjack_act(), 'Not enough', 'split with 5 GC left is refused');
    eq(row('SELECT bet, status FROM bj_hands WHERE id = ?', [$hid]), ['bet' => 10, 'status' => 'active'], 'refused split left the hand untouched');
    eq(json_decode((string)val('SELECT state FROM bj_hands WHERE id = ?', [$hid]), true)['hands'][0]['cards'], ['8S', '8H'], 'and the cards untouched');
    $_POST = ['move' => 'stand']; $r = blackjack_act();
    eq($r['hand']['status'], 'done', 'the poor player can still stand the hand out');
    q('UPDATE players SET balance = ? WHERE id = ?', [(int)val('SELECT 1000000 + COALESCE(SUM(amount),0) FROM ledger WHERE player_id = ?', [$PID]), $PID]);   // undo the hand-edit above
    // a hand stored before splits existed (single 'player' array) still plays
    $legacy = ['shoe' => rig(['KD', '5S']), 'player' => ['9S', '8H'], 'dealer' => ['6D', '10C'], 'doubled' => false];
    q('INSERT INTO bj_hands (player_id, bet, state) VALUES (?,?,?)', [$PID, 10, json_encode($legacy)]);
    $b0 = balance();
    $_POST = ['move' => 'stand']; $r = blackjack_act(); $h = $r['hand'];
    yes($h['status'] === 'done' && $h['hands'][0]['cards'] === ['9S', '8H'] && $h['outcome'] === 'dealer_bust' && balance() - $b0 === 20, 'legacy single-hand state is lifted and settles');
    // public view of a voided hand
    q('INSERT INTO bj_hands (player_id, bet, status, outcome, payout, state) VALUES (?,?,?,?,?,?)', [$PID, 10, 'void', 'void', 10, json_encode(['hands' => [['cards' => ['9S', '8H'], 'bet' => 10, 'doubled' => false, 'done' => false]], 'dealer' => ['6D', '10C'], 'active' => 0, 'split' => false, 'over' => false])]);
    $pub = bj_public(row('SELECT * FROM bj_hands WHERE id = ?', [(int)db()->lastInsertId()]));
    eq($pub['message'], BJ_OUTCOME_TEXT['void'], 'voided hand shows the void message');
    // the page renders every hand and only the legal buttons (no-JS form)
    $rigged = bj_new(10, rig(['8S', '6D', '8H', '10C', '3S', '9H', '2C', 'KD']));
    q('INSERT INTO bj_hands (player_id, bet, state) VALUES (?,?,?)', [$PID, 10, json_encode($rigged)]);
    $hid = (int)db()->lastInsertId();
    $_SERVER['REQUEST_METHOD'] = 'GET'; $_GET = ['action' => 'blackjack'];
    $html = render('page_blackjack');
    $btn = function (string $m) use (&$html): string { return preg_match('/<button[^>]*data-move="' . $m . '"[^>]*>/', $html, $mm) ? $mm[0] : ''; };   // by reference: the page is re-rendered below
    yes($btn('split') !== '' && !str_contains($btn('split'), 'hidden'), 'page shows Split for a pair');
    yes($btn('surrender') !== '' && !str_contains($btn('surrender'), 'hidden'), 'page shows Surrender on the first two cards');
    yes(str_contains($html, 'data-hand="0"') && !str_contains($html, 'data-hand="1"'), 'one hand rendered before the split');
    $_SERVER['REQUEST_METHOD'] = 'POST'; $_POST = ['move' => 'split']; blackjack_act();
    $html = render('page_blackjack');
    yes(str_contains($html, 'data-hand="1"') && str_contains($html, 'Hand 1') && str_contains($html, 'Hand 2'), 'both hands rendered after the split');
    yes(str_contains($btn('split'), 'hidden') && str_contains($btn('surrender'), 'hidden') && !str_contains($btn('double'), 'hidden'), 'after the split: Split and Surrender hidden, Double offered');
    yes(str_contains($html, 'Split a matching pair once') && str_contains($html, 'Late surrender') && str_contains($html, BJ_EDGE_TEXT), 'house-rules panel advertises the real rule set and the measured return');
    $_POST = ['move' => 'stand']; blackjack_act(); $_POST = ['move' => 'stand']; blackjack_act();
    eq(bj_active($PID), null, 'table cleared');
    yes(ledger_ok(), 'ledger reconstructs the balance at the end of the blackjack section');

    section('blackjack: house edge with basic strategy through bj_new/bj_step');
    $HANDS = (int)(getenv('GT_BJ_HANDS') ?: 600000);
    [$edge, $rtp, $stats] = bj_simulate($HANDS, 20260930);
    printf("  %d hands: edge %.3f%% of the initial bet, %.3f%% of all action returned; doubles %.1f%%, splits %.1f%%, surrenders %.1f%%, naturals %.2f%%, %.1fs\n",
        $HANDS, $edge, $rtp, 100 * $stats['double'] / $HANDS, 100 * $stats['split'] / $HANDS, 100 * $stats['surrender'] / $HANDS, 100 * $stats['natural'] / $HANDS, $stats['secs']);
    yes($edge > 0.05 && $edge < 0.9, 'house edge sits in the 6D/S17/DAS/split-once/late-surrender band (0.05–0.9%)');
    preg_match('/([\d.]+)% of all coins wagered \(house edge ([\d.]+)%/', BJ_EDGE_TEXT, $adv);
    near($rtp, (float)$adv[1], 0.45, 'advertised return of all action matches the measurement (tolerance 3σ at 600k hands)');
    near($edge, (float)$adv[2], 0.45, 'advertised house edge matches the measurement');
}
/** Player stats row: record_round() must count the whole stake of a split/doubled round. */
function record_round_probe(int $pid): array { return row('SELECT rounds_played, total_wagered, total_won FROM players WHERE id = ?', [$pid]) ?? []; }

/**
 * Total-dependent basic strategy for 6 decks, S17, DAS, split once, split aces one card, late surrender, peek.
 * The moves are exactly the ones the engine offers (bj_legal), so this plays the table like a disciplined guest would.
 */
function bj_basic(array $st): string {
    $legal = bj_legal($st);
    $h = $st['hands'][$st['active']];
    $c = $h['cards'];
    [$pt, $soft] = bj_value($c);
    $up = bj_card_value($st['dealer'][0]);   // 2..11
    $two = count($c) === 2;
    $pair = $two && bj_card_value($c[0]) === bj_card_value($c[1]);
    $v = $two ? bj_card_value($c[0]) : 0;
    if ($legal['surrender'] && !$pair) {
        if ($pt === 16 && !$soft && in_array($up, [9, 10, 11], true)) { return 'surrender'; }
        if ($pt === 15 && !$soft && $up === 10) { return 'surrender'; }
    }
    if ($legal['split'] && $pair) {
        $split = match ($v) {
            11, 8 => true,
            9 => $up !== 7 && $up <= 9,
            7, 3, 2 => $up <= 7,
            6 => $up <= 6,
            4 => $up === 5 || $up === 6,
            default => false,   // 5s and tens
        };
        if ($split) { return 'split'; }
    }
    $dbl = $legal['double'];
    if ($soft) {
        return match (true) {
            $pt >= 19 => 'stand',
            $pt === 18 => ($dbl && $up >= 3 && $up <= 6) ? 'double' : ($up <= 8 ? 'stand' : 'hit'),
            $pt === 17 => ($dbl && $up >= 3 && $up <= 6) ? 'double' : 'hit',
            $pt >= 15 => ($dbl && $up >= 4 && $up <= 6) ? 'double' : 'hit',
            default => ($dbl && $up >= 5 && $up <= 6) ? 'double' : 'hit',
        };
    }
    return match (true) {
        $pt >= 17 => 'stand',
        $pt >= 13 => $up <= 6 ? 'stand' : 'hit',
        $pt === 12 => ($up >= 4 && $up <= 6) ? 'stand' : 'hit',
        $pt === 11 => ($dbl && $up <= 10) ? 'double' : 'hit',
        $pt === 10 => ($dbl && $up <= 9) ? 'double' : 'hit',
        $pt === 9 => ($dbl && $up >= 3 && $up <= 6) ? 'double' : 'hit',
        default => 'hit',
    };
}
/** Plays $n hands of 10 GC through the engine on a fresh 6-deck shoe each; returns [edge % of initial bet, % of all action returned, stats]. */
function bj_simulate(int $n, int $seed): array {
    $t0 = microtime(true);
    mt_srand($seed);
    $base = [];
    for ($d = 0; $d < 6; $d++) { foreach (['S', 'H', 'D', 'C'] as $s) { foreach (['A', '2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K'] as $r) { $base[] = $r . $s; } } }
    $bet = 10; $staked = 0; $returned = 0;
    $stats = ['double' => 0, 'split' => 0, 'surrender' => 0, 'natural' => 0, 'deep' => 0];
    for ($i = 0; $i < $n; $i++) {
        // Fisher-Yates from the top for the 40 cards a round can reach (two split hands, doubles and the dealer never need more than ~36):
        // each step places a uniformly random remaining card, so the popped sequence is an exact random draw without replacement
        $shoe = $base;
        for ($k = 311; $k >= 272; $k--) { $j = mt_rand(0, $k); [$shoe[$k], $shoe[$j]] = [$shoe[$j], $shoe[$k]]; }
        $st = bj_new($bet, $shoe);
        while (!$st['over']) {
            $m = bj_basic($st);
            $stats[$m] = ($stats[$m] ?? 0) + 1;
            $st = bj_step($st, $m);
        }
        if (count($st['shoe']) < 272) { $stats['deep']++; }
        if (!$st['split'] && bj_natural($st['hands'][0]['cards'])) { $stats['natural']++; }
        $staked += array_sum(array_column($st['hands'], 'bet'));
        $returned += $st['payout'];
    }
    $stats['secs'] = microtime(true) - $t0;
    $edge = 100 * ($staked - $returned) / ($n * $bet);
    return [$edge, 100 * $returned / $staked, $stats];
}

/* ═════════════════ 3. Bayfront Baccarat: banker commission rounding ═════════════════ */
if ($run('bac')) {
    section('baccarat: 0.95:1 rounded to the nearest coin, half up');
    $bad = 0; $floored = 0;
    for ($b = 10; $b <= 5000; $b++) {
        $want = (int)round($b * 1.95, 0, PHP_ROUND_HALF_UP);
        $got = intdiv($b * 195 + 50, 100);
        if ($got !== $want) { $bad++; }
        if ($got < $b * 1.95 - 0.5) { $floored++; }   // nearest-coin rounding may go down by at most half a coin, never a whole one
    }
    eq($bad, 0, 'integer formula equals round-half-up(1.95 × bet) for every legal bet 10..5000');
    eq($floored, 0, 'no bet is ever short by more than half a coin (the old floor() cost up to 0.95 of a coin)');
    eq(intdiv(10 * 195 + 50, 100), 20, '10 GC banker returns 20 (9.5 profit rounds to 10)');
    eq(intdiv(30 * 195 + 50, 100), 59, '30 GC banker returns 59');
    eq(intdiv(50 * 195 + 50, 100), 98, '50 GC banker returns 98');
    eq(intdiv(100 * 195 + 50, 100), 195, '100 GC banker returns 195 exactly');
    // through the engine until the banker wins on a 10 GC chip (P ≈ 46% per hand)
    $hit = null; $others = 0; $othersOk = true;
    for ($i = 0; $i < 80 && $hit === null; $i++) {
        $_POST = ['bets' => json_encode([['key' => 'banker', 'amount' => 10]])];
        $b0 = balance();
        $r = baccarat_play();
        if ($r['result'] === 'banker') { $hit = [$r['payout'], balance() - $b0]; }
        elseif ($r['result'] === 'tie') { $others++; $othersOk = $othersOk && $r['payout'] === 10 && balance() === $b0; }
        else { $others++; $othersOk = $othersOk && $r['payout'] === 0 && balance() - $b0 === -10; }
    }
    yes($hit !== null, 'banker won within 80 hands');
    yes($othersOk, "the $others player wins / ties before it paid 0 / pushed the banker chip");
    if ($hit) { eq($hit, [20, 10], 'a 10 GC banker win returns 20 GC through the ledger (net +10)'); }
    $rules = implode(' ', GAME_RULES['baccarat']);
    yes(str_contains($rules, 'nearest whole coin') && str_contains($rules, '10 GC Banker win returns 20 GC'), 'baccarat rules text states the rounding rule');
    yes(ledger_ok(), 'ledger reconstructs the balance after baccarat');
}

/* ═════════════════ 4. Surf Sic Bo: 50 spots, exact returns ═════════════════ */
if ($run('sicbo')) {
    section('sic bo: the board has exactly 50 bets and every return matches the paytable');
    $cands = ['small', 'big', 'any_triple', 'Small', 'small ', ' small', "small\n", 'any triple', 'anytriple', 'combo:', 'combo:1', 'combo:1-1', 'combo:2-1', 'combo:1-7', 'combo:0-1', 'combo:01-2', "combo:1-2\n", 'combo:1-2-3', 'total', 'total:', 'single:', 'triple:x'];
    for ($n = -1; $n <= 20; $n++) { foreach (['total', 'single', 'double', 'triple', 'combo', 'pair'] as $t) { $cands[] = "$t:$n"; $cands[] = "$t:0$n"; $cands[] = "$t:00$n"; $cands[] = "$t:$n\n"; $cands[] = "$t:$n "; $cands[] = "$t:+$n"; $cands[] = "$t:$n.0"; } }
    for ($a = 0; $a <= 7; $a++) { for ($b = 0; $b <= 7; $b++) { $cands[] = "combo:$a-$b"; $cands[] = "combo:$a:$b"; $cands[] = "combo:0$a-$b"; } }
    $valid = array_values(array_unique(array_filter($cands, 'sicbo_valid')));
    eq(count($valid), 50, 'exactly 50 keys accepted out of ' . count(array_unique($cands)) . ' candidate spellings');
    $combos = array_values(array_filter($valid, fn($k) => str_starts_with($k, 'combo:')));
    eq(count($combos), 15, '15 two-dice combination bets');
    yes(!sicbo_valid('total:04') && !sicbo_valid("total:4\n") && !sicbo_valid('triple:01') && !sicbo_valid('combo:2-1') && !sicbo_valid('combo:1-1'), 'aliases rejected: leading zero, trailing newline, reversed or same-face combo');
    // exact return per key over the 216 equally likely rolls
    $ret = [];
    foreach ($valid as $k) { $ret[$k] = 0; }
    for ($a = 1; $a <= 6; $a++) { for ($b = 1; $b <= 6; $b++) { for ($c = 1; $c <= 6; $c++) { foreach ($valid as $k) { $ret[$k] += sicbo_returns($k, [$a, $b, $c]); } } } }
    eq([$ret['small'], $ret['big'], $ret['any_triple']], [210, 210, 186], 'small/big 210/216 = 97.22%, any triple 186/216 = 86.11%');
    $ok = true; foreach (range(1, 6) as $n) { $ok = $ok && $ret["single:$n"] === 199 && $ret["double:$n"] === 176 && $ret["triple:$n"] === 181; }
    yes($ok, 'singles 199/216 = 92.13%, doubles 176/216 = 81.48%, triples 181/216 = 83.80%');
    $ok = true; foreach ($combos as $k) { $ok = $ok && $ret[$k] === 210; }
    yes($ok, 'every combination returns 210/216 = 97.22% (6:1 on 30 of 216 rolls)');
    $want = [4 => 183, 5 => 186, 6 => 180, 7 => 195, 8 => 189, 9 => 175, 10 => 189, 11 => 189, 12 => 175, 13 => 189, 14 => 195, 15 => 180, 16 => 186, 17 => 183];
    $ok = true; foreach ($want as $t => $w) { $ok = $ok && $ret["total:$t"] === $w; }
    yes($ok, 'totals return 175–195/216 = 81.02–90.28%');
    $rules = implode(' ', GAME_RULES['sicbo']);
    yes(str_contains($rules, 'combinations') && str_contains($rules, 'pay 6:1') && str_contains($rules, 'Small/Big 97.2%') && str_contains($rules, 'combinations 97.2%'), 'sic bo rules text lists the combination bet and the returns');
    // Monte Carlo of the whole board through sicbo_returns: 50 spots × 200k rolls against the exact expectation
    $rolls = 60000; $tot = 0; mt_srand(7);
    for ($i = 0; $i < $rolls; $i++) { $d = [mt_rand(1, 6), mt_rand(1, 6), mt_rand(1, 6)]; foreach ($valid as $k) { $tot += sicbo_returns($k, $d); } }
    $exact = array_sum($ret) / 216;   // expected return per roll with one unit on every spot (SD ≈ 38 per roll, so ±0.6 is ~4σ)
    near($tot / $rolls, $exact, 0.6, "whole-board return per roll over $rolls rolls (house edge " . round(100 * (1 - $exact / 50), 2) . '% across the layout)');
    // the board markup carries all 50 spots and the engine accepts a combination bet
    $html = panel_sicbo(row('SELECT * FROM players WHERE id = ?', [$PID]), row("SELECT * FROM games WHERE slug = 'sicbo'"));
    preg_match_all('/data-bet="([^"]+)"/', $html, $mm);
    eq(count(array_unique($mm[1])), 50, 'panel renders 50 spots');
    eq(count(array_diff($valid, $mm[1])), 0, 'every valid key is on the board');
    $_POST = ['bets' => json_encode([['key' => 'combo:1-2', 'amount' => 10], ['key' => 'small', 'amount' => 10]])];
    $b0 = balance(); $r = sicbo_play();
    $d = $r['dice']; $cnt = array_count_values($d);
    $wantPay = (isset($cnt[1], $cnt[2]) ? 70 : 0) + (sicbo_returns('small', $d) ? 20 : 0);
    eq($r['payout'], $wantPay, 'combo:1-2 paid 6:1 (plus stake) on roll ' . implode('-', $d));
    eq(balance() - $b0, $r['payout'] - 20, 'balance moved by payout minus the 20 GC staked');
    $rej = probe('sicbo_play', ['bets' => json_encode([['key' => 'total:04', 'amount' => 10]])]);
    yes(($rej['ok'] ?? true) === false && str_contains($rej['error'] ?? '', 'isn\'t on this table'), 'total:04 rejected by the server: ' . ($rej['error'] ?? '?'));
    $rej = probe('sicbo_play', ['bets' => json_encode([['key' => "triple:1\n", 'amount' => 10]])]);
    yes(($rej['ok'] ?? true) === false, 'triple:1 with a trailing newline rejected');
    $acc = probe('sicbo_play', ['bets' => json_encode([['key' => 'combo:5-6', 'amount' => 10]])]);
    yes(($acc['ok'] ?? false) === true, 'combo:5-6 accepted by the server');
    yes(ledger_ok(), 'ledger reconstructs the balance after sic bo');
}

/* ═════════════════ 5. 3D roulette: exact key spellings ═════════════════ */
if ($run('rl')) {
    section('3D roulette: one spelling per spot');
    $keys = [];
    for ($n = 0; $n <= 36; $n++) { $keys[] = "straight:$n"; }
    foreach (['red', 'black', 'odd', 'even', 'low', 'high'] as $k) { $keys[] = "$k:0"; }
    foreach ([1, 2, 3] as $n) { $keys[] = "dozen:$n"; $keys[] = "column:$n"; }
    eq(count($keys), 49, '49 canonical spots');
    foreach (array_chunk($keys, 25) as $chunk) {   // parse_bets caps a round at 40 spots
        $_POST = ['bets' => json_encode(array_map(fn($k) => ['key' => $k, 'amount' => 10], $chunk))];
        $b0 = balance(); $r = roulette3d_play();
        $n = $r['number'];
        $want = 0; foreach ($chunk as $k) { [$t, $v] = explode(':', $k); $want += 10 * roulette_wins($t, (int)$v, $n); }
        eq($r['payout'], $want, count($chunk) . ' canonical keys accepted and paid correctly on ' . $n);
        eq(balance() - $b0, $r['payout'] - 10 * count($chunk), 'balance moved by payout minus stake');
    }
    foreach (['straight:07', "straight:7\n", 'red:00', 'dozen:01', 'straight:37', 'straight:-1', 'straight:', 'red:1', 'column:0', 'STRAIGHT:7', 'straight:7 '] as $alias) {
        $rej = probe('roulette3d_play', ['bets' => json_encode([['key' => $alias, 'amount' => 10]])]);
        yes(($rej['ok'] ?? true) === false && str_contains($rej['error'] ?? '', 'isn\'t on this table'), 'rejected ' . json_encode($alias));
    }
    $rej = probe('roulette3d_play', ['bets' => json_encode([['key' => 'straight:7', 'amount' => 5000], ['key' => 'straight:07', 'amount' => 5000]])]);
    yes(($rej['ok'] ?? true) === false, 'the leading-zero alias can no longer stack a second 5,000 on number 7');
    yes(ledger_ok(), 'ledger reconstructs the balance after roulette');
}

/* ───────── summary ───────── */
printf("\n%d passed, %d failed in %.1fs\n", $PASS, $FAIL, microtime(true) - $T0);
foreach ($FAILS as $f) { echo "  - $f\n"; }
exit($FAIL ? 1 : 0);
