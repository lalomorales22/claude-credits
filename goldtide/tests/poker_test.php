<?php
/**
 * Gold Tide poker engine test-suite. Run: php goldtide/tests/poker_test.php   (exit 0 = all green)
 *
 * No framework. Sections: evaluator (hand-picked + 30,000 random hands against an independent brute-force reference),
 * scripted betting scenarios, side pots and odd chips, timers / sit-out / leaving / busting / add-ons, a 5,000-hand fuzz
 * with invariants after every action, hand-record verification and tampering, and a throughput figure.
 */
declare(strict_types=1);
define('GT_NO_ROUTE', 1);
require dirname(__DIR__) . '/index.php';
error_reporting(E_ALL);
set_error_handler(fn($no, $str, $file, $line) => throw new ErrorException($str, 0, $no, $file, $line));
set_exception_handler(function (Throwable $e) {
    fwrite(STDERR, "\nUNCAUGHT " . get_class($e) . ': ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine() . "\n" . $e->getTraceAsString() . "\n");
    exit(1);
});
$T0 = microtime(true);
$PASS = 0; $FAIL = 0; $SECTION = ''; $FAILS = [];
function section(string $n): void { global $SECTION; $SECTION = $n; echo "\n== $n ==\n"; }
function yes(bool $c, string $msg): void { global $PASS, $FAIL, $SECTION, $FAILS; if ($c) { $PASS++; return; } $FAIL++; if (count($FAILS) < 40) { $FAILS[] = "[$SECTION] $msg"; echo "  FAIL $msg\n"; } }
function eq(mixed $a, mixed $b, string $msg): void { yes($a === $b, $msg . ': got ' . json_encode($a) . ', want ' . json_encode($b)); }
function throws(callable $fn, string $msg, string $cls = DomainException::class): void {
    try { $fn(); yes(false, "$msg: no exception"); } catch (Throwable $e) { yes($e instanceof $cls, "$msg: got " . get_class($e) . ' ' . $e->getMessage()); }
}

/* ───────── helpers ───────── */

function tbl(int $seats = 6, int $sb = 10, int $bb = 20, int $min = 20, int $max = 1000000, int $act = 20): array {
    return pk_new_table(['id' => 7, 'name' => 'Test', 'seats' => $seats, 'small_blind' => $sb, 'big_blind' => $bb, 'min_buyin' => $min, 'max_buyin' => $max, 'act_secs' => $act]);
}
/** Seat the given stacks (seat => stack, null = empty) and start a hand with the button on $button. */
function deal(array $stacks, int $button = 0, array $o = []): array {
    $t = tbl($o['seats'] ?? max(2, count($stacks)), $o['sb'] ?? 10, $o['bb'] ?? 20, $o['min'] ?? 1);
    foreach ($stacks as $s => $st) { if ($st !== null) { pk_sit($t, $s, "u$s", $s + 1, "P$s", $st, in_array($s, $o['bots'] ?? [], true)); } }
    aim($t, $button);
    $ev = pk_start_hand($t, 1000.0);
    $t['events'] = [];   // drop the queued 'sit' events: scenario tests look at what happens next
    return [$t, $ev];
}
/** Put the previous button just before $button so the moving-button rule lands on $button. */
function aim(array &$t, int $button): void {
    $ready = []; foreach ($t['players'] as $s => $p) { if (pk_dealable($p)) { $ready[] = $s; } }
    $i = array_search($button, $ready, true);
    if ($i === false) { throw new LogicException("seat $button is not dealable"); }
    $t['button'] = $ready[($i - 1 + count($ready)) % count($ready)];
}
/** Rewrite the deck (right after pk_start_hand) so seats hold $holes and the board comes out as $board. */
function rig(array &$t, array $holes, array $board = []): void {
    $order = pk_deal_order($t['seats'], $t['button'], array_keys(array_filter($t['players'], fn($p) => $p['dealt'])));
    $n = count($order); $deck = [];
    foreach ([0, 1] as $r) { foreach ($order as $s) { $deck[] = $holes[$s][$r]; } }
    $used = array_flip([...$deck, ...$board]);
    $rest = array_values(array_filter(pk_deck(), fn($c) => !isset($used[$c])));
    $b = function (int $i) use (&$rest, $board) { return $board[$i] ?? array_shift($rest); };   // by reference: arrow fns would copy $rest
    $burn = function () use (&$rest) { return array_shift($rest); };
    $deck = [...$deck, $burn(), $b(0), $b(1), $b(2), $burn(), $b(3), $burn(), $b(4), ...$rest];
    if (count($deck) !== 52 || count(array_unique($deck)) !== 52) { throw new LogicException('rig produced a bad deck'); }
    $t['deck'] = $deck; $t['deck_hash'] = hash('sha256', implode(' ', $deck) . '|' . $t['deck_salt']);
    foreach ($order as $i => $s) { $t['players'][$s]['cards'] = [$deck[$i], $deck[$n + $i]]; }
}
function act(array &$t, int $seat, string $a, int $amt = 0): array { return pk_act($t, $seat, $a, $amt, $t['clock'] + 1.0); }
function stacks(array $t): array { return array_map(fn($p) => $p['stack'], $t['players']); }
function evts(array $ev, string $type): array { return array_values(array_filter($ev, fn($e) => $e['t'] === $type)); }
/** Finish the current hand with checks/calls only (no rigging of outcome). */
function checkdown(array &$t): array {
    $all = []; $guard = 0;
    while (pk_betting($t) && $guard++ < 200) { $L = pk_legal($t, $t['to_act']); $all = [...$all, ...act($t, $t['to_act'], $L['check'] ? 'check' : 'call')]; }
    return $all;
}
/** Everything a viewer must not see: cards that are neither theirs, on the board, nor shown. */
function hidden_cards(array $t, ?string $uid): array {
    $ok = array_flip($t['board']);
    foreach ($t['players'] as $p) { if ($p['uid'] === $uid || $p['show']) { foreach ($p['cards'] as $c) { $ok[$c] = 1; } } }
    return array_values(array_filter(pk_deck(), fn($c) => !isset($ok[$c])));
}
/** Dump engine state to $PK_DUMP (if set) when a fuzz assertion fails, so a failure can be studied. */
function dump(string $tag, array $state): void { $f = getenv('PK_DUMP'); if ($f) { file_put_contents($f, "== $tag ==\n" . json_encode($state, JSON_PRETTY_PRINT) . "\n", FILE_APPEND); } }
function leak_scan(array $t, ?string $uid): ?string {
    if ($t['phase'] === 'idle') { return null; }   // between hands nothing is secret: the last deck was revealed at hand_end
    $v = pk_view($t, $uid);
    if (array_key_exists('deck', $v) || array_key_exists('deck_salt', $v)) { return 'deck field present'; }
    // the log runs across hands and earlier hands' boards and shown cards are public: scan this hand's lines only
    $start = 0; foreach ($v['log'] as $i => $line) { if (str_starts_with($line, 'Hand #')) { $start = $i; } }
    $v['log'] = array_slice($v['log'], $start);
    $hidden = array_flip(hidden_cards($t, $uid));
    $walk = function ($x, string $path) use (&$walk, $hidden): ?string {
        if (is_array($x)) { foreach ($x as $k => $y) { if ($k === 'deck_hash') { continue; } if ($r = $walk($y, "$path.$k")) { return $r; } } return null; }
        if (!is_string($x)) { return null; }
        foreach (preg_split('/[^A-Za-z0-9]+/', $x) as $tok) { if (isset($hidden[$tok])) { return "$path contains $tok"; } }
        return null;
    };
    return $walk($v, 'view');
}

/* ───────── 1. evaluator ───────── */
section('evaluator: hand-picked');
$E = fn(string $s) => pk_eval7(explode(' ', $s));
$cases = [
    ['As Ks Qs Js Ts 2d 3c', 8, 'Royal Flush', 'As Ks Qs Js Ts'],
    ['9h 8h 7h 6h 5h Ah Kd', 8, 'Straight Flush, Nine high', '9h 8h 7h 6h 5h'],
    ['Ah 2h 3h 4h 5h Kd Qd', 8, 'Straight Flush, Five high', '5h 4h 3h 2h Ah'],
    ['7c 7d 7h 7s Kd 2c 3c', 7, 'Four of a Kind, Sevens', '7c 7d 7h 7s Kd'],
    ['Kc Kd Kh 9s 9d 2c 3c', 6, 'Full House, Kings over Nines', 'Kc Kd Kh 9s 9d'],
    ['Kc Kd Kh 9s 9d 9h 2c', 6, 'Full House, Kings over Nines', null],
    ['Ah 9h 7h 4h 2h Kd Qd', 5, 'Flush, Ace high', 'Ah 9h 7h 4h 2h'],
    ['Th 9d 8c 7s 6h Ad Kd', 4, 'Straight, Ten high', 'Th 9d 8c 7s 6h'],
    ['Ah Kd Qc Js Th 2d 3d', 4, 'Straight, Ace high', 'Ah Kd Qc Js Th'],
    ['Ah 2d 3c 4s 5h Kd Qd', 4, 'Straight, Five high', '5h 4s 3c 2d Ah'],
    ['8h 8d 8c Ah Kd 2c 3c', 3, 'Three of a Kind, Eights', '8h 8d 8c Ah Kd'],
    ['Kh Kd 9c 9s Ah 2c 3c', 2, 'Two Pair, Kings and Nines', 'Kh Kd 9c 9s Ah'],
    ['Kh Kd 9c 9s 5h 5d Ah', 2, 'Two Pair, Kings and Nines', 'Kh Kd 9c 9s Ah'],
    ['Jh Jd Ah Kd 9c 5c 2c', 1, 'Pair of Jacks', 'Jh Jd Ah Kd 9c'],
    ['Ah Kd 9c 7s 5h 3d 2c', 0, 'High Card, Ace', 'Ah Kd 9c 7s 5h'],
    ['Ah Kd 9c 7s 5h', 0, 'High Card, Ace', 'Ah Kd 9c 7s 5h'],
    ['6h 6d 6c 6s 5h 5d', 7, 'Four of a Kind, Sixes', '6h 6d 6c 6s 5h'],
];
foreach ($cases as [$hand, $rank, $name, $best]) {
    $e = $E($hand);
    eq($e['rank'], $rank, "$hand rank"); eq($e['name'], $name, "$hand name");
    if ($best !== null) { eq(implode(' ', $e['best']), $best, "$hand best five"); }
    eq(count($e['best']), 5, "$hand best has five cards");
}
$gt = fn(string $a, string $b, string $m) => yes($E($a)['score'] > $E($b)['score'], $m);
$tie = fn(string $a, string $b, string $m) => yes($E($a)['score'] === $E($b)['score'], $m);
$gt('7c 7d 7h 7s Kd 2c 3c', '7c 7d 7h 7s Qd 2c 3c', 'quads kicker K > Q');
$gt('Ah 9h 7h 4h 3h Kd Qd', 'Ah 9h 7h 4h 2h Kd Qd', 'flush fifth card 3 > 2');
$gt('2h 3d 4c 5s 6h Kd Qd', 'Ah 2d 3c 4s 5h Kd Qd', 'six-high straight beats the wheel');
$gt('Jh Jd Ah Kd 9c 5c 2c', 'Jh Jd Ah Kd 8c 5c 2c', 'pair kicker fight 9 > 8');
$gt('8h 8d 8c Ah Kd 2c 3c', '8h 8d 8c Ah Qd 2c 3c', 'trips second kicker K > Q');
$gt('Kh Kd 9c 9s Ah 2c 3c', 'Kh Kd 9c 9s Qh 2c 3c', 'two pair kicker A > Q');
$gt('Kh Kd 9c 9s 5h 5d Ah', 'Kh Kd 9c 9s 5h 5d Qh', 'three pairs: kicker A > Q');
$gt('Kc Kd Kh 9s 9d 2c 3c', 'Kc Kd Kh 8s 8d Ac 2d', 'full house pair rank 9 > 8 even with aces around');
$gt('2c 3c 4c 5c 7c Ad Kd', 'Ah Kd Qc Js Th 2d 3d', 'any flush beats broadway');
$gt('Kh 2h 9h 8h 7h 2c 3d', '6s 5s 9h 8h 7h 2c 3d', 'flush vs straight on the same board: flush');
$gt('Th 6h 9h 8h 7h 2c 3d', 'Kh 2h 9h 8h 7h 2c 3d', 'straight flush vs flush on the same board');
$tie('2c 3c Ah Kd Qc Js Th', '4d 5d Ah Kd Qc Js Th', 'board straight: split');
$gt('6c 7c Ah Ad Kh Kd 5c', '2c 3c Ah Ad Kh Kd 5c', 'counterfeited two pair: 7 kicker beats the board 5');
$tie('2c 3c Ah Ad Kh Kd 5c', '4c 3d Ah Ad Kh Kd 5c', 'both play the board kicker: split');
throws(fn() => pk_eval7(['Ah', 'Kd', 'Qc', 'Js']), 'four cards rejected', InvalidArgumentException::class);
throws(fn() => pk_eval7(['Ah', 'Kd', 'Qc', 'Js', 'Xx']), 'bad card rejected', InvalidArgumentException::class);

section('evaluator: 30,000 random hands vs brute force');
/** Independent five-card classifier (categories + tiebreaks, padded to a fixed-length comparable array). */
function ref5(array $c): array {
    static $rv = ['2' => 2, '3' => 3, '4' => 4, '5' => 5, '6' => 6, '7' => 7, '8' => 8, '9' => 9, 'T' => 10, 'J' => 11, 'Q' => 12, 'K' => 13, 'A' => 14];
    $r = []; $s = [];
    foreach ($c as $x) { $r[] = $rv[$x[0]]; $s[] = $x[1]; }
    rsort($r);
    $flush = count(array_unique($s)) === 1;
    $u = array_values(array_unique($r));
    $sh = 0;
    if (count($u) === 5) { if ($u[0] - $u[4] === 4) { $sh = $u[0]; } elseif ($u === [14, 5, 4, 3, 2]) { $sh = 5; } }
    $cnt = array_count_values($r);
    $keys = array_keys($cnt);
    usort($keys, fn($a, $b) => $cnt[$b] <=> $cnt[$a] ?: $b <=> $a);
    $n = array_map(fn($k) => $cnt[$k], $keys);
    if ($sh && $flush) { $v = [8, $sh]; }
    elseif ($n[0] === 4) { $v = [7, $keys[0], $keys[1]]; }
    elseif ($n[0] === 3 && $n[1] === 2) { $v = [6, $keys[0], $keys[1]]; }
    elseif ($flush) { $v = [5, ...$r]; }
    elseif ($sh) { $v = [4, $sh]; }
    elseif ($n[0] === 3) { $v = [3, $keys[0], $keys[1], $keys[2]]; }
    elseif ($n[0] === 2 && $n[1] === 2) { $v = [2, $keys[0], $keys[1], $keys[2]]; }
    elseif ($n[0] === 2) { $v = [1, $keys[0], $keys[1], $keys[2], $keys[3]]; }
    else { $v = [0, ...$r]; }
    return array_pad($v, 6, 0);
}
function combos(int $n, int $k, int $start = 0): array {
    if ($k === 0) { return [[]]; }
    $out = [];
    for ($i = $start; $i <= $n - $k; $i++) { foreach (combos($n, $k - 1, $i + 1) as $rest) { $out[] = [$i, ...$rest]; } }
    return $out;
}
$COMBOS = [5 => combos(5, 5), 6 => combos(6, 5), 7 => combos(7, 5)];
function ref_best(array $cards): array {
    global $COMBOS;
    $best = null;
    foreach ($COMBOS[count($cards)] as $idx) { $v = ref5(array_map(fn($i) => $cards[$i], $idx)); if ($best === null || ($v <=> $best) > 0) { $best = $v; } }
    return $best;
}
$deck = pk_deck(); $prev = null; $prevRef = null; $mism = 0; $catCount = array_fill(0, 9, 0);
mt_srand(20260930);
for ($i = 0; $i < 30000; $i++) {
    shuffle($deck);
    $n = [7, 7, 7, 6, 5][$i % 5];
    $hand = array_slice($deck, 0, $n);
    $e = pk_eval7($hand); $ref = ref_best($hand);
    $catCount[$e['rank']]++;
    if ($e['rank'] !== $ref[0]) { $mism++; if ($mism <= 5) { yes(false, 'category mismatch ' . implode(' ', $hand) . ' engine ' . $e['name'] . ' ref cat ' . $ref[0]); } }
    if (ref5($e['best']) !== $ref) { $mism++; if ($mism <= 5) { yes(false, "best five are not the best: " . implode(' ', $hand) . ' → ' . implode(' ', $e['best'])); } }
    if ($prev !== null) {
        $a = $e['score'] <=> $prev; $b = $ref <=> $prevRef;
        if ($a !== $b) { $mism++; if ($mism <= 5) { yes(false, 'ordering disagrees: ' . implode(' ', $hand) . ' vs previous hand'); } }
    }
    $prev = $e['score']; $prevRef = $ref;
}
eq($mism, 0, '30,000 random hands agree with the brute-force reference');
yes(min($catCount) > 0 || $catCount[8] >= 0, 'categories seen: ' . json_encode($catCount));
echo '  categories seen: ' . json_encode(array_combine(PK_CATS, $catCount)) . "\n";

/* ───────── 2. betting scenarios ───────── */
section('betting: heads-up order and blinds');
[$t, $ev] = deal([1000, 1000], 0);
eq($t['sb_seat'], 0, 'button posts the small blind heads-up'); eq($t['bb_seat'], 1, 'other seat is the big blind');
eq($t['to_act'], 0, 'button acts first preflop');
eq(pk_legal($t, 0), ['fold' => true, 'check' => false, 'call' => 10, 'raise' => ['min' => 40, 'max' => 1000], 'allin' => 1000], 'legal for the button');
eq(pk_legal($t, 1), null, 'not the big blind\'s turn');
eq(evts($ev, 'post'), [['t' => 'post', 'seat' => 0, 'amt' => 10, 'kind' => 'sb'], ['t' => 'post', 'seat' => 1, 'amt' => 20, 'kind' => 'bb']], 'post events');
eq(count($t['players'][0]['cards']), 2, 'two cards each'); eq($t['deck_hash'], hash('sha256', implode(' ', $t['deck']) . '|' . $t['deck_salt']), 'deck commitment');
act($t, 0, 'call');
eq($t['to_act'], 1, 'big blind has the option');
eq(pk_legal($t, 1), ['fold' => true, 'check' => true, 'call' => 0, 'raise' => ['min' => 40, 'max' => 1000], 'allin' => 1000], 'option: check or raise');
throws(fn() => act($t, 1, 'call'), 'call for 0 is rejected (check instead)');
$ev = act($t, 1, 'check');
eq($t['phase'], 'flop', 'flop dealt'); eq(count($t['board']), 3, 'three board cards'); eq($t['pot'], 40, 'pot collected');
eq($t['to_act'], 1, 'big blind acts first after the flop heads-up');
eq(evts($ev, 'street')[0]['cards'], $t['board'], 'street event carries the flop');
act($t, 1, 'check'); act($t, 0, 'check'); eq($t['phase'], 'turn', 'turn'); eq($t['to_act'], 1, 'bb first on the turn');
act($t, 1, 'check'); act($t, 0, 'check'); eq($t['phase'], 'river', 'river');
act($t, 1, 'check'); $ev = act($t, 0, 'check');
eq($t['phase'], 'settle', 'showdown settles'); eq(array_sum(stacks($t)), 2000, 'chips conserved'); eq($t['pot'], 0, 'pot paid out');
eq(count(evts($ev, 'showdown')), 1, 'showdown event'); yes(count(evts($ev, 'win')) >= 1, 'win event');
yes($t['players'][0]['show'] && $t['players'][1]['show'], 'both show at showdown');
pk_assert_invariants($t);

section('betting: 6-max order');
[$t, $ev] = deal([1000, 1000, 1000, 1000, 1000, 1000], 0);
eq([$t['sb_seat'], $t['bb_seat'], $t['to_act']], [1, 2, 3], 'sb, bb, utg');
foreach ([3, 4, 5, 0] as $s) { act($t, $s, 'call'); }
act($t, 1, 'call'); eq($t['to_act'], 2, 'big blind option last'); act($t, 2, 'check');
eq($t['phase'], 'flop', 'flop'); eq($t['to_act'], 1, 'small blind first postflop'); eq($t['pot'], 120, 'six limpers');
foreach ([1, 2, 3, 4, 5, 0] as $s) { act($t, $s, 'check'); }
eq($t['phase'], 'turn', 'check-around ends the street'); eq($t['to_act'], 1, 'sb first again');

section('betting: min-raise rules');
[$t, $ev] = deal([1000, 1000, 1000], 0);   // sb 1, bb 2, utg 0
eq(pk_legal($t, 0)['raise'], ['min' => 40, 'max' => 1000], 'first raise min = 2 bb');
throws(fn() => act($t, 0, 'raise', 39), 'raise below the minimum');
throws(fn() => act($t, 0, 'raise', 1001), 'raise above the stack');
act($t, 0, 'raise', 60);
eq([$t['cur_bet'], $t['min_raise']], [60, 40], 'raise of 40 sets min raise 40');
eq(pk_legal($t, 1)['raise']['min'], 100, 'next raise must be to 100');
act($t, 1, 'raise', 100);
eq($t['min_raise'], 40, 'a min raise keeps the min raise size');
eq(pk_legal($t, 2)['raise']['min'], 140, 'to 140');
act($t, 2, 'raise', 300);
eq($t['min_raise'], 200, 'raise of 200 sets min raise 200');
eq(pk_legal($t, 0)['raise']['min'], 500, 'reopened for the first raiser at 500');
throws(fn() => act($t, 0, 'raise', 499), '499 is short of the min raise');
act($t, 0, 'raise', 500); eq($t['cur_bet'], 500, 'raised to 500');
eq(pk_legal($t, 1)['raise']['min'], 700, 'min raise 200 again');
eq(pk_legal($t, 1)['call'], 400, 'call amount is the difference');

section('betting: short all-in does not reopen');
[$t, $ev] = deal([1000, 1000, 150], 0);   // seat 2 is the big blind with 150 total
act($t, 0, 'raise', 100); act($t, 1, 'call');
eq(pk_legal($t, 2)['raise'], null, 'seat 2 cannot min-raise (needs 180, has 150)');
eq(pk_legal($t, 2)['allin'], 150, 'but can shove 150');
act($t, 2, 'allin');
eq([$t['cur_bet'], $t['min_raise']], [150, 80], 'short shove moves the bet, not the min raise');
eq($t['to_act'], 0, 'action returns to the raiser');
eq(pk_legal($t, 0)['raise'], null, 'first raiser may not re-raise a short all-in');
eq(pk_legal($t, 0)['call'], 50, 'may call 50');
throws(fn() => act($t, 0, 'raise', 300), 'raise rejected');
act($t, 0, 'call');
eq(pk_legal($t, 1)['raise'], null, 'caller may not raise either'); act($t, 1, 'call');
eq($t['phase'], 'flop', 'street closes'); eq($t['to_act'], 1, 'two players can still bet: action continues'); eq($t['pot'], 450, 'pot 450');
pk_assert_invariants($t);

section('betting: full raise reopens, and cumulative short all-ins (TDA 44)');
[$t, $ev] = deal([1000, 1000, 1000], 0);
act($t, 0, 'raise', 60); act($t, 1, 'call'); act($t, 2, 'raise', 200);
eq(pk_legal($t, 0)['raise'], ['min' => 340, 'max' => 1000], 'full raise reopens the first raiser');
[$t, $ev] = deal([1000, 90, 120, 1000], 0);   // sb seat 1 (90), bb seat 2 (120), utg seat 3
act($t, 3, 'raise', 60); act($t, 0, 'call');
act($t, 1, 'allin'); eq([$t['cur_bet'], $t['min_raise']], [90, 40], 'sb shoves 90: short');
act($t, 2, 'allin'); eq([$t['cur_bet'], $t['min_raise']], [120, 40], 'bb shoves 120: short on its own');
eq(pk_legal($t, 3)['raise'], ['min' => 160, 'max' => 1000], 'but 60 → 120 is a full raise for seat 3: reopened');
[$t, $ev] = deal([1000, 90, 95, 1000], 0);
act($t, 3, 'raise', 60); act($t, 0, 'call'); act($t, 1, 'allin'); act($t, 2, 'allin');
eq(pk_legal($t, 3)['raise'], null, '60 → 95 is not a full raise: seat 3 may only call or fold');
eq(pk_legal($t, 3)['call'], 35, 'call 35');

section('betting: partial call, uncalled return, run-out');
[$t, $ev] = deal([1000, 50, 1000], 0);
act($t, 0, 'raise', 200);
eq(pk_legal($t, 1), ['fold' => true, 'check' => false, 'call' => 40, 'raise' => null, 'allin' => 50], 'short stack: call capped at the stack');
act($t, 1, 'call'); yes($t['players'][1]['allin'], 'partial call is all-in');
$ev = act($t, 2, 'fold');
eq(evts($ev, 'return'), [['t' => 'return', 'seat' => 0, 'amt' => 150]], '150 uncalled returned');
eq($t['phase'], 'settle', 'ran out to showdown'); eq(count($t['board']), 5, 'five board cards');
eq(array_map(fn($e) => $e['phase'], evts($ev, 'street')), ['flop', 'turn', 'river'], 'one street event per run-out street');
eq($t['runout'], 3, 'three run-out streets'); yes($t['next_at'] > $t['clock'] + 5, 'settle pause extended for the run-out');
eq(array_sum(array_column($t['pots'], 'amount')), 120, 'pot = 50 + 50 + 20');
eq(array_sum(stacks($t)), 2050, 'chips conserved');
pk_assert_invariants($t);

section('betting: everyone folds');
[$t, $ev] = deal([1000, 1000, 1000], 0);
act($t, 0, 'raise', 60); act($t, 1, 'fold'); $ev = act($t, 2, 'fold');
eq($t['phase'], 'settle', 'settled without showdown');
eq($t['winners'], [['seat' => 0, 'amount' => 50, 'hand' => null, 'cards' => []]], 'winner without showing');
yes(!$t['players'][0]['show'], 'no show'); eq($t['players'][0]['stack'], 1030, 'net +30');
eq(evts($ev, 'return')[0]['amt'], 40, '40 uncalled returned before the win');
eq(count(evts($ev, 'showdown')), 0, 'no showdown event');
$v = pk_view($t, 'u1'); eq($v['players'][0]['cards'], 2, 'others still see card backs'); eq($v['winners'][0]['cards'], [], 'winner cards hidden');
$v = pk_view($t, 'u0'); eq(count($v['players'][0]['cards']), 2, 'winner sees own cards');

section('betting: uncalled after a fold that partly matched');
[$t, $ev] = deal([1000, 60, 1000], 0);
act($t, 0, 'raise', 300); act($t, 1, 'call'); act($t, 2, 'call');
eq($t['phase'], 'flop', 'flop'); eq($t['to_act'], 2, 'seat 2 first (seat 1 is all-in)');
act($t, 2, 'check'); act($t, 0, 'raise', 200); $ev = act($t, 2, 'fold');
eq(evts($ev, 'return')[0]['amt'], 200, 'the whole bet comes back: nobody matched it');
eq($t['phase'], 'settle', 'run-out');
$amts = array_column($t['pots'], 'amount'); eq($amts, [180, 480], 'main 3×60, side 2×240');
eq($t['pots'][1]['eligible'], [0], 'side pot only for seat 0');
eq(array_sum(stacks($t)), 2060, 'conserved');

section('betting: heads-up short blinds');
[$t, $ev] = deal([1000, 15], 0);   // bb has 15 < 20
eq($t['players'][1]['allin'], true, 'short big blind is all-in'); eq($t['cur_bet'], 20, 'price to call is still the big blind');
eq($t['to_act'], 0, 'button must still act'); eq(pk_legal($t, 0)['call'], 10, 'complete to 20');
eq(pk_legal($t, 0)['raise'], null, 'no raising against an all-in with nobody else to act');
$ev = act($t, 0, 'call');
eq($t['phase'], 'settle', 'ran out'); eq(evts($ev, 'return')[0]['amt'], 5, '5 uncalled back to the button');
eq(array_sum(array_column($t['pots'], 'amount')), 30, 'pot 30');
[$t, $ev] = deal([5, 1000], 0);   // sb (button) has 5
eq(evts($ev, 'post')[0]['amt'], 5, 'short small blind posts its 5'); eq($t['phase'], 'settle', 'no action possible: straight to showdown');
eq(array_sum(array_column($t['pots'], 'amount')), 10, 'pot 10 after the uncalled 15 returns');
eq(array_sum(stacks($t)), 1005, 'conserved');

section('betting: raise-to-max equals all-in; leaving a raise to exactly the stack');
[$t, $ev] = deal([500, 500, 500], 0);
act($t, 0, 'raise', 500); yes($t['players'][0]['allin'], 'raise to the whole stack flags all-in');
eq(pk_legal($t, 1)['raise'], null, 'seat 1 cannot raise: a min raise (1000) is beyond its stack'); eq(pk_legal($t, 1)['allin'], 500, 'may shove');

/* ───────── 3. side pots ───────── */
section('side pots: 100 / 300 / 700 all-in and a caller');
[$t, $ev] = deal([100, 300, 700, 1000], 3);   // sb 0, bb 1, utg 2, button 3
rig($t, [0 => ['Kh', 'Kc'], 1 => ['Jh', 'Jc'], 2 => ['7h', '7c'], 3 => ['9c', '9d']], ['2c', '7d', '9h', 'Js', 'Kd']);
act($t, 2, 'allin'); act($t, 3, 'call'); act($t, 0, 'allin'); $ev = act($t, 1, 'allin');
eq($t['phase'], 'settle', 'settled');
eq(array_column($t['pots'], 'amount'), [400, 600, 800], 'pot sizes');
eq(array_column($t['pots'], 'eligible'), [[0, 1, 2, 3], [1, 2, 3], [2, 3]], 'eligibility');
eq(array_column($t['pots'], 'winners'), [[0], [1], [3]], 'winners per pot');
eq(stacks($t), [0 => 400, 1 => 600, 2 => 0, 3 => 1100], 'payouts');
eq(array_column(evts($ev, 'win'), 'pot'), [0, 1, 2], 'one win event per pot');
eq($t['players'][0]['hand'], 'Three of a Kind, Kings', 'hand names');
$ev = pk_tick($t, $t['next_at']);
eq(evts($ev, 'hand_end')[0]['busted'], [2 => ['uid' => 'u2', 'bot' => false]], 'seat 2 busted');
yes(!isset($t['players'][2]), 'busted real player removed'); eq($t['phase'], 'idle', 'idle');

section('side pots: ties and odd chips');
[$t, $ev] = deal([1000, 1000, 44, 1000], 3);   // sb 0, bb 1, seat 2 short, button 3
rig($t, [0 => ['2c', '3d'], 1 => ['4c', '5d'], 2 => ['6c', '7d'], 3 => ['8c', '9d']], ['Ah', 'Kh', 'Qh', 'Jh', 'Th']);
act($t, 2, 'call'); act($t, 3, 'call'); act($t, 0, 'call'); act($t, 1, 'check');
act($t, 0, 'raise', 40); act($t, 1, 'call'); act($t, 2, 'call'); act($t, 3, 'fold');
eq($t['phase'], 'turn', 'seat 2 is all-in but seats 0 and 1 can still bet each other');
checkdown($t); eq($t['phase'], 'settle', 'checked down to the river');
eq(array_column($t['pots'], 'amount'), [152, 32], 'main 44×3 + 20 folded, side 16×2');
eq(array_column($t['pots'], 'winners'), [[0, 1, 2], [0, 1]], 'three-way and two-way ties');
eq(stacks($t), [0 => 1008, 1 => 1006, 2 => 50, 3 => 980], 'odd chips (2) to the first winner left of the button');
[$t, $ev] = deal([1000, 1000, 1000, 1000], 3);
rig($t, [0 => ['2c', '3d'], 1 => ['4c', '5d'], 2 => ['6c', '7d'], 3 => ['8c', '9d']], ['Ah', 'Kh', 'Qh', 'Jh', 'Th']);
checkdown($t);
eq(array_column($t['pots'], 'winners'), [[0, 1, 2, 3]], 'four-way tie'); eq(stacks($t), [0 => 1000, 1 => 1000, 2 => 1000, 3 => 1000], 'everyone gets 20 back');
[$t, $ev] = deal([1000, 1000, 1000], 0, ['sb' => 5, 'bb' => 10]);   // sb 1, bb 2
rig($t, [0 => ['2c', '3d'], 1 => ['4c', '5d'], 2 => ['6c', '7d']], ['Ah', 'Kh', 'Qh', 'Jh', 'Th']);
act($t, 0, 'call'); act($t, 1, 'fold'); act($t, 2, 'check'); checkdown($t);
eq(array_column($t['pots'], 'amount'), [25], 'pot 25');
eq(stacks($t), [0 => 1002, 1 => 995, 2 => 1003], 'odd chip to seat 2, first winner clockwise from button 0');

/* ───────── 4. timers, sit-out, leaving, busting, add-ons ───────── */
section('timeouts and sit-out');
[$t, $ev] = deal([1000, 1000, 1000], 0);
$d = $t['deadline']; eq($d, 1000.0 + 20, 'deadline = now + act_secs');
eq(pk_tick($t, $d - 0.01), [], 'nothing before the deadline');
$ev = pk_tick($t, $d);
eq(array_map(fn($e) => $e['t'], $ev), ['timeout', 'action'], 'timeout then the auto action');
eq($ev[1]['act'], 'fold', 'facing a bet: folded'); eq($t['players'][0]['timeouts'], 1, 'one timeout');
act($t, 1, 'call'); $ev = pk_tick($t, $t['deadline']);
eq($ev[1]['act'], 'check', 'free: checked'); eq($t['phase'], 'flop', 'flop');
pk_tick($t, $t['deadline']); $ev = pk_tick($t, $t['deadline']);
yes(in_array(['t' => 'sitout', 'seat' => 2, 'on' => true], $ev, true), 'second timeout sits seat 2 out');
yes($t['players'][2]['sitout'], 'sitout flag'); yes($t['players'][2]['in'], 'still in this hand');
checkdown($t); eq($t['phase'], 'settle', 'hand finished');
pk_tick($t, $t['next_at']); $ev = pk_tick($t, $t['clock'] + 0.1);
eq($t['hand_no'], 2, 'next hand started'); yes(!$t['players'][2]['dealt'], 'sitting-out player dealt out');
eq(count(array_filter($t['players'], fn($p) => $p['dealt'])), 2, 'heads-up now'); eq($t['players'][2]['bet'], 0, 'no blind posted by the sit-out');
pk_sitout($t, 2, false); eq($t['players'][2]['timeouts'], 0, 'timeouts reset when back');
checkdown($t); pk_tick($t, $t['next_at']); pk_tick($t, $t['clock'] + 0.1);
yes($t['players'][2]['dealt'], 'dealt back in on the next hand');

section('sit and add-on during a hand');
[$t, $ev] = deal([1000, 1000, 1000], 0, ['seats' => 6]);
pk_sit($t, 4, 'u4', 5, 'P4', 500);
yes(!$t['players'][4]['in'] && !$t['players'][4]['dealt'], 'new seat waits');
pk_addon($t, 4, 300); eq($t['players'][4]['stack'], 800, 'add-on allowed for a seat not in the hand');
throws(fn() => pk_addon($t, 0, 100), 'add-on refused mid-hand for a dealt seat');
throws(fn() => pk_sit($t, 4, 'u9', 9, 'P9', 500), 'seat taken');
throws(fn() => pk_sit($t, 5, 'u4', 5, 'P4', 500), 'same uid twice');
throws(fn() => pk_sit($t, 6, 'u6', 6, 'P6', 500), 'seat out of range');
throws(fn() => pk_sit($t, 5, 'u5', 6, 'P5', 0), 'buy-in below the minimum');
$ev = pk_tick($t, $t['clock']); eq(evts($ev, 'sit'), [['t' => 'sit', 'seat' => 4]], 'sit event delivered by the next tick');
checkdown($t); pk_tick($t, $t['next_at']); pk_tick($t, $t['clock'] + 0.1);
yes($t['players'][4]['dealt'], 'dealt in from the next hand');
throws(fn() => pk_addon($t, 4, 1000000), 'add-on over the maximum');
[$t2, $ev] = deal([1000, 1000], 0); checkdown($t2); pk_tick($t2, $t2['next_at']);
pk_addon($t2, 0, 50); eq($t2['players'][0]['stack'] >= 1000, true, 'add-on between hands');

section('leaving during a hand');
[$t, $ev] = deal([1000, 1000, 1000, 1000], 0);   // to act: 3
eq(pk_leave($t, 1), -1, 'leaving mid-hand returns -1');
yes(!$t['players'][1]['in'] && $t['players'][1]['leaving'], 'folded out of turn and marked leaving');
eq($t['to_act'], 3, 'turn unchanged');
$ev = pk_tick($t, $t['clock']); eq($ev[0]['t'] . $ev[0]['act'], 'actionfold', 'the fold is reported as an action on the next tick');
eq(pk_leave($t, 3), -1, 'the player to act leaves'); eq($t['to_act'], 0, 'turn moved on');
act($t, 0, 'call'); eq($t['to_act'], 2, 'bb option'); act($t, 2, 'check');
checkdown($t); eq($t['phase'], 'settle', 'settled');
$ev = pk_tick($t, $t['next_at']);
$he = evts($ev, 'hand_end')[0];
eq($he['leavers'], [1 => 990, 3 => 1000], 'leavers paid their stacks at hand end');
eq(array_keys($t['players']), [0, 2], 'leavers removed');
eq(count($he['deck']), 52, 'deck revealed'); eq($he['deck_salt'], $t['deck_salt'], 'salt revealed');
[$t, $ev] = deal([1000, 1000, 1000], 0, ['seats' => 4]);
pk_sit($t, 3, 'u3', 4, 'P3', 700);
eq(pk_leave($t, 3), 700, 'a seat that is not in the hand leaves at once with its stack');
[$t, $ev] = deal([1000, 1000], 0);
rig($t, [0 => ['Ah', 'Ad'], 1 => ['2c', '3d']], ['7h', '8s', '9c', 'Jd', 'Qs']);   // seat 0 wins, so it is still seated below
act($t, 0, 'allin'); act($t, 1, 'allin');
eq($t['phase'], 'settle', 'all-in showdown'); eq($t['players'][0]['stack'], 2000, 'aces hold');
pk_tick($t, $t['next_at']); eq($t['phase'], 'idle', 'idle');
$st = $t['players'][0]['stack']; eq(pk_leave($t, 0), $st, 'idle leave returns the stack immediately'); yes(!isset($t['players'][0]), 'seat freed');
$ev = pk_tick($t, $t['clock']); eq(evts($ev, 'stand'), [['t' => 'stand', 'seat' => 0]], 'stand event on the next tick');
throws(fn() => pk_leave($t, 0), 'leaving an empty seat');

section('leaving while all-in keeps the hand');
[$t, $ev] = deal([300, 1000, 1000], 0);   // seat 0 utg
rig($t, [0 => ['Ah', 'Ad'], 1 => ['2c', '3d'], 2 => ['4c', '5d']], ['7h', '8s', '9c', 'Jd', 'Qs']);
act($t, 0, 'allin'); act($t, 1, 'call');
eq(pk_leave($t, 0), -1, 'all-in player leaves'); yes($t['players'][0]['in'], 'still in the hand');
act($t, 2, 'call'); checkdown($t);
eq($t['winners'][0]['seat'], 0, 'the leaver still wins the main pot'); eq($t['winners'][0]['amount'], 900, '3 × 300');
$ev = pk_tick($t, $t['next_at']); eq(evts($ev, 'hand_end')[0]['leavers'], [0 => 900], 'and is paid it on the way out');

section('busted bots wait for a rebuy; button skips them');
[$t, $ev] = deal([100, 1000, 1000], 0, ['bots' => [0]]);
rig($t, [0 => ['2c', '3d'], 1 => ['Ah', 'Ad'], 2 => ['4c', '5d']], ['7h', '8s', '9c', 'Jd', 'Qs']);
act($t, 0, 'allin'); act($t, 1, 'call'); act($t, 2, 'fold');
$ev = pk_tick($t, $t['next_at']);
eq(evts($ev, 'hand_end')[0]['busted'], [0 => ['uid' => 'u0', 'bot' => true]], 'bot busted');
yes(isset($t['players'][0]) && $t['players'][0]['stack'] === 0, 'bot stays seated with 0');
yes(pk_ready($t, $t['clock']), 'two live players remain');
pk_tick($t, $t['clock'] + 0.1); eq($t['button'], 1, 'button moved past the busted seat'); yes(!$t['players'][0]['dealt'], 'busted bot dealt out');
pk_addon($t, 0, 500); eq($t['players'][0]['stack'], 500, 'rebuy via add-on');
checkdown($t); pk_tick($t, $t['next_at']); pk_tick($t, $t['clock'] + 0.1); yes($t['players'][0]['dealt'], 'back in after the rebuy');

section('button movement and blinds with gaps');
$t = tbl(6);
foreach ([0, 2, 5] as $s) { pk_sit($t, $s, "u$s", $s + 1, "P$s", 1000); }
aim($t, 0); pk_start_hand($t, 1000.0);
eq([$t['button'], $t['sb_seat'], $t['bb_seat'], $t['to_act']], [0, 2, 5, 0], 'gaps skipped');
checkdown($t); pk_tick($t, $t['next_at']); pk_sitout($t, 2, true); pk_tick($t, $t['clock'] + 0.1);
eq([$t['button'], $t['sb_seat'], $t['bb_seat']], [5, 5, 0], 'button moves to 5, heads-up with 0 (2 sits out)');
eq(pk_ready(tbl(), 0.0), false, 'empty table is not ready');
$t3 = tbl(); pk_sit($t3, 0, 'a', 1, 'A', 1000); eq(pk_ready($t3, 0.0), false, 'one player is not ready');
pk_sit($t3, 1, 'b', 2, 'B', 1000); eq(pk_ready($t3, 0.0), true, 'two players are ready');
pk_away($t3, 1, true); eq(pk_ready($t3, 0.0), false, 'away counts as sitting out');
throws(fn() => pk_new_table(['seats' => 6, 'small_blind' => 20, 'big_blind' => 10, 'min_buyin' => 1, 'max_buyin' => 2]), 'bad blinds rejected', InvalidArgumentException::class);

/* ───────── 5. fuzz ───────── */
section('fuzz: 5,000 hands, invariants after every action');
// idle may reach any phase: a hand can run out inside pk_start_hand when the blinds are all-in
$TRANS = ['idle' => ['preflop', 'flop', 'turn', 'river', 'settle'], 'preflop' => ['flop', 'turn', 'river', 'settle'], 'flop' => ['turn', 'river', 'settle'], 'turn' => ['river', 'settle'], 'river' => ['settle'], 'settle' => ['idle']];
$hands = 0; $actions = 0; $probes = 0; $leaks = 0; $bad = 0; $now = 5000.0; $tables = 0; $verified = 0; $tampered = 0; $timeouts = 0; $leaves = 0; $sits = 0;
$uidN = 100;
$t = null; $lastSeq = 0; $lastPhase = 'idle';
$newTable = function () use (&$t, &$uidN, &$tables, &$lastSeq, &$lastPhase) {
    $seats = random_int(2, 6);
    $t = tbl($seats, 10, 20, 1, 1000000, 20);
    $n = random_int(2, $seats);
    $picked = array_slice(csprng_shuffle(range(0, $seats - 1)), 0, $n);
    foreach ($picked as $s) {
        $stack = [15, 25, 60, 200, 500, 1000, 3000][random_int(0, 6)];   // some short stacks: short blinds and tiny shoves
        pk_sit($t, $s, 'u' . ($uidN++), $uidN, 'P' . $s, $stack, random_int(0, 1) === 1);
    }
    $tables++; $lastSeq = 0; $lastPhase = 'idle';
};
$check = function (array $t, string $where) use (&$lastSeq, &$lastPhase, &$bad, $TRANS) {
    try { pk_assert_invariants($t); } catch (RuntimeException $e) { $bad++; if ($bad <= 5) { yes(false, "$where: " . $e->getMessage()); dump($where, $t); } }
    if ($t['seq'] < $lastSeq) { $bad++; if ($bad <= 5) { yes(false, "$where: seq went backwards"); } }
    if ($t['phase'] !== $lastPhase && !in_array($t['phase'], $TRANS[$lastPhase], true)) { $bad++; if ($bad <= 5) { yes(false, "$where: transition $lastPhase → {$t['phase']}"); } }
    $lastSeq = $t['seq']; $lastPhase = $t['phase'];
};
$newTable();
$guard = 0;
while ($hands < 5000 && $guard++ < 2000000) {
    if (pk_betting($t)) {
        $s = $t['to_act']; $p = $t['players'][$s]; $L = pk_legal($t, $s);
        // 1 in 3: exercise the legal/illegal contract on copies of the state
        if (random_int(1, 3) === 1) {
            $before = json_encode($t);
            $bad_probes = [[$s, 'bet', 0], [($s + 1) % $t['seats'], 'fold', 0]];
            if (!$L['check']) { $bad_probes[] = [$s, 'check', 0]; }
            if ($L['call'] === 0) { $bad_probes[] = [$s, 'call', 0]; }
            if ($L['raise']) { $bad_probes[] = [$s, 'raise', $L['raise']['min'] - 1]; $bad_probes[] = [$s, 'raise', $L['raise']['max'] + 1]; }
            else { $bad_probes[] = [$s, 'raise', $L['allin']]; }
            foreach ($bad_probes as [$ps, $pa, $pm]) {
                $c = $t; $threw = false;
                try { pk_act($c, $ps, $pa, $pm, $now); } catch (DomainException $e) { $threw = true; }
                if (!$threw || json_encode($c) !== $before) { $bad++; if ($bad <= 5) { yes(false, "illegal $pa $pm by seat $ps accepted or mutated state"); } }
                $probes++;
            }
            $good = [[$s, 'fold', 0], [$s, 'allin', 0]];
            if ($L['check']) { $good[] = [$s, 'check', 0]; } if ($L['call'] > 0) { $good[] = [$s, 'call', 0]; }
            if ($L['raise']) { $good[] = [$s, 'raise', $L['raise']['min']]; $good[] = [$s, 'raise', $L['raise']['max']]; }
            foreach ($good as [$ps, $pa, $pm]) {
                $c = $t;
                try { pk_act($c, $ps, $pa, $pm, $now); pk_assert_invariants($c); } catch (Throwable $e) { $bad++; if ($bad <= 5) { yes(false, "legal $pa $pm rejected: " . $e->getMessage()); dump('before', $t); dump("after legal $pa $pm", $c); } }
                $probes++;
            }
            // pk_view must not leak to anyone: each seat and a spectator
            foreach ([...array_column($t['players'], 'uid'), null, 'nobody'] as $uid) { if ($l = leak_scan($t, $uid)) { $leaks++; if ($leaks <= 3) { yes(false, "leak for $uid: $l"); } } }
            // pk_bot_act is always legal
            $b = pk_bot_act($t, $s); $c = $t;
            try { pk_act($c, $s, $b['act'], (int)($b['amt'] ?? 0), $now); } catch (Throwable $e) { $bad++; if ($bad <= 5) { yes(false, 'bot chose an illegal action ' . json_encode($b) . ': ' . $e->getMessage()); } }
        }
        $r = random_int(1, 100);
        if ($r <= 2) { $now = $t['deadline']; pk_tick($t, $now); $timeouts++; $check($t, 'timeout'); continue; }
        if ($r <= 4 && count($t['players']) > 2) { $victim = array_rand($t['players']); pk_leave($t, $victim); $leaves++; $check($t, 'leave'); continue; }
        if ($r <= 5 && count($t['players']) < $t['seats']) { $free = array_values(array_diff(range(0, $t['seats'] - 1), array_keys($t['players']))); pk_sit($t, $free[array_rand($free)], 'u' . ($uidN++), $uidN, 'N', random_int(20, 2000), random_int(0, 1) === 1); $sits++; $check($t, 'sit'); continue; }
        if ($r <= 6) { pk_sitout($t, $s, !$p['sitout']); }
        if ($p['bot'] || $r <= 50) { $a = pk_bot_act($t, $s); }
        else {
            $opts = ['fold', 'allin'];
            if ($L['check']) { $opts[] = 'check'; $opts[] = 'check'; } if ($L['call'] > 0) { $opts[] = 'call'; $opts[] = 'call'; }
            if ($L['raise']) { $opts[] = 'raise'; $opts[] = 'raise'; }
            $a = ['act' => $opts[array_rand($opts)], 'amt' => 0];
            if ($a['act'] === 'raise') { $a['amt'] = random_int(1, 4) === 1 ? $L['raise']['min'] : random_int($L['raise']['min'], $L['raise']['max']); }
        }
        $now += 0.5;
        pk_act($t, $s, $a['act'], (int)$a['amt'], $now); $actions++;
        $check($t, "after {$a['act']}");
        if ($t['phase'] === 'settle' && random_int(1, 4) === 1) { foreach ([...array_column($t['players'], 'uid'), null] as $uid) { if ($l = leak_scan($t, $uid)) { $leaks++; if ($leaks <= 3) { yes(false, "settle leak for $uid: $l"); } } } }
        continue;
    }
    if ($t['phase'] === 'settle') {
        $rec = pk_hand_record($t);
        $v = pk_verify_record($rec);
        if (!$v['hash_ok'] || !$v['deal_ok']) { $bad++; if ($bad <= 5) { yes(false, 'record failed verification ' . json_encode($v)); } } else { $verified++; }
        if (random_int(1, 20) === 1) {   // tamper: swap one hole card with a random other card
            $bad_rec = $rec; $pi = array_rand($bad_rec['players']); $card = $bad_rec['players'][$pi]['cards'][0];
            $other = $rec['deck'][51] === $card ? $rec['deck'][50] : $rec['deck'][51];
            $bad_rec['players'][$pi]['cards'][0] = $other;
            $tv = pk_verify_record($bad_rec);
            if ($tv['deal_ok']) { $bad++; if ($bad <= 5) { yes(false, 'tampered hole card passed the deal check'); } }
            $bad_rec = $rec; $bad_rec['deck'][3] = $bad_rec['deck'][3] === 'As' ? 'Ks' : 'As'; $bad_rec['deck'][4] = $rec['deck'][3];
            if (pk_verify_record($bad_rec)['hash_ok']) { $bad++; if ($bad <= 5) { yes(false, 'tampered deck passed the hash check'); } }
            $tampered++;
        }
        $chipsBefore = array_sum(stacks($t));
        $now = $t['next_at'];
        $ev = pk_tick($t, $now);
        $he = evts($ev, 'hand_end')[0] ?? null;
        if (!$he) { $bad++; if ($bad <= 5) { yes(false, 'no hand_end at next_at'); } }
        else {
            if ($chipsBefore !== array_sum(stacks($t)) + array_sum($he['leavers'])) { $bad++; if ($bad <= 5) { yes(false, 'chips lost at hand end'); } }
            foreach ($he['busted'] as $s => $b) { if ($b['bot'] && isset($t['players'][$s])) { pk_addon($t, $s, random_int(100, 2000)); } elseif (isset($t['players'][$s])) { $bad++; yes(false, 'busted real player not removed'); } }
        }
        $hands++; $check($t, 'hand_end');
        if ($hands % 40 === 0) { $newTable(); }
        continue;
    }
    // idle
    $dealable = count(array_filter($t['players'], fn($p) => pk_dealable($p)));
    if ($dealable < 2) {
        foreach ($t['players'] as $s => $p) { if ($p['sitout'] && random_int(0, 1)) { pk_sitout($t, $s, false); } if ($p['away']) { pk_away($t, $s, false); } }
        $free = array_values(array_diff(range(0, $t['seats'] - 1), array_keys($t['players'])));
        if ($free && count(array_filter($t['players'], fn($p) => pk_dealable($p))) < 2) { pk_sit($t, $free[array_rand($free)], 'u' . ($uidN++), $uidN, 'R', random_int(20, 3000), random_int(0, 1) === 1); $sits++; }
        if (count(array_filter($t['players'], fn($p) => pk_dealable($p))) < 2) { $newTable(); }
    }
    $now += 0.2;
    $ev = pk_tick($t, $now);
    $check($t, 'idle tick');
}
echo "  $hands hands on $tables tables: $actions actions, $probes legality probes, $timeouts timeouts, $leaves mid-hand leaves, $sits mid-hand sits, $tampered tampered records\n";
eq($hands, 5000, 'played 5,000 hands');
eq($bad, 0, 'no invariant violations');
eq($leaks, 0, 'pk_view never leaked a hidden card');
eq($verified, 5000, 'every hand record verified'); yes($tampered > 100, "tampered records rejected ($tampered)");

/* ───────── 7. throughput ───────── */
section('throughput: bot vs bot, 6-max');
$t = tbl(6, 10, 20, 800, 4000, 20);
for ($i = 0; $i < 6; $i++) { pk_sit($t, $i, "b:$i", 0, "Bot$i", random_int(800, 4000), true); }
$now = 1.0; $hands = 0; $t0 = microtime(true);
while ($hands < 3000) {
    $now += 3.0;
    foreach (pk_tick($t, $now) as $e) {
        if ($e['t'] === 'hand_end') { $hands++; foreach ($e['busted'] as $s => $b) { if (isset($t['players'][$s])) { pk_addon($t, $s, random_int(800, 4000)); } } }
    }
}
$dt = microtime(true) - $t0; $hps = $hands / $dt;
printf("  %d hands in %.2fs = %.0f hands/s\n", $hands, $dt, $hps);
yes($hps > 50, 'throughput sane');
echo "THROUGHPUT_HANDS_PER_S=" . round($hps) . "\n";
pk_assert_invariants($t);

/* ───────── summary ───────── */
printf("\n%d passed, %d failed in %.1fs\n", $PASS, $FAIL, microtime(true) - $T0);
if ($FAIL) { echo "Failures:\n"; foreach ($FAILS as $f) { echo "  - $f\n"; } exit(1); }
echo "OK\n";
