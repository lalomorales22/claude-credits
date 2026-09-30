#!/usr/bin/env php
<?php
/**
 * tests/poker_e2e_test.php: ws.php hosting the REAL poker engine, end to end over WebSocket. Two real players sit at
 * table 1 with two house players (poker_action_seconds = 3) and play from pk_state.legal like a client would: call when
 * owed, check otherwise, fold about a fifth of the time. Along the way it checks what REALTIME.md → Persistence promises:
 *
 *   - every hand ends and hand_no climbs by one; poker_hands rows exist and pk_verify_record() passes on each;
 *   - nothing sent to B ever carries A's hole cards while A is in the hand and not shown (every pk_state / pk_events
 *     frame B received is scanned against the cards A saw in its own view);
 *   - coins are conserved for the real players after every hand: balance + seat stack moves by exactly the record's
 *     net (bots' chips are outside the ledger), and every record's nets sum to zero;
 *   - a player who stops acting is folded by the clock and sat out after two timeouts; sitting back in with pk_post
 *     gets the returning player dealt in again;
 *   - pk_leave mid-hand is paid at hand_end, exactly the record's end stack, once;
 *   - kill -9 mid-hand + restart refunds the start-of-hand stacks ('table reset' ledger rows equal to poker_seats.stack
 *     before the kill), leaves poker_seats empty and never records the void hand;
 *   - record_round counted one round per real player per hand they were dealt into.
 *
 * Runs from a scratch copy of goldtide/ (TMPDIR honoured) on a free port in 8900-8949; about 2 minutes; exit 1 on failure.
 *
 *     php goldtide/tests/poker_e2e_test.php
 */
declare(strict_types=1);
error_reporting(E_ALL);

require __DIR__ . '/ws_client.php';
$root = dirname(__DIR__);
$tmp = scratch_copy($root, 'poker_e2e');
define('GT_NO_ROUTE', 1);
require "$tmp/index.php";
ini_set('display_errors', 'stderr');
set_exception_handler(function (Throwable $e): void { fwrite(STDERR, "\nUNCAUGHT " . $e::class . ': ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine() . "\n"); exit(1); });
db();
$T0 = microtime(true);
const E2E_BUDGET = 170.0;   // seconds for the whole scripted session

$pass = 0; $fail = 0; $failures = [];
function check(bool $ok, string $name, string $detail = ''): bool {
    global $pass, $fail, $failures;
    if ($ok) { $pass++; echo "  ok   $name\n"; }
    else { $fail++; $failures[] = $name; echo "  FAIL $name" . ($detail !== '' ? "  -- $detail" : '') . "\n"; }
    return $ok;
}
function section(string $s): void { echo "\n== $s\n"; }
function short(mixed $v): string { return substr((string)json_encode($v), 0, 200); }
function note(string $s): void { global $T0; printf("       [%5.1fs] %s\n", microtime(true) - $T0, $s); }

/* ───────────────────────── fixtures ───────────────────────── */

q('UPDATE poker_tables SET bots = 2 WHERE id = 1');
q('UPDATE poker_tables SET enabled = 0 WHERE id <> 1');
q("UPDATE settings SET value = '3' WHERE key = 'poker_action_seconds'");
$mk = function (string $name, int $balance): int {
    q('INSERT INTO players (username, pass_hash, balance) VALUES (?,?,?)', [$name, password_hash('x', PASSWORD_BCRYPT, ['cost' => 4]), $balance]);
    return (int)db()->lastInsertId();
};
$A = $mk('e2e_alice', 20000);
$B = $mk('e2e_bob', 20000);
$uidA = "p$A"; $uidB = "p$B";
$balance = fn(int $pid) => (int)val('SELECT balance FROM players WHERE id = ?', [$pid]);
$seatRow = fn(int $pid) => row('SELECT * FROM poker_seats WHERE player_id = ?', [$pid]);
$stackOf = fn(int $pid) => (int)(row('SELECT stack FROM poker_seats WHERE player_id = ?', [$pid])['stack'] ?? 0);
$ticket = fn(int $pid, string $name) => rt_ticket_make(['uid' => "p$pid", 'pid' => $pid, 'name' => $name]);
$tbl = row('SELECT * FROM poker_tables WHERE id = 1');
$BB = (int)$tbl['big_blind']; $BUYIN = (int)$tbl['max_buyin'];

/* ───────────────────────── server ───────────────────────── */

section('start-up');
$port = free_port(8900, 8949);
$serverArgs = ['--tick', '20', '--away', '3', '--verbose'];
[$proc, $logPath] = start_server($tmp, $port, $serverArgs);
$h = wait_health($port);
check((bool)$h && $h['ok'] === true && count($h['tables']) === 1 && $h['tables'][0]['seated'] === 2, "ws.php up on 127.0.0.1:$port hosting table 1 with 2 house players", short($h) . ' ' . (string)file_get_contents($logPath));
if (!$h) { proc_terminate($proc); exit(1); }

/* ───────────────────────── sit down ───────────────────────── */

section('two real players sit with two house players');
$a = WsClient::open($port, 'http://localhost:8100', null, 'A');
$b = WsClient::open($port, 'http://localhost:8100', null, 'B');
$wa = $a->hello($ticket($A, 'e2e_alice'), 'poker');
$wb = $b->hello($ticket($B, 'e2e_bob'), 'poker');
check($wa !== null && $wb !== null && $wa['tables'][0]['seated'] === 2 && $wa['tables'][0]['playing'] === false, 'both connected; the table summary shows 2 seated (bots) and not playing', short([$wa['tables'] ?? null]));
// seats are taken blind (the bots sat at random seats); a refused seat is retried with the next one
$errs = 0;
$sitDown = function (WsClient $cl) use ($BUYIN, &$errs): ?int {
    for ($s = 0; $s < 6; $s++) {
        $cl->send(['t' => 'pk_join', 'table' => 1, 'seat' => $s, 'buyin' => $BUYIN]);
        $t0 = microtime(true);
        while (microtime(true) - $t0 < 3) {
            $cl->pump(0.05);
            foreach ($cl->inbox as $i => $m) {
                if ($m['t'] !== 'pk_err' && $m['t'] !== 'bal') { continue; }
                unset($cl->inbox[$i]); $cl->inbox = array_values($cl->inbox);
                if ($m['t'] === 'bal') { return $s; }
                $errs++; continue 3;   // taken: try the next seat
            }
        }
        return null;   // no answer at all
    }
    return null;
};
$seatA = $sitDown($a);   // hand 1 starts on this very tick: A and the two bots (all owe a blind, so the restart waiver deals everyone in)
$seatB = $sitDown($b);   // B therefore sits down during hand 1 and owes a big blind: it posts one to be dealt into hand 2 at once
$b->send(['t' => 'pk_post', 'on' => true]);
check($seatA !== null && $seatB !== null && $seatA !== $seatB, "A sits at seat $seatA and B at seat $seatB (after $errs refusals for taken seats)", short([$seatA, $seatB]));
check($balance($A) === 20000 - $BUYIN && $balance($B) === 20000 - $BUYIN && $stackOf($A) === $BUYIN && $stackOf($B) === $BUYIN, "buy-ins of $BUYIN moved to poker_seats rows", short([$balance($A), $balance($B), $seatRow($A), $seatRow($B)]));
$initA = 20000; $initB = 20000;   // balance + chips in play, per real player; only the records may move it from here

/* ───────────────────────── the session: a scripted client for both players ─────────────────────────
 *
 * phases:  play     both act from legal until 5 hands with both dealt in have finished
 *          timeout  A stops acting: the clock folds A, two timeouts sit A out; B leaves mid-hand meanwhile
 *          return   A lets one hand start without it (so it owes a big blind), then pk_sitout(false) + pk_post(true)
 *          kill     A is dealt in again: as soon as the hand is in a betting street, kill -9 the server
 */
$phase = 'play';
$acts = ['A' => true, 'B' => true];
$clients = ['A' => [$a, $uidA, $seatA], 'B' => [$b, $uidB, $seatB]];
$lastAct = ['A' => null, 'B' => null];
$folds = 0; $calls = 0; $checks = 0; $decisions = 0;
$hands = [];               // hand_no => ['start' => t, 'end' => t|null, 'dealt' => [uid => true], 'record' => row|null]
$curHand = 0;
$cardsA = [];              // hand_no => A's own hole cards, from A's view
$bothDone = 0;             // finished hands both A and B were dealt into
$timeoutsA = []; $sitoutA = null; $sitoutHand = null; $autoFoldSeen = false;
$bLeaveHand = null; $bLeaveSent = false; $bPaid = null; $bEndStack = null; $bLeaversEv = null;
$returnHandStart = null; $postSent = false; $postSentHand = null; $owesSeenA = false; $dealtBackHand = null; $postKind = null; $skippedHands = 0;
$killed = false; $killHand = null; $killRows = []; $killBal = []; $killPhase = null;
$conserveFails = 0; $conserveChecks = 0; $sumNetFails = 0; $hashFails = 0; $recordsChecked = 0; $netA = 0; $netB = 0; $bPaidWire = null;
$handStartsSeen = 0; $handEndsSeen = 0; $monotonic = true; $prevHandNo = 0;
$busted = [];
$deadline = $T0 + E2E_BUDGET;
$stopReason = null;

$actFrom = function (string $k, array $tbl) use (&$lastAct, &$folds, &$calls, &$checks, &$decisions, $clients, $BB): void {
    [$cl] = $clients[$k];
    $L = $tbl['legal'];
    $key = $tbl['hand_no'] . ':' . $tbl['seq'];
    if ($lastAct[$k] === $key) { return; }   // already answered this decision (a later state arrived before the action was processed)
    $lastAct[$k] = $key;
    $decisions++;
    if ((int)($L['call'] ?? 0) > 0) {
        $act = ((int)$L['call'] > 25 * $BB || mt_rand(1, 5) === 1) ? 'fold' : 'call';   // a fifth of the time, and never more than 25 big blinds at once
    } else { $act = 'check'; }
    if ($act === 'fold') { $folds++; } elseif ($act === 'call') { $calls++; } else { $checks++; }
    $cl->send(['t' => 'pk_act', 'act' => $act, 'amt' => 0, 'hand' => $tbl['hand_no'], 'seq' => $tbl['seq']]);
};

/** After hand_end: the row, its verification, record_round bookkeeping and conservation for both real players. */
$onHandEnd = function (int $handNo, array $ev) use (&$hands, &$conserveFails, &$conserveChecks, &$sumNetFails, &$hashFails, &$recordsChecked, &$busted, &$bPaid, &$bEndStack, &$bLeaversEv, &$bLeaveHand, $balance, $stackOf, $seatRow, $uidA, $uidB, $A, $B, &$initA, &$initB, &$netA, &$netB): void {
    $rowH = row('SELECT * FROM poker_hands WHERE table_id = 1 AND hand_no = ?', [$handNo]);
    $rec = $rowH ? json_decode((string)$rowH['record'], true) : null;
    $hands[$handNo]['record'] = $rec;
    if (!is_array($rec)) { $hashFails++; note("hand #$handNo: no poker_hands row at hand_end"); return; }
    $recordsChecked++;
    $v = pk_verify_record($rec);
    if ($v !== ['hash_ok' => true, 'deal_ok' => true]) { $hashFails++; note("hand #$handNo: pk_verify_record " . json_encode($v)); }
    $sum = 0; $net = [$uidA => 0, $uidB => 0]; $dealt = [];
    foreach ($rec['players'] as $p) { $sum += (int)$p['net']; $dealt[$p['uid']] = true; if (isset($net[$p['uid']])) { $net[$p['uid']] = (int)$p['net']; } if (!$p['bot'] && (int)$p['end_stack'] === 0) { $busted[] = $p['uid']; } }
    if ($sum !== 0) { $sumNetFails++; note("hand #$handNo: nets sum to $sum"); }
    $hands[$handNo]['dealt'] = $dealt;
    $netA += $net[$uidA]; $netB += $net[$uidB];
    foreach ([[$A, $initA + $netA, 'A'], [$B, $initB + $netB, 'B']] as [$pid, $expect, $k]) {
        $conserveChecks++;
        $have = $balance($pid) + $stackOf($pid);
        if ($have !== $expect) { $conserveFails++; note("hand #$handNo: $k has balance+stack $have, expected $expect"); }
    }
    if ($bLeaveHand === $handNo) {
        foreach ($rec['players'] as $p) { if ($p['uid'] === $uidB) { $bEndStack = (int)$p['end_stack']; } }
        $bLeaversEv = $ev['leavers'] ?? null;
        $bPaid = row("SELECT * FROM ledger WHERE player_id = ? AND kind = 'payout' ORDER BY id DESC LIMIT 1", [$B]);
    }
};
$t0Hands = microtime(true);
while (microtime(true) < $deadline && $stopReason === null) {
    foreach ($clients as $k => [$cl, $uid, $seat]) {
        $cl->pump(0.02);
        if ($cl->eof && $k === 'A' && !$killed) { $stopReason = 'A lost its connection'; break; }
        foreach ($cl->inbox as $i => $m) {
            unset($cl->inbox[$i]);
            if ($m['t'] === 'pk_events') {
                foreach ($m['events'] as $e) {
                    if ($k !== 'A') { continue; }   // A's stream is the timeline; B's frames are scanned afterwards
                    switch ($e['t']) {
                        case 'hand_start':
                            $handStartsSeen++;
                            $curHand = (int)$e['hand'];
                            if ($curHand !== $prevHandNo + 1 && $prevHandNo !== 0) { $monotonic = false; }
                            $prevHandNo = $curHand;
                            $hands[$curHand] = ['start' => microtime(true), 'end' => null, 'dealt' => [], 'record' => null];
                            if ($phase === 'return' && $returnHandStart === null) { $returnHandStart = $curHand; }
                            break;
                        case 'post':
                            if ($phase === 'return' && (int)$e['seat'] === $seatA && $postSent) { $postKind = $e['kind']; }
                            break;
                        case 'timeout':
                            if ((int)$e['seat'] === $seatA) { $timeoutsA[] = $curHand; }
                            break;
                        case 'sitout':
                            if ((int)$e['seat'] === $seatA && !empty($e['on']) && $phase === 'timeout') { $sitoutA = true; $sitoutHand = $curHand; }
                            break;
                        case 'hand_end':
                            $handEndsSeen++;
                            if (isset($hands[$curHand])) { $hands[$curHand]['end'] = microtime(true); }
                            $onHandEnd($curHand, $e);
                            $d = $hands[$curHand]['dealt'] ?? [];
                            if (isset($d[$uidA], $d[$uidB])) { $bothDone++; }
                            if ($phase === 'play' && $bothDone >= 5) { $phase = 'timeout'; $acts['A'] = false; note("hand #$curHand done: $bothDone hands with both dealt in; A goes silent, B will leave mid-hand"); }
                            elseif ($phase === 'timeout' && $sitoutA && $bLeaveSent) { $phase = 'return'; note("hand #$curHand done: A is sitting out; waiting for one hand to start without A"); }
                            break;
                    }
                }
                continue;
            }
            if ($m['t'] === 'bal' && $k === 'B' && $bLeaveSent) { $bPaidWire = $m['balance']; }
            if ($m['t'] !== 'pk_state') { continue; }
            $tbl = $m['table'];
            $me = $tbl['me'];
            $mine = $me !== null ? ($tbl['players'][$me] ?? null) : null;
            if ($k === 'A' && $mine && is_array($mine['cards']) && count($mine['cards']) === 2) { $cardsA[(int)$tbl['hand_no']] = $mine['cards']; }
            $betting = in_array($tbl['phase'], ['preflop', 'flop', 'turn', 'river'], true);
            // phase logic
            if ($k === 'B' && $phase === 'timeout' && !$bLeaveSent && $betting && $mine && !empty($mine['in'])) {
                $bLeaveSent = true; $bLeaveHand = (int)$tbl['hand_no'];
                $b->send(['t' => 'pk_leave']);
                note("hand #$bLeaveHand: B asks to leave mid-hand (in the hand, phase {$tbl['phase']})");
            }
            if ($k === 'A' && $phase === 'return') {
                if ($mine && !empty($mine['owes'])) { $owesSeenA = true; }
                if ($returnHandStart !== null && !$postSent && (int)$tbl['hand_no'] === $returnHandStart && $mine && empty($mine['in'])) {
                    $postSent = true; $postSentHand = $returnHandStart;
                    $a->send(['t' => 'pk_sitout', 'on' => false]);
                    $a->send(['t' => 'pk_post', 'on' => true]);
                    note("hand #$returnHandStart runs without A (owes: " . json_encode($mine['owes']) . "); A sits back in and asks to post");
                }
                if ($postSent && (int)$tbl['hand_no'] > $postSentHand && $mine && !empty($mine['in']) && $dealtBackHand === null) {
                    $dealtBackHand = (int)$tbl['hand_no']; $skippedHands = $dealtBackHand - $postSentHand - 1;
                    $acts['A'] = true; $phase = 'kill';
                    note("hand #$dealtBackHand: A is dealt in again (" . ($postKind === 'post' ? 'posted a live big blind' : 'as the big blind') . ", $skippedHands hand(s) skipped)");
                }
            }
            if ($k === 'A' && $phase === 'kill' && !$killed && $betting && $mine && (int)$mine['total'] > 0 && (int)$tbl['hand_no'] >= $dealtBackHand) {   // A has chips in this hand
                $killHand = (int)$tbl['hand_no']; $killPhase = $tbl['phase'];
                foreach ([$A, $B] as $pid) { $r = $seatRow($pid); if ($r) { $killRows[$pid] = (int)$r['stack']; } $killBal[$pid] = $balance($pid); }
                proc_terminate($proc, SIGKILL);
                $killed = true;
                note("hand #$killHand ({$tbl['phase']}): kill -9 with poker_seats " . json_encode($killRows));
                $stopReason = 'killed';
                break 2;
            }
            if ($acts[$k] && $betting && !empty($tbl['legal'])) { $actFrom($k, $tbl); }
        }
        $cl->inbox = array_values($cl->inbox);
    }
}
$elapsed = microtime(true) - $t0Hands;
if ($stopReason !== 'killed') { note('session stopped: ' . ($stopReason ?? 'time budget exhausted') . " in phase $phase after " . count($hands) . ' hands'); }

/* ───────────────────────── what the session proved ───────────────────────── */

section('hands');
$finished = array_filter($hands, fn($h) => $h['end'] !== null);
$durs = array_map(fn($h) => round($h['end'] - $h['start'], 1), $finished);
check(count($finished) >= 5 && $handEndsSeen >= 5, count($finished) . ' hands finished in ' . round($elapsed) . ' s (' . implode(', ', $durs) . ' s each), ' . $decisions . " client decisions: $calls calls, $checks checks, $folds folds", short([$handStartsSeen, $handEndsSeen]));
check($monotonic && $handStartsSeen === $handEndsSeen + ($killed ? 1 : 0), 'hand_no climbed by one each time and every started hand ended (but the one killed)', short([$handStartsSeen, $handEndsSeen, $killed]));
check($bothDone >= 5, "$bothDone finished hands had both real players dealt in", short(array_map(fn($h) => array_keys($h['dealt']), $finished)));
check($recordsChecked === count($finished) && $hashFails === 0, "poker_hands has a row for each of the $recordsChecked finished hands and pk_verify_record() passes on every record", "records $recordsChecked, failures $hashFails");
$maxHand = (int)val('SELECT MAX(hand_no) FROM poker_hands WHERE table_id = 1');
check($killed && $maxHand === $killHand - 1, 'the killed hand was never recorded (void), the one before it was', short([$maxHand, $killHand]));
check($busted === [], 'no real player busted during the session (calls capped at 25 big blinds)', short($busted));

section('privacy: what B received');
$leaks = 0; $scanned = 0; $handB = 0; $shownA = false;
$strip = function (array $m): string { if (is_array($m['table'] ?? null)) { unset($m['table']['log']); } return (string)json_encode($m, JSON_UNESCAPED_SLASHES); };   // the log spans hands: earlier shown cards are public
$hasCard = function (string $json, array $cards): bool { foreach ($cards as $c) { if (str_contains($json, '"' . $c . '"')) { return true; } } return false; };
foreach ($b->seen as $m) {
    if ($m['t'] === 'pk_events') {
        $ended = false;
        foreach ($m['events'] as $e) {
            if ($e['t'] === 'hand_start') { $handB = (int)$e['hand']; $shownA = false; }
            if ($e['t'] === 'showdown' && (isset($e['shows'][$seatA]) || isset($e['shows'][(string)$seatA]))) { $shownA = true; }
            if ($e['t'] === 'hand_end') { $ended = true; }
        }
        if ($handB && !$shownA && !$ended && isset($cardsA[$handB])) { $scanned++; if ($hasCard($strip($m), $cardsA[$handB])) { $leaks++; } }
        continue;
    }
    if ($m['t'] !== 'pk_state') { continue; }
    $tbl = $m['table'];
    $hn = (int)$tbl['hand_no'];
    if ($tbl['phase'] === 'idle' || !isset($cardsA[$hn])) { continue; }
    $pa = $tbl['players'][$seatA] ?? null;
    if ($pa && !empty($pa['show'])) { $shownA = true; }
    if ($shownA) { continue; }
    $scanned++;
    if ($pa && is_array($pa['cards'])) { $leaks++; }
    foreach ($tbl['winners'] as $w) { if ((int)$w['seat'] === $seatA && !empty($w['cards'])) { $leaks++; } }
    if ($hasCard($strip($m), $cardsA[$hn])) { $leaks++; }
}
check(count($cardsA) >= 5, 'A saw its own hole cards in ' . count($cardsA) . ' hands');
check($scanned > 50 && $leaks === 0, "none of the $scanned pk_state / pk_events frames B received while A was in a hand and not shown carried A's hole cards (players[], winners[], events, any string)", "leaks $leaks");

section('money: conservation after every hand');
check($conserveChecks >= 10 && $conserveFails === 0, "after each of the " . intdiv($conserveChecks, 2) . " hands, balance + seat stack of A and of B moved by exactly the record's net", "checks $conserveChecks, failures $conserveFails");
check($sumNetFails === 0, 'every record\'s nets (bots included) sum to zero', "failures $sumNetFails");

section('clock: a silent player');
check(count($timeoutsA) >= 2 && $sitoutA === true, 'A was timed out ' . count($timeoutsA) . ' times (hands ' . implode(',', $timeoutsA) . ") and sat out by the engine after the second (hand $sitoutHand)", short([$timeoutsA, $sitoutA]));
$autoActs = 0;
foreach ($hands as $hn => $hh) {
    foreach ($hh['record']['actions'] ?? [] as $act) { if ((int)$act['seat'] === $seatA && !empty($act['auto']) && in_array($act['act'], ['fold', 'check'], true)) { $autoActs++; } }
}
check($autoActs >= 2, "the records show $autoActs automatic (clock) actions for A's seat", (string)$autoActs);
$stA = null;
foreach (array_reverse($a->seen) as $m) { if ($m['t'] === 'pk_state' && $sitoutHand && (int)$m['table']['hand_no'] === $sitoutHand) { $stA = $m['table']['players'][$seatA] ?? null; break; } }
check($stA !== null && !empty($stA['sitout']), 'pk_state showed A sitting out', short($stA));

section('pk_leave mid-hand');
check($bLeaveSent && $bEndStack !== null, "B left during hand #$bLeaveHand and the record lists B's end stack $bEndStack", short([$bLeaveHand, $bEndStack]));
$lv = is_array($bLeaversEv) ? $bLeaversEv : [];
check(isset($lv[$seatB]) && (int)$lv[$seatB] === $bEndStack, 'hand_end.leavers[seat B] equals that end stack', short($bLeaversEv));
check($bPaid && str_starts_with($bPaid['detail'], 'cash-out') && (int)$bPaid['amount'] === $bEndStack && $bPaid['game'] === 'poker', 'B was paid exactly the end stack as one poker payout in that hand\'s tx', short($bPaid));
check((int)val("SELECT COUNT(*) FROM ledger WHERE player_id = ? AND kind = 'payout'", [$B]) === 1 && !$seatRow($B), 'it is the only payout B ever received and B\'s seat row is gone (paid once)', short([$seatRow($B)]));
check($bPaidWire !== null && $bPaidWire === $balance($B), 'B got bal on the wire with the new balance', short([$bPaidWire, $balance($B)]));

section('pk_post: sitting back in');
check($returnHandStart !== null && $owesSeenA && $postSent, "hand #$returnHandStart started without A; A owed a big blind (owes:true in its view) and sent pk_sitout(false) + pk_post(true)", short([$returnHandStart, $owesSeenA, $postSent]));
check($dealtBackHand !== null && $skippedHands <= 1, "A was dealt in again at hand #$dealtBackHand (" . ($postKind === 'post' ? 'posted a live big blind, kind "post"' : 'the big blind came round to it') . ", skipped $skippedHands; the only legal skip is the stretch between the button and the small blind)", short([$dealtBackHand, $postKind, $skippedHands]));

section('kill -9 mid-hand, restart');
check($killed && isset($killRows[$A]) && !isset($killRows[$B]), "the server was killed during hand #$killHand ($killPhase) with A's start-of-hand stack " . ($killRows[$A] ?? '?') . ' in poker_seats and B already gone', short($killRows));
if (!$killed) { proc_terminate($proc, SIGKILL); }
$killRows[$A] ??= -1; $killBal[$A] ??= -1;
$st = wait_exit($proc, 5);
check(!$st['running'], 'the old process is gone', short($st));
proc_close($proc);
$stackLive = null;
foreach (array_reverse($a->seen) as $m) { if ($m['t'] === 'pk_state' && (int)$m['table']['hand_no'] === $killHand) { $stackLive = (int)$m['table']['players'][$seatA]['stack']; break; } }
[$proc2, $logPath2] = start_server($tmp, $port, $serverArgs, [], 'server2.log');
$h2 = wait_health($port);
check((bool)$h2 && $h2['ok'] === true, 'a new ws.php starts on the same port (the dead one\'s lock is released)', (string)file_get_contents($logPath2));
$reset = row("SELECT * FROM ledger WHERE player_id = ? AND kind = 'payout' AND detail LIKE 'table reset%' ORDER BY id DESC LIMIT 1", [$A]);
check($reset && (int)$reset['amount'] === $killRows[$A], "start-up refunded A's poker_seats stack ({$killRows[$A]}) as a 'table reset' payout", short($reset));
check($stackLive !== null && $stackLive < $killRows[$A], "that is the start-of-hand stack, not the live one ($stackLive after the blinds / bets of the void hand)", short([$stackLive, $killRows[$A]]));
check($balance($A) === $killBal[$A] + $killRows[$A], 'A\'s balance = balance before the kill + the refunded stack', short([$balance($A), $killBal[$A], $killRows[$A]]));
check(!row('SELECT 1 FROM poker_seats'), 'poker_seats is empty after the restart');
check((int)val("SELECT COUNT(*) FROM ledger WHERE player_id = ? AND kind = 'payout'", [$A]) === 1, 'the refund is the only payout A ever received (no cash-out doubled it)');

section('ledger totals');
$sumA = 0; $sumB = 0;
foreach (q('SELECT record FROM poker_hands WHERE table_id = 1')->fetchAll() as $r) {
    foreach (json_decode((string)$r['record'], true)['players'] ?? [] as $p) { if ($p['uid'] === $uidA) { $sumA += (int)$p['net']; } if ($p['uid'] === $uidB) { $sumB += (int)$p['net']; } }
}
check($balance($A) === 20000 + $sumA && $balance($B) === 20000 + $sumB, "final balances equal 20000 + the sum of the recorded nets (A $sumA, B $sumB): every path paid exactly once", short([$balance($A), $balance($B)]));
$dealtA = 0; $dealtB = 0;
foreach (q('SELECT record FROM poker_hands WHERE table_id = 1')->fetchAll() as $r) {
    foreach (json_decode((string)$r['record'], true)['players'] ?? [] as $p) { if ($p['uid'] === $uidA) { $dealtA++; } if ($p['uid'] === $uidB) { $dealtB++; } }
}
$rp = fn(int $pid) => (int)val('SELECT rounds_played FROM players WHERE id = ?', [$pid]);
check($rp($A) === $dealtA && $rp($B) === $dealtB && $dealtA >= 5, "record_round counted one round per hand dealt in: A $dealtA, B $dealtB", short([$rp($A), $rp($B)]));
$wagerA = (int)val('SELECT total_wagered FROM players WHERE id = ?', [$A]);
check($wagerA > 0, "total_wagered climbed for A ($wagerA)", (string)$wagerA);

section('shutdown');
proc_terminate($proc2, SIGTERM);
$st = wait_exit($proc2, 5);
check(!$st['running'] && $st['exitcode'] === 0, 'the second server exits 0 on SIGTERM', short($st));
proc_close($proc2);
check(str_contains((string)file_get_contents($logPath2), 'bye') && !row('SELECT 1 FROM poker_seats'), 'and leaves poker_seats empty');

$total = round(microtime(true) - $T0, 1);
if ($fail) { echo "\nserver logs kept at $logPath and $logPath2\n"; } else { rm_tree($tmp); }
echo "\n$pass passed, $fail failed in {$total}s" . ($fail ? ":\n  - " . implode("\n  - ", $failures) : '') . "\n";
exit($fail ? 1 : 0);
