<?php
/**
 * tests/pk_stub.php: a tiny FAKE poker engine with the real engine's signatures (REALTIME.md → Poker engine API).
 * Only tests/ws_test.php uses it. ws.php loads it when GT_PK_STUB=1 is set AND no real pk_* functions exist, and
 * logs a loud warning when it does. The rules are deliberately trivial so the file stays small: blinds, two hole
 * cards, ONE betting round, then the board is run out and the highest hole card takes the whole pot. No side pots,
 * no hand ranking. What matters is that every event and state shape matches the contract, so ws.php's plumbing
 * (buy-ins, views per viewer, hand_end persistence, leavers, busted players, timeouts) can be exercised end to end.
 */
declare(strict_types=1);

const PKS_RANKS = ['2', '3', '4', '5', '6', '7', '8', '9', 'T', 'J', 'Q', 'K', 'A'];
const PKS_BETTING = ['preflop', 'flop', 'turn', 'river'];

function pk_new_table(array $row): array {
    return ['id' => (int)$row['id'], 'name' => (string)$row['name'], 'seats' => (int)$row['seats'], 'sb' => (int)$row['small_blind'], 'bb' => (int)$row['big_blind'],
        'min_buy' => (int)$row['min_buyin'], 'max_buy' => (int)$row['max_buyin'], 'act_secs' => isetting('poker_action_seconds', 20),
        'hand_no' => 0, 'phase' => 'idle', 'button' => null, 'players' => [], 'deck' => [], 'deck_salt' => '', 'deck_hash' => '',
        'board' => [], 'pot' => 0, 'pots' => [], 'to_act' => null, 'deadline' => null, 'cur_bet' => 0, 'min_raise' => (int)$row['big_blind'], 'last_aggressor' => null,
        'seq' => 0, 'actions' => [], 'winners' => [], 'started_at' => null, 'next_at' => null, 'bot_at' => null, 'log' => [],
        '_q' => [], '_last' => null, '_dealt' => 0];
}

function pks_player(string $uid, int $pid, string $name, int $stack, bool $bot): array {
    return ['uid' => $uid, 'pid' => $pid, 'name' => $name, 'bot' => $bot, 'stack' => $stack, 'bet' => 0, 'total' => 0, 'cards' => [], 'in' => false, 'allin' => false,
        'sitout' => false, 'acted' => false, 'timeouts' => 0, 'show' => false, 'last' => null, 'leaving' => false, 'away' => false, '_start' => $stack];
}

function pks_log(array &$t, string $line): void { $t['log'][] = $line; $t['log'] = array_slice($t['log'], -30); }

function pk_sit(array &$t, int $seat, string $uid, int $pid, string $name, int $stack, bool $bot = false): void {
    if ($seat < 0 || $seat >= $t['seats']) { throw new DomainException('No such seat.'); }
    if (isset($t['players'][$seat])) { throw new DomainException('That seat is taken.'); }
    foreach ($t['players'] as $p) { if ($p['uid'] === $uid) { throw new DomainException('Already seated here.'); } }
    if ($stack < $t['min_buy'] || $stack > $t['max_buy']) { throw new DomainException('Stack outside the buy-in range.'); }
    $t['players'][$seat] = pks_player($uid, $pid, $name, $stack, $bot);
    ksort($t['players']);
    $t['_q'][] = ['t' => 'sit', 'seat' => $seat];
    pks_log($t, "$name sits down with $stack");
}

function pk_addon(array &$t, int $seat, int $amount): void {
    $p = $t['players'][$seat] ?? throw new DomainException('Empty seat.');
    if ($p['in'] && $t['phase'] !== 'idle') { throw new DomainException('Add on between hands.'); }
    if ($amount <= 0 || $p['stack'] + $amount > $t['max_buy']) { throw new DomainException('Add-on over the table maximum.'); }
    $t['players'][$seat]['stack'] += $amount;
    $t['players'][$seat]['_start'] = $t['players'][$seat]['stack'];
    pks_log($t, "{$p['name']} adds on $amount");
}

function pk_leave(array &$t, int $seat): int {
    $p = $t['players'][$seat] ?? throw new DomainException('Empty seat.');
    if (!$p['in'] || !in_array($t['phase'], PKS_BETTING, true)) {   // not in a live hand: gone at once, stack returned
        unset($t['players'][$seat]);
        $t['_q'][] = ['t' => 'stand', 'seat' => $seat];
        pks_log($t, "{$p['name']} leaves");
        return $p['stack'];
    }
    $t['players'][$seat]['in'] = false;      // folded
    $t['players'][$seat]['leaving'] = true;  // removed by pk_tick at hand end, stack in the hand_end 'leavers'
    if ($t['to_act'] === $seat) { $t['_q'] = array_merge($t['_q'], pks_advance($t, microtime(true))); }
    return -1;
}

function pk_sitout(array &$t, int $seat, bool $on): void {
    if (!isset($t['players'][$seat])) { throw new DomainException('Empty seat.'); }
    $t['players'][$seat]['sitout'] = $on;
    $t['_q'][] = ['t' => 'sitout', 'seat' => $seat, 'on' => $on];
}

function pks_ready_seats(array $t): array {
    $r = [];
    foreach ($t['players'] as $s => $p) { if ($p['stack'] > 0 && !$p['sitout'] && !$p['leaving']) { $r[] = $s; } }
    return $r;
}

function pk_ready(array $t, float $now): bool {
    return $t['phase'] === 'idle' && ($t['next_at'] === null || $now >= $t['next_at']) && count(pks_ready_seats($t)) >= 2;
}

/** The ready seat after $seat, wrapping. */
function pks_after(array $seats, int $seat): int {
    foreach ($seats as $s) { if ($s > $seat) { return $s; } }
    return $seats[0];
}

function pk_start_hand(array &$t, float $now): array {
    $ready = pks_ready_seats($t);
    $btn = $t['button'] === null ? $ready[random_int(0, count($ready) - 1)] : pks_after($ready, $t['button']);
    $t['hand_no']++;
    $t['phase'] = 'preflop'; $t['button'] = $btn;
    $t['board'] = []; $t['pot'] = 0; $t['pots'] = []; $t['actions'] = []; $t['winners'] = []; $t['started_at'] = $now; $t['last_aggressor'] = null;
    foreach ($t['players'] as $s => &$p) {
        $p = array_merge($p, ['bet' => 0, 'total' => 0, 'cards' => [], 'in' => in_array($s, $ready, true), 'allin' => false, 'acted' => false, 'show' => false, 'last' => null]);
        $p['_start'] = $p['stack'];
    }
    unset($p);
    $order = [];   // seats in the hand starting left of the button
    for ($s = pks_after($ready, $btn), $i = 0; $i < count($ready); $s = pks_after($ready, $s), $i++) { $order[] = $s; }
    $n = count($ready);
    [$sb, $bb] = $n === 2 ? [$btn, pks_after($ready, $btn)] : [$order[0], $order[1]];
    $ev = [['t' => 'hand_start', 'hand' => $t['hand_no'], 'button' => $btn, 'deck_hash' => '']];
    foreach ([[$sb, $t['sb'], 'sb'], [$bb, $t['bb'], 'bb']] as [$seat, $amt, $kind]) {
        $post = min($t['players'][$seat]['stack'], $amt);
        $t['players'][$seat]['stack'] -= $post; $t['players'][$seat]['bet'] = $post; $t['players'][$seat]['total'] = $post;
        $t['players'][$seat]['allin'] = $t['players'][$seat]['stack'] === 0;
        $ev[] = ['t' => 'post', 'seat' => $seat, 'amt' => $post, 'kind' => $kind];
    }
    $deck = [];
    foreach (PKS_RANKS as $r) { foreach (['s', 'h', 'd', 'c'] as $su) { $deck[] = $r . $su; } }
    $t['deck'] = csprng_shuffle($deck);
    $t['deck_salt'] = bin2hex(random_bytes(16));
    $t['deck_hash'] = hash('sha256', implode(' ', $t['deck']) . '|' . $t['deck_salt']);
    $ev[0]['deck_hash'] = $t['deck_hash'];
    $i = 0;
    for ($round = 0; $round < 2; $round++) { foreach ($order as $s) { $t['players'][$s]['cards'][] = $t['deck'][$i++]; } }
    $t['_dealt'] = $i;
    $ev[] = ['t' => 'deal'];
    $t['cur_bet'] = $t['bb']; $t['min_raise'] = $t['bb']; $t['seq'] = $t['seq'];
    $t['to_act'] = $n === 2 ? $btn : $order[2];
    $t['deadline'] = $now + $t['act_secs'];
    $t['bot_at'] = $t['players'][$t['to_act']]['bot'] ? $now + 0.2 : null;
    pks_log($t, "Hand #{$t['hand_no']}: blinds posted, cards dealt");
    return $ev;
}

function pk_legal(array $t, int $seat): ?array {
    if ($t['to_act'] !== $seat || !in_array($t['phase'], PKS_BETTING, true) || !isset($t['players'][$seat])) { return null; }
    $p = $t['players'][$seat];
    $call = max(0, min($p['stack'], $t['cur_bet'] - $p['bet']));
    $allin = $p['bet'] + $p['stack'];
    $minTo = $t['cur_bet'] + $t['min_raise'];
    return ['fold' => true, 'check' => $call === 0, 'call' => $call, 'raise' => ($p['stack'] > $call && $allin >= $minTo) ? ['min' => $minTo, 'max' => $allin] : null, 'allin' => $allin];
}

function pks_next_seat(array $t, int $from): ?int {
    $seats = array_keys($t['players']);
    $n = count($seats);
    $start = array_search($from, $seats, true);
    if ($start === false) { $start = -1; }
    for ($k = 1; $k <= $n; $k++) {
        $s = $seats[($start + $k) % $n];
        $p = $t['players'][$s];
        if ($p['in'] && !$p['allin'] && (!$p['acted'] || $p['bet'] < $t['cur_bet'])) { return $s; }
    }
    return null;
}

function pks_live(array $t): array { return array_keys(array_filter($t['players'], fn($p) => $p['in'])); }

function pks_advance(array &$t, float $now): array {
    if (count(pks_live($t)) <= 1) { return pks_showdown($t, $now, false); }
    $next = pks_next_seat($t, (int)$t['to_act']);
    if ($next !== null) {
        $t['to_act'] = $next; $t['deadline'] = $now + $t['act_secs'];
        $t['bot_at'] = $t['players'][$next]['bot'] ? $now + 0.2 : null;
        return [];
    }
    return pks_showdown($t, $now, true);
}

/** One betting round is the whole hand: collect bets, run the board out, highest hole card wins everything. */
function pks_showdown(array &$t, float $now, bool $show): array {
    $ev = [];
    foreach ($t['players'] as &$p) { $t['pot'] += $p['bet']; $p['bet'] = 0; }
    unset($p);
    $live = pks_live($t);
    if ($show) {
        foreach (['flop' => 3, 'turn' => 1, 'river' => 1] as $phase => $n) {
            $t['_dealt']++;   // burn
            $cards = array_slice($t['deck'], $t['_dealt'], $n);
            $t['_dealt'] += $n;
            $t['board'] = array_merge($t['board'], $cards);
            $t['phase'] = $phase;
            $ev[] = ['t' => 'street', 'phase' => $phase, 'cards' => $cards];
        }
        $shows = [];
        foreach ($live as $s) { $t['players'][$s]['show'] = true; $shows[$s] = $t['players'][$s]['cards']; }
        $t['phase'] = 'showdown';
        $ev[] = ['t' => 'showdown', 'shows' => $shows];
    }
    $best = null; $w = $live[0];
    foreach ($live as $s) {
        $score = max(array_map('card_rank', $t['players'][$s]['cards']));
        if ($best === null || $score > $best) { $best = $score; $w = $s; }
    }
    $name = 'High Card ' . PKS_RANKS[$best - 2];
    $t['players'][$w]['stack'] += $t['pot'];
    $t['pots'] = [['amount' => $t['pot'], 'eligible' => $live, 'winners' => [$w]]];
    $t['winners'] = [['seat' => $w, 'amount' => $t['pot'], 'hand' => $name, 'cards' => $t['players'][$w]['cards']]];
    $ev[] = ['t' => 'win', 'seat' => $w, 'amount' => $t['pot'], 'hand' => $name, 'pot' => 0];
    $t['phase'] = 'settle'; $t['next_at'] = $now + 1.0; $t['to_act'] = null; $t['deadline'] = null; $t['bot_at'] = null;
    pks_log($t, "{$t['players'][$w]['name']} wins {$t['pot']} with $name");
    return $ev;
}

function pk_act(array &$t, int $seat, string $act, int $amt, float $now): array {
    $L = pk_legal($t, $seat) ?? throw new DomainException('Not your turn.');
    $p = &$t['players'][$seat];
    switch ($act) {
        case 'fold': $p['in'] = false; $amount = 0; break;
        case 'check': if (!$L['check']) { throw new DomainException('You cannot check here.'); } $amount = 0; break;
        case 'call': if ($L['call'] <= 0) { throw new DomainException('Nothing to call.'); } $amount = $L['call']; break;
        case 'raise': if (!$L['raise'] || $amt < $L['raise']['min'] || $amt > $L['raise']['max']) { throw new DomainException('Illegal raise size.'); } $amount = $amt - $p['bet']; break;
        case 'allin': $amount = $p['stack']; break;
        default: throw new DomainException('Unknown action.');
    }
    if ($amount > 0) {
        $p['stack'] -= $amount; $p['bet'] += $amount; $p['total'] += $amount;
        if ($p['stack'] === 0) { $p['allin'] = true; }
    }
    if ($p['bet'] > $t['cur_bet']) {
        $t['min_raise'] = max($t['min_raise'], $p['bet'] - $t['cur_bet']); $t['cur_bet'] = $p['bet']; $t['last_aggressor'] = $seat;
        foreach ($t['players'] as $s => &$o) { if ($s !== $seat) { $o['acted'] = false; } }
        unset($o);
    }
    $p['acted'] = true; $p['last'] = $act;
    $bet = $p['bet'];
    unset($p);
    $t['seq']++;
    $t['actions'][] = ['street' => $t['phase'], 'seat' => $seat, 'act' => $act, 'amt' => $bet, 'at' => $now];
    pks_log($t, "{$t['players'][$seat]['name']} {$act}s" . ($amount ? " ($bet)" : ''));
    return array_merge([['t' => 'action', 'seat' => $seat, 'act' => $act, 'amt' => $bet, 'seq' => $t['seq']]], pks_advance($t, $now));
}

function pk_bot_act(array $t, int $seat): array {
    $L = pk_legal($t, $seat) ?? ['check' => true];
    return $L['check'] ? ['act' => 'check', 'amt' => 0] : ['act' => 'call', 'amt' => 0];
}

function pk_eval7(array $cards): array {
    usort($cards, fn($a, $b) => card_rank($b) <=> card_rank($a));
    return ['rank' => 0, 'score' => card_rank($cards[0]), 'name' => 'High Card ' . PKS_RANKS[card_rank($cards[0]) - 2], 'best' => array_slice($cards, 0, 5)];
}

function pks_record(array $t, float $now): array {
    $players = [];
    foreach ($t['players'] as $s => $p) {
        if (!$p['cards']) { continue; }
        $players[] = ['seat' => $s, 'uid' => $p['uid'], 'name' => $p['name'], 'bot' => $p['bot'], 'start_stack' => $p['_start'], 'end_stack' => $p['stack'], 'cards' => $p['cards'], 'result' => $p['stack'] - $p['_start']];
    }
    return ['hand_no' => $t['hand_no'], 'deck_hash' => $t['deck_hash'], 'deck_salt' => $t['deck_salt'], 'deck' => $t['deck'], 'board' => $t['board'], 'players' => $players,
        'actions' => $t['actions'], 'pots' => $t['pots'], 'winners' => $t['winners'], 'started_at' => $t['started_at'], 'ended_at' => $now];
}

function pk_hand_record(array $t): array {
    return $t['phase'] === 'idle' && $t['_last'] ? $t['_last'] : pks_record($t, microtime(true));
}

/** settle → idle: leavers and busted humans go, busted bots stay at 0 for ws.php to rebuy, hand fields reset. */
function pks_hand_end(array &$t, float $now): array {
    $t['_last'] = pks_record($t, $now);
    $leavers = []; $busted = [];
    foreach ($t['players'] as $seat => $p) {
        if ($p['leaving']) { $leavers[$seat] = $p['stack']; unset($t['players'][$seat]); continue; }
        if ($p['stack'] <= 0) { $busted[] = $seat; if (!$p['bot']) { unset($t['players'][$seat]); continue; } }
        // cards and show flags stay as they were until the next deal, so shown cards remain shown and mucked ones hidden
        $t['players'][$seat] = array_merge($p, ['bet' => 0, 'total' => 0, 'in' => false, 'allin' => false, 'acted' => false, 'last' => null]);
    }
    $t['phase'] = 'idle'; $t['next_at'] = $now + 1.0; $t['to_act'] = null; $t['deadline'] = null; $t['pot'] = 0;
    return [['t' => 'hand_end', 'deck_salt' => $t['deck_salt'], 'deck' => $t['deck'], 'leavers' => $leavers, 'busted' => $busted]];
}

function pk_tick(array &$t, float $now): array {
    $ev = $t['_q']; $t['_q'] = [];
    if (in_array($t['phase'], PKS_BETTING, true) && $t['to_act'] !== null) {
        $seat = $t['to_act'];
        if (!isset($t['players'][$seat])) { $ev = array_merge($ev, pks_advance($t, $now)); }
        elseif ($now >= $t['deadline']) {
            $L = pk_legal($t, $seat);
            $ev[] = ['t' => 'timeout', 'seat' => $seat];
            if (++$t['players'][$seat]['timeouts'] >= 2) { $t['players'][$seat]['sitout'] = true; $ev[] = ['t' => 'sitout', 'seat' => $seat, 'on' => true]; }
            $ev = array_merge($ev, pk_act($t, $seat, $L['check'] ? 'check' : 'fold', 0, $now));
        } elseif ($t['players'][$seat]['bot'] && $t['bot_at'] !== null && $now >= $t['bot_at']) {
            $a = pk_bot_act($t, $seat);
            $ev = array_merge($ev, pk_act($t, $seat, $a['act'], $a['amt'], $now));
        }
    }
    if ($t['phase'] === 'settle' && $now >= $t['next_at']) { $ev = array_merge($ev, pks_hand_end($t, $now)); }
    if ($t['phase'] === 'idle' && pk_ready($t, $now)) { $ev = array_merge($ev, pk_start_hand($t, $now)); }
    return $ev;
}

/** What one viewer may know: own hole cards, shown cards, never the deck or the salt. */
function pk_view(array $t, ?string $uid): array {
    $me = null;
    foreach ($t['players'] as $s => $p) { if ($uid !== null && $p['uid'] === $uid) { $me = $s; } }
    $players = [];
    foreach ($t['players'] as $s => $p) {
        $vis = $s === $me || $p['show'];
        $players[] = ['seat' => $s, 'uid' => $p['uid'], 'name' => $p['name'], 'bot' => $p['bot'], 'stack' => $p['stack'], 'bet' => $p['bet'], 'total' => $p['total'],
            'in' => $p['in'], 'allin' => $p['allin'], 'sitout' => $p['sitout'], 'away' => $p['away'], 'leaving' => $p['leaving'], 'show' => $p['show'], 'last' => $p['last'],
            'holding' => count($p['cards']), 'cards' => $vis ? $p['cards'] : null];
    }
    $now = microtime(true);
    return ['id' => $t['id'], 'name' => $t['name'], 'seats' => $t['seats'], 'sb' => $t['sb'], 'bb' => $t['bb'], 'min_buy' => $t['min_buy'], 'max_buy' => $t['max_buy'],
        'act_secs' => $t['act_secs'], 'hand_no' => $t['hand_no'], 'phase' => $t['phase'], 'button' => $t['button'], 'players' => $players, 'board' => $t['board'],
        'pot' => $t['pot'], 'pots' => $t['pots'], 'to_act' => $t['to_act'], 'ms' => $t['deadline'] !== null ? max(0, (int)(($t['deadline'] - $now) * 1000)) : null,
        'cur_bet' => $t['cur_bet'], 'min_raise' => $t['min_raise'], 'seq' => $t['seq'], 'winners' => $t['winners'], 'log' => $t['log'], 'deck_hash' => $t['deck_hash'],
        'me' => $me, 'legal' => $me !== null ? pk_legal($t, $me) : null, 'stub' => true];
}
