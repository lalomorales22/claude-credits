#!/usr/bin/env php
<?php
/**
 * tests/ws_test.php: end-to-end tests for ws.php against REALTIME.md (Running it, Tickets, Wire protocol, The floor,
 * Persistence, Security rules) with the real poker engine from index.php. No framework: one line per check, a
 * summary, exit 1 on any failure. It runs from a temporary copy of the app with its own SQLite file (under
 * TMPDIR / the system temp dir), so the real data/ is never touched, and it starts and stops its own ws.php on a
 * free port in 8300-8399. The poker part plays two hands heads-up on table 1 (bots off, 2 s clock) and checks the
 * ledger after every path that moves coins. tests/poker_e2e_test.php covers the longer multi-hand scenarios.
 *
 *     php tests/ws_test.php
 */
declare(strict_types=1);
error_reporting(E_ALL);

require __DIR__ . '/ws_client.php';
$root = dirname(__DIR__);
$tmp = scratch_copy($root, 'ws_test');
define('GT_NO_ROUTE', 1);
require "$tmp/index.php";          // headless: db(), q(), tx(), rt_ticket_make() on the scratch database
ini_set('display_errors', 'stderr');
set_exception_handler(function (Throwable $e): void { fwrite(STDERR, "\nUNCAUGHT " . $e::class . ': ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine() . "\n"); exit(1); });
db();

/* ───────────────────────── tiny harness ───────────────────────── */

$pass = 0; $fail = 0; $failures = [];
function check(bool $ok, string $name, string $detail = ''): bool {
    global $pass, $fail, $failures;
    if ($ok) { $pass++; echo "  ok   $name\n"; }
    else { $fail++; $failures[] = $name; echo "  FAIL $name" . ($detail !== '' ? "  -- $detail" : '') . "\n"; }
    return $ok;
}
function section(string $s): void { echo "\n== $s\n"; }
function short(mixed $v): string { return substr((string)json_encode($v), 0, 160); }

/* ───────────────────────── fixtures ───────────────────────── */

q('UPDATE poker_tables SET bots = 0');                                     // hands start only when two test players sit
q("UPDATE settings SET value = '2' WHERE key = 'poker_action_seconds'");    // fast clocks
$mk = function (string $name, int $balance): int {
    q('INSERT INTO players (username, pass_hash, balance) VALUES (?,?,?)', [$name, password_hash('x', PASSWORD_BCRYPT, ['cost' => 4]), $balance]);
    return (int)db()->lastInsertId();
};
$A = $mk('wstest_a', 10000);
$B = $mk('wstest_b', 1500);
$S = $mk('wstest_seat', 100);
q('INSERT INTO poker_seats (table_id, player_id, seat, stack) VALUES (1, ?, 0, 500)', [$S]);   // a crash left this behind
$balance = fn(int $pid) => (int)val('SELECT balance FROM players WHERE id = ?', [$pid]);
$seatRow = fn(int $pid) => row('SELECT * FROM poker_seats WHERE player_id = ?', [$pid]);

/* ───────────────────────── start the server ───────────────────────── */

section('start-up');
$port = free_port();
[$proc, $logPath] = start_server($tmp, $port, ['--idle', '3', '--away', '6', '--tick', '20', '--verbose']);
$h = wait_health($port);
check((bool)$h && $h['ok'] === true, "ws.php is up on 127.0.0.1:$port and answers GET /health", (string)file_get_contents($logPath));
if (!$h) { proc_terminate($proc); exit(1); }
check(count($h['tables'] ?? []) === 3 && isset($h['tables'][0]['id'], $h['tables'][0]['seated'], $h['tables'][0]['hand_no']), '/health lists the 3 seeded tables with id/seated/hand_no', short($h));
$boot = (string)file_get_contents($logPath);
check(!str_contains($boot, 'STUB') && !str_contains($boot, 'no poker engine') && str_contains($boot, 'tables 3'), 'the real engine from index.php is hosting (no stub, no floor-only warning)', substr($boot, 0, 300));
check($balance($S) === 600 && !$seatRow($S), 'start-up refunded the stale poker_seats row (100 + 500 = 600) and deleted it', 'balance ' . $balance($S));
$led = row("SELECT * FROM ledger WHERE player_id = ? ORDER BY id DESC LIMIT 1", [$S]);
check($led && $led['kind'] === 'payout' && $led['game'] === 'poker' && (int)$led['amount'] === 500 && str_starts_with($led['detail'], 'table reset'), 'the refund is a poker payout in the ledger', short($led));

/* ───────────────────────── handshake ───────────────────────── */

section('handshake');
$c = WsClient::open($port, 'http://localhost:8100', 'dGhlIHNhbXBsZSBub25jZQ==');
check($c->ok(), 'GET / with Upgrade → 101 Switching Protocols', $c->status);
check(($c->headers['sec-websocket-accept'] ?? '') === 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=', 'Sec-WebSocket-Accept = base64(sha1(key + GUID)) (RFC 6455 sample key)', short($c->headers));
$c->close();
$c = WsClient::open($port, 'https://evil.example');
check(str_starts_with($c->status, 'HTTP/1.1 403'), 'foreign Origin → 403 and no upgrade', $c->status);
$c->close();
$c = WsClient::open($port, 'http://127.0.0.1:9999');
check($c->ok(), 'localhost / 127.0.0.1 origin on any port is accepted when the Host is local', $c->status);
$c->close();
$c = WsClient::open($port, null);
check($c->ok(), 'no Origin header (non-browser client) is accepted; the ticket is the credential', $c->status);
$c->close();
[$st] = raw_http($port, "GET / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nConnection: close\r\n\r\n");
check(str_starts_with($st, 'HTTP/1.1 426'), 'plain GET / without Upgrade → 426', $st);
[$st] = raw_http($port, "POST /health HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
check(str_starts_with($st, 'HTTP/1.1 405'), 'POST → 405', $st);

/* ───────────────────────── tickets ───────────────────────── */

section('tickets');
$c = WsClient::open($port);
$c->send(['t' => 'hello', 'ticket' => 'garbage.deadbeef', 'room' => 'floor']);
check($c->waitClose() === 1008, 'hello with a bad ticket → close 1008', (string)$c->closeCode);
$c = WsClient::open($port);
$c->send(['t' => 'hello', 'ticket' => ticket_for($A, 'wstest_a', ['exp' => time() - 5]), 'room' => 'floor']);
check($c->waitClose() === 1008, 'hello with an expired ticket → close 1008', (string)$c->closeCode);
$c = WsClient::open($port);
$c->send(['t' => 'hello', 'ticket' => rt_ticket_make(['uid' => 'p' . $A, 'pid' => $A, 'name' => 'x']) . 'a', 'room' => 'floor']);
check($c->waitClose() === 1008, 'hello with a tampered signature → close 1008', (string)$c->closeCode);
$tk = ticket_for($A, 'wstest_a');
$c1 = WsClient::open($port);
$w = $c1->hello($tk);
check($w !== null && $w['uid'] === 'p' . $A && $w['name'] === 'wstest_a' && $w['guest'] === false && isset($w['id'], $w['players'], $w['tables'], $w['online']), 'a fresh ticket → welcome {id, uid, name, guest:false, players, tables, online}', short($w));
$c2 = WsClient::open($port);
$c2->send(['t' => 'hello', 'ticket' => $tk, 'room' => 'floor']);
check($c2->waitClose() === 1008, 'the same ticket again (reused nonce) → close 1008', (string)$c2->closeCode);
$c1->close();
$c = WsClient::open($port);
$c->send(['t' => 'chat', 'text' => 'hi']);
check($c->waitClose() === 1008, 'anything before hello → close 1008', (string)$c->closeCode);
$c = WsClient::open($port);
$c->send(['t' => 'hello', 'ticket' => ticket_for($A, 'wstest_a'), 'room' => 'kitchen']);
check($c->waitClose() === 1008, 'unknown room → close 1008', (string)$c->closeCode);
$cT = WsClient::open($port, 'http://localhost:8100', null, 'hello-timeout');   // never says hello: checked at the end
$cI = WsClient::open($port, 'http://localhost:8100', null, 'idle');            // says hello, then goes silent and ignores pings
$cI->autoPong = false;
$cI->hello(ticket_for($A, 'wstest_a'), 'poker');
$tStart = microtime(true);

/* ───────────────────────── guests ───────────────────────── */

section('guests');
$g = WsClient::open($port, 'http://localhost:8100', null, 'guest');
$w = $g->hello(guest_ticket());
check($w !== null && $w['guest'] === true && str_starts_with($w['uid'], 'g'), 'guest ticket → welcome with guest:true', short($w));
$g->send(['t' => 'pk_join', 'table' => 1, 'seat' => 0, 'buyin' => 1000]);
$e = $g->waitFor('pk_err');
check($e !== null && str_contains($e['msg'], 'Log in'), 'guest pk_join → pk_err', short($e));

/* ───────────────────────── the floor ───────────────────────── */

section('the floor');
$a = WsClient::open($port, 'http://localhost:8100', null, 'A');
$wa = $a->hello(ticket_for($A, 'wstest_a'));
check($wa !== null && count(array_filter($wa['players'], fn($p) => $p[0] === $w['id'])) === 1, 'welcome roster lists the guest already on the floor as [id, uid, name, x, z, ry, a, st]', short($wa['players'] ?? null));
$b = WsClient::open($port, 'http://localhost:8100', null, 'B');
$wb = $b->hello(ticket_for($B, 'wstest_b'));
$j = $a->waitFor('join');
check($j !== null && $j['p'][0] === $wb['id'] && $j['p'][1] === 'p' . $B && $j['p'][2] === 'wstest_b', 'A receives join for B', short($j));
$on = $a->waitFor('online', 2);
check($on !== null && $on['n'] >= 3, 'online count broadcast (≥ 3 distinct people)', short($on));

$b->send(['t' => 'pos', 'x' => 1000, 'z' => -1000, 'ry' => 10, 'a' => 1]);
$snap = $a->waitFor('snap', 2, fn($m) => (bool)array_filter($m['ps'], fn($p) => $p[0] === $wb['id']));
$ps = $snap ? array_values(array_filter($snap['ps'], fn($p) => $p[0] === $wb['id']))[0] : null;
check($ps !== null && $ps[1] == 60 && $ps[2] == -60 && abs($ps[3] - M_PI) < 0.01 && $ps[4] === 1, 'pos is clamped to ±60 / ±π and relayed in snap as [id, x, z, ry, a]', short($ps));
$a->pump(1.1);   // a new rate window (and everyone answers the server's pings meanwhile)
for ($i = 1; $i <= 30; $i++) { $b->send(['t' => 'pos', 'x' => $i, 'z' => 0, 'ry' => 0, 'a' => 0]); }
$a->pump(0.6);
$maxX = 0;
foreach ($a->inbox as $m) { if ($m['t'] === 'snap') { foreach ($m['ps'] as $p) { if ($p[0] === $wb['id']) { $maxX = max($maxX, $p[1]); } } } }
$a->inbox = array_values(array_filter($a->inbox, fn($m) => $m['t'] !== 'snap'));
check($maxX == 15, 'pos beyond 15 per second is dropped (30 sent, the 15th is the last one seen)', "max x $maxX");

$b->send(['t' => 'seat', 'st' => 'slot:tiki:2']);
$s = $a->waitFor('seat');
check($s !== null && $s['id'] === $wb['id'] && $s['st'] === 'slot:tiki:2', 'seat {st} is relayed to the floor', short($s));
$b->send(['t' => 'seat', 'st' => str_repeat('x', 50)]);
$s = $a->waitFor('seat');
check($s !== null && strlen($s['st']) === 32, 'station ids are cut to 32 chars', short($s));
$b->send(['t' => 'seat', 'st' => str_repeat('x', 50)]);   // the same station again
check($a->waitFor('seat', 0.3) === null, 'a repeat of the current station is not relayed');
$a->pump(0.8);   // a fresh one-second window for the seat limiter
for ($i = 1; $i <= 30; $i++) { $b->send(['t' => 'seat', 'st' => "spam:$i"]); }
$a->pump(0.6);
$nSeat = count(array_filter($a->inbox, fn($m) => $m['t'] === 'seat'));
$a->inbox = array_values(array_filter($a->inbox, fn($m) => $m['t'] !== 'seat'));
check($nSeat === 4, 'seat changes beyond 4 per second are dropped (30 sent in a burst, 4 relayed)', "relayed $nSeat");

$b->send(['t' => 'chat', 'text' => "  hello <b> & \x01friends " . str_repeat('!', 200)]);
$ca = $a->waitFor('chat');
$cb = $b->waitFor('chat');
check($ca !== null && $ca['id'] === $wb['id'] && $ca['name'] === 'wstest_b' && str_starts_with($ca['text'], 'hello <b> &  friends') && mb_strlen($ca['text']) === 140, 'chat reaches others: trimmed, control chars stripped, 140 chars, name from the ticket', short($ca));
check($cb !== null && $cb['text'] === $ca['text'], 'the sender gets the same chat echo');
$b->send(['t' => 'chat', 'text' => 'too fast']);
$e = $b->waitFor('err');
check($e !== null && $e['msg'] === 'Slow down.', 'a second chat inside 1.5 s → err "Slow down."', short($e));
check($a->waitFor('chat', 0.3) === null, 'the rate-limited chat was not relayed');

$a->send(['t' => 'ping']);
check($a->waitFor('pong') !== null, 'JSON ping → pong');
$a->sendRaw($a->frame('xyz', 9));
$a->pump(0.5, fn() => $a->pongs !== []);
check(in_array('xyz', $a->pongs, true), 'WebSocket ping frame → pong frame with the same payload');
$a->sendRaw($a->frame('{"t":"pi', 1, true, false) . $a->frame('ng"}', 0, true, true));
check($a->waitFor('pong') !== null, 'fragmented text message (continuation frames) is reassembled');

/* ───────────────────────── frame policing ───────────────────────── */

section('frame policing');
$c = WsClient::open($port); $c->hello(ticket_for($A, 'wstest_a'));
$c->sendRaw($c->frame(str_repeat('a', 9000)));
check($c->waitClose() === 1009, 'payload over 8 KB → close 1009', (string)$c->closeCode);
$c = WsClient::open($port); $c->hello(ticket_for($A, 'wstest_a'));
$c->sendRaw($c->frame('{"t":"ping"}', 1, false));
check($c->waitClose() === 1002, 'unmasked client frame → close 1002', (string)$c->closeCode);
$c = WsClient::open($port); $c->hello(ticket_for($A, 'wstest_a'));
$c->sendRaw($c->frame('binary', 2));
check($c->waitClose() === 1003, 'binary frame → close 1003', (string)$c->closeCode);
$c = WsClient::open($port); $c->hello(ticket_for($A, 'wstest_a'));
$c->sendRaw($c->frame('not json'));
$e1 = $c->waitFor('err');
$c->sendRaw($c->frame("\xff\xfe bad utf8"));
$e2 = $c->waitFor('err');
$c->sendRaw($c->frame('[1,2,3]'));
check($e1 !== null && $e2 !== null && $c->waitClose() === 1008, 'malformed messages: err, err, then close 1008 on the third strike', (string)$c->closeCode);
$c = WsClient::open($port); $c->hello(ticket_for($A, 'wstest_a'));
$c->send(['t' => 'no_such_type', 'x' => 1]);
$c->send(['t' => 'ping']);
check($c->waitFor('pong') !== null && $c->closeCode === null, 'unknown message types are ignored');
$c->sendRaw($c->frame(pack('n', 1000) . 'bye', 8));
check($c->waitClose() === 1000, 'client close frame is answered with a close frame', (string)$c->closeCode);

/* ───────────────────────── poker ───────────────────────── */

section('poker');
$g->send(['t' => 'pk_watch', 'table' => 1]);
$st = $g->waitFor('pk_state');
check($st !== null && ($st['table']['id'] ?? 0) === 1 && ($st['table']['phase'] ?? '') === 'idle', 'pk_watch → pk_state for the table', short($st['table'] ?? null));
$g->send(['t' => 'pk_watch', 'table' => 99]);
$e = $g->waitFor('pk_err');
check($e !== null, 'pk_watch of a missing table → pk_err', short($e));

$a->send(['t' => 'pk_join', 'table' => 1, 'seat' => 0, 'buyin' => 1000]);
$bal = $a->waitFor('bal');
$sa = $a->waitFor('pk_state');
check($bal !== null && $bal['balance'] === 9000 && $balance($A) === 9000, 'pk_join moves the buy-in: bal 9000 on the wire and in players.balance', short($bal));
$r = $seatRow($A);
check($r && (int)$r['table_id'] === 1 && (int)$r['seat'] === 0 && (int)$r['stack'] === 1000, 'poker_seats row written with the buy-in', short($r));
$led = row('SELECT * FROM ledger WHERE player_id = ? ORDER BY id DESC LIMIT 1', [$A]);
check($led && $led['kind'] === 'wager' && $led['game'] === 'poker' && (int)$led['amount'] === -1000 && str_starts_with($led['detail'], 'buy-in'), 'buy-in is a poker wager in the ledger', short($led));
check($sa !== null && $sa['table']['me'] === 0 && $sa['table']['players'][0]['uid'] === 'p' . $A, 'A sees itself in seat 0', short($sa['table'] ?? null));
check($sa['table']['players'][0]['owes'] === true && $sa['table']['players'][0]['post'] === false, 'a new seat owes a big blind (owes:true, post:false in the view)', short($sa['table']['players'][0] ?? null));
$a->send(['t' => 'pk_post', 'on' => true]);
$st = $a->waitFor('pk_state', 2, fn($m) => !empty($m['table']['players'][0]['post']));
check($st !== null, 'pk_post {on:true} is relayed to pk_post(): the seat now asks to post (players[].post true in the next pk_state)', short($st['table']['players'][0] ?? null));
$a->send(['t' => 'pk_post', 'on' => true]);   // a repeat is a no-op
check($a->waitFor('pk_state', 0.3) === null, 'a repeat of the current post flag sends no new state');
$a->send(['t' => 'pk_post', 'on' => false]);
$st = $a->waitFor('pk_state', 2, fn($m) => empty($m['table']['players'][0]['post']));
check($st !== null, 'pk_post {on:false} withdraws it');
$a->send(['t' => 'pk_addon', 'amount' => 500]);
$bal = $a->waitFor('bal');
check($bal !== null && $bal['balance'] === 8500 && $balance($A) === 8500 && (int)$seatRow($A)['stack'] === 1500, 'pk_addon between hands: 500 more on the table, the seat row follows (1500), bal 8500', short([$bal, $seatRow($A)]));
$led = row('SELECT * FROM ledger WHERE player_id = ? ORDER BY id DESC LIMIT 1', [$A]);
check($led && $led['kind'] === 'wager' && (int)$led['amount'] === -500 && str_starts_with($led['detail'], 'add-on'), 'the add-on is a poker wager in the ledger', short($led));
$ledgerN = (int)val('SELECT COUNT(*) FROM ledger WHERE player_id = ?', [$A]);
$a->send(['t' => 'pk_addon', 'amount' => 3000]);   // 1500 + 3000 > max_buy 4000
$e = $a->waitFor('pk_err');
check($e !== null && str_contains($e['msg'], 'maximum') && $balance($A) === 8500 && (int)$seatRow($A)['stack'] === 1500 && (int)val('SELECT COUNT(*) FROM ledger WHERE player_id = ?', [$A]) === $ledgerN, 'an add-on over the table maximum is refused by the engine before anything is written', short([$e, $balance($A)]));

// a second ws.php against the same database (double launch, restart overlap) must exit before it "recovers" A's live seat
$ledgerN = (int)val('SELECT COUNT(*) FROM ledger WHERE player_id = ?', [$A]);
[$code2, $out2] = second_server($tmp, free_port());   // another port: only the database is shared
check($code2 !== null && $code2 !== 0 && str_contains($out2, 'already owns'), 'a second ws.php on another port refuses to start: the database already has a server', short([$code2, substr($out2, -200)]));
[$code3] = second_server($tmp, $port);                // the same port
check($code3 !== null && $code3 !== 0, 'a second ws.php on the same port exits non-zero', short($code3));
check($balance($A) === 8500 && (int)($seatRow($A)['stack'] ?? 0) === 1500 && (int)val('SELECT COUNT(*) FROM ledger WHERE player_id = ?', [$A]) === $ledgerN, 'neither touched the ledger: A still has 8500 GC in the bank and 1500 GC on the table, no phantom "table reset" refund', short([$balance($A), $seatRow($A)]));
check(health($port) !== null, 'the live server is unaffected');
$a->send(['t' => 'pk_join', 'table' => 1, 'seat' => 2, 'buyin' => 1000]);
$e = $a->waitFor('pk_err');
check($e !== null && str_contains($e['msg'], 'already seated'), 'a second pk_join for a seated player → pk_err', short($e));
$a->send(['t' => 'pk_sitout', 'on' => true]);
$a->send(['t' => 'pk_sitout', 'on' => true]);    // a repeat: no-op
$a->send(['t' => 'pk_sitout', 'on' => false]);
$a->send(['t' => 'pk_sitout', 'on' => true]);    // the third real toggle inside a second
$e = $a->waitFor('pk_err');
$a->pump(0.3);
$so = [];
foreach ($a->inbox as $i => $m) {
    if ($m['t'] === 'pk_events') { foreach ($m['events'] as $ev) { if ($ev['t'] === 'sitout') { $so[] = $ev['on']; } } }
    if ($m['t'] === 'pk_events' || $m['t'] === 'pk_state') { unset($a->inbox[$i]); }
}
$a->inbox = array_values($a->inbox);
check($e !== null && $e['msg'] === 'Slow down.' && $so === [true, false], 'pk_sitout: a repeat is a no-op, the third toggle inside a second → pk_err "Slow down." (events: on, off; A is back in)', short([$e, $so]));
$b->send(['t' => 'pk_join', 'table' => 1, 'seat' => 0, 'buyin' => 1000]);
$e = $b->waitFor('pk_err');
check($e !== null && str_contains($e['msg'], 'taken'), 'pk_join on a taken seat → pk_err', short($e));
$b->send(['t' => 'pk_join', 'table' => 1, 'seat' => 1, 'buyin' => 100]);
$e = $b->waitFor('pk_err');
check($e !== null && str_contains($e['msg'], 'between'), 'buy-in outside [min_buy, max_buy] → pk_err', short($e));
$b->send(['t' => 'pk_join', 'table' => 1, 'seat' => 1, 'buyin' => 2000]);
$e = $b->waitFor('pk_err');
check($e !== null && str_contains($e['msg'], 'Not enough') && $balance($B) === 1500 && !$seatRow($B), 'buy-in above the balance → pk_err from move_coins inside the tx, nothing written', short($e));
$a2 = WsClient::open($port, 'http://localhost:8100', null, 'A2');
$w2 = $a2->hello(ticket_for($A, 'wstest_a'), 'poker');
$s2 = $a2->waitFor('pk_state');
check($w2 !== null && $s2 !== null && $s2['table']['me'] === 0, 'a second connection of a seated uid gets its table view right after welcome', short($s2['table'] ?? null));
$a2->close();

$b->send(['t' => 'pk_join', 'table' => 1, 'seat' => 1, 'buyin' => 1000]);
$bal = $b->waitFor('bal');
check($bal !== null && $bal['balance'] === 500 && $balance($B) === 500, 'B buys in for 1000', short($bal));
$hs = fn($m) => (bool)array_filter($m['events'], fn($e) => $e['t'] === 'hand_start');
$evA = $a->waitFor('pk_events', 5, $hs);
$stA = $a->waitFor('pk_state', 2);
$evG = $g->waitFor('pk_events', 5, $hs);
check($evA !== null && $stA !== null, 'with two players a hand starts: pk_events (hand_start, post, deal) then pk_state', short($evA));
check($evG !== null, 'the watcher receives the same events');
$deckHash = '';
foreach ($evA['events'] ?? [] as $e) { if ($e['t'] === 'hand_start') { $deckHash = $e['deck_hash']; } }
check(strlen($deckHash) === 64 && $stA['table']['deck_hash'] === $deckHash && !isset($stA['table']['deck']) && !isset($stA['table']['deck_salt']), 'the deck commitment is published, the deck and salt are not', short($stA['table']['deck_hash'] ?? null));
$tb = $g->waitFor('pk_tables', 2, fn($m) => ($m['tables'][0]['seated'] ?? 0) === 2);
check($tb !== null && isset($tb['tables'][0]['playing'], $tb['tables'][0]['min_buy']), 'pk_tables broadcast reflects the occupancy (seated 2)', short($tb));

$a->send(['t' => 'pk_act', 'act' => 'call', 'amt' => 0, 'hand' => $stA['table']['hand_no'], 'seq' => 999]);
$e = $a->waitFor('pk_err');
check($e !== null && str_contains($e['msg'], 'moved on'), 'pk_act with a stale seq → pk_err, no-op', short($e));
$b->send(['t' => 'pk_act', 'act' => 'call', 'amt' => 0, 'hand' => 0, 'seq' => $stA['table']['seq']]);
$e = $b->waitFor('pk_err');
check($e !== null, 'pk_act with a stale hand number → pk_err', short($e));

// play the hand: whoever is told it is their turn checks or calls; remember everyone's own hole cards
$cards = []; $ended = null; $deadline = microtime(true) + 20;
$players = ['A' => [$a, $A], 'B' => [$b, $B]];
while (microtime(true) < $deadline && !$ended) {
    foreach ($players as $k => [$cl, $pid]) {
        $cl->pump(0.05);
        foreach ($cl->inbox as $i => $m) {
            if ($m['t'] === 'pk_events') { foreach ($m['events'] as $e) { if ($e['t'] === 'hand_end') { $ended = $e; } } unset($cl->inbox[$i]); continue; }
            if ($m['t'] !== 'pk_state') { continue; }
            $tbl = $m['table'];
            if ((int)$tbl['hand_no'] !== 1) { continue; }   // hand 2 deals on the tick after hand_end and can already be in the inbox: left queued for the hand-2 loop
            unset($cl->inbox[$i]);
            foreach ($tbl['players'] as $p) { if ($p['uid'] === 'p' . $pid && $p['cards']) { $cards[$k] = $p['cards']; } }
            if (!empty($tbl['legal']) && $tbl['phase'] !== 'settle') {
                $cl->send(['t' => 'pk_act', 'act' => $tbl['legal']['check'] ? 'check' : 'call', 'amt' => 0, 'hand' => $tbl['hand_no'], 'seq' => $tbl['seq']]);
            }
        }
        $cl->inbox = array_values($cl->inbox);
    }
}
check($ended !== null && isset($ended['deck_salt'], $ended['deck'], $ended['leavers'], $ended['busted']), 'the hand runs to hand_end (deck_salt, deck, leavers, busted revealed)', short($ended));
check(count($cards) === 2, 'both players saw their own hole cards', short($cards));

// nobody ever sees another seat's hole cards before they are shown
$leak = 0; $checked = 0;
foreach ([['A', $a, 'p' . $B, 'B'], ['B', $b, 'p' . $A, 'A'], ['guest', $g, null, null]] as [$who, $cl, $otherUid, $otherKey]) {
    foreach ($cl->seen as $m) {
        if ($m['t'] !== 'pk_state' || ($m['table']['id'] ?? 0) !== 1 || (int)($m['table']['hand_no'] ?? 0) !== 1) { continue; }   // hand 1 only: another hand's board may hold these cards
        $json = (string)json_encode($m);
        foreach ($m['table']['players'] as $p) {
            $mine = $who !== 'guest' && $p['uid'] === ($who === 'A' ? 'p' . $A : 'p' . $B);
            if ($mine || !empty($p['show'])) { continue; }
            $checked++;
            if ($p['cards'] !== null) { $leak++; }
            if ($p['uid'] === $otherUid) { foreach ($cards[$otherKey] ?? [] as $card) { if (str_contains($json, '"' . $card . '"')) { $leak++; } } }
        }
    }
}
check($checked > 0 && $leak === 0, "no pk_state ever carried another seat's hole cards before showdown ($checked seat views scanned)", "leaks: $leak");

$hand = row('SELECT * FROM poker_hands WHERE table_id = 1 ORDER BY id DESC LIMIT 1');
$rec = $hand ? json_decode((string)$hand['record'], true) : null;
check($hand && (int)$hand['hand_no'] === 1 && $hand['deck_hash'] === $deckHash && $hand['ended_at'] !== null, 'poker_hands row written at hand_end with the committed deck_hash', short($hand ? array_diff_key($hand, ['record' => 1]) : null));
check(is_array($rec) && count($rec['players'] ?? []) === 2 && hash('sha256', implode(' ', $rec['deck'] ?? []) . '|' . $hand['deck_salt']) === $hand['deck_hash'], 'the stored record verifies: sha256(deck + "|" + salt) = deck_hash', short($rec['players'] ?? null));
$stacks = [];
foreach ($rec['players'] ?? [] as $p) { $stacks[$p['uid']] = (int)$p['end_stack']; }
$rowA = $seatRow($A); $rowB = $seatRow($B);
check($rowA && $rowB && (int)$rowA['stack'] === $stacks['p' . $A] && (int)$rowB['stack'] === $stacks['p' . $B], 'poker_seats stacks updated to the settled stacks', short([$rowA['stack'] ?? null, $rowB['stack'] ?? null, $stacks]));
$pa = row('SELECT rounds_played, total_wagered, total_won FROM players WHERE id = ?', [$A]);
$pb = row('SELECT rounds_played, total_wagered, total_won FROM players WHERE id = ?', [$B]);
check((int)$pa['rounds_played'] === 1 && (int)$pb['rounds_played'] === 1, 'record_round counted one round for each real player', short([$pa, $pb]));
check((int)$pa['total_wagered'] + (int)$pb['total_wagered'] === (int)$hand['pot'] && (int)$pa['total_won'] + (int)$pb['total_won'] === (int)$hand['pot'] && (int)$hand['pot'] > 0, 'wagered and won across the table both add up to the pot', short([$pa, $pb, $hand['pot']]));
check($stacks['p' . $A] + $stacks['p' . $B] === 2500, 'chips are conserved: 1500 + 1000 in, same out', short($stacks));

// hand 2 ends without a showdown: the first player to act folds. The winner never showed, so nobody else may see the winning hole cards.
// A asks to leave during the settle pause (the hand is decided but not over): the engine defers it, ws.php pays it at hand_end.
// (hand 2 deals on the tick after hand 1's hand_end, so its first states may already be in the inboxes: nothing is discarded here)
$started2 = false; $folded = null; $ended2 = null; $mine2 = []; $leaveAt = null; $leavingSeen = false; $deadline = microtime(true) + 14;
while (microtime(true) < $deadline && !$ended2) {
    foreach ($players as $k => [$cl, $pid]) {
        $cl->pump(0.05);
        foreach ($cl->inbox as $i => $m) {
            if ($m['t'] === 'pk_events') {
                foreach ($m['events'] as $e) { if ($e['t'] === 'hand_start' && (int)$e['hand'] === 2) { $started2 = true; } if ($e['t'] === 'hand_end' && $started2) { $ended2 = $e; } }
                unset($cl->inbox[$i]); continue;
            }
            if ($m['t'] !== 'pk_state') { continue; }
            unset($cl->inbox[$i]);
            $tbl = $m['table'];
            if ((int)$tbl['hand_no'] !== 2) { continue; }
            $started2 = true;
            foreach ($tbl['players'] as $p) { if ($p['uid'] === 'p' . $pid && $p['cards']) { $mine2[$k] = $p['cards']; } }
            if (!empty($tbl['legal']) && $folded === null) { $folded = $k; $cl->send(['t' => 'pk_act', 'act' => 'fold', 'amt' => 0, 'hand' => 2, 'seq' => $tbl['seq']]); }
            if ($k === 'A' && $tbl['phase'] === 'settle' && $leaveAt === null) { $leaveAt = microtime(true); $a->send(['t' => 'pk_leave']); }
            if ($k === 'A' && $tbl['phase'] === 'settle' && !empty($tbl['players'][0]['leaving'])) { $leavingSeen = true; }
        }
        $cl->inbox = array_values($cl->inbox);
    }
}
check($ended2 !== null && $folded !== null, 'hand 2: the first player to act folded and the hand ended uncontested', short([$folded, $ended2]));
$hand2 = row('SELECT * FROM poker_hands WHERE table_id = 1 AND hand_no = 2');
$rec2 = $hand2 ? json_decode((string)$hand2['record'], true) : null;
$end2 = [];
foreach ($rec2['players'] ?? [] as $p) { $end2[$p['uid']] = (int)$p['end_stack']; }
check(count($end2) === 2 && $end2['p' . $A] + $end2['p' . $B] === 2500, 'chips are still conserved after the uncontested pot (record end stacks)', short($end2));
$v2 = pk_verify_record($rec2 ?? []);
check($v2 === ['hash_ok' => true, 'deal_ok' => true], 'pk_verify_record() passes on the stored record', short($v2));
$winner = $folded === 'A' ? 'B' : 'A';
$winUid = 'p' . ($winner === 'A' ? $A : $B);
$winCards = $mine2[$winner] ?? [];
check(count($winCards) === 2, "the winner ($winner) saw their own hole cards", short($mine2));
$leak2 = 0; $settled = 0; $ownSeen = false;
foreach ([['A', $a], ['B', $b], ['guest', $g]] as [$who, $cl]) {
    foreach ($cl->seen as $m) {
        if ($m['t'] !== 'pk_state' || (int)($m['table']['hand_no'] ?? 0) !== 2) { continue; }
        $tbl = $m['table'];
        if ($who === $winner) { foreach ($tbl['winners'] as $w) { if (($w['cards'] ?? null) === $winCards) { $ownSeen = true; } } continue; }
        if ($tbl['winners']) { $settled++; }
        $json = (string)json_encode($m);
        foreach ($winCards as $card) { if (str_contains($json, '"' . $card . '"')) { $leak2++; } }
        foreach ($tbl['winners'] as $w) { if (($w['cards'] ?? null) !== null) { $leak2++; } }
        foreach ($tbl['players'] as $p) { if ($p['uid'] === $winUid && ($p['cards'] !== null || !empty($p['show']))) { $leak2++; } }
    }
}
check($settled > 0 && $leak2 === 0, "the winner never showed: no view of the loser or the watcher carried the winning hole cards, in players[] or winners[] ($settled settled views scanned)", "leaks: $leak2");
check($ownSeen, 'the winner still sees their own cards in winners[]');

check($leaveAt !== null && $leavingSeen, 'pk_leave during settle: the engine defers it (players[].leaving true in the next pk_state, no fold recorded)', short([$leaveAt, $leavingSeen]));
check(array_values((array)($ended2['leavers'] ?? [])) === [$end2['p' . $A] ?? -1], 'hand_end lists A in leavers[] with exactly the record\'s end stack', short($ended2['leavers'] ?? null));
$bal = $a->waitFor('bal', 3);
check($bal !== null && $bal['balance'] === 8500 + $end2['p' . $A] && $balance($A) === $bal['balance'] && !$seatRow($A), 'A is paid at hand_end: balance = 8500 + the record\'s end stack, seat row gone, bal on the wire', short([$bal, $balance($A), $end2]));
$led = row("SELECT * FROM ledger WHERE player_id = ? AND kind = 'payout' ORDER BY id DESC LIMIT 1", [$A]);
check($led && $led['game'] === 'poker' && str_starts_with($led['detail'], 'cash-out') && (int)$led['amount'] === $end2['p' . $A], 'the cash-out is one poker payout in the ledger for that amount', short($led));
check((int)val("SELECT COUNT(*) FROM ledger WHERE player_id = ? AND kind = 'payout'", [$A]) === 1, 'and it is the only payout A ever received (paid exactly once)');
check((int)($seatRow($B)['stack'] ?? -1) === $end2['p' . $B], 'B\'s poker_seats row carries the settled stack', short([$seatRow($B), $end2]));
// the leaver's seat is gone when hand_end is flushed, yet A must still see the end of the hand it was in: the hand_end
// pk_events and a closing pk_state (hand 2, idle, me null, seat gone), not a last frame stuck in 'settle' with leaving=true
$hasEnd = fn(array $m) => $m['t'] === 'pk_events' && array_filter($m['events'], fn($e) => $e['t'] === 'hand_end' && ($e['deck'] ?? null) === ($ended2['deck'] ?? 0));   // hand 2's, by its revealed deck
$isFinal = fn(array $m) => $m['t'] === 'pk_state' && (int)($m['table']['hand_no'] ?? 0) === 2 && ($m['table']['phase'] ?? '') === 'idle';
$a->pump(3, fn() => array_filter($a->seen, $hasEnd) && array_filter($a->seen, $isFinal));
check((bool)array_filter($a->seen, $hasEnd), 'the mid-hand leaver A still received the hand_end pk_events of hand 2', short(array_map(fn($m) => $m['t'], array_slice($a->seen, -4))));
$fin = array_values(array_filter($a->seen, $isFinal));
$finA = $fin ? array_filter((array)$fin[0]['table']['players'], fn($p) => ($p['uid'] ?? null) === 'p' . $A) : null;
check($fin && $fin[0]['table']['me'] === null && $finA === [], 'and a closing pk_state of it: hand 2, phase idle, me null, A\'s seat gone', short($fin ? array_intersect_key($fin[0]['table'], ['hand_no' => 1, 'phase' => 1, 'me' => 1, 'players' => 1]) : $fin));
$stackB = (int)$seatRow($B)['stack'];
$b->close();   // vanish without a word while the table is idle: the away window (6 s in this run) must cash B out
$t0 = microtime(true);
while (microtime(true) - $t0 < 10 && $seatRow($B)) { $a->pump(0.1); }
check(!$seatRow($B) && $balance($B) === 500 + $stackB && microtime(true) - $t0 >= 5, 'a disconnected player at an idle table is cashed out after the away window (not before)', short([$balance($B), $stackB, round(microtime(true) - $t0, 1)]));
check(str_contains((string)file_get_contents($logPath), 'away p' . $B), 'the log records the away period');
$led = row("SELECT * FROM ledger WHERE player_id = ? AND kind = 'payout' ORDER BY id DESC LIMIT 1", [$B]);
check($led && (int)$led['amount'] === $stackB && str_contains($led['detail'], '(away)') && (int)val("SELECT COUNT(*) FROM ledger WHERE player_id = ? AND kind = 'payout'", [$B]) === 1, 'as one poker payout "(away)" for the seat row\'s stack', short($led));
$g->inbox = [];   // drop the states buffered while the hand ran
$g->send(['t' => 'pk_watch', 'table' => 1]);
$st = $g->waitFor('pk_state', 3, fn($m) => $m['table']['players'] === []);
check($st !== null && $st['table']['phase'] === 'idle', 'the table is empty again', short($st['table'] ?? null));

// a player who vanishes during a hand: pk_away(true) at once, paid exactly once at hand_end (table 3, two fresh players)
$E = $mk('wstest_e', 60000); $F = $mk('wstest_f', 60000);
$ce = WsClient::open($port, 'http://localhost:8100', null, 'E'); $ce->hello(ticket_for($E, 'wstest_e'), 'poker');
$cf = WsClient::open($port, 'http://localhost:8100', null, 'F'); $cf->hello(ticket_for($F, 'wstest_f'), 'poker');
$ce->send(['t' => 'pk_join', 'table' => 3, 'seat' => 0, 'buyin' => 20000]); $ce->waitFor('bal');
$cf->send(['t' => 'pk_join', 'table' => 3, 'seat' => 1, 'buyin' => 20000]); $cf->waitFor('bal');
check($stackOf = (int)($seatRow($E)['stack'] ?? 0) === 20000 && (int)($seatRow($F)['stack'] ?? 0) === 20000, 'E and F sit at table 3 with 20000 each');
$dropped = null; $ended3 = null; $awayEv = false; $awayState = false; $fFolded = false; $deadline = microtime(true) + 15;
while (microtime(true) < $deadline && !$ended3) {
    foreach (['E' => $ce, 'F' => $cf] as $k => $cl) {
        if ($cl->eof) { continue; }
        $cl->pump(0.05);
        foreach ($cl->inbox as $i => $m) {
            unset($cl->inbox[$i]);
            if ($m['t'] === 'pk_events') { foreach ($m['events'] as $ev) { if ($ev['t'] === 'hand_end') { $ended3 = $ev; } if ($ev['t'] === 'away' && (int)$ev['seat'] === 1 && !empty($ev['on'])) { $awayEv = true; } } continue; }
            if ($m['t'] !== 'pk_state' || (int)$m['table']['id'] !== 3) { continue; }
            $tbl = $m['table'];
            if (!empty($tbl['players'][1]['away'])) { $awayState = true; }
            if (!empty($tbl['legal'])) {   // F folds as soon as it may; E checks or calls
                $act = $k === 'F' ? 'fold' : ($tbl['legal']['check'] ? 'check' : 'call');
                if ($k === 'F') { $fFolded = true; }
                $cl->send(['t' => 'pk_act', 'act' => $act, 'amt' => 0, 'hand' => $tbl['hand_no'], 'seq' => $tbl['seq']]);
            }
            if ($k === 'F' && $tbl['phase'] === 'settle' && $dropped === null) { $dropped = microtime(true); $cf->close(); }   // gone during the settle pause
        }
        $cl->inbox = array_values($cl->inbox);
    }
}
check($fFolded && $dropped !== null && $ended3 !== null, 'F folded, the hand settled, F vanished during the settle pause and the hand ended', short([$fFolded, $dropped, $ended3 !== null]));
check($awayEv && $awayState, "E received the 'away' event for F's seat and sees away:true in pk_state");
$rec3 = json_decode((string)(row('SELECT record FROM poker_hands WHERE table_id = 3 ORDER BY id DESC LIMIT 1')['record'] ?? ''), true);
$end3 = []; foreach ($rec3['players'] ?? [] as $p) { $end3[$p['uid']] = (int)$p['end_stack']; }
$t0 = microtime(true);
while (microtime(true) - $t0 < 2 && $seatRow($F)) { $ce->pump(0.1); }
check(!$seatRow($F) && $balance($F) === 40000 + ($end3['p' . $F] ?? -1), 'F was cashed out at hand_end with the record\'s end stack, seat row gone', short([$balance($F), $end3, $seatRow($F)]));
$led = row("SELECT * FROM ledger WHERE player_id = ? AND kind = 'payout' ORDER BY id DESC LIMIT 1", [$F]);
$n = (int)val("SELECT COUNT(*) FROM ledger WHERE player_id = ? AND kind = 'payout'", [$F]);
check($led && $n === 1 && str_starts_with($led['detail'], 'cash-out') && (int)$led['amount'] === ($end3['p' . $F] ?? -1), 'exactly one poker payout for F: ' . ($led ? $led['detail'] : '-') . (str_contains((string)($led['detail'] ?? ''), 'disconnected') ? ' (the hand_end branch, before the away window)' : ''), short([$led, $n]));
check((int)($seatRow($E)['stack'] ?? -1) === ($end3['p' . $E] ?? -2), 'E\'s seat row carries the settled stack');
$ce->send(['t' => 'pk_leave']);
$bal = $ce->waitFor('bal');
check($bal !== null && !$seatRow($E) && $balance($E) === 40000 + $end3['p' . $E] && (int)val("SELECT COUNT(*) FROM ledger WHERE player_id = ? AND kind = 'payout'", [$E]) === 1, 'E leaves the idle table: paid at once, once', short([$bal, $balance($E)]));
$ce->close();

/* ───────────────────────── timers ───────────────────────── */

section('timers');
$left = max(0.0, 6.5 - (microtime(true) - $tStart));
$cT->pump($left, fn() => $cT->closeCode !== null || $cT->eof);
check($cT->closeCode === 1008, 'a socket that never says hello is closed (1008) after 5 s', (string)$cT->closeCode);
$cI->pump(0.5, fn() => $cI->closeCode !== null || $cI->eof);
check($cI->pings !== [] && $cI->closeCode === 1001, 'a silent client is pinged and then closed (1001) after the idle limit (3 s here)', 'pings ' . count($cI->pings) . ' code ' . (string)$cI->closeCode);
check($a->closeCode === null && $g->closeCode === null, 'clients that answer pings stay connected');

/* ───────────────────────── shutdown ───────────────────────── */

section('shutdown');
$balBefore = $balance($A);
$c = WsClient::open($port); $c->hello(ticket_for($A, 'wstest_a'));
$c->send(['t' => 'pk_join', 'table' => 2, 'seat' => 3, 'buyin' => 5000]);
$c->waitFor('bal');
check($seatRow($A) && (int)$seatRow($A)['stack'] === 5000 && $balance($A) === $balBefore - 5000, 'a player is seated at table 2 when SIGTERM arrives');
proc_terminate($proc, SIGTERM);
$code = $c->waitClose(3);
check($code === 1001, 'clients get close 1001 on shutdown', (string)$code);
$t0 = microtime(true); $status = proc_get_status($proc);
while ($status['running'] && microtime(true) - $t0 < 5) { usleep(100000); $status = proc_get_status($proc); }
check(!$status['running'] && $status['exitcode'] === 0, 'ws.php exits 0 on SIGTERM', short($status));
check(!$seatRow($A) && $balance($A) === $balBefore, 'shutdown refunded the seated player what the seat row said (5000)', short([$balance($A), $balBefore]));
$led = row("SELECT * FROM ledger WHERE player_id = ? ORDER BY id DESC LIMIT 1", [$A]);
check($led && $led['kind'] === 'payout' && (int)$led['amount'] === 5000 && str_starts_with($led['detail'], 'table reset'), 'as one "table reset" payout in the ledger', short($led));
check(str_contains((string)file_get_contents($logPath), 'bye'), 'the log ends with bye');
check(!row('SELECT 1 FROM poker_seats'), 'poker_seats is empty after shutdown');

/* ───────────────────────── summary ───────────────────────── */

proc_close($proc);
if ($fail) { echo "\nserver log kept at $logPath\n"; } else { rm_tree($tmp); }
echo "\n$pass passed, $fail failed" . ($fail ? ":\n  - " . implode("\n  - ", $failures) : '') . "\n";
exit($fail ? 1 : 0);
