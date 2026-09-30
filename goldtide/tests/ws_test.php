#!/usr/bin/env php
<?php
/**
 * tests/ws_test.php: end-to-end tests for ws.php against REALTIME.md (Running it, Tickets, Wire protocol, The floor,
 * Persistence, Security rules) using the stub poker engine (tests/pk_stub.php). No framework: one line per check,
 * a summary, exit 1 on any failure. It runs from a temporary copy of goldtide/ with its own SQLite file, so the
 * real data/ is never touched, and it starts and stops its own ws.php on a free port in 8300-8399.
 *
 *     php goldtide/tests/ws_test.php
 */
declare(strict_types=1);
error_reporting(E_ALL);

$root = dirname(__DIR__);
$tmp = rtrim(sys_get_temp_dir(), '/') . '/gt_ws_test_' . getmypid();
if (!is_dir("$tmp/tests") && !mkdir("$tmp/tests", 0700, true)) { fwrite(STDERR, "cannot create $tmp\n"); exit(1); }
foreach (['index.php', 'ws.php', 'tests/pk_stub.php'] as $f) {
    if (!copy("$root/$f", "$tmp/$f")) { fwrite(STDERR, "cannot copy $f\n"); exit(1); }
}
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

function free_port(): int {
    for ($p = 8300; $p <= 8399; $p++) {
        $s = @stream_socket_server("tcp://127.0.0.1:$p", $errno, $errstr);
        if ($s) { fclose($s); return $p; }
    }
    throw new RuntimeException('no free port in 8300-8399');
}

/** Plain HTTP exchange with the socket server (for /health and non-upgrade requests). Returns [status line, headers, body]. */
function raw_http(int $port, string $request): array {
    $s = @stream_socket_client("tcp://127.0.0.1:$port", $errno, $errstr, 3);
    if (!$s) { return ['', [], '']; }
    stream_set_timeout($s, 3);
    fwrite($s, $request);
    $resp = '';
    while (!feof($s)) { $chunk = fread($s, 8192); if ($chunk === false || $chunk === '') { $info = stream_get_meta_data($s); if ($info['timed_out']) { break; } if ($chunk === '') { usleep(5000); } continue; } $resp .= $chunk; }
    fclose($s);
    $p = strpos($resp, "\r\n\r\n");
    if ($p === false) { return [$resp, [], '']; }
    $lines = explode("\r\n", substr($resp, 0, $p));
    $status = array_shift($lines);
    $h = [];
    foreach ($lines as $l) { $q = strpos($l, ':'); if ($q !== false) { $h[strtolower(trim(substr($l, 0, $q)))] = trim(substr($l, $q + 1)); } }
    return [$status, $h, substr($resp, $p + 4)];
}

function health(int $port): ?array {
    [$status, , $body] = raw_http($port, "GET /health HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nConnection: close\r\n\r\n");
    return str_starts_with($status, 'HTTP/1.1 200') ? (json_decode($body, true) ?: null) : null;
}

/** Start another ws.php against the same scratch database and wait (≤ 5 s) for it to exit. [exit code (null = still running, killed), output]. */
function second_server(string $tmp, int $port): array {
    $pr = proc_open([PHP_BINARY, "$tmp/ws.php", '--port', (string)$port, '--bind', '127.0.0.1'], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pp, $tmp, ['GT_PK_STUB' => '1'] + getenv());
    if (!is_resource($pr)) { return [null, 'proc_open failed']; }
    fclose($pp[0]);
    stream_set_blocking($pp[1], false); stream_set_blocking($pp[2], false);
    $out = ''; $code = null; $t0 = microtime(true);
    while (microtime(true) - $t0 < 5) {
        $out .= (string)stream_get_contents($pp[1]) . (string)stream_get_contents($pp[2]);
        $st = proc_get_status($pr);
        if (!$st['running']) { $code = $st['exitcode']; break; }
        usleep(50000);
    }
    if ($code === null) { proc_terminate($pr, SIGKILL); }
    $out .= (string)stream_get_contents($pp[1]) . (string)stream_get_contents($pp[2]);
    fclose($pp[1]); fclose($pp[2]); proc_close($pr);
    return [$code, $out];
}

function ticket_for(int $pid, string $name, array $extra = []): string {
    return rt_ticket_make(['uid' => 'p' . $pid, 'pid' => $pid, 'name' => $name] + $extra);
}
function guest_ticket(): string {
    $g = bin2hex(random_bytes(4));
    return rt_ticket_make(['uid' => 'g' . $g, 'pid' => 0, 'name' => 'Guest ' . substr($g, 0, 4)]);
}

/* ───────────────────────── a small WebSocket client (RFC 6455, masked client frames) ───────────────────────── */

final class WsClient {
    public $s = null;
    public string $status = '';
    public array $headers = [];
    public string $buf = '';
    public array $inbox = [];      // decoded messages not consumed yet
    public array $seen = [];       // every decoded message, for scans
    public array $pings = [], $pongs = [];
    public ?int $closeCode = null;
    public bool $eof = false;
    public bool $autoPong = true;
    public string $label = '';

    public static function open(int $port, ?string $origin = 'http://localhost:8100', ?string $key = null, string $label = ''): self {
        $c = new self();
        $c->label = $label;
        $c->s = @stream_socket_client("tcp://127.0.0.1:$port", $errno, $errstr, 3);
        if (!$c->s) { throw new RuntimeException("connect failed: $errstr"); }
        stream_set_timeout($c->s, 3);
        $key ??= base64_encode(random_bytes(16));
        $h = "GET / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: $key\r\nSec-WebSocket-Version: 13\r\n";
        if ($origin !== null) { $h .= "Origin: $origin\r\n"; }
        fwrite($c->s, $h . "\r\n");
        $head = '';
        $deadline = microtime(true) + 3;
        while (!str_contains($head, "\r\n\r\n") && microtime(true) < $deadline) {
            $chunk = fread($c->s, 4096);
            if ($chunk === false || ($chunk === '' && feof($c->s))) { break; }
            if ($chunk === '') { usleep(5000); continue; }
            $head .= $chunk;
        }
        $p = strpos($head, "\r\n\r\n");
        if ($p === false) { $c->status = trim($head); $c->eof = true; return $c; }
        $c->buf = substr($head, $p + 4);
        $lines = explode("\r\n", substr($head, 0, $p));
        $c->status = (string)array_shift($lines);
        foreach ($lines as $l) { $q = strpos($l, ':'); if ($q !== false) { $c->headers[strtolower(trim(substr($l, 0, $q)))] = trim(substr($l, $q + 1)); } }
        stream_set_blocking($c->s, false);
        if (!$c->ok()) { $c->eof = true; }
        self::$all[] = $c;
        return $c;
    }

    public function ok(): bool { return str_starts_with($this->status, 'HTTP/1.1 101'); }

    public function frame(string $payload, int $op = 1, bool $mask = true, bool $fin = true): string {
        $len = strlen($payload);
        $h = chr(($fin ? 0x80 : 0) | $op);
        $m = $mask ? 0x80 : 0;
        if ($len < 126) { $h .= chr($m | $len); } elseif ($len < 65536) { $h .= chr($m | 126) . pack('n', $len); } else { $h .= chr($m | 127) . pack('J', $len); }
        if (!$mask) { return $h . $payload; }
        $key = random_bytes(4);
        return $h . $key . ($payload ^ substr(str_repeat($key, intdiv($len, 4) + 1), 0, $len));
    }

    public function sendRaw(string $bytes): void { if ($this->s) { @fwrite($this->s, $bytes); } }
    public function send(array $msg): void { $this->sendRaw($this->frame((string)json_encode($msg))); }

    /** @var self[] every open client: pumping any one of them services all of them (pongs keep the others alive) */
    public static array $all = [];

    /** Read for up to $secs, decoding frames for every open client; stops early when $until() is true. */
    public function pump(float $secs, ?callable $until = null): void {
        $deadline = microtime(true) + $secs;
        while (true) {
            if ($until && $until()) { return; }
            if ($this->eof) { return; }
            $left = $deadline - microtime(true);
            if ($left <= 0) { return; }
            $r = []; $by = [];
            foreach (self::$all as $c) { if (!$c->eof && $c->s) { $r[] = $c->s; $by[get_resource_id($c->s)] = $c; } }
            if (!$r) { return; }
            $w = null; $e = null;
            if (@stream_select($r, $w, $e, 0, (int)min(200000, $left * 1e6)) > 0) {
                foreach ($r as $s) {
                    $c = $by[get_resource_id($s)];
                    $d = fread($s, 65536);
                    if ($d === false || ($d === '' && feof($s))) { $c->eof = true; continue; }
                    $c->buf .= $d;
                    $c->parse();
                }
            }
        }
    }

    private function parse(): void {
        while (strlen($this->buf) >= 2) {
            $b0 = ord($this->buf[0]); $b1 = ord($this->buf[1]);
            $op = $b0 & 0x0f; $len = $b1 & 0x7f; $off = 2;
            if ($len === 126) { if (strlen($this->buf) < 4) { return; } $len = unpack('n', $this->buf, 2)[1]; $off = 4; }
            elseif ($len === 127) { if (strlen($this->buf) < 10) { return; } $len = unpack('J', $this->buf, 2)[1]; $off = 10; }
            if ($b1 & 0x80) { $off += 4; }
            if (strlen($this->buf) < $off + $len) { return; }
            $payload = substr($this->buf, $off, $len);
            $this->buf = (string)substr($this->buf, $off + $len);
            switch ($op) {
                case 1: $m = json_decode($payload, true); if (is_array($m)) { $this->inbox[] = $m; $this->seen[] = $m; } break;
                case 8: $this->closeCode = $len >= 2 ? unpack('n', $payload)[1] : 1005; break;
                case 9: $this->pings[] = $payload; if ($this->autoPong) { $this->sendRaw($this->frame($payload, 10)); } break;
                case 10: $this->pongs[] = $payload; break;
            }
        }
    }

    /** The next message of type $t (optionally matching $pred) within $secs; other messages stay queued in order. */
    public function waitFor(string $t, float $secs = 3.0, ?callable $pred = null): ?array {
        $deadline = microtime(true) + $secs;
        while (true) {
            foreach ($this->inbox as $i => $m) {
                if (($m['t'] ?? '') === $t && (!$pred || $pred($m))) { unset($this->inbox[$i]); $this->inbox = array_values($this->inbox); return $m; }
            }
            $left = $deadline - microtime(true);
            if ($left <= 0 || $this->eof) { return null; }
            $n = count($this->inbox);
            $this->pump(min($left, 0.25), fn() => count($this->inbox) > $n || $this->closeCode !== null);
        }
    }

    /** Close code from the server (or -1 for a bare EOF), null when still open after $secs. */
    public function waitClose(float $secs = 3.0): ?int {
        $this->pump($secs, fn() => $this->closeCode !== null || $this->eof);
        return $this->closeCode ?? ($this->eof ? -1 : null);
    }

    public function hello(string $ticket, string $room = 'floor'): ?array {
        $this->send(['t' => 'hello', 'ticket' => $ticket, 'room' => $room]);
        return $this->waitFor('welcome');
    }

    public function close(): void {
        if ($this->s) { @fclose($this->s); }
        $this->eof = true;
        self::$all = array_values(array_filter(self::$all, fn($c) => $c !== $this));
    }
}

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
$logPath = "$tmp/server.log";
$log = fopen($logPath, 'wb');
$cmd = [PHP_BINARY, "$tmp/ws.php", '--port', (string)$port, '--bind', '127.0.0.1', '--idle', '3', '--away', '2', '--tick', '20', '--verbose'];
$proc = proc_open($cmd, [0 => ['pipe', 'r'], 1 => $log, 2 => $log], $pipes, $tmp, ['GT_PK_STUB' => '1'] + getenv());
if (!is_resource($proc)) { fwrite(STDERR, "cannot start ws.php\n"); exit(1); }
$h = null;
for ($i = 0; $i < 100 && !$h; $i++) { usleep(100000); $h = health($port); }
check((bool)$h && $h['ok'] === true, "ws.php is up on 127.0.0.1:$port and answers GET /health", (string)file_get_contents($logPath));
if (!$h) { proc_terminate($proc); exit(1); }
check(count($h['tables'] ?? []) === 3 && isset($h['tables'][0]['id'], $h['tables'][0]['seated'], $h['tables'][0]['hand_no']), '/health lists the 3 seeded tables with id/seated/hand_no', short($h));
check(str_contains((string)file_get_contents($logPath), 'STUB active'), 'the stub engine announces itself loudly in the log');
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

// a second ws.php against the same database (double launch, restart overlap) must exit before it "recovers" A's live seat
$ledgerN = (int)val('SELECT COUNT(*) FROM ledger WHERE player_id = ?', [$A]);
[$code2, $out2] = second_server($tmp, free_port());   // another port: only the database is shared
check($code2 !== null && $code2 !== 0 && str_contains($out2, 'already owns'), 'a second ws.php on another port refuses to start: the database already has a server', short([$code2, substr($out2, -200)]));
[$code3] = second_server($tmp, $port);                // the same port
check($code3 !== null && $code3 !== 0, 'a second ws.php on the same port exits non-zero', short($code3));
check($balance($A) === 9000 && (int)($seatRow($A)['stack'] ?? 0) === 1000 && (int)val('SELECT COUNT(*) FROM ledger WHERE player_id = ?', [$A]) === $ledgerN, 'neither touched the ledger: A still has 9000 GC in the bank and 1000 GC on the table, no phantom "table reset" refund', short([$balance($A), $seatRow($A)]));
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
            unset($cl->inbox[$i]);
            $tbl = $m['table'];
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
        if ($m['t'] !== 'pk_state' || ($m['table']['id'] ?? 0) !== 1) { continue; }
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
check($stacks['p' . $A] + $stacks['p' . $B] === 2000, 'chips are conserved: 1000 + 1000 in, same out', short($stacks));

// hand 2 ends without a showdown: the first player to act folds. The winner never showed, so nobody else may see the winning hole cards
$a->inbox = []; $b->inbox = [];
$started2 = false; $folded = null; $ended2 = null; $mine2 = []; $deadline = microtime(true) + 12;
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
        }
        $cl->inbox = array_values($cl->inbox);
    }
}
$stacks = ['p' . $A => (int)($seatRow($A)['stack'] ?? -1), 'p' . $B => (int)($seatRow($B)['stack'] ?? -1)];
$a->send(['t' => 'pk_leave']);   // now, before the next hand deals A in again; the checks below read what has already arrived
check($ended2 !== null && $folded !== null, 'hand 2: the first player to act folded and the hand ended uncontested', short([$folded, $ended2]));
check($stacks['p' . $A] + $stacks['p' . $B] === 2000, 'chips are still conserved after the uncontested pot', short($stacks));
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

$bal = $a->waitFor('bal', 6);
check($bal !== null && $bal['balance'] === 9000 + $stacks['p' . $A] && $balance($A) === $bal['balance'] && !$seatRow($A), 'pk_leave cashes out: stack back to the balance, seat row gone', short([$bal, $balance($A)]));
$led = row("SELECT * FROM ledger WHERE player_id = ? AND kind = 'payout' ORDER BY id DESC LIMIT 1", [$A]);
check($led && $led['game'] === 'poker' && str_starts_with($led['detail'], 'cash-out'), 'cash-out is a poker payout in the ledger', short($led));
$stackB = (int)$seatRow($B)['stack'];
$b->close();   // vanish without a word: the away window (2 s in this run) must cash B out
$t0 = microtime(true);
while (microtime(true) - $t0 < 6 && $seatRow($B)) { $a->pump(0.1); }
check(!$seatRow($B) && $balance($B) === 500 + $stackB, 'a disconnected player is cashed out after the away window', short([$balance($B), $stackB]));
check(str_contains((string)file_get_contents($logPath), 'away p' . $B), 'the log records the away period');
$g->inbox = [];   // drop the states buffered while the hand ran
$g->send(['t' => 'pk_watch', 'table' => 1]);
$st = $g->waitFor('pk_state', 3, fn($m) => $m['table']['players'] === []);
check($st !== null && $st['table']['phase'] === 'idle', 'the table is empty again', short($st['table'] ?? null));

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
$c = WsClient::open($port); $c->hello(ticket_for($A, 'wstest_a'));
$c->send(['t' => 'pk_join', 'table' => 2, 'seat' => 3, 'buyin' => 5000]);
$c->waitFor('bal');
check($seatRow($A) && (int)$seatRow($A)['stack'] === 5000, 'a player is seated at table 2 when SIGTERM arrives');
proc_terminate($proc, SIGTERM);
$code = $c->waitClose(3);
check($code === 1001, 'clients get close 1001 on shutdown', (string)$code);
$t0 = microtime(true); $status = proc_get_status($proc);
while ($status['running'] && microtime(true) - $t0 < 5) { usleep(100000); $status = proc_get_status($proc); }
check(!$status['running'] && $status['exitcode'] === 0, 'ws.php exits 0 on SIGTERM', short($status));
check(!$seatRow($A) && $balance($A) === 9000 + $stacks['p' . $A], 'shutdown refunded the seated player', short([$balance($A)]));
check(str_contains((string)file_get_contents($logPath), 'bye'), 'the log ends with bye');
check(!row('SELECT 1 FROM poker_seats'), 'poker_seats is empty after shutdown');

/* ───────────────────────── summary ───────────────────────── */

fclose($log);
proc_close($proc);
$rm = function (string $d) use (&$rm): void { foreach (scandir($d) ?: [] as $f) { if ($f === '.' || $f === '..') { continue; } is_dir("$d/$f") ? $rm("$d/$f") : @unlink("$d/$f"); } @rmdir($d); };
if ($fail) { echo "\nserver log kept at $logPath\n"; } else { $rm($tmp); }
echo "\n$pass passed, $fail failed" . ($fail ? ":\n  - " . implode("\n  - ", $failures) : '') . "\n";
exit($fail ? 1 : 0);
