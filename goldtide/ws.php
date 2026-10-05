#!/usr/bin/env php
<?php
/**
 * SLOP CASINO realtime server: the floor, chat and every live poker table over one WebSocket.
 *
 *     php ws.php [--port 8081] [--bind 0.0.0.0] [--tick 50] [--idle 40] [--away 90] [--max 500] [--verbose]
 *     php ws.php --help
 *
 * One process, one stream_select() loop, no threads, no dependencies. Run it next to index.php (it includes it
 * headlessly with GT_NO_ROUTE, so it shares the database, tx()/move_coins(), settings, tickets and the poker
 * engine, the pk_* functions), as the same user the web server writes data/ as, one copy per database. Settings
 * (rt_origins, poker_action_seconds) are read once at start-up: restart after changing them. Logs go to stdout
 * and data/ws.log; GET /health on the socket port is a plain HTTP monitor. The contract with the engine and the
 * browser clients is REALTIME.md; keep the three in step.
 *
 * How it drives the engine: pk_tick($t, now) on every loop tick and pk_view() after it (one pk_events and one
 * pk_state per viewer per changed table per tick). pk_sit / pk_leave / pk_sitout / pk_away / pk_post only queue
 * their events for the next pk_tick, so the table is marked dirty right after them and a fresh pk_state goes out
 * the same tick. pk_act is guarded by the hand/seq echo; every DomainException the engine throws goes back to that
 * client as pk_err with the state untouched. A disconnected player is pk_away(true) (dealt out, no blinds) and
 * pk_away(false) again on a reconnect inside the away window.
 *
 * What it persists, and when:
 *   poker_seats  one row per real seated player: written with the buy-in (same tx() as the 'wager'), += add-on,
 *                set to the end-of-hand stack at hand_end, deleted in the same tx() as the cash-out payout. So
 *                between hands the row is the stack in front of the player; during a hand it is the stack the
 *                hand started with.
 *   poker_hands  one row per finished hand with pk_hand_record() as JSON. Written when pk_tick returns hand_end,
 *                in ONE tx() in this order: the hand row, UPDATE poker_seats.stack from the record's end stacks,
 *                pay every leavers[seat] (move_coins +stack 'payout' + DELETE the row), DELETE the rows of busted
 *                real players, record_round(pid, start − end + won, won) per real player. Then busted bots rebuy
 *                (pk_addon) and players who disconnected during the hand are cashed out; the engine only deals the
 *                next hand on the following tick, so all of that lands before it.
 *   ledger       via move_coins() inside tx() only: 'wager' (buy-in, add-on), 'payout' ("cash-out …" for a leave,
 *                a mid-hand leave paid at hand_end, a disconnected player, a closed table; "table reset" for the
 *                start-up / shutdown refunds).
 * Refund rule, an interrupted hand is void: on start-up and on SIGINT/SIGTERM every poker_seats row still there
 * is paid back at what the row says (the start-of-hand stack), never at a live mid-hand stack. Only the process
 * that owns the database may do that: run() takes an exclusive flock on data/ws.lock and binds the listening
 * socket BEFORE it touches a single row, so a second copy (double launch, restart overlap, two servers on one
 * database) exits without refunding seats the live server still holds. Every path pays exactly once because a
 * payout and the DELETE of the seat row always share one tx(). Bots (pid 0) never touch the ledger. Nothing here
 * calls fail()/redirect()/json_out(): those exit.
 *
 * Environment (tests shorten the timers): GT_WS_IDLE, GT_WS_AWAY (seconds).
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
define('GT_NO_ROUTE', 1);
require __DIR__ . '/index.php';

// index.php installs a web exception handler (prints JSON/HTML, exits). The server just logs and dies loudly.
set_exception_handler(function (Throwable $e): void {
    ws_log('FATAL ' . $e::class . ': ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
    exit(1);
});

define('GT_POKER', function_exists('pk_new_table'));   // an index.php without the engine hosts the floor only

/** One line to stdout and to data/ws.log (rotated to ws.log.1 above 5 MB). */
function ws_log(string $msg): void {
    static $fh = null, $n = 0;
    $t = microtime(true);
    $line = '[' . gmdate('Y-m-d H:i:s', (int)$t) . sprintf('.%03d', (int)(($t - floor($t)) * 1000)) . '] ' . $msg . "\n";
    fwrite(STDOUT, $line);
    $file = DATA_DIR . '/ws.log';
    if ($fh === null || ++$n % 200 === 0) {
        clearstatcache(true, $file);
        if ($fh && is_file($file) && filesize($file) > 5 * 1024 * 1024) { fclose($fh); @rename($file, $file . '.1'); $fh = null; }
        $fh ??= @fopen($file, 'ab') ?: false;
    }
    if ($fh) { fwrite($fh, $line); }
}

function ws_usage(): string {
    return "Slop Casino realtime server\n  php ws.php [--port 8081] [--bind 0.0.0.0] [--tick 50] [--idle 40] [--away 90] [--max 500] [--verbose]\n"
        . "  --tick  loop period in ms        --idle  close silent sockets after N s (ping at N/2)\n"
        . "  --away  cash out a disconnected player after N s (0 = at once)   --max  client cap\n";
}

/** --key value / --key=value / --verbose. Env GT_WS_IDLE / GT_WS_AWAY seed the timers; flags win. */
function ws_options(array $argv): array {
    $o = ['port' => 8081, 'bind' => '0.0.0.0', 'tick' => 50, 'idle' => (int)(getenv('GT_WS_IDLE') ?: 40),
          'away' => getenv('GT_WS_AWAY') !== false ? (int)getenv('GT_WS_AWAY') : 90, 'max' => 500, 'verbose' => false];
    for ($i = 1, $n = count($argv); $i < $n; $i++) {
        $a = $argv[$i];
        if ($a === '--verbose' || $a === '-v') { $o['verbose'] = true; continue; }
        if ($a === '--help' || $a === '-h') { echo ws_usage(); exit(0); }
        if (!preg_match('/^--([a-z]+)(?:=(.*))?$/', $a, $m) || !isset($o[$m[1]]) || $m[1] === 'verbose') { fwrite(STDERR, "Unknown option $a\n" . ws_usage()); exit(2); }
        $v = $m[2] ?? ($argv[++$i] ?? null);
        if ($v === null) { fwrite(STDERR, "--{$m[1]} needs a value\n"); exit(2); }
        $o[$m[1]] = $m[1] === 'bind' ? $v : (int)$v;
    }
    if ($o['port'] < 1 || $o['port'] > 65535 || $o['tick'] < 5 || $o['tick'] > 1000 || $o['idle'] < 2 || $o['away'] < 0 || $o['max'] < 1) {
        fwrite(STDERR, "Option out of range\n" . ws_usage()); exit(2);
    }
    return $o;
}

/* ───────────────────────── per-connection state ───────────────────────── */

final class GTClient {
    public string $rbuf = '', $wbuf = '';
    public bool $shook = false;          // HTTP upgrade done
    public bool $closing = false;        // close frame / HTTP reply sent, waiting for the flush + peer EOF
    public bool $shut = false;           // write side shut down after the flush
    public float $closeAt = 0;
    public ?string $uid = null;          // set by hello
    public int $pid = 0;
    public string $name = '';
    public bool $guest = true, $brk = false;
    public string $room = '';            // '' until hello, then 'floor' | 'poker'
    public array $pos = [0.0, 0.0, 0.0, 0];   // x, z, ry, a
    public ?string $st = null;           // station id shown to others
    public bool $dirty = false;          // moved since the last snap
    public float $lastRecv, $lastPing = 0, $posWin = 0;
    public int $posN = 0, $strikes = 0, $fragOp = 0;
    public string $fragBuf = '';
    public array $chatTimes = [];        // send times inside the last minute
    public array $rl = [];               // kind => [window start, count] for the per-second limiters (seat, sitout)
    public array $watch = [];            // poker table id => true

    public function __construct(public int $id, public $sock, public string $ip, public float $connectedAt) {
        $this->lastRecv = $connectedAt;
    }
}

/* ───────────────────────── the server ───────────────────────── */

final class GTServer {
    private const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
    private const MAX_MSG = 8192;
    private const MAX_WBUF = 524288;
    private const BOT_NAMES = ['Marina', 'Dutch', 'Rosie', 'Sal', 'Tino', 'Birdie', 'Lupe', 'Hank', 'Coco', 'Ray', 'Nita', 'Gus', 'Pearl', 'Mo', 'Vera', 'Ike'];

    private $srv = null;
    private $lock = null;          // data/ws.lock handle, held for the life of the process (see lockOrExit)
    private array $clients = [];   // id => GTClient
    private array $bySock = [];    // resource id => client id
    private array $byUid = [];     // uid => [client id => true]
    private array $nonces = [];    // ticket nonce => accepted at
    private array $tables = [];    // table id => hosting record, see pkHost()
    private array $seatOf = [];    // uid => ['tid', 'seat', 'pid'] for real players; a mid-hand leaver keeps its entry until hand_end pays it
    private int $nextId = 1;
    private float $now;
    private float $lastSnap = 0, $lastHouse = 0, $lastReload = 0, $lastOnline = 0, $lastTables = 0;
    private bool $onlineDirty = false, $tablesDirty = false, $stop = false;
    private int $tickUs;

    public function __construct(private array $opt) {
        $this->now = microtime(true);
        $this->tickUs = $opt['tick'] * 1000;
    }

    private function v(string $msg): void { if ($this->opt['verbose']) { ws_log($msg); } }

    public function run(): void {
        db();
        if (!GT_POKER) { ws_log('WARNING: no poker engine (pk_* functions missing): hosting the floor only, poker messages get pk_err.'); }
        // Ownership first, ledger last: the lock keeps a second copy off this database and the bound socket proves
        // this process is the server. Failing either step exits here with nothing written; the live server's seats stand.
        $this->lockOrExit();
        $ctx = stream_context_create(['socket' => ['so_reuseaddr' => true, 'backlog' => 128, 'tcp_nodelay' => true]]);
        $bind = $this->opt['bind'];
        if (str_contains($bind, ':') && $bind[0] !== '[') { $bind = "[$bind]"; }   // IPv6 literal
        $addr = 'tcp://' . $bind . ':' . $this->opt['port'];
        $this->srv = @stream_socket_server($addr, $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx);
        if (!$this->srv) { ws_log("Cannot listen on $addr: $errstr ($errno)"); exit(1); }
        stream_set_blocking($this->srv, false);
        $this->refundAllSeats('table reset');
        if (GT_POKER) { $this->pkLoadTables(); }
        if (function_exists('pcntl_async_signals')) {   // clean shutdown on Ctrl-C / systemd stop; without pcntl the startup refund covers a hard stop
            pcntl_async_signals(true);
            foreach ([SIGINT, SIGTERM] as $sig) { pcntl_signal($sig, function () { $this->stop = true; }); }
        } else { ws_log('pcntl not available: Ctrl-C ends without the shutdown refund; the next start refunds every seat instead'); }
        ws_log("listening on ws://{$this->opt['bind']}:{$this->opt['port']}/  tick {$this->opt['tick']} ms, idle {$this->opt['idle']} s, away {$this->opt['away']} s, tables " . count($this->tables));
        while (!$this->stop) { $this->tick(); }
        $this->shutdown();
    }

    /**
     * One server per database: an exclusive, non-blocking flock on data/ws.lock, kept on $this->lock so the handle
     * (and with it the lock) lives exactly as long as the process. Two servers on one database would each "recover"
     * the other's live seats and pay every stack out twice; the loser exits 1 before it has touched the ledger.
     */
    private function lockOrExit(): void {
        $file = DATA_DIR . '/ws.lock';
        $fh = @fopen($file, 'c+');
        if (!$fh) { ws_log("Cannot open $file for the instance lock"); exit(1); }
        if (!flock($fh, LOCK_EX | LOCK_NB)) {
            $owner = trim((string)stream_get_contents($fh));
            ws_log('Another ws.php already owns ' . DB_FILE . ($owner !== '' ? " (pid $owner)" : '') . ': not starting, nothing refunded');
            fclose($fh);
            exit(1);
        }
        ftruncate($fh, 0); fwrite($fh, getmypid() . "\n"); fflush($fh);
        $this->lock = $fh;
    }

    /** One loop iteration: wait up to one tick for socket activity, then run the timers. */
    private function tick(): void {
        $r = [$this->srv]; $w = []; $e = null;
        foreach ($this->clients as $c) { $r[] = $c->sock; if ($c->wbuf !== '') { $w[] = $c->sock; } }
        $n = @stream_select($r, $w, $e, 0, $this->tickUs);
        $this->now = microtime(true);
        if ($n === false) { return; }   // EINTR from a signal: run() checks the stop flag
        foreach ($r as $s) {
            if ($s === $this->srv) { $this->accept(); continue; }
            $c = $this->clients[$this->bySock[get_resource_id($s)] ?? 0] ?? null;
            if ($c) { $this->readFrom($c); }
        }
        foreach ($w as $s) {
            $c = $this->clients[$this->bySock[get_resource_id($s)] ?? 0] ?? null;
            if ($c) { $this->flush($c); }
        }
        if ($this->now - $this->lastHouse >= 0.5) { $this->housekeeping(); }
        if ($this->now - $this->lastSnap >= 0.1) { $this->snapshot(); }
        if (GT_POKER) { $this->pkTick(); }
        $this->debounced();
    }

    private function accept(): void {
        while (($s = @stream_socket_accept($this->srv, 0, $peer)) !== false) {
            stream_set_blocking($s, false);
            if (count($this->clients) >= $this->opt['max']) {
                @fwrite($s, "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
                @fclose($s);
                continue;
            }
            $c = new GTClient($this->nextId++, $s, (string)$peer, $this->now);
            $this->clients[$c->id] = $c;
            $this->bySock[get_resource_id($s)] = $c->id;
            $this->v("open #{$c->id} from $peer");
        }
    }

    private function readFrom(GTClient $c): void {
        $data = @fread($c->sock, 65536);
        if ($data === false || ($data === '' && feof($c->sock))) { $this->drop($c, $c->closing ? 'closed' : 'eof'); return; }
        if ($data === '') { return; }
        if ($c->closing) { return; }   // draining until the peer's close/EOF; nothing more is processed
        $c->rbuf .= $data;
        $c->lastRecv = $this->now;
        try {
            if (!$c->shook) { $this->handshake($c); }
            if ($c->shook && !$c->closing) { $this->parseFrames($c); }
            if (strlen($c->rbuf) > 65536) { $this->close($c, 1009, 'too much unread data'); }
        } catch (Throwable $e) {
            ws_log("client #{$c->id} error: " . $e::class . ': ' . $e->getMessage() . ' @ ' . basename($e->getFile()) . ':' . $e->getLine());
            $this->close($c, 1011, 'server error');
        }
    }

    /** Write what we can now, buffer the rest; a peer that lets 512 KB pile up is too slow to keep. */
    private function raw(GTClient $c, string $bytes): void {
        if ($c->shut || !isset($this->clients[$c->id])) { return; }
        if ($c->wbuf === '') {
            $n = @fwrite($c->sock, $bytes);
            if ($n === false) { $this->drop($c, 'write error'); return; }
            $bytes = (string)substr($bytes, $n);
        }
        $c->wbuf .= $bytes;
        if (strlen($c->wbuf) > self::MAX_WBUF) { $this->drop($c, 'too slow'); return; }
        if ($c->wbuf === '' && $c->closing) { $this->shutWrite($c); }
    }

    private function flush(GTClient $c): void {
        if ($c->wbuf === '') { return; }
        $n = @fwrite($c->sock, $c->wbuf);
        if ($n === false) { $this->drop($c, 'write error'); return; }
        if ($n > 0) { $c->wbuf = (string)substr($c->wbuf, $n); }
        if ($c->wbuf === '' && $c->closing) { $this->shutWrite($c); }
    }

    /** Half-close after a close frame / HTTP reply is flushed; the peer's EOF (or the 1 s timer) drops the socket. */
    private function shutWrite(GTClient $c): void {
        if ($c->shut) { return; }
        $c->shut = true;
        @stream_socket_shutdown($c->sock, STREAM_SHUT_WR);
    }

    private function send(GTClient $c, array $msg): void {
        $this->raw($c, $this->frame((string)json_encode($msg, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE)));
    }

    private function sendUid(string $uid, array $msg): void {
        foreach (array_keys($this->byUid[$uid] ?? []) as $cid) { if (isset($this->clients[$cid])) { $this->send($this->clients[$cid], $msg); } }
    }

    private function broadcast(string $room, array $msg, int $except = 0): void {
        $f = $this->frame((string)json_encode($msg, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE));
        foreach ($this->clients as $c) {
            if ($c->id !== $except && ($room === '*' ? $c->room !== '' : $c->room === $room)) { $this->raw($c, $f); }
        }
    }

    /* ───────────────────────── HTTP upgrade ───────────────────────── */

    private function handshake(GTClient $c): void {
        $end = strpos($c->rbuf, "\r\n\r\n");
        if ($end === false) {
            if (strlen($c->rbuf) > self::MAX_MSG) { $this->httpReply($c, 431, 'Request header too large'); }
            return;
        }
        $head = substr($c->rbuf, 0, $end);
        $c->rbuf = (string)substr($c->rbuf, $end + 4);
        if (strlen($head) > self::MAX_MSG) { $this->httpReply($c, 431, 'Request header too large'); return; }
        $lines = explode("\r\n", $head);
        $req = (string)array_shift($lines);
        if (!preg_match('#^([A-Z]+) (\S+) HTTP/1\.[01]$#', $req, $m)) { $this->httpReply($c, 400, 'Bad request'); return; }
        $h = [];
        foreach ($lines as $l) {
            $p = strpos($l, ':');
            if ($p !== false) { $h[strtolower(trim(substr($l, 0, $p)))] = trim(substr($l, $p + 1)); }
        }
        $path = parse_url($m[2], PHP_URL_PATH) ?: '/';
        $upgrade = strtolower($h['upgrade'] ?? '') === 'websocket' && str_contains(strtolower($h['connection'] ?? ''), 'upgrade');
        if ($m[1] === 'GET' && !$upgrade && $path === '/health') {
            $this->httpReply($c, 200, (string)json_encode($this->health(), JSON_UNESCAPED_SLASHES), 'application/json');
            return;
        }
        if ($m[1] !== 'GET' || !$upgrade) { $this->httpReply($c, $m[1] === 'GET' ? 426 : 405, 'This is a WebSocket endpoint', 'text/plain', "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"); return; }
        if (($h['sec-websocket-version'] ?? '') !== '13') { $this->httpReply($c, 426, 'Unsupported WebSocket version', 'text/plain', "Sec-WebSocket-Version: 13\r\n"); return; }
        $key = $h['sec-websocket-key'] ?? '';
        if (strlen((string)base64_decode($key, true)) !== 16) { $this->httpReply($c, 400, 'Bad Sec-WebSocket-Key'); return; }
        if (!$this->originOk($h['origin'] ?? null, $h['host'] ?? '')) {
            ws_log('403 origin ' . ($h['origin'] ?? '-') . ' host ' . ($h['host'] ?? '-') . " from {$c->ip}");
            $this->httpReply($c, 403, 'Origin not allowed');
            return;
        }
        $accept = base64_encode(sha1($key . self::WS_GUID, true));
        $this->raw($c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: $accept\r\n\r\n");
        $c->shook = true;
        $this->v("upgrade #{$c->id} origin " . ($h['origin'] ?? '-'));
    }

    /**
     * Origin policy (REALTIME.md → Security rules): the rt_origins setting is the allow-list when set. Otherwise the
     * Host header the socket was reached on decides: http(s)://<host> exactly, or any port when the host is
     * localhost / 127.0.0.1 / ::1 / a bare IP (dev boxes). A request without an Origin header is not a browser;
     * the ticket is its credential, so it is let through.
     */
    private function originOk(?string $origin, string $host): bool {
        if ($origin === null || $origin === '') { return true; }
        $origin = strtolower(rtrim(trim($origin), '/'));
        $allowed = array_values(array_filter(array_map(fn($s) => strtolower(rtrim(trim($s), '/')), explode(',', setting('rt_origins')))));
        if ($allowed) { return in_array($origin, $allowed, true); }
        $host = strtolower(trim($host));
        if ($host === '' || !preg_match('/^[a-z0-9.\-\[\]:]{1,253}$/', $host)) { return false; }
        $po = parse_url($origin);
        if (!$po || empty($po['host']) || !in_array($po['scheme'] ?? '', ['http', 'https'], true)) { return false; }
        if ($origin === 'http://' . $host || $origin === 'https://' . $host) { return true; }
        $name = trim((string)preg_replace('/:\d+$/', '', $host), '[]');
        $ohost = trim(strtolower($po['host']), '[]');
        $local = ['localhost', '127.0.0.1', '::1'];
        if (in_array($name, $local, true)) { return in_array($ohost, $local, true); }
        if (filter_var($name, FILTER_VALIDATE_IP)) { return $ohost === $name; }
        return false;
    }

    private function httpReply(GTClient $c, int $code, string $body, string $type = 'text/plain', string $extra = ''): void {
        $text = [200 => 'OK', 400 => 'Bad Request', 403 => 'Forbidden', 405 => 'Method Not Allowed', 426 => 'Upgrade Required', 431 => 'Request Header Fields Too Large'][$code] ?? 'Error';
        $c->closing = true;
        $c->closeAt = $this->now + 1;
        $this->raw($c, "HTTP/1.1 $code $text\r\nContent-Type: $type; charset=utf-8\r\nContent-Length: " . strlen($body) . "\r\nCache-Control: no-store\r\nConnection: close\r\n$extra\r\n$body");
    }

    private function health(): array {
        $tables = [];
        foreach ($this->tables as $tid => $T) { $tables[] = ['id' => $tid, 'seated' => count($T['t']['players']), 'hand_no' => (int)$T['t']['hand_no']]; }
        return ['ok' => true, 'online' => $this->onlineCount(), 'tables' => $tables];
    }

    /* ───────────────────────── RFC 6455 frames ───────────────────────── */

    /** Server frames are never masked. 7 / 16 / 64-bit length forms. */
    private function frame(string $payload, int $op = 1): string {
        $len = strlen($payload);
        $head = chr(0x80 | $op);
        if ($len < 126) { $head .= chr($len); }
        elseif ($len < 65536) { $head .= chr(126) . pack('n', $len); }
        else { $head .= chr(127) . pack('J', $len); }
        return $head . $payload;
    }

    private function parseFrames(GTClient $c): void {
        while (!$c->closing && isset($this->clients[$c->id])) {
            $buf = $c->rbuf;
            $len = strlen($buf);
            if ($len < 2) { return; }
            $b0 = ord($buf[0]); $b1 = ord($buf[1]);
            $fin = ($b0 & 0x80) !== 0; $op = $b0 & 0x0f;
            $masked = ($b1 & 0x80) !== 0; $plen = $b1 & 0x7f; $off = 2;
            if ($b0 & 0x70) { $this->close($c, 1002, 'reserved bits set'); return; }
            if ($plen === 126) { if ($len < 4) { return; } $plen = unpack('n', $buf, 2)[1]; $off = 4; }
            elseif ($plen === 127) { if ($len < 10) { return; } $plen = unpack('J', $buf, 2)[1]; $off = 10; if ($plen < 0) { $this->close($c, 1009, 'frame too large'); return; } }
            if (!$masked) { $this->close($c, 1002, 'client frames must be masked'); return; }
            if ($plen > self::MAX_MSG || strlen($c->fragBuf) + $plen > self::MAX_MSG) { $this->close($c, 1009, 'message too large'); return; }
            if ($op >= 8 && (!$fin || $plen > 125)) { $this->close($c, 1002, 'bad control frame'); return; }
            if ($len < $off + 4 + $plen) { return; }   // wait for the rest of the frame
            $key = substr($buf, $off, 4);
            $payload = (string)substr($buf, $off + 4, $plen);
            $c->rbuf = (string)substr($buf, $off + 4 + $plen);
            if ($plen) { $payload ^= substr(str_repeat($key, intdiv($plen, 4) + 1), 0, $plen); }
            switch ($op) {
                case 0:   // continuation
                    if ($c->fragOp === 0) { $this->close($c, 1002, 'unexpected continuation'); return; }
                    $c->fragBuf .= $payload;
                    if ($fin) { $whole = $c->fragBuf; $c->fragBuf = ''; $c->fragOp = 0; $this->handleText($c, $whole); }
                    break;
                case 1:   // text
                    if ($c->fragOp !== 0) { $this->close($c, 1002, 'fragment interleaving'); return; }
                    if ($fin) { $this->handleText($c, $payload); } else { $c->fragOp = 1; $c->fragBuf = $payload; }
                    break;
                case 2: $this->close($c, 1003, 'binary frames not accepted'); return;
                case 8:
                    $code = $plen >= 2 ? unpack('n', $payload)[1] : 1005;
                    $this->v("close from #{$c->id} code $code");
                    $this->raw($c, $this->frame($plen >= 2 ? substr($payload, 0, 2) : '', 8));
                    $this->drop($c, 'peer close');
                    return;
                case 9: $this->raw($c, $this->frame($payload, 10)); break;   // ping → pong, same payload
                case 10: break;                                             // pong: lastRecv already bumped
                default: $this->close($c, 1002, 'bad opcode'); return;
            }
        }
    }

    /** Send a close frame; the socket is dropped when the peer answers (or after 1 s). */
    private function close(GTClient $c, int $code, string $reason = ''): void {
        if ($c->closing || !isset($this->clients[$c->id])) { return; }
        $c->closing = true;
        $c->closeAt = $this->now + 1;
        $c->rbuf = '';
        $this->v("close #{$c->id} $code $reason");
        $this->raw($c, $this->frame(pack('n', $code) . substr($reason, 0, 120), 8));
    }

    /** Forget the connection: maps, presence, poker seat (goes 'away'), online count. */
    private function drop(GTClient $c, string $why): void {
        if (!isset($this->clients[$c->id])) { return; }
        unset($this->clients[$c->id], $this->bySock[get_resource_id($c->sock)]);
        @fclose($c->sock);
        $this->v("drop #{$c->id} ($why)" . ($c->uid ? " {$c->uid}" : ''));
        foreach (array_keys($c->watch) as $tid) { unset($this->tables[$tid]['watch'][$c->id]); }
        if ($c->uid === null) { return; }
        unset($this->byUid[$c->uid][$c->id]);
        if ($c->room === 'floor') { $this->broadcast('floor', ['t' => 'leave', 'id' => $c->id]); }
        if (empty($this->byUid[$c->uid])) {
            unset($this->byUid[$c->uid]);
            if (GT_POKER && isset($this->seatOf[$c->uid])) { $this->pkAway($c->uid); }
        }
        $this->onlineDirty = true;
    }

    /** Twice a second: handshake / hello deadlines, idle sockets, pings, stuck closes. */
    private function housekeeping(): void {
        $this->lastHouse = $this->now;
        $idle = $this->opt['idle'];
        $ping = max(1.0, $idle / 2);
        foreach ($this->clients as $c) {
            if ($c->closing) { if ($this->now >= $c->closeAt) { $this->drop($c, 'close timeout'); } continue; }
            if (!$c->shook) { if ($this->now - $c->connectedAt > 5) { $this->drop($c, 'handshake timeout'); } continue; }
            if ($c->room === '') { if ($this->now - $c->connectedAt > 5) { $this->close($c, 1008, 'hello timeout'); } continue; }
            if ($this->now - $c->lastRecv > $idle) { $this->close($c, 1001, 'idle'); continue; }
            if ($this->now - max($c->lastRecv, $c->lastPing) >= $ping) { $c->lastPing = $this->now; $this->raw($c, $this->frame('gt', 9)); }
        }
        if ($this->now - $this->lastReload >= 30) {
            $this->lastReload = $this->now;
            $this->nonces = array_filter($this->nonces, fn($at) => $this->now - $at < 120);
            if (GT_POKER) { $this->pkLoadTables(); }
        }
    }

    /* ───────────────────────── messages ───────────────────────── */

    /** A text message: must be valid UTF-8 JSON with a string `t`. Three strikes close the socket (1008). */
    private function handleText(GTClient $c, string $raw): void {
        $msg = mb_check_encoding($raw, 'UTF-8') ? json_decode($raw, true, 32) : null;
        if (!is_array($msg) || !is_string($msg['t'] ?? null)) {
            if (++$c->strikes >= 3) { $this->close($c, 1008, 'malformed messages'); }
            else { $this->send($c, ['t' => 'err', 'msg' => 'Malformed message.']); }
            return;
        }
        $t = $msg['t'];
        try {
            if ($c->room === '') {
                if ($t !== 'hello') { $this->close($c, 1008, 'hello first'); return; }
                $this->onHello($c, $msg);
                return;
            }
            switch ($t) {
                case 'hello': throw new DomainException('Already connected.');
                case 'pos': $this->onPos($c, $msg); break;
                case 'seat': $this->onSeat($c, $msg); break;
                case 'chat': $this->onChat($c, $msg); break;
                case 'ping': $this->send($c, ['t' => 'pong']); break;
                case 'pk_watch': $this->pkWatch($c, $msg, true); break;
                case 'pk_unwatch': $this->pkWatch($c, $msg, false); break;
                case 'pk_join': $this->pkJoin($c, $msg); break;
                case 'pk_addon': $this->pkAddon($c, $msg); break;
                case 'pk_leave': $this->pkLeave($c); break;
                case 'pk_sitout': $this->pkSitout($c, $msg); break;
                case 'pk_post': $this->pkPost($c, $msg); break;
                case 'pk_act': $this->pkAct($c, $msg); break;
                default: $this->v("ignored '$t' from #{$c->id}");   // unknown types are ignored (forward compatible)
            }
        } catch (DomainException $e) {
            // a rule the player bumped into, never a bug: tell them and carry on
            $this->send($c, ['t' => str_starts_with($t, 'pk_') ? 'pk_err' : 'err', 'msg' => $e->getMessage()]);
        }
    }

    /* ───────────────────────── the floor: hello, presence, chat ───────────────────────── */

    /** First message. The ticket (rt_ticket_make in index.php) is the only thing we trust; each nonce works once. */
    private function onHello(GTClient $c, array $m): void {
        $ticket = $m['ticket'] ?? null;
        $room = $m['room'] ?? 'floor';
        if (!is_string($ticket) || !in_array($room, ['floor', 'poker'], true)) { $this->close($c, 1008, 'bad hello'); return; }
        $p = rt_ticket_verify($ticket, (int)floor($this->now));
        $nonce = is_array($p) ? (string)$p['nonce'] : '';
        if (!$p || $nonce === '' || isset($this->nonces[$nonce])) {
            $this->v("hello #{$c->id} rejected: " . ($p ? 'nonce reused' : 'bad or expired ticket'));
            $this->close($c, 1008, $p ? 'ticket already used' : 'bad ticket');
            return;
        }
        $this->nonces[$nonce] = $this->now;
        $c->uid = (string)$p['uid'];
        $c->pid = max(0, (int)($p['pid'] ?? 0));
        $c->name = mb_substr(trim((string)$p['name']), 0, 24) ?: 'Player';
        $c->guest = $c->pid === 0 || !str_starts_with($c->uid, 'p');
        $c->brk = !empty($p['brk']);
        $c->room = $room;
        $this->byUid[$c->uid][$c->id] = true;
        $roster = [];
        if ($room === 'floor') {
            foreach ($this->clients as $o) { if ($o->room === 'floor' && $o->id !== $c->id) { $roster[] = $this->entry($o); } }
        }
        $this->send($c, ['t' => 'welcome', 'id' => $c->id, 'uid' => $c->uid, 'name' => $c->name, 'guest' => $c->guest,
            'players' => $roster, 'tables' => $this->pkSummaries(), 'online' => $this->onlineCount()]);
        if ($room === 'floor') { $this->broadcast('floor', ['t' => 'join', 'p' => $this->entry($c)], $c->id); }
        $this->onlineDirty = true;
        if (GT_POKER) { $this->pkReattach($c); }
        $this->v("hello #{$c->id} {$c->uid} '{$c->name}' room=$room" . ($c->guest ? ' guest' : '') . ($c->brk ? ' on-break' : ''));
    }

    /** Roster / join entry: [id, uid, name, x, z, ry, a, st]. */
    private function entry(GTClient $c): array {
        return [$c->id, $c->uid, $c->name, $c->pos[0], $c->pos[1], $c->pos[2], $c->pos[3], $c->st];
    }

    private static function num(mixed $v): float {
        if (is_int($v) || is_float($v)) { return is_finite((float)$v) ? (float)$v : 0.0; }
        return is_string($v) && is_numeric($v) && is_finite((float)$v) ? (float)$v : 0.0;
    }

    /** Position: clamped to the floor (±60), yaw to [-π, π], at most 15 updates a second; the rest are dropped. */
    private function onPos(GTClient $c, array $m): void {
        if ($c->room !== 'floor') { return; }
        if ($this->now - $c->posWin >= 1.0) { $c->posWin = $this->now; $c->posN = 0; }
        if (++$c->posN > 15) { return; }
        $x = max(-60.0, min(60.0, self::num($m['x'] ?? 0)));
        $z = max(-60.0, min(60.0, self::num($m['z'] ?? 0)));
        $ry = max(-M_PI, min(M_PI, self::num($m['ry'] ?? 0)));
        $a = max(0, min(3, (int)self::num($m['a'] ?? 0)));
        $c->pos = [round($x, 3), round($z, 3), round($ry, 3), $a];
        $c->dirty = true;
    }

    /** Every 100 ms: one snap with everyone who moved. */
    private function snapshot(): void {
        $this->lastSnap = $this->now;
        $ps = [];
        foreach ($this->clients as $c) {
            if ($c->dirty) { $c->dirty = false; if ($c->room === 'floor') { $ps[] = [$c->id, $c->pos[0], $c->pos[1], $c->pos[2], $c->pos[3]]; } }
        }
        if ($ps) { $this->broadcast('floor', ['t' => 'snap', 'ps' => $ps]); }
    }

    /** Per-connection limiter: at most $perSec messages of one kind inside a one-second window; the caller drops the rest. */
    private function allow(GTClient $c, string $kind, int $perSec): bool {
        if (!isset($c->rl[$kind]) || $this->now - $c->rl[$kind][0] >= 1.0) { $c->rl[$kind] = [$this->now, 0]; }
        return ++$c->rl[$kind][1] <= $perSec;
    }

    /**
     * Cosmetic station id (≤ 32 chars) so other avatars can be posed; null = stood up. Real poker seating is pk_join.
     * Every one of these fans out to the whole floor, so a repeat of the current station is ignored and at most 4
     * changes a second are relayed per connection: one client cannot turn its uplink into a broadcast storm.
     */
    private function onSeat(GTClient $c, array $m): void {
        if ($c->room !== 'floor') { return; }
        $st = $m['st'] ?? null;
        if ($st !== null) {
            if (!is_string($st)) { return; }
            $st = mb_substr((string)preg_replace('/[\x00-\x1F\x7F]/u', '', $st), 0, 32);
            if ($st === '') { $st = null; }
        }
        if ($st === $c->st || !$this->allow($c, 'seat', 4)) { return; }
        $c->st = $st;
        $this->broadcast('floor', ['t' => 'seat', 'id' => $c->id, 'st' => $st], $c->id);
    }

    /** Chat: trimmed, control characters stripped, 140 chars, 1 per 1.5 s and 10 per minute. */
    private function onChat(GTClient $c, array $m): void {
        if ($c->room !== 'floor') { return; }
        $text = $m['text'] ?? '';
        if (!is_string($text)) { return; }
        $text = mb_substr(trim((string)preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $text)), 0, 140);
        if ($text === '') { return; }
        $c->chatTimes = array_values(array_filter($c->chatTimes, fn($at) => $this->now - $at < 60));
        if (count($c->chatTimes) >= 10 || ($c->chatTimes && $this->now - end($c->chatTimes) < 1.5)) {
            throw new DomainException('Slow down.');
        }
        $c->chatTimes[] = $this->now;
        $this->broadcast('floor', ['t' => 'chat', 'id' => $c->id, 'name' => $c->name, 'text' => $text]);
        $this->v("chat #{$c->id} {$c->name}: " . mb_substr($text, 0, 40));
    }

    /** Distinct people (uids) past hello, both rooms; two tabs count once. */
    private function onlineCount(): int { return count($this->byUid); }

    /** 'online' and 'pk_tables' go out at most twice a second. */
    private function debounced(): void {
        if ($this->onlineDirty && $this->now - $this->lastOnline >= 0.5) {
            $this->onlineDirty = false; $this->lastOnline = $this->now;
            $this->broadcast('*', ['t' => 'online', 'n' => $this->onlineCount()]);
        }
        if ($this->tablesDirty && $this->now - $this->lastTables >= 0.5) {
            $this->tablesDirty = false; $this->lastTables = $this->now;
            $this->broadcast('*', ['t' => 'pk_tables', 'tables' => $this->pkSummaries()]);
        }
    }

    /* ───────────────────────── poker hosting: tables, bots, ticks, views ───────────────────────── */

    private function pkNeed(): void { if (!GT_POKER) { throw new DomainException('Poker is closed right now.'); } }

    /**
     * Hosting record per table. The engine state is 't' (only pk_* functions touch it, plus the between-hands
     * reconfiguration in pkApplyRow); everything else is ws.php bookkeeping:
     *   watch   connection ids watching (seated players' connections are added at send time)
     *   events  engine events since the last pk_state, flushed once per tick
     *   away    uid => ['since' => float] for disconnected players inside the grace window
     *   pending a changed poker_tables row waiting for the table to go idle; closing = disabled, emptying out;
     *   farewell = uids whose seat the engine just removed (paid at hand_end, busted, or cashed out at once): they
     *   still get this tick's pk_events and a closing pk_state (me null) even though they are no longer seated
     * act_secs is passed in explicitly (read once at start-up) so the engine never touches the database.
     */
    private function pkHost(array $row): void {
        $tid = (int)$row['id'];
        $t = pk_new_table($row + ['act_secs' => isetting('poker_action_seconds', 20)]);
        $this->tables[$tid] = ['row' => $row, 't' => $t, 'watch' => [], 'dirty' => true, 'events' => [], 'away' => [],
                               'closing' => false, 'pending' => null, 'farewell' => []];
        $this->pkBots($tid, (int)$row['bots']);
        $this->tablesDirty = true;
        ws_log("table $tid '{$row['name']}' open: {$t['seats']} seats, blinds {$t['sb']}/{$t['bb']}, buy-in {$t['min_buy']}-{$t['max_buy']}, bots {$row['bots']}");
    }

    /** A bot stack: random inside the buy-in range, rounded to the big blind. */
    private function pkBotStack(array $t): int {
        $bb = max(1, (int)$t['bb']);
        $s = intdiv(random_int((int)$t['min_buy'], (int)$t['max_buy']), $bb) * $bb;
        return max((int)$t['min_buy'], min((int)$t['max_buy'], $s));
    }

    /** House players up to $n at random free seats (extra ones stand up). uid b:<table>:<n>, pid 0, never in the ledger. */
    private function pkBots(int $tid, int $n): void {
        $t = &$this->tables[$tid]['t'];
        $bots = [];
        foreach ($t['players'] as $s => $p) { if (!empty($p['bot'])) { $bots[$s] = $p['uid']; } }
        while (count($bots) > $n) {
            $s = array_key_last($bots);
            try { pk_leave($t, $s); } catch (Throwable $e) { ws_log("table $tid: bot stand failed: " . $e->getMessage()); }
            unset($bots[$s]);
        }
        $free = array_values(array_diff(range(0, (int)$t['seats'] - 1), array_keys($t['players'])));
        shuffle($free);
        for ($k = 1; count($bots) < $n && $free; $k++) {
            if (in_array("b:$tid:$k", $bots, true)) { continue; }
            $seat = array_pop($free);
            $name = self::BOT_NAMES[($tid * 5 + $k) % count(self::BOT_NAMES)];
            try { pk_sit($t, $seat, "b:$tid:$k", 0, $name, $this->pkBotStack($t), true); $bots[$seat] = "b:$tid:$k"; }
            catch (Throwable $e) { ws_log("table $tid: bot seat failed: " . $e->getMessage()); }
        }
    }

    /** Every 30 s (and at start-up): host new tables, close disabled ones, queue blind/name changes for the next hand. */
    private function pkLoadTables(): void {
        try { $rows = q('SELECT * FROM poker_tables ORDER BY sort_order, id')->fetchAll(); }
        catch (Throwable $e) { ws_log('table reload failed: ' . $e->getMessage()); return; }
        $meta = fn(array $r) => array_intersect_key($r, array_flip(['name', 'seats', 'small_blind', 'big_blind', 'min_buyin', 'max_buyin', 'bots', 'sort_order']));
        $seen = [];
        foreach ($rows as $row) {
            $tid = (int)$row['id'];
            $seen[$tid] = true;
            if (!(int)$row['enabled']) { if (isset($this->tables[$tid]) && !$this->tables[$tid]['closing']) { $this->pkClose($tid); } continue; }
            if (!isset($this->tables[$tid])) { $this->pkHost($row); continue; }
            if ($this->tables[$tid]['closing']) { continue; }
            if ($meta($row) != $meta($this->tables[$tid]['row'])) { $this->tables[$tid]['pending'] = $row; }
        }
        foreach (array_keys($this->tables) as $tid) {
            if (!isset($seen[$tid]) && !$this->tables[$tid]['closing']) { $this->pkClose($tid); }
        }
    }

    /** Between hands: rebuild the meta fields from a changed row. Seats only shrink when nobody sits that high. */
    private function pkApplyRow(int $tid, array $row): void {
        $T = &$this->tables[$tid];
        $t = &$T['t'];
        $t['name'] = (string)$row['name'];
        $t['sb'] = (int)$row['small_blind']; $t['bb'] = (int)$row['big_blind'];
        $t['min_buy'] = (int)$row['min_buyin']; $t['max_buy'] = (int)$row['max_buyin'];
        $top = $t['players'] ? max(array_keys($t['players'])) : -1;
        if ((int)$row['seats'] > $top) { $t['seats'] = (int)$row['seats']; }
        $T['row'] = $row;
        $T['pending'] = null;
        $this->pkBots($tid, (int)$row['bots']);
        $T['dirty'] = true;
        $this->tablesDirty = true;
        ws_log("table $tid reconfigured: '{$t['name']}' {$t['seats']} seats, blinds {$t['sb']}/{$t['bb']}, buy-in {$t['min_buy']}-{$t['max_buy']}, bots {$row['bots']}");
    }

    /** Disabled or deleted in the back office: everyone is cashed out (after the hand if in one) and the table vanishes. */
    private function pkClose(int $tid): void {
        $T = &$this->tables[$tid];
        $T['closing'] = true;
        foreach ($T['t']['players'] as $seat => $p) {
            if (!empty($p['bot'])) { try { pk_leave($T['t'], $seat); } catch (Throwable) {} }
            elseif (isset($this->seatOf[$p['uid']])) { $this->pkStand($tid, $p['uid'], 'table closed'); }
        }
        foreach (array_keys($T['watch']) as $cid) { if (isset($this->clients[$cid])) { $this->send($this->clients[$cid], ['t' => 'pk_err', 'msg' => 'This table is closing.']); } }
        $T['dirty'] = true;
        $this->tablesDirty = true;
        ws_log("table $tid closing");
    }

    private function pkRealCount(int $tid): int {
        $n = 0;
        foreach ($this->tables[$tid]['t']['players'] as $p) { if (empty($p['bot'])) { $n++; } }
        return $n;
    }

    /**
     * House players want company: at a table nobody real is seated at or watching they sit out between hands, so an
     * empty room does not burn CPU or pile up bot-only hand histories. They sit back in as soon as someone shows up.
     */
    private function pkBotsCompany(int $tid): void {
        $T = &$this->tables[$tid];
        $company = $this->pkRealCount($tid) > 0;
        foreach (array_keys($T['watch']) as $cid) { if (isset($this->clients[$cid])) { $company = true; break; } }
        foreach ($T['t']['players'] as $seat => $p) {
            if (empty($p['bot']) || !empty($p['sitout']) !== $company) { continue; }
            try { pk_sitout($T['t'], $seat, !$company); $T['dirty'] = true; }
            catch (Throwable $e) { ws_log("table $tid: bot sitout failed: " . $e->getMessage()); }
        }
    }

    /** Every tick: advance every table, expire away players, apply queued config, retire closed tables, flush views. */
    private function pkTick(): void {
        foreach (array_keys($this->tables) as $tid) {
            $T = &$this->tables[$tid];
            if ($T['t']['phase'] === 'idle' && !$T['closing']) { $this->pkBotsCompany($tid); }
            try { $ev = pk_tick($T['t'], $this->now); }
            catch (Throwable $e) { ws_log("table $tid: engine error in pk_tick: " . $e->getMessage() . ' @ ' . basename($e->getFile()) . ':' . $e->getLine()); $ev = []; }
            if ($ev) { $this->pkEvents($tid, $ev); }
            foreach ($T['away'] as $uid => $a) {
                if ($this->now - $a['since'] >= $this->opt['away']) { unset($T['away'][$uid]); $this->pkStand($tid, $uid, 'away'); }
            }
            if ($T['pending'] && $T['t']['phase'] === 'idle') { $this->pkApplyRow($tid, $T['pending']); }
            if ($T['closing'] && !$this->pkRealCount($tid) && ($T['t']['phase'] === 'idle' || !$T['t']['players'])) {
                foreach (array_keys($T['watch']) as $cid) { if (isset($this->clients[$cid])) { unset($this->clients[$cid]->watch[$tid]); } }
                unset($T, $this->tables[$tid]);
                $this->tablesDirty = true;
                ws_log("table $tid closed");
                continue;
            }
            unset($T);
        }
        $this->pkFlush();
    }

    /** Engine events: queue them for the viewers and act on the ones with side effects (hand_end persists the hand). */
    private function pkEvents(int $tid, array $events): void {
        $T = &$this->tables[$tid];
        $T['dirty'] = true;
        foreach ($events as $ev) {
            if (!is_array($ev) || !isset($ev['t'])) { continue; }
            $T['events'][] = $ev;
            switch ($ev['t']) {
                case 'hand_start':
                    $this->tablesDirty = true;
                    $this->v("table $tid hand #{$ev['hand']} start, button seat {$ev['button']}, deck " . substr((string)($ev['deck_hash'] ?? ''), 0, 12));
                    break;
                case 'hand_end':
                    $this->pkHandEnd($tid, $ev);
                    $this->tablesDirty = true;
                    break;
                case 'sit': case 'stand':
                    $this->tablesDirty = true;
                    break;
            }
        }
    }

    /**
     * Last connection of a seated player went away: pk_away(true) deals them out of future hands with no blinds (the
     * hand they are in still runs its clock on them). They are cashed out at the end of the hand they were dealt into
     * (pkHandEnd), otherwise after the grace window (pkTick), or at once when --away is 0.
     */
    private function pkAway(string $uid): void {
        $s = $this->seatOf[$uid];
        $tid = $s['tid'];
        if (!isset($this->tables[$tid])) { unset($this->seatOf[$uid]); return; }
        $T = &$this->tables[$tid];
        $p = $T['t']['players'][$s['seat']] ?? null;
        if (!$p || $p['uid'] !== $uid) { unset($this->seatOf[$uid]); return; }
        if ($this->opt['away'] <= 0) { $this->pkStand($tid, $uid, 'disconnected'); return; }
        $T['away'][$uid] = ['since' => $this->now];
        try { pk_away($T['t'], $s['seat'], true); } catch (Throwable $e) { ws_log("table $tid: pk_away failed: " . $e->getMessage()); }
        $T['dirty'] = true;
        ws_log("away $uid table $tid seat {$s['seat']} ({$this->opt['away']} s grace)");
    }

    /** A connection for a uid that holds a seat (reconnect inside the grace window, or a second tab): pk_away(false) and refresh. */
    private function pkReattach(GTClient $c): void {
        $s = $this->seatOf[$c->uid] ?? null;
        if (!$s || !isset($this->tables[$s['tid']])) { return; }
        $T = &$this->tables[$s['tid']];
        if (isset($T['away'][$c->uid])) {
            unset($T['away'][$c->uid]);
            if (isset($T['t']['players'][$s['seat']])) {
                try { pk_away($T['t'], $s['seat'], false); } catch (Throwable $e) { ws_log("table {$s['tid']}: pk_away(false) failed: " . $e->getMessage()); }
            }
            $T['dirty'] = true;
            ws_log("back {$c->uid} table {$s['tid']} seat {$s['seat']}");
        }
        $this->pkSendState($c, $s['tid']);
    }

    /**
     * pk_view() plus the rule ws.php enforces itself, whatever engine is loaded (REALTIME.md → Security rules): hole
     * cards reach a viewer only for their own seat and for seats with show=true, in players[] AND in winners[] (a pot
     * taken because everyone else folded is won without showing), and the deck and its salt never leave the server.
     */
    private function pkView(array $t, ?string $uid): array {
        $v = pk_view($t, $uid);
        unset($v['deck'], $v['deck_salt']);
        $shown = [];
        foreach ((array)($v['players'] ?? []) as $i => $p) {
            if (!is_array($p)) { continue; }
            $ok = ($uid !== null && ($p['uid'] ?? null) === $uid) || !empty($p['show']);
            $shown[(int)($p['seat'] ?? $i)] = $ok;
            if (!$ok && array_key_exists('cards', $p)) { $v['players'][$i]['cards'] = null; }
        }
        foreach ((array)($v['winners'] ?? []) as $i => $w) {
            if (is_array($w) && array_key_exists('cards', $w) && empty($shown[(int)($w['seat'] ?? -1)])) { $v['winners'][$i]['cards'] = null; }
        }
        return $v;
    }

    private function pkSendState(GTClient $c, int $tid): void {
        if (!isset($this->tables[$tid])) { return; }
        try { $this->send($c, ['t' => 'pk_state', 'table' => $this->pkView($this->tables[$tid]['t'], $c->uid)]); }
        catch (Throwable $e) { ws_log("table $tid: pk_view failed: " . $e->getMessage()); }
    }

    /** Table summaries for welcome / pk_tables: id, name, seats, sb, bb, min_buy, max_buy, seated, playing. */
    private function pkSummaries(): array {
        $out = [];
        foreach ($this->tables as $tid => $T) {
            if ($T['closing']) { continue; }
            $t = $T['t'];
            $out[] = ['id' => $tid, 'name' => (string)$t['name'], 'seats' => (int)$t['seats'], 'sb' => (int)$t['sb'], 'bb' => (int)$t['bb'],
                      'min_buy' => (int)$t['min_buy'], 'max_buy' => (int)$t['max_buy'], 'seated' => count($t['players']), 'playing' => $t['phase'] !== 'idle',
                      '_o' => [(int)$T['row']['sort_order'], $tid]];
        }
        usort($out, fn($a, $b) => $a['_o'] <=> $b['_o']);
        foreach ($out as &$o) { unset($o['_o']); }
        return $out;
    }

    /**
     * Once per tick per changed table: pk_events (same for all) then pk_state built with pk_view() per viewer, never shared.
     * The viewers are the watchers, the seated real players, and (this tick only) the players whose seat was just removed,
     * so a mid-hand leaver or a busted player sees the hand_end events and the final state of the hand they were in.
     */
    private function pkFlush(): void {
        foreach ($this->tables as $tid => $T) {
            if (!$T['dirty'] && !$T['events']) { continue; }
            $viewers = $T['watch'];
            foreach ($T['t']['players'] as $p) {
                if (empty($p['bot'])) { foreach (array_keys($this->byUid[$p['uid']] ?? []) as $cid) { $viewers[$cid] = true; } }
            }
            foreach (array_keys($T['farewell']) as $uid) { foreach (array_keys($this->byUid[$uid] ?? []) as $cid) { $viewers[$cid] = true; } }
            $evFrame = $T['events'] ? $this->frame((string)json_encode(['t' => 'pk_events', 'table' => $tid, 'events' => array_values($T['events'])], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE)) : null;
            $views = [];
            foreach (array_keys($viewers) as $cid) {
                $c = $this->clients[$cid] ?? null;
                if (!$c || $c->room === '' || $c->closing) { continue; }
                if ($evFrame) { $this->raw($c, $evFrame); }
                if (!isset($views[$c->uid])) {
                    try { $views[$c->uid] = $this->frame((string)json_encode(['t' => 'pk_state', 'table' => $this->pkView($T['t'], $c->uid)], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE)); }
                    catch (Throwable $e) { ws_log("table $tid: pk_view failed: " . $e->getMessage()); continue; }
                }
                $this->raw($c, $views[$c->uid]);
            }
            if (isset($this->tables[$tid])) { $this->tables[$tid]['dirty'] = false; $this->tables[$tid]['events'] = []; $this->tables[$tid]['farewell'] = []; }
        }
    }

    /* ───────────────────────── poker: what a client may do ───────────────────────── */

    /** [table id, seat] of this player's seat, verified against the live state. */
    private function pkSeated(GTClient $c): array {
        $s = $this->seatOf[$c->uid] ?? null;
        $p = $s ? ($this->tables[$s['tid']]['t']['players'][$s['seat']] ?? null) : null;
        if (!$p || $p['uid'] !== $c->uid) { unset($this->seatOf[$c->uid]); throw new DomainException("You're not seated at a table."); }
        return [$s['tid'], $s['seat']];
    }

    private function pkWatch(GTClient $c, array $m, bool $on): void {
        $this->pkNeed();
        $tid = (int)self::num($m['table'] ?? 0);
        if (!$on) { unset($c->watch[$tid], $this->tables[$tid]['watch'][$c->id]); return; }
        if (!isset($this->tables[$tid]) || $this->tables[$tid]['closing']) { throw new DomainException('No such table.'); }
        $c->watch[$tid] = true;
        $this->tables[$tid]['watch'][$c->id] = true;
        $this->pkSendState($c, $tid);
    }

    /**
     * Buy in. Everything is checked against the live table first (the engine's own rules on a copy of the state, so a
     * refusal costs no ledger row), then ONE tx() moves the coins and writes the seat row (move_coins throws inside the
     * tx when the balance is short; the UNIQUE player_id row stops double seating across processes). Only then does the
     * engine seat the player for real; should that still fail, the buy-in is reversed in a second tx().
     */
    private function pkJoin(GTClient $c, array $m): void {
        $this->pkNeed();
        if ($c->guest) { throw new DomainException('Log in to sit down. Guests can watch.'); }
        if ($c->brk) { throw new DomainException("You're on a break right now."); }
        $tid = (int)self::num($m['table'] ?? 0);
        $seat = (int)self::num($m['seat'] ?? -1);
        $buyin = (int)self::num($m['buyin'] ?? 0);
        if (!isset($this->tables[$tid]) || $this->tables[$tid]['closing']) { throw new DomainException('That table is closed.'); }
        $t = $this->tables[$tid]['t'];
        if (isset($this->seatOf[$c->uid])) { throw new DomainException("You're already seated at a table."); }
        if ($seat < 0 || $seat >= (int)$t['seats']) { throw new DomainException('No such seat.'); }
        if (isset($t['players'][$seat])) { throw new DomainException('That seat is taken.'); }
        if ($buyin < (int)$t['min_buy'] || $buyin > (int)$t['max_buy']) { throw new DomainException('Buy-in must be between ' . coins((int)$t['min_buy']) . ' and ' . coins((int)$t['max_buy']) . ' GC.'); }
        pk_sit($t, $seat, $c->uid, $c->pid, $c->name, $buyin, false);   // dry run on the copy: DomainException → pk_err, nothing written
        $bal = (int)tx(function () use ($c, $tid, $seat, $buyin, $t) {
            $b = move_coins($c->pid, -$buyin, 'wager', 'poker', "buy-in {$t['name']} #$tid");
            try { q('INSERT INTO poker_seats (table_id, player_id, seat, stack) VALUES (?,?,?,?)', [$tid, $c->pid, $seat, $buyin]); }
            catch (PDOException) { throw new DomainException("You're already seated at a table."); }
            return $b;
        });
        try { pk_sit($this->tables[$tid]['t'], $seat, $c->uid, $c->pid, $c->name, $buyin, false); }
        catch (Throwable $e) {
            tx(function () use ($c, $tid, $buyin) {
                move_coins($c->pid, $buyin, 'payout', 'poker', "buy-in reversed #$tid");
                q('DELETE FROM poker_seats WHERE player_id = ?', [$c->pid]);
            });
            ws_log("table $tid: pk_sit refused {$c->uid}: " . $e->getMessage());
            throw $e instanceof DomainException ? $e : new DomainException('Could not seat you. Your coins were returned.');
        }
        $this->seatOf[$c->uid] = ['tid' => $tid, 'seat' => $seat, 'pid' => $c->pid];
        $this->tables[$tid]['dirty'] = true;
        $this->tablesDirty = true;
        $this->send($c, ['t' => 'bal', 'balance' => $bal]);
        ws_log("sit {$c->uid} '{$c->name}' table $tid seat $seat buy-in $buyin, balance $bal");
    }

    /** Top up between hands, up to max_buy in front. Same shape as the buy-in: the engine's rules on a copy, one tx(), then the engine for real, else reverse. */
    private function pkAddon(GTClient $c, array $m): void {
        $this->pkNeed();
        [$tid, $seat] = $this->pkSeated($c);
        $t = &$this->tables[$tid]['t'];
        $amt = (int)self::num($m['amount'] ?? 0);
        if ($amt <= 0) { throw new DomainException('Add-on amount must be positive.'); }
        if (!empty($t['players'][$seat]['leaving'])) { throw new DomainException("You're leaving this table."); }
        $probe = $t; pk_addon($probe, $seat, $amt); unset($probe);   // the engine decides (a seat dealt into the running hand waits for hand_end)
        $bal = (int)tx(function () use ($c, $tid, $amt, $t) {
            $b = move_coins($c->pid, -$amt, 'wager', 'poker', "add-on {$t['name']} #$tid");
            q("UPDATE poker_seats SET stack = stack + ?, updated_at = datetime('now') WHERE player_id = ?", [$amt, $c->pid]);
            return $b;
        });
        try { pk_addon($t, $seat, $amt); }
        catch (Throwable $e) {
            tx(function () use ($c, $tid, $amt) {
                move_coins($c->pid, $amt, 'payout', 'poker', "add-on reversed #$tid");
                q("UPDATE poker_seats SET stack = stack - ?, updated_at = datetime('now') WHERE player_id = ?", [$amt, $c->pid]);
            });
            throw $e instanceof DomainException ? $e : new DomainException('Add-on failed. Your coins were returned.');
        }
        $this->tables[$tid]['dirty'] = true;
        $this->send($c, ['t' => 'bal', 'balance' => $bal]);
        ws_log("add-on {$c->uid} table $tid seat $seat +$amt, balance $bal");
    }

    private function pkLeave(GTClient $c): void {
        $this->pkNeed();
        [$tid] = $this->pkSeated($c);
        $this->pkStand($tid, $c->uid, 'cash-out');
    }

    /** Sit out / back in. A repeat of the current state is a no-op; more than 2 real toggles a second → pk_err (each one costs every viewer a pk_events + pk_state). */
    private function pkSitout(GTClient $c, array $m): void {
        $this->pkNeed();
        [$tid, $seat] = $this->pkSeated($c);
        $on = !empty($m['on']);
        if (!empty($this->tables[$tid]['t']['players'][$seat]['sitout']) === $on) { return; }
        if (!$this->allow($c, 'sitout', 2)) { throw new DomainException('Slow down.'); }
        pk_sitout($this->tables[$tid]['t'], $seat, $on);
        $this->tables[$tid]['dirty'] = true;
    }

    /** Post a live big blind to be dealt into the next hand instead of waiting for the big blind (matters while the seat owes one). Same no-op / limiter rules as pk_sitout. */
    private function pkPost(GTClient $c, array $m): void {
        $this->pkNeed();
        [$tid, $seat] = $this->pkSeated($c);
        $on = array_key_exists('on', $m) ? !empty($m['on']) : true;
        if (!empty($this->tables[$tid]['t']['players'][$seat]['post']) === $on) { return; }
        if (!$this->allow($c, 'post', 2)) { throw new DomainException('Slow down.'); }
        pk_post($this->tables[$tid]['t'], $seat, $on);
        $this->tables[$tid]['dirty'] = true;
    }

    /** An action: the hand / seq echo must match the live state (stale UI or double click → pk_err, no-op), then pk_act() rules. */
    private function pkAct(GTClient $c, array $m): void {
        $this->pkNeed();
        [$tid, $seat] = $this->pkSeated($c);
        $t = &$this->tables[$tid]['t'];
        $act = is_string($m['act'] ?? null) ? $m['act'] : '';
        if (!in_array($act, ['fold', 'check', 'call', 'raise', 'allin'], true)) { throw new DomainException('Unknown action.'); }
        if ((int)self::num($m['hand'] ?? -1) !== (int)$t['hand_no'] || (int)self::num($m['seq'] ?? -1) !== (int)$t['seq']) {
            throw new DomainException('The table moved on. Check the latest state and try again.');
        }
        $ev = pk_act($t, $seat, $act, (int)self::num($m['amt'] ?? 0), $this->now);
        $this->tables[$tid]['dirty'] = true;
        if ($ev) { $this->pkEvents($tid, $ev); }
        $this->v("act {$c->uid} table $tid seat $seat $act " . (int)self::num($m['amt'] ?? 0));
    }

    /**
     * Stand a real player up. pk_leave() returns the stack when the seat is not in a live hand: paid now (one tx() with
     * the row delete). It returns -1 for a seat dealt into the running hand (folded now, or left as is during 'settle'):
     * the seat, its poker_seats row and its seatOf entry stay until hand_end pays it from the event's leavers[].
     */
    private function pkStand(int $tid, string $uid, string $why): void {
        $s = $this->seatOf[$uid] ?? null;
        if (!$s || $s['tid'] !== $tid || !isset($this->tables[$tid])) { unset($this->seatOf[$uid]); return; }
        $T = &$this->tables[$tid];
        unset($T['away'][$uid]);
        $p = $T['t']['players'][$s['seat']] ?? null;
        if (!$p || $p['uid'] !== $uid) { unset($this->seatOf[$uid]); return; }
        if (!empty($p['leaving'])) { if ($why === 'cash-out') { throw new DomainException("You're leaving after this hand."); } return; }
        try { $r = (int)pk_leave($T['t'], $s['seat']); }
        catch (DomainException $e) { if ($why === 'cash-out') { throw $e; } ws_log("table $tid: pk_leave refused $uid: " . $e->getMessage()); return; }
        catch (Throwable $e) { ws_log("table $tid: pk_leave failed for $uid: " . $e->getMessage()); return; }
        $T['dirty'] = true;
        $this->tablesDirty = true;
        if ($r < 0) { ws_log("leaving $uid table $tid seat {$s['seat']} after this hand ($why)"); return; }
        unset($this->seatOf[$uid]);
        $T['farewell'][$uid] = true;
        $bal = $this->pkCashOut($s['pid'], $r, "cash-out {$T['t']['name']} #$tid" . ($why !== 'cash-out' ? " ($why)" : ''));
        $this->sendUid($uid, ['t' => 'bal', 'balance' => $bal]);
        ws_log("stand $uid table $tid seat {$s['seat']} +$r GC ($why), balance $bal");
    }

    /** Chips back to the balance and the seat row gone, in one tx(). Returns the new balance. */
    private function pkCashOut(int $pid, int $stack, string $detail): int {
        return (int)tx(function () use ($pid, $stack, $detail) {
            $b = $stack > 0 ? move_coins($pid, $stack, 'payout', 'poker', $detail) : bal($pid);
            q('DELETE FROM poker_seats WHERE player_id = ?', [$pid]);
            return $b;
        });
    }

    /**
     * hand_end (pk_tick moved settle → idle; the next hand only deals on the next tick). ONE tx(), in this order:
     * the poker_hands row (full pk_hand_record()), then per real player in the record: a leaver (leavers[seat] from
     * the event, equal to the record's end stack) is paid with move_coins(+stack, 'payout') and its seat row deleted;
     * a busted player (end stack 0, removed by the engine) has its row deleted; everyone else gets poker_seats.stack =
     * end stack; and record_round(pid, start − end + won, won) for each of them. After the tx: players who
     * disconnected during the hand are cashed out (the seat is idle now, so pk_leave returns the stack), and busted
     * house players rebuy. Should the tx fail (nothing written), the leavers are still paid one by one, each in its own
     * tx() with its row delete, and the failure is logged.
     */
    private function pkHandEnd(int $tid, array $ev): void {
        $T = &$this->tables[$tid];
        $t = &$T['t'];
        $rec = null;
        try { $rec = pk_hand_record($t); } catch (Throwable $e) { ws_log("table $tid: pk_hand_record failed: " . $e->getMessage()); }
        if (!is_array($rec)) { $rec = null; }
        $handNo = (int)($rec['hand_no'] ?? $t['hand_no']);
        $leavers = is_array($ev['leavers'] ?? null) ? $ev['leavers'] : [];   // seat => stack, bots included (they get nothing)
        $real = [];                                                          // seat => [uid, pid]: this table's real players, mid-hand leavers included
        foreach ($this->seatOf as $uid => $s) { if ($s['tid'] === $tid) { $real[$s['seat']] = ['uid' => $uid, 'pid' => (int)$s['pid']]; $T['farewell'][$uid] = true; } }
        $players = [];                                                       // the record's real players by seat
        foreach ((array)($rec['players'] ?? []) as $p) {
            if (!is_array($p) || !empty($p['bot']) || !isset($p['seat'])) { continue; }
            $seat = (int)$p['seat'];
            if (!isset($real[$seat]) || $real[$seat]['uid'] !== ($p['uid'] ?? null)) { ws_log("table $tid: hand #$handNo seat $seat ({$p['uid']}) has no seat map entry, not settled"); continue; }
            $players[$seat] = $p;
        }
        $stamp = fn($v) => is_int($v) || is_float($v) ? gmdate('Y-m-d H:i:s', (int)$v) : (is_string($v) && $v !== '' ? $v : now());
        $paid = []; $busted = [];
        $write = function () use ($tid, $t, $rec, $ev, $handNo, $leavers, $real, $players, $stamp, &$paid, &$busted) {
            if ($rec) {
                q('INSERT INTO poker_hands (table_id, hand_no, deck_hash, deck_salt, board, pot, record, started_at, ended_at) VALUES (?,?,?,?,?,?,?,?,?)', [
                    $tid, $handNo, (string)($rec['deck_hash'] ?? ''), (string)($rec['deck_salt'] ?? $ev['deck_salt'] ?? ''),
                    implode(' ', (array)($rec['board'] ?? [])), (int)($rec['pot'] ?? 0), (string)json_encode($rec, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE),
                    $stamp($rec['started_at'] ?? null), $stamp($rec['ended_at'] ?? null)]);
            }
            foreach ($players as $seat => $p) {
                ['uid' => $uid, 'pid' => $pid] = $real[$seat];
                $start = (int)($p['start_stack'] ?? 0); $end = (int)($p['end_stack'] ?? 0); $won = (int)($p['won'] ?? 0);
                if (array_key_exists($seat, $leavers)) {                       // left during the hand: paid what the engine handed back
                    $stack = max(0, (int)$leavers[$seat]);
                    if ($stack !== $end) { ws_log("table $tid: hand #$handNo leaver $uid: leavers[] says $stack, the record $end"); }
                    $b = $stack > 0 ? move_coins($pid, $stack, 'payout', 'poker', "cash-out {$t['name']} #$tid") : bal($pid);
                    q('DELETE FROM poker_seats WHERE player_id = ?', [$pid]);
                    $paid[$uid] = ['bal' => $b, 'stack' => $stack];
                } elseif ($end <= 0 || !isset($t['players'][$seat])) {          // busted: the engine removed the seat, nothing to return
                    q('DELETE FROM poker_seats WHERE player_id = ?', [$pid]);
                    $busted[$uid] = (string)($p['name'] ?? $uid);
                } else {                                                       // still seated: the row follows the settled stack
                    q("UPDATE poker_seats SET stack = ?, updated_at = datetime('now') WHERE player_id = ?", [$end, $pid]);
                }
                record_round($pid, max(0, $start - $end + $won), $won);
            }
            foreach ($leavers as $seat => $stack) {                            // a real leaver the record does not list (cannot happen: only dealt-in seats defer): still paid, once
                if (!isset($real[(int)$seat]) || isset($players[(int)$seat])) { continue; }
                ['uid' => $uid, 'pid' => $pid] = $real[(int)$seat];
                ws_log("table $tid: hand #$handNo leaver $uid is not in the record, paying leavers[] $stack");
                $b = (int)$stack > 0 ? move_coins($pid, (int)$stack, 'payout', 'poker', "cash-out {$t['name']} #$tid") : bal($pid);
                q('DELETE FROM poker_seats WHERE player_id = ?', [$pid]);
                $paid[$uid] = ['bal' => $b, 'stack' => (int)$stack];
            }
        };
        try { tx($write); }
        catch (Throwable $e) {
            ws_log("table $tid: hand_end persistence FAILED (hand #$handNo): " . $e->getMessage());
            $paid = []; $busted = [];
            foreach ($leavers as $seat => $stack) {
                if (!isset($real[(int)$seat])) { continue; }
                ['uid' => $uid, 'pid' => $pid] = $real[(int)$seat];
                try { $paid[$uid] = ['bal' => $this->pkCashOut($pid, max(0, (int)$stack), "cash-out {$t['name']} #$tid"), 'stack' => (int)$stack]; }
                catch (Throwable $e2) { ws_log("table $tid: cash-out FAILED for $uid ($stack GC): " . $e2->getMessage()); }
            }
            foreach ($players as $seat => $p) {   // busted players are gone from the table whatever the database says: forget the seat
                if ((int)($p['end_stack'] ?? 0) <= 0 && !isset($t['players'][$seat]) && !array_key_exists($seat, $leavers)) { $busted[$real[$seat]['uid']] = (string)($p['name'] ?? ''); }
            }
        }
        foreach ($paid as $uid => $x) {
            unset($this->seatOf[$uid], $T['away'][$uid]);
            $this->sendUid($uid, ['t' => 'bal', 'balance' => $x['bal']]);
            ws_log("stand $uid table $tid +{$x['stack']} GC (after hand #$handNo), balance {$x['bal']}");
        }
        foreach ($busted as $uid => $name) {
            unset($this->seatOf[$uid], $T['away'][$uid]);
            $this->sendUid($uid, ['t' => 'pk_err', 'msg' => "You're out of chips at {$t['name']}. Buy in again any time."]);
            ws_log("busted $uid '$name' table $tid hand #$handNo");
        }
        // disconnected during the hand they were dealt into: cashed out now that the seat is idle (a settled stack, paid once)
        foreach (array_keys($T['away']) as $uid) {
            $seat = $this->seatOf[$uid]['seat'] ?? null;
            if ($seat !== null && isset($players[$seat])) { $this->pkStand($tid, $uid, 'disconnected'); }
        }
        // house players never leave the table short of chips: a busted bot keeps its seat at 0 and rebuys here
        foreach ($t['players'] as $seat => $p) {
            if (empty($p['bot']) || (int)$p['stack'] > 0) { continue; }
            $amt = $this->pkBotStack($t);
            try { pk_addon($t, $seat, $amt); $this->v("table $tid bot {$p['name']} rebuys $amt"); }
            catch (Throwable $e) { ws_log("table $tid: bot rebuy failed: " . $e->getMessage()); }
        }
        $T['dirty'] = true;
        $this->v("table $tid hand #$handNo saved, pot " . (int)($rec['pot'] ?? 0) . ', ' . count($players) . ' real players, ' . count($paid) . ' paid out, ' . count($busted) . ' busted');
    }

    /* ───────────────────────── safety: refunds and shutdown ───────────────────────── */

    /**
     * Every poker_seats row back to its player at what the ROW says: between hands that is the stack in front of them,
     * during a hand the stack the hand started with (an interrupted hand is void). Start-up (crash recovery) and
     * shutdown both end here; each row is one tx() of payout + delete, so a row is never paid twice.
     */
    private function refundAllSeats(string $why): void {
        try { $rows = q('SELECT s.table_id, s.player_id, s.seat, s.stack, p.username FROM poker_seats s JOIN players p ON p.id = s.player_id')->fetchAll(); }
        catch (Throwable $e) { ws_log('seat refund query failed: ' . $e->getMessage()); return; }
        foreach ($rows as $r) {
            try {
                $bal = $this->pkCashOut((int)$r['player_id'], (int)$r['stack'], "$why #{$r['table_id']}");
                ws_log("refund {$r['stack']} GC to '{$r['username']}' (player {$r['player_id']}) from table {$r['table_id']} seat {$r['seat']}: $why, balance $bal");
            } catch (Throwable $e) { ws_log("refund FAILED for player {$r['player_id']} ({$r['stack']} GC): " . $e->getMessage()); }
        }
        if (!$rows) { $this->v("no seats to refund ($why)"); }
    }

    /** SIGINT / SIGTERM: 1001 to everyone, a moment to flush, refund every seat row, exit 0. */
    private function shutdown(): void {
        ws_log('shutting down: closing ' . count($this->clients) . ' connection(s)');
        foreach ($this->clients as $c) { if ($c->shook && !$c->closing) { $this->close($c, 1001, 'server going away'); } }
        $until = microtime(true) + 0.5;
        while (microtime(true) < $until) {
            $w = []; $r = []; $e = null;
            foreach ($this->clients as $c) { if ($c->wbuf !== '') { $w[] = $c->sock; } }
            if (!$w) { break; }
            if (@stream_select($r, $w, $e, 0, 50000)) {
                foreach ($w as $s) { $c = $this->clients[$this->bySock[get_resource_id($s)] ?? 0] ?? null; if ($c) { $this->flush($c); } }
            }
        }
        foreach ($this->clients as $c) { @fclose($c->sock); }
        $this->clients = []; $this->bySock = [];
        if ($this->srv) { @fclose($this->srv); }
        $this->refundAllSeats('table reset');
        if ($this->lock) { flock($this->lock, LOCK_UN); fclose($this->lock); $this->lock = null; }
        ws_log('bye');
    }
}

(new GTServer(ws_options($argv)))->run();
exit(0);
