<?php
/**
 * tests/ws_client.php: shared helpers for the realtime end-to-end tests (ws_test.php, poker_e2e_test.php).
 * A hand-written RFC 6455 client (masked frames, ping/pong, close codes, an inbox per connection and a `seen`
 * log for scans), plus scratch-copy / server start / health / port helpers. Everything runs against a temporary
 * copy of the app so the real data/ is never created. No framework.
 */
declare(strict_types=1);

/** First free TCP port on 127.0.0.1 inside [$from, $to]. */
function free_port(int $from = 8300, int $to = 8399): int {
    for ($p = $from; $p <= $to; $p++) {
        $s = @stream_socket_server("tcp://127.0.0.1:$p", $errno, $errstr);
        if ($s) { fclose($s); return $p; }
    }
    throw new RuntimeException("no free port in $from-$to");
}

/**
 * A scratch copy of the app (index.php + ws.php) under the system temp dir (TMPDIR honoured) with its own data/, so the
 * real data/ is never created or touched. Returns the directory; remove it with rm_tree() when the run is green.
 */
function scratch_copy(string $root, string $tag): string {
    $tmp = rtrim(sys_get_temp_dir(), '/') . "/gt_{$tag}_" . getmypid();
    if (!is_dir($tmp) && !mkdir($tmp, 0700, true)) { throw new RuntimeException("cannot create $tmp"); }
    foreach (['index.php', 'ws.php'] as $f) { if (!copy("$root/$f", "$tmp/$f")) { throw new RuntimeException("cannot copy $f"); } }
    return $tmp;
}
function rm_tree(string $d): void {
    foreach (scandir($d) ?: [] as $f) { if ($f === '.' || $f === '..') { continue; } is_dir("$d/$f") ? rm_tree("$d/$f") : @unlink("$d/$f"); }
    @rmdir($d);
}

/** Start ws.php from a scratch copy: [process, log path]. $args are extra CLI flags; $env extra environment variables. */
function start_server(string $tmp, int $port, array $args = [], array $env = [], string $logName = 'server.log'): array {
    $logPath = "$tmp/$logName";
    $log = fopen($logPath, 'ab');
    $cmd = [PHP_BINARY, "$tmp/ws.php", '--port', (string)$port, '--bind', '127.0.0.1', ...$args];
    $proc = proc_open($cmd, [0 => ['pipe', 'r'], 1 => $log, 2 => $log], $pipes, $tmp, $env + getenv());
    if (!is_resource($proc)) { throw new RuntimeException('cannot start ws.php'); }
    fclose($log);
    return [$proc, $logPath];
}
/** Poll /health until the server answers (≤ $secs). */
function wait_health(int $port, float $secs = 10.0): ?array {
    $t0 = microtime(true); $h = null;
    while (!$h && microtime(true) - $t0 < $secs) { usleep(100000); $h = health($port); }
    return $h;
}
/** Wait for a process to exit (≤ $secs); returns proc_get_status() (running=true when it did not). */
function wait_exit($proc, float $secs = 5.0): array {
    $t0 = microtime(true); $st = proc_get_status($proc);
    while ($st['running'] && microtime(true) - $t0 < $secs) { usleep(50000); $st = proc_get_status($proc); }
    return $st;
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
    $pr = proc_open([PHP_BINARY, "$tmp/ws.php", '--port', (string)$port, '--bind', '127.0.0.1'], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pp, $tmp, getenv());
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
