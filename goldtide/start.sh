#!/usr/bin/env bash
# Slop Casino launcher: starts the site (php -S) and the realtime server (ws.php), opens the browser,
# and stops both on Ctrl+C.
#
#   ./start.sh                 site on http://127.0.0.1:8000 + multiplayer, opens the browser
#   ./start.sh --port 8080     pick the site port (the next free one is used if it's taken)
#   ./start.sh --lan           let phones and other computers on your network join
#   ./start.sh --no-ws         site only, no multiplayer floor or live poker
#   ./start.sh --no-open       don't open a browser
set -u

cd "$(dirname "$0")" || exit 1

PORT=8000
WS_PORT=8081          # the page looks for the socket on 8081 in dev (see rt_ws_url in index.php)
BIND=127.0.0.1
WS=1
OPEN=1
LOGS=data/logs

c_coral=$'\033[38;2;237;115;87m'; c_dim=$'\033[2m'; c_bold=$'\033[1m'; c_off=$'\033[0m'
[ -t 1 ] || { c_coral=; c_dim=; c_bold=; c_off=; }
say()  { printf '%s●%s %s\n' "$c_coral" "$c_off" "$*"; }
warn() { printf '%s!%s %s\n' "$c_coral" "$c_off" "$*" >&2; }
die()  { warn "$*"; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --port)    [ $# -ge 2 ] || die "--port needs a number"; PORT="$2"; shift ;;
    --port=*)  PORT="${1#*=}" ;;
    --lan)     BIND=0.0.0.0 ;;
    --no-ws)   WS=0 ;;
    --no-open) OPEN=0 ;;
    -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
  shift
done
case "$PORT" in ''|*[!0-9]*) die "--port must be a number" ;; esac
[ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "--port must be between 1 and 65535"
[ "$PORT" != "$WS_PORT" ] || die "port $WS_PORT is reserved for the realtime server; pick another --port"

# --- PHP checks -------------------------------------------------------------------------------
command -v php >/dev/null 2>&1 || die "PHP isn't installed. macOS: brew install php   Debian/Ubuntu/Pi: sudo apt install php-cli php-sqlite3"
php -r 'exit(PHP_VERSION_ID >= 80100 ? 0 : 1);' || die "PHP 8.1+ is needed (found $(php -r 'echo PHP_VERSION;'))"
php -r 'exit(extension_loaded("pdo_sqlite") ? 0 : 1);' || die "PHP is missing pdo_sqlite. Debian/Ubuntu/Pi: sudo apt install php-sqlite3"

listening() { php -r '$s = @fsockopen("127.0.0.1", (int)$argv[1], $e, $m, 0.3); exit($s ? 0 : 1);' "$1"; }

# --- pick a free site port --------------------------------------------------------------------
tries=0
while listening "$PORT" || [ "$PORT" = "$WS_PORT" ]; do
  tries=$((tries + 1)); [ $tries -le 20 ] || die "no free port found near $PORT"
  warn "port $PORT is busy, trying $((PORT + 1))"; PORT=$((PORT + 1))
done

mkdir -p "$LOGS"
WEB_PID=; WS_PID=

cleanup() {
  trap - INT TERM EXIT
  echo
  say "shutting down…"
  # ws.php refunds any seats in an unfinished poker hand when it gets TERM, so give it a moment
  [ -n "$WS_PID" ]  && kill -TERM "$WS_PID"  2>/dev/null
  [ -n "$WEB_PID" ] && kill -TERM "$WEB_PID" 2>/dev/null
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    { [ -z "$WS_PID" ] || ! kill -0 "$WS_PID" 2>/dev/null; } && { [ -z "$WEB_PID" ] || ! kill -0 "$WEB_PID" 2>/dev/null; } && break
    sleep 0.5
  done
  [ -n "$WS_PID" ]  && kill -KILL "$WS_PID"  2>/dev/null
  [ -n "$WEB_PID" ] && kill -KILL "$WEB_PID" 2>/dev/null
  say "bye"
  exit 0
}
trap cleanup INT TERM EXIT

# --- the site ---------------------------------------------------------------------------------
# a few workers so the floor's machine screens, assets and API calls don't queue behind each other
PHP_CLI_SERVER_WORKERS="${PHP_CLI_SERVER_WORKERS:-4}" php -S "$BIND:$PORT" index.php >"$LOGS/web.log" 2>&1 &
WEB_PID=$!

for _ in $(seq 1 50); do listening "$PORT" && break; kill -0 "$WEB_PID" 2>/dev/null || break; sleep 0.2; done
if ! listening "$PORT"; then
  WEB_PID=
  tail -n 20 "$LOGS/web.log" >&2
  die "the site didn't start (log above, full log in $LOGS/web.log)"
fi
# the first request builds data/app.sqlite and runs migrations; do it here so the browser opens fast
php -r '@file_get_contents("http://127.0.0.1:" . $argv[1] . "/");' "$PORT"

# --- the realtime server ----------------------------------------------------------------------
if [ "$WS" = 1 ]; then
  if listening "$WS_PORT"; then
    warn "port $WS_PORT is already in use, so multiplayer will use whatever is running there"
    warn "(if that's an old ws.php, fine; otherwise stop it and run this again)"
  else
    php ws.php --port "$WS_PORT" >"$LOGS/ws.log" 2>&1 &
    WS_PID=$!
    for _ in $(seq 1 50); do listening "$WS_PORT" && break; kill -0 "$WS_PID" 2>/dev/null || break; sleep 0.2; done
    if ! listening "$WS_PORT"; then
      WS_PID=
      tail -n 10 "$LOGS/ws.log" >&2
      warn "the realtime server didn't start; the site still works, the floor just plays solo"
    fi
  fi
fi

# --- tell the human ---------------------------------------------------------------------------
URL="http://127.0.0.1:$PORT/"
echo
printf '  %sSlop Casino%s%s.%s  premium slop, free Gold Coins, zero cash value\n\n' "$c_bold" "$c_off" "$c_coral" "$c_off"
say "site         $URL"
if [ "$BIND" = 0.0.0.0 ]; then
  LAN_IP=$( (ipconfig getifaddr en0 || ipconfig getifaddr en1 || hostname -I | awk '{print $1}') 2>/dev/null | head -n 1)
  [ -n "$LAN_IP" ] && say "on your wifi http://$LAN_IP:$PORT/"
fi
if [ -n "$WS_PID" ] || { [ "$WS" = 1 ] && listening "$WS_PORT"; }; then
  say "multiplayer  ws://…:$WS_PORT  (the floor + live hold'em)"
else
  say "multiplayer  off"
fi
[ -f admin_password.txt ] && say "back office  ${URL}?action=admin  ${c_dim}(password in admin_password.txt)${c_off}"
say "logs         $LOGS/web.log, $LOGS/ws.log"
printf '\n  %sCtrl+C stops everything%s\n\n' "$c_dim" "$c_off"

if [ "$OPEN" = 1 ]; then
  if command -v open >/dev/null 2>&1 && [ "$(uname)" = Darwin ]; then open "$URL"
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL" >/dev/null 2>&1 &
  elif command -v wslview >/dev/null 2>&1; then wslview "$URL"
  else say "open $URL in your browser"
  fi
fi

# --- stay up; if either server dies, say so ---------------------------------------------------
while :; do
  if ! kill -0 "$WEB_PID" 2>/dev/null; then
    WEB_PID=; warn "the site stopped unexpectedly (see $LOGS/web.log)"; cleanup
  fi
  if [ -n "$WS_PID" ] && ! kill -0 "$WS_PID" 2>/dev/null; then
    WS_PID=; warn "the realtime server stopped (see $LOGS/ws.log); the site keeps running"
  fi
  sleep 2
done
