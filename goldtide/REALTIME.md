# Gold Tide realtime layer: the floor, multiplayer and poker

This file is the contract between the pieces that make the casino live:

| piece | where | what |
|---|---|---|
| poker engine | `index.php`, `pk_*` functions (pure, no I/O except the CSPRNG) | no-limit Texas hold'em rules, side pots, evaluator, timers, bots, deck commit |
| realtime server | `ws.php` (`php ws.php`) | RFC 6455 WebSocket server over stream sockets. Presence on the floor, chat, hosts every poker table, persists seats and hand histories |
| ticket + config | `index.php`: `rt_*` functions, `?action=rt_ticket`, `?action=floor`, `?action=poker` | issues short-lived HMAC tickets so the socket server can trust who is connecting without sharing the PHP session |
| the floor | `index.php`: `floor_js()` served at `?action=asset&f=floor` | first-person 3D casino, machines and tables you walk up to and sit at, other players as avatars |
| poker client | `index.php`: `poker_js()` served at `?action=asset&f=poker` | the table UI, used by the 2D poker page and by the floor's HUD |

Everything below is normative. If an implementation needs to deviate, change this file in the same commit.

## Running it

```bash
PHP_CLI_SERVER_WORKERS=8 php -S 0.0.0.0:8000 index.php   # the site
php ws.php                                                # the realtime server, port 8081 by default
php ws.php --port 9000 --bind 127.0.0.1                   # options
php ws.php --help                                         # --port --bind --tick (ms) --idle (s) --away (s) --max (clients) --verbose
php tests/ws_test.php                                     # end-to-end tests: start their own ws.php on 8300-8399 against a scratch database
```

`ws.php` includes `index.php` with `GT_NO_ROUTE` defined, so it shares the database, `tx()`, `move_coins()`, settings and the poker engine. It never touches the PHP session.

- `GET /health` on the socket port (a plain HTTP request without `Upgrade`) answers `{ "ok": true, "online": n, "tables": [{ "id", "seated", "hand_no" }] }` for monitoring.
- Logs go to stdout and to `data/ws.log` (rotated to `ws.log.1` above 5 MB); `--verbose` adds one line per connection event, action and hand.
- The timers can be shortened with `--idle` / `--away` or the environment variables `GT_WS_IDLE` / `GT_WS_AWAY` (the tests do). Settings such as `rt_origins` and `poker_action_seconds` are read once at start-up: restart `ws.php` after changing them.
- Without an engine (no `pk_*` functions in `index.php`) the server hosts the floor only and answers every `pk_*` message with `pk_err`. `GT_PK_STUB=1` loads `tests/pk_stub.php`, a fake engine for the test-suite only; the server logs a loud warning when it is active.
- SIGINT / SIGTERM close every socket with 1001, refund every `poker_seats` row and exit 0.

Client auto-discovery of the socket URL, in order:
1. the `ws_url` setting if it is not blank (e.g. `wss://casino.example.com/ws` behind a Cloudflare tunnel or nginx),
2. otherwise, if the page was served on a non-standard port (dev with `php -S`), `ws://<hostname>:8081/`,
3. otherwise `wss://<host>/ws` (or `ws://` on plain http).

`rt_ws_url()` in `index.php` computes this server-side and puts it in the page config; the CSP `connect-src` allows exactly that origin.

## Tickets

`POST ?action=rt_ticket` (CSRF-protected, JSON) returns

```json
{ "ticket": "<base64url payload>.<hex hmac>", "ws": "ws://localhost:8081/", "uid": "p12", "name": "lalo" }
```

Payload (JSON): `{ "uid": "p12" | "g<8 hex>", "pid": 12 | 0, "name": "lalo" | "Guest 4f2a", "exp": <unix seconds, now+60>, "nonce": "<16 hex>" }`.
HMAC-SHA256 over the exact base64url payload string with the `rt_secret` row from `meta`. `rt_ticket_make()` and `rt_ticket_verify()` live in `index.php`; `ws.php` uses the verifier and rejects any nonce it has already accepted (keep the set for 120 s).

Guests (not logged in) get a guest ticket: they can walk the floor and chat, but cannot sit anywhere. Logged-in players on a self-imposed break (`on_break()`) get a normal ticket with `"brk": true` and the server refuses `pk_join` for them.

## Wire protocol

JSON text frames, one message per frame (continuation frames are reassembled), `t` is the type. Unknown types are ignored. Numbers are integers unless stated.

Close codes: a message over 8 KB closes the connection with 1009, a binary frame with 1003, an unmasked or otherwise protocol-violating frame with 1002. A text frame that is not valid UTF-8 JSON with a string `t` is answered with `err` and counts as a strike; the third strike closes with 1008. Anything sent before `hello`, a bad or reused ticket and an unknown room close with 1008; idle sockets and a server shutdown close with 1001; an internal error while handling a client closes that client with 1011.

### Client → server

| t | fields | notes |
|---|---|---|
| `hello` | `ticket`, `room` (`"floor"` or `"poker"`) | must be the first message, within 5 s of connecting |
| `pos` | `x`, `z`, `ry`, `a` | floats; `ry` yaw radians; `a` animation: `0` idle, `1` walk, `2` run, `3` sit. Server ignores more than 15/s and clamps to the floor bounds ±60 |
| `seat` | `st` (station id string, ≤ 32 chars) or `null` | announce sitting at / leaving a station on the floor; purely cosmetic for others |
| `chat` | `text` (≤ 140 chars) | rate limit 1 per 1.5 s, 10 per minute, else dropped with `err` |
| `pk_watch` | `table` (int) | receive `pk_state` for a table without sitting; also subscribes to its events |
| `pk_unwatch` | `table` | |
| `pk_join` | `table`, `seat` (0-based), `buyin` | buy-in must be within the table's min/max and ≤ balance. Coins move in a `tx()` before the seat is granted |
| `pk_addon` | `amount` | top up between hands, up to `max_buyin` total stack |
| `pk_leave` | | cash out, coins return to balance (after the current hand if in one: the player is folded/marked leaving and paid when the hand ends) |
| `pk_sitout` | `on` (bool) | |
| `pk_act` | `act` (`fold`,`check`,`call`,`raise`,`allin`), `amt` (raise TO total, only for `raise`), `hand`, `seq` | `hand` and `seq` must match the current hand number and action sequence, else `pk_err` and no-op (protects against double clicks and stale UIs) |
| `ping` | | server replies `pong` |

### Server → client

| t | fields |
|---|---|
| `welcome` | `id` (your connection id), `uid`, `name`, `guest` (bool), `players` (array of `[id, uid, name, x, z, ry, a, st]`; empty in the `poker` room), `tables` (poker table summaries: `id, name, seats, sb, bb, min_buy, max_buy, seated, playing`; `seated` counts house players, `playing` is a bool), `online` (distinct people, both rooms). A connection whose uid already holds a poker seat (a reconnect inside the away window, or a second tab) also gets a `pk_state` for that table right after `welcome` |
| `join` | `p`: `[id, uid, name, x, z, ry, a, st]` |
| `leave` | `id` |
| `snap` | `ps`: array of `[id, x, z, ry, a]` for everyone who moved since the last snapshot, 10 per second |
| `seat` | `id`, `st` |
| `chat` | `id`, `name`, `text` (already length-limited; the client must still HTML-escape) |
| `online` | `n` |
| `bal` | `balance` (after a buy-in, add-on or cash-out) |
| `err` | `msg` |
| `pong` | |
| `pk_tables` | `tables` (same summaries as in `welcome`), sent when occupancy changes |
| `pk_state` | `table`: the `pk_view()` output for this viewer, sent on watch/join and after every event batch (authoritative, replaces client state) |
| `pk_events` | `table` (id), `events`: list of engine events since the last state, for animation. Always followed by a `pk_state` in the same tick |
| `pk_err` | `msg` |

Connections that send nothing (not even a `ping` or a pong) for 40 s are closed with 1001; the server sends a WebSocket ping at half that interval (browsers answer automatically). A socket that has not sent `hello` within 5 s of connecting is closed with 1008. `--idle` changes the 40 s.

## The floor (3D) and stations

Station ids are strings chosen by the floor module, e.g. `slot:tiki:2`, `table:craps`, `poker:1:3` (table 1, seat 3). The server does not validate them except for length; it only relays `seat` so other avatars can be posed. Real poker seating goes through `pk_join`.

When a player sits at a station the floor module loads `?action=<slug>&embed=1` in an iframe on the machine's screen. In `embed` mode the page renders without header, footer, rules and rail, and `setBalance()` also posts `{t:'gt_balance', balance}` to `window.parent` (same origin) so the HUD stays current.

## Poker engine API (`index.php`)

All functions are pure over a table state array except that `pk_start_hand()` draws randomness with `random_int` / `random_bytes`. Nothing here touches the database or the session; `ws.php` owns persistence. Seats are 0-based.

### Table state

```php
[
  'id' => 1, 'name' => 'Bayside 10/20', 'seats' => 6, 'sb' => 10, 'bb' => 20, 'min_buy' => 800, 'max_buy' => 4000, 'act_secs' => 20,
  'hand_no' => 0,                    // increments on each pk_start_hand
  'phase' => 'idle',                 // idle | preflop | flop | turn | river | showdown | settle
  'button' => null,                  // seat index or null before the first hand
  'players' => [                     // seat => player, only occupied seats present
    0 => ['uid' => 'p12', 'pid' => 12, 'name' => 'lalo', 'bot' => false,
          'stack' => 4000, 'bet' => 0, 'total' => 0,   // bet = this street, total = whole hand
          'cards' => [], 'in' => false, 'allin' => false, 'sitout' => false, 'acted' => false,
          'timeouts' => 0, 'show' => false, 'last' => null, 'leaving' => false, 'away' => false],
  ],
  'deck' => [], 'deck_salt' => '', 'deck_hash' => '',   // deck is the full shuffled 52 in deal order
  'board' => [], 'pot' => 0,          // pot = chips committed on finished streets (bets of the live street are in players[*].bet)
  'pots' => [],                       // filled at showdown: [['amount' => 300, 'eligible' => [0, 2], 'winners' => [2]], ...]
  'to_act' => null, 'deadline' => null, 'cur_bet' => 0, 'min_raise' => 20, 'last_aggressor' => null,
  'seq' => 0,                         // increments on every accepted action; clients echo it in pk_act
  'actions' => [],                    // [['street' => 'preflop', 'seat' => 0, 'act' => 'raise', 'amt' => 60, 'at' => 1712345678.1], ...]
  'winners' => [],                    // at settle: [['seat' => 2, 'amount' => 300, 'hand' => 'Two Pair, Kings and Nines', 'cards' => ['Kh','9d']]]
  'started_at' => null, 'next_at' => null, 'bot_at' => null,
  'log' => [],                        // last 30 human-readable lines
]
```

Cards are two-character strings: rank `2..9 T J Q K A`, suit `s h d c` (e.g. `As`, `Td`).

### Functions

```php
pk_new_table(array $row): array
    // from a poker_tables DB row (name, seats, small_blind, big_blind, min_buyin, max_buyin); act_secs from setting poker_action_seconds

pk_sit(array &$t, int $seat, string $uid, int $pid, string $name, int $stack, bool $bot = false): void
    // DomainException if the seat is taken or out of range, the uid already sits here, or stack is outside [min_buy, max_buy].
    // A player who sits during a live hand waits for the next one (in=false).

pk_addon(array &$t, int $seat, int $amount): void
    // only when the seat is not in a live hand; stack after add-on ≤ max_buy.

pk_leave(array &$t, int $seat): int
    // Removes the seat immediately if not in a live hand and returns the stack. If in a live hand: folds them (if to act or later),
    // marks leaving=true and returns -1; pk_tick() removes them at hand end and the 'hand_end' event carries ['leavers' => [seat => stack]].

pk_sitout(array &$t, int $seat, bool $on): void

pk_ready(array $t, float $now): bool
    // phase idle, next_at reached (or null), and ≥ 2 seats with stack > 0 and !sitout and !leaving.

pk_start_hand(array &$t, float $now): array   // events
    // Moves the button (first hand: random seat among the ready ones). Heads-up: button is the small blind and acts first preflop.
    // Posts blinds (a short stack posts what it has and is all-in). Shuffles with csprng_shuffle(), salt = bin2hex(random_bytes(16)),
    // deck_hash = hash('sha256', implode(' ', $deck) . '|' . $salt). Deals two cards each starting left of the button.
    // Sets to_act (left of the big blind, or the button heads-up), deadline = now + act_secs, cur_bet = bb, min_raise = bb.

pk_legal(array $t, int $seat): ?array
    // null unless it is this seat's turn. Otherwise:
    // ['fold' => true, 'check' => bool, 'call' => int (0 when check is available; capped at the stack),
    //  'raise' => ['min' => int, 'max' => int] | null   (raise TO totals; null when the stack can't cover a min raise: then only allin),
    //  'allin' => int (total the seat would have in front after shoving)]

pk_act(array &$t, int $seat, string $act, int $amt, float $now): array   // events
    // Validates against pk_legal, DomainException on anything illegal. 'raise' with $amt = the total to raise TO.
    // 'allin' is always legal in turn. A shove that doesn't reach a full min raise does not reopen the action for players who already acted.
    // Advances the street when everyone has acted and matched (or is all-in), runs out the board when ≤1 player can still act,
    // and runs the showdown + settlement, filling pots/winners and moving to phase 'settle' with next_at = now + 5.
    // Each accepted action bumps seq and appends to actions. Odd chips go to the first winning seat left of the button.

pk_tick(array &$t, float $now): array   // events
    // Called every loop tick by ws.php. Handles: action timeouts (check if free, else fold; timeouts++ and sitout after 2),
    // bot decisions when to_act is a bot and now ≥ bot_at (bot_at is set to now + 0.8..2.5 s when a bot comes to act),
    // settle → idle after next_at, removing leavers and busted real players, marking busted bots for rebuy (ws.php rebuys them),
    // idle → start the next hand when pk_ready(). Returns [] when nothing happened.

pk_view(array $t, ?string $uid): array
    // What one viewer may know. Hole cards only for the viewer's own seat, plus every seat with show=true (showdown).
    // Never includes deck or deck_salt (deck_hash yes). Includes legal actions for the viewer when it is their turn,
    // ms remaining on the clock, seq, hand_no, and everything the client needs to render the table.

pk_bot_act(array $t, int $seat): array   // ['act' => 'raise', 'amt' => 60]
    // Rule-based: preflop chart by hand class and position, postflop by made-hand strength + draws + pot odds, an occasional bluff.
    // Must always return a legal action.

pk_eval7(array $cards): array
    // 5, 6 or 7 cards. ['rank' => 0..8 (high card .. straight flush), 'score' => int (higher wins, total order),
    //                   'name' => 'Full House, Kings over Nines', 'best' => the five cards used]

pk_hand_record(array $t): array
    // After a hand: everything needed for poker_hands + a public verifier: hand_no, deck_hash, deck_salt, deck (in deal order),
    // board, players (seat, uid, name, bot, start_stack, end_stack, cards, result), actions, pots, winners, started_at, ended_at.
```

### Events (returned by the engine, relayed by `ws.php` as `pk_events`)

`['t' => 'hand_start', 'hand' => n, 'button' => seat, 'deck_hash' => ..]`, `['t' => 'post', 'seat', 'amt', 'kind' => 'sb'|'bb']`, `['t' => 'deal']`, `['t' => 'action', 'seat', 'act', 'amt', 'seq']`, `['t' => 'street', 'phase' => 'flop', 'cards' => [..]]`, `['t' => 'showdown', 'shows' => [seat => cards]]`, `['t' => 'win', 'seat', 'amount', 'hand', 'pot' => index]`, `['t' => 'hand_end', 'deck_salt', 'deck', 'leavers' => [..], 'busted' => [..]]`, `['t' => 'timeout', 'seat']`, `['t' => 'sitout', 'seat', 'on']`, `['t' => 'sit', 'seat']`, `['t' => 'stand', 'seat']`.

### Deck commitment (why players can trust the deal)

Before any card is dealt the server publishes `deck_hash = sha256(deck_in_deal_order + '|' + salt)`. After the hand it reveals the deck and the salt. Anyone can recompute the hash and check the hole cards and board against the deal order (two rounds to the seats starting left of the button, then burn + 3, burn + 1, burn + 1). `?action=poker_hand&id=N` renders a hand history with the check built in.

## Persistence (`ws.php`)

- `poker_tables`: configuration, editable in the back office. Loaded at startup and re-read every 30 s: a new enabled table is hosted, a disabled or deleted one cashes everyone out (after the current hand) and disappears, name / blind / buy-in / seat / bot changes apply when the table is next idle.
- House players want company: at a table where nobody real is seated or watching (`pk_watch`) the bots sit out between hands, so an empty room burns no CPU and writes no bot-only hand histories; they sit back in as soon as someone sits down or watches.
- `poker_seats`: one row per real seated player (unique on player_id). Written when a player sits (in the same `tx()` as the buy-in `move_coins(pid, -buyin, 'wager', 'poker', ...)`), updated with the end-of-hand stack after every hand, deleted on cash-out (`move_coins(pid, +stack, 'payout', 'poker', ...)`).
- On startup `ws.php` refunds every row still in `poker_seats` to the players' balances ("table reset") and deletes the rows, so a crash can never eat chips: the worst case is that the interrupted hand is void.
- `poker_hands`: one row per completed hand with the full `pk_hand_record()`. `record_round(pid, wagered, won)` is called per real player per hand so the leaderboards count poker.
- Bots have `pid = 0`, `uid = "b:<table>:<n>"`, names from a fixed list, and are labelled as house players in every view (`bot: true`). They rebuy to a random stack within the buy-in range after busting.
- A real player who disconnects is marked `away` (auto sit-out); if still away after 90 s, or at the end of the hand they were in, the server cashes them out.

## Security rules that apply everywhere

- The socket server trusts nothing from the client except a valid ticket; every `pk_act` is validated by `pk_legal()` and the `hand`/`seq` echo.
- Hole cards, the deck and the salt are never sent to anyone who is not entitled to them; `pk_view()` is the only serializer used for clients.
- Chat text is length-limited server-side and HTML-escaped client-side. Names come from the ticket, not from the client.
- Position updates are clamped and rate-limited; a client can't teleport others or spoof another connection id.
- `ws.php` checks the `Origin` header against the site origin(s) and answers mismatches with 403 before the handshake completes. Setting `rt_origins` (comma-separated) is the allow-list when set; blank = derive from the `Host` header the socket was reached on: `http(s)://<host>` exactly, or any port when the host is localhost / 127.0.0.1 / ::1 / a bare IP address (dev boxes). A request without an `Origin` header is not a browser and is admitted: the ticket is its credential (single use, 60 s, HMAC-signed).
