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
php tests/ws_test.php                                     # end-to-end tests: start their own ws.php on 8300-8399 against a scratch copy (~40 s)
php tests/poker_e2e_test.php                              # a scripted 2-player + 2-bot session against the real engine on 8900-8949 (~2.5 min)
```

`ws.php` includes `index.php` with `GT_NO_ROUTE` defined, so it shares the database, `tx()`, `move_coins()`, settings and the poker engine. It never touches the PHP session.

- `GET /health` on the socket port (a plain HTTP request without `Upgrade`) answers `{ "ok": true, "online": n, "tables": [{ "id", "seated", "hand_no" }] }` for monitoring.
- Logs go to stdout and to `data/ws.log` (rotated to `ws.log.1` above 5 MB); `--verbose` adds one line per connection event, action and hand.
- The timers can be shortened with `--idle` / `--away` or the environment variables `GT_WS_IDLE` / `GT_WS_AWAY` (the tests do). Settings such as `rt_origins` and `poker_action_seconds` are read once at start-up: restart `ws.php` after changing them.
- The engine is the `pk_*` block of `index.php`; `ws.php` passes `act_secs` (the `poker_action_seconds` setting, read once at start-up) into `pk_new_table()` so the engine never touches the database. Without an engine (no `pk_*` functions) the server hosts the floor only and answers every `pk_*` message with `pk_err`. There is no stub engine any more: the tests run the real one.
- SIGINT / SIGTERM close every socket with 1001, refund every `poker_seats` row at what the row says (see Persistence: an interrupted hand is void) and exit 0.
- One `ws.php` per database: it holds an exclusive lock on `data/ws.lock` for as long as it runs. A second copy (double launch, restart overlap, two servers pointed at one database) logs `Another ws.php already owns …` and exits 1 before it has touched the ledger.

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
| `seat` | `st` (station id string, ≤ 32 chars) or `null` | announce sitting at / leaving a station on the floor; purely cosmetic for others. A repeat of the current station is ignored, and more than 4 changes a second are dropped (each one is relayed to the whole floor) |
| `chat` | `text` (≤ 140 chars) | rate limit 1 per 1.5 s, 10 per minute, else dropped with `err` |
| `pk_watch` | `table` (int) | receive `pk_state` for a table without sitting; also subscribes to its events |
| `pk_unwatch` | `table` | |
| `pk_join` | `table`, `seat` (0-based), `buyin` | buy-in must be within the table's min/max and ≤ balance. Coins move in a `tx()` before the seat is granted |
| `pk_addon` | `amount` | top up between hands, up to `max_buyin` total stack |
| `pk_leave` | | cash out, coins return to balance (after the current hand if in one: the player is folded/marked leaving and paid when the hand ends) |
| `pk_sitout` | `on` (bool) | a repeat of the current state is a no-op; more than 2 real toggles a second → `pk_err` (each one costs every viewer a `pk_events` + `pk_state`) |
| `pk_post` | `on` (bool, default true) | post a big blind to be dealt into the next hand instead of waiting for the big blind; only matters while the seat `owes` one. Relayed to `pk_post()`; a repeat of the current flag is a no-op, more than 2 real toggles a second → `pk_err` |
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
| `pk_state` | `table`: the `pk_view()` output for this viewer, sent on watch/join and after every event batch (authoritative, replaces client state). `players` is keyed by seat: JSON carries it as an array when seats `0..n-1` are exactly the occupied ones and as an object (`{"1": …, "3": …}`) otherwise, so clients index it by seat number either way and never assume a dense list |
| `pk_events` | `table` (id), `events`: list of engine events since the last state, for animation. Always followed by a `pk_state` in the same tick. A player whose seat the engine just removed (paid at `hand_end`, busted, or cashed out at once) is still a viewer for that tick: they get the `hand_end` events and one closing `pk_state` (`me` null, seat gone) of the hand they were in |
| `pk_err` | `msg` |

Connections that send nothing (not even a `ping` or a pong) for 40 s are closed with 1001; the server sends a WebSocket ping at half that interval (browsers answer automatically). A socket that has not sent `hello` within 5 s of connecting is closed with 1008. `--idle` changes the 40 s.

## The floor (3D) and stations

Station ids are strings chosen by the floor module, e.g. `slot:tiki:2`, `table:craps`, `poker:1:3` (table 1, seat 3). The server does not validate them except for length; it only relays `seat` so other avatars can be posed. Real poker seating goes through `pk_join`.

When a player sits at a station the floor module loads `?action=<slug>&embed=1` in an iframe on the machine's screen. The iframe renders at a virtual size up to 1/0.6 of the screen's on-screen size and is scaled down so the game's main button (the first visible gold button in `.game-stage`) fits; if it still doesn't, the floor scrolls the embed page to it. The floor sends `pos` at most 10 times a second (a held-back change goes out once 100 ms have passed, so the resting position always arrives). In `embed` mode the page renders without header, footer, rules and rail, and `setBalance()` also posts `{t:'gt_balance', balance}` to `window.parent` (same origin) so the HUD stays current.

## Poker engine API (`index.php`)

All functions are pure over a table state array except that `pk_start_hand()` draws randomness with `random_int` / `random_bytes` (and bots / bot timing use `random_int`). Nothing here touches the database or the session; `ws.php` owns persistence. Seats are 0-based.

Tests: `php goldtide/tests/poker_test.php` (no framework, exit 0 = green, ~5 s): evaluator against a brute-force reference, scripted betting scenarios, side pots, timers, a 5,000-hand fuzz with invariants after every action, record verification and a throughput figure. A casino partner's auditor can run it as is.

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
          'timeouts' => 0, 'show' => false, 'last' => null, 'leaving' => false, 'away' => false,
          'owes' => true, 'post' => false],             // owes a big blind (new seat / sat a hand out); post = asked to post one to be dealt in now
  ],
  'deck' => [], 'deck_salt' => '', 'deck_hash' => '',   // deck is the full shuffled 52 in deal order
  'board' => [], 'pot' => 0,          // pot = chips committed on finished streets (bets of the live street are in players[*].bet)
  'pots' => [],                       // filled at showdown: [['amount' => 300, 'eligible' => [0, 2], 'winners' => [2]], ...]
  'to_act' => null, 'deadline' => null, 'cur_bet' => 0, 'min_raise' => 20, 'last_aggressor' => null,
  'seq' => 0,                         // increments on every accepted action; clients echo it in pk_act
  'actions' => [],                    // [['street' => 'preflop', 'seat' => 0, 'act' => 'raise', 'amt' => 60, 'at' => 1712345678.1], ...]
  'winners' => [],                    // at settle: [['seat' => 2, 'amount' => 300, 'hand' => 'Two Pair, Kings and Nines', 'cards' => ['Kh','9d']]]
                                      // (engine state; pk_view() blanks 'cards' for a seat that did not show, except in that seat's own view, see below)
  'started_at' => null, 'next_at' => null, 'bot_at' => null,
  'log' => [],                        // last 30 human-readable lines
  // private bookkeeping, never serialised by pk_view(): sb_seat, bb_seat, dpos (next deck position), hand_chips (chips dealt in, for the
  // conservation check), clock (last $now the engine saw), events (queued sit/stand/sitout/away/leaver-fold events, flushed by the next
  // pk_tick), hrec (record of the last finished hand), runout (streets dealt with no betting). Per player: dealt, abet (bet after the seat's
  // last action, for the reopen rule), sstack (stack at hand start), hand (hand name once shown).
]
```

Cards are two-character strings: rank `2..9 T J Q K A`, suit `s h d c` (e.g. `As`, `Td`).

### House rules the engine implements

- Simple moving button: it moves clockwise to the next seat that will be dealt in; no dead button / dead small blind. Heads-up the button posts the small blind, acts first preflop and last postflop.
- Missed blinds (so sitting out, disconnecting or seat-hopping never dodges a blind): the moving button carries the game on without a seat that is not dealt in (its blinds land on the seats after it), so every seat that sits a hand out (sitting out, away, busted, or new) owes a big blind (`owes: true`) before it is dealt in again. It is dealt in when the big blind comes round to it, or, from behind the big blind, by posting a live big blind to play at once (`pk_post()`, wire `pk_post`; house players always post). Nobody enters between the button and the big blind. A posted big blind is live: it counts as the seat's bet and the seat keeps the option, like a second big blind (`post` event with `kind: "post"`, action `post`). When fewer than two seats are free of debt the game is (re)starting: everyone is dealt in and the debts are waived. (With a moving button "which seats the big blind passed" stops being well defined once several seats are out, so the rule is the simple one: a hand out costs a big blind on the way back in.)
- Short blinds post what they have and are all-in; the price to see the flop stays the full big blind.
- Min bet = big blind; min raise = size of the last full raise; a short all-in does not reopen the action for a player who already acted unless the bet has grown by a full raise since that player's own last action (TDA rule 44, so several short all-ins can add up to a reopen). Nobody may raise when no other player can still act.
- `call` is only legal when there is something to call (`legal['call'] > 0`); with nothing to call the client sends `check`.
- Uncalled chips (the excess over the largest other bet of the street, folded players' bets included) go back at the end of the street with a `return` event.
- When at most one player can still act the board runs out in the same call: one `street` event per street, and the settle pause is 5 s + 1.2 s per run-out street so clients can animate. Clients pace the animation themselves from the events.
- Everyone who reaches the showdown shows (no mucking); the last player standing wins without showing. Side pots by total contribution; ties split evenly; odd chips one each to the first winning seats clockwise from the button (35 three ways is 12 / 12 / 11).
- Timeout: check if free, else fold; two timeouts sit the player out (they still finish the hand folded). A sit-out asked for mid-hand takes effect at the next hand. `away` (set by ws.php on disconnect) counts as sitting out for dealing and for `pk_ready()`.
- Leaving mid-hand folds the player at once (in turn or out of turn; an all-in player has no decision left and stays in) and pays them at hand end. Leaving during `settle` folds nothing: the hand is decided, so `seq`, `actions` and the players' `in`/`show` are untouched and no `action` event is emitted; the seat is only marked `leaving` and paid at `hand_end`.
- Burn cards: one before the flop, turn and river, so with n players dealt in the flop is `deck[2n+1..2n+3]`, the turn `deck[2n+5]`, the river `deck[2n+7]`.

### Functions

```php
pk_new_table(array $row): array
    // from a poker_tables DB row (name, seats, small_blind, big_blind, min_buyin, max_buyin); act_secs from setting poker_action_seconds

pk_sit(array &$t, int $seat, string $uid, int $pid, string $name, int $stack, bool $bot = false): void
    // DomainException if the seat is taken or out of range, the uid already sits here, or stack is outside [min_buy, max_buy].
    // Never joins a running hand (in=false). A new seat owes a big blind: it is dealt in when the big blind reaches it, or at once
    // by posting one (pk_post) from behind the big blind; on a (re)starting table (fewer than two debt-free seats) everyone is dealt in.

pk_addon(array &$t, int $seat, int $amount): void
    // only when the seat is not in a live hand (a seat dealt into the running hand waits for hand_end, even after folding);
    // stack after add-on ≤ max_buy. Also how ws.php rebuys a busted bot (stack 0 → any amount ≤ max_buy).

pk_leave(array &$t, int $seat): int
    // Removes the seat immediately if not in a live hand and returns the stack. If in a live hand: folds them at once (in turn through the
    // normal action path, otherwise out of turn; an all-in player stays in; during 'settle' nothing is folded), marks leaving=true and
    // returns -1; pk_tick() removes them at hand end and the 'hand_end' event carries ['leavers' => [seat => stack]]. The fold's events
    // arrive with the next pk_tick().

pk_sitout(array &$t, int $seat, bool $on): void
    // Takes effect from the next hand (a player mid-hand keeps acting in it). Off resets the timeout counter. A seat that sits a hand out
    // owes a big blind (owes=true) and comes back only as the big blind or by posting (pk_post).

pk_post(array &$t, int $seat, bool $on = true): void
    // Ask to post a live big blind to be dealt in at the next hand instead of waiting for the big blind. Only matters while owes=true;
    // consumed when the seat is dealt in; never honoured between the button and the big blind. Bots post without asking.

pk_away(array &$t, int $seat, bool $on): void
    // Same as a sit-out, flagged separately so clients can show "away"; ws.php sets it on disconnect and clears it on reconnect.

pk_ready(array $t, float $now): bool
    // phase idle, next_at reached (or null), and ≥ 2 seats with stack > 0 and !sitout and !away and !leaving.

pk_start_hand(array &$t, float $now): array   // events
    // Moves the button among the debt-free dealable seats (first hand: random). Deals in every debt-free seat, an owing seat that has
    // become the big blind, and owing seats behind the big blind that asked to post (or are bots); every occupied seat not dealt in owes a
    // big blind from now on (owes=true, log line). Heads-up: button is the small blind and acts first preflop.
    // Posts blinds and the posters' live big blinds (a short stack posts what it has and is all-in). Shuffles with csprng_shuffle(), salt = bin2hex(random_bytes(16)),
    // deck_hash = hash('sha256', implode(' ', $deck) . '|' . $salt). Deals two cards each starting left of the button.
    // Sets to_act (left of the big blind, or the button heads-up), deadline = now + act_secs, cur_bet = bb, min_raise = bb.

pk_legal(array $t, int $seat): ?array
    // null unless it is this seat's turn. Otherwise:
    // ['fold' => true, 'check' => bool, 'call' => int (0 when check is available; capped at the stack),
    //  'raise' => ['min' => int, 'max' => int] | null   (raise TO totals; null when the stack can't cover a min raise: then only allin),
    //  'allin' => int (total the seat would have in front after shoving)]

pk_act(array &$t, int $seat, string $act, int $amt, float $now): array   // events
    // Validates against pk_legal, DomainException on anything illegal (state untouched). 'raise' with $amt = the total to raise TO;
    // 'call' only when legal['call'] > 0. 'allin' is always legal in turn. A shove that doesn't reach a full min raise does not reopen
    // the action for players who already acted (unless it adds up to a full raise since their last action).
    // Advances the street when everyone has acted and matched (or is all-in), runs out the board when ≤1 player can still act,
    // and runs the showdown + settlement, filling pots/winners and moving to phase 'settle' with next_at = now + 5 (+1.2 s per run-out street).
    // Each accepted action bumps seq and appends to actions ('amt' = the seat's bet after the action, 'put' = chips added, 'auto' on
    // timeouts and leaver folds). Odd chips go one each to the first winning seats left of the button.

pk_tick(array &$t, float $now): array   // events
    // Called every loop tick by ws.php. Returns queued sit/stand/sitout/away events first, then handles at most one player decision:
    // action timeouts (check if free, else fold; timeouts++ and sitout after 2), bot decisions when to_act is a bot and now ≥ bot_at
    // (bot_at is set to now + 0.8..2.5 s when a bot comes to act), settle → idle after next_at (the 'hand_end' event; removes leavers and
    // busted real players, busted bots stay seated with stack 0 for ws.php to rebuy with pk_addon), idle → start the next hand when
    // pk_ready(). A hand never ends and restarts in the same tick, so ws.php can persist the record, pay leavers and rebuy bots
    // between the two. Returns [] when nothing happened. ws.php calls pk_tick() before pk_view(): the view's clocks use the last $now seen.

pk_view(array $t, ?string $uid): array
    // What one viewer may know. Hole cards only for the viewer's own seat, plus every seat with show=true (showdown); other seats get
    // 'cards' => <int count> so clients can draw backs. Never includes deck or deck_salt (deck_hash yes).
    // Keys: id, name, seats, sb, bb, min_buy, max_buy, act_secs, hand_no, phase, button, sb_seat, bb_seat, board, pot (finished streets),
    // pot_total (pot + live bets), pots (from showdown), cur_bet, min_raise, to_act, ms_left, next_ms (until the next hand / null), seq,
    // deck_hash, winners (cards only for seats that show), log (last 30), players (seat => uid, name, bot, stack, bet, total, in, allin,
    // sitout, away, leaving, show, owes, post, last, cards, hand), me (viewer's seat or null), legal (pk_legal() for the viewer in turn, else null).
    // Clients show owes as "waiting for the big blind" with a "post to play" control that sends pk_post.
    // That rule covers winners[].cards as much as players[].cards: a pot taken because everyone else folded is won without
    // showing, so its winner's cards are null for everyone but the winner (the hand record keeps them).

pk_bot_act(array $t, int $seat): array   // ['act' => 'raise', 'amt' => 60]
    // Rule-based: preflop chart by hand class and position, postflop by made-hand strength + draws + pot odds, an occasional bluff.
    // Must always return a legal action.

pk_eval7(array $cards): array
    // 5, 6 or 7 cards. ['rank' => 0..8 (high card .. straight flush), 'score' => int (higher wins, total order),
    //                   'name' => 'Full House, Kings over Nines', 'best' => the five cards used]

pk_hand_record(array $t): array
    // The last finished hand (frozen at settle, kept until the next settle; read it when 'hand_end' arrives): hand_no,
    // table (id, name, seats, sb, bb, min_buy, max_buy), deck_hash, deck_salt, deck (in deal order), button, sb_seat, bb_seat, board, pot,
    // players (seat, uid, name, bot, start_stack, end_stack, net, cards, show, hand, won, result 'win'|'lose'|'fold'), actions, pots,
    // winners, started_at, ended_at. Folded players' cards are in the record too: the verifier needs every dealt card.

pk_verify_record(array $rec): array   // ['hash_ok' => bool, 'deal_ok' => bool]
    // Recomputes deck_hash from deck + salt and checks every player's hole cards and the board against the deal order. Safe on untrusted
    // input (a pasted hand history): pk_record_shape_ok() first bounds every field it uses (seats 2..9, button in range, 52 distinct card
    // strings, string salt/hash, ≤ seats players with distinct in-range integer seats and two card strings, a 0/3/4/5 card board) and a
    // malformed record fails both checks without warnings or unbounded loops.

pk_deal_order(int $seats, int $button, array $occupiedSeats): array
    // Seats in deal order: clockwise from the seat left of the button, button last. Pure; the hand-history page reuses it.

pk_assert_invariants(array $t): void
    // Debug helper (tests): RuntimeException naming the first broken invariant (chip conservation, stacks ≥ 0, board length per phase, ...).
```

### Events (returned by the engine, relayed by `ws.php` as `pk_events`)

`['t' => 'hand_start', 'hand' => n, 'button' => seat, 'deck_hash' => ..]`, `['t' => 'post', 'seat', 'amt', 'kind' => 'sb'|'bb'|'post']` (`post` = a live big blind posted to be dealt in), `['t' => 'deal']`, `['t' => 'action', 'seat', 'act', 'amt' (bet after the action), 'put' (chips added), 'seq']`, `['t' => 'street', 'phase' => 'flop', 'cards' => [..]]`, `['t' => 'return', 'seat', 'amt']` (uncalled chips back), `['t' => 'showdown', 'shows' => [seat => cards]]`, `['t' => 'win', 'seat', 'amount', 'hand', 'pot' => index]`, `['t' => 'hand_end', 'deck_salt', 'deck', 'leavers' => [seat => stack], 'busted' => [seat => ['uid', 'bot']]]`, `['t' => 'timeout', 'seat']`, `['t' => 'sitout', 'seat', 'on']`, `['t' => 'away', 'seat', 'on']`, `['t' => 'sit', 'seat']`, `['t' => 'stand', 'seat']`.

Events from `pk_sit`, `pk_leave`, `pk_sitout`, `pk_post` and `pk_away` are queued and come out of the next `pk_tick()`; `ws.php` marks the table dirty right after those calls, so the fresh `pk_state` goes out in the same tick as the events. `ws.php` calls `pk_tick($t, microtime(true))` on every loop tick and `pk_view()` after it, wraps every engine call from a client message in `try/catch DomainException → pk_err` (the state is untouched on a refusal), checks the `hand`/`seq` echo of `pk_act` against `$t['hand_no']` / `$t['seq']` before calling the engine, and passes `call` / `check` through exactly as the client sent them (the engine rejects a `call` when nothing is owed).

### Deck commitment (why players can trust the deal)

Before any card is dealt the server publishes `deck_hash = sha256(deck_in_deal_order + '|' + salt)`. After the hand it reveals the deck and the salt. Anyone can recompute the hash and check the hole cards and board against the deal order (two rounds to the seats starting left of the button, then burn + 3, burn + 1, burn + 1). `?action=poker_hand&id=N` renders a hand history with the check built in.

## Persistence (`ws.php`)

- `poker_tables`: configuration, editable in the back office. Loaded at startup and re-read every 30 s: a new enabled table is hosted, a disabled or deleted one cashes everyone out (after the current hand) and disappears, name / blind / buy-in / seat / bot changes apply when the table is next idle.
- House players want company: at a table where nobody real is seated or watching (`pk_watch`) the bots sit out between hands, so an empty room burns no CPU and writes no bot-only hand histories; they sit back in as soon as someone sits down or watches.
- `poker_seats`: one row per real seated player (unique on player_id). Written when a player sits (in the same `tx()` as the buy-in `move_coins(pid, -buyin, 'wager', 'poker', ...)`), `+= amount` with an add-on (same tx as its wager), set to the end-of-hand stack at `hand_end`, deleted in the same `tx()` as the cash-out `move_coins(pid, +stack, 'payout', 'poker', ...)`. So between hands the row is the stack in front of the player; during a hand it is the stack the hand started with. The engine's own rules are checked on a copy of the state before the tx (a refused buy-in or add-on writes nothing).
- `hand_end` (the event `pk_tick()` returns when settle → idle; the engine never deals the next hand in the same tick) is persisted in ONE `tx()`, in this order: the `poker_hands` row (full `pk_hand_record()`), then per real player in the record: a mid-hand leaver (`leavers[seat]`, equal to the record's `end_stack`) is paid `move_coins(+stack, 'payout', 'poker', 'cash-out …')` and its seat row deleted; a busted player (end stack 0, already removed by the engine) has its row deleted and gets a `pk_err` notice; everyone else gets `poker_seats.stack = end_stack`; and `record_round(pid, start_stack − end_stack + won, won)` for each of them (so the leaderboards count poker: `rounds_played` +1 per hand dealt into). After the tx, players who disconnected during that hand are cashed out (the seat is idle now, so `pk_leave()` returns the stack: one more payout + delete tx) and busted bots rebuy with `pk_addon($t, $seat, random stack in the buy-in range rounded to the big blind)`. Should the hand_end tx fail, nothing of it is written; the leavers are still paid one by one (each with its row delete) and the failure is logged.
- `pk_leave` for a seat dealt into the running hand returns −1: the engine folds the player (or, during `settle`, only marks them leaving) and `ws.php` leaves the seat, its row and its bookkeeping in place until `hand_end` pays it from `leavers[]`. A second `pk_leave` meanwhile answers `pk_err`. A seat not in a live hand (idle, or sat down while a hand ran) is paid at once.
- Refund rule, an interrupted hand is void: on startup and on SIGINT/SIGTERM `ws.php` pays every row still in `poker_seats` back at what the row says ("table reset" payout) and deletes it, never at a live mid-hand stack. So a crash (or `kill -9`) costs the players nothing but the hand in flight, which is never recorded. Only the process that owns the database does this: `ws.php` first takes the exclusive lock on `data/ws.lock` and binds its listening socket, and touches the ledger only after both succeeded. A second `ws.php` started by mistake therefore exits without paying out seats the live server still holds (which would otherwise be paid a second time when those players cash out).
- Every path pays exactly once, because a payout and the DELETE of the seat row always share one `tx()`: cash-out now (idle seat), cash-out at `hand_end` (mid-hand leaver), the away window, the end of the hand a disconnected player was dealt into, a table disabled in the back office (each seat once, by the same two rules), busted (row deleted, nothing to pay), and the startup / shutdown refund of whatever rows are left.
- `poker_hands`: one row per completed hand with the full `pk_hand_record()` (the tests run `pk_verify_record()` on every stored row).
- Bots have `pid = 0`, `uid = "b:<table>:<n>"`, names from a fixed list, and are labelled as house players in every view (`bot: true`). They rebuy to a random stack within the buy-in range after busting and never touch the ledger.
- Disconnects: when the last connection of a seated player drops, `ws.php` calls `pk_away($t, seat, true)`: the player is dealt out of the following hands and posts no blinds; the hand they are in still runs its clock on them (timeouts fold them, an all-in player can still win). A reconnect (fresh ticket, same uid) inside the away window (90 s, `--away`) calls `pk_away(false)` and sends a `pk_state` right after `welcome`, no `pk_join` needed. The player is cashed out at the end of the hand they were dealt into, otherwise when the window expires (at once with `--away 0`).

## Security rules that apply everywhere

- The socket server trusts nothing from the client except a valid ticket; every `pk_act` is validated by `pk_legal()` and the `hand`/`seq` echo.
- Hole cards, the deck and the salt are never sent to anyone who is not entitled to them; `pk_view()` is the only serializer used for clients, and `ws.php` re-applies the rule to every view before it goes out (cards only for the viewer's own seat and seats with `show=true`, in `players[]` and `winners[]` alike; never `deck` or `deck_salt`), so an engine bug cannot leak a hand.
- Chat text is length-limited server-side and HTML-escaped client-side. Names come from the ticket, not from the client.
- Position updates are clamped and rate-limited; a client can't teleport others or spoof another connection id.
- `ws.php` checks the `Origin` header against the site origin(s) and answers mismatches with 403 before the handshake completes. Setting `rt_origins` (comma-separated) is the allow-list when set; blank = derive from the `Host` header the socket was reached on: `http(s)://<host>` exactly, or any port when the host is localhost / 127.0.0.1 / ::1 / a bare IP address (dev boxes). A request without an `Origin` header is not a browser and is admitted: the ticket is its credential (single use, 60 s, HMAC-signed).

## JS module API (`?action=asset&f=poker`, imported by the poker page and by the floor)

The poker module owns the socket. The floor imports it (the page config carries `poker_asset`, the versioned URL) and shares one connection for presence and poker.

```js
const M = await import(new URL(cfg.poker_asset, location.href).href);   // '?action=…' is not a valid bare specifier: resolve it first

// One socket per page. Fetches a ticket (POST cfg.ticket with the csrf meta), opens cfg.ws, sends hello,
// heartbeats every 20 s, reconnects with backoff (1,2,4,8…30 s + jitter, fresh ticket each time),
// state: 'connecting' | 'open' | 'closed' | 'offline' (4 failures; keeps retrying every 30 s).
// Dead sockets are dropped and retried: the ticket fetch times out after 10 s, a socket with no welcome 10 s after
// it is created is closed, and so is one that has received nothing (pong included) for 45 s (half-open TCP, a hung server).
const rt = M.connectRealtime(cfg, { room: 'floor' | 'poker', onOpen(welcome), onClose(), onMessage(msg) });
rt.send({ t: 'pos', x, z, ry, a });      // any protocol message
const off = rt.on('snap', msg => …);      // per-type subscription; returns an unsubscribe fn
rt.me;                                    // { id, uid, name, guest } after welcome
rt.tables;                                // latest poker table summaries (welcome / pk_tables)
rt.seated;                                // { id, name, turn } of the table this player sits at (from pk_state), or null
rt.syncBalance();                         // re-read the balance from ?action=api_me (done on every welcome)
rt.state; rt.close();

// Poker lobby: cards per cfg.tables with live counts. onOpen(tableId) is the navigation hook.
const lobby = M.mountPokerLobby(host, { rt, cfg, onOpen });   // → { destroy() }

// One table. mode 'page' draws the felt; mode 'hud' is the compact bottom bar the floor uses
// (the floor renders the felt/cards/chips in 3D from onState(view)). Never auto-leaves a seat.
// onOpenTable(id) navigates to the table the player is seated at when it is another one ("Back to my seat").
// The action bar unlocks on any reconnect (a pk_act can die with its socket) and 4 s after an act nobody answered.
const tbl = M.mountPokerTable(host, { rt, tableId, cfg, mode, seatHint, onState(view), onEvents(list), onLeave(), onOpenTable(id) });
tbl.sit(seat, buyin); tbl.leave(); tbl.act('raise', amountTo); tbl.sitout(true); tbl.post(true); tbl.addon(amount); tbl.view; tbl.destroy();

// Hand history replay + client-side deck-commitment check for ?action=poker_hand.
M.renderHandHistory(host, record);
```

Events the floor cares about from `onState(view)`: `view.players[seat].cards` is an array (faces known) or an integer (card backs), `view.board`, `view.pot`, `view.pots`, `view.to_act`, `view.button`, `view.winners`, `view.phase`, `view.me`.

Balance updates: on `bal` the module calls `window.goldTide.setBalance(balance)` when present. Refunds and cash-outs paid while a page was disconnected (ws.php start-up refund, the away window) send no `bal`, so every welcome, and every seat that disappears without one, re-reads `?action=api_me`; a `bal` frame that arrives while that request is out wins. Pages embedded in the floor (`?embed=1`) post `{t:'gt_balance', balance}` to `window.parent`; the floor checks `e.origin === location.origin` before trusting it.
