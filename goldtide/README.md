# Slop Casino

**A free-to-play social casino.** 26 games, a walk-around 3D casino floor, and live multiplayer Texas hold'em, all played with Gold Coins: play money with no cash value. Built so a casino partner can hand it to guests as a practice floor, a marketing hook, or an event activation without touching real-money gaming.

It's one `index.php` plus a SQLite database that builds itself on first run, and an optional `ws.php` realtime server for the multiplayer parts. No composer, no npm, no build step, no CDNs: three.js and the fonts are embedded.

```bash
php -S localhost:8000 index.php   # the site: every game works with just this
php ws.php                        # optional: multiplayer floor + live poker (port 8081)
# open http://localhost:8000
```

Or drop `index.php` on Bluehost or any Apache+PHP host, or run it on a Raspberry Pi behind a Cloudflare tunnel. Needs PHP 8.1+ with `pdo_sqlite`; `ws.php` runs on the built-in stream functions (no extensions to install); `pcntl` is used for clean shutdowns when present. On shared hosting that can't run a long-lived process, everything except multiplayer still works: the floor plays solo and shows "Multiplayer floor offline".

## what's inside

**For players: 26 games in six rooms, plus the floor**

| room | game | what it is | return |
|---|---|---|---|
| Slot Hall | **Sunset Reels** | the classic: 3 reels, 5 paylines | ~95% |
| | **Abyss Critters** | deep-sea creatures, kraken wilds, 10–25 free spins ×3, Sunken Treasure pick bonus | 95.5% |
| | **Tinfoil Hat** | conspiracy theories: UFOs, bigfoot, lizard people; free spins ×3, Declassified pick bonus | 95.0% |
| | **Black Site Breach** | top-secret data heist: keycards, vaults, lasers; free spins ×4, Vault Cracker pick bonus | 95.3% |
| | **Code Rain** | green digital-rain hacker world; rare free spins ×5, Mainframe Hack pick bonus | 95.0% |
| | **Tiki Tides** | tiki-bar luau, low volatility, free spins ×2, Volcano Wheel | 95.6% |
| | **Calavera Fiesta** | Día de los Muertos, 12–24 free spins ×2, Fiesta Wheel | 95.1% |
| 3D Games | **Coronado Roulette 3D** | real 3D wheel: rotor, frets, a ball that orbits, drops and settles | 97.3% |
| | **Harbor Craps** | full bubble craps: line, come, 3-4-5× odds, place/buy/lay on every number, Big 6/8, field, hardways, horn, C&E, every prop; 3D table or glass bubble dome | 98.6% pass |
| | **Pier Pusher** | boardwalk coin pusher in 3D | 95% |
| | *3D slot cabinet* | a toggle on every themed slot: curved drum reels, chrome, chasing bulbs | same as slot |
| Scratch & Keno | | | |
| | **Sunset Scratchers** | scratch 9 spots with your finger/mouse, match 3 | 91% |
| | **Kelp Keno** | pick 1–10 of 40, ten drawn | 94.2–95.6% (every pick count) |
| Table Games | **Coronado Roulette** | single-zero wheel, full board | 97.3% |
| | **Bayfront Baccarat** | player / banker / tie, full third-card tableau; 5% commission rounds to the nearest coin | 98.8% player / 98.9% banker |
| | **Surf Sic Bo** | three dice, 50 bets on the board (incl. 15 two-dice combinations at 6:1) | 97.2% small/big/combos, 92.1% singles, 81–90% the rest |
| | **Boardwalk Big Six** | 54-stop carnival money wheel | 78–89% (it's a carnival wheel) |
| | **Crab Crawl Derby** | six racing crabs at fixed odds, animated race | 93.9% |
| Card Room | **Harbor Blackjack** | 6 decks, S17, 3:2, double any two, split once (DAS), late surrender, peek | 99.6% (basic strategy, measured over 600k hands) |
| | **Boardwalk Poker** | Jacks or Better 9/6 video poker | 99.5% perfect play |
| | **Coastline 3-Card** | ante/play vs dealer + Pair Plus | ~98% ante/play (Q-6-4), 97.7% Pair Plus |
| | **Bayside Hold'em** | live no-limit Texas hold'em against real players, house players fill empty seats (always labelled); three tables from 10/20 to 250/500 | player vs player (no rake) |
| | **Tide Hi-Lo** | higher or lower, multiplier builds, cash out anytime | 99% |
| Boardwalk Arcade | **Tide Crash** | live multiplier curve, cash out before it breaks (a cash-out at exactly the break multiplier wins, manual or auto), auto cash-out | 99% |
| | **Pearl Drop** ★ | the flagship plinko (see below) | 98.5–98.9% (exact at multiples of 100 GC; 97.5–99.4% at the 10 GC minimum; 96.8–100.3% over every stake 10–5,000 GC, 98.3–99.1% from 100 GC up) |
| | **Reef Mines** | 5×5 grid, pick 1–24 urchins, find pearls; wins capped at 5,000× the bet | 99% |
| | **Lighthouse Dice** | slide your own odds, roll over (target or higher) / under (below target) | 99% |

### ★ The Floor (`?action=floor`)

A first-person 3D casino you walk around in. It's built in code (no downloaded assets): a roughly 70 × 45 m hall with a marble entrance lobby and the site name in gold, a bar, a cashier cage for free coins, the **Slot Hall** (48 cabinets, every slot several times), **the Pit** (an island per table game with a real centerpiece: a spinning roulette wheel, the craps bubble dome, the big six wheel, a sic bo cup, a crab track, the coin pusher, each ringed by seat terminals), the **Card Room** (blackjack-style tables and one oval poker table per live table), and the **Arcade** with Pearl Drop as a tall showpiece. Coffered ceilings, chandeliers, casino carpet, fog for depth.

- **Walk up and sit down.** WASD + mouse (pointer lock), Shift to run, E to play, Esc to stand. The camera eases into the seat and the machine's screen becomes the real game: the actual game page runs on the screen in true 3D perspective, so you still see the machines to your left and right and can turn your head (arrow keys or drag the edges) while you play. Every enabled game has at least one station (116 in all).
- **Other people.** Everyone on the floor shows up as an avatar with their name over their head, walking around, sitting at machines (their screen shows IN PLAY) and at poker tables. Positions are smoothed, chat pops up over their heads and in a chat panel (Enter to talk).
- **Poker in 3D.** Sit at a poker table and the felt, cards, chip stacks, bets, pot, dealer button and a light on whoever's acting are all drawn in the room, with the betting controls in a bar at the bottom.
- **Phones too.** A virtual joystick, drag to look, tap a machine to walk over and sit.
- **Graceful.** Without the realtime server the floor still plays solo. Without WebGL it lists every game as a link.
- **Your own building.** Drop a binary glTF at `data/floor.glb` (meters, y-up, origin at the entrance doors, hall toward −z, x −35..35, z 0..−45, 5 m ceiling; static meshes with PBR base colour and embedded textures) and it replaces the procedural floor, walls and ceiling while machines, tables and collisions stay. That's the path for a room modelled in Blender to match a partner's real property.

### Bayside Hold'em: live poker

Real no-limit Texas hold'em between players, hosted by `ws.php`.

- **Live-room rules**: moving button, heads-up blinds (button posts the small blind), min-raise = last full raise, short all-ins don't reopen the action (TDA rule), uncalled bets returned, exact side pots, odd chips to the first winner clockwise from the button, a missed-blind rule so nobody can sit out the big blind for free, an action clock (two timeouts and you sit out).
- **Exact evaluator**, checked against an independent brute-force reference on 30,000 random hands, plus a 5,000-hand fuzz that asserts chip conservation and legality after every single action.
- **Provably fair deal.** Before a card moves the table publishes SHA-256 of the shuffled deck plus a salt; after the hand it reveals both. Every hand has a history page (`?action=poker_hand&id=N`) that re-checks the hash and the deal order on the server and again in your browser.
- **Hidden cards stay hidden.** Each player gets their own view of the table; tests scan every frame sent to opponents and watchers for cards they shouldn't have.
- **Your coins are safe.** Buy-ins and cash-outs go through the same ledger as every other game. If the server crashes mid-hand, the next start refunds every seat its start-of-hand stack (the interrupted hand is void); a kill -9 test checks it to the coin.
- **House players** keep tables dealing when it's quiet. They're always marked HOUSE and never touch the ledger.

### The look

Slop Casino is themed after slop.cc: a near-black background (`#1d1d1a`), the coral mascot (`#ed7357`) as the logo, favicon and a blinking lobby hero, and bold heavy-sans headings. The lobby shows games as rounded video-style tiles, each with a dark pill in the corner (bet range, `3D` or `LIVE`). On the 3D floor the mascot floats over a marble plinth in the entrance lobby, and the big sign reads whatever `site_name` is set to. The light theme swaps in a warm off-white with a deeper coral. The games keep their own themed rooms and casino lettering inside the felt. Palette tokens live at the top of `app_css()` (`--bg`, `--gold` is the coral accent, `--gold-ink`), and the mascot is `slop_logo_svg()`.

### Rooms

Every classic game has its own themed room: an animated night-time scene behind the table and a sound palette. The harbor at night with a lighthouse beam (blackjack), a velvet VIP lounge with chandelier glow (baccarat), carnival bulbs and a turning Ferris wheel (big six), a kelp forest (keno), rolling surf (sic bo), fish crossing the reef (mines), a synthwave grid (video poker), a sunset with gulls (Sunset Reels), and more. Cards get a soft flip sound as they land, dice rattle, wheels tick, and every game has BIG / MEGA / EPIC win banners. One sound switch in the header mutes the whole site.

### 3D games

These are real 3D gameplay, built with three.js r170 (MIT). three.js is embedded in `index.php` (gzip+base64) and served from `?action=asset`, so everything still works offline from a single file. The 3D module only loads on pages that need it. The server still decides every outcome and the scene is steered to it: the roulette ball is guided into the pocket the server picked, and the dice tumble and settle on the rolled faces (a browser test checks 40 of 40 throws). Without WebGL, the 2D controls still play every game.

### Full craps

Harbor Craps deals the whole menu, bubble-craps style. You get Pass and Don't Pass, and Come and Don't Come, which travel to their own number. Odds are 3-4-5× behind the line and come bets, and 6× when laying, and they pay exactly true odds: the server only accepts odds in the multiples that pay without fractions (1 GC on 4/10, 2 GC on 5/9, 5 GC on 6/8; lay odds 2 / 3 / 6 GC). Every number has Place, Buy and Lay. Place 6/8 pays 7:6 in multiples of 6 GC, place 5/9 (7:5) and 4/10 (9:5) in multiples of 5 GC. Buy pays true odds and charges a 5% commission on the amount bought, only on a win, rounded to the nearest coin, so the house edge is 1.67% on 4/10, 2.00% on 5/9 and 2.27% on 6/8; buy bets go down in multiples of 20 GC so the vig is a whole coin. Lay pays true odds the other way less 5% of the win, only on a win (1.67% / 2.00% / 2.27%), in multiples of 40 GC on 4/10, 30 GC on 5/9 and 24 GC on 6/8. Any other amount is refused with a message naming the right multiple, and the chip rack snaps a tap to it (20 and 30 GC chips are on the rack for exactly this). Big 6 and Big 8, the field and all four hardways are on the board. The props are Any 7, Any craps, Aces, Ace-deuce, Yo, Boxcars, Horn and C & E. Place, buy, lay, big, hardway and come-odds bets are OFF on the come-out (lay bets being off is a house rule here; many live tables work them). **Take bets down** pulls back anything that isn't a contract bet. The 3D view flips between a full table (every chip stack sits on its printed spot) and a glass bubble dome where air jets pop the dice. `tests/audit_arcade3d_test.php` checks the exact expectation of every place, buy, lay and odds bet at every legal amount, and a CLI simulation of 80k rolls per bet matched the textbook house edges within noise.

### Slot Hall

Six themed 5-reel video slots on one shared engine: 243 ways (matching symbols pay left to right on adjacent reels), wilds on reels 2–4, and 3+ bonus symbols triggering free spins with a multiplier. Every cell is drawn independently, which gives the return-to-player an exact closed form. Each slot's table was solved to 95.0–95.6% (the figure in the table above, bonus included) and confirmed by simulation. Pays are 2-decimal multiples of the bet, so the engine does all win math in integer hundredths of the bet and rounds the spin's total (free spins included) down to a whole coin **once**: every part shown on screen adds up to the coins paid, and the coin paytable is produced by the same arithmetic. That single rounding still costs up to about 20/bet points of return, which is why the video slots take **50 GC minimum, in steps of 10 GC** (about 0.1 points at 50 GC, under 0.4 at any allowed bet, nothing at multiples of 100 GC, versus 1.5 points at the old 10 GC minimum and 0.4 at odd bets such as 51 GC). Wins cap at 5,000× the bet per spin, bonus included; the cap is applied to the same running total, so a capped spin's parts still add up, and free spins end at the spin that reaches it. Each slot has its own hand-drawn symbol set, animated backdrop (bubbles, digital rain, laser grid, UFO searchlights, torch embers, marigold petals), synthesized sound palette and volatility. Every slot also has a **bonus game with four jackpots**. It starts when a wild lands on each of reels 2, 3 and 4 in the base game (not during free spins). The sea, conspiracy, black-site and hacker slots play a real pick-3-of-12 bonus (Sunken Treasure, Declassified, Vault Cracker, Mainframe Hack): when it triggers the server deals 12 hidden prizes and keeps them in the round; the three tiles you tap are posted back, revealed and paid (bet × their sum), and the other nine then flip to show what they really held. A pick left unfinished is resumed when the page loads again, or settled with three random tiles before your next spin (the spin reply says so). Tiki Tides and Calavera Fiesta spin a jackpot wheel that shows a result the server already drew when the bonus started. A marquee shows the Mini (25×), Minor (75×), Major (250×) and Grand (1,000×) values at your current bet. The bonus EV is part of the closed-form RTP (any 3 of 12 i.i.d. tiles have the same expected sum as 3 draws) and was re-checked by simulation. You also get near-miss slowdowns when two bonus symbols land, a full free-spins mode, big/mega/epic win banners, autospin and turbo.

### ★ Pearl Drop, the flagship

The house favorite, and it's featured at the top of the lobby.

- **Golden pegs.** Every drop, 3 pegs light up gold. Each one a pearl touches doubles that pearl's multiplier, and they stack (×2, ×4, ×8). The math stays exact because every path touches exactly one peg per row, so the bonus factor is the same for every path. Each paytable is scaled so the total with golden pegs lands at 98.5–98.9% for all 15 rows/risk combos. Each pearl pays bet × multiplier rounded to the nearest coin in integer math (`pay_mult()`), so the figure is exact whenever the bet per pearl is a multiple of 100 GC; at other stakes the rounding moves it: 97.5–99.4% at the 10 GC minimum, 96.8–100.3% across every stake from 10 to 5,000 GC (a few odd stakes under 100 GC, 12 GC for instance, come out slightly player-positive on some tables), and 98.3–99.1% at any stake of 100 GC or more. We kept the 10 GC minimum and state the exhaustive range rather than raising it; `tests/audit_arcade3d_test.php` sweeps every stake. One drop can wager at most 10× the table maximum (bet × pearls), the same per-round limit as the chip boards.
- **8, 10, 12, 14 or 16 rows**, **low / medium / high risk**, and **1, 3, 5, 10 or 20 pearls per drop**, all falling at once.
- **Provably fair.** Outcomes are HMAC-SHA256(server seed, `client:nonce:ball:N`). Players see the seed's SHA-256 fingerprint before they play, set their own client seed, and can rotate to reveal the seed and recompute any drop with the checker built into the page. The NEXT server seed is pre-committed too: its hash is shown before the player chooses the client seed that will be paired with it, and a rotation promotes exactly that seed, so the server can never pick a seed after seeing the client's input.
- **Autoplay** with stop-on-big-hit, a profit target and a loss limit, plus **turbo** and the space bar.
- Synthesized sound (peg tinks, gold chimes, bucket thuds) with a mute toggle, a live bucket heatmap, session stats, a multiplier history strip, and BIG / MEGA / LEGENDARY win banners.

Every paytable was checked with exact math or a 200k-hand simulation. The formulas are in comments next to each engine. Fractional payouts (baccarat banker 0.95:1, blackjack 3:2 and surrender, the craps buy/lay commission) round to the nearest whole coin, half up, never down; craps place, odds, buy and lay bets are taken only in the unit their odds pay whole, so those payouts are exact. `tests/audit_tables_test.php` re-derives the table-game figures: all 22,100 three-card hands against a brute-force ranker, the blackjack return with basic strategy through the live engine, the exact 216-roll sic bo returns, the craps betting units and exact unit returns (place 6 98.48%, buy/lay 4 98.33%), and the exact bet-key spellings of sic bo, roulette, craps and the crab derby.

- **Free coins**: 10,000 GC welcome stack, a daily bonus with a 7-day streak, a "running low" refill every 4h (it unlocks when your balance **plus the chips you have on tables** is under 500 GC, so parking craps chips doesn't count as being broke), and **promo codes** you can hand out at events
- **Leaderboards**: biggest stack, biggest single win, most rounds. Only chips that were actually decided count as a round, wagered or won: craps chips you park and take back down count for nothing.
- **Table limits**, the same on every chip board (both roulettes, sic bo, big six, crabs, baccarat, craps): one spot holds at most the table max (default 5,000 GC; duplicate chips on a spot merge before the check, and a spot's name has to match the table's spelling exactly), and one spin or round at most 10× the table max. On craps the per-spot max counts chips already working, and the 10× cap applies to the new chips on each roll.
- **Take a break**: players can lock their own account for 1–90 days, and it can't be shortened. A live Tide Crash wave is settled at its current multiplier inside the same transaction that starts the break (cashed out, or already lost if it had broken), so no round keeps running while the player is locked out; other multi-step games just resume afterwards- Dark ("night harbor") and light ("day at the pier") themes, fully responsive, keyboard accessible, and it honors reduced motion
- Every game still plays with JavaScript off (plain forms). JS adds the animation.

**For the house (`?action=admin`)**
- Dashboard: players, active users, coins in play, today's wagers and hold, actual RTP per game over the last 7 days. Wagers and RTP count chips that were decided: craps chips taken back down are logged as a reversal of their wager (a positive `wager` row, shown to the player as "Chips back"), so they net out of both.
- Full CRUD on every table (players, games, game rounds, promo codes, redemptions, ledger, blackjack hands, settings, admins, lockouts), with search, filters, sorting, pagination, bulk actions, and CSV export
- Changing a player's balance writes an `admin` row to the coin ledger. The edit form remembers the balance it was opened with and the save is refused ("Balance changed to X while you were editing. Reload and try again.") if the player's balance moved in between, so an open tab can't erase a win or a loss. Round and blackjack-hand edits carry the same kind of check.
- Voiding a stuck round (any game) refunds the chips still at risk on it: for craps that is what's on the layout right now, not chips already paid or taken down. The refund is decided inside the same transaction as the status change, a settled or voided round can't be reopened or voided again, and the round's `payout` ends up as everything it returned (paid so far + refund). The refund is logged as a reversal of the wager (a positive `wager` row, like a craps take-down), so voided chips drop out of "Wagered today", hold and RTP rather than counting as an admin credit on top of a wager that never resolved. A video slot waiting on its bonus picks also gets the base and free-spin win it had already banked.
- Turn any game on or off, rename it, or change its min/max bet under **Games**. Disabled games vanish from the lobby.
- Append-only audit log of every admin action, enforced by database triggers
- Site settings for brand name, tagline, partner name ("Presented with ___"), announcement banner, starting coins, bonus amounts, minimum age, opening/closing signups, and `trusted_proxies` (see security)

## running the realtime server

```bash
php ws.php                              # 0.0.0.0:8081
php ws.php --port 9000 --bind 127.0.0.1 # options; --verbose for more logging
```

`ws.php` includes `index.php`, so it shares the database and every rule. It never trusts the browser: players connect with a 60-second signed ticket from the site, and every poker action is checked against the engine's legal moves. It idles at about 0.2% CPU and used about 0.5% with 20 players walking around. Keep it running with systemd, `pm2`, or a `@reboot` cron line on the Pi.

The page finds the socket automatically: in dev (`php -S` on a non-standard port) it uses port 8081 on the same host; behind a proxy it uses `wss://your-host/ws`. To put it behind Cloudflare or nginx, proxy `/ws` to port 8081 with WebSocket upgrade, or set `ws_url` under **Settings**. Set `rt_origins` if the site is reachable under more than one hostname. Full protocol, engine API and persistence rules: [`REALTIME.md`](REALTIME.md).

```nginx
location /ws { proxy_pass http://127.0.0.1:8081; proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade"; proxy_read_timeout 120s; }
```

## tests

Everything a partner's auditor needs to re-check the claims, no frameworks:

| command | what it proves |
|---|---|
| `php tests/poker_test.php` | hold'em rules, evaluator vs brute force, side pots, 5,000-hand fuzz, deck-commitment verifier (375 checks, ~3 s) |
| `php tests/ws_test.php` | WebSocket protocol (RFC 6455), tickets, origin checks, presence, chat limits, buy-in/cash-out ledger, shutdown refunds (117 checks) |
| `php tests/poker_e2e_test.php` | two real players + house players over real sockets for 5+ hands, hidden-card frame scan, kill -9 refund, ledger reconciliation (~2 min) |
| `php tests/audit_core_test.php` | void refunds, races, trusted proxies, refill gate, table limits, stale admin edits |
| `php tests/audit_slots_test.php` | slot RTP by simulation at the minimum bet, the round-trip pick bonus, max-win cap |
| `php tests/audit_tables_test.php` | three-card ranking over all 22,100 hands, blackjack split/surrender and RTP, baccarat rounding, sic bo combinations |
| `php tests/audit_arcade3d_test.php` | craps betting units and exact payouts, multiplier rounding, keno, dice, crash ties, Pearl Drop seed pre-commit, mines cap |
| `node tests/floor_test.js` | the 3D floor in two browsers: presence, chat escaping, sitting at machines and poker, guest and offline modes, phones (needs Playwright) |
| `node tests/poker_client_test.js` | the poker client in two browsers: buy-in, real hands, no leaked cards, hand-history verification, phones (needs Playwright) |

## first run

1. Load the site once. It creates `data/app.sqlite` and `admin_password.txt`.
2. Open `admin_password.txt`, log in at `?action=admin`, and change the password under **Password**. The file deletes itself.
3. Under **Settings**, set `site_name`, `tagline`, and `partner_name` for whoever you're presenting it with.
4. Under **Promos**, make a code for your next event (e.g. `SUMMER5K` → 5,000 GC).

## security

- Every outcome is decided server-side with `random_int` (a CSPRNG). The browser only animates results, so nobody can edit JS to pump the leaderboard. Hidden state (mine positions, the crash point, the dealer's hole cards, the rest of the deck) never leaves the server.
- Multi-step games keep one active round per player per game in the `rounds` table. Crash runs on server time, so lag can't be exploited.
- Multiplier games (Pearl Drop, Kelp Keno, Tide Crash, Reef Mines, Lighthouse Dice) pay in integer math: the multiplier is carried as whole hundredths (ten-thousandths for Dice) and the win is `intdiv(bet × m + half, scale)`, i.e. bet × multiplier rounded to the nearest coin, so the multiplier on screen is the one that's paid (`floor(100 * 0.29)` on binary floats is 28). Hi-lo (4-dp multiplier) and the video-slot engine (base ways, free spins, bonus and the total) go through the same `pay_mult()`, and the slot paytable on screen uses the same rounding. Reef Mines wins are capped at 5,000× the bet, like hi-lo and the slots. `tests/audit_arcade3d_test.php` covers all of this against a scratch database, and `tests/keno_rtp.php` prints the Keno RTP per pick count.
- All coin movement goes through one function inside `BEGIN IMMEDIATE` transactions, with a `CHECK (balance >= 0)` in the schema as a backstop.
- bcrypt (cost 12), CSRF tokens on every POST, PDO prepared statements, a CSP with script nonces, HSTS on HTTPS, `SameSite=Strict` cookies, and session regeneration on login
- Login lockout after 5 failures in 15 minutes (players and admins), promo-code brute-force lockout (per player), signup rate limiting per IP, and a 2-hour admin idle timeout
- **Visitor IP and proxies.** The lockouts, the signup throttle and the audit log key on the connecting address (`REMOTE_ADDR`). A `CF-Connecting-IP` header is honored only when the connection itself comes from a proxy you trust; anything else can be typed by an attacker and is ignored. Trusted by default: loopback only, which covers a `cloudflared` tunnel running on the same box (the Raspberry Pi setup). For anything else, set the `trusted_proxies` setting under **Settings**: a comma-separated list of IPs or CIDRs (e.g. `10.0.0.5, 192.168.1.0/24`), or the word `cloudflare` to trust Cloudflare's published edge ranges (IPv4 + IPv6, embedded in `index.php` as `CF_RANGES`; re-check them against <https://www.cloudflare.com/ips/> if Cloudflare announces a change). Use `cloudflare` when the site sits behind Cloudflare's proxy (orange cloud) with your origin reached directly by Cloudflare; leave it blank for a tunnel. If you set it wrong, nothing breaks: rate limits simply key on the proxy's address until you fix it.
- On Apache it writes `.htaccess` files that block `data/`, `admin_password.txt`, and `*.sqlite`. **On nginx, deny those paths yourself:**
  ```nginx
  location ~ (^/data/|admin_password\.txt|\.sqlite) { deny all; }
  ```

## the legal line (read this)

This is built to stay a **pure social casino**: coins can't be bought, sold, redeemed, or traded, and there's no prize path of any kind. That's what keeps it out of gambling law.

- **Don't add a coin store.** Selling coins, even with "no cash value," pushes this into territory regulators watch closely.
- **Don't add sweepstakes coins or prize redemption.** California banned dual-currency sweepstakes casinos (AB 831, in effect Jan 1, 2026), and prizes of any value for casino-style play is the definition of gambling.
- If a tribal casino partner wants to run it under their brand, have their gaming commission / compliance team sign off first. Their compacts and marketing rules vary.

Not legal advice. Get a gaming attorney to review before a partner launch.

## files it creates

| path | what |
|---|---|
| `data/app.sqlite` | the whole database (WAL mode) |
| `data/error.log` | PHP errors (display_errors is off) |
| `admin_password.txt` | first-run admin password, wiped when you change it |
| `.htaccess`, `data/.htaccess` | Apache deny rules |
| `data/ws.log` | realtime server log (truncated above 5 MB) |
| `data/floor.glb` | optional: your own 3D room shell (you add this) |

All of these are gitignored.
