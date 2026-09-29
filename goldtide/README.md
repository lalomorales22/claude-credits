# ☀ GOLD TIDE

**A free-to-play social casino in one file.** Slots, blackjack, and roulette played with Gold Coins, which are play money with no cash value. Built so a casino partner can hand it to guests as a practice table, a marketing hook, or an event activation without touching real-money gaming.

It's one `index.php` plus a SQLite database that builds itself on first run. No composer, no npm, no build step.

```bash
php -S localhost:8000 index.php
# open http://localhost:8000
```

Or drop `index.php` on Bluehost or any Apache+PHP host, or run it on a Raspberry Pi behind a Cloudflare tunnel. Needs PHP 8.1+ with `pdo_sqlite`.

## what's inside

**For players: 25 games in six rooms**

| room | game | what it is | return |
|---|---|---|---|
| Slot Hall | **Sunset Reels** | the classic: 3 reels, 5 paylines | ~95% |
| | **Abyss Critters** | deep-sea creatures, kraken wilds, 10–25 free spins ×3 | 95.1% |
| | **Tinfoil Hat** | conspiracy theories: UFOs, bigfoot, lizard people; free spins ×3 | 95.7% |
| | **Black Site Breach** | top-secret data heist: keycards, vaults, lasers; free spins ×4 | 95.1% |
| | **Code Rain** | green digital-rain hacker world; rare free spins ×5 | 95.6% |
| | **Tiki Tides** | tiki-bar luau, low volatility, free spins ×2 | 95.4% |
| | **Calavera Fiesta** | Día de los Muertos, 12–24 free spins ×2 | 95.1% |
| 3D Games | **Coronado Roulette 3D** | real 3D wheel: rotor, frets, a ball that orbits, drops and settles | 97.3% |
| | **Harbor Craps** | new: pass/don't pass, true-odds, field, props, hardways, 3D dice | 98.6% pass |
| | **Pier Pusher** | boardwalk coin pusher in 3D | 95% |
| | *3D slot cabinet* | a toggle on every themed slot: curved drum reels, chrome, chasing bulbs | same as slot |
| Scratch & Keno | | | |
| | **Sunset Scratchers** | scratch 9 spots with your finger/mouse, match 3 | 91% |
| | **Kelp Keno** | pick 1–10 of 40, ten drawn | 94–96% |
| Table Games | **Coronado Roulette** | single-zero wheel, full board | 97.3% |
| | **Bayfront Baccarat** | player / banker / tie, full third-card tableau | 98.8% banker |
| | **Surf Sic Bo** | three dice, 50 bets on the board | 97% small/big |
| | **Boardwalk Big Six** | 54-stop carnival money wheel | 78–89% (it's a carnival wheel) |
| | **Crab Crawl Derby** | six racing crabs at fixed odds, animated race | 93.9% |
| Card Room | **Harbor Blackjack** | 6 decks, S17, 3:2, double | ~99.5% |
| | **Boardwalk Poker** | Jacks or Better 9/6 video poker | 99.5% perfect play |
| | **Coastline 3-Card** | ante/play vs dealer + Pair Plus | ~97% |
| | **Tide Hi-Lo** | higher or lower, multiplier builds, cash out anytime | 99% |
| Boardwalk Arcade | **Tide Crash** | live multiplier curve, cash out before it breaks, auto cash-out | 99% |
| | **Pearl Drop** ★ | the flagship plinko (see below) | 98.5–99% |
| | **Reef Mines** | 5×5 grid, pick 1–24 urchins, find pearls | 99% |
| | **Lighthouse Dice** | slide your own odds, roll over/under | 99% |

### Rooms

Every classic game has its own themed room: an animated night-time scene behind the table and a sound palette. The harbor at night with a lighthouse beam (blackjack), a velvet VIP lounge with chandelier glow (baccarat), carnival bulbs and a turning Ferris wheel (big six), a kelp forest (keno), rolling surf (sic bo), fish crossing the reef (mines), a synthwave grid (video poker), a sunset with gulls (Sunset Reels), and more. Cards get a soft flip sound as they land, dice rattle, wheels tick, and every game has BIG / MEGA / EPIC win banners. One sound switch in the header mutes the whole site.

### 3D games

These are real 3D gameplay, built with three.js r170 (MIT). three.js is embedded in `index.php` (gzip+base64) and served from `?action=asset`, so everything still works offline from a single file. The 3D module only loads on pages that need it. The server still decides every outcome and the scene is steered to it: the roulette ball is guided into the pocket the server picked, and the dice tumble and settle on the rolled faces (a browser test checks 40 of 40 throws). Without WebGL, the 2D controls still play every game.

### Slot Hall

Six themed 5-reel video slots on one shared engine: 243 ways (matching symbols pay left to right on adjacent reels), wilds on reels 2–4, and 3+ bonus symbols triggering free spins with a multiplier. Every cell is drawn independently, which gives the return-to-player an exact closed form. Each slot's table was solved to 95.0–95.8% and confirmed with 1.5M simulated spins. Each one has its own hand-drawn symbol set, animated backdrop (bubbles, digital rain, laser grid, UFO searchlights, torch embers, marigold petals), synthesized sound palette and volatility. You also get near-miss slowdowns when two bonus symbols land, a full free-spins mode, big/mega/epic win banners, autospin and turbo.

### ★ Pearl Drop, the flagship

The house favorite, and it's featured at the top of the lobby.

- **Golden pegs.** Every drop, 3 pegs light up gold. Each one a pearl touches doubles that pearl's multiplier, and they stack (×2, ×4, ×8). The math stays exact because every path touches exactly one peg per row, so the bonus factor is the same for every path. Each paytable is scaled so the total with golden pegs lands at 98.5–99% for all 15 rows/risk combos.
- **8, 10, 12, 14 or 16 rows**, **low / medium / high risk**, and **1, 3, 5, 10 or 20 pearls per drop**, all falling at once.
- **Provably fair.** Outcomes are HMAC-SHA256(server seed, `client:nonce:ball:N`). Players see the seed's SHA-256 fingerprint before they play, set their own client seed, and can rotate to reveal the seed and recompute any drop with the checker built into the page.
- **Autoplay** with stop-on-big-hit, a profit target and a loss limit, plus **turbo** and the space bar.
- Synthesized sound (peg tinks, gold chimes, bucket thuds) with a mute toggle, a live bucket heatmap, session stats, a multiplier history strip, and BIG / MEGA / LEGENDARY win banners.

Every paytable was checked with exact math or a 200k-hand simulation. The formulas are in comments next to each engine.

- **Free coins**: 10,000 GC welcome stack, a daily bonus with a 7-day streak, a "running low" refill every 4h, and **promo codes** you can hand out at events
- **Leaderboards**: biggest stack, biggest single win, most rounds
- **Take a break**: players can lock their own account for 1–90 days, and it can't be shortened
- Dark ("night harbor") and light ("day at the pier") themes, fully responsive, keyboard accessible, and it honors reduced motion
- Every game still plays with JavaScript off (plain forms). JS adds the animation.

**For the house (`?action=admin`)**
- Dashboard: players, active users, coins in play, today's wagers and hold, actual RTP per game over the last 7 days
- Full CRUD on every table (players, games, game rounds, promo codes, redemptions, ledger, blackjack hands, settings, admins, lockouts), with search, filters, sorting, pagination, bulk actions, and CSV export
- Changing a player's balance writes an `admin` row to the coin ledger. Voiding a stuck round (any game) refunds its stake.
- Turn any game on or off, rename it, or change its min/max bet under **Games**. Disabled games vanish from the lobby.
- Append-only audit log of every admin action, enforced by database triggers
- Site settings for brand name, tagline, partner name ("Presented with ___"), announcement banner, starting coins, bonus amounts, minimum age, and opening/closing signups

## first run

1. Load the site once. It creates `data/app.sqlite` and `admin_password.txt`.
2. Open `admin_password.txt`, log in at `?action=admin`, and change the password under **Password**. The file deletes itself.
3. Under **Settings**, set `site_name`, `tagline`, and `partner_name` for whoever you're presenting it with.
4. Under **Promos**, make a code for your next event (e.g. `SUMMER5K` → 5,000 GC).

## security

- Every outcome is decided server-side with `random_int` (a CSPRNG). The browser only animates results, so nobody can edit JS to pump the leaderboard. Hidden state (mine positions, the crash point, the dealer's hole cards, the rest of the deck) never leaves the server.
- Multi-step games keep one active round per player per game in the `rounds` table. Crash runs on server time, so lag can't be exploited.
- All coin movement goes through one function inside `BEGIN IMMEDIATE` transactions, with a `CHECK (balance >= 0)` in the schema as a backstop.
- bcrypt (cost 12), CSRF tokens on every POST, PDO prepared statements, a CSP with script nonces, HSTS on HTTPS, `SameSite=Strict` cookies, and session regeneration on login
- Login lockout after 5 failures in 15 minutes (players and admins), promo-code brute-force lockout, signup rate limiting per IP, and a 2-hour admin idle timeout
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

All of these are gitignored.
