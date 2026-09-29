# ☀ GOLD TIDE

**A free-to-play social casino in one file.** Slots, blackjack, and roulette played with Gold Coins, which are play money with no cash value. Built so a casino partner can hand it to guests as a practice table, a marketing hook, or an event activation without touching real-money gaming.

It's one `index.php` plus a SQLite database that builds itself on first run. No composer, no npm, no build step.

```bash
php -S localhost:8000 index.php
# open http://localhost:8000
```

Or drop `index.php` on Bluehost or any Apache+PHP host, or run it on a Raspberry Pi behind a Cloudflare tunnel. Needs PHP 8.1+ with `pdo_sqlite`.

## what's inside

**For players**
- **Sunset Reels**: 3 reels, 5 paylines, ~95% theoretical return (the math is in the code comments)
- **Harbor Blackjack**: 6-deck shoe, dealer peeks and stands on all 17s, blackjack pays 3:2, double down
- **Coronado Roulette**: single-zero wheel, a full betting board with chips, undo/clear/rebet, and payouts at standard odds
- **Free coins**: 10,000 GC welcome stack, a daily bonus with a 7-day streak, a "running low" refill every 4h, and **promo codes** you can hand out at events
- **Leaderboards**: biggest stack, biggest single win, most rounds
- **Take a break**: players can lock their own account for 1–90 days, and it can't be shortened
- Dark ("night harbor") and light ("day at the pier") themes, fully responsive, keyboard accessible, and it honors reduced motion

**For the house (`?action=admin`)**
- Dashboard: players, active users, coins in play, today's wagers and hold, actual RTP per game over the last 7 days
- Full CRUD on every table (players, games, promo codes, redemptions, ledger, blackjack hands, settings, admins, lockouts), with search, filters, sorting, pagination, bulk actions, and CSV export
- Changing a player's balance writes an `admin` row to the coin ledger. Voiding a stuck blackjack hand refunds the bet.
- Append-only audit log of every admin action, enforced by database triggers
- Site settings for brand name, tagline, partner name ("Presented with ___"), announcement banner, starting coins, bonus amounts, minimum age, and opening/closing signups

## first run

1. Load the site once. It creates `data/app.sqlite` and `admin_password.txt`.
2. Open `admin_password.txt`, log in at `?action=admin`, and change the password under **Password**. The file deletes itself.
3. Under **Settings**, set `site_name`, `tagline`, and `partner_name` for whoever you're presenting it with.
4. Under **Promos**, make a code for your next event (e.g. `SUMMER5K` → 5,000 GC).

## security

- Every outcome is decided server-side with `random_int` (a CSPRNG). The browser only animates results, so nobody can edit JS to pump the leaderboard.
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
