#!/usr/bin/env node
/**
 * tests/poker_client_test.js: the poker client (poker_js(), page_poker(), page_poker_hand()) end to end in Chromium.
 *
 * Starts its own `php -S` (ports 8500-8549) and `php ws.php` (8550-8599) on a scratch copy of goldtide/ (the real data/
 * is never touched), with table 1 at 2 house players and an 8 s clock. Two real players register in two browser
 * contexts: A on a desktop viewport, B on a 390x844 phone. Checks:
 *   - lobby with live counts, lobby -> table without a reload (pushState) and back/forward (popstate);
 *   - A buys in through the dialog: header balance drops by the buy-in, poker_seats has the row; B sits too;
 *   - at least 3 full hands are played by driving A and B from the action bar (Check/Call), bots doing the rest;
 *   - B's DOM and every WebSocket frame B receives never carry A's hole cards while A is in the hand and not shown;
 *   - the timer arc shows, showdowns reveal hand names, the pot readout equals the sum of the players' bets;
 *   - a stale-seq pk_act sent through the rt comes back as a pk_err toast;
 *   - A leaves: the seat row goes, the balance comes back as buy-in +/- results (balance = start + sum of A's nets);
 *   - the hand history page says "Deck commitment verified" from PHP and from the client-side check (deal order too);
 *   - client hardening on a scripted rt (no server): the action bar unlocks after a reconnect / a lost act, the raise slider
 *     reaches all-in, add-on is off while dealt into a hand, the "Back to my seat" note (lobby and other tables), the
 *     pot readout never calls an uncalled excess a side pot, the replay gives uncalled bets back;
 *   - ws.php killed and restarted while B is seated: B's header balance matches the database after the refund;
 *   - no horizontal scroll on the phone, zero console errors on every page.
 * Screenshots go to tests/out/ (gitignored). Exit 1 on any failure.
 *
 *     /opt/node22/bin/node goldtide/tests/poker_client_test.js
 */
'use strict';
const PW = process.env.PLAYWRIGHT || '/opt/node22/lib/node_modules/playwright';
const { chromium } = require(PW);
const { spawn, execFileSync } = require('child_process');
const fs = require('fs'), path = require('path'), os = require('os'), net = require('net'), http = require('http');

const ROOT = path.resolve(__dirname, '..');
const OUT = path.join(__dirname, 'out');
const PHP = process.env.PHP || '/usr/bin/php';
const T0 = Date.now();
const BUDGET = 230e3;
const ACT_SECS = 8;

let pass = 0, fail = 0;
const failures = [];
const elapsed = () => ((Date.now() - T0) / 1000).toFixed(1).padStart(5);
function check(ok, name, detail = '') {
  if (ok) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; failures.push(name); console.log(`  FAIL ${name}${detail ? '  -- ' + detail : ''}`); }
  return ok;
}
const note = s => console.log(`       [${elapsed()}s] ${s}`);
const section = s => console.log(`\n== ${s}`);
const sleep = ms => new Promise(r => setTimeout(r, ms));

function freePort(from, to) {
  return new Promise((resolve, reject) => {
    const tryPort = p => {
      if (p > to) return reject(new Error(`no free port in ${from}-${to}`));
      const srv = net.createServer();
      srv.once('error', () => tryPort(p + 1));
      srv.once('listening', () => srv.close(() => resolve(p)));
      srv.listen(p, '127.0.0.1');
    };
    tryPort(from);
  });
}
function getJSON(url) {
  return new Promise(resolve => {
    const req = http.get(url, res => { let b = ''; res.on('data', d => { b += d; }); res.on('end', () => { try { resolve(JSON.parse(b)); } catch (e) { resolve(null); } }); });
    req.on('error', () => resolve(null));
    req.setTimeout(1500, () => { req.destroy(); resolve(null); });
  });
}
async function waitFor(fn, ms, step = 150) {
  const end = Date.now() + ms;
  while (Date.now() < end) { const v = await fn(); if (v) return v; await sleep(step); }
  return null;
}

/* ───────────────────────── scratch copy + servers ───────────────────────── */

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gt_pkclient_'));
for (const f of ['index.php', 'ws.php']) fs.copyFileSync(path.join(ROOT, f), path.join(tmp, f));
const php = code => execFileSync(PHP, ['-r', `define('GT_NO_ROUTE', 1); require ${JSON.stringify(path.join(tmp, 'index.php'))}; db(); ${code}`], { cwd: tmp, encoding: 'utf8' });
const procs = [];
function cleanup() {
  for (const p of procs) { try { p.kill('SIGTERM'); } catch (e) { /* gone */ } }
}
process.on('exit', cleanup);
process.on('SIGINT', () => { cleanup(); process.exit(130); });

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const range = (env, d) => (process.env[env] || d).split('-').map(Number);   // e.g. PK_WEB_PORTS=8700-8749 PK_WS_PORTS=8750-8799
  const webPort = await freePort(...range('PK_WEB_PORTS', '8500-8549'));
  const wsPort = await freePort(...range('PK_WS_PORTS', '8550-8599'));
  const base = `http://127.0.0.1:${webPort}/`;
  php(`q('UPDATE poker_tables SET bots = 2 WHERE id = 1'); q("UPDATE settings SET value = '${ACT_SECS}' WHERE key = 'poker_action_seconds'"); q('UPDATE settings SET value = ? WHERE key = ?', ['ws://127.0.0.1:${wsPort}/', 'ws_url']);`);
  const wsLog = fs.openSync(path.join(tmp, 'ws.out'), 'a');
  const webLog = fs.openSync(path.join(tmp, 'web.out'), 'a');
  procs.push(spawn(PHP, ['ws.php', '--port', String(wsPort), '--bind', '127.0.0.1', '--tick', '20'], { cwd: tmp, stdio: ['ignore', wsLog, wsLog] }));
  procs.push(spawn(PHP, ['-S', `127.0.0.1:${webPort}`, 'index.php'], { cwd: tmp, stdio: ['ignore', webLog, webLog], env: { ...process.env, PHP_CLI_SERVER_WORKERS: '4' } }));

  section('start-up');
  const health = await waitFor(() => getJSON(`http://127.0.0.1:${wsPort}/health`), 10000);
  check(!!health && health.ok === true, `ws.php up on ${wsPort} with table 1 hosted`, JSON.stringify(health));
  const page0 = await waitFor(async () => { try { const r = await fetch(base); return r.ok; } catch (e) { return false; } }, 10000);
  check(!!page0, `site up on ${webPort}`);
  if (!health || !page0) throw new Error('servers did not start');

  const browser = await chromium.launch({ args: ['--use-gl=angle', '--use-angle=swiftshader', '--enable-unsafe-swiftshader'] });
  const ctxA = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const ctxB = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true, deviceScaleFactor: 2 });
  const errors = [];
  const watchPage = (page, label) => {
    page.on('console', m => { if (m.type() === 'error') errors.push(`${label}: ${m.text()}`); });
    page.on('pageerror', e => errors.push(`${label}: pageerror ${e.message}`));
    return page;
  };
  const pA = watchPage(await ctxA.newPage(), 'A');
  const pB = watchPage(await ctxB.newPage(), 'B');

  // frames: A's own hole cards per hand (from A's views), and everything B receives
  const aCards = new Map(); let aSeat = null;
  const bFrames = [];
  pA.on('websocket', ws => ws.on('framereceived', f => {
    try {
      const m = JSON.parse(f.payload);
      if (m.t === 'pk_state' && m.table && m.table.me !== null && m.table.me !== undefined) {
        const me = m.table.players[m.table.me];
        aSeat = m.table.me;
        if (me && Array.isArray(me.cards) && me.cards.length === 2) aCards.set(m.table.hand_no, me.cards.slice());
      }
    } catch (e) { /* not JSON */ }
  }));
  pB.on('websocket', ws => ws.on('framereceived', f => bFrames.push(String(f.payload))));

  /* ───────────────────────── register ───────────────────────── */

  section('register two players');
  const tag = Math.random().toString(36).slice(2, 7);
  const names = { A: `alice_${tag}`, B: `bob_${tag}` };
  async function register(page, name) {
    await page.goto(base + '?action=register');
    await page.fill('input[name=username]', name);
    await page.fill('input[name=password]', 'correct-horse-9');
    await page.fill('input[name=password2]', 'correct-horse-9');
    await page.check('input[name=age_ok]');
    await page.check('input[name=terms_ok]');
    await Promise.all([page.waitForURL(u => !String(u).includes('register'), { timeout: 15000 }), page.click('form.form button')]);
  }
  await register(pA, names.A);
  await register(pB, names.B);
  const pidA = +php(`echo (int)val('SELECT id FROM players WHERE username = ?', ['${names.A}']);`);
  const pidB = +php(`echo (int)val('SELECT id FROM players WHERE username = ?', ['${names.B}']);`);
  check(pidA > 0 && pidB > 0, `registered ${names.A} (#${pidA}) and ${names.B} (#${pidB})`);
  const dbBal = pid => +php(`echo (int)val('SELECT balance FROM players WHERE id = ?', [${pid}]);`);
  const seatRow = pid => JSON.parse(php(`echo json_encode(row('SELECT * FROM poker_seats WHERE player_id = ?', [${pid}]) ?: null);`));
  const startA = dbBal(pidA);

  /* ───────────────────────── lobby + navigation ───────────────────────── */

  section('lobby and navigation');
  await pA.goto(base + '?action=poker');
  await pA.waitForSelector('.pk-lobby [data-table-card="1"] [data-open="1"]', { timeout: 10000 });
  const counted = await waitFor(() => pA.evaluate(() => /^\d+ \//.test(document.querySelector('[data-table-card="1"] [data-seated]').textContent.trim())), 8000);
  const cardText = await pA.textContent('[data-table-card="1"]');
  check(!!counted && /2 house players/.test(cardText) && /Blinds/.test(cardText) && /Buy-in/.test(cardText), 'lobby card shows live seated count, blinds, buy-in range and house players', cardText.replace(/\s+/g, ' '));
  await pA.screenshot({ path: path.join(OUT, 'poker_lobby.png'), fullPage: false });
  await pA.evaluate(() => { window.__noReload = 'still here'; });
  await pA.click('[data-table-card="1"] [data-open="1"]');
  await pA.waitForSelector('.pk-table .pk-seat', { timeout: 10000 });
  check(/[?&]t=1\b/.test(pA.url()) && await pA.evaluate(() => window.__noReload === 'still here'), 'lobby -> table without a reload (URL t=1)', pA.url());
  await pA.goBack();
  await pA.waitForSelector('.pk-lobby', { timeout: 5000 });
  await pA.goForward();
  await pA.waitForSelector('.pk-table .pk-seat', { timeout: 5000 });
  check(await pA.evaluate(() => window.__noReload === 'still here' && !!document.querySelector('.pk-table')), 'back/forward switch lobby and table through popstate');
  const recentShown = await pA.evaluate(() => { const s = document.querySelector('[data-recent-for="1"]'); return !!s && !s.hidden; });
  check(recentShown, 'the "Recent hands" list for table 1 shows under the table');

  /* ───────────────────────── sit down ───────────────────────── */

  section('buy in');
  const BUYIN = 2000;
  await pA.waitForSelector('.pk-sit', { timeout: 8000 });
  const balBefore = +(await pA.getAttribute('[data-balance]', 'data-balance'));
  await pA.click('.pk-sit');
  await pA.waitForSelector('dialog[open] [data-amt]');
  await pA.fill('dialog[open] [data-amt]', '5');
  const invalid = await pA.evaluate(() => document.querySelector('dialog[open] [data-ok]').disabled);
  check(invalid, 'buy-in dialog rejects an amount under the minimum');
  await pA.fill('dialog[open] [data-amt]', String(BUYIN));
  await pA.click('dialog[open] [data-ok]');
  const dropped = await waitFor(async () => +(await pA.getAttribute('[data-balance]', 'data-balance')) === balBefore - BUYIN, 8000);
  check(!!dropped, `header balance drops by the buy-in (${balBefore} -> ${balBefore - BUYIN})`, await pA.getAttribute('[data-balance]', 'data-balance'));
  const rowA = seatRow(pidA);
  check(!!rowA && +rowA.stack === BUYIN && +rowA.table_id === 1, 'poker_seats has A\'s row with the buy-in', JSON.stringify(rowA));
  await pA.click('[data-post]:not([hidden])', { timeout: 3000 }).catch(() => {});

  await pB.goto(base + '?action=poker&t=1');
  await pB.waitForSelector('.pk-sit', { timeout: 10000 });
  await pB.click('.pk-sit');
  await pB.waitForSelector('dialog[open] [data-quick]');
  await pB.click('dialog[open] [data-quick]');   // Min
  await pB.click('dialog[open] [data-ok]');
  const bSat = await waitFor(() => pB.evaluate(() => { const t = window.goldTidePoker.table; return t && t.view && t.view.me !== null; }), 8000);
  check(!!bSat && !!seatRow(pidB), 'B sits with the Min quick button');
  await pB.click('[data-post]:not([hidden])', { timeout: 3000 }).catch(() => {});
  const noScroll = () => pB.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
  check(await noScroll(), 'phone (390x844): no horizontal scroll with the table up');

  /* ───────────────────────── play ───────────────────────── */

  section('play hands');
  const S = { timer: false, handNames: false, potChecks: 0, potBad: [], domLeak: [], actions: { A: 0, B: 0 }, hands: new Set(), mobileScroll: true, shotShowdown: false, shotTurn: false };
  const readState = page => page.evaluate(() => {
    const T = window.goldTidePoker && window.goldTidePoker.table, v = T && T.view;
    if (!v) return null;
    const ps = Object.entries(v.players || {});
    const sum = ps.reduce((a, [, p]) => a + (p.total || 0), 0);
    const potEl = document.querySelector('.pk-pot[data-pot]');
    const potNums = ((potEl && potEl.textContent) || '').match(/\d[\d,]*/g) || [];
    const shown = potNums.reduce((a, n) => a + Number(n.replace(/,/g, '')), 0);
    const timer = [...document.querySelectorAll('.pk-seat.pk-turn .pk-timer')].some(t => getComputedStyle(t).display !== 'none');
    const names = [...document.querySelectorAll('.pk-handname')].map(e => e.textContent).filter(Boolean);
    const bar = document.querySelector('.pk-actions:not([hidden]) .pk-call:not([disabled])');
    return { hand: v.hand_no, phase: v.phase, me: v.me, legal: !!v.legal, sum, shown, potTotal: potEl ? +potEl.dataset.potTotal : null, timer, names, bar: !!bar,
      pots: (v.pots || []).length, mine: v.me !== null && v.players[v.me] ? v.players[v.me] : null };
  });
  const bView = () => pB.evaluate(seat => {
    const v = window.goldTidePoker.table && window.goldTidePoker.table.view;
    if (!v) return null;
    const pa = seat === null ? null : v.players[seat];
    const cards = [...document.querySelectorAll('.pk-table [data-c]')].filter(c => !c.closest('.pk-seat.pk-me') && !c.closest('.pk-mine') && !c.closest('[data-board]')).map(c => c.dataset.c);
    return { hand: v.hand_no, aShow: !!(pa && pa.show), cards };
  }, aSeat);

  async function driveOnce() {
    for (const [page, who] of [[pA, 'A'], [pB, 'B']]) {
      let st;
      try { st = await readState(page); } catch (e) { continue; }
      if (!st) continue;
      if (st.hand) S.hands.add(st.hand);
      if (st.timer) S.timer = true;
      if (st.names.length && st.phase === 'settle') {
        S.handNames = true;
        if (!S.shotShowdown && who === 'A') { S.shotShowdown = true; await pA.screenshot({ path: path.join(OUT, 'poker_showdown.png') }); }
      }
      if (['preflop', 'flop', 'turn', 'river', 'settle'].includes(st.phase)) {
        S.potChecks++;
        if (st.potTotal !== st.sum || st.shown !== st.sum) S.potBad.push(`${who} hand ${st.hand} ${st.phase}: shown ${st.shown} / data ${st.potTotal} vs bets ${st.sum}`);
      }
      if (st.legal && st.bar) {
        if (!S.shotTurn && who === 'B') { S.shotTurn = true; await pB.screenshot({ path: path.join(OUT, 'poker_mobile_turn.png') }); S.mobileScroll = S.mobileScroll && await noScroll(); }
        try { await page.click('.pk-actions:not([hidden]) .pk-call:not([disabled])', { timeout: 1500 }); S.actions[who]++; } catch (e) { /* the state moved on */ }
      }
    }
    // B's DOM must never show A's hole cards while A is in the hand and not shown
    const h = [...aCards.keys()].pop();
    if (h !== undefined) {
      try {
        const b = await bView();
        if (b && b.hand === h && !b.aShow) { const leak = aCards.get(h).filter(c => b.cards.includes(c)); if (leak.length) S.domLeak.push(`hand ${h}: ${leak.join(' ')}`); }
      } catch (e) { /* navigating */ }
    }
  }
  async function drive(until, ms, label) {
    const end = Date.now() + ms;
    let lastHand = Math.max(0, ...S.hands), lastMove = Date.now();
    while (Date.now() < end && Date.now() - T0 < BUDGET) {
      await driveOnce();
      const top = Math.max(0, ...S.hands);
      if (top !== lastHand) { lastHand = top; lastMove = Date.now(); note(`hand #${top} (A acted ${S.actions.A}x, B ${S.actions.B}x)`); }
      if (Date.now() - lastMove > 45000) { check(false, `${label}: the table keeps dealing`, `stuck on hand #${top} for 45 s`); return false; }
      if (await until()) return true;
      await sleep(200);
    }
    return !!(await until());
  }
  const firstHand = await waitFor(async () => { await driveOnce(); return S.hands.size ? Math.min(...S.hands) : 0; }, 40000, 250);
  check(!!firstHand, 'a hand is dealt with A, B and the house players');
  const finishedHands = () => +php(`echo (int)val('SELECT COUNT(*) FROM poker_hands WHERE table_id = 1 AND record LIKE ? AND record LIKE ?', ['%"uid":"p${pidA}"%', '%"uid":"p${pidB}"%']);`);
  const played = await drive(async () => finishedHands() >= 3 && S.handNames, 150000, 'three hands');
  check(played && finishedHands() >= 3, `at least 3 full hands played with A and B dealt in (${finishedHands()} recorded)`);
  check(S.actions.A > 0 && S.actions.B > 0, `A and B acted from the action bar (A ${S.actions.A}x, B ${S.actions.B}x)`);
  check(S.timer, 'the timer arc shows on the seat to act');
  check(S.handNames, 'a showdown reveals hand names on the felt');
  check(S.potChecks > 10 && S.potBad.length === 0, `pot readout equals the sum of the players' bets (${S.potChecks} checks)`, S.potBad.slice(0, 3).join(' | '));
  check(S.domLeak.length === 0, "B's DOM never shows A's hole cards while A is in the hand", S.domLeak.join(' | '));
  check(S.mobileScroll && await noScroll(), 'phone: no horizontal scroll with the action bar up');

  // frames B received: A's cards only once A shows them
  let frameLeaks = [], scanned = 0, curHand = 0;
  for (const raw of bFrames) {
    let m; try { m = JSON.parse(raw); } catch (e) { continue; }
    if (m.t === 'pk_state' && m.table) {
      scanned++;
      const v = m.table; curHand = v.hand_no;
      const mine = aCards.get(v.hand_no);
      if (!mine || aSeat === null) continue;
      for (const [s, p] of Object.entries(v.players || {})) {
        if (+s === +v.me || !Array.isArray(p.cards)) continue;
        if (!p.show && p.cards.some(c => mine.includes(c))) frameLeaks.push(`pk_state hand ${v.hand_no} seat ${s}`);
      }
      for (const w of v.winners || []) { const pa = v.players[w.seat]; if (Array.isArray(w.cards) && w.cards.length && !(pa && pa.show) && +w.seat !== +v.me) frameLeaks.push(`winners hand ${v.hand_no} seat ${w.seat}`); }
    } else if (m.t === 'pk_events' && Array.isArray(m.events)) {
      let h = curHand;
      for (const e of m.events) {
        if (e.t === 'hand_start') h = e.hand;
        if (e.t === 'hand_end' || e.t === 'showdown') continue;
        const mine = aCards.get(h);
        if (mine && mine.some(c => JSON.stringify(e).includes(`"${c}"`))) frameLeaks.push(`event ${e.t} hand ${h}`);
      }
    }
  }
  check(scanned > 10 && aCards.size >= 3 && frameLeaks.length === 0, `B's WebSocket frames never carry A's hole cards (${scanned} states, ${aCards.size} of A's hands)`, frameLeaks.slice(0, 4).join(' | '));

  /* ───────────────────────── stale seq, verify link ───────────────────────── */

  section('stale action, verify link');
  await pA.evaluate(() => { const g = window.goldTidePoker, v = g.table.view; g.rt.send({ t: 'pk_act', act: 'check', amt: 0, hand: v.hand_no, seq: v.seq - 1 }); });
  const staleToast = await pA.waitForSelector('.toast.err:has-text("moved on")', { timeout: 6000 }).then(() => true, () => false);
  check(staleToast, 'a stale-seq pk_act comes back as a pk_err toast');
  const verifyHref = await pA.getAttribute('[data-verify]', 'href');
  check(!!verifyHref && /action=poker_hand&h=[0-9a-f]{64}/.test(verifyHref), 'the deck badge links to the last finished hand', String(verifyHref));
  await pA.evaluate(() => { document.documentElement.dataset.theme = 'light'; });
  await sleep(300);
  await pA.screenshot({ path: path.join(OUT, 'poker_table_light.png') });
  await pA.evaluate(() => { document.documentElement.dataset.theme = 'dark'; });
  await pA.screenshot({ path: path.join(OUT, 'poker_table_dark.png') });
  await pB.screenshot({ path: path.join(OUT, 'poker_mobile.png') });

  // the floor's HUD mode: same module, felt hidden, compact strip; destroy() never leaves the seat
  const hud = await pB.evaluate(async () => {
    const M = await import(new URL(JSON.parse(document.getElementById('poker-cfg').textContent).poker_asset, location.href).href);
    const host = document.createElement('div'); host.id = 'hud-host'; document.body.appendChild(host);
    const cfg = JSON.parse(document.getElementById('poker-cfg').textContent);
    let states = 0;
    const tbl = M.mountPokerTable(host, { rt: window.goldTidePoker.rt, tableId: 1, cfg, mode: 'hud', seatHint: 0, onState: () => { states++; } });
    await new Promise(r => setTimeout(r, 2500));
    const felt = host.querySelector('.pk-felt-wrap'), strip = host.querySelector('.pk-hudstrip');
    const out = { states, feltHidden: !!felt && getComputedStyle(felt).display === 'none', strip: !!strip && getComputedStyle(strip).display !== 'none',
      me: tbl.view && tbl.view.me, api: ['sit', 'leave', 'act', 'sitout', 'post', 'addon', 'destroy'].every(k => typeof tbl[k] === 'function') };
    tbl.destroy();
    out.gone = !document.querySelector('#hud-host .pk-table');
    host.remove();
    out.stillSeated = window.goldTidePoker.table.view.me !== null;
    return out;
  });
  check(hud.states > 0 && hud.feltHidden && hud.strip && hud.me !== null && hud.api && hud.gone && hud.stillSeated, 'HUD mode mounts on the shared socket, hides the felt, and destroy() keeps the seat', JSON.stringify(hud));


  /* ───────────────────────── client hardening on a scripted rt ───────────────────────── */

  section('client hardening (scripted rt)');
  const H = await pA.evaluate(async () => {
    const cfg = JSON.parse(document.getElementById('poker-cfg').textContent);
    const M = await import(new URL(cfg.poker_asset, location.href).href);
    const subs = {}, sent = [];
    const rt = { state: 'open', me: { uid: 'p999', name: 'tester', guest: false }, tables: [], seated: null,
      send(o) { sent.push(o); return true; }, on(t, f) { (subs[t] = subs[t] || new Set()).add(f); return () => subs[t].delete(f); }, off(t, f) { if (subs[t]) subs[t].delete(f); } };
    const emit = m => { for (const f of [...(subs[m.t] || [])]) f(m, rt); };
    const sleep = ms => new Promise(r => setTimeout(r, ms));
    const host = document.createElement('div'); host.id = 'fake-host'; document.body.appendChild(host);
    const base = { id: 77, name: 'Scripted', seats: 6, sb: 10, bb: 20, min_buy: 400, max_buy: 6000, hand_no: 7, seq: 3, phase: 'flop', button: 1,
      board: ['2c', '7d', 'Jh'], to_act: 0, ms_left: 8000, act_secs: 8, cur_bet: 0, me: 0,
      players: { 0: { name: 'tester', stack: 4753, bet: 0, total: 40, in: true, allin: false, cards: ['As', 'Kd'] }, 1: { name: 'house', bot: true, stack: 1000, bet: 0, total: 40, in: true, allin: false, cards: 2 } },
      legal: { check: true, call: 0, raise: { min: 40, max: 4753 }, allin: 4753 } };
    const st = over => ({ t: 'pk_state', table: Object.assign(JSON.parse(JSON.stringify(base)), over || {}) });
    const tbl = M.mountPokerTable(host, { rt, tableId: 77, cfg, mode: 'page' });
    emit(st());
    const q = s => host.querySelector(s);
    const out = {};
    // raise slider: 4753 is not on the 10-chip grid from 40; the far right must still mean all-in
    const r = q('[data-raise-range]');
    r.value = r.max; r.dispatchEvent(new Event('input', { bubbles: true }));
    out.slider = { max: +r.max, label: q('[data-raise-label]').textContent };
    // add-on while dealt into the flop, then between hands
    out.addonLive = { disabled: q('[data-addon]').disabled, text: q('[data-addon]').textContent };
    // the bar locks on send and unlocks on a dropped socket, on a welcome, and 4 s after an unanswered act
    const lockAndCheck = async how => {
      q('.pk-call').click();
      const locked = q('.pk-call').disabled && q('[data-status]').textContent === 'Sending…';
      if (how === 'drop') { rt.state = 'closed'; emit({ t: 'rt_state', state: 'closed' }); rt.state = 'open'; emit({ t: 'rt_state', state: 'open' }); }
      if (how === 'welcome') emit({ t: 'welcome', id: 1, uid: 'p999', name: 'tester' });
      if (how === 'timeout') await sleep(4400);
      emit(st());   // the same hand / seq with legal still set, as after a reconnect
      return locked && !q('.pk-call').disabled && q('[data-status]').textContent === 'Your turn.';
    };
    out.unlock = { drop: await lockAndCheck('drop'), welcome: await lockAndCheck('welcome'), timeout: await lockAndCheck('timeout') };
    out.acts = sent.filter(m => m.t === 'pk_act').length;
    emit(st({ phase: 'idle', hand_no: 8, seq: 0, to_act: null, legal: null, board: [], players: { 0: { name: 'tester', stack: 4753, bet: 0, total: 0, in: false, cards: [] }, 1: { name: 'house', bot: true, stack: 1000, bet: 0, total: 0, in: false, cards: [] } } }));
    out.addonIdle = { disabled: q('[data-addon]').disabled, text: q('[data-addon]').textContent };
    // seated at another table: watching this one shows "Back to my seat" and no "Sit here"
    rt.seated = { id: 78, name: 'Other table', turn: true };
    emit(st({ me: null, legal: null }));
    out.elsewhere = { note: !q('[data-elsewhere]').hidden && /your turn/i.test(q('[data-elsewhere]').textContent) && !!q('[data-elsewhere] [data-goto="78"]'), sits: host.querySelectorAll('.pk-sit').length };
    tbl.destroy();
    const lob = M.mountPokerLobby(host, { rt, cfg });
    const ln = host.querySelector('[data-seated-note]');
    out.lobby = !ln.hidden && /Other table/.test(ln.textContent) && !!ln.querySelector('[data-open="78"]');
    rt.seated = null; emit({ t: 'welcome', id: 1, uid: 'p999', name: 'tester' });
    out.lobbyCleared = ln.hidden;
    lob.destroy();
    // pot readout: A all-in 1,640, B all-in 7,740, blinds folded: B's 6,100 is uncalled, not a side pot
    const pv = { phase: 'preflop', players: { 0: { total: 1640, in: true, allin: true }, 1: { total: 7740, in: true, allin: true }, 2: { total: 20, in: false }, 3: { total: 60, in: false } } };
    out.pot = M.potText(M.potInfo(pv));
    const pv2 = { phase: 'turn', players: { 0: { total: 100, in: true, allin: true }, 1: { total: 500, in: true }, 2: { total: 500, in: true }, 3: { total: 900, in: true } } };
    out.pot2 = M.potText(M.potInfo(pv2));
    out.pot3 = M.potText(M.potInfo({ phase: 'flop', players: { 0: { total: 120, in: true }, 1: { total: 60, in: true } } }));
    // replay: b shoves 11,600, a calls 800 all-in: 10,800 goes back before the flop
    const rec = { button: 1, pot: 1600, board: ['2c', '7d', 'Jh', 'Qs', '3d'],
      players: [{ seat: 0, name: 'a', start_stack: 800, end_stack: 1600, cards: ['As', 'Ad'], net: 800, won: 1600 }, { seat: 1, name: 'b', start_stack: 12000, end_stack: 11200, cards: ['Kc', 'Kd'], net: -800, won: 0 }],
      actions: [{ street: 'preflop', seat: 1, act: 'sb', amt: 10, put: 10 }, { street: 'preflop', seat: 0, act: 'bb', amt: 20, put: 20 },
        { street: 'preflop', seat: 1, act: 'allin', amt: 11600, put: 11590 }, { street: 'preflop', seat: 0, act: 'call', amt: 800, put: 780 }],
      winners: [{ seat: 0, amount: 1600, hand: 'Pair of aces' }], pots: [{ amount: 1600, winners: [0] }] };
    const hh = document.createElement('div'); document.body.appendChild(hh);
    M.renderHandHistory(hh, rec);
    const steps = [...hh.querySelectorAll('[data-hh-go]')];
    out.replay = [];
    for (const b of steps) {
      b.click();
      out.replay.push(`${hh.querySelector('[data-hh-text]').textContent} | ${hh.querySelector('[data-hh-pot]').textContent} | b ${hh.querySelector('[data-hh-seat="1"] [data-hh-stack]').textContent}`);
    }
    hh.remove(); host.remove();
    return out;
  });
  check(H.slider.max >= 4753 && /All-in 4,753/.test(H.slider.label), 'the raise slider\'s far right is all-in when the stack is off the step grid', JSON.stringify(H.slider));
  check(H.unlock.drop && H.unlock.welcome && H.unlock.timeout && H.acts === 3, 'the action bar unlocks after a dropped socket, a reconnect welcome, and 4 s with no answer', JSON.stringify(H.unlock) + ' acts ' + H.acts);
  check(H.addonLive.disabled && /sit out/i.test(H.addonLive.text) && !H.addonIdle.disabled && H.addonIdle.text === 'Add on', 'Add on is off while dealt into a hand (with the reason) and on between hands', JSON.stringify([H.addonLive, H.addonIdle]));
  check(H.elsewhere.note && H.elsewhere.sits === 0, 'another table shows "your turn at Other table / Back to my seat" and no Sit here', JSON.stringify(H.elsewhere));
  check(H.lobby && H.lobbyCleared, 'the lobby shows "Back to my seat" from rt.seated and clears it when the seat is gone');
  check(H.pot === 'Pot 3,360 · Uncalled 6,100' && H.pot2 === 'Main 400 · Side 1,200 · Uncalled 400' && H.pot3 === 'Pot 180', 'the pot readout shows an unmatched excess as uncalled, never as a side pot', `${H.pot} / ${H.pot2} / ${H.pot3}`);
  const flop = H.replay.find(t => /^Flop/.test(t)) || '', river = H.replay.find(t => /^River/.test(t)) || '';
  check(/takes back 10,800/.test(flop) && /Pot 1,600 \| b 11,200$/.test(flop) && /Pot 1,600 \| b 11,200$/.test(river), 'the replay hands the uncalled 10,800 back before the run-out (pot 1,600)', H.replay.slice(3).join(' || '));

  /* ───────────────────────── leave ───────────────────────── */

  section('A leaves');
  await pA.click('[data-leave]');
  const confirm = await pA.waitForSelector('dialog[open] [data-ok]', { timeout: 1500 }).then(() => true, () => false);
  if (confirm) { note('A was in a hand: confirm dialog'); await pA.click('dialog[open] [data-ok]'); }
  const gone = await drive(async () => !seatRow(pidA), 60000, 'leave');
  check(gone, `A's seat row is gone after leaving${confirm ? ' (paid at hand end)' : ''}`);
  const endA = dbBal(pidA);
  const nets = +php(`$n = 0; foreach (q('SELECT record FROM poker_hands')->fetchAll() as $r) { foreach ((json_decode($r['record'], true)['players'] ?? []) as $p) { if (($p['uid'] ?? '') === 'p${pidA}') { $n += (int)$p['net']; } } } echo $n;`);
  check(endA === startA + nets, `A's coins are conserved: ${startA} start ${nets >= 0 ? '+' : ''}${nets} at the table = ${endA}`);
  const headerOk = await waitFor(async () => +(await pA.getAttribute('[data-balance]', 'data-balance')) === endA, 6000);
  check(!!headerOk, `A's header balance shows the cash-out (${endA})`, await pA.getAttribute('[data-balance]', 'data-balance'));
  const aSeated = await pA.evaluate(() => { const t = window.goldTidePoker.table; return t && t.view ? t.view.me : 'none'; });
  check(aSeated === null, 'A is back to watching (me = null)');


  /* ───────────────────────── ws.php restart refund ───────────────────────── */

  section('ws.php restart while B is seated');
  if (seatRow(pidB)) {
    const errAt = errors.length;
    procs[0].kill('SIGKILL');
    const tKill = Date.now();
    await sleep(300);
    procs[0] = spawn(PHP, ['ws.php', '--port', String(wsPort), '--bind', '127.0.0.1', '--tick', '20'], { cwd: tmp, stdio: ['ignore', wsLog, wsLog] });
    const refunded = await waitFor(async () => !seatRow(pidB), 10000);
    const back = await waitFor(() => pB.evaluate(() => window.goldTidePoker.rt.state === 'open' && window.goldTidePoker.table && window.goldTidePoker.table.view && window.goldTidePoker.table.view.me === null), 20000, 250);
    const balB = dbBal(pidB);
    const hdrB = await waitFor(async () => +(await pB.getAttribute('[data-balance]', 'data-balance')) === balB, 6000);
    const toastB = await pB.evaluate(() => [...document.querySelectorAll('.toast')].map(t => t.textContent).join(' | '));
    check(!!refunded && !!back && !!hdrB, `after the restart refund B's header balance matches the database (${balB})`, `header ${await pB.getAttribute('[data-balance]', 'data-balance')} refunded ${!!refunded} back ${!!back}`);
    check(/seat was closed while you were disconnected/.test(toastB), 'B is told the seat was closed and the chips refunded', toastB);
    // the browser logs refused connections while ws.php was down: those are expected, nothing else is
    for (let i = errors.length - 1; i >= errAt; i--) if (/WebSocket connection to .* failed/.test(errors[i])) errors.splice(i, 1);
    note(`restart round trip ${((Date.now() - tKill) / 1000).toFixed(1)} s`);
  } else note('B is no longer seated: restart check skipped');

  /* ───────────────────────── hand history ───────────────────────── */

  section('hand history');
  await pA.goto(base + verifyHref.replace(/^\?/, '?'));
  await pA.waitForSelector('[data-client-check].ok, [data-client-check].bad', { timeout: 8000 });
  const phpCheck = await pA.textContent('.ph-check strong');
  const clientCheck = await pA.textContent('[data-client-check]');
  const dealCheck = await pA.getAttribute('[data-deal-check]', 'data-deal-check');
  check(/Deck commitment verified/.test(phpCheck) && await pA.$('.ph-check.ok') !== null, 'PHP says "Deck commitment verified"', phpCheck);
  check(/Deck commitment verified/.test(clientCheck), 'the client-side SHA-256 says "Deck commitment verified"', clientCheck);
  check(dealCheck === 'ok' && await pA.$('.ph-deal.ok') !== null, 'deal order verified client-side and server-side');
  const t1 = await pA.textContent('[data-hh-text]');
  await pA.click('[data-hh="next"]'); await pA.click('[data-hh="next"]'); await pA.click('[data-hh="next"]');
  const t2 = await pA.textContent('[data-hh-text]');
  await pA.click('[data-hh="last"]');
  const t3 = await pA.textContent('[data-hh-text]');
  check(t1 !== t2 && /wins|Hand over/.test(t3), 'the replay steps through the actions to the result', `${t1} / ${t2} / ${t3}`);
  await pA.screenshot({ path: path.join(OUT, 'poker_hand_history.png'), fullPage: true });
  const lastId = +php(`echo (int)val('SELECT MAX(id) FROM poker_hands WHERE table_id = 1');`);
  await pA.goto(base + `?action=poker_hand&id=${lastId}`);
  await pA.waitForSelector('[data-client-check].ok, [data-client-check].bad', { timeout: 8000 });
  check(/verified/.test(await pA.textContent('[data-client-check]')), `hand #id=${lastId} verifies too`);
  await pB.goto(base + `?action=poker_hand&id=${lastId}`);
  await pB.waitForSelector('[data-client-check].ok, [data-client-check].bad', { timeout: 8000 });
  check(await noScroll(), 'phone: hand history has no horizontal scroll');

  /* ───────────────────────── wrap up ───────────────────────── */

  section('console');
  check(errors.length === 0, 'zero console errors on every page', errors.slice(0, 6).join(' | '));
  await browser.close();
  console.log(`\n${pass} passed, ${fail} failed in ${elapsed().trim()} s${fail ? '\nFAILED: ' + failures.join('; ') : ''}`);
  if (fail) console.log(`(scratch copy kept for inspection: ${tmp})`);
  else fs.rmSync(tmp, { recursive: true, force: true });
  cleanup();
  process.exit(fail ? 1 : 0);
})().catch(e => {
  console.error('\nUNCAUGHT', e && e.stack || e);
  console.log(`(scratch copy kept: ${tmp})`);
  cleanup();
  process.exit(1);
});
