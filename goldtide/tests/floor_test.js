#!/usr/bin/env node
/**
 * tests/floor_test.js: end-to-end tests for The Floor (?action=floor, floor_js()) with Playwright + Chromium.
 *
 * It runs from a temporary copy of goldtide/ with its own SQLite file (the real data/ is never touched), starts its own
 * `php -S` on a free port in 8400-8449 and its own `php ws.php` in 8450-8499, and points the ws_url setting at it.
 * Two registered players, a guest and a phone walk the floor: first frame, roster, movement seen by the other player,
 * escaped chat, sitting at a slot cabinet (iframe on the screen), standing up, sitting at a poker seat (HUD + 'st' seen by
 * the other player), the guest sign-up prompt, the mobile joystick, the socket-offline case, and no console errors.
 * Screenshots go to goldtide/tests/out/ (gitignored). Exit code 1 on any failure.
 *
 *     node goldtide/tests/floor_test.js            # PLAYWRIGHT=/path/to/playwright to override the module location
 */
'use strict';
const path = require('path'), fs = require('fs'), os = require('os'), net = require('net');
const { spawn, execFileSync } = require('child_process');
const { chromium } = require(process.env.PLAYWRIGHT || '/opt/node22/lib/node_modules/playwright');

const ROOT = path.resolve(__dirname, '..');
const OUT = path.join(__dirname, 'out');
const PHP = process.env.PHP || 'php';
const GL_ARGS = ['--use-gl=angle', '--use-angle=swiftshader', '--enable-unsafe-swiftshader'];
const T0 = Date.now();
const sleep = ms => new Promise(r => setTimeout(r, ms));

let pass = 0, fail = 0;
const failures = [];
function check(ok, name, detail = '') {
  if (ok) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; failures.push(name); console.log(`  FAIL ${name}${detail ? '  -- ' + String(detail).slice(0, 400) : ''}`); }
  return ok;
}
const section = s => console.log(`\n== ${s}  (${((Date.now() - T0) / 1000).toFixed(1)} s)`);

function freePort(lo, hi) {
  return new Promise((resolve, reject) => {
    const tryPort = p => {
      if (p > hi) return reject(new Error(`no free port in ${lo}-${hi}`));
      const s = net.createServer(); s.unref();
      s.once('error', () => tryPort(p + 1));
      s.listen(p, '127.0.0.1', () => s.close(() => resolve(p)));
    };
    tryPort(lo + Math.floor(Math.random() * (hi - lo)));
  });
}
async function waitHttp(url, ms = 15000) {
  const end = Date.now() + ms;
  while (Date.now() < end) { try { const r = await fetch(url); if (r.status < 500) return true; } catch (e) {} await sleep(150); }
  return false;
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gt_floor_test_'));
  for (const f of ['index.php', 'ws.php']) fs.copyFileSync(path.join(ROOT, f), path.join(tmp, f));
  // FLOOR_TEST_PORTS=8600,8650 moves the two 50-port ranges (web, socket) so parallel runs don't collide
  const [WLO, SLO] = (process.env.FLOOR_TEST_PORTS || '8400,8450').split(',').map(Number);
  const webPort = await freePort(WLO, WLO + 49), wsPort = await freePort(SLO, SLO + 49);
  const BASE = `http://127.0.0.1:${webPort}/`;
  // install the scratch database and point the page at our socket server
  execFileSync(PHP, ['-r', `define("GT_NO_ROUTE",1); require "index.php"; db(); q("UPDATE settings SET value=? WHERE key=?", ["ws://127.0.0.1:${wsPort}/", "ws_url"]);`], { cwd: tmp });
  const procs = [];
  const start = (args, env = {}) => { const p = spawn(PHP, args, { cwd: tmp, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] }); let log = ''; p.stdout.on('data', d => { log += d; }); p.stderr.on('data', d => { log += d; }); p.log = () => log; procs.push(p); return p; };
  const web = start(['-S', `127.0.0.1:${webPort}`, 'index.php'], { PHP_CLI_SERVER_WORKERS: '4' });
  let ws = start(['ws.php', '--port', String(wsPort), '--bind', '127.0.0.1']);
  const cleanup = () => { for (const p of procs) { try { p.kill('SIGTERM'); } catch (e) {} } try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (e) {} };
  process.on('exit', cleanup);

  let browser;
  const errors = []; // [page label, text]
  try {
    section('start-up');
    check(await waitHttp(BASE + '?action=rules'), `php -S is up on ${webPort}`, web.log());
    check(await waitHttp(`http://127.0.0.1:${wsPort}/health`), `ws.php is up on ${wsPort}`, ws.log());
    browser = await chromium.launch({ args: GL_ARGS });

    const newPage = async (label, opts = {}) => {
      const ctx = await browser.newContext({ viewport: { width: 1100, height: 720 }, ...opts });
      await ctx.addInitScript(() => { try { localStorage.setItem('gt_floor', JSON.stringify({ quality: 'low' })); } catch (e) {} });
      const page = await ctx.newPage();
      page.on('console', m => { if (m.type() === 'error') errors.push([label, m.text()]); });
      page.on('pageerror', e => errors.push([label, 'pageerror: ' + e.message]));
      page.label = label;
      page.posSent = []; // [ms, {x, z}] of every 'pos' frame this page sends
      page.on('websocket', w => w.on('framesent', f => { try { const m = JSON.parse(String(f.payload)); if (m.t === 'pos') page.posSent.push([Date.now(), m]); } catch (e) {} }));
      return page;
    };
    const register = async (page, name) => {
      await page.goto(BASE + '?action=register');
      await page.fill('input[name=username]', name);
      await page.fill('input[name=password]', 'floor-pass-123');
      await page.fill('input[name=password2]', 'floor-pass-123');
      await page.check('input[name=age_ok]'); await page.check('input[name=terms_ok]');
      await Promise.all([page.waitForNavigation(), page.click('form.form button')]);
      return page.evaluate(() => !!document.querySelector('.who'));
    };
    const openFloor = async page => {
      await page.goto(BASE + '?action=floor');
      await page.waitForFunction(() => window.__floor && window.__floor.ready, null, { timeout: 60000 });
      await sleep(2500);
    };
    const shot = (page, name) => page.screenshot({ path: path.join(OUT, name + '.png') });
    const F = (page, fn, arg) => page.evaluate(fn, arg);
    const suffix = Math.random().toString(36).slice(2, 7);
    const nameA = 'floor_a_' + suffix, nameB = 'floor_b_' + suffix;

    section('two players walk in');
    const A = await newPage('A'), B = await newPage('B', { colorScheme: 'dark' });
    check(await register(A, nameA), 'player A registers through the sign-up form');
    check(await register(B, nameB), 'player B registers through the sign-up form');
    // Every page in one browser shares one software GPU process, so the test keeps only the page it is looking at rendering
    // (window.__floor.pause skips the WebGL draw; networking, avatars and the DOM keep running).
    await openFloor(A); await F(A, () => window.__floor.pause(true));
    await openFloor(B); await F(B, () => window.__floor.pause(true)); await F(A, () => window.__floor.pause(false));
    const pixA = await F(A, () => window.__floor.pixels());
    check(pixA.lit >= pixA.n * .6, 'the first frame renders (most sampled canvas pixels are lit)', JSON.stringify(pixA));
    const stA = await F(A, () => window.__floor.state());
    check(stA.calls > 0 && stA.calls <= 250, `draw calls at the entrance stay within budget (${stA.calls} ≤ 250)`, JSON.stringify(stA));
    check(await F(A, () => !!document.querySelector('.fl-me .fl-bal') && document.querySelector('.fl-me .fl-name').textContent.length > 0), 'the HUD shows the balance and the player name');
    await shot(A, 'floor-a-entrance');

    section('roster');
    const seesOther = async (page, name) => { try { await page.waitForFunction(n => window.__floor.remotes().some(r => r.name === n), name, { timeout: 15000 }); return true; } catch (e) { return false; } };
    check(await seesOther(A, nameB), 'A has an avatar for B');
    check(await seesOther(B, nameA), 'B has an avatar for A');
    await A.waitForFunction(() => +document.querySelector('.fl-online-n').textContent >= 2, null, { timeout: 10000 }).catch(() => {});
    check(+(await F(A, () => document.querySelector('.fl-online-n').textContent)) >= 2, 'the online count shows both players');

    section('movement is seen by the other player');
    const posOfA = () => F(B, n => { const r = window.__floor.remotes().find(r => r.name === n); return r ? [r.x, r.z] : null; }, nameA);
    const before = await posOfA();
    await A.bringToFront();
    await A.keyboard.down('KeyW'); await sleep(1000); await A.keyboard.up('KeyW');
    await sleep(900);
    const meA = await F(A, () => window.__floor.state());
    let after = await posOfA();
    for (let i = 0; i < 10 && after && before && Math.hypot(after[0] - before[0], after[1] - before[1]) < .3; i++) { await sleep(300); after = await posOfA(); }
    check(Math.hypot(meA.x - stA.x, meA.z - stA.z) > .3, 'holding W for a second walks A forward', JSON.stringify([stA.x, stA.z, meA.x, meA.z]));
    check(before && after && Math.hypot(after[0] - before[0], after[1] - before[1]) > .3, "B sees A's avatar move", JSON.stringify({ before, after }));
    // position updates: at most 10 a second (the server drops past 15/s), and the spot A stopped on is the one B ends up with
    A.posSent.length = 0;
    await A.keyboard.down('KeyD'); await sleep(1500); await A.keyboard.up('KeyD'); await sleep(1200);
    const ts = A.posSent.map(p => p[0]); let maxWin = 0;
    for (let i = 0; i < ts.length; i++) { let j = i; while (j < ts.length && ts[j] - ts[i] < 1000) j++; maxWin = Math.max(maxWin, j - i); }
    check(ts.length >= 5 && maxWin <= 11, `walking sends about 10 'pos' a second, not one per frame (${maxWin} in the busiest second, ${ts.length} in all)`);
    const endA = await F(A, () => window.__floor.state());
    let seenEnd = null;
    for (let i = 0; i < 10; i++) { seenEnd = await posOfA(); if (seenEnd && Math.hypot(seenEnd[0] - endA.x, seenEnd[1] - endA.z) < .05) break; await sleep(300); }
    check(seenEnd && Math.hypot(seenEnd[0] - endA.x, seenEnd[1] - endA.z) < .05, "B ends up with the exact spot A stopped on", JSON.stringify({ a: [endA.x, endA.z], seenEnd }));

    section('chat');
    await A.keyboard.press('Enter');
    await A.waitForSelector('.fl-chat.typing .fl-chat-in', { timeout: 5000 });
    await A.keyboard.type('<b>hi</b>');
    await A.keyboard.press('Enter');
    let chatOk = false;
    try {
      await B.waitForFunction(() => [...document.querySelectorAll('.fl-chat-log .fl-line span')].some(s => s.textContent === '<b>hi</b>'), null, { timeout: 10000 });
      chatOk = true;
    } catch (e) {}
    check(chatOk, 'A\'s chat line reaches B');
    check(await F(B, () => { const s = [...document.querySelectorAll('.fl-chat-log .fl-line span')].find(s => s.textContent === '<b>hi</b>'); return !!s && s.children.length === 0 && !document.querySelector('.fl-chat-log span b'); }), 'the chat text is shown escaped: literal <b> tags, no element');
    await F(B, () => window.__floor.pause(false)); await sleep(1200); await shot(B, 'floor-b-chat'); await F(B, () => window.__floor.pause(true));

    section('sit at a slot cabinet');
    const stations = await F(A, () => window.__floor.stations());
    const slot = stations.find(s => s.id === 'slot:tiki:1') || stations.find(s => s.kind === 'cabinet' && s.zone === 'slots');
    check(!!slot, 'the layout has slot cabinets', stations.length);
    const games = await F(A, () => Object.keys(JSON.parse(document.getElementById('floor-cfg').textContent).games));
    const missing = games.filter(g => !stations.some(s => s.slug === g));
    check(missing.length === 0, `every enabled game has a station (${games.length} games, ${stations.length} stations)`, missing.join(', '));
    await F(A, s => { window.__floor.setPos(s.stand[0], s.stand[1]); return window.__floor.face(s.id); }, slot);
    const tgt = await F(A, () => window.__floor.state().target);
    check(tgt === slot.id, 'facing the cabinet highlights it as the target', tgt);
    const promptA = await F(A, () => document.querySelector('.fl-prompt').textContent);
    check(/^E · Play /.test(promptA), 'the prompt says "E · Play …"', promptA);
    await F(A, () => window.__floor.interact());
    let iframeOk = false;
    try { await A.waitForSelector('.floor-css3d iframe.fl-screen[data-loaded="1"]', { timeout: 25000 }); iframeOk = true; } catch (e) {}
    check(iframeOk, 'sitting down creates the game iframe on the screen and it loads');
    const src = await F(A, () => { const f = document.querySelector('iframe.fl-screen'); return f ? f.getAttribute('src') : ''; });
    check(/embed=1/.test(src) && src.includes('action=' + slot.slug), 'the iframe is the embed page of that game', src);
    const frame = A.frames().find(f => /embed=1/.test(f.url()));
    const inner = frame ? await frame.evaluate(() => ({ embed: document.body.classList.contains('embed'), stage: !!document.querySelector('.game-stage, [data-panel], form'), header: getComputedStyle(document.querySelector('.top')).display })) : null;
    check(inner && inner.embed && inner.stage && inner.header === 'none', 'the screen page loaded in embed mode (no header, game panel present)', JSON.stringify(inner));
    check(await F(A, () => document.querySelectorAll('iframe.fl-screen').length === 1), 'exactly one iframe exists');
    check(await F(A, () => getComputedStyle(document.querySelector('.floor-gl')).pointerEvents === 'none' && !document.querySelector('.fl-seated').hidden), 'seated: the canvas lets clicks through and the seated HUD shows');
    await sleep(1800); // the screen fits itself to the game after load
    const fit = frame ? await frame.evaluate(() => { const b = [...document.querySelectorAll('.game-stage .btn.gold')].find(b => b.offsetParent); const r = b && b.getBoundingClientRect(); return b ? { text: b.textContent.trim(), bottom: Math.round(r.bottom), ih: innerHeight } : null; }) : null;
    check(fit && fit.bottom <= fit.ih, "the game's main button is inside the visible part of the screen", JSON.stringify(fit));
    const cover = await F(A, () => {
      const f = document.querySelector('iframe.fl-screen').getBoundingClientRect(), y = Math.max(f.top, 0) + 12, out = [];
      for (const fx of [.1, .5, .85, .95]) { const e = document.elementFromPoint(f.left + f.width * fx, y); out.push(e ? e.tagName + '.' + e.className : 'none'); }
      return { out, map: getComputedStyle(document.querySelector('.fl-map')).display };
    });
    check(cover.map === 'none' && cover.out.every(t => /^IFRAME/.test(t)), 'seated at a screen: the map is hidden and nothing in the HUD covers the top of the game', JSON.stringify(cover));
    let busy = false;
    try { await B.waitForFunction(([n, id]) => window.__floor.remotes().some(r => r.name === n && r.st === id), [nameA, slot.id], { timeout: 8000 }); busy = true; } catch (e) {}
    check(busy, "B sees A seated at that cabinet ('st')");
    await sleep(2500);
    await shot(A, 'floor-a-seated-slot');
    // B walks over to look at A on the stool (and at the IN PLAY screen)
    await F(A, () => window.__floor.pause(true)); await F(B, () => window.__floor.pause(false));
    await F(B, s => { window.__floor.setPos(s.stand[0] + 1.6, s.stand[1] + 2.2); window.__floor.face(s.id); }, slot);
    await sleep(2500); await shot(B, 'floor-b-sees-a-seated');
    check(await F(B, id => window.__floor.state().target !== id || /in play/i.test(document.querySelector('.fl-prompt').textContent), slot.id), 'B is told the cabinet is in play');
    await F(B, () => window.__floor.pause(true)); await F(A, () => window.__floor.pause(false));

    section('stand up');
    await F(A, () => window.__floor.stand());
    await sleep(900);
    check(await F(A, () => document.querySelectorAll('iframe.fl-screen').length === 0 && window.__floor.state().seated === null), 'standing up removes the iframe');
    let freed = false;
    try { await B.waitForFunction(n => window.__floor.remotes().some(r => r.name === n && !r.st), nameA, { timeout: 8000 }); freed = true; } catch (e) {}
    check(freed, 'B sees A stand up');

    section('resize during the sit tween');
    await F(A, s => { window.__floor.setPos(s.stand[0], s.stand[1]); return window.__floor.face(s.id); }, slot);
    await F(A, () => window.__floor.interact());
    await sleep(150);
    const midTween = await F(A, () => window.__floor.state().tweening);
    await A.setViewportSize({ width: 600, height: 900 });
    await A.waitForSelector('.floor-css3d iframe.fl-screen[data-loaded="1"]', { timeout: 25000 }).catch(() => {});
    await sleep(800);
    const rr = await F(A, () => { const r = document.querySelector('iframe.fl-screen').getBoundingClientRect(); return { r: [r.left, r.top, r.right, r.bottom].map(Math.round), W: innerWidth, H: innerHeight }; });
    check(midTween && rr.r[0] >= -2 && rr.r[1] >= -2 && rr.r[2] <= rr.W + 2 && rr.r[3] <= rr.H + 2, 'a resize in the middle of sitting down still fits the screen to the new window', JSON.stringify({ midTween, ...rr }));
    await F(A, () => window.__floor.stand()); await sleep(700);
    await A.setViewportSize({ width: 1100, height: 720 }); await sleep(400);

    section('poker seat');
    const tables = await F(A, () => JSON.parse(document.getElementById('floor-cfg').textContent).tables);
    const t1 = tables[0];
    const pkId = `poker:${t1.id}:${t1.seats - 1}`;
    const pkSt = stations.find(s => s.id === pkId);
    check(!!pkSt, `the card room has a chair for ${pkId}`);
    await F(A, s => { window.__floor.setPos(s.stand[0], s.stand[1]); return window.__floor.face(s.id); }, pkSt);
    await F(A, () => window.__floor.interact());
    let hud = false;
    try { await A.waitForFunction(() => { const h = document.querySelector('.fl-pk-hud'); return h && !h.hidden && h.dataset.mounted === '1' && h.querySelector('.fl-pk-host') && h.querySelector('.fl-pk-host').children.length > 0; }, null, { timeout: 15000 }); hud = true; } catch (e) {}
    check(hud, 'sitting at the poker seat mounts the poker client HUD');
    let gotState = false;
    try { await A.waitForFunction(() => /Seat|buy in|Stack|watching|Buy-in/i.test(document.querySelector('.fl-pk-host').textContent), null, { timeout: 15000 }); gotState = true; } catch (e) {}
    check(gotState, 'the HUD received the table state (buy-in / seat info)', await F(A, () => document.querySelector('.fl-pk-host') && document.querySelector('.fl-pk-host').textContent));
    let pkSeen = false;
    try { await B.waitForFunction(([n, id]) => window.__floor.remotes().some(r => r.name === n && r.st === id), [nameA, pkId], { timeout: 8000 }); pkSeen = true; } catch (e) {}
    check(pkSeen, `B sees A's 'st' as ${pkId}`);
    // buy in and wait to be dealt: the HUD lists your two cards (they are too small to read on the 3D felt at 720p)
    const slid = await F(A, () => /slide over/.test(document.querySelector('.fl-mpk-note') ? document.querySelector('.fl-mpk-note').textContent : ''));
    await A.click('.fl-mpk-row .fl-btn.gold').catch(() => {});
    let dealt = false;
    for (let i = 0; i < 90 && !dealt; i++) {
      await F(A, () => { const p = [...document.querySelectorAll('.fl-mpk-row button')].find(b => /^Post a big blind/.test(b.textContent)); if (p) p.click(); });
      dealt = await F(A, () => document.querySelectorAll('.fl-mpk-hand .fl-mpk-lbl + .fl-mpk-card, .fl-mpk-hand .fl-mpk-card').length >= 2 && /Your hand/i.test(document.querySelector('.fl-mpk-hand').textContent));
      if (!dealt) await sleep(1000);
    }
    const handTxt = await F(A, () => ({ hand: document.querySelector('.fl-mpk-hand').textContent, note: document.querySelector('.fl-mpk-note').textContent, status: document.querySelector('.fl-mpk-status').textContent }));
    check(dealt && /Your hand\s*(10|[2-9JQKA])[♠♥♦♣]\s*(10|[2-9JQKA])[♠♥♦♣]/.test(handTxt.hand), 'once dealt in, the poker HUD shows your two hole cards', JSON.stringify(handTxt));
    check(!/slide over/.test(handTxt.note), `the "you'd slide over" note is gone once you are seated${slid ? ' (it was showing before)' : ''}`, JSON.stringify(handTxt));
    await sleep(1500);
    await shot(A, 'floor-a-poker-seat');
    const leaveSeat = async () => {
      await F(A, () => document.querySelector('.fl-stand') && document.querySelector('.fl-stand').click());
      await sleep(300);
      await F(A, () => { const c = document.querySelector('.fl-confirm:not([hidden]) button.gold'); if (c) c.click(); });
      await sleep(900);
      if (await F(A, () => window.__floor.state().seated !== null)) { await F(A, () => window.__floor.stand()); await sleep(600); }
    };
    await leaveSeat();
    check(await F(A, () => document.querySelector('.fl-pk-hud').hidden && window.__floor.state().seated === null), 'standing up from the poker chair unmounts the HUD');
    // sitting at the same table again reuses its 3D chips / dealer button / spotlight instead of building (and leaking) new ones
    const pkWatch = async () => { await F(A, s => { window.__floor.setPos(s.stand[0], s.stand[1]); window.__floor.face(s.id); return window.__floor.interact(); }, pkSt); await sleep(2200); await F(A, () => window.__floor.stand()); await sleep(600); return F(A, () => { const s = window.__floor.state(); return [s.pkDyn, s.sceneN, s.tex]; }); };
    const w1 = await pkWatch(), w2 = await pkWatch(), w3 = await pkWatch();
    check(w1[0] === 1 && w3[0] === 1 && w3[1] === w1[1], `sitting at the same poker table again reuses its 3D group instead of building a new one (groups ${w1[0]} → ${w3[0]}, scene objects ${w1[1]} → ${w3[1]}, textures ${w1[2]} → ${w2[2]} → ${w3[2]})`);

    await A.keyboard.press('KeyH'); await sleep(1200);
    check(await F(A, () => !document.querySelector('.fl-help').hidden), 'H opens the help overlay');
    await shot(A, 'floor-a-help'); await A.keyboard.press('KeyH');
    section('guest');
    await F(A, () => window.__floor.pause(true));
    const G = await newPage('guest');
    await openFloor(G);
    await F(G, s => { window.__floor.setPos(s.stand[0], s.stand[1]); window.__floor.face(s.id); }, slot);
    await sleep(300);
    const gp = await F(G, () => ({ text: document.querySelector('.fl-prompt').textContent, link: (document.querySelector('.fl-prompt a') || {}).href || '' }));
    check(/sign up/i.test(gp.text) && /action=register/.test(gp.link), 'a guest sees the sign-up prompt with a link', JSON.stringify(gp));
    await F(G, () => window.__floor.interact());
    await sleep(800);
    check(await F(G, () => window.__floor.state().seated === null && !document.querySelector('iframe.fl-screen')), 'a guest cannot sit');
    await shot(G, 'floor-guest-prompt');
    await G.goto(BASE + '?action=floor&floor_nogl=1');
    await G.waitForFunction(() => window.__floor && window.__floor.fallback, null, { timeout: 15000 }).catch(() => {});
    const fb = await F(G, () => ({ links: document.querySelectorAll('.fl-fallback .fl-links a').length, lobby: !!document.querySelector('.fl-fallback a.fl-btn'), games: Object.keys(JSON.parse(document.getElementById('floor-cfg').textContent).games).length }));
    check(fb.links === fb.games && fb.lobby, 'without WebGL the floor lists every game as a link plus the lobby', JSON.stringify(fb));
    await G.context().close();

    section('mobile');
    const Mo = await newPage('mobile', { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true, deviceScaleFactor: 1 });
    await openFloor(Mo);
    const mob = await F(Mo, () => { const j = document.querySelector('.fl-joy'), r = j && j.getBoundingClientRect(); return { joy: !!j && !j.hidden && r.width > 40 && getComputedStyle(j).display !== 'none', sw: document.documentElement.scrollWidth, bw: document.body.scrollWidth, iw: window.innerWidth }; });
    check(mob.joy, 'the phone layout shows the virtual joystick', JSON.stringify(mob));
    check(mob.sw <= mob.iw && mob.bw <= mob.iw, 'no horizontal scroll at 390×844', JSON.stringify(mob));
    await shot(Mo, 'floor-mobile');
    await Mo.context().close();

    section('socket offline');
    await B.context().close();
    ws.kill('SIGTERM');
    await new Promise(r => ws.once('exit', r));
    const offErrStart = errors.length;
    await A.reload();
    await A.waitForFunction(() => window.__floor && window.__floor.ready, null, { timeout: 60000 });
    let badge = false;
    try { await A.waitForFunction(() => { const b = document.querySelector('.fl-offline'); return b && !b.hidden; }, null, { timeout: 15000 }); badge = true; } catch (e) {}
    check(badge, 'with ws.php down the "Multiplayer floor offline" badge shows');
    const pixOff = await F(A, () => window.__floor.pixels());
    check(pixOff.lit >= pixOff.n * .6, 'the floor still renders offline', JSON.stringify(pixOff));
    const s0 = await F(A, () => window.__floor.state());
    await A.keyboard.down('KeyW'); await sleep(700); await A.keyboard.up('KeyW'); await sleep(200);
    const s1 = await F(A, () => window.__floor.state());
    check(Math.hypot(s1.x - s0.x, s1.z - s0.z) > .2, 'and you can still walk around solo');
    await shot(A, 'floor-offline');
    // A refused WebSocket is reported by Chromium itself ("WebSocket connection to … failed"); that is the browser's network log, not page code.
    const wsNoise = errors.slice(offErrStart).filter(([, t]) => /^WebSocket connection to 'ws:\/\/127\.0\.0\.1:\d+\/' failed/.test(t));
    for (const n of wsNoise) errors.splice(errors.indexOf(n), 1);
    console.log(`  (set aside ${wsNoise.length} browser network line(s) about the refused socket)`);

    section('console');
    check(errors.length === 0, 'no console errors or page errors anywhere', errors.map(e => e.join(': ')).join('\n'));
  } catch (e) {
    check(false, 'test run crashed', e.stack || e.message);
  } finally {
    if (browser) await browser.close().catch(() => {});
    cleanup();
  }
  console.log(`\n${pass} passed, ${fail} failed in ${((Date.now() - T0) / 1000).toFixed(1)} s. Screenshots: ${OUT}`);
  if (fail) console.log('Failures:\n - ' + failures.join('\n - '));
  process.exit(fail ? 1 : 0);
})();
