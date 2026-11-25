// Overload server: rest alerts, crew, accounts and cloud sync. © 2026 Jake Scarpa. All rights reserved.
// Bindings: TIMER (RestTimer), CREW (Crew), VAULT (Vault). Secret: VAPID_PRIVATE.

const ORIGIN = 'https://jscarp9.github.io';
const RP_ID = 'jscarp9.github.io';
const SUBJECT = 'https://jscarp9.github.io/Overload/';
const RANK_WEEKS = [0, 2, 6, 12, 20, 32, 45, 52];

const cors = {
  'Access-Control-Allow-Origin': ORIGIN,
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { ...cors, 'Content-Type': 'application/json' } });
const enc = new TextEncoder();
const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64u = s => Uint8Array.from(atob(String(s).replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - String(s).length % 4) % 4)), c => c.charCodeAt(0));
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const sha = async s => hex(await crypto.subtle.digest('SHA-256', typeof s === 'string' ? enc.encode(s) : s));
const clip = (v, n) => String(v == null ? '' : v).slice(0, n);
const rid = () => crypto.randomUUID().replace(/-/g, '').slice(0, 12);
const randTok = () => b64u(crypto.getRandomValues(new Uint8Array(32)));
async function withCors(r) { return new Response(r.body, { status: r.status, headers: { ...cors, 'Content-Type': 'application/json' } }); }

/* ---------- web push ---------- */
async function vapidAuth(endpoint, env) {
  const jwk = JSON.parse(env.VAPID_PRIVATE);
  const key = await crypto.subtle.importKey('jwk', { ...jwk, ext: true }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const pub = b64u(new Uint8Array([4, ...fromB64u(jwk.x), ...fromB64u(jwk.y)]));
  const head = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const body = b64u(enc.encode(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: SUBJECT })));
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(head + '.' + body));
  return `vapid t=${head}.${body}.${b64u(sig)}, k=${pub}`;
}
async function sendPush(endpoint, env) {
  const r = await fetch(endpoint, { method: 'POST', headers: { Authorization: await vapidAuth(endpoint, env), TTL: '120', Urgency: 'high', 'Content-Length': '0' } });
  return r.status;
}
function okEndpoint(u) {
  try { return /(^|\.)(push\.apple\.com|googleapis\.com|push\.services\.mozilla\.com|notify\.windows\.com)$/.test(new URL(u).hostname); } catch (e) { return false; }
}

/* ---------- passkey challenge (stateless, signed) ---------- */
async function hmacKey(env) {
  const raw = await crypto.subtle.digest('SHA-256', enc.encode('overload-challenge:' + env.VAPID_PRIVATE));
  return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
async function makeChallenge(env) {
  const ts = new Uint8Array(8); new DataView(ts.buffer).setFloat64(0, Date.now());
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(env), ts)).slice(0, 24);
  return b64u(new Uint8Array([...ts, ...mac]));
}
async function checkChallenge(env, ch) {
  try {
    const b = fromB64u(ch); if (b.length !== 32) return false;
    const ts = b.slice(0, 8), t = new DataView(ts.buffer).getFloat64(0);
    if (!(Date.now() - t < 5 * 60 * 1000 && Date.now() - t > -60000)) return false;
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(env), ts)).slice(0, 24);
    return mac.every((v, i) => v === b[8 + i]);
  } catch (e) { return false; }
}
function derToRaw(der) {
  // ECDSA DER signature -> 64 byte r||s
  let i = 2; if (der[1] & 0x80) i += der[1] & 0x7f;
  const rl = der[i + 1]; let r = der.slice(i + 2, i + 2 + rl); i = i + 2 + rl;
  const sl = der[i + 1]; let s = der.slice(i + 2, i + 2 + sl);
  const pad = x => { while (x.length > 32 && x[0] === 0) x = x.slice(1); const o = new Uint8Array(32); o.set(x, 32 - x.length); return o; };
  return new Uint8Array([...pad(r), ...pad(s)]);
}
async function verifyAssertion(cred, a, challengeOk) {
  const cd = JSON.parse(new TextDecoder().decode(fromB64u(a.clientDataJSON)));
  if (cd.type !== 'webauthn.get' || cd.origin !== ORIGIN || !(await challengeOk(cd.challenge))) return false;
  const ad = fromB64u(a.authenticatorData);
  const rpHash = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(RP_ID)));
  if (!rpHash.every((v, i) => v === ad[i]) || !(ad[32] & 1)) return false;
  const data = new Uint8Array([...ad, ...new Uint8Array(await crypto.subtle.digest('SHA-256', fromB64u(a.clientDataJSON)))]);
  const sig = fromB64u(a.signature);
  if (cred.alg === -257) {
    const k = await crypto.subtle.importKey('spki', fromB64u(cred.pk), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    return crypto.subtle.verify('RSASSA-PKCS1-v1_5', k, sig, data);
  }
  const k = await crypto.subtle.importKey('spki', fromB64u(cred.pk), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, k, derToRaw(sig), data);
}
const acctFromCode = async code => (await sha('acct:' + String(code).toUpperCase().replace(/[^A-Z0-9]/g, ''))).slice(0, 24);
const verFromCode = async code => sha('ver:' + String(code).toUpperCase().replace(/[^A-Z0-9]/g, ''));
function newCode() {
  const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789', b = crypto.getRandomValues(new Uint8Array(16));
  const s = [...b].map(x => A[x % A.length]).join('');
  return s.match(/.{4}/g).join('-');
}

/* ---------- router ---------- */
const WORDS = ['IRON', 'PLATE', 'BEAST', 'TITAN', 'FORGE', 'APEX', 'GRIND', 'ALPHA', 'BULL', 'RAGE', 'LIFT', 'PUMP', 'SQUAD', 'STEEL'];
export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors });
    const url = new URL(req.url);
    if (req.method === 'GET' && url.pathname === '/') return json({ ok: true, app: 'Overload push' });
    if (req.method === 'GET' && url.pathname === '/crew/ws') {
      if (req.headers.get('Upgrade') !== 'websocket') return json({ error: 'expected websocket' }, 426);
      const code = String(url.searchParams.get('code') || '').toUpperCase();
      if (!/^[A-Z]{3,6}-\d{4}$/.test(code)) return json({ error: 'bad code' }, 400);
      return env.CREW.get(env.CREW.idFromName(code)).fetch(new Request('https://do/ws' + url.search, req));
    }
    if (req.method !== 'POST') return json({ error: 'not found' }, 404);
    let b;
    try { b = await req.json(); } catch (e) { return json({ error: 'bad json' }, 400); }
    if (JSON.stringify(b || {}).length > 900000) return json({ error: 'too big' }, 413);

    if (url.pathname.startsWith('/vault/')) {
      const p = url.pathname.slice(6);
      if (p === '/challenge') return json({ challenge: await makeChallenge(env) });
      if (p === '/new') {
        for (let i = 0; i < 4; i++) {
          const code = newCode(), acct = await acctFromCode(code);
          const r = await env.VAULT.get(env.VAULT.idFromName(acct)).fetch('https://do/create', { method: 'POST', body: JSON.stringify({ acct, ver: await verFromCode(code), name: clip(b.name, 24) }) });
          if (r.status === 409) continue;
          const j = await r.json();
          return json({ ...j, acct, code });
        }
        return json({ error: 'try again' }, 500);
      }
      let acct = clip(b.acct, 40);
      if (p === '/recover') {
        acct = await acctFromCode(b.code);
        const r = await env.VAULT.get(env.VAULT.idFromName(acct)).fetch('https://do/recover', { method: 'POST', body: JSON.stringify({ ver: await verFromCode(b.code) }) });
        const j = await r.json();
        return json(r.ok ? { ...j, acct } : j, r.status);
      }
      if (p === '/passkey/login') {
        acct = new TextDecoder().decode(fromB64u(b.userHandle || ''));
        if (!/^[0-9a-f]{24}$/.test(acct)) return json({ error: 'unknown passkey' }, 404);
      }
      if (!/^[0-9a-f]{24}$/.test(acct)) return json({ error: 'bad account' }, 400);
      return withCors(await env.VAULT.get(env.VAULT.idFromName(acct)).fetch('https://do' + p, { method: 'POST', body: JSON.stringify({ ...b, acct }) }));
    }

    if (url.pathname.startsWith('/crew/')) {
      let code = String(b && b.code || '').toUpperCase().trim();
      if (url.pathname === '/crew/create') {
        for (let i = 0; i < 8; i++) {
          const c = WORDS[Math.floor(Math.random() * WORDS.length)] + '-' + (1000 + Math.floor(Math.random() * 9000));
          const r = await env.CREW.get(env.CREW.idFromName(c)).fetch('https://do/create', { method: 'POST', body: JSON.stringify({ ...b, code: c }) });
          if (r.status !== 409) return withCors(r);
        }
        return json({ error: 'try again' }, 500);
      }
      if (!/^[A-Z]{3,6}-\d{4}$/.test(code)) return json({ error: 'bad code' }, 400);
      return withCors(await env.CREW.get(env.CREW.idFromName(code)).fetch('https://do' + url.pathname.slice(5), { method: 'POST', body: JSON.stringify({ ...b, code }) }));
    }

    if (!b || !okEndpoint(b.endpoint)) return json({ error: 'bad endpoint' }, 400);
    const stub = env.TIMER.get(env.TIMER.idFromName(b.endpoint));
    if (url.pathname === '/schedule') {
      const delay = Math.max(1000, Math.min(15 * 60 * 1000, +b.delay || 0));
      return stub.fetch('https://do/schedule', { method: 'POST', body: JSON.stringify({ endpoint: b.endpoint, at: Date.now() + delay }) });
    }
    if (url.pathname === '/cancel') return stub.fetch('https://do/cancel', { method: 'POST' });
    if (url.pathname === '/test') return json({ sent: await sendPush(b.endpoint, env) });
    return json({ error: 'not found' }, 404);
  },
};

/* ---------- workout math (mirrors the app) ---------- */
const full = x => x && x.w !== '' && x.w != null && x.r !== '' && x.r != null && +x.r > 0 && x.d;
const e1 = x => (+x.w || 0) * (1 + (+x.r || 0) / 30);
const isoD = d => { const z = new Date(d); return z.getFullYear() + '-' + String(z.getMonth() + 1).padStart(2, '0') + '-' + String(z.getDate()).padStart(2, '0'); };
const toDate = s => { const [y, m, d] = s.split('-').map(Number); return new Date(y, m - 1, d); };
const monday = s => { const d = toDate(s); d.setDate(d.getDate() - ((d.getDay() + 6) % 7)); return isoD(d); };
function computeStats(sessions, todayIso, unit) {
  const rs = Object.values(sessions).filter(s => s && !s._del && s.day !== 'base' && s.ex && Object.values(s.ex).some(a => Array.isArray(a) && a.some(full))).sort((a, b) => a.date < b.date ? -1 : a.date > b.date ? 1 : 0);
  const best = {}, lifts = {}; let prs = 0, vol = 0;
  const wk = {};
  rs.forEach(s => {
    const k = monday(s.date); const w = wk[k] = wk[k] || { days: new Set(), sets: 0, vol: 0, prs: 0 };
    w.days.add(s.date);
    Object.entries(s.ex).forEach(([id, a]) => {
      let sb = 0;
      (a || []).forEach(x => { if (!full(x)) return; const v = e1(x); w.sets++; w.vol += x.w * x.r; vol += x.w * x.r; sb = Math.max(sb, v); const n = (s.names && s.names[id]) || id; if (!lifts[n] || v > lifts[n].e) lifts[n] = { e: Math.round(v), w: +x.w, r: +x.r }; });
      if (sb > 0) { if (best[id] && sb > best[id]) { prs++; w.prs++; } best[id] = Math.max(best[id] || 0, sb); }
    });
  });
  const tw = monday(todayIso), lw = isoD(new Date(toDate(tw).getTime() - 7 * 864e5)), pw = isoD(new Date(toDate(tw).getTime() - 14 * 864e5));
  let active = 0, streak = 0;
  Object.values(wk).forEach(w => { if (w.days.size >= 2) active++; });
  if (rs.length) { for (let d = toDate(monday(rs[0].date)); isoD(d) <= tw; d.setDate(d.getDate() + 7)) { const w = wk[isoD(d)]; if (w && w.days.size) streak++; else if (isoD(d) !== tw) streak = 0; } }
  const pack = k => { const w = wk[k]; return { wk: k, days: w ? w.days.size : 0, sets: w ? w.sets : 0, vol: w ? Math.round(w.vol) : 0, prs: w ? w.prs : 0 }; };
  return { workouts: rs.length, lifeVol: Math.round(vol), unit: unit || 'lb', active, streak, lifePR: prs, week: pack(tw), last: pack(lw), prev: pack(pw), days: [...new Set(rs.map(s => s.date))].slice(-21), lifts: Object.fromEntries(Object.entries(lifts).sort((a, b) => b[1].e - a[1].e).slice(0, 30)), since: rs.length ? rs[0].date : null };
}

/* ---------- Vault: one per account ---------- */
const SNAP_KEEP = 30, CHUNK = 100000;
export class Vault {
  constructor(state, env) { this.state = state; this.env = env; }
  async meta() { return this.state.storage.get('meta'); }
  async issue(meta) { const t = randTok(); meta.tokens = [await sha(t), ...(meta.tokens || [])].slice(0, 12); await this.state.storage.put('meta', meta); return t; }
  async authed(b) { const m = await this.meta(); if (!m || !b.token) return null; const h = await sha(String(b.token)); return m.tokens.includes(h) ? m : null; }
  async fetch(req) {
    const path = new URL(req.url).pathname, s = this.state.storage;
    let b; try { b = await req.json(); } catch (e) { return json({ error: 'bad json' }, 400); }
    if (path === '/create') {
      if (await this.meta()) return json({ error: 'taken' }, 409);
      const meta = { acct: b.acct, ver: b.ver, created: Date.now(), name: b.name || '', creds: [], tokens: [], seq: 0 };
      const token = await this.issue(meta);
      return json({ token, seq: 0 });
    }
    if (path === '/recover') {
      const m = await this.meta();
      if (!m || m.ver !== b.ver) return json({ error: 'wrong code' }, 404);
      return json({ token: await this.issue(m), seq: m.seq, passkeys: m.creds.length });
    }
    if (path === '/passkey/login') {
      const m = await this.meta(); if (!m) return json({ error: 'unknown passkey' }, 404);
      const cred = m.creds.find(c => c.id === b.id); if (!cred) return json({ error: 'unknown passkey' }, 404);
      const ok = await verifyAssertion(cred, b, ch => checkChallenge(this.env, ch)).catch(() => false);
      if (!ok) return json({ error: 'passkey check failed' }, 403);
      return json({ token: await this.issue(m), seq: m.seq });
    }
    const meta = await this.authed(b);
    if (path === '/stats') {
      if (!meta) return json({ error: 'auth' }, 403);
      return json(computeStats(await this.sessions(), clip(b.today, 10) || isoD(Date.now()), ((await s.get('i:settings')) || {}).unit));
    }
    if (!meta) return json({ error: 'auth' }, 403);
    switch (path) {
      case '/passkey/register': {
        const pk = clip(b.publicKey, 2000), id = clip(b.id, 600), alg = b.alg === -257 ? -257 : -7;
        if (!pk || !id) return json({ error: 'bad passkey' }, 400);
        meta.creds = [...meta.creds.filter(c => c.id !== id), { id, pk, alg, added: Date.now(), label: clip(b.label, 40) }].slice(-10);
        await s.put('meta', meta);
        return json({ ok: true, passkeys: meta.creds.length });
      }
      case '/signout': { const h = await sha(String(b.token)); meta.tokens = meta.tokens.filter(x => x !== h); await s.put('meta', meta); return json({ ok: true }); }
      case '/delete': await s.deleteAll(); return json({ ok: true, deleted: true });
      case '/info': return json({ created: meta.created, passkeys: meta.creds.length, devices: meta.tokens.length, seq: meta.seq });
      case '/sync': return json(await this.sync(meta, b));
      case '/snaps': return json({ days: ((await s.get('snapIdx')) || []).slice().reverse() });
      case '/snap': {
        const idx = (await s.get('snapIdx')) || []; const d = clip(b.day, 10); if (!idx.includes(d)) return json({ error: 'no snapshot' }, 404);
        const n = (await s.get('snapN:' + d)) || 0; let txt = ''; for (let i = 0; i < n; i++) txt += (await s.get('snap:' + d + ':' + i)) || '';
        return json({ day: d, data: txt });
      }
      default: return json({ error: 'not found' }, 404);
    }
  }
  async sessions() { const m = await this.state.storage.list({ prefix: 's:' }); const o = {}; for (const [k, v] of m) o[k.slice(2)] = v; return o; }
  async sync(meta, b) {
    const s = this.state.storage, since = +b.since || 0, ch = b.changes || {}, now = Date.now();
    let seq = meta.seq || 0; const bump = () => ++seq;
    const sess = ch.sessions && typeof ch.sessions === 'object' ? ch.sessions : {};
    const keys = Object.keys(sess).slice(0, 2000);
    for (const k of keys) {
      if (!/^[\w-]{1,40}$/.test(k)) continue;
      const inc = sess[k], cur = await s.get('s:' + k);
      const merged = mergeSession(cur, inc);
      if (merged && JSON.stringify(merged) !== JSON.stringify(cur)) { merged._v = bump(); await s.put('s:' + k, merged); }
    }
    for (const kind of ['plan', 'notes', 'settings', 'flags']) {
      const inc = ch[kind]; if (!inc || typeof inc !== 'object') continue;
      const cur = await s.get('i:' + kind);
      if (!cur || (+inc._t || 0) > (+cur._t || 0)) { const v = { ...inc, _v: bump() }; await s.put('i:' + kind, v); }
    }
    if (seq !== meta.seq) { meta.seq = seq; meta.last = now; await s.put('meta', meta); }
    // daily snapshot of the merged state
    const day = clip(b.today, 10) || isoD(now), idx = (await s.get('snapIdx')) || [];
    if (!idx.includes(day) && seq > 0) {
      const all = { sessions: await this.sessions(), plan: await s.get('i:plan'), notes: await s.get('i:notes'), settings: await s.get('i:settings'), at: now };
      const txt = JSON.stringify(all); const n = Math.ceil(txt.length / CHUNK);
      for (let i = 0; i < n; i++) await s.put('snap:' + day + ':' + i, txt.slice(i * CHUNK, (i + 1) * CHUNK));
      await s.put('snapN:' + day, n); idx.push(day); idx.sort();
      while (idx.length > SNAP_KEEP) { const old = idx.shift(); const on = (await s.get('snapN:' + old)) || 0; for (let i = 0; i < on; i++) await s.delete('snap:' + old + ':' + i); await s.delete('snapN:' + old); }
      await s.put('snapIdx', idx);
    }
    // everything newer than the caller's last seq
    const out = { sessions: {} };
    const all = await this.sessions();
    for (const [k, v] of Object.entries(all)) if ((v._v || 0) > since) out.sessions[k] = v;
    for (const kind of ['plan', 'notes', 'settings', 'flags']) { const v = await s.get('i:' + kind); if (v && (v._v || 0) > since) out[kind] = v; }
    return { seq, changes: out, at: now };
  }
}
function mergeSession(cur, inc) {
  if (!inc || typeof inc !== 'object') return cur;
  const it = +inc._t || 0;
  if (!cur) return inc._del ? { _del: 1, _t: it } : inc;
  const ct = +cur._t || 0;
  if (inc._del || cur._del) { if (inc._del && it >= ct) return { _del: 1, _t: it }; if (cur._del && ct >= it) return cur; return inc._del ? cur : inc; }
  // exercise-level merge using _xt stamps, everything else follows the newer session
  const newer = it >= ct ? inc : cur, older = newer === inc ? cur : inc;
  const out = { ...older, ...newer, ex: { ...(older.ex || {}) }, _xt: { ...(older._xt || {}) } };
  const ids = new Set([...Object.keys(cur.ex || {}), ...Object.keys(inc.ex || {})]);
  ids.forEach(id => {
    const a = (cur._xt || {})[id] || ct, b = (inc._xt || {})[id] || it;
    const pick = b >= a ? inc : cur;
    if (pick.ex && id in pick.ex) out.ex[id] = pick.ex[id]; else if (id in (cur.ex || {})) out.ex[id] = cur.ex[id]; else out.ex[id] = inc.ex[id];
    out._xt[id] = Math.max(a, b);
  });
  out.names = { ...(cur.names || {}), ...(inc.names || {}) };
  out._t = Math.max(it, ct);
  delete out._v;
  return out;
}

/* ---------- Crew ---------- */
const BANNERS = { steel: 1, ember: 2, ocean: 3, toxic: 5, royal: 7, gold: 10 };
const crewLevel = xp => 1 + Math.floor(Math.sqrt((xp || 0) / 60));
export class Crew {
  constructor(state, env) { this.state = state; this.env = env; }
  async load() {
    if (this.c) return;
    const s = this.state.storage;
    this.c = await s.get('crew');
    this.m = (await s.get('members')) || {};
    this.p = (await s.get('posts')) || [];
    this.ev = (await s.get('events')) || [];
    this.live = (await s.get('live')) || {};
  }
  async save() {
    const s = this.state.storage;
    await s.put('crew', this.c); await s.put('members', this.m); await s.put('posts', this.p); await s.put('events', this.ev); await s.put('live', this.live);
  }
  event(type, from, to, extra) { this.ev.unshift({ id: rid(), ts: Date.now(), type, from, to: to || '*', ...extra }); this.ev = this.ev.slice(0, 200); }
  liveNow() { const o = {}, now = Date.now(); for (const [id, l] of Object.entries(this.live)) if (l.on && now - l.ts < 15 * 60 * 1000 && now - l.start < 4 * 3600 * 1000) o[id] = { day: l.day, start: l.start }; return o; }
  view(me) {
    const members = Object.entries(this.m).map(([id, x]) => ({ id, name: x.name, joined: x.joined, last: x.last, profile: x.profile || null, pings: !!x.push, ok: !!x.ok }));
    const bud = {}; (this.c.buddies || []).forEach(x => { if (x.a === me || x.b === me) { const o = x.a === me ? x.b : x.a; bud[o] = (bud[o] || 0) + 1; } });
    const mine = (this.c.buddies || []).filter(x => x.a === me || x.b === me).map(x => x.date);
    return {
      crew: { name: this.c.name, code: this.c.code, owner: this.c.owner, created: this.c.created, challenge: this.c.challenge || null, xp: this.c.xp || 0, level: crewLevel(this.c.xp), banner: this.c.banner || 'steel' },
      members, posts: this.p.slice(0, 60), me, live: this.liveNow(), buddies: bud, buddyDates: mine,
      events: this.ev.filter(e => e.to === '*' || e.to === me).slice(0, 60),
      votes: this.voteView(me),
    };
  }
  voteView(me) {
    const V = this.c.votes || {}, out = {};
    for (const [mo, cats] of Object.entries(V)) { out[mo] = {}; for (const [cat, ballots] of Object.entries(cats)) { const tally = {}; Object.values(ballots).forEach(t => tally[t] = (tally[t] || 0) + 1); out[mo][cat] = { tally, mine: ballots[me] || null }; } }
    return out;
  }
  async notify(fromId, title) {
    const jobs = [];
    for (const [id, x] of Object.entries(this.m)) if (id !== fromId && x.push) jobs.push(sendPush(x.push, this.env).then(s => { if (s === 404 || s === 410) x.push = null; }).catch(() => {}));
    await Promise.all(jobs);
    this.c.lastNote = { title, ts: Date.now(), from: fromId };
  }
  broadcast(msg, onlyTo) {
    const txt = JSON.stringify(msg);
    for (const ws of this.state.getWebSockets ? this.state.getWebSockets(onlyTo) : []) { try { ws.send(txt); } catch (e) {} }
  }
  async fetch(req) {
    const url = new URL(req.url), path = url.pathname;
    await this.load();
    if (path === '/ws') {
      if (!this.c) return new Response('no crew', { status: 404 });
      const id = clip(url.searchParams.get('id'), 40), me = this.m[id];
      if (!me || me.key !== url.searchParams.get('key')) return new Response('auth', { status: 403 });
      const pair = new WebSocketPair(); const [client, server] = Object.values(pair);
      this.state.acceptWebSocket(server, [id]);
      server.send(JSON.stringify({ t: 'live', live: this.liveNow() }));
      return new Response(null, { status: 101, webSocket: client });
    }
    let b; try { b = await req.json(); } catch (e) { return json({ error: 'bad json' }, 400); }
    if (JSON.stringify(b).length > 60000) return json({ error: 'too big' }, 413);
    if (path === '/create') {
      if (this.c) return json({ error: 'taken' }, 409);
      const id = clip(b.id, 40), key = clip(b.key, 80);
      if (!id || key.length < 16) return json({ error: 'bad member' }, 400);
      this.c = { name: clip(b.name, 30) || 'My crew', code: b.code, owner: id, created: Date.now(), challenge: null, xp: 0, banner: 'steel', votes: {}, buddies: [] };
      this.m = { [id]: { name: clip(b.member, 24) || 'Lifter', key, joined: Date.now(), last: Date.now(), profile: null, push: null } };
      this.p = []; this.ev = []; this.live = {};
      await this.save();
      return json(this.view(id));
    }
    if (!this.c) return json({ error: 'no crew' }, 404);
    const id = clip(b.id, 40), me = this.m[id];
    if (path === '/join') {
      if (me) { if (me.key !== b.key) return json({ error: 'auth' }, 403); }
      else {
        if (Object.keys(this.m).length >= 30) return json({ error: 'full' }, 403);
        if (!id || clip(b.key, 80).length < 16) return json({ error: 'bad member' }, 400);
        this.m[id] = { name: clip(b.member, 24) || 'Lifter', key: clip(b.key, 80), joined: Date.now(), last: Date.now(), profile: null, push: null };
        this.p.unshift({ id: rid(), by: id, ts: Date.now(), type: 'join', reacts: {}, comments: [] });
        this.event('join', id);
        this.broadcast({ t: 'refresh' });
      }
      await this.save();
      return json(this.view(id));
    }
    if (!me || me.key !== b.key) return json({ error: 'auth' }, 403);
    me.last = Date.now();
    const post = id2 => this.p.find(x => x.id === id2);
    let changed = true;
    switch (path) {
      case '/state': changed = false; break;
      case '/profile': {
        const p = b.profile && typeof b.profile === 'object' ? b.profile : null;
        if (b.member) me.name = clip(b.member, 24);
        me.ok = false;
        if (p && b.acct && b.atoken && this.env.VAULT) {
          try {
            const r = await this.env.VAULT.get(this.env.VAULT.idFromName(clip(b.acct, 40))).fetch('https://do/stats', { method: 'POST', body: JSON.stringify({ token: b.atoken, today: clip(b.today, 10) }) });
            if (r.ok) {
              const st = await r.json(); me.acct = clip(b.acct, 40);
              const prevW = me.srvWorkouts || 0;
              if (st.workouts > prevW && me.srvWorkouts !== undefined) this.c.xp = (this.c.xp || 0) + (st.workouts - prevW) * 10;
              me.srvWorkouts = st.workouts;
              Object.assign(p, { workouts: st.workouts, lifeVol: st.lifeVol, unit: st.unit, active: st.active, week: st.week, last: st.last, prev: st.prev, days: st.days, lifts: st.lifts, since: st.since, lifePR: st.lifePR });
              let rank = Math.max(0, Math.min(7, +p.rank || 0)); while (rank > 0 && RANK_WEEKS[rank] > st.active) rank--;
              if (rank !== +p.rank) { p.rank = rank; p.div = 3; p.rname = ['Iron', 'Bronze', 'Silver', 'Gold', 'Platinum', 'Diamond', 'Titan', 'Olympian'][rank] + (rank < 7 ? ' III' : ''); p.pres = 0; }
              p.streak = Math.min(+p.streak || 0, st.streak + 2); p.bcount = Math.min(+p.bcount || 0, 400);
              p.power = Math.round(p.rank * 120 + (p.rank < 7 ? (3 - (+p.div || 3)) * 40 : 0) + (+p.pres || 0) * 100 + st.active * 6 + p.bcount * 3 + st.lifePR * 2 + p.streak * 4);
              me.ok = true;
            }
          } catch (e) {}
        }
        me.profile = p;
        break;
      }
      case '/post': {
        const t = b.post && b.post.type === 'rank' ? 'rank' : 'workout';
        const p = { id: rid(), by: id, ts: Date.now(), type: t, cap: clip(b.post && b.post.cap, 280), data: b.post && b.post.data || null, reacts: {}, comments: [] };
        this.p.unshift(p); this.p = this.p.slice(0, 150);
        this.c.xp = (this.c.xp || 0) + 5;
        if (t === 'rank') this.event('rank', id, '*', { text: clip(p.data && p.data.rname, 30) });
        await this.notify(id, t === 'rank' ? `${me.name} ranked up` : `${me.name} posted a workout`);
        break;
      }
      case '/react': {
        const p = post(b.post); const e = clip(b.emoji, 8);
        if (p && ['fire', 'muscle', 'trophy'].includes(e)) { const a = p.reacts[e] = p.reacts[e] || []; const i = a.indexOf(id); if (i < 0) { a.push(id); if (p.by !== id) this.event('react', id, p.by, { post: p.id, emoji: e }); } else a.splice(i, 1); }
        break;
      }
      case '/comment': {
        const p = post(b.post); const t = clip(b.text, 200).trim();
        if (p && t) { p.comments.push({ by: id, ts: Date.now(), text: t }); p.comments = p.comments.slice(-50); if (p.by !== id) this.event('comment', id, p.by, { post: p.id, text: t.slice(0, 60) }); }
        break;
      }
      case '/delete': { const p = post(b.post); if (p && (p.by === id || this.c.owner === id)) this.p = this.p.filter(x => x !== p); break; }
      case '/kick': { if (this.c.owner === id && b.target !== id) { const t = clip(b.target, 40); delete this.m[t]; this.broadcast({ t: 'kicked' }, t); } break; }
      case '/leave': {
        delete this.m[id];
        if (this.c.owner === id) { const next = Object.keys(this.m)[0]; if (next) this.c.owner = next; }
        if (!Object.keys(this.m).length) { await this.state.storage.deleteAll(); this.c = null; return json({ ok: true }); }
        await this.save(); this.broadcast({ t: 'refresh' }); return json({ ok: true });
      }
      case '/challenge': {
        const ty = clip(b.type, 10);
        this.c.challenge = ['sets', 'days', 'vol', 'prs'].includes(ty) ? { type: ty, target: Math.max(1, Math.min(1e7, +b.target || 0)), wk: clip(b.wk, 10), by: id, title: clip(b.title, 60) } : null;
        if (this.c.challenge) this.event('challenge', id, '*', { text: this.c.challenge.title });
        break;
      }
      case '/banner': { const k = clip(b.banner, 10); if (this.c.owner === id && BANNERS[k] && crewLevel(this.c.xp) >= BANNERS[k]) this.c.banner = k; break; }
      case '/vote': {
        const mo = clip(b.month, 7), cat = clip(b.cat, 12), t = clip(b.target, 40);
        if (/^\d{4}-\d{2}$/.test(mo) && ['grinder', 'hype', 'comeback', 'improved', 'post'].includes(cat) && this.m[t] && t !== id) {
          const V = this.c.votes = this.c.votes || {}; V[mo] = V[mo] || {}; V[mo][cat] = V[mo][cat] || {}; V[mo][cat][id] = t;
          const ks = Object.keys(V).sort(); while (ks.length > 3) delete V[ks.shift()];
        }
        break;
      }
      case '/live': { this.setLive(id, b); changed = false; await this.save(); this.broadcast({ t: 'live', live: this.liveNow() }); return json({ ok: true, live: this.liveNow() }); }
      case '/pings': me.push = b.endpoint && okEndpoint(b.endpoint) ? b.endpoint : null; changed = false; break;
      case '/latest': {
        const p = this.p.find(x => x.by !== id && x.type !== 'join');
        const who = p && this.m[p.by] ? this.m[p.by].name : 'Your crew';
        return json(p ? { title: p.type === 'rank' ? `${who} ranked up 🏅` : `${who} just finished a workout 💪`, body: p.type === 'rank' ? 'Tap to see their new rank' : (p.cap || (p.data && p.data.day ? p.data.day + ' is done' : 'Tap to see it')) } : { title: 'Overload', body: 'New activity in your crew' });
      }
      default: return json({ error: 'not found' }, 404);
    }
    await this.save();
    if (changed) this.broadcast({ t: 'refresh' });
    return json(this.view(id));
  }
  setLive(id, b) {
    const now = Date.now(), prev = this.live[id];
    if (b.on) { this.live[id] = { on: true, day: clip(b.day, 30), start: prev && prev.on ? prev.start : (+b.start || now), ts: now }; return; }
    if (prev && prev.on) {
      const s1 = prev.start, e1 = now; this.c.buddies = this.c.buddies || []; const today = isoD(now);
      for (const [oid, l] of Object.entries(this.live)) {
        if (oid === id || !l.start) continue;
        const e2 = l.on ? now : (l.end || l.ts), overlap = Math.min(e1, e2) - Math.max(s1, l.start);
        if (overlap >= 20 * 60 * 1000 && !this.c.buddies.some(x => x.date === today && ((x.a === id && x.b === oid) || (x.a === oid && x.b === id)))) this.c.buddies.push({ a: id, b: oid, date: today });
      }
      this.c.buddies = this.c.buddies.slice(-500);
    }
    this.live[id] = { on: false, start: prev && prev.start, end: now, ts: now };
  }
  async webSocketMessage(ws, msg) {
    await this.load(); if (!this.c) return;
    let m; try { m = JSON.parse(msg); } catch (e) { return; }
    const tags = this.state.getTags ? this.state.getTags(ws) : []; const id = tags[0]; if (!id || !this.m[id]) return;
    if (m.t === 'live') { this.setLive(id, m); await this.save(); this.broadcast({ t: 'live', live: this.liveNow() }); }
    else if (m.t === 'hype' && this.m[m.to]) { this.broadcast({ t: 'hype', from: this.m[id].name, fromId: id }, clip(m.to, 40)); this.event('hype', id, clip(m.to, 40)); await this.save(); }
    else if (m.t === 'ping') { try { ws.send('{"t":"pong"}'); } catch (e) {} }
  }
  async webSocketClose(ws) { try { ws.close(); } catch (e) {} }
  async webSocketError() {}
}

/* ---------- RestTimer ---------- */
export class RestTimer {
  constructor(state, env) { this.state = state; this.env = env; }
  async fetch(req) {
    const path = new URL(req.url).pathname;
    if (path === '/schedule') {
      const { endpoint, at } = await req.json();
      await this.state.storage.put('endpoint', endpoint);
      await this.state.storage.setAlarm(at);
      return json({ ok: true, at });
    }
    if (path === '/cancel') { await this.state.storage.deleteAlarm(); return json({ ok: true }); }
    return json({ error: 'not found' }, 404);
  }
  async alarm() {
    const endpoint = await this.state.storage.get('endpoint');
    if (!endpoint) return;
    const s = await sendPush(endpoint, this.env);
    if (s === 404 || s === 410) await this.state.storage.deleteAll();
  }
}
