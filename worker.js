// Overload server 0.16 (founder crew banner). 0.15: (raids, lift together, profiles, founder, OG, stats). Previously 0.14: rest alerts, crew (chat, trophies, scenes, trash, daily backups), accounts and cloud sync. © 2026 Jake Scarpa. All rights reserved.
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

    if (url.pathname.startsWith('/stats/')) {
      if (!env.STATS) return json({ error: 'stats off' }, 503);
      const p = url.pathname.slice(6);
      if (p === '/dash') {
        const acct = clip(b.acct, 40); if (!/^[0-9a-f]{24}$/.test(acct)) return json({ error: 'auth' }, 401);
        const r = await env.VAULT.get(env.VAULT.idFromName(acct)).fetch('https://do/isfounder', { method: 'POST', body: JSON.stringify({ token: b.token }) });
        const j = await r.json().catch(() => ({})); if (!j.founder) return json({ error: 'owner only' }, 401);
      }
      if (p !== '/ping' && p !== '/dash') return json({ error: 'not found' }, 404);
      return withCors(await env.STATS.get(env.STATS.idFromName('global')).fetch('https://do' + p, { method: 'POST', body: JSON.stringify(b) }));
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
    if (path === '/isfounder') return json({ founder: !!(meta && meta.founder) });
    if (path === '/founder') {
      if (!meta) return json({ error: 'auth' }, 403);
      if ((await sha('founder:' + String(b.code || '').trim().toUpperCase())) !== FOUNDER_HASH) return json({ error: 'wrong code' }, 400);
      meta.founder = true; await s.put('meta', meta); return json({ ok: true, founder: true });
    }
    if (path === '/stats') {
      if (!meta) return json({ error: 'auth' }, 403);
      return json({ ...computeStats(await this.sessions(), clip(b.today, 10) || isoD(Date.now()), ((await s.get('i:settings')) || {}).unit), founder: !!meta.founder });
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
      case '/delete': return json({ error: 'Account deletion is turned off' }, 403);
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
// 0.14 animated scene banners: unlocked by crew level (lv), crew rank (rank) or a crew trophy (trophy)
const SCENES = { forge: { lv: 1 }, city: { lv: 2 }, ocean2: { lv: 3 }, gym: { lv: 4 }, aurora: { lv: 6 }, volcano: { lv: 8 }, colosseum: { rank: 3 }, space: { rank: 5 }, thunder: { trophy: 'mpc' }, olympus: { rank: 7 }, founder: { founder: 1 } };
const CREST = { shape: ['shield', 'plate', 'circle', 'hex'], icon: ['barbell', 'skull', 'crown', 'bolt', 'wolf', 'flame', 'star', 'none'] };
const REACTS = ['fire', 'muscle', 'trophy', 'clap', 'goat', 'rocket', 'skull', 'crown', 'lol', 'heart', 'crest'];
const CREW_RANK_PTS = [0, 400, 1200, 2500, 4500, 7500, 11500, 17000];
// 0.15
const FOUNDER_HASH = '28f8f69ed443c0fb11e41c2961f3d72f1958675f2bdcc62ed3e541049bad9466'; // sha256('founder:' + secret code); only the hash is public
const OG_CUTOFF = Date.UTC(2027, 11, 31); // OG numbers for everyone who joins before the App Store launch
const BOSSES = [['titan', 'The Iron Titan'], ['golem', 'Plate Golem'], ['hydra', 'Rack Hydra'], ['kraken', 'Deadlift Kraken'], ['dragon', 'Dumbbell Dragon'], ['minotaur', 'Bench Minotaur'], ['yeti', 'Squat Yeti'], ['phoenix', 'Cardio Phoenix']];
const BOSS_HP_PER = 45000; // lb per member, at least 2 members
const ROLES = ['Captain', 'Co-captain', 'Hype Man', 'Spotter', 'Coach', 'Rookie', 'Legend', 'Enforcer', 'Comedian'];
const wkIndex = d => Math.floor((toDate(d) - Date.UTC(2026, 0, 5)) / (7 * DAY));
const DAY = 864e5, TRASH_KEEP = 30 * DAY, ARCHIVE_KEEP = 90 * DAY, CREW_SNAPS = 30, PAGE = 100;
const crewRankOf = c => { const pts = (c.xp || 0) + Object.keys(c.trophies || {}).length * 400; let r = 0; CREW_RANK_PTS.forEach((t, i) => { if (pts >= t) r = i; }); return r; };
const toLb = (v, u) => u === 'kg' ? v * 2.20462 : v;
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
    this.t = (await s.get('trash')) || [];
    this.f = (await s.get('former')) || {};
    this.cp = {};
  }
  async save() {
    const s = this.state.storage;
    // posts are never dropped: overflow goes to archive pages
    if (this.p.length > 150) { const old = this.p.splice(150); this.c.pArch = this.c.pArch || 0; let pg = (await s.get('pa:' + this.c.pArch)) || []; for (const x of old) { pg.push(x); if (pg.length >= PAGE) { await s.put('pa:' + this.c.pArch, pg); this.c.pArch++; pg = []; } } await s.put('pa:' + this.c.pArch, pg); }
    const now = Date.now(); this.t = this.t.filter(x => now - x.ts < TRASH_KEEP).slice(0, 3000);
    await s.put('crew', this.c); await s.put('members', this.m); await s.put('posts', this.p); await s.put('events', this.ev); await s.put('live', this.live); await s.put('trash', this.t); await s.put('former', this.f);
    for (const [n, arr] of Object.entries(this.cp)) if (arr && arr._dirty) { delete arr._dirty; await s.put('cp:' + n, arr); }
  }
  // one full backup of the crew per day, kept 30 days; taken before the first change of the day
  async snapshot() {
    if (!this.c) return; const day = isoD(Date.now()); if (this.c.snapDay === day) return;
    const s = this.state.storage, data = JSON.stringify({ v: 1, ts: Date.now(), c: this.c, m: this.m, p: this.p, t: this.t, f: this.f, chat: await this.chatTail(300) });
    const parts = Math.ceil(data.length / 400000) || 1;
    for (let i = 0; i < parts; i++) await s.put('snap:' + day + ':' + i, data.slice(i * 400000, (i + 1) * 400000));
    const idx = ((await s.get('snapIdx')) || []).filter(x => x.day !== day); idx.push({ day, parts, ts: Date.now() });
    while (idx.length > CREW_SNAPS) { const o = idx.shift(); for (let i = 0; i < o.parts; i++) await s.delete('snap:' + o.day + ':' + i); }
    await s.put('snapIdx', idx); this.c.snapDay = day;
  }
  async readSnap(day) {
    const idx = (await this.state.storage.get('snapIdx')) || [], e = idx.find(x => x.day === day); if (!e) return null;
    let t = ''; for (let i = 0; i < e.parts; i++) t += (await this.state.storage.get('snap:' + day + ':' + i)) || '';
    try { return JSON.parse(t); } catch (x) { return null; }
  }
  /* chat: append-only pages of 100 messages, nothing is ever dropped */
  async page(n) { if (n < 0) return []; if (!this.cp[n]) this.cp[n] = (await this.state.storage.get('cp:' + n)) || []; return this.cp[n]; }
  async chatTail(k) { const N = this.c.chatN || 0; let out = []; for (let n = N; n >= 0 && out.length < k; n--) out = (await this.page(n)).concat(out); return out.slice(-k); }
  async findMsg(mid) { const n = parseInt(String(mid).split('-')[0], 10); if (!(n >= 0)) return null; const pg = await this.page(n); const m = pg.find(x => x.id === mid); return m ? { m, pg } : null; }
  pubMsg(x) { return x.del ? { id: x.id, by: x.by, ts: x.ts, del: 1 } : x; }
  trophyCheck() {
    const c = this.c, ms = Object.values(this.m).filter(x => x.profile), T = c.trophies = c.trophies || {}, now = Date.now(), got = [];
    const give = (k, tier, name) => { const cur = T[k] ? T[k].tier : 0; if (tier > cur) { T[k] = { tier, ts: now }; got.push(name); } };
    const vol = ms.reduce((a, x) => a + toLb(+x.profile.lifeVol || 0, x.profile.unit), 0);
    give('mpc', vol >= 1e7 ? 3 : vol >= 5e6 ? 2 : vol >= 1e6 ? 1 : 0, 'Million Pound Club');
    const wo = ms.reduce((a, x) => a + (+x.profile.workouts || 0), 0);
    give('century', wo >= 1000 ? 3 : wo >= 500 ? 2 : wo >= 100 ? 1 : 0, 'Century Club');
    if (ms.length >= 2) {
      for (const k of ['week', 'last']) {
        if (ms.every(x => x.profile[k] && x.profile[k].days >= 1)) give('unbroken', 1, 'Unbroken');
        if (ms.every(x => x.profile[k] && x.profile[k].days >= 3)) give('ironweek', 1, 'Iron Week');
        if (ms.reduce((a, x) => a + (x.profile[k] ? +x.profile[k].prs || 0 : 0), 0) >= 10) give('prstorm', 1, 'PR Storm');
      }
    }
    if (ms.length >= 3) { const sets = ms.map(x => new Set(x.profile.days || [])); const any = [...sets[0]].some(d => sets.every(z => z.has(d))); if (any) give('fullhouse', 1, 'Full House'); }
    for (const x of ms) { const d = (x.profile.days || []).slice().sort(); if (d.length >= 2) { const a = toDate(d[d.length - 2]), b = toDate(d[d.length - 1]); if (b - a >= 14 * DAY && now - b < 8 * DAY) give('comeback', 1, 'Comeback Crew'); } }
    const r0 = c.rank || 0, r1 = crewRankOf(c);
    if (r1 > r0) { c.rank = r1; this.event('crewrank', '', '*', { text: ['Iron', 'Bronze', 'Silver', 'Gold', 'Platinum', 'Diamond', 'Titan', 'Olympian'][r1] }); }
    else if (c.rank === undefined) c.rank = r1;
    for (const name of got) { this.event('trophy', '', '*', { text: name }); this.p.unshift({ id: rid(), by: '', ts: now, type: 'trophy', data: { name }, reacts: {}, comments: [] }); }
  }
  event(type, from, to, extra) { this.ev.unshift({ id: rid(), ts: Date.now(), type, from, to: to || '*', ...extra }); this.ev = this.ev.slice(0, 200); }
  liveNow() { const o = {}, now = Date.now(); for (const [id, l] of Object.entries(this.live)) if (l.on && now - l.ts < 15 * 60 * 1000 && now - l.start < 4 * 3600 * 1000) o[id] = { day: l.day, start: l.start, g: l.g || '', sets: l.sets || 0, vol: l.vol || 0, ex: l.ex || '', rest: l.rest || 0, prs: l.prs || 0, unit: l.unit || 'lb' }; return o; }
  view(me) {
    const members = Object.entries(this.m).map(([id, x]) => ({ id, name: x.name, joined: x.joined, last: x.last, profile: x.profile || null, pings: !!x.push, ok: !!x.ok, respect: x.respect || 0, nick: this.nickOf(id), role: (this.c.roles || {})[id] || (id === this.c.owner ? 'Captain' : ''), jersey: (this.c.jerseys || {})[id] || (id === this.c.founder ? 1 : null) }));
    const bud = {}; (this.c.buddies || []).forEach(x => { if (x.a === me || x.b === me) { const o = x.a === me ? x.b : x.a; bud[o] = (bud[o] || 0) + 1; } });
    const mine = (this.c.buddies || []).filter(x => x.a === me || x.b === me).map(x => x.date);
    return {
      crew: { name: this.c.name, code: this.c.code, owner: this.c.owner, created: this.c.created, challenge: this.c.challenge || null, xp: this.c.xp || 0, level: crewLevel(this.c.xp), fcrew: this.fcrew(), banner: this.c.banner || 'forge', crest: this.c.crest || null, trophies: this.c.trophies || {}, rank: this.c.rank || 0, founders: this.c.created < Date.UTC(2027, 0, 1), shame: this.c.shame && this.c.shame.until > Date.now() ? this.c.shame : null, shameVotes: this.shameView(me), chatN: this.c.chatN || 0, chatLast: this.c.chatLast || 0, chatRecent: (this.c.chatRecent || []).slice(-40), muted: this.c.muted || {} },
      raid: this.raidView(), groups: this.groupView(), style: { motto: this.c.motto || '', c1: this.c.sc1 || '', c2: this.c.sc2 || '' }, pins: (this.c.pins || []).slice(0, 10), hof: (this.c.hof || []).slice(0, 40), nickVotes: Object.fromEntries(Object.entries(this.c.nickV || {}).map(([t, v]) => [t, v[me] || null])), respectGiven: Object.entries(this.c.respLog || {}).filter(([k]) => k.startsWith(isoD(Date.now()) + ':' + me + ':')).map(([k]) => k.split(':')[2]),
      former: Object.fromEntries(Object.entries(this.f).map(([k, v]) => [k, v.name])), trashN: this.t.filter(x => x.by === me || this.c.owner === me).length,
      members, posts: this.p.slice(0, 60), me, live: this.liveNow(), buddies: bud, buddyDates: mine,
      events: this.ev.filter(e => e.to === '*' || e.to === me).slice(0, 60),
      votes: this.voteView(me),
    };
  }
  // 0.16: a crew whose owner is the verified founder
  fcrew() { const o = this.m && this.m[this.c.owner]; return !!(o && o.ok && o.profile && o.profile.founder); }
  nickOf(id) { const V = (this.c.nickV || {})[id]; if (!V) return ''; const t = {}; Object.values(V).forEach(n => t[n] = (t[n] || 0) + 1); const best = Object.entries(t).sort((a, b2) => b2[1] - a[1])[0]; const need = Math.max(1, Math.ceil((Object.keys(this.m).length - 1) / 2)); return best && best[1] >= need ? best[0] : ''; }
  raidNow() {
    const d = isoD(Date.now()), wk = monday(d), i = ((wkIndex(wk) % BOSSES.length) + BOSSES.length) % BOSSES.length, n = Math.max(2, Object.keys(this.m).length);
    const R = this.c.raids = this.c.raids || {}; if (!R[wk]) { R[wk] = { boss: BOSSES[i][0], name: BOSSES[i][1], hp: BOSS_HP_PER * n, dmg: {}, beaten: 0 }; const ks = Object.keys(R).sort(); while (ks.length > 26) delete R[ks.shift()]; }
    if (!R[wk].beaten) R[wk].hp = BOSS_HP_PER * n;
    return [wk, R[wk]];
  }
  raidHit() {
    const [wk, r] = this.raidNow(); if (r.beaten) return;
    for (const [id, x] of Object.entries(this.m)) { const w = x.profile && x.profile.week; if (w) { const v = Math.round(toLb(+w.vol || 0, x.profile.unit)); if (v > (r.dmg[id] || 0)) r.dmg[id] = v; } }
    const tot = Object.values(r.dmg).reduce((a, v) => a + v, 0);
    if (tot >= r.hp) { r.beaten = Date.now(); this.c.raidWins = (this.c.raidWins || 0) + 1; this.c.xp = (this.c.xp || 0) + 300; this.event('raid', '', '*', { text: r.name }); this.p.unshift({ id: rid(), by: '', ts: Date.now(), type: 'raid', data: { name: r.name, boss: r.boss, hp: r.hp, dmg: r.dmg }, reacts: {}, comments: [] }); }
  }
  raidView() { const [wk, r] = this.raidNow(); const tot = Object.values(r.dmg).reduce((a, v) => a + v, 0); return { wk, boss: r.boss, name: r.name, hp: r.hp, dmg: Math.min(tot, r.hp), hits: r.dmg, beaten: r.beaten, wins: this.c.raidWins || 0, won: Object.entries(this.c.raids || {}).filter(([k, x]) => x.beaten).map(([k, x]) => ({ wk: k, name: x.name, by: Object.keys(x.dmg).filter(m => x.dmg[m] > 0) })) }; }
  groupView() { const G = this.c.groups || {}, now = Date.now(), out = {}; for (const [gid, g] of Object.entries(G)) if (!g.ended && now - g.ts < 4 * 3600 * 1000) out[gid] = { host: g.host, ts: g.ts, members: g.members, sync: !!g.sync }; return out; }
  shameView(me) { const wk = monday(isoD(Date.now())), V = (this.c.shameV || {})[wk] || {}, tally = {}; Object.values(V).forEach(t => tally[t] = (tally[t] || 0) + 1); return { wk, tally, mine: V[me] || null }; }
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
    if (this.c && path !== '/state' && path !== '/latest' && path !== '/chat/get') { try { await this.snapshot(); } catch (e) {} }
    if (path === '/create') {
      if (this.c) return json({ error: 'taken' }, 409);
      const id = clip(b.id, 40), key = clip(b.key, 80);
      if (!id || key.length < 16) return json({ error: 'bad member' }, 400);
      this.c = { name: clip(b.name, 30) || 'My crew', code: b.code, owner: id, created: Date.now(), challenge: null, xp: 0, banner: 'forge', votes: {}, buddies: [], trophies: {}, rank: 0, founder: clip(b.id, 40) };
      this.m = { [id]: { name: clip(b.member, 24) || 'Lifter', key, joined: Date.now(), last: Date.now(), profile: null, push: null } };
      this.p = []; this.ev = []; this.live = {};
      await this.save();
      return json(this.view(id));
    }
    if (!this.c) return json({ error: 'no crew' }, 404);
    const id = clip(b.id, 40), me = this.m[id];
    if (path === '/join') {
      if (me) { if (me.key !== b.key) return json({ error: 'auth' }, 403); }
      else if (this.f[id] && this.f[id].key === clip(b.key, 80)) {
        // coming back: same member, all their history is still here
        const o = this.f[id]; delete this.f[id];
        this.m[id] = { name: clip(b.member, 24) || o.name, key: o.key, joined: o.joined || Date.now(), last: Date.now(), profile: o.profile || null, push: null };
        this.event('join', id); this.broadcast({ t: 'refresh' });
      }
      else {
        if (Object.keys(this.m).length >= 30) return json({ error: 'full' }, 403);
        if (!id || clip(b.key, 80).length < 16) return json({ error: 'bad member' }, 400);
        this.m[id] = { name: clip(b.member, 24) || 'Lifter', key: clip(b.key, 80), joined: Date.now(), last: Date.now(), profile: null, push: null };
        if (this.c.archived) { this.c.archived = null; if (!this.m[this.c.owner]) this.c.owner = id; try { await this.state.storage.deleteAlarm(); } catch (e) {} }
        this.p.unshift({ id: rid(), by: id, ts: Date.now(), type: 'join', reacts: {}, comments: [] });
        this.event('join', id);
        this.broadcast({ t: 'refresh' });
      }
      if (this.c.archived && Object.keys(this.m).length) { this.c.archived = null; if (!this.m[this.c.owner]) this.c.owner = id; try { await this.state.storage.deleteAlarm(); } catch (e) {} }
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
              if (st.founder) p.founder = 1; else delete p.founder;
            }
          } catch (e) {}
        }
        if (p && !me.ok) delete p.founder;
        if (p) {
          if (!me.og && this.env.STATS) { try { const r = await this.env.STATS.get(this.env.STATS.idFromName('global')).fetch('https://do/og', { method: 'POST', body: JSON.stringify({ mid: id, founder: !!p.founder }) }); const j = await r.json(); if (j.og) me.og = j.og; } catch (e) {} }
          if (p.founder && me.og !== 1 && this.env.STATS) { try { const r = await this.env.STATS.get(this.env.STATS.idFromName('global')).fetch('https://do/og', { method: 'POST', body: JSON.stringify({ mid: id, founder: true }) }); const j = await r.json(); if (j.og) me.og = j.og; } catch (e) {} }
          if (me.og) p.og = me.og; else delete p.og;
          ['motto', 'gym', 'phase', 'ltype', 'song'].forEach(k => { if (p[k] !== undefined) p[k] = clip(p[k], k === 'motto' ? 60 : 30); });
        }
        me.profile = p;
        this.trophyCheck();
        this.raidHit();
        break;
      }
      case '/post': {
        const t = b.post && b.post.type === 'rank' ? 'rank' : 'workout';
        const p = { id: rid(), by: id, ts: Date.now(), type: t, cap: clip(b.post && b.post.cap, 280), data: b.post && b.post.data || null, reacts: {}, comments: [] };
        this.p.unshift(p);
        this.c.xp = (this.c.xp || 0) + 5;
        if (t === 'rank') this.event('rank', id, '*', { text: clip(p.data && p.data.rname, 30) });
        await this.notify(id, t === 'rank' ? `${me.name} ranked up` : `${me.name} posted a workout`);
        break;
      }
      case '/react': {
        const p = post(b.post); const e = clip(b.emoji, 8);
        if (p && REACTS.includes(e)) { const a = p.reacts[e] = p.reacts[e] || []; const i = a.indexOf(id); if (i < 0) { a.push(id); if (p.by !== id) this.event('react', id, p.by, { post: p.id, emoji: e }); } else a.splice(i, 1); }
        break;
      }
      case '/comment': {
        const p = post(b.post); const t = clip(b.text, 200).trim();
        if (p && t) { p.comments.push({ by: id, ts: Date.now(), text: t }); p.comments = p.comments.slice(-300); if (p.by !== id) this.event('comment', id, p.by, { post: p.id, text: t.slice(0, 60) }); }
        break;
      }
      case '/delete': { const p = post(b.post); if (p && (p.by === id || this.c.owner === id)) { this.p = this.p.filter(x => x !== p); this.t.unshift({ id: rid(), kind: 'post', by: p.by, delBy: id, ts: Date.now(), item: p }); } break; }
      case '/kick': { if (this.c.owner === id && b.target !== id) { const t = clip(b.target, 40); if (this.m[t]) { this.f[t] = { ...this.m[t], left: Date.now(), kicked: true }; delete this.m[t]; } this.broadcast({ t: 'kicked' }, t); } break; }
      case '/leave': {
        this.f[id] = { ...me, left: Date.now() }; delete this.m[id];
        if (this.c.owner === id) { const next = Object.keys(this.m)[0]; if (next) this.c.owner = next; }
        if (!Object.keys(this.m).length) {
          // last one out: keep everything for 90 days instead of wiping it
          this.c.archived = Date.now(); await this.save(); try { await this.state.storage.setAlarm(Date.now() + ARCHIVE_KEEP); } catch (e) {}
          return json({ ok: true, archived: true });
        }
        await this.save(); this.broadcast({ t: 'refresh' }); return json({ ok: true });
      }
      case '/trash': { changed = false; await this.save(); return json({ items: this.t.filter(x => x.by === id || this.c.owner === id).map(x => ({ id: x.id, kind: x.kind, by: x.by, ts: x.ts, left: Math.max(0, Math.ceil((x.ts + TRASH_KEEP - Date.now()) / DAY)), text: x.kind === 'post' ? (x.item.cap || (x.item.data && x.item.data.day) || x.item.type) : x.text })) }); }
      case '/restore': {
        const i = this.t.findIndex(x => x.id === b.item); const x = this.t[i];
        if (x && (x.by === id || this.c.owner === id)) {
          if (x.kind === 'post') { if (!this.p.some(q => q.id === x.item.id)) { this.p.push(x.item); this.p.sort((a, c2) => c2.ts - a.ts); } }
          if (x.kind === 'msg') { const f = await this.findMsg(x.mid); if (f) { f.m.text = x.text; f.m.card = x.card || null; delete f.m.del; f.pg._dirty = 1; this.broadcast({ t: 'chatupd', msg: f.m }); } }
          this.t.splice(i, 1);
        }
        break;
      }
      case '/snaps': { changed = false; if (this.c.owner !== id) return json({ error: 'owner only' }, 409); return json({ days: ((await this.state.storage.get('snapIdx')) || []).map(x => ({ day: x.day, ts: x.ts })).reverse() }); }
      case '/snaprestore': {
        // owner only, and it only ADDS back what is missing: nothing current is ever removed
        if (this.c.owner !== id) return json({ error: 'owner only' }, 409);
        const o = await this.readSnap(clip(b.day, 10)); if (!o) return json({ error: 'no backup for that day' }, 410);
        let added = 0;
        for (const [k, v] of Object.entries(o.m || {})) if (!this.m[k] && !(this.f[k] && this.f[k].kicked)) { this.m[k] = v; delete this.f[k]; added++; }
        const have = new Set(this.p.map(x => x.id)); for (const x of o.p || []) if (!have.has(x.id)) { this.p.push(x); added++; }
        this.p.sort((a, c2) => c2.ts - a.ts);
        for (const x of o.chat || []) { const f = await this.findMsg(x.id); if (f && f.m.del && !x.del) { Object.assign(f.m, x); delete f.m.del; f.pg._dirty = 1; added++; } }
        if (o.c) { this.c.xp = Math.max(this.c.xp || 0, o.c.xp || 0); this.c.trophies = { ...(o.c.trophies || {}), ...(this.c.trophies || {}) }; }
        this.event('restore', id, '*', { text: clip(b.day, 10) });
        await this.save(); this.broadcast({ t: 'refresh' }); return json({ ok: true, added, ...this.view(id) });
      }
      case '/respect': {
        const t = clip(b.target, 40), key = isoD(Date.now()) + ':' + id + ':' + t;
        if (this.m[t] && t !== id) { const L = this.c.respLog = this.c.respLog || {}; if (!L[key]) { L[key] = 1; this.m[t].respect = (this.m[t].respect || 0) + 1; this.event('respect', id, t); const ks = Object.keys(L); if (ks.length > 600) ks.sort().slice(0, ks.length - 600).forEach(k => delete L[k]); } }
        break;
      }
      case '/nick': {
        const t = clip(b.target, 40), n = clip(b.nick, 20).trim();
        if (this.m[t] && t !== id) { const V = this.c.nickV = this.c.nickV || {}; V[t] = V[t] || {}; if (n) V[t][id] = n; else delete V[t][id]; const before = this.nickOf(t); if (n && before === n) this.event('nick', '', t, { text: n }); }
        break;
      }
      case '/role': {
        const t = clip(b.target, 40), r = clip(b.role, 16).trim();
        if (this.c.owner === id && this.m[t]) { this.c.roles = this.c.roles || {}; if (r) this.c.roles[t] = r; else delete this.c.roles[t]; }
        break;
      }
      case '/jersey': {
        const n = Math.round(+b.num); const J = this.c.jerseys = this.c.jerseys || {};
        if (b.off) delete J[id];
        else if (n >= 0 && n <= 99 && !Object.entries(J).some(([k, v]) => v === n && k !== id) && !(n === 1 && this.c.founder && this.c.founder !== id)) J[id] = n;
        else return json({ error: 'taken' }, 409);
        break;
      }
      case '/crewstyle': {
        if (this.c.owner === id) { this.c.motto = clip(b.motto, 60); const hx = v => /^#[0-9a-f]{6}$/i.test(v || '') ? v : ''; this.c.sc1 = hx(b.c1); this.c.sc2 = hx(b.c2); }
        break;
      }
      case '/chat/pin': {
        const f = await this.findMsg(clip(b.mid, 30)), P = this.c.pins = this.c.pins || [], rl = (this.c.roles || {})[id] || '';
        if (f && !f.m.del && (this.c.owner === id || rl === 'Co-captain')) { const i = P.findIndex(x => x.id === f.m.id); if (i >= 0) P.splice(i, 1); else { P.unshift({ id: f.m.id, by: f.m.by, text: clip(f.m.text, 200), card: f.m.card ? { day: f.m.card.day } : null, ts: f.m.ts, pinBy: id }); P.splice(10); } }
        await this.save(); this.broadcast({ t: 'refresh' }); return json({ ok: true, pins: P });
      }
      case '/hof': {
        const H = this.c.hof = this.c.hof || [], rl = (this.c.roles || {})[id] || '';
        if (this.c.owner !== id && rl !== 'Co-captain') return json({ error: 'owner only' }, 409);
        if (b.remove) { this.c.hof = H.filter(x => x.id !== b.remove); break; }
        const kind = b.kind === 'member' ? 'member' : 'post';
        if (kind === 'member' && this.m[b.ref]) H.unshift({ id: rid(), kind, ref: b.ref, name: this.m[b.ref].name, text: clip(b.text, 80), by: id, ts: Date.now() });
        if (kind === 'post') { const q = post(b.ref); if (q) H.unshift({ id: rid(), kind, ref: q.id, who: q.by, text: clip(b.text || q.cap || (q.data && q.data.day) || 'Legendary session', 80), data: q.data ? { day: q.data.day, vol: q.data.vol, sets: q.data.sets, prs: q.data.prs, unit: q.data.unit, top: (q.data.top || []).slice(0, 3) } : null, by: id, ts: Date.now() }); }
        this.c.hof = H.slice(0, 40); this.event('hof', id, '*', { text: clip(b.text || '', 40) });
        break;
      }
      case '/group/start': {
        const G = this.c.groups = this.c.groups || {}; for (const [k, g] of Object.entries(G)) if (g.members.includes(id) && !g.ended) g.members = g.members.filter(x => x !== id);
        const gid = rid().slice(0, 8); G[gid] = { host: id, ts: Date.now(), members: [id], sync: !!b.sync, ended: 0 };
        const ks = Object.keys(G); if (ks.length > 30) ks.sort((a, c2) => G[a].ts - G[c2].ts).slice(0, ks.length - 30).forEach(k => delete G[k]);
        this.event('group', id, '*', { text: me.name, gid }); await this.save(); this.broadcast({ t: 'group' });
        const pushTo = Object.entries(this.m).filter(([k, x]) => k !== id && x.push);
        if (pushTo.length) { this.c.lastNote = { title: me.name + ' started a group lift', ts: Date.now(), from: id, body: 'Tap to lift together' }; await this.save(); await Promise.all(pushTo.map(([k, x]) => sendPush(x.push, this.env).catch(() => {}))); }
        return json({ ok: true, gid, ...this.view(id) });
      }
      case '/group/join': {
        const G = this.c.groups || {}, g = G[clip(b.gid, 12)];
        if (!g || g.ended) return json({ error: 'group ended' }, 410);
        for (const x of Object.values(G)) if (x !== g) x.members = x.members.filter(m => m !== id);
        if (!g.members.includes(id)) g.members.push(id); this.event('groupjoin', id, g.host); await this.save(); this.broadcast({ t: 'group' }); return json({ ok: true, ...this.view(id) });
      }
      case '/group/leave': { const g = (this.c.groups || {})[clip(b.gid, 12)]; if (g) { g.members = g.members.filter(m => m !== id); if (!g.members.length) g.ended = Date.now(); else if (g.host === id) g.host = g.members[0]; } this.broadcast({ t: 'group' }); break; }
      case '/group/end': {
        const g = (this.c.groups || {})[clip(b.gid, 12)]; if (!g || g.ended) return json({ error: 'group ended' }, 410);
        if (g.host !== id && !g.members.includes(id)) return json({ error: 'not in group' }, 409);
        const L = this.liveNow(), mins = Math.max(1, Math.round((Date.now() - g.ts) / 60000)), rows = g.members.map(m => ({ id: m, sets: (L[m] || {}).sets || 0, vol: Math.round(toLb((L[m] || {}).vol || 0, (L[m] || {}).unit)), prs: (L[m] || {}).prs || 0 }));
        const extra = b.rows && typeof b.rows === 'object' ? b.rows : {};
        rows.forEach(r => { const x = extra[r.id]; if (x && r.id === id) { r.sets = Math.max(r.sets, +x.sets || 0); r.vol = Math.max(r.vol, Math.round(+x.vol || 0)); r.prs = Math.max(r.prs, +x.prs || 0); } });
        g.ended = Date.now();
        const pst = { id: rid(), by: id, ts: Date.now(), type: 'group', data: { min: mins, rows, unit: 'lb' }, reacts: {}, comments: [] };
        if (rows.length >= 2) { this.p.unshift(pst); this.c.xp = (this.c.xp || 0) + 25 * rows.length; }
        this.event('groupend', id, '*', { text: String(rows.length) }); await this.save(); this.broadcast({ t: 'group' }); this.broadcast({ t: 'refresh' });
        return json({ ok: true, post: pst, ...this.view(id) });
      }
      case '/rename': { const n = clip(b.name, 30).trim(); if (this.c.owner === id && n) { const old = this.c.name; this.c.name = n; this.event('rename', id, '*', { text: n, old }); } break; }
      case '/crest': {
        if (this.c.owner === id) { const c = b.crest || {}; this.c.crest = { shape: CREST.shape.includes(c.shape) ? c.shape : 'shield', icon: CREST.icon.includes(c.icon) ? c.icon : 'barbell', c1: /^#[0-9a-f]{6}$/i.test(c.c1) ? c.c1 : '#ef2b36', c2: /^#[0-9a-f]{6}$/i.test(c.c2) ? c.c2 : '#14161c', txt: clip(c.txt, 3).toUpperCase().replace(/[^A-Z0-9]/g, '') }; }
        break;
      }
      case '/shame': {
        const t = clip(b.target, 40), wk = monday(isoD(Date.now()));
        if (this.m[t] && t !== id) {
          const V = this.c.shameV = this.c.shameV || {}; V[wk] = V[wk] || {}; V[wk][id] = t;
          const ks = Object.keys(V).sort(); while (ks.length > 4) delete V[ks.shift()];
          const n = Object.values(V[wk]).filter(x => x === t).length, need = Math.max(1, Math.ceil((Object.keys(this.m).length - 1) / 2));
          if (n >= need && !(this.c.shame && this.c.shame.wk === wk)) { this.c.shame = { target: t, wk, until: Date.now() + 7 * DAY }; this.event('shame', '', '*', { text: this.m[t].name, target: t }); }
        }
        break;
      }
      case '/chat/get': {
        changed = false; const N = this.c.chatN || 0; let before = b.before === undefined ? N : Math.max(0, Math.min(N, +b.before || 0));
        let msgs = (await this.page(before)).slice(); if (b.before === undefined && before > 0 && msgs.length < 40) { msgs = (await this.page(before - 1)).concat(msgs); before--; }
        await this.save(); return json({ msgs: msgs.map(x => this.pubMsg(x)), page: before, more: before > 0 });
      }
      case '/chat/send': {
        const mu = (this.c.muted || {})[id]; if (mu && mu > Date.now()) return json({ error: 'muted', until: mu }, 423);
        const text = clip(b.text, 500).trim(), card = b.card && typeof b.card === 'object' ? JSON.parse(clip(JSON.stringify(b.card), 6000)) : null;
        if (!text && !card) return json({ error: 'empty' }, 400);
        this.rate = this.rate || {}; const r = this.rate[id] = (this.rate[id] || []).filter(t => Date.now() - t < 60000); if (r.length >= 20) return json({ error: 'slow down' }, 429); r.push(Date.now());
        const N = this.c.chatN || 0, pg = await this.page(N);
        const rp = b.reply ? await this.findMsg(clip(b.reply, 30)) : null;
        const msg = { id: N + '-' + rid(), by: id, ts: Date.now(), text, card, reply: rp && !rp.m.del ? { id: rp.m.id, by: rp.m.by, text: clip(rp.m.text, 80) } : null, reacts: {} };
        pg.push(msg); pg._dirty = 1; if (pg.length >= PAGE) this.c.chatN = N + 1;
        this.c.chatLast = msg.ts; this.c.chatCount = (this.c.chatCount || 0) + 1; this.c.chatRecent = [...(this.c.chatRecent || []), { ts: msg.ts, by: id }].slice(-40);
        const low = text.toLowerCase(), tagged = Object.entries(this.m).filter(([k, x]) => k !== id && x.name && low.includes('@' + x.name.toLowerCase())).map(([k]) => k);
        for (const k of tagged) this.event('mention', id, k, { text: clip(text, 60) });
        if (rp && rp.m.by !== id && !tagged.includes(rp.m.by)) this.event('reply', id, rp.m.by, { text: clip(text, 60) });
        await this.save(); this.broadcast({ t: 'chat', msg });
        const pushTo = tagged.filter(k => this.m[k] && this.m[k].push);
        if (pushTo.length) { this.c.lastNote = { title: `${me.name} mentioned you`, ts: Date.now(), from: id, body: clip(text, 80) }; await Promise.all(pushTo.map(k => sendPush(this.m[k].push, this.env).catch(() => {}))); await this.save(); }
        return json({ ok: true, msg });
      }
      case '/chat/react': {
        const f = await this.findMsg(clip(b.mid, 30)), e = clip(b.emoji, 8);
        if (f && !f.m.del && REACTS.includes(e)) { const a = f.m.reacts[e] = f.m.reacts[e] || []; const i = a.indexOf(id); if (i < 0) a.push(id); else a.splice(i, 1); f.pg._dirty = 1; await this.save(); this.broadcast({ t: 'chatupd', msg: f.m }); }
        return json({ ok: true });
      }
      case '/chat/delete': {
        const f = await this.findMsg(clip(b.mid, 30));
        if (f && !f.m.del && (f.m.by === id || this.c.owner === id)) { this.t.unshift({ id: rid(), kind: 'msg', mid: f.m.id, by: f.m.by, delBy: id, ts: Date.now(), text: f.m.text, card: f.m.card || null }); f.m.del = 1; f.m.text = ''; f.m.card = null; f.pg._dirty = 1; await this.save(); this.broadcast({ t: 'chatupd', msg: this.pubMsg(f.m) }); }
        return json({ ok: true });
      }
      case '/chat/mute': {
        if (this.c.owner !== id) return json({ error: 'owner only' }, 409);
        const t = clip(b.target, 40); this.c.muted = this.c.muted || {}; if (b.off) delete this.c.muted[t]; else if (this.m[t] && t !== id) this.c.muted[t] = Date.now() + Math.max(1, Math.min(168, +b.hours || 24)) * 3600000;
        break;
      }
      case '/challenge': {
        const ty = clip(b.type, 10);
        this.c.challenge = ['sets', 'days', 'vol', 'prs'].includes(ty) ? { type: ty, target: Math.max(1, Math.min(1e7, +b.target || 0)), wk: clip(b.wk, 10), by: id, title: clip(b.title, 60) } : null;
        if (this.c.challenge) this.event('challenge', id, '*', { text: this.c.challenge.title });
        break;
      }
      case '/banner': {
        const k = clip(b.banner, 12), sc = SCENES[k], lv = crewLevel(this.c.xp);
        const ok = sc ? ((sc.lv && lv >= sc.lv) || (sc.rank && (this.c.rank || 0) >= sc.rank) || (sc.trophy && (this.c.trophies || {})[sc.trophy]) || (sc.founder && this.fcrew())) : (BANNERS[k] && lv >= BANNERS[k]);
        if (this.c.owner === id && ok) this.c.banner = k; break;
      }
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
        const ln = this.c.lastNote; if (ln && ln.body && Date.now() - ln.ts < 120000) return json({ title: ln.title, body: ln.body });
        const p = this.p.find(x => x.by !== id && x.type !== 'join' && x.by);
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
    if (b.on) { this.live[id] = { on: true, day: clip(b.day, 30), start: prev && prev.on ? prev.start : (+b.start || now), ts: now, g: clip(b.g, 12) || (prev && prev.g) || '', sets: Math.max(0, Math.min(400, +b.sets || 0)), vol: Math.max(0, +b.vol || 0), ex: clip(b.ex, 40), rest: +b.rest || 0, prs: Math.max(0, Math.min(50, +b.prs || 0)), unit: b.unit === 'kg' ? 'kg' : 'lb' }; return; }
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
  async alarm() {
    await this.load(); if (!this.c || !this.c.archived) return;
    if (Date.now() - this.c.archived >= ARCHIVE_KEEP - 60000 && !Object.keys(this.m).length) { await this.state.storage.deleteAll(); this.c = null; }
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


/* ---------- 0.15: app usage stats (owner dashboard) and OG numbers ---------- */
export class Stats {
  constructor(state, env) { this.state = state; this.env = env; }
  async fetch(req) {
    const path = new URL(req.url).pathname, s = this.state.storage, now = Date.now();
    let b; try { b = await req.json(); } catch (e) { return json({ error: 'bad json' }, 400); }
    if (path === '/ping') {
      const dev = String(b.dev || ''); if (!/^[\w-]{8,40}$/.test(dev)) return json({ error: 'bad device' }, 400);
      const rec = (await s.get('dev:' + dev)) || { first: now, pings: 0 };
      if (now - (rec.last || 0) < 20000) return json({ ok: true });
      Object.assign(rec, { name: clip(b.name, 24), plat: clip(b.plat, 12), sa: !!b.sa, ver: clip(b.ver, 20), crew: clip(b.crew, 30), sync: !!b.sync, wk: Math.max(0, Math.min(99, +b.wk || 0)), tot: Math.max(0, +b.tot || 0), sets: Math.max(0, +b.sets || 0), vol: Math.max(0, +b.vol || 0), last: now, pings: (rec.pings || 0) + 1 });
      await s.put('dev:' + dev, rec);
      const d = isoD(now), day = (await s.get('day:' + d)) || {}; if (!day[dev]) { day[dev] = 1; await s.put('day:' + d, day); }
      const idx = (await s.get('days')) || []; if (!idx.includes(d)) { idx.push(d); while (idx.length > 120) await s.delete('day:' + idx.shift()); await s.put('days', idx); }
      return json({ ok: true });
    }
    if (path === '/og') {
      const og = (await s.get('og')) || { n: 1, m: {} }, mid = clip(b.mid, 40);
      if (!mid) return json({ og: null });
      if (b.founder) { if (og.m[mid] !== 1) { for (const k of Object.keys(og.m)) if (og.m[k] === 1 && k !== mid) delete og.m[k]; og.m[mid] = 1; await s.put('og', og); } return json({ og: 1 }); }
      if (!og.m[mid] && now < OG_CUTOFF) { og.n = Math.max(og.n || 1, 1) + 1; og.m[mid] = og.n; await s.put('og', og); }
      return json({ og: og.m[mid] || null });
    }
    if (path === '/dash') {
      const devs = []; for (const [k, v] of await s.list({ prefix: 'dev:' })) devs.push({ id: k.slice(4), ...v });
      const idx = (await s.get('days')) || [], days = [];
      for (const d of idx.slice(-30)) { const x = (await s.get('day:' + d)) || {}; days.push({ d, n: Object.keys(x).length, nw: devs.filter(v => isoD(v.first) === d).length }); }
      const ago = t => now - (t || 0), within = ms => devs.filter(v => ago(v.last) < ms).length;
      const ver = {}, plat = {}; devs.forEach(v => { ver[v.ver || '?'] = (ver[v.ver || '?'] || 0) + 1; plat[v.plat || '?'] = (plat[v.plat || '?'] || 0) + 1; });
      return json({ total: devs.length, dau: within(DAY), wau: within(7 * DAY), mau: within(30 * DAY), home: devs.filter(v => v.sa).length, synced: devs.filter(v => v.sync).length, crews: new Set(devs.map(v => v.crew).filter(Boolean)).size, wkWorkouts: devs.filter(v => ago(v.last) < 7 * DAY).reduce((a, v) => a + (v.wk || 0), 0), totVol: devs.reduce((a, v) => a + (v.vol || 0), 0), ver, plat, days, devices: devs.sort((a, c) => (c.last || 0) - (a.last || 0)).slice(0, 300) });
    }
    return json({ error: 'not found' }, 404);
  }
}
