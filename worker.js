// Overload rest timer push server. © 2026 Jake Scarpa. All rights reserved.
// Needs: a Durable Object binding named TIMER (class RestTimer),
// a Durable Object binding named CREW (class Crew), and a secret named VAPID_PRIVATE.

const ORIGIN = 'https://jscarp9.github.io';
const SUBJECT = 'https://jscarp9.github.io/Overload/';

const cors = {
  'Access-Control-Allow-Origin': ORIGIN,
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { ...cors, 'Content-Type': 'application/json' } });

const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
const enc = new TextEncoder();

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
  const r = await fetch(endpoint, {
    method: 'POST',
    headers: { Authorization: await vapidAuth(endpoint, env), TTL: '120', Urgency: 'high', 'Content-Length': '0' },
  });
  return r.status;
}

function okEndpoint(u) {
  try {
    const h = new URL(u).hostname;
    return /(^|\.)(push\.apple\.com|googleapis\.com|push\.services\.mozilla\.com|notify\.windows\.com)$/.test(h);
  } catch (e) { return false; }
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors });
    const url = new URL(req.url);
    if (req.method === 'GET' && url.pathname === '/') return json({ ok: true, app: 'Overload push' });
    if (req.method !== 'POST') return json({ error: 'not found' }, 404);
    let b;
    try { b = await req.json(); } catch (e) { return json({ error: 'bad json' }, 400); }
    if (url.pathname.startsWith('/crew/')) {
      let code = String(b && b.code || '').toUpperCase().trim();
      if (url.pathname === '/crew/create') {
        for (let i = 0; i < 8; i++) {
          const c = WORDS[Math.floor(Math.random() * WORDS.length)] + '-' + (1000 + Math.floor(Math.random() * 9000));
          const st = env.CREW.get(env.CREW.idFromName(c));
          const r = await st.fetch('https://do/create', { method: 'POST', body: JSON.stringify({ ...b, code: c }) });
          if (r.status !== 409) return withCors(r);
        }
        return json({ error: 'try again' }, 500);
      }
      if (!/^[A-Z]{3,6}-\d{4}$/.test(code)) return json({ error: 'bad code' }, 400);
      const st = env.CREW.get(env.CREW.idFromName(code));
      return withCors(await st.fetch('https://do' + url.pathname.slice(5), { method: 'POST', body: JSON.stringify({ ...b, code }) }));
    }
    if (!b || !okEndpoint(b.endpoint)) return json({ error: 'bad endpoint' }, 400);
    const id = env.TIMER.idFromName(b.endpoint);
    const stub = env.TIMER.get(id);
    if (url.pathname === '/schedule') {
      const delay = Math.max(1000, Math.min(15 * 60 * 1000, +b.delay || 0));
      return stub.fetch('https://do/schedule', { method: 'POST', body: JSON.stringify({ endpoint: b.endpoint, at: Date.now() + delay }) });
    }
    if (url.pathname === '/cancel') return stub.fetch('https://do/cancel', { method: 'POST' });
    if (url.pathname === '/test') {
      const s = await sendPush(b.endpoint, env);
      return json({ sent: s });
    }
    return json({ error: 'not found' }, 404);
  },
};

const WORDS = ['IRON', 'PLATE', 'BEAST', 'TITAN', 'FORGE', 'APEX', 'GRIND', 'ALPHA', 'BULL', 'RAGE', 'LIFT', 'PUMP', 'SQUAD', 'STEEL'];
async function withCors(r) { return new Response(r.body, { status: r.status, headers: { ...cors, 'Content-Type': 'application/json' } }); }
const clip = (v, n) => String(v == null ? '' : v).slice(0, n);
const rid = () => crypto.randomUUID().replace(/-/g, '').slice(0, 12);

export class Crew {
  constructor(state, env) { this.state = state; this.env = env; }
  async load() {
    if (this.c) return;
    const s = this.state.storage;
    this.c = await s.get('crew');
    this.m = (await s.get('members')) || {};
    this.p = (await s.get('posts')) || [];
  }
  async save() {
    const s = this.state.storage;
    await s.put('crew', this.c); await s.put('members', this.m); await s.put('posts', this.p);
  }
  view(me) {
    const members = Object.entries(this.m).map(([id, x]) => ({ id, name: x.name, joined: x.joined, last: x.last, profile: x.profile || null, pings: !!x.push }));
    return { crew: { name: this.c.name, code: this.c.code, owner: this.c.owner, created: this.c.created, challenge: this.c.challenge || null }, members, posts: this.p.slice(0, 60), me };
  }
  async notify(fromId, title) {
    const jobs = [];
    for (const [id, x] of Object.entries(this.m)) if (id !== fromId && x.push) jobs.push(sendPush(x.push, this.env).then(s => { if (s === 404 || s === 410) x.push = null; }).catch(() => {}));
    await Promise.all(jobs);
    this.c.lastNote = { title, ts: Date.now(), from: fromId };
  }
  async fetch(req) {
    const path = new URL(req.url).pathname;
    let b; try { b = await req.json(); } catch (e) { return json({ error: 'bad json' }, 400); }
    if (JSON.stringify(b).length > 40000) return json({ error: 'too big' }, 413);
    await this.load();
    if (path === '/create') {
      if (this.c) return json({ error: 'taken' }, 409);
      const id = clip(b.id, 40), key = clip(b.key, 80);
      if (!id || key.length < 16) return json({ error: 'bad member' }, 400);
      this.c = { name: clip(b.name, 30) || 'My crew', code: b.code, owner: id, created: Date.now(), challenge: null };
      this.m = { [id]: { name: clip(b.member, 24) || 'Lifter', key, joined: Date.now(), last: Date.now(), profile: null, push: null } };
      this.p = [];
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
      }
      await this.save();
      return json(this.view(id));
    }
    if (!me || me.key !== b.key) return json({ error: 'auth' }, 403);
    me.last = Date.now();
    const post = id2 => this.p.find(x => x.id === id2);
    switch (path) {
      case '/state': break;
      case '/profile':
        me.profile = b.profile && typeof b.profile === 'object' ? b.profile : null;
        if (b.member) me.name = clip(b.member, 24);
        break;
      case '/post': {
        const t = b.post && b.post.type === 'rank' ? 'rank' : 'workout';
        const p = { id: rid(), by: id, ts: Date.now(), type: t, cap: clip(b.post && b.post.cap, 280), data: b.post && b.post.data || null, reacts: {}, comments: [] };
        this.p.unshift(p); this.p = this.p.slice(0, 150);
        await this.notify(id, t === 'rank' ? `${me.name} ranked up` : `${me.name} posted a workout`);
        break;
      }
      case '/react': {
        const p = post(b.post); const e = clip(b.emoji, 4);
        if (p && ['fire', 'muscle', 'trophy'].includes(e)) { const a = p.reacts[e] = p.reacts[e] || []; const i = a.indexOf(id); i < 0 ? a.push(id) : a.splice(i, 1); }
        break;
      }
      case '/comment': {
        const p = post(b.post); const t = clip(b.text, 200).trim();
        if (p && t) { p.comments.push({ by: id, ts: Date.now(), text: t }); p.comments = p.comments.slice(-50); }
        break;
      }
      case '/delete': { const p = post(b.post); if (p && (p.by === id || this.c.owner === id)) this.p = this.p.filter(x => x !== p); break; }
      case '/kick': { if (this.c.owner === id && b.target !== id) delete this.m[clip(b.target, 40)]; break; }
      case '/leave': {
        delete this.m[id];
        if (this.c.owner === id) { const next = Object.keys(this.m)[0]; if (next) this.c.owner = next; }
        if (!Object.keys(this.m).length) { await this.state.storage.deleteAll(); this.c = null; return json({ ok: true }); }
        await this.save(); return json({ ok: true });
      }
      case '/challenge': {
        const ty = clip(b.type, 10);
        this.c.challenge = ['sets', 'days', 'vol', 'prs'].includes(ty) ? { type: ty, target: Math.max(1, Math.min(1e7, +b.target || 0)), wk: clip(b.wk, 10), by: id, title: clip(b.title, 60) } : null;
        break;
      }
      case '/pings': me.push = b.endpoint && okEndpoint(b.endpoint) ? b.endpoint : null; break;
      case '/latest': {
        const p = this.p.find(x => x.by !== id && x.type !== 'join');
        const who = p && this.m[p.by] ? this.m[p.by].name : 'Your crew';
        return json(p ? { title: p.type === 'rank' ? `${who} ranked up 🏅` : `${who} just finished a workout 💪`, body: p.type === 'rank' ? 'Tap to see their new rank' : (p.cap || (p.data && p.data.day ? p.data.day + ' is done' : 'Tap to see it')) } : { title: 'Overload', body: 'New activity in your crew' });
      }
      default: return json({ error: 'not found' }, 404);
    }
    await this.save();
    return json(this.view(id));
  }
}

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
    if (path === '/cancel') {
      await this.state.storage.deleteAlarm();
      return json({ ok: true });
    }
    return json({ error: 'not found' }, 404);
  }
  async alarm() {
    const endpoint = await this.state.storage.get('endpoint');
    if (!endpoint) return;
    const s = await sendPush(endpoint, this.env);
    if (s === 404 || s === 410) await this.state.storage.deleteAll();
  }
}
