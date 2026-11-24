// Overload rest timer push server. © 2026 Jake Scarpa. All rights reserved.
// Needs: a Durable Object binding named TIMER (class RestTimer),
// and a secret named VAPID_PRIVATE (the private key text Claude gave you).

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
