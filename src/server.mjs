// Proof Gatekeeper agent — HTTPS endpoint. Node built-ins only (http, crypto).
// Flow: verify HMAC over RAW body BEFORE parsing -> route by "type" -> decide -> sign response.
// Fail closed. Secrets from env only. See SPEC.md.
import http from 'node:http';
import crypto from 'node:crypto';
import { decide } from './decide.mjs';

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const PORT = Number(process.env.PORT || 8787);
const AGENT_PATH = process.env.AGENT_PATH || '/agent';
const HARD_DEADLINE_MS = 60_000;

const hmacHex = (raw, secret = SECRET) =>
  crypto.createHmac('sha256', secret).update(raw).digest('hex');

function sigMatches(raw, header, secret = SECRET) {
  if (!secret || !header) return false;
  const got = String(header).replace(/^sha256=/i, '').trim().toLowerCase();
  const want = hmacHex(raw, secret);
  if (got.length !== want.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(got, 'hex'), Buffer.from(want, 'hex')); }
  catch { return false; }
}

// Pure handler: raw Buffer + headers -> { status, body(string), sig }. Testable without a socket.
export function handle(raw, headers = {}, secret = SECRET) {
  const sig = headers['x-agent-games-signature'] || headers['X-Agent-Games-Signature'];
  if (!sigMatches(raw, sig, secret)) return signed({ error: 'bad signature' }, 401, secret);
  let msg;
  try { msg = JSON.parse(raw.toString('utf8')); }
  catch { return signed({ error: 'bad json' }, 400, secret); }

  if (msg.type === 'agent-games.preflight.v1')
    return signed({ ok: true, protocolVersion: 'v1' }, 200, secret);

  if (msg.type === 'agent-games.proof-gatekeeper.v1') {
    const out = decide(msg); // deterministic, fail-closed
    return signed(out, 200, secret);
  }
  return signed({ error: 'unknown type' }, 400, secret);
}

function signed(obj, status, secret = SECRET) {
  const body = JSON.stringify(obj);
  return { status, body, sig: hmacHex(body, secret) };
}

function server() {
  return http.createServer((req, res) => {
    if (req.method !== 'POST' || req.url !== AGENT_PATH) {
      res.writeHead(404); return res.end('not found');
    }
    const chunks = [];
    let aborted = false;
    const timer = setTimeout(() => { aborted = true; try { res.writeHead(504); res.end(); } catch {} }, HARD_DEADLINE_MS);
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      if (aborted) return; clearTimeout(timer);
      const raw = Buffer.concat(chunks);
      const r = handle(raw, req.headers);
      res.writeHead(r.status, { 'content-type': 'application/json', 'x-agent-games-signature': r.sig });
      res.end(r.body);
    });
    req.on('error', () => { clearTimeout(timer); try { res.writeHead(400); res.end(); } catch {} });
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  if (!SECRET) console.warn('WARN: AGENT_GAMES_HMAC_SECRET is empty — set it before preflight.');
  server().listen(PORT, () => console.log(`gatekeeper agent on :${PORT}${AGENT_PATH}`));
}
