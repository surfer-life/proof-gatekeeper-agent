// Proof Gatekeeper agent as a Cloudflare Worker (free, always-on, no card).
// Web standard APIs only (fetch handler + Web Crypto). Shares decide.mjs (pure JS).
// Deploy: wrangler deploy. Secret: wrangler secret put AGENT_GAMES_HMAC_SECRET
import { decide } from './decide.mjs';

async function hmacHex(secret, data) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, data);
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function timingSafeEqHex(a, b) {
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export async function handleRaw(rawBytes, headers, secret, env) {
  const got = (headers.get('x-agent-games-signature') || '').replace(/^sha256=/i, '').trim().toLowerCase();
  const want = await hmacHex(secret, rawBytes);
  if (!got || !timingSafeEqHex(got, want)) return sign(secret, { error: 'bad signature' }, 401);
  let msg;
  try { msg = JSON.parse(new TextDecoder().decode(rawBytes)); }
  catch { return sign(secret, { error: 'bad json' }, 400); }
  if (msg.type === 'agent-games.preflight.v1') return sign(secret, { ok: true, protocolVersion: 'v1' }, 200);
  if (msg.type === 'agent-games.proof-gatekeeper.v1') {
    const res = decide(msg);
    // Durable replay check (KV), layered on decide()'s in-memory cache (see worker-bundled.mjs).
    if (env && env.SEEN) {
      const ref = (msg.input && typeof msg.input.proof_tx === 'string') ? msg.input.proof_tx.trim().toLowerCase() : '';
      // Record every proof reference seen and reject any repeat (a reference is unique, so a repeat
      // is always a replay — even if the first appearance was in a task we rejected for another reason).
      if (ref) {
        try {
          if (await env.SEEN.get(ref)) { res.decision = 'REJECT'; res.reason_code = 'PROOF_REUSED'; }
          else await env.SEEN.put(ref, '1', { expirationTtl: 2592000 });
        } catch { /* KV hiccup: keep decide()'s decision */ }
      }
    }
    // Best-effort Groth16 proof via the prover sidecar (Workers can't run snarkjs). If PROVER_URL
    // is unset or the prover is down, return the correct decision without a proof.
    if (env && env.PROVER_URL) {
      try {
        const ctl = new AbortController();
        const to = setTimeout(() => ctl.abort(), 25000);
        const pr = await fetch(env.PROVER_URL, {
          method: 'POST', signal: ctl.signal,
          headers: { 'content-type': 'application/json', 'x-prover-key': env.PROVER_KEY || '' },
          body: JSON.stringify({ input: msg.input, task_id: msg.task_id, approve: res.decision === 'APPROVE', reuse: res.reason_code === 'PROOF_REUSED' }),
        });
        clearTimeout(to);
        if (pr.ok) {
          const pj = await pr.json();
          if (Array.isArray(pj.public_signals)) res.public_signals = pj.public_signals;
          if (pj.proof) res.proof = pj.proof;
        }
      } catch { /* prover unavailable: decision stands, no proof attached */ }
    }
    return sign(secret, res, 200);
  }
  return sign(secret, { error: 'unknown type' }, 400);
}

async function sign(secret, obj, status) {
  const body = JSON.stringify(obj);
  const sig = await hmacHex(secret, new TextEncoder().encode(body));
  return new Response(body, { status, headers: { 'content-type': 'application/json', 'x-agent-games-signature': sig } });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = env.AGENT_PATH || '/agent';
    if (request.method !== 'POST' || url.pathname !== path) return new Response('not found', { status: 404 });
    const secret = env.AGENT_GAMES_HMAC_SECRET;
    if (!secret) return new Response('misconfigured', { status: 500 });
    const raw = new Uint8Array(await request.arrayBuffer());
    try { return await handleRaw(raw, request.headers, secret, env); }
    catch { return sign(secret, { decision: 'REJECT', reason_code: 'INTERNAL_ERROR' }, 200); } // fail closed
  }
};
