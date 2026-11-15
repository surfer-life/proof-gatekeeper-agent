// Proof Gatekeeper agent — single-file Cloudflare Worker (paste into dashboard editor).
// Set secret: Worker > Settings > Variables > AGENT_GAMES_HMAC_SECRET (encrypt). Optional AGENT_PATH.

// Proof Gatekeeper decision logic — deterministic checklist (no LLM in the final call).
// Spec: agentgames.zkverify.io/events/proof-gatekeeper (Trap Encyclopedia + expected response).
// APPROVE only if EVERY documented check passes; otherwise REJECT with the exact trap reason_code.
// Reason codes from the event Trap Encyclopedia: VALID_CONDITION (approve), VK_SUBSTITUTION,
// THRESHOLD_MISMATCH, RECIPIENT_MISMATCH, AMOUNT_OVERFLOW, EXPIRED_CONDITION, PROOF_REUSED.
// Only these seven cases exist in competition; we do NOT invent extra rejections (which would
// wrongly reject valid conditions). deadline_at is the 60s *response* window, not a condition
// field, so it is never a rejection reason.

const bi = (v) => { try { return BigInt(v); } catch { return null; } };
const norm = (a) => (typeof a === 'string' ? a.trim().toLowerCase() : a);

// seen proof references, to catch replay/reuse across tasks (in-memory; persist later)
const seenProofTx = new Set();

function decide(task, { markSeen = true } = {}) {
  // Fail closed on anything malformed.
  try {
    const inp = task?.input;
    if (!inp || typeof inp !== 'object') return rej('MALFORMED_INPUT', task);

    // 1. Verification key: the proof's VK must match the registered condition VK.
    if (norm(inp.proof_vk) !== norm(inp.registered_vk)) return rej('VK_SUBSTITUTION', task);

    // 2. Threshold: the public balance disclosed in the proof must meet the minimum.
    const bal = bi(inp.public_balance), min = bi(inp.minimum);
    if (bal === null || min === null) return rej('MALFORMED_INPUT', task);
    if (bal < min) return rej('THRESHOLD_MISMATCH', task);

    // 3. Recipient: the recipient committed in the proof must match the payment condition.
    if (norm(inp.recipient) !== norm(inp.condition_recipient)) return rej('RECIPIENT_MISMATCH', task);

    // 4. Amount cap: requested amount must not exceed the single-transfer cap.
    const amt = bi(inp.amount), maxT = bi(inp.max_transfer);
    if (amt === null || maxT === null) return rej('MALFORMED_INPUT', task);
    if (amt > maxT) return rej('AMOUNT_OVERFLOW', task);

    // 5. Expiry: the condition's block-height expiry must not have passed.
    const cur = bi(inp.current_block), exp = bi(inp.expiry_block);
    if (cur !== null && exp !== null && cur >= exp) return rej('EXPIRED_CONDITION', task);

    // 6. Reuse: the proof reference must not have been accepted in a previous task.
    const ref = norm(inp.proof_tx);
    if (ref && seenProofTx.has(ref)) return rej('PROOF_REUSED', task);

    // All documented checks pass → approve.
    if (markSeen && ref) seenProofTx.add(ref);
    return { decision: 'APPROVE', reason_code: 'VALID_CONDITION', proof_tx: inp.proof_tx };
  } catch {
    return rej('INTERNAL_ERROR', task); // fail closed
  }
}

function rej(code, task) {
  return { decision: 'REJECT', reason_code: code, proof_tx: task?.input?.proof_tx };
}

function _resetSeen() { seenProofTx.clear(); } // for tests

// Proof Gatekeeper agent as a Cloudflare Worker (free, always-on, no card).
// Web standard APIs only (fetch handler + Web Crypto). Shares decide.mjs (pure JS).
// Deploy: wrangler deploy. Secret: wrangler secret put AGENT_GAMES_HMAC_SECRET

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

async function handleRaw(rawBytes, headers, secret, env) {
  const got = (headers.get('x-agent-games-signature') || '').replace(/^sha256=/i, '').trim().toLowerCase();
  const want = await hmacHex(secret, rawBytes);
  if (!got || !timingSafeEqHex(got, want)) return sign(secret, { error: 'bad signature' }, 401);
  let msg;
  try { msg = JSON.parse(new TextDecoder().decode(rawBytes)); }
  catch { return sign(secret, { error: 'bad json' }, 400); }
  if (msg.type === 'agent-games.preflight.v1') return sign(secret, { ok: true, protocolVersion: 'v1' }, 200);
  if (msg.type === 'agent-games.proof-gatekeeper.v1') {
    const res = decide(msg);
    // Durable replay check (KV), layered on decide()'s in-memory cache. Workers are ephemeral,
    // so a cold start could otherwise forget a proof accepted earlier in the same round and
    // wrongly APPROVE a PROOF_REUSED trap. Only accepted references are recorded (spec: a valid
    // proof does not gain re-entry). Guarded so the agent still works if no KV is bound.
    if (env && env.SEEN) {
      const ref = (msg.input && typeof msg.input.proof_tx === 'string') ? msg.input.proof_tx.trim().toLowerCase() : '';
      if (ref && res.decision === 'APPROVE') {
        try {
          if (await env.SEEN.get(ref)) { res.decision = 'REJECT'; res.reason_code = 'PROOF_REUSED'; }
          else await env.SEEN.put(ref, '1', { expirationTtl: 2592000 });
        } catch { /* KV hiccup: fall back to the decision decide() already made */ }
      }
    }
    // Attach a Groth16 proof via the prover sidecar (Workers can't run snarkjs). Best-effort:
    // if PROVER_URL is unset or the prover is slow/down, return the correct decision without a
    // proof (−2 but never Unhealthy). For PROOF_REUSED the prover returns public_signals only.
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
