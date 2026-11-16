// Vercel serverless prover for the Proof Gatekeeper circuit. Node runtime (snarkjs needs
// worker_threads). The always-on Cloudflare Worker computes the decision and calls this to attach a
// Groth16 proof. Circuit artifacts are fetched to /tmp on cold start (sha256-pinned), so the repo
// stays light. See github.com/surfer-life/proof-gatekeeper-agent (prover/) for the verified mapping.
import { groth16 } from 'snarkjs';
import sha3 from 'js-sha3';
import { writeFile, readFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
const { keccak256 } = sha3;

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const field = (v) => (((BigInt(v) % P) + P) % P).toString();
// taskId: the 128-bit value of the UUID that ends task_id (e.g. "practice_<uuid>", "gk_..._<uuid>").
// Until 2026-11-17 this was keccak256(task_id) mod p; R04 then scored every proof invalid (8 x (12-2)).
// The UUID mapping is what a public agent whose proofs do score uses (whale99999/agent-games-agent,
// policy.mjs gatekeeperTaskField) — credit to them. Falls back to keccak if no trailing UUID.
const taskIdField = (s) => {
  const tail = String(s).slice(-36).replace(/-/g, '');
  if (/^[0-9a-f]{1,64}$/i.test(tail)) return field('0x' + tail);
  return field('0x' + keccak256(Buffer.from(String(s), 'utf8')));
};

const ART = {
  wasm: { url: 'https://agentgames.zkverify.io/circuits/gatekeeper.wasm', path: '/tmp/gk.wasm', sha: 'be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f' },
  zkey: { url: 'https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey', path: '/tmp/gk.zkey', sha: 'adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d' },
};
let vk = null;
let ready = null;
async function fetchArt(a) {
  try { const b = await readFile(a.path); if (createHash('sha256').update(b).digest('hex') === a.sha) return; } catch {}
  const r = await fetch(a.url); if (!r.ok) throw new Error('fetch ' + a.url + ' ' + r.status);
  const buf = Buffer.from(await r.arrayBuffer());
  if (createHash('sha256').update(buf).digest('hex') !== a.sha) throw new Error('sha mismatch ' + a.url);
  await writeFile(a.path, buf);
}
async function prepare() {
  await mkdir('/tmp', { recursive: true }).catch(() => {});
  await Promise.all([fetchArt(ART.wasm), fetchArt(ART.zkey)]);
  if (!vk) { const m = await import('../lib/vk.js'); vk = m.default; }
}

function buildInputs(input, taskId, decision) {
  return {
    registeredVkHash: field(input.registered_vk), proofVkHash: field(input.proof_vk),
    minimum: field(input.minimum), publicBalance: field(input.public_balance),
    expiryBlock: field(input.expiry_block), currentBlock: field(input.current_block),
    recipient: field(input.recipient), conditionRecipient: field(input.condition_recipient),
    amount: field(input.amount), maxTransfer: field(input.max_transfer),
    taskId: taskIdField(taskId ?? ''), decision: decision ? '1' : '0', salt: '0',
  };
}
function fallbackSignals(input, taskId, decision) {
  const ci = buildInputs(input, taskId, decision);
  return ['0', ci.registeredVkHash, ci.proofVkHash, ci.minimum, ci.publicBalance, ci.expiryBlock,
    ci.currentBlock, ci.recipient, ci.conditionRecipient, ci.amount, ci.maxTransfer, ci.decision, ci.taskId];
}

export default async function handler(req, res) {
  if (req.method === 'GET') return res.status(200).json({ ok: true });
  if (req.method !== 'POST') return res.status(404).json({ error: 'not found' });
  if (!process.env.PROVER_KEY || req.headers['x-prover-key'] !== process.env.PROVER_KEY)
    return res.status(401).json({ error: 'bad key' });
  let body = req.body;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch { return res.status(400).json({ error: 'bad json' }); } }
  const { input, task_id, approve, reuse } = body || {};
  if (!input || typeof input !== 'object') return res.status(400).json({ error: 'bad input' });
  try {
    if (!ready) ready = prepare();
    await ready;
    if (reuse) return res.status(200).json({ proof: null, public_signals: fallbackSignals(input, task_id, false), note: 'reuse-no-proof' });
    try {
      const ci = buildInputs(input, task_id, !!approve);
      const { proof, publicSignals } = await groth16.fullProve(ci, ART.wasm.path, ART.zkey.path);
      const ok = await groth16.verify(vk, publicSignals, proof);
      if (!ok) return res.status(200).json({ proof: null, public_signals: fallbackSignals(input, task_id, !!approve), note: 'self-verify-failed' });
      return res.status(200).json({ proof, public_signals: publicSignals, self_verified: true });
    } catch (e) {
      return res.status(200).json({ proof: null, public_signals: fallbackSignals(input, task_id, !!approve), note: 'prove-failed:' + String(e.message || '').slice(0, 80) });
    }
  } catch (e) { return res.status(500).json({ error: String(e.message || 'err').slice(0, 120) }); }
}
