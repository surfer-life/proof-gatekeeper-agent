// Prover sidecar for the Proof Gatekeeper agent. The always-on Cloudflare Worker computes the
// decision and calls this service to attach a Groth16 proof (Workers can't run snarkjs). Native
// Node only — snarkjs needs worker_threads. Shared-key auth so the compute endpoint isn't abused.
import { createServer } from 'node:http';
import { groth16 } from 'snarkjs';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { prove, buildPublicSignals } from './prover.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const VK = JSON.parse(readFileSync(join(HERE, 'vk.json'), 'utf8'));
const KEY = process.env.PROVER_KEY || '';
const PORT = Number(process.env.PORT || 8799);

const readBody = (req) => new Promise((res, rej) => {
  let d = ''; req.on('data', c => { d += c; if (d.length > 1e6) req.destroy(); });
  req.on('end', () => res(d)); req.on('error', rej);
});

createServer(async (req, res) => {
  const send = (code, obj) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };
  try {
    if (req.method === 'GET' && req.url === '/health') return send(200, { ok: true });
    if (req.method !== 'POST' || req.url !== '/prove') return send(404, { error: 'not found' });
    if (!KEY || req.headers['x-prover-key'] !== KEY) return send(401, { error: 'bad key' });
    const { input, task_id, approve, reuse } = JSON.parse(await readBody(req));
    if (!input || typeof input !== 'object') return send(400, { error: 'bad input' });
    // PROOF_REUSED: the circuit forces decision=1 for otherwise-valid inputs, so a REJECT proof is
    // impossible. Return honest public signals (decision=0) with no proof.
    if (reuse) return send(200, { proof: null, public_signals: buildPublicSignals(input, task_id, false), note: 'reuse-no-proof' });
    try {
      const { proof, publicSignals } = await prove(input, task_id, !!approve);
      const ok = await groth16.verify(VK, publicSignals, proof); // self-verify against the official vk
      if (!ok) return send(200, { proof: null, public_signals: buildPublicSignals(input, task_id, !!approve), note: 'self-verify-failed' });
      return send(200, { proof, public_signals: publicSignals, self_verified: true });
    } catch (e) {
      // Decision contradicts inputs (circuit assert) or a prover error: fall back to signals only.
      return send(200, { proof: null, public_signals: buildPublicSignals(input, task_id, !!approve), note: 'prove-failed:' + (e.message || '').slice(0, 80) });
    }
  } catch (e) { send(500, { error: (e.message || 'err').slice(0, 120) }); }
}).listen(PORT, () => console.log(`prover listening on :${PORT} (key ${KEY ? 'set' : 'MISSING'})`));
