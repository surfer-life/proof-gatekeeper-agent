// Steal the VFY agent — Vercel serverless (Node; snarkjs needs worker_threads).
// Implements the signed turn contract: verify HMAC, decide the action from the committed strategy
// params (circuit-enforced), generate the per-turn Groth16 proof against the official vfy-policy
// circuit, and return a signed TurnResponse. Preflight supported.
//
// The circuit interface (17 inputs: 9 scalars + strategyParams[0..7]) and the publicInputsHash
// formula are a property of the shared official artifact, publicly documented and verified here
// (a turn proof verifies against the official vk 0x6c56…be047; a wrong action is rejected by the
// circuit). The STRATEGY (params) is mine: [10,0,0,0] = always EXTRACT 10, which never loses a turn
// (vs HOLD +20, vs FORTIFY +10, vs EXTRACT draw). Decision logic per the circuit's strict list.
import { groth16 } from 'snarkjs';
import sha3 from 'js-sha3';
import crypto from 'node:crypto';
import { writeFile, readFile, mkdir } from 'node:fs/promises';
const { keccak256 } = sha3;

const PARAMS = [10, 0, 0, 0, 0, 0, 0, 0];
const SALT = process.env.VFY_SALT || '';
const COMMITMENT = process.env.VFY_COMMITMENT || '';
const SECRET = process.env.VFY_SECRET || '';
const ACTION_CODE = { HOLD: 0, FORTIFY: 1, EXTRACT: 2 };

const ART = {
  wasm: { url: 'https://agentgames.zkverify.io/circuits/vfy-policy.wasm', path: '/tmp/vfy.wasm', sha: 'bc0998250d2baf75b89deef5306867ffa7085a08d4f7d2caf0dd63a060b134d2' },
  zkey: { url: 'https://agentgames.zkverify.io/circuits/vfy-policy_final.zkey', path: '/tmp/vfy.zkey', sha: 'f9666a1655279ef27f7fee6d535ac8aa9e39286ac40ff6279fea87c21ab6ce41' },
};
let ready = null;
async function fetchArt(a) {
  try { const b = await readFile(a.path); if (crypto.createHash('sha256').update(b).digest('hex') === a.sha) return; } catch {}
  const r = await fetch(a.url); if (!r.ok) throw new Error('fetch ' + a.url + ' ' + r.status);
  const buf = Buffer.from(await r.arrayBuffer());
  if (crypto.createHash('sha256').update(buf).digest('hex') !== a.sha) throw new Error('sha mismatch ' + a.url);
  await writeFile(a.path, buf);
}
async function prepare() { await mkdir('/tmp', { recursive: true }).catch(() => {}); await Promise.all([fetchArt(ART.wasm), fetchArt(ART.zkey)]); }

const sign = (raw) => crypto.createHmac('sha256', SECRET).update(raw).digest('hex');
function verify(raw, header) {
  if (!SECRET || !header) return false;
  const got = (Array.isArray(header) ? header[0] : header).trim().replace(/^sha256=/i, '').toLowerCase();
  const want = sign(raw);
  const a = Buffer.from(got, 'utf8'), b = Buffer.from(want, 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const matchIdToBig = (m) => BigInt('0x' + m.trim().replace(/-/g, '').toLowerCase());
const be32 = (v) => { let h = BigInt(v).toString(16); if (h.length > 64) throw new Error('overflow'); return Buffer.from(h.padStart(64, '0'), 'hex'); };

// Circuit's strict decision list for PARAMS=[10,0,0,0]: FORTIFY if self<p1; else HOLD if opp<=p2 or p3==1; else EXTRACT p0.
function decide(selfBalance, opponentBalance) {
  if (selfBalance < PARAMS[1]) return { type: 'FORTIFY' };
  if (opponentBalance <= PARAMS[2] || PARAMS[3] === 1) return { type: 'HOLD' };
  return { type: 'EXTRACT', amount: PARAMS[0] };
}
function publicInputsHash({ commitment, matchId, turn, selfBalance, opponentBalance, action, amount, circuitVersion }) {
  const fields = Buffer.concat([
    be32(BigInt(commitment)), be32(matchIdToBig(matchId)), be32(turn), be32(selfBalance),
    be32(opponentBalance), be32(ACTION_CODE[action]), be32(amount), be32(circuitVersion),
  ]);
  return '0x' + keccak256(fields);
}
async function proveTurn(env, action, amount) {
  const inputs = {
    commitment: BigInt(COMMITMENT).toString(),
    matchId: matchIdToBig(env.matchId).toString(),
    selfBalance: BigInt(env.state.selfBalance).toString(),
    opponentBalance: BigInt(env.state.opponentBalance).toString(),
    action: ACTION_CODE[action].toString(),
    amount: amount.toString(),
    circuitVersion: '1',
    turnNumber: BigInt(env.turn).toString(),
    salt: SALT,
    strategyParams: PARAMS.map(String),
  };
  const { proof, publicSignals } = await groth16.fullProve(inputs, ART.wasm.path, ART.zkey.path);
  return { proof, publicSignals };
}

export default async function handler(req, res) {
  const raw = Buffer.isBuffer(req.body) ? req.body : Buffer.from(typeof req.body === 'string' ? req.body : JSON.stringify(req.body || {}), 'utf8');
  const send = (obj, status = 200) => { const body = JSON.stringify(obj); res.setHeader('content-type', 'application/json'); res.setHeader('x-agent-games-signature', sign(body)); res.status(status).send(body); };
  if (req.method === 'GET') return res.status(200).json({ ok: true });
  if (req.method !== 'POST') return res.status(404).json({ error: 'not found' });
  if (!verify(raw, req.headers['x-agent-games-signature'])) return res.status(401).json({ error: 'bad signature' });
  let msg; try { msg = JSON.parse(raw.toString('utf8')); } catch { return res.status(400).json({ error: 'bad json' }); }
  if (msg.type === 'agent-games.preflight.v1') return send({ ok: true, protocolVersion: 'v1' });
  // turn envelope
  try {
    if (!ready) ready = prepare();
    await ready;
    const selfBalance = Number(msg.state?.selfBalance), opponentBalance = Number(msg.state?.opponentBalance);
    const action = decide(selfBalance, opponentBalance);
    const amount = action.type === 'EXTRACT' ? action.amount : 0;
    const { proof, publicSignals } = await proveTurn(msg, action.type, amount);
    const pih = publicInputsHash({ commitment: COMMITMENT, matchId: msg.matchId, turn: msg.turn, selfBalance, opponentBalance, action: action.type, amount, circuitVersion: 'v1' });
    const response = {
      protocolVersion: msg.protocolVersion || 'v1',
      matchId: msg.matchId,
      turn: msg.turn,
      action,
      policyProof: { circuitVersion: 'v1', proof, publicSignals, publicInputsHash: pih },
      agentTimestamp: new Date().toISOString(),
      idempotencyKey: msg.idempotencyKey || `${msg.matchId}:${msg.turn}`,
    };
    return send(response);
  } catch (e) {
    // Fail closed to HOLD (no proof) so we stay schema-valid rather than silent.
    return send({ protocolVersion: msg.protocolVersion || 'v1', matchId: msg.matchId, turn: msg.turn, action: { type: 'HOLD' }, policyProof: { circuitVersion: 'v1' }, agentTimestamp: new Date().toISOString(), idempotencyKey: msg.idempotencyKey || `${msg.matchId}:${msg.turn}`, note: String(e.message || e).slice(0, 80) });
  }
}
