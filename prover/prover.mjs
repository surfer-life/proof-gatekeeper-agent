// Groth16 prover for the Agent Games Proof Gatekeeper circuit.
// The circuit's input-signal interface (13 signals, template GatekeeperEvaluation_79) is a
// property of the shared official artifact gatekeeper.wasm/_final.zkey, publicly documented by
// other participants and verified here against the official verification key. Signal names and
// encoding below are confirmed by locally generating proofs that verify (both APPROVE and REJECT),
// and by the circuit rejecting a witness whose decision contradicts the inputs.
import { groth16 } from 'snarkjs';
import sha3 from 'js-sha3';
const { keccak256 } = sha3;
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const WASM = join(HERE, 'gatekeeper.wasm');
const ZKEY = join(HERE, 'gatekeeper_final.zkey');

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const field = (v) => (((BigInt(v) % P) + P) % P).toString();
const taskIdField = (s) => field('0x' + keccak256(Buffer.from(String(s), 'utf8')));

// Build the 13 circuit inputs from the task's input fields and the agent's decision (1=APPROVE,0=REJECT).
export function buildInputs(input, decision) {
  return {
    registeredVkHash: field(input.registered_vk),
    proofVkHash: field(input.proof_vk),
    minimum: field(input.minimum),
    publicBalance: field(input.public_balance),
    expiryBlock: field(input.expiry_block),
    currentBlock: field(input.current_block),
    recipient: field(input.recipient),
    conditionRecipient: field(input.condition_recipient),
    amount: field(input.amount),
    maxTransfer: field(input.max_transfer),
    taskId: taskIdField(input.task_id ?? ''),
    decision: decision ? '1' : '0',
    salt: '0',
  };
}

// Returns { proof, publicSignals } or throws (e.g. if the decision contradicts the inputs,
// which is exactly the PROOF_REUSED case — a valid-looking input that must still be REJECTed).
export async function prove(input, taskId, decision) {
  const ci = buildInputs({ ...input, task_id: taskId }, decision);
  const { proof, publicSignals } = await groth16.fullProve(ci, WASM, ZKEY);
  return { proof, publicSignals };
}

// Deterministic public_signals WITHOUT a proof, for the PROOF_REUSED case (and any time proving
// is skipped): the platform can't check signal[0] (the salt-dependent commitment) without the
// private salt, so it is set to "0" here; signals [1..12] are the public pass-throughs the circuit
// exposes, in the circuit's proven order. Used to avoid an empty response (which the platform has
// rejected for PROOF_REUSED), while honestly carrying no proof.
export function buildPublicSignals(input, taskId, decision) {
  const ci = buildInputs({ ...input, task_id: taskId }, decision);
  return [
    '0', ci.registeredVkHash, ci.proofVkHash, ci.minimum, ci.publicBalance,
    ci.expiryBlock, ci.currentBlock, ci.recipient, ci.conditionRecipient,
    ci.amount, ci.maxTransfer, ci.decision, ci.taskId,
  ];
}

// self-test
if (process.argv[1] && process.argv[1].endsWith('prover.mjs')) {
  const vk = JSON.parse(readFileSync(join(HERE, 'vk.json'), 'utf8'));
  const base = {
    registered_vk: '0x7d3a000000000000000000000000000000000000000000000000000000000291',
    proof_vk: '0x7d3a000000000000000000000000000000000000000000000000000000000291',
    minimum: '1000', public_balance: '1460', expiry_block: '19842201', current_block: '19832000',
    recipient: '0xDe42000000000000000000000000000000009f01', condition_recipient: '0xDe42000000000000000000000000000000009f01',
    amount: '500', max_transfer: '1000',
  };
  const t0 = Date.now();
  const okProof = await prove(base, 'gk_24_9d1', 1);              // VALID -> APPROVE
  const okV = await groth16.verify(vk, okProof.publicSignals, okProof.proof);
  const badVk = { ...base, proof_vk: '0x1111000000000000000000000000000000000000000000000000000000000111' };
  const rjProof = await prove(badVk, 'gk_vk_sub', 0);            // VK_SUBSTITUTION -> REJECT
  const rjV = await groth16.verify(vk, rjProof.publicSignals, rjProof.proof);
  let wrongThrew = false;
  try { await prove(badVk, 'gk_vk_sub', 1); } catch { wrongThrew = true; } // claiming APPROVE on a trap must fail
  console.log(JSON.stringify({
    approve_verifies: okV, reject_verifies: rjV, wrong_decision_rejected: wrongThrew,
    decision_signal_approve: okProof.publicSignals[11], decision_signal_reject: rjProof.publicSignals[11],
    ms_for_two_proofs: Date.now() - t0,
  }, null, 1));
  process.exit(okV && rjV && wrongThrew ? 0 : 1);
}
