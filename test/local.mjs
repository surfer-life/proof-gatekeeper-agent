// Local test harness: sign sample envelopes with a TEST secret, run handle(), check results.
import crypto from 'node:crypto';
import { handle } from '../src/server.mjs';
import { _resetSeen } from '../src/decide.mjs';

const SECRET = 'test-secret-0123456789';
const sign = (obj) => {
  const raw = Buffer.from(JSON.stringify(obj));
  const sig = crypto.createHmac('sha256', SECRET).update(raw).digest('hex');
  return { raw, headers: { 'x-agent-games-signature': sig } };
};
const VK = '0x7d00000000000000000000000000000000000000000000000000000000000091';
const RCP = '0xDe420000000000000000000000000000000009f01';
const base = () => ({
  type: 'agent-games.proof-gatekeeper.v1', task_id: 'gk_' + Math.random().toString(16).slice(2),
  mode: 'competition', issued_at: new Date().toISOString(),
  deadline_at: new Date(Date.now() + 60000).toISOString(),
  input: { registered_vk: VK, proof_vk: VK, minimum: '1000', public_balance: '1460',
    expiry_block: 8430000, current_block: 8420000, recipient: RCP, condition_recipient: RCP,
    amount: '500', max_transfer: '1000', proof_tx: '0x' + crypto.randomBytes(8).toString('hex') } });

let pass = 0, fail = 0;
function check(name, task, wantDecision, wantReason, secret = SECRET) {
  const { raw, headers } = sign(task);
  const r = handle(raw, headers, secret);
  const body = JSON.parse(r.body);
  // verify response signature is valid under the secret
  const wantSig = crypto.createHmac('sha256', secret).update(r.body).digest('hex');
  const sigOK = r.sig === wantSig;
  const ok = body.decision === wantDecision && (wantReason == null || body.reason_code === wantReason) && sigOK;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}  -> ${body.decision}/${body.reason_code ?? ''} sig:${sigOK}`);
  ok ? pass++ : fail++;
}

// preflight
{
  const pf = { type: 'agent-games.preflight.v1', agent_id: 'agt_x', issued_at: new Date().toISOString(), nonce: 'abc' };
  const { raw, headers } = sign(pf);
  const r = handle(raw, headers, SECRET);
  const b = JSON.parse(r.body);
  const ok = b.ok === true && b.protocolVersion === 'v1' && r.status === 200;
  console.log(`${ok ? 'PASS' : 'FAIL'}  preflight -> ${r.body}`); ok ? pass++ : fail++;
}
// bad signature -> 401
{
  const t = base(); const raw = Buffer.from(JSON.stringify(t));
  const r = handle(raw, { 'x-agent-games-signature': 'deadbeef' }, SECRET);
  const ok = r.status === 401; console.log(`${ok ? 'PASS' : 'FAIL'}  bad-signature -> ${r.status}`); ok ? pass++ : fail++;
}

_resetSeen();
check('valid request', base(), 'APPROVE', 'VALID_CONDITION');
check('VK substitution', (() => { const t = base(); t.input.proof_vk = '0x' + '1'.repeat(64); return t; })(), 'REJECT', 'VK_SUBSTITUTION');
check('recipient mismatch', (() => { const t = base(); t.input.recipient = '0x' + 'a'.repeat(40); return t; })(), 'REJECT', 'RECIPIENT_MISMATCH');
check('threshold mismatch', (() => { const t = base(); t.input.public_balance = '999'; return t; })(), 'REJECT', 'THRESHOLD_MISMATCH');
check('amount overflow', (() => { const t = base(); t.input.amount = '1500'; return t; })(), 'REJECT', 'AMOUNT_OVERFLOW');
check('expired condition', (() => { const t = base(); t.input.current_block = 8430001; return t; })(), 'REJECT', 'EXPIRED_CONDITION');
// deadline_at is the 60s response window, NOT a condition field: a valid condition still APPROVEs.
check('past response deadline still approves', (() => { const t = base(); t.deadline_at = new Date(Date.now() - 1000).toISOString(); return t; })(), 'APPROVE', 'VALID_CONDITION');
// proof reuse: same proof_tx twice
{
  const t = base(); const fixed = '0xreuse00000000aa';
  t.input.proof_tx = fixed;
  check('first use of proof_tx', t, 'APPROVE', 'VALID_CONDITION');
  const t2 = base(); t2.input.proof_tx = fixed;
  check('reused proof_tx', t2, 'REJECT', 'PROOF_REUSED');
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
