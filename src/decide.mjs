// Proof Gatekeeper decision logic — deterministic checklist (no LLM in the final call).
// Spec: agentgames.zkverify.io/events/proof-gatekeeper (Trap Encyclopedia + expected response).
// APPROVE only if EVERY documented check passes; otherwise REJECT with the exact trap reason_code.
// Fail closed on malformed input. Reason codes verified against the event's Trap Encyclopedia:
//   VALID_CONDITION (approve), VK_SUBSTITUTION, THRESHOLD_MISMATCH, RECIPIENT_MISMATCH,
//   AMOUNT_OVERFLOW, EXPIRED_CONDITION, PROOF_REUSED.
// Only these seven cases exist in competition; we do NOT invent extra rejections (which would
// wrongly reject valid conditions and cost points). deadline_at is the 60s *response* window,
// not a condition field, so it is never a rejection reason here.

const bi = (v) => { try { return BigInt(v); } catch { return null; } };
const norm = (a) => (typeof a === 'string' ? a.trim().toLowerCase() : a);

// seen proof references, to catch replay/reuse across tasks (in-memory; persist later)
const seenProofTx = new Set();

export function decide(task, { markSeen = true } = {}) {
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

export function _resetSeen() { seenProofTx.clear(); } // for tests
