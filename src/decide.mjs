// Proof Gatekeeper decision logic — deterministic checklist (no LLM in the final call).
// Spec: SPEC.md (agentgames.zkverify.io/build, Security checklist).
// APPROVE only if EVERY check passes; otherwise REJECT with a reason_code. Fail closed.
// NOTE: reason_code strings are my best guess except VK_SUBSTITUTION (from the spec example);
//       confirm/adjust against practice-mode feedback before scored rounds.

const bi = (v) => { try { return BigInt(v); } catch { return null; } };
const norm = (a) => (typeof a === 'string' ? a.trim().toLowerCase() : a);

// seen proof references, to catch replay/reuse across tasks (in-memory; persist later)
const seenProofTx = new Set();

export function decide(task, { markSeen = true } = {}) {
  // Fail closed on anything malformed.
  try {
    const inp = task?.input;
    if (!inp || typeof inp !== 'object') return rej('MALFORMED_INPUT', task);

    // 6. deadline valid (timestamp). If deadline passed, reject.
    if (task.deadline_at) {
      const dl = Date.parse(task.deadline_at);
      if (Number.isFinite(dl) && Date.now() > dl) return rej('DEADLINE_PASSED', task);
    }

    // 1. VK matches the key registered for this condition.
    if (norm(inp.proof_vk) !== norm(inp.registered_vk)) return rej('VK_SUBSTITUTION', task);

    // 3a. public inputs prove the required recipient.
    if (norm(inp.recipient) !== norm(inp.condition_recipient)) return rej('RECIPIENT_MISMATCH', task);

    // 3b. threshold: public_balance must meet the minimum.
    const bal = bi(inp.public_balance), min = bi(inp.minimum);
    if (bal === null || min === null) return rej('MALFORMED_INPUT', task);
    if (bal < min) return rej('BELOW_MINIMUM', task);

    // 3c. action/amount within max_transfer.
    const amt = bi(inp.amount), maxT = bi(inp.max_transfer);
    if (amt === null || maxT === null) return rej('MALFORMED_INPUT', task);
    if (amt <= 0n) return rej('NONPOSITIVE_AMOUNT', task);
    if (amt > maxT) return rej('AMOUNT_EXCEEDS_MAX', task);
    // amount must also be spendable from the proven balance.
    if (amt > bal) return rej('AMOUNT_EXCEEDS_BALANCE', task);

    // expiry: current_block must be before expiry_block.
    if (inp.current_block != null && inp.expiry_block != null) {
      if (Number(inp.current_block) >= Number(inp.expiry_block)) return rej('EXPIRED', task);
    }

    // 4. proof reference not already used.
    const ref = norm(inp.proof_tx);
    if (ref && seenProofTx.has(ref)) return rej('PROOF_REUSE', task);

    // 5. finalized-before-approval: checked elsewhere (zkVerify). Placeholder:
    // if (!(await isFinalized(inp.proof_tx))) return rej('NOT_FINALIZED', task);

    if (markSeen && ref) seenProofTx.add(ref);
    return { decision: 'APPROVE', reason_code: 'OK', proof_tx: inp.proof_tx };
  } catch {
    return rej('INTERNAL_ERROR', task); // fail closed
  }
}

function rej(code, task) {
  return { decision: 'REJECT', reason_code: code, proof_tx: task?.input?.proof_tx };
}

export function _resetSeen() { seenProofTx.clear(); } // for tests
