# proof-gatekeeper prover (sidecar)

A tiny always-on Node service that generates the **Groth16 proof** for each Proof Gatekeeper
decision. The always-on Cloudflare Worker (the registered agent endpoint) computes the decision and
calls this service to attach the proof, because Workers can't run snarkjs. Best-effort: if this
service is down, the Worker still returns the correct decision (just without a proof).

## Why a proof matters
On the Proof Gatekeeper leaderboard the top agents all make the correct decision; the differentiator
is the **verified proof** (reliability bonus, and avoiding the −2 for a missing/invalid proof). Most
agents attach no proof.

## The circuit interface
The circuit (`gatekeeper.wasm` / `gatekeeper_final.zkey`, downloaded from
`https://agentgames.zkverify.io/circuits/`, sha256 verified) is **shared** by every participant; its
input-signal interface is a property of that shared artifact, not anyone's strategy. The 13 input
signals (`registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock, currentBlock,
recipient, conditionRecipient, amount, maxTransfer, taskId, decision, salt`), their encoding, and the
public-signals layout were **publicly documented by other participants** and are **verified here**:
`prover.mjs`'s self-test generates proofs that verify against the official verification key (vk_hash
`0x6b79c6…77b0`) for both APPROVE and REJECT, and confirms the circuit rejects a witness whose
`decision` contradicts the inputs (so a correct decision is required to produce a valid proof).
Proving takes ~120 ms. Credit for discovering the interface is the public research; this service
verifies it and does its own proving. The agent's decision logic is its own (see the Worker repo).

`decision` is `1`=APPROVE, `0`=REJECT. `PROOF_REUSED` is the one case with no provable REJECT (the
circuit, lacking off-chain reuse state, only accepts APPROVE for those inputs), so the service returns
honest `public_signals` with `proof: null`.

## Run / test locally
```
npm install
node prover.mjs          # self-test: approve + reject verify, wrong decision rejected
PROVER_KEY=... node prover-server.mjs   # POST /prove  {input, task_id, approve, reuse} + x-prover-key
```

## Deploy (always-on) and go live
Any always-on Node host works (Fly.io config included). Then it's a two-variable change on the Worker:
```
# host the service, set its PROVER_KEY secret, note its URL
# on the Cloudflare Worker, set:
#   PROVER_URL = https://<host>/prove
#   PROVER_KEY = <same key>
```
The Worker calls it with a 25 s timeout and falls back to decision-only if it can't reach it.

Not security advice.
