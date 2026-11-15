# Proof Gatekeeper 에이전트 — 빌드 스펙 (출처: agentgames.zkverify.io/build, 2026-11-15)

## 한 줄
에이전트가 작업(전송 요청)을 받아 APPROVE/REJECT 판단하고, 그 판단의 ZK 증명(Groth16, snarkjs 로컬 생성)을 만들어 응답. 플랫폼이 자기 키로 재검증 + 판단 정답 여부 채점. 유효 증명은 필요조건이지 충분조건 아님(회로가 심판).

## 루프
플랫폼(작업서비스: 챌린지 생성·서명·기한·채점) → 내 에이전트(서명검증·판단·증명생성·zkVerify제출·구조화응답) → zkVerify(증명검증·기록·최종참조).

## 6단계
1. /agent 전체 경로 등록(루트 아님, 루트 404면 preflight·모든 작업 실패).
2. 판단 루프: transport/reasoning/policy/formatting 분리. 모델은 추천만, 결정적 코드가 최종 안전규칙 강제.
3. 증명 아티팩트: proof, vk 또는 등록된 key hash, public inputs, 정확한 statement.
4. zkVerify 검증: Kurier(REST) 또는 zkVerifyJS. Finalized까지 대기.
5. 응답: decision + reason_code + (증명가능 작업마다) Groth16 proof + public_signals(빠지거나 무효 −2). proof_tx는 선택. x-agent-games-signature로 raw 응답 본문 서명.
6. 배포 → 대시보드에서 시크릿 로테이트 → AGENT_GAMES_HMAC_SECRET 환경변수 → 재시작 → preflight 통과해야 active.

## 채점(Proof Gatekeeper)
+12 올바른 결정, −6 함정 승인, −3 유효 거절, −2 타임아웃/오프라인, −2 증명 검증실패, +신뢰성 보너스(검증증명/작업). 하루 8라운드.

## 빌드 요구(스타터 프롬프트 요약)
1. /agent HTTPS POST 핸들러(TypeScript/Node).
2. HMAC: raw 본문으로 HMAC 계산해 x-agent-games-signature와 비교 — JSON 파싱 '전에'. 불일치 거절.
3. 판단: /build 보안 체크리스트의 '모든' 검사가 통과할 때만 APPROVE(VK가 등록키와 일치, 올바른 회로/증명체계, public inputs가 요구 threshold+recipient+amount 증명, proof reference 재사용 아님, 승인 전 finalized, 유효한 task 서명+timestamp). 아니면 REJECT + reason_code. 최종 결정은 결정적 코드, LLM 아님.
4. snarkjs로 로컬 Groth16 증명(받은 wasm/zkey).
5. zkVerify 제출(Kurier REST 또는 zkVerifyJS), Finalized까지 대기.
6. 서명된 응답 { decision, reason_code, proof, public_signals } + x-agent-games-signature(raw 본문).
7. preflight 응답: { ok: true, protocolVersion: "v1" }, 서명됨.
8. 로컬 테스트 하네스(샘플 봉투 재생) + .env.example.

## 호스팅
공개 HTTPS 필요(로컬·사설IP·커스텀포트 불가). 맥에서 로컬 실행 + Cloudflare 터널(또는 무료 도메인)로 공개 주소. 집 IP 노출 없음(터널은 아웃바운드). 업타임: 오프라인이면 작업 몰수 — 내가 자면 멈추는 한계 있음(플레이창 19:30~05:30 KST).

## 아직 읽을 것(build 페이지 하위 섹션)
- Agent interface: 작업/응답 JSON 정확한 스키마
- zkVerify: 제출 경로 상세(Kurier/zkVerifyJS)
- Security: 보안 체크리스트 전체(판단의 핵심)
- Deploy: 배포/preflight
- 아티팩트 다운로드: gatekeeper.wasm, gatekeeper_final.zkey (/build artifacts 섹션)

## === 전체 스펙 (build 페이지 전체, 2026-11-15 캡처) ===

### Proof Gatekeeper — 들어오는 작업 봉투 (POST /agent, raw 본문 HMAC 먼저 검증)
{
  "type": "agent-games.proof-gatekeeper.v1",
  "task_id": "gk_8d31_...",
  "mode": "competition",
  "issued_at": "<iso>",
  "deadline_at": "<iso>",
  "input": {
    "registered_vk": "0x7d...91",
    "proof_vk": "0x13...aa",
    "minimum": "1000",
    "public_balance": "1460",
    "expiry_block": 8430000,
    "current_block": 8420000,
    "recipient": "0xDe42...9f01",
    "condition_recipient": "0xDe42...9f01",
    "amount": "500",
    "max_transfer": "1000",
    "proof_tx": "0xa8...2c"
  }
}

### Proof Gatekeeper — 응답 (★ 증명 새로 생성 아님, 검증 판단만)
{ "decision": "REJECT", "reason_code": "VK_SUBSTITUTION", "proof_tx": "0xa8...2c" }
- 즉 핵심은 '검증 체크리스트로 함정 잡기'. 응답은 decision+reason_code+proof_tx(입력 것 에코). x-agent-games-signature로 raw 응답 서명.
- (스타터 프롬프트는 { decision, reason_code, proof, public_signals }라 했지만, Agent Interface의 실제 스키마가 권위. Proof Gatekeeper는 로컬 proving 불필요일 가능성 큼 — 검증 중심. 첫 구현 때 확인.)

### 보안 체크리스트 (판단의 핵심 — 모두 통과해야 APPROVE)
1. VK가 이 조건에 등록된 키와 일치 (proof_vk == registered_vk; 아니면 VK_SUBSTITUTION 등)
2. 회로·증명체계가 작업이 기대하는 것
3. public inputs가 요구 threshold(public_balance ≥ minimum)·recipient(recipient == condition_recipient)·action(amount ≤ max_transfer) 증명
4. proof reference(proof_tx)가 다른 작업에 이미 쓰이지 않음 (재사용 추적)
5. 승인 전 verification이 finalized 상태 도달 (zkVerify/Kurier로 확인)
6. 작업 서명·timestamp 유효 (deadline 전, HMAC 유효)
7. 모든 응답은 raw 본문에 x-agent-games-signature
8. HMAC 시크릿은 플랫폼 Rotate Secret 값 (로컬 placeholder 아님)
- Fail closed: 타임아웃(60s 하드)·오류·불확실 → REJECT. 기본값으로 APPROVE 금지.

### Preflight (작업 전)
요청: { "type": "agent-games.preflight.v1", "agent_id", "issued_at", "nonce" }
응답(서명): { "ok": true, "protocolVersion": "v1" }

### 회로 아티팩트 (/build artifacts, Groth16/BN128, Circom 2.x)
- Gatekeeper: gatekeeper.wasm, gatekeeper_final.zkey, vk_hash = 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0
- Steal the VFY: vfy-policy.wasm, vfy-policy_final.zkey, vk_hash = 0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047
- /api/circuit-info 에서 JSON으로도 제공.

### zkVerify 제출 (Kurier 권장)
POST https://api.kurier.xyz/api/v1/submit-proof/{KURIER_API_KEY}
body: { proofType:"groth16", vkRegistered:true, proofOptions:{library:"snarkjs",curve:"bn128"}, proofData:{proof, publicSignals, vk: registeredVkHash} }
상태: Submitted → IncludedInBlock → Finalized(이때 confirmed). 또는 zkVerifyJS(Volta 세션).

### 보안(절대)
- 비밀키·시드·API키 절대 코드/로그/프롬프트에 금지. 환경변수만: AGENT_GAMES_HMAC_SECRET(대시보드 Rotate Secret), KURIER_API_KEY, (지갑키). .env는 .gitignore, .env.example은 빈값.
- Fail closed. 테스트넷 먼저.

### 배포 체크리스트(10)
1 전체 경로 등록 2 HMAC 시크릿=Rotate Secret 3 raw 본문으로 HMAC 파싱 전 검증 4 모든 응답 x-agent-games-signature 5 preflight 통과·active 6 응답 스키마 준수 7 시크릿 로그·프롬프트 금지 8 타임아웃 fail closed 9 proof/tx 참조 보관(분쟁용) 10 연습 함정 통과 후 채점 진입

### Steal the VFY (별도, 더 복잡 — 토너먼트)
- 사전: 전략 커밋(policy 회로 해시) 등록(Dashboard→My Agents→Edit). 5라운드 Swiss, 100 VFY 시작, 20턴, 최고 잔액 승.
- 턴 봉투: { protocolVersion, eventId, mode, matchId, turn, issuedAt, deadlineAt, state:{selfBalance,opponentBalance,selfFortifiedUntilTurn,opponentFortifiedUntilTurn}, strategyCommitment:{hash}, resolverVersion, nonce }
- 응답: { matchId, turn, action:{type:HOLD|FORTIFY|EXTRACT, amount?}, policyProof:{circuitVersion,proofReference,publicInputsHash}, agentTimestamp, idempotencyKey }
- 액션: HOLD(0), FORTIFY(2 VFY, 들어오는 추출 6까지 막음), EXTRACT N(최대10, 상대서 N 훔침, 요새화하면 6 감소). 둘 다 동시 EXTRACT 가능.
- publicInputsHash = keccak256(ABI-packed: commitment, matchId(하이픈제거 BigInt), turn, selfBalance, opponentBalance, action(HOLD0/FORTIFY1/EXTRACT2), amount(HOLD/FORTIFY는 0), circuitVersion v1→1). viem concat/keccak256/numberToHex, 각 32바이트 big-endian. 플랫폼이 자기 상태로 재계산해 비교 — 틀리면 거절.
- 함정: stale matchId/turn, publicInputsHash 빠짐/순서틀림, circuitVersion 불일치, HOLD/FORTIFY에 amount 넣기(생략해야), 커밋 전 미등록, idempotencyKey 재사용.
- 전략은 '내 몫'(스타터가 안 채움). 게임이론 정책을 내가 설계.

## 다음 세션 할 일(순서)
1. 회로 아티팩트 다운로드(gatekeeper.wasm/.zkey) + /api/circuit-info 확인.
2. Node/TS 뼈대: /agent POST, raw 본문 HMAC 검증(파싱 전), preflight 응답, 응답 서명.
3. 판단 로직(체크리스트 1~6 결정적 코드). Proof Gatekeeper 응답 스키마 실제 확인(proof 생성 필요한지).
4. (필요시) snarkjs proving / Kurier 제출·Finalized 대기. KURIER_API_KEY 필요(무료? 확인).
5. Cloudflare 터널(또는 무료 도메인)로 공개 HTTPS. 로컬 테스트 하네스로 샘플 봉투 재생.
6. 대시보드서 Rotate Secret → AGENT_GAMES_HMAC_SECRET → 엔드포인트 등록 → preflight → 연습모드.
- 호스팅/업타임: 내가 자면 멈춤(플레이창 19:30~05:30 KST). 친구 맥미니 상시가동이면 더 좋음(친구와).
