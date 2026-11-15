import { handleRaw } from '../src/worker.mjs';
import { _resetSeen } from '../src/decide.mjs';
const SECRET = 'test-secret-0123456789';
async function hmacHex(secret, data) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, data);
  return [...new Uint8Array(sig)].map(b=>b.toString(16).padStart(2,'0')).join('');
}
const VK='0x7d'+'0'.repeat(62), RCP='0xDe42'+'0'.repeat(35)+'f01';
const base=()=>({type:'agent-games.proof-gatekeeper.v1',task_id:'gk_'+Math.random().toString(16).slice(2),deadline_at:new Date(Date.now()+60000).toISOString(),
  input:{registered_vk:VK,proof_vk:VK,minimum:'1000',public_balance:'1460',expiry_block:8430000,current_block:8420000,recipient:RCP,condition_recipient:RCP,amount:'500',max_transfer:'1000',proof_tx:'0x'+Math.random().toString(16).slice(2,18)}});
let pass=0,fail=0;
async function check(name,obj,wantDec,wantReason){
  const body=new TextEncoder().encode(JSON.stringify(obj));
  const sig=await hmacHex(SECRET,body);
  const resp=await handleRaw(body,new Headers({'x-agent-games-signature':sig}),SECRET);
  const text=await resp.text(); const b=JSON.parse(text);
  const respSig=resp.headers.get('x-agent-games-signature');
  const sigOK=respSig===await hmacHex(SECRET,new TextEncoder().encode(text));
  const ok=(wantDec==null?resp.status===wantReason:(b.decision===wantDec&&(wantReason==null||b.reason_code===wantReason)))&&sigOK;
  console.log(`${ok?'PASS':'FAIL'}  ${name} -> ${resp.status} ${b.decision||''}/${b.reason_code||b.ok||''} sig:${sigOK}`); ok?pass++:fail++;
}
// preflight
await check('preflight',{type:'agent-games.preflight.v1',nonce:'x'},null,200);
// bad signature
{const body=new TextEncoder().encode(JSON.stringify(base()));const resp=await handleRaw(body,new Headers({'x-agent-games-signature':'deadbeef'}),SECRET);const ok=resp.status===401;console.log(`${ok?'PASS':'FAIL'}  bad-sig -> ${resp.status}`);ok?pass++:fail++;}
_resetSeen();
await check('valid',base(),'APPROVE','OK');
await check('VK sub',(()=>{const t=base();t.input.proof_vk='0x'+'1'.repeat(64);return t;})(),'REJECT','VK_SUBSTITUTION');
await check('amount>max',(()=>{const t=base();t.input.amount='1500';return t;})(),'REJECT','AMOUNT_EXCEEDS_MAX');
await check('expired',(()=>{const t=base();t.input.current_block=8430001;return t;})(),'REJECT','EXPIRED');
console.log(`\n${pass} passed, ${fail} failed`); process.exit(fail?1:0);
