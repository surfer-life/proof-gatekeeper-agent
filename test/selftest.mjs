import http from 'node:http';
import crypto from 'node:crypto';
import { handle } from '../src/server.mjs';
const SECRET='test-secret-0123456789';
const srv=http.createServer((req,res)=>{const ch=[];req.on('data',c=>ch.push(c));req.on('end',()=>{const r=handle(Buffer.concat(ch),req.headers,SECRET);res.writeHead(r.status,{'content-type':'application/json','x-agent-games-signature':r.sig});res.end(r.body);});});
await new Promise(r=>srv.listen(8799,'127.0.0.1',r));
const body=JSON.stringify({type:'agent-games.preflight.v1',nonce:'self'});
const sig=crypto.createHmac('sha256',SECRET).update(body).digest('hex');
try{
  const resp=await fetch('http://127.0.0.1:8799/agent',{method:'POST',headers:{'content-type':'application/json','x-agent-games-signature':sig},body});
  console.log('OK status',resp.status,'body',await resp.text());
}catch(e){console.log('FAIL',e.message);}
srv.close();
