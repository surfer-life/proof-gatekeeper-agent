# Vercel deployment of the prover

Same Groth16 prover as ../prover, packaged as a Vercel serverless function (free Hobby, no card,
Node runtime so snarkjs works). Circuit artifacts are fetched to /tmp on cold start (sha256-pinned).

Deploy: import this repo on Vercel with **Root Directory = `vercel-prover`**, set env var
`PROVER_KEY`, deploy. Endpoint: `https://<project>.vercel.app/api/prove`.
Then on the Cloudflare Worker set `PROVER_URL` to that and `PROVER_KEY` to the same value.
