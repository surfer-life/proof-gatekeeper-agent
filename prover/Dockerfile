FROM node:22-slim
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev
# Official shared circuit artifacts (sha256-pinned below), fetched at build time so the repo stays light.
ADD https://agentgames.zkverify.io/circuits/gatekeeper.wasm ./gatekeeper.wasm
ADD https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey ./gatekeeper_final.zkey
RUN echo "be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f  gatekeeper.wasm" | sha256sum -c - \
 && echo "adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d  gatekeeper_final.zkey" | sha256sum -c -
COPY prover.mjs prover-server.mjs vk.json ./
ENV PORT=8080
EXPOSE 8080
CMD ["node", "prover-server.mjs"]
