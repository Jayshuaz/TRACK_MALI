# Signed Checkpoint Server (Phase-0 PoC)

This minimal Node/Express server implements two endpoints used by the Phase‑0 verification flow:

- POST /api/v1/telemetry/checkpoint
  - Accepts a JSON body { events: [ ... ] } or uses sample_events.json when none provided.
  - Builds a deterministic Merkle tree from canonicalized event JSON, computes merkle_root, and signs it using ed25519.
  - Returns a checkpoint { merkle_root, signature, public_key, event_count, created_at } and stores the checkpoint in memory for PoC.

- POST /api/v1/verification/proof
  - Accepts { leaf_index } or { leaf_hash } and returns the Merkle branch for that leaf plus the checkpoint's signature and public key.

Security notes
- Do NOT commit private keys. Set ED25519_PRIVATE_KEY_BASE64 in your environment for signing with a real key. The server expects the private key as base64:
  - either a 32-byte seed (base64) or
  - a 64-byte secretKey (base64) produced by tweetnacl
- If ED25519_PRIVATE_KEY_BASE64 is missing, the server generates an ephemeral keypair for PoC only.

Run locally (PoC)
1. cd server/signed-checkpoint
2. npm install
3. node src/index.js

Example requests
- Create checkpoint (uses sample events):
  curl -X POST http://localhost:8080/api/v1/telemetry/checkpoint -H "Content-Type: application/json" -d '{}'

- Request proof for leaf 0:
  curl -X POST http://localhost:8080/api/v1/verification/proof -H "Content-Type: application/json" -d '{"leaf_index":0}'

Next steps (recommended)
- Replace in-memory storage with a persisted store for production (signed_event logs stored in append-only store)
- Implement mTLS or signed envelopes on ingest for production
- Add rate limits and authentication for proof retrieval
