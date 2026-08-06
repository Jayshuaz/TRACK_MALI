# Signed Checkpoint Server (Phase-0 PoC)

This minimal Node/Express server implements two endpoints used by the Phase‑0 verification flow:

- POST /api/v1/telemetry/checkpoint
  - Accepts a JSON body { events: [ ... ] } or uses sample_events.json when none provided.
  - Builds a deterministic Merkle tree from canonicalized event JSON, computes merkle_root, and signs it using ed25519.
  - Returns a checkpoint { merkle_root, signature, public_key, event_count, created_at } and persists the checkpoint to an append-only file for auditability.

- POST /api/v1/verification/proof
  - Accepts { leaf_index } or { leaf_hash } and returns the Merkle branch for that leaf plus the checkpoint's signature and public key.

Security notes
- Do NOT commit private keys. Set ED25519_PRIVATE_KEY_BASE64 in your environment for signing with a real key. The server expects the private key as base64:
  - either a 32-byte seed (base64) or
  - a 64-byte secretKey (base64) produced by tweetnacl
- If ED25519_PRIVATE_KEY_BASE64 is missing, the server generates an ephemeral keypair for PoC only.

Persistence & anchoring
- Checkpoints are appended to server/signed-checkpoint/data/checkpoints.jsonl (one JSON object per line). File mode is 0600 by default.
- To enable automatic anchoring, set:
  - ANCHOR_ENDPOINT - the full URL to POST anchor payloads to
  - ANCHOR_BEARER_TOKEN - optional bearer token for Authorization header
  - MANIFEST_URL - optional URL reference to include in anchor metadata
  - BUILD_HASH - optional build hash to include in anchor metadata

When ANCHOR_ENDPOINT is present, the server will POST {
  merkle_root, event_count, source, metadata: { manifest_url, build_hash }
} and persist the anchor response in the checkpoint record. The server does not forward any private keys to the anchor endpoint.

Run locally (PoC)
1. cd server/signed-checkpoint
2. npm install
3. node src/index.js

Example requests
- Create checkpoint (uses sample events):
  curl -X POST http://localhost:8080/api/v1/telemetry/checkpoint -H "Content-Type: application/json" -d '{}'

- Request proof for leaf 0:
  curl -X POST http://localhost:8080/api/v1/verification/proof -H "Content-Type: application/json" -d '{"leaf_index":0}'

Debug
- Internal info endpoint shows the checkpoint file path and a summary of the last checkpoint:
  GET /internal/info

Next steps (recommended)
- Move checkpoints.jsonl into an immutable store (S3 with object lock or append-only ledger) for stronger audit guarantees
- Add mTLS or signed envelopes for ingest; add authentication and rate limiting for proof retrieval
- Add automated integration tests that verify signature, Merkle reconstruction, and anchor round-trip
