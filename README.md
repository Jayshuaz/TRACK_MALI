# TRACK_MALI

MaliTrack Phase-0 repository for deterministic Rust→WebAssembly build automation and signed checkpoint verification.

## Contents

- `.github/workflows/deterministic-build.yml`
  - Builds the Rust WASM artifact deterministically
  - Produces a content-addressed SHA-256 hash
  - Publishes an optional checkpoint payload to a configured verification endpoint
  - Optionally uploads the artifact to S3 and attaches artifacts to a release tag

- `server/signed-checkpoint`
  - Node/Express proof-of-concept checkpoint service
  - Builds signed Merkle roots from canonical telemetry event payloads
  - Emits Merkle proofs for leaf verification and persists checkpoints append-only

## Quick start

```bash
cd server/signed-checkpoint
npm install
npm test
node src/index.js
```

## Notes

- The signed checkpoint service falls back to `src/sample_events.json` when the checkpoint POST body does not include an event array.
- Use `ED25519_PRIVATE_KEY_BASE64` to sign checkpoints with a stable key.
- The repository is designed for Phase-0 integration work; the CI workflow enforces server verification before build publication.
