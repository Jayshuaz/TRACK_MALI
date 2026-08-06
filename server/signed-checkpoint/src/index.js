const express = require('express');
const bodyParser = require('express').json;
const fetch = require('node-fetch');
const { leafHash, buildMerkleTree, getMerkleProof } = require('./merkle');
const { signRoot, genKeypairBase64 } = require('./crypto');
const { appendCheckpoint, CHECKPOINTS_FILE } = require('./persistence');

const app = express();
app.use(bodyParser({ limit: '2mb' }));

// lastCheckpoint kept for fast proofs; persisted checkpoints live in data/checkpoints.jsonl
let lastCheckpoint = null; // { merkle_root, signature, public_key, event_count, created_at, leaves, layers, anchor_response }

app.get('/', (req, res) => res.send('MaliTrack Phase-0 Signed Checkpoint Server (PoC)'));

// POST /api/v1/telemetry/checkpoint
// Body: { events: [ { id: "...", ... }, ... ] }
// Response: { checkpoint, note }
app.post('/api/v1/telemetry/checkpoint', async (req, res) => {
  try {
    const events = req.body && Array.isArray(req.body.events) ? req.body.events : [];
    if (events.length === 0) return res.status(400).json({ error: 'No events provided' });

    // Deterministic leaves in-order
    const leaves = events.map(e => leafHash(e));
    const tree = buildMerkleTree(leaves);
    const root = tree.root;

    // Signing
    const envKey = process.env.ED25519_PRIVATE_KEY_BASE64;
    let pubkeyBase64;
    let signatureBase64;

    if (!envKey) {
      // ephemeral keypair for PoC only — DO NOT use in production
      const kp = genKeypairBase64();
      pubkeyBase64 = kp.publicKey;
      signatureBase64 = signRoot(root, kp.secretKey);
    } else {
      // For production tests: supply private key base64 via env var
      const raw = Buffer.from(envKey, 'base64');
      if (raw.length === 32) {
        const nacl = require('tweetnacl');
        const kp = nacl.sign.keyPair.fromSeed(new Uint8Array(raw));
        pubkeyBase64 = require('tweetnacl-util').encodeBase64(kp.publicKey);
      } else if (raw.length === 64) {
        const pub = raw.slice(32, 64);
        pubkeyBase64 = require('tweetnacl-util').encodeBase64(pub);
      }
      signatureBase64 = signRoot(root, envKey);
    }

    const checkpoint = {
      merkle_root: root,
      signature: signatureBase64,
      public_key: pubkeyBase64,
      event_count: leaves.length,
      created_at: new Date().toISOString()
    };

    // Prepare persisted record
    const persisted = { ...checkpoint, leaves, layers: tree.layers };

    // Anchor integration (optional)
    const anchorEndpoint = process.env.ANCHOR_ENDPOINT;
    if (anchorEndpoint) {
      try {
        const anchorBody = {
          merkle_root: root,
          event_count: leaves.length,
          source: process.env.ANCHOR_SOURCE || 'maliTrack-phase0',
          metadata: {
            manifest_url: process.env.MANIFEST_URL || null,
            build_hash: process.env.BUILD_HASH || null
          }
        };
        const headers = { 'Content-Type': 'application/json' };
        if (process.env.ANCHOR_BEARER_TOKEN) headers.Authorization = `Bearer ${process.env.ANCHOR_BEARER_TOKEN}`;
        const r = await fetch(anchorEndpoint, { method: 'POST', body: JSON.stringify(anchorBody), headers, timeout: 10000 });
        const anchorRespText = await r.text();
        let anchorRespJson = null;
        try { anchorRespJson = JSON.parse(anchorRespText); } catch (e) { anchorRespJson = { raw: anchorRespText }; }
        persisted.anchor = { endpoint: anchorEndpoint, response: anchorRespJson, status: r.status, submitted_at: new Date().toISOString() };
      } catch (anchorErr) {
        persisted.anchor = { error: String(anchorErr), submitted_at: new Date().toISOString() };
      }
    }

    // Persist checkpoint (append-only)
    try {
      await appendCheckpoint(persisted);
    } catch (perr) {
      console.error('Failed to persist checkpoint:', perr);
    }

    // Update in-memory lastCheckpoint
    lastCheckpoint = persisted;

    res.json({ checkpoint: persisted, note: anchorEndpoint ? 'anchored (attempted) and persisted' : 'persisted (no anchor endpoint configured)' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err) });
  }
});

// POST /api/v1/verification/proof
// Body: { leaf_index: number }  OR { leaf_hash: hex }
// Response: { leaf_hash, index, merkle_branch: [ { sibling, isLeft } ], merkle_root, public_key, signature }
app.post('/api/v1/verification/proof', (req, res) => {
  try {
    if (!lastCheckpoint) return res.status(404).json({ error: 'No checkpoint available. POST /telemetry/checkpoint first.' });
    const { leaf_index, leaf_hash } = req.body || {};
    let index = -1;
    if (typeof leaf_index === 'number') {
      index = leaf_index;
    } else if (typeof leaf_hash === 'string') {
      index = lastCheckpoint.leaves.indexOf(leaf_hash);
    } else {
      return res.status(400).json({ error: 'Provide leaf_index or leaf_hash' });
    }
    if (index < 0 || index >= lastCheckpoint.leaves.length) return res.status(400).json({ error: 'Leaf not found' });

    const branch = getMerkleProof(lastCheckpoint.layers, index);
    res.json({ leaf_hash: lastCheckpoint.leaves[index], index, merkle_branch: branch, merkle_root: lastCheckpoint.merkle_root, public_key: lastCheckpoint.public_key, signature: lastCheckpoint.signature, anchor: lastCheckpoint.anchor || null });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err) });
  }
});

// Expose a simple health and info endpoint for debugging
app.get('/internal/info', (req, res) => {
  res.json({ checkpoint_file: CHECKPOINTS_FILE, last_checkpoint: lastCheckpoint ? { merkle_root: lastCheckpoint.merkle_root, event_count: lastCheckpoint.event_count, anchor: !!lastCheckpoint.anchor } : null });
});

function startServer(port = process.env.PORT || 8080) {
  return app.listen(port, () => console.log(`Signed-checkpoint server listening on http://0.0.0.0:${port}`));
}

if (require.main === module) {
  startServer();
}

module.exports = { app, startServer };