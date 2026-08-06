const express = require('express');
const bodyParser = require('express').json;
const { leafHash, buildMerkleTree, getMerkleProof } = require('./merkle');
const { signRoot, genKeypairBase64 } = require('./crypto');

const app = express();
app.use(bodyParser({ limit: '1mb' }));

// Sample in-memory storage for PoC (not for production)
let lastCheckpoint = null; // { root, signature, publicKey, leaves, layers, created_at }

app.get('/', (req, res) => res.send('MaliTrack Phase-0 Signed Checkpoint Server (PoC)'));

// POST /api/v1/telemetry/checkpoint
// Body: { events: [ { id: "...", ... }, ... ] }
// Response: { merkle_root, signature, public_key, event_count, checkpoint_time }
app.post('/api/v1/telemetry/checkpoint', async (req, res) => {
  try {
    const events = Array.isArray(req.body && req.body.events) ? req.body.events : require('./sample_events.json');
    if (!Array.isArray(events) || events.length === 0) return res.status(400).json({ error: 'No events provided' });

    // Deterministic leaves in-order
    const leaves = events.map(e => leafHash(e));
    const tree = buildMerkleTree(leaves);
    const root = tree.root;

    // Signing
    const envKey = process.env.ED25519_PRIVATE_KEY_BASE64;
    let secretProvided = !!envKey;
    let pubkeyBase64;
    let signatureBase64;

    if (!envKey) {
      // ephemeral keypair for PoC only — DO NOT use in production
      const kp = genKeypairBase64();
      pubkeyBase64 = kp.publicKey;
      signatureBase64 = signRoot(root, kp.secretKey);
    } else {
      // For production tests: supply private key base64 via env var
      // We need to derive publicKey from secret if secret is 64 bytes or seed 32 bytes
      const raw = Buffer.from(envKey, 'base64');
      if (raw.length === 32) {
        const nacl = require('tweetnacl');
        const kp = nacl.sign.keyPair.fromSeed(new Uint8Array(raw));
        pubkeyBase64 = require('tweetnacl-util').encodeBase64(kp.publicKey);
      } else if (raw.length === 64) {
        // secretKey includes public key as suffix; extract public
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

    // Save minimal checkpoint for PoC proof retrieval
    lastCheckpoint = { ...checkpoint, leaves, layers: tree.layers };

    res.json({ checkpoint, note: secretProvided ? 'signed with provided env key' : 'signed with ephemeral key (POC only)' });
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
    res.json({ leaf_hash: lastCheckpoint.leaves[index], index, merkle_branch: branch, merkle_root: lastCheckpoint.merkle_root, public_key: lastCheckpoint.public_key, signature: lastCheckpoint.signature });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err) });
  }
});

const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`Signed-checkpoint server listening on http://0.0.0.0:${port}`));
