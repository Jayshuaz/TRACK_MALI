const test = require('node:test');
const assert = require('node:assert/strict');
const { once } = require('node:events');
const path = require('node:path');
const fs = require('node:fs');
const fetch = require('node-fetch');
const nacl = require('tweetnacl');
const { createHash } = require('node:crypto');
const { leafHash, buildMerkleTree, getMerkleProof } = require('../src/merkle');
const { signRoot } = require('../src/crypto');
const { startServer } = require('../src/index');
const { CHECKPOINTS_FILE } = require('../src/persistence');

function verifyProof(leafHashHex, proof, rootHex) {
  let current = leafHashHex;
  for (const step of proof) {
    const sibling = step.sibling;
    current = step.isLeft
      ? Buffer.from(`${sibling}${current}`, 'hex').toString('hex')
      : Buffer.from(`${current}${sibling}`, 'hex').toString('hex');
    current = createHash('sha256').update(Buffer.from(current, 'hex')).digest('hex');
  }
  return current === rootHex;
}

test('Merkle proof reconstructs the root from a deterministic leaf set', () => {
  const events = [
    { id: 'e1', type: 'fulfillment', value: 0.98 },
    { id: 'e2', type: 'query_acceleration', value: 0.25 },
    { id: 'e3', type: 'turnaround_time', value: 0.20 }
  ];
  const leaves = events.map(event => leafHash(event));
  const tree = buildMerkleTree(leaves);
  const proof = getMerkleProof(tree.layers, 1);
  assert.equal(verifyProof(leaves[1], proof, tree.root), true);
});

test('ed25519 signatures verify against the derived public key', () => {
  const rootHex = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  const seed = Buffer.alloc(32, 7);
  const kp = nacl.sign.keyPair.fromSeed(seed);
  const signature = signRoot(rootHex, Buffer.from(kp.secretKey).toString('base64'));
  const sigBytes = Buffer.from(signature, 'base64');
  assert.equal(nacl.sign.detached.verify(Buffer.from(rootHex, 'hex'), sigBytes, kp.publicKey), true);
});

test('checkpoint endpoint returns a proof that reconstructs the stored root', async () => {
  const seed = Buffer.alloc(32, 9);
  process.env.ED25519_PRIVATE_KEY_BASE64 = seed.toString('base64');
  const dataDir = path.dirname(CHECKPOINTS_FILE);
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
  if (fs.existsSync(CHECKPOINTS_FILE)) {
    fs.rmSync(CHECKPOINTS_FILE, { force: true });
  }

  const server = startServer(0);
  await once(server, 'listening');
  const { port } = server.address();

  try {
    const checkpointResponse = await fetch(`http://127.0.0.1:${port}/api/v1/telemetry/checkpoint`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ events: [{ id: 'test-1', type: 'fulfillment', value: 0.98 }] })
    });
    assert.equal(checkpointResponse.status, 200);
    const checkpointBody = await checkpointResponse.json();
    assert.ok(checkpointBody.checkpoint.merkle_root);

    const proofResponse = await fetch(`http://127.0.0.1:${port}/api/v1/verification/proof`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ leaf_index: 0 })
    });
    assert.equal(proofResponse.status, 200);
    const proofBody = await proofResponse.json();

    const verified = verifyProof(proofBody.leaf_hash, proofBody.merkle_branch, proofBody.merkle_root);
    assert.equal(verified, true);
    assert.equal(proofBody.merkle_root, checkpointBody.checkpoint.merkle_root);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
