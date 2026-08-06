// Minimal deterministic JSON canonicalization
function canonicalize(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(canonicalize);
  const keys = Object.keys(obj).sort();
  const out = {};
  for (const k of keys) out[k] = canonicalize(obj[k]);
  return out;
}

const crypto = require('crypto');

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function leafHash(obj) {
  const canon = JSON.stringify(canonicalize(obj));
  return sha256Hex(Buffer.from(canon, 'utf8'));
}

function buildMerkleTree(leaves) {
  // leaves: array of hex strings
  if (!leaves || leaves.length === 0) return {root: null, layers: []};
  let layer = leaves.slice();
  const layers = [layer];
  while (layer.length > 1) {
    const next = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = (i + 1 < layer.length) ? layer[i+1] : layer[i];
      const concat = Buffer.from(left + right, 'hex');
      const h = crypto.createHash('sha256').update(concat).digest('hex');
      next.push(h);
    }
    layer = next;
    layers.push(layer);
  }
  return { root: layers[layers.length-1][0], layers };
}

function getMerkleProof(layers, index) {
  // layers as returned, index is leaf index
  const proof = [];
  let idx = index;
  for (let i = 0; i < layers.length - 1; i++) {
    const layer = layers[i];
    const pairIndex = idx ^ 1; // sibling
    const sibling = (pairIndex < layer.length) ? layer[pairIndex] : layer[idx];
    proof.push({ sibling, isLeft: pairIndex < idx });
    idx = Math.floor(idx / 2);
  }
  return proof;
}

module.exports = { canonicalize, leafHash, buildMerkleTree, getMerkleProof };
