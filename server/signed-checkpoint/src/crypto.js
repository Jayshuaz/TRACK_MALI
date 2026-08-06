const nacl = require('tweetnacl');
const util = require('tweetnacl-util');

function signRoot(rootHex, privateKeyBase64) {
  // rootHex: hex string; privateKeyBase64: base64 64-byte (secretKey) or 32-byte seed
  const rootBytes = Buffer.from(rootHex, 'hex');
  let secretKey;
  if (!privateKeyBase64) throw new Error('No private key provided');
  const raw = Buffer.from(privateKeyBase64, 'base64');
  if (raw.length === 32) {
    const keypair = nacl.sign.keyPair.fromSeed(new Uint8Array(raw));
    secretKey = keypair.secretKey;
  } else if (raw.length === 64) {
    secretKey = new Uint8Array(raw);
  } else {
    throw new Error('Invalid private key length');
  }
  const sig = nacl.sign.detached(new Uint8Array(rootBytes), secretKey);
  return util.encodeBase64(sig);
}

function genKeypairBase64() {
  const kp = nacl.sign.keyPair();
  return {
    publicKey: util.encodeBase64(kp.publicKey),
    secretKey: util.encodeBase64(kp.secretKey)
  };
}

module.exports = { signRoot, genKeypairBase64 };
