const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const fetch = require('node-fetch');

const DATA_DIR = path.join(__dirname, '..', 'data');
const CHECKPOINTS_FILE = path.join(DATA_DIR, 'checkpoints.jsonl');
const S3_OBJECT_KEY = process.env.CHECKPOINTS_S3_KEY || 'checkpoints.jsonl';

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(CHECKPOINTS_FILE)) fs.writeFileSync(CHECKPOINTS_FILE, '');
}

function writeLocalCheckpoint(line) {
  ensureDataDir();
  fs.appendFileSync(CHECKPOINTS_FILE, line, { encoding: 'utf8', mode: 0o600 });
}

function encodeRfc3986(value) {
  return encodeURIComponent(value).replace(/%7E/g, '~').replace(/%2F/g, '/');
}

function createCanonicalRequest(method, pathName, query, headers, payloadHash) {
  const sortedHeaders = Object.keys(headers).sort((a, b) => a.localeCompare(b));
  const canonicalHeaders = sortedHeaders.map(k => `${k.toLowerCase()}:${headers[k].trim()}`).join('\n');
  const signedHeaders = sortedHeaders.map(k => k.toLowerCase()).join(';');
  return [method, pathName, query, canonicalHeaders, '', signedHeaders, payloadHash].join('\n');
}

function signAwsV4(method, url, body, headers, region, accessKeyId, secretAccessKey, sessionToken) {
  const parsed = new URL(url);
  const date = new Date();
  const amzDate = date.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = crypto.createHash('sha256').update(Buffer.from(body || '', 'utf8')).digest('hex');
  const host = parsed.host;
  const pathName = parsed.pathname || '/';
  const query = parsed.search.replace(/^\?/, '');
  const normalizedHeaders = { host, 'x-amz-content-sha256': payloadHash, 'x-amz-date': amzDate };
  if (sessionToken) normalizedHeaders['x-amz-security-token'] = sessionToken;

  const canonicalRequest = createCanonicalRequest(method, pathName, query, normalizedHeaders, payloadHash);
  const credentialScope = [dateStamp, region, 's3', 'aws4_request'].join('/');
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, credentialScope, crypto.createHash('sha256').update(canonicalRequest).digest('hex')].join('\n');

  const signingKey = Buffer.from(`AWS4${secretAccessKey}`, 'utf8');
  const kDate = signHmac(signingKey, dateStamp);
  const kRegion = signHmac(kDate, region);
  const kService = signHmac(kRegion, 's3');
  const kSigning = signHmac(kService, 'aws4_request');
  const signature = signHmac(kSigning, stringToSign, 'hex');

  normalizedHeaders.Authorization = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${Object.keys(normalizedHeaders).sort((a, b) => a.localeCompare(b)).map(k => k.toLowerCase()).join(';')}, Signature=${signature}`;
  return { headers: normalizedHeaders, payloadHash };
}

function signHmac(key, value, encoding = 'buffer') {
  const digest = crypto.createHmac('sha256', key).update(value).digest();
  return encoding === 'hex' ? digest.toString('hex') : digest;
}

async function fetchS3Text(method, url, body = '') {
  const bucket = process.env.CHECKPOINTS_S3_BUCKET;
  if (!bucket) throw new Error('CHECKPOINTS_S3_BUCKET is not configured');

  const region = process.env.AWS_REGION || 'us-east-1';
  const accessKeyId = process.env.AWS_ACCESS_KEY_ID;
  const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;
  const sessionToken = process.env.AWS_SESSION_TOKEN || '';
  if (!accessKeyId || !secretAccessKey) throw new Error('AWS credentials are not configured');

  const { headers } = signAwsV4(method, url, body, {}, region, accessKeyId, secretAccessKey, sessionToken);
  const response = await fetch(url, { method, body, headers });
  if (!response.ok) {
    const text = await response.text();
    const error = new Error(`S3 request failed: ${response.status} ${text}`);
    error.status = response.status;
    throw error;
  }
  return response.text();
}

async function appendToS3(line) {
  const bucket = process.env.CHECKPOINTS_S3_BUCKET;
  const region = process.env.AWS_REGION || 'us-east-1';
  const endpoint = process.env.CHECKPOINTS_S3_ENDPOINT || `https://s3.${region}.amazonaws.com`;
  const url = new URL(`/${bucket}/${S3_OBJECT_KEY}`, endpoint);
  let existing = '';
  try {
    existing = await fetchS3Text('GET', url.toString());
  } catch (err) {
    if (err.status !== 404) throw err;
  }
  const nextBody = existing + line;
  await fetchS3Text('PUT', url.toString(), nextBody);
  return { storage: 's3', file: url.toString() };
}

async function appendCheckpoint(obj) {
  const line = JSON.stringify(obj) + '\n';
  if (process.env.CHECKPOINTS_S3_BUCKET) {
    try {
      return await appendToS3(line);
    } catch (err) {
      console.warn('Falling back to local checkpoint storage:', err.message);
    }
  }
  writeLocalCheckpoint(line);
  return { storage: 'local', file: CHECKPOINTS_FILE };
}

function readAllCheckpoints() {
  ensureDataDir();
  const data = fs.readFileSync(CHECKPOINTS_FILE, 'utf8').trim();
  if (!data) return [];
  return data.split('\n').map(l => JSON.parse(l));
}

module.exports = { appendCheckpoint, readAllCheckpoints, CHECKPOINTS_FILE };
