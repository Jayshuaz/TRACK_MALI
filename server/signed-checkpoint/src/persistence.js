const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', 'data');
const CHECKPOINTS_FILE = path.join(DATA_DIR, 'checkpoints.jsonl');

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(CHECKPOINTS_FILE)) fs.writeFileSync(CHECKPOINTS_FILE, '');
}

function appendCheckpoint(obj) {
  ensureDataDir();
  const line = JSON.stringify(obj) + '\n';
  fs.appendFileSync(CHECKPOINTS_FILE, line, { encoding: 'utf8', mode: 0o600 });
}

function readAllCheckpoints() {
  ensureDataDir();
  const data = fs.readFileSync(CHECKPOINTS_FILE, 'utf8').trim();
  if (!data) return [];
  return data.split('\n').map(l => JSON.parse(l));
}

module.exports = { appendCheckpoint, readAllCheckpoints, CHECKPOINTS_FILE };
