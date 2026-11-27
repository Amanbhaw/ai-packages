'use strict';
/**
 * tiny-zk-auth — tiny, zero-dependency authentication + commitment toolkit.
 *
 * Byte-identical in the browser, Node.js, Python, and a $1 MCU (integer-only field core).
 *   1. Mersenne-31 field + fingerprint()  — fast cross-platform integrity checksum (NOT crypto-strength).
 *   2. HMAC-SHA256 challenge-response       — real symmetric device auth (make/respond/verify).
 *   3. Merkle commitment                    — prove one member, hide the rest.
 *
 * HONEST: this is commitments + symmetric auth, NOT a zero-knowledge proof system
 * (a 31-bit field cannot give sound ZK). See README.
 *
 * In Node this uses the built-in `crypto`. In a browser bundle, provide a SHA-256/HMAC shim
 * or build only the field + fingerprint (which need no crypto). MIT.
 */
let nodeCrypto = null;
try { nodeCrypto = require('crypto'); } catch (_) { /* browser: HMAC parts unavailable */ }

const VERSION = '0.1.0';
const P = 2 ** 31 - 1; // 2147483647  (NB: `1 << 31` is negative in JS — do not use it)

// ----------------------------- Mersenne-31 field (BigInt mul for exact 31-bit arithmetic) ---
const PB = BigInt(P);
function m31Add(a, b) { return ((a % P) + (b % P)) % P; }
function m31Mul(a, b) { return Number((BigInt(a) * BigInt(b)) % PB); }
function m31Pow(a, e) {
  let base = ((a % P) + P) % P;
  let r = 1;
  let exp = e;
  while (exp > 0) {
    if (exp & 1) r = m31Mul(r, base);
    base = m31Mul(base, base);
    exp = Math.floor(exp / 2);
  }
  return r;
}

function fingerprintBytes(bytes, base) {
  base = (base === undefined ? 2654435761 % P : base) % P;
  let acc = (bytes.length + 1) % P;
  const bb = BigInt(base);
  let accB = BigInt(acc);
  for (let i = 0; i < bytes.length; i++) {
    accB = (accB * bb + BigInt((bytes[i] & 0xff) + 1)) % PB;
  }
  return Number(accB);
}

function fingerprintStr(text, base) {
  return fingerprintBytes(Buffer.from(text, 'utf8'), base);
}

// ----------------------------- HMAC challenge-response -----------------------------
function requireCrypto() {
  if (!nodeCrypto) throw new Error('tiny-zk-auth: HMAC auth needs Node crypto or a SHA-256 shim');
  return nodeCrypto;
}
function makeChallenge(nbytes = 32) {
  return requireCrypto().randomBytes(nbytes).toString('hex');
}
function respond(secret, challenge) {
  return requireCrypto().createHmac('sha256', secret).update(challenge, 'utf8').digest('hex');
}
function verify(secret, challenge, response) {
  const c = requireCrypto();
  const expected = c.createHmac('sha256', secret).update(challenge, 'utf8').digest('hex');
  if (typeof response !== 'string' || response.length !== expected.length) return false;
  return c.timingSafeEqual(Buffer.from(expected), Buffer.from(response));
}

// ----------------------------- Merkle commitment -----------------------------
function sha256(buf) { return requireCrypto().createHash('sha256').update(buf).digest(); }
function toBuf(x) { return Buffer.isBuffer(x) ? x : Buffer.from(String(x), 'utf8'); }
function leaf(data) { return sha256(Buffer.concat([Buffer.from([0]), toBuf(data)])); }
function node(a, b) { return sha256(Buffer.concat([Buffer.from([1]), a, b])); }

function merkleRoot(items) {
  if (!items.length) return sha256(Buffer.from('\x02empty', 'utf8')).toString('hex');
  let level = items.map(leaf);
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : level[i];
      next.push(node(left, right));
    }
    level = next;
  }
  return level[0].toString('hex');
}

function merkleProve(items, index) {
  if (index < 0 || index >= items.length) throw new RangeError('index out of range');
  let level = items.map(leaf);
  let idx = index;
  const proof = [];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : level[i];
      next.push(node(left, right));
    }
    let sib = idx ^ 1;
    if (sib >= level.length) sib = idx;
    proof.push([level[sib].toString('hex'), sib > idx ? 'R' : 'L']);
    idx = Math.floor(idx / 2);
    level = next;
  }
  return proof;
}

function merkleVerify(root, item, proof) {
  let h = leaf(item);
  for (const [sibHex, side] of proof) {
    const sib = Buffer.from(sibHex, 'hex');
    h = side === 'R' ? node(h, sib) : node(sib, h);
  }
  const hex = h.toString('hex');
  if (hex.length !== root.length) return false;
  return requireCrypto().timingSafeEqual(Buffer.from(hex), Buffer.from(root));
}

function proTier(licenseKey) { return !!licenseKey; } // commercial flag only; no crypto effect

module.exports = {
  VERSION, P,
  m31Add, m31Mul, m31Pow, fingerprintBytes, fingerprintStr,
  makeChallenge, respond, verify,
  merkleRoot, merkleProve, merkleVerify, proTier,
};
