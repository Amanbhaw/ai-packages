'use strict';
/**
 * ai-receipt — zero-dependency cryptographic audit receipts for AI agents / LLM calls.
 *
 * Tamper-evident SHA-256 hash chain (same primitive Git and blockchains use). No ZK.
 * Receipts are byte-for-byte cross-verifiable with the Python `ai-receipt` package:
 * the canonical field string and hashing are identical in both.
 *
 * Node >= 14 (uses the built-in `crypto` module; no external runtime dependencies).
 * MIT licensed.
 */
const crypto = require('crypto');

const VERSION = '0.1.0';
const SPEC = 'ai-receipt/1';
const US = '\x1f'; // ASCII unit separator

function h(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

function canonValue(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) {
      throw new Error('ai-receipt: use integer values (e.g. micro-dollars) for portable hashes');
    }
    return String(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonValue).join(',') + ']';
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return '{' + keys.map((k) => k + ':' + canonValue(value[k])).join(',') + '}';
  }
  return String(value);
}

function commit(value, salt) {
  const text = value === null || value === undefined ? '' : canonValue(value);
  return h(salt + US + text);
}

function newSalt() {
  return crypto.randomBytes(16).toString('hex');
}

function canonicalString(step, model, pc, rc, tc, cost, timestamp, prevHash) {
  return [SPEC, String(step), model, pc, rc, tc, String(cost), String(timestamp), prevHash].join(US);
}

function createReceipt(opts) {
  const {
    step,
    model,
    prompt,
    response,
    toolCalls = null,
    cost = 0,
    prevHash = '',
    secretKey = null,
  } = opts;
  let { timestamp, salt } = opts;
  if (timestamp === undefined || timestamp === null) timestamp = Math.floor(Date.now() / 1000);
  if (salt === undefined || salt === null) salt = newSalt();

  const promptCommit = commit(prompt, salt);
  const responseCommit = commit(response, salt);
  const toolCommit = commit(toolCalls, salt);
  const hash = h(canonicalString(step, model, promptCommit, responseCommit, toolCommit, cost, timestamp, prevHash));

  const receipt = {
    spec: SPEC,
    step,
    model,
    prompt_commit: promptCommit,
    response_commit: responseCommit,
    tool_commit: toolCommit,
    cost,
    timestamp,
    prev_hash: prevHash,
    hash,
  };
  if (secretKey !== null && secretKey !== undefined) {
    receipt.sig = crypto.createHmac('sha256', secretKey).update(hash, 'utf8').digest('hex');
  }
  return receipt;
}

function recomputeHash(r) {
  return h(canonicalString(r.step, r.model, r.prompt_commit, r.response_commit, r.tool_commit, r.cost, r.timestamp, r.prev_hash));
}

function timingSafeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function verifyReceipt(r, secretKey) {
  if (!r || r.spec !== SPEC) return false;
  if (recomputeHash(r) !== r.hash) return false;
  if ('sig' in r) {
    if (secretKey === null || secretKey === undefined) return false;
    const expected = crypto.createHmac('sha256', secretKey).update(r.hash, 'utf8').digest('hex');
    if (!timingSafeEqualHex(expected, r.sig)) return false;
  }
  return true;
}

function openCommitment(commitHex, value, salt) {
  return timingSafeEqualHex(commit(value, salt), commitHex);
}

function foldReceipts(receipts) {
  let root = '';
  for (const r of receipts) root = h(root + r.hash);
  return {
    spec: SPEC,
    count: receipts.length,
    root,
    first_step: receipts.length ? receipts[0].step : null,
    last_step: receipts.length ? receipts[receipts.length - 1].step : null,
  };
}

function verifyChain(receipts, secretKey) {
  let prev = '';
  for (const r of receipts) {
    if (r.prev_hash !== prev) return false;
    if (!verifyReceipt(r, secretKey)) return false;
    prev = r.hash;
  }
  return true;
}

function verifyFold(folded, receipts) {
  const ref = foldReceipts(receipts);
  return folded.root === ref.root && folded.count === ref.count;
}

function proKeyValid(proKey) {
  // TODO (you, when wiring payments): verify against LemonSqueezy license API. Offline here.
  return !!proKey;
}

function exportComplianceReport(folded, receipts, fmt = 'markdown', proKey = null) {
  const pro = proKeyValid(proKey);
  if (fmt === 'json') {
    return JSON.stringify({ report: 'ai-receipt compliance', pro, summary: folded, steps: receipts }, null, 2);
  }
  const lines = ['# ai-receipt — audit report', ''];
  if (pro) lines.push('> **Pro / enterprise report** (SOC2 / EU-AI-Act layout)', '');
  lines.push(
    `- steps: **${folded.count}**`,
    `- root commitment: \`${folded.root}\``,
    `- step range: ${folded.first_step} … ${folded.last_step}`,
    '',
    '| step | model | cost | timestamp | hash (first 16) |',
    '|---|---|---|---|---|'
  );
  for (const r of receipts) {
    lines.push(`| ${r.step} | ${r.model} | ${r.cost} | ${r.timestamp} | \`${r.hash.slice(0, 16)}…\` |`);
  }
  if (!pro) lines.push('', '_Upgrade to Pro for SOC2/EU-AI-Act formatted bundles & signed exports._');
  return lines.join('\n');
}

module.exports = {
  VERSION,
  SPEC,
  createReceipt,
  verifyReceipt,
  verifyChain,
  foldReceipts,
  verifyFold,
  openCommitment,
  exportComplianceReport,
  newSalt,
  // exported for the cross-language test harness:
  _canonValue: canonValue,
  _commit: commit,
};
