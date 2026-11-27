'use strict';
// Real unit + adversarial + cross-language tests. Run: node test/test.js
const assert = require('assert');
const ar = require('../src/index.js');

let passed = 0;
function test(name, fn) {
  fn();
  console.log('  ok  ' + name);
  passed++;
}

function makeChain(secret) {
  const steps = [
    { model: 'gpt-4o', prompt: 'What is 2+2?', response: '4', toolCalls: null, cost: 12 },
    { model: 'gpt-4o', prompt: 'And times 3?', response: '12', toolCalls: [{ tool: 'calc' }], cost: 15 },
    { model: 'claude-opus-4-8', prompt: 'Summarize', response: 'done', toolCalls: null, cost: 40 },
  ];
  const out = [];
  let prev = '';
  steps.forEach((s, i) => {
    const r = ar.createReceipt({ step: i, ...s, timestamp: 1700000000 + i, prevHash: prev, salt: 'salt' + i, secretKey: secret });
    out.push(r);
    prev = r.hash;
  });
  return out;
}

test('single receipt verifies', () => {
  const r = ar.createReceipt({ step: 0, model: 'gpt-4o', prompt: 'hi', response: 'hello', timestamp: 1700000000, salt: 's' });
  assert.ok(ar.verifyReceipt(r));
});

test('no payload leak', () => {
  const r = ar.createReceipt({ step: 0, model: 'gpt-4o', prompt: 'SECRET-PROMPT', response: 'SECRET-RESP', timestamp: 1, salt: 's' });
  const blob = JSON.stringify(r);
  assert.ok(!blob.includes('SECRET-PROMPT') && !blob.includes('SECRET-RESP'));
});

test('selective disclosure', () => {
  const r = ar.createReceipt({ step: 0, model: 'gpt-4o', prompt: 'the answer', response: '42', timestamp: 1, salt: 'mysalt' });
  assert.ok(ar.openCommitment(r.prompt_commit, 'the answer', 'mysalt'));
  assert.ok(!ar.openCommitment(r.prompt_commit, 'wrong', 'mysalt'));
  assert.ok(!ar.openCommitment(r.prompt_commit, 'the answer', 'badsalt'));
});

test('chain verifies', () => assert.ok(ar.verifyChain(makeChain())));

test('tamper field breaks chain', () => {
  const r = makeChain();
  r[1].cost = 999;
  assert.ok(!ar.verifyChain(r));
  assert.ok(!ar.verifyReceipt(r[1]));
});

test('reorder breaks chain', () => {
  const r = makeChain();
  [r[1], r[2]] = [r[2], r[1]];
  assert.ok(!ar.verifyChain(r));
});

test('hmac signing', () => {
  const r = makeChain('topsecret');
  assert.ok(ar.verifyChain(r, 'topsecret'));
  assert.ok(!ar.verifyChain(r, 'wrongkey'));
  assert.ok(!ar.verifyReceipt(r[0])); // signed receipt needs key
});

test('fold constant size + binds', () => {
  const r = makeChain();
  const f = ar.foldReceipts(r);
  assert.strictEqual(f.root.length, 64);
  assert.strictEqual(f.count, 3);
  assert.ok(ar.verifyFold(f, r));
  const r2 = makeChain();
  r2[0] = Object.assign({}, r2[0], { hash: '00'.repeat(32) });
  assert.notStrictEqual(ar.foldReceipts(r2).root, f.root);
});

test('report pro gate', () => {
  const r = makeChain();
  const f = ar.foldReceipts(r);
  assert.ok(ar.exportComplianceReport(f, r).includes('Upgrade to Pro'));
  assert.ok(ar.exportComplianceReport(f, r, 'markdown', 'LS-xxxx').includes('Pro / enterprise'));
});

// --- CROSS-LANGUAGE: these exact hashes were produced by the Python ai_receipt package ---
test('cross-language hash matches python', () => {
  const r = ar.createReceipt({
    step: 0, model: 'gpt-4o', prompt: 'hello world', response: 'hi there',
    toolCalls: [{ tool: 'calc', args: [1, 2] }], cost: 123, timestamp: 1700000000,
    prevHash: '', salt: 'fixedsalt', secretKey: 'k',
  });
  assert.strictEqual(r.prompt_commit, '7e8c63ca92a5aa3eb4a72079ba1c57ab01ffd8b27368e7d58c9d12ed00b4c618');
  assert.strictEqual(r.response_commit, '9a5777b302f1602f6e6e638a9c8e78a5f7154cceaf9462a2ab1edb06d8c1f745');
  assert.strictEqual(r.tool_commit, '9ab1c95d2216e505db927bd9bcdf14fe9b68cb890f0eec496a2577f8f22478c7');
  assert.strictEqual(r.hash, '5a0d7d6af57cdb5c5158c0aa8db3fa534b0556a3cd55977af686801cd7fc8055');
  assert.strictEqual(r.sig, '06307cab805f02dc65b57d2cd33c6e0c6f07cd79cbfd190c13b6e2a7fb6ee479');
  assert.strictEqual(ar.foldReceipts([r]).root, '64c64aa8a43959c0d27258d1c75a5a4a927b96dff3e0ab44a8b9e8268311ac7d');
});

console.log('\n' + passed + ' tests passed');
