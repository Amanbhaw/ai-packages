'use strict';
const assert = require('assert');
const t = require('../src/index.js');

let passed = 0;
function test(name, fn) { fn(); console.log('  ok  ' + name); passed++; }

test('field basic', () => {
  assert.strictEqual(t.m31Add(t.P - 1, 2), 1);
  assert.strictEqual(t.m31Mul(t.P - 1, t.P - 1), 1);
  assert.strictEqual(t.m31Pow(2, 31), 1);  // 2^31 ≡ 1 (mod 2^31-1)
  assert.strictEqual(t.m31Pow(2, 32), 2);
});

test('fingerprint deterministic + sensitive', () => {
  const a = t.fingerprintStr('hello world');
  assert.strictEqual(a, t.fingerprintStr('hello world'));
  assert.notStrictEqual(a, t.fingerprintStr('hello worle'));
  assert.ok(a >= 0 && a < t.P);
  assert.notStrictEqual(t.fingerprintStr('ab'), t.fingerprintStr('ba'));
});

test('auth roundtrip', () => {
  const secret = 'device-shared-secret';
  const ch = t.makeChallenge();
  const resp = t.respond(secret, ch);
  assert.ok(t.verify(secret, ch, resp));
  assert.ok(!t.verify('wrong-secret', ch, resp));
  assert.ok(!t.verify(secret, t.makeChallenge(), resp));
});

test('merkle membership', () => {
  const items = ['alice', 'bob', 'carol', 'dave', 'erin'];
  const root = t.merkleRoot(items);
  items.forEach((it, i) => assert.ok(t.merkleVerify(root, it, t.merkleProve(items, i))));
});

test('merkle rejects non-member', () => {
  const items = ['alice', 'bob', 'carol', 'dave'];
  const root = t.merkleRoot(items);
  const proof = t.merkleProve(items, 1);
  assert.ok(t.merkleVerify(root, 'bob', proof));
  assert.ok(!t.merkleVerify(root, 'mallory', proof));
  const bad = [['00'.repeat(32), proof[0][1]], ...proof.slice(1)];
  assert.ok(!t.merkleVerify(root, 'bob', bad));
});

test('odd count', () => {
  const items = ['a', 'b', 'c'];
  const root = t.merkleRoot(items);
  items.forEach((it, i) => assert.ok(t.merkleVerify(root, it, t.merkleProve(items, i))));
});

// --- CROSS-LANGUAGE: values produced by the Python tiny_zk_auth package ---
test('cross-language matches python', () => {
  assert.strictEqual(t.fingerprintStr('hello world'), 1951127573);
  assert.strictEqual(t.respond('device-shared-secret', 'abcd1234'),
    'a4aba254228b9495cb4b7d061721943542e955dedd14cc70a946cdadc0ddd7ce');
  assert.strictEqual(t.merkleRoot(['alice', 'bob', 'carol', 'dave', 'erin']),
    '886cb81d8d8479d13f5c2c2cc2f5c3f8ed297bf58c16dc73f4d5e3a542ea2f84');
  // the python-generated proof for index 2 must verify here too
  const pyProof = [
    ['262bdada8a2e394abb74edde5b72151581231631a2959b611d54c473639a40f9', 'R'],
    ['3bc1199d175a1cfc2c3fe16b1920a93ca6397484cbda581a4b7c6b920f93ba83', 'L'],
    ['26d700380aa716bbef8ee6dd6539a9ea797f18c22ccef13f0419c395c8e6232a', 'R'],
  ];
  assert.ok(t.merkleVerify('886cb81d8d8479d13f5c2c2cc2f5c3f8ed297bf58c16dc73f4d5e3a542ea2f84', 'carol', pyProof));
});

console.log('\n' + passed + ' tests passed');
