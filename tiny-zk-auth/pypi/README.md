# tiny-zk-auth

**Tiny, zero-dependency authentication + commitment toolkit** that runs **byte-identically**
in the browser, Node.js, Python, and a **$1 microcontroller** (the field core is integer-only).

```
npm i tiny-zk-auth        # Node >= 12 (browser: field + fingerprint need no crypto)
pip install tiny-zk-auth  # Python >= 3.8
```

Three real pieces:

### 1. Mersenne-31 fingerprint (fast, cross-platform integrity)
```js
const { fingerprintStr } = require('tiny-zk-auth');
fingerprintStr('hello world');   // 1951127573  — same number in Python, Node, browser, MCU
```
A polynomial (Horner) fingerprint over `p = 2³¹−1`. Deterministic everywhere, great for
integrity / dedup / cache keys on tiny devices. **Not** a cryptographic hash (≈2⁻³¹ collision) —
use it for integrity, not as a security boundary.

### 2. HMAC-SHA256 device auth (the real security)
```js
const ch = makeChallenge();            // server
const resp = respond(secret, ch);      // device
verify(secret, ch, resp);              // server -> true
```
Symmetric shared-secret challenge-response, replay-resistant via random challenges.

### 3. Merkle commitment (prove one, hide the rest)
```js
const root = merkleRoot(['alice','bob','carol','dave']);  // commit, reveals nothing
const proof = merkleProve(items, 1);
merkleVerify(root, 'bob', proof);       // true — and the proof leaks no other member
```

## Honest scope (read this)
Despite the name, **this is not a zero-knowledge *proof system*.** A 31-bit field cannot give
sound ZK. What you get is: a fast cross-platform **fingerprint**, **symmetric (HMAC) auth**, and
**Merkle commitments** with selective disclosure. That combination is genuinely useful for IoT /
DePIN / Web3 device identity and tamper-evident sets — just don't market it as "proving statements
in zero knowledge." If you need real ZK, that's a separate, heavier lattice/elliptic construction.

## Cross-platform guarantee
The JS and Python packages produce identical fingerprints, HMAC responses and Merkle roots —
verified by a cross-language test fixture in both test suites.

## Open-core
- **Free (MIT):** everything above.
- **Pro:** commercial license + support tier (`proTier` flag). It gates **no cryptography** —
  honesty: the crypto is all free. You sell support, SLAs, and signed release builds.

## Tests
```
cd npm  && node test/test.js          # 7 tests incl. cross-language fixture
cd pypi && python3 tests/test_auth.py # 7 tests
```

## License
MIT.
