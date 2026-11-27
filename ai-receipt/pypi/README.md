# ai-receipt

**Zero-dependency cryptographic audit receipts for AI agents & LLM pipelines.**
Prove *what* prompt, model, tool call and output happened at time `T` — tamper-evident,
offline, < 1 ms, with no sensitive payload stored. Available on **npm** and **PyPI**, and
receipts made by one are byte-for-byte verifiable by the other.

```
npm i ai-receipt          #  JavaScript / TypeScript (Node >= 14)
pip install ai-receipt    #  Python >= 3.9
```

## Quickstart (JS)
```js
const { createReceipt, verifyChain, foldReceipts } = require('ai-receipt');

let prev = '';
const log = [];
for (const step of agentSteps) {
  const r = createReceipt({
    step: step.i, model: 'gpt-4o',
    prompt: step.prompt, response: step.output, toolCalls: step.tools,
    cost: step.microDollars, prevHash: prev, secretKey: process.env.AUDIT_KEY,
  });
  log.push(r); prev = r.hash;
}

verifyChain(log, process.env.AUDIT_KEY);   // true — nothing was tampered
const summary = foldReceipts(log);          // one 32-byte root for the whole trajectory
```

## Quickstart (Python)
```python
from ai_receipt import create_receipt, verify_chain, fold_receipts

prev, log = "", []
for s in agent_steps:
    r = create_receipt(step=s.i, model="gpt-4o", prompt=s.prompt,
                        response=s.output, tool_calls=s.tools,
                        cost=s.micro_dollars, prev_hash=prev, secret_key=KEY)
    log.append(r); prev = r["hash"]

assert verify_chain(log, secret_key=KEY)
summary = fold_receipts(log)
```

## What it actually is (honest)
- A **SHA-256 hash chain** — the same tamper-evidence Git commits and blockchains use.
  Change any past field and every later `hash` breaks. **This is not zero-knowledge**; it is
  a clean, standard, auditable primitive, which is exactly why you can trust it.
- Payloads are stored as **salted commitments**, never in plaintext — so the receipt proves
  what happened without leaking the prompt/PII. Reveal `(value, salt)` later to *open* a
  commitment (selective disclosure).
- `foldReceipts` collapses an N-step trajectory into one **constant-size** root.
- Optional **HMAC-SHA256** signing binds the log to a secret key.

## Why it's useful
US/EU AI startups get asked by banks, auditors and the EU AI Act: *"prove this AI output and
its audit log weren't tampered with."* `ai-receipt` is a 2-line answer with zero dependencies
and no data leaving the process.

## Open-core
- **Free (MIT):** everything above — receipts, chain/fold verification, selective disclosure, signing.
- **Pro (commercial license key):** `exportComplianceReport(..., proKey)` emits SOC2 / EU-AI-Act
  formatted bundles with a signed header. The key check is a documented hook
  (`_pro_key_valid`) you wire to your license provider (e.g. LemonSqueezy) before selling —
  it does **not** phone home in this repo.

## Tests
```
cd npm  && node test/test.js          # 11 tests incl. a cross-language hash fixture
cd pypi && python3 tests/test_receipt.py   # 10 tests
```
The JS cross-language test asserts the exact hashes produced by the Python package, so the
two implementations are provably interoperable.

## License
MIT.
