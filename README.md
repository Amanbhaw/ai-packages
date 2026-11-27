# ai-packages — three zero-dependency developer packages (npm + PyPI)

Three small, real, tested open-core packages you can publish to npm and PyPI for **₹0**
(GitHub + npm + PyPI are free) and monetize with a Pro tier via LemonSqueezy/Gumroad
(Merchant-of-Record → USD to an Indian bank, no company/GST needed).

Each package has: **working code**, **real passing tests** (npm + PyPI), a **cross-language
test fixture** proving the JS and Python builds produce identical output, a README, and MIT LICENSE.

| package | what it does | why someone pays |
|---|---|---|
| **ai-receipt** | Tamper-evident SHA-256 audit receipts for AI agents; selective disclosure; O(1) fold. | Pro: SOC2 / EU-AI-Act formatted compliance export + signed bundles. |
| **prompt-firewall** | Local guardrail: blocks leaking API keys, PII (Luhn cards, Verhoeff Aadhaar), prompt injection. | Pro: maintained threat-signature packs (new jailbreaks, vendor tokens, regional IDs). |
| **tiny-zk-auth** | Mersenne-31 cross-platform fingerprint + HMAC device auth + Merkle commitments. | Pro: commercial support/SLA + signed release builds for IoT/DePIN teams. |

## Honesty baked in
- `ai-receipt` is a hash chain (standard, auditable) — **not** sold as ZK.
- `prompt-firewall` is deterministic regex+checksum — documented as best-effort, not a full boundary.
- `tiny-zk-auth` is commitments + symmetric auth — **explicitly not** a zero-knowledge proof system.

This honesty is a feature: reviewers on Hacker News / Reddit trust packages that don't overclaim.

## Run every test (verified on this machine)
```bash
# Python (3.8+)
python3 ai-receipt/pypi/tests/test_receipt.py        # 10 passed
python3 prompt-firewall/pypi/tests/test_firewall.py  # 12 passed
python3 tiny-zk-auth/pypi/tests/test_auth.py         # 7 passed

# JavaScript (Node 12+; verified on Node 18)
node ai-receipt/npm/test/test.js        # 10 passed (incl. cross-language fixture)
node prompt-firewall/npm/test/test.js   # 12 passed
node tiny-zk-auth/npm/test/test.js      # 7 passed (incl. cross-language fixture)
```

## Publish checklist (₹0)
Per package, in `npm/` and `pypi/`:
1. Replace `Amanbhaw` in `package.json` / `pyproject.toml` and `Aman Bhawsar` in `LICENSE`.
2. **npm:** `cd npm && npm publish` (needs a free npmjs.com account; `npm login` first).
3. **PyPI:** `cd pypi && python3 -m build && python3 -m twine upload dist/*`
   (needs free pypi.org account + `pip install build twine`).
4. Create a free GitHub repo and push the package folder.
5. On LemonSqueezy/Gumroad, list a "Pro license key" product and wire the `_pro_key_valid` /
   `pro_tier` hook to their license-verification API.

## Realistic expectation
Most packages get little traffic — treat these as **portfolio + credibility** first (they make
grants and consulting much easier), with a real-but-uncertain shot at Pro revenue. The one most
likely to get adoption is **prompt-firewall** (every AI dev fears key/PII leaks) and **ai-receipt**
(compliance pressure is rising). Ship all three; push the one that gets traction.
