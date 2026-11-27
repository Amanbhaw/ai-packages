# prompt-firewall

**Local, zero-dependency guardrail for LLM apps.** Catch leaking **API keys / secrets**,
**PII** (credit cards *validated by Luhn*, India Aadhaar *validated by Verhoeff*, SSN, email,
phone, IP) and **prompt-injection** attempts — **before** the text is sent to an LLM, logged,
or stored. Pure regex + checksum math: **no network calls, sub-millisecond, nothing leaves the host.**

```
npm i prompt-firewall       # Node >= 12
pip install prompt-firewall # Python >= 3.8
```

## Quickstart (JS)
```js
const { guard, redact, scan } = require('prompt-firewall');

guard(userInput);                 // throws FirewallBlocked on a card / key / injection
const clean = redact(userInput);  // or mask findings and continue
const report = scan(userInput);   // or inspect: report.findings, report.blocked, report.safe
```

## Quickstart (Python)
```python
from prompt_firewall import guard, redact, scan, FirewallBlocked

try:
    guard(user_input)             # raises on high/critical findings
except FirewallBlocked as e:
    for f in e.result.findings:
        print(f.rule, f.severity, f.start, f.end)

clean = redact(user_input)        # "[REDACTED:credit_card] ..."
```

## Why it's real (not just regex)
- **Credit cards** are confirmed with the **Luhn** checksum, so a random 16-digit order number
  is *not* flagged — far fewer false positives than naive regex scanners.
- **Aadhaar** numbers are confirmed with the **Verhoeff** checksum (the real algorithm UIDAI uses).
- Secret patterns cover current formats: `sk-…`, `sk-ant-…`, `AKIA…/ASIA…`, `ghp_…`, `xox…`,
  `AIza…`, PEM private-key blocks, JWTs.
- Findings carry exact `start`/`end` offsets and a severity, so you can redact precisely.

## Open-core
- **Free (MIT):** all detectors above, `scan` / `redact` / `guard`, custom signatures.
- **Pro (threat-signatures pack):** ship curated, versioned signature sets (new jailbreak
  phrasings, cloud-vendor tokens, regional IDs) and load them with
  `scan(text, {extraSignatures})`. Sell the maintained pack + updates; the loader is free.

## Tests
```
cd npm  && node test/test.js             # 13 tests
cd pypi && python3 tests/test_firewall.py  # 12 tests
```

## Honest limits
Regex/heuristic detection is **best-effort**: it will miss novel obfuscations and can false-positive
on odd text. Treat it as a fast first layer, not a complete security boundary. No ML, no guarantee
of catching every injection — by design it is deterministic, auditable and offline.

## License
MIT.
