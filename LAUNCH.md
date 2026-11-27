# Launch posts (honest, measured — the trust angle)

## Show HN / r/LocalLLaMA — vedic-bpe
**Title:** Show HN: vedic-bpe – lossless LLM token reducer for repetitive JSON (64–82%, measured)

Most "prompt compressors" delete words and silently change the model's answer.
vedic-bpe is **lossless** and **type-preserving**: it folds repetitive structured
JSON (support tickets, RAG rows, sensor/API logs) into a compact table and recovers
it bit-for-bit.

Measured against real `tiktoken` (o200k_base), lossless round-trip verified:
- 20 repetitive sensor rows: 782 → 138 tokens (82% saved)
- 20 varied rows: 742 → 269 tokens (64% saved)

Zero dependencies, npm + PyPI, byte-identical output across JS and Python.

```python
from vedic_bpe import pack, unpack
packed = pack(json_text)   # send to LLM — still readable, model reasons over it
assert unpack(packed) == json.loads(json_text)   # bit-exact
```

Honest about limits: it only helps on **redundant structured data** — arbitrary prose
can't be compressed (Shannon: a token holds ≤ ~17.6 bits). It never inflates; if it
can't shrink the real token count it returns the input untouched.

The transforms are named after classical Indian math (Panini's Anuvritti key-folding,
Nikhilam/Brahmagupta delta coding) — that's branding; the savings are measured, not claimed.

Repo: https://github.com/Amanbhaw/ai-packages

## r/Python / r/node — one-liner
"npm i vedic-bpe / pip install vedic-bpe — losslessly cut 60–80% of the tokens in
repetitive JSON you send to an LLM. Zero deps, measured vs tiktoken, never inflates."
