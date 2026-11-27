# vedic-bpe

**Lossless LLM token reducer for repetitive structured JSON.** Zero dependencies.
Bit-exact round-trip (types preserved). 0% token-inflation guarantee.

Named after classical Indian mathematics (**branding**); the transforms are standard
and **measured against real `tiktoken` (o200k_base)** — not claimed.

| transform | classical name | what it does |
|---|---|---|
| key-folding + row inheritance | **Anuvritti** (Panini, Ashtadhyayi) | repeated object keys → one header; a cell equal to the one above → `.` |
| base-anchor delta coding | **Nikhilam / Brahmagupta** (finite differences) | string ID columns `SUP-101, SUP-102` → base `SUP-100` + delta `1, 2` |

## Measured results (real `tiktoken` o200k_base, lossless verified)
| input | before | after | saved |
|---|---|---|---|
| 20 highly-repetitive sensor rows | 782 tok | 138 tok | **82%** |
| 20 varied rows | 742 tok | 269 tok | **64%** |
| 4-row support tickets | 138 tok | 48 tok | **65%** |

Savings **scale with redundancy** (Shannon limit: a token holds ≤ log₂(V) ≈ 17.6 bits,
so *arbitrary* text can't be squeezed — only redundant structured data can).

## Usage
```python
from vedic_bpe import pack, unpack
packed = pack(json_text)      # send `packed` to the LLM (still human/LLM-readable)
original = unpack(packed)     # bit-exact recovery
```

## Honest scope — what this is NOT
- **Not** a compressor for arbitrary prose (information theory forbids it).
- Works on **arrays of flat JSON objects with shared keys and scalar values**
  (support tickets, RAG metadata rows, API/sensor logs). Values must not contain `|` or newline.
- Output stays **readable** so the model can still reason over it — unlike bit-packing
  into opaque glyphs (which saves tokens but the model can't understand).
- `pack()` **never inflates**: if it can't shrink the real token count, it returns the input untouched.

MIT © Aman Bhawsar
