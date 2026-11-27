"""ai-receipt — zero-dependency cryptographic audit receipts for AI agents / LLM calls.

Standard, tamper-evident hash-chain audit log (same primitive Git and blockchains use).
No ZK, no magic: SHA-256 over a canonical byte string. Receipts are *cross-verifiable*
with the npm `ai-receipt` package because the canonical string and hashing are identical.

Core ideas:
  * Each step is committed to a 32-byte SHA-256 hash of a canonical field string.
  * Each receipt links to the previous one (`prev_hash`), forming a tamper-evident chain:
    changing any past field breaks every later hash.
  * Payloads (prompt / response / tool calls) are stored as *salted commitments*, so the
    receipt proves what happened at time T without leaking the sensitive text
    (selective disclosure: reveal (value, salt) later to open a commitment).
  * `fold_receipts` collapses N steps into one constant-size (O(1)) summary root.
  * Optional HMAC-SHA256 signing with a secret key.

MIT licensed. Free core; a Pro compliance export is a thin wrapper on top (see exportComplianceReport).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from typing import Any, Dict, List, Optional, Sequence

__version__ = "0.1.0"
SPEC = "ai-receipt/1"  # canonical format version; bump only on breaking change
_US = "\x1f"  # ASCII unit separator: delimiter that cannot appear in normal text


def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _commit(value: Any, salt: str) -> str:
    """Salted commitment of a value. Hiding (salt is secret) and binding (SHA-256)."""
    text = "" if value is None else _canon_value(value)
    return _h((salt + _US + text).encode("utf-8"))


def _canon_value(value: Any) -> str:
    """Deterministic, language-portable string form of a value (no JSON float ambiguity)."""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int,)):
        return str(value)
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canon_value(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(
            k + ":" + _canon_value(value[k]) for k in sorted(value.keys())
        ) + "}"
    # Fallback: stringify. Avoid passing raw floats if you need cross-language hashes.
    return str(value)


def new_salt() -> str:
    """Random 128-bit hex salt for a commitment."""
    return os.urandom(16).hex()


def _canonical_string(
    step: int,
    model: str,
    prompt_commit: str,
    response_commit: str,
    tool_commit: str,
    cost: int,
    timestamp: int,
    prev_hash: str,
) -> str:
    return _US.join([
        SPEC,
        str(step),
        model,
        prompt_commit,
        response_commit,
        tool_commit,
        str(cost),
        str(timestamp),
        prev_hash,
    ])


def create_receipt(
    step: int,
    model: str,
    prompt: Any,
    response: Any,
    tool_calls: Any = None,
    cost: int = 0,
    timestamp: Optional[int] = None,
    prev_hash: str = "",
    salt: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Create one tamper-evident receipt for an agent step.

    `cost` is an integer (e.g. micro-dollars or tokens) to keep hashes language-portable.
    `timestamp` is integer epoch seconds (pass it explicitly for reproducible receipts).
    Returns a dict; the sensitive payload is NOT stored, only salted commitments.
    """
    if timestamp is None:
        timestamp = int(time.time())
    if salt is None:
        salt = new_salt()

    prompt_commit = _commit(prompt, salt)
    response_commit = _commit(response, salt)
    tool_commit = _commit(tool_calls, salt)

    canonical = _canonical_string(
        step, model, prompt_commit, response_commit, tool_commit, cost, timestamp, prev_hash
    )
    h = _h(canonical.encode("utf-8"))

    receipt: Dict[str, Any] = {
        "spec": SPEC,
        "step": step,
        "model": model,
        "prompt_commit": prompt_commit,
        "response_commit": response_commit,
        "tool_commit": tool_commit,
        "cost": cost,
        "timestamp": timestamp,
        "prev_hash": prev_hash,
        "hash": h,
    }
    if secret_key is not None:
        receipt["sig"] = hmac.new(
            secret_key.encode("utf-8"), h.encode("utf-8"), hashlib.sha256
        ).hexdigest()
    return receipt


def _recompute_hash(receipt: Dict[str, Any]) -> str:
    canonical = _canonical_string(
        receipt["step"],
        receipt["model"],
        receipt["prompt_commit"],
        receipt["response_commit"],
        receipt["tool_commit"],
        receipt["cost"],
        receipt["timestamp"],
        receipt["prev_hash"],
    )
    return _h(canonical.encode("utf-8"))


def verify_receipt(receipt: Dict[str, Any], secret_key: Optional[str] = None) -> bool:
    """Return True iff the receipt's hash (and signature, if present) is internally consistent."""
    if receipt.get("spec") != SPEC:
        return False
    if _recompute_hash(receipt) != receipt.get("hash"):
        return False
    if "sig" in receipt:
        if secret_key is None:
            return False
        expected = hmac.new(
            secret_key.encode("utf-8"), receipt["hash"].encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, receipt["sig"]):
            return False
    return True


def open_commitment(commit: str, value: Any, salt: str) -> bool:
    """Selective disclosure: prove a committed payload without having leaked it earlier."""
    return hmac.compare_digest(_commit(value, salt), commit)


def fold_receipts(receipts: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Fold N receipts into one constant-size O(1) summary root (sequential hash accumulator)."""
    root = ""
    for r in receipts:
        root = _h((root + r["hash"]).encode("utf-8"))
    return {
        "spec": SPEC,
        "count": len(receipts),
        "root": root,
        "first_step": receipts[0]["step"] if receipts else None,
        "last_step": receipts[-1]["step"] if receipts else None,
    }


def verify_chain(receipts: Sequence[Dict[str, Any]], secret_key: Optional[str] = None) -> bool:
    """Verify every receipt and that each links to the previous (prev_hash == prior hash)."""
    prev = ""
    for r in receipts:
        if r.get("prev_hash") != prev:
            return False
        if not verify_receipt(r, secret_key=secret_key):
            return False
        prev = r["hash"]
    return True


def verify_fold(folded: Dict[str, Any], receipts: Sequence[Dict[str, Any]]) -> bool:
    """Check a folded summary matches the given receipts."""
    ref = fold_receipts(receipts)
    return (
        folded.get("root") == ref["root"]
        and folded.get("count") == ref["count"]
    )


def export_compliance_report(
    folded: Dict[str, Any],
    receipts: Sequence[Dict[str, Any]],
    fmt: str = "markdown",
    pro_key: Optional[str] = None,
) -> str:
    """Audit artifact. Free: plain JSON/Markdown summary. Pro (valid key): adds a signed header.

    The gate here is a *placeholder for your commercial license check* — it does NOT phone home.
    Replace `_pro_key_valid` with your LemonSqueezy license verification when you wire payments.
    """
    import json

    pro = _pro_key_valid(pro_key)
    if fmt == "json":
        return json.dumps(
            {
                "report": "ai-receipt compliance",
                "pro": pro,
                "summary": folded,
                "steps": receipts,
            },
            indent=2,
        )

    lines = ["# ai-receipt — audit report", ""]
    if pro:
        lines += ["> **Pro / enterprise report** (SOC2 / EU-AI-Act layout)", ""]
    lines += [
        f"- steps: **{folded.get('count')}**",
        f"- root commitment: `{folded.get('root')}`",
        f"- step range: {folded.get('first_step')} … {folded.get('last_step')}",
        "",
        "| step | model | cost | timestamp | hash (first 16) |",
        "|---|---|---|---|---|",
    ]
    for r in receipts:
        lines.append(
            f"| {r['step']} | {r['model']} | {r['cost']} | {r['timestamp']} | `{r['hash'][:16]}…` |"
        )
    if not pro:
        lines += ["", "_Upgrade to Pro for SOC2/EU-AI-Act formatted bundles & signed exports._"]
    return "\n".join(lines)


def _pro_key_valid(pro_key: Optional[str]) -> bool:
    # TODO (you, when wiring payments): verify against LemonSqueezy license API.
    # Intentionally offline + no network. Any non-empty key is treated as "pro" in this OSS build.
    return bool(pro_key)


__all__ = [
    "create_receipt",
    "verify_receipt",
    "verify_chain",
    "fold_receipts",
    "verify_fold",
    "open_commitment",
    "export_compliance_report",
    "new_salt",
    "__version__",
]
