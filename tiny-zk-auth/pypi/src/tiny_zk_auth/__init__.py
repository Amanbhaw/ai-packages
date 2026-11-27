"""tiny-zk-auth — tiny, zero-dependency authentication + commitment toolkit.

Runs identically in the browser, Node.js, Python, and a $1 Cortex-M0 / ESP32 (the field
core is integer-only). Three real pieces:

  1. Mersenne-31 field + `fingerprint()` — a fast polynomial (Horner) fingerprint over
     p = 2**31 - 1. Deterministic and byte-identical across all platforms. Great for
     integrity / dedup / cache keys on tiny devices.
     *Honest note:* a 31-bit fingerprint is NOT a cryptographic-strength hash
     (~2**-31 collision). Use it for integrity, not as a security boundary.

  2. HMAC-SHA256 challenge-response device auth — the actual cryptographic security.
     `make_challenge()`, `respond(secret, challenge)`, `verify(secret, challenge, resp)`.
     Symmetric (shared-secret), replay-resistant via random challenges. This is a MAC,
     not public-key and NOT a zero-knowledge proof.

  3. Merkle commitment — `merkle_root()`, `merkle_prove()`, `merkle_verify()`. Commit to a
     set, later prove ONE member without revealing the others (selective disclosure).

HONEST SCOPE: despite the name, this package does not implement a zero-knowledge *proof
system* (a 31-bit field cannot give sound ZK). It gives commitments + symmetric auth. If you
need real ZK, that is a separate, heavier lattice/elliptic construction.

MIT core; a commercial license key gates nothing cryptographic — it is a support/commercial
tier flag only.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import List, Optional, Sequence, Tuple

__version__ = "0.1.0"

P = (1 << 31) - 1  # Mersenne-31 prime, 2147483647


# ----------------------------- Mersenne-31 field -----------------------------

def m31_add(a: int, b: int) -> int:
    s = (a + b) % P
    return s


def m31_mul(a: int, b: int) -> int:
    return (a * b) % P


def m31_pow(a: int, e: int) -> int:
    return pow(a % P, e, P)


def fingerprint(data: bytes, base: int = 2654435761 % P) -> int:
    """Polynomial (Horner) fingerprint over Mersenne-31. Byte-identical on every platform.

    acc = ((acc * base) + byte) mod P, iterated over bytes, seeded with the length.
    Deterministic integrity checksum (NOT cryptographically strong).
    """
    acc = (len(data) + 1) % P
    base %= P
    for byte in data:
        acc = (acc * base + (byte + 1)) % P
    return acc


def fingerprint_str(text: str, base: int = 2654435761 % P) -> int:
    return fingerprint(text.encode("utf-8"), base)


# ----------------------------- HMAC challenge-response auth -----------------------------

def make_challenge(nbytes: int = 32) -> str:
    """Random challenge (hex). The server stores it and expects a matching response."""
    return os.urandom(nbytes).hex()


def respond(secret: str, challenge: str) -> str:
    """Device side: HMAC-SHA256(secret, challenge) -> hex response."""
    return hmac.new(secret.encode("utf-8"), challenge.encode("utf-8"), hashlib.sha256).hexdigest()


def verify(secret: str, challenge: str, response: str) -> bool:
    """Server side: constant-time check of a device response."""
    return hmac.compare_digest(respond(secret, challenge), response)


# ----------------------------- Merkle commitment -----------------------------

def _leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + a + b).digest()


def _leaves(items: Sequence[bytes]) -> List[bytes]:
    return [_leaf(x if isinstance(x, (bytes, bytearray)) else str(x).encode("utf-8")) for x in items]


def merkle_root(items: Sequence[bytes]) -> str:
    """Commit to an ordered list; returns the root hex. Hides every item."""
    if not items:
        return hashlib.sha256(b"\x02empty").hexdigest()
    level = _leaves(items)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_node(level[i], level[i + 1]))
            else:
                nxt.append(_node(level[i], level[i]))  # duplicate last (odd count)
        level = nxt
    return level[0].hex()


def merkle_prove(items: Sequence[bytes], index: int) -> List[Tuple[str, str]]:
    """Membership proof for items[index]: list of (sibling_hex, side) where side in L/R."""
    if index < 0 or index >= len(items):
        raise IndexError("index out of range")
    level = _leaves(items)
    proof: List[Tuple[str, str]] = []
    idx = index
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            nxt.append(_node(left, right))
        sib_i = idx ^ 1
        if sib_i >= len(level):
            sib_i = idx  # duplicated last node
        if sib_i > idx:
            proof.append((level[sib_i].hex(), "R"))
        else:
            proof.append((level[sib_i].hex(), "L"))
        idx //= 2
        level = nxt
    return proof


def merkle_verify(root: str, item: bytes, proof: Sequence[Tuple[str, str]]) -> bool:
    """Verify item is in the committed set, revealing nothing about the other items."""
    h = _leaf(item if isinstance(item, (bytes, bytearray)) else str(item).encode("utf-8"))
    for sib_hex, side in proof:
        sib = bytes.fromhex(sib_hex)
        if side == "R":
            h = _node(h, sib)
        else:
            h = _node(sib, h)
    return hmac.compare_digest(h.hex(), root)


def pro_tier(license_key: Optional[str]) -> bool:
    """Commercial support/tier flag only. No cryptographic effect. Wire to your license API."""
    return bool(license_key)


__all__ = [
    "P", "m31_add", "m31_mul", "m31_pow", "fingerprint", "fingerprint_str",
    "make_challenge", "respond", "verify",
    "merkle_root", "merkle_prove", "merkle_verify", "pro_tier", "__version__",
]
