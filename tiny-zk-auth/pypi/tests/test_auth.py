import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import tiny_zk_auth as t  # noqa: E402


def test_field_basic():
    assert t.m31_add(t.P - 1, 2) == 1
    assert t.m31_mul(t.P - 1, t.P - 1) == 1  # (-1)*(-1)=1
    assert t.m31_pow(2, 31) == 1             # 2^31 ≡ 1 (mod 2^31-1)
    assert t.m31_pow(2, 32) == 2             # 2^32 ≡ 2 (mod 2^31-1)


def test_fingerprint_deterministic_and_sensitive():
    a = t.fingerprint_str("hello world")
    assert a == t.fingerprint_str("hello world")      # deterministic
    assert a != t.fingerprint_str("hello worle")      # 1-char change -> different
    assert 0 <= a < t.P
    assert t.fingerprint_str("ab") != t.fingerprint_str("ba")  # order matters


def test_auth_roundtrip():
    secret = "device-shared-secret"
    ch = t.make_challenge()
    resp = t.respond(secret, ch)
    assert t.verify(secret, ch, resp)
    assert not t.verify("wrong-secret", ch, resp)
    assert not t.verify(secret, t.make_challenge(), resp)  # replay with new challenge fails


def test_merkle_membership():
    items = [b"alice", b"bob", b"carol", b"dave", b"erin"]
    root = t.merkle_root(items)
    for i, it in enumerate(items):
        proof = t.merkle_prove(items, i)
        assert t.merkle_verify(root, it, proof)


def test_merkle_rejects_non_member():
    items = [b"alice", b"bob", b"carol", b"dave"]
    root = t.merkle_root(items)
    proof = t.merkle_prove(items, 1)
    assert t.merkle_verify(root, b"bob", proof)
    assert not t.merkle_verify(root, b"mallory", proof)  # wrong item
    # tampered proof fails
    if proof:
        bad = [("00" * 32, proof[0][1])] + list(proof[1:])
        assert not t.merkle_verify(root, b"bob", bad)


def test_merkle_hides_others():
    # The proof for one item must not contain any other item's plaintext.
    items = [b"SECRET-alice", b"SECRET-bob", b"SECRET-carol", b"SECRET-dave"]
    proof = t.merkle_prove(items, 0)
    blob = str(proof)
    for other in items[1:]:
        assert other.decode() not in blob


def test_odd_count():
    items = [b"a", b"b", b"c"]
    root = t.merkle_root(items)
    for i, it in enumerate(items):
        assert t.merkle_verify(root, it, t.merkle_prove(items, i))


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
