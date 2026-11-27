"""Real unit + adversarial tamper tests for ai_receipt. Run: python3 -m pytest (or this file)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import ai_receipt as ar  # noqa: E402


def make_chain(secret=None):
    r = []
    prev = ""
    steps = [
        ("gpt-4o", "What is 2+2?", "4", None, 12),
        ("gpt-4o", "And times 3?", "12", [{"tool": "calc"}], 15),
        ("claude-opus-4-8", "Summarize", "done", None, 40),
    ]
    for i, (model, p, resp, tc, cost) in enumerate(steps):
        rec = ar.create_receipt(
            step=i, model=model, prompt=p, response=resp, tool_calls=tc,
            cost=cost, timestamp=1700000000 + i, prev_hash=prev, salt=f"salt{i}",
            secret_key=secret,
        )
        r.append(rec)
        prev = rec["hash"]
    return r


def test_single_receipt_verifies():
    r = ar.create_receipt(0, "gpt-4o", "hi", "hello", timestamp=1700000000, salt="s")
    assert ar.verify_receipt(r)


def test_no_payload_leak():
    r = ar.create_receipt(0, "gpt-4o", "SECRET-PROMPT", "SECRET-RESP", timestamp=1, salt="s")
    blob = str(r)
    assert "SECRET-PROMPT" not in blob and "SECRET-RESP" not in blob


def test_selective_disclosure():
    r = ar.create_receipt(0, "gpt-4o", "the answer", "42", timestamp=1, salt="mysalt")
    assert ar.open_commitment(r["prompt_commit"], "the answer", "mysalt")
    assert not ar.open_commitment(r["prompt_commit"], "wrong", "mysalt")
    assert not ar.open_commitment(r["prompt_commit"], "the answer", "badsalt")


def test_chain_verifies():
    assert ar.verify_chain(make_chain())


def test_tamper_field_breaks_chain():
    r = make_chain()
    r[1]["cost"] = 999  # tamper a past cost
    assert not ar.verify_chain(r)
    assert not ar.verify_receipt(r[1])


def test_tamper_reorder_breaks_chain():
    r = make_chain()
    r[1], r[2] = r[2], r[1]  # reorder
    assert not ar.verify_chain(r)


def test_insert_fake_step_breaks_chain():
    r = make_chain()
    fake = ar.create_receipt(99, "gpt-4o", "x", "y", timestamp=5, salt="z", prev_hash=r[1]["hash"])
    r.insert(2, fake)
    assert not ar.verify_chain(r)  # fake's prev is fine but next link now broken


def test_hmac_signing():
    r = make_chain(secret="topsecret")
    assert ar.verify_chain(r, secret_key="topsecret")
    assert not ar.verify_chain(r, secret_key="wrongkey")
    # signed receipt without key must fail
    assert not ar.verify_receipt(r[0])


def test_fold_is_constant_size_and_binds():
    r = make_chain()
    f = ar.fold_receipts(r)
    assert len(f["root"]) == 64 and f["count"] == 3
    assert ar.verify_fold(f, r)
    # Any change to a receipt hash must change the fold root (binding).
    r2 = make_chain()
    r2[0] = dict(r2[0], hash="00" * 32)
    assert ar.fold_receipts(r2)["root"] != f["root"]
    assert not ar.verify_fold(f, r2)


def test_report_pro_gate():
    r = make_chain()
    f = ar.fold_receipts(r)
    free = ar.export_compliance_report(f, r)
    pro = ar.export_compliance_report(f, r, pro_key="LS-xxxx")
    assert "Upgrade to Pro" in free
    assert "Pro / enterprise" in pro


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
        passed += 1
    print(f"\n{passed}/{len(fns)} tests passed")
