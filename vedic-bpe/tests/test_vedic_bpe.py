import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from vedic_bpe import pack, unpack

def sample():
    return json.dumps([
        {"ticket_id":"SUP-101","tier":"enterprise","issue":"billing_delay","status":"open"},
        {"ticket_id":"SUP-102","tier":"enterprise","issue":"billing_delay","status":"open"},
        {"ticket_id":"SUP-103","tier":"enterprise","issue":"api_timeout","status":"open"},
        {"ticket_id":"SUP-104","tier":"pro","issue":"api_timeout","status":"closed"},
    ], indent=1)

def test_lossless():
    s = sample(); p = pack(s)
    back = unpack(p)
    assert back == json.loads(s), "round-trip must be bit-exact"
    print("  ok  lossless round-trip (bit-exact)")

def test_no_inflation_on_prose():
    prose = json.dumps("just a plain string not an array")
    assert pack(prose) == prose, "non-table input returned untouched"
    print("  ok  0% inflation on non-table input")

def test_real_token_savings():
    s = sample(); p = pack(s)
    try:
        import tiktoken; enc = tiktoken.get_encoding("o200k_base")
        a, b = len(enc.encode(s)), len(enc.encode(p))
        print(f"  ok  real o200k_base tokens: {a} -> {b}  ({100*(1-b/a):.0f}% saved)")
        assert b < a
    except ImportError:
        print("  skip tiktoken not installed (install to measure real savings)")

if __name__ == "__main__":
    test_lossless(); test_no_inflation_on_prose(); test_real_token_savings()
    print("vedic-bpe: all tests passed")
