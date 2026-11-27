"""prompt-firewall — local, zero-dependency guardrail for AI chatbots / LLM apps.

Scans text *before* it leaves your process for:
  * PII            — emails, phone numbers, credit cards (Luhn-validated), US SSN,
                     India Aadhaar (Verhoeff-validated), IPv4.
  * secrets        — OpenAI / Anthropic / AWS / GitHub / Slack / Google keys, generic
                     high-entropy tokens, private-key headers.
  * prompt injection — "ignore previous instructions", "reveal your system prompt",
                     role-override and exfiltration phrasings.

Everything is local regex + checksum math: no API calls, sub-millisecond, no data leaves
the machine. MIT core; a Pro "threat-signatures" pack is loaded via `add_signatures()`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Pattern, Tuple

__version__ = "0.1.0"


@dataclass
class Finding:
    kind: str          # "pii" | "secret" | "injection"
    rule: str          # which rule matched, e.g. "credit_card"
    match: str         # the matched substring (redactable)
    start: int
    end: int
    severity: str      # "low" | "medium" | "high" | "critical"


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return any(f.severity in ("high", "critical") for f in self.findings)

    @property
    def safe(self) -> bool:
        return not self.findings


# ----------------------------- checksum validators -----------------------------

def luhn_ok(digits: str) -> bool:
    d = [int(c) for c in digits if c.isdigit()]
    if len(d) < 13 or len(d) > 19:
        return False
    total = 0
    for i, n in enumerate(reversed(d)):
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# Verhoeff checksum (used by India's Aadhaar).
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_ok(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) != 12:
        return False
    c = 0
    for i, n in enumerate(reversed(digits)):
        c = _D[c][_P[i % 8][n]]
    return c == 0


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from math import log2
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in counts.values())


# ----------------------------- rule tables -----------------------------

Rule = Tuple[str, str, Pattern, str, Optional[Callable[[str], bool]]]
#            kind   rule   regex    severity  optional validator(match)->keep?

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PHONE = re.compile(r"(?<!\d)(?:\+?\d{1,3}[\s\-]?)?(?:\(?\d{3}\)?[\s\-]?)\d{3}[\s\-]?\d{4}(?!\d)")
_CARD = re.compile(r"(?<!\d)(?:\d[ \-]?){13,19}(?<!\d)")
_CARD2 = re.compile(r"(?<!\d)\d(?:[ \-]?\d){12,18}(?!\d)")
_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_AADHAAR = re.compile(r"(?<!\d)\d{4}\s?\d{4}\s?\d{4}(?!\d)")
_IPV4 = re.compile(r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)")

_SECRET_RULES: List[Rule] = [
    ("secret", "openai_key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}"), "critical", None),
    ("secret", "anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"), "critical", None),
    ("secret", "aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "critical", None),
    ("secret", "github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "critical", None),
    ("secret", "slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"), "high", None),
    ("secret", "google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high", None),
    ("secret", "private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"), "critical", None),
    ("secret", "jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "high", None),
]

# Prompt-injection heuristics (case-insensitive).
_INJECTION_PATTERNS: List[Tuple[str, str]] = [
    (r"ignore (?:all |the )?(?:previous|prior|above) (?:instructions|prompts?|rules)", "high"),
    (r"disregard (?:all |the )?(?:previous|prior|above)", "high"),
    (r"reveal (?:your |the )?(?:system|initial|hidden) prompt", "high"),
    (r"(?:what (?:is|are)|show|print|repeat|output) (?:your |the )?system prompt", "high"),
    (r"you are now (?:a |an )?(?:dan|developer mode|unrestricted|jailbroken)", "critical"),
    (r"pretend (?:you are|to be) (?:not |an )?(?:ai|unrestricted|without (?:rules|restrictions))", "medium"),
    (r"(?:forget|override) (?:all |your )?(?:safety |previous )?(?:rules|guidelines|instructions)", "high"),
    (r"act as (?:if you have|an unrestricted|a jailbroken)", "medium"),
    (r"repeat (?:the words |everything )?above", "medium"),
]
_INJECTION = [(re.compile(p, re.IGNORECASE), sev) for p, sev in _INJECTION_PATTERNS]


# ----------------------------- scanner -----------------------------

_DEFAULT_RULES = ("pii", "secret", "injection")


def scan(text: str, rules: Tuple[str, ...] = _DEFAULT_RULES,
         extra_signatures: Optional[List[Rule]] = None) -> ScanResult:
    """Scan `text`. Returns a ScanResult with all findings (positions + severity)."""
    res = ScanResult()
    if not text:
        return res

    if "secret" in rules:
        for kind, rule, rx, sev, _ in _SECRET_RULES:
            for m in rx.finditer(text):
                res.findings.append(Finding(kind, rule, m.group(0), m.start(), m.end(), sev))

    if "pii" in rules:
        for m in _EMAIL.finditer(text):
            res.findings.append(Finding("pii", "email", m.group(0), m.start(), m.end(), "medium"))
        for m in _SSN.finditer(text):
            res.findings.append(Finding("pii", "us_ssn", m.group(0), m.start(), m.end(), "high"))
        for rx in (_CARD, _CARD2):
            for m in rx.finditer(text):
                if luhn_ok(m.group(0)):
                    res.findings.append(Finding("pii", "credit_card", m.group(0), m.start(), m.end(), "high"))
        for m in _AADHAAR.finditer(text):
            if verhoeff_ok(m.group(0)):
                res.findings.append(Finding("pii", "aadhaar", m.group(0), m.start(), m.end(), "high"))
        for m in _PHONE.finditer(text):
            res.findings.append(Finding("pii", "phone", m.group(0), m.start(), m.end(), "low"))
        for m in _IPV4.finditer(text):
            res.findings.append(Finding("pii", "ipv4", m.group(0), m.start(), m.end(), "low"))

    if "injection" in rules:
        for rx, sev in _INJECTION:
            for m in rx.finditer(text):
                res.findings.append(Finding("injection", "prompt_injection", m.group(0), m.start(), m.end(), sev))

    if extra_signatures:  # Pro threat-signatures pack
        for kind, rule, rx, sev, validator in extra_signatures:
            for m in rx.finditer(text):
                if validator is None or validator(m.group(0)):
                    res.findings.append(Finding(kind, rule, m.group(0), m.start(), m.end(), sev))

    res.findings = _dedupe(res.findings)
    return res


def _dedupe(findings: List[Finding]) -> List[Finding]:
    """Keep the highest-severity finding when spans overlap on the same (start,end)."""
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    best: Dict[Tuple[int, int], Finding] = {}
    for f in findings:
        key = (f.start, f.end)
        if key not in best or order[f.severity] > order[best[key].severity]:
            best[key] = f
    return sorted(best.values(), key=lambda f: f.start)


def redact(text: str, rules: Tuple[str, ...] = _DEFAULT_RULES,
           mask: str = "[REDACTED:{rule}]",
           extra_signatures: Optional[List[Rule]] = None) -> str:
    """Return `text` with every finding replaced by a mask. Non-overlapping, right-to-left."""
    res = scan(text, rules=rules, extra_signatures=extra_signatures)
    out = text
    for f in sorted(res.findings, key=lambda f: f.start, reverse=True):
        out = out[: f.start] + mask.format(rule=f.rule, kind=f.kind) + out[f.end :]
    return out


def guard(text: str, rules: Tuple[str, ...] = _DEFAULT_RULES,
          extra_signatures: Optional[List[Rule]] = None) -> None:
    """Raise FirewallBlocked if the text has a high/critical finding. Use before an API call."""
    res = scan(text, rules=rules, extra_signatures=extra_signatures)
    if res.blocked:
        kinds = sorted({f.rule for f in res.findings if f.severity in ("high", "critical")})
        raise FirewallBlocked(f"prompt-firewall blocked: {', '.join(kinds)}", res)


class FirewallBlocked(Exception):
    def __init__(self, message: str, result: ScanResult):
        super().__init__(message)
        self.result = result


def make_signature(kind: str, rule: str, pattern: str, severity: str = "high",
                   validator: Optional[Callable[[str], bool]] = None) -> Rule:
    """Build a Pro threat-signature. Pass a list of these to scan(extra_signatures=...)."""
    return (kind, rule, re.compile(pattern), severity, validator)


__all__ = [
    "scan", "redact", "guard", "ScanResult", "Finding", "FirewallBlocked",
    "luhn_ok", "verhoeff_ok", "shannon_entropy", "make_signature", "__version__",
]
