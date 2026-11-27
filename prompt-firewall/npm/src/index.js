'use strict';
/**
 * prompt-firewall — local, zero-dependency guardrail for AI chatbots / LLM apps.
 *
 * Scans text BEFORE it leaves your process for PII (emails, phones, credit cards with
 * Luhn validation, US SSN, India Aadhaar with Verhoeff validation, IPv4), secrets
 * (OpenAI/Anthropic/AWS/GitHub/Slack/Google keys, private-key blocks, JWTs), and prompt
 * injection. Pure regex + checksum math: no network, sub-millisecond, nothing leaves the host.
 *
 * Node >= 12 (lookbehind regex). MIT core; Pro threat-signatures via makeSignature().
 */

const VERSION = '0.1.0';

// ----------------------------- checksum validators -----------------------------
function luhnOk(digits) {
  const d = String(digits).split('').filter((c) => c >= '0' && c <= '9').map(Number);
  if (d.length < 13 || d.length > 19) return false;
  let total = 0;
  for (let i = 0; i < d.length; i++) {
    let n = d[d.length - 1 - i];
    if (i % 2 === 1) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    total += n;
  }
  return total % 10 === 0;
}

const _D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const _P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];
function verhoeffOk(number) {
  const digits = String(number).split('').filter((c) => c >= '0' && c <= '9').map(Number);
  if (digits.length !== 12) return false;
  let c = 0;
  for (let i = 0; i < digits.length; i++) {
    c = _D[c][_P[i % 8][digits[digits.length - 1 - i]]];
  }
  return c === 0;
}

function shannonEntropy(s) {
  if (!s) return 0;
  const counts = {};
  for (const ch of s) counts[ch] = (counts[ch] || 0) + 1;
  const n = s.length;
  let e = 0;
  for (const k in counts) {
    const p = counts[k] / n;
    e -= p * Math.log2(p);
  }
  return e;
}

// ----------------------------- rule tables -----------------------------
const EMAIL = /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g;
const PHONE = /(?<!\d)(?:\+?\d{1,3}[\s\-]?)?(?:\(?\d{3}\)?[\s\-]?)\d{3}[\s\-]?\d{4}(?!\d)/g;
const CARD = /(?<!\d)(?:\d[ \-]?){13,19}(?<!\d)/g;
const CARD2 = /(?<!\d)\d(?:[ \-]?\d){12,18}(?!\d)/g;
const SSN = /(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)/g;
const AADHAAR = /(?<!\d)\d{4}\s?\d{4}\s?\d{4}(?!\d)/g;
const IPV4 = /(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)/g;

const SECRET_RULES = [
  ['secret', 'openai_key', /sk-(?:proj-)?[A-Za-z0-9_\-]{20,}/g, 'critical', null],
  ['secret', 'anthropic_key', /sk-ant-[A-Za-z0-9_\-]{20,}/g, 'critical', null],
  ['secret', 'aws_access_key', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, 'critical', null],
  ['secret', 'github_token', /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, 'critical', null],
  ['secret', 'slack_token', /\bxox[baprs]-[A-Za-z0-9\-]{10,}\b/g, 'high', null],
  ['secret', 'google_api_key', /\bAIza[0-9A-Za-z_\-]{35}\b/g, 'high', null],
  ['secret', 'private_key_block', /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g, 'critical', null],
  ['secret', 'jwt', /\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/g, 'high', null],
];

const INJECTION = [
  [/ignore (?:all |the )?(?:previous|prior|above) (?:instructions|prompts?|rules)/gi, 'high'],
  [/disregard (?:all |the )?(?:previous|prior|above)/gi, 'high'],
  [/reveal (?:your |the )?(?:system|initial|hidden) prompt/gi, 'high'],
  [/(?:what (?:is|are)|show|print|repeat|output) (?:your |the )?system prompt/gi, 'high'],
  [/you are now (?:a |an )?(?:dan|developer mode|unrestricted|jailbroken)/gi, 'critical'],
  [/pretend (?:you are|to be) (?:not |an )?(?:ai|unrestricted|without (?:rules|restrictions))/gi, 'medium'],
  [/(?:forget|override) (?:all |your )?(?:safety |previous )?(?:rules|guidelines|instructions)/gi, 'high'],
  [/act as (?:if you have|an unrestricted|a jailbroken)/gi, 'medium'],
  [/repeat (?:the words |everything )?above/gi, 'medium'],
];

const SEV_ORDER = { low: 0, medium: 1, high: 2, critical: 3 };
const DEFAULT_RULES = ['pii', 'secret', 'injection'];

function pushAll(findings, rx, kind, rule, severity, text, validator) {
  rx.lastIndex = 0;
  let m;
  while ((m = rx.exec(text)) !== null) {
    if (m[0].length === 0) { rx.lastIndex++; continue; }
    if (!validator || validator(m[0])) {
      findings.push({ kind, rule, match: m[0], start: m.index, end: m.index + m[0].length, severity });
    }
  }
}

function dedupe(findings) {
  const best = new Map();
  for (const f of findings) {
    const key = f.start + ':' + f.end;
    const cur = best.get(key);
    if (!cur || SEV_ORDER[f.severity] > SEV_ORDER[cur.severity]) best.set(key, f);
  }
  return Array.from(best.values()).sort((a, b) => a.start - b.start);
}

function scan(text, opts = {}) {
  const rules = opts.rules || DEFAULT_RULES;
  const extra = opts.extraSignatures || null;
  const findings = [];
  if (!text) return result(findings);

  if (rules.includes('secret')) {
    for (const [kind, rule, rx, sev] of SECRET_RULES) pushAll(findings, rx, kind, rule, sev, text, null);
  }
  if (rules.includes('pii')) {
    pushAll(findings, EMAIL, 'pii', 'email', 'medium', text, null);
    pushAll(findings, SSN, 'pii', 'us_ssn', 'high', text, null);
    pushAll(findings, CARD, 'pii', 'credit_card', 'high', text, luhnOk);
    pushAll(findings, CARD2, 'pii', 'credit_card', 'high', text, luhnOk);
    pushAll(findings, AADHAAR, 'pii', 'aadhaar', 'high', text, verhoeffOk);
    pushAll(findings, PHONE, 'pii', 'phone', 'low', text, null);
    pushAll(findings, IPV4, 'pii', 'ipv4', 'low', text, null);
  }
  if (rules.includes('injection')) {
    for (const [rx, sev] of INJECTION) pushAll(findings, rx, 'injection', 'prompt_injection', sev, text, null);
  }
  if (extra) {
    for (const [kind, rule, rx, sev, validator] of extra) pushAll(findings, rx, kind, rule, sev, text, validator);
  }
  return result(dedupe(findings));
}

function result(findings) {
  return {
    findings,
    get blocked() { return findings.some((f) => f.severity === 'high' || f.severity === 'critical'); },
    get safe() { return findings.length === 0; },
  };
}

function redact(text, opts = {}) {
  const mask = opts.mask || '[REDACTED:{rule}]';
  const res = scan(text, opts);
  let out = text;
  const ordered = res.findings.slice().sort((a, b) => b.start - a.start);
  for (const f of ordered) {
    const token = mask.replace('{rule}', f.rule).replace('{kind}', f.kind);
    out = out.slice(0, f.start) + token + out.slice(f.end);
  }
  return out;
}

class FirewallBlocked extends Error {
  constructor(message, result) {
    super(message);
    this.name = 'FirewallBlocked';
    this.result = result;
  }
}

function guard(text, opts = {}) {
  const res = scan(text, opts);
  if (res.blocked) {
    const kinds = Array.from(new Set(res.findings.filter((f) => f.severity === 'high' || f.severity === 'critical').map((f) => f.rule))).sort();
    throw new FirewallBlocked('prompt-firewall blocked: ' + kinds.join(', '), res);
  }
}

function makeSignature(kind, rule, pattern, severity = 'high', validator = null) {
  const rx = pattern instanceof RegExp ? new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g') : new RegExp(pattern, 'g');
  return [kind, rule, rx, severity, validator];
}

module.exports = {
  VERSION, scan, redact, guard, FirewallBlocked,
  luhnOk, verhoeffOk, shannonEntropy, makeSignature,
};
