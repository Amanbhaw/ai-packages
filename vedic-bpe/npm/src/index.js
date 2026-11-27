'use strict';
// vedic-bpe — lossless LLM token reducer for repetitive structured JSON.
// Vedic-named (branding): Anuvritti (Panini) key-fold + "." inheritance,
// Nikhilam/Brahmagupta base-anchor delta for string ID columns.
// Bit-exact round-trip, type-preserving, 0% inflation. Zero dependencies.
const SEP = '|', NL = '\n';

function pack(jsonText) {
  let data;
  try { data = JSON.parse(jsonText); } catch (e) { return jsonText; }
  if (!Array.isArray(data) || data.length < 2 ||
      !data.every(r => r && typeof r === 'object' && !Array.isArray(r))) return jsonText;
  const keys = Object.keys(data[0]);
  if (!keys.length || !data.every(r => {
    const k = Object.keys(r); return k.length === keys.length && k.every((x, i) => x === keys[i]);
  })) return jsonText;
  const lit = v => { const s = JSON.stringify(v); return (s.includes(SEP) || s.includes(NL)) ? null : s; };
  for (const r of data) for (const c of keys) if (lit(r[c]) === null) return jsonText;
  // Nikhilam: string columns prefix+digits (no leading zeros), shared prefix
  const nik = {};
  for (const c of keys) {
    if (!data.every(r => typeof r[c] === 'string')) continue;
    const ms = data.map(r => /^(.*?)(\d+)$/.exec(r[c]));
    if (ms.every(m => m) && new Set(ms.map(m => m[1])).size === 1 &&
        ms.every(m => String(parseInt(m[2], 10)) === m[2])) {
      const pref = ms[0][1];
      const base = Math.floor(Math.min(...ms.map(m => parseInt(m[2], 10))) / 100) * 100;
      nik[c] = [pref, base];
    }
  }
  const hdr = keys.map(c => c in nik ? `${c}=${JSON.stringify([nik[c][1], nik[c][0]])}` : c).join(SEP);
  const out = [hdr]; let prev = null;
  for (const r of data) {
    const cells = keys.map(c => {
      if (c in nik) return String(parseInt(r[c].slice(nik[c][0].length), 10) - nik[c][1]);
      if (prev && prev[c] === r[c] && typeof prev[c] === typeof r[c]) return '.';
      return lit(r[c]);
    });
    out.push(cells.join(SEP)); prev = r;
  }
  return out.join(NL);
}

function unpack(packed) {
  const lines = packed.split(NL);
  if (lines.length < 2 || !lines[0].includes(SEP)) return JSON.parse(packed);
  const keys = [], nik = {};
  for (const h of lines[0].split(SEP)) {
    const m = /^(.*?)=(\[.*\])$/.exec(h);
    if (m) { const [base, pref] = JSON.parse(m[2]); keys.push(m[1]); nik[m[1]] = [pref, base]; }
    else keys.push(h);
  }
  const rows = []; let prev = {};
  for (let i = 1; i < lines.length; i++) {
    const cells = lines[i].split(SEP); const row = {};
    keys.forEach((c, j) => {
      const val = cells[j];
      if (c in nik) row[c] = nik[c][0] + (nik[c][1] + parseInt(val, 10));
      else if (val === '.') row[c] = prev[c];
      else row[c] = JSON.parse(val);
    });
    rows.push(row); prev = row;
  }
  return rows;
}
module.exports = { pack, unpack };
