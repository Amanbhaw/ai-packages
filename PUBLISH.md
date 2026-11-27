# PUBLISH.md — exact steps to publish all 3 packages (₹0 cost)

Do each package once. Commands are copy-paste. `$` lines run in a terminal.

## 0. One-time accounts (all free)
- GitHub:  https://github.com/signup
- npm:     https://www.npmjs.com/signup   (then `$ npm login`)
- PyPI:    https://pypi.org/account/register/  (create an API token in Account → API tokens)
- LemonSqueezy (for paid Pro tier later): https://www.lemonsqueezy.com/

Install the Python build tools once:
```bash
pip install --user build twine
```

## 1. Fill in your details (every package)
In each of `ai-receipt/`, `prompt-firewall/`, `tiny-zk-auth/`:
- `LICENSE` → replace `Aman Bhawsar` with your real name.
- `npm/package.json` → replace `Amanbhaw` with your GitHub username.
- `pypi/pyproject.toml` → replace `Amanbhaw` with your GitHub username.

## 2. Run the tests (must all pass before publishing)
```bash
cd ai-packages
python3 ai-receipt/pypi/tests/test_receipt.py        # 10/10
python3 prompt-firewall/pypi/tests/test_firewall.py  # 12
python3 tiny-zk-auth/pypi/tests/test_auth.py         # 7
node    ai-receipt/npm/test/test.js                  # 10
node    prompt-firewall/npm/test/test.js             # 12
node    tiny-zk-auth/npm/test/test.js                # 7
```

## 3. Publish to npm  (do this in each package's `npm/` folder)
```bash
cd ai-receipt/npm
npm publish --access public
cd ../../prompt-firewall/npm
npm publish --access public
cd ../../tiny-zk-auth/npm
npm publish --access public
```
> If a name is already taken on npm, rename in `package.json` (e.g. `@yourname/ai-receipt`)
> and publish again. A scoped name needs `--access public` (already above).

## 4. Publish to PyPI  (do this in each package's `pypi/` folder)
```bash
cd ai-receipt/pypi
python3 -m build                 # creates dist/*.whl and dist/*.tar.gz
python3 -m twine upload dist/*   # paste your PyPI API token when asked
cd ../../prompt-firewall/pypi
python3 -m build && python3 -m twine upload dist/*
cd ../../tiny-zk-auth/pypi
python3 -m build && python3 -m twine upload dist/*
```
> If a name is taken on PyPI, change `name=` in `pyproject.toml` and rebuild.

## 5. Put the code on GitHub (one repo per package, or one repo with all 3)
```bash
cd ai-packages/ai-receipt
git init && git add . && git commit -m "ai-receipt v0.1.0"
git branch -M main
git remote add origin https://github.com/Amanbhaw/ai-receipt.git
git push -u origin main
```
Repeat for `prompt-firewall` and `tiny-zk-auth`.

## 6. Turn on paid Pro tier (when ready to earn USD)
1. LemonSqueezy → create a product "Pro License Key" ($29–$299/mo or lifetime).
2. In the code, find the hook (`_pro_key_valid` in Python / `proKeyValid` or `proTier` in JS)
   and replace the stub with a call to LemonSqueezy's license-verification API.
3. LemonSqueezy is Merchant-of-Record: it handles US/EU tax and pays out to your Indian
   bank account in INR. No company or GST registration needed to start.

## 7. Launch (free marketing)
Post a short, honest "Show HN" / Reddit (r/LocalLLaMA, r/node, r/Python) / X post with a
2-line code demo. Example: "I built a zero-dependency tamper-proof audit-receipt package for
AI agents — npm i ai-receipt, works offline, < 1 ms."

---
Order of effort: publish **prompt-firewall** and **ai-receipt** first (widest appeal), then
`tiny-zk-auth`. Keep the honest "what this is NOT" sections — they build trust.
