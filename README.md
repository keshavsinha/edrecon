# EDRecon — Explainable Reconnaissance Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-0e7490.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-0e7490.svg)](https://www.python.org/downloads/)
[![Authorised Use Only](https://img.shields.io/badge/use-authorised%20targets%20only-c53030.svg)](#authorisation-is-structural)
[![Docs](https://img.shields.io/badge/docs-81%20page%20PDF-0e7490.svg)](EDRecon_Complete_Documentation.pdf)

**An EDCatalyst teaching tool**
Dr. Keshav Sinha · School of Computer Science, UPES, Dehradun, India · [edcatalyst.in](https://edcatalyst.in)

---

Most scanners print observations. EDRecon explains them.

Every finding carries **WHAT** was observed, **WHY** it matters, **HOW** it was
detected, how to **VERIFY** it by hand, and how to **FIX** it — because a tool
that only prints results teaches students to read output, not to reason.

```
  [WEB-007] Version control directory exposed  ............... high
  ------------------------------------------------------------------
  SOURCE   ACTIVE module 'content_discovery' | confidence: confirmed
  OBSERVED http://target/.git/HEAD -> HTTP 200, 23 bytes.
  WHAT     An exposed repository often allows reconstruction of the
           entire application source, including commit history.
  WHY      History is the real prize: credentials and keys committed
           and later removed remain recoverable from earlier commits.
  HOW      Request to the version control path returned a resource.
  VERIFY   curl -sI http://<target>/.git/HEAD
  FIX      Deny dot-directories at the web server. Rotate any
           credential that was ever committed.
  REFS     CWE-527 | CWE-540
  TAGS     source-disclosure . version-control . secret-leakage
```

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt        # no sudo
python3 edrecon.py --version
```

## Use

```bash
# Passive only — no packets to target, no scope file needed
python3 edrecon.py -t example.com --passive-only

# Full scan of an authorised lab target
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml --all

# Browse the knowledge base with no target at all
python3 edrecon.py --kb-search clickjacking
python3 edrecon.py --concepts
```

## Authorisation is structural

Active modules require a valid, unexpired scope file listing the target.
There is no `--force` flag. An expired scope is refused exactly as real
authorisation lapses.

**Unauthorised scanning may violate the IT Act 2000 (India), ss. 43/66.**

## Features

- **Passive** — DNS, SPF/DMARC, WHOIS, certificate transparency subdomains
- **Active system** — host discovery, TCP connect scan, banner grabbing, TLS audit
- **Active web** — fingerprinting, security headers, cookies, forms, content discovery
- **Knowledge base** — all explanations in editable YAML, decoupled from code
- **Evidence log** — hash-chained JSONL with tamper verification
- **Reports** — styled HTML + machine-readable JSON

Scope: enumeration and misconfiguration identification. **No exploitation.**

## Documentation

| Document | Contents |
|---|---|
| [MANUAL.md](MANUAL.md) | Full manual — installation, modules, classroom labs, extending |
| [COMMANDS.md](COMMANDS.md) | Every command, organised by task, with a lab-by-lab sheet |
| [EDRecon_Complete_Documentation.pdf](EDRecon_Complete_Documentation.pdf) | 81-page printable: manual, commands, knowledge base, full source |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to add knowledge base entries and modules |

## Citing

If you use EDRecon in teaching or research, see [CITATION.cff](CITATION.cff).

## Author

**Dr. Keshav Sinha** — School of Computer Science, University of Petroleum
and Energy Studies (UPES), Dehradun, India.
Part of the [EDCatalyst](https://edcatalyst.in) educational technology
initiative.

---

*Authorised testing only.*
