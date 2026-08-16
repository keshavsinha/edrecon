# EDRecon — Explainable Reconnaissance Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-0e7490.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-0e7490.svg)](https://www.python.org/downloads/)
[![Authorised Use Only](https://img.shields.io/badge/use-authorised%20targets%20only-c53030.svg)](#authorisation-is-structural-not-advisory)
[![Docs](https://img.shields.io/badge/docs-81%20page%20PDF-0e7490.svg)](EDRecon_Complete_Documentation.pdf)
[![Findings](https://img.shields.io/badge/knowledge%20base-44%20findings-0e7490.svg)](knowledge/)

**An [EDCatalyst](https://edcatalyst.in) teaching tool**
Dr. Keshav Sinha · School of Computer Science, UPES, Dehradun, India

---

> **Most scanners print observations. EDRecon explains them.**

`nmap` tells you port 445 is open. `nikto` tells you a header is missing. Both
are correct — and neither tells a student *why that matters* or *how the tool
knows*.

EDRecon is built on a different premise: **the explanation is the product.**

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

The **VERIFY** field matters more than it looks. Every finding ships with a
manual command — `dig`, `curl`, `openssl`, `nmap`. A student who runs it learns
that EDRecon has no special powers: it automates ordinary protocol
conversations. That demystification is the point of the tool.

---

## Quick start

```bash
git clone https://github.com/keshavsinha/edrecon.git
cd edrecon

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt    # never with sudo

python3 edrecon.py --version
```

Three things to try immediately, in increasing order of commitment:

```bash
# 1. Browse the knowledge base — no target, no network, no scope file
python3 edrecon.py --concepts
python3 edrecon.py --kb-search clickjacking

# 2. Passive reconnaissance — no packets reach the target
python3 edrecon.py -t example.com --passive-only

# 3. Full scan of a lab target you are authorised to test
cp scope.example.yaml scope.yaml && nano scope.yaml
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml --all
```

---

## Authorisation is structural, not advisory

Active modules require a valid, unexpired scope file that lists the target.

```yaml
engagement:
  name: "Ethical Hacking Lab - Unit 2"
  authorised_by: "Dr. Keshav Sinha, UPES"
  contact: "keshav.sinha@ddn.upes.ac.in"
  expires: "2026-12-31"

in_scope:
  networks: ["192.168.56.0/24"]

out_of_scope:
  - "192.168.56.1"      # exclusions always win
```

```console
$ python3 edrecon.py -t scanme.nmap.org --system --scope scope.yaml

[x] TARGET NOT AUTHORISED: 'scanme.nmap.org' is not covered by the
    scope file 'scope.yaml'.
    Active scanning refused.
```

**There is no `--force` flag.** An expired scope is refused exactly as real
authorisation lapses. Exclusions override in-scope networks. This is a hard
gate in the code path, not a banner you click past.

> ⚠️ **Unauthorised scanning of computer systems is a criminal offence in most
> jurisdictions.** In India the Information Technology Act, 2000 (ss. 43 and 66)
> applies. Use this only against systems you own or hold **written**
> authorisation to test.

---

## What it does

### Passive — no packet reaches the target

Queries go to resolvers, registries and public logs. The target's own logs stay
empty.

| Module | Finds |
|---|---|
| `dns_recon` | A/AAAA, NS, MX, TXT, SPF, DMARC |
| `whois_lookup` | Registrar, dates, contacts, expiry risk |
| `cert_transparency` | Subdomains from public CT logs |

### Active system — requires scope

| Module | Finds |
|---|---|
| `host_discovery` | Liveness via TCP probe |
| `port_scan` | TCP connect scan, service banners |
| `tls_audit` | Certificates, protocol versions, weak ciphers |

### Active web — requires scope

| Module | Finds |
|---|---|
| `http_audit` | Fingerprinting, security headers, cookie flags, forms |
| `content_discovery` | Paths, directory listings, exposed `.git` |

**Scope of the project:** enumeration and misconfiguration identification.
**No exploitation, no brute-forcing, no payload delivery.** That boundary is
deliberate — it keeps the tool usable in a classroom, and better-maintained
tools exist for the rest.

---

## What makes it a teaching tool

**Explanations are decoupled from code.** All 44 findings live in
`knowledge/*.yaml`. Edit, translate or extend them without touching Python:

```yaml
HDR-001:
  title: "Strict-Transport-Security header missing"
  why_it_matters: >
    Without HSTS, a user typing the bare hostname makes an initial plain
    HTTP request. An attacker on the path can intercept that first request
    and strip the redirect, keeping the session on HTTP indefinitely.
  how_to_verify: "curl -sI https://<target>/ | grep -i strict-transport"
  severity: medium
  concept_tags: ["hsts", "ssl-stripping", "transport-security"]
```

**Confidence is stated, never implied.**

| Level | Meaning |
|---|---|
| `confirmed` | A full protocol exchange completed, or the target said so directly |
| `probable` | A distinctive signature that is rarely wrong |
| `inferred` | A guess from indirect signals, defeatable by deception |

An open port is `confirmed` — the handshake completed. A version number from a
banner is `probable` — administrators edit banners. Students learn to weigh
evidence rather than trust output.

**Negative results are reported.** Closed and filtered port counts appear in
the output, because "nothing there" is itself a finding — and silence is not
proof of absence.

**Every scan ends with what it taught you:**

```
==============================================================
  WHAT THIS SCAN TAUGHT YOU
==============================================================
   Concepts exercised in this run — revisit any that are unfamiliar:

   * banner-grabbing      * baseline-comparison   * clickjacking
   * cleartext-protocol   * credential-exposure   * csrf
   * forced-browsing      * hsts                  * tcp-handshake
```

Any tag you cannot explain is a gap. `--kb-search <tag>` fills it.

**Evidence is hash-chained.** Each log entry contains the SHA-256 of the
previous one, so altering any earlier line invalidates every line after it:

```console
$ python3 edrecon.py --verify-log reports/evidence_target.jsonl
[+] Evidence chain intact - no entry has been altered.

$ nano reports/evidence_target.jsonl     # change one value
$ python3 edrecon.py --verify-log reports/evidence_target.jsonl
[x] Chain BROKEN at line 3: content hash mismatch
```

Same principle as a forensic hash chain, at a scale students can inspect by
hand.

---

## Output

Every scan produces three artefacts:

| File | Purpose |
|---|---|
| `report_<target>_<time>.html` | Styled report with the full teaching layer |
| `report_<target>_<time>.json` | Machine-readable findings |
| `evidence_<target>_<time>.jsonl` | Hash-chained event log |

Pull findings out of the JSON with `jq`:

```bash
R=$(ls -t reports/report_*.json | head -1)
jq -r '.findings[] | "\(.id)\t\(.severity)\t\(.title)"' "$R" | column -t
jq '.findings[] | select(.severity=="high") | .title' "$R"
```

---

## Classroom use

A six-lab progression is documented in [MANUAL.md](MANUAL.md) §11:

| Lab | Focus |
|---|---|
| 1 | Passive reconnaissance — verify three findings by hand |
| 2 | Writing a scope file — hand out an expired one and let the tool refuse |
| 3 | Active system scanning — compare against `nmap -sV`, discuss confidence |
| 4 | Web scanning — why the soft-404 baseline is necessary |
| 5 | Evidence integrity — tamper with a log, watch the chain break |
| 6 | Extend the tool — students write a knowledge base entry |

Lab 6 is the most useful assessment in the set: writing a good
`why_it_matters` field tests understanding far better than running a scan does.

---

## Project layout

```
edrecon/
├── edrecon.py              Main CLI
├── core/                   Finding schema, scope guard, KB loader,
│                           evidence log, renderers
├── knowledge/              All explanations — dns, ports, tls, web (YAML)
├── modules/
│   ├── passive/            No packets to target
│   ├── system/             Active — scope gated
│   └── web/                Active — scope gated
├── wordlists/
└── reports/                Runtime output (git-ignored)
```

Full annotated tree in [STRUCTURE.txt](STRUCTURE.txt).

---

## Requirements

Python 3.8+. Developed and tested on Kali Linux; works on macOS and Windows.

| Package | Required | Used for |
|---|---|---|
| `PyYAML` | yes | Scope file and knowledge base |
| `requests` | yes | HTTP modules, certificate transparency |
| `dnspython` | yes | DNS reconnaissance |
| `beautifulsoup4` | recommended | Form analysis |
| `python-whois` | recommended | WHOIS lookups |

Missing optional packages degrade gracefully — that module reports an error and
the scan continues.

> **Never run `sudo pip` inside an activated virtual environment.** `sudo` runs
> as root, bypasses the venv, and writes into directories your package manager
> owns. On Kali and Debian this produces `uninstall-no-record-file` and leaves
> packages split across two Python installations.

---

## Documentation

| Document | Contents |
|---|---|
| [MANUAL.md](MANUAL.md) | Full manual — installation, modules, classroom labs, extending |
| [COMMANDS.md](COMMANDS.md) | Every command, organised by task, with a lab-by-lab sheet |
| [STRUCTURE.txt](STRUCTURE.txt) | Annotated directory tree — which file to edit for what |
| [EDRecon_Complete_Documentation.pdf](EDRecon_Complete_Documentation.pdf) | 81-page printable: manual, commands, knowledge base, full source |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to add knowledge base entries and modules |

---

## Contributing

The most valuable contribution is **a knowledge base entry** — it requires no
Python, and a well-researched explanation is worth more than a new module. See
[CONTRIBUTING.md](CONTRIBUTING.md).

Three rules for any new active module:

1. `scope.assert_in_scope(host)` is the **first executable line**
2. Return `Finding` objects — never `print()`
3. Raise `RuntimeError` on failure so the runner can isolate it

---

## Citing

If you use EDRecon in teaching or research, see [CITATION.cff](CITATION.cff).

```
Sinha, K. (2026). EDRecon: An Explainable Reconnaissance Framework for
Security Education (Version 1.0.0) [Computer software].
https://github.com/keshavsinha/edrecon
```

---

## Licence

MIT — see [LICENSE](LICENSE). The licence grants rights over the software. It
does not grant permission to test any system, and it is not a defence against
misuse.

---

## Author

**Dr. Keshav Sinha**
School of Computer Science, University of Petroleum and Energy Studies (UPES)
Dehradun, Uttarakhand, India

Part of the [EDCatalyst](https://edcatalyst.in) educational technology
initiative.

---

*Authorised testing only.*
