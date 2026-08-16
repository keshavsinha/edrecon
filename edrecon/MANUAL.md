# EDRecon — User Manual

**Explainable Reconnaissance Framework**
Version 1.0.0

An **EDCatalyst** teaching tool
Dr. Keshav Sinha — School of Computer Science, UPES, Dehradun, India
edcatalyst.in

---

## Contents

1. [What EDRecon is, and why it exists](#1-what-edrecon-is-and-why-it-exists)
2. [Legal and ethical boundaries](#2-legal-and-ethical-boundaries)
3. [Installation](#3-installation)
4. [The scope file](#4-the-scope-file)
5. [Quick start](#5-quick-start)
6. [Command reference](#6-command-reference)
7. [Understanding the output](#7-understanding-the-output)
8. [Module reference](#8-module-reference)
9. [The knowledge base](#9-the-knowledge-base)
10. [Reports and evidence](#10-reports-and-evidence)
11. [Classroom use](#11-classroom-use)
12. [Extending EDRecon](#12-extending-edrecon)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. What EDRecon is, and why it exists

Most reconnaissance tools print observations. `nmap` tells you port 445 is
open. `nikto` tells you a header is missing. Both are correct, and neither
tells a student *why that matters* or *how the tool knows*.

EDRecon is built on a different premise: **the explanation is the product**.
Every finding carries six fields:

| Field | Question it answers |
|---|---|
| `OBSERVED` | What did the tool literally see? |
| `WHAT` | What does that mean technically? |
| `WHY` | Why does it matter to an attacker or defender? |
| `HOW` | What mechanism revealed it? |
| `VERIFY` | How do I reproduce this by hand, without the tool? |
| `FIX` | What should the defender do? |

The `VERIFY` field matters more than it looks. It always gives a manual
command — `dig`, `curl`, `openssl`, `nmap`. A student who runs it learns
that EDRecon has no special powers; it automates ordinary protocol
conversations. That demystification is the point of the tool.

### Design principles

1. **The explanation is decoupled from the code.** All teaching text lives
   in `knowledge/*.yaml`. Edit it without touching a single line of Python.
2. **Authorisation is structural, not advisory.** A scope file is required
   for every active module, and there is no override flag.
3. **Confidence is stated, never implied.** A completed TCP handshake is
   `confirmed`. A banner string is `probable` — banners can be edited.
   Students learn to weigh evidence rather than trust output.
4. **Failures are isolated.** One broken module never ends the run. Errors
   are collected and reported at the end.
5. **Negative results are reported.** Closed and filtered port counts appear
   in the output, because "nothing there" is itself a finding.

### What EDRecon deliberately does *not* do

It stops at **enumeration and misconfiguration identification**. There is no
exploitation, no payload delivery, no credential brute-forcing, no
vulnerability chaining. That boundary is intentional: your students already
have Metasploit for the exploitation unit, and a recon tool that stays a
recon tool is both pedagogically cleaner and not a weapon.

---

## 2. Legal and ethical boundaries

**Scanning a system you do not own or have written permission to test is a
criminal offence in most jurisdictions.**

In India, unauthorised access and related conduct fall under the
**Information Technology Act, 2000**, principally sections 43 and 66.
Penalties include imprisonment. "I was only scanning" and "I was learning"
are not defences. Neither is the fact that the target had a weakness.

Note carefully: **passive reconnaissance is not automatically lawful either.**
Querying public records is generally fine; aggregating them into a profile
of a private individual may not be. EDRecon is designed for infrastructure
assessment, not for investigating people.

### The rule this tool enforces

Active modules run only against targets listed in a valid, unexpired scope
file. This is not a warning banner you can click past — it is a hard gate in
the code path. If you find yourself wanting to disable it, that is the
signal to stop and get authorisation instead.

### Safe practice targets

- Your own lab VMs (Metasploitable 2/3, DVWA, OWASP Juice Shop, VulnHub)
- Systems you personally own
- Deliberately public scanning targets such as `scanme.nmap.org`, within
  the terms its operator publishes
- Client or employer systems **with written authorisation**

---

## 3. Installation

### Requirements

- Python 3.8 or newer
- Linux, macOS, or Windows (developed and tested on Kali Linux)

### Steps

```bash
# 1. Place the edrecon folder wherever you keep tools
cd ~/tools/edrecon

# 2. Create a virtual environment  (as your normal user - NOT with sudo)
python3 -m venv .venv

# 3. Activate it
source .venv/bin/activate          # Linux / macOS
# .venv\Scripts\activate           # Windows

# 4. Install dependencies  (no sudo - the venv is yours)
pip install -r requirements.txt

# 5. Confirm it runs
python3 edrecon.py --version
```

> **Never use `sudo pip` inside an activated virtual environment.**
> `sudo` runs as root with root's environment, bypasses the venv entirely,
> and writes into system directories that your distribution's package
> manager owns. On Kali and Debian this produces the
> `uninstall-no-record-file` error and leaves packages scattered across two
> Python installations. If you hit permission errors, the venv directory is
> root-owned — delete it, recreate it without `sudo`, and reinstall.

### Dependencies

| Package | Required? | Used for |
|---|---|---|
| `PyYAML` | **Yes** | Scope file and knowledge base parsing |
| `requests` | **Yes** | HTTP modules, certificate transparency |
| `dnspython` | **Yes** | DNS reconnaissance |
| `beautifulsoup4` | Recommended | Form analysis |
| `python-whois` | Recommended | WHOIS lookups |

Missing optional packages degrade gracefully — that module reports an error
and the scan continues.

### Verifying the install

```bash
python3 edrecon.py --concepts       # should list ~85 concept tags
python3 edrecon.py --kb             # should print the full knowledge base
```

Both work with no target and no network connection.

---

## 4. The scope file

The scope file is the authorisation record. Copy `scope.example.yaml` and
edit it.

```yaml
engagement:
  name: "Ethical Hacking Lab - Unit 2 Reconnaissance"
  authorised_by: "Dr. Keshav Sinha, School of Computer Science, UPES"
  contact: "keshav.sinha@ddn.upes.ac.in"
  expires: "2026-12-31"
  notes: >
    Isolated lab environment. Metasploitable 3 on a host-only network.

in_scope:
  hosts:
    - "192.168.56.101"
    - "192.168.56.102"
  networks:
    - "192.168.56.0/24"
  domains: []

out_of_scope:
  - "192.168.56.1"       # VirtualBox host adapter
  - "192.168.56.100"     # your Kali VM
```

### Rules

- All four `engagement` fields are **required**. EDRecon refuses to start
  without them.
- `expires` must be `YYYY-MM-DD`. **An expired scope is refused**, exactly
  as real authorisation lapses. This is the field students most often
  overlook, and that lesson is deliberate.
- At least one of `hosts`, `networks`, or `domains` must be non-empty.
- `domains` automatically includes subdomains.
- **`out_of_scope` always wins.** A host inside an in-scope network is still
  refused if it is explicitly excluded. This models the real situation where
  one device on an in-scope subnet must not be touched.

### Testing your scope file

```bash
python3 edrecon.py -t 192.168.56.101 --system --scope scope.yaml
```

The authorisation block prints before anything is scanned. Read it. If it
does not say what you expect, fix the file before continuing.

---

## 5. Quick start

### Passive only — no scope file needed

```bash
python3 edrecon.py -t example.com --passive-only
```

No packets reach the target. Safe to run against any domain.

### Full scan of an authorised lab target

```bash
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml --all
```

### System scan with a custom port range

```bash
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml \
    --system --ports 1-1024
```

### Web scan with content discovery

```bash
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml \
    --web --discover
```

### Browse the knowledge base — no target at all

```bash
python3 edrecon.py --kb
python3 edrecon.py --kb-search clickjacking
python3 edrecon.py --concepts
```

---

## 6. Command reference

### Target selection

| Flag | Meaning |
|---|---|
| `-t`, `--target` | Domain, hostname, or IP address |
| `-s`, `--scope` | Path to the authorisation scope file |
| `-u`, `--url` | Explicit URL for the web phase |

### Phases

| Flag | Meaning |
|---|---|
| `--passive-only` | Passive reconnaissance only. No scope file needed. |
| `--system` | Active system scan (host discovery, ports, TLS) |
| `--web` | Active web scan (headers, cookies, forms) |
| `--all` | All three phases |

With no phase flag, EDRecon runs `--passive-only`. Safe by default.

### Scan options

| Flag | Default | Meaning |
|---|---|---|
| `--ports` | `top` | `top`, `1-1024`, or `22,80,443` |
| `--threads` | `50` | Concurrent scan threads |
| `--timeout` | `3.0` | Per-connection timeout (seconds) |
| `--delay` | `0.35` | Delay between web requests |
| `--no-banners` | off | Skip banner grabbing |
| `--axfr` | off | Attempt zone transfer (**active**, needs scope) |
| `--discover` | off | Run content discovery in the web phase |
| `--wordlist` | built-in | Custom wordlist file |
| `--max-paths` | `400` | Cap on paths probed |
| `--no-whois` | off | Skip WHOIS |
| `--no-ct` | off | Skip certificate transparency |

### Output

| Flag | Meaning |
|---|---|
| `--brief` | One line per finding (suppresses the teaching layer) |
| `--no-explain` | Observations without WHAT/WHY/HOW |
| `--outdir` | Report directory (default `reports`) |
| `--no-color` | Disable ANSI colour |
| `--no-report` | Skip file output |

### Knowledge base

| Flag | Meaning |
|---|---|
| `--kb` | Print the entire knowledge base |
| `--kb-search TERM` | Search the knowledge base |
| `--concepts` | List all concept tags |
| `--verify-log PATH` | Verify an evidence log's hash chain |

---

## 7. Understanding the output

### Anatomy of a finding

```
  [WEB-007] Version control directory exposed  ............... high
  ------------------------------------------------------------------
  SOURCE   ACTIVE module 'content_discovery' | confidence: confirmed
  OBSERVED http://target/.git/HEAD -> HTTP 200, 23 bytes.
  WHAT     An exposed repository often allows reconstruction of the
           entire application source, including commit history.
  WHY      History is the real prize: credentials and keys that were
           committed and later removed remain recoverable.
  HOW      Request to the version control path returned an existing
           resource.
  VERIFY   curl -sI http://<target>/.git/HEAD
  FIX      Deny access to dot-directories at the web server. Rotate any
           credential that was ever committed.
  REFS     CWE-527 | CWE-540
  TAGS     source-disclosure . version-control . secret-leakage
```

### Severity

| Level | Meaning |
|---|---|
| `info` | Neutral fact. Not a weakness by itself. |
| `low` | Minor hygiene issue. Useful only in combination. |
| `medium` | Real weakness. Meaningfully expands attack surface. |
| `high` | Serious weakness. Direct path toward compromise. |
| `critical` | Compromise likely trivial from here. |

### Confidence — read this carefully

This is the field that separates a practitioner from someone reading tool
output credulously.

| Level | Meaning |
|---|---|
| `confirmed` | Directly proven. The target told us, or a full protocol exchange completed. |
| `probable` | Strongly indicated by a distinctive signature that is rarely wrong. |
| `inferred` | A best guess from indirect signals. Defeatable by misconfiguration or deliberate deception. |

An open port is `confirmed` — the handshake completed. A version number from
a banner is `probable` — administrators can and do edit banners. Never
report an inferred finding as fact.

### The "WHAT THIS SCAN TAUGHT YOU" block

Every finding carries concept tags. At the end of a run, EDRecon lists every
concept the scan touched. Use it as a revision checklist: any tag you cannot
explain is a gap, and `--kb-search <tag>` will fill it.

---

## 8. Module reference

### Passive modules

Passive means **no packet reaches the target**. Queries go to resolvers,
registries and public logs. The target's own logs stay empty.

| Module | Findings | What it does |
|---|---|---|
| `dns_recon` | `DNS-001`–`DNS-009` | A/AAAA, NS, MX, TXT, SPF, DMARC |
| `whois_lookup` | `WHO-001`, `WHO-002` | Registrar, dates, contacts, expiry |
| `cert_transparency` | `DNS-010` | Subdomains from public CT logs |

**Certificate transparency deserves special attention in teaching.** Every
publicly trusted certificate issued since 2018 is written to a public,
append-only log. Querying crt.sh enumerates subdomains without sending a
single packet to the target — the organisation published that data itself,
as an unavoidable side effect of obtaining certificates.

### Active system modules

| Module | Findings | What it does |
|---|---|---|
| `host_discovery` | `HOST-001` | TCP-based liveness probe |
| `port_scan` | `PORT-001`–`PORT-006` | TCP connect scan, banner grabbing |
| `tls_audit` | `TLS-001`–`TLS-009` | Certificates, versions, ciphers |

**On the scan type:** this is a TCP *connect* scan — the full three-way
handshake completes before the socket closes. That makes it reliable and
unprivileged, but also loud: the connection appears in the target's
application logs. A SYN scan avoids that by never completing the handshake,
but needs raw sockets and therefore root. The stealth-versus-privilege
trade-off is worth demonstrating directly in class.

**On AXFR:** zone transfer is the one DNS check labelled **active**, because
the request goes straight to the target's authoritative nameserver. It needs
a scope file.

### Active web modules

| Module | Findings | What it does |
|---|---|---|
| `http_audit` | `HTTP-001`–`HTTP-003`, `HDR-001`–`HDR-006`, `WEB-001`, `WEB-004`–`WEB-006` | Fingerprinting, headers, cookies, forms |
| `content_discovery` | `WEB-002`, `WEB-003`, `WEB-007` | Wordlist path discovery |

**On the baseline in content discovery:** a naive scanner reports every HTTP
200 as a hit, which produces pages of noise against any server with a custom
404 page. Before probing anything, EDRecon requests two paths that certainly
do not exist and records the response — status, length, body hash. Every
subsequent response is compared against that baseline. When soft-404
behaviour is detected, EDRecon says so explicitly in the output.

Content discovery is rate-limited by construction. Unthrottled forced
browsing is indistinguishable from a denial-of-service attempt.

---

## 9. The knowledge base

All explanatory text lives in `knowledge/`:

```
knowledge/
├── dns.yaml       DNS, SPF, DMARC, WHOIS
├── ports.yaml     Hosts, ports, services
├── tls.yaml       Certificates, protocol versions, ciphers
└── web.yaml       HTTP, headers, cookies, content discovery
```

### Editing an explanation

```yaml
HDR-001:
  title: "Strict-Transport-Security header missing"
  what: >
    The server does not instruct browsers to use HTTPS exclusively.
  why_it_matters: >
    Without HSTS, a user typing the bare hostname makes an initial plain
    HTTP request that an attacker on the path can intercept.
  how_detected: "Response headers checked for Strict-Transport-Security."
  how_to_verify: "curl -sI https://<target>/ | grep -i strict-transport"
  how_to_fix: >
    Send: Strict-Transport-Security: max-age=31536000; includeSubDomains
  severity: medium
  references: ["RFC 6797", "CWE-319"]
  concept_tags: ["hsts", "ssl-stripping", "transport-security"]
```

Save the file and rerun. No code changes, no restart beyond the next
invocation.

### Why this separation matters

- **Translate it.** Produce a Hindi knowledge base without forking the code.
- **Version the pedagogy separately.** Explanations improve on a different
  cycle from scanner logic.
- **Set it as reading.** Students can browse `--kb` before ever running a
  scan.
- **Let students write entries.** Adding a well-researched KB entry is an
  excellent assessed exercise — and a considerably better test of
  understanding than running a scan.

---

## 10. Reports and evidence

Every scan produces three artefacts in `reports/`:

| File | Purpose |
|---|---|
| `report_<target>_<timestamp>.html` | Styled report with the full teaching layer |
| `report_<target>_<timestamp>.json` | Machine-readable findings |
| `evidence_<target>_<timestamp>.jsonl` | Append-only, hash-chained event log |

### The evidence log

Each entry contains the SHA-256 hash of the previous entry. Altering any
earlier line invalidates every line after it — the same principle as a
forensic hash chain, at a scale students can inspect by hand.

```bash
python3 edrecon.py --verify-log reports/evidence_target_20260816.jsonl
```

```
[+] Evidence chain intact - no entry has been altered.
```

If a line is modified:

```
[x] Chain BROKEN at line 2: content hash mismatch
```

**Classroom exercise:** have students run a scan, open the JSONL in an
editor, change one recorded value, and re-verify. Watching the chain break
teaches integrity verification far better than a lecture slide about it.
This also bridges directly into your Digital Forensics course.

---

## 11. Classroom use

### Suggested lab progression

**Lab 1 — Passive reconnaissance (no scope file)**
Run `--passive-only` against the institution's own domain. Discuss what was
learned without touching a single target system. Have students verify three
findings by hand using the `VERIFY` commands.

**Lab 2 — Writing a scope file**
Before any active scanning, each student writes and defends a scope file.
Deliberately give them an expired one first and let the tool refuse. The
lesson lands better from a refusal than from a slide.

**Lab 3 — Active system scanning**
Scan Metasploitable 3. Compare EDRecon's output against
`nmap -sV`. Where do they agree? Where does confidence differ, and why?

**Lab 4 — Web scanning and content discovery**
Run `--web --discover`. Discuss the baseline mechanism: why is comparing
against a known-bad path necessary?

**Lab 5 — Evidence integrity**
Verify a log, tamper with it, verify again. Connect to chain of custody.

**Lab 6 — Extend the tool**
Students add a knowledge base entry or a module. Assessed on the quality of
the explanation, not the code.

### Assessment ideas

- Give students a JSON report and ask them to write the executive summary.
- Give a finding with `confidence: inferred` and ask what evidence would
  raise it to `confirmed`.
- Ask students to identify which findings in a report would change if the
  target sat behind a CDN.
- Have students critique a KB entry's `why_it_matters` field and improve it.

### Demonstrating the safety model

Run this in front of the class:

```bash
python3 edrecon.py -t scanme.nmap.org --system --scope scope.yaml
```

```
[x] TARGET NOT AUTHORISED: 'scanme.nmap.org' is not covered by the
    scope file 'scope.yaml'.
```

Then show there is no `--force` flag in `--help`. The point is that
professional tooling should make the wrong thing hard, not merely
discouraged.

---

## 12. Extending EDRecon

### Adding a knowledge base entry

Add to any `knowledge/*.yaml`:

```yaml
SNMP-001:
  title: "SNMP responds to default community string"
  what: >
    The service accepted 'public' as a community string.
  why_it_matters: >
    Community strings are effectively passwords sent in cleartext in
    SNMPv1 and v2c. A default value exposes the full device
    configuration, interface list and routing table.
  how_detected: "An SNMP GET for sysDescr.0 using the string 'public'."
  how_to_verify: "snmpwalk -v2c -c public <target> system"
  how_to_fix: >
    Change the community string, restrict by source IP, migrate to
    SNMPv3 with authentication and privacy.
  severity: high
  references: ["CWE-1188", "RFC 3411"]
  concept_tags: ["snmp", "default-credentials", "cleartext-protocol"]
```

### Adding a module

Create `modules/system/snmp_check.py`:

```python
from core.finding import Finding
from core.knowledge import kb

MODULE = "snmp_check"

def _mk(fid, target, observation, evidence=None, **kw):
    f = Finding(id=fid, module=MODULE, target=target, title="",
                observation=observation, evidence=evidence or {},
                passive=False, **kw)
    return f.enrich(kb().get(fid))

def check(host, scope, timeout=3, evidence_log=None):
    scope.assert_in_scope(host)        # MANDATORY - first line, always
    findings = []
    # ... your logic ...
    return findings
```

Then wire it into the relevant phase function in `edrecon.py` using
`run_module()`, which handles error isolation for you.

### The three rules for a new active module

1. `scope.assert_in_scope(host)` is the **first executable line**.
2. Return `Finding` objects. Never `print()` directly.
3. Raise `RuntimeError` with a clear message on failure — `run_module()`
   catches it, records it, and lets the scan continue.

---

## 13. Troubleshooting

### `ModuleNotFoundError` after installing

The virtual environment is almost certainly not activated. Check your
prompt — it should show `(.venv)`. If not:

```bash
source .venv/bin/activate
```

This must be done in every new terminal session.

### `Permission denied` when creating the venv

The directory is root-owned, usually because an installer ran under `sudo`.

```bash
sudo chown -R $USER:$USER .
rm -rf .venv
python3 -m venv .venv       # no sudo
```

### `error: uninstall-no-record-file`

You ran `sudo pip install` on a Debian-family system. `sudo` bypassed the
venv and pip tried to remove a package that `apt` owns. Recreate the venv
and install without `sudo`.

### `AUTHORISATION EXPIRED`

Working as designed. Update `engagement.expires` in the scope file — but
only if you actually still hold authorisation.

### `TARGET NOT AUTHORISED`

The target is not in the scope file, or is explicitly excluded. Add it only
if you hold written permission. There is no override, and that is deliberate.

### crt.sh returns HTTP 429

Rate limited. Wait a minute and retry, or use `--no-ct`.

### Content discovery finds nothing on a known-vulnerable target

Check whether the output mentions soft-404 behaviour. If the server returns
200 for everything with identical bodies, all responses are filtered as
baseline matches. Try a different wordlist, or inspect responses manually
with `curl -I`.

### The scan is very slow

Reduce `--timeout`, raise `--threads`, or narrow `--ports`. On a lab network
`--timeout 1 --threads 100` is usually comfortable. Do not raise thread
counts against systems you do not control.

### TLS audit fails on a self-signed lab certificate

It should not — certificate verification is disabled deliberately, because
the point is to *observe* the certificate, not to trust it. If the handshake
itself fails, the service may not speak TLS on that port.

---

## Appendix — Finding ID index

| Range | Domain |
|---|---|
| `DNS-001`–`DNS-010` | DNS records, SPF, DMARC, subdomains |
| `WHO-001`–`WHO-002` | WHOIS registration |
| `HOST-001` | Host liveness |
| `PORT-001`–`PORT-006` | Ports and services |
| `TLS-001`–`TLS-009` | Certificates and TLS configuration |
| `HTTP-001`–`HTTP-003` | HTTP fingerprinting |
| `HDR-001`–`HDR-006` | Security headers and cookies |
| `WEB-001`–`WEB-007` | Web surface and content discovery |

Full detail for any ID:

```bash
python3 edrecon.py --kb-search DNS-008
```

---

*EDRecon — an EDCatalyst teaching tool.*
*Dr. Keshav Sinha, UPES, Dehradun, India.*
*Authorised testing only.*
