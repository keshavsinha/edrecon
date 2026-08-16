# Contributing to EDRecon

EDRecon is a teaching tool first. Contributions are judged on whether they
make the tool a better instrument for learning, not only on whether the code
works.

## The most valuable contribution

**Knowledge base entries.** The explanations in `knowledge/*.yaml` are the
product. A well-researched entry — one that genuinely explains why a finding
matters to an attacker and a defender — is worth more than a new module.

Adding one requires no Python:

```yaml
SNMP-001:
  title: "SNMP responds to default community string"
  what: >
    The service accepted 'public' as a community string.
  why_it_matters: >
    Community strings are effectively passwords, sent in cleartext in SNMPv1
    and v2c. A default value exposes the full device configuration,
    interface list and routing table.
  how_detected: "An SNMP GET for sysDescr.0 using the string 'public'."
  how_to_verify: "snmpwalk -v2c -c public <target> system"
  how_to_fix: >
    Change the community string, restrict by source IP, migrate to SNMPv3
    with authentication and privacy.
  severity: high
  references: ["CWE-1188", "RFC 3411"]
  concept_tags: ["snmp", "default-credentials", "cleartext-protocol"]
```

### Writing a good `why_it_matters`

This is the field that carries the teaching. It should answer: *what can
someone actually do with this?* Compare:

- Weak: "Missing this header is a security risk."
- Good: "Without HSTS, a user typing the bare hostname makes an initial
  plain HTTP request. An attacker on the path can intercept that first
  request and strip the redirect, keeping the session on HTTP indefinitely."

Name the attack. Explain the mechanism. Assume the reader is a student who
has not seen it before.

## Contributing a module

Three rules, no exceptions:

1. **`scope.assert_in_scope(host)` is the first executable line** of any
   function that sends a packet. Pull requests that omit it are closed.
2. **Return `Finding` objects.** Never `print()` from a module.
3. **Raise `RuntimeError` with a clear message on failure.** The runner
   catches it, records it, and lets the scan continue.

Template:

```python
from core.finding import Finding
from core.knowledge import kb

MODULE = "your_module"

def _mk(fid, target, observation, evidence=None, **kw):
    f = Finding(id=fid, module=MODULE, target=target, title="",
                observation=observation, evidence=evidence or {},
                passive=False, **kw)
    return f.enrich(kb().get(fid))

def check(host, scope, timeout=3, evidence_log=None):
    scope.assert_in_scope(host)        # MANDATORY - first line
    findings = []
    # ...
    return findings
```

Set `passive=True` only if **no packet reaches the target**. A query to a
third-party service is passive; a query to the target's own nameserver is
not.

## Scope of the project

EDRecon stops at **enumeration and misconfiguration identification**.

Out of scope, and will not be merged:

- Exploitation, payload delivery, or shell handling
- Credential brute-forcing or password spraying
- Anything that modifies state on the target
- Any bypass, override or `--force` for the scope guard
- Modules aimed at profiling people rather than infrastructure

This boundary is deliberate. It keeps the tool usable in a classroom without
supervision concerns, and there are better-maintained tools for the rest.

## Confidence levels

Set these honestly — the distinction is a core teaching point.

| Level | Use when |
|---|---|
| `confirmed` | A full protocol exchange completed, or the target stated it directly |
| `probable` | A distinctive signature that is rarely wrong (e.g. a banner string) |
| `inferred` | A guess from indirect signals, defeatable by misconfiguration |

A banner is `probable`, never `confirmed` — administrators edit banners.

## Before opening a pull request

```bash
python3 -m py_compile edrecon.py core/*.py modules/*/*.py
python3 edrecon.py --kb-search YOUR-FINDING-ID
python3 edrecon.py --concepts
```

Test against a lab VM you own (Metasploitable, DVWA, Juice Shop). Never
against third-party infrastructure.

## Reporting a problem

Open an issue with the command you ran, the expected behaviour, and what
happened. **Redact target details** — hostnames, IPs, and organisation names
from real scans do not belong in a public issue tracker.

If you find a flaw in the scope guard itself, please report it privately
first rather than opening a public issue.
