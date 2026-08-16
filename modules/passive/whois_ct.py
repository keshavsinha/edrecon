"""
PASSIVE - WHOIS registration data and Certificate Transparency logs.

Certificate Transparency deserves emphasis in teaching. Every publicly
trusted certificate issued since 2018 is written to a public append-only
log. Querying crt.sh therefore enumerates subdomains without sending a
single packet to the target - the organisation published this data itself,
as a side effect of getting certificates.
"""

import json
import re
from datetime import datetime, timezone, timedelta

from core.finding import Finding
from core.knowledge import kb
from core.evidence import USER_AGENT

MODULE_WHOIS = "whois_lookup"
MODULE_CT = "cert_transparency"

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

try:
    import whois as whois_lib
    HAVE_WHOIS = True
except ImportError:
    HAVE_WHOIS = False


def _mk(fid, module, target, observation, evidence=None, **kw):
    f = Finding(id=fid, module=module, target=target, title="",
                observation=observation, evidence=evidence or {}, **kw)
    return f.enrich(kb().get(fid))


def _as_date(value):
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, datetime):
        return value.replace(tzinfo=value.tzinfo or timezone.utc)
    if isinstance(value, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(value[:19], fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def run_whois(target, evidence_log=None, opts=None):
    findings = []
    if not HAVE_WHOIS:
        raise RuntimeError(
            "python-whois not installed. Run: pip install python-whois"
        )

    data = whois_lib.whois(target)
    if not data or not getattr(data, "domain_name", None):
        raise RuntimeError("No WHOIS data returned for {}".format(target))

    registrar = data.get("registrar") or "not disclosed"
    created = _as_date(data.get("creation_date"))
    expires = _as_date(data.get("expiration_date"))
    emails = data.get("emails") or []
    if isinstance(emails, str):
        emails = [emails]

    age = ""
    if created:
        days = (datetime.now(timezone.utc) - created).days
        age = " Domain age: {} days ({:.1f} years).".format(days, days / 365.25)

    findings.append(_mk(
        "WHO-001", MODULE_WHOIS, target,
        "Registrar: {}. Created: {}. Expires: {}.{}".format(
            registrar,
            created.date().isoformat() if created else "unknown",
            expires.date().isoformat() if expires else "unknown",
            age,
        ),
        {
            "registrar": registrar,
            "created": created.isoformat() if created else None,
            "expires": expires.isoformat() if expires else None,
            "emails": emails[:10],
            "name_servers": data.get("name_servers") or [],
        },
        passive=True,
    ))

    if expires and expires < datetime.now(timezone.utc) + timedelta(days=30):
        findings.append(_mk(
            "WHO-002", MODULE_WHOIS, target,
            "Registration expires {} - within 30 days.".format(
                expires.date().isoformat()),
            {"expires": expires.isoformat()},
            passive=True,
        ))

    if evidence_log:
        evidence_log.record("whois", MODULE_WHOIS, target, {"registrar": registrar})

    return findings


def run_ct(target, rate=None, evidence_log=None, opts=None):
    """Query crt.sh certificate transparency logs for subdomains."""
    opts = opts or {}
    findings = []
    if not HAVE_REQUESTS:
        raise RuntimeError("requests not installed. Run: pip install requests")

    url = "https://crt.sh/?q=%25.{}&output=json".format(target)
    if rate:
        rate.wait("crt.sh")

    resp = requests.get(
        url, headers={"User-Agent": USER_AGENT},
        timeout=float(opts.get("timeout", 25)),
    )
    if resp.status_code == 429:
        retry = resp.headers.get("Retry-After", 10)
        if rate:
            rate.backoff("crt.sh", retry)
        raise RuntimeError("crt.sh rate limited (HTTP 429). Try again shortly.")
    if resp.status_code != 200:
        raise RuntimeError("crt.sh returned HTTP {}".format(resp.status_code))

    try:
        entries = resp.json()
    except json.JSONDecodeError:
        raise RuntimeError("crt.sh returned malformed JSON.")

    names = set()
    for entry in entries:
        for field in ("name_value", "common_name"):
            val = entry.get(field) or ""
            for line in str(val).split("\n"):
                line = line.strip().lower().lstrip("*.")
                if line.endswith(target) and re.match(r"^[a-z0-9._-]+$", line):
                    names.add(line)

    names.discard(target)
    ordered = sorted(names)

    if ordered:
        findings.append(_mk(
            "DNS-010", MODULE_CT, target,
            "{} unique hostname(s) recovered from certificate "
            "transparency logs.".format(len(ordered)),
            {"count": len(ordered), "hostnames": ordered[:200]},
            passive=True, confidence="confirmed",
        ))
        if evidence_log:
            evidence_log.record("ct_query", MODULE_CT, target,
                                {"count": len(ordered)})

    return findings, ordered
