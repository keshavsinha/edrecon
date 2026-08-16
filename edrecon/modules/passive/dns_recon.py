"""
PASSIVE - DNS reconnaissance.

No packet reaches the target. Queries go to a recursive resolver, which
does the work on our behalf. This is the cleanest illustration of what
"passive" actually means, and worth stressing in class: passive does not
mean undetectable, it means the target's own logs show nothing.

AXFR is the one exception and is labelled ACTIVE, because a zone transfer
request goes directly to the target's authoritative nameserver.
"""

from core.finding import Finding
from core.knowledge import kb

MODULE = "dns_recon"

try:
    import dns.resolver
    import dns.query
    import dns.zone
    import dns.exception
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False


def _mk(fid, target, observation, evidence=None, **kw):
    f = Finding(id=fid, module=MODULE, target=target,
                title="", observation=observation,
                evidence=evidence or {}, **kw)
    return f.enrich(kb().get(fid))


def run(target, scope=None, evidence_log=None, opts=None):
    """Returns a list of Findings. Never raises."""
    opts = opts or {}
    findings = []

    if not HAVE_DNS:
        raise RuntimeError(
            "dnspython not installed. Run: pip install dnspython"
        )

    resolver = dns.resolver.Resolver()
    resolver.timeout = float(opts.get("timeout", 5))
    resolver.lifetime = float(opts.get("timeout", 5))

    def q(name, rtype):
        try:
            return resolver.resolve(name, rtype)
        except Exception:
            return []

    # --- A / AAAA -------------------------------------------------------
    addrs = []
    for rtype in ("A", "AAAA"):
        for rdata in q(target, rtype):
            addrs.append(str(rdata))
    if addrs:
        findings.append(_mk(
            "DNS-001", target,
            "Resolved to: {}".format(", ".join(addrs)),
            {"addresses": addrs},
            passive=True, confidence="confirmed",
        ))
        if evidence_log:
            evidence_log.record("dns_resolve", MODULE, target, {"addresses": addrs})

    # --- NS -------------------------------------------------------------
    nameservers = [str(r).rstrip(".") for r in q(target, "NS")]
    if nameservers:
        findings.append(_mk(
            "DNS-007", target,
            "Authoritative nameservers: {}".format(", ".join(nameservers)),
            {"nameservers": nameservers},
            passive=True,
        ))

    # --- MX -------------------------------------------------------------
    mx = []
    for r in q(target, "MX"):
        mx.append(str(r))
    if mx:
        provider = "self-hosted or unknown"
        blob = " ".join(mx).lower()
        if "google" in blob or "googlemail" in blob:
            provider = "Google Workspace"
        elif "outlook" in blob or "protection.outlook" in blob:
            provider = "Microsoft 365"
        elif "zoho" in blob:
            provider = "Zoho Mail"
        findings.append(_mk(
            "DNS-002", target,
            "MX records: {} (provider appears to be {})".format(
                "; ".join(mx), provider),
            {"mx": mx, "provider_guess": provider},
            passive=True,
            confidence="probable" if provider != "self-hosted or unknown" else "confirmed",
        ))

    # --- TXT / SPF ------------------------------------------------------
    txts = []
    for r in q(target, "TXT"):
        txt = str(r).strip('"').replace('" "', "")
        txts.append(txt)

    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    if spf:
        record = spf[0]
        includes = [
            part.split(":", 1)[1]
            for part in record.split()
            if part.lower().startswith("include:")
        ]
        mech = "-all" if "-all" in record else ("~all" if "~all" in record else "unspecified")
        findings.append(_mk(
            "DNS-003", target,
            "SPF present, terminates with '{}'. Third-party senders: {}".format(
                mech, ", ".join(includes) if includes else "none"),
            {"record": record, "includes": includes, "all_mechanism": mech},
            passive=True,
        ))
    else:
        findings.append(_mk(
            "DNS-004", target,
            "No v=spf1 TXT record published for this domain.",
            {"txt_records_seen": len(txts)},
            passive=True,
        ))

    other_txt = [
        t for t in txts
        if not t.lower().startswith("v=spf1") and not t.lower().startswith("v=dmarc1")
    ]
    if other_txt:
        findings.append(_mk(
            "DNS-009", target,
            "{} non-SPF TXT record(s) present, typically SaaS "
            "verification tokens.".format(len(other_txt)),
            {"records": other_txt[:20]},
            passive=True,
        ))

    # --- DMARC ----------------------------------------------------------
    dmarc = []
    for r in q("_dmarc." + target, "TXT"):
        dmarc.append(str(r).strip('"').replace('" "', ""))
    dmarc = [d for d in dmarc if d.lower().startswith("v=dmarc1")]
    if dmarc:
        record = dmarc[0]
        policy = "none"
        for part in record.split(";"):
            part = part.strip()
            if part.lower().startswith("p="):
                policy = part.split("=", 1)[1].strip()
        sev = "medium" if policy.lower() == "none" else "info"
        extra = ""
        if policy.lower() == "none":
            extra = (
                " Policy is p=none, which only monitors - spoofed mail is "
                "still delivered."
            )
        f = _mk(
            "DNS-005", target,
            "DMARC published with policy p={}.{}".format(policy, extra),
            {"record": record, "policy": policy},
            passive=True,
        )
        f.severity = sev
        findings.append(f)
    else:
        findings.append(_mk(
            "DNS-006", target,
            "No DMARC record at _dmarc.{}".format(target),
            {}, passive=True,
        ))

    # --- AXFR (ACTIVE - scope gated) ------------------------------------
    if opts.get("try_axfr") and nameservers:
        if scope is None:
            raise RuntimeError("AXFR requires a scope file (active check).")
        scope.assert_in_scope(target)
        for ns in nameservers:
            try:
                ns_ip = str(resolver.resolve(ns, "A")[0])
            except Exception:
                continue
            try:
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns_ip, target, timeout=8, lifetime=8)
                )
                names = [str(n) for n in zone.nodes.keys()]
                findings.append(_mk(
                    "DNS-008", target,
                    "Nameserver {} returned the full zone: {} records "
                    "disclosed.".format(ns, len(names)),
                    {"nameserver": ns, "record_count": len(names),
                     "sample": names[:40]},
                    passive=False, confidence="confirmed",
                ))
                if evidence_log:
                    evidence_log.record("axfr_success", MODULE, target,
                                        {"nameserver": ns, "records": len(names)})
            except Exception:
                continue  # refused = correctly configured

    return findings


def enumerate_subdomains(target, names, opts=None):
    """Resolve a candidate list, return Findings for those that exist."""
    findings = []
    if not HAVE_DNS:
        return findings
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    seen = set()
    for name in names:
        if name in seen:
            continue
        seen.add(name)
        try:
            answers = resolver.resolve(name, "A")
            ips = [str(a) for a in answers]
            findings.append(_mk(
                "DNS-010", name,
                "Subdomain resolves to {}".format(", ".join(ips)),
                {"host": name, "addresses": ips},
                passive=True,
            ))
        except Exception:
            continue
    return findings
