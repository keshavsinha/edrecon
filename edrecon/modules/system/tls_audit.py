"""
ACTIVE - TLS configuration and certificate audit.

Purely observational: we complete handshakes and read what the server
offers. No data is sent beyond the handshake itself.

The version-probing loop is a good classroom demonstration - it shows that
"which TLS versions does this server support" is not a single question but
one handshake attempt per version.
"""

import socket
import ssl
from datetime import datetime, timezone, timedelta

from core.finding import Finding
from core.knowledge import kb

MODULE = "tls_audit"

WEAK_CIPHER_MARKERS = ["RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "anon"]

NO_PFS_MARKERS = ["TLS_RSA_", "AES128-", "AES256-", "DES-CBC3-SHA"]


def _mk(fid, target, observation, evidence=None, **kw):
    f = Finding(id=fid, module=MODULE, target=target, title="",
                observation=observation, evidence=evidence or {},
                passive=False, **kw)
    return f.enrich(kb().get(fid))


def _parse_dn(dn_tuple):
    out = {}
    for rdn in dn_tuple or ():
        for key, val in rdn:
            out[key] = val
    return out


def _hostname_matches(hostname, cert):
    names = []
    for typ, val in cert.get("subjectAltName", ()) or ():
        if typ == "DNS":
            names.append(val.lower())
    subject = _parse_dn(cert.get("subject"))
    if subject.get("commonName"):
        names.append(subject["commonName"].lower())

    host = hostname.lower()
    for name in names:
        if name == host:
            return True, names
        if name.startswith("*."):
            suffix = name[1:]
            if host.endswith(suffix) and host.count(".") == name.count("."):
                return True, names
    return False, names


def audit(host, scope, port=443, timeout=8, evidence_log=None):
    """Full TLS audit. Scope-gated before any connection."""
    scope.assert_in_scope(host)
    findings = []

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                cipher = tls.cipher()
                version = tls.version()
    except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError) as exc:
        raise RuntimeError("TLS handshake failed on {}:{} - {}".format(host, port, exc))

    if not cert:
        raise RuntimeError("No certificate returned by {}:{}".format(host, port))

    subject = _parse_dn(cert.get("subject"))
    issuer = _parse_dn(cert.get("issuer"))
    cn = subject.get("commonName", "unknown")
    issuer_cn = issuer.get("commonName", issuer.get("organizationName", "unknown"))

    san = [v for t, v in (cert.get("subjectAltName") or ()) if t == "DNS"]

    not_after = None
    if cert.get("notAfter"):
        try:
            not_after = datetime.strptime(
                cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            not_after = None

    findings.append(_mk(
        "TLS-001", host,
        "Certificate for CN={} issued by {}. Valid until {}.".format(
            cn, issuer_cn,
            not_after.date().isoformat() if not_after else "unknown"),
        {"subject": subject, "issuer": issuer,
         "not_after": cert.get("notAfter"), "san_count": len(san)},
        confidence="confirmed",
    ))

    # --- expiry ---------------------------------------------------------
    now = datetime.now(timezone.utc)
    if not_after:
        if not_after < now:
            findings.append(_mk(
                "TLS-002", host,
                "Certificate expired on {} ({} days ago).".format(
                    not_after.date().isoformat(), (now - not_after).days),
                {"not_after": cert.get("notAfter")},
                confidence="confirmed",
            ))
        elif not_after < now + timedelta(days=30):
            findings.append(_mk(
                "TLS-003", host,
                "Certificate expires on {} ({} days remaining).".format(
                    not_after.date().isoformat(), (not_after - now).days),
                {"not_after": cert.get("notAfter")},
                confidence="confirmed",
            ))

    # --- hostname match -------------------------------------------------
    matched, names = _hostname_matches(host, cert)
    if not matched and names:
        findings.append(_mk(
            "TLS-004", host,
            "Hostname '{}' not covered by certificate names: {}".format(
                host, ", ".join(names[:8])),
            {"requested": host, "cert_names": names},
            confidence="confirmed",
        ))

    # --- self-signed ----------------------------------------------------
    if subject and issuer and subject == issuer:
        findings.append(_mk(
            "TLS-005", host,
            "Certificate is self-signed (issuer equals subject: {}).".format(cn),
            {"subject_cn": cn},
            confidence="confirmed",
        ))

    # --- SAN disclosure -------------------------------------------------
    if len(san) > 1:
        findings.append(_mk(
            "TLS-009", host,
            "{} hostnames listed in the SAN extension: {}".format(
                len(san), ", ".join(san[:10]) + ("..." if len(san) > 10 else "")),
            {"san": san},
            confidence="confirmed",
        ))

    # --- negotiated cipher ----------------------------------------------
    if cipher:
        cipher_name, cipher_proto, cipher_bits = cipher
        weak = [m for m in WEAK_CIPHER_MARKERS if m in cipher_name.upper()]
        no_pfs = any(cipher_name.startswith(m) for m in NO_PFS_MARKERS)
        if weak or no_pfs:
            reason = "weak algorithm ({})".format(", ".join(weak)) if weak \
                else "no forward secrecy"
            findings.append(_mk(
                "TLS-008", host,
                "Negotiated {} ({} bits) - {}.".format(
                    cipher_name, cipher_bits, reason),
                {"cipher": cipher_name, "bits": cipher_bits,
                 "protocol": cipher_proto},
                confidence="confirmed",
            ))

    # --- version probing ------------------------------------------------
    supported = _probe_versions(host, port, timeout)
    obsolete = [v for v in supported if v in ("SSLv3", "TLSv1", "TLSv1.1")]
    modern = [v for v in supported if v in ("TLSv1.2", "TLSv1.3")]

    if obsolete:
        findings.append(_mk(
            "TLS-006", host,
            "Server accepts deprecated protocol version(s): {}".format(
                ", ".join(obsolete)),
            {"obsolete": obsolete, "all_supported": supported},
            confidence="confirmed",
        ))
    if modern:
        findings.append(_mk(
            "TLS-007", host,
            "Server supports {} (negotiated {} on the default "
            "handshake).".format(", ".join(modern), version),
            {"modern": modern, "negotiated": version},
            confidence="confirmed",
        ))

    if evidence_log:
        evidence_log.record("tls_audit", MODULE, host,
                            {"cn": cn, "versions": supported})

    return findings


def _probe_versions(host, port, timeout):
    """One pinned handshake per version - the honest way to enumerate."""
    supported = []
    candidates = []

    for label, attr in [
        ("TLSv1", "TLSv1"), ("TLSv1.1", "TLSv1_1"),
        ("TLSv1.2", "TLSv1_2"), ("TLSv1.3", "TLSv1_3"),
    ]:
        ver = getattr(ssl.TLSVersion, attr, None)
        if ver is not None:
            candidates.append((label, ver))

    for label, ver in candidates:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            try:
                ctx.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                pass
            with socket.create_connection((host, port), timeout=timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host):
                    supported.append(label)
        except Exception:
            continue
    return supported
