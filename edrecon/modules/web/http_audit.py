"""
ACTIVE - HTTP fingerprinting, security header audit, form analysis.

All requests are ordinary GET/HEAD requests to documents the server is
already publishing. Nothing here submits data or attempts injection - the
tool stops at "here is the attack surface and its misconfigurations",
which is the correct boundary for a recon tool.
"""

import re
from urllib.parse import urljoin, urlparse

from core.finding import Finding
from core.knowledge import kb
from core.evidence import USER_AGENT

MODULE = "http_audit"

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAVE_BS4 = True
except ImportError:
    HAVE_BS4 = False


DISCLOSURE_HEADERS = [
    "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-runtime", "x-version",
]


def _mk(fid, target, observation, evidence=None, **kw):
    f = Finding(id=fid, module=MODULE, target=target, title="",
                observation=observation, evidence=evidence or {},
                passive=False, **kw)
    return f.enrich(kb().get(fid))


def _session(timeout):
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    s.verify = False
    return s


def audit(url, scope, timeout=10, rate=None, evidence_log=None):
    """Fetch the URL and audit headers, cookies and forms."""
    if not HAVE_REQUESTS:
        raise RuntimeError("requests not installed. Run: pip install requests")

    parsed = urlparse(url if "://" in url else "http://" + url)
    host = parsed.hostname
    scope.assert_in_scope(host)

    import urllib3
    urllib3.disable_warnings()

    findings = []
    sess = _session(timeout)
    if rate:
        rate.wait(host)

    resp = sess.get(url, timeout=timeout, allow_redirects=True)
    headers = {k.lower(): v for k, v in resp.headers.items()}

    findings.append(_mk(
        "HTTP-001", url,
        "HTTP {} received. Final URL after redirects: {}".format(
            resp.status_code, resp.url),
        {"status": resp.status_code, "final_url": resp.url,
         "length": len(resp.content),
         "redirect_chain": [r.url for r in resp.history]},
        confidence="confirmed",
    ))

    # --- server / stack disclosure --------------------------------------
    server = headers.get("server")
    if server:
        has_version = bool(re.search(r"\d+\.\d+", server))
        findings.append(_mk(
            "HTTP-002", url,
            "Server header: {}{}".format(
                server,
                " (includes a version number)" if has_version else
                " (version suppressed)"),
            {"server": server, "version_disclosed": has_version},
            confidence="probable",
        ))

    stack = {h: headers[h] for h in DISCLOSURE_HEADERS if h in headers}
    if stack:
        findings.append(_mk(
            "HTTP-003", url,
            "Technology headers present: {}".format(
                "; ".join("{}: {}".format(k, v) for k, v in stack.items())),
            {"headers": stack},
            confidence="probable",
        ))

    # --- HTTP -> HTTPS redirect -----------------------------------------
    if parsed.scheme == "http":
        if not resp.url.lower().startswith("https://"):
            findings.append(_mk(
                "WEB-001", url,
                "Plain HTTP request returned content (HTTP {}) without "
                "redirecting to HTTPS.".format(resp.status_code),
                {"final_url": resp.url, "status": resp.status_code},
                confidence="confirmed",
            ))

    # --- security headers ------------------------------------------------
    csp = headers.get("content-security-policy", "")

    if parsed.scheme == "https" or resp.url.startswith("https://"):
        if "strict-transport-security" not in headers:
            findings.append(_mk(
                "HDR-001", url,
                "No Strict-Transport-Security header in the response.",
                {}, confidence="confirmed",
            ))
        else:
            findings.append(_mk(
                "HDR-006", url,
                "Strict-Transport-Security present: {}".format(
                    headers["strict-transport-security"]),
                {"value": headers["strict-transport-security"]},
                confidence="confirmed",
            ))

    if not csp:
        findings.append(_mk(
            "HDR-002", url,
            "No Content-Security-Policy header in the response.",
            {}, confidence="confirmed",
        ))
    else:
        weak = []
        if "unsafe-inline" in csp:
            weak.append("unsafe-inline")
        if "unsafe-eval" in csp:
            weak.append("unsafe-eval")
        f = _mk(
            "HDR-006", url,
            "Content-Security-Policy present{}".format(
                " but weakened by {}".format(", ".join(weak)) if weak else ""),
            {"csp": csp[:500], "weak_directives": weak},
            confidence="confirmed",
        )
        if weak:
            f.severity = "low"
            f.title = "Content-Security-Policy present but permissive"
        findings.append(f)

    if "x-frame-options" not in headers and "frame-ancestors" not in csp:
        findings.append(_mk(
            "HDR-003", url,
            "Neither X-Frame-Options nor a CSP frame-ancestors directive "
            "is present.",
            {}, confidence="confirmed",
        ))

    if headers.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(_mk(
            "HDR-004", url,
            "X-Content-Type-Options is missing or not set to 'nosniff'.",
            {"value": headers.get("x-content-type-options")},
            confidence="confirmed",
        ))

    # --- cookies ---------------------------------------------------------
    for cookie in resp.cookies:
        missing = []
        if not cookie.secure:
            missing.append("Secure")
        rest = {k.lower(): v for k, v in (cookie._rest or {}).items()}
        if "httponly" not in rest:
            missing.append("HttpOnly")
        if "samesite" not in rest:
            missing.append("SameSite")
        if missing:
            findings.append(_mk(
                "HDR-005", url,
                "Cookie '{}' set without: {}".format(
                    cookie.name, ", ".join(missing)),
                {"cookie": cookie.name, "missing_flags": missing},
                confidence="confirmed",
            ))

    # --- robots.txt -------------------------------------------------------
    try:
        robots_url = urljoin(resp.url, "/robots.txt")
        if rate:
            rate.wait(host)
        r = sess.get(robots_url, timeout=timeout)
        if r.status_code == 200 and "user-agent" in r.text.lower():
            disallowed = re.findall(r"(?im)^\s*Disallow:\s*(\S+)", r.text)
            if disallowed:
                findings.append(_mk(
                    "WEB-004", robots_url,
                    "{} Disallow entries published: {}".format(
                        len(disallowed), ", ".join(disallowed[:12])),
                    {"disallowed": disallowed[:60]},
                    confidence="confirmed",
                ))
    except requests.RequestException:
        pass

    # --- forms -------------------------------------------------------------
    if HAVE_BS4 and resp.text:
        findings.extend(_analyse_forms(resp.text, resp.url))

    if evidence_log:
        evidence_log.record("http_audit", MODULE, url,
                            {"status": resp.status_code, "server": server})

    return findings


def _analyse_forms(body, base_url):
    findings = []
    try:
        soup = BeautifulSoup(body, "html.parser")
    except Exception:
        return findings

    for form in soup.find_all("form"):
        method = (form.get("method") or "GET").upper()
        action = form.get("action") or ""
        action_url = urljoin(base_url, action)

        inputs = []
        has_password = False
        has_csrf = False
        for inp in form.find_all(["input", "select", "textarea"]):
            itype = (inp.get("type") or "text").lower()
            iname = inp.get("name") or ""
            inputs.append({"name": iname, "type": itype})
            if itype == "password":
                has_password = True
            if re.search(r"csrf|token|authenticity|nonce", iname, re.I):
                has_csrf = True

        note = ""
        if method == "POST" and not has_csrf:
            note = " No CSRF token field detected on this state-changing form."

        findings.append(_mk(
            "WEB-005", action_url,
            "{} form with {} input(s) -> {}.{}".format(
                method, len(inputs), action_url, note),
            {"method": method, "action": action_url, "inputs": inputs,
             "csrf_field_present": has_csrf},
            confidence="confirmed",
        ))

        if has_password and action_url.lower().startswith("http://"):
            findings.append(_mk(
                "WEB-006", action_url,
                "Form containing a password field submits to a cleartext "
                "HTTP URL: {}".format(action_url),
                {"action": action_url},
                confidence="confirmed",
            ))

    return findings
