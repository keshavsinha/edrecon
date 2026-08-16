"""
ACTIVE - content discovery (forced browsing).

Teaching emphasis: the baseline. A naive scanner reports every 200 status
as a hit, which produces pages of noise against any server with a custom
404 handler. Before probing anything, this module requests a path that
certainly does not exist and records what the server does. Every
subsequent response is compared against that baseline.

Rate limiting is mandatory here, not optional - unthrottled content
discovery is indistinguishable from a denial-of-service attempt.
"""

import hashlib
import re
import time
from urllib.parse import urljoin, urlparse

from core.finding import Finding
from core.knowledge import kb
from core.evidence import USER_AGENT

MODULE = "content_discovery"

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False


DEFAULT_PATHS = [
    "admin/", "administrator/", "login", "login.php", "wp-admin/",
    "wp-login.php", "phpmyadmin/", "manager/html", "cgi-bin/",
    "console", "dashboard", "panel", "portal",
    ".git/HEAD", ".git/config", ".svn/entries", ".hg/",
    ".env", ".env.local", ".env.backup",
    "config.php", "config.php.bak", "configuration.php",
    "web.config", "settings.py", "application.yml",
    "backup/", "backup.zip", "backup.tar.gz", "db.sql", "dump.sql",
    "database.sql", "site.zip", "www.zip", "old/", "bak/", "tmp/",
    "test/", "dev/", "staging/", "beta/",
    "server-status", "server-info", "status", "health", "metrics",
    "api/", "api/v1/", "api/docs", "swagger.json", "swagger-ui.html",
    "openapi.json", "graphql",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "security.txt",
    ".well-known/security.txt", "readme.html", "README.md",
    "info.php", "phpinfo.php", "test.php",
    "uploads/", "files/", "images/", "assets/", "static/",
    "logs/", "log/", "error.log", "access.log", "debug.log",
]

INDEX_MARKERS = [
    "index of /", "<title>index of", "directory listing for",
    "[to parent directory]", "parent directory</a>",
]


def _mk(fid, target, observation, evidence=None, **kw):
    f = Finding(id=fid, module=MODULE, target=target, title="",
                observation=observation, evidence=evidence or {},
                passive=False, **kw)
    return f.enrich(kb().get(fid))


def _fingerprint(resp):
    """Status + rounded length + body hash: enough to spot soft-404s."""
    body = resp.content or b""
    return {
        "status": resp.status_code,
        "length": len(body),
        "hash": hashlib.sha256(body).hexdigest()[:16],
    }


def _load_wordlist(path):
    if not path:
        return list(DEFAULT_PATHS)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            words = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        return words or list(DEFAULT_PATHS)
    except OSError:
        return list(DEFAULT_PATHS)


def discover(base_url, scope, wordlist=None, delay=0.35, timeout=8,
             max_paths=400, evidence_log=None, progress=None):
    """
    Wordlist-driven path discovery with baseline comparison.
    Scope-gated. Rate-limited by construction.
    """
    if not HAVE_REQUESTS:
        raise RuntimeError("requests not installed. Run: pip install requests")

    parsed = urlparse(base_url if "://" in base_url else "http://" + base_url)
    host = parsed.hostname
    scope.assert_in_scope(host)

    import urllib3
    urllib3.disable_warnings()

    if not base_url.endswith("/"):
        base_url += "/"

    sess = requests.Session()
    sess.headers.update({"User-Agent": USER_AGENT})
    sess.verify = False

    findings = []

    # --- establish the baseline -----------------------------------------
    baselines = []
    for probe in ("edrecon-baseline-a9f3c1x/", "edrecon-baseline-7k2m8q.html"):
        try:
            r = sess.get(urljoin(base_url, probe), timeout=timeout,
                         allow_redirects=False)
            baselines.append(_fingerprint(r))
        except requests.RequestException:
            pass
        time.sleep(delay)

    baseline_statuses = {b["status"] for b in baselines}
    baseline_hashes = {b["hash"] for b in baselines}
    baseline_lengths = {b["length"] for b in baselines}

    soft_404 = 200 in baseline_statuses
    if soft_404:
        findings.append(_mk(
            "HTTP-001", base_url,
            "Server returns HTTP 200 for non-existent paths (soft 404). "
            "Results below are filtered by body hash and length, not "
            "status code alone.",
            {"baseline": baselines},
            confidence="confirmed",
        ))

    words = _load_wordlist(wordlist)[:max_paths]
    total = len(words)

    for idx, word in enumerate(words, 1):
        if progress and idx % 25 == 0:
            progress(idx, total)

        url = urljoin(base_url, word.lstrip("/"))
        try:
            r = sess.get(url, timeout=timeout, allow_redirects=False)
        except requests.RequestException:
            time.sleep(delay)
            continue

        time.sleep(delay)

        if r.status_code == 429:
            retry = r.headers.get("Retry-After", 5)
            try:
                time.sleep(min(float(retry), 30))
            except (TypeError, ValueError):
                time.sleep(5)
            continue

        fp = _fingerprint(r)

        # Filter against baseline
        if fp["hash"] in baseline_hashes:
            continue
        if r.status_code in (404, 400):
            continue
        if soft_404 and fp["length"] in baseline_lengths:
            continue
        if r.status_code not in (200, 201, 204, 301, 302, 307, 401, 403, 500):
            continue

        body_l = (r.text or "")[:4000].lower()

        # Directory listing?
        if r.status_code == 200 and any(m in body_l for m in INDEX_MARKERS):
            findings.append(_mk(
                "WEB-003", url,
                "Directory listing enabled at {} (HTTP 200).".format(url),
                {"url": url, "length": fp["length"]},
                confidence="confirmed",
            ))
            continue

        # Version control exposure?
        if re.search(r"/\.(git|svn|hg)/", url) and r.status_code == 200:
            findings.append(_mk(
                "WEB-007", url,
                "Version control artefact reachable: {} (HTTP 200, "
                "{} bytes).".format(url, fp["length"]),
                {"url": url, "length": fp["length"],
                 "preview": (r.text or "")[:200]},
                confidence="confirmed",
            ))
            continue

        # Generic hit
        interpretation = {
            200: "exists and is readable",
            201: "exists",
            204: "exists, empty response",
            301: "redirects to {}".format(r.headers.get("Location", "?")),
            302: "redirects to {}".format(r.headers.get("Location", "?")),
            307: "redirects to {}".format(r.headers.get("Location", "?")),
            401: "exists but requires authentication",
            403: "exists but access is forbidden - the path is confirmed",
            500: "exists and triggered a server error",
        }.get(r.status_code, "responded")

        f = _mk(
            "WEB-002", url,
            "{} -> HTTP {} ({}), {} bytes.".format(
                url, r.status_code, interpretation, fp["length"]),
            {"url": url, "status": r.status_code, "length": fp["length"],
             "content_type": r.headers.get("Content-Type", "")},
            confidence="confirmed",
        )
        if r.status_code in (401, 403):
            f.severity = "low"
        findings.append(f)

        if evidence_log:
            evidence_log.record("path_found", MODULE, url,
                                {"status": r.status_code, "length": fp["length"]})

    return findings
