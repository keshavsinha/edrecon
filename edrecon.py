#!/usr/bin/env python3
"""
EDRecon - Explainable Reconnaissance Framework
===============================================

An EDCatalyst teaching tool.
Dr. Keshav Sinha, UPES, Dehradun, India.

Every finding explains WHAT was observed, WHY it matters, and HOW it was
detected -- because a scanner that only prints results teaches students to
read output, not to reason about it.

AUTHORISED USE ONLY. Active modules require a valid scope file.
"""

import argparse
import os
import sys
import time
from datetime import datetime
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from core import output as out
from core.banner import C, VERSION, show_banner
from core.evidence import EvidenceLog, RateLimiter
from core.finding import FindingSet, CONFIDENCE_MEANING
from core.knowledge import kb
from core.scope_guard import ScopeGuard, ScopeError, OutOfScope

from modules.passive import dns_recon
from modules.passive import whois_ct
from modules.system import port_scan
from modules.system import tls_audit
from modules.web import http_audit
from modules.web import content_discovery


# ---------------------------------------------------------------------------
# Module runner -- isolates failures so one broken module never ends the run
# ---------------------------------------------------------------------------

def run_module(fs, name, label, fn, *args, **kwargs):
    out.step(label)
    try:
        result = fn(*args, **kwargs)
    except OutOfScope as exc:
        out.error(str(exc))
        fs.record_error(name, "out of scope")
        return None
    except RuntimeError as exc:
        out.warn("{}: {}".format(name, exc))
        fs.record_error(name, str(exc))
        return None
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        out.warn("{} failed: {}: {}".format(name, type(exc).__name__, exc))
        fs.record_error(name, "{}: {}".format(type(exc).__name__, exc))
        return None
    return result


def emit(fs, findings, brief, explain):
    if not findings:
        out.info("No findings from this module.")
        return
    fs.extend(findings)
    for f in findings:
        out.render_finding(f, brief=brief, explain=explain)


# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------

def phase_passive(fs, target, args, rate, elog, scope):
    out.section("PHASE 1 - PASSIVE RECONNAISSANCE")
    out.info(
        "No packets are sent to the target in this phase. Queries go to "
        "resolvers,\n    registries and public logs, so the target's own "
        "logs stay empty."
    )

    res = run_module(fs, "dns_recon", "DNS records", dns_recon.run,
                     target, scope=scope, evidence_log=elog,
                     opts={"try_axfr": args.axfr, "timeout": args.timeout})
    emit(fs, res, args.brief, not args.no_explain)

    if not args.no_whois:
        res = run_module(fs, "whois_lookup", "WHOIS registration",
                         whois_ct.run_whois, target, evidence_log=elog)
        emit(fs, res, args.brief, not args.no_explain)

    subdomains = []
    if not args.no_ct:
        res = run_module(fs, "cert_transparency",
                         "Certificate transparency logs (crt.sh)",
                         whois_ct.run_ct, target, rate=rate, evidence_log=elog,
                         opts={"timeout": args.timeout + 15})
        if res:
            findings, subdomains = res
            emit(fs, findings, args.brief, not args.no_explain)
            if subdomains and not args.brief:
                out.info("Hostnames recovered ({}):".format(len(subdomains)))
                for s in subdomains[:30]:
                    print(C.GREY + "       " + s + C.RESET)
                if len(subdomains) > 30:
                    print(C.GREY + "       ... and {} more (see report)".format(
                        len(subdomains) - 30) + C.RESET)
    return subdomains


def phase_system(fs, host, args, elog, scope):
    out.section("PHASE 2 - ACTIVE SYSTEM SCAN")
    out.warn(
        "Packets are now being sent to {}. This is logged by the target.".format(host)
    )

    res = run_module(fs, "host_discovery", "Host discovery",
                     port_scan.discover, host, scope,
                     timeout=args.timeout, evidence_log=elog)
    if res is None:
        return []
    findings, alive = res
    emit(fs, findings, args.brief, not args.no_explain)

    if not alive:
        out.warn(
            "No response on common ports. The host may be down, or filtering "
            "all probes.\n    Remember: silence is not proof of absence."
        )
        return []

    ports = port_scan.parse_ports(args.ports)
    out.info("Probing {} port(s) with {} threads...".format(len(ports), args.threads))

    res = run_module(fs, "port_scan", "TCP connect scan", port_scan.scan,
                     host, scope, ports=ports, timeout=args.timeout,
                     threads=args.threads, banners=not args.no_banners,
                     evidence_log=elog)
    if res is None:
        return []
    findings, open_ports = res
    emit(fs, findings, args.brief, not args.no_explain)

    # TLS on any port that looks encrypted
    tls_ports = [p for p in open_ports if p in (443, 8443, 993, 995, 465, 636)]
    for port in tls_ports:
        res = run_module(fs, "tls_audit", "TLS audit on port {}".format(port),
                         tls_audit.audit, host, scope, port=port,
                         timeout=args.timeout + 4, evidence_log=elog)
        emit(fs, res, args.brief, not args.no_explain)

    return open_ports


def phase_web(fs, host, open_ports, args, rate, elog, scope):
    out.section("PHASE 3 - ACTIVE WEB SCAN")

    candidates = []
    if args.url:
        candidates.append(args.url)
    else:
        web_ports = [p for p in (open_ports or []) if p in port_scan.WEB_PORTS]
        if not web_ports:
            web_ports = [80, 443]
        for p in web_ports:
            scheme = "https" if p in (443, 8443) else "http"
            suffix = "" if p in (80, 443) else ":{}".format(p)
            candidates.append("{}://{}{}/".format(scheme, host, suffix))

    seen = set()
    for url in candidates:
        if url in seen:
            continue
        seen.add(url)

        res = run_module(fs, "http_audit", "HTTP audit: {}".format(url),
                         http_audit.audit, url, scope, timeout=args.timeout,
                         rate=rate, evidence_log=elog)
        if res is None:
            continue
        emit(fs, res, args.brief, not args.no_explain)

        if args.discover:
            def progress(done, total):
                pct = 100.0 * done / max(1, total)
                sys.stdout.write(
                    "\r    {}[*]{} content discovery {:.0f}% ({}/{})".format(
                        C.GREY, C.RESET, pct, done, total))
                sys.stdout.flush()

            res = run_module(
                fs, "content_discovery",
                "Content discovery: {}".format(url),
                content_discovery.discover, url, scope,
                wordlist=args.wordlist, delay=args.delay,
                timeout=args.timeout, max_paths=args.max_paths,
                evidence_log=elog, progress=progress,
            )
            sys.stdout.write("\r" + " " * 60 + "\r")
            emit(fs, res, args.brief, not args.no_explain)


# ---------------------------------------------------------------------------
# Knowledge base browsing (no target required)
# ---------------------------------------------------------------------------

def show_kb(term=None):
    base = kb()
    if not base.entries:
        out.error("Knowledge base is empty. Is PyYAML installed, and does "
                  "knowledge/ contain YAML files?")
        return

    if term:
        hits = base.search(term)
        out.section("KNOWLEDGE BASE SEARCH: '{}'".format(term))
        if not hits:
            out.info("No entries matched.")
            return
    else:
        hits = [(k, base.get(k)) for k in base.all_ids()]
        out.section("KNOWLEDGE BASE - {} ENTRIES".format(len(hits)))

    for key, entry in hits:
        print()
        print(C.CYAN + "  [{}] ".format(key) + C.BOLD +
              entry.get("title", "") + C.RESET)
        print(C.GREY + "  " + "-" * 70 + C.RESET)
        for label, field in [
            ("WHAT", "what"), ("WHY", "why_it_matters"),
            ("HOW", "how_detected"), ("VERIFY", "how_to_verify"),
            ("FIX", "how_to_fix"),
        ]:
            if entry.get(field):
                colour = {"WHY": C.YELLOW, "HOW": C.GREEN,
                          "VERIFY": C.MAGENTA, "FIX": C.BLUE}.get(label, C.WHITE)
                print(colour + "  {:<8}".format(label) + C.RESET +
                      out._wrap(entry[field], indent=10))
        if entry.get("concept_tags"):
            print(C.GREY + "  {:<8}".format("TAGS") + " " +
                  " . ".join(entry["concept_tags"]) + C.RESET)
    print()


def show_concepts():
    base = kb()
    concepts = base.concepts()
    out.section("CONCEPT INDEX - {} CONCEPTS".format(len(concepts)))
    for i in range(0, len(concepts), 3):
        print("   " + "".join("{:<26}".format(c) for c in concepts[i:i + 3]))
    print()
    out.info("Search any concept with:  edrecon.py --kb-search <concept>")
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="edrecon.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="EDRecon - explainable reconnaissance for teaching.",
        epilog="""
EXAMPLES
  Passive only (no packets to target, no scope file needed):
    python3 edrecon.py -t example.com --passive-only

  Full scan against an authorised lab target:
    python3 edrecon.py -t 192.168.56.101 --scope scope.yaml --all

  System scan only, custom ports:
    python3 edrecon.py -t 192.168.56.101 --scope scope.yaml \\
        --system --ports 1-1024

  Web scan with content discovery:
    python3 edrecon.py -t 192.168.56.101 --scope scope.yaml \\
        --web --discover

  Browse the knowledge base with no target at all:
    python3 edrecon.py --kb
    python3 edrecon.py --kb-search clickjacking
    python3 edrecon.py --concepts

  Verify an evidence log has not been altered:
    python3 edrecon.py --verify-log reports/evidence_xyz.jsonl

AUTHORISED USE ONLY. Active phases require --scope with a valid,
unexpired authorisation file. There is no override.
""",
    )

    p.add_argument("-t", "--target", help="domain, hostname or IP address")
    p.add_argument("-s", "--scope", help="path to authorisation scope file (YAML)")
    p.add_argument("-u", "--url", help="explicit URL for the web phase")

    ph = p.add_argument_group("phases")
    ph.add_argument("--passive-only", action="store_true",
                    help="passive reconnaissance only; no scope file required")
    ph.add_argument("--system", action="store_true", help="active system scan")
    ph.add_argument("--web", action="store_true", help="active web scan")
    ph.add_argument("--all", action="store_true", help="passive + system + web")

    sc = p.add_argument_group("scan options")
    sc.add_argument("--ports", default="top",
                    help="'top' (default), '1-1024', or '22,80,443'")
    sc.add_argument("--threads", type=int, default=50, help="scan threads (default 50)")
    sc.add_argument("--timeout", type=float, default=3.0,
                    help="per-connection timeout in seconds (default 3)")
    sc.add_argument("--delay", type=float, default=0.35,
                    help="delay between web requests (default 0.35s)")
    sc.add_argument("--no-banners", action="store_true", help="skip banner grabbing")
    sc.add_argument("--axfr", action="store_true",
                    help="attempt zone transfer (ACTIVE; needs scope)")
    sc.add_argument("--discover", action="store_true",
                    help="run content discovery in the web phase")
    sc.add_argument("--wordlist", help="wordlist file for content discovery")
    sc.add_argument("--max-paths", type=int, default=400,
                    help="cap on paths probed (default 400)")
    sc.add_argument("--no-whois", action="store_true", help="skip WHOIS")
    sc.add_argument("--no-ct", action="store_true",
                    help="skip certificate transparency lookup")

    o = p.add_argument_group("output")
    o.add_argument("--brief", action="store_true",
                   help="one line per finding (suppresses the teaching layer)")
    o.add_argument("--no-explain", action="store_true",
                   help="show observations without WHAT/WHY/HOW")
    o.add_argument("--outdir", default="reports", help="report directory")
    o.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    o.add_argument("--no-report", action="store_true", help="skip file output")

    k = p.add_argument_group("knowledge base (no target needed)")
    k.add_argument("--kb", action="store_true", help="print the whole knowledge base")
    k.add_argument("--kb-search", metavar="TERM", help="search the knowledge base")
    k.add_argument("--concepts", action="store_true", help="list all concept tags")
    k.add_argument("--verify-log", metavar="PATH",
                   help="verify the hash chain of an evidence log")

    p.add_argument("--version", action="version",
                   version="EDRecon {} - EDCatalyst / Dr. Keshav Sinha, UPES".format(VERSION))
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    show_banner(no_color=args.no_color)

    # --- knowledge base modes (no target, no scope) ---------------------
    if args.kb:
        show_kb()
        return 0
    if args.kb_search:
        show_kb(args.kb_search)
        return 0
    if args.concepts:
        show_concepts()
        return 0
    if args.verify_log:
        ok, line, msg = EvidenceLog.verify(args.verify_log)
        if ok:
            out.good("Evidence chain intact - no entry has been altered.")
        else:
            out.error("Chain BROKEN at line {}: {}".format(line, msg))
        return 0 if ok else 2

    if not args.target:
        parser.print_help()
        return 1

    target = args.target.strip()
    if "://" in target:
        target = urlparse(target).hostname or target

    do_passive = args.passive_only or args.all or not (args.system or args.web)
    do_system = args.system or args.all
    do_web = args.web or args.all

    # --- scope enforcement ----------------------------------------------
    scope = None
    if do_system or do_web or args.axfr:
        try:
            scope = ScopeGuard(args.scope)
        except ScopeError as exc:
            out.error(str(exc))
            print()
            out.info("Active scanning is refused without a valid scope file.")
            out.info("Passive reconnaissance needs no scope:  "
                     "edrecon.py -t {} --passive-only".format(target))
            print()
            return 3

        out.section("AUTHORISATION")
        print(scope.summary())
        print()
        try:
            scope.assert_in_scope(target)
            out.good("Target '{}' is within the authorised scope.".format(target))
        except OutOfScope as exc:
            out.error(str(exc))
            return 3

    # --- run -------------------------------------------------------------
    fs = FindingSet(target)
    rate = RateLimiter(delay=args.delay)
    started = time.time()

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = "".join(ch if ch.isalnum() or ch in ".-_" else "_" for ch in target)
    elog = None
    if not args.no_report:
        elog = EvidenceLog(os.path.join(
            args.outdir, "evidence_{}_{}.jsonl".format(safe, stamp)))
        elog.record("scan_start", "edrecon", target,
                    {"version": VERSION,
                     "phases": {"passive": do_passive, "system": do_system,
                                "web": do_web},
                     "scope_file": scope.path if scope else None})

    open_ports = []
    try:
        if do_passive:
            phase_passive(fs, target, args, rate, elog, scope)
        if do_system:
            open_ports = phase_system(fs, target, args, elog, scope) or []
        if do_web:
            phase_web(fs, target, open_ports, args, rate, elog, scope)
    except KeyboardInterrupt:
        print()
        out.warn("Interrupted by user. Reporting what was collected so far.")

    elapsed = time.time() - started

    # --- summary ----------------------------------------------------------
    out.render_summary(fs, elapsed)

    if not args.brief and fs.findings:
        out.section("READING THIS REPORT")
        print(C.GREY + "   Confidence levels used above:" + C.RESET)
        for level, meaning in CONFIDENCE_MEANING.items():
            print("   " + C.CYAN + "{:<11}".format(level) + C.RESET +
                  out._wrap(meaning, indent=14))
        print()

    if not args.no_report:
        jpath = os.path.join(args.outdir, "report_{}_{}.json".format(safe, stamp))
        hpath = os.path.join(args.outdir, "report_{}_{}.html".format(safe, stamp))
        out.save_json(fs, jpath)
        out.save_html(fs, hpath)
        if elog:
            elog.record("scan_end", "edrecon", target,
                        {"findings": len(fs), "seconds": round(elapsed, 1)})

        out.section("ARTEFACTS")
        out.good("HTML report : " + hpath)
        out.good("JSON report : " + jpath)
        if elog:
            out.good("Evidence log: " + elog.path)
            print(C.GREY + "                 verify with: python3 edrecon.py "
                  "--verify-log " + elog.path + C.RESET)
        print()

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Aborted.")
        sys.exit(130)
