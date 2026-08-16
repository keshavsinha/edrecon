"""
Renderers.

Console output is the teaching surface: each finding is printed as a
labelled block (OBSERVED / WHAT / WHY / HOW / VERIFY / FIX) rather than a
single cryptic line. --brief collapses this to one line per finding for
users who already know the material.
"""

import html
import json
import os
import textwrap
from datetime import datetime, timezone

from core.banner import C, VERSION
from core.finding import SEVERITY_MEANING, CONFIDENCE_MEANING

SEV_COLOR = {
    "info": C.BLUE,
    "low": C.CYAN,
    "medium": C.YELLOW,
    "high": C.RED,
    "critical": C.MAGENTA,
}

SEV_HTML = {
    "info": "#3b82f6",
    "low": "#06b6d4",
    "medium": "#f59e0b",
    "high": "#ef4444",
    "critical": "#a855f7",
}

WIDTH = 74


def _wrap(text, indent=11):
    if not text:
        return ""
    pad = " " * indent
    return textwrap.fill(
        str(text).strip(),
        width=WIDTH + indent,
        initial_indent="",
        subsequent_indent=pad,
    )


def info(msg):
    print(C.BLUE + "[i] " + C.RESET + msg)


def good(msg):
    print(C.GREEN + "[+] " + C.RESET + msg)


def warn(msg):
    print(C.YELLOW + "[!] " + C.RESET + msg)


def error(msg):
    print(C.RED + "[x] " + C.RESET + msg)


def step(msg):
    print(C.CYAN + "\n[>] " + C.BOLD + msg + C.RESET)


def section(title):
    print()
    print(C.CYAN + "=" * WIDTH + C.RESET)
    print(C.BOLD + C.WHITE + "  " + title + C.RESET)
    print(C.CYAN + "=" * WIDTH + C.RESET)


def render_finding(f, brief=False, explain=True):
    """Print a single finding."""
    color = SEV_COLOR.get(f.severity, C.WHITE)

    if brief:
        print(
            "{}[{:<8}]{} {:<10} {} {}".format(
                color,
                f.severity.upper(),
                C.RESET,
                f.id,
                f.title,
                C.GREY + "(" + f.target + ")" + C.RESET,
            )
        )
        return

    print()
    print(
        color
        + "  ["
        + f.id
        + "] "
        + C.BOLD
        + f.title
        + C.RESET
        + C.GREY
        + "  "
        + "." * max(2, WIDTH - len(f.id) - len(f.title) - 20)
        + " "
        + f.severity
        + C.RESET
    )
    print(C.GREY + "  " + "-" * (WIDTH - 2) + C.RESET)

    mode = "PASSIVE" if f.passive else "ACTIVE"
    print(
        C.GREY
        + "  {:<9}".format("SOURCE")
        + C.RESET
        + "{} module '{}' | confidence: {}".format(mode, f.module, f.confidence)
    )

    if f.observation:
        print(C.WHITE + "  {:<9}".format("OBSERVED") + C.RESET + _wrap(f.observation))
    if explain:
        if f.what:
            print(C.CYAN + "  {:<9}".format("WHAT") + C.RESET + _wrap(f.what))
        if f.why_it_matters:
            print(C.YELLOW + "  {:<9}".format("WHY") + C.RESET + _wrap(f.why_it_matters))
        if f.how_detected:
            print(C.GREEN + "  {:<9}".format("HOW") + C.RESET + _wrap(f.how_detected))
        if f.how_to_verify:
            print(C.MAGENTA + "  {:<9}".format("VERIFY") + C.RESET + _wrap(f.how_to_verify))
        if f.how_to_fix:
            print(C.BLUE + "  {:<9}".format("FIX") + C.RESET + _wrap(f.how_to_fix))
        if f.references:
            print(C.GREY + "  {:<9}".format("REFS") + " " + " | ".join(f.references) + C.RESET)
        if f.concept_tags:
            print(C.GREY + "  {:<9}".format("TAGS") + " " + " . ".join(f.concept_tags) + C.RESET)


def render_summary(fs, elapsed):
    """End-of-scan summary, including the 'what you learned' block."""
    section("SCAN SUMMARY")

    counts = fs.by_severity()
    print("   Target        : " + C.BOLD + fs.target + C.RESET)
    print("   Findings      : " + str(len(fs)))
    print("   Duration      : {:.1f}s".format(elapsed))
    print()
    for sev in ["critical", "high", "medium", "low", "info"]:
        if counts.get(sev):
            print(
                "   {}{:<10}{} {:>3}   {}{}".format(
                    SEV_COLOR.get(sev, ""),
                    sev,
                    C.RESET,
                    counts[sev],
                    C.GREY + SEVERITY_MEANING[sev],
                    C.RESET,
                )
            )

    if fs.errors:
        print()
        warn("{} module(s) reported errors (scan continued):".format(len(fs.errors)))
        for e in fs.errors:
            print(C.GREY + "       {}: {}".format(e["module"], e["error"]) + C.RESET)

    concepts = fs.concepts_touched()
    if concepts:
        section("WHAT THIS SCAN TAUGHT YOU")
        print(
            C.GREY
            + "   Concepts exercised in this run -- revisit any that are unfamiliar:"
            + C.RESET
        )
        print()
        for i in range(0, len(concepts), 3):
            row = concepts[i:i + 3]
            print("   " + "".join(C.CYAN + "* " + C.RESET + "{:<22}".format(c) for c in row))
    print()


def save_json(fs, path):
    data = {
        "tool": "EDRecon",
        "version": VERSION,
        "author": "Dr. Keshav Sinha, UPES, India",
        "project": "EDCatalyst",
        "target": fs.target,
        "generated": datetime.now(timezone.utc).isoformat(),
        "summary": fs.by_severity(),
        "concepts": fs.concepts_touched(),
        "errors": fs.errors,
        "findings": [f.to_dict() for f in fs.sorted_by_severity()],
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    return path


def save_html(fs, path):
    e = html.escape
    counts = fs.by_severity()

    cards = []
    for f in fs.sorted_by_severity():
        color = SEV_HTML.get(f.severity, "#666")
        rows = []
        for label, value, cls in [
            ("OBSERVED", f.observation, "obs"),
            ("WHAT", f.what, "what"),
            ("WHY IT MATTERS", f.why_it_matters, "why"),
            ("HOW DETECTED", f.how_detected, "how"),
            ("HOW TO VERIFY", f.how_to_verify, "verify"),
            ("HOW TO FIX", f.how_to_fix, "fix"),
        ]:
            if value:
                rows.append(
                    '<div class="row {}"><span class="lbl">{}</span>'
                    '<span class="val">{}</span></div>'.format(cls, label, e(str(value)))
                )
        refs = ""
        if f.references:
            refs = '<div class="refs">' + " &middot; ".join(e(r) for r in f.references) + "</div>"
        tags = ""
        if f.concept_tags:
            tags = '<div class="tags">' + "".join(
                '<span class="tag">{}</span>'.format(e(t)) for t in f.concept_tags
            ) + "</div>"
        ev = ""
        if f.evidence:
            ev = '<details><summary>Raw evidence</summary><pre>{}</pre></details>'.format(
                e(json.dumps(f.evidence, indent=2, default=str))
            )

        cards.append(
            """
      <div class="card" style="border-left-color:{color}">
        <div class="head">
          <span class="fid">{fid}</span>
          <span class="title">{title}</span>
          <span class="sev" style="background:{color}">{sev}</span>
        </div>
        <div class="meta">{mode} &middot; module <code>{module}</code>
             &middot; confidence <b>{conf}</b> &middot; {target}</div>
        {rows}{refs}{tags}{ev}
      </div>""".format(
                color=color,
                fid=e(f.id),
                title=e(f.title),
                sev=e(f.severity.upper()),
                mode="PASSIVE" if f.passive else "ACTIVE",
                module=e(f.module),
                conf=e(f.confidence),
                target=e(f.target),
                rows="".join(rows),
                refs=refs,
                tags=tags,
                ev=ev,
            )
        )

    chips = "".join(
        '<span class="chip" style="background:{}">{} {}</span>'.format(
            SEV_HTML[s], counts[s], s
        )
        for s in ["critical", "high", "medium", "low", "info"]
        if counts.get(s)
    )

    concepts = "".join(
        '<span class="tag">{}</span>'.format(e(c)) for c in fs.concepts_touched()
    )

    doc = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>EDRecon Report - {target}</title>
<style>
  :root {{ --bg:#0f172a; --panel:#1e293b; --ink:#e2e8f0; --dim:#94a3b8; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink);
         font-family:ui-sans-serif,system-ui,'Segoe UI',Roboto,sans-serif;
         line-height:1.6; }}
  header {{ background:linear-gradient(135deg,#0891b2,#0e7490); padding:28px 32px; }}
  header h1 {{ margin:0; font-size:26px; letter-spacing:1px; }}
  header .sub {{ opacity:.9; font-size:13px; margin-top:4px; }}
  header .auth {{ margin-top:14px; font-size:12px; opacity:.85;
                  border-top:1px solid rgba(255,255,255,.25); padding-top:10px; }}
  .wrap {{ max-width:960px; margin:0 auto; padding:24px 32px 60px; }}
  .bar {{ display:flex; gap:8px; flex-wrap:wrap; margin:18px 0 26px; }}
  .chip {{ padding:5px 13px; border-radius:20px; font-size:12px;
           font-weight:600; color:#0f172a; }}
  .card {{ background:var(--panel); border-left:5px solid #666; border-radius:8px;
           padding:18px 20px; margin-bottom:18px; }}
  .head {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
  .fid {{ font-family:ui-monospace,monospace; font-size:12px; color:var(--dim); }}
  .title {{ font-weight:600; font-size:16px; flex:1; }}
  .sev {{ font-size:10px; font-weight:700; color:#0f172a;
          padding:3px 9px; border-radius:4px; letter-spacing:.5px; }}
  .meta {{ font-size:11.5px; color:var(--dim); margin:6px 0 14px; }}
  .row {{ display:flex; gap:14px; margin-bottom:9px; align-items:flex-start; }}
  .lbl {{ flex:0 0 118px; font-size:10.5px; font-weight:700; letter-spacing:.6px;
          color:var(--dim); padding-top:3px; }}
  .val {{ flex:1; font-size:14px; }}
  .why .val {{ color:#fde68a; }}
  .how .val {{ color:#bbf7d0; }}
  .verify .val {{ font-family:ui-monospace,monospace; font-size:12.5px; color:#e9d5ff; }}
  .fix .val {{ color:#bfdbfe; }}
  .refs {{ font-size:11px; color:var(--dim); margin-top:12px;
           border-top:1px solid #334155; padding-top:9px; }}
  .tags {{ margin-top:9px; }}
  .tag {{ display:inline-block; background:#334155; color:#cbd5e1; font-size:11px;
          padding:2px 9px; border-radius:4px; margin:2px 5px 2px 0; }}
  details {{ margin-top:11px; }}
  summary {{ cursor:pointer; font-size:12px; color:var(--dim); }}
  pre {{ background:#0b1220; padding:12px; border-radius:6px; overflow-x:auto;
         font-size:11.5px; color:#94a3b8; }}
  h2 {{ font-size:15px; letter-spacing:1px; color:var(--dim);
        border-bottom:1px solid #334155; padding-bottom:8px; margin-top:36px; }}
  footer {{ text-align:center; color:var(--dim); font-size:11.5px;
            padding:26px; border-top:1px solid #334155; }}
</style></head><body>
<header>
  <h1>EDRecon Reconnaissance Report</h1>
  <div class="sub">Target: <b>{target}</b> &middot; Generated {when}</div>
  <div class="auth">EDCatalyst &middot; Dr. Keshav Sinha &middot; UPES, Dehradun, India
   &middot; edcatalyst.in</div>
</header>
<div class="wrap">
  <div class="bar">{chips}</div>
  <h2>FINDINGS</h2>
  {cards}
  <h2>CONCEPTS EXERCISED</h2>
  <div class="tags">{concepts}</div>
</div>
<footer>
  Generated by EDRecon v{version} &middot; Authorised testing only.<br>
  This report is a teaching artefact. Verify every finding independently.
</footer>
</body></html>""".format(
        target=e(fs.target),
        when=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        chips=chips,
        cards="".join(cards) or "<p>No findings recorded.</p>",
        concepts=concepts or "<i>none</i>",
        version=VERSION,
    )

    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path
