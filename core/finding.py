"""
The Finding object.

This is the heart of EDRecon. Every module returns Findings, never raw
print statements. A Finding carries not only WHAT was observed but WHY it
matters and HOW it was detected -- so the output teaches, rather than
merely reporting.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Severity and confidence vocabularies
# ---------------------------------------------------------------------------

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

SEVERITY_MEANING = {
    "info": "Neutral fact about the target. Not a weakness by itself.",
    "low": "Minor hygiene issue. Useful to an attacker only in combination.",
    "medium": "Real weakness. Meaningfully expands attack surface.",
    "high": "Serious weakness. Direct path toward compromise.",
    "critical": "Severe. Compromise likely trivial from here.",
}

CONFIDENCE_MEANING = {
    "confirmed": (
        "Directly proven by the evidence. The target itself told us this, "
        "or we completed a full protocol exchange."
    ),
    "probable": (
        "Strongly indicated but not proven. Based on a distinctive signature "
        "that is rarely wrong."
    ),
    "inferred": (
        "A best guess from indirect signals. Could be defeated by "
        "misconfiguration, a proxy, or deliberate deception."
    ),
}


@dataclass
class Finding:
    """A single explainable observation about a target."""

    # --- identity -----------------------------------------------------
    id: str                       # stable ID, e.g. "TLS-003"
    module: str                   # module that produced it
    target: str                   # host / URL the finding concerns
    title: str                    # one-line human summary

    # --- the raw observation ------------------------------------------
    observation: str = ""         # WHAT was seen, factually
    evidence: Dict[str, Any] = field(default_factory=dict)

    # --- the teaching layer -------------------------------------------
    what: str = ""                # what this technically means
    why_it_matters: str = ""      # security significance / attacker use
    how_detected: str = ""        # the mechanism that revealed it
    how_to_verify: str = ""       # manual command to reproduce
    how_to_fix: str = ""          # defender-side remediation

    # --- classification -----------------------------------------------
    # Left empty by default ON PURPOSE. An empty severity lets enrich()
    # fill it from the knowledge base; a default of "info" would be truthy
    # and silently suppress every KB severity.
    severity: str = ""
    confidence: str = "confirmed"
    references: List[str] = field(default_factory=list)
    concept_tags: List[str] = field(default_factory=list)

    # --- provenance ---------------------------------------------------
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    passive: bool = True          # True if no packet was sent to target

    def __post_init__(self):
        # "" is permitted here -- enrich() resolves it. Anything else
        # invalid is coerced.
        if self.severity and self.severity not in SEVERITY_ORDER:
            self.severity = "info"
        if self.confidence not in CONFIDENCE_MEANING:
            self.confidence = "inferred"

    @property
    def severity_rank(self) -> int:
        if self.severity not in SEVERITY_ORDER:
            return 0
        return SEVERITY_ORDER.index(self.severity)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def enrich(self, kb_entry: Dict[str, Any]) -> "Finding":
        """
        Fill the teaching fields from a knowledge-base entry.

        Values already set on the Finding win, so a module can override
        the generic explanation with a target-specific one.
        """
        if not kb_entry:
            return self
        for key in (
            "title",
            "what",
            "why_it_matters",
            "how_detected",
            "how_to_verify",
            "how_to_fix",
            "severity",
        ):
            if not getattr(self, key, "") and kb_entry.get(key):
                setattr(self, key, kb_entry[key])
        for key in ("references", "concept_tags"):
            if not getattr(self, key) and kb_entry.get(key):
                setattr(self, key, list(kb_entry[key]))

        # Whatever happened above, end with a valid severity.
        if self.severity not in SEVERITY_ORDER:
            self.severity = "info"
        return self


class FindingSet:
    """A collection of findings for one scan run."""

    def __init__(self, target: str):
        self.target = target
        self.findings: List[Finding] = []
        self.started = datetime.now(timezone.utc)
        self.errors: List[Dict[str, str]] = []

    def add(self, finding: Finding):
        self.findings.append(finding)

    def extend(self, findings):
        for f in findings or []:
            self.add(f)

    def record_error(self, module: str, message: str):
        """A module failing must never stop the run."""
        self.errors.append({"module": module, "error": str(message)})

    def sorted_by_severity(self) -> List[Finding]:
        return sorted(
            self.findings, key=lambda f: (-f.severity_rank, f.module, f.id)
        )

    def by_severity(self) -> Dict[str, int]:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    def concepts_touched(self) -> List[str]:
        """Used to build the 'what you learned' summary."""
        tags = set()
        for f in self.findings:
            tags.update(f.concept_tags)
        return sorted(tags)

    def __len__(self):
        return len(self.findings)
