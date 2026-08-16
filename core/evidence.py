"""
Rate limiting and evidence logging.

Two things most teaching tools get wrong:

  1. They hammer third-party services with no throttle and no User-Agent,
     then students learn nothing except how to get HTTP 403'd.
  2. They print results to a terminal that scrolls away, so there is no
     artefact to submit, grade, or reason about later.

RateLimiter fixes the first. EvidenceLog fixes the second, and doubles as
a chain-of-custody demonstration for the forensics side of the syllabus.
"""

import hashlib
import json
import os
import threading
import time
from datetime import datetime, timezone

USER_AGENT = (
    "EDRecon/1.0 (EDCatalyst teaching tool; UPES Dehradun; "
    "+https://edcatalyst.in)"
)


class RateLimiter:
    """Simple per-host throttle. Honours Retry-After when told to."""

    def __init__(self, delay=1.0):
        self.delay = float(delay)
        self._last = {}
        self._lock = threading.Lock()

    def wait(self, host):
        with self._lock:
            now = time.monotonic()
            last = self._last.get(host, 0.0)
            gap = now - last
            if gap < self.delay:
                time.sleep(self.delay - gap)
            self._last[host] = time.monotonic()

    def backoff(self, host, seconds):
        try:
            seconds = float(seconds)
        except (TypeError, ValueError):
            seconds = self.delay * 5
        seconds = min(seconds, 60.0)
        time.sleep(seconds)
        with self._lock:
            self._last[host] = time.monotonic()


class EvidenceLog:
    """
    Append-only JSONL log. Every entry is hashed, and each hash includes
    the previous hash -- so tampering with an earlier line invalidates
    every line after it. That is the same principle as a forensic hash
    chain, at a scale students can inspect by hand.
    """

    def __init__(self, path):
        self.path = path
        self._prev_hash = "0" * 64
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("")

    def record(self, event_type, module, target, payload=None):
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            "module": module,
            "target": target,
            "payload": payload or {},
            "prev_hash": self._prev_hash,
        }
        body = json.dumps(entry, sort_keys=True, ensure_ascii=False)
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        entry["hash"] = digest

        with self._lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self._prev_hash = digest
        return digest

    @staticmethod
    def verify(path):
        """Re-walk the chain and report the first broken link, if any."""
        prev = "0" * 64
        with open(path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                claimed = entry.pop("hash", None)
                if entry.get("prev_hash") != prev:
                    return False, lineno, "prev_hash mismatch"
                body = json.dumps(entry, sort_keys=True, ensure_ascii=False)
                actual = hashlib.sha256(body.encode("utf-8")).hexdigest()
                if actual != claimed:
                    return False, lineno, "content hash mismatch"
                prev = claimed
        return True, None, "chain intact"
