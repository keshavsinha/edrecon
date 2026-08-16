"""
Knowledge base loader.

Explanations live in knowledge/*.yaml, NOT in module code. This means the
pedagogy can be edited, translated and version-controlled independently of
the scanner logic -- and students can read the KB as a reference even with
no target at all.
"""

import os
import glob

try:
    import yaml
except ImportError:
    yaml = None

KB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "knowledge")


class KnowledgeBase:
    def __init__(self, kb_dir=None):
        self.kb_dir = kb_dir or KB_DIR
        self.entries = {}
        self._load()

    def _load(self):
        if yaml is None:
            return
        for path in sorted(glob.glob(os.path.join(self.kb_dir, "*.yaml"))):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh) or {}
                for key, val in data.items():
                    if isinstance(val, dict):
                        self.entries[key] = val
            except Exception:
                continue

    def get(self, finding_id):
        return self.entries.get(finding_id, {})

    def all_ids(self):
        return sorted(self.entries.keys())

    def search(self, term):
        term = term.lower()
        hits = []
        for key, val in self.entries.items():
            blob = " ".join(str(v) for v in val.values()).lower()
            if term in key.lower() or term in blob:
                hits.append((key, val))
        return hits

    def concepts(self):
        tags = set()
        for val in self.entries.values():
            tags.update(val.get("concept_tags", []) or [])
        return sorted(tags)


_KB = None


def kb():
    global _KB
    if _KB is None:
        _KB = KnowledgeBase()
    return _KB
