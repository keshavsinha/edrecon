"""
Scope guard.

Every ACTIVE module must call ScopeGuard.assert_in_scope() before it sends
a single packet. There is deliberately no --force flag and no bypass.

The scope file IS the authorisation record. In a real engagement it mirrors
the signed rules-of-engagement; in the classroom it mirrors the lab sheet.
Teaching students to treat it as mandatory is the point.
"""

import ipaddress
import os
import socket
from datetime import date, datetime
from typing import List, Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


class ScopeError(Exception):
    """Raised when a target is not authorised. Never caught silently."""


class OutOfScope(ScopeError):
    pass


class ScopeGuard:
    """Loads and enforces a scope file."""

    def __init__(self, scope_path: str):
        if yaml is None:
            raise ScopeError(
                "PyYAML is required for scope enforcement. "
                "Install it with: pip install pyyaml"
            )
        if not scope_path:
            raise ScopeError(
                "No scope file supplied. Active modules cannot run without "
                "an authorisation scope. Use --scope <file>."
            )
        if not os.path.isfile(scope_path):
            raise ScopeError("Scope file not found: {}".format(scope_path))

        self.path = os.path.abspath(scope_path)
        with open(scope_path, "r", encoding="utf-8") as fh:
            self.data = yaml.safe_load(fh) or {}

        self._validate()

        self.engagement = self.data.get("engagement", {})
        self.hosts: List[str] = [
            str(h) for h in (self.data.get("in_scope", {}).get("hosts") or [])
        ]
        self.networks: List[str] = [
            str(n) for n in (self.data.get("in_scope", {}).get("networks") or [])
        ]
        self.domains: List[str] = [
            str(d).lower().lstrip(".")
            for d in (self.data.get("in_scope", {}).get("domains") or [])
        ]
        self.excluded: List[str] = [
            str(x) for x in (self.data.get("out_of_scope") or [])
        ]

        self._networks = []
        for net in self.networks:
            try:
                self._networks.append(ipaddress.ip_network(net, strict=False))
            except ValueError:
                raise ScopeError("Invalid network in scope file: {}".format(net))

        self._excluded_nets = []
        self._excluded_hosts = []
        for item in self.excluded:
            try:
                self._excluded_nets.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                self._excluded_hosts.append(item.lower())

    # -- validation --------------------------------------------------------

    def _validate(self):
        eng = self.data.get("engagement")
        if not isinstance(eng, dict):
            raise ScopeError(
                "Scope file must contain an 'engagement:' block with "
                "authorised_by, contact and expires fields."
            )

        for required in ("name", "authorised_by", "contact", "expires"):
            if not eng.get(required):
                raise ScopeError(
                    "Scope file is missing required field "
                    "'engagement.{}'".format(required)
                )

        expires = eng.get("expires")
        if isinstance(expires, str):
            try:
                expires = datetime.strptime(expires, "%Y-%m-%d").date()
            except ValueError:
                raise ScopeError(
                    "engagement.expires must be YYYY-MM-DD, got: "
                    "{}".format(expires)
                )
        if isinstance(expires, datetime):
            expires = expires.date()
        if not isinstance(expires, date):
            raise ScopeError("engagement.expires must be a date (YYYY-MM-DD).")

        if expires < date.today():
            raise ScopeError(
                "AUTHORISATION EXPIRED on {}. This scope is no longer valid. "
                "Obtain fresh written authorisation before scanning.".format(
                    expires.isoformat()
                )
            )
        self.expires = expires

        scope = self.data.get("in_scope") or {}
        if not any(scope.get(k) for k in ("hosts", "networks", "domains")):
            raise ScopeError(
                "Scope file defines no in-scope hosts, networks or domains."
            )

    # -- resolution --------------------------------------------------------

    @staticmethod
    def _resolve(target: str) -> Optional[str]:
        try:
            return socket.gethostbyname(target)
        except (socket.gaierror, UnicodeError, OSError):
            return None

    @staticmethod
    def _strip(target: str) -> str:
        t = target.strip()
        for prefix in ("https://", "http://"):
            if t.lower().startswith(prefix):
                t = t[len(prefix):]
        t = t.split("/")[0]
        if ":" in t and not t.count(":") > 1:  # strip port, keep IPv6
            t = t.split(":")[0]
        return t.lower().rstrip(".")

    # -- the check ---------------------------------------------------------

    def is_in_scope(self, target: str) -> bool:
        host = self._strip(target)
        if not host:
            return False

        # Explicit exclusions always win.
        if host in self._excluded_hosts:
            return False

        ip = None
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            resolved = self._resolve(host)
            if resolved:
                try:
                    ip = ipaddress.ip_address(resolved)
                except ValueError:
                    ip = None

        if ip is not None:
            for net in self._excluded_nets:
                if ip in net:
                    return False

        # Literal host match
        if host in [h.lower() for h in self.hosts]:
            return True

        # Domain / subdomain match
        for dom in self.domains:
            if host == dom or host.endswith("." + dom):
                return True

        # Network membership
        if ip is not None:
            for net in self._networks:
                if ip in net:
                    return True
            if str(ip) in self.hosts:
                return True

        return False

    def assert_in_scope(self, target: str):
        """
        Called by every active module before sending traffic.
        Raises OutOfScope -- which the CLI does NOT swallow.
        """
        if not self.is_in_scope(target):
            raise OutOfScope(
                "TARGET NOT AUTHORISED: '{}' is not covered by the scope "
                "file '{}'.\n"
                "        Active scanning refused. Add the target to the scope "
                "file only if you hold written authorisation for it.".format(
                    target, os.path.basename(self.path)
                )
            )

    # -- display -----------------------------------------------------------

    def summary(self) -> str:
        lines = [
            "Engagement : {}".format(self.engagement.get("name")),
            "Authorised : {}".format(self.engagement.get("authorised_by")),
            "Contact    : {}".format(self.engagement.get("contact")),
            "Expires    : {}".format(self.expires.isoformat()),
        ]
        if self.hosts:
            lines.append("Hosts      : {}".format(", ".join(self.hosts)))
        if self.networks:
            lines.append("Networks   : {}".format(", ".join(self.networks)))
        if self.domains:
            lines.append("Domains    : {}".format(", ".join(self.domains)))
        if self.excluded:
            lines.append("EXCLUDED   : {}".format(", ".join(self.excluded)))
        return "\n".join("   " + ln for ln in lines)
