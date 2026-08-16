"""
ACTIVE - host discovery, TCP connect scan, banner grabbing.

Every function here sends packets to the target and MUST pass the scope
check first. There is no bypass.

Design note for students: this is a TCP *connect* scan, meaning the full
three-way handshake completes before we close. That makes it reliable and
unprivileged, but also loud - the connection appears in the target's
application logs. A SYN scan avoids that by never completing the
handshake, but requires raw sockets and therefore root. The trade-off
between stealth and privilege is worth understanding directly.
"""

import socket
import ssl
import threading
from queue import Queue

from core.finding import Finding
from core.knowledge import kb

MODULE = "port_scan"

# Well-known ports with their teaching classification
SERVICES = {
    21:   ("FTP", "cleartext"),
    22:   ("SSH", "management"),
    23:   ("Telnet", "cleartext"),
    25:   ("SMTP", "mail"),
    53:   ("DNS", "infrastructure"),
    69:   ("TFTP", "cleartext"),
    80:   ("HTTP", "web"),
    110:  ("POP3", "cleartext"),
    111:  ("rpcbind", "infrastructure"),
    135:  ("MSRPC", "windows"),
    139:  ("NetBIOS-SSN", "windows"),
    143:  ("IMAP", "cleartext"),
    161:  ("SNMP", "infrastructure"),
    389:  ("LDAP", "directory"),
    443:  ("HTTPS", "web"),
    445:  ("SMB", "windows"),
    512:  ("rexec", "cleartext"),
    513:  ("rlogin", "cleartext"),
    514:  ("rsh", "cleartext"),
    587:  ("SMTP-submission", "mail"),
    631:  ("IPP", "printing"),
    993:  ("IMAPS", "mail"),
    995:  ("POP3S", "mail"),
    1099: ("Java RMI", "application"),
    1433: ("MS-SQL", "database"),
    1521: ("Oracle DB", "database"),
    2049: ("NFS", "filesharing"),
    3000: ("HTTP-alt", "web"),
    3306: ("MySQL", "database"),
    3389: ("RDP", "management"),
    3632: ("distccd", "application"),
    4444: ("Metasploit default", "application"),
    5432: ("PostgreSQL", "database"),
    5900: ("VNC", "management"),
    5985: ("WinRM", "management"),
    6379: ("Redis", "database"),
    6667: ("IRC", "application"),
    8000: ("HTTP-alt", "web"),
    8009: ("AJP13", "application"),
    8080: ("HTTP-proxy", "web"),
    8081: ("HTTP-alt", "web"),
    8180: ("Tomcat", "web"),
    8443: ("HTTPS-alt", "web"),
    9200: ("Elasticsearch", "database"),
    11211: ("Memcached", "database"),
    27017: ("MongoDB", "database"),
}

TOP_PORTS = sorted(SERVICES.keys())

CLEARTEXT_PORTS = {p for p, (_, c) in SERVICES.items() if c == "cleartext"}
DATABASE_PORTS = {p for p, (_, c) in SERVICES.items() if c == "database"}
MANAGEMENT_PORTS = {p for p, (_, c) in SERVICES.items() if c == "management"}

WEB_PORTS = {p for p, (_, c) in SERVICES.items() if c == "web"}


def _mk(fid, target, observation, evidence=None, **kw):
    f = Finding(id=fid, module=MODULE, target=target, title="",
                observation=observation, evidence=evidence or {},
                passive=False, **kw)
    return f.enrich(kb().get(fid))


def parse_ports(spec):
    """Accept '80', '1-1024', '22,80,443', or 'top'."""
    if not spec or spec == "top":
        return list(TOP_PORTS)
    ports = set()
    for part in str(spec).split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            try:
                lo, hi = int(lo), int(hi)
            except ValueError:
                continue
            ports.update(range(max(1, lo), min(65535, hi) + 1))
        elif part.isdigit():
            ports.add(int(part))
    return sorted(ports)


def _connect(host, port, timeout):
    """Return (state, reason). state in open/closed/filtered."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return "open", sock
    except socket.timeout:
        sock.close()
        return "filtered", None
    except ConnectionRefusedError:
        sock.close()
        return "closed", None
    except OSError as exc:
        sock.close()
        return "error:{}".format(exc.errno), None


def _grab_banner(sock, port, timeout=3):
    """Read whatever the service volunteers, nudging HTTP if silent."""
    banner = b""
    try:
        sock.settimeout(timeout)
        try:
            banner = sock.recv(512)
        except socket.timeout:
            banner = b""

        if not banner and port in WEB_PORTS:
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(512)
            except (socket.timeout, OSError):
                banner = b""
    except OSError:
        pass
    return banner.decode("utf-8", errors="replace").strip()


def discover(host, scope, timeout=2.0, evidence_log=None):
    """Is the host up? Scope-gated."""
    scope.assert_in_scope(host)
    findings = []

    probe_ports = [80, 443, 22, 445, 3389, 21]
    for port in probe_ports:
        state, sock = _connect(host, port, timeout)
        if sock:
            sock.close()
        if state in ("open", "closed"):
            findings.append(_mk(
                "HOST-001", host,
                "Host responded on TCP/{} ({}), confirming it is live.".format(
                    port, state),
                {"probe_port": port, "state": state},
                confidence="confirmed",
            ))
            if evidence_log:
                evidence_log.record("host_up", MODULE, host, {"port": port})
            return findings, True

    return findings, False


def scan(host, scope, ports=None, timeout=1.5, threads=50,
         banners=True, evidence_log=None):
    """
    TCP connect scan. Scope check happens before any socket is opened.
    """
    scope.assert_in_scope(host)

    ports = ports or TOP_PORTS
    findings = []
    open_ports = []
    results_lock = threading.Lock()
    queue = Queue()
    for p in ports:
        queue.put(p)

    filtered_count = [0]
    closed_count = [0]

    def worker():
        while True:
            try:
                port = queue.get_nowait()
            except Exception:
                return
            try:
                state, sock = _connect(host, port, timeout)
                if state == "open":
                    banner = ""
                    if banners and sock:
                        banner = _grab_banner(sock, port)
                    if sock:
                        try:
                            sock.close()
                        except OSError:
                            pass
                    with results_lock:
                        open_ports.append((port, banner))
                elif state == "filtered":
                    with results_lock:
                        filtered_count[0] += 1
                elif state == "closed":
                    with results_lock:
                        closed_count[0] += 1
            finally:
                queue.task_done()

    pool = []
    for _ in range(min(threads, max(1, len(ports)))):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        pool.append(t)
    for t in pool:
        t.join()

    open_ports.sort()

    for port, banner in open_ports:
        name, category = SERVICES.get(port, ("unknown", "unknown"))

        findings.append(_mk(
            "PORT-001", host,
            "TCP/{} open - likely {}. Full three-way handshake "
            "completed.".format(port, name),
            {"port": port, "service": name, "category": category},
            confidence="confirmed",
        ))

        if banner:
            clean = banner.replace("\r", " ").replace("\n", " ")[:200]
            findings.append(_mk(
                "PORT-002", host,
                "TCP/{} banner: {}".format(port, clean),
                {"port": port, "banner": banner[:1000]},
                confidence="probable",
            ))

        if port in CLEARTEXT_PORTS:
            findings.append(_mk(
                "PORT-003", host,
                "TCP/{} ({}) transmits data and credentials without "
                "encryption.".format(port, name),
                {"port": port, "service": name},
                confidence="confirmed",
            ))

        if port in DATABASE_PORTS:
            findings.append(_mk(
                "PORT-004", host,
                "TCP/{} ({}) is a database service reachable from this "
                "host.".format(port, name),
                {"port": port, "service": name},
                confidence="confirmed",
            ))

        if port in MANAGEMENT_PORTS:
            findings.append(_mk(
                "PORT-005", host,
                "TCP/{} ({}) provides remote administrative access.".format(
                    port, name),
                {"port": port, "service": name},
                confidence="confirmed",
            ))

        if evidence_log:
            evidence_log.record("port_open", MODULE, host,
                                {"port": port, "banner": banner[:200]})

    # Report the negative space too - it teaches port-state reasoning.
    if filtered_count[0] or closed_count[0]:
        findings.append(_mk(
            "PORT-006", host,
            "{} port(s) closed (RST received), {} filtered (no response) "
            "out of {} probed.".format(
                closed_count[0], filtered_count[0], len(ports)),
            {"closed": closed_count[0], "filtered": filtered_count[0],
             "probed": len(ports)},
            confidence="confirmed",
        ))

    return findings, [p for p, _ in open_ports]
