# EDRecon — Complete Command Reference

**EDCatalyst · Dr. Keshav Sinha · UPES, Dehradun, India**

Every command assumes you are in the `edrecon` directory with the virtual
environment active:

```bash
cd ~/edrecon && source .venv/bin/activate
```

---

## 1. Setup and verification

| Command | What it does |
|---|---|
| `python3 -m venv .venv` | Create the virtual environment (never with `sudo`) |
| `source .venv/bin/activate` | Activate it — needed in every new terminal |
| `deactivate` | Leave the virtual environment |
| `pip install -r requirements.txt` | Install dependencies (no `sudo`) |
| `python3 edrecon.py --version` | Print version and attribution |
| `python3 edrecon.py --help` | Full flag list |
| `python3 edrecon.py` | Print help (no target given) |

**Offline self-test — no network, no target:**

```bash
python3 edrecon.py --concepts        # ~85 concept tags should list
python3 edrecon.py --kb              # full knowledge base prints
```

---

## 2. Knowledge base — no target required

| Command | What it does |
|---|---|
| `python3 edrecon.py --kb` | Print every knowledge base entry |
| `python3 edrecon.py --kb \| less` | Page through it |
| `python3 edrecon.py --concepts` | List all concept tags |
| `python3 edrecon.py --kb-search TERM` | Search titles and body text |

**Search examples:**

```bash
python3 edrecon.py --kb-search clickjacking
python3 edrecon.py --kb-search zone-transfer
python3 edrecon.py --kb-search forward-secrecy
python3 edrecon.py --kb-search cleartext
python3 edrecon.py --kb-search DNS-008          # search by finding ID
python3 edrecon.py --kb-search TLS              # all TLS entries
python3 edrecon.py --kb-search spf
python3 edrecon.py --kb-search csrf
```

**Export the knowledge base as a handout:**

```bash
python3 edrecon.py --kb --no-color > edrecon_knowledge_base.txt
```

---

## 3. Passive reconnaissance — no scope file needed

No packets reach the target. Safe against any domain.

| Command | What it does |
|---|---|
| `python3 edrecon.py -t DOMAIN --passive-only` | Full passive sweep |
| `python3 edrecon.py -t DOMAIN` | Same — passive is the default |

**Variations:**

```bash
# Full passive scan
python3 edrecon.py -t upes.ac.in --passive-only

# Skip certificate transparency (faster, or if crt.sh is rate limiting)
python3 edrecon.py -t upes.ac.in --passive-only --no-ct

# Skip WHOIS
python3 edrecon.py -t upes.ac.in --passive-only --no-whois

# DNS only — fastest
python3 edrecon.py -t upes.ac.in --passive-only --no-ct --no-whois

# One line per finding
python3 edrecon.py -t upes.ac.in --passive-only --brief

# Longer DNS timeout on a slow link
python3 edrecon.py -t upes.ac.in --passive-only --timeout 10
```

---

## 4. Scope file management

The scope file is required for every active module. There is no override.

```bash
# Create your own from the template
cp scope.example.yaml scope.yaml
nano scope.yaml

# Find your Metasploitable IP first (run on the target VM)
ip a

# Confirm the target is reachable before scanning
ping -c 2 192.168.56.101
```

**Test that the guard actually refuses — run these in class:**

```bash
# 1. No scope file at all
python3 edrecon.py -t 192.168.56.101 --system

# 2. Target not listed in the scope file
python3 edrecon.py -t scanme.nmap.org --system --scope scope.yaml

# 3. Expired authorisation
sed 's/expires: .*/expires: "2020-01-01"/' scope.yaml > /tmp/dead.yaml
python3 edrecon.py -t 192.168.56.101 --system --scope /tmp/dead.yaml

# 4. Prove there is no bypass flag
python3 edrecon.py --help | grep -i force        # returns nothing
```

**Inspect scope logic directly:**

```bash
python3 -c "
import sys; sys.path.insert(0,'.')
from core.scope_guard import ScopeGuard
s = ScopeGuard('scope.yaml')
print(s.summary())
for t in ['192.168.56.101','192.168.56.1','8.8.8.8']:
    print(f'{t:20} -> {\"ALLOWED\" if s.is_in_scope(t) else \"REFUSED\"}')
"
```

---

## 5. Active system scanning

Requires `--scope`. Packets reach the target and are logged by it.

| Command | What it does |
|---|---|
| `--system` | Host discovery + port scan + TLS audit |

**Port specification:**

```bash
# Default: ~48 curated well-known ports
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml --system

# Explicit list
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml \
    --system --ports 21,22,23,80,443,3306

# Range
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml \
    --system --ports 1-1024

# Full sweep (slow — tune timeout and threads)
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml \
    --system --ports 1-65535 --threads 200 --timeout 1

# Mixed
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml \
    --system --ports 1-1024,3306,8080,8443
```

**Speed tuning (lab network):**

```bash
# Fast
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml \
    --system --ports 1-10000 --threads 200 --timeout 0.5

# Slow and reliable (across a WAN or through a firewall)
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml \
    --system --threads 20 --timeout 8
```

**Other system options:**

```bash
# Skip banner grabbing (quieter, faster)
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml \
    --system --no-banners

# Zone transfer attempt (ACTIVE — needs scope)
python3 edrecon.py -t lab.example.local --scope scope.yaml --axfr
```

---

## 6. Active web scanning

```bash
# Auto-detect web ports from the system scan
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml --web

# Explicit URL
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml \
    --web -u http://192.168.56.101:8080/

# HTTPS
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml \
    --web -u https://192.168.56.101/

# Specific application path
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml \
    --web -u http://192.168.56.101/dvwa/
```

**Content discovery:**

```bash
# Built-in wordlist (~70 paths)
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml --web --discover

# Bundled wordlist file
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml \
    --web --discover --wordlist wordlists/common.txt

# SecLists, capped
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml \
    --web --discover \
    --wordlist /usr/share/wordlists/dirb/common.txt \
    --max-paths 1000

# Fast on an isolated lab
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml \
    --web --discover --delay 0.05 --max-paths 500

# Gentle — for anything you do not fully control
python3 edrecon.py -t target --scope scope.yaml \
    --web --discover --delay 1.0 --max-paths 100
```

---

## 7. Combined scans

```bash
# Everything
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml --all

# Everything plus content discovery
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml --all --discover

# Full assessment, tuned
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml \
    --all --discover --ports 1-10000 --threads 150 \
    --timeout 1 --delay 0.1 --max-paths 500

# Active only, skipping passive
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml --system --web
```

---

## 8. Output control

| Flag | Effect |
|---|---|
| *(default)* | Full teaching layer — all six fields |
| `--no-explain` | Observation only, no WHAT/WHY/HOW |
| `--brief` | One line per finding |
| `--no-color` | Strip ANSI codes (for piping to files) |
| `--no-report` | Console only, write no files |
| `--outdir DIR` | Change the report directory |

```bash
# Full explanations — use for Labs 1 and 2
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml --all

# Brief — use from Lab 3 onward
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml --all --brief

# Save console output to a file
python3 edrecon.py -t upes.ac.in --passive-only --no-color \
    > scan_output.txt

# Both screen and file
python3 edrecon.py -t upes.ac.in --passive-only --no-color \
    | tee scan_output.txt

# Per-student report directories
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml --all \
    --outdir reports/student_R2142220001

# Console only, no artefacts
python3 edrecon.py -t upes.ac.in --passive-only --no-report
```

---

## 9. Reports and evidence

```bash
# List generated artefacts
ls -lt reports/

# Open the newest HTML report
firefox reports/report_*.html
xdg-open $(ls -t reports/*.html | head -1)

# Pretty-print the JSON report
cat reports/report_*.json | python3 -m json.tool | less

# Verify an evidence chain
python3 edrecon.py --verify-log reports/evidence_192.168.56.101_20260816.jsonl

# Verify the newest log
python3 edrecon.py --verify-log $(ls -t reports/evidence_*.jsonl | head -1)
```

**Tampering demonstration (Lab 5):**

```bash
LOG=$(ls -t reports/evidence_*.jsonl | head -1)
python3 edrecon.py --verify-log "$LOG"     # intact
nano "$LOG"                                 # change one value on line 3
python3 edrecon.py --verify-log "$LOG"     # chain BROKEN at line 3
```

**Extract findings from JSON with `jq`:**

```bash
R=$(ls -t reports/report_*.json | head -1)

# All high-severity findings
jq '.findings[] | select(.severity=="high") | .title' "$R"

# Severity counts
jq '.summary' "$R"

# Concepts touched
jq '.concepts' "$R"

# ID, severity and title as a table
jq -r '.findings[] | "\(.id)\t\(.severity)\t\(.title)"' "$R" | column -t

# Only confirmed findings
jq '.findings[] | select(.confidence=="confirmed") | .id' "$R"

# Every VERIFY command from the report
jq -r '.findings[].how_to_verify' "$R" | sort -u
```

---

## 10. Full flag list

### Target

| Flag | Default | Meaning |
|---|---|---|
| `-t`, `--target` | — | Domain, hostname or IP |
| `-s`, `--scope` | — | Path to authorisation scope file |
| `-u`, `--url` | auto | Explicit URL for the web phase |

### Phases

| Flag | Meaning |
|---|---|
| `--passive-only` | Passive only. No scope file needed. |
| `--system` | Active system scan |
| `--web` | Active web scan |
| `--all` | All three phases |

*No phase flag given → passive only. Safe by default.*

### Scan options

| Flag | Default | Meaning |
|---|---|---|
| `--ports` | `top` | `top`, `1-1024`, or `22,80,443` |
| `--threads` | `50` | Concurrent scan threads |
| `--timeout` | `3.0` | Per-connection timeout (seconds) |
| `--delay` | `0.35` | Delay between web requests |
| `--no-banners` | off | Skip banner grabbing |
| `--axfr` | off | Attempt zone transfer (active) |
| `--discover` | off | Content discovery in web phase |
| `--wordlist` | built-in | Custom wordlist path |
| `--max-paths` | `400` | Cap on paths probed |
| `--no-whois` | off | Skip WHOIS |
| `--no-ct` | off | Skip certificate transparency |

### Output

| Flag | Default | Meaning |
|---|---|---|
| `--brief` | off | One line per finding |
| `--no-explain` | off | Hide WHAT/WHY/HOW |
| `--outdir` | `reports` | Report directory |
| `--no-color` | off | Disable ANSI colour |
| `--no-report` | off | Skip file output |

### Knowledge base and utilities

| Flag | Meaning |
|---|---|
| `--kb` | Print the whole knowledge base |
| `--kb-search TERM` | Search the knowledge base |
| `--concepts` | List all concept tags |
| `--verify-log PATH` | Verify an evidence hash chain |
| `--version` | Version and attribution |
| `--help` | Full help text |

---

## 11. Lab-by-lab command sheet

**Lab 1 — Passive reconnaissance**

```bash
python3 edrecon.py --concepts
python3 edrecon.py --kb-search dns-resolution
python3 edrecon.py -t upes.ac.in --passive-only
dig +short TXT upes.ac.in | grep spf1
dig +short TXT _dmarc.upes.ac.in
```

**Lab 2 — Scope files and authorisation**

```bash
python3 edrecon.py -t 192.168.56.101 --system
cp scope.example.yaml scope.yaml && nano scope.yaml
sed 's/expires: .*/expires: "2020-01-01"/' scope.yaml > /tmp/dead.yaml
python3 edrecon.py -t 192.168.56.101 --system --scope /tmp/dead.yaml
python3 edrecon.py -t scanme.nmap.org --system --scope scope.yaml
python3 edrecon.py --help | grep -i force
```

**Lab 3 — Active system scanning**

```bash
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml --system
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml \
    --system --ports 1-10000 --threads 100 --timeout 1
nmap -sV -p- 192.168.56.101                  # compare
python3 edrecon.py --kb-search banner-grabbing
```

**Lab 4 — Web scanning**

```bash
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml --web
python3 edrecon.py -t 192.168.56.101 --scope scope.yaml \
    --web --discover --delay 0.1
python3 edrecon.py --kb-search baseline-comparison
firefox reports/report_*.html
```

**Lab 5 — Evidence integrity**

```bash
LOG=$(ls -t reports/evidence_*.jsonl | head -1)
python3 edrecon.py --verify-log "$LOG"
head -3 "$LOG" | python3 -m json.tool
nano "$LOG"
python3 edrecon.py --verify-log "$LOG"
```

**Lab 6 — Extending the tool**

```bash
nano knowledge/web.yaml                       # add an entry
python3 edrecon.py --kb-search YOUR-ID        # confirm it loads
python3 -m py_compile edrecon.py core/*.py modules/*/*.py
```

---

## 12. Maintenance and troubleshooting

```bash
# Confirm all modules compile
python3 -m py_compile edrecon.py core/*.py modules/*/*.py && echo OK

# Check which dependencies are present
python3 -c "
for m in ['yaml','requests','dns.resolver','bs4','whois']:
    try:
        __import__(m); print(f'{m:16} OK')
    except ImportError:
        print(f'{m:16} MISSING')
"

# List installed packages in the venv
pip list

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall

# Fix a root-owned virtual environment
sudo chown -R $USER:$USER ~/edrecon
rm -rf .venv && python3 -m venv .venv
source .venv/bin/activate && pip install -r requirements.txt

# Clear caches and old reports
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null
rm -f reports/*

# Archive a student's results
tar czf student_R2142220001_results.tar.gz reports/
```

**Common errors:**

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError` | venv not activated | `source .venv/bin/activate` |
| `Permission denied` creating venv | directory root-owned | `sudo chown -R $USER:$USER .` |
| `uninstall-no-record-file` | ran `sudo pip` | recreate venv, install without `sudo` |
| `AUTHORISATION EXPIRED` | scope lapsed | update `expires` — only if still authorised |
| `TARGET NOT AUTHORISED` | not in scope | add it only with written permission |
| crt.sh HTTP 429 | rate limited | wait, or use `--no-ct` |
| Content discovery finds nothing | soft-404 filtering | check output for the baseline note |

---

*EDRecon — an EDCatalyst teaching tool.*
*Dr. Keshav Sinha, UPES, Dehradun, India. Authorised testing only.*
