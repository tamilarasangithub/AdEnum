# ADenum v0.2.0

**Active Directory Attack Path Analytics and Vulnerability Mapper**

> **Author:** Tamilarasan  
> ⚠️ For use **only** against environments you are explicitly authorized to assess.

ADenum collects AD objects via LDAP, loads them into a Neo4j graph, and runs
attack-path / misconfiguration queries against it — inspired by BloodHound but
built in Python for full Kali-native control.

---

## Feature Overview

| Feature | Status |
|---------|--------|
| LDAP collection (users, groups, computers, OUs) | ✅ |
| Pass-the-hash (NTLM) authentication | ✅ |
| LDAPS (TLS) support | ✅ |
| Neo4j graph ingestion with uniqueness indexes | ✅ |
| Shortest attack path (all relationship types) | ✅ |
| Kerberoastable / AS-REP roastable detection | ✅ |
| Unconstrained / constrained / RBCD delegation | ✅ |
| Dangerous ACL detection (GenericAll, WriteDacl, …) | ✅ |
| ADCS ESC1 / ESC2 / ESC3 misconfiguration detection | ✅ |
| Interactive graph explorer (browser UI) | ✅ |
| Docker Compose full-stack deployment | ✅ |

---

## 1. Requirements

- Kali Linux (or any Debian/Ubuntu system) with `sudo`
- Python 3.10+
- Docker + Docker Compose V2 (for Neo4j)
- Network access to target Domain Controller on LDAP/389 or LDAPS/636

---

## 2. Install on Kali (recommended: local venv + Docker Neo4j)

```bash
# 1. System packages
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git \
    docker.io docker-compose \
    libkrb5-dev krb5-user build-essential

# 2. Clone / enter project directory
cd ~/adenum         # wherever you extracted the project

# 3. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 4. Install ADenum + all dependencies
pip install -e ".[dev]"

# 5. Verify the CLI is on PATH
adenum --help
```

> **Tip:** If `pip install` fails on `impacket`, the fix is always:
> `sudo apt install libkrb5-dev krb5-user` then retry.

---

## 3. Start Neo4j (Docker)

```bash
# Start only the Neo4j container (run the Python CLI locally)
sudo docker-compose up -d neo4j

# Wait for it to be healthy (~30 s on first pull)
sudo docker-compose ps
# adenum-neo4j   running (healthy)

# Open Neo4j browser (optional)
xdg-open http://localhost:7474
# Login: neo4j / adenum123
```

> Change the default password in `docker-compose.yml` and `.env` before any real engagement.

---

## 4. Configure environment

```bash
cp .env.example .env
# Edit .env — set your target domain, DC IP, and credentials
nano .env
```

The CLI auto-loads `.env` via `python-dotenv`.

---

## 5. Complete workflow (collect → ingest → query → explore)

### 5a. Collect AD data

```bash
# Standard (plaintext password)
adenum collect -d corp.local -u svcaccount -p 'Passw0rd!' -dc-ip 10.10.10.5

# Pass-the-hash (no plaintext password needed)
adenum collect -d corp.local -u administrator --nt-hash 32ed87bdb5fdc5e9cba88547376818d4 -dc-ip 10.10.10.5

# LDAPS (encrypted, port 636)
adenum collect -d corp.local -u svcaccount -p 'Passw0rd!' -dc-ip 10.10.10.5 \
    --ldap-ssl --ldap-port 636

# Include ADCS certificate template enumeration
adenum collect -d corp.local -u svcaccount -p 'Passw0rd!' -dc-ip 10.10.10.5 --adcs

# Custom output directory
adenum collect -d corp.local -u svcaccount -p 'Passw0rd!' -dc-ip 10.10.10.5 \
    --out /tmp/corp-assessment
```

Output: `./collected/adenum_collection_corp.local.json`

### 5b. Ingest into Neo4j

```bash
# Load (wipe first for a fresh run)
adenum ingest --input ./collected/adenum_collection_corp.local.json --wipe

# Load ADCS data
adenum ingest --input ./collected/adenum_adcs_corp.local.json
```

### 5c. Query the graph

```bash
# Kerberoastable accounts (SPN set, account enabled)
adenum query --kerberoastable

# AS-REP roastable accounts (pre-auth disabled)
adenum query --asrep-roastable

# Unconstrained delegation hosts (TGT capture risk)
adenum query --unconstrained-delegation

# Dangerous ACLs on high-value targets (GenericAll, WriteDacl, WriteOwner…)
adenum query --dangerous-acls

# High-value group members (transitive)
adenum query --high-value-groups

# Resource-Based Constrained Delegation
adenum query --rbcd

# Shortest attack path (all relationship types, not just MemberOf)
adenum query --shortest-path --from "jdoe" --to "Domain Admins"
```

### 5d. Launch the graph explorer

```bash
adenum serve --port 8080
# Open: http://localhost:8080
```

The browser UI shows:
- Interactive force-directed graph with color-coded nodes
- Sidebar: findings panel (Kerberoastable, Dangerous ACLs, etc.)
- Path finder: enter From/To to find shortest attack paths
- Node detail: click any node to inspect its properties
- Search bar: highlight nodes by name in real-time

---

## 6. REST API endpoints

The `adenum serve` command exposes these endpoints (also usable via `curl`):

```bash
# Health check
curl http://localhost:8080/health

# Full graph (for custom frontends)
curl http://localhost:8080/api/graph

# Findings
curl http://localhost:8080/api/findings/kerberoastable
curl http://localhost:8080/api/findings/asrep-roastable
curl http://localhost:8080/api/findings/unconstrained-delegation
curl http://localhost:8080/api/findings/dangerous-acls
curl http://localhost:8080/api/findings/high-value-groups
curl http://localhost:8080/api/findings/rbcd

# Paths
curl "http://localhost:8080/api/paths/shortest?start=jdoe&end=Domain%20Admins"
curl "http://localhost:8080/api/paths/to-da?start=jdoe&max_hops=6"

# OpenAPI docs
xdg-open http://localhost:8080/docs
```

---

## 7. Full Docker Compose (app + Neo4j together)

```bash
# Build and start everything
sudo docker-compose up -d --build

# Run collector/ingest from inside the container
sudo docker exec -it adenum-api adenum collect -d corp.local -u svc -p pw -dc-ip 10.10.10.5
sudo docker exec -it adenum-api adenum ingest --input /app/collected/adenum_collection_corp.local.json
sudo docker exec -it adenum-api adenum query --kerberoastable

# Logs
sudo docker-compose logs -f api
```

---

## 8. Development

```bash
source .venv/bin/activate
pip install -e ".[dev]"

# Formatting
black adenum tests

# Linting
ruff check adenum tests

# Run all tests (no live AD or Neo4j required)
pytest -v

# With coverage report
pytest --cov=adenum --cov-report=term-missing
```

### Project layout

```
adenum/
├── adenum/
│   ├── __init__.py      # package version
│   ├── cli.py           # Click CLI (collect/ingest/query/serve)
│   ├── collector.py     # LDAP collection (ldap3 + NTLM)
│   ├── adcs.py          # ADCS certificate template enumeration (ESC1-3)
│   ├── ingest.py        # Neo4j loader (MERGE + uniqueness indexes)
│   ├── query.py         # Cypher queries (paths, findings, ACLs)
│   ├── serve.py         # FastAPI REST API + static file serving
│   └── static/
│       └── index.html   # Graph explorer UI (vis-network)
├── tests/
│   ├── __init__.py
│   ├── test_collector.py
│   ├── test_ingest.py
│   ├── test_query.py
│   └── test_adcs.py
├── docker-compose.yml
├── Dockerfile
├── pyproject.toml
├── requirements.txt
├── .env.example
└── README.md
```

---

## 9. Testing phase — full checklist

### Step 1: Automated tests (no live AD/Neo4j needed)

```bash
pytest -v --cov=adenum --cov-report=term-missing
```

Expected: all tests green, coverage ≥ 80%

Test matrix:

| Test File | Tests | What it covers |
|-----------|-------|---------------|
| `test_collector.py` | 14 | UAC flags, LDAP socket leak fix, RuntimeError fix, JSON output |
| `test_ingest.py`    |  9 | Null single() fix, index creation, string/empty member handling |
| `test_query.py`     |  9 | All query methods, dangerous_acls, full_graph structure |
| `test_adcs.py`      | 13 | ESC1/2/3 edge cases, esc_findings grouping, JSON output |

### Step 2: Import sanity

```bash
python -c "
import adenum.cli
import adenum.collector
import adenum.adcs
import adenum.ingest
import adenum.query
import adenum.serve
print('All imports OK')
"
```

### Step 3: CLI help text

```bash
adenum --help
adenum collect --help     # Check: --ldap-ssl, --ldap-port, --nt-hash, --adcs
adenum ingest --help
adenum query --help       # Check: --dangerous-acls, --rbcd
adenum serve --help
```

### Step 4: Neo4j connectivity

```bash
# With docker compose up -d neo4j running:
python -c "
from neo4j import GraphDatabase
d = GraphDatabase.driver('bolt://localhost:7687', auth=('neo4j','adenum123'))
d.verify_connectivity()
print('Neo4j reachable')
d.close()
"
```

### Step 5: LDAP connectivity (lab DC only)

```bash
python -c "
from adenum.collector import ADCollector
c = ADCollector(domain='corp.local', dc_ip='10.10.10.5', username='svc', password='pw')
c.connect()
print('LDAP bind OK')
c.conn.unbind()
"
```

### Step 6: End-to-end (lab domain)

Run the full `collect → ingest → query → serve` sequence from section 5
against a lab domain (see section 10). Spot-check results in Neo4j browser:

```cypher
MATCH (n) RETURN n LIMIT 50
MATCH (u:User {kerberoastable: true}) RETURN u
MATCH (start)-[*1..5]->(da:Group) WHERE da.name =~ '(?i)domain admins.*' RETURN start, da
```

### Common errors and fixes

| Error | Fix |
|-------|-----|
| `ldap3.core.exceptions.LDAPSocketOpenError` | DC IP unreachable — check firewall/VPN/port 389 |
| `invalidCredentials` on bind | Wrong domain\\user\\password — verify NTLM format |
| `ServiceUnavailable` from neo4j driver | Neo4j not up — `sudo docker-compose up -d neo4j` and wait for healthy |
| `impacket` fails to build | `sudo apt install libkrb5-dev krb5-user build-essential` then retry |
| Empty query results after ingest | Check ingest stats — zero counts = wrong JSON path or empty file |
| `version` deprecation warning in Docker | Already fixed — `version:` key removed from docker-compose.yml |
| `TypeError: 'NoneType' object is not subscriptable` in ingest | Already fixed — `result.single()` null guard in `_link_members()` |
| Graph explorer shows "Neo4j unreachable" | Run `adenum serve` first AND have Neo4j container healthy |

---

## 10. Lab environment recommendation

Never point ADenum at a production domain during development or testing.
Use a dedicated lab instead:

- **[DetectionLab](https://github.com/clong/DetectionLab)** — Vagrant/Packer
  single-domain lab, good for basic collection testing
- **[GOAD (Game of Active Directory)](https://github.com/Orange-Cyberdefense/GOAD)** — deliberately
  vulnerable multi-domain environment, ideal for exercising all attack-path queries
  including Kerberoasting, delegation abuse, and ACL chains
- **[vulnerable-AD](https://github.com/WazeHell/vulnerable-AD)** — lightweight
  PowerShell script to stand up a misconfigured domain on a single Windows Server VM

---

## 11. ADCS enumeration reference (ESC1–ESC3)

| ESC | Condition | Impact |
|-----|-----------|--------|
| ESC1 | Template allows enrollee to supply SAN (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) | Attacker requests cert as Domain Admin |
| ESC2 | Template has "Any Purpose" EKU or no EKU | Cert usable for any purpose including smart-card auth |
| ESC3 | Template has Certificate Request Agent EKU | Attacker can request certs on behalf of other users |

```bash
# Collect + flag in one command
adenum collect -d corp.local -u svc -p 'pw' -dc-ip 10.10.10.5 --adcs --out ./collected

# View the JSON findings
cat ./collected/adenum_adcs_corp.local.json | python -m json.tool | grep -A5 '"esc1": true'
```
