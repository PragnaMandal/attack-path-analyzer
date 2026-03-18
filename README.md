# KubePath — Kubernetes Attack Path Visualizer

> *"Security is not about preventing every possible attack — it is about making every attack path visible."*

KubePath is a graph-based security analysis tool for cloud-native infrastructure. It models a Kubernetes cluster as a Directed Graph and applies classical computer science algorithms to surface hidden, exploitable attack chains before an adversary does.

---

## 🏆 Deliverables

| # | Deliverable | Location |
|---|-------------|----------|
| ✅ | Working CLI Tool — rich terminal dashboard with AI summary | Terminal output |
| ✅ | Kill Chain Report — formal PDF with attack path details | `output/Kill_Chain_Report.pdf` |
| ✅ | JSON Graph Export — fully processed graph with all metadata | `output/cluster-graph-export.json` |
| ✅ | Algorithm Implementations — BFS, Dijkstra, DFS, Critical Node | `src/graph_engine.py` |
| ✅ | **Bonus 1** — Interactive HTML/JS Visualizer (Cytoscape.js) | `output/index.html` |
| ✅ | **Bonus 2** — Live CVE Scoring via NIST NVD API | `src/cve_scorer.py` |
| ✅ | **Bonus 3** — Temporal Analysis: snapshot diffing & new-path alerting | `src/temporal.py` |
| ✅ | **Bonus** — AI Executive Summaries via Google Gemini | `src/ai_agent.py` |

---

## ⚙️ Setup

**Prerequisites:** Python 3.8+

```bash
# 1. Clone the repository
git clone <repo-url>
cd kubepath_project

# 2. Create and activate virtual environment
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Set API keys
export GEMINI_API_KEY="your-gemini-key"   # AI executive summaries
export NVD_API_KEY="your-nvd-key"         # Higher NVD rate limit (50 req/30s vs 5)
```

---

## 🚀 Running the Tool

```bash
# Standard run — mock cluster data, mock CVE DB
python main.py

# Ingest from a live Kubernetes cluster via kubectl
python main.py --live

# Fetch real CVSS scores from the NIST NVD API (requires internet)
python main.py --cve

# Auto-open the interactive dashboard in your browser after generation
python main.py --serve

# Full run — live cluster + live CVE scoring + open browser
python main.py --live --cve --serve
```

### What happens when you run `python main.py`

```
Loading KubePath Engine...
```
The tool silently:
1. Ingests cluster data (mock JSON, enriched with namespace / risk scores / CVE annotations)
2. Scores CVE data from the mock database (or live NVD API with `--cve`)
3. Builds the NetworkX directed graph

Then the **rich terminal dashboard** appears:

```
╔══════════════════════════════════════╗
║   KubePath Advanced Security Dashboard ║
╚══════════════════════════════════════╝

┌─ AI Executive Summary (Gemini) ────────────────────────────────┐
│  Critical vulnerability detected bridging public endpoints...   │
└─────────────────────────────────────────────────────────────────┘

Critical Attack Path Detected: internet → postgres
 Hop  Entity Node ID         Display Name            Type
  0   internet               Internet                EXTERNAL
  1   frontend-1             Frontend Pod 1          POD
  2   gateway                API Gateway             SERVICE
  ...

  Total Resistance Weight: 9  |  Total Hops: 6

┌─ Graph Analytics ──────────────────────────────────────────────┐
│  ✓ Blast Radius (internet): 14 nodes compromised within 3 hops │
│  ✓ DFS Cycle Detection: 1 privilege loops found                │
│    (auth-service ↔ logging-service)                            │
└─────────────────────────────────────────────────────────────────┘

┌─ Recommended Remediation (Task 4) ─────────────────────────────┐
│  Choke point: role-secrets                                      │
│  Removing this node breaks 5 active attack paths.              │
└─────────────────────────────────────────────────────────────────┘
```

Finally:
```
[✔] DELIVERABLES GENERATED:
 ├── PDF Kill Chain Report : /path/to/output/Kill_Chain_Report.pdf
 ├── JSON Graph Export     : /path/to/output/cluster-graph-export.json
 ├── Interactive Dashboard : /path/to/output/index.html
 ├── Temporal Snapshots    : /path/to/data/snapshots/
 └── CVE Cache             : /path/to/data/cve_cache.json
```

---

## 📁 Project Structure

```
kubepath_project/
├── main.py                    # Entry point
├── requirements.txt
├── data/
│   ├── mock-cluster-graph.json    # Sample 21-node cluster dataset
│   ├── cluster-graph.json         # Enriched graph (generated on run)
│   ├── cve_cache.json             # Cached NVD API results
│   └── snapshots/                 # Temporal analysis snapshots
│       └── snapshot_YYYYMMDD_HHMMSS.json
├── output/
│   ├── Kill_Chain_Report.pdf      # PDF kill chain report
│   ├── cluster-graph-export.json  # Full graph JSON export
│   └── index.html                 # Interactive Cytoscape.js dashboard
└── src/
    ├── __init__.py
    ├── ingester.py        # Task 1  — kubectl ingestion + mock enrichment
    ├── graph_engine.py    # Task 2  — NetworkX graph + all algorithms
    ├── reporter.py        # Task 3  — Rich CLI dashboard
    ├── pdf_generator.py   # Task 3  — PDF kill chain report
    ├── visualizer.py      # Bonus 1 — Interactive HTML dashboard
    ├── cve_scorer.py      # Bonus 2 — NIST NVD API CVE scoring
    ├── temporal.py        # Bonus 3 — Snapshot storage & graph diffing
    └── ai_agent.py        # Bonus   — Gemini AI executive summaries
```

---

## 📊 Graph Schema

### Node Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier (e.g., `frontend-1`) |
| `type` | string | Entity kind: `pod`, `service`, `db`, `external`, `role`, `sa`, `secret`, `configmap` |
| `label` | string | Human-readable display name |
| `namespace` | string | Kubernetes namespace (e.g., `default`, `data`, `cluster-wide`) |
| `risk_score` | float | Composite risk score 0.0–10.0 (base type risk + CVE severity) |
| `cve` | string | Known vulnerability ID (e.g., `CVE-2023-44487`) |
| `cvss` | float | CVSS base score 0.0–10.0, fetched from NIST NVD |
| `cve_desc` | string | Short vulnerability description |
| `labels` | object | Kubernetes labels map |
| `is_public` | bool | True for external ingress points (attack entry nodes) |
| `is_crown_jewel` | bool | True for critical targets (databases, admin roles) |

### Edge Fields

| Field | Type | Description |
|-------|------|-------------|
| `source` | string | Origin node ID |
| `target` | string | Destination node ID |
| `relationship` | string | Trust relationship type (e.g., `uses_service_account`, `bound_to_role`, `grants_access`) |
| `weight` | int | Exploitability score — lower = easier to traverse for an attacker |

---

## 🧠 Algorithms

### Algorithm 1 — Blast Radius Detection (BFS)
**Purpose:** If a pod is compromised today, how far can an attacker reach?

Uses `networkx.ego_graph` to run Breadth-First Search up to `N` hops (default: 3) from a source node. Returns the full set of reachable nodes — the *Danger Zone* — enabling rapid incident response scoping.

```
BFS Blast Radius of 'frontend-1': 14 nodes within 3 hops
```

### Algorithm 2 — Shortest Attack Path (Dijkstra's Algorithm)
**Purpose:** What is the easiest route from the internet to the Production Database?

Runs Dijkstra's shortest-path algorithm on edge weights (exploitability scores). Lower weight = less resistance = higher attacker priority. Returns the minimum-cost path and total risk score.

```
internet → frontend-1 → gateway → auth-service → sa-auth → role-admin → api-key → internal-api → postgres
Total Hops: 8  |  Path Risk Score: 9.0
```

### Algorithm 3 — Circular Permission Detection (DFS)
**Purpose:** Detect misconfigured mutual admin grants that amplify every attack path.

Custom recursive DFS tracking `visited` and `rec_stack` sets to detect back-edges (cycles). Deduplicates cycles by canonical sorted signature. Finds privilege escalation loops like `auth-service ↔ logging-service`.

```
✓ Cycles Detected: 1 (auth-service ↔ logging-service mutual admin grant)
```

### Task 4 — Critical Node Identification
**Purpose:** Find the single fix that eliminates the most attack paths.

For each intermediate node on any source→target path, temporarily removes it and recounts valid paths. The node causing the greatest reduction is the critical choke point.

```
Recommendation: Remove 'role-secrets' to eliminate 5 of 6 attack paths.
```

---

## 🌐 Interactive Dashboard (Bonus 1)

Open `output/index.html` in any browser. No server required.

| Button | Algorithm | What it shows |
|--------|-----------|---------------|
| ☢ **Blast Radius** | BFS | Amber nodes — all nodes reachable within 3 hops of the compromised pod |
| ⚔ **Attack Path** | Dijkstra | Red path — the minimum-resistance route to the Crown Jewel database |
| 🔄 **Circular Perms** | DFS | Purple nodes/edges — circular permission loops |
| 📊 **Risk Score** | Composite | Live risk meter: 0–100% based on entity types, density, and active kill chain |
| ✓ **Simulate Patch** | Critical Node | Greys out the choke point; re-run Attack Path to confirm the kill chain is broken |

**Two graph views** (toggle top-right):
- **Force** — original left-to-right attack chain layout
- **Clusters** — nodes grouped into type bubbles (Pods, Services, Secrets, etc.)

Node shapes indicate type: ◆ diamond = external, ● circle = pod, ▭ rectangle = service, ⬡ octagon = ServiceAccount, ⬠ pentagon = role, ★ star = secret, ▣ barrel = database.

---

## 🔍 Live CVE Scoring (Bonus 2)

`src/cve_scorer.py` queries the [NIST NVD API v2](https://nvd.nist.gov/developers/vulnerabilities) to auto-assign real CVSS scores to cluster nodes based on their container image name.

```bash
# Run standalone CVE lookup
python -m src.cve_scorer nginx postgres redis
```

Results are cached in `data/cve_cache.json` to avoid redundant API calls on repeated runs. Set `NVD_API_KEY` in your environment to raise the rate limit from 5 to 50 requests per 30 seconds.

---

## ⏱️ Temporal Analysis (Bonus 3)

`src/temporal.py` stores a JSON snapshot of the graph state after every run and diffs consecutive scans to detect security regressions.

```bash
# List all stored snapshots
python -m src.temporal --list

# Diff the two most recent snapshots
python -m src.temporal --diff

# Clear all snapshots
python -m src.temporal --clear
```

**Sample diff output:**
```
──────────────────────────────────────────────────
  KubePath — Temporal Diff Report
──────────────────────────────────────────────────
  Old scan : 2024-01-15T10:00:00Z
  New scan : 2024-01-15T11:30:00Z

  ATTACK PATH CHANGES
  ⚠  2 NEW attack path(s) detected!

    + internet→frontend-2→gateway→orders-service→...→postgres
    + internet→analytics-dashboard→sa-analytics→...→postgres

  RISK SCORE
  Path risk: 9.0 → 18.0  (+9.0)

  🔴 ACTION REQUIRED — new attack vectors have appeared.
```

---

## 🤖 AI Executive Summary

When `GEMINI_API_KEY` is set, KubePath calls Google Gemini to generate a 3-sentence board-level executive summary of the most critical attack path and the recommended remediation — displayed at the top of the CLI dashboard.

If the key is not set, a static fallback summary is used automatically.

---

## 📦 Dependencies

```
networkx==3.2.1      # Graph construction and algorithms
rich==13.7.0         # Terminal dashboard formatting
requests==2.31.0     # NIST NVD API calls
reportlab==4.0.9     # PDF kill chain report generation
google-generativeai==0.4.0  # Gemini AI executive summaries
```

Install with:
```bash
pip install -r requirements.txt
```