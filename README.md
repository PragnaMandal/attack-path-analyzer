# KubePath — Kubernetes Attack Path Visualizer

> *"Security is not about preventing every possible attack — it is about making every attack path visible."*

---

KubePath is a dynamic **Graph-Based Security Posture Management** tool. It ingests a Kubernetes cluster's state, models it as a directed graph, and applies advanced graph theory algorithms to surface hidden multi-hop attack chains — producing an actionable Kill Chain Report before threats are exploited.

Traditional RBAC audits review permissions in isolation. Each individual binding looks benign. The actual threat — privilege escalation via lateral movement across Pods, Service Accounts, Roles, and Secrets — stays invisible until it is exploited. **KubePath makes every attack path visible.**

---

## 🏆 Deliverables

| | Deliverable | File |
|---|---|---|
| ✅ | Rich terminal dashboard with AI executive summary | CLI output |
| ✅ | PDF Kill Chain Report | `output/Kill_Chain_Report.pdf` |
| ✅ | JSON graph export | `output/cluster-graph-export.json` |
| ✅ | 4 algorithms: BlastRank · A\* · DFS · Min-Cut | `src/graph_engine.py` |
| ✅ | **Bonus 1** — Interactive Cytoscape.js dashboard | `output/index.html` |
| ✅ | **Bonus 2** — Live CVE scoring via NIST NVD API | `src/cve_scorer.py` |
| ✅ | **Bonus 3 Phase 1** — Temporal graph diffing & alerting | `src/temporal.py` |
| ✅ | **Bonus 3 Phase 2** — KAN predictive AI (pure NumPy) | `src/kan_predictor.py` |
| ✅ | **Bonus** — Google Gemini AI executive summary | `src/ai_agent.py` |

---

## ⚙️ Setup

**Prerequisites:** Python 3.8+

```bash
# 1. Clone the repository
git clone https://github.com/PragnaMandal/attack-path-analyzer
cd kubepath_project

# 2. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install all dependencies
pip install -r requirements.txt

# 4. (Optional) Set API keys
export GEMINI_API_KEY="your-gemini-key"    # enables AI executive summaries
export NVD_API_KEY="your-nvd-key"          # raises NVD rate limit to 50 req/30s
```

---

## 🚀 Running

```bash
python main.py                       # standard run — mock data, offline CVEs
python main.py --live                # ingest from a live cluster via kubectl
python main.py --cve                 # fetch live CVSS scores from NIST NVD API
python main.py --serve               # auto-open HTML dashboard in browser
python main.py --live --cve --serve  # full run
```

### What `python main.py` does step by step

```
Loading KubePath Engine...
```

Silently in background:
- Ingests and enriches cluster graph (mock or live kubectl)
- Scores CVEs via mock database (or NVD API with `--cve`)
- Builds NetworkX DiGraph with full node/edge metadata
- Runs all four algorithms

Then the **rich terminal dashboard** appears:

```
╔══════════════════════════════════════════════╗
║   KubePath  ·  Advanced Security Dashboard   ║
╚══════════════════════════════════════════════╝

┌─ AI Executive Summary (Gemini) ──────────────────────────────────┐
│  A critical vulnerability chain connects the public internet to  │
│  the production database via exploitable RBAC misconfigurations. │
│  Patching role-secrets eliminates 5 of 6 attack paths...        │
└──────────────────────────────────────────────────────────────────┘

  ⚔  A* Attack Path Detected: internet → postgres
  Hop  Node ID               Display Name          Type      CVE              CVSS
   0   internet              Internet              EXTERNAL  CVE-1999-0280    7.5
   1   analytics-dashboard   Analytics Dashboard   POD       CVE-2023-46604   9.8
   2   sa-analytics          Analytics SA          SA        —                —
   3   role-secrets          Read Secrets Role     ROLE      —                —
   4   db-secret             DB Credentials        SECRET    —                —
   5   internal-api          Internal Core API     SERVICE   CVE-2018-5256    7.5
   6   postgres              Production DB         DB        —                —

  Algorithm: A* + Privilege Proximity Heuristic | Risk Score: 8.0 | Hops: 6

┌─ Graph Analytics ────────────────────────────────────────────────┐
│  ✓ BlastRank Blast Radius (frontend-1): 14 nodes within 3 hops  │
│  ✓ Algorithm: BFS ego-graph + Eigenvector Centrality (Markov)   │
│  → Top: auth-service(1.000) logging-service(1.000) sa-auth(0.87)│
│  ✓ DFS Cycle Detection: 1 loop — auth-service ↔ logging-service │
└──────────────────────────────────────────────────────────────────┘

┌─ Recommended Remediation — Critical Node (Min-Cut) ──────────────┐
│  Algorithm: Min-Cut / Max-Flow (Ford-Fulkerson node-split)       │
│  Choke point: role-secrets                                        │
│  Removing this node breaks 5 active attack paths.               │
└──────────────────────────────────────────────────────────────────┘

──────────────────────────────────────────────────────────────────
  KAN Predictive Analysis (Phase 2)
──────────────────────────────────────────────────────────────────
🔴 HIGH RISK — KAN predicts a NEW attack path will appear
  Prediction probability: 78.3%
  Top contributing features:
    · path_risk=9.0    [↑ pushing risk up, contribution=+0.421]
    · edge_count=26    [↑ pushing risk up, contribution=+0.187]
    · cycle_count=1    [↑ pushing risk up, contribution=+0.093]

[✔] DELIVERABLES GENERATED:
 ├── PDF Kill Chain Report : .../output/Kill_Chain_Report.pdf
 ├── JSON Graph Export     : .../output/cluster-graph-export.json
 ├── Interactive Dashboard : .../output/index.html
 ├── Temporal Snapshots    : .../data/snapshots/
 └── CVE Cache             : .../data/cve_cache.json
```

> **Note:** KAN prediction requires ≥ 3 runs of `python main.py` to build enough snapshot history to train on. It will inform you how many more runs are needed.

---

## 📁 Project Structure

```
kubepath_project/
├── main.py                        # entry point
├── requirements.txt
├── data/
│   ├── mock-cluster-graph.json    # 21-node synthetic dataset
│   ├── cluster-graph.json         # enriched graph (generated at runtime)
│   ├── cve_cache.json             # cached NVD API results
│   ├── kan_model.json             # saved KAN spline coefficients
│   └── snapshots/
│       └── snapshot_YYYYMMDD_HHMMSS.json
├── output/
│   ├── Kill_Chain_Report.pdf
│   ├── cluster-graph-export.json
│   └── index.html
└── src/
    ├── ingester.py        # Task 1  — kubectl ingestion + mock enrichment
    ├── graph_engine.py    # Task 2  — graph construction + all 4 algorithms
    ├── reporter.py        # Task 3  — rich terminal dashboard
    ├── pdf_generator.py   # Task 3  — PDF kill chain report
    ├── visualizer.py      # Bonus 1 — interactive Cytoscape.js dashboard
    ├── cve_scorer.py      # Bonus 2 — NIST NVD API CVE scoring
    ├── temporal.py        # Bonus 3 Phase 1 — snapshot diffing & alerting
    ├── kan_predictor.py   # Bonus 3 Phase 2 — KAN predictive AI
    └── ai_agent.py        # Bonus   — Gemini AI executive summaries
```

---

## 📊 Graph Schema

### Node Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier (e.g. `frontend-1`) |
| `type` | string | `pod` · `service` · `db` · `external` · `role` · `sa` · `secret` · `configmap` |
| `label` | string | Human-readable display name |
| `namespace` | string | Kubernetes namespace |
| `risk_score` | float | Composite 0.0–10.0 (base type risk + CVE contribution) |
| `cve` | string | Vulnerability ID (e.g. `CVE-2023-44487`) |
| `cvss` | float | CVSS base score 0.0–10.0 from NIST NVD |
| `cve_desc` | string | Short description of the vulnerability |
| `is_public` | bool | `true` for external ingress/attack entry nodes |
| `is_crown_jewel` | bool | `true` for production databases and admin roles |

### Edge Fields

| Field | Type | Description |
|-------|------|-------------|
| `source` | string | Origin node ID |
| `target` | string | Destination node ID |
| `relationship` | string | `uses_service_account` · `bound_to_role` · `grants_access` · `calls_service` · etc. |
| `weight` | int | Exploitability score — lower = easier to traverse |

---

## 🧠 Algorithms

### 1. BlastRank — BFS + Markov Chain (Eigenvector Centrality)

**File:** `src/graph_engine.py` → `get_blast_radius()`

**The problem with plain BFS:** counts hops and treats every node equally. A dead-end pod 2 hops away looks as dangerous as the central auth service 2 hops away.

**Our approach:**
1. BFS `ego_graph` identifies the N-hop danger zone (same as before)
2. **Eigenvector Centrality** runs on that subgraph — mathematically equivalent to the **PageRank stationary distribution** of a Markov Chain. An APT randomly walking trust links will spend time proportional to each node's BlastRank score.

**Result:** Nodes are ranked by *influence*, not just distance. `auth-service` scores 1.000 because every path flows through it. A dead-end pod scores 0.000.

```
Returns: (blast_nodes: list, blast_ranks: dict{node: score})
```

---

### 2. A\* Search with Privilege Proximity Heuristic h(n)

**File:** `src/graph_engine.py` → `get_shortest_path()`

**The problem with Dijkstra:** searches blindly in all directions — equivalent to a script-kiddie scanner. It has no concept of which nodes are interesting to an attacker.

**Our approach:** Custom A\* with heuristic:

```
h(n) = hop_distance_to_target × 0.2
       − privilege_rank(type) × 0.3
       − cvss_score × 0.15
```

Lower `h(n)` = node is closer to a crown jewel in privilege space. The search is steered toward high-privilege nodes (roles, secrets, databases) before exploring low-value pods and configmaps. Simulates an **APT that knows what it is hunting**.

**Privilege rank:** `db=10, secret=9, clusterrole=8, role=7, sa=6, service=4, pod=3, external=1`

```
Returns: (path: list, cost: float, hops: int)
```

On the mock cluster, A\* found a **different path than Dijkstra** — one that goes through the analytics pod (CVSS 9.8) rather than the higher-weight frontend path, because the heuristic correctly identifies the analytics→sa→role→secret chain as the path of least privilege resistance.

---

### 3. DFS Circular Permission Detection

**File:** `src/graph_engine.py` → `get_cycles()`

Explicit recursive DFS maintaining a `visited` set and a `rec_stack` (nodes currently on the active DFS path). A back-edge — neighbour already in `rec_stack` — proves a cycle exists. Deduplicates by canonical sorted signature so `A→B→A` is not reported twice as `A↔B` and `B↔A`.

**Security value:** Privilege escalation loops like `auth-service ↔ logging-service` mean any compromise in the loop grants access to both — amplifying every attack path that touches either node.

```
Returns: list of cycles, each cycle is a list of node IDs
```

---

### 4. Critical Node — Min-Cut / Max-Flow (Ford-Fulkerson)

**File:** `src/graph_engine.py` → `get_critical_node()`

**The problem with brute-force:** remove each node, recount paths, restore — O(V × P). For enterprise clusters with thousands of nodes and paths this is completely intractable.

**Our approach — node-split flow network:**

1. Each real node `v` is split into `v_IN` and `v_OUT` with an internal edge of **capacity 1** (meaning at most one unit of attack flow can pass through each node)
2. Edges between nodes get **capacity ∞** (connections between nodes are free)
3. **Ford-Fulkerson Max-Flow** runs from `source_IN` to `target_OUT`
4. By the **Min-Cut / Max-Flow theorem**, saturated internal edges (`flow = capacity = 1`) identify exactly the nodes whose removal disconnects the source from the target — these are the choke points

The node with the highest flow through its internal edge is the critical node. One flow computation replaces V graph reconstructions.

```
Returns: (critical_node_id: str, paths_broken: int)
Falls back to brute-force for disconnected graphs where flow fails.
```

---

## ⏱️ Temporal Analysis — Bonus 3

### Phase 1 — Deterministic Graph Diffing ✅

**File:** `src/temporal.py`

After every `python main.py` run, a JSON snapshot is saved to `data/snapshots/`. The diff engine compares consecutive snapshots and alerts on:
- New attack paths that appeared
- Paths that were remediated
- New privilege loops
- Risk score delta
- Critical node changes

```bash
python -m src.temporal --list    # list all snapshots
python -m src.temporal --diff    # diff the two most recent scans
python -m src.temporal --clear   # delete all snapshots
```

Sample alert:
```
⚠  2 NEW attack path(s) detected!
  + internet→frontend-2→gateway→orders-service→...→postgres

Risk: 9.0 → 18.0  (+9.0)
🔴 ACTION REQUIRED — new attack vectors have appeared.
```

### Phase 2 — KAN Predictive AI ✅

**File:** `src/kan_predictor.py`

**Why not an MLP?**

| | MLP | KAN |
|---|---|---|
| Activations | Fixed (ReLU/sigmoid) on **nodes** | Learnable **B-splines** on **edges** |
| Weights | Scalar multipliers | Full spline functions φ(x) |
| Interpretable | ❌ Black box | ✅ Every edge function is readable |
| Explanation | "Weight=0.73" | "path_risk>7 → steep risk increase" |

**Architecture:** 7 → 4 → 1 (two KAN layers, 32 spline functions total)

**Input features** (extracted from each snapshot):

| Feature | Description |
|---------|-------------|
| `node_count` | Total nodes in the graph |
| `edge_count` | Total edges |
| `path_count` | Number of active attack paths |
| `path_risk` | A\* shortest path risk score |
| `cycle_count` | Number of circular permission loops |
| `critical_node_rank` | Privilege rank of the current choke point |
| `risk_delta` | Change in path risk since last scan |

**Output:** Probability that the **next scan** will contain a new attack path.

**How it works:**
- Each edge in the KAN carries a learnable B-spline `φ(x)` computed via the Cox-de Boor recursion formula
- Trained with numerical gradient descent (finite differences) — zero framework dependency, pure NumPy
- After training, each spline can be directly inspected: *"edge path_risk→hidden_0 steepens sharply at values above 7.0"*
- Model saved to `data/kan_model.json` and reloaded on subsequent runs

```bash
python -m src.kan_predictor              # train + predict
python -m src.kan_predictor --explain    # show all 32 learned spline functions
```

> **Note:** Requires ≥ 3 runs of `python main.py` to build training history.

---

## 🌐 Interactive Dashboard — Bonus 1

Open `output/index.html` in any browser. No server required.

| Button | Algorithm | Shows |
|--------|-----------|-------|
| ☢ Blast Radius | BlastRank (BFS + Eigenvector) | Amber nodes — danger zone, sized by BlastRank score |
| ⚔ Attack Path | A\* + Privilege Proximity | Red path — minimum-resistance route to the Crown Jewel |
| 🔄 Circular Perms | DFS cycle detection | Purple nodes/edges — privilege escalation loops |
| 📊 Risk Score | Composite scoring | Live meter 0–100% with entity type breakdown |
| ✓ Simulate Patch | Min-Cut choke point | Greys out critical node; re-run Attack Path to confirm kill chain broken |

**Two graph views** (toggle top-right corner):
- **Force** — original left-to-right kill chain flow layout
- **Clusters** — nodes grouped into type bubbles (Pods · Services · Secrets · Roles · etc.)

---

## 🔍 Live CVE Scoring — Bonus 2

**File:** `src/cve_scorer.py`

Queries the [NIST NVD API v2](https://nvd.nist.gov/developers/vulnerabilities) to assign real CVSS scores to nodes based on container image names. Scores feed directly into the A\* heuristic so that more vulnerable nodes are preferentially explored as attack routes.

```bash
python -m src.cve_scorer nginx postgres redis kafka
```

Results cached in `data/cve_cache.json`. Set `NVD_API_KEY` to increase rate limit from 5 to 50 requests per 30 seconds. Falls back to a built-in mock CVE database when the API is unavailable.

---

## 🤖 AI Executive Summary — Bonus

**File:** `src/ai_agent.py`

When `GEMINI_API_KEY` is set, Google Gemini generates a 3-sentence board-level executive summary of the most critical attack path and recommended remediation — displayed at the top of the dashboard for CISO-facing reporting.

---

## 🏗️ Technical Architecture

| Layer | Technology |
|-------|-----------|
| **Frontend** | HTML5 · Cytoscape.js |
| **Backend** | Python 3.8+ |
| **Graph Engine** | NetworkX (in-memory DiGraph) |
| **AI / ML** | Google Gemini (summarisation) · KAN in NumPy (prediction) |
| **APIs** | Kubernetes API (kubectl) · NIST NVD API |
| **Libraries** | NetworkX · Rich · ReportLab · Requests · NumPy |

---

## 📈 Algorithm Complexity

| Algorithm | Complexity | Notes |
|-----------|-----------|-------|
| BlastRank BFS | O(V + E) | Linear; eigenvector centrality O(V²) on subgraph only |
| A\* Attack Path | O(E log V) | Sub-linear with Privilege Proximity heuristic |
| DFS Cycle Detection | O(V + E) | Linear — full graph traversal |
| Min-Cut Critical Node | O(VE²) | Polynomial — tractable for enterprise graphs |
| KAN Training | O(epochs × 32 × 2ε) | Fixed architecture; fast on small snapshot history |

---

## 📦 Dependencies

```
networkx==3.2.1           # graph construction and all 4 algorithms
rich==13.7.0              # terminal dashboard formatting
requests==2.31.0          # NIST NVD API calls
reportlab==4.0.9          # PDF kill chain report generation
google-generativeai==0.4.0  # Gemini AI executive summaries
numpy>=1.24.0             # KAN predictor — B-spline basis, matrix ops
```

```bash
pip install -r requirements.txt
```

---

## 👥 Who Benefits

**DevSecOps Teams & CISOs** — eliminates blind spots in cloud-native infrastructure, saving hundreds of hours of manual RBAC auditing and spreadsheet review.

**Real-world impact** — traditional tools catch single misconfigurations. KubePath catches *chained* exploits before they happen. Finding the Min-Cut choke point means fixing **one RoleBinding** can eliminate **80% of cluster risk**.