"""
KubePath — main.py
===================
Simply run:   python main.py

Algorithms used:
  1. BlastRank  — BFS + Eigenvector Centrality (Markov Chain model)
  2. A* Search  — Dijkstra base + Privilege Proximity heuristic h(n)
  3. DFS        — Explicit cycle detection with rec_stack
  4. Min-Cut    — Max-Flow (Ford-Fulkerson) critical node identification

Flags:
    --live    Ingest from live kubectl cluster instead of mock
    --cve     Fetch real CVSS scores from NIST NVD API (requires internet)
    --serve   Auto-open the HTML dashboard in your browser
"""

import os
import json
import argparse
import warnings
warnings.filterwarnings("ignore")

from src.ingester       import ingest_live, ingest_mock, _kubectl_available
from src.graph_engine   import KubeGraphEngine
from src.reporter       import CLIReport
from src.visualizer     import GraphVisualizer
from src.ai_agent       import SecurityAI
from src.pdf_generator  import PDFReport
from src.cve_scorer     import CVEScorer
from src.temporal       import TemporalAnalyzer


def main():
    parser = argparse.ArgumentParser(description="KubePath — Kubernetes Attack Path Analyzer")
    parser.add_argument("--live",  action="store_true",
                        help="Ingest from live kubectl cluster (default: mock data)")
    parser.add_argument("--cve",   action="store_true",
                        help="Fetch live CVE scores from NIST NVD API (requires internet)")
    parser.add_argument("--serve", action="store_true",
                        help="Open the HTML dashboard in your browser after generation")
    args = parser.parse_args()

    os.makedirs("data",   exist_ok=True)
    os.makedirs("output", exist_ok=True)

    graph_path      = "data/cluster-graph.json"
    source_node     = "internet"
    target_node     = "postgres"
    compromised_pod = "frontend-1"

    # ── 1. DATA INGESTION (Task 1) ────────────────────────────────────────────
    print("Loading KubePath Engine...")

    if args.live and _kubectl_available():
        print("[*] Querying live Kubernetes cluster via kubectl...")
        raw_data = ingest_live()
    else:
        if args.live:
            print("[!] kubectl not available — using mock data.")
        raw_data = ingest_mock()

    with open(graph_path, "w") as f:
        json.dump(raw_data, f, indent=2)

    # ── 2. CVE SCORING (Bonus 2) ──────────────────────────────────────────────
    scorer = CVEScorer(use_api=args.cve, cache=True)
    raw_data["nodes"] = scorer.score_all_nodes(raw_data["nodes"])
    with open(graph_path, "w") as f:
        json.dump(raw_data, f, indent=2)

    # ── 3. GRAPH CONSTRUCTION (Task 2) ────────────────────────────────────────
    engine   = KubeGraphEngine(graph_path)
    reporter = CLIReport()
    ai       = SecurityAI()

    # ── 4. ALGORITHM 1: BlastRank (BFS + Eigenvector Centrality) ─────────────
    blast_nodes, blast_ranks = engine.get_blast_radius(compromised_pod, hops=3)

    # ── 5. ALGORITHM 2: A* Search (Privilege Proximity Heuristic) ────────────
    path, path_risk, hops = engine.get_shortest_path(source_node, target_node)

    # ── 6. ALGORITHM 3: DFS Cycle Detection ──────────────────────────────────
    cycles = engine.get_cycles()

    # ── 7. ALGORITHM 4: Min-Cut Critical Node (Ford-Fulkerson) ───────────────
    critical_node, reduction = engine.get_critical_node(source_node, target_node)

    if not path:
        print("\n[✔] No attack path found from public nodes to Crown Jewels.")
        return

    # ── 8. AI EXECUTIVE SUMMARY ───────────────────────────────────────────────
    ai_summary = ai.generate_executive_summary(
        path, path_risk, critical_node, reduction
    )

    # ── 9. RICH CLI DASHBOARD (Task 3) ────────────────────────────────────────
    reporter.print_dashboard(
        G=engine.G,
        source=source_node,
        target=target_node,
        path=path,
        path_risk=path_risk,
        blast_nodes=blast_nodes,
        blast_ranks=blast_ranks,
        cycles=cycles,
        critical_node=critical_node,
        reduction=reduction,
        ai_summary=ai_summary,
    )

    # ── 10. PDF KILL CHAIN REPORT (Task 3) ───────────────────────────────────
    pdf_path = PDFReport.generate(
        G=engine.G,
        source=source_node,
        target=target_node,
        path=path,
        path_risk=path_risk,
        blast_radius=blast_nodes,
        cycles=cycles,
        critical_node=critical_node,
        reduction=reduction,
    )

    # ── 11. JSON EXPORT (Task 2) ──────────────────────────────────────────────
    json_export = engine.export_to_json("output/cluster-graph-export.json")

    # ── 12. INTERACTIVE DASHBOARD (Bonus 1) ───────────────────────────────────
    html_path = GraphVisualizer.generate_html(
        G=engine.G,
        critical_path=path,
        blast_radius=blast_nodes,
        critical_node=critical_node,
        reduction=reduction,
        cycles=cycles,
        path_risk=path_risk,
        source_node=source_node,
        target_node=target_node,
    )

    # ── 13. TEMPORAL SNAPSHOT + DIFF (Bonus 3 Phase 1) ──────────────────────
    temporal = TemporalAnalyzer(source=source_node, target=target_node)
    temporal.save_snapshot(engine)
    diff = temporal.diff_latest()
    if diff and not diff.get("is_unchanged"):
        temporal.print_diff_report(diff)

    # ── 14. KAN PREDICTION (Bonus 3 Phase 2) ─────────────────────────────────
    kan_prob, kan_explanation = temporal.predict_next()
    if kan_prob is not None:
        print("\n" + "─" * 60)
        print("  KAN Predictive Analysis (Phase 2)")
        print("─" * 60)
        print(kan_explanation)
    else:
        if kan_explanation:
            print(f"\n[KAN] {kan_explanation}")

    # ── DELIVERABLES SUMMARY ──────────────────────────────────────────────────
    print("\n[✔] DELIVERABLES GENERATED:")
    print(f" ├── PDF Kill Chain Report : {os.path.abspath(pdf_path)}")
    print(f" ├── JSON Graph Export     : {os.path.abspath(json_export)}")
    print(f" ├── Interactive Dashboard : {os.path.abspath(html_path)}")
    print(f" ├── Temporal Snapshots    : {os.path.abspath('data/snapshots/')}")
    print(f" └── CVE Cache             : {os.path.abspath('data/cve_cache.json')}")
    print("\nOpen the HTML file in your browser to view the cluster!")

    if args.serve:
        import webbrowser
        webbrowser.open(f"file://{os.path.abspath(html_path)}")


if __name__ == "__main__":
    main()