"""
KubePath — main.py
===================
Simply run:   python main.py

What happens:
  1. Ingests cluster data (mock by default, live with --live)
  2. Scores CVE data silently from mock DB (use --cve for live NVD API)
  3. Builds the NetworkX graph
  4. Runs BFS, Dijkstra, DFS, Critical Node algorithms
  5. Calls Gemini AI for executive summary
  6. Prints the full rich CLI dashboard (original look)
  7. Generates PDF Kill Chain Report
  8. Generates Interactive HTML Dashboard
  9. Saves a temporal snapshot + diffs against the previous run
 10. Prints the file paths of all deliverables

Flags:
    --live       Ingest from live kubectl cluster instead of mock
    --cve        Fetch real CVSS scores from the NIST NVD API (slow, needs internet)
    --serve      Auto-open the HTML dashboard in your browser
"""

import os
import sys
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

    graph_path = "data/cluster-graph.json"

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
    # Silent by default (mock DB). Pass --cve to hit the NIST NVD API.
    scorer = CVEScorer(use_api=args.cve, cache=True)
    raw_data["nodes"] = scorer.score_all_nodes(raw_data["nodes"])
    with open(graph_path, "w") as f:
        json.dump(raw_data, f, indent=2)

    # ── 3. GRAPH CONSTRUCTION (Task 2) ───────────────────────────────────────
    engine = KubeGraphEngine(graph_path)
    reporter = CLIReport()
    ai = SecurityAI()

    source_node     = "internet"
    target_node     = "postgres"
    compromised_pod = "frontend-1"

    # ── 4. ALGORITHMS (Tasks 3 & 4) ──────────────────────────────────────────
    blast_radius             = engine.get_blast_radius(compromised_pod, hops=3)
    path, path_risk          = engine.get_shortest_path(source_node, target_node)
    cycles                   = engine.get_cycles()
    critical_node, reduction = engine.get_critical_node(source_node, target_node)

    if not path:
        print("\n[✔] No attack path found from public nodes to Crown Jewels.")
        return

    # ── 5. AI SUMMARY ────────────────────────────────────────────────────────
    ai_summary = ai.generate_executive_summary(
        path, path_risk, critical_node, reduction
    )

    # ── 6. RICH CLI DASHBOARD (Task 3) — original look ───────────────────────
    reporter.print_dashboard(
        G=engine.G, source=source_node, target=target_node,
        path=path, path_risk=path_risk,
        blast_radius=blast_radius, cycles=cycles,
        critical_node=critical_node, reduction=reduction,
        ai_summary=ai_summary,
    )

    # ── 7. PDF KILL CHAIN REPORT (Task 3) ────────────────────────────────────
    pdf_path = PDFReport.generate(
        G=engine.G, source=source_node, target=target_node,
        path=path, path_risk=path_risk,
        blast_radius=blast_radius, cycles=cycles,
        critical_node=critical_node, reduction=reduction,
    )

    # ── 8. JSON EXPORT (Task 2) ───────────────────────────────────────────────
    json_export = engine.export_to_json("output/cluster-graph-export.json")

    # ── 9. INTERACTIVE DASHBOARD (Bonus 1) ───────────────────────────────────
    html_path = GraphVisualizer.generate_html(
        G=engine.G,
        critical_path=path,
        blast_radius=blast_radius,
        critical_node=critical_node,
        reduction=reduction,
        cycles=cycles,
        path_risk=path_risk,
        source_node=source_node,
        target_node=target_node,
    )

    # ── 10. TEMPORAL SNAPSHOT + DIFF (Bonus 3) ───────────────────────────────
    temporal = TemporalAnalyzer(source=source_node, target=target_node)
    temporal.save_snapshot(engine)
    diff = temporal.diff_latest()
    if diff and not diff.get("is_unchanged"):
        temporal.print_diff_report(diff)

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