import os
import warnings
import networkx as nx
warnings.filterwarnings("ignore") 

from src.graph_engine import KubeGraphEngine
from src.reporter import CLIReport
from src.visualizer import GraphVisualizer
from src.ai_agent import SecurityAI
from src.pdf_generator import PDFReport

def main():
    print("Loading KubePath Engine...")
    
    os.makedirs('data', exist_ok=True)
    os.makedirs('output', exist_ok=True)
    
    engine = KubeGraphEngine("data/mock-cluster-graph.json")
    reporter = CLIReport()
    ai = SecurityAI()

    source_node = "internet"
    target_node = "postgres"
    compromised_pod = "frontend-1" 
    
    # --- Run Core DSA Algorithms ---
    blast_radius = engine.get_blast_radius(compromised_pod, hops=3)
    path, path_risk = engine.get_shortest_path(source_node, target_node)
    cycles = engine.get_cycles()
    critical_node, reduction = engine.get_critical_node(source_node, target_node)

    if path:
        ai_summary = ai.generate_executive_summary(path, path_risk, critical_node, reduction)

        reporter.print_dashboard(
            G=engine.G, source=source_node, target=target_node, 
            path=path, path_risk=path_risk, 
            blast_radius=blast_radius, cycles=cycles,
            critical_node=critical_node, reduction=reduction,
            ai_summary=ai_summary
        )
        
        # --- NEW: Generate PDF Kill Chain Report ---
        pdf_path = PDFReport.generate(
            G=engine.G, source=source_node, target=target_node,
            path=path, path_risk=path_risk, blast_radius=blast_radius,
            cycles=cycles, critical_node=critical_node, reduction=reduction
        )
        
        # --- NEW: Export JSON Data ---
        json_path = engine.export_to_json("output/cluster-graph-export.json")
        
        html_path = GraphVisualizer.generate_html(
            G=engine.G, critical_path=path, blast_radius=blast_radius, 
            critical_node=critical_node, reduction=reduction
        )
        
        print("\n[✔] DELIVERABLES GENERATED:")
        print(f" ├── PDF Kill Chain Report: {os.path.abspath(pdf_path)}")
        print(f" ├── JSON Data Export:      {os.path.abspath(json_path)}")
        print(f" └── Interactive Dashboard: {os.path.abspath(html_path)}")
        print("\nOpen the HTML file in your browser to view the cluster!")
    else:
        print("\n[Safe] No attack path found from public nodes to Crown Jewels.")

if __name__ == "__main__":
    main()