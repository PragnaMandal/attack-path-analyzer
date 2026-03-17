from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
import os

class PDFReport:
    @staticmethod
    def generate(G, source, target, path, path_risk, blast_radius, cycles, critical_node, reduction, output_path="output/Kill_Chain_Report.pdf"):
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        c = canvas.Canvas(output_path, pagesize=letter)
        width, height = letter
        
        # Header
        c.setFont("Helvetica-Bold", 18)
        c.setFillColor(colors.darkblue)
        c.drawString(50, height - 50, "KubePath - Kill Chain Report")
        
        c.setStrokeColor(colors.grey)
        c.line(50, height - 60, width - 50, height - 60)
        
        # Warning Section
        c.setFont("Helvetica-Bold", 14)
        c.setFillColor(colors.red)
        c.drawString(50, height - 90, "⚠ WARNING: Attack Path Detected")
        
        c.setFont("Helvetica", 12)
        c.setFillColor(colors.black)
        c.drawString(50, height - 110, f"User/Entry '{source}' can reach '{target}' via:")
        
        # Path details
        y = height - 135
        for i, node in enumerate(path):
            node_data = G.nodes[node]
            cve = node_data.get('cve', '')
            cvss = node_data.get('cvss', 0.0)
            
            vuln_str = f" ({cve}, CVSS {cvss})" if cve and cvss > 0 else ""
            prefix = "    " * i + "→ " if i > 0 else ""
            
            c.drawString(50, y, f"{prefix}{node}{vuln_str}")
            y -= 20
            
        # Metrics
        y -= 10
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, f"Total Hops: {len(path)-1}   |   Path Risk Score: {path_risk:.1f} (CRITICAL)")
        
        # Graph Analytics (BFS/DFS)
        y -= 40
        c.setFont("Helvetica", 12)
        c.drawString(50, y, f"✓ Blast Radius of {path[1] if len(path) > 1 else path[0]}: {len(blast_radius)} resources within 3 hops")
        
        y -= 20
        cycle_str = f"{len(cycles)} (e.g., {' <-> '.join(cycles[0])} loop)" if cycles else "0"
        c.drawString(50, y, f"✓ Cycles Detected: {cycle_str}")
        
        # Remediation
        y -= 40
        c.setStrokeColor(colors.lightgrey)
        c.rect(45, y - 40, width - 90, 60, fill=0, stroke=1)
        
        c.setFont("Helvetica-Bold", 12)
        c.setFillColor(colors.darkgreen)
        c.drawString(55, y, "Actionable Recommendation (Critical Node):")
        
        c.setFont("Helvetica", 12)
        c.setFillColor(colors.black)
        c.drawString(55, y - 20, f"Remove permission binding / node '{critical_node}' to eliminate {reduction} attack paths.")
        
        c.save()
        return output_path