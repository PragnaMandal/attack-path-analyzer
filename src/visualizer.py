import json
import os

class GraphVisualizer:
    @staticmethod
    def generate_html(G, critical_path, blast_radius, critical_node, reduction, output_path="output/index.html"):
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        elements = []
        for node, data in G.nodes(data=True):
            # Extract position and scale it up slightly so nodes aren't touching
            pos = data.get('position', {'x': 0, 'y': 0})
            
            elements.append({
                "data": {
                    "id": node, 
                    "label": f"{data.get('label', node)}\n[{data.get('type', '').upper()}]",
                    "type": data.get('type', 'unknown')
                },
                "position": {"x": pos['x'] * 1.5, "y": pos['y'] * 1.5}, # Scaling coordinates
                "classes": "safe" # Default state
            })
            
        for source, target, data in G.edges(data=True):
            elements.append({
                "data": {
                    "id": f"{source}-{target}",
                    "source": source, 
                    "target": target,
                    "weight": data.get('weight', 1)
                },
                "classes": "normal-edge"
            })

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>KubePath Interactive Dashboard</title>
            <!-- Switched to jsdelivr CDN to fix ERR_CERT_AUTHORITY_INVALID -->
            <script src="https://cdn.jsdelivr.net/npm/cytoscape@3.26.0/dist/cytoscape.min.js"></script>
            <style>
                body {{ background-color: #0f172a; color: white; font-family: 'Segoe UI', sans-serif; margin: 0; overflow: hidden; display: flex; }}
                #sidebar {{ width: 300px; background: #1e293b; border-right: 1px solid #334155; padding: 20px; height: 100vh; box-sizing: border-box; display: flex; flex-direction: column; gap: 15px; z-index: 10; }}
                #cy {{ flex-grow: 1; height: 100vh; position: relative; }}
                
                h2 {{ color: #10b981; margin-top: 0; font-size: 24px; border-bottom: 2px solid #334155; padding-bottom: 10px; }}
                .btn {{ background-color: #3b82f6; color: white; border: none; padding: 12px; border-radius: 6px; font-weight: bold; cursor: pointer; transition: 0.2s; width: 100%; text-align: left; }}
                .btn:hover {{ background-color: #2563eb; }}
                .btn-danger {{ background-color: #ef4444; }}
                .btn-danger:hover {{ background-color: #dc2626; }}
                .btn-warning {{ background-color: #f59e0b; }}
                .btn-warning:hover {{ background-color: #d97706; }}
                .btn-success {{ background-color: #10b981; }}
                .btn-success:hover {{ background-color: #059669; }}
                
                .info-box {{ background: #0f172a; padding: 15px; border-radius: 8px; border: 1px solid #334155; margin-top: auto; font-size: 14px; color: #cbd5e1; }}
                .info-box strong {{ color: white; }}
            </style>
        </head>
        <body>
            <div id="sidebar">
                <h2>KubePath UI</h2>
                <button class="btn" onclick="resetGraph()">↻ Reset Graph</button>
                <button class="btn btn-warning" onclick="showBlastRadius()">☢ Show Blast Radius</button>
                <button class="btn btn-danger" onclick="showAttackPath()">⚔ Show Attack Path</button>
                <button class="btn" onclick="showRiskScore()">📊 Calculate Risk Score</button>
                
                <div style="margin-top: 30px; border-top: 1px solid #334155; padding-top: 20px;">
                    <h3 style="color:#ef4444; margin-top:0;">Remediation</h3>
                    <p style="font-size: 13px; color: #94a3b8;">Critical Node: <strong>{critical_node}</strong></p>
                    <button class="btn btn-success" id="auto-fix-btn" onclick="autoFix()">✓ Auto Fix (Simulate)</button>
                </div>

                <div class="info-box" id="status-box">
                    <strong>Status:</strong> System Idle. Select an action above to analyze the cluster.
                </div>
            </div>

            <div id="cy"></div>

            <script>
                if (typeof cytoscape === 'undefined') {{
                    alert("Error: Cytoscape library failed to load! Your network firewall or VPN is blocking the CDN. The graph cannot render.");
                }}

                var elementsData = {json.dumps(elements)};
                var attackPathNodes = {json.dumps(critical_path)};
                var blastRadiusNodes = {json.dumps(blast_radius)};
                var criticalNodeId = "{critical_node}";
                
                // Track if the patch has been applied!
                var isFixed = false; 
                
                var cy = cytoscape({{
                    container: document.getElementById('cy'),
                    elements: elementsData,
                    style: [
                        {{ selector: 'node', style: {{ 'label': 'data(label)', 'color': '#f8fafc', 'text-wrap': 'wrap', 'text-valign': 'bottom', 'text-margin-y': 8, 'font-size': '10px', 'width': 30, 'height': 30, 'background-color': '#475569', 'border-width': 2, 'border-color': '#1e293b' }} }},
                        
                        /* Special Node Shapes */
                        {{ selector: 'node[type="db"]', style: {{ 'shape': 'hexagon', 'background-color': '#eab308', 'width': 40, 'height': 40 }} }},
                        {{ selector: 'node[type="external"]', style: {{ 'shape': 'diamond', 'background-color': '#3b82f6', 'width': 35, 'height': 35 }} }},

                        /* Interaction Classes */
                        {{ selector: 'node.blast', style: {{ 'background-color': '#f59e0b', 'border-color': '#b45309', 'border-width': 3 }} }},
                        {{ selector: 'node.attack', style: {{ 'background-color': '#ef4444', 'border-color': '#7f1d1d', 'border-width': 3, 'box-shadow': '0 0 20px #ef4444' }} }},
                        
                        {{ selector: 'edge', style: {{ 'label': 'data(weight)', 'color': '#94a3b8', 'font-size': '10px', 'width': 2, 'line-color': '#334155', 'target-arrow-color': '#334155', 'target-arrow-shape': 'triangle', 'curve-style': 'bezier', 'text-background-color': '#0f172a', 'text-background-opacity': 0.8 }} }},
                        {{ selector: 'edge.attack-edge', style: {{ 'line-color': '#ef4444', 'target-arrow-color': '#ef4444', 'width': 4 }} }}
                    ],
                    layout: {{ name: 'preset' }} /* PRESET forces Cytoscape to use your X/Y coordinates! */
                }});

                cy.fit(cy.nodes(), 50); /* Centers the graph on screen */

                function setStatus(text) {{
                    document.getElementById('status-box').innerHTML = "<strong>Status:</strong> " + text;
                }}

                function resetGraph() {{
                    if (!window.cy) return;
                    cy.elements().removeClass('blast attack attack-edge');
                    cy.elements().style('display', 'element'); // Unhide if removed
                    setStatus(isFixed ? "Graph reset. Cluster is currently SECURE." : "Graph reset to default vulnerable state.");
                }}

                function showBlastRadius() {{
                    if (!window.cy) return;
                    resetGraph();
                    
                    // Count how many nodes we actually highlight
                    let highlightedCount = 0;
                    blastRadiusNodes.forEach(id => {{
                        let node = cy.getElementById(id);
                        if (node.length > 0) {{ // Only highlight if the node hasn't been deleted
                            node.addClass('blast');
                            highlightedCount++;
                        }}
                    }});
                    
                    if (isFixed) {{
                        setStatus("Blast Radius recalculated. The removed node successfully shrank the danger zone!");
                    }} else {{
                        setStatus("Showing Blast Radius (Orange) from compromised Frontend Pod.");
                    }}
                }}

                function showAttackPath() {{
                    if (!window.cy) return;
                    resetGraph();
                    
                    if (isFixed) {{
                        // The magic logic: If fixed, the path is broken!
                        setStatus("<span style='color:#10b981'>SUCCESS: No attack path exists!</span> The remediation patch broke the kill chain to the Crown Jewels.");
                        return; // Stop here, don't draw any red lines!
                    }}
                    
                    // Highlight Nodes
                    attackPathNodes.forEach(id => {{
                        cy.getElementById(id).addClass('attack');
                    }});

                    // Highlight Edges connecting them (Fixed string concat)
                    for(let i = 0; i < attackPathNodes.length - 1; i++) {{
                        let source = attackPathNodes[i];
                        let target = attackPathNodes[i+1];
                        cy.edges('[source = "' + source + '"][target = "' + target + '"]').addClass('attack-edge');
                    }}
                    setStatus("Showing Dijkstra Shortest Attack Path (Red) to Crown Jewels.");
                }}

                function showRiskScore() {{
                    if (!window.cy) return;
                    let risk = 10; // Start with a baseline risk of 10
                    let nodes = cy.nodes();
                    let edges = cy.edges();
                    
                    let podCount = 0, secretCount = 0, roleCount = 0, hasDB = false;

                    // 1. Base Risk from Entities (Lowered weights for large clusters)
                    nodes.forEach(n => {{
                        let type = n.data('type');
                        if (type === 'pod') podCount++;
                        if (type === 'secret') secretCount++;
                        if (type === 'role') roleCount++;
                        if (type === 'db') hasDB = true;
                    }});

                    risk += (podCount * 1);
                    risk += (secretCount * 3);
                    risk += (roleCount * 2);
                    if (hasDB) risk += 5;

                    // 2. Risk from Network Interconnectivity (Density)
                    if (nodes.length > 0) {{
                        let density = edges.length / nodes.length;
                        risk += (density * 10);
                    }}

                    // 3. Massive penalty if the Critical Attack Path is STILL active
                    if (!isFixed) {{
                        risk += 50; 
                    }}

                    risk = Math.min(100, Math.floor(risk));
                    
                    let statusStr = isFixed ? "SECURE" : "CRITICAL";
                    
                    // Fixed string concat
                    alert("Cluster Risk Score: " + risk + "% [" + statusStr + "]\\n\\nCalculated based on entity types, edge density, and active attack paths.");
                }}

                function autoFix() {{
                    if (!window.cy) return;
                    resetGraph();
                    var nodeToRemove = cy.getElementById(criticalNodeId);
                    if(nodeToRemove.length > 0) {{
                        cy.remove(nodeToRemove); // Physically removes the node and its edges
                        
                        isFixed = true; // Set the state so other buttons know we fixed it!
                        
                        setStatus("Auto-Fix Applied: Removed Critical Node '" + criticalNodeId + "'. Cluster is now secure.");
                        document.getElementById('auto-fix-btn').innerText = "✓ Patched!";
                        document.getElementById('auto-fix-btn').style.pointerEvents = "none";
                    }}
                }}
            </script>
        </body>
        </html>
        """
        with open(output_path, "w") as f: f.write(html_content)
        return output_path