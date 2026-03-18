import json
import os

class GraphVisualizer:
    @staticmethod
    def generate_html(G, critical_path, blast_radius, critical_node, reduction,
                      cycles=None, path_risk=0, source_node="internet", target_node="postgres",
                      output_path="output/index.html"):
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        if cycles is None:
            cycles = []

        # ── Build Cytoscape elements with SMART LAYOUT ───────────────────────
        # Group nodes by original x-column, then redistribute into evenly-spaced lanes.
        # Column spacing: 200px | Row spacing: 130px | Sizes: much larger than before.

        raw_positions = {}
        for n, data in G.nodes(data=True):
            pos = data.get('position', {'x': 0, 'y': 0})
            raw_positions[n] = (pos.get('x', 0), pos.get('y', 0))

        all_x = sorted(set(p[0] for p in raw_positions.values()))
        col_index = {x: i for i, x in enumerate(all_x)}

        cols = {}
        for n, (x, y) in raw_positions.items():
            ci = col_index[x]
            cols.setdefault(ci, []).append((y, n))

        H_SPACING = 210
        V_SPACING = 125
        X_OFFSET  = 90
        Y_OFFSET  = 70

        final_positions = {}
        for ci in range(len(all_x)):
            nodes_in_col = sorted(cols.get(ci, []), key=lambda t: t[0])
            for ri, (_, node_id) in enumerate(nodes_in_col):
                final_positions[node_id] = (
                    X_OFFSET + ci * H_SPACING,
                    Y_OFFSET + ri * V_SPACING
                )

        elements = []
        for node, data in G.nodes(data=True):
            ntype = data.get('type', 'unknown')
            label = data.get('label', node)
            cve   = data.get('cve', '')
            cvss  = data.get('cvss', 0.0)
            fx, fy = final_positions.get(node, (0, 0))
            elements.append({
                "data": {
                    "id":    node,
                    "label": label,
                    "type":  ntype,
                    "cve":   cve,
                    "cvss":  float(cvss) if cvss else 0.0,
                },
                "position": {"x": fx, "y": fy},
            })

        for src, tgt, data in G.edges(data=True):
            elements.append({
                "data": {
                    "id":     f"{src}-{tgt}",
                    "source": src,
                    "target": tgt,
                    "weight": data.get('weight', 1)
                }
            })

        node_count = G.number_of_nodes()
        edge_count = G.number_of_edges()
        path_hops  = len(critical_path) - 1 if critical_path else 0
        cycle_strings = [" <-> ".join(c) for c in cycles] if cycles else []
        all_cycle_node_ids = list(set(n for cyc in cycles for n in cyc))

        if path_risk >= 30:   risk_color = "#ef4444"
        elif path_risk >= 15: risk_color = "#f97316"
        else:                 risk_color = "#fbbf24"

        type_badge_cls = {
            'external':'external','pod':'pod','service':'service',
            'sa':'sa','role':'role','secret':'secret','db':'db'
        }
        path_rows_html = ""
        for i, n in enumerate(critical_path):
            ndata  = G.nodes[n] if n in G.nodes else {}
            ntype  = ndata.get('type', 'default')
            nlabel = ndata.get('label', n)
            badge  = type_badge_cls.get(ntype, 'default')
            arrow  = '<div class="pn-arrow">&#8595;</div>' if i > 0 else ''
            path_rows_html += (
                f'<div class="path-node-row">{arrow}'
                f'<span class="pn-badge {badge}">{ntype.upper()}</span>'
                f'<span class="pn-name">{nlabel}</span></div>'
            )

        if cycle_strings:
            cycle_html = '<ul class="cycle-list">' + ''.join(
                f'<li>&#x1F504; {c}</li>' for c in cycle_strings) + '</ul>'
        else:
            cycle_html = '<p style="font-size:11px;color:var(--muted)">No circular permission loops detected.</p>'

        def mc_cls(v, hi=30, med=15):
            return "mc-red" if v >= hi else "mc-amber" if v >= med else "mc-green"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>KubePath &middot; Attack Graph Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/cytoscape@3.26.0/dist/cytoscape.min.js"></script>
<style>
:root {{
  --bg:      #060b14;
  --surf:    #0d1627;
  --surf2:   #132035;
  --surf3:   #1a2d47;
  --border:  rgba(56,189,248,0.10);
  --border2: rgba(56,189,248,0.22);
  --text:    #e2e8f0;
  --muted:   #64748b;
  --accent:  #38bdf8;
  --high:    #ef4444;
  --warn:    #fbbf24;
  --low:     #4ade80;
  --purple:  #a78bfa;
  --fh:      'Syne', sans-serif;
  --fm:      'JetBrains Mono', monospace;
}}
*, *::before, *::after {{ box-sizing:border-box; margin:0; padding:0; }}
html,body {{ height:100%; overflow:hidden; background:var(--bg); color:var(--text); font-family:var(--fm); display:flex; flex-direction:column; }}

/* TOPBAR */
.topbar {{ height:50px; background:var(--surf); border-bottom:1px solid var(--border2); display:flex; align-items:center; padding:0 18px; gap:14px; flex-shrink:0; }}
.t-logo {{ font-family:var(--fh); font-size:16px; font-weight:800; color:var(--accent); display:flex; align-items:center; gap:7px; }}
.t-blink {{ width:7px; height:7px; border-radius:50%; background:var(--high); box-shadow:0 0 8px var(--high); animation:blink 1.8s ease-in-out infinite; }}
@keyframes blink {{ 0%,100%{{opacity:1;transform:scale(1)}} 50%{{opacity:.4;transform:scale(.7)}} }}
.t-div {{ width:1px; height:22px; background:var(--border2); }}
.t-tag {{ font-size:10px; letter-spacing:.06em; padding:3px 9px; border-radius:4px; background:var(--surf2); border:1px solid var(--border); color:var(--muted); }}
.t-tag.danger {{ color:#f87171; border-color:rgba(239,68,68,.35); background:rgba(239,68,68,.07); }}
.t-tag.ok     {{ color:#4ade80; border-color:rgba(74,222,128,.35); background:rgba(74,222,128,.07); }}
.t-space {{ flex:1; }}
.t-chips {{ display:flex; gap:8px; }}
.chip {{ font-size:11px; font-weight:600; padding:3px 11px; border-radius:20px; border:1px solid var(--border2); background:var(--surf2); color:var(--muted); display:flex; align-items:center; gap:5px; }}
.chip span {{ color:var(--text); font-size:13px; }}
.chip.red   {{ border-color:rgba(239,68,68,.4);  color:#f87171; }}
.chip.amber {{ border-color:rgba(251,191,36,.4); color:#fbbf24; }}
.chip.green {{ border-color:rgba(74,222,128,.4); color:#4ade80; }}
.chip.blue  {{ border-color:rgba(56,189,248,.4); color:#38bdf8; }}

/* WORKSPACE */
.workspace {{ display:flex; flex:1; overflow:hidden; }}

/* SIDEBAR */
.sidebar {{ width:255px; flex-shrink:0; background:var(--surf); border-right:1px solid var(--border); display:flex; flex-direction:column; overflow-y:auto; }}
.sb {{ padding:12px 12px 8px; border-bottom:1px solid var(--border); }}
.sb:last-child {{ border-bottom:none; flex:1; }}
.sb-lbl {{ font-size:9.5px; font-weight:700; letter-spacing:.12em; text-transform:uppercase; color:var(--muted); margin-bottom:8px; padding:0 2px; }}

.abtn {{ width:100%; display:flex; align-items:center; gap:9px; padding:9px 11px; border-radius:7px; border:1px solid var(--border); background:var(--surf2); color:var(--text); font-family:var(--fm); font-size:11.5px; font-weight:500; cursor:pointer; margin-bottom:5px; transition:all .15s; text-align:left; }}
.abtn .ico {{ font-size:14px; flex-shrink:0; }}
.abtn .bdg {{ margin-left:auto; font-size:9.5px; padding:2px 6px; border-radius:10px; font-weight:700; }}
.abtn:hover        {{ background:var(--surf3); border-color:var(--border2); }}
.abtn.blast:hover  {{ background:rgba(251,191,36,.08); border-color:rgba(251,191,36,.5); color:#fbbf24; }}
.abtn.attack:hover {{ background:rgba(239,68,68,.08);  border-color:rgba(239,68,68,.5);  color:#f87171; }}
.abtn.cycle:hover  {{ background:rgba(167,139,250,.08);border-color:rgba(167,139,250,.5);color:#a78bfa; }}
.abtn.risk:hover   {{ background:rgba(56,189,248,.08); border-color:rgba(56,189,248,.5); color:#38bdf8; }}
.abtn.fix          {{ color:#4ade80; border-color:rgba(74,222,128,.3); }}
.abtn.fix:hover    {{ background:rgba(74,222,128,.1); border-color:rgba(74,222,128,.6); }}
.abtn.fix:disabled {{ opacity:.35; cursor:not-allowed; }}

.pbox {{ background:var(--bg); border:1px solid var(--border); border-radius:7px; padding:9px 11px; margin-bottom:7px; }}
.pbox-ttl {{ font-size:9.5px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); margin-bottom:6px; }}
.path-node-row {{ display:flex; align-items:center; gap:5px; font-size:10.5px; margin-bottom:3px; }}
.pn-arrow {{ color:var(--muted); font-size:9px; }}
.pn-badge {{ font-size:8.5px; padding:1px 5px; border-radius:3px; font-weight:700; letter-spacing:.04em; flex-shrink:0; }}
.pn-badge.external {{ background:rgba(59,130,246,.2);  color:#60a5fa; }}
.pn-badge.pod      {{ background:rgba(56,189,248,.2);  color:#38bdf8; }}
.pn-badge.service  {{ background:rgba(167,139,250,.2); color:#a78bfa; }}
.pn-badge.sa       {{ background:rgba(251,191,36,.2);  color:#fbbf24; }}
.pn-badge.role     {{ background:rgba(249,115,22,.2);  color:#fb923c; }}
.pn-badge.secret   {{ background:rgba(239,68,68,.2);   color:#f87171; }}
.pn-badge.db       {{ background:rgba(234,179,8,.2);   color:#eab308; }}
.pn-badge.default  {{ background:rgba(100,116,139,.2); color:#94a3b8; }}
.pn-name {{ color:var(--text); }}

.mini-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:5px; margin-bottom:7px; }}
.mc {{ background:var(--bg); border:1px solid var(--border); border-radius:6px; padding:7px 9px; }}
.mc .mc-lbl {{ font-size:8.5px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); margin-bottom:2px; }}
.mc .mc-val {{ font-family:var(--fh); font-size:19px; font-weight:700; line-height:1; }}
.mc-red   {{ color:var(--high); }}
.mc-amber {{ color:var(--warn); }}
.mc-blue  {{ color:var(--accent); }}
.mc-green {{ color:var(--low); }}

.cycle-list {{ list-style:none; }}
.cycle-list li {{ font-size:10.5px; padding:5px 8px; border-radius:5px; margin-bottom:4px; background:rgba(167,139,250,.07); border:1px solid rgba(167,139,250,.18); color:#a78bfa; }}

.sbox {{ background:var(--bg); border:1px solid var(--border2); border-radius:7px; padding:9px 11px; font-size:11px; color:var(--muted); min-height:46px; margin-top:8px; line-height:1.55; }}
.sbox strong {{ color:var(--text); }}

/* GRAPH */
#cy-wrap {{
  flex:1; position:relative; overflow:hidden; background:var(--bg);
  background-image:
    radial-gradient(ellipse 60% 50% at 25% 40%, rgba(56,189,248,0.035) 0%, transparent 70%),
    radial-gradient(ellipse 50% 40% at 78% 65%, rgba(239,68,68,0.035) 0%, transparent 70%);
}}
#cy {{ width:100%; height:100%; }}
.cy-controls {{ position:absolute; bottom:14px; right:14px; display:flex; gap:6px; z-index:10; }}
.cy-btn {{ background:var(--surf); border:1px solid var(--border2); color:var(--muted); border-radius:6px; padding:7px 13px; font-family:var(--fm); font-size:12px; cursor:pointer; transition:all .15s; }}
.cy-btn:hover {{ background:var(--surf2); color:var(--text); }}
.mode-toggle {{ position:absolute; top:12px; right:14px; display:flex; gap:2px; z-index:10; background:var(--bg); border:1px solid var(--border2); border-radius:7px; padding:3px; }}
.mode-btn {{ font-family:var(--fm); font-size:11px; font-weight:500; padding:5px 13px; border-radius:5px; border:none; cursor:pointer; background:none; color:var(--muted); transition:all .18s; display:flex; align-items:center; gap:6px; }}
.mode-btn:hover {{ color:var(--text); }}
.mode-btn.active {{ background:var(--surf2); color:var(--accent); }}

/* RIGHT PANEL */
.rpanel {{ width:235px; flex-shrink:0; background:var(--surf); border-left:1px solid var(--border); display:flex; flex-direction:column; overflow-y:auto; }}
.rp {{ padding:12px 12px 9px; border-bottom:1px solid var(--border); }}
.rp:last-child {{ border-bottom:none; flex:1; }}
.rp-lbl {{ font-size:9.5px; font-weight:700; letter-spacing:.12em; text-transform:uppercase; color:var(--muted); margin-bottom:8px; }}
.nd-empty {{ font-size:11px; color:var(--muted); text-align:center; padding:10px 0; }}
.nd-row {{ display:flex; justify-content:space-between; align-items:center; margin-bottom:5px; font-size:11px; }}
.nd-k {{ color:var(--muted); }}
.nd-v {{ color:var(--text); font-weight:500; text-align:right; max-width:115px; word-break:break-word; }}
.rm-bg {{ height:10px; background:var(--surf3); border-radius:5px; overflow:hidden; margin-bottom:5px; }}
.rm-fill {{ height:100%; border-radius:5px; transition:width .6s cubic-bezier(.4,0,.2,1); }}
.rm-lbl {{ display:flex; justify-content:space-between; font-size:10.5px; }}
.leg-item {{ display:flex; align-items:center; gap:7px; margin-bottom:6px; font-size:10.5px; }}
.leg-dot  {{ width:11px; height:11px; border-radius:50%; flex-shrink:0; border:2px solid transparent; }}
.leg-sq   {{ width:14px; height:9px; border-radius:2px; flex-shrink:0; border:2px solid transparent; }}
.leg-line {{ width:22px; height:0; border-top-width:3px; border-top-style:solid; flex-shrink:0; }}

/* TOOLTIP */
#tt {{ position:fixed; pointer-events:none; background:var(--surf); border:1px solid var(--border2); border-radius:8px; padding:10px 13px; font-size:11.5px; z-index:999; display:none; box-shadow:0 8px 32px rgba(0,0,0,.7); min-width:175px; }}
#tt .tt-id {{ font-family:var(--fh); font-size:13px; font-weight:700; margin-bottom:5px; }}
#tt .tt-row {{ display:flex; justify-content:space-between; gap:10px; margin-top:3px; }}
#tt .tt-k {{ color:var(--muted); }}

::-webkit-scrollbar {{ width:4px; }}
::-webkit-scrollbar-thumb {{ background:var(--border2); border-radius:2px; }}
::-webkit-scrollbar-track {{ background:transparent; }}
</style>
</head>
<body>

<!-- TOPBAR -->
<header class="topbar">
  <div class="t-logo"><div class="t-blink"></div>KubePath</div>
  <div class="t-div"></div>
  <span class="t-tag">Attack Graph Analyzer</span>
  <span class="t-tag danger" id="path-tag">&#9888; ATTACK PATH ACTIVE</span>
  <div class="t-space"></div>
  <div class="t-chips">
    <div class="chip blue">{node_count} <span>nodes</span></div>
    <div class="chip blue">{edge_count} <span>edges</span></div>
    <div class="chip red">{path_hops} <span>hops</span></div>
    <div class="chip amber">{path_risk:.1f} <span>risk</span></div>
    <div class="chip {'red' if len(cycles)>0 else 'green'}">{len(cycles)} <span>{'cycle' if len(cycles)==1 else 'cycles'}</span></div>
  </div>
</header>

<div class="workspace">

<!-- LEFT SIDEBAR -->
<aside class="sidebar">
  <div class="sb">
    <div class="sb-lbl">Actions</div>
    <button class="abtn"        onclick="resetGraph()"><span class="ico">&#8635;</span> Reset Graph</button>
    <button class="abtn blast"  onclick="showBlastRadius()"><span class="ico">&#9762;</span> Blast Radius<span class="bdg" style="background:rgba(251,191,36,.2);color:#fbbf24">{len(blast_radius)}</span></button>
    <button class="abtn attack" onclick="showAttackPath()"><span class="ico">&#9876;</span> Attack Path<span class="bdg" style="background:rgba(239,68,68,.2);color:#f87171">{path_hops} hops</span></button>
    <button class="abtn cycle"  onclick="showCycles()"><span class="ico">&#128260;</span> Circular Perms<span class="bdg" style="background:rgba(167,139,250,.2);color:#a78bfa">{len(cycles)}</span></button>
    <button class="abtn risk"   onclick="showRiskScore()"><span class="ico">&#128202;</span> Risk Score</button>
  </div>

  <div class="sb">
    <div class="sb-lbl">Kill Chain &middot; {source_node} &rarr; {target_node}</div>
    <div class="pbox">
      <div class="pbox-ttl">Dijkstra Shortest Path</div>
      {path_rows_html}
    </div>
    <div class="mini-grid">
      <div class="mc"><div class="mc-lbl">Risk Score</div><div class="mc-val {mc_cls(path_risk)}">{path_risk:.0f}</div></div>
      <div class="mc"><div class="mc-lbl">Hops</div><div class="mc-val mc-amber">{path_hops}</div></div>
      <div class="mc"><div class="mc-lbl">Blast Zone</div><div class="mc-val mc-amber">{len(blast_radius)}</div></div>
      <div class="mc"><div class="mc-lbl">Status</div><div class="mc-val mc-red" id="status-val">VULN</div></div>
    </div>
  </div>

  <div class="sb">
    <div class="sb-lbl">Cycles &middot; {len(cycles)} detected</div>
    {cycle_html}
  </div>

  <div class="sb" style="flex:1">
    <div class="sb-lbl">Remediation</div>
    <div class="pbox">
      <div class="pbox-ttl">Critical Choke Point</div>
      <div style="font-size:12px;color:#f87171;font-weight:600">{critical_node}</div>
      <div style="font-size:10.5px;color:var(--muted);margin-top:3px">Removing breaks <strong style="color:var(--text)">{reduction}</strong> attack path(s).</div>
    </div>
    <button class="abtn fix" id="fix-btn" onclick="autoFix()"><span class="ico">&#10003;</span> Simulate Patch (Auto-Fix)</button>
    <div class="sbox" id="sbox"><strong>Status:</strong> System idle. Select an action above.</div>
  </div>
</aside>

<!-- GRAPH -->
<div id="cy-wrap">
  <div id="cy"></div>
  <!-- View mode toggle -->
  <div class="mode-toggle">
    <button class="mode-btn active" id="btn-force" onclick="setViewMode('force', this)">
      <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
        <circle cx="6" cy="6" r="2" fill="currentColor"/>
        <circle cx="1.5" cy="1.5" r="1.5" fill="currentColor" opacity=".5"/>
        <circle cx="10.5" cy="1.5" r="1.5" fill="currentColor" opacity=".5"/>
        <circle cx="1.5" cy="10.5" r="1.5" fill="currentColor" opacity=".5"/>
        <circle cx="10.5" cy="10.5" r="1.5" fill="currentColor" opacity=".5"/>
      </svg>
      Force
    </button>
    <button class="mode-btn" id="btn-cluster" onclick="setViewMode('cluster', this)">
      <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
        <circle cx="3.5" cy="3.5" r="3" stroke="currentColor" stroke-width="1.2"/>
        <circle cx="8.5" cy="3.5" r="3" stroke="currentColor" stroke-width="1.2"/>
        <circle cx="3.5" cy="8.5" r="3" stroke="currentColor" stroke-width="1.2"/>
        <circle cx="8.5" cy="8.5" r="3" stroke="currentColor" stroke-width="1.2"/>
      </svg>
      Clusters
    </button>
  </div>
  <div class="cy-controls">
    <button class="cy-btn" onclick="cy.fit(cy.nodes(),80)">&#8860; Fit</button>
    <button class="cy-btn" onclick="cy.zoom(cy.zoom()*1.3)">+</button>
    <button class="cy-btn" onclick="cy.zoom(cy.zoom()*0.77)">&minus;</button>
  </div>
</div>

<!-- RIGHT PANEL -->
<aside class="rpanel">
  <div class="rp">
    <div class="rp-lbl">Node Inspector</div>
    <div id="nd"><div class="nd-empty">Click any node to inspect</div></div>
  </div>
  <div class="rp">
    <div class="rp-lbl">Cluster Risk Meter</div>
    <div class="rm-bg"><div class="rm-fill" id="rm-fill" style="width:0%;background:var(--high)"></div></div>
    <div class="rm-lbl"><span id="rm-pct" style="color:var(--muted)">Run Risk Score</span><span id="rm-status"></span></div>
  </div>
  <div class="rp">
    <div class="rp-lbl">Node Types</div>
    <div class="leg-item"><div class="leg-dot" style="background:#1d3a6e;border-color:#3b82f6"></div> External / Internet</div>
    <div class="leg-item"><div class="leg-dot" style="background:#0c2a3a;border-color:#38bdf8"></div> Pod</div>
    <div class="leg-item"><div class="leg-sq" style="background:#1e1a3a;border-color:#a78bfa"></div> Service / API</div>
    <div class="leg-item"><div class="leg-dot" style="background:#2a200a;border-color:#fbbf24;border-radius:30%"></div> ServiceAccount</div>
    <div class="leg-item"><div class="leg-dot" style="background:#2a1200;border-color:#f97316;border-radius:20%"></div> Role</div>
    <div class="leg-item"><div class="leg-dot" style="background:#2d0a0a;border-color:#f87171"></div> Secret</div>
    <div class="leg-item"><div class="leg-dot" style="background:#2a1e00;border-color:#eab308;width:14px;height:14px"></div> Database &#128081;</div>
    <div style="height:6px"></div>
    <div class="rp-lbl">Edge Types</div>
    <div class="leg-item"><div class="leg-line" style="border-color:#ef4444"></div> Attack path</div>
    <div class="leg-item"><div class="leg-line" style="border-color:#fbbf24;border-top-style:dashed"></div> Blast radius</div>
    <div class="leg-item"><div class="leg-line" style="border-color:#a78bfa;border-top-style:dotted"></div> Cycle loop</div>
    <div class="leg-item"><div class="leg-line" style="border-color:#1e3a55"></div> Normal edge</div>
  </div>
  <div class="rp" style="flex:1">
    <div class="rp-lbl">Algorithms</div>
    <div style="font-size:10.5px;color:var(--muted);line-height:1.8">
      <div><span style="color:#fbbf24;font-weight:600">BFS</span> &mdash; 3-hop blast radius</div>
      <div><span style="color:#f87171;font-weight:600">Dijkstra</span> &mdash; Shortest attack path</div>
      <div><span style="color:#a78bfa;font-weight:600">DFS</span> &mdash; Cycle detection</div>
      <div><span style="color:#38bdf8;font-weight:600">Choke Point</span> &mdash; Critical node</div>
    </div>
  </div>
</aside>
</div>

<div id="tt"></div>


<script>
// ── DATA (injected by Python) ─────────────────────────────────────────────────
var ELEMENTS    = {json.dumps(elements)};
var ATTACK_PATH = {json.dumps(critical_path)};
var BLAST_NODES = {json.dumps(blast_radius)};
var CRITICAL_ID = {json.dumps(critical_node)};
var CYCLE_NODES = {json.dumps(all_cycle_node_ids)};
var CYCLE_STRS  = {json.dumps(cycle_strings)};
var PATH_RISK   = {path_risk};
var REDUCTION   = {reduction};
var isFixed     = false;

// ── TYPE COLORS (used in inspector & tooltip) ─────────────────────────────────
var TYPE_COLORS = {{
  external:'#3b82f6', pod:'#38bdf8', service:'#a78bfa',
  sa:'#fbbf24', role:'#f97316', secret:'#ef4444', db:'#eab308'
}};

// ── CYTOSCAPE INIT ────────────────────────────────────────────────────────────
var cy = cytoscape({{
  container: document.getElementById('cy'),
  elements:  ELEMENTS,
  style: [
    // Base node
    {{ selector: 'node', style: {{
      'label': 'data(label)', 'text-wrap': 'wrap', 'text-max-width': '100px',
      'text-valign': 'bottom', 'text-halign': 'center', 'text-margin-y': 9,
      'font-size': '11px', 'font-family': 'JetBrains Mono, monospace',
      'color': '#cbd5e1',
      'text-background-color': '#060b14', 'text-background-opacity': 0.80, 'text-background-padding': '3px',
      'width': 48, 'height': 48,
      'background-color': '#132035', 'border-width': 2.5, 'border-color': '#334155',
      'transition-property': 'background-color, border-color, border-width, width, height, opacity',
      'transition-duration': '200ms',
    }} }},
    // Type-specific shapes & colours
    {{ selector: 'node[type="external"]', style: {{ 'shape':'diamond','width':58,'height':58,'background-color':'#1d3a6e','border-color':'#3b82f6','border-width':3,'color':'#93c5fd','font-size':'11px' }} }},
    {{ selector: 'node[type="pod"]',      style: {{ 'shape':'ellipse','width':52,'height':52,'background-color':'#0c2a3a','border-color':'#38bdf8','border-width':3,'color':'#7dd3fc' }} }},
    {{ selector: 'node[type="service"]',  style: {{ 'shape':'round-rectangle','width':72,'height':42,'background-color':'#1e1a3a','border-color':'#a78bfa','border-width':2.5,'color':'#c4b5fd' }} }},
    {{ selector: 'node[type="sa"]',       style: {{ 'shape':'octagon','width':52,'height':52,'background-color':'#2a200a','border-color':'#fbbf24','border-width':2.5,'color':'#fde68a' }} }},
    {{ selector: 'node[type="role"]',     style: {{ 'shape':'pentagon','width':54,'height':54,'background-color':'#2a1200','border-color':'#f97316','border-width':2.5,'color':'#fdba74' }} }},
    {{ selector: 'node[type="secret"]',   style: {{ 'shape':'star','width':58,'height':58,'background-color':'#2d0a0a','border-color':'#ef4444','border-width':2.5,'color':'#fca5a5' }} }},
    {{ selector: 'node[type="db"]',       style: {{ 'shape':'barrel','width':70,'height':70,'background-color':'#2a1e00','border-color':'#eab308','border-width':4,'color':'#fde047','font-size':'12px' }} }},
    // Highlight classes
    {{ selector: 'node.attack',   style: {{ 'background-color':'#3d0a0a','border-color':'#ef4444','border-width':4,'color':'#fca5a5' }} }},
    {{ selector: 'node.blast',    style: {{ 'background-color':'#3d2800','border-color':'#fbbf24','border-width':3.5,'color':'#fde68a' }} }},
    {{ selector: 'node.critical', style: {{ 'background-color':'#4a0a0a','border-color':'#ef4444','border-width':5,'width':66,'height':66,'color':'#fca5a5' }} }},
    {{ selector: 'node.cycle-n',  style: {{ 'background-color':'#1e1040','border-color':'#a78bfa','border-width':3.5,'color':'#c4b5fd' }} }},
    {{ selector: 'node.patched',  style: {{ 'background-color':'#0a2214','border-color':'#4ade80','border-width':3,'color':'#86efac','opacity':0.55 }} }},
    {{ selector: 'node.dim',      style: {{ 'opacity':0.15 }} }},
    // Base edge
    {{ selector: 'edge', style: {{
      'label': 'data(weight)', 'color': '#64748b',
      'font-size': '11px', 'font-family': 'JetBrains Mono, monospace',
      'width': 2.5, 'line-color': '#1e3a55',
      'target-arrow-color': '#1e3a55', 'target-arrow-shape': 'triangle', 'arrow-scale': 1.3,
      'curve-style': 'bezier', 'control-point-step-size': 60,
      'text-background-color': '#060b14', 'text-background-opacity': 0.9, 'text-background-padding': '3px',
      'transition-property': 'line-color, width, opacity', 'transition-duration': '200ms',
    }} }},
    {{ selector: 'edge.attack-e', style: {{ 'line-color':'#ef4444','target-arrow-color':'#ef4444','width':4.5,'color':'#f87171','arrow-scale':1.5,'z-index':10 }} }},
    {{ selector: 'edge.blast-e',  style: {{ 'line-color':'#fbbf24','target-arrow-color':'#fbbf24','line-style':'dashed','line-dash-pattern':[7,4],'width':3,'color':'#fde68a' }} }},
    {{ selector: 'edge.cycle-e',  style: {{ 'line-color':'#a78bfa','target-arrow-color':'#a78bfa','line-style':'dotted','width':3,'color':'#c4b5fd' }} }},
    {{ selector: 'edge.dim',      style: {{ 'opacity':0.07 }} }},
  ],
  layout: {{ name:'preset' }},
  minZoom: 0.15, maxZoom: 4.0, wheelSensitivity: 0.25,
}});

// Store original positions for Force mode restore
var ORIG_POSITIONS = {{}};
cy.ready(function() {{
  cy.fit(cy.nodes(), 90);
  cy.nodes().forEach(function(n) {{
    ORIG_POSITIONS[n.id()] = {{ x: n.position('x'), y: n.position('y') }};
  }});
}});

// ── UTILS ─────────────────────────────────────────────────────────────────────
var tt = document.getElementById('tt');

function setStatus(html) {{
  document.getElementById('sbox').innerHTML = '<strong>Status:</strong> ' + html;
}}

function clearAll() {{
  cy.nodes().removeClass('attack blast critical cycle-n dim');
  cy.edges().removeClass('attack-e blast-e cycle-e dim');
  // Re-apply patched state persistently so it survives every clearAll call
  if (isFixed && CRITICAL_ID) {{
    cy.getElementById(CRITICAL_ID).addClass('patched');
    cy.getElementById(CRITICAL_ID).connectedEdges().addClass('dim');
  }}
}}

function resetGraph() {{
  // Remove dim from everything first, then clearAll re-applies patched state
  cy.nodes().removeClass('attack blast critical cycle-n dim');
  cy.edges().removeClass('attack-e blast-e cycle-e dim');
  clearAll();
  setStatus(isFixed
    ? 'Graph reset. Cluster is currently <span style="color:#4ade80;font-weight:600">SECURE</span>. '
      + '<strong style="color:#f87171">' + CRITICAL_ID + '</strong> remains patched.'
    : 'Graph reset to default vulnerable state.');
}}

// ── BLAST RADIUS ──────────────────────────────────────────────────────────────
function showBlastRadius() {{
  clearAll();
  // Exclude the patched node from blast highlighting
  var bset = new Set(BLAST_NODES.filter(function(id) {{ return !isFixed || id !== CRITICAL_ID; }}));
  cy.nodes().addClass('dim');
  cy.edges().addClass('dim');
  // Re-apply patched styling (clearAll does this, but addClass('dim') above overwrites it)
  if (isFixed && CRITICAL_ID) {{
    cy.getElementById(CRITICAL_ID).removeClass('dim').addClass('patched');
    cy.getElementById(CRITICAL_ID).connectedEdges().addClass('dim');
  }}
  bset.forEach(function(id) {{
    cy.getElementById(id).removeClass('dim').addClass('blast');
  }});
  cy.edges().forEach(function(e) {{
    var src = e.data('source'), tgt = e.data('target');
    if (isFixed && (src === CRITICAL_ID || tgt === CRITICAL_ID)) return;
    if (bset.has(src) && bset.has(tgt))
      e.removeClass('dim').addClass('blast-e');
  }});
  var visibleCount = bset.size;
  setStatus('BFS Blast Radius <span style="color:#fbbf24">(amber)</span> &mdash; '
    + visibleCount + ' nodes within 3 hops of compromised pod.'
    + (isFixed ? ' <span style="color:#4ade80">Patch reduced the danger zone.</span>' : ''));
}}

// ── ATTACK PATH ───────────────────────────────────────────────────────────────
function showAttackPath() {{
  clearAll();
  if (isFixed) {{
    setStatus('<span style="color:#4ade80;font-weight:600">&#10003; Kill chain BROKEN.</span> '
      + 'Patch on <strong>' + CRITICAL_ID + '</strong> eliminated the path to Crown Jewels.');
    return;
  }}
  cy.nodes().addClass('dim');
  cy.edges().addClass('dim');
  ATTACK_PATH.forEach(function(id) {{
    cy.getElementById(id).removeClass('dim').addClass('attack');
  }});
  if (CRITICAL_ID) cy.getElementById(CRITICAL_ID).addClass('critical');
  for (var i = 0; i < ATTACK_PATH.length - 1; i++) {{
    cy.edges('[source="' + ATTACK_PATH[i] + '"][target="' + ATTACK_PATH[i+1] + '"]')
      .removeClass('dim').addClass('attack-e');
  }}
  setStatus('Dijkstra Attack Path <span style="color:#f87171">(red)</span> &mdash; '
    + (ATTACK_PATH.length - 1) + ' hops, risk <strong>' + PATH_RISK.toFixed(1)
    + '</strong> [<span style="color:#ef4444">CRITICAL</span>]. Choke point: '
    + '<strong style="color:#f87171">' + CRITICAL_ID + '</strong>');
}}

// ── CYCLES ────────────────────────────────────────────────────────────────────
function showCycles() {{
  clearAll();
  if (CYCLE_NODES.length === 0) {{
    setStatus('<span style="color:#4ade80">&#10003; No circular permissions.</span> RBAC bindings are acyclic.');
    return;
  }}
  cy.nodes().addClass('dim');
  cy.edges().addClass('dim');
  // Keep patched node styled correctly even while dimming everything
  if (isFixed && CRITICAL_ID) {{
    cy.getElementById(CRITICAL_ID).removeClass('dim').addClass('patched');
    cy.getElementById(CRITICAL_ID).connectedEdges().addClass('dim');
  }}
  var cset = new Set(CYCLE_NODES);
  CYCLE_NODES.forEach(function(id) {{
    if (isFixed && id === CRITICAL_ID) return; // don't re-highlight patched node
    cy.getElementById(id).removeClass('dim').addClass('cycle-n');
  }});
  cy.edges().forEach(function(e) {{
    var src = e.data('source'), tgt = e.data('target');
    if (isFixed && (src === CRITICAL_ID || tgt === CRITICAL_ID)) return;
    if (cset.has(src) && cset.has(tgt))
      e.removeClass('dim').addClass('cycle-e');
  }});
  setStatus('DFS Cycles <span style="color:#a78bfa">(purple)</span>: ' + CYCLE_STRS.join(' | '));
}}

// ── RISK SCORE ────────────────────────────────────────────────────────────────
function showRiskScore() {{
  var pods=0, secrets=0, roles=0, sas=0, hasDB=false;
  cy.nodes(':visible').forEach(function(n) {{
    var t = n.data('type');
    if (t==='pod')    pods++;
    if (t==='secret') secrets++;
    if (t==='role')   roles++;
    if (t==='sa')     sas++;
    if (t==='db')     hasDB=true;
  }});
  var risk = pods*2 + secrets*5 + roles*4 + sas*3;
  if (hasDB) risk += 8;
  if (CYCLE_NODES.length > 0) risk += 10;
  var nv = cy.nodes(':visible').length;
  var ev = cy.edges(':visible').length;
  if (nv > 0) risk += Math.floor((ev/nv)*8);
  if (!isFixed) risk += 40;
  risk = Math.min(100, Math.floor(risk));

  var col, lbl;
  if      (risk >= 70) {{ col='#ef4444'; lbl='CRITICAL'; }}
  else if (risk >= 40) {{ col='#f97316'; lbl='HIGH'; }}
  else if (risk >= 20) {{ col='#fbbf24'; lbl='MEDIUM'; }}
  else                 {{ col='#4ade80'; lbl='LOW'; }}

  document.getElementById('rm-fill').style.width      = risk + '%';
  document.getElementById('rm-fill').style.background = col;
  document.getElementById('rm-pct').textContent       = risk + '% risk';
  document.getElementById('rm-pct').style.color       = col;
  document.getElementById('rm-status').textContent    = lbl;
  document.getElementById('rm-status').style.color    = col;

  setStatus('Risk: <span style="color:' + col + ';font-weight:600">' + risk + '% [' + lbl + ']</span>'
    + ' &nbsp;&middot;&nbsp; Pods:' + pods + '  Secrets:' + secrets + '  Roles:' + roles + '  SA:' + sas
    + (CYCLE_NODES.length ? ' &nbsp;&middot;&nbsp; &#9888; Cycles +10' : '')
    + (!isFixed ? ' &nbsp;&middot;&nbsp; <span style="color:#f87171">Kill chain +40</span>'
                : ' &nbsp;&middot;&nbsp; <span style="color:#4ade80">Patched</span>'));
}}

// ── AUTO FIX ──────────────────────────────────────────────────────────────────
function autoFix() {{
  if (isFixed) return;
  clearAll();
  var node = cy.getElementById(CRITICAL_ID);
  if (node.length) {{
    node.addClass('patched');
    node.connectedEdges().addClass('dim');
    isFixed = true;
    document.getElementById('status-val').textContent = 'SECURE';
    document.getElementById('status-val').className   = 'mc-val mc-green';
    document.getElementById('path-tag').innerHTML     = '&#10003; CLUSTER SECURE';
    document.getElementById('path-tag').className     = 't-tag ok';
    var btn = document.getElementById('fix-btn');
    btn.innerHTML = '<span class="ico">&#10003;</span> Patched! (' + CRITICAL_ID + ')';
    btn.disabled  = true;
    setStatus('<span style="color:#4ade80;font-weight:600">&#10003; Patch Applied.</span> '
      + 'Simulated removal of <strong>' + CRITICAL_ID + '</strong> &mdash; eliminates '
      + '<strong>' + REDUCTION + '</strong> attack path(s). '
      + 'Click Attack Path to verify kill chain is broken.');
    setTimeout(showRiskScore, 350);
  }}
}}

// ── NODE CLICK INSPECTOR ──────────────────────────────────────────────────────
cy.on('tap', 'node', function(evt) {{
  var n = evt.target, d = n.data();
  var col = TYPE_COLORS[d.type] || '#94a3b8';
  var html =
      '<div class="nd-row"><span class="nd-k">ID</span><span class="nd-v" style="color:' + col + ';font-weight:600">' + d.id + '</span></div>'
    + '<div class="nd-row"><span class="nd-k">Label</span><span class="nd-v">' + (d.label || '&mdash;') + '</span></div>'
    + '<div class="nd-row"><span class="nd-k">Type</span><span class="nd-v" style="color:' + col + '">' + (d.type || '?').toUpperCase() + '</span></div>'
    + '<div class="nd-row"><span class="nd-k">Edges</span><span class="nd-v">' + n.connectedEdges().length + '</span></div>';
  if (d.id === CRITICAL_ID)       html += '<div style="color:#ef4444;font-size:10px;margin-top:4px;font-weight:600">&#9888; CRITICAL NODE &mdash; Choke Point</div>';
  if (ATTACK_PATH.includes(d.id)) html += '<div style="color:#f87171;font-size:10px;margin-top:3px">&#10007; On attack path</div>';
  if (BLAST_NODES.includes(d.id)) html += '<div style="color:#fbbf24;font-size:10px;margin-top:3px">&#9762; In blast radius</div>';
  if (!ATTACK_PATH.includes(d.id) && !BLAST_NODES.includes(d.id))
                                   html += '<div style="color:#4ade80;font-size:10px;margin-top:3px">&#10003; Not in attack path</div>';
  document.getElementById('nd').innerHTML = html;
}});
cy.on('tap', function(evt) {{
  if (evt.target === cy)
    document.getElementById('nd').innerHTML = '<div class="nd-empty">Click any node to inspect</div>';
}});

// ── TOOLTIP ───────────────────────────────────────────────────────────────────
var ttTarget = null;

cy.on('mouseover', 'node', function(evt) {{
  ttTarget = evt.target;
  var d   = ttTarget.data();
  var col = TYPE_COLORS[d.type] || '#94a3b8';
  tt.innerHTML =
      '<div class="tt-id" style="color:' + col + '">' + (d.label || d.id) + '</div>'
    + '<div class="tt-row"><span class="tt-k">type</span><span style="color:' + col + '">' + (d.type || '?').toUpperCase() + '</span></div>'
    + '<div class="tt-row"><span class="tt-k">id</span><span>' + d.id + '</span></div>'
    + '<div class="tt-row"><span class="tt-k">edges</span><span>' + ttTarget.connectedEdges().length + '</span></div>'
    + (d.id === CRITICAL_ID ? '<div style="color:#ef4444;font-size:9.5px;margin-top:4px">&#9888; Critical choke point</div>' : '');
}});
cy.on('mouseover', 'edge', function(evt) {{
  ttTarget = evt.target;
  var d = ttTarget.data();
  tt.innerHTML =
      '<div class="tt-id">Edge</div>'
    + '<div class="tt-row"><span class="tt-k">from</span><span>' + d.source + '</span></div>'
    + '<div class="tt-row"><span class="tt-k">to</span><span>' + d.target + '</span></div>'
    + '<div class="tt-row"><span class="tt-k">weight</span><span style="color:#fbbf24">' + d.weight + '</span></div>';
}});
cy.on('mouseout', 'node edge', function() {{
  ttTarget = null;
  tt.style.display = 'none';
}});
var cyWrap = document.getElementById('cy-wrap');
cyWrap.addEventListener('mousemove', function(e) {{
  if (ttTarget) {{
    tt.style.display = 'block';
    tt.style.left = (e.clientX + 18) + 'px';
    tt.style.top  = (e.clientY - 12) + 'px';
  }} else {{
    tt.style.display = 'none';
  }}
}});
cyWrap.addEventListener('mouseleave', function() {{
  ttTarget = null;
  tt.style.display = 'none';
}});

// ── VIEW MODE: FORCE vs CLUSTER ───────────────────────────────────────────────
var currentMode  = 'force';
var TYPE_ORDER = ['external','pod','service','sa','role','secret','db'];

var TYPE_COL = {{
  external:'#3b82f6', pod:'#38bdf8', service:'#a78bfa',
  sa:'#fbbf24', role:'#f97316', secret:'#ef4444', db:'#eab308'
}};

function setViewMode(mode, el) {{
  if (mode === currentMode) return;
  currentMode = mode;
  document.querySelectorAll('.mode-btn').forEach(function(b) {{ b.classList.remove('active'); }});
  el.classList.add('active');
  clearAll();
  if (mode === 'force') {{
    removeBubbleParents();
    applyForceLayout();
  }} else {{
    applyClusterLayout();
  }}
}}

function applyForceLayout() {{
  cy.nodes('[!isBubble]').forEach(function(n) {{
    var orig = ORIG_POSITIONS[n.id()];
    if (orig) n.position({{ x: orig.x, y: orig.y }});
  }});
  cy.fit(cy.nodes('[!isBubble]'), 90);
  setStatus('View: <span style="color:var(--accent)">Force Layout</span> &mdash; original graph positions.');
}}

function removeBubbleParents() {{
  // Detach children first, then remove parents
  cy.nodes('[?isBubble]').forEach(function(p) {{
    p.children().move({{ parent: null }});
  }});
  cy.remove('[?isBubble]');
}}

function applyClusterLayout() {{
  removeBubbleParents();

  var groups = {{}};
  TYPE_ORDER.forEach(function(t) {{ groups[t] = []; }});
  cy.nodes('[!isBubble]').forEach(function(n) {{
    var t = n.data('type') || 'unknown';
    if (!groups[t]) groups[t] = [];
    groups[t].push(n);
  }});

  var activeTypes = TYPE_ORDER.filter(function(t) {{ return groups[t] && groups[t].length > 0; }});
  var numTypes    = activeTypes.length;
  var cols        = Math.min(numTypes, 4);

  // Spacing between bubble centres in Cytoscape graph units.
  // Each bubble needs room for ring + node diameter + padding.
  // Worst case: 6 nodes, footprint 60 each -> ring ~120 -> diameter ~320
  var BUBBLE_SPACING = 350;

  activeTypes.forEach(function(type, idx) {{
    var col_i   = idx % cols;
    var row_i   = Math.floor(idx / cols);
    var cx      = col_i * BUBBLE_SPACING;
    var cy_     = row_i * BUBBLE_SPACING;
    var members = groups[type];
    var count   = members.length;

    // Ring radius: space nodes so they never touch each other
    // Each node has a visual diameter of ~60 units; want 20-unit gap between edges
    var footprint = 80;  // node diameter + gap
    var ringR;
    if (count <= 1) {{
      ringR = 0;
    }} else {{
      ringR = Math.max((count * footprint) / (2 * Math.PI), footprint * 0.8);
    }}

    // Add compound parent bubble
    var parentId = '__bubble__' + type;
    cy.add({{
      group: 'nodes',
      data:  {{ id: parentId, label: type.toUpperCase() + ' (' + count + ')',
               isBubble: true, bubbleType: type }}
    }});

    // Position members in a ring, then assign to parent
    members.forEach(function(n, i) {{
      var angle = count <= 1 ? 0 : (2 * Math.PI / count) * i - Math.PI / 2;
      n.position({{
        x: cx + ringR * Math.cos(angle),
        y: cy_ + ringR * Math.sin(angle)
      }});
      n.move({{ parent: parentId }});
    }});
  }});

  // Style the compound parent nodes as bubbles
  var TYPE_COL_REF = TYPE_COL;
  cy.nodes('[?isBubble]').forEach(function(n) {{
    var type  = n.data('bubbleType');
    var color = TYPE_COL_REF[type] || '#64748b';
    n.style({{
      'shape':               'ellipse',
      'background-color':    color,
      'background-opacity':  0.06,
      'border-width':        2,
      'border-color':        color,
      'border-opacity':      0.60,
      'border-style':        'dashed',
      'label':               n.data('label'),
      'color':               color,
      'font-size':           '12px',
      'font-family':         'JetBrains Mono, monospace',
      'text-valign':         'top',
      'text-halign':         'center',
      'text-margin-y':       -8,
      'text-background-color':   '#060b14',
      'text-background-opacity': 0.85,
      'text-background-padding': '4px',
      'padding':             '45px',
      'compound-sizing-wrt-labels': 'exclude',
    }});
  }});

  cy.fit(cy.elements(), 55);
  setStatus('View: <span style="color:var(--accent)">Cluster Layout</span> &mdash; nodes grouped by type.');
}}

// ── AUTO SHOW ATTACK PATH ON LOAD ─────────────────────────────────────────────
window.addEventListener('load', function() {{ setTimeout(showAttackPath, 600); }});
</script>
</body>
</html>"""

        with open(output_path, "w") as f:
            f.write(html_content)
        return output_path