"""
KubePath — src/graph_engine.py
================================
Task 2: Graph Construction

Nodes store: id, type, label, namespace, risk_score, cve, cvss, cve_desc, labels
Edges store: source, target, relationship, weight (exploitability score)
"""

import networkx as nx
import json
import os


class KubeGraphEngine:
    def __init__(self, json_filepath: str):
        self.G            = nx.DiGraph()
        self.public_nodes: list = []
        self.crown_jewels: list = []
        self._load_and_build(json_filepath)

    def _load_and_build(self, filepath: str):
        with open(filepath, "r") as f:
            data = json.load(f)

        for node in data["nodes"]:
            node_id    = node["id"]
            node_type  = node.get("type", "unknown")
            node_label = (
                node.get("data", {}).get("label")
                or node.get("label")
                or node_id
            )
            node_pos   = node.get("position", {"x": 0, "y": 0})
            is_public      = (node_type == "external" or node_id == "internet")
            is_crown_jewel = (node_type == "db")

            self.G.add_node(
                node_id,
                type           = node_type,
                label          = node_label,
                namespace      = node.get("namespace", "default"),
                risk_score     = node.get("risk_score", 5.0),
                cve            = node.get("cve", ""),
                cvss           = node.get("cvss", 0.0),
                cve_desc       = node.get("cve_desc", ""),
                labels         = node.get("labels", {}),
                is_public      = is_public,
                is_crown_jewel = is_crown_jewel,
                position       = node_pos,
            )

            if is_public:      self.public_nodes.append(node_id)
            if is_crown_jewel: self.crown_jewels.append(node_id)

        for edge in data["edges"]:
            source = edge["source"]
            target = edge["target"]
            weight = edge.get("weight", 1)
            rel    = edge.get("relationship", "connected_to")
            if source in self.G.nodes and target in self.G.nodes:
                self.G.add_edge(source, target, weight=weight, relationship=rel)

        print(f"✅  Graph built → {self.G.number_of_nodes()} nodes, "
              f"{self.G.number_of_edges()} edges")

    # Algorithm 1 — BFS Blast Radius
    def get_blast_radius(self, source_node: str, hops: int = 3) -> list:
        if source_node not in self.G:
            return []
        return list(nx.ego_graph(self.G, source_node, radius=hops).nodes())

    # Algorithm 2 — Dijkstra Shortest Path
    def get_shortest_path(self, source: str, target: str) -> tuple:
        try:
            path = nx.shortest_path(self.G, source=source, target=target, weight="weight")
            path_risk = sum(
                self.G[path[i]][path[i + 1]]["weight"] for i in range(len(path) - 1)
            )
            return path, path_risk
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None, 0

    # Algorithm 3 — DFS Cycle Detection
    def get_cycles(self) -> list:
        visited = set(); rec_stack = set(); path = []
        cycles = []; seen_cycles = set()

        def dfs(node):
            visited.add(node); rec_stack.add(node); path.append(node)
            for neighbor in self.G.neighbors(node):
                if neighbor not in visited:
                    dfs(neighbor)
                elif neighbor in rec_stack:
                    cycle_start = path.index(neighbor)
                    cycle = path[cycle_start:]
                    if len(cycle) > 1:
                        canonical = tuple(sorted(cycle))
                        if canonical not in seen_cycles:
                            seen_cycles.add(canonical)
                            cycles.append(list(cycle))
            rec_stack.remove(node); path.pop()

        for node in self.G.nodes():
            if node not in visited:
                dfs(node)
        return cycles

    # Task 4 — Critical Node Identification
    def get_critical_node(self, source: str, target: str) -> tuple:
        try:
            baseline_paths = list(nx.all_simple_paths(self.G, source, target))
            baseline_count = len(baseline_paths)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None, 0

        if baseline_count == 0:
            return None, 0

        critical_node, max_reduction = None, 0
        nodes_in_paths = set(n for p in baseline_paths for n in p)
        nodes_in_paths.discard(source); nodes_in_paths.discard(target)

        for node in nodes_in_paths:
            in_edges  = list(self.G.in_edges(node, data=True))
            out_edges = list(self.G.out_edges(node, data=True))
            node_data = dict(self.G.nodes[node])
            self.G.remove_node(node)
            try:
                new_paths = list(nx.all_simple_paths(self.G, source, target))
                reduction = baseline_count - len(new_paths)
            except Exception:
                reduction = baseline_count
            if reduction > max_reduction:
                max_reduction = reduction; critical_node = node
            self.G.add_node(node, **node_data)
            self.G.add_edges_from([(u, v, d) for u, v, d in in_edges])
            self.G.add_edges_from([(u, v, d) for u, v, d in out_edges])

        return critical_node, max_reduction

    def export_to_json(self, output_filepath: str) -> str:
        os.makedirs(os.path.dirname(output_filepath) or ".", exist_ok=True)
        data = nx.node_link_data(self.G)
        with open(output_filepath, "w") as f:
            json.dump(data, f, indent=4)
        print(f"✅  Graph exported → {output_filepath}")
        return output_filepath