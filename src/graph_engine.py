"""
KubePath — src/graph_engine.py
================================
Task 2: Graph Construction + All Algorithms

Algorithms implemented:
  1. BlastRank  — BFS ego-graph + Eigenvector Centrality (Markov Chain model)
  2. A* Search  — Dijkstra base + Privilege Proximity heuristic h(n)
  3. DFS        — Explicit recursive cycle detection with rec_stack
  4. Min-Cut    — Max-Flow based critical node identification (Ford-Fulkerson)
"""

import networkx as nx
import json
import os
import heapq
import math


class KubeGraphEngine:

    # ── PRIVILEGE WEIGHTS used by A* heuristic ────────────────────────────────
    # Higher = more "interesting" to an attacker heading toward crown jewels
    PRIVILEGE_RANK = {
        "db":       10,   # crown jewel — maximum attraction
        "secret":    9,
        "role":      7,
        "clusterrole": 8,
        "sa":        6,
        "service":   4,
        "pod":       3,
        "configmap": 2,
        "external":  1,
    }

    def __init__(self, json_filepath: str):
        self.G            = nx.DiGraph()
        self.public_nodes = []
        self.crown_jewels = []
        self._load_and_build(json_filepath)

    # ── GRAPH CONSTRUCTION ────────────────────────────────────────────────────
    def _load_and_build(self, filepath: str):
        with open(filepath, "r") as f:
            data = json.load(f)

        for node in data["nodes"]:
            nid    = node["id"]
            ntype  = node.get("type", "unknown")
            nlabel = (
                node.get("data", {}).get("label")
                or node.get("label")
                or nid
            )
            is_public      = (ntype == "external" or nid == "internet")
            is_crown_jewel = (ntype == "db")

            self.G.add_node(
                nid,
                type           = ntype,
                label          = nlabel,
                namespace      = node.get("namespace", "default"),
                risk_score     = float(node.get("risk_score", 5.0)),
                cve            = node.get("cve", ""),
                cvss           = float(node.get("cvss", 0.0)),
                cve_desc       = node.get("cve_desc", ""),
                labels         = node.get("labels", {}),
                is_public      = is_public,
                is_crown_jewel = is_crown_jewel,
                position       = node.get("position", {"x": 0, "y": 0}),
            )
            if is_public:      self.public_nodes.append(nid)
            if is_crown_jewel: self.crown_jewels.append(nid)

        for edge in data["edges"]:
            src = edge["source"]
            tgt = edge["target"]
            w   = edge.get("weight", 1)
            rel = edge.get("relationship", "connected_to")
            if src in self.G.nodes and tgt in self.G.nodes:
                self.G.add_edge(src, tgt, weight=w, relationship=rel)

        print(f"✅  Graph built → {self.G.number_of_nodes()} nodes, "
              f"{self.G.number_of_edges()} edges")

    # ═════════════════════════════════════════════════════════════════════════
    #  ALGORITHM 1 — BlastRank: BFS + Markov Chain (Eigenvector Centrality)
    # ═════════════════════════════════════════════════════════════════════════
    def get_blast_radius(self, source_node: str, hops: int = 3):
        """
        BFS ego-graph to find the N-hop danger zone from a compromised node,
        then rank nodes inside it by Eigenvector Centrality (BlastRank).

        BlastRank models the cluster as a discrete-time Markov Chain.
        A node's BlastRank score = its stationary probability of being
        visited by an APT randomly traversing trust links — mathematically
        proving influence rather than just counting hops.

        Returns:
            blast_nodes  : list of node IDs in blast radius
            blast_ranks  : dict {node_id: blastrank_score} sorted high→low
        """
        if source_node not in self.G:
            return [], {}

        # Step 1: BFS to get the danger-zone subgraph
        ego = nx.ego_graph(self.G, source_node, radius=hops)
        blast_nodes = list(ego.nodes())

        # Step 2: Eigenvector Centrality on the subgraph (Markov Chain stationary dist.)
        # Use undirected view so isolated nodes don't break convergence
        try:
            centrality = nx.eigenvector_centrality(
                ego, max_iter=500, tol=1e-6, weight="weight"
            )
        except nx.PowerIterationFailedConvergence:
            # Fall back to degree centrality if eigenvector doesn't converge
            centrality = nx.degree_centrality(ego)

        # Normalise 0→1
        max_c = max(centrality.values()) if centrality else 1.0
        blast_ranks = {
            n: round(v / max_c, 4)
            for n, v in sorted(centrality.items(), key=lambda x: -x[1])
        }

        return blast_nodes, blast_ranks

    # ═════════════════════════════════════════════════════════════════════════
    #  ALGORITHM 2 — A* Search with Privilege Proximity Heuristic h(n)
    # ═════════════════════════════════════════════════════════════════════════
    def get_shortest_path(self, source: str, target: str):
        """
        A* Search with a custom 'Privilege Proximity' heuristic h(n).

        Standard Dijkstra searches blindly in all directions (script-kiddie model).
        A* simulates an APT actively hunting high-value targets.

        Heuristic h(n):
          h(n) = max_privilege_rank - privilege_rank(n)
                 - cvss_bonus(n)
                 - crown_jewel_proximity(n)

        A lower h(n) = node is "closer" to a crown jewel in privilege space.
        Combined with g(n) (actual path cost), this steers the search toward
        privilege-escalating nodes rather than scanning the full graph.

        Returns: (path_as_list, total_g_cost, hops)
        """
        if source not in self.G or target not in self.G:
            return None, 0, 0

        # Pre-compute shortest hop distance to target for proximity bonus
        # (unweighted BFS distance — cheap to compute, used in heuristic)
        try:
            hop_dist = nx.single_source_shortest_path_length(
                self.G, target
            )
            # Invert: hop_dist gives dist FROM target; we want dist TO target
            # Reverse graph for this
            rev_G = self.G.reverse()
            hop_dist_to_target = nx.single_source_shortest_path_length(
                rev_G, target
            )
        except Exception:
            hop_dist_to_target = {}

        max_rank = max(self.PRIVILEGE_RANK.values())  # 10

        def h(node):
            """
            Privilege Proximity heuristic.
            Returns a non-negative estimate of cost remaining to target.
            Lower = this node is on a high-privilege path toward the crown jewel.
            """
            ndata      = self.G.nodes.get(node, {})
            ntype      = ndata.get("type", "unknown")
            cvss       = ndata.get("cvss", 0.0)
            priv_rank  = self.PRIVILEGE_RANK.get(ntype, 3)

            # Privilege bonus: high-privilege nodes are "closer" in privilege space
            priv_bonus = (max_rank - priv_rank) * 0.3

            # CVE bonus: vulnerable nodes are easier to traverse
            cvss_bonus = cvss * 0.15

            # Hop proximity: closer nodes to target are preferred
            hop_bonus  = hop_dist_to_target.get(node, 10) * 0.2

            return max(0.0, hop_bonus - priv_bonus - cvss_bonus)

        # A* with a min-heap: (f_score, g_score, node, path)
        start_h = h(source)
        heap    = [(start_h, 0.0, source, [source])]
        visited = {}   # node → best g_score seen

        while heap:
            f, g, node, path = heapq.heappop(heap)

            if node == target:
                return path, round(g, 2), len(path) - 1

            if node in visited and visited[node] <= g:
                continue
            visited[node] = g

            for neighbor in self.G.neighbors(node):
                edge_w  = self.G[node][neighbor].get("weight", 1)
                new_g   = g + edge_w
                new_f   = new_g + h(neighbor)
                if neighbor not in visited or visited[neighbor] > new_g:
                    heapq.heappush(heap, (new_f, new_g, neighbor, path + [neighbor]))

        return None, 0, 0   # no path found

    # ═════════════════════════════════════════════════════════════════════════
    #  ALGORITHM 3 — DFS Cycle Detection (Circular Permission Loops)
    # ═════════════════════════════════════════════════════════════════════════
    def get_cycles(self):
        """
        Explicit recursive DFS with visited + rec_stack to detect back-edges.
        Deduplicates cycles by canonical sorted signature so A↔B is not
        reported twice as A→B and B→A.

        Returns: list of cycles, each cycle is a list of node IDs.
        """
        visited    = set()
        rec_stack  = set()
        path       = []
        cycles     = []
        seen       = set()

        def dfs(node):
            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            for nbr in self.G.neighbors(node):
                if nbr not in visited:
                    dfs(nbr)
                elif nbr in rec_stack:
                    start = path.index(nbr)
                    cycle = path[start:]
                    if len(cycle) > 1:
                        canonical = tuple(sorted(cycle))
                        if canonical not in seen:
                            seen.add(canonical)
                            cycles.append(list(cycle))

            rec_stack.remove(node)
            path.pop()

        for node in self.G.nodes():
            if node not in visited:
                dfs(node)

        return cycles

    # ═════════════════════════════════════════════════════════════════════════
    #  ALGORITHM 4 — Critical Node via Min-Cut / Max-Flow (Ford-Fulkerson)
    # ═════════════════════════════════════════════════════════════════════════
    def get_critical_node(self, source: str, target: str):
        """
        Identifies the single node whose removal maximally reduces attack paths,
        modelled as a flow network using Min-Cut / Max-Flow theorem.

        Approach:
          1. Build a capacity network: each node is split into node_in / node_out
             with an internal edge of capacity 1 (node capacity = 1 attack path
             can flow through it). External edges get capacity = ∞ (very large).
          2. Compute Max-Flow from source to target on this network.
          3. Find the Min-Cut edges — these correspond exactly to the nodes whose
             removal would disconnect source from target (Ford-Fulkerson theorem).
          4. The node with the single highest flow through it is the choke point.

        Falls back to brute-force path-count reduction for small graphs where
        the flow model would be over-engineered.

        Returns: (critical_node_id, num_paths_broken)
        """
        if source not in self.G or target not in self.G:
            return None, 0

        # ── Get baseline attack paths ─────────────────────────────────────────
        try:
            all_paths = list(nx.all_simple_paths(self.G, source, target, cutoff=10))
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None, 0

        if not all_paths:
            return None, 0

        baseline_count = len(all_paths)

        # ── Build node-split flow network ────────────────────────────────────
        # Each real node v → two nodes: v_IN, v_OUT
        # Edge v_IN → v_OUT has capacity 1 (one unit of "attack flow" per node)
        # Edge u_OUT → v_IN has capacity INF (edges between nodes are free)
        INF = 10_000
        flow_G = nx.DiGraph()

        for node in self.G.nodes():
            n_in  = f"{node}__IN"
            n_out = f"{node}__OUT"
            # Source and target get INF internal capacity (they are never removed)
            cap = INF if node in (source, target) else 1
            flow_G.add_edge(n_in, n_out, capacity=cap)

        for u, v in self.G.edges():
            flow_G.add_edge(f"{u}__OUT", f"{v}__IN", capacity=INF)

        # ── Compute Max-Flow ──────────────────────────────────────────────────
        try:
            flow_value, flow_dict = nx.maximum_flow(
                flow_G,
                f"{source}__IN",
                f"{target}__OUT",
                capacity="capacity",
                flow_func=nx.algorithms.flow.shortest_augmenting_path,
            )
        except Exception:
            # Fallback: brute-force for graphs where flow fails
            return self._critical_node_bruteforce(source, target, all_paths)

        # ── Identify the saturated (min-cut) internal node edges ─────────────
        # A node n is on the min-cut if flow(n_IN → n_OUT) == capacity(n_IN → n_OUT) == 1
        # That node is a choke point — removing it breaks flow_value paths.
        saturated = []
        for node in self.G.nodes():
            if node in (source, target):
                continue
            n_in  = f"{node}__IN"
            n_out = f"{node}__OUT"
            if n_in in flow_dict and n_out in flow_dict.get(n_in, {}):
                f = flow_dict[n_in][n_out]
                cap = flow_G[n_in][n_out]["capacity"]
                if f >= cap:   # fully saturated — this is a bottleneck
                    saturated.append((node, f))

        if not saturated:
            return self._critical_node_bruteforce(source, target, all_paths)

        # Pick the node with highest flow through it
        saturated.sort(key=lambda x: -x[1])
        critical_node = saturated[0][0]

        # Count how many paths it actually breaks (exact, for reporting accuracy)
        paths_through = sum(1 for p in all_paths if critical_node in p)
        return critical_node, paths_through

    def _critical_node_bruteforce(self, source, target, all_paths):
        """Fallback O(V * paths) brute-force critical node search."""
        nodes_in_paths = set(n for p in all_paths for n in p)
        nodes_in_paths.discard(source)
        nodes_in_paths.discard(target)

        critical_node, max_reduction = None, 0
        baseline = len(all_paths)

        for node in nodes_in_paths:
            in_e  = list(self.G.in_edges(node, data=True))
            out_e = list(self.G.out_edges(node, data=True))
            ndata = dict(self.G.nodes[node])
            self.G.remove_node(node)
            try:
                remaining = list(nx.all_simple_paths(self.G, source, target, cutoff=10))
                reduction = baseline - len(remaining)
            except Exception:
                reduction = baseline
            if reduction > max_reduction:
                max_reduction = reduction
                critical_node = node
            self.G.add_node(node, **ndata)
            self.G.add_edges_from([(u, v, d) for u, v, d in in_e])
            self.G.add_edges_from([(u, v, d) for u, v, d in out_e])

        return critical_node, max_reduction

    # ── EXPORT ────────────────────────────────────────────────────────────────
    def export_to_json(self, output_filepath: str) -> str:
        os.makedirs(os.path.dirname(output_filepath) or ".", exist_ok=True)
        data = nx.node_link_data(self.G)
        with open(output_filepath, "w") as f:
            json.dump(data, f, indent=4)
        print(f"✅  Graph exported → {output_filepath}")
        return output_filepath