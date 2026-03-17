import networkx as nx
import json

class KubeGraphEngine:
    def __init__(self, json_filepath):
        self.G = nx.DiGraph()
        self.public_nodes = []
        self.crown_jewels = []
        self._load_and_build(json_filepath)

    def _load_and_build(self, filepath):
        with open(filepath, 'r') as f:
            data = json.load(f)

        for node in data['nodes']:
            node_id = node['id']
            node_type = node.get('type', 'unknown')
            node_label = node.get('data', {}).get('label', node_id)
            node_pos = node.get('position', {'x': 0, 'y': 0})
            
            is_public = (node_type == 'external' or node_id == 'internet')
            is_crown_jewel = (node_type == 'db')

            self.G.add_node(
                node_id, 
                type=node_type, 
                label=node_label, 
                is_public=is_public, 
                is_crown_jewel=is_crown_jewel,
                position=node_pos # Saving the position!
            )
            
            if is_public:
                self.public_nodes.append(node_id)
            if is_crown_jewel:
                self.crown_jewels.append(node_id)

        for edge in data['edges']:
            source = edge['source']
            target = edge['target']
            weight = edge.get('weight', 1)
            if source in self.G.nodes and target in self.G.nodes:
                self.G.add_edge(source, target, weight=weight)

    def get_blast_radius(self, source_node, hops=3):
        if source_node not in self.G: return []
        return list(nx.ego_graph(self.G, source_node, radius=hops).nodes())

    def get_shortest_path(self, source, target):
        try:
            path = nx.shortest_path(self.G, source=source, target=target, weight='weight')
            path_risk = sum([self.G[path[i]][path[i+1]]['weight'] for i in range(len(path)-1)])
            return path, path_risk
        except nx.NetworkXNoPath:
            return None, 0

    def get_cycles(self):
        """
        Algorithm 3: Circular Permission Detection (Explicit Depth-First Search)
        Uses a recursive DFS with a recursion stack to detect back-edges (cycles).
        """
        visited = set()       # Tracks fully processed nodes
        rec_stack = set()     # Tracks nodes currently in the DFS path
        path = []             # Tracks the actual sequence of the current path
        cycles = []
        seen_cycles = set()   # Used to prevent logging the exact same loop twice

        def dfs(node):
            # Mark the current node as visited and add to recursion stack
            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            for neighbor in self.G.neighbors(node):
                if neighbor not in visited:
                    dfs(neighbor)
                elif neighbor in rec_stack:
                    # A back-edge is found! This means we hit a node already in our current path
                    cycle_start = path.index(neighbor)
                    cycle = path[cycle_start:]
                    
                    if len(cycle) > 1: # Ignore single-node self-loops
                        # Create a sorted signature to avoid duplicate reports (A->B is same loop as B->A)
                        canonical = tuple(sorted(cycle))
                        if canonical not in seen_cycles:
                            seen_cycles.add(canonical)
                            cycles.append(cycle)

            # Remove the node from the recursion stack before backtracking
            rec_stack.remove(node)
            path.pop()

        # Run DFS from every node to ensure disconnected subgraphs are checked
        for node in self.G.nodes():
            if node not in visited:
                dfs(node)

        return cycles

    def get_critical_node(self, source, target):
        try:
            baseline_paths = list(nx.all_simple_paths(self.G, source, target))
            baseline_count = len(baseline_paths)
        except nx.NetworkXNoPath: return None, 0
            
        if baseline_count == 0: return None, 0

        critical_node, max_reduction = None, 0
        nodes_in_paths = set(node for path in baseline_paths for node in path)
        nodes_in_paths.discard(source)
        nodes_in_paths.discard(target)

        for node in nodes_in_paths:
            temp_edges = list(self.G.in_edges(node, data=True)) + list(self.G.out_edges(node, data=True))
            node_data = self.G.nodes[node]
            self.G.remove_node(node)
            
            new_paths = list(nx.all_simple_paths(self.G, source, target))
            reduction = baseline_count - len(new_paths)
            if reduction > max_reduction:
                max_reduction = reduction
                critical_node = node
                
            self.G.add_node(node, **node_data)
            self.G.add_edges_from([(u, v, d) for u, v, d in temp_edges])

        return critical_node, max_reduction

    def export_to_json(self, output_filepath):
        """Exports the fully mapped graph to a JSON file (Requirement 2.1)"""
        import os
        os.makedirs(os.path.dirname(output_filepath), exist_ok=True)
        data = nx.node_link_data(self.G)
        with open(output_filepath, 'w') as f:
            json.dump(data, f, indent=4)
        return output_filepath