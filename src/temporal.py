"""
KubePath — src/temporal.py
============================
Bonus 3: Temporal Analysis

Stores graph snapshots over time and diffs consecutive scans to alert
when new attack paths appear or disappear.

Usage:
    from src.temporal import TemporalAnalyzer

    analyzer = TemporalAnalyzer()
    analyzer.save_snapshot(engine)                  # save current graph state
    report = analyzer.diff_latest()                 # diff last two snapshots
    analyzer.print_diff_report(report)

Standalone:
    python -m src.temporal                          # diff latest two snapshots
    python -m src.temporal --list                   # list all stored snapshots
    python -m src.temporal --clear                  # delete all snapshots
"""

import os
import json
import hashlib
import argparse
from datetime import datetime

# KAN predictor — try multiple import paths to handle
# both `python main.py` (src.kan_predictor) and
# `python -m src.temporal` (.kan_predictor) contexts.
import numpy as _np_check   # numpy must exist before KAN is useful
_KAN_AVAILABLE = False
_KANPredictor  = None
try:
    from src.kan_predictor import KANPredictor as _KANPredictor
    _KAN_AVAILABLE = True
except ImportError:
    try:
        from kan_predictor import KANPredictor as _KANPredictor
        _KAN_AVAILABLE = True
    except ImportError:
        try:
            import importlib, os, sys
            _this_dir = os.path.dirname(os.path.abspath(__file__))
            if _this_dir not in sys.path:
                sys.path.insert(0, _this_dir)
            _mod = importlib.import_module("kan_predictor")
            _KANPredictor = _mod.KANPredictor
            _KAN_AVAILABLE = True
        except Exception:
            pass


SNAPSHOT_DIR = "data/snapshots"


class TemporalAnalyzer:
    """
    Stores serialised graph snapshots and computes structural diffs
    to detect new attack paths between consecutive cluster scans.
    """

    def __init__(self, snapshot_dir: str = SNAPSHOT_DIR,
                 source: str = "internet", target: str = "postgres"):
        self.snapshot_dir = snapshot_dir
        self.source       = source
        self.target       = target
        os.makedirs(snapshot_dir, exist_ok=True)

    # ── SNAPSHOT STORAGE ─────────────────────────────────────────────────────
    def save_snapshot(self, engine) -> str:
        """
        Serialise the current graph state and write it to the snapshot store.

        Args:
            engine: KubeGraphEngine instance (must have .G, .get_shortest_path,
                    .get_cycles, .get_critical_node)

        Returns:
            Path of the saved snapshot file.
        """
        import networkx as nx

        G = engine.G

        # Collect all simple paths (capped at 50 to avoid combinatorial explosion)
        try:
            import itertools
            all_paths = list(itertools.islice(
                nx.all_simple_paths(G, self.source, self.target, cutoff=8), 50
            ))
        except (nx.NetworkXNoPath, nx.NodeNotFound, nx.NetworkXError):
            all_paths = []

        # Represent each path as a stable string signature
        path_sigs = sorted(["→".join(p) for p in all_paths])

        shortest_path, path_risk, _ = engine.get_shortest_path(self.source, self.target)
        cycles      = engine.get_cycles()
        crit_node, reduction = engine.get_critical_node(self.source, self.target)

        snapshot = {
            "timestamp":    datetime.utcnow().isoformat() + "Z",
            "source":       self.source,
            "target":       self.target,
            "node_count":   G.number_of_nodes(),
            "edge_count":   G.number_of_edges(),
            "attack_paths": path_sigs,
            "path_count":   len(path_sigs),
            "shortest_path": shortest_path or [],
            "path_risk":    path_risk,
            "cycle_count":  len(cycles),
            "cycles":       [list(c) for c in cycles],
            "critical_node":    crit_node,
            "critical_reduction": reduction,
            # Stable graph hash for fast equality check
            "graph_hash":   self._graph_hash(G),
        }

        ts_safe = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(self.snapshot_dir, f"snapshot_{ts_safe}.json")
        with open(filepath, "w") as f:
            json.dump(snapshot, f, indent=2)

        print(f"[Temporal] Snapshot saved → {filepath}")
        print(f"           Nodes: {snapshot['node_count']}  "
              f"Edges: {snapshot['edge_count']}  "
              f"Attack paths: {snapshot['path_count']}")
        return filepath

    def _graph_hash(self, G) -> str:
        """Stable hash of graph topology (nodes + edges, sorted)."""
        nodes = sorted(G.nodes())
        edges = sorted((u, v) for u, v in G.edges())
        blob  = json.dumps({"nodes": nodes, "edges": edges}, sort_keys=True)
        return hashlib.sha256(blob.encode()).hexdigest()[:16]

    # ── SNAPSHOT LOADING ──────────────────────────────────────────────────────
    def list_snapshots(self) -> list:
        """Return all snapshot file paths sorted oldest→newest."""
        files = [
            os.path.join(self.snapshot_dir, f)
            for f in os.listdir(self.snapshot_dir)
            if f.startswith("snapshot_") and f.endswith(".json")
        ]
        return sorted(files)

    def load_snapshot(self, filepath: str) -> dict:
        with open(filepath) as f:
            return json.load(f)

    # ── DIFF ENGINE ───────────────────────────────────────────────────────────
    def diff_snapshots(self, old: dict, new: dict) -> dict:
        """
        Compute a structural diff between two graph snapshots.

        Returns a dict with:
          - new_attack_paths:  paths in `new` but not in `old`  ← ALERTS
          - removed_attack_paths: paths in `old` but not in `new`
          - new_cycles / removed_cycles
          - node_delta / edge_delta
          - critical_node_changed
          - risk_delta
          - is_unchanged: True if graph_hash matches
        """
        old_paths = set(old.get("attack_paths", []))
        new_paths = set(new.get("attack_paths", []))
        old_cycles = set(tuple(sorted(c)) for c in old.get("cycles", []))
        new_cycles = set(tuple(sorted(c)) for c in new.get("cycles", []))

        return {
            "old_timestamp":       old.get("timestamp"),
            "new_timestamp":       new.get("timestamp"),
            "is_unchanged":        old.get("graph_hash") == new.get("graph_hash"),

            # Attack path changes
            "new_attack_paths":     sorted(new_paths - old_paths),
            "removed_attack_paths": sorted(old_paths - new_paths),
            "total_path_delta":     len(new_paths) - len(old_paths),

            # Cycle changes
            "new_cycles":           [list(c) for c in new_cycles - old_cycles],
            "removed_cycles":       [list(c) for c in old_cycles - new_cycles],

            # Graph size changes
            "node_delta": new.get("node_count", 0) - old.get("node_count", 0),
            "edge_delta": new.get("edge_count", 0) - old.get("edge_count", 0),

            # Risk changes
            "risk_delta": round(
                new.get("path_risk", 0) - old.get("path_risk", 0), 2),
            "old_risk":   old.get("path_risk", 0),
            "new_risk":   new.get("path_risk", 0),

            # Critical node changes
            "critical_node_changed": (
                old.get("critical_node") != new.get("critical_node")
            ),
            "old_critical_node": old.get("critical_node"),
            "new_critical_node": new.get("critical_node"),
        }

    def diff_latest(self):
        """Diff the two most recent snapshots. Returns None if < 2 exist."""
        snaps = self.list_snapshots()
        if len(snaps) < 2:
            print("[Temporal] Need at least 2 snapshots to diff. Run more scans first.")
            return None
        old = self.load_snapshot(snaps[-2])
        new = self.load_snapshot(snaps[-1])
        return self.diff_snapshots(old, new)

    # ── REPORT PRINTER ────────────────────────────────────────────────────────
    def print_diff_report(self, diff: dict):
        """Print a human-readable temporal diff report to stdout."""
        if diff is None:
            return

        W = 66
        def hr(): print("─" * W)
        def h(t): print(f"\n{'─'*W}\n  {t}\n{'─'*W}")

        print()
        hr()
        print("  KubePath — Temporal Diff Report")
        hr()
        print(f"  Old scan : {diff['old_timestamp']}")
        print(f"  New scan : {diff['new_timestamp']}")

        if diff["is_unchanged"]:
            print("\n  ✓ Graph topology unchanged between scans.")
            return

        h("ATTACK PATH CHANGES")
        if diff["new_attack_paths"]:
            print(f"  ⚠  {len(diff['new_attack_paths'])} NEW attack path(s) detected!\n")
            for p in diff["new_attack_paths"]:
                print(f"    + {p}")
        else:
            print("  ✓ No new attack paths.")

        if diff["removed_attack_paths"]:
            print(f"\n  ✓ {len(diff['removed_attack_paths'])} path(s) remediated:\n")
            for p in diff["removed_attack_paths"]:
                print(f"    - {p}")

        h("RISK SCORE")
        delta_sym = "+" if diff["risk_delta"] > 0 else ""
        print(f"  Path risk: {diff['old_risk']:.1f} → {diff['new_risk']:.1f}"
              f"  ({delta_sym}{diff['risk_delta']:.1f})")

        h("GRAPH CHANGES")
        print(f"  Nodes : {delta_sym}{diff['node_delta']:+d}")
        print(f"  Edges : {delta_sym}{diff['edge_delta']:+d}")
        print(f"  Paths : {diff['total_path_delta']:+d}")

        if diff["new_cycles"]:
            h("NEW PRIVILEGE LOOPS DETECTED")
            for c in diff["new_cycles"]:
                print(f"  ⚠  {' ↔ '.join(c)}")

        if diff["critical_node_changed"]:
            h("CRITICAL NODE CHANGED")
            print(f"  Was : {diff['old_critical_node']}")
            print(f"  Now : {diff['new_critical_node']}")

        h("ALERT SUMMARY")
        if diff["new_attack_paths"] or diff["new_cycles"]:
            print("  🔴 ACTION REQUIRED — new attack vectors have appeared.")
            print(f"     Run 'python main.py' for full analysis.")
        else:
            print("  🟢 No new attack paths. Security posture maintained or improved.")
        print()

    # ── KAN PREDICTION ───────────────────────────────────────────────────────
    def predict_next(self) -> tuple:
        """
        Phase 2: Use the trained KAN to predict whether the next scan
        will contain a new attack path.

        Returns (probability, explanation_string).
        If not enough snapshots exist to train, returns (None, message).
        """
        if not _KAN_AVAILABLE:
            return None, "[KAN] Could not load KAN module. Ensure kan_predictor.py is in the src/ folder."

        snaps = self.list_snapshots()
        if len(snaps) < 3:
            return None, (
                f"[KAN] Need ≥ 3 snapshots to train (have {len(snaps)}). "
                f"Run python main.py more times to build history."
            )

        predictor = _KANPredictor()
        trained   = predictor.fit(self.snapshot_dir)
        if not trained:
            return None, "[KAN] Training failed — not enough data."

        latest = self.load_snapshot(snaps[-1])
        prev   = self.load_snapshot(snaps[-2]) if len(snaps) >= 2 else None
        return predictor.predict(latest, prev)

    # ── CLEANUP ───────────────────────────────────────────────────────────────
    def clear_snapshots(self):
        for f in self.list_snapshots():
            os.remove(f)
        print(f"[Temporal] Cleared all snapshots from {self.snapshot_dir}.")


# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="KubePath Temporal Analyzer")
    parser.add_argument("--list",  action="store_true", help="List all snapshots")
    parser.add_argument("--clear", action="store_true", help="Delete all snapshots")
    parser.add_argument("--diff",  action="store_true", help="Diff latest two snapshots (default)")
    args = parser.parse_args()

    analyzer = TemporalAnalyzer()

    if args.clear:
        analyzer.clear_snapshots()
    elif args.list:
        snaps = analyzer.list_snapshots()
        if not snaps:
            print("No snapshots found.")
        else:
            print(f"\n{len(snaps)} snapshot(s) in {SNAPSHOT_DIR}:\n")
            for s in snaps:
                snap = analyzer.load_snapshot(s)
                print(f"  {os.path.basename(s)}")
                print(f"    Timestamp : {snap['timestamp']}")
                print(f"    Paths     : {snap['path_count']}")
                print(f"    Risk      : {snap['path_risk']}")
                print(f"    Hash      : {snap['graph_hash']}\n")
    else:
        diff = analyzer.diff_latest()
        analyzer.print_diff_report(diff)