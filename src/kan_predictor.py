"""
KubePath — src/kan_predictor.py
=================================
Bonus 3 Phase 2: Proactive Attack Path Prediction via KAN

Implements a Kolmogorov-Arnold Network (KAN) purely in NumPy — no PyTorch
or deep learning framework required, so it runs in any hackathon environment.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  WHY KAN INSTEAD OF AN MLP?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  MLP: fixed activation functions on NODES (ReLU, sigmoid…)
       → weights on edges are just scalars
       → "black box" — you can't read off what it learned

  KAN: learnable SPLINE functions on EDGES
       → each edge carries a B-spline φ(x) with trainable coefficients
       → the final output is a sum of these learnable univariate functions
       → every edge's contribution is directly inspectable:
         "edge sa-auth → role-admin has a steep upward spline at cvss > 7"
       → fully interpretable: security teams can audit the learned functions

  Mathematical basis (Kolmogorov-Arnold representation theorem):
    Any continuous multivariate function f(x₁…xₙ) can be written as
    a finite sum of univariate continuous functions:
      f(x) = Σ_q Φ_q( Σ_p φ_{q,p}(x_p) )
    KAN implements this directly — no universal approximation needed.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  WHAT IT PREDICTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Input features extracted from each temporal snapshot:
    [node_count, edge_count, path_count, path_risk,
     cycle_count, critical_node_type_rank, risk_delta_from_prev]

  Output: probability that the NEXT scan will contain a NEW attack path
          (binary classification: 0 = safe, 1 = new path will appear)

  Training: supervised on the historical snapshot sequence.
  Each sample = (snapshot_t features) → label = (did paths increase at t+1?)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Usage:
    from src.kan_predictor import KANPredictor

    kan = KANPredictor()
    kan.train_from_snapshots("data/snapshots/")   # learns from history
    risk, explanation = kan.predict_next_risk(current_snapshot)
    print(risk, explanation)

Standalone:
    python -m src.kan_predictor                   # train + predict from snapshots
    python -m src.kan_predictor --explain          # show learned spline shapes
"""

import os
import json
import math
import numpy as np
from datetime import datetime


# ─────────────────────────────────────────────────────────────
#  B-SPLINE BASIS (learnable activation on each KAN edge)
# ─────────────────────────────────────────────────────────────

def bspline_basis(x: np.ndarray, knots: np.ndarray, degree: int = 3) -> np.ndarray:
    """
    Evaluate B-spline basis functions at points x.

    B-splines are piecewise polynomial curves defined by a knot vector.
    Each basis function B_{i,k}(x) is non-zero only over a local interval,
    giving the spline its key property: LOCAL control.
    Changing one coefficient only affects the curve near that knot — 
    exactly the interpretability property we want for KAN edge functions.

    Args:
        x      : (N,) array of input values
        knots  : (K,) knot vector (sorted)
        degree : spline degree (3 = cubic, smooth)

    Returns:
        B : (N, K - degree - 1) basis matrix
    """
    n_basis = len(knots) - degree - 1
    N       = len(x)
    B       = np.zeros((N, n_basis))

    # Cox-de Boor recursion
    # Degree 0: B_{i,0}(x) = 1 if knots[i] <= x < knots[i+1]
    B0 = np.zeros((N, len(knots) - 1))
    for i in range(len(knots) - 1):
        if i < len(knots) - 2:
            B0[:, i] = ((x >= knots[i]) & (x < knots[i + 1])).astype(float)
        else:
            # Last interval is closed on the right
            B0[:, i] = ((x >= knots[i]) & (x <= knots[i + 1])).astype(float)

    Bprev = B0
    for d in range(1, degree + 1):
        n_b  = len(knots) - d - 1
        Bcur = np.zeros((N, n_b))
        for i in range(n_b):
            denom1 = knots[i + d]     - knots[i]
            denom2 = knots[i + d + 1] - knots[i + 1]
            t1 = (x - knots[i])           / denom1 if denom1 != 0 else np.zeros(N)
            t2 = (knots[i + d + 1] - x)   / denom2 if denom2 != 0 else np.zeros(N)
            Bcur[:, i] = t1 * Bprev[:, i] + t2 * Bprev[:, i + 1]
        Bprev = Bcur

    return Bprev   # shape (N, n_basis)


class KANEdge:
    """
    A single KAN edge: a learnable B-spline φ(x) + a residual linear term.

    φ(x) = Σ_i  c_i * B_{i,k}(x)   ← spline (interpretable, local)
          + w * x                    ← residual linear (for global trends)

    The spline coefficients c_i are what get trained.
    Each coefficient controls the curve's shape in one local interval.
    """

    def __init__(self, n_knots: int = 8, degree: int = 3, x_range=(-3.0, 3.0)):
        self.degree   = degree
        self.x_min    = x_range[0]
        self.x_max    = x_range[1]
        n_basis       = n_knots - degree - 1

        # Uniform knot vector with clamped ends (multiplicity = degree+1)
        inner  = np.linspace(x_range[0], x_range[1], n_knots - 2 * degree)
        self.knots = np.concatenate([
            np.repeat(x_range[0], degree),
            inner,
            np.repeat(x_range[1], degree),
        ])
        self.knots = np.linspace(x_range[0], x_range[1], n_knots)

        # Trainable parameters
        self.coeffs  = np.zeros(n_basis)      # spline coefficients
        self.w_resid = 0.1                    # residual linear weight

    def forward(self, x: np.ndarray) -> np.ndarray:
        """Evaluate φ(x) for a batch of inputs."""
        # Clamp x to knot range to avoid extrapolation issues
        xc = np.clip(x, self.x_min + 1e-6, self.x_max - 1e-6)
        B  = bspline_basis(xc, self.knots, self.degree)
        return B @ self.coeffs + self.w_resid * x

    def get_spline_description(self, feature_name: str) -> str:
        """
        Returns a human-readable description of what this edge learned.
        This is the interpretability advantage of KAN over MLP.
        """
        c = self.coeffs
        if len(c) == 0:
            return f"{feature_name}: no pattern learned"

        # Find the knot interval where the spline is most steeply rising
        max_idx  = int(np.argmax(c))
        min_idx  = int(np.argmin(c))
        span     = self.x_max - self.x_min
        n        = len(c)

        x_peak   = self.x_min + (max_idx / n) * span
        x_trough = self.x_min + (min_idx / n) * span

        direction = "increases" if c[max_idx] > abs(c[min_idx]) else "decreases"
        pivot     = x_peak if direction == "increases" else x_trough

        return (
            f"{feature_name}: risk {direction} sharply when value ≈ {pivot:.2f} "
            f"(spline peak={c[max_idx]:.3f}, trough={c[min_idx]:.3f})"
        )


# ─────────────────────────────────────────────────────────────
#  KAN LAYER
# ─────────────────────────────────────────────────────────────

class KANLayer:
    """
    One KAN layer: maps n_in features → n_out features.

    Each of the n_in × n_out connections is a KANEdge (learnable spline).
    Output j = Σ_i φ_{i,j}(x_i)

    In standard KAN architecture this replaces the linear layer in MLP.
    The key difference: the φ functions are LEARNED, not fixed activations.
    """

    def __init__(self, n_in: int, n_out: int, n_knots: int = 8, degree: int = 3):
        self.n_in  = n_in
        self.n_out = n_out
        self.edges = [
            [KANEdge(n_knots, degree) for _ in range(n_out)]
            for _ in range(n_in)
        ]
        # Layer-level bias
        self.bias  = np.zeros(n_out)

    def forward(self, x: np.ndarray) -> np.ndarray:
        """
        x : (N, n_in)
        returns: (N, n_out)
        """
        N   = x.shape[0]
        out = np.zeros((N, self.n_out))
        for i in range(self.n_in):
            for j in range(self.n_out):
                out[:, j] += self.edges[i][j].forward(x[:, i])
        return out + self.bias

    def get_all_descriptions(self, feature_names):
        """Return interpretable description of every learned edge."""
        desc = []
        for i, fname in enumerate(feature_names):
            for j in range(self.n_out):
                edge_desc = self.edges[i][j].get_spline_description(fname)
                desc.append(f"  Edge [{fname} → output_{j}]: {edge_desc}")
        return desc


# ─────────────────────────────────────────────────────────────
#  FULL KAN NETWORK  [7 → 4 → 1]
# ─────────────────────────────────────────────────────────────

class KAN:
    """
    Two-layer KAN for attack path prediction.

    Architecture: 7 input features → 4 hidden → 1 output (risk probability)
    All connections are learnable B-spline edges.

    Layer 1: 7×4 = 28 spline edges
    Layer 2: 4×1 = 4  spline edges
    Total:        32 spline functions, each independently inspectable.
    """

    FEATURE_NAMES = [
        "node_count",
        "edge_count",
        "path_count",
        "path_risk",
        "cycle_count",
        "critical_node_rank",
        "risk_delta",
    ]

    # Maps node type → privilege rank for feature encoding
    TYPE_RANK = {
        "db": 10, "secret": 9, "clusterrole": 8, "role": 7,
        "sa": 6, "service": 4, "pod": 3, "external": 1,
    }

    def __init__(self, n_knots: int = 8, degree: int = 3):
        self.layer1 = KANLayer(7, 4, n_knots, degree)
        self.layer2 = KANLayer(4, 1, n_knots, degree)
        self.trained = False

    def _sigmoid(self, x: np.ndarray) -> np.ndarray:
        return 1.0 / (1.0 + np.exp(-np.clip(x, -50, 50)))

    def forward(self, X: np.ndarray) -> np.ndarray:
        """
        X : (N, 7) normalised feature matrix
        returns: (N,) probability of new attack path in next scan
        """
        h = self.layer1.forward(X)
        h = np.tanh(h)               # smooth non-linearity between layers
        o = self.layer2.forward(h)
        return self._sigmoid(o[:, 0])

    # ── FEATURE EXTRACTION ────────────────────────────────────────────────────
    def snapshot_to_features(self, snap: dict, prev_snap: dict = None) -> np.ndarray:
        """Convert a snapshot dict into the 7-dimensional feature vector."""
        crit_type = "unknown"
        # Try to look up the type of the critical node from stored graph data
        # (best effort — may not be available in older snapshots)
        crit_node = snap.get("critical_node", "") or ""
        # Heuristic: infer type from node ID prefix
        for prefix, t in [("sa-", "sa"), ("role-", "role"), ("secret-", "secret"),
                           ("db-", "db"), ("pod-", "pod"), ("internet", "external")]:
            if crit_node.startswith(prefix):
                crit_type = t
                break

        risk_delta = 0.0
        if prev_snap:
            risk_delta = snap.get("path_risk", 0) - prev_snap.get("path_risk", 0)

        return np.array([
            snap.get("node_count",  0),
            snap.get("edge_count",  0),
            snap.get("path_count",  0),
            snap.get("path_risk",   0.0),
            snap.get("cycle_count", 0),
            float(self.TYPE_RANK.get(crit_type, 5)),
            risk_delta,
        ], dtype=float)

    # ── TRAINING ──────────────────────────────────────────────────────────────
    def train_from_snapshots(self, snapshot_dir: str,
                              epochs: int = 200,
                              lr: float = 0.08):
        """
        Train the KAN on the historical snapshot sequence.

        Labels: did the number of attack paths INCREASE in the next scan?
                1 = yes (dangerous), 0 = no (safe / improving)

        Uses mini-batch gradient descent with numerical gradients
        (no autograd — pure NumPy).

        Requires >= 3 snapshots to form at least 2 training samples.
        """
        snaps = self._load_snapshots(snapshot_dir)
        if len(snaps) < 3:
            print(f"[KAN] Not enough snapshots to train ({len(snaps)} found, need ≥ 3).")
            print(f"[KAN] Run python main.py at least 3 times to accumulate history.")
            return False

        # Build (X, y) pairs: X = features at time t, y = did paths increase at t+1?
        X_list, y_list = [], []
        for i in range(len(snaps) - 1):
            feat  = self.snapshot_to_features(snaps[i],
                                              snaps[i-1] if i > 0 else None)
            label = 1.0 if snaps[i+1].get("path_count", 0) > snaps[i].get("path_count", 0) else 0.0
            X_list.append(feat)
            y_list.append(label)

        X = np.array(X_list, dtype=float)
        y = np.array(y_list, dtype=float)

        # Normalise features to [-1, 1] range (B-splines work best in this range)
        self._feat_mean = X.mean(axis=0)
        self._feat_std  = X.std(axis=0) + 1e-8
        X_norm = (X - self._feat_mean) / self._feat_std

        print(f"[KAN] Training on {len(X_norm)} samples, {epochs} epochs...")

        # ── Stochastic gradient descent with numerical gradients ──────────────
        # We use numerical gradient (finite differences) on the spline coefficients.
        # This is less efficient than backprop but requires zero framework dependency.
        eps       = 1e-4
        best_loss = float("inf")

        for epoch in range(epochs):
            preds = self.forward(X_norm)

            # Binary cross-entropy loss
            loss = -np.mean(
                y * np.log(preds + 1e-9) + (1 - y) * np.log(1 - preds + 1e-9)
            )

            if loss < best_loss:
                best_loss = loss

            # Numerical gradient update on layer 1 spline coefficients
            for i in range(self.layer1.n_in):
                for j in range(self.layer1.n_out):
                    edge = self.layer1.edges[i][j]
                    grad = np.zeros_like(edge.coeffs)
                    for k in range(len(edge.coeffs)):
                        edge.coeffs[k] += eps
                        loss_plus = -np.mean(
                            y * np.log(self.forward(X_norm) + 1e-9)
                            + (1-y) * np.log(1 - self.forward(X_norm) + 1e-9)
                        )
                        edge.coeffs[k] -= 2 * eps
                        loss_minus = -np.mean(
                            y * np.log(self.forward(X_norm) + 1e-9)
                            + (1-y) * np.log(1 - self.forward(X_norm) + 1e-9)
                        )
                        edge.coeffs[k] += eps  # restore
                        grad[k] = (loss_plus - loss_minus) / (2 * eps)
                    edge.coeffs -= lr * grad

            # Layer 2 gradient update
            for i in range(self.layer2.n_in):
                edge = self.layer2.edges[i][0]
                grad = np.zeros_like(edge.coeffs)
                for k in range(len(edge.coeffs)):
                    edge.coeffs[k] += eps
                    loss_plus = -np.mean(
                        y * np.log(self.forward(X_norm) + 1e-9)
                        + (1-y) * np.log(1 - self.forward(X_norm) + 1e-9)
                    )
                    edge.coeffs[k] -= 2 * eps
                    loss_minus = -np.mean(
                        y * np.log(self.forward(X_norm) + 1e-9)
                        + (1-y) * np.log(1 - self.forward(X_norm) + 1e-9)
                    )
                    edge.coeffs[k] += eps
                    grad[k] = (loss_plus - loss_minus) / (2 * eps)
                edge.coeffs -= lr * grad

            if epoch % 50 == 0:
                print(f"[KAN]   Epoch {epoch:3d}  loss={loss:.4f}")

        final_preds = self.forward(X_norm)
        acc = np.mean((final_preds > 0.5) == y.astype(bool))
        print(f"[KAN] Training complete. Loss={best_loss:.4f}  Accuracy={acc*100:.1f}%")
        self.trained = True
        self._X_norm = X_norm
        self._y      = y
        return True

    # ── PREDICTION ────────────────────────────────────────────────────────────
    def predict_next_risk(self, current_snapshot: dict, prev_snapshot: dict = None):
        """
        Predict whether the NEXT cluster scan will contain a new attack path.

        Returns:
            probability  : float 0–1  (> 0.6 = HIGH RISK of new path appearing)
            explanation  : human-readable string explaining the prediction
        """
        if not self.trained:
            return 0.0, "KAN not trained yet — run train_from_snapshots() first."

        feat     = self.snapshot_to_features(current_snapshot, prev_snapshot)
        feat_norm = (feat - self._feat_mean) / self._feat_std
        prob      = float(self.forward(feat_norm.reshape(1, -1))[0])

        # ── Generate explanation from spline shapes ───────────────────────────
        # This is the KAN interpretability advantage:
        # We inspect which features have steep splines at the current input value
        contributions = []
        for i, fname in enumerate(self.FEATURE_NAMES):
            x_val = feat_norm[i]
            # Sum of spline outputs for this feature across all hidden units
            total_contrib = sum(
                self.layer1.edges[i][j].forward(np.array([x_val]))[0]
                for j in range(self.layer1.n_out)
            )
            contributions.append((fname, total_contrib, feat[i]))

        # Sort by absolute contribution
        contributions.sort(key=lambda c: abs(c[1]), reverse=True)

        top3 = contributions[:3]
        reason_parts = []
        for fname, contrib, raw_val in top3:
            direction = "↑ pushing risk up" if contrib > 0 else "↓ reducing risk"
            reason_parts.append(
                f"{fname}={raw_val:.1f} [{direction}, contribution={contrib:+.3f}]"
            )

        if prob > 0.7:
            verdict = "🔴 HIGH RISK — KAN predicts a NEW attack path will appear"
        elif prob > 0.4:
            verdict = "🟡 MEDIUM RISK — cluster state is evolving, monitor closely"
        else:
            verdict = "🟢 LOW RISK — KAN predicts no new attack paths next scan"

        explanation = (
            f"{verdict}\n"
            f"  Prediction probability: {prob:.1%}\n"
            f"  Top contributing features:\n"
            + "\n".join(f"    · {r}" for r in reason_parts)
        )

        return prob, explanation

    def explain_learned_functions(self) -> str:
        """
        Print all learned spline functions across both layers.
        This is the unique interpretability output of KAN —
        security teams can audit exactly what the model learned.
        """
        lines = [
            "━" * 60,
            "  KAN Learned Spline Functions (Edge Interpretability)",
            "━" * 60,
            "",
            "  Layer 1 — Input features → Hidden representation:",
        ]
        for desc in self.layer1.get_all_descriptions(self.FEATURE_NAMES):
            lines.append(desc)
        lines += ["", "  Layer 2 — Hidden → Risk prediction:"]
        hidden_names = [f"hidden_{j}" for j in range(self.layer1.n_out)]
        for desc in self.layer2.get_all_descriptions(hidden_names):
            lines.append(desc)
        lines.append("━" * 60)
        return "\n".join(lines)

    # ── PERSISTENCE ───────────────────────────────────────────────────────────
    def save(self, path: str = "data/kan_model.json"):
        """Save trained spline coefficients to JSON."""
        if not self.trained:
            return
        model = {
            "trained": True,
            "feat_mean": self._feat_mean.tolist(),
            "feat_std":  self._feat_std.tolist(),
            "layer1": [
                [self.layer1.edges[i][j].coeffs.tolist()
                 for j in range(self.layer1.n_out)]
                for i in range(self.layer1.n_in)
            ],
            "layer2": [
                [self.layer2.edges[i][j].coeffs.tolist()
                 for j in range(self.layer2.n_out)]
                for i in range(self.layer2.n_in)
            ],
        }
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump(model, f, indent=2)
        print(f"[KAN] Model saved → {path}")

    def load(self, path: str = "data/kan_model.json") -> bool:
        """Load previously trained model from JSON."""
        if not os.path.exists(path):
            return False
        with open(path) as f:
            model = json.load(f)
        self._feat_mean = np.array(model["feat_mean"])
        self._feat_std  = np.array(model["feat_std"])
        for i in range(self.layer1.n_in):
            for j in range(self.layer1.n_out):
                self.layer1.edges[i][j].coeffs = np.array(model["layer1"][i][j])
        for i in range(self.layer2.n_in):
            for j in range(self.layer2.n_out):
                self.layer2.edges[i][j].coeffs = np.array(model["layer2"][i][j])
        self.trained = True
        print(f"[KAN] Model loaded ← {path}")
        return True

    # ── HELPERS ───────────────────────────────────────────────────────────────
    def _load_snapshots(self, snapshot_dir: str) -> list:
        files = sorted([
            os.path.join(snapshot_dir, f)
            for f in os.listdir(snapshot_dir)
            if f.startswith("snapshot_") and f.endswith(".json")
        ])
        snaps = []
        for fp in files:
            with open(fp) as f:
                snaps.append(json.load(f))
        return snaps


# ─────────────────────────────────────────────────────────────
#  PUBLIC API USED BY temporal.py AND main.py
# ─────────────────────────────────────────────────────────────

class KANPredictor:
    """
    Thin wrapper around KAN for easy integration with the rest of KubePath.

    Usage:
        predictor = KANPredictor()
        predictor.fit("data/snapshots/")          # train on history
        prob, explanation = predictor.predict(current_snapshot)
    """

    MODEL_PATH = "data/kan_model.json"

    def __init__(self):
        self.kan = KAN()
        # Try to load a previously saved model
        self.kan.load(self.MODEL_PATH)

    def fit(self, snapshot_dir: str = "data/snapshots/",
            epochs: int = 200, lr: float = 0.08) -> bool:
        ok = self.kan.train_from_snapshots(snapshot_dir, epochs=epochs, lr=lr)
        if ok:
            self.kan.save(self.MODEL_PATH)
        return ok

    def predict(self, current_snapshot: dict,
                prev_snapshot: dict = None):
        return self.kan.predict_next_risk(current_snapshot, prev_snapshot)

    def explain(self) -> str:
        return self.kan.explain_learned_functions()


# ─────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="KubePath KAN Predictor")
    parser.add_argument("--explain", action="store_true",
                        help="Show learned spline function descriptions")
    parser.add_argument("--snapshots", default="data/snapshots/",
                        help="Snapshot directory")
    parser.add_argument("--epochs", type=int, default=200)
    args = parser.parse_args()

    predictor = KANPredictor()
    trained   = predictor.fit(args.snapshots, epochs=args.epochs)

    if not trained:
        print("\nRun 'python main.py' at least 3 times to build snapshot history,")
        print("then re-run this script to train the KAN.")
        sys.exit(0)

    # Load the most recent snapshot and predict
    snap_files = sorted([
        os.path.join(args.snapshots, f)
        for f in os.listdir(args.snapshots)
        if f.startswith("snapshot_") and f.endswith(".json")
    ])

    if snap_files:
        with open(snap_files[-1]) as f:
            latest = json.load(f)
        prev = None
        if len(snap_files) >= 2:
            with open(snap_files[-2]) as f:
                prev = json.load(f)

        prob, explanation = predictor.predict(latest, prev)
        print("\n" + "━" * 60)
        print("  KAN Prediction — Next Scan Risk")
        print("━" * 60)
        print(explanation)

    if args.explain:
        print()
        print(predictor.explain())