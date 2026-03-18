"""
KubePath — src/ingester.py
===========================
Task 1: Data Ingestion (Kubernetes → JSON)

Queries a live Kubernetes cluster via kubectl and exports a structured
cluster-graph.json file.  Falls back gracefully to mock data if kubectl
is unavailable (e.g. in CI or hackathon demo environments).

Usage:
    python -m src.ingester                          # live cluster → data/cluster-graph.json
    python -m src.ingester --mock                   # generate fresh mock data
    python -m src.ingester --out data/my-graph.json # custom output path
"""

import subprocess
import json
import os
import sys
import argparse
from datetime import datetime

# ── CVE MOCK DATABASE ─────────────────────────────────────────────────────────
# Maps image substrings → (CVE-ID, CVSS score, description).
# In production these are fetched from the NIST NVD API (see cve_scorer.py).
MOCK_CVE_DB = {
    "nginx":      ("CVE-2023-44487", 7.5, "HTTP/2 Rapid Reset DoS"),
    "postgres":   ("CVE-2023-5869",  8.8, "Buffer overflow in range type functions"),
    "redis":      ("CVE-2023-41053", 3.3, "OBJECT ENCODING command info leak"),
    "fluentd":    ("CVE-2022-39379", 5.3, "Fluentd arbitrary code execution"),
    "kafka":      ("CVE-2023-25194", 8.8, "Apache Kafka SASL SCRAM RCE"),
    "auth":       ("CVE-2024-1234",  8.1, "Authentication bypass via JWT weakness"),
    "analytics":  ("CVE-2023-46604", 9.8, "Remote code execution via Log4Shell variant"),
    "gateway":    ("CVE-2024-2222",  6.5, "API gateway path traversal"),
}

def _cve_for_image(image_str: str):
    """Return (cve_id, cvss, description) for a known vulnerable image, or empty."""
    img = image_str.lower()
    for key, val in MOCK_CVE_DB.items():
        if key in img:
            return val
    return ("", 0.0, "")


# ── RISK SCORE HEURISTICS ─────────────────────────────────────────────────────
TYPE_BASE_RISK = {
    "external": 6.0, "pod": 5.0, "service": 4.0,
    "sa": 6.0, "role": 7.0, "clusterrole": 9.0,
    "secret": 9.5, "configmap": 2.0, "db": 8.0,
}

def _risk_score(node_type: str, cve_cvss: float) -> float:
    base = TYPE_BASE_RISK.get(node_type, 5.0)
    return round(min(10.0, base + cve_cvss * 0.15), 2)


# ── KUBECTL HELPERS ───────────────────────────────────────────────────────────
def _kubectl(args: list):
    """Run kubectl and return parsed JSON, or None on failure."""
    try:
        result = subprocess.run(
            ["kubectl"] + args + ["-o", "json"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            return None
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        return None


def _kubectl_available() -> bool:
    try:
        r = subprocess.run(["kubectl", "version", "--client"],
                           capture_output=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ── LIVE INGESTION ────────────────────────────────────────────────────────────
def ingest_live() -> dict:
    """
    Pull live state from kubectl and build the graph JSON.
    Covers: pods, serviceaccounts, secrets, configmaps,
            roles, clusterroles, rolebindings, clusterrolebindings.
    """
    print("[*] Querying live Kubernetes cluster via kubectl...")
    nodes, edges = [], []
    node_ids = set()

    def add_node(nid, ntype, label, namespace, image="", labels=None):
        if nid in node_ids:
            return
        node_ids.add(nid)
        cve_id, cvss, cve_desc = _cve_for_image(image or label)
        nodes.append({
            "id":        nid,
            "type":      ntype,
            "position":  {"x": 0, "y": 0},   # visualizer handles layout
            "data": {"label": label},
            "namespace": namespace,
            "labels":    labels or {},
            "risk_score": _risk_score(ntype, cvss),
            "cve":       cve_id,
            "cvss":      cvss,
            "cve_desc":  cve_desc,
        })

    def add_edge(src, tgt, rel, weight=1):
        if src in node_ids and tgt in node_ids:
            edges.append({
                "id":           f"{src}--{rel}--{tgt}",
                "source":       src,
                "target":       tgt,
                "relationship": rel,
                "weight":       weight,
            })

    # Internet entry point
    add_node("internet", "external", "Internet", "cluster-wide")

    # ── PODS ──────────────────────────────────────────────────────────────────
    pods_raw = _kubectl(["get", "pods", "--all-namespaces"])
    if pods_raw:
        for item in pods_raw.get("items", []):
            meta = item["metadata"]
            spec = item.get("spec", {})
            ns   = meta.get("namespace", "default")
            name = meta["name"]
            nid  = f"pod-{ns}-{name}"
            # Grab first container image for CVE lookup
            containers = spec.get("containers", [])
            image = containers[0]["image"] if containers else ""
            add_node(nid, "pod", name, ns, image=image,
                     labels=meta.get("labels", {}))
            # Edge: internet → pod if it has an external-facing service (heuristic)
            if any(k in str(meta.get("labels", {})).lower()
                   for k in ["frontend", "ingress", "gateway", "external"]):
                add_edge("internet", nid, "exposes", weight=2)
            # Pod → serviceaccount
            sa_name = spec.get("serviceAccountName", "default")
            sa_id   = f"sa-{ns}-{sa_name}"
            add_node(sa_id, "sa", sa_name, ns)
            add_edge(nid, sa_id, "uses_service_account", weight=1)

    # ── SECRETS ───────────────────────────────────────────────────────────────
    secrets_raw = _kubectl(["get", "secrets", "--all-namespaces"])
    if secrets_raw:
        for item in secrets_raw.get("items", []):
            meta = item["metadata"]
            ns   = meta.get("namespace", "default")
            name = meta["name"]
            # Skip default token secrets
            if item.get("type", "") == "kubernetes.io/service-account-token":
                continue
            nid  = f"secret-{ns}-{name}"
            add_node(nid, "secret", name, ns, image=name,
                     labels=meta.get("labels", {}))

    # ── CONFIGMAPS ────────────────────────────────────────────────────────────
    cms_raw = _kubectl(["get", "configmaps", "--all-namespaces"])
    if cms_raw:
        for item in cms_raw.get("items", []):
            meta = item["metadata"]
            ns   = meta.get("namespace", "default")
            name = meta["name"]
            if name in ("kube-root-ca.crt",):
                continue
            nid  = f"cm-{ns}-{name}"
            add_node(nid, "configmap", name, ns, labels=meta.get("labels", {}))

    # ── ROLES ─────────────────────────────────────────────────────────────────
    roles_raw   = _kubectl(["get", "roles", "--all-namespaces"])
    croles_raw  = _kubectl(["get", "clusterroles"])
    for item in (roles_raw or {}).get("items", []):
        meta = item["metadata"]
        ns   = meta.get("namespace", "default")
        name = meta["name"]
        nid  = f"role-{ns}-{name}"
        add_node(nid, "role", name, ns, image=name, labels=meta.get("labels", {}))
        # Role → secrets it grants access to (rules inspection)
        for rule in item.get("rules", []):
            if "secrets" in rule.get("resources", []):
                weight = 9 if "*" in rule.get("verbs", []) else 5
                for secret_node in [n for n in nodes if n["type"] == "secret"
                                    and n["namespace"] == ns]:
                    add_edge(nid, secret_node["id"], "grants_access", weight=weight)

    for item in (croles_raw or {}).get("items", []):
        meta = item["metadata"]
        name = meta["name"]
        if name.startswith("system:"):
            continue
        nid  = f"clusterrole-{name}"
        add_node(nid, "clusterrole", name, "cluster-wide",
                 image=name, labels=meta.get("labels", {}))

    # ── ROLEBINDINGS ──────────────────────────────────────────────────────────
    rbs_raw  = _kubectl(["get", "rolebindings",        "--all-namespaces"])
    crbs_raw = _kubectl(["get", "clusterrolebindings"])

    def _process_binding(item, is_cluster=False):
        meta      = item["metadata"]
        ns        = "cluster-wide" if is_cluster else meta.get("namespace", "default")
        role_ref  = item.get("roleRef", {})
        role_name = role_ref.get("name", "")
        role_kind = role_ref.get("kind", "Role").lower()
        role_id   = f"{'clusterrole' if role_kind == 'clusterrole' else 'role'}-{ns if not is_cluster else ''}-{role_name}".strip("-")

        for subject in item.get("subjects", []):
            subj_kind = subject.get("kind", "").lower()
            subj_name = subject.get("name", "")
            subj_ns   = subject.get("namespace", ns)

            if subj_kind == "serviceaccount":
                subj_id = f"sa-{subj_ns}-{subj_name}"
            elif subj_kind == "user":
                subj_id = f"user-{subj_name}"
                add_node(subj_id, "external", subj_name, "cluster-wide")
            else:
                continue

            weight = 10 if "admin" in role_name.lower() else 5
            add_edge(subj_id, role_id, "bound_to_role", weight=weight)

    for item in (rbs_raw or {}).get("items", []):
        _process_binding(item, is_cluster=False)
    for item in (crbs_raw or {}).get("items", []):
        _process_binding(item, is_cluster=True)

    return _build_output(nodes, edges, source="live-kubectl")


# ── MOCK DATA ─────────────────────────────────────────────────────────────────
def ingest_mock() -> dict:
    """
    Load and enrich the bundled mock-cluster-graph.json with full metadata
    (namespace, risk_score, CVE, relationship types) so it conforms to the
    documented schema.
    """
    mock_path = os.path.join(os.path.dirname(__file__), "..", "data", "mock-cluster-graph.json")
    if not os.path.exists(mock_path):
        mock_path = "data/mock-cluster-graph.json"

    print(f"[*] Loading mock data from {mock_path} ...")
    with open(mock_path) as f:
        raw = json.load(f)

    # Map node-id prefixes → namespace heuristic
    NS_MAP = {
        "internet": "cluster-wide", "frontend": "default", "gateway": "default",
        "orders": "orders", "auth": "default", "logging": "default",
        "analytics": "monitoring", "safe": "default", "sa-": "default",
        "role-": "cluster-wide", "db-": "data", "api-": "default",
        "internal": "default", "postgres": "data",
    }
    def _ns(node_id):
        for prefix, ns in NS_MAP.items():
            if node_id.startswith(prefix):
                return ns
        return "default"

    # Relationship labels for edges (by weight heuristic)
    REL_MAP = {1: "calls_service", 2: "escalates_to", 3: "grants_admin_access"}

    enriched_nodes = []
    for n in raw["nodes"]:
        nid   = n["id"]
        ntype = n["type"]
        label = n.get("data", {}).get("label", nid)
        image = label  # use label as image proxy for CVE lookup
        cve_id, cvss, cve_desc = _cve_for_image(image)
        enriched_nodes.append({
            "id":         nid,
            "type":       ntype,
            "position":   n.get("position", {"x": 0, "y": 0}),
            "data":       n.get("data", {"label": label}),
            "namespace":  _ns(nid),
            "labels":     {},
            "risk_score": _risk_score(ntype, cvss),
            "cve":        cve_id,
            "cvss":       cvss,
            "cve_desc":   cve_desc,
        })

    enriched_edges = []
    for e in raw["edges"]:
        w   = e.get("weight", 1)
        rel = REL_MAP.get(w, "connected_to")
        enriched_edges.append({
            "id":           e["id"],
            "source":       e["source"],
            "target":       e["target"],
            "relationship": rel,
            "weight":       w,
        })

    return _build_output(enriched_nodes, enriched_edges, source="mock")


def _build_output(nodes, edges, source="unknown") -> dict:
    return {
        "schema_version": "1.0",
        "metadata": {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "source":       source,
            "node_count":   len(nodes),
            "edge_count":   len(edges),
        },
        "schema": {
            "node_fields": ["id","type","position","data","namespace",
                            "labels","risk_score","cve","cvss","cve_desc"],
            "edge_fields": ["id","source","target","relationship","weight"],
            "node_types":  ["external","pod","service","sa","role",
                            "clusterrole","secret","configmap","db"],
        },
        "nodes": nodes,
        "edges": edges,
    }


# ── MAIN ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="KubePath Data Ingester")
    parser.add_argument("--mock", action="store_true",
                        help="Use mock data instead of live kubectl")
    parser.add_argument("--out", default="data/cluster-graph.json",
                        help="Output file path (default: data/cluster-graph.json)")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

    if args.mock or not _kubectl_available():
        if not args.mock:
            print("[!] kubectl not available — falling back to mock data.")
        data = ingest_mock()
    else:
        data = ingest_live()

    with open(args.out, "w") as f:
        json.dump(data, f, indent=2)

    print(f"[✔] Graph written → {os.path.abspath(args.out)}")
    print(f"    Nodes : {data['metadata']['node_count']}")
    print(f"    Edges : {data['metadata']['edge_count']}")
    print(f"    Source: {data['metadata']['source']}")


if __name__ == "__main__":
    main()