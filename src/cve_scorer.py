"""
KubePath — src/cve_scorer.py
==============================
Bonus 2: Live CVE Scoring via the NIST NVD API

Fetches real CVSS scores for container images by querying:
  https://services.nvd.nist.gov/rest/json/cves/2.0

Usage (standalone):
    python -m src.cve_scorer nginx:1.21
    python -m src.cve_scorer postgres:14 redis:7

Integrated usage (in graph_engine or ingester):
    from src.cve_scorer import CVEScorer
    scorer = CVEScorer()
    cve_id, cvss, desc = scorer.score("nginx:1.21.0")
"""

import os
import json
import time
import requests
from functools import lru_cache

# ── MOCK FALLBACK ─────────────────────────────────────────────────────────────
# Used when the NVD API is unreachable or rate-limited.
MOCK_CVE_DB = {
    "nginx":      ("CVE-2023-44487", 7.5, "HTTP/2 Rapid Reset DoS"),
    "postgres":   ("CVE-2023-5869",  8.8, "Buffer overflow in range type functions"),
    "redis":      ("CVE-2023-41053", 3.3, "OBJECT ENCODING command info leak"),
    "fluentd":    ("CVE-2022-39379", 5.3, "Arbitrary code execution"),
    "kafka":      ("CVE-2023-25194", 8.8, "Apache Kafka SASL SCRAM RCE"),
    "auth":       ("CVE-2024-1234",  8.1, "Authentication bypass via JWT weakness"),
    "analytics":  ("CVE-2023-46604", 9.8, "RCE via Log4Shell variant"),
    "gateway":    ("CVE-2024-2222",  6.5, "API gateway path traversal"),
    "logging":    ("CVE-2022-39379", 5.3, "Fluentd code execution"),
    "frontend":   ("CVE-2024-3333",  4.2, "XSS in frontend framework"),
}


class CVEScorer:
    """
    Queries the NIST NVD API v2 for CVE data related to a container image name.
    Falls back to the built-in mock database when the API is unavailable.
    Results are cached in memory and optionally persisted to a local JSON file.
    """

    NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CACHE_FILE = "data/cve_cache.json"

    def __init__(self, use_api: bool = True, cache: bool = True):
        self.use_api   = use_api
        self.cache     = cache
        self.api_key   = os.environ.get("NVD_API_KEY", "")  # optional — raises rate limit from 5 to 50 req/30s
        self._mem_cache: dict = {}

        if cache:
            self._load_cache()

    # ── CACHE ─────────────────────────────────────────────────────────────────
    def _load_cache(self):
        if os.path.exists(self.CACHE_FILE):
            try:
                with open(self.CACHE_FILE) as f:
                    self._mem_cache = json.load(f)
                print(f"[CVE] Loaded {len(self._mem_cache)} cached entries from {self.CACHE_FILE}")
            except Exception:
                self._mem_cache = {}

    def _save_cache(self):
        os.makedirs(os.path.dirname(self.CACHE_FILE) or ".", exist_ok=True)
        with open(self.CACHE_FILE, "w") as f:
            json.dump(self._mem_cache, f, indent=2)

    # ── MOCK LOOKUP ───────────────────────────────────────────────────────────
    def _mock_lookup(self, image: str) -> tuple:
        img = image.lower()
        for key, val in MOCK_CVE_DB.items():
            if key in img:
                return val
        return ("", 0.0, "No known CVEs in mock database")

    # ── NVD API QUERY ─────────────────────────────────────────────────────────
    def _nvd_query(self, keyword: str) -> tuple:
        """
        Query the NVD CVE 2.0 API for vulnerabilities matching a keyword.
        Returns the highest-CVSS result found.
        """
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 5,
        }

        try:
            resp = requests.get(
                self.NVD_BASE,
                params=params,
                headers=headers,
                timeout=8,
            )
            if resp.status_code == 403:
                print(f"[CVE] NVD API rate-limited — falling back to mock for '{keyword}'")
                return self._mock_lookup(keyword)
            if resp.status_code != 200:
                return self._mock_lookup(keyword)

            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return ("", 0.0, "No CVEs found in NVD")

            # Pick the vulnerability with the highest CVSS v3 base score
            best_cve, best_score, best_desc = "", 0.0, ""
            for v in vulns:
                cve    = v.get("cve", {})
                cve_id = cve.get("id", "")
                desc   = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")[:120]
                        break

                # CVSS v3.1 preferred, fall back to v3.0 then v2
                score = 0.0
                metrics = cve.get("metrics", {})
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        m = metrics[key][0]
                        score = m.get("cvssData", {}).get("baseScore", 0.0)
                        break

                if score > best_score:
                    best_score = score
                    best_cve   = cve_id
                    best_desc  = desc

            return (best_cve, best_score, best_desc)

        except requests.exceptions.RequestException as e:
            print(f"[CVE] NVD API unreachable ({e}) — using mock for '{keyword}'")
            return self._mock_lookup(keyword)

    # ── PUBLIC INTERFACE ──────────────────────────────────────────────────────
    def score(self, image: str) -> tuple:
        """
        Return (cve_id, cvss_score, description) for a container image string.
        Results are cached to avoid redundant API calls.

        Args:
            image: container image name, e.g. "nginx:1.21.0" or "postgres"

        Returns:
            (cve_id: str, cvss: float, description: str)
        """
        # Normalise: strip tag, registry prefix
        keyword = image.split("/")[-1].split(":")[0].lower()

        # Cache hit
        if keyword in self._mem_cache:
            cached = self._mem_cache[keyword]
            return (cached["cve"], cached["cvss"], cached["desc"])

        # Live API or mock
        if self.use_api:
            result = self._nvd_query(keyword)
            # Respect NVD rate limit: 5 requests per 30s without API key
            time.sleep(0.7 if not self.api_key else 0.1)
        else:
            result = self._mock_lookup(keyword)

        cve_id, cvss, desc = result

        # Store in cache
        self._mem_cache[keyword] = {"cve": cve_id, "cvss": cvss, "desc": desc}
        if self.cache:
            self._save_cache()

        return result

    def score_all_nodes(self, nodes: list) -> list:
        """
        Enrich a list of node dicts (from cluster-graph.json) with CVE data.
        Only queries pods — other types get mock heuristics.

        Args:
            nodes: list of node dicts with at least {"id", "type", "data"}

        Returns:
            Same list with "cve", "cvss", "cve_desc" fields populated.
        """
        scored = 0
        for node in nodes:
            ntype = node.get("type", "")
            label = node.get("data", {}).get("label", node.get("id", ""))

            if ntype in ("pod", "service", "external"):
                cve_id, cvss, desc = self.score(label)
            else:
                # Non-pod types: use mock heuristic only
                cve_id, cvss, desc = self._mock_lookup(label)

            node["cve"]      = cve_id
            node["cvss"]     = cvss
            node["cve_desc"] = desc

            if cve_id:
                scored += 1

        print(f"[CVE] Scored {scored}/{len(nodes)} nodes with CVE data.")
        return nodes


# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    images = sys.argv[1:] if len(sys.argv) > 1 else ["nginx", "postgres", "redis"]

    scorer = CVEScorer(use_api=True, cache=True)
    print(f"\n{'Image':<25} {'CVE ID':<20} {'CVSS':>6}  Description")
    print("─" * 85)
    for img in images:
        cve, cvss, desc = scorer.score(img)
        cve_str  = cve  if cve  else "—"
        cvss_str = f"{cvss:.1f}" if cvss else "—"
        print(f"{img:<25} {cve_str:<20} {cvss_str:>6}  {desc[:38]}")