# KubePath - Kubernetes Attack Path Visualizer

KubePath is a graph-based security analysis tool for cloud-native infrastructure. It models a
Kubernetes cluster as a Directed Acyclic Graph (DAG) and applies classical computer science
algorithms to surface hidden, exploitable attack chains.

## 🏆 Deliverables Included

```
Working CLI Tool: Professional terminal dashboard.
Kill Chain Report: Automatically exported as a formal PDF
(output/Kill_Chain_Report.pdf).
JSON Data Export: The fully processed graph exported to JSON (output/cluster-
graph-export.json).
Algorithm Implementations: Custom BFS, DFS, and Dijkstra's implementations.
Bonus 1: Interactive HTML/JS Visualizer (output/index.html).
Bonus 2: Live CVE Scoring via the NIST NVD API.
Bonus Feature: AI-powered executive summaries via Google Gemini.
```
## ⚙ Setup Instructions

**Prerequisites:** Python 3.10+

1. **Clone the repository and enter the directory.**
2. **Create a virtual environment:**

```
python -m venv venv
source venv/bin/activate # On Windows use: venv\Scripts\activate
```
3. **Install dependencies:**

```
pip install -r requirements.txt
```
4. **(Optional) Set Gemini API Key for AI Insights:**

```
export GEMINI_API_KEY="your-api-key-here"
```
5. **Run the Application:**


```
python main.py
```
```
Check the output/ directory for the PDF report, JSON export, and HTML Dashboard!
```
## 📊 Graph Schema Documentation

KubePath maps entities into an actionable mathematical format.

**Node Schema**

Represents Kubernetes entities (Pods, Services, Secrets, Roles).

```
id: Unique identifier (e.g., frontend-1).
type: The entity kind (pod, service, db, external, role, sa, secret).
label: Human-readable display name.
cve: Known vulnerability identifier (e.g., CVE-2021-44228).
cvss: Vulnerability severity score (0.0 to 10.0). Dynamically fetched from NIST NVD.
is_public: Boolean. Identifies external ingress points.
is_crown_jewel: Boolean. Identifies critical target assets.
```
**Edge Schema**

Represents the trust relationship or RBAC permission bridging two nodes.

```
source: ID of the origin node.
target: ID of the destination node.
weight: The calculated resistance of the edge. Derived mathematically as 10.0 - CVSS
Score. A lower weight indicates a path of lesser resistance for an attacker.
```
## 🧠 Algorithms Used

1. **Blast Radius Detection (Breadth-First Search):** Generates an ego_graph extending 3
    hops outward from a compromised pod to define the incident response Danger Zone.
2. **Attack Path Detection (Dijkstra's Algorithm):** Calculates the shortest path from public
    external nodes to internal db Crown Jewels, utilizing edge weights to find the path of
    least resistance.
3. **Circular Permission Detection (Depth-First Search):** Utilizes a custom recursive DFS
    algorithm tracking visited sets and a rec_stack to mathematically prove the existence
    of back-edges (privilege escalation loops).
4. **Critical Node Simulation:** Iteratively drops nodes that exist on valid attack paths,
    recounting the total available paths to identify the single "choke point" remediation target.

## Screenshots
<img width="1468" height="831" alt="image" src="https://github.com/user-attachments/assets/c0b6ee8a-1808-4647-96cf-3eb0d5f3a255" />
<img width="1469" height="832" alt="image" src="https://github.com/user-attachments/assets/94b1130f-be40-4d93-9c5a-0dd41582c897" />
<img width="1470" height="830" alt="image" src="https://github.com/user-attachments/assets/5fb35835-b0b3-4553-8745-e4c661c448ce" />
<img width="1470" height="838" alt="image" src="https://github.com/user-attachments/assets/f6185fb8-08e6-4c48-a19f-3f8c34d71aad" />
