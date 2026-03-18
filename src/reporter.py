from rich.console import Console
from rich.panel   import Panel
from rich.text    import Text
from rich.table   import Table
from rich         import box


class CLIReport:
    def __init__(self):
        self.console = Console()

    def print_dashboard(
        self, G, source, target,
        path, path_risk,
        blast_nodes, blast_ranks,
        cycles,
        critical_node, reduction,
        ai_summary,
    ):
        self.console.clear()

        # ── Header ────────────────────────────────────────────────────────────
        self.console.print(Panel(
            Text("KubePath  ·  Advanced Security Dashboard", justify="center", style="bold green"),
            box=box.DOUBLE
        ))

        # ── AI Executive Summary ───────────────────────────────────────────────
        self.console.print(Panel(
            f"[italic cyan]{ai_summary}[/italic cyan]",
            title="[bold]AI Executive Summary (Gemini)[/bold]",
            border_style="cyan"
        ))
        self.console.print()

        # ── A* Attack Path ────────────────────────────────────────────────────
        path_table = Table(
            title=f"⚔  A* Attack Path Detected: {source} → {target}",
            box=box.SIMPLE_HEAVY,
            title_style="bold red",
        )
        path_table.add_column("Hop",          style="cyan",    justify="center", width=5)
        path_table.add_column("Node ID",       style="bold white")
        path_table.add_column("Display Name",  style="magenta")
        path_table.add_column("Type",          style="yellow",  justify="right")
        path_table.add_column("CVE",           style="red",     justify="center")
        path_table.add_column("CVSS",          style="red",     justify="center")

        for i, node in enumerate(path):
            nd   = G.nodes[node]
            cve  = nd.get("cve", "") or "—"
            cvss = nd.get("cvss", 0.0)
            path_table.add_row(
                str(i),
                node,
                nd.get("label", node),
                nd.get("type", "unknown").upper(),
                cve,
                f"{cvss:.1f}" if cvss else "—",
            )

        self.console.print(path_table)
        self.console.print(
            f"   [bold yellow]Algorithm:[/bold yellow] A* Search + Privilege Proximity Heuristic  "
            f"[bold yellow]|[/bold yellow]  "
            f"[bold yellow]Path Risk Score:[/bold yellow] {path_risk:.1f}  "
            f"[bold yellow]|[/bold yellow]  "
            f"[bold yellow]Hops:[/bold yellow] {len(path)-1}\n"
        )

        # ── BlastRank panel ───────────────────────────────────────────────────
        top_ranked = list(blast_ranks.items())[:5]   # top 5 by BlastRank

        blast_table = Table(show_header=False, box=None, padding=(0, 1))
        blast_table.add_row(
            "[bold green]✓[/bold green]",
            f"[bold]BlastRank Blast Radius ({source}):[/bold]",
            f"[white]{len(blast_nodes)} nodes compromised within 3 hops[/white]",
        )
        blast_table.add_row(
            "[bold green]✓[/bold green]",
            "[bold]Algorithm:[/bold]",
            "[white]BFS ego-graph + Eigenvector Centrality (Markov Chain)[/white]",
        )
        if top_ranked:
            ranked_str = "  ".join(
                f"[cyan]{n}[/cyan] [dim]({s:.3f})[/dim]" for n, s in top_ranked
            )
            blast_table.add_row(
                "[bold green]→[/bold green]",
                "[bold]Top BlastRank nodes:[/bold]",
                ranked_str,
            )

        # ── DFS Cycles ────────────────────────────────────────────────────────
        if cycles:
            cycle_txt = f"{len(cycles)} privilege loop(s) — e.g. {' ↔ '.join(cycles[0])}"
        else:
            cycle_txt = "0 — no circular permission loops detected"

        blast_table.add_row(
            "[bold green]✓[/bold green]",
            "[bold]DFS Cycle Detection:[/bold]",
            f"[white]{cycle_txt}[/white]",
        )

        self.console.print(Panel(
            blast_table,
            title="[bold]Graph Analytics[/bold]",
            border_style="green",
        ))

        # ── Min-Cut Critical Node ─────────────────────────────────────────────
        remed = (
            f"[bold]Algorithm:[/bold] Min-Cut / Max-Flow (Ford-Fulkerson node-split network)\n\n"
            f"The mathematical choke point of this cluster is [bold red]{critical_node}[/bold red].\n"
            f"Removing or patching this single node breaks "
            f"[bold white]{reduction}[/bold white] active attack path(s) to the Crown Jewels."
        )
        self.console.print(Panel(
            remed,
            title="[bold]Recommended Remediation — Critical Node (Min-Cut)[/bold]",
            border_style="red",
        ))