from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box

class CLIReport:
    def __init__(self):
        self.console = Console()

    def print_dashboard(self, G, source, target, path, path_risk, blast_radius, cycles, critical_node, reduction, ai_summary):
        self.console.clear()
        
        self.console.print(Panel(Text("KubePath Advanced Security Dashboard", justify="center", style="bold green"), box=box.DOUBLE))
        
        ai_panel = Panel(f"[italic cyan]{ai_summary}[/italic cyan]", title="[bold]AI Executive Summary (Gemini)[/bold]", border_style="cyan")
        self.console.print(ai_panel)
        self.console.print("\n")

        table = Table(title=f"Critical Attack Path Detected: {source} → {target}", box=box.SIMPLE_HEAVY, title_style="bold red")
        table.add_column("Hop", style="cyan", justify="center")
        table.add_column("Entity Node ID", style="bold white")
        table.add_column("Display Name", style="magenta")
        table.add_column("Node Type", style="yellow", justify="right")

        for i, node in enumerate(path):
            node_data = G.nodes[node]
            table.add_row(
                str(i), 
                node, 
                node_data.get('label', 'Unknown'), 
                node_data.get('type', 'Unknown').upper()
            )

        self.console.print(table)
        self.console.print(f"   [bold yellow]Total Resistance Weight (Lower = Easier):[/bold yellow] {path_risk} | [bold yellow]Total Hops:[/bold yellow] {len(path)-1}\n")

        stat_table = Table(show_header=False, box=None)
        stat_table.add_row(f"[bold green]✓[/bold green] [bold]Blast Radius ({source}):[/bold] {len(blast_radius)} nodes compromised within 3 hops.")
        cycle_txt = f"{len(cycles)} privilege loops found" + (f" ({' ↔ '.join(cycles[0])})" if cycles else "")
        stat_table.add_row(f"[bold green]✓[/bold green] [bold]DFS Cycle Detection:[/bold] {cycle_txt}")
        self.console.print(Panel(stat_table, title="[bold]Graph Analytics[/bold]", border_style="green"))

        remed_text = (
            f"The mathematical choke point of this cluster is [bold red]{critical_node}[/bold red].\n"
            f"Removing or patching this single node breaks [bold white]{reduction}[/bold white] active attack paths to the Crown Jewels."
        )
        self.console.print(Panel(remed_text, title="[bold]Recommended Remediation (Task 4)[/bold]", border_style="red"))