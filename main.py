import click
from rich.console import Console
from rich.panel import Panel
from datetime import datetime

console = Console()

BANNER = """
██████╗ ████████╗██╗  ██╗
██╔══██╗╚══██╔══╝██║  ██║
██████╔╝   ██║   ███████║
██╔═══╝    ██║   ██╔══██║
██║        ██║   ██║  ██║
╚═╝        ╚═╝   ╚═╝  ╚═╝

Persistent Threat Hunter v0.1
UEFI Rootkit & Anti-Forensics Detection Platform
"""


@click.group()
def cli():
    """Persistent Threat Hunter — Forensic Analysis Platform"""
    console.print(Panel(BANNER, style="bold red"))
    console.print(
        f"[dim]Session started: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC[/dim]\n"
    )


@cli.command()
@click.option("--firmware", default=None, help="Path to firmware dump (.bin)")
@click.option("--disk", default=None, help="Path to disk image (.dd / .img)")
@click.option("--memory", default=None, help="Path to memory dump (.raw)")
@click.option("--case-id", default=None, help="Custom case ID (auto-generated if not set)")
def analyze(firmware, disk, memory, case_id):
    """Run full forensic analysis pipeline"""
    if not any([firmware, disk, memory]):
        console.print("[red]Error:[/red] Provide at least one input (--firmware, --disk, or --memory)")
        return

    case = case_id or f"PTH-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
    console.print(f"[bold green]Case ID:[/bold green] {case}")
    console.print("[yellow]Full analysis pipeline not yet implemented — modules coming in next steps[/yellow]")


@cli.command()
@click.option("--disk", required=True, help="Path to disk image")
def antiforensics(disk):
    """Run only the anti-forensics detection module"""
    console.print(f"[bold]Analyzing disk:[/bold] {disk}")
    console.print("[yellow]Anti-forensics module not yet implemented[/yellow]")


@cli.command()
@click.option("--case-id", required=True, help="Case ID to generate report for")
def report(case_id):
    """Generate forensic report for a completed analysis"""
    console.print(f"[bold]Generating report for:[/bold] {case_id}")
    console.print("[yellow]Report module not yet implemented[/yellow]")


if __name__ == "__main__":
    cli()