from rich.console import Console
from rich.panel import Panel

console = Console()

def info(msg: str):
    console.print(f"[cyan][*][/cyan] {msg}")

def ok(msg: str):
    console.print(f"[green][ok][/green] {msg}")

def warn(msg: str):
    console.print(f"[yellow][!][/yellow] {msg}")

def err(msg: str):
    console.print(f"[red][x][/red] {msg}")

def title(msg: str):
    console.print(Panel(msg, border_style="cyan"))