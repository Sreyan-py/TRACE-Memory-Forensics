from pyfiglet import Figlet
from rich.console import Console

console = Console()

def show_banner():
    banner = Figlet(font="slant")
    text = banner.renderText("TRACE")

    console.print(f"[cyan]{text}[/cyan]")
    console.print("[bold red]Advanced Memory Forensics & Threat Detection[/bold red]")
