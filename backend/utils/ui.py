from rich.console import Console
from rich.panel import Panel

console = Console()


def show_status(message):

    console.print(
        Panel.fit(
            f"[bold cyan]{message}[/bold cyan]",
            border_style="cyan"
        )
    )


def show_success(message):

    console.print(
        Panel.fit(
            f"[bold green]{message}[/bold green]",
            border_style="green"
        )
    )


def show_warning(message):

    console.print(
        Panel.fit(
            f"[bold yellow]{message}[/bold yellow]",
            border_style="yellow"
        )
    )


def show_error(message):

    console.print(
        Panel.fit(
            f"[bold red]{message}[/bold red]",
            border_style="red"
        )
    )


def show_title():

    console.print(
        Panel.fit(
            "[bold magenta]TRACE DFIR ENGINE[/bold magenta]",
            border_style="magenta"
        )
    )
