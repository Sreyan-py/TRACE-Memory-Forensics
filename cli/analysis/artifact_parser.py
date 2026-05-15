from rich.console import Console
from rich.table import Table

console = Console()


def analyze_artifacts(output):

    table = Table(
        title="TRACE Artifact Analysis",
        border_style="#b57cff"
    )

    table.add_column(
        "Artifact",
        style="cyan"
    )

    table.add_column(
        "Status",
        style="magenta"
    )

    suspicious_keywords = [
        "powershell",
        "cmd",
        "temp",
        "wget",
        "curl",
        "base64"
    ]

    found = False

    for keyword in suspicious_keywords:

        if keyword.lower() in output.lower():

            found = True

            table.add_row(
                keyword,
                "[red]Suspicious[/red]"
            )

    if not found:

        table.add_row(
            "No suspicious artifacts",
            "[green]Clean[/green]"
        )

    console.print(table)
