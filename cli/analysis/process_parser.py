from rich.table import Table
from rich.console import Console

console = Console()


def calculate_risk(process_name):

    suspicious = [
        "cmd.exe",
        "powershell.exe",
        "mimikatz.exe",
        "dumpit.exe",
        "winrar.exe",
        "nc.exe",
        "psexec.exe",
        "procdump.exe"
    ]

    if process_name.lower() in suspicious:

        return "[red]HIGH[/red]"

    return "[green]LOW[/green]"


def display_process_table(output):

    table = Table(
        title="TRACE Process Analysis",
        border_style="#b57cff"
    )

    table.add_column(
        "PID",
        style="cyan"
    )

    table.add_column(
        "Process",
        style="white"
    )

    table.add_column(
        "Risk",
        style="magenta"
    )

    lines = output.splitlines()

    for line in lines:

        parts = line.split()

        if len(parts) < 4:

            continue

        pid = parts[0]

        process = parts[2]

        if not pid.isdigit():

            continue

        risk = calculate_risk(
            process
        )

        table.add_row(
            pid,
            process,
            risk
        )

    console.print(table)
