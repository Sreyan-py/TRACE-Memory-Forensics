from rich.table import Table
from rich.console import Console

console = Console()


def display_dll_table(output):

    table = Table(
        title="TRACE DLL Analysis"
    )

    table.add_column(
        "Process",
        style="cyan"
    )

    table.add_column(
        "DLL",
        style="green"
    )

    table.add_column(
        "Risk",
        style="red"
    )

    suspicious_keywords = [
        "temp",
        "mimikatz",
        "meterpreter",
        "malware"
    ]

    lines = output.splitlines()

    for line in lines:

        if ".dll" in line.lower():

            risk = "LOW"

            for keyword in suspicious_keywords:

                if keyword in line.lower():
                    risk = "HIGH"

            parts = line.split()

            process = parts[0]

            dll_name = parts[-1]

            table.add_row(
                process,
                dll_name,
                risk
            )

    console.print(table)
