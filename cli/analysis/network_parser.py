from rich.table import Table
from rich.console import Console

console = Console()


def display_network_table(output):

    table = Table(
        title="TRACE Network Analysis"
    )

    table.add_column(
        "Protocol",
        style="cyan"
    )

    table.add_column(
        "Local Address",
        style="green"
    )

    table.add_column(
        "Foreign Address",
        style="yellow"
    )

    table.add_column(
        "State",
        style="magenta"
    )

    table.add_column(
        "Risk",
        style="red"
    )

    suspicious_ports = [
        "4444",
        "1337",
        "6666",
        "31337"
    ]

    lines = output.splitlines()

    for line in lines:

        if (
            "TCPv4" in line
            or "TCPv6" in line
            or "UDPv4" in line
            or "UDPv6" in line
        ):

            parts = line.split()
            print(parts)

            if len(parts) >= 7:

                protocol = parts[1]
                local_addr = parts[2]
                foreign_addr = parts[3]

                state = "N/A"

                if "LISTENING" in line:
                    state = "LISTENING"

                risk = "LOW"

                for port in suspicious_ports:

                    if port in line:
                        risk = "HIGH"

                table.add_row(
                    protocol,
                    local_addr,
                    foreign_addr,
                    state,
                    risk
                )

    console.print(table)
