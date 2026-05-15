from rich.panel import Panel
from rich.console import Console

console = Console()


def show_dashboard():

    console.print(
        Panel.fit(
            """
TRACE DFIR PLATFORM

Modules:
✔ Process Analysis
✔ DLL Analysis
✔ Malware Detection
✔ Threat Scoring
✔ Report Generation
""",
            title="TRACE Dashboard",
            border_style="cyan"
        )
    )


