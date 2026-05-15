from rich.panel import Panel
from rich.console import Console

console = Console()


def generate_summary(
    suspicious_processes,
    malware_found,
    suspicious_dlls
):

    score = 0

    if suspicious_processes:
        score += 30

    if malware_found:
        score += 50

    if suspicious_dlls:
        score += 20

    level = "LOW"

    if score >= 70:
        level = "HIGH"

    elif score >= 40:
        level = "MEDIUM"

    console.print(
        Panel.fit(
            f"""
Threat Score : {score}/100

Threat Level : {level}

Suspicious Processes : {len(suspicious_processes)}
Suspicious DLLs : {len(suspicious_dlls)}
Malware Indicators : {"YES" if malware_found else "NO"}
""",
            title="TRACE Threat Summary",
            border_style="red"
        )
    )
