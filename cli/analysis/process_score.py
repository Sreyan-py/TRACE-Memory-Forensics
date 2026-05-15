def calculate_process_risk(process):

    high_risk = [
        "powershell.exe",
        "cmd.exe",
        "mimikatz.exe",
        "psexec.exe",
        "nc.exe",
        "winrar.exe"
    ]

    if process.lower() in high_risk:
        return "HIGH"

    return "LOW"
