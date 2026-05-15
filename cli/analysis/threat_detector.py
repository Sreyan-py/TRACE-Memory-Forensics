def detect_suspicious_processes(output):

    suspicious_processes = [

        "powershell.exe",
        "cmd.exe",
        "mimikatz.exe",
        "psexec.exe",
        "nc.exe",
        "netcat.exe",
        "dumpit.exe",
        "winrar.exe"

    ]

    findings = []

    output = output.lower()

    for process in suspicious_processes:

        if process in output:

            findings.append(process)

    return findings
