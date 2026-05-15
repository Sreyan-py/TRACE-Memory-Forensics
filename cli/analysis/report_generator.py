import json
from datetime import datetime

from analysis.threat_score import (
    calculate_threat_score,
    get_threat_level
)


def generate_report(
    process_output,
    artifact_output,
    malware_output
):

    suspicious_processes = []

    suspicious_artifacts = []

    malware_indicators = []

    process_keywords = [
        "cmd.exe",
        "powershell.exe",
        "mimikatz.exe",
        "dumpit.exe",
        "winrar.exe",
        "nc.exe"
    ]

    artifact_keywords = [
        "powershell",
        "cmd",
        "temp",
        "wget",
        "curl",
        "base64"
    ]

    malware_keywords = [
        "PAGE_EXECUTE_READWRITE",
        "VadS",
        "Injected",
        "MZ"
    ]

    for keyword in process_keywords:

        if keyword.lower() in process_output.lower():

            suspicious_processes.append(
                keyword
            )

    for keyword in artifact_keywords:

        if keyword.lower() in artifact_output.lower():

            suspicious_artifacts.append(
                keyword
            )

    for keyword in malware_keywords:

        if keyword in malware_output:

            malware_indicators.append(
                keyword
            )

    score = calculate_threat_score(
        len(suspicious_processes),
        len(suspicious_artifacts),
        len(malware_indicators)
    )

    level = get_threat_level(score)

    report = {

        "trace_version": "TRACE DFIR v1.0",

        "analysis_time": str(
            datetime.now()
        ),

        "threat_score": score,

        "threat_level": level,

        "suspicious_processes":
        suspicious_processes,

        "artifact_indicators":
        suspicious_artifacts,

        "malware_indicators":
        malware_indicators,

        "summary": {

            "process_findings":
            len(suspicious_processes),

            "artifact_findings":
            len(suspicious_artifacts),

            "malware_findings":
            len(malware_indicators)
        }
    }

    filename = (
        "report_" +
        datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        ) +
        ".json"
    )

    with open(
        filename,
        "w"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    print(
        f"\n[+] JSON Report Saved: {filename}"
    )
