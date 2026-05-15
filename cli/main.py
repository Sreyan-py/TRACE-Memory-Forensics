from rich import print
from rich.console import Console

from halo import Halo

from analysis.threat_score import (
    calculate_threat_score,
    get_threat_level
)

from analysis.os_detector import (
    detect_os
)

from analysis.process_parser import (
    display_process_table
)

from analysis.artifact_parser import (
    analyze_artifacts
)

from analysis.malware_parser import (
    analyze_malfind
)

from analysis.report_generator import (
    generate_report
)

from analysis.volatility_runner import (
    run_plugin
)

from analysis.threat_detector import (
    detect_suspicious_processes
)

from utils.banner import (
    show_banner
)

from utils.ui import (
    show_success,
    show_warning,
    show_error
)

console = Console()


# =====================================================
# THREAT METER
# =====================================================

def show_threat_meter(score):

    if score <= 25:

        color = "green"
        level = "LOW"

    elif score <= 50:

        color = "yellow"
        level = "MEDIUM"

    elif score <= 75:

        color = "magenta"
        level = "HIGH"

    else:

        color = "red"
        level = "CRITICAL"

    filled = int(score / 5)

    bar = (
        "█" * filled +
        "░" * (20 - filled)
    )

    print()

    console.print(
        f"[bold {color}]"
        f"{bar}  {score}%"
        f"[/bold {color}]"
    )

    console.print(
        f"[bold {color}]"
        f"{level} RISK"
        f"[/bold {color}]"
    )


# =====================================================
# PROCESS ANALYSIS
# =====================================================

def run_process_analysis(memory_dump):

    print()

    console.print(
        "[bold #b57cff]"
        "◈ PROCESS ANALYSIS"
        "[/bold #b57cff]"
    )

    spinner = Halo(
        text="Scanning active processes",
        spinner="dots"
    )

    spinner.start()

    try:

        os_type = detect_os(
            memory_dump
        )

        if os_type == "windows":

            plugin = (
                "windows.pslist.PsList"
            )

        else:

            plugin = (
                "linux.pslist.PsList"
            )

        pslist_output = run_plugin(
            memory_dump,
            plugin
        )

        spinner.stop()

        display_process_table(
            pslist_output
        )

        findings = (
            detect_suspicious_processes(
                pslist_output
            )
        )

        if findings:

            print()

            console.print(
                "[bold red]"
                "Suspicious activity detected"
                "[/bold red]"
            )

            for process in findings:

                console.print(
                    f"[red]• {process}[/red]"
                )

            threat_score = min(
                len(findings) * 20,
                100
            )

        else:

            console.print(
                "[green]"
                "No suspicious processes found"
                "[/green]"
            )

            threat_score = 15

        show_threat_meter(
            threat_score
        )

        return pslist_output

    except Exception as e:

        spinner.stop()

        show_error(str(e))

        return ""


# =====================================================
# ARTIFACT ANALYSIS
# =====================================================

def run_artifact_analysis(memory_dump):

    print()

    console.print(
        "[bold #b57cff]"
        "◈ ARTIFACT ANALYSIS"
        "[/bold #b57cff]"
    )

    spinner = Halo(
        text="Inspecting forensic artifacts",
        spinner="dots"
    )

    spinner.start()

    try:

        os_type = detect_os(
            memory_dump
        )

        if os_type == "windows":

            plugin = (
                "windows.registry.userassist.UserAssist"
            )

        else:

            plugin = (
                "linux.bash.Bash"
            )

        artifact_output = run_plugin(
            memory_dump,
            plugin
        )

        spinner.stop()

        analyze_artifacts(
            artifact_output
        )

        suspicious_keywords = [
            "powershell",
            "cmd",
            "temp",
            "wget",
            "curl",
            "base64"
        ]

        findings = []

        for keyword in suspicious_keywords:

            if keyword.lower() in artifact_output.lower():

                findings.append(keyword)

        if findings:

            print()

            console.print(
                "[bold magenta]"
                "Suspicious artifacts identified"
                "[/bold magenta]"
            )

            for item in findings:

                console.print(
                    f"[magenta]• {item}[/magenta]"
                )

            threat_score = min(
                len(findings) * 15,
                100
            )

        else:

            console.print(
                "[green]"
                "No suspicious artifacts found"
                "[/green]"
            )

            threat_score = 20

        show_threat_meter(
            threat_score
        )

        return artifact_output

    except Exception as e:

        spinner.stop()

        show_error(str(e))

        return ""


# =====================================================
# MALWARE ANALYSIS
# =====================================================

def run_malware_analysis(memory_dump):

    print()

    console.print(
        "[bold #b57cff]"
        "◈ MALWARE ANALYSIS"
        "[/bold #b57cff]"
    )

    spinner = Halo(
        text="Scanning injected memory",
        spinner="dots"
    )

    spinner.start()

    try:

        os_type = detect_os(
            memory_dump
        )

        if os_type == "windows":

            plugin = (
                "windows.malfind.Malfind"
            )

        else:

            plugin = (
                "linux.malfind.Malfind"
            )

        malfind_output = run_plugin(
            memory_dump,
            plugin
        )

        spinner.stop()

        analyze_malfind(
            malfind_output
        )

        indicators = [
            "PAGE_EXECUTE_READWRITE",
            "VadS",
            "MZ",
            "Injected"
        ]

        findings = []

        for item in indicators:

            if item in malfind_output:

                findings.append(item)

        if findings:

            print()

            console.print(
                "[bold red]"
                "Malware indicators detected"
                "[/bold red]"
            )

            for item in findings:

                console.print(
                    f"[red]• {item}[/red]"
                )

            threat_score = min(
                len(findings) * 25,
                100
            )

        else:

            console.print(
                "[green]"
                "No injected memory detected"
                "[/green]"
            )

            threat_score = 25

        show_threat_meter(
            threat_score
        )

        return malfind_output

    except Exception as e:

        spinner.stop()

        show_error(str(e))

        return ""


# =====================================================
# FULL ANALYSIS
# =====================================================

def full_analysis(memory_dump):

    os_type = detect_os(
        memory_dump
    )

    print()

    console.print(
        f"[bold #b57cff]"
        f"Detected OS: {os_type.upper()}"
        f"[/bold #b57cff]"
    )

    process_output = (
        run_process_analysis(
            memory_dump
        )
    )

    artifact_output = (
        run_artifact_analysis(
            memory_dump
        )
    )

    malware_output = (
        run_malware_analysis(
            memory_dump
        )
    )

    suspicious_processes = 0

    suspicious_artifacts = 0

    malware_hits = 0

    process_keywords = [
        "cmd.exe",
        "powershell.exe",
        "mimikatz.exe",
        "dumpit.exe",
        "winrar.exe"
    ]

    artifact_keywords = [
        "powershell",
        "cmd",
        "temp",
        "wget",
        "curl"
    ]

    malware_keywords = [
        "PAGE_EXECUTE_READWRITE",
        "VadS",
        "Injected",
        "MZ"
    ]

    for keyword in process_keywords:

        if keyword.lower() in process_output.lower():

            suspicious_processes += 1

    for keyword in artifact_keywords:

        if keyword.lower() in artifact_output.lower():

            suspicious_artifacts += 1

    for keyword in malware_keywords:

        if keyword in malware_output:

            malware_hits += 1

    final_score = calculate_threat_score(
        suspicious_processes,
        suspicious_artifacts,
        malware_hits
    )

    threat_level = get_threat_level(
        final_score
    )

    print()

    console.print(
        "[bold #b57cff]"
        "FINAL THREAT ASSESSMENT"
        "[/bold #b57cff]"
    )

    show_threat_meter(
        final_score
    )

    console.print(
        f"[bold white]"
        f"Threat Level: "
        f"[/bold white]"
        f"[bold red]"
        f"{threat_level}"
        f"[/bold red]"
    )

    generate_report(
        process_output,
        artifact_output,
        malware_output
    )

    print()

    console.print(
        "[bold #b57cff]"
        "Analysis completed successfully"
        "[/bold #b57cff]"
    )

# =====================================================
# MENU
# =====================================================

def menu():

    while True:

        print()

        console.print(
            "[bold #b57cff]"
            "MAIN MENU"
            "[/bold #b57cff]"
        )

        print()

        console.print(
            "[white][1][/white]  Full Analysis"
        )

        console.print(
            "[white][2][/white]  Process Analysis"
        )

        console.print(
            "[white][3][/white]  Artifact Analysis"
        )

        console.print(
            "[white][4][/white]  Malware Scan"
        )

        console.print(
            "[white][5][/white]  Generate Report"
        )

        console.print(
            "[white][6][/white]  Exit"
        )

        print()

        choice = input(
            "❯ Enter choice: "
        )

        if choice == "1":

            memory_dump = input(
                "\n❯ Enter memory dump path: "
            )

            full_analysis(
                memory_dump
            )

        elif choice == "2":

            memory_dump = input(
                "\n❯ Enter memory dump path: "
            )

            run_process_analysis(
                memory_dump
            )

        elif choice == "3":

            memory_dump = input(
                "\n❯ Enter memory dump path: "
            )

            run_artifact_analysis(
                memory_dump
            )

        elif choice == "4":

            memory_dump = input(
                "\n❯ Enter memory dump path: "
            )

            run_malware_analysis(
                memory_dump
            )

        elif choice == "5":

            console.print(
                "\n[yellow]"
                "Run Full Analysis First"
                "[/yellow]"
            )

        elif choice == "6":

            console.print(
                "\n[#b57cff]"
                "Exiting TRACE..."
                "[/#b57cff]"
            )

            break

        else:

            console.print(
                "\n[red]"
                "Invalid option"
                "[/red]"
            )


show_banner()

menu()
