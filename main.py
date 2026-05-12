from utils.banner import show_banner
from utils.ui import (
    show_status,
    show_success,
    show_warning,
    show_error,
    show_title
)

from analysis.volatility_runner import run_plugin
from analysis.threat_detector import detect_suspicious_processes

from halo import Halo


def run_process_analysis(memory_dump):

    show_status("Running Process Analysis")

    spinner = Halo(
        text='Running PsList...',
        spinner='dots'
    )

    spinner.start()

    pslist_output = run_plugin(
        memory_dump,
        "windows.pslist"
    )

    spinner.stop()

    print(pslist_output)

    findings = detect_suspicious_processes(
        pslist_output
    )

    if findings:

        show_warning("Suspicious Processes Detected")

        for process in findings:
            show_error(f"Suspicious Process: {process}")

    else:
        show_success("No Suspicious Processes Found")


def run_network_analysis(memory_dump):

    show_status("Running Network Analysis")

    spinner = Halo(
        text='Running Netscan...',
        spinner='dots'
    )

    spinner.start()

    netscan_output = run_plugin(
        memory_dump,
        "windows.netscan"
    )

    spinner.stop()

    print(netscan_output)


def run_malware_analysis(memory_dump):

    show_status("Running Malware Detection")

    spinner = Halo(
        text='Running Malfind...',
        spinner='dots'
    )

    spinner.start()

    malfind_output = run_plugin(
        memory_dump,
        "windows.malfind"
    )

    spinner.stop()

    print(malfind_output)

    if "PAGE_EXECUTE_READWRITE" in malfind_output:

        show_error(
            "Injected Memory Region Detected"
        )

    else:

        show_success(
            "No Injected Memory Detected"
        )


def full_analysis(memory_dump):

    show_title()

    run_process_analysis(memory_dump)

    run_network_analysis(memory_dump)

    run_malware_analysis(memory_dump)

    show_success("Full Memory Analysis Completed")


def menu():

    print("\n[1] Full Memory Analysis")
    print("[2] Exit")

    choice = input("\nEnter choice: ")

    if choice == "1":

        memory_dump = input(
            "\nEnter memory dump path: "
        )

        full_analysis(memory_dump)

    elif choice == "2":

        print("\nExiting TRACE...")

    else:

        print("\nInvalid Option")


show_banner()
menu()
