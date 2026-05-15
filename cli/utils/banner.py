from rich.console import Console
from rich.text import Text

console = Console()


def show_banner():

    banner = r"""

████████╗██████╗  █████╗  ██████╗███████╗
╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
   ██║   ██████╔╝███████║██║     █████╗
   ██║   ██╔══██╗██╔══██║██║     ██╔══╝
   ██║   ██║  ██║██║  ██║╚██████╗███████╗
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝

      advanced memory offensive analysis engine

"""

    console.print()

    console.print(
        Text(
            banner,
            style="bold #b57cff"
        )
    )

    console.print(
        "[#6e4aa3]"
        "        memory forensics  •  malware hunting  •  dfir"
        "[/#6e4aa3]"
    )

    console.print()
