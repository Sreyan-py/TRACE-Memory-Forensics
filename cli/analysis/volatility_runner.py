import subprocess
import os


def run_plugin(memory_dump, plugin_name):

    current_dir = os.path.dirname(
        os.path.abspath(__file__)
    )

    vol_path = os.path.abspath(
        os.path.join(
            current_dir,
            "..",
            "..",
            "volatility3",
            "vol.py"
        )
    )

    memory_path = os.path.abspath(memory_dump)

    command = [
        "python3",
        vol_path,
        "-f",
        memory_path,
        plugin_name
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    output = result.stdout + result.stderr

    return output
