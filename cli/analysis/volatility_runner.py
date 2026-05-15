import subprocess
import platform
import os


def run_plugin(memory_dump, plugin):

    base_dir = os.path.dirname(
        os.path.dirname(__file__)
    )

    vol_path = os.path.abspath(
        os.path.join(
            base_dir,
            "..",
            "volatility3",
            "vol.py"
        )
    )

    if platform.system() == "Windows":

        python_cmd = "python"

    else:

        python_cmd = "python3"

    command = [
        python_cmd,
        vol_path,
        "-f",
        memory_dump,
        plugin
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    output = (
        result.stdout +
        result.stderr
    )

    return output
