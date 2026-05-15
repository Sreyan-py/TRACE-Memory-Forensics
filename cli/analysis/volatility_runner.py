import subprocess


def run_plugin(memory_dump, plugin):

    command = [
        "python3",
        "../volatility3/vol.py",
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
