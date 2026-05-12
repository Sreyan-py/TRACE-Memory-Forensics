import subprocess

def run_plugin(memory_dump, plugin):

    command = [
        "python3",
        "volatility3/vol.py",
        "-f",
        memory_dump,
        plugin
    ]

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    output = ""

    for line in process.stdout:
        print(line, end="")
        output += line

    process.wait()

    return output
