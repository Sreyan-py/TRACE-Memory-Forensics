def detect_os(memory_dump):

    lower = memory_dump.lower()

    if (
        ".raw" in lower
        or ".dmp" in lower
        or ".vmem" in lower
    ):

        return "windows"

    elif (
        ".lime" in lower
        or ".mem" in lower
    ):

        return "linux"

    return "windows"
