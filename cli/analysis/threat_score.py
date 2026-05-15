def calculate_threat_score(
    suspicious_processes,
    suspicious_artifacts,
    malware_hits
):

    score = 0

    score += suspicious_processes * 20

    score += suspicious_artifacts * 15

    score += malware_hits * 25

    if score > 100:

        score = 100

    return score


def get_threat_level(score):

    if score <= 25:

        return "LOW"

    elif score <= 50:

        return "MEDIUM"

    elif score <= 75:

        return "HIGH"

    return "CRITICAL"
