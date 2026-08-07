import subprocess
import json
import os
import struct
import logging
from datetime import datetime
from analysis.threat_detector import ThreatDetector

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Supported memory dump extensions and their display names
# ──────────────────────────────────────────────────────────────────────────────
SUPPORTED_EXTENSIONS = {"raw", "mem", "dmp", "img", "vmem", "pdf"}

EXTENSION_LABELS = {
    "vmem": "VMware Memory Dump",
    "raw": "Raw Memory Image",
    "mem": "Memory Dump",
    "dmp": "Windows Crash Dump",
    "img": "Disk/Memory Image",
    "pdf": "PDF Forensic Report",
}

# Minimum file size for memory dumps: 10 MB
MIN_FILE_SIZE_BYTES = 10 * 1024 * 1024

# Per-plugin subprocess timeout (seconds)
PLUGIN_TIMEOUT = 120

# OS detection timeout (first probe, seconds)
OS_DETECT_TIMEOUT = 60

# ──────────────────────────────────────────────────────────────────────────────
# Validation
# ──────────────────────────────────────────────────────────────────────────────

def _validate_memory_dump(filepath: str, ext: str) -> dict | None:
    """
    Validate the uploaded file before running Volatility.
    Returns an error dict if invalid, None if OK.
    """
    if not os.path.exists(filepath):
        return {"error": "Uploaded file not found on server."}

    size = os.path.getsize(filepath)
    if size == 0:
        return {"error": "This file is empty (0 bytes)."}

    if ext not in SUPPORTED_EXTENSIONS:
        return {
            "error": (
                "Unsupported file format. "
                "Supported formats: .vmem · .raw · .mem · .img · .dmp · .pdf"
            )
        }

    if size > 200 * 1024 * 1024:
        return {"error": "File size exceeds maximum allowed limit of 200 MB."}

    # Magic byte sanity check — reject obvious non-memory binaries for memory dumps
    try:
        with open(filepath, "rb") as f:
            header = f.read(8)

        if ext == "pdf":
            if not header.startswith(b"%PDF"):
                return {"error": "Invalid or corrupted PDF document stream."}
            return None

        # Non-PDF memory files:
        # ZIP / Office
        if header[:4] == b"PK\x03\x04":
            return {"error": "This file is a ZIP/Office archive, not a memory dump."}
        # ELF executable
        if header[:4] == b"\x7fELF":
            return {"error": "This file is an ELF binary, not a memory dump."}
        # Windows PE executable
        if header[:2] == b"MZ" and ext != "dmp":
            return {"error": "This file is a PE executable, not a memory dump."}
        # RAR
        if header[:4] == b"Rar!":
            return {"error": "This file is a RAR archive, not a memory dump."}
        # GZIP
        if header[:2] == b"\x1f\x8b":
            return {"error": "This file is a GZIP archive, not a memory dump."}
    except Exception as e:
        logger.warning(f"Magic byte check failed: {e}")

    return None  # All checks passed


# ──────────────────────────────────────────────────────────────────────────────
# Volatility plugin runner
# ──────────────────────────────────────────────────────────────────────────────

def _run_plugin(filepath: str, plugin: str, timeout: int = PLUGIN_TIMEOUT) -> list | None:
    """
    Run a single Volatility 3 plugin against the memory dump.
    Returns parsed JSON list, [] on empty, or None on failure/timeout.
    """
    command = ["vol", "-f", filepath, "-r", "json", plugin]
    try:
        logger.info(f"[VOL] Running: {plugin}")
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stdout = result.stdout.strip()
        if not stdout:
            logger.warning(f"[VOL] {plugin} produced no output (returncode={result.returncode})")
            return [] if result.returncode == 0 else None

        # Volatility 3 sometimes emits log lines before the JSON array
        for line in stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("[") or stripped.startswith("{"):
                try:
                    data = json.loads(stripped)
                    return data if isinstance(data, list) else [data]
                except json.JSONDecodeError:
                    continue

        # Try full output
        try:
            data = json.loads(stdout)
            return data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            logger.warning(f"[VOL] {plugin} returned non-JSON output — likely unsupported image")
            return None  # Treat non-JSON as failure, not empty success

    except subprocess.TimeoutExpired:
        logger.warning(f"[VOL] {plugin} timed out after {timeout}s")
        return None
    except FileNotFoundError:
        logger.error("[VOL] 'vol' executable not found in PATH")
        return None
    except subprocess.CalledProcessError as e:
        logger.error(f"[VOL] {plugin} CalledProcessError: {e.stderr[:500]}")
        return None
    except Exception as e:
        logger.error(f"[VOL] {plugin} unexpected exception: {e}")
        return None


# ──────────────────────────────────────────────────────────────────────────────
# OS Detection
# ──────────────────────────────────────────────────────────────────────────────

def _detect_os(filepath: str) -> str:
    """
    Attempt to detect the OS in the memory dump.
    Returns 'windows', 'linux', or 'unknown'.
    """
    logger.info("[VOL] Attempting OS detection via windows.info...")
    info = _run_plugin(filepath, "windows.info.Info", timeout=OS_DETECT_TIMEOUT)
    if info is not None:  # even [] means Volatility ran and found a Windows profile
        logger.info("[VOL] OS detected: Windows")
        return "windows"

    logger.info("[VOL] windows.info failed, trying linux.pslist...")
    lps = _run_plugin(filepath, "linux.pslist.PsList", timeout=OS_DETECT_TIMEOUT)
    if lps is not None:
        logger.info("[VOL] OS detected: Linux")
        return "linux"

    logger.warning("[VOL] OS detection inconclusive")
    return "unknown"


# ──────────────────────────────────────────────────────────────────────────────
# Windows analysis
# ──────────────────────────────────────────────────────────────────────────────

def _run_windows_plugins(filepath: str) -> dict:
    """Run the full Windows plugin suite and return raw results."""
    plugins = {
        "info":     "windows.info.Info",
        "pslist":   "windows.pslist.PsList",
        "psscan":   "windows.psscan.PsScan",
        "dlllist":  "windows.dlllist.DllList",
        "netscan":  "windows.netscan.NetScan",
        "cmdline":  "windows.cmdline.CmdLine",
        "handles":  "windows.handles.Handles",
        "hivelist": "windows.registry.hivelist.HiveList",
        "malfind":  "windows.malfind.Malfind",
        "filescan": "windows.filescan.FileScan",
    }
    results = {}
    for key, plugin in plugins.items():
        results[key] = _run_plugin(filepath, plugin)
        logger.info(f"[VOL] {plugin}: {'OK' if results[key] is not None else 'FAILED/TIMEOUT'}")
    return results


# ──────────────────────────────────────────────────────────────────────────────
# Linux analysis
# ──────────────────────────────────────────────────────────────────────────────

def _run_linux_plugins(filepath: str) -> dict:
    """Run the Linux plugin suite and return raw results."""
    plugins = {
        "pslist":  "linux.pslist.PsList",
        "netstat": "linux.netstat.Netstat",
        "lsmod":   "linux.lsmod.Lsmod",
        "bash":    "linux.bash.Bash",
        "check_modules": "linux.check_modules.CheckModules",
    }
    results = {}
    for key, plugin in plugins.items():
        results[key] = _run_plugin(filepath, plugin)
        logger.info(f"[VOL] {plugin}: {'OK' if results[key] is not None else 'FAILED/TIMEOUT'}")
    return results


# ──────────────────────────────────────────────────────────────────────────────
# Main entry point
# ──────────────────────────────────────────────────────────────────────────────

def analyze_memory(filepath: str, file_hash: str = None) -> dict:
    """
    Main forensic analysis entry point.

    1. Validates the memory dump (size, extension, magic bytes).
    2. Detects the OS (Windows vs Linux).
    3. Runs the appropriate Volatility 3 plugin set.
    4. Scores threats using real forensic evidence.
    5. Returns a structured JSON result for the dashboard.

    Never returns a hanging/frozen result — always finishes or returns a
    professional error explaining why analysis could not be completed.
    """
    scan_start = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    filename = os.path.basename(filepath)
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    file_type_label = EXTENSION_LABELS.get(ext, "Memory Image")

    logger.info(f"[TRACE] Starting memory forensics: {filename} ({ext})")

    # ── Step 1: Validate ──────────────────────────────────────────────────────
    validation_error = _validate_memory_dump(filepath, ext)
    if validation_error:
        logger.warning(f"[TRACE] Validation rejected: {validation_error['error']}")
        return {**validation_error, "validation_failed": True}

    file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
    logger.info(f"[TRACE] File validated: {file_size_mb:.1f} MB")

    # ── Step 2: OS Detection ──────────────────────────────────────────────────
    detected_os = _detect_os(filepath)

    # ── Step 3: Run plugins ───────────────────────────────────────────────────
    if detected_os == "windows":
        raw = _run_windows_plugins(filepath)
        architecture = "x64"
    elif detected_os == "linux":
        raw = _run_linux_plugins(filepath)
        architecture = "x64"
    else:
        # Unknown OS — try Windows as best effort
        logger.warning("[TRACE] Unknown OS — attempting Windows plugins as fallback")
        raw = _run_windows_plugins(filepath)
        detected_os = "windows"
        architecture = "Unknown"

    # ── Step 4: Check if Volatility produced any usable data ─────────────────
    # None = plugin crashed/timed out/unsupported image
    # []   = plugin ran but found nothing (valid empty result)
    all_failed = all(v is None for v in raw.values())
    if all_failed:
        scan_end = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        logger.error("[TRACE] All Volatility plugins failed — returning structured error")
        return {
            "success": False,
            "error": (
                "Analysis could not be completed.\n\n"
                "Possible reasons:\n"
                "• Unsupported memory image format\n"
                "• Corrupted memory dump\n"
                "• Missing Volatility symbol tables\n"
                "• Volatility analysis timed out\n\n"
                "Please upload another supported memory image."
            ),
            "volatility_failed": True,
            "timestamps": {"scan_start": scan_start, "scan_end": scan_end},
        }

    # ── Step 5: Threat scoring ────────────────────────────────────────────────
    detector = ThreatDetector()
    results = detector.calculate_threats_full(raw, detected_os)

    scan_end = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    # ── Step 6: Build forensic summary ───────────────────────────────────────
    severity = results["severity"]
    indicators = results.get("malware_indicators", [])
    ind_detail = f" Indicators: {', '.join(indicators[:3])}." if indicators else ""

    if severity == "CRITICAL":
        forensic_summary = (
            f"CRITICAL INCIDENT — Memory analysis of '{filename}' reveals active compromise signatures. "
            f"Multiple high-confidence threat indicators detected including potential credential harvesting, "
            f"code injection artifacts, and anomalous process execution chains.{ind_detail} "
            f"Immediate incident response protocol recommended. Isolate affected endpoints and initiate forensic triage."
        )
    elif severity == "HIGH":
        forensic_summary = (
            f"HIGH SEVERITY ALERT — Behavioral analysis of '{filename}' identified suspicious patterns consistent "
            f"with advanced persistent threat (APT) techniques. Elevated process privileges and anomalous memory "
            f"regions were flagged during inspection.{ind_detail} "
            f"Recommend escalation to Tier-2 SOC analyst for manual verification and threat hunting."
        )
    elif severity == "MEDIUM":
        forensic_summary = (
            f"MODERATE RISK — Inspection of '{filename}' detected anomalous data patterns that warrant further review. "
            f"While no definitive malware signatures were confirmed, heuristic analysis flagged potential indicators "
            f"of compromise.{ind_detail} "
            f"Recommend secondary analysis and continued monitoring of associated processes."
        )
    else:
        forensic_summary = (
            f"CLEAN ASSESSMENT — Analysis of '{filename}' completed with no significant threat indicators. "
            f"File structure, entropy levels, and behavioral heuristics are within acceptable baselines. "
            f"No immediate remediation required. Asset classified as low-risk."
        )

    results.update({
        "analysis_mode": "volatility",
        "analysis_type": "Memory Forensics",
        "detected_os": detected_os,
        "architecture": architecture,
        "file_type_label": file_type_label,
        "file_size_mb": round(file_size_mb, 2),
        "forensic_summary": forensic_summary,
        "timestamps": {"scan_start": scan_start, "scan_end": scan_end},
        "plugin_results": {k: (v or []) for k, v in raw.items()},
    })

    logger.info(
        f"[TRACE] Analysis complete: score={results['threat_score']} severity={results['severity']} "
        f"os={detected_os}"
    )
    return results