import subprocess
import json
import os
from datetime import datetime
import logging
from analysis.threat_detector import ThreatDetector

logger = logging.getLogger(__name__)

def run_volatility_plugin(filepath, plugin_name):
    command = ["vol", "-f", filepath, "-r", "json", plugin_name]
    try:
        if not os.path.exists(filepath):
            return None
            
        logger.info(f"Running Volatility3 plugin: {plugin_name}...")
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=300)
        
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            lines = result.stdout.split('\n')
            for line in lines:
                if line.strip().startswith('['):
                    return json.loads(line)
            return []
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running plugin {plugin_name}: {e.stderr}")
        return None
    except FileNotFoundError:
        logger.error("Volatility 'vol' executable not found. Ensure it is installed and in your PATH.")
        return None
    except subprocess.TimeoutExpired:
        logger.warning(f"Plugin {plugin_name} timed out after 300 seconds.")
        return None
    except Exception as e:
        logger.error(f"Exception during {plugin_name}: {e}")
        return None

def analyze_memory(filepath, file_hash=None):
    """
    Main entry point for hybrid memory analysis.
    Attempts Volatility3 analysis, fallbacks to deterministic metadata analysis if Volatility fails.
    """
    is_render = os.environ.get("RENDER") is not None
    
    try:
        scan_start = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        mode = "volatility"
        
        # On Render free tier, we skip heavy plugins to avoid SIGKILL
        if is_render:
            logger.info("Render environment detected. Using lightweight forensic mode.")
            pslist_data = run_volatility_plugin(filepath, "windows.pslist.PsList")
            malfind_data = None # Skip malfind on Render (CPU/Mem heavy)
            netscan_data = None # Skip netscan on Render
        else:
            pslist_data = run_volatility_plugin(filepath, "windows.pslist.PsList")
            malfind_data = run_volatility_plugin(filepath, "windows.malfind.Malfind")
            netscan_data = run_volatility_plugin(filepath, "windows.netscan.NetScan")
        
        detector = ThreatDetector()
        
        if pslist_data is None and malfind_data is None and netscan_data is None:
            # Fallback for non-memory files (like PDFs), timeouts, or Render SIGKILL protection
            logger.warning("Volatility analysis failed or was skipped. Using deterministic fallback mode.")
            mode = "fallback"
            results = detector.calculate_deterministic_fallback(filepath, file_hash or "unknown")
        else:
            results = detector.calculate_threats(pslist_data, malfind_data, netscan_data)
        
        results["analysis_mode"] = mode
        
        scan_end = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        results["timestamps"] = {
            "scan_start": scan_start,
            "scan_end": scan_end
        }
        
        # We also want to return plugin results so they can be cached
        results["plugin_results"] = {
            "pslist": pslist_data or [],
            "malfind": malfind_data or [],
            "netscan": netscan_data or []
        }
        
        severity = results["severity"]
        if severity == "CRITICAL":
            forensic_summary = "CRITICAL INCIDENT: Intrusions and active compromises detected. Immediate incident response required."
        elif severity == "HIGH":
            forensic_summary = "HIGH SEVERITY ALERT: Multiple forensic indicators point to a successful compromise."
        elif severity == "MEDIUM":
            forensic_summary = "MODERATE THREAT: System exhibits unusual behavior, including atypical process execution."
        else:
            forensic_summary = "LOW THREAT: Memory structures intact. System is likely safe."
            
        results["forensic_summary"] = forensic_summary
        
        return results
    except Exception as e:
        return {"error": str(e)}