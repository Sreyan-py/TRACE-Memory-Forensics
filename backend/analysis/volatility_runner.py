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

def analyze_memory(filepath):
    """
    Main entry point for memory analysis.
    Executes Volatility3 plugins and evaluates threats.
    """
    try:
        scan_start = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        pslist_data = run_volatility_plugin(filepath, "windows.pslist.PsList")
        malfind_data = run_volatility_plugin(filepath, "windows.malfind.Malfind")
        netscan_data = run_volatility_plugin(filepath, "windows.netscan.NetScan")
        
        if pslist_data is None and malfind_data is None and netscan_data is None:
            return {"error": "All Volatility plugins failed or timed out. Analysis cannot proceed."}
            
        detector = ThreatDetector()
        results = detector.calculate_threats(pslist_data, malfind_data, netscan_data)
        
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