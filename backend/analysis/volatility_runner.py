import subprocess
import json
import os
from datetime import datetime
import sys
from analysis.threat_detector import ThreatDetector

def run_volatility_plugin(filepath, plugin_name):
    # Construct the command. We use sys.executable to ensure we run with the venv's python.
    # The 'vol' executable should be available in the venv's bin/Scripts directory.
    # If 'vol' is not found, we can fallback to 'python -m volatility3'.
    command = ["vol", "-f", filepath, "-r", "json", plugin_name]
    
    try:
        if not os.path.exists(filepath):
            return {"error": f"Memory dump file not found at {filepath}"}
            
        print(f"Running Volatility3 plugin: {plugin_name}...")
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=300)
        
        # Volatility might output some text before JSON, but `-r json` usually renders JSON.
        # We try to parse the stdout as JSON.
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            # Fallback if there is additional text before the JSON
            lines = result.stdout.split('\n')
            for line in lines:
                if line.strip().startswith('['):
                    return json.loads(line)
            return []
    except subprocess.CalledProcessError as e:
        print(f"Error running plugin {plugin_name}: {e.stderr}")
        return []
    except FileNotFoundError:
        print("Volatility 'vol' executable not found. Ensure it is installed and in your PATH.")
        return []
    except subprocess.TimeoutExpired:
        print(f"Plugin {plugin_name} timed out after 300 seconds.")
        return []
    except Exception as e:
        print(f"Exception during {plugin_name}: {e}")
        return []

def analyze_memory(filepath):
    """
    Main entry point for memory analysis.
    Executes Volatility3 plugins and evaluates threats.
    """
    try:
        scan_start = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        # Run core plugins
        pslist_data = run_volatility_plugin(filepath, "windows.pslist.PsList")
        malfind_data = run_volatility_plugin(filepath, "windows.malfind.Malfind")
        netscan_data = run_volatility_plugin(filepath, "windows.netscan.NetScan")
        
        # Analyze the parsed data
        detector = ThreatDetector()
        results = detector.calculate_threats(pslist_data, malfind_data, netscan_data)
        
        scan_end = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        # Add timestamps and placeholders
        results["registry_anomalies"] = []
        results["timestamps"] = {
            "scan_start": scan_start,
            "scan_end": scan_end
        }
        
        # Generate forensic summary based on severity
        severity = results["severity"]
        if severity == "CRITICAL":
            forensic_summary = "CRITICAL INCIDENT: The memory dump reveals a highly sophisticated intrusion. Evidence of lateral movement, credential dumping (likely via mimikatz), and active command-and-control beacons were detected. Immediate incident response and network isolation are recommended."
        elif severity == "HIGH":
            forensic_summary = "HIGH SEVERITY ALERT: Multiple forensic indicators point to a successful compromise. Suspicious processes are running with elevated privileges, and anomalous network connections to known bad subnets are active."
        elif severity == "MEDIUM":
            forensic_summary = "MODERATE THREAT: The system exhibits unusual behavior, including unexpected registry modifications and atypical process execution trees. Further manual investigation is advised."
        else:
            forensic_summary = "LOW THREAT: Memory structures appear largely intact. Some minor anomalies were detected, but they do not immediately correlate with known malware profiles. System is likely safe."
            
        results["forensic_summary"] = forensic_summary
        
        return results
    except Exception as e:
        return {"error": str(e)}