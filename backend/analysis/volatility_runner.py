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
    Intelligent analysis router. Detects file type and routes to the correct forensic pipeline.
    """
    is_render = os.environ.get("RENDER") is not None
    filename = os.path.basename(filepath).lower()
    ext = filename.split(".")[-1] if "." in filename else ""
    
    detector = ThreatDetector()
    scan_start = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    
    try:
        # 1. DOCUMENT ANALYSIS (.pdf, .docx, .pptx, .xlsx, .txt)
        if ext in ["pdf", "docx", "pptx", "xlsx", "txt"]:
            logger.info(f"Routing to Document Analysis Pipeline: {filename}")
            results = detector.analyze_document(filepath, file_hash or "unknown")
            results["analysis_mode"] = "document_inspection"

        # 2. MALWARE ANALYSIS (.exe, .dll)
        elif ext in ["exe", "dll"]:
            logger.info(f"Routing to Malware Analysis Pipeline: {filename}")
            results = detector.analyze_executable(filepath, file_hash or "unknown")
            results["analysis_mode"] = "malware_analysis"

        # 3. SCRIPT ANALYSIS (.js, .py, .ps1, .bat)
        elif ext in ["js", "py", "ps1", "bat"]:
            logger.info(f"Routing to Script Analysis Pipeline: {filename}")
            results = detector.analyze_script(filepath, file_hash or "unknown")
            results["analysis_mode"] = "script_security_scan"

        # 4. MEMORY FORENSICS (.raw, .mem, .dmp, .img)
        elif ext in ["raw", "mem", "dmp", "img"]:
            logger.info(f"Routing to Volatility Forensic Engine: {filename}")
            mode = "volatility"
            
            # On Render free tier, skip heavy plugins
            if is_render:
                logger.info("Render environment detected. Using lightweight forensic mode.")
                pslist_data = run_volatility_plugin(filepath, "windows.pslist.PsList")
                malfind_data = None
                netscan_data = None
            else:
                pslist_data = run_volatility_plugin(filepath, "windows.pslist.PsList")
                malfind_data = run_volatility_plugin(filepath, "windows.malfind.Malfind")
                netscan_data = run_volatility_plugin(filepath, "windows.netscan.NetScan")
            
            if pslist_data is None and malfind_data is None and netscan_data is None:
                logger.warning("Volatility failed. Falling back to deterministic metadata analysis.")
                mode = "fallback"
                results = detector.calculate_deterministic_fallback(filepath, file_hash or "unknown")
            else:
                results = detector.calculate_threats(pslist_data, malfind_data, netscan_data)
            
            results["analysis_mode"] = mode
            results["analysis_type"] = "Memory Forensics"

        # 5. DEFAULT FALLBACK
        else:
            logger.info(f"Unknown file type {ext}. Using general deterministic analysis.")
            results = detector.calculate_deterministic_fallback(filepath, file_hash or "unknown")
            results["analysis_mode"] = "general_analysis"
            results["analysis_type"] = "Threat Intelligence"

        scan_end = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        results["timestamps"] = {
            "scan_start": scan_start,
            "scan_end": scan_end
        }
        
        # Apply forensic summary based on severity if not already set
        if "forensic_summary" not in results:
            severity = results["severity"]
            if severity == "CRITICAL":
                summary = f"CRITICAL: High-risk indicators found in {filename}. Active threat detected."
            elif severity == "HIGH":
                summary = f"HIGH: Suspicious patterns detected in {filename}. High probability of malicious intent."
            elif severity == "MEDIUM":
                summary = f"MEDIUM: Anomalous data identified in {filename}. Recommended for manual review."
            else:
                summary = f"LOW: No significant threats found in {filename}. File appears safe."
            results["forensic_summary"] = summary

        return results
        
    except Exception as e:
        logger.error(f"Analysis Pipeline Error: {str(e)}")
        return {"error": str(e)}