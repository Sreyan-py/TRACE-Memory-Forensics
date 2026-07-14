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
        
        # Apply forensic summary based on severity and analysis mode
        if "forensic_summary" not in results or not results["forensic_summary"]:
            severity = results["severity"]
            mode = results.get("analysis_mode", "general_analysis")
            indicators = results.get("malware_indicators", [])
            indicator_detail = f" Indicators: {', '.join(indicators[:3])}." if indicators else ""
            
            if severity == "CRITICAL":
                results["forensic_summary"] = (
                    f"CRITICAL INCIDENT — Memory analysis of '{filename}' reveals active compromise signatures. "
                    f"Multiple high-confidence threat indicators detected including potential credential harvesting, "
                    f"code injection artifacts, and anomalous process execution chains.{indicator_detail} "
                    f"Immediate incident response protocol recommended. Isolate affected endpoints and initiate forensic triage."
                )
            elif severity == "HIGH":
                results["forensic_summary"] = (
                    f"HIGH SEVERITY ALERT — Behavioral analysis of '{filename}' identified suspicious patterns consistent "
                    f"with advanced persistent threat (APT) techniques. Elevated process privileges and anomalous memory "
                    f"regions were flagged during inspection.{indicator_detail} "
                    f"Recommend escalation to Tier-2 SOC analyst for manual verification and threat hunting."
                )
            elif severity == "MEDIUM":
                results["forensic_summary"] = (
                    f"MODERATE RISK — Inspection of '{filename}' detected anomalous data patterns that warrant further review. "
                    f"While no definitive malware signatures were confirmed, heuristic analysis flagged potential indicators "
                    f"of compromise.{indicator_detail} "
                    f"Recommend secondary analysis and continued monitoring of associated processes."
                )
            else:
                results["forensic_summary"] = (
                    f"CLEAN ASSESSMENT — Analysis of '{filename}' completed with no significant threat indicators. "
                    f"File structure, entropy levels, and behavioral heuristics are within acceptable baselines. "
                    f"No immediate remediation required. Asset classified as low-risk."
                )

        return results
        
    except Exception as e:
        logger.error(f"Analysis Pipeline Error: {str(e)}")
        return {"error": str(e)}