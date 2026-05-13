import json

class ThreatDetector:
    def __init__(self):
        # In a real environment, this list would be extensive or dynamically updated.
        self.known_bad_processes = {
            "mimikatz.exe", "nc.exe", "netcat.exe", "psexec.exe", 
            "cmd.exe", "powershell.exe" # These are common but not always bad; we include them for scoring.
        }
        
    def calculate_threats(self, pslist_data, malfind_data, netscan_data):
        threat_score = 0
        suspicious_processes = []
        hidden_processes = []
        dll_injections = []
        network_connections = []
        malware_indicators = []
        
        # Parse pslist data
        if pslist_data:
            for proc in pslist_data:
                image_name = proc.get("ImageFileName", "")
                if image_name.lower() in self.known_bad_processes:
                    if image_name not in suspicious_processes:
                        suspicious_processes.append(image_name)
                    threat_score += 15
                
        # Parse malfind data
        if malfind_data:
            for entry in malfind_data:
                process = entry.get("Process", "")
                if process and process not in dll_injections:
                    dll_injections.append(process)
                    threat_score += 20
            if dll_injections:
                malware_indicators.append("Unbacked executable memory regions (Malfind)")
                
        # Parse netscan data
        if netscan_data:
            for conn in netscan_data:
                state = conn.get("State", "")
                foreign_addr = conn.get("ForeignAddr", "")
                # We flag established connections to external IPs
                if state == "ESTABLISHED" and foreign_addr not in ["0.0.0.0", "::", "127.0.0.1", "*"]:
                    connection_str = f"{conn.get('LocalAddr', '')}:{conn.get('LocalPort', '')} -> {foreign_addr}:{conn.get('ForeignPort', '')} ({state})"
                    if connection_str not in network_connections:
                        network_connections.append(connection_str)
                        threat_score += 10
        
        threat_score = min(threat_score, 100)
        
        if threat_score < 40:
            severity = "LOW"
        elif threat_score < 70:
            severity = "MEDIUM"
        elif threat_score < 90:
            severity = "HIGH"
        else:
            severity = "CRITICAL"
            
        return {
            "threat_score": threat_score,
            "severity": severity,
            "suspicious_processes": list(set(suspicious_processes)),
            "hidden_processes": list(set(hidden_processes)),
            "dll_injections": list(set(dll_injections)),
            "network_connections": list(set(network_connections))[:5],  # Limit to Top 5 for dashboard
            "malware_indicators": malware_indicators,
        }
