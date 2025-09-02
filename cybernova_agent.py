#!/usr/bin/env python3
"""
CyberNova Security Agent
Local device scanner that sends data to cloud dashboard
Compatible with Python 3.8+ (Updated for latest Python versions)
"""

import time
import json
import requests
import psutil
import platform
import socket
import hashlib
from datetime import datetime, timezone
import logging
import sys
import os
from typing import Dict, List, Optional, Tuple, Any, Union

# Configuration
API_URL = os.environ.get("CYBERNOVA_API_URL", "https://cybernova-launch-api-gateway.onrender.com")
SCAN_INTERVAL = 30  # seconds

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CyberNovaAgent:
    def __init__(self) -> None:
        self.user_id: str = self.generate_user_id()
        self.running: bool = True
        self.session: requests.Session = requests.Session()
        self.session.timeout = 10
        
        logger.info("🛡️ CyberNova Agent Started")
        logger.info(f"📱 Device ID: {self.user_id}")
        logger.info(f"🌐 API URL: {API_URL}")

    def generate_user_id(self) -> str:
        """Generate unique device ID"""
        hostname = platform.node()
        system = platform.system()
        device_hash = hashlib.md5(f"{hostname}_{system}".encode()).hexdigest()[:12]
        return f"user_{device_hash}"

    def get_system_info(self) -> Dict[str, Any]:
        """Get real system information"""
        try:
            # Get real IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                ip_address = s.getsockname()[0]
            except:
                ip_address = "127.0.0.1"
            finally:
                s.close()

            memory = psutil.virtual_memory()
            cpu_percent = psutil.cpu_percent(interval=1)

            return {
                "user_id": self.user_id,
                "hostname": platform.node(),
                "platform": f"{platform.system()} {platform.release()}",
                "architecture": platform.architecture()[0],
                "processor": platform.processor(),
                "ip_address": ip_address,
                "cpu_count": psutil.cpu_count(),
                "cpu_percent": cpu_percent,
                "memory_total": memory.total,
                "memory_available": memory.available,
                "memory_percent": memory.percent,
                "boot_time": psutil.boot_time(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "Real Device Agent"
            }
        except Exception as e:
            logger.error(f"System info error: {e}")
            return {"error": str(e), "user_id": self.user_id}

    def scan_processes(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Scan for process threats with intelligent filtering"""
        threats = []
        safe_processes = []
        
        # Whitelist of known safe processes (including our own agent)
        safe_processes_whitelist = {
            'cybernova_agent.py', 'python.exe', 'python3', 'python', 'explorer.exe', 
            'dwm.exe', 'winlogon.exe', 'csrss.exe', 'smss.exe', 'services.exe',
            'lsass.exe', 'svchost.exe', 'chrome.exe', 'firefox.exe', 'edge.exe',
            'code.exe', 'notepad.exe', 'taskmgr.exe', 'system', 'registry',
            'audiodg.exe', 'conhost.exe', 'fontdrvhost.exe', 'dllhost.exe'
        }
        
        # Known malware patterns (more specific)
        malware_patterns = [
            'cryptolocker', 'wannacry', 'petya', 'notpetya', 'ransomware',
            'trojan', 'keylogger', 'backdoor', 'rootkit', 'botnet'
        ]
        
        # Suspicious but not necessarily malicious patterns
        suspicious_patterns = ['powershell', 'cmd', 'wscript', 'cscript']
        
        # Risky locations
        risky_locations = ['\\temp\\', '\\tmp\\', '\\downloads\\', '\\appdata\\local\\temp\\']

        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cpu_percent', 'memory_percent', 'username']):
                try:
                    info = proc.info
                    if not info.get('name'):
                        continue

                    name = info['name'].lower()
                    cpu = info.get('cpu_percent') or 0
                    memory = info.get('memory_percent') or 0
                    exe_path = (info.get('exe') or '').lower()
                    cmdline = ' '.join(info.get('cmdline') or []).lower()

                    # Skip if it's a whitelisted safe process
                    if any(safe_proc in name for safe_proc in safe_processes_whitelist):
                        if len(safe_processes) < 10:
                            safe_processes.append({
                                "pid": info['pid'],
                                "name": info['name'],
                                "exe_path": info.get('exe') or '',
                                "cpu_percent": cpu,
                                "memory_percent": memory,
                                "username": info.get('username') or 'Unknown',
                                "threat_level": "safe",
                                "threat_reasons": ["Verified safe process"],
                                "threat_score": 0,
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            })
                        continue

                    # Skip our own agent process
                    if 'cybernova' in name or 'cybernova' in exe_path or 'cybernova' in cmdline:
                        continue

                    # Threat analysis
                    threat_level = "safe"
                    threat_reasons = []
                    threat_score = 0

                    # Check for known malware patterns (highest priority)
                    if any(malware in name or malware in exe_path or malware in cmdline for malware in malware_patterns):
                        threat_level = "critical"
                        threat_reasons.append("Known malware signature detected")
                        threat_score += 80

                    # Extremely high resource usage (potential crypto mining or DoS)
                    if cpu > 95:
                        threat_level = "critical"
                        threat_reasons.append(f"Extreme CPU usage: {cpu:.1f}% (possible crypto mining)")
                        threat_score += 60
                    elif cpu > 80:
                        threat_level = "high" if threat_level == "safe" else "critical"
                        threat_reasons.append(f"Very high CPU usage: {cpu:.1f}%")
                        threat_score += 35

                    if memory > 80:
                        threat_level = "high" if threat_level == "safe" else "critical"
                        threat_reasons.append(f"Excessive memory usage: {memory:.1f}%")
                        threat_score += 40

                    # Suspicious script execution with high resource usage
                    if any(pattern in name for pattern in suspicious_patterns):
                        if cpu > 30 or memory > 30:  # Only flag if using significant resources
                            threat_level = "medium" if threat_level == "safe" else "high"
                            threat_reasons.append(f"Suspicious script execution with high resource usage")
                            threat_score += 25

                    # Process running from risky locations
                    if any(loc in exe_path for loc in risky_locations):
                        threat_level = "medium" if threat_level == "safe" else "high"
                        threat_reasons.append("Process running from temporary/download directory")
                        threat_score += 30

                    # Unsigned or suspicious executable names
                    suspicious_names = ['svchost32', 'lsass32', 'winlogon32', 'csrss32']  # Fake system processes
                    if any(sus_name in name for sus_name in suspicious_names):
                        threat_level = "high"
                        threat_reasons.append("Suspicious process name mimicking system process")
                        threat_score += 50

                    # Process with no executable path (potentially injected)
                    if not exe_path and name not in ['system', 'registry', '[system process]']:
                        threat_level = "medium" if threat_level == "safe" else "high"
                        threat_reasons.append("Process with no executable path (potential code injection)")
                        threat_score += 35

                    process_data = {
                        "pid": info['pid'],
                        "name": info['name'],
                        "exe_path": info.get('exe') or '',
                        "cpu_percent": cpu,
                        "memory_percent": memory,
                        "username": info.get('username') or 'Unknown',
                        "threat_level": threat_level,
                        "threat_reasons": threat_reasons,
                        "threat_score": threat_score,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }

                    # Only add to threats if there are actual threat indicators
                    if threat_level != "safe" and threat_score > 0:
                        threats.append(process_data)
                    elif threat_level == "safe" and len(safe_processes) < 10:
                        safe_processes.append(process_data)
                        
                except:
                    continue
                    
        except Exception as e:
            logger.error(f"Process scan error: {e}")

        return threats, safe_processes

    def scan_network_connections(self):
        """Scan network connections"""
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    
                    if remote_ip.startswith(('127.', '10.', '192.168.', '172.')):
                        continue

                    threat_level = "low"
                    if remote_port in [22, 23, 135, 139, 445, 1433, 3389, 5900]:
                        threat_level = "high"

                    process_name = "Unknown"
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            process_name = proc.name()
                        except:
                            pass

                    connections.append({
                        "local_ip": conn.laddr.ip if conn.laddr else "",
                        "local_port": conn.laddr.port if conn.laddr else 0,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "status": conn.status,
                        "pid": conn.pid,
                        "process_name": process_name,
                        "threat_level": threat_level,
                        "activity_description": f"Connection to {remote_ip}:{remote_port}",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                    
        except Exception as e:
            logger.error(f"Network scan error: {e}")

        return connections

    def scan_open_ports(self):
        """Scan for risky open ports"""
        risky_ports = []
        
        ports_to_check = {
            21: ("FTP", "File Transfer Protocol"),
            22: ("SSH", "SSH Remote Access"),
            23: ("Telnet", "Unencrypted Remote Access"),
            135: ("RPC", "Windows RPC"),
            139: ("NetBIOS", "File Sharing"),
            445: ("SMB", "Windows File Sharing"),
            1433: ("SQL Server", "Database Server"),
            3389: ("RDP", "Remote Desktop"),
            5900: ("VNC", "Remote Desktop")
        }

        try:
            listening_ports = set()
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_LISTEN:
                    listening_ports.add(conn.laddr.port)

            for port in listening_ports:
                if port in ports_to_check:
                    service, description = ports_to_check[port]
                    threat_level = "critical" if port in [23, 3389, 1433] else "high"
                    
                    risky_ports.append({
                        "port": port,
                        "service": service,
                        "description": description,
                        "threat_level": threat_level,
                        "reason": f"{service} port is exposed",
                        "recommendation": f"Secure {service} or disable if not needed",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                    
        except Exception as e:
            logger.error(f"Port scan error: {e}")

        return risky_ports

    def generate_recommendations(self, threats, connections, ports):
        """Generate security recommendations"""
        recommendations = []

        critical_threats = [t for t in threats if t['threat_level'] == 'critical']
        if critical_threats:
            recommendations.append({
                "id": "critical_processes",
                "type": "malware",
                "priority": "critical",
                "title": "Critical Process Threats",
                "description": f"{len(critical_threats)} critical threats detected",
                "action": "Investigate and terminate suspicious processes",
                "details": [t['name'] for t in critical_threats[:3]]
            })

        risky_connections = [c for c in connections if c['threat_level'] in ['high', 'critical']]
        if risky_connections:
            recommendations.append({
                "id": "risky_connections",
                "type": "network",
                "priority": "high",
                "title": "Suspicious Network Activity",
                "description": f"{len(risky_connections)} risky connections found",
                "action": "Review and block unauthorized connections",
                "details": [f"{c['remote_ip']}:{c['remote_port']}" for c in risky_connections[:3]]
            })

        if ports:
            recommendations.append({
                "id": "open_ports",
                "type": "security", 
                "priority": "high",
                "title": "Risky Ports Exposed",
                "description": f"{len(ports)} risky ports open",
                "action": "Secure or close unnecessary ports",
                "details": [f"Port {p['port']} ({p['service']})" for p in ports]
            })

        return recommendations

    def perform_scan(self):
        """Perform complete device scan"""
        logger.info("🔍 Scanning device...")
        
        try:
            system_info = self.get_system_info()
            threats, safe_processes = self.scan_processes()
            connections = self.scan_network_connections()
            ports = self.scan_open_ports()
            recommendations = self.generate_recommendations(threats, connections, ports)

            total_threats = len(threats) + len([c for c in connections if c['threat_level'] in ['medium', 'high', 'critical']]) + len(ports)
            
            scan_data = {
                "user_id": self.user_id,
                "system_info": system_info,
                "threats": threats,
                "safe_processes": safe_processes,
                "network_connections": connections,
                "risky_ports": ports,
                "recommendations": recommendations,
                "statistics": {
                    "total_threats": total_threats,
                    "high_threats": len([t for t in threats if t['threat_level'] in ['high', 'critical']]),
                    "process_count": len(threats) + len(safe_processes),
                    "connection_count": len(connections),
                    "port_count": len(ports)
                },
                "scan_timestamp": datetime.now(timezone.utc).isoformat()
            }

            logger.info(f"✅ Scan completed: {total_threats} threats detected")
            return scan_data
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            return None

    def send_data(self, scan_data: Dict[str, Any]) -> bool:
        """Send data to API"""
        try:
            response = self.session.post(f"{API_URL}/agent-data", json=scan_data)
            
            if response.status_code == 200:
                logger.info("📡 Data sent successfully")
                return True
            else:
                logger.error(f"❌ API error: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Send error: {e}")
            return False

    def run_cycle(self) -> bool:
        """Run one scan cycle"""
        scan_data = self.perform_scan()
        if scan_data:
            return self.send_data(scan_data)
        return False

    def start(self) -> None:
        """Start continuous monitoring"""
        logger.info(f"🚀 Starting monitoring (every {SCAN_INTERVAL}s)")
        
        # Perform immediate scan on startup
        logger.info("🔍 Performing initial security scan...")
        try:
            initial_success = self.run_cycle()
            if initial_success:
                logger.info("✅ Initial scan completed and sent to dashboard")
            else:
                logger.warning("⚠️ Initial scan failed, will retry in monitoring loop")
        except Exception as e:
            logger.error(f"❌ Initial scan error: {e}")
        
        while self.running:
            try:
                self.run_cycle()
                time.sleep(SCAN_INTERVAL)
                
            except KeyboardInterrupt:
                logger.info("🛑 Agent stopped by user")
                break
            except Exception as e:
                logger.error(f"❌ Error: {e}")
                time.sleep(10)

        logger.info("🔴 Agent stopped")

def main():
    try:
        agent = CyberNovaAgent()
        agent.start()
    except KeyboardInterrupt:
        print("\n🛑 CyberNova Agent stopped")
        sys.exit(0)

if __name__ == "__main__":
    main()
