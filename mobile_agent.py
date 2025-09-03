#!/usr/bin/env python3
"""
CyberNova Mobile Security Agent
Cross-platform mobile security monitoring for Android and iOS
Compatible with Kivy/BeeWare for mobile deployment
"""

import time
import json
import requests
import platform
import socket
import hashlib
from datetime import datetime, timezone
import logging
import sys
import os
from typing import Dict, List, Optional, Tuple, Any, Union

# Mobile-specific imports (install with: pip install kivy plyer)
try:
    from kivy.app import App
    from kivy.uix.boxlayout import BoxLayout
    from kivy.uix.label import Label
    from kivy.uix.button import Button
    from kivy.clock import Clock
    from plyer import notification, battery, gps, accelerometer
    MOBILE_AVAILABLE = True
except ImportError:
    MOBILE_AVAILABLE = False
    print("Mobile libraries not available. Install with: pip install kivy plyer")

# Configuration
API_URL = os.environ.get("CYBERNOVA_API_URL", "https://cybernova-launch-api-gateway.onrender.com")
SCAN_INTERVAL = 60  # seconds (longer for mobile to save battery)

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CyberNovaMobileAgent:
    def __init__(self) -> None:
        self.user_id = self.generate_user_id()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberNova-Mobile-Agent/1.0',
            'Content-Type': 'application/json'
        })
        
        logger.info("🛡️ CyberNova Mobile Agent Started")
        logger.info(f"📱 Device ID: {self.user_id}")
        logger.info(f"🌐 API URL: {API_URL}")

    def generate_user_id(self) -> str:
        """Generate unique device ID for mobile"""
        try:
            # Use device-specific information
            device_info = f"{platform.node()}-{platform.machine()}-{platform.system()}"
            return hashlib.sha256(device_info.encode()).hexdigest()[:16]
        except Exception:
            return f"mobile_{int(time.time())}"

    def get_mobile_system_info(self) -> Dict[str, Any]:
        """Get mobile device system information"""
        try:
            system_info = {
                "platform": platform.system(),
                "platform_release": platform.release(),
                "platform_version": platform.version(),
                "architecture": platform.machine(),
                "processor": platform.processor(),
                "device_name": platform.node(),
                "python_version": platform.python_version(),
                "device_type": "mobile"
            }
            
            # Add mobile-specific info if available
            if MOBILE_AVAILABLE:
                try:
                    # Battery information
                    battery_info = battery.status
                    system_info["battery_level"] = battery_info.get("percentage", "unknown")
                    system_info["battery_charging"] = battery_info.get("isCharging", False)
                except:
                    pass
                
                try:
                    # GPS information (if permission granted)
                    gps.configure(on_location=lambda **kwargs: None)
                    system_info["gps_available"] = True
                except:
                    system_info["gps_available"] = False
            
            return system_info
        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            return {"error": str(e), "device_type": "mobile"}

    def scan_mobile_processes(self) -> List[Dict[str, Any]]:
        """Scan for suspicious mobile processes (limited on mobile)"""
        threats = []
        
        try:
            # Mobile process scanning is limited due to OS restrictions
            # Focus on app-level security checks
            
            # Check for common mobile threats
            suspicious_patterns = [
                "malware", "trojan", "virus", "spyware", "adware",
                "rootkit", "keylogger", "backdoor", "suspicious"
            ]
            
            # Simulate mobile security scan
            running_apps = self.get_running_apps()
            
            for app in running_apps:
                threat_level = "low"
                threat_reasons = []
                
                # Check app name for suspicious patterns
                app_name_lower = app.get("name", "").lower()
                for pattern in suspicious_patterns:
                    if pattern in app_name_lower:
                        threat_level = "high"
                        threat_reasons.append(f"Suspicious app name contains '{pattern}'")
                
                # Check for excessive permissions (simulated)
                if app.get("permissions", 0) > 20:
                    threat_level = "medium"
                    threat_reasons.append("App requests excessive permissions")
                
                if threat_reasons:
                    threats.append({
                        "name": app.get("name", "Unknown App"),
                        "package": app.get("package", "unknown"),
                        "threat_level": threat_level,
                        "threat_reasons": threat_reasons,
                        "permissions": app.get("permissions", 0),
                        "version": app.get("version", "unknown")
                    })
            
        except Exception as e:
            logger.error(f"Error scanning mobile processes: {e}")
        
        return threats

    def get_running_apps(self) -> List[Dict[str, Any]]:
        """Get list of running mobile apps (simulated for demo)"""
        # In a real mobile app, this would use platform-specific APIs
        # For demo purposes, return sample data
        sample_apps = [
            {"name": "System UI", "package": "com.android.systemui", "permissions": 15, "version": "1.0"},
            {"name": "Chrome", "package": "com.android.chrome", "permissions": 8, "version": "91.0"},
            {"name": "WhatsApp", "package": "com.whatsapp", "permissions": 12, "version": "2.21"},
            {"name": "Settings", "package": "com.android.settings", "permissions": 25, "version": "1.0"},
        ]
        return sample_apps

    def scan_mobile_network(self) -> List[Dict[str, Any]]:
        """Scan mobile network connections"""
        connections = []
        
        try:
            # Mobile network scanning is limited
            # Focus on basic connectivity checks
            
            # Check internet connectivity
            try:
                socket.create_connection(("8.8.8.8", 53), timeout=3)
                connections.append({
                    "type": "internet",
                    "status": "connected",
                    "threat_level": "low",
                    "description": "Internet connectivity active"
                })
            except:
                connections.append({
                    "type": "internet",
                    "status": "disconnected",
                    "threat_level": "low",
                    "description": "No internet connectivity"
                })
            
            # Check for suspicious network activity (simulated)
            if MOBILE_AVAILABLE:
                try:
                    # In a real app, this would check actual network usage
                    connections.append({
                        "type": "mobile_data",
                        "status": "active",
                        "threat_level": "low",
                        "description": "Mobile data connection active"
                    })
                except:
                    pass
            
        except Exception as e:
            logger.error(f"Error scanning mobile network: {e}")
        
        return connections

    def get_mobile_security_recommendations(self) -> List[Dict[str, Any]]:
        """Get mobile-specific security recommendations"""
        recommendations = []
        
        try:
            # Mobile security recommendations
            recommendations.extend([
                {
                    "type": "mobile_security",
                    "priority": "high",
                    "title": "Enable Screen Lock",
                    "description": "Use PIN, pattern, or biometric lock",
                    "action": "Go to Settings > Security > Screen Lock"
                },
                {
                    "type": "mobile_security",
                    "priority": "high",
                    "title": "Keep OS Updated",
                    "description": "Install latest security updates",
                    "action": "Go to Settings > System Update"
                },
                {
                    "type": "mobile_security",
                    "priority": "medium",
                    "title": "Review App Permissions",
                    "description": "Check which apps have access to sensitive data",
                    "action": "Go to Settings > Apps > Permissions"
                },
                {
                    "type": "mobile_security",
                    "priority": "medium",
                    "title": "Enable Find My Device",
                    "description": "Activate remote locate and wipe features",
                    "action": "Go to Settings > Security > Find My Device"
                },
                {
                    "type": "mobile_security",
                    "priority": "low",
                    "title": "Use Secure Wi-Fi",
                    "description": "Avoid public Wi-Fi for sensitive activities",
                    "action": "Connect only to trusted networks"
                }
            ])
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
        
        return recommendations

    def perform_mobile_scan(self) -> Dict[str, Any]:
        """Perform comprehensive mobile security scan"""
        logger.info("🔍 Starting mobile security scan...")
        
        try:
            # Get system information
            system_info = self.get_mobile_system_info()
            
            # Scan for threats
            threats = self.scan_mobile_processes()
            
            # Scan network
            network_connections = self.scan_mobile_network()
            
            # Get recommendations
            recommendations = self.get_mobile_security_recommendations()
            
            # Calculate statistics
            statistics = {
                "total_threats": len(threats),
                "high_threats": len([t for t in threats if t.get("threat_level") == "high"]),
                "medium_threats": len([t for t in threats if t.get("threat_level") == "medium"]),
                "low_threats": len([t for t in threats if t.get("threat_level") == "low"]),
                "network_connections": len(network_connections),
                "recommendations": len(recommendations)
            }
            
            scan_results = {
                "user_id": self.user_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "system_info": system_info,
                "threats": threats,
                "network_connections": network_connections,
                "recommendations": recommendations,
                "statistics": statistics,
                "scan_type": "mobile_security_scan"
            }
            
            logger.info(f"✅ Mobile scan completed: {statistics['total_threats']} threats found")
            return scan_results
            
        except Exception as e:
            logger.error(f"❌ Mobile scan failed: {e}")
            return {
                "user_id": self.user_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "error": str(e),
                "scan_type": "mobile_security_scan"
            }

    def send_scan_results(self, scan_data: Dict[str, Any]) -> bool:
        """Send mobile scan results to API"""
        try:
            response = self.session.post(f"{API_URL}/agent-data", json=scan_data)
            
            if response.status_code == 200:
                logger.info("✅ Mobile scan results sent successfully")
                return True
            else:
                logger.error(f"❌ Failed to send results: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error sending results: {e}")
            return False

    def run_continuous_monitoring(self):
        """Run continuous mobile monitoring"""
        logger.info("🔄 Starting continuous mobile monitoring...")
        
        while True:
            try:
                # Perform scan
                scan_results = self.perform_mobile_scan()
                
                # Send results
                self.send_scan_results(scan_results)
                
                # Wait before next scan (longer interval for mobile to save battery)
                logger.info(f"⏳ Waiting {SCAN_INTERVAL} seconds before next scan...")
                time.sleep(SCAN_INTERVAL)
                
            except KeyboardInterrupt:
                logger.info("🛑 Mobile monitoring stopped by user")
                break
            except Exception as e:
                logger.error(f"❌ Monitoring error: {e}")
                time.sleep(30)  # Wait before retrying

# Mobile App UI (if Kivy is available)
class CyberNovaMobileApp(App):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.agent = CyberNovaMobileAgent()
        self.monitoring = False

    def build(self):
        layout = BoxLayout(orientation='vertical', padding=20, spacing=10)
        
        # Title
        title = Label(
            text='🛡️ CyberNova Mobile Security',
            font_size='24sp',
            size_hint_y=None,
            height='60dp'
        )
        layout.add_widget(title)
        
        # Status
        self.status_label = Label(
            text='Ready to start monitoring',
            font_size='16sp',
            size_hint_y=None,
            height='40dp'
        )
        layout.add_widget(self.status_label)
        
        # Start/Stop button
        self.toggle_button = Button(
            text='Start Monitoring',
            font_size='18sp',
            size_hint_y=None,
            height='60dp'
        )
        self.toggle_button.bind(on_press=self.toggle_monitoring)
        layout.add_widget(self.toggle_button)
        
        # Scan button
        scan_button = Button(
            text='Run Quick Scan',
            font_size='18sp',
            size_hint_y=None,
            height='60dp'
        )
        scan_button.bind(on_press=self.run_scan)
        layout.add_widget(scan_button)
        
        return layout

    def toggle_monitoring(self, instance):
        if not self.monitoring:
            self.start_monitoring()
        else:
            self.stop_monitoring()

    def start_monitoring(self):
        self.monitoring = True
        self.toggle_button.text = 'Stop Monitoring'
        self.status_label.text = '🔄 Monitoring active...'
        
        # Schedule periodic scans
        Clock.schedule_interval(self.scheduled_scan, SCAN_INTERVAL)
        
        # Show notification
        if MOBILE_AVAILABLE:
            notification.notify(
                title='CyberNova Security',
                message='Mobile monitoring started',
                timeout=5
            )

    def stop_monitoring(self):
        self.monitoring = False
        self.toggle_button.text = 'Start Monitoring'
        self.status_label.text = 'Monitoring stopped'
        
        # Unschedule scans
        Clock.unschedule(self.scheduled_scan)

    def scheduled_scan(self, dt):
        """Scheduled scan callback"""
        if self.monitoring:
            self.run_scan(None)

    def run_scan(self, instance):
        """Run a security scan"""
        self.status_label.text = '🔍 Scanning...'
        
        # Perform scan in background
        scan_results = self.agent.perform_mobile_scan()
        
        # Send results
        success = self.agent.send_scan_results(scan_results)
        
        # Update status
        threats_found = scan_results.get('statistics', {}).get('total_threats', 0)
        if success:
            self.status_label.text = f'✅ Scan complete: {threats_found} threats found'
        else:
            self.status_label.text = '❌ Scan failed - check connection'
        
        # Show notification
        if MOBILE_AVAILABLE:
            notification.notify(
                title='CyberNova Security',
                message=f'Scan complete: {threats_found} threats found',
                timeout=5
            )

def main():
    """Main entry point"""
    if len(sys.argv) > 1 and sys.argv[1] == "--gui" and MOBILE_AVAILABLE:
        # Run mobile app with GUI
        CyberNovaMobileApp().run()
    else:
        # Run command-line version
        agent = CyberNovaMobileAgent()
        
        print("🛡️ CyberNova Mobile Security Agent")
        print("==================================")
        print("1. Run single scan")
        print("2. Start continuous monitoring")
        print("3. Exit")
        
        while True:
            try:
                choice = input("\nSelect option (1-3): ").strip()
                
                if choice == "1":
                    print("🔍 Running security scan...")
                    scan_results = agent.perform_mobile_scan()
                    agent.send_scan_results(scan_results)
                    
                elif choice == "2":
                    agent.run_continuous_monitoring()
                    
                elif choice == "3":
                    print("👋 Goodbye!")
                    break
                    
                else:
                    print("❌ Invalid option. Please select 1-3.")
                    
            except KeyboardInterrupt:
                print("\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
