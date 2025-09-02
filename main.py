# CyberNova AI - Database-Free Beta Testing Platform
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import os, json, smtplib, ssl, time, logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from starlette.responses import StreamingResponse
from pydantic import BaseModel, EmailStr

app = FastAPI(
    title="CyberNova AI - Beta Testing Platform", 
    version="1.0",
    description="Database-Free Beta Testing Platform"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True, 
    allow_methods=["*"], 
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO)

# Email Configuration
EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
EMAIL_USER = os.getenv("EMAIL_USER", "cybernova073@gmail.com")
EMAIL_PASS = os.getenv("EMAIL_PASS", "hsrz fymn gplp enbp")

# File-based storage (only emails - scan data is real-time only)
EMAILS_FILE = "beta_emails.json"

# Global variable to store latest scan data (in-memory for beta testing)
latest_scan_data = None
latest_alerts_data = []

# Pydantic Models
class BetaSignup(BaseModel):
    email: EmailStr

# File Storage Functions
def load_emails():
    """Load beta emails from file"""
    try:
        if os.path.exists(EMAILS_FILE):
            with open(EMAILS_FILE, 'r') as f:
                return json.load(f)
        return []
    except:
        return []

def save_email(email: str):
    """Save email to file"""
    try:
        emails = load_emails()
        # Check if email already exists
        for entry in emails:
            if entry["email"] == email:
                return False
        
        # Add new email
        emails.append({
            "email": email,
            "timestamp": datetime.now().isoformat(),
            "downloaded_agent": False
        })
        
        with open(EMAILS_FILE, 'w') as f:
            json.dump(emails, f, indent=2)
        return True
    except Exception as e:
        logging.error(f"Error saving email: {e}")
        return False

def mark_agent_downloaded(email: str):
    """Mark that user downloaded the agent"""
    try:
        emails = load_emails()
        for entry in emails:
            if entry["email"] == email:
                entry["downloaded_agent"] = True
                entry["download_timestamp"] = datetime.now().isoformat()
                break
        
        with open(EMAILS_FILE, 'w') as f:
            json.dump(emails, f, indent=2)
        return True
    except Exception as e:
        logging.error(f"Error marking download: {e}")
        return False

def get_beta_stats():
    """Get beta testing statistics"""
    try:
        emails = load_emails()
        total_signups = len(emails)
        downloads = sum(1 for entry in emails if entry.get("downloaded_agent", False))
        return {
            "total_signups": total_signups,
            "agent_downloads": downloads,
            "conversion_rate": round((downloads / total_signups * 100) if total_signups > 0 else 0, 2)
        }
    except:
        return {"total_signups": 0, "agent_downloads": 0, "conversion_rate": 0}



def send_email(to_email: str, subject: str, body: str):
    """Send email via SMTP"""
    if not all([EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASS]):
        logging.warning("Email not configured")
        return False

    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_USER
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "html"))

        context = ssl.create_default_context()
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls(context=context)
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_USER, to_email, msg.as_string())
        
        logging.info(f"Email sent to {to_email}")
        return True
    except Exception as e:
        logging.error(f"Failed to send email: {e}")
        return False

# API Endpoints
@app.post("/api/beta-signup")
async def beta_signup(signup_data: BetaSignup, background_tasks: BackgroundTasks):
    """Beta testing signup - File-based storage"""
    try:
        # Check if email already exists
        emails = load_emails()
        existing_email = any(entry["email"] == signup_data.email for entry in emails)
        
        if existing_email:
            return {"message": "Email already registered for beta testing!", "status": "exists"}
        
        # Save email to file
        if save_email(signup_data.email):
            # Send beta access email
            email_subject = "🚀 Welcome to CyberNova AI Beta Testing!"
            email_body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h1 style="color: #1976d2; text-align: center;">🛡️ Welcome to CyberNova AI Beta!</h1>
                    
                    <p>Thank you for joining our exclusive beta testing program! You're now part of an elite group testing the future of cybersecurity.</p>
                    
                    <div style="background: #e3f2fd; padding: 20px; border-radius: 8px; margin: 20px 0; text-align: center;">
                        <h2 style="color: #1976d2; margin: 0 0 15px 0;">🚀 Beta Testing Access</h2>
                        <div style="background: #fff; padding: 15px; border-radius: 5px; margin: 10px 0; border: 2px solid #1976d2;">
                            <h3 style="color: #1976d2; margin: 0 0 10px 0;">🔗 Universal Installer (Recommended)</h3>
                            <p style="margin: 5px 0;"><strong>1-Click Installation for ALL Devices</strong></p>
                            <a href="http://localhost:8080/universal-installer" 
                               style="display: inline-block; background: #1976d2; color: white; padding: 12px 24px; 
                                      text-decoration: none; border-radius: 5px; font-weight: bold; margin: 10px 0;">
                                🚀 Install & Run Agent (1-Click)
                            </a>
                            <p style="margin: 5px 0; font-size: 14px; color: #666;">
                                Auto-detects your device • Windows, Mac, Linux, Android, iOS
                            </p>
                        </div>
                        <p style="margin: 15px 0 5px 0; color: #666; font-size: 14px;">Alternative Downloads:</p>
                        <p style="margin: 5px 0;"><a href="http://localhost:8080/agent-download?email={signup_data.email}" style="color: #1976d2;">Direct Agent Download</a></p>
                        <p style="margin: 5px 0;"><a href="http://localhost:8080/installer-download?email={signup_data.email}" style="color: #1976d2;">Python Installer</a></p>
                    </div>
                    
                    <h3 style="color: #1976d2;">🔧 Getting Started (3 Simple Steps):</h3>
                    <ol>
                        <li><strong>Click Universal Installer:</strong> Use the 1-click installer above (works on ALL devices)</li>
                        <li><strong>Install & Run:</strong> Agent installs and starts automatically</li>
                        <li><strong>Start Scanning:</strong> Click "Start Security Scan" to see your device's security status</li>
                    </ol>
                    
                    <div style="background: #e8f5e8; padding: 15px; border-radius: 8px; margin: 15px 0;">
                        <h4 style="color: #2e7d32; margin: 0 0 10px 0;">✨ What Happens After Installation:</h4>
                        <p style="margin: 5px 0;">• Agent starts monitoring your device immediately</p>
                        <p style="margin: 5px 0;">• Click "Start Security Scan" to see real-time results</p>
                        <p style="margin: 5px 0;">• View live dashboard with your device's security data</p>
                        <p style="margin: 5px 0;">• Agent auto-starts with your system</p>
                    </div>
                    
                    <h3 style="color: #1976d2;">🛡️ What You'll Experience:</h3>
                    <ul>
                        <li>Real-time threat detection and analysis</li>
                        <li>Process and network monitoring</li>
                        <li>AI-powered security recommendations</li>
                        <li>Automated security scanning</li>
                        <li>Intelligent threat filtering</li>
                    </ul>
                    
                    <div style="background: #fff3e0; padding: 15px; border-radius: 8px; margin: 20px 0;">
                        <h3 style="color: #f57c00; margin: 0;">⚠️ Beta Testing Guidelines:</h3>
                        <p style="margin: 10px 0;">• This is a beta version - expect some rough edges</p>
                        <p style="margin: 10px 0;">• Your feedback is crucial for improvement</p>
                        <p style="margin: 10px 0;">• Report any issues to cybernova073@gmail.com</p>
                        <p style="margin: 10px 0;">• Agent runs locally on your device</p>
                    </div>
                    
                    <p style="text-align: center; margin: 30px 0;">
                        <strong>Questions or need help?</strong><br>
                        Email us at <a href="mailto:cybernova073@gmail.com" style="color: #1976d2;">cybernova073@gmail.com</a>
                    </p>
                    
                    <div style="text-align: center; padding: 20px; background: #f5f5f5; border-radius: 8px;">
                        <p style="margin: 0; color: #666;">Thank you for being part of the CyberNova AI journey!</p>
                        <p style="margin: 5px 0 0 0; color: #666;">🚀 The CyberNova Team</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            background_tasks.add_task(send_email, signup_data.email, email_subject, email_body)
            
            return {"message": "Successfully registered for beta testing! Check your email for access details.", "status": "success"}
        else:
            raise HTTPException(status_code=500, detail="Failed to save email")
        
    except Exception as e:
        logging.error(f"Beta signup error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to register for beta testing: {str(e)}")

@app.get("/agent-download")
async def download_agent(email: str = None):
    """Download CyberNova agent for device installation"""
    try:
        # Mark agent as downloaded if email provided
        if email:
            mark_agent_downloaded(email)
        
        # Read the agent file
        agent_path = "cybernova_agent.py"
        if not os.path.exists(agent_path):
            raise HTTPException(status_code=404, detail="Agent file not found")
        
        with open(agent_path, 'r', encoding='utf-8') as f:
            agent_content = f.read()
        
        # Return as downloadable file
        def generate():
            yield agent_content.encode('utf-8')
        
        return StreamingResponse(
            generate(),
            media_type='application/octet-stream',
            headers={"Content-Disposition": "attachment; filename=cybernova_agent.py"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to download agent: {str(e)}")

@app.get("/installer-download")
async def download_installer(email: str = None, type: str = "python"):
    """Download platform-specific CyberNova installer"""
    try:
        # Mark agent as downloaded if email provided
        if email:
            mark_agent_downloaded(email)
        
        # Determine installer file based on type
        installer_files = {
            "python": "install_agent.py",
            "windows": "install_cybernova.bat",
            "powershell": "install_cybernova.ps1",
            "unix": "install_cybernova.sh",
            "macos": "install_cybernova.sh",
            "linux": "install_cybernova.sh"
        }
        
        installer_path = installer_files.get(type, "install_agent.py")
        
        if not os.path.exists(installer_path):
            raise HTTPException(status_code=404, detail=f"Installer file not found: {installer_path}")
        
        # Read the installer file
        with open(installer_path, 'r', encoding='utf-8') as f:
            installer_content = f.read()
        
        # Set appropriate filename and media type
        filename_map = {
            "python": "install_cybernova.py",
            "windows": "install_cybernova.bat",
            "powershell": "install_cybernova.ps1",
            "unix": "install_cybernova.sh",
            "macos": "install_cybernova.sh",
            "linux": "install_cybernova.sh"
        }
        
        filename = filename_map.get(type, "install_cybernova.py")
        
        # Return as downloadable file
        def generate():
            yield installer_content.encode('utf-8')
        
        return StreamingResponse(
            generate(),
            media_type='application/octet-stream',
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to download installer: {str(e)}")

@app.get("/universal-installer")
async def universal_installer():
    """Serve the universal web-based installer"""
    try:
        installer_path = "universal_installer.html"
        if not os.path.exists(installer_path):
            raise HTTPException(status_code=404, detail="Universal installer not found")
        
        with open(installer_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        return StreamingResponse(
            iter([html_content.encode('utf-8')]),
            media_type='text/html'
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to serve universal installer: {str(e)}")

@app.get("/api/beta-stats")
async def get_beta_statistics():
    """Get beta testing statistics"""
    try:
        stats = get_beta_stats()
        return stats
    except Exception as e:
        logging.error(f"Error getting beta stats: {e}")
        return {"total_signups": 0, "agent_downloads": 0, "conversion_rate": 0}

@app.get("/api/dashboard/stats")
async def get_dashboard_stats():
    """Get dashboard statistics - ONLY real data from agent scans"""
    global latest_scan_data
    
    if latest_scan_data:
        # Return real scan data from user's device
        threats_count = len(latest_scan_data.get("threats", []))
        network_connections = len(latest_scan_data.get("network_connections", []))
        risky_ports = len(latest_scan_data.get("risky_ports", []))
        
        total_threats = threats_count
        active_alerts = threats_count + len([conn for conn in latest_scan_data.get("network_connections", []) if conn.get("threat_level") in ["high", "critical"]])
        
        # Calculate risk score based on real threats
        risk_score = min((threats_count * 15) + (risky_ports * 10), 100)
        system_health = max(100 - risk_score, 0)
        
        return {
            "totalThreats": total_threats,
            "activeAlerts": active_alerts,
            "riskScore": risk_score,
            "systemHealth": system_health,
            "lastScanTime": latest_scan_data.get("timestamp"),
            "scanStatus": "completed" if latest_scan_data else "No scans yet"
        }
    else:
        # No real data available - return empty state
        return {
            "totalThreats": 0,
            "activeAlerts": 0,
            "riskScore": 0,
            "systemHealth": 100,
            "lastScanTime": None,
            "scanStatus": "No scans yet - Run agent to see real data"
        }

@app.get("/api/dashboard/alerts")
async def get_dashboard_alerts():
    """Get dashboard alerts - ONLY real alerts from agent scans"""
    global latest_alerts_data
    
    # Return only real alerts from actual scans
    return latest_alerts_data

@app.post("/agent-data")
async def receive_agent_data(scan_data: dict):
    """Receive REAL scan data from CyberNova agents"""
    global latest_scan_data, latest_alerts_data
    
    try:
        # Store the real scan data in memory
        latest_scan_data = {
            "timestamp": datetime.now().isoformat(),
            "threats": scan_data.get("threats", []),
            "network_connections": scan_data.get("network_connections", []),
            "risky_ports": scan_data.get("risky_ports", []),
            "system_info": scan_data.get("system_info", {}),
            "recommendations": scan_data.get("recommendations", [])
        }
        
        # Generate real alerts from the scan data
        alerts = []
        
        # Process suspicious processes
        for threat in scan_data.get("threats", []):
            alerts.append({
                "id": f"threat_{threat.get('pid', 'unknown')}_{int(time.time())}",
                "title": f"Suspicious Process: {threat.get('name', 'Unknown')}",
                "description": f"Process {threat.get('name')} (PID: {threat.get('pid')}) detected with threat level: {threat.get('threat_level', 'unknown')}",
                "severity": threat.get("threat_level", "low"),
                "timestamp": datetime.now().isoformat(),
                "sourceIp": "Local System",
                "riskScore": {"critical": 90, "high": 70, "medium": 50, "low": 30}.get(threat.get("threat_level", "low"), 30),
                "isBlocked": False,
                "type": "process",
                "details": threat.get("threat_reasons", [])
            })
        
        # Process risky ports
        for port in scan_data.get("risky_ports", []):
            alerts.append({
                "id": f"port_{port.get('port')}_{int(time.time())}",
                "title": f"Risky Port: {port.get('port')} ({port.get('service', 'Unknown')})",
                "description": f"Port {port.get('port')} is open and may pose a security risk: {port.get('reason', 'Unknown reason')}",
                "severity": port.get("threat_level", "medium"),
                "timestamp": datetime.now().isoformat(),
                "sourceIp": "Local System",
                "riskScore": {"critical": 80, "high": 60, "medium": 40, "low": 20}.get(port.get("threat_level", "medium"), 40),
                "isBlocked": False,
                "type": "network",
                "details": port.get("recommendation", "")
            })
        
        # Process suspicious network connections
        for conn in scan_data.get("network_connections", []):
            if conn.get("threat_level") in ["high", "critical"]:
                alerts.append({
                    "id": f"network_{conn.get('remote_ip', 'unknown')}_{int(time.time())}",
                    "title": f"Suspicious Network Activity",
                    "description": f"Suspicious connection to {conn.get('remote_ip')}:{conn.get('remote_port')} - {conn.get('activity_description', 'Unknown activity')}",
                    "severity": conn.get("threat_level", "medium"),
                    "timestamp": datetime.now().isoformat(),
                    "sourceIp": conn.get("remote_ip", "Unknown"),
                    "riskScore": {"critical": 85, "high": 65}.get(conn.get("threat_level", "medium"), 50),
                    "isBlocked": False,
                    "type": "network",
                    "details": conn.get("activity_description", "")
                })
        
        # Store the real alerts
        latest_alerts_data = alerts
        
        threats_count = len(scan_data.get('threats', []))
        logging.info(f"Processed real scan data: {threats_count} threats, {len(alerts)} alerts generated")
        
        return {
            "status": "success", 
            "message": "Real scan data processed successfully",
            "threats_detected": threats_count,
            "alerts_generated": len(alerts),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logging.error(f"Error processing real agent data: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to process agent data: {str(e)}")

@app.get("/mobile-app/{filename}")
async def download_mobile_app(filename: str):
    """Download mobile apps (APK/IPA)"""
    try:
        # For beta testing, return placeholder or redirect to actual app
        if filename.endswith('.apk'):
            # Android APK download
            return {"message": "Android APK download - Coming soon in beta", "platform": "android"}
        elif filename.endswith('.ipa'):
            # iOS IPA download
            return {"message": "iOS app download - Coming soon in beta", "platform": "ios"}
        else:
            raise HTTPException(status_code=404, detail="Mobile app not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to download mobile app: {str(e)}")

@app.post("/api/scan/trigger")
async def trigger_security_scan(scan_request: dict):
    """Trigger a security scan for the user - returns real data if available"""
    try:
        email = scan_request.get("email", "unknown")
        scan_type = scan_request.get("scan_type", "basic")
        
        # Check if we have real scan data from agent
        global latest_scan_data
        
        if latest_scan_data and latest_scan_data.get("threats") is not None:
            # Return real data from agent
            logging.info(f"Returning real scan data for {email}: {len(latest_scan_data.get('threats', []))} threats")
            
            scan_results = {
                "scan_id": f"real_scan_{int(time.time())}",
                "email": email,
                "timestamp": latest_scan_data.get("timestamp", datetime.now().isoformat()),
                "scan_type": scan_type,
                "status": "completed",
                "threats": latest_scan_data.get("threats", []),
                "system_info": latest_scan_data.get("system_info", {}),
                "network_connections": latest_scan_data.get("network_connections", []),
                "risky_ports": latest_scan_data.get("risky_ports", []),
                "recommendations": latest_scan_data.get("recommendations", [])
            }
            
            return scan_results
        
        else:
            # No real user data available - return empty scan results (NO SERVER DATA)
            logging.info(f"No agent data available for {email}, returning empty scan results")
            
            scan_results = {
                "scan_id": f"no_agent_scan_{int(time.time())}",
                "email": email,
                "timestamp": datetime.now().isoformat(),
                "scan_type": scan_type,
                "status": "no_agent",
                "threats": [],
                "system_info": {
                    "message": "No agent installed on user device",
                    "status": "Install CyberNova agent to see real device data",
                    "data_source": "None - Agent required"
                },
                "network_connections": [],
                "risky_ports": [],
                "recommendations": [
                    "Install CyberNova agent to see real security data from YOUR device",
                    "Agent will monitor your actual system processes and network activity",
                    "No data available without agent installation on your device"
                ]
            }
            
            return scan_results
                return {
                    "scan_id": f"fallback_scan_{int(time.time())}",
                    "email": email,
                    "timestamp": datetime.now().isoformat(),
                    "scan_type": scan_type,
                    "status": "completed",
                    "threats": [],
                    "system_info": {
                        "os": "⚠️ NO AGENT DETECTED", 
                        "status": "Install agent to scan your device",
                        "cpu_percent": 0,
                        "memory_percent": 0,
                        "process_count": 0,
                        "disk_usage": 0,
                        "source": "No real device data available"
                    },
                    "network_connections": [],
                    "risky_ports": [],
                    "recommendations": [
                        "❌ No CyberNova agent detected on your device",
                        "📥 Download and install the agent to scan your actual device", 
                        "🔄 This scan shows no data because no agent is running"
                    ]
                }
        
    except Exception as e:
        logging.error(f"Scan trigger failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to trigger scan: {str(e)}")

@app.get("/api/system/status")
async def get_system_status():
    """Get current system and agent status"""
    try:
        import platform
        from datetime import datetime, timedelta
        
        # Check if we have real agent data
        global latest_scan_data
        agent_active = latest_scan_data is not None and latest_scan_data.get("threats") is not None
        
        # Only show user agent data, no server data
        if agent_active:
            # Use real user data from agent
            system_info = latest_scan_data.get("system_info", {})
            uptime = "Agent Active"
        else:
            # No user data available
            uptime = "No Agent"
            system_info = {
                "message": "No agent installed on user device",
                "status": "Install agent to see real device data"
            }
        
        status_data = {
            "status": "running" if agent_active else "no_agent",
            "agent_active": agent_active,
            "uptime": str(uptime).split('.')[0] if uptime != "Unknown" else "Unknown",
            "last_scan": latest_scan_data.get("timestamp") if latest_scan_data else "Never",
            "system_info": system_info,
            "agent_info": {
                "version": "1.0.0",
                "last_update": datetime.now().strftime("%Y-%m-%d"),
                "scan_interval": 30,
                "auto_start": True,
                "data_received": agent_active,
                "last_data_time": latest_scan_data.get("timestamp") if latest_scan_data else None
            }
        }
        
        return status_data
        
    except Exception as e:
        logging.error(f"System status check failed: {e}")
        # Return a basic status instead of failing
        global latest_scan_data
        agent_active = latest_scan_data is not None and latest_scan_data.get("threats") is not None
        
        return {
            "status": "running" if agent_active else "no_agent",
            "agent_active": agent_active,
            "uptime": "No Agent",
            "last_scan": latest_scan_data.get("timestamp") if latest_scan_data else "Never",
            "system_info": {
                "message": "No agent installed on user device",
                "status": "Install agent to see real device data"
            },
            "agent_info": {
                "version": "1.0.0",
                "last_update": datetime.now().strftime("%Y-%m-%d"),
                "scan_interval": 30,
                "auto_start": True,
                "data_received": agent_active,
                "last_data_time": latest_scan_data.get("timestamp") if latest_scan_data else None
            }
        }

@app.post("/api/agent/install")
async def install_agent(install_request: dict):
    """Handle agent installation request"""
    try:
        email = install_request.get("email", "unknown")
        platform_type = install_request.get("platform", "unknown")
        
        # Log installation attempt
        logging.info(f"Agent installation requested by {email} on {platform_type}")
        
        # In a real implementation, this would:
        # 1. Generate a unique installation token
        # 2. Create installation package
        # 3. Set up user account
        # 4. Configure monitoring
        
        installation_data = {
            "installation_id": f"install_{int(time.time())}",
            "email": email,
            "platform": platform_type,
            "status": "initiated",
            "timestamp": datetime.now().isoformat(),
            "download_url": f"/installer-download?type={platform_type.lower()}",
            "instructions": f"Installation package ready for {platform_type}"
        }
        
        return installation_data
        
    except Exception as e:
        logging.error(f"Agent installation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to install agent: {str(e)}")

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

# Root endpoint
@app.get("/")
async def root():
    return {"message": "CyberNova AI Beta Testing Platform", "version": "1.0"}

# Startup event
@app.on_event("startup")
async def startup_event():
    try:
        print("🚀 CyberNova AI Beta Testing Platform Starting...")
        print("📧 Email Service: cybernova073@gmail.com")
        print("📁 File-based Storage: Ready")
        print("✅ Status: Ready for beta testing")
        
        # Create storage files if they don't exist
        if not os.path.exists(EMAILS_FILE):
            with open(EMAILS_FILE, 'w') as f:
                json.dump([], f)
        
    except Exception as e:
        print(f"❌ Startup failed: {e}")
        raise e

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
