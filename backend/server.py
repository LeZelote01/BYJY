#!/usr/bin/env python3
"""
CyberSec Assistant Portable - Backend Server V1.3
Features: Complete Database System, Import/Export, Backup, Encryption
Architecture: FastAPI + Advanced SQLite + WebSocket + Portable Design
"""

import os
import sys
import sqlite3
import json
import asyncio
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
import logging
import psutil
import platform
import time

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn

# Import new database system
import database_manager
import database_api
import stealth_api

# Import des modules de furtivité
from stealth_engine import get_global_stealth_engine
from proxy_manager import get_global_proxy_manager

# Portable path detection
PORTABLE_DIR = Path(__file__).parent.parent.absolute()
DATABASE_PATH = PORTABLE_DIR / "data" / "cybersec.db"
LOGS_PATH = PORTABLE_DIR / "logs"

# Ensure directories exist
DATABASE_PATH.parent.mkdir(exist_ok=True)
LOGS_PATH.mkdir(exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOGS_PATH / "backend.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize database manager
db_manager = database_manager.get_database_manager(str(DATABASE_PATH))

# Database initialization (using new database manager)
def init_database():
    """Initialize database using the new database manager"""
    try:
        # Database manager handles all initialization
        logger.info("Database manager initialized with complete schema")
        return True
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        return False

# Background task for system monitoring
async def system_monitoring_task():
    """Background task to monitor system and broadcast updates"""
    while True:
        try:
            metrics = get_system_metrics()
            processes = get_running_processes()
            
            monitoring_data = {
                "type": "system_update",
                "timestamp": datetime.now().isoformat(),
                "metrics": metrics,
                "processes": processes[:10]  # Top 10 for real-time
            }
            
            await manager.broadcast(json.dumps(monitoring_data))
            await asyncio.sleep(5)  # Update every 5 seconds
            
        except Exception as e:
            logger.error(f"System monitoring error: {e}")
            await asyncio.sleep(10)

# Lifespan event handler (replaces deprecated on_event)
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    # Startup
    logger.info("Starting CyberSec Assistant Portable Backend v1.3...")
    logger.info(f"Portable directory: {PORTABLE_DIR}")
    logger.info(f"Database path: {DATABASE_PATH}")
    
    # Initialize database
    if init_database():
        logger.info("✅ Complete database system initialized successfully")
    else:
        logger.error("❌ Database initialization failed")
    
    
    # Initialize stealth systems
    try:
        stealth_engine = get_global_stealth_engine()
        proxy_manager = get_global_proxy_manager()
        logger.info("✅ Stealth systems initialized successfully")
        
        # Log stealth capabilities
        stealth_status = stealth_engine.get_stealth_status()
        proxy_stats = proxy_manager.get_proxy_statistics()
        
        logger.info(f"🕵️ Stealth Level: {stealth_status.get('stealth_level', 'unknown')}/10")
        logger.info(f"🔄 Active Proxies: {proxy_stats.get('active_proxies', 0)}/{proxy_stats.get('total_proxies', 0)}")
        logger.info(f"🛡️ Tor Available: {proxy_stats.get('tor_available', False)}")
        
    except Exception as e:
        logger.error(f"❌ Stealth systems initialization failed: {e}")
    
    # Log database statistics
    stats = db_manager.get_database_stats()
    logger.info(f"📊 Database stats: {stats.get('total_records', 0)} total records across {len(stats.get('tables', {}))} tables")
        
    # Check system compatibility
    system_info = {
        "platform": sys.platform,
        "python_version": sys.version,
        "portable_dir": str(PORTABLE_DIR),
        "database_path": str(DATABASE_PATH),
        "database_features": ["import_export", "auto_backup", "compression", "encryption"]
    }
    logger.info(f"System info: {system_info}")
    
    # Start system monitoring background task
    asyncio.create_task(system_monitoring_task())
    logger.info("✅ System monitoring started")
    
    yield  # Application runs here
    
    # Shutdown
    logger.info("Shutting down CyberSec Assistant Portable Backend...")

# FastAPI app with lifespan handler
app = FastAPI(
    title="CyberSec Assistant Portable",
    description="Comprehensive portable cybersecurity toolkit with advanced database",
    version="1.3.0",
    lifespan=lifespan
)

# Include database management routes
app.include_router(database_api.router)

# Include stealth management routes
app.include_router(stealth_api.router)

# Include stealth control routes (nouveau)
try:
    import stealth_control_api
    app.include_router(stealth_control_api.router)
    logger.info("✅ Stealth Control API routes loaded")
except ImportError as e:
    logger.warning(f"⚠️ Stealth Control API not available: {e}")

# Include evasion management routes
try:
    import evasion_api
    app.include_router(evasion_api.router)
    logger.info("✅ Evasion API routes loaded")
except ImportError as e:
    logger.warning(f"⚠️ Evasion API not available: {e}")

# Include integration management routes
try:
    import integration_api
    app.include_router(integration_api.router)
    logger.info("✅ Integration API routes loaded")
except ImportError as e:
    logger.warning(f"⚠️ Integration API not available: {e}")

# Include reconnaissance routes
try:
    import reconnaissance_api
    app.include_router(reconnaissance_api.router)
    logger.info("✅ Reconnaissance API routes loaded")
except ImportError as e:
    logger.warning(f"⚠️ Reconnaissance API not available: {e}")

# Include brute force routes  
try:
    import bruteforce_api
    app.include_router(bruteforce_api.router)
    logger.info("✅ Brute Force API routes loaded")
except ImportError as e:
    logger.warning(f"⚠️ Brute Force API not available: {e}")

# Include vulnerability scanner routes
try:
    import vulnerability_api
    app.include_router(vulnerability_api.router)
    logger.info("✅ Vulnerability Scanner API routes loaded")
except ImportError as e:
    logger.warning(f"⚠️ Vulnerability Scanner API not available: {e}")

# Include configuration analysis routes
try:
    import config_analysis_api
    app.include_router(config_analysis_api.router)
    logger.info("✅ Configuration Analysis API routes loaded")
except ImportError as e:
    logger.warning(f"⚠️ Configuration Analysis API not available: {e}")
except Exception as e:
    logger.error(f"❌ Failed to load Configuration Analysis API: {e}")

# Include web vulnerability scanner routes
try:
    import web_vulnerability_api
    app.include_router(web_vulnerability_api.router)
    logger.info("✅ Web Vulnerability Scanner API routes loaded")
except ImportError as e:
    logger.warning(f"⚠️ Web Vulnerability Scanner API not available: {e}")
except Exception as e:
    logger.error(f"❌ Failed to load Web Vulnerability Scanner API: {e}")

# Include forensics analysis routes
try:
    import forensics_api
    app.include_router(forensics_api.forensics_router)
    logger.info("✅ Forensics Analysis API routes loaded")
except ImportError as e:
    logger.warning(f"⚠️ Forensics Analysis API not available: {e}")
except Exception as e:
    logger.error(f"❌ Failed to load Forensics Analysis API: {e}")

# Include exploitation framework routes
try:
    import exploitation_api
    app.include_router(exploitation_api.router)
    logger.info("✅ Exploitation Framework API routes loaded")
except ImportError as e:
    logger.warning(f"⚠️ Exploitation Framework API not available: {e}")
except Exception as e:
    logger.error(f"❌ Failed to load Exploitation Framework API: {e}")

# Include user proxy configuration routes
try:
    import proxy_user_config_api
    app.include_router(proxy_user_config_api.router)
    logger.info("✅ User Proxy Configuration API routes loaded")
except ImportError as e:
    logger.warning(f"⚠️ User Proxy Configuration API not available: {e}")
except Exception as e:
    logger.error(f"❌ Failed to load User Proxy Configuration API: {e}")

# CORS configuration for portable use
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables for real-time monitoring
active_processes = {}
websocket_connections = []

# Database Models
class ScanResult(BaseModel):
    id: Optional[int] = None
    scan_type: str
    target: str
    status: str
    results: Dict[str, Any]
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

class SystemConfig(BaseModel):
    key: str
    value: Any
    description: Optional[str] = None

class TerminalCommand(BaseModel):
    command: str
    working_directory: Optional[str] = None

# Database helper functions (legacy compatibility)
def get_db_connection():
    """Get database connection (legacy compatibility)"""
    return db_manager.get_connection()

# System monitoring functions
def get_system_metrics():
    """Get current system metrics"""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage(str(PORTABLE_DIR))
        
        return {
            "cpu": {
                "percent": cpu_percent,
                "count": psutil.cpu_count(),
                "freq": psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None
            },
            "memory": {
                "total": memory.total,
                "available": memory.available,
                "percent": memory.percent,
                "used": memory.used
            },
            "disk": {
                "total": disk.total,
                "used": disk.used,
                "free": disk.free,
                "percent": (disk.used / disk.total) * 100
            },
            "network": dict(psutil.net_io_counters()._asdict()) if psutil.net_io_counters() else {},
            "boot_time": psutil.boot_time(),
            "uptime": time.time() - psutil.boot_time()
        }
    except Exception as e:
        logger.error(f"Failed to get system metrics: {e}")
        return {}

def get_running_processes():
    """Get list of running processes"""
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'create_time']):
            try:
                process_info = proc.info
                process_info['cpu_percent'] = proc.cpu_percent()
                process_info['memory_percent'] = proc.memory_percent()
                processes.append(process_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Sort by CPU usage
        processes.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
        return processes[:50]  # Top 50 processes
        
    except Exception as e:
        logger.error(f"Failed to get processes: {e}")
        return []

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")

    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            self.disconnect(websocket)

    async def broadcast(self, message: str):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error(f"Failed to broadcast message: {e}")
                disconnected.append(connection)
        
        # Remove disconnected connections
        for connection in disconnected:
            self.disconnect(connection)

manager = ConnectionManager()

# API Routes

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "CyberSec Assistant Portable API",
        "version": "1.3.0",
        "status": "operational", 
        "features": ["terminal", "monitoring", "logs", "database_management", "import_export", "auto_backup", "stealth_engine", "proxy_management", "obfuscation"],
        "stealth_features": ["anti_detection", "proxy_rotation", "code_obfuscation", "tor_integration", "forensics_cleanup"],
        "database_features": ["complete_schema", "encryption", "compression", "integrity_checks"],
        "portable_dir": str(PORTABLE_DIR),
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/health")
async def health_check():
    """Health check endpoint with database verification"""
    try:
        # Test database connection and get stats
        stats = db_manager.get_database_stats()
        
        # Run integrity check
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA integrity_check")
            integrity = cursor.fetchone()[0] == "ok"
        
        return {
            "status": "healthy",
            "version": "1.3.0",
            "database": {
                "connected": True,
                "integrity": "ok" if integrity else "corrupted",
                "total_records": stats.get("total_records", 0),
                "tables_count": len(stats.get("tables", {})),
                "size_bytes": stats.get("database_size", 0)
            },
            "portable_dir": str(PORTABLE_DIR),
            "features": ["terminal", "monitoring", "logs", "database_management", "import_export", "stealth_engine"],
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Health check failed: {e}")

@app.get("/api/system/info")
async def get_system_info():
    """Get system information"""
    return {
        "platform": sys.platform,
        "platform_release": platform.release(),
        "platform_machine": platform.machine(),
        "python_version": sys.version,
        "portable_dir": str(PORTABLE_DIR),
        "database_path": str(DATABASE_PATH),
        "logs_path": str(LOGS_PATH),
        "disk_usage": {
            "total": "N/A",  # TODO: Implement disk usage calculation
            "used": "N/A",
            "free": "N/A"
        }
    }

@app.get("/api/system/metrics")
async def get_system_metrics_api():
    """Get current system metrics"""
    metrics = get_system_metrics()
    return {
        "metrics": metrics,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/system/processes")
async def get_processes_api():
    """Get running processes"""
    processes = get_running_processes()
    return {
        "processes": processes,
        "count": len(processes),
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/config")
async def get_config():
    """Get system configuration"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT key, value, description FROM system_config")
        configs = cursor.fetchall()
        conn.close()
        
        return {
            "configs": [dict(config) for config in configs]
        }
    except Exception as e:
        logger.error(f"Failed to get config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get config: {e}")

@app.post("/api/config")
async def update_config(config: SystemConfig):
    """Update system configuration"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO system_config (key, value, description, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        """, (config.key, json.dumps(config.value), config.description))
        conn.commit()
        conn.close()
        
        logger.info(f"Configuration updated: {config.key}")
        return {"message": "Configuration updated successfully"}
        
    except Exception as e:
        logger.error(f"Failed to update config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update config: {e}")

@app.get("/api/scans")
async def get_scans():
    """Get all scan results from various scan tables"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get port scans
        cursor.execute("""
            SELECT id, scan_id as scan_type, target, state as status, 
                   CASE WHEN service IS NOT NULL THEN json_object('service', service, 'version', version, 'banner', banner) 
                        ELSE '{}' END as results, 
                   created_at, created_at as updated_at
            FROM port_scans
            ORDER BY created_at DESC
            LIMIT 50
        """)
        port_scans = cursor.fetchall()
        
        # Get network discovery
        cursor.execute("""
            SELECT id, 'network_discovery' as scan_type, ip_address as target, 
                   status, '{}' as results, created_at, created_at as updated_at
            FROM network_discovery
            ORDER BY created_at DESC
            LIMIT 50
        """)
        network_scans = cursor.fetchall()
        
        conn.close()
        
        all_scans = []
        
        # Process port scans
        for scan in port_scans:
            try:
                results = json.loads(scan["results"]) if scan["results"] else {}
            except:
                results = {}
            
            all_scans.append({
                "id": scan["id"],
                "scan_type": scan["scan_type"] or "port_scan",
                "target": scan["target"],
                "status": scan["status"] or "unknown",
                "results": results,
                "created_at": scan["created_at"],
                "updated_at": scan["updated_at"]
            })
        
        # Process network scans
        for scan in network_scans:
            all_scans.append({
                "id": f"net_{scan['id']}",
                "scan_type": scan["scan_type"],
                "target": scan["target"],
                "status": scan["status"],
                "results": {},
                "created_at": scan["created_at"],
                "updated_at": scan["updated_at"]
            })
        
        # Sort by created_at
        all_scans.sort(key=lambda x: x["created_at"] or "", reverse=True)
        
        return {
            "scans": all_scans[:100]  # Limit to 100 total
        }
    except Exception as e:
        logger.error(f"Failed to get scans: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get scans: {e}")

@app.post("/api/scans")
async def create_scan(scan: ScanResult):
    """Create new scan result"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Insert into appropriate table based on scan type
        if scan.scan_type in ['port_scan', 'nmap']:
            cursor.execute("""
                INSERT INTO port_scans (scan_id, target, port, status, service, version, results, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (scan.scan_type, scan.target, 0, scan.status, '', '', json.dumps(scan.results)))
        else:
            # Default to port_scans table for now
            cursor.execute("""
                INSERT INTO port_scans (scan_id, target, port, status, service, version, results, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (scan.scan_type, scan.target, 0, scan.status, '', '', json.dumps(scan.results)))
        
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        logger.info(f"Scan created: {scan_id}")
        return {"message": "Scan created successfully", "scan_id": scan_id}
        
    except Exception as e:
        logger.error(f"Failed to create scan: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create scan: {e}")

@app.get("/api/tools/status")
async def get_tools_status():
    """Get status of all security tools"""
    try:
        # TODO: Implement tool detection logic
        tools = [
            {"name": "nmap", "status": "checking", "version": "unknown"},
            {"name": "hashcat", "status": "checking", "version": "unknown"},
            {"name": "john", "status": "checking", "version": "unknown"},
            {"name": "aircrack-ng", "status": "checking", "version": "unknown"},
        ]
        
        return {"tools": tools}
        
    except Exception as e:
        logger.error(f"Failed to get tools status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get tools status: {e}")

@app.get("/api/logs")
async def get_logs(lines: int = 100, level: str = None, search: str = None):
    """Get application logs with filtering"""
    try:
        log_file = LOGS_PATH / "backend.log"
        if not log_file.exists():
            return {"logs": [], "total_lines": 0, "filtered_lines": 0}
            
        with open(log_file, 'r') as f:
            all_lines = f.readlines()
        
        # Apply filters
        filtered_lines = all_lines
        
        if level:
            level_upper = level.upper()
            filtered_lines = [line for line in filtered_lines if level_upper in line]
        
        if search:
            search_lower = search.lower()
            filtered_lines = [line for line in filtered_lines if search_lower in line.lower()]
        
        # Get recent lines
        recent_lines = filtered_lines[-lines:] if len(filtered_lines) > lines else filtered_lines
        
        return {
            "logs": [
                {
                    "timestamp": line.split(" - ")[0] if " - " in line else "unknown",
                    "level": line.split(" - ")[2] if len(line.split(" - ")) > 2 else "unknown",
                    "message": line.strip(),
                    "raw": line.strip()
                }
                for line in recent_lines
            ],
            "total_lines": len(all_lines),
            "filtered_lines": len(filtered_lines),
            "returned_lines": len(recent_lines)
        }
        
    except Exception as e:
        logger.error(f"Failed to get logs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get logs: {e}")

@app.post("/api/terminal/execute")
async def execute_terminal_command(command: TerminalCommand):
    """Execute terminal command and return results"""
    try:
        start_time = time.time()
        working_dir = command.working_directory or str(PORTABLE_DIR)
        
        # Security: Basic command validation
        dangerous_commands = ['rm -rf', 'del /f', 'format', 'fdisk', 'dd if=']
        if any(dangerous in command.command.lower() for dangerous in dangerous_commands):
            raise HTTPException(status_code=400, detail="Dangerous command blocked for security")
        
        # Execute command
        process = subprocess.run(
            command.command,
            shell=True,
            cwd=working_dir,
            capture_output=True,
            text=True,
            timeout=30  # 30 second timeout
        )
        
        execution_time = time.time() - start_time
        
        # Save to database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO terminal_history (command, working_directory, output, exit_code, execution_time)
            VALUES (?, ?, ?, ?, ?)
        """, (command.command, working_dir, process.stdout + process.stderr, process.returncode, execution_time))
        conn.commit()
        conn.close()
        
        return {
            "command": command.command,
            "working_directory": working_dir,
            "stdout": process.stdout,
            "stderr": process.stderr,
            "exit_code": process.returncode,
            "execution_time": execution_time,
            "timestamp": datetime.now().isoformat()
        }
        
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Command timed out after 30 seconds")
    except Exception as e:
        logger.error(f"Failed to execute command: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to execute command: {e}")

@app.get("/api/terminal/history")
async def get_terminal_history(limit: int = 50):
    """Get terminal command history"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT command, working_directory, output, exit_code, execution_time, created_at
            FROM terminal_history
            ORDER BY created_at DESC
            LIMIT ?
        """, (limit,))
        history = cursor.fetchall()
        conn.close()
        
        return {
            "history": [
                {
                    "command": record["command"],
                    "working_directory": record["working_directory"],
                    "output": record["output"],
                    "exit_code": record["exit_code"],
                    "execution_time": record["execution_time"],
                    "timestamp": record["created_at"]
                }
                for record in history
            ]
        }
        
    except Exception as e:
        logger.error(f"Failed to get terminal history: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get terminal history: {e}")

# WebSocket endpoints
@app.websocket("/ws/terminal")
async def websocket_terminal(websocket: WebSocket):
    """WebSocket endpoint for real-time terminal"""
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            command_data = json.loads(data)
            
            # Execute command (simplified for WebSocket)
            try:
                result = subprocess.run(
                    command_data.get("command", ""),
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                response = {
                    "type": "command_result",
                    "command": command_data.get("command"),
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "exit_code": result.returncode,
                    "timestamp": datetime.now().isoformat()
                }
                
                await manager.send_personal_message(json.dumps(response), websocket)
                
            except Exception as e:
                error_response = {
                    "type": "error",
                    "message": str(e),
                    "timestamp": datetime.now().isoformat()
                }
                await manager.send_personal_message(json.dumps(error_response), websocket)
    
    except Exception as e:
        logger.error(f"WebSocket terminal error: {e}")
    finally:
        manager.disconnect(websocket)

@app.websocket("/ws/monitoring")
async def websocket_monitoring(websocket: WebSocket):
    """WebSocket endpoint for real-time system monitoring"""
    await manager.connect(websocket)
    try:
        while True:
            # This connection will receive broadcast updates from the background task
            await asyncio.sleep(1)
    except Exception as e:
        logger.error(f"WebSocket monitoring error: {e}")
    finally:
        manager.disconnect(websocket)

if __name__ == "__main__":
    # Portable server configuration
    port = int(os.environ.get("PORT", 8001))
    host = "127.0.0.1"  # Bind to localhost for security
    
    logger.info(f"Starting server on {host}:{port}")
    logger.info(f"Portable directory: {PORTABLE_DIR}")
    
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
        reload=False  # Disable reload for portable use
    )