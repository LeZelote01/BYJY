#!/usr/bin/env python3
"""
CyberSec Assistant Portable - Configuration Analyzer V1.0
Phase 4.2: Advanced System Configuration Security Analysis
Architecture: FastAPI + Security Compliance + Stealth Integration
"""

import os
import re
import json
import stat
import pwd
import grp
import subprocess
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
from dataclasses import dataclass, asdict
import configparser
import yaml
import xml.etree.ElementTree as ET

# Import existing modules for integration
from stealth_engine import get_global_stealth_engine
from database_manager import get_database_manager

logger = logging.getLogger(__name__)

@dataclass
class ConfigurationIssue:
    """Configuration security issue data structure"""
    issue_id: str
    severity: str
    title: str
    description: str
    file_path: str
    line_number: Optional[int] = None
    current_value: str = ""
    recommended_value: str = ""
    compliance_frameworks: List[str] = None
    remediation_steps: List[str] = None
    risk_score: float = 0.0

@dataclass
class ConfigurationScan:
    """Configuration scan results"""
    scan_id: str
    target_path: str
    scan_type: str
    status: str
    start_time: datetime
    end_time: Optional[datetime] = None
    total_issues: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    files_analyzed: List[str] = None
    compliance_score: float = 0.0

class SecurityCompliance:
    """Security compliance framework checker"""
    
    def __init__(self):
        self.frameworks = {
            "CIS": self._load_cis_benchmarks(),
            "NIST": self._load_nist_guidelines(),
            "ISO27001": self._load_iso27001_controls()
        }
    
    def _load_cis_benchmarks(self) -> Dict[str, Any]:
        """Load CIS (Center for Internet Security) benchmarks"""
        return {
            "ssh_config": {
                "PermitRootLogin": {"value": "no", "severity": "HIGH"},
                "PasswordAuthentication": {"value": "no", "severity": "MEDIUM"},
                "PermitEmptyPasswords": {"value": "no", "severity": "CRITICAL"},
                "X11Forwarding": {"value": "no", "severity": "MEDIUM"},
                "MaxAuthTries": {"value": "3", "severity": "MEDIUM"},
                "ClientAliveInterval": {"value": "300", "severity": "LOW"},
                "ClientAliveCountMax": {"value": "0", "severity": "LOW"},
                "Protocol": {"value": "2", "severity": "HIGH"}
            },
            "apache_config": {
                "ServerTokens": {"value": "Prod", "severity": "MEDIUM"},
                "ServerSignature": {"value": "Off", "severity": "MEDIUM"},
                "TraceEnable": {"value": "Off", "severity": "HIGH"},
                "Options": {"exclude": ["Indexes", "Includes"], "severity": "HIGH"},
                "AllowOverride": {"value": "None", "severity": "MEDIUM"}
            },
            "nginx_config": {
                "server_tokens": {"value": "off", "severity": "MEDIUM"},
                "ssl_protocols": {"exclude": ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"], "severity": "HIGH"},
                "ssl_ciphers": {"require": "ECDHE", "severity": "HIGH"},
                "add_header X-Frame-Options": {"value": "DENY", "severity": "MEDIUM"},
                "add_header X-Content-Type-Options": {"value": "nosniff", "severity": "MEDIUM"}
            },
            "mysql_config": {
                "bind-address": {"value": "127.0.0.1", "severity": "HIGH"},
                "skip-networking": {"value": "true", "severity": "MEDIUM"},
                "local-infile": {"value": "0", "severity": "MEDIUM"},
                "safe-user-create": {"value": "1", "severity": "MEDIUM"}
            },
            "file_permissions": {
                "/etc/passwd": {"permissions": "644", "severity": "HIGH"},
                "/etc/shadow": {"permissions": "600", "severity": "CRITICAL"},
                "/etc/group": {"permissions": "644", "severity": "MEDIUM"},
                "/etc/gshadow": {"permissions": "600", "severity": "HIGH"},
                "/etc/ssh/sshd_config": {"permissions": "600", "severity": "HIGH"}
            }
        }
    
    def _load_nist_guidelines(self) -> Dict[str, Any]:
        """Load NIST security guidelines"""
        return {
            "password_policy": {
                "min_length": {"value": 12, "severity": "HIGH"},
                "complexity": {"require": True, "severity": "HIGH"},
                "max_age": {"value": 90, "severity": "MEDIUM"},
                "history": {"value": 5, "severity": "MEDIUM"}
            },
            "account_lockout": {
                "threshold": {"value": 5, "severity": "MEDIUM"},
                "duration": {"value": 30, "severity": "MEDIUM"}
            },
            "audit_logging": {
                "enabled": {"value": True, "severity": "HIGH"},
                "remote_logging": {"value": True, "severity": "MEDIUM"}
            }
        }
    
    def _load_iso27001_controls(self) -> Dict[str, Any]:
        """Load ISO 27001 security controls"""
        return {
            "access_control": {
                "A.9.1.1": "Access control policy",
                "A.9.2.1": "User registration and de-registration",
                "A.9.4.2": "Secure log-on procedures"
            },
            "cryptography": {
                "A.10.1.1": "Policy on the use of cryptographic controls",
                "A.10.1.2": "Key management"
            },
            "system_security": {
                "A.12.6.1": "Management of technical vulnerabilities",
                "A.12.2.1": "Controls against malware"
            }
        }

class ConfigurationAnalyzer:
    """Main configuration analyzer class"""
    
    def __init__(self, database_path: str):
        self.db_path = database_path
        self.db_manager = get_database_manager(database_path)
        self.compliance = SecurityCompliance()
        self._active_scans = {}
        self._init_config_tables()
        
        # Common configuration file patterns
        self.config_patterns = {
            "ssh": ["/etc/ssh/sshd_config", "/etc/ssh/ssh_config"],
            "apache": ["/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf", 
                      "/etc/apache2/sites-available/*", "/etc/apache2/conf-available/*"],
            "nginx": ["/etc/nginx/nginx.conf", "/etc/nginx/sites-available/*", 
                     "/etc/nginx/conf.d/*"],
            "mysql": ["/etc/mysql/mysql.conf.d/mysqld.cnf", "/etc/my.cnf", 
                     "/etc/mysql/my.cnf"],
            "postgresql": ["/etc/postgresql/*/main/postgresql.conf", 
                          "/etc/postgresql/*/main/pg_hba.conf"],
            "docker": ["/etc/docker/daemon.json", "/etc/default/docker"],
            "system": ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
                      "/etc/sudoers", "/etc/hosts", "/etc/fstab"]
        }
    
    def _init_config_tables(self):
        """Initialize configuration analysis database tables"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                # Configuration scans table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS config_scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT UNIQUE NOT NULL,
                        target_path TEXT NOT NULL,
                        scan_type TEXT NOT NULL,
                        status TEXT NOT NULL,
                        start_time TIMESTAMP,
                        end_time TIMESTAMP,
                        total_issues INTEGER DEFAULT 0,
                        critical_count INTEGER DEFAULT 0,
                        high_count INTEGER DEFAULT 0,
                        medium_count INTEGER DEFAULT 0,
                        low_count INTEGER DEFAULT 0,
                        files_analyzed TEXT,
                        compliance_score REAL DEFAULT 0.0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Configuration issues table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS config_issues (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT NOT NULL,
                        issue_id TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT,
                        file_path TEXT NOT NULL,
                        line_number INTEGER,
                        current_value TEXT,
                        recommended_value TEXT,
                        compliance_frameworks TEXT,
                        remediation_steps TEXT,
                        risk_score REAL DEFAULT 0.0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (scan_id) REFERENCES config_scans(scan_id)
                    )
                """)
                
                # File permissions audit table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS file_permissions_audit (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT NOT NULL,
                        file_path TEXT NOT NULL,
                        current_permissions TEXT,
                        recommended_permissions TEXT,
                        owner_user TEXT,
                        owner_group TEXT,
                        is_compliant BOOLEAN DEFAULT FALSE,
                        severity TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (scan_id) REFERENCES config_scans(scan_id)
                    )
                """)
                
                # Services audit table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS services_audit (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT NOT NULL,
                        service_name TEXT NOT NULL,
                        service_status TEXT,
                        is_unnecessary BOOLEAN DEFAULT FALSE,
                        is_dangerous BOOLEAN DEFAULT FALSE,
                        recommendation TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (scan_id) REFERENCES config_scans(scan_id)
                    )
                """)
                
                conn.commit()
                logger.info("✅ Configuration analyzer tables initialized successfully")
                
        except Exception as e:
            logger.error(f"❌ Failed to initialize config analyzer tables: {e}")
            raise
    
    async def start_configuration_scan(self, target_path: str, scan_type: str = "comprehensive") -> str:
        """Start a configuration security scan"""
        try:
            scan_id = f"configscan_{int(datetime.now().timestamp())}"
            
            scan = ConfigurationScan(
                scan_id=scan_id,
                target_path=target_path,
                scan_type=scan_type,
                status="running",
                start_time=datetime.now()
            )
            
            self._active_scans[scan_id] = scan
            
            # Store scan in database
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO config_scans 
                    (scan_id, target_path, scan_type, status, start_time)
                    VALUES (?, ?, ?, ?, ?)
                """, (scan_id, target_path, scan_type, "running", scan.start_time.isoformat()))
                conn.commit()
            
            # Start scan in background
            import asyncio
            asyncio.create_task(self._execute_configuration_scan(scan_id))
            
            logger.info(f"🚀 Started configuration scan {scan_id} for path {target_path}")
            return scan_id
            
        except Exception as e:
            logger.error(f"❌ Failed to start configuration scan: {e}")
            raise
    
    async def _execute_configuration_scan(self, scan_id: str) -> None:
        """Execute the configuration scan"""
        try:
            scan = self._active_scans[scan_id]
            scan.status = "scanning"
            
            issues = []
            files_analyzed = []
            
            # Determine scan scope based on target_path and scan_type
            if scan.target_path == "system" or scan.target_path == "/":
                # Full system scan
                config_files = self._discover_system_configs()
            else:
                # Specific path scan
                config_files = self._discover_configs_in_path(scan.target_path)
            
            # Analyze each configuration file
            for config_file in config_files:
                try:
                    file_issues = await self._analyze_config_file(config_file, scan_id)
                    issues.extend(file_issues)
                    files_analyzed.append(config_file)
                except Exception as e:
                    logger.warning(f"⚠️ Failed to analyze {config_file}: {e}")
            
            # Analyze file permissions
            permission_issues = await self._analyze_file_permissions(scan_id)
            issues.extend(permission_issues)
            
            # Analyze running services
            service_issues = await self._analyze_services(scan_id)
            issues.extend(service_issues)
            
            # Process results
            scan.total_issues = len(issues)
            scan.files_analyzed = files_analyzed
            
            # Count by severity
            for issue in issues:
                if issue.severity == "CRITICAL":
                    scan.critical_count += 1
                elif issue.severity == "HIGH":
                    scan.high_count += 1
                elif issue.severity == "MEDIUM":
                    scan.medium_count += 1
                else:
                    scan.low_count += 1
            
            # Calculate compliance score
            scan.compliance_score = self._calculate_compliance_score(issues)
            
            scan.status = "completed"
            scan.end_time = datetime.now()
            
            # Save results to database
            await self._save_config_scan_results(scan, issues)
            
            logger.info(f"✅ Configuration scan {scan_id} completed. Found {scan.total_issues} issues")
            
        except Exception as e:
            logger.error(f"❌ Configuration scan {scan_id} failed: {e}")
            if scan_id in self._active_scans:
                self._active_scans[scan_id].status = "failed"
    
    def _discover_system_configs(self) -> List[str]:
        """Discover configuration files across the system"""
        config_files = []
        
        for service_type, patterns in self.config_patterns.items():
            for pattern in patterns:
                if "*" in pattern:
                    # Handle glob patterns
                    import glob
                    config_files.extend(glob.glob(pattern))
                else:
                    if os.path.exists(pattern):
                        config_files.append(pattern)
        
        return config_files
    
    def _discover_configs_in_path(self, target_path: str) -> List[str]:
        """Discover configuration files in a specific path"""
        config_files = []
        
        if os.path.isfile(target_path):
            return [target_path]
        
        if os.path.isdir(target_path):
            # Common config file extensions
            config_extensions = ['.conf', '.config', '.cfg', '.ini', '.yaml', '.yml', '.json']
            
            for root, dirs, files in os.walk(target_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if any(file.endswith(ext) for ext in config_extensions):
                        config_files.append(file_path)
        
        return config_files
    
    async def _analyze_config_file(self, config_file: str, scan_id: str) -> List[ConfigurationIssue]:
        """Analyze a single configuration file"""
        issues = []
        
        try:
            # Stealth file access
            stealth_engine = get_global_stealth_engine()
            
            # Determine file type and appropriate analyzer
            if "ssh" in config_file.lower():
                issues.extend(await self._analyze_ssh_config(config_file, scan_id))
            elif "apache" in config_file.lower() or "httpd" in config_file.lower():
                issues.extend(await self._analyze_apache_config(config_file, scan_id))
            elif "nginx" in config_file.lower():
                issues.extend(await self._analyze_nginx_config(config_file, scan_id))
            elif "mysql" in config_file.lower() or "my.cnf" in config_file:
                issues.extend(await self._analyze_mysql_config(config_file, scan_id))
            else:
                # Generic configuration analysis
                issues.extend(await self._analyze_generic_config(config_file, scan_id))
                
        except Exception as e:
            logger.error(f"❌ Failed to analyze config file {config_file}: {e}")
        
        return issues
    
    async def _analyze_ssh_config(self, config_file: str, scan_id: str) -> List[ConfigurationIssue]:
        """Analyze SSH configuration for security issues"""
        issues = []
        
        try:
            with open(config_file, 'r') as f:
                lines = f.readlines()
            
            cis_ssh = self.compliance.frameworks["CIS"]["ssh_config"]
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if line.startswith('#') or not line:
                    continue
                
                for setting, rules in cis_ssh.items():
                    if line.startswith(setting):
                        current_value = line.split(maxsplit=1)[1] if len(line.split()) > 1 else ""
                        
                        if current_value.lower() != rules["value"].lower():
                            issue = ConfigurationIssue(
                                issue_id=f"ssh_{setting.lower()}_{scan_id}_{line_num}",
                                severity=rules["severity"],
                                title=f"Insecure SSH {setting} configuration",
                                description=f"SSH {setting} is set to '{current_value}' but should be '{rules['value']}'",
                                file_path=config_file,
                                line_number=line_num,
                                current_value=current_value,
                                recommended_value=rules["value"],
                                compliance_frameworks=["CIS"],
                                remediation_steps=[
                                    f"Edit {config_file}",
                                    f"Set {setting} {rules['value']}",
                                    "Restart SSH service: sudo systemctl restart sshd"
                                ],
                                risk_score=self._calculate_risk_score(rules["severity"])
                            )
                            issues.append(issue)
            
        except Exception as e:
            logger.error(f"❌ SSH config analysis failed: {e}")
        
        return issues
    
    async def _analyze_apache_config(self, config_file: str, scan_id: str) -> List[ConfigurationIssue]:
        """Analyze Apache configuration for security issues"""
        issues = []
        
        try:
            with open(config_file, 'r') as f:
                content = f.read()
                lines = content.splitlines()
            
            cis_apache = self.compliance.frameworks["CIS"]["apache_config"]
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if line.startswith('#') or not line:
                    continue
                
                # Check for dangerous options
                if line.startswith("Options"):
                    if "Indexes" in line:
                        issue = ConfigurationIssue(
                            issue_id=f"apache_indexes_{scan_id}_{line_num}",
                            severity="HIGH",
                            title="Apache directory browsing enabled",
                            description="Directory browsing (Indexes) is enabled, allowing attackers to see directory contents",
                            file_path=config_file,
                            line_number=line_num,
                            current_value=line,
                            recommended_value="Options -Indexes",
                            compliance_frameworks=["CIS"],
                            remediation_steps=[
                                f"Edit {config_file}",
                                "Remove 'Indexes' from Options directive or use 'Options -Indexes'",
                                "Restart Apache: sudo systemctl restart apache2"
                            ],
                            risk_score=8.0
                        )
                        issues.append(issue)
                
                # Check ServerTokens
                if line.startswith("ServerTokens"):
                    current_value = line.split(maxsplit=1)[1] if len(line.split()) > 1 else ""
                    if current_value != "Prod":
                        issue = ConfigurationIssue(
                            issue_id=f"apache_servertokens_{scan_id}_{line_num}",
                            severity="MEDIUM",
                            title="Apache server information disclosure",
                            description=f"ServerTokens is set to '{current_value}', revealing server information",
                            file_path=config_file,
                            line_number=line_num,
                            current_value=current_value,
                            recommended_value="Prod",
                            compliance_frameworks=["CIS"],
                            remediation_steps=[
                                f"Edit {config_file}",
                                "Set ServerTokens Prod",
                                "Restart Apache: sudo systemctl restart apache2"
                            ],
                            risk_score=5.0
                        )
                        issues.append(issue)
            
        except Exception as e:
            logger.error(f"❌ Apache config analysis failed: {e}")
        
        return issues
    
    async def _analyze_nginx_config(self, config_file: str, scan_id: str) -> List[ConfigurationIssue]:
        """Analyze Nginx configuration for security issues"""
        issues = []
        
        try:
            with open(config_file, 'r') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if line.startswith('#') or not line:
                    continue
                
                # Check server_tokens
                if "server_tokens" in line and "off" not in line:
                    issue = ConfigurationIssue(
                        issue_id=f"nginx_servertokens_{scan_id}_{line_num}",
                        severity="MEDIUM",
                        title="Nginx server information disclosure",
                        description="server_tokens should be set to 'off' to hide Nginx version",
                        file_path=config_file,
                        line_number=line_num,
                        current_value=line,
                        recommended_value="server_tokens off;",
                        compliance_frameworks=["CIS"],
                        remediation_steps=[
                            f"Edit {config_file}",
                            "Add or modify: server_tokens off;",
                            "Test config: nginx -t",
                            "Reload Nginx: sudo systemctl reload nginx"
                        ],
                        risk_score=4.0
                    )
                    issues.append(issue)
                
                # Check for weak SSL protocols
                if "ssl_protocols" in line:
                    weak_protocols = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
                    for weak_protocol in weak_protocols:
                        if weak_protocol in line:
                            issue = ConfigurationIssue(
                                issue_id=f"nginx_weak_ssl_{scan_id}_{line_num}",
                                severity="HIGH",
                                title="Weak SSL/TLS protocol enabled",
                                description=f"Weak protocol {weak_protocol} is enabled",
                                file_path=config_file,
                                line_number=line_num,
                                current_value=line,
                                recommended_value="ssl_protocols TLSv1.2 TLSv1.3;",
                                compliance_frameworks=["CIS", "NIST"],
                                remediation_steps=[
                                    f"Edit {config_file}",
                                    "Use only: ssl_protocols TLSv1.2 TLSv1.3;",
                                    "Test config: nginx -t",
                                    "Reload Nginx: sudo systemctl reload nginx"
                                ],
                                risk_score=8.5
                            )
                            issues.append(issue)
            
        except Exception as e:
            logger.error(f"❌ Nginx config analysis failed: {e}")
        
        return issues
    
    async def _analyze_mysql_config(self, config_file: str, scan_id: str) -> List[ConfigurationIssue]:
        """Analyze MySQL configuration for security issues"""
        issues = []
        
        try:
            config = configparser.ConfigParser()
            config.read(config_file)
            
            # Check bind-address
            if config.has_option('mysqld', 'bind-address'):
                bind_address = config.get('mysqld', 'bind-address')
                if bind_address != '127.0.0.1':
                    issue = ConfigurationIssue(
                        issue_id=f"mysql_bind_address_{scan_id}",
                        severity="HIGH",
                        title="MySQL listening on all interfaces",
                        description=f"MySQL is bound to {bind_address}, allowing external connections",
                        file_path=config_file,
                        current_value=bind_address,
                        recommended_value="127.0.0.1",
                        compliance_frameworks=["CIS"],
                        remediation_steps=[
                            f"Edit {config_file}",
                            "Set bind-address = 127.0.0.1",
                            "Restart MySQL: sudo systemctl restart mysql"
                        ],
                        risk_score=8.0
                    )
                    issues.append(issue)
            
            # Check for skip-networking
            if not config.has_option('mysqld', 'skip-networking'):
                issue = ConfigurationIssue(
                    issue_id=f"mysql_skip_networking_{scan_id}",
                    severity="MEDIUM",
                    title="MySQL networking not disabled",
                    description="skip-networking option should be enabled for local-only access",
                    file_path=config_file,
                    current_value="not set",
                    recommended_value="skip-networking",
                    compliance_frameworks=["CIS"],
                    remediation_steps=[
                        f"Edit {config_file}",
                        "Add skip-networking under [mysqld] section",
                        "Restart MySQL: sudo systemctl restart mysql"
                    ],
                    risk_score=6.0
                )
                issues.append(issue)
            
        except Exception as e:
            logger.error(f"❌ MySQL config analysis failed: {e}")
        
        return issues
    
    async def _analyze_generic_config(self, config_file: str, scan_id: str) -> List[ConfigurationIssue]:
        """Generic configuration file analysis for common security issues"""
        issues = []
        
        try:
            with open(config_file, 'r') as f:
                content = f.read()
                lines = content.splitlines()
            
            # Check for hardcoded passwords or keys
            sensitive_patterns = [
                (r'password\s*=\s*[\'"]?(\w+)[\'"]?', "Hardcoded password found"),
                (r'api[_-]?key\s*=\s*[\'"]?(\w+)[\'"]?', "Hardcoded API key found"),
                (r'secret[_-]?key\s*=\s*[\'"]?(\w+)[\'"]?', "Hardcoded secret key found"),
                (r'token\s*=\s*[\'"]?(\w+)[\'"]?', "Hardcoded token found")
            ]
            
            for line_num, line in enumerate(lines, 1):
                for pattern, description in sensitive_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        issue = ConfigurationIssue(
                            issue_id=f"generic_sensitive_{scan_id}_{line_num}",
                            severity="HIGH",
                            title="Sensitive information in configuration",
                            description=description,
                            file_path=config_file,
                            line_number=line_num,
                            current_value=line.strip(),
                            recommended_value="Use environment variables or secure vault",
                            compliance_frameworks=["NIST", "ISO27001"],
                            remediation_steps=[
                                "Remove hardcoded sensitive information",
                                "Use environment variables or configuration management",
                                "Implement proper secrets management"
                            ],
                            risk_score=8.5
                        )
                        issues.append(issue)
            
        except Exception as e:
            logger.error(f"❌ Generic config analysis failed: {e}")
        
        return issues
    
    async def _analyze_file_permissions(self, scan_id: str) -> List[ConfigurationIssue]:
        """Analyze file permissions for security compliance"""
        issues = []
        
        try:
            cis_permissions = self.compliance.frameworks["CIS"]["file_permissions"]
            
            for file_path, rules in cis_permissions.items():
                if os.path.exists(file_path):
                    file_stat = os.stat(file_path)
                    current_perms = oct(file_stat.st_mode)[-3:]
                    expected_perms = rules["permissions"]
                    
                    if current_perms != expected_perms:
                        issue = ConfigurationIssue(
                            issue_id=f"file_perms_{file_path.replace('/', '_')}_{scan_id}",
                            severity=rules["severity"],
                            title=f"Incorrect file permissions: {file_path}",
                            description=f"File {file_path} has permissions {current_perms} but should have {expected_perms}",
                            file_path=file_path,
                            current_value=current_perms,
                            recommended_value=expected_perms,
                            compliance_frameworks=["CIS"],
                            remediation_steps=[
                                f"Change permissions: chmod {expected_perms} {file_path}",
                                "Verify ownership is appropriate",
                                "Test system functionality after change"
                            ],
                            risk_score=self._calculate_risk_score(rules["severity"])
                        )
                        issues.append(issue)
                    
                    # Store in file permissions audit table
                    try:
                        owner_user = pwd.getpwuid(file_stat.st_uid).pw_name
                        owner_group = grp.getgrgid(file_stat.st_gid).gr_name
                    except:
                        owner_user = str(file_stat.st_uid)
                        owner_group = str(file_stat.st_gid)
                    
                    with self.db_manager.get_connection() as conn:
                        cursor = conn.cursor()
                        cursor.execute("""
                            INSERT INTO file_permissions_audit
                            (scan_id, file_path, current_permissions, recommended_permissions,
                             owner_user, owner_group, is_compliant, severity)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            scan_id, file_path, current_perms, expected_perms,
                            owner_user, owner_group, current_perms == expected_perms,
                            rules["severity"]
                        ))
                        conn.commit()
            
        except Exception as e:
            logger.error(f"❌ File permissions analysis failed: {e}")
        
        return issues
    
    async def _analyze_services(self, scan_id: str) -> List[ConfigurationIssue]:
        """Analyze running services for security issues"""
        issues = []
        
        try:
            # Get list of running services
            result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running'], 
                                 capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.splitlines()
                
                # Dangerous services that should typically be disabled
                dangerous_services = {
                    'telnet': {'severity': 'CRITICAL', 'reason': 'Unencrypted remote access'},
                    'rsh': {'severity': 'CRITICAL', 'reason': 'Unencrypted remote shell'},
                    'rlogin': {'severity': 'CRITICAL', 'reason': 'Unencrypted remote login'},
                    'tftp': {'severity': 'HIGH', 'reason': 'Insecure file transfer'},
                    'finger': {'severity': 'MEDIUM', 'reason': 'Information disclosure'},
                    'rpcbind': {'severity': 'MEDIUM', 'reason': 'RPC service exposure'},
                    'nfs': {'severity': 'MEDIUM', 'reason': 'Network file system exposure'},
                    'ypbind': {'severity': 'MEDIUM', 'reason': 'NIS client service'},
                    'ypserv': {'severity': 'HIGH', 'reason': 'NIS server service'}
                }
                
                for line in lines:
                    if '.service' in line and 'loaded active running' in line:
                        service_name = line.split()[0].replace('.service', '')
                        
                        if service_name in dangerous_services:
                            service_info = dangerous_services[service_name]
                            
                            issue = ConfigurationIssue(
                                issue_id=f"service_{service_name}_{scan_id}",
                                severity=service_info['severity'],
                                title=f"Dangerous service running: {service_name}",
                                description=f"Service {service_name} is running. {service_info['reason']}",
                                file_path=f"/etc/systemd/system/{service_name}.service",
                                current_value="enabled/running",
                                recommended_value="disabled/stopped",
                                compliance_frameworks=["CIS", "NIST"],
                                remediation_steps=[
                                    f"Stop service: sudo systemctl stop {service_name}",
                                    f"Disable service: sudo systemctl disable {service_name}",
                                    "Verify no critical dependencies are broken"
                                ],
                                risk_score=self._calculate_risk_score(service_info['severity'])
                            )
                            issues.append(issue)
                            
                            # Store in services audit table
                            with self.db_manager.get_connection() as conn:
                                cursor = conn.cursor()
                                cursor.execute("""
                                    INSERT INTO services_audit
                                    (scan_id, service_name, service_status, is_dangerous, recommendation)
                                    VALUES (?, ?, ?, ?, ?)
                                """, (
                                    scan_id, service_name, "running", True,
                                    f"Disable {service_name} service - {service_info['reason']}"
                                ))
                                conn.commit()
            
        except Exception as e:
            logger.error(f"❌ Services analysis failed: {e}")
        
        return issues
    
    def _calculate_risk_score(self, severity: str) -> float:
        """Calculate numerical risk score from severity"""
        severity_scores = {
            "CRITICAL": 9.5,
            "HIGH": 8.0,
            "MEDIUM": 5.0,
            "LOW": 2.0
        }
        return severity_scores.get(severity, 0.0)
    
    def _calculate_compliance_score(self, issues: List[ConfigurationIssue]) -> float:
        """Calculate overall compliance score"""
        if not issues:
            return 100.0
        
        total_possible_score = len(issues) * 10  # Each issue can deduct up to 10 points
        total_deduction = sum(issue.risk_score for issue in issues)
        
        compliance_score = max(0, (total_possible_score - total_deduction) / total_possible_score * 100)
        return round(compliance_score, 2)
    
    async def _save_config_scan_results(self, scan: ConfigurationScan, issues: List[ConfigurationIssue]) -> None:
        """Save configuration scan results to database"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                # Update scan record
                cursor.execute("""
                    UPDATE config_scans 
                    SET status = ?, end_time = ?, total_issues = ?,
                        critical_count = ?, high_count = ?, medium_count = ?, low_count = ?,
                        files_analyzed = ?, compliance_score = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE scan_id = ?
                """, (
                    scan.status, scan.end_time.isoformat() if scan.end_time else None,
                    scan.total_issues, scan.critical_count, scan.high_count,
                    scan.medium_count, scan.low_count,
                    json.dumps(scan.files_analyzed), scan.compliance_score, scan.scan_id
                ))
                
                # Save configuration issues
                for issue in issues:
                    cursor.execute("""
                        INSERT INTO config_issues
                        (scan_id, issue_id, severity, title, description, file_path,
                         line_number, current_value, recommended_value, compliance_frameworks,
                         remediation_steps, risk_score)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        scan.scan_id, issue.issue_id, issue.severity, issue.title,
                        issue.description, issue.file_path, issue.line_number,
                        issue.current_value, issue.recommended_value,
                        json.dumps(issue.compliance_frameworks or []),
                        json.dumps(issue.remediation_steps or []), issue.risk_score
                    ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"❌ Failed to save config scan results: {e}")
    
    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get configuration scan status and results"""
        try:
            if scan_id in self._active_scans:
                scan = self._active_scans[scan_id]
                return {
                    "scan_id": scan_id,
                    "target_path": scan.target_path,
                    "status": scan.status,
                    "start_time": scan.start_time.isoformat(),
                    "end_time": scan.end_time.isoformat() if scan.end_time else None,
                    "total_issues": scan.total_issues,
                    "critical_count": scan.critical_count,
                    "high_count": scan.high_count,
                    "medium_count": scan.medium_count,
                    "low_count": scan.low_count,
                    "compliance_score": scan.compliance_score
                }
            
            # Check database for completed scans
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT scan_id, target_path, scan_type, status, start_time, end_time,
                           total_issues, critical_count, high_count, medium_count, low_count,
                           compliance_score
                    FROM config_scans
                    WHERE scan_id = ?
                """, (scan_id,))
                
                result = cursor.fetchone()
                if result:
                    return {
                        "scan_id": result[0],
                        "target_path": result[1],
                        "scan_type": result[2],
                        "status": result[3],
                        "start_time": result[4],
                        "end_time": result[5],
                        "total_issues": result[6] or 0,
                        "critical_count": result[7] or 0,
                        "high_count": result[8] or 0,
                        "medium_count": result[9] or 0,
                        "low_count": result[10] or 0,
                        "compliance_score": result[11] or 0.0
                    }
            
            return {"error": "Scan not found"}
            
        except Exception as e:
            logger.error(f"❌ Failed to get config scan status: {e}")
            return {"error": str(e)}
    
    def get_configuration_issues(self, scan_id: str) -> List[Dict]:
        """Get detailed configuration issues for a scan"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT issue_id, severity, title, description, file_path,
                           line_number, current_value, recommended_value, 
                           compliance_frameworks, remediation_steps, risk_score
                    FROM config_issues
                    WHERE scan_id = ?
                    ORDER BY risk_score DESC, severity DESC
                """, (scan_id,))
                
                results = cursor.fetchall()
                
                issues = []
                for row in results:
                    issue = {
                        "issue_id": row[0],
                        "severity": row[1],
                        "title": row[2],
                        "description": row[3],
                        "file_path": row[4],
                        "line_number": row[5],
                        "current_value": row[6],
                        "recommended_value": row[7],
                        "compliance_frameworks": json.loads(row[8]) if row[8] else [],
                        "remediation_steps": json.loads(row[9]) if row[9] else [],
                        "risk_score": row[10]
                    }
                    issues.append(issue)
                
                return issues
                
        except Exception as e:
            logger.error(f"❌ Failed to get configuration issues: {e}")
            return []

# Global instance
_config_analyzer = None

def get_configuration_analyzer(database_path: str = None) -> ConfigurationAnalyzer:
    """Get global configuration analyzer instance"""
    global _config_analyzer
    
    if _config_analyzer is None:
        if not database_path:
            # Use default path from main application
            from pathlib import Path
            portable_dir = Path(__file__).parent.parent.absolute()
            database_path = str(portable_dir / "data" / "cybersec.db")
        
        _config_analyzer = ConfigurationAnalyzer(database_path)
    
    return _config_analyzer

if __name__ == "__main__":
    # Test the configuration analyzer
    import asyncio
    
    async def test_analyzer():
        analyzer = get_configuration_analyzer()
        
        # Start a system configuration scan
        scan_id = await analyzer.start_configuration_scan("system", "comprehensive")
        print(f"Started configuration scan: {scan_id}")
        
        # Wait a bit for scan to complete
        await asyncio.sleep(5)
        
        # Get scan status
        status = analyzer.get_scan_status(scan_id)
        print(f"Scan status: {status}")
        
        if status.get("status") == "completed":
            # Get detailed issues
            issues = analyzer.get_configuration_issues(scan_id)
            print(f"Found {len(issues)} configuration issues")
            
            for issue in issues[:5]:  # Show first 5
                print(f"- {issue['severity']}: {issue['title']}")
    
    asyncio.run(test_analyzer())