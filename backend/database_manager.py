#!/usr/bin/env python3
"""
CyberSec Assistant Portable - Database Manager V1.3
Complete database schema for all cybersecurity modules
Features: SQLite + Import/Export + Auto-backup + Optional Encryption
"""

import os
import sqlite3
import json
import uuid
import shutil
import gzip
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import logging

logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self, db_path: str, backup_dir: str = None, encryption_key: str = None):
        self.db_path = Path(db_path)
        self.backup_dir = Path(backup_dir) if backup_dir else self.db_path.parent / "backups"
        self.backup_dir.mkdir(exist_ok=True)
        
        # Encryption setup
        self.encryption_enabled = bool(encryption_key)
        self.cipher_suite = None
        if self.encryption_enabled:
            self.cipher_suite = self._setup_encryption(encryption_key)
        
        # Auto-backup configuration
        self.auto_backup_enabled = True
        self.backup_interval_hours = 24
        self.max_backups = 30
        
        # Initialize database
        self._init_complete_schema()
        self._setup_auto_backup()
    
    def _setup_encryption(self, password: str) -> Fernet:
        """Setup encryption using password-based key derivation"""
        password_bytes = password.encode()
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return Fernet(key)
    
    def _encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        if not self.encryption_enabled or not data:
            return data
        return self.cipher_suite.encrypt(data.encode()).decode()
    
    def _decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        if not self.encryption_enabled or not encrypted_data:
            return encrypted_data
        try:
            return self.cipher_suite.decrypt(encrypted_data.encode()).decode()
        except Exception:
            return encrypted_data  # Return as-is if decryption fails
    
    def get_connection(self) -> sqlite3.Connection:
        """Get database connection with optimizations"""
        conn = sqlite3.connect(
            self.db_path,
            timeout=30,
            isolation_level=None  # Autocommit mode
        )
        conn.row_factory = sqlite3.Row
        
        # Performance optimizations
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=10000")
        conn.execute("PRAGMA temp_store=MEMORY")
        
        return conn
    
    def _init_complete_schema(self):
        """Initialize complete database schema for all cybersecurity modules"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # 1. Core System Tables
                self._create_core_tables(cursor)
                
                # 2. Network Scanning Module
                self._create_scanning_tables(cursor)
                
                # 3. Brute Force Module  
                self._create_bruteforce_tables(cursor)
                
                # 4. WiFi Security Module
                self._create_wifi_tables(cursor)
                
                # 5. MITM Attacks Module
                self._create_mitm_tables(cursor)
                
                # 6. Forensics Module
                self._create_forensics_tables(cursor)
                
                # 7. Reports & Configuration
                self._create_reports_tables(cursor)
                
                # 8. OSINT & Threat Intelligence
                self._create_osint_tables(cursor)
                
                # 9. Vulnerability Assessment
                self._create_vulnerability_tables(cursor)
                
                # 10. Tools Integration
                self._create_tools_tables(cursor)
                
                # Create indexes for performance
                self._create_indexes(cursor)
                
                logger.info("✅ Complete database schema initialized successfully")
                
        except Exception as e:
            logger.error(f"❌ Database schema initialization failed: {e}")
            raise
    
    def _create_core_tables(self, cursor):
        """Core system tables"""
        # Enhanced system configuration
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                data_type TEXT DEFAULT 'string',
                encrypted BOOLEAN DEFAULT FALSE,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(category, key)
            )
        """)
        
        # User sessions and activity
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                id TEXT PRIMARY KEY,
                session_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                ip_address TEXT,
                user_agent TEXT
            )
        """)
        
        # Activity audit log
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                module TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                details TEXT,
                success BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Terminal command history
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS terminal_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command TEXT NOT NULL,
                working_directory TEXT,
                output TEXT,
                exit_code INTEGER,
                execution_time REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    
    def _create_scanning_tables(self, cursor):
        """Network scanning and reconnaissance tables"""
        # Port scan results
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS port_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                target TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT DEFAULT 'tcp',
                state TEXT NOT NULL,
                service TEXT,
                version TEXT,
                banner TEXT,
                scan_technique TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Network discovery results
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS network_discovery (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                hostname TEXT,
                mac_address TEXT,
                vendor TEXT,
                os_guess TEXT,
                response_time REAL,
                status TEXT DEFAULT 'up',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Service enumeration
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS service_enumeration (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                target TEXT NOT NULL,
                service TEXT NOT NULL,
                port INTEGER,
                details TEXT,
                vulnerabilities TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    
    def _create_bruteforce_tables(self, cursor):
        """Brute force and password cracking tables"""
        # Authentication attacks
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auth_attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_id TEXT NOT NULL,
                target TEXT NOT NULL,
                service TEXT NOT NULL,
                username TEXT,
                password_hash TEXT,
                success BOOLEAN DEFAULT FALSE,
                response_time REAL,
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Hash cracking sessions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hash_cracking (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                hash_type TEXT NOT NULL,
                hash_value TEXT NOT NULL,
                salt TEXT,
                cracked_password TEXT,
                wordlist_used TEXT,
                rules_used TEXT,
                crack_time REAL,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Custom wordlists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS wordlists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                category TEXT NOT NULL,
                file_path TEXT NOT NULL,
                word_count INTEGER,
                file_size INTEGER,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    
    def _create_wifi_tables(self, cursor):
        """WiFi security testing tables"""
        # WiFi networks discovered
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS wifi_networks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid TEXT NOT NULL,
                ssid TEXT,
                channel INTEGER,
                frequency INTEGER,
                signal_strength INTEGER,
                encryption TEXT,
                authentication TEXT,
                vendor TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # WiFi handshakes captured
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS wifi_handshakes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                network_id INTEGER,
                bssid TEXT NOT NULL,
                ssid TEXT,
                handshake_file TEXT NOT NULL,
                handshake_type TEXT DEFAULT '4-way',
                capture_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                cracked BOOLEAN DEFAULT FALSE,
                password TEXT
            )
        """)
        
        # WiFi clients
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS wifi_clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address TEXT NOT NULL,
                associated_bssid TEXT,
                vendor TEXT,
                signal_strength INTEGER,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    
    def _create_mitm_tables(self, cursor):
        """MITM attacks and network interception tables"""
        # MITM sessions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mitm_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                target_ip TEXT,
                gateway_ip TEXT,
                interface TEXT,
                status TEXT DEFAULT 'active',
                packets_captured INTEGER DEFAULT 0,
                data_intercepted INTEGER DEFAULT 0,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ended_at TIMESTAMP
            )
        """)
        
        # Captured credentials
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS intercepted_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                protocol TEXT NOT NULL,
                hostname TEXT,
                username TEXT,
                password TEXT,
                additional_data TEXT,
                captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Network traffic analysis
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS traffic_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                protocol TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                packet_size INTEGER,
                payload_preview TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    
    def _create_forensics_tables(self, cursor):
        """Digital forensics and analysis tables"""
        # File analysis results
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                file_name TEXT NOT NULL,
                file_size INTEGER,
                file_hash TEXT NOT NULL,
                file_type TEXT,
                mime_type TEXT,
                metadata TEXT,
                suspicious_indicators TEXT,
                analysis_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Log analysis results
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS log_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_file TEXT NOT NULL,
                log_type TEXT NOT NULL,
                events_total INTEGER,
                events_suspicious INTEGER,
                anomalies TEXT,
                timeline_start TIMESTAMP,
                timeline_end TIMESTAMP,
                analysis_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Evidence chain
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS evidence_chain (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                file_path TEXT,
                hash_value TEXT NOT NULL,
                collector TEXT,
                collection_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                chain_of_custody TEXT,
                notes TEXT
            )
        """)
    
    def _create_reports_tables(self, cursor):
        """Reporting and documentation tables"""
        # Generated reports
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                report_type TEXT NOT NULL,
                template_used TEXT,
                data_sources TEXT,
                file_path TEXT,
                status TEXT DEFAULT 'draft',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                generated_at TIMESTAMP
            )
        """)
        
        # Report templates
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report_templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                category TEXT NOT NULL,
                template_content TEXT NOT NULL,
                variables TEXT,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    
    def _create_osint_tables(self, cursor):
        """OSINT and threat intelligence tables"""
        # OSINT results
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS osint_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                source TEXT NOT NULL,
                data_type TEXT NOT NULL,
                results TEXT NOT NULL,
                confidence_score REAL,
                collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Threat intelligence
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_type TEXT NOT NULL,
                indicator_value TEXT NOT NULL,
                threat_type TEXT,
                confidence REAL,
                source TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                active BOOLEAN DEFAULT TRUE
            )
        """)
    
    def _create_vulnerability_tables(self, cursor):
        """Vulnerability assessment tables"""
        # Vulnerability scan results
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                target TEXT NOT NULL,
                cve_id TEXT,
                vulnerability_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                cvss_score REAL,
                description TEXT,
                solution TEXT,
                reference_links TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # CVE database (offline)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_database (
                id INTEGER PRIMARY KEY,
                cve_id TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL,
                cvss_v2_score REAL,
                cvss_v3_score REAL,
                published_date TIMESTAMP,
                modified_date TIMESTAMP,
                cwe_id TEXT,
                affected_products TEXT,
                reference_links TEXT
            )
        """)
    
    def _create_tools_tables(self, cursor):
        """Security tools integration tables"""
        # Enhanced tools status
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tools_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool_name TEXT NOT NULL UNIQUE,
                category TEXT NOT NULL,
                version TEXT,
                path TEXT,
                status TEXT DEFAULT 'unknown',
                installation_date TIMESTAMP,
                last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                configuration TEXT,
                notes TEXT
            )
        """)
        
        # Tool execution history
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tool_executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool_name TEXT NOT NULL,
                command TEXT NOT NULL,
                arguments TEXT,
                exit_code INTEGER,
                execution_time REAL,
                output_file TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    
    def _create_indexes(self, cursor):
        """Create database indexes for performance"""
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_port_scans_target ON port_scans (target)",
            "CREATE INDEX IF NOT EXISTS idx_port_scans_scan_id ON port_scans (scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_network_discovery_ip ON network_discovery (ip_address)",
            "CREATE INDEX IF NOT EXISTS idx_auth_attacks_target ON auth_attacks (target)",
            "CREATE INDEX IF NOT EXISTS idx_wifi_networks_bssid ON wifi_networks (bssid)",
            "CREATE INDEX IF NOT EXISTS idx_mitm_sessions_target ON mitm_sessions (target_ip)",
            "CREATE INDEX IF NOT EXISTS idx_file_analysis_hash ON file_analysis (file_hash)",
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve ON vulnerabilities (cve_id)",
            "CREATE INDEX IF NOT EXISTS idx_activity_log_module ON activity_log (module)",
            "CREATE INDEX IF NOT EXISTS idx_activity_log_created ON activity_log (created_at)",
        ]
        
        for index_sql in indexes:
            cursor.execute(index_sql)
    
    # Data Management Methods
    
    def export_data(self, output_file: str, modules: List[str] = None, 
                   date_range: tuple = None) -> Dict[str, Any]:
        """Export database data to JSON file"""
        try:
            export_data = {
                "export_info": {
                    "version": "1.3",
                    "created_at": datetime.now().isoformat(),
                    "modules": modules or "all",
                    "date_range": date_range
                },
                "data": {}
            }
            
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get all table names
                cursor.execute("""
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name NOT LIKE 'sqlite_%'
                """)
                tables = [row[0] for row in cursor.fetchall()]
                
                # Filter tables by modules if specified
                if modules:
                    table_filters = self._get_module_tables(modules)
                    tables = [t for t in tables if any(f in t for f in table_filters)]
                
                # Export each table
                for table in tables:
                    cursor.execute(f"SELECT * FROM {table}")
                    rows = cursor.fetchall()
                    export_data["data"][table] = [dict(row) for row in rows]
            
            # Write to file (compressed)
            output_path = Path(output_file)
            with gzip.open(output_path, 'wt', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            logger.info(f"✅ Data exported to {output_path}")
            return {
                "success": True,
                "file_path": str(output_path),
                "tables_exported": len(export_data["data"]),
                "file_size": output_path.stat().st_size
            }
            
        except Exception as e:
            logger.error(f"❌ Export failed: {e}")
            return {"success": False, "error": str(e)}
    
    def import_data(self, import_file: str, merge_strategy: str = "merge") -> Dict[str, Any]:
        """Import data from JSON file"""
        try:
            import_path = Path(import_file)
            if not import_path.exists():
                raise FileNotFoundError(f"Import file not found: {import_file}")
            
            # Read compressed file
            with gzip.open(import_path, 'rt', encoding='utf-8') as f:
                import_data = json.load(f)
            
            imported_records = 0
            skipped_records = 0
            
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                for table_name, records in import_data["data"].items():
                    if not records:
                        continue
                    
                    # Get table schema
                    cursor.execute(f"PRAGMA table_info({table_name})")
                    columns = [col[1] for col in cursor.fetchall()]
                    
                    for record in records:
                        try:
                            # Filter record to match table schema
                            filtered_record = {k: v for k, v in record.items() if k in columns}
                            
                            if merge_strategy == "replace":
                                # Delete existing record if has unique key
                                if "id" in filtered_record:
                                    cursor.execute(f"DELETE FROM {table_name} WHERE id = ?", 
                                                 (filtered_record["id"],))
                            
                            # Insert record
                            placeholders = ", ".join(["?" for _ in filtered_record])
                            columns_str = ", ".join(filtered_record.keys())
                            values = list(filtered_record.values())
                            
                            cursor.execute(f"""
                                INSERT OR IGNORE INTO {table_name} ({columns_str}) 
                                VALUES ({placeholders})
                            """, values)
                            
                            imported_records += 1
                            
                        except Exception as record_error:
                            logger.warning(f"Skipped record in {table_name}: {record_error}")
                            skipped_records += 1
                            continue
            
            logger.info(f"✅ Import completed: {imported_records} records imported, {skipped_records} skipped")
            return {
                "success": True,
                "imported_records": imported_records,
                "skipped_records": skipped_records
            }
            
        except Exception as e:
            logger.error(f"❌ Import failed: {e}")
            return {"success": False, "error": str(e)}
    
    def create_backup(self, backup_name: str = None) -> Dict[str, Any]:
        """Create database backup"""
        try:
            if not backup_name:
                backup_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
            
            backup_path = self.backup_dir / backup_name
            shutil.copy2(self.db_path, backup_path)
            
            # Compress backup
            compressed_path = backup_path.with_suffix('.db.gz')
            with open(backup_path, 'rb') as f_in:
                with gzip.open(compressed_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # Remove uncompressed backup
            backup_path.unlink()
            
            logger.info(f"✅ Backup created: {compressed_path}")
            return {
                "success": True,
                "backup_file": str(compressed_path),
                "size": compressed_path.stat().st_size
            }
            
        except Exception as e:
            logger.error(f"❌ Backup failed: {e}")
            return {"success": False, "error": str(e)}
    
    def restore_backup(self, backup_file: str) -> Dict[str, Any]:
        """Restore database from backup"""
        try:
            backup_path = Path(backup_file)
            if not backup_path.exists():
                raise FileNotFoundError(f"Backup file not found: {backup_file}")
            
            # Create backup of current database
            current_backup = self.create_backup("before_restore")
            
            # Restore from backup
            if backup_path.suffix == '.gz':
                with gzip.open(backup_path, 'rb') as f_in:
                    with open(self.db_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
            else:
                shutil.copy2(backup_path, self.db_path)
            
            logger.info(f"✅ Database restored from {backup_path}")
            return {
                "success": True,
                "restored_from": str(backup_path),
                "current_backup": current_backup["backup_file"] if current_backup["success"] else None
            }
            
        except Exception as e:
            logger.error(f"❌ Restore failed: {e}")
            return {"success": False, "error": str(e)}
    
    def _setup_auto_backup(self):
        """Setup automatic backup system"""
        # Check if backup is needed
        last_backup = self._get_last_backup_time()
        if not last_backup or (datetime.now() - last_backup).total_seconds() > (self.backup_interval_hours * 3600):
            self.create_backup()
            self._cleanup_old_backups()
    
    def _get_last_backup_time(self) -> Optional[datetime]:
        """Get timestamp of last backup"""
        backups = list(self.backup_dir.glob("backup_*.db.gz"))
        if not backups:
            return None
        
        latest_backup = max(backups, key=lambda x: x.stat().st_mtime)
        return datetime.fromtimestamp(latest_backup.stat().st_mtime)
    
    def _cleanup_old_backups(self):
        """Remove old backups beyond max_backups limit"""
        backups = sorted(self.backup_dir.glob("backup_*.db.gz"), 
                        key=lambda x: x.stat().st_mtime, reverse=True)
        
        for old_backup in backups[self.max_backups:]:
            old_backup.unlink()
            logger.info(f"🗑️ Removed old backup: {old_backup.name}")
    
    def _get_module_tables(self, modules: List[str]) -> List[str]:
        """Get table prefixes for specific modules"""
        module_mapping = {
            "scanning": ["port_scans", "network_discovery", "service_enumeration"],
            "bruteforce": ["auth_attacks", "hash_cracking", "wordlists"],
            "wifi": ["wifi_networks", "wifi_handshakes", "wifi_clients"],
            "mitm": ["mitm_sessions", "intercepted_credentials", "traffic_analysis"],
            "forensics": ["file_analysis", "log_analysis", "evidence_chain"],
            "reports": ["reports", "report_templates"],
            "osint": ["osint_results", "threat_intelligence"],
            "vulnerabilities": ["vulnerabilities", "cve_database"],
            "tools": ["tools_status", "tool_executions"]
        }
        
        tables = []
        for module in modules:
            tables.extend(module_mapping.get(module, []))
        return tables
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get comprehensive database statistics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                stats = {
                    "database_size": self.db_path.stat().st_size,
                    "created_at": datetime.fromtimestamp(self.db_path.stat().st_ctime).isoformat(),
                    "modified_at": datetime.fromtimestamp(self.db_path.stat().st_mtime).isoformat(),
                    "tables": {},
                    "total_records": 0
                }
                
                # Get table statistics
                cursor.execute("""
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name NOT LIKE 'sqlite_%'
                """)
                
                for (table_name,) in cursor.fetchall():
                    cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                    record_count = cursor.fetchone()[0]
                    
                    stats["tables"][table_name] = {
                        "records": record_count
                    }
                    stats["total_records"] += record_count
                
                return stats
                
        except Exception as e:
            logger.error(f"❌ Failed to get database stats: {e}")
            return {"error": str(e)}

# Factory function
def get_database_manager(db_path: str, encryption_key: str = None) -> DatabaseManager:
    """Get database manager instance"""
    backup_dir = Path(db_path).parent / "backups"
    return DatabaseManager(db_path, str(backup_dir), encryption_key)