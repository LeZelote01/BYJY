#!/usr/bin/env python3
"""
CyberSec Assistant Portable - Database API V1.3
API endpoints for database management, import/export, backups
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, UploadFile, File
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import logging
from pathlib import Path
from datetime import datetime
import os

import database_manager

# Import path utilities for dynamic path resolution
from path_utils import get_database_path

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/database", tags=["Database Management"])

# Pydantic models
class ExportRequest(BaseModel):
    modules: Optional[List[str]] = None
    date_range_start: Optional[str] = None
    date_range_end: Optional[str] = None
    include_encrypted: bool = False

class ImportRequest(BaseModel):
    merge_strategy: str = "merge"  # "merge" or "replace"
    
class BackupRequest(BaseModel):
    backup_name: Optional[str] = None
    compress: bool = True

class RestoreRequest(BaseModel):
    backup_file: str

class DatabaseConfig(BaseModel):
    auto_backup_enabled: bool = True
    backup_interval_hours: int = 24
    max_backups: int = 30
    encryption_enabled: bool = False

# Global database manager instance
db_manager = None

def get_db_manager():
    """Get or create database manager instance"""
    global db_manager
    if not db_manager:
        # Get database path dynamically or from environment
        db_path = os.environ.get("DATABASE_PATH") or get_database_path()
        encryption_key = os.environ.get("DB_ENCRYPTION_KEY")
        db_manager = database_manager.get_database_manager(db_path, encryption_key)
    return db_manager

@router.get("/status")
async def get_database_status():
    """Get comprehensive database status and statistics"""
    try:
        manager = get_db_manager()
        stats = manager.get_database_stats()
        
        # Add backup information
        backup_dir = manager.backup_dir
        backups = []
        if backup_dir.exists():
            for backup_file in backup_dir.glob("*.db.gz"):
                backups.append({
                    "name": backup_file.name,
                    "size": backup_file.stat().st_size,
                    "created_at": datetime.fromtimestamp(backup_file.stat().st_ctime).isoformat()
                })
        
        stats["backups"] = {
            "count": len(backups),
            "latest_backup": max(backups, key=lambda x: x["created_at"])["created_at"] if backups else None,
            "total_backup_size": sum(b["size"] for b in backups)
        }
        
        stats["config"] = {
            "encryption_enabled": manager.encryption_enabled,
            "auto_backup_enabled": manager.auto_backup_enabled,
            "backup_interval_hours": manager.backup_interval_hours,
            "max_backups": manager.max_backups
        }
        
        return {
            "status": "healthy",
            "statistics": stats
        }
        
    except Exception as e:
        logger.error(f"Failed to get database status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get database status: {e}")

@router.post("/export")
async def export_database(request: ExportRequest, background_tasks: BackgroundTasks):
    """Export database data to file"""
    try:
        manager = get_db_manager()
        
        # Generate export filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        modules_str = "_".join(request.modules) if request.modules else "all"
        export_filename = f"cybersec_export_{modules_str}_{timestamp}.json.gz"
        export_path = manager.backup_dir / export_filename
        
        # Date range parsing
        date_range = None
        if request.date_range_start and request.date_range_end:
            date_range = (request.date_range_start, request.date_range_end)
        
        # Export data
        result = manager.export_data(
            output_file=str(export_path),
            modules=request.modules,
            date_range=date_range
        )
        
        if not result["success"]:
            raise HTTPException(status_code=500, detail=result["error"])
        
        return {
            "message": "Export completed successfully",
            "export_file": export_filename,
            "file_path": str(export_path),
            "tables_exported": result["tables_exported"],
            "file_size": result["file_size"],
            "download_url": f"/api/database/download/{export_filename}"
        }
        
    except Exception as e:
        logger.error(f"Export failed: {e}")
        raise HTTPException(status_code=500, detail=f"Export failed: {e}")

@router.post("/import")
async def import_database(request: ImportRequest, file: UploadFile = File(...)):
    """Import database data from uploaded file"""
    try:
        manager = get_db_manager()
        
        # Save uploaded file
        import_path = manager.backup_dir / f"import_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
        
        with open(import_path, "wb") as f:
            content = await file.read()
            f.write(content)
        
        # Import data
        result = manager.import_data(
            import_file=str(import_path),
            merge_strategy=request.merge_strategy
        )
        
        # Cleanup import file
        import_path.unlink()
        
        if not result["success"]:
            raise HTTPException(status_code=500, detail=result["error"])
        
        return {
            "message": "Import completed successfully",
            "imported_records": result["imported_records"],
            "skipped_records": result["skipped_records"]
        }
        
    except Exception as e:
        logger.error(f"Import failed: {e}")
        raise HTTPException(status_code=500, detail=f"Import failed: {e}")

@router.post("/backup")
async def create_backup(request: BackupRequest):
    """Create database backup"""
    try:
        manager = get_db_manager()
        
        result = manager.create_backup(request.backup_name)
        
        if not result["success"]:
            raise HTTPException(status_code=500, detail=result["error"])
        
        return {
            "message": "Backup created successfully",
            "backup_file": Path(result["backup_file"]).name,
            "file_path": result["backup_file"],
            "size": result["size"],
            "download_url": f"/api/database/download/{Path(result['backup_file']).name}"
        }
        
    except Exception as e:
        logger.error(f"Backup failed: {e}")
        raise HTTPException(status_code=500, detail=f"Backup failed: {e}")

@router.get("/backups")
async def list_backups():
    """List all available backups"""
    try:
        manager = get_db_manager()
        
        backups = []
        if manager.backup_dir.exists():
            for backup_file in sorted(manager.backup_dir.glob("*.db.gz"), key=lambda x: x.stat().st_mtime, reverse=True):
                stat = backup_file.stat()
                backups.append({
                    "name": backup_file.name,
                    "size": stat.st_size,
                    "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "download_url": f"/api/database/download/{backup_file.name}"
                })
        
        return {
            "backups": backups,
            "total_count": len(backups),
            "total_size": sum(b["size"] for b in backups)
        }
        
    except Exception as e:
        logger.error(f"Failed to list backups: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list backups: {e}")

@router.post("/restore")
async def restore_backup(request: RestoreRequest):
    """Restore database from backup"""
    try:
        manager = get_db_manager()
        
        # Verify backup file exists
        backup_path = manager.backup_dir / request.backup_file
        if not backup_path.exists():
            raise HTTPException(status_code=404, detail="Backup file not found")
        
        result = manager.restore_backup(str(backup_path))
        
        if not result["success"]:
            raise HTTPException(status_code=500, detail=result["error"])
        
        return {
            "message": "Database restored successfully",
            "restored_from": request.backup_file,
            "current_backup": result.get("current_backup")
        }
        
    except Exception as e:
        logger.error(f"Restore failed: {e}")
        raise HTTPException(status_code=500, detail=f"Restore failed: {e}")

@router.get("/download/{filename}")
async def download_file(filename: str):
    """Download backup or export file"""
    try:
        manager = get_db_manager()
        file_path = manager.backup_dir / filename
        
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        return FileResponse(
            path=str(file_path),
            filename=filename,
            media_type="application/octet-stream"
        )
        
    except Exception as e:
        logger.error(f"Download failed: {e}")
        raise HTTPException(status_code=500, detail=f"Download failed: {e}")

@router.delete("/backups/{backup_name}")
async def delete_backup(backup_name: str):
    """Delete a specific backup file"""
    try:
        manager = get_db_manager()
        backup_path = manager.backup_dir / backup_name
        
        if not backup_path.exists():
            raise HTTPException(status_code=404, detail="Backup file not found")
        
        backup_path.unlink()
        
        return {"message": f"Backup {backup_name} deleted successfully"}
        
    except Exception as e:
        logger.error(f"Failed to delete backup: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete backup: {e}")

@router.post("/vacuum")
async def vacuum_database():
    """Optimize database by running VACUUM"""
    try:
        manager = get_db_manager()
        
        with manager.get_connection() as conn:
            cursor = conn.cursor()
            
            # Get size before vacuum
            cursor.execute("PRAGMA page_count")
            pages_before = cursor.fetchone()[0]
            
            cursor.execute("VACUUM")
            
            # Get size after vacuum
            cursor.execute("PRAGMA page_count")
            pages_after = cursor.fetchone()[0]
            
            cursor.execute("PRAGMA page_size")
            page_size = cursor.fetchone()[0]
        
        size_before = pages_before * page_size
        size_after = pages_after * page_size
        size_saved = size_before - size_after
        
        return {
            "message": "Database optimized successfully",
            "size_before": size_before,
            "size_after": size_after,
            "size_saved": size_saved,
            "pages_freed": pages_before - pages_after
        }
        
    except Exception as e:
        logger.error(f"Database vacuum failed: {e}")
        raise HTTPException(status_code=500, detail=f"Database vacuum failed: {e}")

@router.get("/schema")
async def get_database_schema():
    """Get complete database schema information"""
    try:
        manager = get_db_manager()
        
        with manager.get_connection() as conn:
            cursor = conn.cursor()
            
            # Get all tables
            cursor.execute("""
                SELECT name, sql FROM sqlite_master 
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
            """)
            tables = cursor.fetchall()
            
            # Get all indexes
            cursor.execute("""
                SELECT name, sql FROM sqlite_master 
                WHERE type='index' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
            """)
            indexes = cursor.fetchall()
            
            schema = {
                "tables": {},
                "indexes": [{"name": idx[0], "sql": idx[1]} for idx in indexes]
            }
            
            for table_name, table_sql in tables:
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = cursor.fetchall()
                
                schema["tables"][table_name] = {
                    "sql": table_sql,
                    "columns": [
                        {
                            "name": col[1],
                            "type": col[2],
                            "nullable": not col[3],
                            "default": col[4],
                            "primary_key": bool(col[5])
                        }
                        for col in columns
                    ]
                }
        
        return schema
        
    except Exception as e:
        logger.error(f"Failed to get database schema: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get database schema: {e}")

@router.get("/integrity-check")
async def check_database_integrity():
    """Run database integrity check"""
    try:
        manager = get_db_manager()
        
        with manager.get_connection() as conn:
            cursor = conn.cursor()
            
            # Run integrity check
            cursor.execute("PRAGMA integrity_check")
            integrity_result = cursor.fetchall()
            
            # Run foreign key check
            cursor.execute("PRAGMA foreign_key_check")
            fk_violations = cursor.fetchall()
            
            is_healthy = (
                len(integrity_result) == 1 and 
                integrity_result[0][0] == "ok" and 
                len(fk_violations) == 0
            )
            
            return {
                "healthy": is_healthy,
                "integrity_check": [row[0] for row in integrity_result],
                "foreign_key_violations": [
                    {
                        "table": row[0],
                        "rowid": row[1], 
                        "parent": row[2],
                        "fkid": row[3]
                    }
                    for row in fk_violations
                ],
                "checked_at": datetime.now().isoformat()
            }
        
    except Exception as e:
        logger.error(f"Database integrity check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Database integrity check failed: {e}")

@router.put("/config")
async def update_database_config(config: DatabaseConfig):
    """Update database configuration"""
    try:
        manager = get_db_manager()
        
        # Update configuration
        manager.auto_backup_enabled = config.auto_backup_enabled
        manager.backup_interval_hours = config.backup_interval_hours
        manager.max_backups = config.max_backups
        
        # Save configuration to database
        with manager.get_connection() as conn:
            cursor = conn.cursor()
            
            config_items = [
                ("database", "auto_backup_enabled", str(config.auto_backup_enabled)),
                ("database", "backup_interval_hours", str(config.backup_interval_hours)),
                ("database", "max_backups", str(config.max_backups)),
                ("database", "encryption_enabled", str(config.encryption_enabled)),
            ]
            
            for category, key, value in config_items:
                cursor.execute("""
                    INSERT OR REPLACE INTO system_config (category, key, value, updated_at)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                """, (category, key, value))
        
        return {"message": "Database configuration updated successfully"}
        
    except Exception as e:
        logger.error(f"Failed to update database config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update database config: {e}")