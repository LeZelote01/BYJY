#!/usr/bin/env python3
"""
CyberSec Assistant Portable - Configuration Analysis API V1.0
Phase 4.2: REST API for Configuration Security Analysis
Architecture: FastAPI + Configuration Analyzer + Real-time Scanning
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator

# Import our configuration analyzer
from config_analyzer import get_configuration_analyzer

logger = logging.getLogger(__name__)

# API Router
router = APIRouter(prefix="/api/configuration", tags=["configuration"])

# Pydantic Models
class ConfigurationScanRequest(BaseModel):
    """Request model for configuration scan"""
    target_path: str = Field(..., description="Target path to analyze (system, /etc, or specific directory)")
    scan_type: str = Field(default="comprehensive", description="Type of scan: quick, comprehensive, compliance")
    compliance_frameworks: List[str] = Field(default=["CIS"], description="Compliance frameworks to check: CIS, NIST, ISO27001")
    include_permissions: bool = Field(default=True, description="Include file permissions analysis")
    include_services: bool = Field(default=True, description="Include services analysis")

class ComplianceCheckRequest(BaseModel):
    """Request model for compliance check"""
    config_file: str = Field(..., description="Configuration file to check")
    framework: str = Field(default="CIS", description="Compliance framework: CIS, NIST, ISO27001")
    service_type: Optional[str] = Field(None, description="Service type: ssh, apache, nginx, mysql")

class ConfigurationIssueResponse(BaseModel):
    """Response model for configuration issue"""
    issue_id: str
    severity: str
    title: str
    description: str
    file_path: str
    line_number: Optional[int] = None
    current_value: str
    recommended_value: str
    compliance_frameworks: List[str]
    remediation_steps: List[str]
    risk_score: float

class ConfigurationScanResponse(BaseModel):
    """Response model for configuration scan status"""
    scan_id: str
    target_path: str
    status: str
    start_time: str
    end_time: Optional[str] = None
    progress_percentage: int = 0
    total_issues: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    compliance_score: float = 0.0
    files_analyzed: Optional[List[str]] = None

class FilePermissionsResponse(BaseModel):
    """Response model for file permissions audit"""
    file_path: str
    current_permissions: str
    recommended_permissions: str
    owner_user: str
    owner_group: str
    is_compliant: bool
    severity: str

class ServicesAuditResponse(BaseModel):
    """Response model for services audit"""
    service_name: str
    service_status: str
    is_dangerous: bool
    is_unnecessary: bool
    recommendation: str

# Dependency to get configuration analyzer
def get_analyzer() -> Any:
    """Dependency to get configuration analyzer instance"""
    try:
        return get_configuration_analyzer()
    except Exception as e:
        logger.error(f"Failed to get configuration analyzer: {e}")
        raise HTTPException(status_code=500, detail="Configuration analyzer unavailable")

# API Endpoints

@router.post("/scan/start", response_model=Dict[str, Any])
async def start_configuration_scan(
    request: ConfigurationScanRequest,
    background_tasks: BackgroundTasks,
    analyzer = Depends(get_analyzer)
):
    """Start a new configuration security scan"""
    try:
        # Validate scan type
        valid_scan_types = ["quick", "comprehensive", "compliance"]
        if request.scan_type not in valid_scan_types:
            raise HTTPException(status_code=400, detail=f"Invalid scan type. Must be one of: {valid_scan_types}")
        
        # Validate target path
        if request.target_path != "system" and not Path(request.target_path).exists():
            raise HTTPException(status_code=400, detail=f"Target path does not exist: {request.target_path}")
        
        # Start the scan
        scan_id = await analyzer.start_configuration_scan(
            target_path=request.target_path,
            scan_type=request.scan_type
        )
        
        logger.info(f"🚀 Started configuration scan {scan_id} for {request.target_path}")
        
        return {
            "status": "success",
            "scan_id": scan_id,
            "message": f"Configuration scan started for {request.target_path}",
            "target_path": request.target_path,
            "scan_type": request.scan_type,
            "estimated_duration": "3-10 minutes"
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to start configuration scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scan/{scan_id}/status", response_model=ConfigurationScanResponse)
async def get_scan_status(
    scan_id: str,
    analyzer = Depends(get_analyzer)
):
    """Get status of a configuration scan"""
    try:
        status = analyzer.get_scan_status(scan_id)
        
        if "error" in status:
            raise HTTPException(status_code=404, detail=status["error"])
        
        # Calculate progress percentage
        progress = 100 if status["status"] in ["completed", "failed"] else 50
        
        response = ConfigurationScanResponse(
            scan_id=status["scan_id"],
            target_path=status["target_path"],
            status=status["status"],
            start_time=status["start_time"],
            end_time=status.get("end_time"),
            progress_percentage=progress,
            total_issues=status.get("total_issues", 0),
            critical_count=status.get("critical_count", 0),
            high_count=status.get("high_count", 0),
            medium_count=status.get("medium_count", 0),
            low_count=status.get("low_count", 0),
            compliance_score=status.get("compliance_score", 0.0)
        )
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to get configuration scan status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scan/{scan_id}/results", response_model=Dict[str, Any])
async def get_scan_results(
    scan_id: str,
    severity_filter: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(100, description="Maximum results to return"),
    analyzer = Depends(get_analyzer)
):
    """Get detailed results of a configuration scan"""
    try:
        # Get basic scan status first
        status = analyzer.get_scan_status(scan_id)
        if "error" in status:
            raise HTTPException(status_code=404, detail=status["error"])
        
        # Get detailed configuration issues
        issues = analyzer.get_configuration_issues(scan_id)
        
        # Apply severity filter if requested
        if severity_filter:
            severity_filter = severity_filter.upper()
            issues = [
                issue for issue in issues 
                if issue.get("severity", "").upper() == severity_filter
            ]
        
        # Limit results
        issues = issues[:limit]
        
        # Format issues for response
        formatted_issues = []
        for issue in issues:
            formatted_issue = ConfigurationIssueResponse(
                issue_id=issue["issue_id"],
                severity=issue["severity"],
                title=issue["title"],
                description=issue["description"],
                file_path=issue["file_path"],
                line_number=issue.get("line_number"),
                current_value=issue["current_value"],
                recommended_value=issue["recommended_value"],
                compliance_frameworks=issue["compliance_frameworks"],
                remediation_steps=issue["remediation_steps"],
                risk_score=issue["risk_score"]
            )
            formatted_issues.append(formatted_issue.dict())
        
        return {
            "scan_id": scan_id,
            "status": status["status"],
            "total_issues": status.get("total_issues", 0),
            "filtered_issues": len(formatted_issues),
            "compliance_score": status.get("compliance_score", 0.0),
            "summary": {
                "critical": status.get("critical_count", 0),
                "high": status.get("high_count", 0),
                "medium": status.get("medium_count", 0),
                "low": status.get("low_count", 0)
            },
            "issues": formatted_issues,
            "scan_info": {
                "target_path": status["target_path"],
                "start_time": status["start_time"],
                "end_time": status.get("end_time")
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to get configuration scan results: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scan/list", response_model=Dict[str, Any])
async def list_configuration_scans(
    limit: int = Query(50, description="Maximum scans to return"),
    status_filter: Optional[str] = Query(None, description="Filter by status"),
    analyzer = Depends(get_analyzer)
):
    """List all configuration scans"""
    try:
        with analyzer.db_manager.get_connection() as conn:
            cursor = conn.cursor()
            
            # Build query with optional status filter
            query = """
                SELECT scan_id, target_path, scan_type, status, start_time, end_time,
                       total_issues, critical_count, high_count, medium_count, low_count,
                       compliance_score, created_at
                FROM config_scans
            """
            params = []
            
            if status_filter:
                query += " WHERE status = ?"
                params.append(status_filter)
            
            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            results = cursor.fetchall()
            
            scans = []
            for row in results:
                scan = {
                    "scan_id": row[0],
                    "target_path": row[1],
                    "scan_type": row[2],
                    "status": row[3],
                    "start_time": row[4],
                    "end_time": row[5],
                    "total_issues": row[6] or 0,
                    "critical_count": row[7] or 0,
                    "high_count": row[8] or 0,
                    "medium_count": row[9] or 0,
                    "low_count": row[10] or 0,
                    "compliance_score": row[11] or 0.0,
                    "created_at": row[12]
                }
                scans.append(scan)
            
            return {
                "scans": scans,
                "total_count": len(scans),
                "filtered_by_status": status_filter
            }
        
    except Exception as e:
        logger.error(f"❌ Failed to list configuration scans: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scan/{scan_id}/permissions", response_model=Dict[str, Any])
async def get_file_permissions_audit(
    scan_id: str,
    analyzer = Depends(get_analyzer)
):
    """Get file permissions audit results for a scan"""
    try:
        with analyzer.db_manager.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT file_path, current_permissions, recommended_permissions,
                       owner_user, owner_group, is_compliant, severity
                FROM file_permissions_audit
                WHERE scan_id = ?
                ORDER BY severity DESC, file_path
            """, (scan_id,))
            
            results = cursor.fetchall()
            
            permissions_audit = []
            for row in results:
                audit = FilePermissionsResponse(
                    file_path=row[0],
                    current_permissions=row[1],
                    recommended_permissions=row[2],
                    owner_user=row[3],
                    owner_group=row[4],
                    is_compliant=bool(row[5]),
                    severity=row[6]
                )
                permissions_audit.append(audit.dict())
            
            return {
                "scan_id": scan_id,
                "permissions_audit": permissions_audit,
                "total_files": len(permissions_audit),
                "compliant_files": len([p for p in permissions_audit if p["is_compliant"]]),
                "non_compliant_files": len([p for p in permissions_audit if not p["is_compliant"]])
            }
        
    except Exception as e:
        logger.error(f"❌ Failed to get file permissions audit: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scan/{scan_id}/services", response_model=Dict[str, Any])
async def get_services_audit(
    scan_id: str,
    analyzer = Depends(get_analyzer)
):
    """Get services audit results for a scan"""
    try:
        with analyzer.db_manager.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT service_name, service_status, is_unnecessary, is_dangerous, recommendation
                FROM services_audit
                WHERE scan_id = ?
                ORDER BY is_dangerous DESC, is_unnecessary DESC, service_name
            """, (scan_id,))
            
            results = cursor.fetchall()
            
            services_audit = []
            for row in results:
                audit = ServicesAuditResponse(
                    service_name=row[0],
                    service_status=row[1],
                    is_unnecessary=bool(row[2]),
                    is_dangerous=bool(row[3]),
                    recommendation=row[4]
                )
                services_audit.append(audit.dict())
            
            return {
                "scan_id": scan_id,
                "services_audit": services_audit,
                "total_services": len(services_audit),
                "dangerous_services": len([s for s in services_audit if s["is_dangerous"]]),
                "unnecessary_services": len([s for s in services_audit if s["is_unnecessary"]])
            }
        
    except Exception as e:
        logger.error(f"❌ Failed to get services audit: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/compliance/check", response_model=Dict[str, Any])
async def quick_compliance_check(
    request: ComplianceCheckRequest,
    analyzer = Depends(get_analyzer)
):
    """Perform quick compliance check on a single configuration file"""
    try:
        # Validate file exists
        if not Path(request.config_file).exists():
            raise HTTPException(status_code=400, detail=f"Configuration file not found: {request.config_file}")
        
        # Start a focused scan on the specific file
        scan_id = await analyzer.start_configuration_scan(
            target_path=request.config_file,
            scan_type="compliance"
        )
        
        # Wait a bit for scan to complete (this is a quick check)
        await asyncio.sleep(2)
        
        # Get results
        status = analyzer.get_scan_status(scan_id)
        issues = analyzer.get_configuration_issues(scan_id)
        
        return {
            "file_path": request.config_file,
            "framework": request.framework,
            "service_type": request.service_type,
            "compliance_score": status.get("compliance_score", 0.0),
            "total_issues": len(issues),
            "issues_summary": {
                "critical": status.get("critical_count", 0),
                "high": status.get("high_count", 0),
                "medium": status.get("medium_count", 0),
                "low": status.get("low_count", 0)
            },
            "top_issues": issues[:5],  # Return top 5 issues
            "scan_id": scan_id
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to perform compliance check: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/frameworks", response_model=Dict[str, Any])
async def get_compliance_frameworks(analyzer = Depends(get_analyzer)):
    """Get available compliance frameworks and their rules"""
    try:
        frameworks_info = {
            "CIS": {
                "name": "Center for Internet Security",
                "description": "Industry-standard security configuration benchmarks",
                "supported_services": ["ssh", "apache", "nginx", "mysql", "file_permissions"],
                "severity_levels": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            },
            "NIST": {
                "name": "National Institute of Standards and Technology",
                "description": "Federal cybersecurity framework and guidelines",
                "supported_services": ["password_policy", "account_lockout", "audit_logging"],
                "severity_levels": ["HIGH", "MEDIUM", "LOW"]
            },
            "ISO27001": {
                "name": "ISO/IEC 27001",
                "description": "International standard for information security management",
                "supported_services": ["access_control", "cryptography", "system_security"],
                "severity_levels": ["HIGH", "MEDIUM", "LOW"]
            }
        }
        
        return {
            "available_frameworks": frameworks_info,
            "default_framework": "CIS",
            "supported_file_types": [
                "SSH configuration (/etc/ssh/sshd_config)",
                "Apache configuration (.conf files)",
                "Nginx configuration (.conf files)",
                "MySQL configuration (.cnf files)",
                "System files (/etc/passwd, /etc/shadow, etc.)",
                "Generic configuration files"
            ]
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to get compliance frameworks: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/scan/{scan_id}", response_model=Dict[str, Any])
async def delete_configuration_scan(
    scan_id: str,
    analyzer = Depends(get_analyzer)
):
    """Delete configuration scan results"""
    try:
        with analyzer.db_manager.get_connection() as conn:
            cursor = conn.cursor()
            
            # Check if scan exists
            cursor.execute("SELECT COUNT(*) FROM config_scans WHERE scan_id = ?", (scan_id,))
            if cursor.fetchone()[0] == 0:
                raise HTTPException(status_code=404, detail="Scan not found")
            
            # Delete related records first (foreign key constraints)
            cursor.execute("DELETE FROM config_issues WHERE scan_id = ?", (scan_id,))
            issues_deleted = cursor.rowcount
            
            cursor.execute("DELETE FROM file_permissions_audit WHERE scan_id = ?", (scan_id,))
            permissions_deleted = cursor.rowcount
            
            cursor.execute("DELETE FROM services_audit WHERE scan_id = ?", (scan_id,))
            services_deleted = cursor.rowcount
            
            # Delete main scan record
            cursor.execute("DELETE FROM config_scans WHERE scan_id = ?", (scan_id,))
            scan_deleted = cursor.rowcount
            
            conn.commit()
            
            # Remove from active scans if present
            if scan_id in analyzer._active_scans:
                del analyzer._active_scans[scan_id]
            
            logger.info(f"🗑️ Deleted configuration scan {scan_id}")
            
            return {
                "status": "success",
                "message": f"Configuration scan {scan_id} deleted successfully",
                "deleted_records": {
                    "scan": scan_deleted,
                    "issues": issues_deleted,
                    "permissions": permissions_deleted,
                    "services": services_deleted
                }
            }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to delete configuration scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health", response_model=Dict[str, Any])
async def configuration_health_check(analyzer = Depends(get_analyzer)):
    """Health check for configuration analyzer"""
    try:
        # Test database connection
        with analyzer.db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM config_scans")
            scans_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM config_issues")
            issues_count = cursor.fetchone()[0]
        
        # Check active scans
        active_scans = len(analyzer._active_scans)
        
        return {
            "status": "healthy",
            "configuration_analyzer": "operational",
            "database": {
                "connected": True,
                "total_scans": scans_count,
                "total_issues": issues_count
            },
            "active_scans": active_scans,
            "compliance_frameworks": ["CIS", "NIST", "ISO27001"],
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"❌ Configuration analyzer health check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Health check failed: {e}")

# Background task for automated compliance monitoring
@router.post("/monitor/start", response_model=Dict[str, Any])
async def start_compliance_monitoring(
    target_paths: List[str] = Query(..., description="Paths to monitor"),
    check_interval: int = Query(3600, description="Check interval in seconds"),
    background_tasks: BackgroundTasks = None,
    analyzer = Depends(get_analyzer)
):
    """Start automated compliance monitoring"""
    try:
        # This would implement continuous monitoring
        # For now, return a placeholder response
        
        return {
            "status": "success",
            "message": "Compliance monitoring started",
            "monitored_paths": target_paths,
            "check_interval": check_interval,
            "note": "Continuous monitoring feature to be implemented"
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to start compliance monitoring: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    print("Configuration Analysis API module loaded successfully")
    print("Available endpoints:")
    for route in router.routes:
        if hasattr(route, 'methods') and hasattr(route, 'path'):
            methods = list(route.methods)
            print(f"  {methods[0]:6} {route.path}")