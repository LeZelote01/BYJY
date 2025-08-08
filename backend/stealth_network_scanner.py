#!/usr/bin/env python3
"""
CyberSec Assistant Portable - Stealth Network Scanner V1.0
Système de scan réseau furtif avec intégration Nmap et techniques d'évasion
Features: Decoy Scanning, Fragmentation, Timing Control, Anti-Detection
"""

import os
import sys
import json
import time
import random
import subprocess
import threading
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass
import ipaddress
import socket

from stealth_engine import get_global_stealth_engine
from proxy_manager import get_global_proxy_manager

logger = logging.getLogger(__name__)

@dataclass
class ScanTarget:
    """Représente une cible de scan"""
    host: str
    ports: str = "1-1000"
    scan_type: str = "syn"
    stealth_level: int = 7

@dataclass
class ScanResult:
    """Résultat de scan réseau"""
    target: str
    scan_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    status: str = "running"
    open_ports: List[Dict] = None
    services: List[Dict] = None
    os_detection: Dict = None
    vulnerabilities: List[Dict] = None
    raw_output: str = ""
    stealth_score: float = 100.0
    progress: float = 0.0
    current_phase: str = "initializing"
    total_ports: int = 0
    scanned_ports: int = 0

class StealthNetworkScanner:
    """
    Scanner réseau furtif avec intégration Nmap et techniques d'évasion avancées
    """
    
    def __init__(self):
        self.stealth_engine = get_global_stealth_engine()
        self.proxy_manager = get_global_proxy_manager()
        self.active_scans = {}
        self.scan_history = []
        self.nmap_path = self._find_nmap_executable()
        
        # Configuration des techniques furtives
        self.stealth_techniques = {
            "decoy_scanning": True,
            "fragmentation": True,
            "timing_evasion": True,
            "source_port_spoofing": True,
            "tcp_sequence_prediction": True,
            "idle_zombie_scan": False,  # Plus avancé
            "dns_resolution_bypass": True
        }
        
        # Base de données des décoys
        self.decoy_hosts = [
            "8.8.8.8",      # Google DNS
            "1.1.1.1",      # Cloudflare DNS
            "208.67.222.222", # OpenDNS
            "4.2.2.2",      # Level3 DNS
            "9.9.9.9",      # Quad9 DNS
        ]
        
        logger.info("✅ Stealth Network Scanner initialized")
    
    def _find_nmap_executable(self) -> Optional[str]:
        """Trouver l'exécutable Nmap"""
        possible_paths = [
            "/usr/bin/nmap",
            "/usr/local/bin/nmap",
            "nmap",  # PATH
            "tools/nmap/nmap",  # Portable
            "tools/nmap.exe"    # Windows portable
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run([path, "--version"], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    logger.info(f"✅ Nmap found: {path}")
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        logger.warning("⚠️ Nmap not found - using basic scanner")
        return None
    
    def create_stealth_scan(self, target: ScanTarget) -> str:
        """Créer un scan furtif"""
        scan_id = f"scan_{int(time.time())}_{random.randint(1000, 9999)}"
        
        scan_result = ScanResult(
            target=target.host,
            scan_id=scan_id,
            start_time=datetime.now(),
            open_ports=[],
            services=[],
            os_detection={},
            vulnerabilities=[]
        )
        
        self.active_scans[scan_id] = scan_result
        
        # Démarrer le scan en arrière-plan
        scan_thread = threading.Thread(
            target=self._execute_stealth_scan,
            args=(scan_id, target),
            daemon=True
        )
        scan_thread.start()
        
        logger.info(f"🕵️ Stealth scan initiated: {scan_id} -> {target.host}")
        return scan_id
    
    def _execute_stealth_scan(self, scan_id: str, target: ScanTarget):
        """Exécuter le scan furtif avec progression en temps réel"""
        scan_result = self.active_scans[scan_id]
        
        try:
            # Phase 1: Initialisation (0-10%)
            scan_result.current_phase = "initializing"
            scan_result.progress = 5.0
            
            # Calculer le nombre total de ports
            if '-' in target.ports:
                start, end = map(int, target.ports.split('-'))
                scan_result.total_ports = end - start + 1
            else:
                scan_result.total_ports = len(target.ports.split(','))
            
            scan_result.progress = 10.0
            time.sleep(0.5)  # Simulation de l'initialisation
            
            # Phase 2: Préparation du scan (10-20%)
            scan_result.current_phase = "preparing"
            scan_result.progress = 15.0
            time.sleep(0.5)
            
            if self.nmap_path:
                # Phase 3: Scan Nmap avec progression (20-90%)
                scan_result.current_phase = "scanning"
                nmap_result = self._nmap_stealth_scan_with_progress(target, scan_result)
                scan_result.raw_output = nmap_result.get("raw_output", "")
                scan_result.open_ports = nmap_result.get("open_ports", [])
                scan_result.services = nmap_result.get("services", [])
                scan_result.os_detection = nmap_result.get("os_detection", {})
            else:
                # Scanner basique avec progression
                scan_result.current_phase = "scanning"
                basic_result = self._basic_stealth_scan_with_progress(target, scan_result)
                scan_result.open_ports = basic_result.get("open_ports", [])
                scan_result.services = basic_result.get("services", [])
            
            # Phase 4: Analyse des vulnérabilités (90-95%)
            scan_result.current_phase = "analyzing"
            scan_result.progress = 90.0
            scan_result.vulnerabilities = self._analyze_vulnerabilities(scan_result)
            scan_result.progress = 95.0
            
            # Phase 5: Finalisation (95-100%)
            scan_result.current_phase = "finalizing"
            scan_result.stealth_score = self._calculate_stealth_score(target)
            scan_result.progress = 100.0
            scan_result.status = "completed"
            scan_result.end_time = datetime.now()
            
            logger.info(f"✅ Stealth scan completed: {scan_id}")
            
        except Exception as e:
            logger.error(f"❌ Stealth scan failed: {scan_id} - {e}")
            scan_result.status = "failed"
            scan_result.current_phase = "failed"
            scan_result.raw_output = f"Error: {str(e)}"
            scan_result.end_time = datetime.now()
        
        # Nettoyer les traces
        self.stealth_engine.cleanup_forensics()
    
    def _nmap_stealth_scan_with_progress(self, target: ScanTarget, scan_result: ScanResult) -> Dict[str, Any]:
        """Exécuter un scan Nmap furtif avec progression en temps réel"""
        stealth_level = target.stealth_level
        
        # Construire la commande Nmap furtive
        nmap_cmd = [self.nmap_path]
        
        # Type de scan selon le niveau de furtivité
        if stealth_level >= 9:
            # Maximum stealth - Idle/Zombie scan si possible
            nmap_cmd.extend(["-sI", random.choice(self.decoy_hosts)])
        elif stealth_level >= 7:
            # SYN scan avec decoys
            nmap_cmd.extend(["-sS"])
        elif stealth_level >= 5:
            # FIN scan (plus furtif que SYN)
            nmap_cmd.extend(["-sF"])
        else:
            # TCP connect scan
            nmap_cmd.extend(["-sT"])
        
        # Ajout des décoys pour masquer la source
        if self.stealth_techniques["decoy_scanning"] and stealth_level >= 6:
            decoys = random.sample(self.decoy_hosts, min(3, len(self.decoy_hosts)))
            decoy_list = ",".join(decoys) + ",ME"
            nmap_cmd.extend(["-D", decoy_list])
        
        # Fragmentation des paquets
        if self.stealth_techniques["fragmentation"] and stealth_level >= 7:
            nmap_cmd.append("-f")  # Fragment packets
        
        # Source port spoofing
        if self.stealth_techniques["source_port_spoofing"] and stealth_level >= 5:
            common_ports = [53, 80, 443, 25, 21]  # DNS, HTTP, HTTPS, SMTP, FTP
            source_port = random.choice(common_ports)
            nmap_cmd.extend(["--source-port", str(source_port)])
        
        # Timing template selon le niveau
        timing_templates = {
            10: "-T0",  # Paranoid (très lent)
            9: "-T1",   # Sneaky
            7: "-T2",   # Polite
            5: "-T3",   # Normal
            3: "-T4",   # Aggressive
            1: "-T5"    # Insane
        }
        
        timing = timing_templates.get(stealth_level, "-T2")
        nmap_cmd.append(timing)
        
        # Ports à scanner
        nmap_cmd.extend(["-p", target.ports])
        
        # Options additionnelles pour l'évasion
        if stealth_level >= 8:
            nmap_cmd.extend([
                "--randomize-hosts",  # Ordre aléatoire
                "--data-length", str(random.randint(10, 50)),  # Padding aléatoire
                "--max-retries", "1",  # Limiter les retries
                "--host-timeout", "300s"  # Timeout
            ])
        
        # Detection de services et OS si niveau élevé
        if stealth_level >= 6:
            nmap_cmd.extend(["-sV", "--version-intensity", "2"])
        
        if stealth_level >= 8:
            nmap_cmd.extend(["-O", "--osscan-guess"])
        
        # Format de sortie XML pour parsing
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False)
        temp_file.close()
        nmap_cmd.extend(["-oX", temp_file.name])
        
        # Bypass DNS resolution si nécessaire
        if self.stealth_techniques["dns_resolution_bypass"]:
            nmap_cmd.append("-n")
        
        # Cible
        nmap_cmd.append(target.host)
        
        # Appliquer le délai de furtivité avant execution
        delay = self.stealth_engine.apply_stealth_timing()
        logger.debug(f"🕐 Applied stealth delay: {delay:.2f}s")
        
        # Exécuter la commande avec progression
        logger.debug(f"🔍 Executing stealth nmap: {' '.join(nmap_cmd)}")
        
        try:
            # Démarrer le processus
            process = subprocess.Popen(
                nmap_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Simuler la progression basée sur le timing
            progress_start = 20.0
            progress_end = 90.0
            scan_duration = self._estimate_scan_duration(target, stealth_level)
            
            start_time = time.time()
            while process.poll() is None:
                # Calculer la progression basée sur le temps écoulé
                elapsed = time.time() - start_time
                progress = progress_start + (elapsed / scan_duration) * (progress_end - progress_start)
                progress = min(progress, progress_end)
                
                scan_result.progress = progress
                scan_result.scanned_ports = int((progress - progress_start) / (progress_end - progress_start) * scan_result.total_ports)
                
                time.sleep(0.5)  # Mise à jour toutes les 0.5 secondes
                
                # Timeout après 30 minutes
                if elapsed > 1800:
                    process.terminate()
                    break
            
            # Attendre la fin du processus
            stdout, stderr = process.communicate(timeout=30)
            
            # Parser les résultats XML
            results = self._parse_nmap_xml(temp_file.name)
            results["raw_output"] = stdout
            
            # Nettoyer le fichier temporaire
            os.unlink(temp_file.name)
            
            return results
            
        except subprocess.TimeoutExpired:
            logger.warning("⚠️ Nmap scan timed out")
            return {"error": "Scan timeout", "raw_output": "Timeout after 30 minutes"}
        except Exception as e:
            logger.error(f"❌ Nmap execution failed: {e}")
            return {"error": str(e), "raw_output": f"Execution error: {e}"}
        """Exécuter un scan Nmap furtif"""
        stealth_level = target.stealth_level
        
        # Construire la commande Nmap furtive
        nmap_cmd = [self.nmap_path]
        
        # Type de scan selon le niveau de furtivité
        if stealth_level >= 9:
            # Maximum stealth - Idle/Zombie scan si possible
            nmap_cmd.extend(["-sI", random.choice(self.decoy_hosts)])
        elif stealth_level >= 7:
            # SYN scan avec decoys
            nmap_cmd.extend(["-sS"])
        elif stealth_level >= 5:
            # FIN scan (plus furtif que SYN)
            nmap_cmd.extend(["-sF"])
        else:
            # TCP connect scan
            nmap_cmd.extend(["-sT"])
        
        # Ajout des décoys pour masquer la source
        if self.stealth_techniques["decoy_scanning"] and stealth_level >= 6:
            decoys = random.sample(self.decoy_hosts, min(3, len(self.decoy_hosts)))
            decoy_list = ",".join(decoys) + ",ME"
            nmap_cmd.extend(["-D", decoy_list])
        
        # Fragmentation des paquets
        if self.stealth_techniques["fragmentation"] and stealth_level >= 7:
            nmap_cmd.append("-f")  # Fragment packets
        
        # Source port spoofing
        if self.stealth_techniques["source_port_spoofing"] and stealth_level >= 5:
            common_ports = [53, 80, 443, 25, 21]  # DNS, HTTP, HTTPS, SMTP, FTP
            source_port = random.choice(common_ports)
            nmap_cmd.extend(["--source-port", str(source_port)])
        
        # Timing template selon le niveau
        timing_templates = {
            10: "-T0",  # Paranoid (très lent)
            9: "-T1",   # Sneaky
            7: "-T2",   # Polite
            5: "-T3",   # Normal
            3: "-T4",   # Aggressive
            1: "-T5"    # Insane
        }
        
        timing = timing_templates.get(stealth_level, "-T2")
        nmap_cmd.append(timing)
        
        # Ports à scanner
        nmap_cmd.extend(["-p", target.ports])
        
        # Options additionnelles pour l'évasion
        if stealth_level >= 8:
            nmap_cmd.extend([
                "--randomize-hosts",  # Ordre aléatoire
                "--data-length", str(random.randint(10, 50)),  # Padding aléatoire
                "--max-retries", "1",  # Limiter les retries
                "--host-timeout", "300s"  # Timeout
            ])
        
        # Detection de services et OS si niveau élevé
        if stealth_level >= 6:
            nmap_cmd.extend(["-sV", "--version-intensity", "2"])
        
        if stealth_level >= 8:
            nmap_cmd.extend(["-O", "--osscan-guess"])
        
        # Format de sortie XML pour parsing
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False)
        temp_file.close()
        nmap_cmd.extend(["-oX", temp_file.name])
        
        # Bypass DNS resolution si nécessaire
        if self.stealth_techniques["dns_resolution_bypass"]:
            nmap_cmd.append("-n")
        
        # Cible
        nmap_cmd.append(target.host)
        
        # Appliquer le délai de furtivité avant execution
        delay = self.stealth_engine.apply_stealth_timing()
        logger.debug(f"🕐 Applied stealth delay: {delay:.2f}s")
        
        # Exécuter la commande
        logger.debug(f"🔍 Executing stealth nmap: {' '.join(nmap_cmd)}")
        
        try:
            process = subprocess.run(
                nmap_cmd,
                capture_output=True,
                text=True,
                timeout=1800  # 30 minutes max
            )
            
            # Parser les résultats XML
            results = self._parse_nmap_xml(temp_file.name)
            results["raw_output"] = process.stdout
            
            # Nettoyer le fichier temporaire
            os.unlink(temp_file.name)
            
            return results
            
        except subprocess.TimeoutExpired:
            logger.warning("⚠️ Nmap scan timed out")
            return {"error": "Scan timeout", "raw_output": "Timeout after 30 minutes"}
        except Exception as e:
            logger.error(f"❌ Nmap execution failed: {e}")
            return {"error": str(e), "raw_output": f"Execution error: {e}"}
    
    def _parse_nmap_xml(self, xml_file: str) -> Dict[str, Any]:
        """Parser les résultats XML de Nmap"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            results = {
                "open_ports": [],
                "services": [],
                "os_detection": {},
                "scan_stats": {}
            }
            
            # Parser les hosts
            for host in root.findall(".//host"):
                # États des ports
                for port in host.findall(".//port"):
                    port_id = port.get("portid")
                    protocol = port.get("protocol")
                    
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        port_info = {
                            "port": int(port_id),
                            "protocol": protocol,
                            "state": state.get("state")
                        }
                        
                        # Information de service
                        service = port.find("service")
                        if service is not None:
                            port_info.update({
                                "service": service.get("name", "unknown"),
                                "version": service.get("version", ""),
                                "product": service.get("product", ""),
                                "extra_info": service.get("extrainfo", "")
                            })
                            
                            results["services"].append(port_info.copy())
                        
                        results["open_ports"].append(port_info)
                
                # Détection OS
                os_elem = host.find(".//os")
                if os_elem is not None:
                    osmatch = os_elem.find("osmatch")
                    if osmatch is not None:
                        results["os_detection"] = {
                            "name": osmatch.get("name", ""),
                            "accuracy": osmatch.get("accuracy", "0"),
                            "line": osmatch.get("line", "")
                        }
            
            # Stats du scan
            runstats = root.find(".//runstats")
            if runstats is not None:
                finished = runstats.find("finished")
                if finished is not None:
                    results["scan_stats"] = {
                        "elapsed_time": finished.get("elapsed"),
                        "exit_code": finished.get("exit")
                    }
            
            return results
            
        except Exception as e:
            logger.error(f"❌ Failed to parse nmap XML: {e}")
            return {"error": f"XML parsing failed: {e}"}
    
    def _basic_stealth_scan_with_progress(self, target: ScanTarget, scan_result: ScanResult) -> Dict[str, Any]:
        """Scanner basique intégré avec progression en temps réel"""
        try:
            host = target.host
            port_range = self._parse_port_range(target.ports)
            stealth_level = target.stealth_level
            
            open_ports = []
            services = []
            
            # Appliquer les délais de furtivité
            base_delay = 0.1 if stealth_level < 5 else 0.5 if stealth_level < 8 else 1.0
            
            progress_start = 20.0
            progress_end = 90.0
            total_ports = len(port_range)
            
            for i, port in enumerate(port_range):
                try:
                    # Calculer la progression réelle
                    progress = progress_start + (i / total_ports) * (progress_end - progress_start)
                    scan_result.progress = progress
                    scan_result.scanned_ports = i + 1
                    
                    # Délai furtif entre chaque port
                    if stealth_level >= 5:
                        delay = random.uniform(base_delay, base_delay * 2)
                        time.sleep(delay)
                    
                    # Test de connexion TCP
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2.0)
                    
                    result = sock.connect_ex((host, port))
                    
                    if result == 0:
                        port_info = {
                            "port": port,
                            "protocol": "tcp",
                            "state": "open"
                        }
                        
                        # Tentative de détection de service basique
                        service_name = self._detect_service(host, port)
                        if service_name:
                            port_info["service"] = service_name
                            services.append(port_info.copy())
                        
                        open_ports.append(port_info)
                        logger.debug(f"✅ Port ouvert: {host}:{port}")
                    
                    sock.close()
                    
                except Exception as e:
                    logger.debug(f"Port {port} test failed: {e}")
                    continue
            
            # Finaliser la progression
            scan_result.progress = progress_end
            scan_result.scanned_ports = total_ports
            
            return {
                "open_ports": open_ports,
                "services": services,
                "scan_method": "basic_tcp_connect"
            }
            
        except Exception as e:
            logger.error(f"❌ Basic scan failed: {e}")
            return {"error": str(e)}
        """Scanner basique intégré pour quand Nmap n'est pas disponible"""
        try:
            host = target.host
            port_range = self._parse_port_range(target.ports)
            stealth_level = target.stealth_level
            
            open_ports = []
            services = []
            
            # Appliquer les délais de furtivité
            base_delay = 0.1 if stealth_level < 5 else 0.5 if stealth_level < 8 else 1.0
            
            for port in port_range:
                try:
                    # Délai furtif entre chaque port
                    if stealth_level >= 5:
                        delay = random.uniform(base_delay, base_delay * 2)
                        time.sleep(delay)
                    
                    # Test de connexion TCP
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2.0)
                    
                    result = sock.connect_ex((host, port))
                    
                    if result == 0:
                        port_info = {
                            "port": port,
                            "protocol": "tcp",
                            "state": "open"
                        }
                        
                        # Tentative de détection de service basique
                        service_name = self._detect_service(host, port)
                        if service_name:
                            port_info["service"] = service_name
                            services.append(port_info.copy())
                        
                        open_ports.append(port_info)
                        logger.debug(f"✅ Port ouvert: {host}:{port}")
                    
                    sock.close()
                    
                except Exception as e:
                    logger.debug(f"Port {port} test failed: {e}")
                    continue
            
            return {
                "open_ports": open_ports,
                "services": services,
                "scan_method": "basic_tcp_connect"
            }
            
        except Exception as e:
            logger.error(f"❌ Basic scan failed: {e}")
            return {"error": str(e)}
    
    def _estimate_scan_duration(self, target: ScanTarget, stealth_level: int) -> float:
        """Estimer la durée du scan basée sur les paramètres"""
        # Calculer le nombre de ports
        if '-' in target.ports:
            start, end = map(int, target.ports.split('-'))
            port_count = end - start + 1
        else:
            port_count = len(target.ports.split(','))
        
        # Base de temps par port selon le niveau de furtivité
        time_per_port = {
            10: 2.0,    # Paranoid - très lent
            9: 1.5,     # Sneaky
            8: 1.0,     # High stealth
            7: 0.8,     # Stealth
            6: 0.6,     # Moderate stealth
            5: 0.4,     # Normal
            4: 0.3,     # Fast
            3: 0.2,     # Aggressive
            2: 0.15,    # Very fast
            1: 0.1      # Insane
        }.get(stealth_level, 0.5)
        
        # Durée estimée
        estimated_duration = port_count * time_per_port
        
        # Ajouter du temps pour les techniques avancées
        if stealth_level >= 8:
            estimated_duration *= 1.5  # OS detection, service detection
        
        return max(estimated_duration, 10.0)  # Minimum 10 secondes
    
    def _parse_port_range(self, port_string: str) -> List[int]:
        """Parser une chaîne de ports (ex: "1-100,443,8080")"""
        ports = []
        
        for part in port_string.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, min(end + 1, 65536)))
            else:
                ports.append(int(part))
        
        return sorted(list(set(ports)))
    
    def _detect_service(self, host: str, port: int) -> Optional[str]:
        """Détection basique de service"""
        common_services = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            993: "imaps",
            995: "pop3s",
            3389: "rdp",
            5432: "postgresql",
            3306: "mysql",
            1433: "mssql",
            27017: "mongodb"
        }
        
        return common_services.get(port, "unknown")
    
    def _analyze_vulnerabilities(self, scan_result: ScanResult) -> List[Dict]:
        """Analyser les vulnérabilités potentielles"""
        vulnerabilities = []
        
        # Base de données simplifiée des vulnérabilités
        vuln_db = {
            21: {"name": "FTP Anonymous Login", "severity": "medium"},
            23: {"name": "Telnet Unencrypted", "severity": "high"},
            80: {"name": "HTTP Information Disclosure", "severity": "low"},
            135: {"name": "Windows RPC Vulnerability", "severity": "high"},
            139: {"name": "NetBIOS Session Service", "severity": "medium"},
            445: {"name": "SMB Service", "severity": "high"},
            1433: {"name": "MSSQL Default Configuration", "severity": "medium"},
            3389: {"name": "RDP Service Exposed", "severity": "high"}
        }
        
        for port_info in scan_result.open_ports:
            port = port_info["port"]
            if port in vuln_db:
                vuln = vuln_db[port].copy()
                vuln["port"] = port
                vuln["service"] = port_info.get("service", "unknown")
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _calculate_stealth_score(self, target: ScanTarget) -> float:
        """Calculer le score de furtivité du scan"""
        base_score = 100.0
        
        # Pénalités selon les techniques utilisées
        if not self.stealth_techniques["decoy_scanning"]:
            base_score -= 15
        
        if not self.stealth_techniques["fragmentation"]:
            base_score -= 10
        
        if target.stealth_level < 5:
            base_score -= 20
        elif target.stealth_level < 7:
            base_score -= 10
        
        # Bonus pour utilisation de proxies
        if self.proxy_manager.get_current_proxy():
            base_score += 10
        
        return max(0, min(100, base_score))
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Obtenir le statut d'un scan"""
        if scan_id not in self.active_scans:
            return None
        
        scan_result = self.active_scans[scan_id]
        
        return {
            "scan_id": scan_id,
            "target": scan_result.target,
            "status": scan_result.status,
            "start_time": scan_result.start_time.isoformat(),
            "end_time": scan_result.end_time.isoformat() if scan_result.end_time else None,
            "open_ports_count": len(scan_result.open_ports),
            "services_count": len(scan_result.services),
            "vulnerabilities_count": len(scan_result.vulnerabilities),
            "stealth_score": scan_result.stealth_score,
            "progress": scan_result.progress,
            "current_phase": scan_result.current_phase,
            "total_ports": scan_result.total_ports,
            "scanned_ports": scan_result.scanned_ports
        }
    
    def get_scan_results(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Obtenir les résultats complets d'un scan"""
        if scan_id not in self.active_scans:
            return None
        
        scan_result = self.active_scans[scan_id]
        
        return {
            "scan_id": scan_id,
            "target": scan_result.target,
            "status": scan_result.status,
            "start_time": scan_result.start_time.isoformat(),
            "end_time": scan_result.end_time.isoformat() if scan_result.end_time else None,
            "open_ports": scan_result.open_ports,
            "services": scan_result.services,
            "os_detection": scan_result.os_detection,
            "vulnerabilities": scan_result.vulnerabilities,
            "stealth_score": scan_result.stealth_score,
            "raw_output": scan_result.raw_output if scan_result.status == "completed" else ""
        }
    
    def list_active_scans(self) -> List[Dict[str, Any]]:
        """Lister tous les scans actifs"""
        return [self.get_scan_status(scan_id) for scan_id in self.active_scans.keys()]
    
    def cancel_scan(self, scan_id: str) -> bool:
        """Annuler un scan"""
        if scan_id in self.active_scans:
            scan_result = self.active_scans[scan_id]
            scan_result.status = "cancelled"
            scan_result.end_time = datetime.now()
            logger.info(f"🛑 Scan cancelled: {scan_id}")
            return True
        return False
    
    def get_scanner_statistics(self) -> Dict[str, Any]:
        """Obtenir les statistiques du scanner"""
        total_scans = len(self.active_scans)
        completed_scans = len([s for s in self.active_scans.values() if s.status == "completed"])
        running_scans = len([s for s in self.active_scans.values() if s.status == "running"])
        
        avg_stealth_score = 0
        if completed_scans > 0:
            total_score = sum(s.stealth_score for s in self.active_scans.values() if s.status == "completed")
            avg_stealth_score = total_score / completed_scans
        
        return {
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "running_scans": running_scans,
            "success_rate": (completed_scans / total_scans * 100) if total_scans > 0 else 0,
            "average_stealth_score": avg_stealth_score,
            "nmap_available": self.nmap_path is not None,
            "stealth_techniques": self.stealth_techniques,
            "proxy_enabled": self.proxy_manager.get_current_proxy() is not None
        }

# Factory functions
def get_stealth_scanner() -> StealthNetworkScanner:
    """Obtenir une instance du scanner furtif"""
    return StealthNetworkScanner()

# Global instance
_scanner = None

def get_global_stealth_scanner() -> StealthNetworkScanner:
    """Obtenir l'instance globale du scanner furtif"""
    global _scanner
    if _scanner is None:
        _scanner = get_stealth_scanner()
    return _scanner