#!/usr/bin/env python3
"""
CyberSec Assistant Portable - Stealth Integration Module V1.0
Intégration de la furtivité dans tous les modules existants
Features: Terminal Stealth, Monitoring Stealth, Database Security, Integrated Evasion
"""

import os
import sys
import json
import time
import random
import hashlib
import tempfile
import subprocess
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
import logging
import psutil

from stealth_engine import get_global_stealth_engine
from proxy_manager import get_global_proxy_manager
from evasion_manager import get_global_evasion_manager

logger = logging.getLogger(__name__)

class StealthTerminal:
    """
    Terminal furtif avec masquage des commandes et anti-forensics
    """
    
    def __init__(self):
        self.stealth_engine = get_global_stealth_engine()
        self.evasion_manager = get_global_evasion_manager()
        self.command_history = []
        self.obfuscated_history = {}
        self.temp_files = set()
        
        # Commandes sensibles à obfusquer/masquer
        self.sensitive_commands = {
            'nmap', 'netcat', 'nc', 'telnet', 'ssh', 'ftp', 'wget', 'curl',
            'ping', 'traceroute', 'dig', 'nslookup', 'whois', 'hydra',
            'john', 'hashcat', 'aircrack-ng', 'wireshark', 'tcpdump',
            'metasploit', 'msfconsole', 'sqlmap', 'nikto', 'dirb', 'gobuster'
        }
        
        logger.info("🕵️ Stealth Terminal initialized")
    
    def execute_stealth_command(self, command: str, working_dir: str = None) -> Dict[str, Any]:
        """Exécuter une commande avec techniques de furtivité"""
        try:
            # Analyser la commande pour détecter les outils sensibles
            is_sensitive = any(tool in command.lower() for tool in self.sensitive_commands)
            
            if is_sensitive:
                return self._execute_sensitive_command(command, working_dir)
            else:
                return self._execute_normal_command(command, working_dir)
                
        except Exception as e:
            logger.error(f"❌ Stealth command execution failed: {e}")
            return {
                "stdout": "",
                "stderr": f"Command execution failed: {str(e)}",
                "exit_code": 1,
                "timestamp": datetime.now().isoformat(),
                "stealth_applied": False
            }
    
    def _execute_sensitive_command(self, command: str, working_dir: str = None) -> Dict[str, Any]:
        """Exécuter une commande sensible avec maximum de furtivité"""
        logger.info(f"🔒 Executing sensitive command with stealth: {command[:20]}...")
        
        # Appliquer le profil d'évasion maximum
        current_profile = self.evasion_manager.current_profile.name
        if current_profile != "maximum":
            self.evasion_manager.activate_profile("maximum")
        
        try:
            # Créer un environnement d'exécution furtif
            stealth_env = self._create_stealth_environment()
            
            # Obfusquer la commande dans l'historique
            obfuscated_cmd = self._obfuscate_command(command)
            self.obfuscated_history[obfuscated_cmd] = command
            
            # Créer un fichier temporaire pour la sortie
            temp_output = tempfile.mktemp(prefix="stealth_", suffix=".out")
            self.temp_files.add(temp_output)
            
            # Modifier la commande pour réduire les traces
            stealth_command = self._wrap_command_with_stealth(command, temp_output)
            
            # Exécuter avec délai anti-détection
            start_time = time.time()
            process = subprocess.Popen(
                stealth_command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=working_dir,
                env=stealth_env
            )
            
            # Appliquer des délais aléatoires pour éviter la détection
            self._apply_execution_delays(process)
            
            stdout, stderr = process.communicate()
            
            # Nettoyer les traces
            self._cleanup_execution_traces(temp_output)
            
            # Signaler le succès ou l'échec
            if process.returncode == 0:
                self.evasion_manager.report_success("stealth_terminal")
            else:
                self.evasion_manager.report_detection_event(
                    "command_failed",
                    "stealth_terminal",
                    {"command": obfuscated_cmd, "exit_code": process.returncode}
                )
            
            return {
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": process.returncode,
                "timestamp": datetime.now().isoformat(),
                "execution_time": time.time() - start_time,
                "stealth_applied": True,
                "obfuscated_command": obfuscated_cmd
            }
            
        finally:
            # Restaurer le profil d'origine si nécessaire
            if current_profile != "maximum":
                self.evasion_manager.activate_profile(current_profile)
    
    def _execute_normal_command(self, command: str, working_dir: str = None) -> Dict[str, Any]:
        """Exécuter une commande normale avec furtivité de base"""
        try:
            start_time = time.time()
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=working_dir
            )
            
            stdout, stderr = process.communicate()
            
            return {
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": process.returncode,
                "timestamp": datetime.now().isoformat(),
                "execution_time": time.time() - start_time,
                "stealth_applied": False
            }
            
        except Exception as e:
            return {
                "stdout": "",
                "stderr": str(e),
                "exit_code": 1,
                "timestamp": datetime.now().isoformat(),
                "stealth_applied": False
            }
    
    def _create_stealth_environment(self) -> Dict[str, str]:
        """Créer un environnement d'exécution furtif"""
        env = os.environ.copy()
        
        # Masquer l'historique de commandes
        env['HISTFILE'] = '/dev/null'
        env['HISTSIZE'] = '0'
        env['HISTFILESIZE'] = '0'
        
        # Variables pour éviter les logs
        env['TERM'] = 'dumb'
        env['COLUMNS'] = '80'
        env['LINES'] = '24'
        
        # Masquer l'identité du processus
        env['USER'] = 'nobody'
        env['LOGNAME'] = 'nobody'
        env['HOME'] = '/tmp'
        
        return env
    
    def _obfuscate_command(self, command: str) -> str:
        """Obfusquer une commande pour l'historique"""
        return self.stealth_engine.obfuscate_string(command)
    
    def _wrap_command_with_stealth(self, command: str, output_file: str) -> str:
        """Envelopper une commande avec des techniques de furtivité"""
        # Ajouter des redirections pour minimiser les traces
        stealth_wrapper = f"""
        {{
            unset HISTFILE
            export HISTSIZE=0
            export HISTFILESIZE=0
            {command}
        }} 2>&1 | tee {output_file}
        """
        return stealth_wrapper
    
    def _apply_execution_delays(self, process: subprocess.Popen):
        """Appliquer des délais pendant l'exécution"""
        current_profile = self.evasion_manager.current_profile
        min_delay = current_profile.timing_profile["min_delay"]
        max_delay = current_profile.timing_profile["max_delay"]
        
        # Attendre avec des intervalles aléatoires
        while process.poll() is None:
            delay = random.uniform(min_delay, max_delay)
            time.sleep(delay)
    
    def _cleanup_execution_traces(self, temp_file: str):
        """Nettoyer les traces d'exécution"""
        try:
            # Supprimer le fichier temporaire
            if os.path.exists(temp_file):
                os.remove(temp_file)
                self.temp_files.discard(temp_file)
            
            # Nettoyer l'historique bash si accessible
            bash_history = os.path.expanduser("~/.bash_history")
            if os.path.exists(bash_history):
                # Supprimer les dernières lignes (commandes récentes)
                with open(bash_history, 'r') as f:
                    lines = f.readlines()
                
                # Garder toutes les lignes sauf les 5 dernières
                if len(lines) > 5:
                    with open(bash_history, 'w') as f:
                        f.writelines(lines[:-5])
            
        except Exception as e:
            logger.warning(f"⚠️ Cleanup traces failed: {e}")
    
    def get_obfuscated_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Obtenir l'historique obfusqué des commandes"""
        recent_history = list(self.obfuscated_history.keys())[-limit:]
        
        return [
            {
                "obfuscated": obf_cmd,
                "timestamp": datetime.now().isoformat(),  # Simplified
                "is_sensitive": True
            }
            for obf_cmd in recent_history
        ]
    
    def cleanup_all(self):
        """Nettoyer toutes les traces du terminal furtif"""
        logger.info("🧹 Starting comprehensive terminal cleanup")
        
        # Nettoyer les fichiers temporaires
        for temp_file in self.temp_files.copy():
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                self.temp_files.discard(temp_file)
            except Exception as e:
                logger.warning(f"⚠️ Failed to cleanup temp file {temp_file}: {e}")
        
        # Nettoyer l'historique local
        self.command_history.clear()
        self.obfuscated_history.clear()
        
        # Nettoyage système via stealth engine
        self.stealth_engine.cleanup_forensics()
        
        logger.info("✅ Terminal cleanup completed")

class StealthMonitoring:
    """
    System monitoring furtif avec masquage des processus surveillés
    """
    
    def __init__(self):
        self.stealth_engine = get_global_stealth_engine()
        self.evasion_manager = get_global_evasion_manager()
        self.process_whitelist = set()
        self.hidden_processes = set()
        
        # Processus à masquer par défaut
        self.default_hidden = {
            'nmap', 'nc', 'netcat', 'hydra', 'john', 'hashcat',
            'aircrack-ng', 'wireshark', 'tcpdump', 'metasploit'
        }
        
        logger.info("📊 Stealth Monitoring initialized")
    
    def get_filtered_processes(self, include_hidden: bool = False) -> List[Dict[str, Any]]:
        """Obtenir la liste des processus avec filtrage furtif"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent', 'status']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info.get('name', '').lower()
                    
                    # Masquer les processus sensibles
                    if not include_hidden and self._should_hide_process(proc_name, proc_info.get('cmdline', [])):
                        continue
                    
                    # Obfusquer les informations sensibles
                    if self._is_sensitive_process(proc_name):
                        proc_info = self._obfuscate_process_info(proc_info)
                    
                    processes.append(proc_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return processes
            
        except Exception as e:
            logger.error(f"❌ Failed to get filtered processes: {e}")
            return []
    
    def _should_hide_process(self, proc_name: str, cmdline: List[str]) -> bool:
        """Déterminer si un processus doit être masqué"""
        # Vérifier le nom du processus
        if any(hidden in proc_name for hidden in self.default_hidden):
            return True
        
        # Vérifier la ligne de commande
        cmdline_str = ' '.join(cmdline).lower()
        if any(hidden in cmdline_str for hidden in self.default_hidden):
            return True
        
        # Vérifier la liste personnalisée
        if proc_name in self.hidden_processes:
            return True
        
        return False
    
    def _is_sensitive_process(self, proc_name: str) -> bool:
        """Déterminer si un processus est sensible"""
        sensitive_indicators = ['hack', 'crack', 'exploit', 'payload', 'shell', 'backdoor']
        return any(indicator in proc_name for indicator in sensitive_indicators)
    
    def _obfuscate_process_info(self, proc_info: Dict[str, Any]) -> Dict[str, Any]:
        """Obfusquer les informations d'un processus sensible"""
        obfuscated = proc_info.copy()
        
        # Obfusquer le nom
        if 'name' in obfuscated:
            obfuscated['name'] = self.stealth_engine.obfuscate_string(obfuscated['name'])
        
        # Obfusquer la ligne de commande
        if 'cmdline' in obfuscated and obfuscated['cmdline']:
            obfuscated['cmdline'] = [
                self.stealth_engine.obfuscate_string(arg) for arg in obfuscated['cmdline']
            ]
        
        return obfuscated
    
    def add_process_to_whitelist(self, process_name: str):
        """Ajouter un processus à la whitelist (toujours affiché)"""
        self.process_whitelist.add(process_name.lower())
        logger.info(f"➕ Added {process_name} to process whitelist")
    
    def hide_process(self, process_name: str):
        """Masquer un processus spécifique"""
        self.hidden_processes.add(process_name.lower())
        logger.info(f"👻 Added {process_name} to hidden processes")
    
    def get_stealth_metrics(self) -> Dict[str, Any]:
        """Obtenir les métriques de monitoring furtif"""
        total_processes = len(list(psutil.process_iter()))
        filtered_processes = len(self.get_filtered_processes())
        hidden_count = total_processes - filtered_processes
        
        return {
            "total_processes": total_processes,
            "visible_processes": filtered_processes,
            "hidden_processes": hidden_count,
            "hide_ratio": (hidden_count / max(1, total_processes)) * 100,
            "whitelist_size": len(self.process_whitelist),
            "custom_hidden": len(self.hidden_processes)
        }

class StealthDatabase:
    """
    Gestionnaire de base de données sécurisé avec chiffrement et obfuscation
    """
    
    def __init__(self, database_path: str):
        self.database_path = database_path
        self.stealth_engine = get_global_stealth_engine()
        self.evasion_manager = get_global_evasion_manager()
        self.encryption_key = self._generate_encryption_key()
        
        logger.info("🗄️ Stealth Database manager initialized")
    
    def _generate_encryption_key(self) -> str:
        """Générer une clé de chiffrement basée sur l'environnement"""
        # Utiliser des informations système pour créer une clé unique
        import platform
        system_info = f"{platform.node()}-{platform.machine()}-{os.getuid() if hasattr(os, 'getuid') else 'windows'}"
        key_base = hashlib.sha256(system_info.encode()).hexdigest()
        return key_base[:32]  # Clé de 32 caractères
    
    def obfuscate_sensitive_data(self, data: str, table_name: str = None) -> str:
        """Obfusquer les données sensibles avant stockage"""
        if self._is_sensitive_table(table_name):
            return self.stealth_engine.obfuscate_string(data)
        return data
    
    def _is_sensitive_table(self, table_name: str) -> bool:
        """Déterminer si une table contient des données sensibles"""
        if not table_name:
            return False
        
        sensitive_tables = [
            'credentials', 'passwords', 'hashes', 'keys', 'tokens',
            'vulnerabilities', 'exploits', 'targets', 'scans'
        ]
        
        return any(sensitive in table_name.lower() for sensitive in sensitive_tables)

# Factory functions
def get_stealth_integration(database_path: str = None):
    """Obtenir une instance du gestionnaire d'intégration furtive"""
    return {
        "stealth_terminal": StealthTerminal(),
        "stealth_monitoring": StealthMonitoring(),
        "stealth_database": StealthDatabase(database_path) if database_path else None
    }

# Global instance
_global_stealth_integration = None

def get_global_stealth_integration():
    """Obtenir l'instance globale du gestionnaire d'intégration"""
    global _global_stealth_integration
    if _global_stealth_integration is None:
        _global_stealth_integration = get_stealth_integration()
    return _global_stealth_integration