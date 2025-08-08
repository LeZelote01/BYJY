#!/usr/bin/env python3
"""
CyberSec Assistant Portable - Evasion Management System V1.0
Système de gestion avancée de l'évasion et des contre-mesures
Features: Profile Management, Detection Evasion, Anti-Forensics, Real-time Adaptation
"""

import os
import sys
import json
import time
import random
import threading
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import logging
import hashlib
import tempfile
from dataclasses import dataclass, asdict

from stealth_engine import get_global_stealth_engine
from proxy_manager import get_global_proxy_manager

logger = logging.getLogger(__name__)

@dataclass
class EvasionProfile:
    """Profil d'évasion avec paramètres spécifiques"""
    name: str
    description: str
    stealth_level: int
    techniques: List[str]
    timing_profile: Dict[str, float]
    proxy_settings: Dict[str, Any]
    obfuscation_settings: Dict[str, Any]
    anti_forensics: bool
    detection_thresholds: Dict[str, float]
    active: bool = False

@dataclass
class DetectionEvent:
    """Événement de détection potentielle"""
    timestamp: datetime
    event_type: str  # 'rate_limit', 'captcha', 'block', 'suspicious_response'
    source: str
    details: Dict[str, Any]
    severity: str  # 'low', 'medium', 'high', 'critical'
    handled: bool = False

class EvasionManager:
    """
    Gestionnaire avancé des techniques d'évasion
    """
    
    def __init__(self, config_path: str = None):
        self.config_path = config_path or os.path.join(os.path.dirname(__file__), "config", "evasion.json")
        self.stealth_engine = get_global_stealth_engine()
        self.proxy_manager = get_global_proxy_manager()
        
        # Profils d'évasion prédéfinis
        self.profiles = {}
        self.current_profile = None
        
        # Historique des détections
        self.detection_events = []
        self.adaptation_rules = {}
        
        # Métriques d'évasion
        self.evasion_metrics = {
            "successful_requests": 0,
            "detected_requests": 0,
            "blocked_requests": 0,
            "captcha_encounters": 0,
            "profile_switches": 0,
            "average_response_time": 0.0,
            "success_rate": 100.0,
            "detection_rate": 0.0
        }
        
        # Monitoring thread
        self.monitoring_active = False
        self.monitoring_thread = None
        
        self._initialize_default_profiles()
        self._load_evasion_config()
        self._start_monitoring()
        
        logger.info("✅ Evasion Manager initialized with advanced detection evasion")
    
    def _initialize_default_profiles(self):
        """Initialiser les profils d'évasion par défaut"""
        
        # Profil Normal (pour usage quotidien)
        normal_profile = EvasionProfile(
            name="normal",
            description="Profile standard pour usage quotidien",
            stealth_level=3,
            techniques=["basic_headers", "user_agent_rotation"],
            timing_profile={"min_delay": 0.5, "max_delay": 2.0, "burst_limit": 10},
            proxy_settings={"enabled": False, "rotation_interval": 60},
            obfuscation_settings={"level": 2, "string_obfuscation": False},
            anti_forensics=False,
            detection_thresholds={"rate_limit": 0.8, "captcha": 0.7, "block": 0.9}
        )
        
        # Profil Furtif (pour reconnaissance discrète)
        stealth_profile = EvasionProfile(
            name="stealth",
            description="Profile furtif pour reconnaissance discrète",
            stealth_level=7,
            techniques=[
                "advanced_headers", "user_agent_rotation", "referer_spoofing",
                "timing_randomization", "request_fingerprint_masking"
            ],
            timing_profile={"min_delay": 2.0, "max_delay": 8.0, "burst_limit": 5},
            proxy_settings={"enabled": True, "rotation_interval": 30, "chains": False},
            obfuscation_settings={"level": 6, "string_obfuscation": True},
            anti_forensics=True,
            detection_thresholds={"rate_limit": 0.3, "captcha": 0.4, "block": 0.5}
        )
        
        # Profil Maximum (pour opérations sensibles)
        maximum_profile = EvasionProfile(
            name="maximum",
            description="Profile d'évasion maximum pour opérations sensibles",
            stealth_level=10,
            techniques=[
                "advanced_headers", "user_agent_rotation", "referer_spoofing",
                "timing_randomization", "request_fingerprint_masking",
                "tcp_fingerprint_evasion", "dns_over_https", "traffic_obfuscation"
            ],
            timing_profile={"min_delay": 5.0, "max_delay": 20.0, "burst_limit": 2},
            proxy_settings={
                "enabled": True, "rotation_interval": 10, 
                "chains": True, "chain_length": 3, "tor_enabled": True
            },
            obfuscation_settings={"level": 10, "string_obfuscation": True, "deep_obfuscation": True},
            anti_forensics=True,
            detection_thresholds={"rate_limit": 0.1, "captcha": 0.2, "block": 0.3}
        )
        
        # Profil Rapide (pour scans rapides avec évasion de base)
        fast_profile = EvasionProfile(
            name="fast",
            description="Profile rapide avec évasion de base",
            stealth_level=5,
            techniques=["basic_headers", "user_agent_rotation", "timing_randomization"],
            timing_profile={"min_delay": 0.1, "max_delay": 1.0, "burst_limit": 20},
            proxy_settings={"enabled": True, "rotation_interval": 120},
            obfuscation_settings={"level": 3, "string_obfuscation": False},
            anti_forensics=False,
            detection_thresholds={"rate_limit": 0.6, "captcha": 0.5, "block": 0.7}
        )
        
        self.profiles = {
            "normal": normal_profile,
            "stealth": stealth_profile, 
            "maximum": maximum_profile,
            "fast": fast_profile
        }
        
        # Activer le profil par défaut
        self.current_profile = self.profiles["stealth"]
        self.current_profile.active = True
    
    def _load_evasion_config(self):
        """Charger la configuration d'évasion"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                
                # Charger les profils personnalisés
                if 'custom_profiles' in config:
                    for profile_data in config['custom_profiles']:
                        profile = EvasionProfile(**profile_data)
                        self.profiles[profile.name] = profile
                
                # Charger les règles d'adaptation
                if 'adaptation_rules' in config:
                    self.adaptation_rules = config['adaptation_rules']
                
                logger.info(f"✅ Loaded evasion config with {len(self.profiles)} profiles")
        
        except Exception as e:
            logger.warning(f"⚠️ Failed to load evasion config: {e}")
    
    def _save_evasion_config(self):
        """Sauvegarder la configuration d'évasion"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            
            config = {
                "profiles": [asdict(profile) for profile in self.profiles.values()],
                "adaptation_rules": self.adaptation_rules,
                "metrics": self.evasion_metrics,
                "last_updated": datetime.now().isoformat()
            }
            
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            logger.info("💾 Evasion configuration saved")
        
        except Exception as e:
            logger.error(f"❌ Failed to save evasion config: {e}")
    
    def _start_monitoring(self):
        """Démarrer le monitoring des détections"""
        if not self.monitoring_active:
            self.monitoring_active = True
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitoring_thread.start()
            logger.info("🔍 Evasion monitoring started")
    
    def _monitoring_loop(self):
        """Boucle de monitoring des détections"""
        while self.monitoring_active:
            try:
                # Vérifier les événements de détection récents
                self._analyze_detection_patterns()
                
                # Adapter le profil si nécessaire
                self._adaptive_profile_adjustment()
                
                # Nettoyer les anciens événements
                self._cleanup_old_events()
                
                # Mettre à jour les métriques
                self._update_evasion_metrics()
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"❌ Monitoring loop error: {e}")
                time.sleep(60)  # Wait longer on error
    
    def activate_profile(self, profile_name: str) -> bool:
        """Activer un profil d'évasion"""
        if profile_name not in self.profiles:
            logger.error(f"❌ Unknown evasion profile: {profile_name}")
            return False
        
        # Désactiver le profil actuel
        if self.current_profile:
            self.current_profile.active = False
        
        # Activer le nouveau profil
        new_profile = self.profiles[profile_name]
        new_profile.active = True
        self.current_profile = new_profile
        
        # Appliquer les paramètres du profil
        self._apply_profile_settings(new_profile)
        
        # Mettre à jour les métriques
        self.evasion_metrics["profile_switches"] += 1
        
        logger.info(f"🎭 Activated evasion profile: {profile_name} (Level: {new_profile.stealth_level})")
        return True
    
    def _apply_profile_settings(self, profile: EvasionProfile):
        """Appliquer les paramètres d'un profil"""
        try:
            # Configurer le moteur de furtivité
            self.stealth_engine.config.update({
                "stealth_level": profile.stealth_level,
                "obfuscation_level": profile.obfuscation_settings["level"],
                "anti_forensics_enabled": profile.anti_forensics,
                "min_request_delay": profile.timing_profile["min_delay"],
                "max_request_delay": profile.timing_profile["max_delay"],
                "max_requests_per_minute": 60 // profile.timing_profile["max_delay"]
            })
            
            # Configurer le gestionnaire de proxy
            if profile.proxy_settings["enabled"]:
                self.proxy_manager.config.update({
                    "auto_rotation": True,
                    "rotation_interval": profile.proxy_settings["rotation_interval"],
                    "proxy_chains_enabled": profile.proxy_settings.get("chains", False),
                    "chain_length": profile.proxy_settings.get("chain_length", 1)
                })
                
                if profile.proxy_settings.get("tor_enabled", False):
                    self.proxy_manager.enable_tor()
            
            logger.info(f"⚙️ Applied profile settings for {profile.name}")
            
        except Exception as e:
            logger.error(f"❌ Failed to apply profile settings: {e}")
    
    def report_detection_event(self, event_type: str, source: str, details: Dict[str, Any]):
        """Signaler un événement de détection"""
        severity = self._calculate_event_severity(event_type, details)
        
        event = DetectionEvent(
            timestamp=datetime.now(),
            event_type=event_type,
            source=source,
            details=details,
            severity=severity
        )
        
        self.detection_events.append(event)
        
        # Réaction immédiate pour les événements critiques
        if severity == 'critical':
            self._handle_critical_detection(event)
        elif severity == 'high':
            self._handle_high_detection(event)
        
        # Mettre à jour les métriques
        if event_type == 'blocked':
            self.evasion_metrics["blocked_requests"] += 1
        elif event_type == 'captcha':
            self.evasion_metrics["captcha_encounters"] += 1
        
        self.evasion_metrics["detected_requests"] += 1
        
        logger.warning(f"🚨 Detection event reported: {event_type} from {source} (Severity: {severity})")
    
    def _calculate_event_severity(self, event_type: str, details: Dict[str, Any]) -> str:
        """Calculer la sévérité d'un événement de détection"""
        severity_map = {
            'rate_limit': 'medium',
            'captcha': 'high',
            'block': 'critical',
            'suspicious_response': 'low',
            'honeypot_detection': 'critical',
            'js_challenge': 'high',
            'fingerprint_detected': 'high',
            'tor_detected': 'high'
        }
        
        base_severity = severity_map.get(event_type, 'medium')
        
        # Ajuster selon les détails
        if details.get('repeated', False):
            if base_severity == 'low':
                base_severity = 'medium'
            elif base_severity == 'medium':
                base_severity = 'high'
        
        return base_severity
    
    def _handle_critical_detection(self, event: DetectionEvent):
        """Gérer une détection critique"""
        logger.critical(f"🚨 CRITICAL DETECTION: {event.event_type} - Taking emergency action")
        
        # Actions d'urgence
        if event.event_type == 'block':
            # Changer immédiatement de proxy
            if self.proxy_manager.get_current_proxy():
                self.proxy_manager.rotate_proxy()
            
            # Activer le profil maximum si pas déjà actif
            if self.current_profile.name != 'maximum':
                self.activate_profile('maximum')
        
        elif event.event_type == 'honeypot_detection':
            # Arrêter toute activité et nettoyer
            self.stealth_engine.cleanup_forensics()
            self.activate_profile('maximum')
            
            # Attendre plus longtemps
            time.sleep(random.uniform(300, 600))  # 5-10 minutes
        
        event.handled = True
    
    def _handle_high_detection(self, event: DetectionEvent):
        """Gérer une détection de niveau élevé"""
        logger.warning(f"⚠️ HIGH DETECTION: {event.event_type} - Adjusting tactics")
        
        if event.event_type == 'captcha':
            # Rotation de proxy et ralentissement
            self.proxy_manager.rotate_proxy()
            
            # Augmenter les délais temporairement
            current_profile = self.current_profile
            current_profile.timing_profile["min_delay"] *= 2
            current_profile.timing_profile["max_delay"] *= 2
            
            # Programmer le retour à la normale
            threading.Timer(1800, self._reset_timing_profile).start()  # 30 minutes
        
        elif event.event_type == 'js_challenge':
            # Passer à un profil plus avancé
            if self.current_profile.stealth_level < 8:
                better_profiles = [p for p in self.profiles.values() 
                                 if p.stealth_level > self.current_profile.stealth_level]
                if better_profiles:
                    best_profile = max(better_profiles, key=lambda p: p.stealth_level)
                    self.activate_profile(best_profile.name)
        
        event.handled = True
    
    def _reset_timing_profile(self):
        """Remettre le profil de timing par défaut"""
        if self.current_profile:
            profile_name = self.current_profile.name
            self.current_profile = self.profiles[profile_name]  # Reload default
            logger.info(f"🔄 Reset timing profile for {profile_name}")
    
    def _analyze_detection_patterns(self):
        """Analyser les patterns de détection"""
        recent_events = [e for e in self.detection_events 
                        if datetime.now() - e.timestamp < timedelta(hours=1)]
        
        if len(recent_events) >= 5:  # Too many detections
            logger.warning("🔍 High detection frequency detected - escalating profile")
            
            # Escalader vers un profil plus sûr
            if self.current_profile.stealth_level < 9:
                safer_profiles = [p for p in self.profiles.values() 
                                if p.stealth_level > self.current_profile.stealth_level]
                if safer_profiles:
                    best_profile = min(safer_profiles, key=lambda p: p.stealth_level)
                    self.activate_profile(best_profile.name)
        
        # Analyser les patterns par source
        source_counts = {}
        for event in recent_events:
            source_counts[event.source] = source_counts.get(event.source, 0) + 1
        
        # Blacklister temporairement les sources problématiques
        for source, count in source_counts.items():
            if count >= 3:
                logger.warning(f"⚫ Temporary blacklist for problematic source: {source}")
                # Implémenter la logique de blacklist temporaire
    
    def _adaptive_profile_adjustment(self):
        """Ajustement adaptatif du profil basé sur le succès"""
        success_rate = self._calculate_current_success_rate()
        
        if success_rate < 50 and self.current_profile.stealth_level < 9:
            # Succès faible - augmenter la furtivité
            better_profiles = [p for p in self.profiles.values() 
                             if p.stealth_level > self.current_profile.stealth_level]
            if better_profiles:
                best_profile = min(better_profiles, key=lambda p: p.stealth_level)
                logger.info(f"📈 Low success rate ({success_rate:.1f}%) - upgrading to {best_profile.name}")
                self.activate_profile(best_profile.name)
        
        elif success_rate > 90 and self.current_profile.stealth_level > 3:
            # Succès élevé - on peut réduire la furtivité pour plus de vitesse
            faster_profiles = [p for p in self.profiles.values() 
                             if p.stealth_level < self.current_profile.stealth_level]
            if faster_profiles:
                faster_profile = max(faster_profiles, key=lambda p: p.stealth_level)
                logger.info(f"📉 High success rate ({success_rate:.1f}%) - downgrading to {faster_profile.name}")
                self.activate_profile(faster_profile.name)
    
    def _calculate_current_success_rate(self) -> float:
        """Calculer le taux de succès actuel"""
        total_requests = self.evasion_metrics["successful_requests"] + self.evasion_metrics["detected_requests"]
        if total_requests == 0:
            return 100.0
        
        return (self.evasion_metrics["successful_requests"] / total_requests) * 100
    
    def _cleanup_old_events(self):
        """Nettoyer les anciens événements de détection"""
        cutoff = datetime.now() - timedelta(hours=24)
        self.detection_events = [e for e in self.detection_events if e.timestamp > cutoff]
    
    def _update_evasion_metrics(self):
        """Mettre à jour les métriques d'évasion"""
        self.evasion_metrics["success_rate"] = self._calculate_current_success_rate()
        
        total_requests = self.evasion_metrics["successful_requests"] + self.evasion_metrics["detected_requests"]
        if total_requests > 0:
            self.evasion_metrics["detection_rate"] = (self.evasion_metrics["detected_requests"] / total_requests) * 100
    
    def get_evasion_status(self) -> Dict[str, Any]:
        """Obtenir le statut complet d'évasion"""
        recent_events = [e for e in self.detection_events 
                        if datetime.now() - e.timestamp < timedelta(hours=1)]
        
        return {
            "current_profile": {
                "name": self.current_profile.name,
                "description": self.current_profile.description,
                "stealth_level": self.current_profile.stealth_level,
                "techniques_count": len(self.current_profile.techniques),
                "anti_forensics": self.current_profile.anti_forensics
            },
            "metrics": self.evasion_metrics,
            "recent_detections": len(recent_events),
            "detection_events": [
                {
                    "timestamp": e.timestamp.isoformat(),
                    "type": e.event_type,
                    "source": e.source,
                    "severity": e.severity,
                    "handled": e.handled
                } for e in recent_events[-10:]  # Last 10 events
            ],
            "available_profiles": [
                {
                    "name": p.name,
                    "description": p.description,
                    "stealth_level": p.stealth_level,
                    "active": p.active
                } for p in self.profiles.values()
            ],
            "recommendations": self._get_evasion_recommendations()
        }
    
    def _get_evasion_recommendations(self) -> List[str]:
        """Obtenir des recommandations d'évasion"""
        recommendations = []
        
        success_rate = self._calculate_current_success_rate()
        recent_detections = len([e for e in self.detection_events 
                               if datetime.now() - e.timestamp < timedelta(hours=1)])
        
        if success_rate < 70:
            recommendations.append("Consider upgrading to a higher stealth profile")
        
        if recent_detections > 5:
            recommendations.append("High detection frequency - activate maximum stealth profile")
        
        if not self.proxy_manager.get_current_proxy():
            recommendations.append("Enable proxy rotation for better anonymity")
        
        if self.current_profile.stealth_level < 7 and self.evasion_metrics["captcha_encounters"] > 0:
            recommendations.append("Recent CAPTCHA encounters - increase stealth level")
        
        if not recommendations:
            recommendations.append("Current evasion configuration appears optimal")
        
        return recommendations
    
    def report_success(self, source: str = "general"):
        """Signaler une requête réussie"""
        self.evasion_metrics["successful_requests"] += 1
        logger.debug(f"✅ Successful request from {source}")
    
    def create_custom_profile(self, name: str, config: Dict[str, Any]) -> bool:
        """Créer un profil d'évasion personnalisé"""
        try:
            profile = EvasionProfile(
                name=name,
                description=config.get("description", f"Custom profile {name}"),
                stealth_level=config.get("stealth_level", 5),
                techniques=config.get("techniques", []),
                timing_profile=config.get("timing_profile", {"min_delay": 1.0, "max_delay": 3.0, "burst_limit": 5}),
                proxy_settings=config.get("proxy_settings", {"enabled": True, "rotation_interval": 60}),
                obfuscation_settings=config.get("obfuscation_settings", {"level": 5}),
                anti_forensics=config.get("anti_forensics", True),
                detection_thresholds=config.get("detection_thresholds", {"rate_limit": 0.5, "captcha": 0.4, "block": 0.6})
            )
            
            self.profiles[name] = profile
            self._save_evasion_config()
            
            logger.info(f"✅ Created custom evasion profile: {name}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to create custom profile {name}: {e}")
            return False
    
    def delete_profile(self, name: str) -> bool:
        """Supprimer un profil d'évasion"""
        if name in ["normal", "stealth", "maximum", "fast"]:
            logger.error(f"❌ Cannot delete default profile: {name}")
            return False
        
        if name in self.profiles:
            if self.current_profile and self.current_profile.name == name:
                # Switch to default profile before deletion
                self.activate_profile("stealth")
            
            del self.profiles[name]
            self._save_evasion_config()
            
            logger.info(f"🗑️ Deleted evasion profile: {name}")
            return True
        
        return False
    
    def export_profiles(self) -> Dict[str, Any]:
        """Exporter tous les profils d'évasion"""
        return {
            "profiles": [asdict(profile) for profile in self.profiles.values()],
            "metrics": self.evasion_metrics,
            "export_date": datetime.now().isoformat()
        }
    
    def import_profiles(self, data: Dict[str, Any]) -> bool:
        """Importer des profils d'évasion"""
        try:
            for profile_data in data.get("profiles", []):
                profile = EvasionProfile(**profile_data)
                self.profiles[profile.name] = profile
            
            self._save_evasion_config()
            logger.info(f"✅ Imported {len(data.get('profiles', []))} evasion profiles")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to import profiles: {e}")
            return False
    
    def shutdown(self):
        """Arrêter le gestionnaire d'évasion"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        
        self._save_evasion_config()
        logger.info("👋 Evasion Manager shutdown")

# Factory functions
def get_evasion_manager(config_path: str = None) -> EvasionManager:
    """Obtenir une instance du gestionnaire d'évasion"""
    return EvasionManager(config_path)

# Global instance
_global_evasion_manager = None

def get_global_evasion_manager() -> EvasionManager:
    """Obtenir l'instance globale du gestionnaire d'évasion"""
    global _global_evasion_manager
    if _global_evasion_manager is None:
        _global_evasion_manager = get_evasion_manager()
    return _global_evasion_manager