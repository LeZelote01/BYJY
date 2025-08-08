#!/usr/bin/env python3
"""
CyberSec Assistant Portable - User Proxy Configuration Manager
Gestionnaire de configuration simple pour les utilisateurs
"""

import os
import json
import configparser
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class ProxyUserConfigManager:
    """
    Gestionnaire de configuration utilisateur simple pour les proxies
    Utilise un format INI facile à comprendre pour les utilisateurs
    """
    
    def __init__(self, config_path: str = None):
        self.config_path = Path(config_path) if config_path else Path(__file__).parent.parent / "data" / "proxy_user_config.ini"
        self.config = configparser.ConfigParser()
        self.config.optionxform = str  # Preserve case sensitivity
        
        # Charger la configuration
        self.load_config()
        
        # Configuration par défaut intégrée
        self.default_config = self._get_default_config()
        
        logger.info(f"✅ User Proxy Config Manager initialized: {self.config_path}")
    
    def load_config(self):
        """Charger la configuration depuis le fichier INI"""
        try:
            if self.config_path.exists():
                self.config.read(self.config_path, encoding='utf-8')
                logger.info("✅ User proxy configuration loaded successfully")
            else:
                logger.info("ℹ️ No user proxy configuration found, will create default")
                self._create_default_config_file()
        except Exception as e:
            logger.error(f"❌ Failed to load user proxy configuration: {e}")
            self.config = configparser.ConfigParser()
    
    def save_config(self):
        """Sauvegarder la configuration dans le fichier INI"""
        try:
            self.config_path.parent.mkdir(exist_ok=True)
            with open(self.config_path, 'w', encoding='utf-8') as f:
                self.config.write(f)
            logger.info("✅ User proxy configuration saved successfully")
        except Exception as e:
            logger.error(f"❌ Failed to save user proxy configuration: {e}")
    
    def _create_default_config_file(self):
        """Créer le fichier de configuration par défaut si il n'existe pas"""
        if not self.config_path.exists():
            try:
                # Le fichier par défaut est déjà créé, on le charge
                self.config.read(self.config_path, encoding='utf-8')
            except Exception as e:
                logger.warning(f"Failed to create default config: {e}")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Configuration par défaut intégrée"""
        return {
            "general": {
                "use_external_proxies": False,
                "stealth_level": 5,
                "auto_rotate_proxies": False,
                "rotation_interval": 50
            },
            "tor": {
                "enabled": False,
                "auto_start": True,
                "use_as_primary": False,
                "socks_port": 9050,
                "control_port": 9051,
                "request_delay_min": 3.0,
                "request_delay_max": 8.0
            },
            "external_proxies": {
                "enabled": False,
                "auto_test_proxies": True,
                "minimum_quality_score": 0.7,
                "test_timeout": 10
            },
            "safety": {
                "enable_safety_checks": True,
                "block_if_no_proxy": False,
                "warn_ip_leak": True,
                "max_failed_attempts": 3,
                "auto_disable_on_detection": True
            },
            "advanced": {
                "rotate_user_agents": True,
                "custom_headers": {},
                "enable_proxy_chaining": False,
                "chain_length": 2,
                "random_delay_max": 2.0,
                "use_persistent_sessions": True
            }
        }
    
    def get_bool(self, section: str, key: str, fallback: bool = False) -> bool:
        """Obtenir une valeur booléenne avec fallback"""
        try:
            if self.config.has_section(section) and self.config.has_option(section, key):
                value = self.config.get(section, key).lower()
                return value in ['true', '1', 'yes', 'on']
            return self.default_config.get(section, {}).get(key, fallback)
        except Exception:
            return fallback
    
    def get_int(self, section: str, key: str, fallback: int = 0) -> int:
        """Obtenir une valeur entière avec fallback"""
        try:
            if self.config.has_section(section) and self.config.has_option(section, key):
                return self.config.getint(section, key)
            return self.default_config.get(section, {}).get(key, fallback)
        except Exception:
            return fallback
    
    def get_float(self, section: str, key: str, fallback: float = 0.0) -> float:
        """Obtenir une valeur flottante avec fallback"""
        try:
            if self.config.has_section(section) and self.config.has_option(section, key):
                return self.config.getfloat(section, key)
            return self.default_config.get(section, {}).get(key, fallback)
        except Exception:
            return fallback
    
    def get_string(self, section: str, key: str, fallback: str = "") -> str:
        """Obtenir une valeur string avec fallback"""
        try:
            if self.config.has_section(section) and self.config.has_option(section, key):
                return self.config.get(section, key)
            return self.default_config.get(section, {}).get(key, fallback)
        except Exception:
            return fallback
    
    def set_value(self, section: str, key: str, value: Any):
        """Définir une valeur dans la configuration"""
        try:
            if not self.config.has_section(section):
                self.config.add_section(section)
            self.config.set(section, key, str(value))
        except Exception as e:
            logger.error(f"Failed to set config value [{section}].{key}: {e}")
    
    def get_proxy_list(self) -> List[str]:
        """Obtenir la liste des proxies externes depuis la configuration"""
        try:
            proxy_list_raw = self.get_string('external_proxies', 'proxy_list', '')
            if not proxy_list_raw.strip():
                return []
            
            proxies = []
            for line in proxy_list_raw.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    proxies.append(line)
            
            return proxies
        except Exception as e:
            logger.error(f"Failed to parse proxy list: {e}")
            return []
    
    def set_proxy_list(self, proxies: List[str]):
        """Définir la liste des proxies externes"""
        try:
            proxy_list_str = '\n'.join(proxies)
            self.set_value('external_proxies', 'proxy_list', proxy_list_str)
        except Exception as e:
            logger.error(f"Failed to set proxy list: {e}")
    
    def get_tor_config(self) -> Dict[str, Any]:
        """Obtenir la configuration Tor"""
        return {
            "enabled": self.get_bool('tor', 'enabled'),
            "auto_start": self.get_bool('tor', 'auto_start'),
            "use_as_primary": self.get_bool('tor', 'use_as_primary'),
            "socks_port": self.get_int('tor', 'socks_port', 9050),
            "control_port": self.get_int('tor', 'control_port', 9051),
            "request_delay_min": self.get_float('tor', 'request_delay_min', 3.0),
            "request_delay_max": self.get_float('tor', 'request_delay_max', 8.0)
        }
    
    def get_general_config(self) -> Dict[str, Any]:
        """Obtenir la configuration générale"""
        return {
            "use_external_proxies": self.get_bool('general', 'use_external_proxies'),
            "stealth_level": self.get_int('general', 'stealth_level', 5),
            "auto_rotate_proxies": self.get_bool('general', 'auto_rotate_proxies'),
            "rotation_interval": self.get_int('general', 'rotation_interval', 50)
        }
    
    def get_external_proxies_config(self) -> Dict[str, Any]:
        """Obtenir la configuration des proxies externes"""
        return {
            "enabled": self.get_bool('external_proxies', 'enabled'),
            "proxy_list": self.get_proxy_list(),
            "auto_test_proxies": self.get_bool('external_proxies', 'auto_test_proxies'),
            "minimum_quality_score": self.get_float('external_proxies', 'minimum_quality_score', 0.7),
            "test_timeout": self.get_int('external_proxies', 'test_timeout', 10)
        }
    
    def get_safety_config(self) -> Dict[str, Any]:
        """Obtenir la configuration de sécurité"""
        return {
            "enable_safety_checks": self.get_bool('safety', 'enable_safety_checks', True),
            "block_if_no_proxy": self.get_bool('safety', 'block_if_no_proxy'),
            "warn_ip_leak": self.get_bool('safety', 'warn_ip_leak', True),
            "max_failed_attempts": self.get_int('safety', 'max_failed_attempts', 3),
            "auto_disable_on_detection": self.get_bool('safety', 'auto_disable_on_detection', True)
        }
    
    def get_advanced_config(self) -> Dict[str, Any]:
        """Obtenir la configuration avancée"""
        custom_headers_str = self.get_string('advanced', 'custom_headers', '{}')
        try:
            custom_headers = json.loads(custom_headers_str)
        except:
            custom_headers = {}
        
        return {
            "rotate_user_agents": self.get_bool('advanced', 'rotate_user_agents', True),
            "custom_headers": custom_headers,
            "enable_proxy_chaining": self.get_bool('advanced', 'enable_proxy_chaining'),
            "chain_length": self.get_int('advanced', 'chain_length', 2),
            "random_delay_max": self.get_float('advanced', 'random_delay_max', 2.0),
            "use_persistent_sessions": self.get_bool('advanced', 'use_persistent_sessions', True)
        }
    
    def get_full_config(self) -> Dict[str, Any]:
        """Obtenir la configuration complète"""
        return {
            "general": self.get_general_config(),
            "tor": self.get_tor_config(),
            "external_proxies": self.get_external_proxies_config(),
            "safety": self.get_safety_config(),
            "advanced": self.get_advanced_config(),
            "metadata": {
                "config_file": str(self.config_path),
                "last_loaded": datetime.now().isoformat()
            }
        }
    
    def update_tor_settings(self, enabled: bool = None, auto_start: bool = None, 
                           use_as_primary: bool = None):
        """Mettre à jour les paramètres Tor"""
        if enabled is not None:
            self.set_value('tor', 'enabled', enabled)
        if auto_start is not None:
            self.set_value('tor', 'auto_start', auto_start)
        if use_as_primary is not None:
            self.set_value('tor', 'use_as_primary', use_as_primary)
        
        self.save_config()
    
    def update_general_settings(self, use_external_proxies: bool = None,
                               stealth_level: int = None, auto_rotate: bool = None):
        """Mettre à jour les paramètres généraux"""
        if use_external_proxies is not None:
            self.set_value('general', 'use_external_proxies', use_external_proxies)
        if stealth_level is not None:
            self.set_value('general', 'stealth_level', stealth_level)
        if auto_rotate is not None:
            self.set_value('general', 'auto_rotate_proxies', auto_rotate)
        
        self.save_config()
    
    def add_external_proxy(self, proxy_url: str) -> bool:
        """Ajouter un proxy externe à la liste"""
        try:
            current_proxies = self.get_proxy_list()
            if proxy_url not in current_proxies:
                current_proxies.append(proxy_url)
                self.set_proxy_list(current_proxies)
                self.save_config()
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to add proxy: {e}")
            return False
    
    def remove_external_proxy(self, proxy_url: str) -> bool:
        """Supprimer un proxy externe de la liste"""
        try:
            current_proxies = self.get_proxy_list()
            if proxy_url in current_proxies:
                current_proxies.remove(proxy_url)
                self.set_proxy_list(current_proxies)
                self.save_config()
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to remove proxy: {e}")
            return False
    
    def reset_to_defaults(self):
        """Réinitialiser la configuration aux valeurs par défaut"""
        try:
            # Sauvegarder l'ancienne configuration
            backup_path = self.config_path.with_suffix('.ini.backup')
            if self.config_path.exists():
                import shutil
                shutil.copy2(self.config_path, backup_path)
                logger.info(f"Configuration backed up to: {backup_path}")
            
            # Créer une nouvelle configuration par défaut
            self._create_default_config_file()
            logger.info("✅ Configuration reset to defaults")
            
        except Exception as e:
            logger.error(f"Failed to reset configuration: {e}")


# Factory functions
def get_user_config_manager(config_path: str = None) -> ProxyUserConfigManager:
    """Factory function pour obtenir une instance du gestionnaire de configuration"""
    return ProxyUserConfigManager(config_path)

# Global instance
_user_config_manager = None

def get_global_user_config_manager() -> ProxyUserConfigManager:
    """Obtenir l'instance globale du gestionnaire de configuration utilisateur"""
    global _user_config_manager
    if _user_config_manager is None:
        _user_config_manager = get_user_config_manager()
    return _user_config_manager


if __name__ == "__main__":
    # Test du gestionnaire de configuration
    manager = get_user_config_manager()
    
    print("📋 Configuration actuelle:")
    config = manager.get_full_config()
    import json
    print(json.dumps(config, indent=2))
    
    print("\n📋 Configuration Tor:")
    tor_config = manager.get_tor_config()
    print(json.dumps(tor_config, indent=2))