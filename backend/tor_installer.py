#!/usr/bin/env python3
"""
CyberSec Assistant Portable - Tor Auto-Installer
Installation automatique de Tor sur différents OS
"""

import os
import sys
import subprocess
import platform
import logging
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Tuple, Optional

logger = logging.getLogger(__name__)

class TorInstaller:
    """
    Installateur automatique de Tor pour différents systèmes d'exploitation
    """
    
    def __init__(self):
        self.system = platform.system().lower()
        self.portable_dir = Path(__file__).parent.parent.absolute()
        self.tor_data_dir = self.portable_dir / "data" / "tor"
        self.tor_data_dir.mkdir(exist_ok=True, parents=True)
        
    def is_tor_installed(self) -> bool:
        """Vérifier si Tor est déjà installé et accessible"""
        try:
            # Vérifier si la commande tor existe
            result = subprocess.run(['tor', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and 'Tor' in result.stdout:
                logger.info(f"✅ Tor already installed: {result.stdout.splitlines()[0]}")
                return True
                
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            pass
            
        # Vérifier si le service Tor est en cours d'exécution
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('127.0.0.1', 9050))
            sock.close()
            if result == 0:
                logger.info("✅ Tor service is already running on port 9050")
                return True
        except Exception:
            pass
            
        return False
    
    def install_tor(self) -> Dict[str, any]:
        """Installer Tor selon le système d'exploitation"""
        if self.is_tor_installed():
            return {
                "success": True,
                "message": "Tor is already installed and accessible",
                "method": "already_installed"
            }
        
        logger.info(f"🔄 Starting Tor installation for {self.system}")
        
        try:
            if self.system == "linux":
                return self._install_tor_linux()
            elif self.system == "darwin":  # macOS
                return self._install_tor_macos()
            elif self.system == "windows":
                return self._install_tor_windows()
            else:
                return {
                    "success": False,
                    "message": f"Unsupported operating system: {self.system}",
                    "method": "unsupported"
                }
                
        except Exception as e:
            logger.error(f"❌ Tor installation failed: {e}")
            return {
                "success": False,
                "message": f"Installation failed: {str(e)}",
                "method": "error"
            }
    
    def _install_tor_linux(self) -> Dict[str, any]:
        """Installer Tor sur Linux"""
        # Détecter la distribution
        try:
            import distro
            distro_id = distro.id().lower()
            distro_name = distro.name()
        except ImportError:
            # Fallback si distro n'est pas disponible
            if os.path.exists('/etc/debian_version'):
                distro_id = 'debian'
                distro_name = 'Debian-based'
            elif os.path.exists('/etc/redhat-release'):
                distro_id = 'rhel'
                distro_name = 'RedHat-based'
            else:
                distro_id = 'unknown'
                distro_name = 'Unknown Linux'
        
        logger.info(f"📋 Detected Linux distribution: {distro_name}")
        
        # Installation selon la distribution
        install_commands = []
        
        if distro_id in ['ubuntu', 'debian', 'mint', 'kali', 'parrot']:
            install_commands = [
                ['sudo', 'apt', 'update'],
                ['sudo', 'apt', 'install', '-y', 'tor']
            ]
        elif distro_id in ['centos', 'rhel', 'fedora', 'rocky', 'alma']:
            if distro_id == 'fedora':
                install_commands = [
                    ['sudo', 'dnf', 'install', '-y', 'tor']
                ]
            else:
                install_commands = [
                    ['sudo', 'yum', 'install', '-y', 'epel-release'],
                    ['sudo', 'yum', 'install', '-y', 'tor']
                ]
        elif distro_id in ['arch', 'manjaro']:
            install_commands = [
                ['sudo', 'pacman', '-Sy', '--noconfirm', 'tor']
            ]
        elif distro_id in ['opensuse', 'suse']:
            install_commands = [
                ['sudo', 'zypper', 'install', '-y', 'tor']
            ]
        else:
            return {
                "success": False,
                "message": f"Unsupported Linux distribution: {distro_name}. Please install Tor manually.",
                "method": "manual_required",
                "instructions": [
                    "Please install Tor manually using your package manager:",
                    "Ubuntu/Debian: sudo apt install tor",
                    "CentOS/RHEL: sudo yum install epel-release && sudo yum install tor",
                    "Fedora: sudo dnf install tor",
                    "Arch: sudo pacman -S tor"
                ]
            }
        
        # Exécuter les commandes d'installation
        for cmd in install_commands:
            try:
                logger.info(f"🔄 Executing: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.returncode != 0:
                    logger.warning(f"⚠️ Command failed: {' '.join(cmd)}")
                    logger.warning(f"Error: {result.stderr}")
            except subprocess.TimeoutExpired:
                logger.error(f"❌ Command timeout: {' '.join(cmd)}")
            except FileNotFoundError:
                logger.error(f"❌ Command not found: {cmd[0]}")
                return {
                    "success": False,
                    "message": f"Package manager not found: {cmd[0]}",
                    "method": "package_manager_missing"
                }
        
        # Démarrer le service Tor
        try:
            subprocess.run(['sudo', 'systemctl', 'start', 'tor'], timeout=30)
            subprocess.run(['sudo', 'systemctl', 'enable', 'tor'], timeout=30)
        except Exception as e:
            logger.warning(f"⚠️ Failed to start Tor service: {e}")
        
        # Vérifier l'installation
        if self.is_tor_installed():
            return {
                "success": True,
                "message": f"Tor successfully installed on {distro_name}",
                "method": f"package_manager_{distro_id}"
            }
        else:
            return {
                "success": False,
                "message": "Tor installation completed but verification failed",
                "method": "verification_failed"
            }
    
    def _install_tor_macos(self) -> Dict[str, any]:
        """Installer Tor sur macOS"""
        # Vérifier si Homebrew est installé
        try:
            subprocess.run(['brew', '--version'], capture_output=True, timeout=10, check=True)
            homebrew_available = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            homebrew_available = False
        
        if homebrew_available:
            try:
                logger.info("🔄 Installing Tor via Homebrew...")
                subprocess.run(['brew', 'install', 'tor'], timeout=300, check=True)
                
                # Démarrer le service
                subprocess.run(['brew', 'services', 'start', 'tor'], timeout=30)
                
                if self.is_tor_installed():
                    return {
                        "success": True,
                        "message": "Tor successfully installed via Homebrew",
                        "method": "homebrew"
                    }
            except subprocess.CalledProcessError as e:
                logger.error(f"❌ Homebrew installation failed: {e}")
        
        # Alternative : Installation via MacPorts si disponible
        try:
            subprocess.run(['port', 'version'], capture_output=True, timeout=10, check=True)
            logger.info("🔄 Installing Tor via MacPorts...")
            subprocess.run(['sudo', 'port', 'install', 'tor'], timeout=300, check=True)
            
            if self.is_tor_installed():
                return {
                    "success": True,
                    "message": "Tor successfully installed via MacPorts",
                    "method": "macports"
                }
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        return {
            "success": False,
            "message": "Tor installation failed. Please install manually.",
            "method": "manual_required",
            "instructions": [
                "Install Tor manually on macOS:",
                "1. Install Homebrew: /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"",
                "2. Install Tor: brew install tor",
                "3. Start Tor: brew services start tor",
                "Or download from: https://www.torproject.org/download/"
            ]
        }
    
    def _install_tor_windows(self) -> Dict[str, any]:
        """Installer Tor sur Windows"""
        # Vérifier si Chocolatey est disponible
        try:
            subprocess.run(['choco', '--version'], capture_output=True, timeout=10, check=True)
            chocolatey_available = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            chocolatey_available = False
        
        if chocolatey_available:
            try:
                logger.info("🔄 Installing Tor via Chocolatey...")
                subprocess.run(['choco', 'install', 'tor', '-y'], timeout=300, check=True)
                
                if self.is_tor_installed():
                    return {
                        "success": True,
                        "message": "Tor successfully installed via Chocolatey",
                        "method": "chocolatey"
                    }
            except subprocess.CalledProcessError as e:
                logger.error(f"❌ Chocolatey installation failed: {e}")
        
        # Alternative : Installation portable
        return self._install_tor_windows_portable()
    
    def _install_tor_windows_portable(self) -> Dict[str, any]:
        """Installation portable de Tor sur Windows"""
        try:
            import requests
            import zipfile
            
            tor_portable_dir = self.portable_dir / "tor_portable"
            tor_portable_dir.mkdir(exist_ok=True)
            
            # URL de téléchargement Tor Browser (version portable)
            tor_download_url = "https://dist.torproject.org/torbrowser/13.0.1/tor-expert-bundle-13.0.1-windows-x86_64.tar.gz"
            
            logger.info("🔄 Downloading Tor portable...")
            
            with tempfile.NamedTemporaryFile(delete=False, suffix='.tar.gz') as tmp_file:
                response = requests.get(tor_download_url, timeout=300)
                response.raise_for_status()
                tmp_file.write(response.content)
                tmp_path = tmp_file.name
            
            # Extraire l'archive
            import tarfile
            with tarfile.open(tmp_path, 'r:gz') as tar:
                tar.extractall(tor_portable_dir)
            
            # Nettoyer le fichier temporaire
            os.unlink(tmp_path)
            
            # Créer un script de démarrage
            tor_exe_path = None
            for root, dirs, files in os.walk(tor_portable_dir):
                if 'tor.exe' in files:
                    tor_exe_path = Path(root) / 'tor.exe'
                    break
            
            if tor_exe_path and tor_exe_path.exists():
                # Créer un script de démarrage
                start_script = tor_portable_dir / "start_tor.bat"
                with open(start_script, 'w') as f:
                    f.write(f'@echo off\n')
                    f.write(f'cd /d "{tor_exe_path.parent}"\n')
                    f.write(f'"{tor_exe_path}" --defaults-torrc torrc\n')
                
                # Démarrer Tor
                subprocess.Popen([str(start_script)], 
                               creationflags=subprocess.CREATE_NEW_CONSOLE)
                
                # Attendre que Tor démarre
                import time
                time.sleep(5)
                
                if self.is_tor_installed():
                    return {
                        "success": True,
                        "message": f"Tor successfully installed (portable) at {tor_portable_dir}",
                        "method": "portable_windows",
                        "tor_path": str(tor_exe_path)
                    }
            
            return {
                "success": False,
                "message": "Tor portable installation failed",
                "method": "portable_failed"
            }
            
        except Exception as e:
            logger.error(f"❌ Portable installation failed: {e}")
            return {
                "success": False,
                "message": "Tor installation failed. Please install manually.",
                "method": "manual_required",
                "instructions": [
                    "Install Tor manually on Windows:",
                    "1. Download Tor Browser from: https://www.torproject.org/download/",
                    "2. Or install via Chocolatey: choco install tor",
                    "3. Or install via Scoop: scoop install tor"
                ]
            }
    
    def get_installation_status(self) -> Dict[str, any]:
        """Obtenir le statut d'installation de Tor"""
        installed = self.is_tor_installed()
        
        status = {
            "installed": installed,
            "system": self.system,
            "portable_dir": str(self.portable_dir)
        }
        
        if installed:
            try:
                result = subprocess.run(['tor', '--version'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    status["version"] = result.stdout.splitlines()[0]
            except Exception:
                pass
                
            # Vérifier le service
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex(('127.0.0.1', 9050))
                sock.close()
                status["service_running"] = result == 0
            except Exception:
                status["service_running"] = False
        
        return status


def get_tor_installer() -> TorInstaller:
    """Factory function pour obtenir une instance de TorInstaller"""
    return TorInstaller()


# CLI pour tester l'installation
if __name__ == "__main__":
    installer = TorInstaller()
    
    print("🔍 Checking Tor installation status...")
    status = installer.get_installation_status()
    print(f"Status: {status}")
    
    if not status["installed"]:
        print("\n🔄 Installing Tor...")
        result = installer.install_tor()
        print(f"Installation result: {result}")
        
        if result["success"]:
            print("✅ Tor installation completed successfully!")
        else:
            print("❌ Tor installation failed.")
            if "instructions" in result:
                print("\nManual installation instructions:")
                for instruction in result["instructions"]:
                    print(f"  {instruction}")
    else:
        print("✅ Tor is already installed and accessible!")