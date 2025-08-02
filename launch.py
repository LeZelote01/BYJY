#!/usr/bin/env python3
"""
CyberSec Assistant - Nouveau Lanceur Simplifié
Version corrigée pour éviter les problèmes de timeout
"""

import os
import sys
import subprocess
import platform
import time
import signal
import webbrowser
from pathlib import Path
import json

class SimpleLauncher:
    def __init__(self):
        self.script_dir = Path(__file__).parent.absolute()
        self.backend_dir = self.script_dir / "backend"
        self.frontend_dir = self.script_dir / "frontend"
        self.data_dir = self.script_dir / "data"
        self.logs_dir = self.script_dir / "logs"
        
        # Créer les dossiers nécessaires
        self.data_dir.mkdir(exist_ok=True)
        self.logs_dir.mkdir(exist_ok=True)
        
        self.backend_process = None
        self.frontend_process = None
        
        # Configuration
        self.backend_port = 8001
        self.frontend_port = 3000
        self.backend_host = "127.0.0.1"

    def print_banner(self):
        """Affiche la bannière de l'application"""
        banner = """
╔══════════════════════════════════════════════════════════════════╗
║                🛡️  CYBERSEC ASSISTANT - NOUVEAU LANCEUR          ║
║                                                                  ║
║              Lanceur Simplifié et Robuste v2.0                  ║
║                         Legal Use Only                          ║
╚══════════════════════════════════════════════════════════════════╝
        """
        print(banner)
        print(f"Platform: {platform.system()} {platform.release()}")
        print(f"Architecture: {platform.machine()}")
        print(f"Répertoire: {self.script_dir}")
        print("=" * 70)

    def check_python(self):
        """Vérifie Python"""
        try:
            version = sys.version.split()[0]
            print(f"✅ Python trouvé: {version}")
            return True
        except Exception as e:
            print(f"❌ Erreur Python: {e}")
            return False

    def check_node(self):
        """Vérifie Node.js"""
        try:
            result = subprocess.run(["node", "--version"], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                version = result.stdout.strip()
                print(f"✅ Node.js trouvé: {version}")
                return True
            else:
                print("❌ Node.js non trouvé")
                return False
        except Exception as e:
            print(f"❌ Erreur Node.js: {e}")
            return False

    def install_backend_dependencies(self):
        """Installe les dépendances Python"""
        print("📦 Installation des dépendances backend...")
        requirements_file = self.backend_dir / "requirements.txt"
        
        if not requirements_file.exists():
            print("⚠️ requirements.txt non trouvé")
            return False
        
        try:
            subprocess.run([
                sys.executable, "-m", "pip", "install", "-r", str(requirements_file)
            ], check=True, cwd=self.backend_dir, timeout=300)  # 5 minutes max
            print("✅ Dépendances backend installées")
            return True
        except subprocess.TimeoutExpired:
            print("❌ Timeout lors de l'installation des dépendances backend")
            return False
        except subprocess.CalledProcessError as e:
            print(f"❌ Erreur installation backend: {e}")
            return False

    def install_frontend_dependencies(self):
        """Installe les dépendances frontend"""
        print("📦 Installation des dépendances frontend...")
        package_json = self.frontend_dir / "package.json"
        
        if not package_json.exists():
            print("⚠️ package.json non trouvé, frontend ignoré")
            return True
        
        try:
            # Utilise yarn si disponible, sinon npm
            yarn_available = subprocess.run(["yarn", "--version"], 
                                          capture_output=True, timeout=10).returncode == 0
            
            if yarn_available:
                print("Utilisation de yarn...")
                subprocess.run(["yarn", "install"], check=True, cwd=self.frontend_dir, timeout=300)
            else:
                print("Utilisation de npm...")
                subprocess.run(["npm", "install"], check=True, cwd=self.frontend_dir, timeout=300)
            
            print("✅ Dépendances frontend installées")
            return True
        except subprocess.TimeoutExpired:
            print("❌ Timeout lors de l'installation des dépendances frontend")
            return False
        except subprocess.CalledProcessError as e:
            print(f"❌ Erreur installation frontend: {e}")
            return False

    def cleanup_ports(self):
        """Nettoie les ports utilisés"""
        print("🧹 Nettoyage des ports...")
        try:
            # Tue les processus sur les ports spécifiques
            subprocess.run(["fuser", "-k", f"{self.backend_port}/tcp"], 
                         capture_output=True, timeout=5)
            subprocess.run(["fuser", "-k", f"{self.frontend_port}/tcp"], 
                         capture_output=True, timeout=5)
            time.sleep(2)
            print("✅ Ports nettoyés")
        except Exception as e:
            print(f"⚠️ Nettoyage des ports: {e}")

    def start_backend(self):
        """Lance le backend de manière robuste"""
        print("🚀 Lancement du backend...")
        
        server_file = self.backend_dir / "server.py"
        if not server_file.exists():
            print(f"❌ Fichier server.py non trouvé: {server_file}")
            return False
        
        try:
            # Variables d'environnement
            env = os.environ.copy()
            env["PYTHONPATH"] = str(self.backend_dir)
            env["PORT"] = str(self.backend_port)
            env["HOST"] = self.backend_host
            
            # Lance le backend avec nohup pour le détacher complètement
            self.backend_process = subprocess.Popen([
                sys.executable, str(server_file)
            ], 
            cwd=self.backend_dir,
            env=env,
            stdout=open(self.logs_dir / "backend_stdout.log", "w"),
            stderr=open(self.logs_dir / "backend_stderr.log", "w"),
            stdin=subprocess.DEVNULL
            )
            
            # Attendre que le backend démarre
            print("⏳ Attente du démarrage du backend...")
            for i in range(30):  # 30 secondes maximum
                try:
                    import requests
                    response = requests.get(f"http://{self.backend_host}:{self.backend_port}/api/health", 
                                          timeout=2)
                    if response.status_code == 200:
                        print("✅ Backend démarré avec succès!")
                        print(f"📋 Backend API: http://localhost:{self.backend_port}")
                        return True
                except:
                    pass
                
                # Vérifier si le processus est toujours en vie
                if self.backend_process.poll() is not None:
                    print(f"❌ Le processus backend s'est arrêté (code: {self.backend_process.returncode})")
                    return False
                
                time.sleep(1)
                print(f"[{i+1}/30] Attente...")
            
            print("❌ Timeout: Le backend ne répond pas après 30 secondes")
            return False
            
        except Exception as e:
            print(f"❌ Erreur lors du lancement du backend: {e}")
            return False

    def start_frontend(self):
        """Lance le frontend"""
        print("🌐 Lancement du frontend...")
        
        package_json = self.frontend_dir / "package.json"
        if not package_json.exists():
            print("⚠️ Pas de frontend à lancer (package.json manquant)")
            return True
        
        try:
            # Utilise yarn si disponible
            yarn_available = subprocess.run(["yarn", "--version"], 
                                          capture_output=True, timeout=5).returncode == 0
            
            cmd = ["yarn", "start"] if yarn_available else ["npm", "start"]
            
            self.frontend_process = subprocess.Popen(
                cmd,
                cwd=self.frontend_dir,
                stdout=open(self.logs_dir / "frontend_stdout.log", "w"),
                stderr=open(self.logs_dir / "frontend_stderr.log", "w"),
                stdin=subprocess.DEVNULL
            )
            
            print("✅ Frontend en cours de démarrage...")
            print(f"🌐 Frontend UI: http://localhost:{self.frontend_port}")
            
            # Ouvrir le navigateur après quelques secondes
            time.sleep(5)
            try:
                webbrowser.open(f"http://localhost:{self.frontend_port}")
            except:
                pass  # Ignore si pas de navigateur disponible
            
            return True
            
        except Exception as e:
            print(f"❌ Erreur lors du lancement du frontend: {e}")
            return False

    def setup_signal_handlers(self):
        """Configure les gestionnaires de signaux"""
        def signal_handler(signum, frame):
            print("\n🛑 Arrêt demandé...")
            self.cleanup()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    def cleanup(self):
        """Nettoie les processus lancés"""
        print("🔄 Nettoyage des processus...")
        
        if self.backend_process and self.backend_process.poll() is None:
            print("Arrêt du backend...")
            self.backend_process.terminate()
            try:
                self.backend_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.backend_process.kill()
        
        if self.frontend_process and self.frontend_process.poll() is None:
            print("Arrêt du frontend...")
            self.frontend_process.terminate()
            try:
                self.frontend_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.frontend_process.kill()
        
        print("✅ Nettoyage terminé")

    def run(self):
        """Lance l'application complète"""
        self.print_banner()
        self.setup_signal_handlers()
        
        # Vérifications préliminaires
        print("🔍 Vérifications système...")
        if not self.check_python():
            return False
        
        node_available = self.check_node()
        
        # Nettoyage préalable
        self.cleanup_ports()
        
        # Installation des dépendances
        if not self.install_backend_dependencies():
            print("❌ Échec de l'installation des dépendances backend")
            return False
        
        if node_available:
            if not self.install_frontend_dependencies():
                print("⚠️ Problème avec les dépendances frontend, mais continuation...")
        
        # Lancement du backend
        if not self.start_backend():
            print("❌ Échec du lancement du backend")
            return False
        
        # Lancement du frontend
        if node_available:
            if not self.start_frontend():
                print("⚠️ Problème avec le frontend, mais backend disponible")
        else:
            print("⚠️ Node.js non disponible, seul le backend sera lancé")
        
        # Application lancée
        print("\n" + "="*70)
        print("🎉 CyberSec Assistant lancé avec succès!")
        print(f"📋 Backend API: http://localhost:{self.backend_port}")
        if node_available:
            print(f"🌐 Frontend UI: http://localhost:{self.frontend_port}")
        print("\n📝 Logs disponibles dans:", self.logs_dir)
        print("⌨️  Appuyez sur Ctrl+C pour arrêter l'application")
        print("="*70)
        
        # Maintenir l'application en vie
        try:
            while True:
                time.sleep(1)
                
                # Vérifier que le backend est toujours en vie
                if self.backend_process and self.backend_process.poll() is not None:
                    print("❌ Le backend s'est arrêté de façon inattendue")
                    break
                
        except KeyboardInterrupt:
            print("\n🛑 Arrêt demandé par l'utilisateur")
        finally:
            self.cleanup()
        
        return True

if __name__ == "__main__":
    launcher = SimpleLauncher()
    success = launcher.run()
    sys.exit(0 if success else 1)