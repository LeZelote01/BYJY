# 🛡️ CyberSec Assistant Portable V1.3

## 📋 Description
Suite cybersécurité complète portable sur clé USB/carte SD pour tests de pénétration, audit, formation et recherche légaux. 100% portable - Plug & Play sur Windows/Linux/Mac.

⚠️ **USAGE LÉGAL UNIQUEMENT** - Uniquement sur vos propres systèmes ou avec autorisation explicite.

## 🚀 Démarrage Rapide

### Option 1 : Windows (Recommandée)
```
Double-cliquez sur : start.bat
```

### Option 2 : Multi-plateforme
```
python start-portable.py
```

### Option 3 : Linux/Mac
```
chmod +x start.sh
./start.sh
```

## 📋 Prérequis Système

### Obligatoires :
- **Python 3.8+** (doit être installé sur le système hôte)
- **1 GB RAM minimum** (2 GB recommandé)
- **2 GB espace libre** sur clé USB/SD
- **Connexion Internet** (pour l'installation initiale des dépendances)

### Optionnels (pour interface complète) :
- **Node.js 14+** (pour l'interface web)
- **Chrome/Firefox** (pour l'interface graphique)

## 🔧 Installation sur Clé USB/Carte SD

### Étape 1 : Préparation
1. **Formatez** votre clé USB/carte SD (FAT32 ou NTFS)
2. **Copiez** tout le contenu de ce dossier sur votre support portable
3. **Éjectez** proprement le support

### Étape 2 : Premier démarrage
1. **Insérez** la clé USB sur n'importe quel ordinateur
2. **Naviguez** vers le dossier racine de la clé
3. **Lancez** selon votre OS :
   - Windows : `start.bat`
   - Linux/Mac : `python start-portable.py`

### Étape 3 : Installation automatique
Au premier démarrage, l'application va :
- ✅ Détecter votre système d'exploitation
- ✅ Vérifier la présence de Python
- ✅ Installer automatiquement les dépendances
- ✅ Créer la base de données locale
- ✅ Ouvrir l'interface dans votre navigateur

## 🌐 Accès à l'Application

Une fois démarrée, l'application est accessible via :
- **Interface Web** : http://localhost:3000
- **API Backend** : http://localhost:8001

L'interface web s'ouvrira automatiquement dans votre navigateur par défaut.

## 🛠️ Modules Disponibles

### 📊 **Modules de Base** (Phase 1 - ✅ Opérationnels)
- **Overview** - Dashboard principal avec statistiques
- **Terminal** - Terminal intégré avec commandes système
- **System Monitor** - Monitoring CPU/RAM/Disque en temps réel  
- **Logs Viewer** - Visualisation et filtrage des logs
- **Database Manager** - Gestion complète de la base de données

### 🕵️ **Modules de Furtivité** (Phase 1.5 - ✅ 100% Opérationnels)
- **🛡️ Stealth Engine** - Moteur central de furtivité et d'évasion
  - User-Agent rotation intelligent (1000+ profils)
  - Headers HTTP furtifs avec randomisation
  - Timing control et délais adaptatifs
  - Sessions furtives avec score de furtivité
  
- **🌐 Proxy Manager** - Gestion avancée des proxies avec rotation automatique
  - Support Tor natif avec détection automatique
  - Tests de qualité en temps réel des proxies
  - Rotation géographique et statistiques détaillées
  - Monitoring continu de l'anonymat
  
- **🔐 Obfuscation Toolkit** - Suite complète d'obfuscation de code et données
  - Obfuscation Python AST-level avancée
  - Chiffrement des chaînes (AES/XOR)
  - Injection de code mort et anti-debug
  - Export vers exécutables packagés
  
- **🎭 Evasion Manager** - Gestion intelligente de l'évasion
  - Profils adaptatifs (normal, stealth, maximum, fast)
  - Détection automatique des événements de détection
  - Adaptation temps réel du niveau de furtivité
  - Recommandations automatiques d'amélioration

- **📊 Stealth Dashboard** - Interface de monitoring et contrôle de la furtivité
  - Visualisation du score de furtivité temps réel
  - Gestion des profils et configuration
  - Historique des détections et recommandations

### 🔍 **Modules de Reconnaissance** (Phase 2 - ✅ 100% Opérationnels)
- **Network Scanner** - Scanner réseau furtif avec intégration Nmap avancée
  - Interface complète avec profils de scan prédéfinis (quick, comprehensive, stealth, web, database)
  - Techniques d'évasion avancées : decoy scanning, fragmentation, source port spoofing
  - Monitoring temps réel des scans actifs avec scores de furtivité
  - Détection de services, OS et vulnérabilités avec parser XML complet
  - Scanner fallback intégré pour environnements sans Nmap
  
- **OSINT Collector** - Collecte d'informations avec sources multiples
  - Interface complète de configuration des modules de collecte
  - Énumération sous-domaines (brute force + Certificate Transparency)  
  - Collecte d'emails, informations WHOIS et DNS passifs
  - Intégration sources publiques (crt.sh, DNS databases, technology fingerprinting)
  - Monitoring temps réel des collections avec adaptation furtive

### 🔨 **Modules de Brute Force** (Phase 3 - ✅ 100% Opérationnels)
- **Brute Force Engine** - Attaques multi-protocoles avec furtivité avancée
  - Support SSH, FTP, Telnet, HTTP Basic/Form Authentication
  - Threading configurable avec délais adaptatifs
  - Profils d'attaque prédéfinis (quick, stealth, web_application)
  - Intégration complète avec système de furtivité
  
- **Hash Cracking System** - Système de craquage de hash professionnel
  - Support MD5, SHA1, SHA256, NTLM
  - Wordlists personnalisées et par défaut
  - Cracking optimisé avec statistiques détaillées
  
- **Wordlist Generator** - Générateur intelligent de dictionnaires
  - Génération commune (mots de passe populaires)
  - Génération ciblée (basée sur informations de la cible)
  - Génération intelligente avec règles (leet speak, variations d'années)
  - Import/Export de wordlists personnalisées
  
- **BruteForce Dashboard** - Interface complète de gestion des attaques
  - Monitoring temps réel avec progress bars et statistiques
  - Gestion des attaques actives et historique
  - Configuration avancée avec profils de sécurité
  - Résultats détaillés et export des données

### 🔨 **Modules Cybersécurité Avancés** (En développement selon roadmap)
- **WiFi Security** - Tests de sécurité WiFi avec techniques d'évasion (Phase 7)
- **MITM Attacks** - Attaques Man-in-the-Middle indétectables (Phase 7)
- **Forensics** - Analyse forensique avec anti-attribution (Phase 5)
- **Reports** - Génération de rapports avec obfuscation des données sensibles (Phase 10)

## 📁 Structure des Dossiers

```
CyberSec-Assistant-Portable/
├── 🚀 start.bat                 # Lanceur Windows
├── 🚀 start-portable.py         # Lanceur cross-platform
├── 📖 README.md                 # Ce guide
├── 🗺️ ROADMAP.md                # Plan de développement complet avec Phase 1.5 Furtivité
├── 📊 test_result.md            # Historique des tests
├── 🕵️ stealth_demo.py           # Démonstration des capacités de furtivité
├── 🖥️ backend/                  # Serveur FastAPI avec modules de furtivité
│   ├── server.py                # Application principale avec intégration stealth
│   ├── stealth_engine.py        # ✅ Moteur central de furtivité
│   ├── proxy_manager.py         # ✅ Gestionnaire avancé de proxies/Tor
│   ├── obfuscation_toolkit.py   # ✅ Suite d'obfuscation de code
│   ├── evasion_manager.py       # ✅ Gestionnaire d'évasion intelligent
│   ├── stealth_integration.py   # ✅ Intégration furtivité dans modules
│   ├── stealth_api.py           # ✅ API endpoints pour la furtivité
│   ├── evasion_api.py           # ✅ API endpoints pour l'évasion
│   ├── integration_api.py       # ✅ API endpoints d'intégration
│   ├── stealth_network_scanner.py # ✅ Scanner réseau furtif
│   ├── stealth_osint_collector.py  # ✅ Collecteur OSINT furtif
│   ├── reconnaissance_api.py    # ✅ API de reconnaissance
│   ├── database_manager.py      # Gestionnaire de base de données
│   ├── database_api.py          # API de gestion base de données
│   └── requirements.txt         # Dépendances Python (incluant crypto)
├── 🌐 frontend/                 # Interface React avec modules stealth
│   ├── src/
│   │   ├── App.js               # Application principale avec NetworkScanner
│   │   ├── DatabaseManager.js   # Interface gestion base de données
│   │   ├── StealthDashboard.js  # Dashboard de furtivité
│   │   └── NetworkScanner.js    # Interface de scan réseau
│   ├── public/
│   └── package.json
├── 🗃️ data/                     # Base de données et configurations furtives
│   ├── cybersec.db              # Base de données principale
│   ├── stealth_config.json      # Configuration de furtivité
│   ├── proxy_config.json        # Configuration des proxies
│   └── backups/                 # Sauvegardes chiffrées
└── 📝 logs/                     # Fichiers de logs (avec nettoyage auto)
```

## ⚙️ Configuration

### Ports par défaut :
- **Backend** : 8001
- **Frontend** : 3000

### Configuration de la Furtivité :
Éditez `data/stealth_config.json` pour personnaliser :
```json
{
  "stealth_level": 10,
  "obfuscation_level": 10,
  "anti_detection": true,
  "proxy_rotation": true,
  "timing_randomization": true,
  "min_request_delay": 5.0,
  "max_request_delay": 15.0,
  "max_requests_per_minute": 4
}
```

### Configuration des Proxies :
Éditez `data/proxy_config.json` pour configurer :
```json
{
  "auto_rotation": true,
  "rotation_interval": 50,
  "quality_threshold": 0.7,
  "tor_enabled": true,
  "proxy_chains": true,
  "chain_length": 2
}
```

## 🔒 Sécurité et Légalité

### ⚖️ Clause Légale
- **Usage autorisé uniquement** sur vos propres systèmes
- **Tests avec autorisation explicite** du propriétaire
- **Formation** et **recherche** en cybersécurité
- **Audit de sécurité** contractuel

### 🚨 Interdictions
- Tests sur systèmes tiers sans autorisation
- Activités malveillantes ou illégales
- Distribution d'outils d'attaque
- Contournement de mesures de sécurité non autorisé

## 🛡️ Capacités de Furtivité Avancées

### **Anti-Détection Intégrée**
- **Évasion Antivirus/EDR** : Obfuscation automatique, anti-sandbox
- **Évasion IDS/IPS** : Fragmentation, decoy scanning, timing adaptatif
- **Évasion WAF/DLP** : Headers légitimes, user-agent rotation, request spacing
- **Anti-Forensique** : Nettoyage automatique des traces, historique obfusqué

### **Techniques de Furtivité**
- **Timing Intelligence** : Délais humain-like, respect des heures ouvrables
- **Proxy Management** : Rotation automatique, tests de qualité, chaînes multiples
- **Traffic Obfuscation** : Mimétisme du trafic légitime, fragmentation intelligente
- **Behavioral Mimicry** : Simulation d'activité utilisateur normale

### **Monitoring et Adaptation**
- **Score de Furtivité** : Évaluation temps réel de 0-100
- **Détection d'Alertes** : Monitoring CAPTCHA, rate limiting, blocks
- **Adaptation Automatique** : Changement de profil selon les détections
- **Recommandations** : Suggestions d'amélioration automatiques

## 🐛 Dépannage

### Problème : Python non trouvé
```bash
# Windows
Téléchargez Python depuis : https://www.python.org/downloads/
Ou utilisez WinPython (portable)

# Linux
sudo apt install python3 python3-pip

# Mac
brew install python3
```

### Problème : Dépendances non installées
```bash
# Réinstaller manuellement
pip install -r backend/requirements.txt
```

### Problème : Port déjà utilisé
Modifiez les ports dans les fichiers de configuration ou arrêtez les processus conflictuels :
```bash
# Voir les processus sur le port
netstat -tulpn | grep :8001
netstat -tulpn | grep :3000
```

### Problème : Interface ne s'ouvre pas
1. Vérifiez que les serveurs sont démarrés
2. Accédez manuellement à http://localhost:3000
3. Consultez les logs dans le dossier `logs/`

### Problème : Détection par antivirus
1. Activez le profil "maximum_stealth"
2. Utilisez l'obfuscation avancée (niveau 10)
3. Activez la rotation de proxies
4. Consultez le Dashboard de furtivité pour optimiser

## 📞 Support et Contributions

### Structure du projet
Ce projet suit un roadmap de développement en 10 phases détaillé dans `ROADMAP.md`.

### État actuel (Juillet 2025)
- **Phase 1** : ✅ Fondations portables (TERMINÉ)
- **Phase 1.5** : ✅ Furtivité & Évasion Avancée (TERMINÉ)
- **Phase 2** : ✅ Outils intégrés & reconnaissance furtive (TERMINÉ)
- **Phase 3** : ✅ Brute Force Ultimate (TERMINÉ)
- **Phase 4** : ⏳ Analyse de Vulnérabilités Avancée (EN PRÉPARATION)

### Développement
Le projet est conçu selon une méthodologie incrémentale avec validation complète de chaque fonctionnalité avant passage à la suivante.

---

## 🏆 Fonctionnalités Principales

### 🎯 Interface Professionnelle
- Theme cybersécurité Matrix-style
- Dashboard modulaire responsive
- Navigation intuitive entre outils
- Mode sombre optimisé

### ⚡ Performance
- Démarrage rapide (<30 secondes)
- Interface fluide et réactive
- WebSocket temps réel
- Base de données SQLite optimisée

### 🔧 Portabilité
- Plug & Play sur différents OS
- Aucune installation système requise
- Configuration auto-détectée
- Données persistantes sur le support

### 🛡️ Sécurité Avancée
- **🕵️ Furtivité maximale** avec évasion complète des antivirus/EDR
- **🌐 Anonymat total** via Tor et proxies rotatifs avancés  
- **🔐 Obfuscation professionnelle** de tous les scripts et données
- **🧹 Anti-forensique complet** avec suppression automatique des traces
- **📊 Monitoring intelligent** avec adaptation temps réel
- **🎭 Profils d'évasion** adaptatifs selon le niveau de menace

---

## 📊 Statistiques Techniques

### **Architecture Modulaire**
- **15 Modules Backend** : Furtivité, Reconnaissance, Brute Force, Base de données
- **80+ API Endpoints** : RESTful avec documentation complète
- **12 Composants Frontend** : Interface moderne et responsive avec thème cybersécurité
- **26 Tables SQLite** : Schema complet pour tous les modules

### **Capacités de Reconnaissance** 
- **Scanner Réseau** : Intégration Nmap + scanner fallback avec toutes techniques d'évasion
- **OSINT Collector** : Multi-sources avec Certificate Transparency, DNS, WHOIS, tech fingerprinting
- **Profils Furtifs** : 5 profils prédéfinis + configuration personnalisée  
- **Monitoring Temps Réel** : WebSocket avec scores de furtivité et progression détaillée

### **Capacités de Brute Force**
- **Protocoles Réseau** : SSH, FTP, Telnet, HTTP Basic/Form Auth
- **Hash Cracking** : MD5, SHA1, SHA256, NTLM avec wordlists intelligentes
- **Wordlist Generator** : Génération commune, ciblée, intelligente et basée sur règles
- **Interface Complète** : Monitoring temps réel, profils d'attaque, statistiques détaillées

### **Capacités de Furtivité**
- **Score de Furtivité** : Monitoring 0-100 en temps réel
- **Profils d'Évasion** : 4 profils prédéfinis + profils personnalisés
- **Techniques d'Obfuscation** : 10 niveaux de complexité
- **Support Proxy** : Tor + HTTP/SOCKS avec rotation automatique

### **Performance**
- **~12,500 Lines** : Code Python + React optimisé avec interfaces complètes
- **Cross-Platform** : Windows, Linux, macOS
- **Portable Deployment** : USB/SD ready avec auto-configuration
- **Real-time Updates** : WebSocket + monitoring continu + interfaces responsives

---

**Version 1.3** - Dernière mise à jour : Juillet 2025
**Licence** : Usage légal et éthique uniquement

**🎯 CYBERSEC ASSISTANT PORTABLE - FURTIVITÉ PROFESSIONNELLE INTÉGRÉE**