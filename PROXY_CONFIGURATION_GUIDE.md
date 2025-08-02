# 🛡️ Guide de Configuration des Proxies Externes - CyberSec Assistant

## 📋 Vue d'ensemble

Ce guide détaille les nouvelles fonctionnalités de configuration des proxies externes ajoutées au framework CyberSec Assistant, permettant aux utilisateurs d'activer facilement Tor et des proxies externes pour améliorer l'anonymat et la furtivité de leurs opérations de sécurité.

## 🎯 Fonctionnalités Implémentées

### ✅ **Installation Automatique de Tor**
- Installation automatique de Tor sur Windows, Linux et macOS
- Détection intelligente du gestionnaire de paquets (apt, yum, brew, chocolatey)
- Installation portable sur Windows si les gestionnaires de paquets ne sont pas disponibles
- Intégration dans les scripts de lancement pour une installation transparente

### ✅ **Fichier de Configuration Simple**
- Format INI lisible par les utilisateurs (non-technique)
- Configuration commentée avec explications détaillées
- Sections organisées : Général, Tor, Proxies Externes, Sécurité, Avancé
- Validation automatique des paramètres

### ✅ **Interface Graphique Complète**
- Interface React moderne avec thème cybersécurité
- Navigation par onglets pour différentes sections
- Contrôles intuitifs avec sliders et checkboxes
- Messages de feedback en temps réel

## 📁 Structure des Fichiers Ajoutés

```
/app/
├── backend/
│   ├── tor_installer.py                 # Installation automatique de Tor
│   ├── proxy_user_config_manager.py     # Gestionnaire de configuration utilisateur
│   ├── proxy_user_config_api.py         # API endpoints pour la configuration
│   └── requirements.txt                 # Dépendances Tor ajoutées
├── frontend/src/
│   ├── ProxyConfigManager.js            # Composant React principal
│   └── ProxyConfigManager.css           # Styles de l'interface
├── data/
│   └── proxy_user_config.ini            # Fichier de configuration utilisateur
└── PROXY_CONFIGURATION_GUIDE.md        # Ce guide
```

## 🔧 Installation et Configuration

### **1. Installation Automatique de Tor**

L'installation de Tor est maintenant automatique lors du démarrage :

```bash
# Linux/Mac
./start.sh

# Windows  
start.bat

# Cross-platform
python launch.py
```

Le système détectera automatiquement votre OS et installera Tor via :
- **Linux** : `apt`, `yum`, `dnf`, `pacman`, `zypper`
- **macOS** : `brew` ou `macports`
- **Windows** : `chocolatey` ou installation portable

### **2. Configuration via Fichier INI**

Éditez le fichier `/app/data/proxy_user_config.ini` :

```ini
[TOR]
# Activer/Désactiver Tor
enabled = true

# Démarrage automatique
auto_start = true

# Utiliser Tor comme proxy principal
use_as_primary = false

[EXTERNAL_PROXIES]
# Activer les proxies externes
enabled = true

# Liste des proxies (un par ligne)
proxy_list = 
http://proxy1.example.com:8080
socks5://proxy2.example.com:1080
```

### **3. Configuration via Interface Web**

1. Accédez à l'interface : `http://localhost:3000`
2. Cliquez sur **"🌐 Proxy Configuration"** dans la sidebar
3. Utilisez les onglets pour configurer :
   - **Général** : Paramètres de base et niveau de furtivité
   - **Tor Network** : Configuration et installation de Tor
   - **Proxies Externes** : Ajout et gestion des proxies
   - **Avancé** : Options pour utilisateurs expérimentés

## 🎭 Utilisation des Fonctionnalités

### **Onglet Général**
- **Utiliser les proxies externes** : Active/désactive l'utilisation globale des proxies
- **Niveau de furtivité** : Slider de 1 (rapide) à 10 (furtivité maximale)
- **Rotation automatique** : Change de proxy après N requêtes

### **Onglet Tor Network**
- **Statut d'installation** : Affiche si Tor est installé
- **Installation automatique** : Bouton pour installer Tor
- **Configuration Tor** : Activation, démarrage auto, utilisation prioritaire
- **Paramètres avancés** : Ports, délais entre requêtes

### **Onglet Proxies Externes**
- **Activation** : Toggle pour activer les proxies externes
- **Test automatique** : Vérification de qualité des proxies
- **Score minimum** : Slider pour définir le seuil de qualité
- **Ajout de proxy** : Interface pour ajouter nouveaux proxies
- **Liste gérée** : Affichage et suppression des proxies existants

### **Onglet Avancé**
- **Paramètres de sécurité** : Vérifications et avertissements
- **Évasion** : Rotation User-Agent, chaînage de proxies
- **Fichier de config** : Accès direct au fichier INI

## 🌐 Formats de Proxies Supportés

Le système accepte différents formats de proxies :

```
# HTTP Proxy
http://proxy.example.com:8080

# HTTPS Proxy
https://proxy.example.com:8080

# SOCKS4 Proxy
socks4://proxy.example.com:1080

# SOCKS5 Proxy
socks5://proxy.example.com:1080

# Proxy avec authentification
http://username:password@proxy.example.com:8080
```

## 🔒 Niveaux de Furtivité

| Niveau | Description | Vitesse | Anonymat |
|--------|-------------|---------|----------|
| 1-3    | Furtivité basique | ⚡⚡⚡ Élevée | 🛡️ Basique |
| 4-6    | Furtivité modérée | ⚡⚡ Modérée | 🛡️🛡️ Modéré |
| 7-10   | Furtivité maximale | ⚡ Réduite | 🛡️🛡️🛡️ Maximum |

## 🔧 API Endpoints

L'API fournit plusieurs endpoints pour la gestion programmatique :

```bash
# Statut de la configuration
GET /api/proxy-config/status

# Configuration Tor
GET /api/proxy-config/config/tor
POST /api/proxy-config/config/tor/update

# Proxies externes
GET /api/proxy-config/proxies/list
POST /api/proxy-config/proxies/add
POST /api/proxy-config/proxies/remove

# Installation Tor
POST /api/proxy-config/tor/install
GET /api/proxy-config/tor/status

# Configuration générale
GET /api/proxy-config/config
POST /api/proxy-config/config/general/update
POST /api/proxy-config/config/reset
```

## 🧪 Tests et Validation

### **Test de l'API**
```bash
# Tester le statut
curl http://localhost:8001/api/proxy-config/status

# Activer Tor
curl -X POST http://localhost:8001/api/proxy-config/config/tor/update \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}'

# Ajouter un proxy
curl -X POST http://localhost:8001/api/proxy-config/proxies/add \
  -H "Content-Type: application/json" \
  -d '{"proxy_url": "http://proxy.example.com:8080"}'
```

### **Test de l'Installation Tor**
```bash
# Vérifier le statut d'installation
python -c "
import sys; sys.path.append('backend')
from tor_installer import get_tor_installer
print(get_tor_installer().get_installation_status())
"
```

### **Test de la Configuration**
```bash
# Vérifier la configuration utilisateur
python -c "
import sys; sys.path.append('backend')
from proxy_user_config_manager import get_user_config_manager
import json
print(json.dumps(get_user_config_manager().get_full_config(), indent=2))
"
```

## 🔍 Dépannage

### **Tor ne s'installe pas**
1. Vérifiez vos droits administrateur
2. Consultez les logs : `/app/logs/backend.log`
3. Installation manuelle selon votre OS :
   - **Ubuntu/Debian** : `sudo apt install tor`
   - **CentOS/RHEL** : `sudo yum install tor`
   - **macOS** : `brew install tor`
   - **Windows** : `choco install tor`

### **Interface ne se charge pas**
1. Vérifiez que le backend fonctionne : `curl http://localhost:8001/api/proxy-config/status`
2. Vérifiez que le frontend est démarré : `curl http://localhost:3000`
3. Redémarrez les services : `sudo supervisorctl restart all`

### **Proxies ne fonctionnent pas**
1. Vérifiez la validité des URLs de proxy
2. Testez manuellement les proxies
3. Consultez les logs de qualité dans l'interface
4. Ajustez le score minimum de qualité

## 📚 Exemples d'Utilisation

### **Configuration Basique**
```ini
[GENERAL]
use_external_proxies = true
stealth_level = 5

[TOR]
enabled = true
auto_start = true

[EXTERNAL_PROXIES]
enabled = true
proxy_list = 
http://free-proxy1.example.com:8080
socks5://free-proxy2.example.com:1080
```

### **Configuration Avancée**
```ini
[GENERAL]
use_external_proxies = true
stealth_level = 8
auto_rotate_proxies = true

[TOR]
enabled = true
use_as_primary = true
request_delay_min = 5.0
request_delay_max = 10.0

[SAFETY]
warn_ip_leak = true
auto_disable_on_detection = true
max_failed_attempts = 3
```

## 🔐 Sécurité et Conformité

### **Usage Légal Uniquement**
- ⚖️ Utilisez uniquement sur vos propres systèmes
- 📝 Obtenez une autorisation explicite pour les tests
- 🎓 Respectez les lois locales sur l'utilisation de proxies/Tor
- 📋 Documentation des activités recommandée

### **Bonnes Pratiques**
- 🔄 Rotez régulièrement vos proxies
- 📊 Surveillez les scores de qualité
- ⚠️ Attention aux fuites d'IP
- 🛡️ Utilisez des niveaux de furtivité appropriés

## 🎯 Roadmap Future

### **Améliorations Prévues**
- [ ] Support des proxies rotatifs commerciaux
- [ ] Intégration avec services VPN
- [ ] Métriques de performance avancées
- [ ] Profiles de configuration prédéfinis
- [ ] Tests de qualité automatisés plus poussés

## 💡 Support

En cas de problème :
1. Consultez ce guide
2. Vérifiez les logs dans `/app/logs/`
3. Testez l'API avec les exemples fournis
4. Vérifiez la configuration dans `/app/data/proxy_user_config.ini`

---

**✅ Configuration des Proxies Externes - Implémentation Complète**
*Version 1.0 - Intégration réussie dans CyberSec Assistant Portable*