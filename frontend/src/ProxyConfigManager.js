import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './ProxyConfigManager.css';

// Backend URL configuration
const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

const api = axios.create({
  baseURL: BACKEND_URL,
  timeout: 10000,
});

const ProxyConfigManager = () => {
  // States
  const [config, setConfig] = useState(null);
  const [torStatus, setTorStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  
  // Form states
  const [newProxy, setNewProxy] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [activeTab, setActiveTab] = useState('general');

  useEffect(() => {
    loadConfiguration();
  }, []);

  const loadConfiguration = async () => {
    setLoading(true);
    try {
      const [configResponse, torResponse] = await Promise.all([
        api.get('/api/proxy-config/config'),
        api.get('/api/proxy-config/tor/status')
      ]);
      
      setConfig(configResponse.data.config);
      setTorStatus(torResponse.data.tor_status);
      setError(null);
    } catch (err) {
      console.error('Failed to load configuration:', err);
      setError('Impossible de charger la configuration');
    } finally {
      setLoading(false);
    }
  };

  const showMessage = (message, type = 'success') => {
    if (type === 'success') {
      setSuccess(message);
      setError(null);
      setTimeout(() => setSuccess(null), 3000);
    } else {
      setError(message);
      setSuccess(null);
    }
  };

  const updateTorConfig = async (updates) => {
    setSaving(true);
    try {
      await api.post('/api/proxy-config/config/tor/update', updates);
      await loadConfiguration();
      showMessage('Configuration Tor mise à jour avec succès');
    } catch (err) {
      console.error('Failed to update Tor config:', err);
      showMessage('Erreur lors de la mise à jour de la configuration Tor', 'error');
    } finally {
      setSaving(false);
    }
  };

  const updateGeneralConfig = async (updates) => {
    setSaving(true);
    try {
      await api.post('/api/proxy-config/config/general/update', updates);
      await loadConfiguration();
      showMessage('Configuration générale mise à jour avec succès');
    } catch (err) {
      console.error('Failed to update general config:', err);
      showMessage('Erreur lors de la mise à jour de la configuration générale', 'error');
    } finally {
      setSaving(false);
    }
  };

  const updateExternalProxiesConfig = async (updates) => {
    setSaving(true);
    try {
      await api.post('/api/proxy-config/config/external-proxies/update', updates);
      await loadConfiguration();
      showMessage('Configuration des proxies externes mise à jour');
    } catch (err) {
      console.error('Failed to update external proxies config:', err);
      showMessage('Erreur lors de la mise à jour des proxies externes', 'error');
    } finally {
      setSaving(false);
    }
  };

  const addProxy = async () => {
    if (!newProxy.trim()) {
      showMessage('Veuillez entrer une URL de proxy valide', 'error');
      return;
    }

    try {
      const response = await api.post('/api/proxy-config/proxies/add', {
        proxy_url: newProxy.trim()
      });

      if (response.data.success) {
        setNewProxy('');
        await loadConfiguration();
        showMessage('Proxy ajouté avec succès');
      } else {
        showMessage(response.data.message, 'error');
      }
    } catch (err) {
      console.error('Failed to add proxy:', err);
      showMessage('Erreur lors de l\'ajout du proxy', 'error');
    }
  };

  const removeProxy = async (proxyUrl) => {
    try {
      const response = await api.post('/api/proxy-config/proxies/remove', {
        proxy_url: proxyUrl
      });

      if (response.data.success) {
        await loadConfiguration();
        showMessage('Proxy supprimé avec succès');
      } else {
        showMessage(response.data.message, 'error');
      }
    } catch (err) {
      console.error('Failed to remove proxy:', err);
      showMessage('Erreur lors de la suppression du proxy', 'error');
    }
  };

  const installTor = async () => {
    setSaving(true);
    try {
      const response = await api.post('/api/proxy-config/tor/install');
      showMessage(response.data.message);
      
      // Recharger le statut après quelques secondes
      setTimeout(loadConfiguration, 3000);
    } catch (err) {
      console.error('Failed to install Tor:', err);
      showMessage('Erreur lors de l\'installation de Tor', 'error');
    } finally {
      setSaving(false);
    }
  };

  const resetConfiguration = async () => {
    if (!window.confirm('Êtes-vous sûr de vouloir réinitialiser la configuration ? Cette action est irréversible.')) {
      return;
    }

    setSaving(true);
    try {
      await api.post('/api/proxy-config/config/reset');
      await loadConfiguration();
      showMessage('Configuration réinitialisée avec succès');
    } catch (err) {
      console.error('Failed to reset configuration:', err);
      showMessage('Erreur lors de la réinitialisation', 'error');
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="proxy-config-container">
        <div className="loading-spinner">
          <div className="spinner"></div>
          <p>Chargement de la configuration...</p>
        </div>
      </div>
    );
  }

  if (!config) {
    return (
      <div className="proxy-config-container">
        <div className="error-message">
          <p>❌ Impossible de charger la configuration</p>
          <button onClick={loadConfiguration}>🔄 Réessayer</button>
        </div>
      </div>
    );
  }

  return (
    <div className="proxy-config-container">
      <div className="config-header">
        <h2>🛡️ Configuration des Proxies Externes</h2>
        <p>Gérez vos paramètres de proxy et d'anonymat pour des opérations furtives</p>
        
        {error && <div className="alert alert-error">{error}</div>}
        {success && <div className="alert alert-success">{success}</div>}
      </div>

      {/* Navigation par onglets */}
      <div className="config-tabs">
        <button 
          className={`tab ${activeTab === 'general' ? 'active' : ''}`}
          onClick={() => setActiveTab('general')}
        >
          ⚙️ Général
        </button>
        <button 
          className={`tab ${activeTab === 'tor' ? 'active' : ''}`}
          onClick={() => setActiveTab('tor')}
        >
          🧅 Tor Network
        </button>
        <button 
          className={`tab ${activeTab === 'proxies' ? 'active' : ''}`}
          onClick={() => setActiveTab('proxies')}
        >
          🌐 Proxies Externes
        </button>
        <button 
          className={`tab ${activeTab === 'advanced' ? 'active' : ''}`}
          onClick={() => setActiveTab('advanced')}
        >
          🔧 Avancé
        </button>
      </div>

      {/* Contenu des onglets */}
      <div className="config-content">
        {/* Onglet Général */}
        {activeTab === 'general' && (
          <div className="config-section">
            <h3>⚙️ Configuration Générale</h3>
            
            <div className="config-group">
              <label className="config-label">
                <input
                  type="checkbox"
                  checked={config.general.use_external_proxies}
                  onChange={(e) => updateGeneralConfig({ use_external_proxies: e.target.checked })}
                  disabled={saving}
                />
                <span>Utiliser les proxies externes</span>
              </label>
              <p className="config-help">Active l'utilisation des proxies configurés pour toutes les requêtes</p>
            </div>

            <div className="config-group">
              <label className="config-label">
                Niveau de furtivité: <strong>{config.general.stealth_level}/10</strong>
              </label>
              <input
                type="range"
                min="1"
                max="10"
                value={config.general.stealth_level}
                onChange={(e) => updateGeneralConfig({ stealth_level: parseInt(e.target.value) })}
                disabled={saving}
                className="stealth-slider"
              />
              <div className="stealth-description">
                {config.general.stealth_level <= 3 && "🚀 Furtivité basique - Vitesse élevée"}
                {config.general.stealth_level >= 4 && config.general.stealth_level <= 6 && "⚖️ Furtivité modérée - Équilibre"}
                {config.general.stealth_level >= 7 && "🛡️ Furtivité maximale - Vitesse réduite"}
              </div>
            </div>

            <div className="config-group">
              <label className="config-label">
                <input
                  type="checkbox"
                  checked={config.general.auto_rotate_proxies}
                  onChange={(e) => updateGeneralConfig({ auto_rotate: e.target.checked })}
                  disabled={saving}
                />
                <span>Rotation automatique des proxies</span>
              </label>
              <p className="config-help">Change automatiquement de proxy après {config.general.rotation_interval} requêtes</p>
            </div>
          </div>
        )}

        {/* Onglet Tor */}
        {activeTab === 'tor' && (
          <div className="config-section">
            <h3>🧅 Configuration Tor Network</h3>
            
            {/* Statut d'installation */}
            <div className="tor-status">
              <h4>Statut d'Installation</h4>
              {torStatus ? (
                <div className={`status-indicator ${torStatus.installed ? 'installed' : 'not-installed'}`}>
                  <span className="status-icon">{torStatus.installed ? '✅' : '❌'}</span>
                  <span className="status-text">
                    {torStatus.installed ? 'Tor est installé' : 'Tor n\'est pas installé'}
                  </span>
                  {torStatus.version && <span className="version">({torStatus.version})</span>}
                </div>
              ) : (
                <div className="status-loading">🔄 Vérification...</div>
              )}
              
              {torStatus && !torStatus.installed && (
                <button 
                  className="install-tor-btn"
                  onClick={installTor}
                  disabled={saving}
                >
                  {saving ? '🔄 Installation...' : '📥 Installer Tor automatiquement'}
                </button>
              )}
            </div>

            <div className="config-group">
              <label className="config-label">
                <input
                  type="checkbox"
                  checked={config.tor.enabled}
                  onChange={(e) => updateTorConfig({ enabled: e.target.checked })}
                  disabled={saving || !torStatus?.installed}
                />
                <span>Activer Tor Network</span>
              </label>
              <p className="config-help">
                {!torStatus?.installed 
                  ? "⚠️ Tor doit être installé pour activer cette option"
                  : "Route le trafic via le réseau Tor pour un anonymat maximum"
                }
              </p>
            </div>

            {config.tor.enabled && (
              <>
                <div className="config-group">
                  <label className="config-label">
                    <input
                      type="checkbox"
                      checked={config.tor.use_as_primary}
                      onChange={(e) => updateTorConfig({ use_as_primary: e.target.checked })}
                      disabled={saving}
                    />
                    <span>Utiliser Tor comme proxy principal</span>
                  </label>
                  <p className="config-help">Force l'utilisation de Tor pour toutes les requêtes</p>
                </div>

                <div className="config-group">
                  <label className="config-label">
                    <input
                      type="checkbox"
                      checked={config.tor.auto_start}
                      onChange={(e) => updateTorConfig({ auto_start: e.target.checked })}
                      disabled={saving}
                    />
                    <span>Démarrage automatique de Tor</span>
                  </label>
                  <p className="config-help">Lance automatiquement Tor au démarrage de l'application</p>
                </div>

                <div className="tor-settings">
                  <div className="setting-row">
                    <label>Port SOCKS5:</label>
                    <span className="port-display">{config.tor.socks_port}</span>
                  </div>
                  <div className="setting-row">
                    <label>Délai entre requêtes:</label>
                    <span className="delay-display">
                      {config.tor.request_delay_min}s - {config.tor.request_delay_max}s
                    </span>
                  </div>
                </div>
              </>
            )}

            <div className="tor-info">
              <h4>ℹ️ Informations sur Tor</h4>
              <ul>
                <li>Tor assure un anonymat maximal mais réduit la vitesse</li>
                <li>Idéal pour les opérations sensibles nécessitant une confidentialité absolue</li>
                <li>Le trafic est routé via plusieurs relais pour masquer l'origine</li>
                <li>Installation automatique supportée sur la plupart des systèmes</li>
              </ul>
            </div>
          </div>
        )}

        {/* Onglet Proxies Externes */}
        {activeTab === 'proxies' && (
          <div className="config-section">
            <h3>🌐 Proxies Externes</h3>
            
            <div className="config-group">
              <label className="config-label">
                <input
                  type="checkbox"
                  checked={config.external_proxies.enabled}
                  onChange={(e) => updateExternalProxiesConfig({ enabled: e.target.checked })}
                  disabled={saving}
                />
                <span>Activer les proxies externes</span>
              </label>
              <p className="config-help">Utilise les proxies de la liste ci-dessous</p>
            </div>

            {config.external_proxies.enabled && (
              <>
                <div className="config-group">
                  <label className="config-label">
                    <input
                      type="checkbox"
                      checked={config.external_proxies.auto_test_proxies}
                      onChange={(e) => updateExternalProxiesConfig({ auto_test_proxies: e.target.checked })}
                      disabled={saving}
                    />
                    <span>Test automatique de qualité</span>
                  </label>
                  <p className="config-help">Teste automatiquement la qualité et la vitesse des proxies</p>
                </div>

                <div className="config-group">
                  <label className="config-label">
                    Score minimum requis: <strong>{(config.external_proxies.minimum_quality_score * 100).toFixed(0)}%</strong>
                  </label>
                  <input
                    type="range"
                    min="0"
                    max="1"
                    step="0.1"
                    value={config.external_proxies.minimum_quality_score}
                    onChange={(e) => updateExternalProxiesConfig({ minimum_quality_score: parseFloat(e.target.value) })}
                    disabled={saving}
                    className="quality-slider"
                  />
                  <p className="config-help">Score minimum pour utiliser un proxy (0% = accepter tous, 100% = parfait uniquement)</p>
                </div>
              </>
            )}

            {/* Ajout de proxy */}
            <div className="proxy-add-section">
              <h4>➕ Ajouter un Proxy</h4>
              <div className="proxy-add-form">
                <input
                  type="text"
                  value={newProxy}
                  onChange={(e) => setNewProxy(e.target.value)}
                  placeholder="http://proxy.example.com:8080"
                  className="proxy-input"
                />
                <button 
                  onClick={addProxy}
                  className="add-proxy-btn"
                  disabled={!newProxy.trim()}
                >
                  ➕ Ajouter
                </button>
              </div>
              <div className="proxy-format-help">
                <strong>Formats supportés:</strong>
                <ul>
                  <li><code>http://proxy.example.com:8080</code></li>
                  <li><code>socks5://proxy.example.com:1080</code></li>
                  <li><code>http://user:pass@proxy.example.com:8080</code></li>
                </ul>
              </div>
            </div>

            {/* Liste des proxies */}
            <div className="proxy-list-section">
              <h4>📋 Liste des Proxies ({config.external_proxies.proxy_list.length})</h4>
              {config.external_proxies.proxy_list.length === 0 ? (
                <div className="no-proxies">
                  <p>Aucun proxy configuré</p>
                  <p>Ajoutez des proxies externes pour améliorer votre anonymat</p>
                </div>
              ) : (
                <div className="proxy-list">
                  {config.external_proxies.proxy_list.map((proxy, index) => (
                    <div key={index} className="proxy-item">
                      <span className="proxy-url">{proxy}</span>
                      <button 
                        onClick={() => removeProxy(proxy)}
                        className="remove-proxy-btn"
                        title="Supprimer ce proxy"
                      >
                        🗑️
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Onglet Avancé */}
        {activeTab === 'advanced' && (
          <div className="config-section">
            <h3>🔧 Configuration Avancée</h3>
            <p className="advanced-warning">
              ⚠️ Ces paramètres sont destinés aux utilisateurs expérimentés
            </p>

            <div className="config-group">
              <h4>🔒 Paramètres de Sécurité</h4>
              
              <label className="config-label">
                <input
                  type="checkbox"
                  checked={config.safety.enable_safety_checks}
                  disabled={true}
                />
                <span>Vérifications de sécurité (recommandé)</span>
              </label>

              <label className="config-label">
                <input
                  type="checkbox"
                  checked={config.safety.warn_ip_leak}
                  disabled={true}
                />
                <span>Avertir si l'IP réelle est détectée</span>
              </label>

              <label className="config-label">
                <input
                  type="checkbox"
                  checked={config.safety.auto_disable_on_detection}
                  disabled={true}
                />
                <span>Désactivation automatique en cas de détection</span>
              </label>
            </div>

            <div className="config-group">
              <h4>🎭 Paramètres d'Évasion</h4>
              
              <label className="config-label">
                <input
                  type="checkbox"
                  checked={config.advanced.rotate_user_agents}
                  disabled={true}
                />
                <span>Rotation des User-Agents</span>
              </label>

              <label className="config-label">
                <input
                  type="checkbox"
                  checked={config.advanced.enable_proxy_chaining}
                  disabled={true}
                />
                <span>Chaînage de proxies (longueur: {config.advanced.chain_length})</span>
              </label>

              <label className="config-label">
                <input
                  type="checkbox"
                  checked={config.advanced.use_persistent_sessions}
                  disabled={true}
                />
                <span>Sessions persistantes</span>
              </label>
            </div>

            <div className="config-info">
              <h4>📝 Fichier de Configuration</h4>
              <p>Pour une configuration plus avancée, vous pouvez éditer directement le fichier:</p>
              <code className="config-path">{config.metadata?.config_file}</code>
            </div>
          </div>
        )}
      </div>

      {/* Actions globales */}
      <div className="config-actions">
        <button 
          onClick={loadConfiguration}
          className="action-btn refresh"
          disabled={loading || saving}
        >
          🔄 Actualiser
        </button>
        
        <button 
          onClick={resetConfiguration}
          className="action-btn reset"
          disabled={saving}
        >
          🔄 Réinitialiser
        </button>
        
        <button 
          onClick={() => window.open(`${BACKEND_URL}/api/proxy-config/help`)}
          className="action-btn help"
        >
          ❓ Aide
        </button>
      </div>

      {saving && (
        <div className="saving-overlay">
          <div className="saving-spinner">
            <div className="spinner"></div>
            <p>Sauvegarde en cours...</p>
          </div>
        </div>
      )}
    </div>
  );
};

export default ProxyConfigManager;