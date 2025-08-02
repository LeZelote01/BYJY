import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import './BruteForceModule.css';

// Backend URL configuration
const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

const api = axios.create({
  baseURL: BACKEND_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  }
});

const BruteForceModule = () => {
  const [activeTab, setActiveTab] = useState('network');
  const [isLoading, setIsLoading] = useState(false);
  const [supportedProtocols, setSupportedProtocols] = useState(null);
  const [activeAttacks, setActiveAttacks] = useState([]);
  const [statistics, setStatistics] = useState(null);
  const [profiles, setProfiles] = useState({});
  const [wordlists, setWordlists] = useState([]);

  // Network Attack State
  const [networkConfig, setNetworkConfig] = useState({
    target_type: 'ssh',
    host: '',
    port: 22,
    service: '',
    username_list: [],
    password_list: [],
    custom_usernames: '',
    custom_passwords: '',
    use_common_usernames: true,
    use_common_passwords: true,
    stealth_level: 5,
    max_threads: 10,
    delay_min: 0.1,
    delay_max: 2.0,
    timeout: 10,
    stop_on_success: true,
    selected_profile: 'quick_network'
  });

  // Hash Cracking State
  const [hashConfig, setHashConfig] = useState({
    hash_value: '',
    hash_type: 'md5',
    wordlist_name: '',
    custom_wordlist: '',
    use_common_passwords: true,
    stealth_level: 5,
    max_attempts: 100000
  });

  // Wordlist Generation State
  const [wordlistGen, setWordlistGen] = useState({
    generation_type: 'common',
    target_info: {
      company: '',
      domain: '',
      keywords: ''
    },
    custom_words: '',
    limit: 10000,
    config: {
      min_length: 1,
      max_length: 12,
      include_numbers: true,
      include_symbols: true,
      include_uppercase: true,
      include_lowercase: true,
      common_patterns: true,
      year_variations: true,
      leet_speak: true
    }
  });

  const [generatedWordlist, setGeneratedWordlist] = useState([]);
  const [selectedAttack, setSelectedAttack] = useState(null);

  useEffect(() => {
    loadInitialData();
    const interval = setInterval(refreshAttacks, 5000);
    return () => clearInterval(interval);
  }, []);

  const loadInitialData = async () => {
    try {
      setIsLoading(true);
      const [protocolsRes, profilesRes, wordlistsRes, statsRes, attacksRes] = await Promise.all([
        api.get('/api/bruteforce/supported_protocols'),
        api.get('/api/bruteforce/profiles'),
        api.get('/api/bruteforce/wordlists'),
        api.get('/api/bruteforce/statistics'),
        api.get('/api/bruteforce/attacks')
      ]);

      setSupportedProtocols(protocolsRes.data);
      setProfiles(profilesRes.data.profiles);
      setWordlists(wordlistsRes.data.wordlists);
      setStatistics(statsRes.data.statistics);
      setActiveAttacks(attacksRes.data.active_attacks);
    } catch (error) {
      console.error('Failed to load initial data:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const refreshAttacks = async () => {
    try {
      const [attacksRes, statsRes] = await Promise.all([
        api.get('/api/bruteforce/attacks'),
        api.get('/api/bruteforce/statistics')
      ]);
      setActiveAttacks(attacksRes.data.active_attacks);
      setStatistics(statsRes.data.statistics);
    } catch (error) {
      console.error('Failed to refresh attacks:', error);
    }
  };

  const startNetworkAttack = async () => {
    try {
      setIsLoading(true);

      // Préparer les listes d'utilisateurs et mots de passe
      let username_list = [];
      let password_list = [];

      if (networkConfig.use_common_usernames) {
        // Les noms d'utilisateur communs seront utilisés par défaut du backend
        username_list = null;
      } else if (networkConfig.custom_usernames) {
        username_list = networkConfig.custom_usernames.split('\n').map(u => u.trim()).filter(u => u);
      }

      if (networkConfig.use_common_passwords) {
        password_list = null; // Backend utilisera les mots de passe par défaut
      } else if (networkConfig.custom_passwords) {
        password_list = networkConfig.custom_passwords.split('\n').map(p => p.trim()).filter(p => p);
      }

      // Appliquer le profil sélectionné
      const profile = profiles[networkConfig.selected_profile];
      const config = profile ? { ...networkConfig, ...profile.config } : networkConfig;

      const attackData = {
        target_type: config.target_type,
        host: config.host,
        port: config.port || (supportedProtocols?.network?.[config.target_type]?.default_port),
        service: config.service,
        username_list: username_list,
        password_list: password_list,
        stealth_level: config.stealth_level,
        max_threads: config.max_threads,
        delay_min: config.delay_min,
        delay_max: config.delay_max,
        timeout: config.timeout,
        stop_on_success: config.stop_on_success
      };

      const response = await api.post('/api/bruteforce/start', attackData);
      
      if (response.data.status === 'started') {
        alert(`Attaque démarrée avec succès!\nID: ${response.data.attack_id}`);
        refreshAttacks();
      }
    } catch (error) {
      console.error('Failed to start network attack:', error);
      alert(`Erreur: ${error.response?.data?.detail || error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const startHashCracking = async () => {
    try {
      setIsLoading(true);

      const attackData = {
        hash_value: hashConfig.hash_value,
        hash_type: hashConfig.hash_type,
        wordlist_name: hashConfig.wordlist_name || null,
        custom_wordlist: hashConfig.custom_wordlist ? 
          hashConfig.custom_wordlist.split('\n').map(p => p.trim()).filter(p => p) : null,
        stealth_level: hashConfig.stealth_level,
        max_attempts: hashConfig.max_attempts
      };

      const response = await api.post('/api/bruteforce/hash/crack', attackData);
      
      if (response.data.status === 'started') {
        alert(`Hash cracking démarré!\nID: ${response.data.attack_id}`);
        refreshAttacks();
      }
    } catch (error) {
      console.error('Failed to start hash cracking:', error);
      alert(`Erreur: ${error.response?.data?.detail || error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const generateWordlist = async () => {
    try {
      setIsLoading(true);

      const requestData = {
        generation_type: wordlistGen.generation_type,
        target_info: wordlistGen.generation_type === 'targeted' ? {
          company: wordlistGen.target_info.company,
          domain: wordlistGen.target_info.domain,
          keywords: wordlistGen.target_info.keywords ? 
            wordlistGen.target_info.keywords.split(',').map(k => k.trim()) : []
        } : null,
        custom_words: wordlistGen.custom_words ? 
          wordlistGen.custom_words.split('\n').map(w => w.trim()).filter(w => w) : null,
        config: wordlistGen.config,
        limit: wordlistGen.limit
      };

      const response = await api.post('/api/bruteforce/wordlists/generate', requestData);
      setGeneratedWordlist(response.data.wordlist);
      alert(`Wordlist générée avec ${response.data.count} mots de passe!`);
    } catch (error) {
      console.error('Failed to generate wordlist:', error);
      alert(`Erreur: ${error.response?.data?.detail || error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const stopAttack = async (attackId) => {
    try {
      await api.post(`/api/bruteforce/attacks/${attackId}/stop`);
      alert('Attaque arrêtée');
      refreshAttacks();
    } catch (error) {
      console.error('Failed to stop attack:', error);
      alert(`Erreur: ${error.response?.data?.detail || error.message}`);
    }
  };

  const viewAttackDetails = async (attackId) => {
    try {
      const response = await api.get(`/api/bruteforce/attacks/${attackId}`);
      setSelectedAttack(response.data);
    } catch (error) {
      console.error('Failed to get attack details:', error);
    }
  };

  const updateNetworkPort = (targetType) => {
    const defaultPort = supportedProtocols?.network?.[targetType]?.default_port;
    if (defaultPort) {
      setNetworkConfig(prev => ({ 
        ...prev, 
        target_type: targetType, 
        port: defaultPort 
      }));
    }
  };

  if (isLoading && !supportedProtocols) {
    return (
      <div className="bruteforce-loading">
        <div className="loading-spinner"></div>
        <p>Chargement du module Brute Force...</p>
      </div>
    );
  }

  return (
    <div className="bruteforce-container">
      {/* Header with Statistics */}
      <div className="bruteforce-header">
        <div className="bruteforce-stats">
          <div className="stat-card">
            <div className="stat-icon">🎯</div>
            <div className="stat-content">
              <div className="stat-value">{Object.keys(activeAttacks).length}</div>
              <div className="stat-label">Attaques Actives</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon">✅</div>
            <div className="stat-content">
              <div className="stat-value">{statistics?.successful_attempts || 0}</div>
              <div className="stat-label">Succès</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon">❌</div>
            <div className="stat-content">
              <div className="stat-value">{statistics?.failed_attempts || 0}</div>
              <div className="stat-label">Échecs</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon">📊</div>
            <div className="stat-content">
              <div className="stat-value">{statistics?.attacks_completed || 0}</div>
              <div className="stat-label">Terminées</div>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="bruteforce-tabs">
        <button 
          className={`tab-button ${activeTab === 'network' ? 'active' : ''}`}
          onClick={() => setActiveTab('network')}
        >
          <span className="tab-icon">🌐</span>
          Attaques Réseau
        </button>
        <button 
          className={`tab-button ${activeTab === 'hash' ? 'active' : ''}`}
          onClick={() => setActiveTab('hash')}
        >
          <span className="tab-icon">🔐</span>
          Hash Cracking
        </button>
        <button 
          className={`tab-button ${activeTab === 'wordlist' ? 'active' : ''}`}
          onClick={() => setActiveTab('wordlist')}
        >
          <span className="tab-icon">📝</span>
          Wordlists
        </button>
        <button 
          className={`tab-button ${activeTab === 'attacks' ? 'active' : ''}`}
          onClick={() => setActiveTab('attacks')}
        >
          <span className="tab-icon">⚡</span>
          Attaques Actives
        </button>
      </div>

      {/* Tab Content */}
      <div className="bruteforce-content">
        {activeTab === 'network' && (
          <div className="network-attack-panel">
            <h3>🌐 Attaques de Services Réseau</h3>
            
            <div className="attack-config">
              <div className="config-section">
                <h4>Configuration de la Cible</h4>
                <div className="config-grid">
                  <div className="config-item">
                    <label>Protocol / Service:</label>
                    <select 
                      value={networkConfig.target_type}
                      onChange={(e) => updateNetworkPort(e.target.value)}
                    >
                      {supportedProtocols?.network && Object.entries(supportedProtocols.network).map(([key, proto]) => (
                        <option key={key} value={key}>{proto.name}</option>
                      ))}
                    </select>
                  </div>
                  
                  <div className="config-item">
                    <label>Adresse IP / Hostname *:</label>
                    <input
                      type="text"
                      value={networkConfig.host}
                      onChange={(e) => setNetworkConfig({...networkConfig, host: e.target.value})}
                      placeholder="192.168.1.100 ou example.com"
                    />
                  </div>
                  
                  <div className="config-item">
                    <label>Port:</label>
                    <input
                      type="number"
                      value={networkConfig.port}
                      onChange={(e) => setNetworkConfig({...networkConfig, port: parseInt(e.target.value)})}
                    />
                  </div>
                  
                  {(networkConfig.target_type === 'http_basic' || networkConfig.target_type === 'http_form') && (
                    <div className="config-item">
                      <label>Service Path:</label>
                      <input
                        type="text"
                        value={networkConfig.service}
                        onChange={(e) => setNetworkConfig({...networkConfig, service: e.target.value})}
                        placeholder="/admin, /login, /api/auth"
                      />
                    </div>
                  )}
                </div>
              </div>

              <div className="config-section">
                <h4>Profil d'Attaque</h4>
                <select 
                  value={networkConfig.selected_profile}
                  onChange={(e) => setNetworkConfig({...networkConfig, selected_profile: e.target.value})}
                >
                  {Object.entries(profiles).map(([key, profile]) => (
                    <option key={key} value={key}>{profile.name}</option>
                  ))}
                </select>
                <p className="profile-description">
                  {profiles[networkConfig.selected_profile]?.description}
                </p>
              </div>

              <div className="config-section">
                <h4>Dictionnaires</h4>
                <div className="wordlist-config">
                  <div className="wordlist-option">
                    <label>
                      <input
                        type="checkbox"
                        checked={networkConfig.use_common_usernames}
                        onChange={(e) => setNetworkConfig({...networkConfig, use_common_usernames: e.target.checked})}
                      />
                      Utiliser les noms d'utilisateur communs
                    </label>
                  </div>
                  
                  <div className="wordlist-option">
                    <label>
                      <input
                        type="checkbox"
                        checked={networkConfig.use_common_passwords}
                        onChange={(e) => setNetworkConfig({...networkConfig, use_common_passwords: e.target.checked})}
                      />
                      Utiliser les mots de passe communs
                    </label>
                  </div>

                  {!networkConfig.use_common_usernames && (
                    <div className="custom-wordlist">
                      <label>Noms d'utilisateur personnalisés (un par ligne):</label>
                      <textarea
                        value={networkConfig.custom_usernames}
                        onChange={(e) => setNetworkConfig({...networkConfig, custom_usernames: e.target.value})}
                        placeholder="admin&#10;root&#10;user&#10;guest"
                        rows="5"
                      />
                    </div>
                  )}

                  {!networkConfig.use_common_passwords && (
                    <div className="custom-wordlist">
                      <label>Mots de passe personnalisés (un par ligne):</label>
                      <textarea
                        value={networkConfig.custom_passwords}
                        onChange={(e) => setNetworkConfig({...networkConfig, custom_passwords: e.target.value})}
                        placeholder="password&#10;123456&#10;admin&#10;root"
                        rows="5"
                      />
                    </div>
                  )}
                </div>
              </div>

              <div className="config-section">
                <h4>Paramètres Avancés</h4>
                <div className="config-grid">
                  <div className="config-item">
                    <label>Niveau de Furtivité (1-10):</label>
                    <input
                      type="range"
                      min="1"
                      max="10"
                      value={networkConfig.stealth_level}
                      onChange={(e) => setNetworkConfig({...networkConfig, stealth_level: parseInt(e.target.value)})}
                    />
                    <span>{networkConfig.stealth_level}</span>
                  </div>
                  
                  <div className="config-item">
                    <label>Threads Simultanés:</label>
                    <input
                      type="number"
                      min="1"
                      max="50"
                      value={networkConfig.max_threads}
                      onChange={(e) => setNetworkConfig({...networkConfig, max_threads: parseInt(e.target.value)})}
                    />
                  </div>
                  
                  <div className="config-item">
                    <label>Délai Min (secondes):</label>
                    <input
                      type="number"
                      step="0.1"
                      min="0.1"
                      value={networkConfig.delay_min}
                      onChange={(e) => setNetworkConfig({...networkConfig, delay_min: parseFloat(e.target.value)})}
                    />
                  </div>
                  
                  <div className="config-item">
                    <label>Délai Max (secondes):</label>
                    <input
                      type="number"
                      step="0.1"
                      min="0.1"
                      value={networkConfig.delay_max}
                      onChange={(e) => setNetworkConfig({...networkConfig, delay_max: parseFloat(e.target.value)})}
                    />
                  </div>
                  
                  <div className="config-item">
                    <label>Timeout (secondes):</label>
                    <input
                      type="number"
                      min="1"
                      value={networkConfig.timeout}
                      onChange={(e) => setNetworkConfig({...networkConfig, timeout: parseInt(e.target.value)})}
                    />
                  </div>
                  
                  <div className="config-item">
                    <label>
                      <input
                        type="checkbox"
                        checked={networkConfig.stop_on_success}
                        onChange={(e) => setNetworkConfig({...networkConfig, stop_on_success: e.target.checked})}
                      />
                      Arrêter au premier succès
                    </label>
                  </div>
                </div>
              </div>

              <div className="attack-actions">
                <button 
                  className="start-attack-btn"
                  onClick={startNetworkAttack}
                  disabled={isLoading || !networkConfig.host}
                >
                  {isLoading ? '⏳ Démarrage...' : '🚀 Démarrer l\'Attaque'}
                </button>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'hash' && (
          <div className="hash-cracking-panel">
            <h3>🔐 Hash Cracking</h3>
            
            <div className="hash-config">
              <div className="config-section">
                <h4>Configuration du Hash</h4>
                <div className="config-grid">
                  <div className="config-item">
                    <label>Type de Hash:</label>
                    <select 
                      value={hashConfig.hash_type}
                      onChange={(e) => setHashConfig({...hashConfig, hash_type: e.target.value})}
                    >
                      {supportedProtocols?.hashing && Object.entries(supportedProtocols.hashing).map(([key, hash]) => (
                        <option key={key} value={key.replace('hash_', '')}>{hash.name}</option>
                      ))}
                    </select>
                  </div>
                </div>
                
                <div className="config-item">
                  <label>Valeur du Hash *:</label>
                  <textarea
                    value={hashConfig.hash_value}
                    onChange={(e) => setHashConfig({...hashConfig, hash_value: e.target.value})}
                    placeholder="5d41402abc4b2a76b9719d911017c592"
                    className="hash-input"
                  />
                </div>
              </div>

              <div className="config-section">
                <h4>Wordlist</h4>
                <div className="wordlist-selection">
                  <div className="wordlist-option">
                    <label>
                      <input
                        type="radio"
                        name="hash_wordlist"
                        checked={hashConfig.use_common_passwords}
                        onChange={() => setHashConfig({...hashConfig, use_common_passwords: true, wordlist_name: '', custom_wordlist: ''})}
                      />
                      Utiliser les mots de passe communs
                    </label>
                  </div>
                  
                  <div className="wordlist-option">
                    <label>
                      <input
                        type="radio"
                        name="hash_wordlist"
                        checked={!!hashConfig.wordlist_name}
                        onChange={() => setHashConfig({...hashConfig, use_common_passwords: false, custom_wordlist: ''})}
                      />
                      Utiliser une wordlist existante
                    </label>
                    {!!hashConfig.wordlist_name && (
                      <select 
                        value={hashConfig.wordlist_name}
                        onChange={(e) => setHashConfig({...hashConfig, wordlist_name: e.target.value})}
                      >
                        <option value="">Sélectionner une wordlist</option>
                        {wordlists.map(wl => (
                          <option key={wl.filename} value={wl.filename}>
                            {wl.filename} ({wl.line_count} mots)
                          </option>
                        ))}
                      </select>
                    )}
                  </div>
                  
                  <div className="wordlist-option">
                    <label>
                      <input
                        type="radio"
                        name="hash_wordlist"
                        checked={!!hashConfig.custom_wordlist}
                        onChange={() => setHashConfig({...hashConfig, use_common_passwords: false, wordlist_name: ''})}
                      />
                      Wordlist personnalisée
                    </label>
                    {!!hashConfig.custom_wordlist && (
                      <textarea
                        value={hashConfig.custom_wordlist}
                        onChange={(e) => setHashConfig({...hashConfig, custom_wordlist: e.target.value})}
                        placeholder="password&#10;123456&#10;admin"
                        rows="8"
                      />
                    )}
                  </div>
                </div>
              </div>

              <div className="config-section">
                <h4>Paramètres</h4>
                <div className="config-grid">
                  <div className="config-item">
                    <label>Max Tentatives:</label>
                    <input
                      type="number"
                      min="1000"
                      max="1000000"
                      step="1000"
                      value={hashConfig.max_attempts}
                      onChange={(e) => setHashConfig({...hashConfig, max_attempts: parseInt(e.target.value)})}
                    />
                  </div>
                  
                  <div className="config-item">
                    <label>Niveau de Furtivité:</label>
                    <input
                      type="range"
                      min="1"
                      max="10"
                      value={hashConfig.stealth_level}
                      onChange={(e) => setHashConfig({...hashConfig, stealth_level: parseInt(e.target.value)})}
                    />
                    <span>{hashConfig.stealth_level}</span>
                  </div>
                </div>
              </div>

              <div className="attack-actions">
                <button 
                  className="start-attack-btn"
                  onClick={startHashCracking}
                  disabled={isLoading || !hashConfig.hash_value}
                >
                  {isLoading ? '⏳ Démarrage...' : '🔓 Démarrer le Cracking'}
                </button>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'wordlist' && (
          <div className="wordlist-panel">
            <h3>📝 Générateur de Wordlists</h3>
            
            <div className="wordlist-generator">
              <div className="config-section">
                <h4>Type de Génération</h4>
                <select 
                  value={wordlistGen.generation_type}
                  onChange={(e) => setWordlistGen({...wordlistGen, generation_type: e.target.value})}
                >
                  <option value="common">Mots de passe communs</option>
                  <option value="targeted">Ciblé (basé sur des informations)</option>
                  <option value="smart">Intelligent (combiné)</option>
                  <option value="rule_based">Basé sur des règles</option>
                </select>
              </div>

              {wordlistGen.generation_type === 'targeted' && (
                <div className="config-section">
                  <h4>Informations de la Cible</h4>
                  <div className="config-grid">
                    <div className="config-item">
                      <label>Nom de l'entreprise:</label>
                      <input
                        type="text"
                        value={wordlistGen.target_info.company}
                        onChange={(e) => setWordlistGen({
                          ...wordlistGen, 
                          target_info: {...wordlistGen.target_info, company: e.target.value}
                        })}
                        placeholder="ACME Corp"
                      />
                    </div>
                    
                    <div className="config-item">
                      <label>Domaine:</label>
                      <input
                        type="text"
                        value={wordlistGen.target_info.domain}
                        onChange={(e) => setWordlistGen({
                          ...wordlistGen, 
                          target_info: {...wordlistGen.target_info, domain: e.target.value}
                        })}
                        placeholder="example.com"
                      />
                    </div>
                    
                    <div className="config-item full-width">
                      <label>Mots-clés (séparés par des virgules):</label>
                      <input
                        type="text"
                        value={wordlistGen.target_info.keywords}
                        onChange={(e) => setWordlistGen({
                          ...wordlistGen, 
                          target_info: {...wordlistGen.target_info, keywords: e.target.value}
                        })}
                        placeholder="tech, innovation, secure, 2025"
                      />
                    </div>
                  </div>
                </div>
              )}

              {(wordlistGen.generation_type === 'rule_based' || wordlistGen.generation_type === 'smart') && (
                <div className="config-section">
                  <h4>Mots de Base</h4>
                  <textarea
                    value={wordlistGen.custom_words}
                    onChange={(e) => setWordlistGen({...wordlistGen, custom_words: e.target.value})}
                    placeholder="password&#10;admin&#10;company&#10;service"
                    rows="6"
                  />
                </div>
              )}

              <div className="config-section">
                <h4>Configuration</h4>
                <div className="config-grid">
                  <div className="config-item">
                    <label>Limite de génération:</label>
                    <input
                      type="number"
                      min="100"
                      max="100000"
                      step="100"
                      value={wordlistGen.limit}
                      onChange={(e) => setWordlistGen({...wordlistGen, limit: parseInt(e.target.value)})}
                    />
                  </div>
                  
                  <div className="config-item">
                    <label>Longueur Min:</label>
                    <input
                      type="number"
                      min="1"
                      max="20"
                      value={wordlistGen.config.min_length}
                      onChange={(e) => setWordlistGen({
                        ...wordlistGen, 
                        config: {...wordlistGen.config, min_length: parseInt(e.target.value)}
                      })}
                    />
                  </div>
                  
                  <div className="config-item">
                    <label>Longueur Max:</label>
                    <input
                      type="number"
                      min="1"
                      max="50"
                      value={wordlistGen.config.max_length}
                      onChange={(e) => setWordlistGen({
                        ...wordlistGen, 
                        config: {...wordlistGen.config, max_length: parseInt(e.target.value)}
                      })}
                    />
                  </div>
                </div>
                
                <div className="config-options">
                  <label>
                    <input
                      type="checkbox"
                      checked={wordlistGen.config.include_numbers}
                      onChange={(e) => setWordlistGen({
                        ...wordlistGen, 
                        config: {...wordlistGen.config, include_numbers: e.target.checked}
                      })}
                    />
                    Inclure des chiffres
                  </label>
                  
                  <label>
                    <input
                      type="checkbox"
                      checked={wordlistGen.config.include_symbols}
                      onChange={(e) => setWordlistGen({
                        ...wordlistGen, 
                        config: {...wordlistGen.config, include_symbols: e.target.checked}
                      })}
                    />
                    Inclure des symboles
                  </label>
                  
                  <label>
                    <input
                      type="checkbox"
                      checked={wordlistGen.config.leet_speak}
                      onChange={(e) => setWordlistGen({
                        ...wordlistGen, 
                        config: {...wordlistGen.config, leet_speak: e.target.checked}
                      })}
                    />
                    Leet Speak (4dm1n)
                  </label>
                  
                  <label>
                    <input
                      type="checkbox"
                      checked={wordlistGen.config.year_variations}
                      onChange={(e) => setWordlistGen({
                        ...wordlistGen, 
                        config: {...wordlistGen.config, year_variations: e.target.checked}
                      })}
                    />
                    Variations d'années
                  </label>
                </div>
              </div>

              <div className="wordlist-actions">
                <button 
                  className="generate-btn"
                  onClick={generateWordlist}
                  disabled={isLoading}
                >
                  {isLoading ? '⏳ Génération...' : '🎯 Générer la Wordlist'}
                </button>
              </div>

              {generatedWordlist.length > 0 && (
                <div className="config-section">
                  <h4>Wordlist Générée ({generatedWordlist.length} mots)</h4>
                  <div className="wordlist-preview">
                    <textarea
                      value={generatedWordlist.slice(0, 100).join('\n')}
                      readOnly
                      rows="10"
                    />
                    {generatedWordlist.length > 100 && (
                      <p>... et {generatedWordlist.length - 100} autres mots</p>
                    )}
                  </div>
                  
                  <div className="wordlist-actions">
                    <button 
                      onClick={() => {
                        const blob = new Blob([generatedWordlist.join('\n')], { type: 'text/plain' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = `wordlist_${Date.now()}.txt`;
                        a.click();
                        URL.revokeObjectURL(url);
                      }}
                    >
                      💾 Télécharger
                    </button>
                    
                    <button
                      onClick={() => setNetworkConfig({
                        ...networkConfig, 
                        custom_passwords: generatedWordlist.join('\n'),
                        use_common_passwords: false
                      })}
                    >
                      🔄 Utiliser pour Attaque Réseau
                    </button>
                    
                    <button
                      onClick={() => setHashConfig({
                        ...hashConfig, 
                        custom_wordlist: generatedWordlist.join('\n'),
                        use_common_passwords: false,
                        wordlist_name: ''
                      })}
                    >
                      🔐 Utiliser pour Hash Cracking
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'attacks' && (
          <div className="attacks-panel">
            <h3>⚡ Attaques Actives et Historique</h3>
            
            {Object.keys(activeAttacks).length === 0 ? (
              <div className="no-attacks">
                <p>Aucune attaque active pour le moment.</p>
                <p>Démarrez une attaque depuis les onglets "Attaques Réseau" ou "Hash Cracking".</p>
              </div>
            ) : (
              <div className="attacks-list">
                {Object.entries(activeAttacks).map(([attackId, attack]) => (
                  <div key={attackId} className={`attack-card ${attack.status}`}>
                    <div className="attack-header">
                      <div className="attack-info">
                        <h4>{attack.target_type.toUpperCase()} - {attack.target_host}</h4>
                        <div className="attack-meta">
                          <span className="attack-id">ID: {attackId.slice(0, 8)}...</span>
                          <span className={`attack-status status-${attack.status}`}>
                            {attack.status === 'running' ? '🔄 En cours' : 
                             attack.status === 'completed' ? '✅ Terminé' : 
                             attack.status === 'stopped' ? '⏹️ Arrêté' : '❌ Erreur'}
                          </span>
                        </div>
                      </div>
                      
                      <div className="attack-actions">
                        <button onClick={() => viewAttackDetails(attackId)}>
                          👁️ Détails
                        </button>
                        {attack.status === 'running' && (
                          <button 
                            onClick={() => stopAttack(attackId)}
                            className="stop-btn"
                          >
                            ⏹️ Arrêter
                          </button>
                        )}
                      </div>
                    </div>
                    
                    <div className="attack-progress">
                      <div className="progress-bar">
                        <div 
                          className="progress-fill" 
                          style={{ width: `${attack.progress}%` }}
                        ></div>
                      </div>
                      <span className="progress-text">{attack.progress.toFixed(1)}%</span>
                    </div>
                    
                    <div className="attack-stats">
                      <span>Résultats: {attack.results_count}</span>
                      <span>
                        Démarré: {new Date(attack.start_time * 1000).toLocaleString()}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Attack Details Modal */}
            {selectedAttack && (
              <div className="attack-modal-overlay" onClick={() => setSelectedAttack(null)}>
                <div className="attack-modal" onClick={(e) => e.stopPropagation()}>
                  <div className="modal-header">
                    <h3>Détails de l'Attaque</h3>
                    <button onClick={() => setSelectedAttack(null)}>✕</button>
                  </div>
                  
                  <div className="modal-content">
                    <div className="attack-details">
                      <div className="detail-section">
                        <h4>Informations Générales</h4>
                        <div className="detail-grid">
                          <div><strong>ID:</strong> {selectedAttack.attack_id}</div>
                          <div><strong>Statut:</strong> {selectedAttack.status}</div>
                          <div><strong>Cible:</strong> {selectedAttack.target.host}:{selectedAttack.target.port}</div>
                          <div><strong>Type:</strong> {selectedAttack.target.type}</div>
                          <div><strong>Progrès:</strong> {selectedAttack.progress.toFixed(1)}%</div>
                          <div><strong>Temps écoulé:</strong> {Math.round(selectedAttack.elapsed_time)}s</div>
                        </div>
                      </div>
                      
                      <div className="detail-section">
                        <h4>Statistiques</h4>
                        <div className="detail-grid">
                          <div><strong>Total tentatives:</strong> {selectedAttack.statistics.total_results}</div>
                          <div><strong>Succès:</strong> {selectedAttack.statistics.successful_attempts}</div>
                          <div><strong>Échecs:</strong> {selectedAttack.statistics.failed_attempts}</div>
                          <div><strong>Taux de succès:</strong> {
                            selectedAttack.statistics.total_results > 0 ? 
                            ((selectedAttack.statistics.successful_attempts / selectedAttack.statistics.total_results) * 100).toFixed(2) + '%' :
                            '0%'
                          }</div>
                        </div>
                      </div>
                      
                      {selectedAttack.successful_credentials.length > 0 && (
                        <div className="detail-section">
                          <h4>🎯 Identifiants Trouvés</h4>
                          <div className="credentials-list">
                            {selectedAttack.successful_credentials.map((cred, index) => (
                              <div key={index} className="credential-item">
                                <div className="credential-info">
                                  <strong>👤 {cred.username}</strong> : 🔑 {cred.password}
                                </div>
                                <div className="credential-meta">
                                  Temps de réponse: {cred.response_time.toFixed(3)}s - 
                                  {new Date(cred.timestamp * 1000).toLocaleString()}
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default BruteForceModule;