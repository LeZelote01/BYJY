import React, { useState, useEffect } from 'react';
import './StealthControl.css';

const StealthControl = () => {
  const [stealthStatus, setStealthStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [profiles, setProfiles] = useState([]);
  const [anonymityStatus, setAnonymityStatus] = useState(null);
  const [testingTor, setTestingTor] = useState(false);

  const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

  useEffect(() => {
    fetchStealthStatus();
    fetchProfiles();
    fetchAnonymityStatus();
  }, []);

  const fetchStealthStatus = async () => {
    try {
      const response = await fetch(`${backendUrl}/api/stealth-control/status`);
      const data = await response.json();
      setStealthStatus(data);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching stealth status:', error);
      setLoading(false);
    }
  };

  const fetchProfiles = async () => {
    try {
      const response = await fetch(`${backendUrl}/api/stealth-control/profiles`);
      const data = await response.json();
      setProfiles(data.profiles || {});
    } catch (error) {
      console.error('Error fetching profiles:', error);
    }
  };

  const fetchAnonymityStatus = async () => {
    try {
      const response = await fetch(`${backendUrl}/api/stealth-control/anonymity-status`);
      const data = await response.json();
      setAnonymityStatus(data.anonymity_status);
    } catch (error) {
      console.error('Error fetching anonymity status:', error);
    }
  };

  const enableTor = async () => {
    try {
      setTestingTor(true);
      const response = await fetch(`${backendUrl}/api/stealth-control/enable-tor`, {
        method: 'POST'
      });
      const data = await response.json();
      
      if (response.ok) {
        await fetchStealthStatus();
        await fetchAnonymityStatus();
        alert('Tor activé avec succès! ' + data.message);
      } else {
        throw new Error(data.detail || 'Failed to enable Tor');
      }
    } catch (error) {
      console.error('Error enabling Tor:', error);
      alert('Erreur lors de l\'activation de Tor: ' + error.message);
    } finally {
      setTestingTor(false);
    }
  };

  const disableTor = async () => {
    try {
      const response = await fetch(`${backendUrl}/api/stealth-control/disable-tor`, {
        method: 'POST'
      });
      const data = await response.json();
      
      if (response.ok) {
        await fetchStealthStatus();
        await fetchAnonymityStatus();
        alert('Tor désactivé avec succès!');
      } else {
        throw new Error(data.detail || 'Failed to disable Tor');
      }
    } catch (error) {
      console.error('Error disabling Tor:', error);
      alert('Erreur lors de la désactivation de Tor: ' + error.message);
    }
  };

  const testTorConnection = async () => {
    try {
      setTestingTor(true);
      const response = await fetch(`${backendUrl}/api/stealth-control/test-tor-connection`, {
        method: 'POST'
      });
      const data = await response.json();
      
      if (data.tor_available) {
        alert('✅ Tor fonctionne correctement!\n\nStatut: ' + 
              (data.anonymity_status?.anonymous ? 'Anonyme' : 'Non anonyme') +
              '\nIP actuelle: ' + (data.anonymity_status?.current_ip || 'Inconnue'));
      } else {
        const helpText = `❌ Tor n'est pas disponible.\n\n` +
          `Guide d'installation:\n` +
          `Ubuntu/Debian: sudo apt install tor && sudo systemctl start tor\n` +
          `CentOS/RHEL: sudo yum install tor && sudo systemctl start tor\n` +
          `Windows: Télécharger Tor Browser\n` +
          `macOS: brew install tor && brew services start tor`;
        alert(helpText);
      }
      
      await fetchStealthStatus();
    } catch (error) {
      console.error('Error testing Tor:', error);
      alert('Erreur lors du test de connexion Tor: ' + error.message);
    } finally {
      setTestingTor(false);
    }
  };

  const changeProfile = async (profileName) => {
    try {
      const response = await fetch(`${backendUrl}/api/stealth-control/update-stealth-config`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ profile: profileName })
      });
      
      const data = await response.json();
      if (response.ok) {
        await fetchStealthStatus();
        alert(`Profil changé vers: ${profileName}`);
      } else {
        throw new Error(data.detail || 'Failed to change profile');
      }
    } catch (error) {
      console.error('Error changing profile:', error);
      alert('Erreur lors du changement de profil: ' + error.message);
    }
  };

  const rotateProxy = async () => {
    try {
      const response = await fetch(`${backendUrl}/api/stealth-control/rotate-proxy`, {
        method: 'POST'
      });
      const data = await response.json();
      
      if (response.ok) {
        await fetchStealthStatus();
        await fetchAnonymityStatus();
        alert(`Rotation effectuée: ${data.old_proxy} → ${data.new_proxy}`);
      } else {
        throw new Error(data.detail || 'Failed to rotate proxy');
      }
    } catch (error) {
      console.error('Error rotating proxy:', error);
      alert('Erreur lors de la rotation: ' + error.message);
    }
  };

  if (loading) {
    return (
      <div className="stealth-control">
        <div className="loading">Chargement du contrôle de furtivité...</div>
      </div>
    );
  }

  return (
    <div className="stealth-control">
      <div className="stealth-header">
        <h2>🛡️ Contrôle de Furtivité</h2>
        <div className="status-indicator">
          <span className={`status-dot ${stealthStatus?.tor_available ? 'active' : 'inactive'}`}></span>
          Tor: {stealthStatus?.tor_available ? 'Disponible' : 'Indisponible'}
        </div>
      </div>

      {/* Statut général */}
      <div className="status-section">
        <h3>📊 Statut Général</h3>
        <div className="status-grid">
          <div className="status-item">
            <label>Score de Furtivité</label>
            <div className="progress-bar">
              <div 
                className="progress-fill" 
                style={{ width: `${stealthStatus?.stealth?.stealth_score || 0}%` }}
              ></div>
              <span>{Math.round(stealthStatus?.stealth?.stealth_score || 0)}%</span>
            </div>
          </div>
          <div className="status-item">
            <label>Niveau de Furtivité</label>
            <span>{stealthStatus?.stealth?.stealth_level || 0}/10</span>
          </div>
          <div className="status-item">
            <label>Proxies Actifs</label>
            <span>{stealthStatus?.proxy?.active_proxies || 0}/{stealthStatus?.proxy?.total_proxies || 0}</span>
          </div>
          <div className="status-item">
            <label>Alertes de Détection</label>
            <span className={stealthStatus?.stealth?.recent_alerts > 0 ? 'warning' : 'success'}>
              {stealthStatus?.stealth?.recent_alerts || 0}
            </span>
          </div>
        </div>
      </div>

      {/* Contrôles Tor */}
      <div className="tor-section">
        <h3>🧅 Contrôles Tor</h3>
        <div className="control-buttons">
          <button 
            className={`btn ${stealthStatus?.tor_enabled ? 'btn-danger' : 'btn-primary'}`}
            onClick={stealthStatus?.tor_enabled ? disableTor : enableTor}
            disabled={testingTor}
          >
            {testingTor ? '⏳ Test...' : 
             stealthStatus?.tor_enabled ? '🚫 Désactiver Tor' : '🧅 Activer Tor'}
          </button>
          
          <button 
            className="btn btn-info"
            onClick={testTorConnection}
            disabled={testingTor}
          >
            {testingTor ? '⏳ Test...' : '🔍 Tester Connexion'}
          </button>
          
          {stealthStatus?.tor_enabled && (
            <button 
              className="btn btn-secondary"
              onClick={rotateProxy}
            >
              🔄 Rotation Proxy
            </button>
          )}
        </div>

        {/* Statut d'anonymat */}
        {anonymityStatus && (
          <div className="anonymity-status">
            <h4>Statut d'Anonymat</h4>
            <div className="anonymity-info">
              <div className={`anonymity-indicator ${anonymityStatus.anonymous ? 'secure' : 'insecure'}`}>
                {anonymityStatus.anonymous ? '✅ Anonyme' : '⚠️ Non Anonyme'}
              </div>
              <div className="ip-info">
                <span>IP Actuelle: {anonymityStatus.current_ip || 'Inconnue'}</span>
                {anonymityStatus.proxy_country && (
                  <span>Pays: {anonymityStatus.proxy_country}</span>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Profils de Furtivité */}
      <div className="profiles-section">
        <h3>🎭 Profils de Furtivité</h3>
        <div className="profiles-grid">
          {Object.entries(profiles).map(([name, profile]) => (
            <div key={name} className="profile-card">
              <h4>{name.replace('_', ' ').toUpperCase()}</h4>
              <p>{profile.description}</p>
              <div className="profile-details">
                <span>Niveau: {profile.stealth_level}/10</span>
                <span>Tor: {profile.tor_enabled ? '✅' : '❌'}</span>
              </div>
              <button 
                className="btn btn-sm btn-outline"
                onClick={() => changeProfile(name)}
              >
                Activer
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Guide d'installation */}
      <div className="help-section">
        <h3>💡 Guide d'Installation Tor</h3>
        <div className="installation-guide">
          <div className="os-guide">
            <h4>Ubuntu/Debian</h4>
            <code>sudo apt install tor && sudo systemctl start tor</code>
          </div>
          <div className="os-guide">
            <h4>CentOS/RHEL</h4>
            <code>sudo yum install tor && sudo systemctl start tor</code>
          </div>
          <div className="os-guide">
            <h4>Windows</h4>
            <p>Télécharger Tor Browser depuis torproject.org</p>
          </div>
          <div className="os-guide">
            <h4>macOS</h4>
            <code>brew install tor && brew services start tor</code>
          </div>
        </div>
      </div>
    </div>
  );
};

export default StealthControl;