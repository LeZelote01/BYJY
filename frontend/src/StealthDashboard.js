import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './StealthDashboard.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

const api = axios.create({
  baseURL: BACKEND_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  }
});

const StealthDashboard = () => {
  const [stealthStatus, setStealthStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    fetchStealthStatus();
    const interval = setInterval(fetchStealthStatus, 5000); // Refresh every 5 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchStealthStatus = async () => {
    try {
      const response = await api.get('/api/stealth/status');
      setStealthStatus(response.data);
      setError(null);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
      console.error('Failed to fetch stealth status:', err);
    } finally {
      setLoading(false);
    }
  };

  const activateProfile = async (profileName) => {
    try {
      await api.post(`/api/stealth/profiles/${profileName}/activate`);
      fetchStealthStatus(); // Refresh status
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  };

  const rotateProxy = async () => {
    try {
      await api.post('/api/stealth/proxies/rotate');
      fetchStealthStatus(); // Refresh status
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  };

  const testAllProxies = async () => {
    try {
      await api.post('/api/stealth/proxies/test');
      setTimeout(fetchStealthStatus, 2000); // Actualiser après 2 secondes
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  };

  const refreshProxySources = async () => {
    try {
      const response = await api.post('/api/stealth/proxies/refresh');
      console.log('Proxy refresh result:', response.data);
      setTimeout(fetchStealthStatus, 3000); // Actualiser après 3 secondes
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  };

  const runStealthTest = async () => {
    try {
      await api.post('/api/stealth/test', {
        target_url: 'https://httpbin.org/ip',
        test_type: 'basic',
        use_proxy: true
      });
      fetchStealthStatus(); // Refresh status
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  };

  const clearAlerts = async () => {
    try {
      await api.delete('/api/stealth/alerts');
      fetchStealthStatus(); // Refresh status
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  };

  const runCleanup = async () => {
    try {
      await api.post('/api/stealth/cleanup');
      // Show success message
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  };

  if (loading) {
    return (
      <div className="stealth-dashboard">
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>Loading stealth status...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="stealth-dashboard">
        <div className="error-container">
          <h3>❌ Error</h3>
          <p>{error}</p>
          <button onClick={fetchStealthStatus} className="retry-btn">
            🔄 Retry
          </button>
        </div>
      </div>
    );
  }

  const stealthData = stealthStatus?.stealth || {};
  const proxiesData = stealthStatus?.proxies || {};
  const anonymityData = stealthStatus?.anonymity || {};

  return (
    <div className="stealth-dashboard">
      <div className="stealth-header">
        <h2>🕵️ Stealth Dashboard</h2>
        <div className="stealth-score">
          <span className="score-label">Stealth Score</span>
          <span className={`score-value ${getScoreClass(stealthData.stealth_score)}`}>
            {Math.round(stealthData.stealth_score || 0)}%
          </span>
        </div>
      </div>

      <div className="stealth-tabs">
        <button 
          className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          📊 Overview
        </button>
        <button 
          className={`tab-btn ${activeTab === 'profiles' ? 'active' : ''}`}
          onClick={() => setActiveTab('profiles')}
        >
          🎭 Profiles
        </button>
        <button 
          className={`tab-btn ${activeTab === 'proxies' ? 'active' : ''}`}
          onClick={() => setActiveTab('proxies')}
        >
          🌐 Proxies
        </button>
        <button 
          className={`tab-btn ${activeTab === 'tools' ? 'active' : ''}`}
          onClick={() => setActiveTab('tools')}
        >
          🛠️ Tools
        </button>
      </div>

      <div className="stealth-content">
        {activeTab === 'overview' && (
          <StealthOverview 
            stealthData={stealthData}
            proxiesData={proxiesData}
            anonymityData={anonymityData}
          />
        )}
        
        {activeTab === 'profiles' && (
          <StealthProfiles 
            stealthData={stealthData}
            onActivateProfile={activateProfile}
          />
        )}
        
        {activeTab === 'proxies' && (
          <StealthProxies 
            proxiesData={proxiesData}
            anonymityData={anonymityData}
            onRotateProxy={rotateProxy}
            onTestProxies={testAllProxies}
            onRefreshProxies={refreshProxySources}
          />
        )}
        
        {activeTab === 'tools' && (
          <StealthTools 
            onRunTest={runStealthTest}
            onClearAlerts={clearAlerts}
            onRunCleanup={runCleanup}
          />
        )}
      </div>
    </div>
  );
};

const StealthOverview = ({ stealthData, proxiesData, anonymityData }) => (
  <div className="stealth-overview">
    <div className="overview-grid">
      <div className="overview-card">
        <div className="card-header">
          <h4>🛡️ Stealth Status</h4>
        </div>
        <div className="card-content">
          <div className="metric">
            <span className="metric-label">Current Level:</span>
            <span className="metric-value">{stealthData.stealth_level || 0}/10</span>
          </div>
          <div className="metric">
            <span className="metric-label">Obfuscation:</span>
            <span className={`metric-value ${stealthData.obfuscation_enabled ? 'enabled' : 'disabled'}`}>
              {stealthData.obfuscation_enabled ? 'Enabled' : 'Disabled'}
            </span>
          </div>
          <div className="metric">
            <span className="metric-label">Anti-Forensics:</span>
            <span className={`metric-value ${stealthData.anti_forensics_enabled ? 'enabled' : 'disabled'}`}>
              {stealthData.anti_forensics_enabled ? 'Enabled' : 'Disabled'}
            </span>
          </div>
        </div>
      </div>

      <div className="overview-card">
        <div className="card-header">
          <h4>🌐 Proxy Status</h4>
        </div>
        <div className="card-content">
          <div className="metric">
            <span className="metric-label">Active Proxies:</span>
            <span className="metric-value">
              {proxiesData.active_proxies || 0}/{proxiesData.total_proxies || 0}
            </span>
          </div>
          <div className="metric">
            <span className="metric-label">Success Rate:</span>
            <span className="metric-value">{Math.round(proxiesData.success_rate || 0)}%</span>
          </div>
          <div className="metric">
            <span className="metric-label">Tor Available:</span>
            <span className={`metric-value ${proxiesData.tor_available ? 'enabled' : 'disabled'}`}>
              {proxiesData.tor_available ? 'Yes' : 'No'}
            </span>
          </div>
        </div>
      </div>

      <div className="overview-card">
        <div className="card-header">
          <h4>🔐 Anonymity</h4>
        </div>
        <div className="card-content">
          <div className="metric">
            <span className="metric-label">Status:</span>
            <span className={`metric-value ${anonymityData.anonymous ? 'enabled' : 'disabled'}`}>
              {anonymityData.anonymous ? 'Anonymous' : 'Direct'}
            </span>
          </div>
          <div className="metric">
            <span className="metric-label">Current IP:</span>
            <span className="metric-value ip-address">{anonymityData.current_ip || 'Unknown'}</span>
          </div>
          <div className="metric">
            <span className="metric-label">Tor Active:</span>
            <span className={`metric-value ${anonymityData.tor_active ? 'enabled' : 'disabled'}`}>
              {anonymityData.tor_active ? 'Yes' : 'No'}
            </span>
          </div>
        </div>
      </div>

      <div className="overview-card">
        <div className="card-header">
          <h4>⚠️ Alerts</h4>
        </div>
        <div className="card-content">
          <div className="metric">
            <span className="metric-label">Detection Score:</span>
            <span className={`metric-value ${getScoreClass(100 - (stealthData.stealth_score || 0))}`}>
              {Math.round(100 - (stealthData.stealth_score || 0))}%
            </span>
          </div>
          <div className="metric">
            <span className="metric-label">Recent Alerts:</span>
            <span className="metric-value">{stealthData.recent_alerts || 0}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
);

const StealthProfiles = ({ stealthData, onActivateProfile }) => {
  const profiles = [
    {
      name: 'normal',
      display: 'Normal',
      level: 3,
      description: 'Standard operations without stealth',
      icon: '🔵'
    },
    {
      name: 'stealth',
      display: 'Stealth',
      level: 7,
      description: 'Balanced stealth and performance',
      icon: '🟡'
    },
    {
      name: 'maximum',
      display: 'Maximum Stealth',
      level: 10,
      description: 'Maximum stealth with slow operations',
      icon: '🔴'
    },
    {
      name: 'fast',
      display: 'Fast Recon',
      level: 5,
      description: 'Quick reconnaissance with basic stealth',
      icon: '🟢'
    }
  ];

  return (
    <div className="stealth-profiles">
      <div className="profiles-header">
        <h4>Available Stealth Profiles</h4>
        <p>Current Profile: <strong>{stealthData.current_profile || 'Unknown'}</strong></p>
      </div>
      
      <div className="profiles-grid">
        {profiles.map(profile => (
          <div 
            key={profile.name}
            className={`profile-card ${stealthData.current_profile === profile.name ? 'active' : ''}`}
          >
            <div className="profile-header">
              <span className="profile-icon">{profile.icon}</span>
              <h5>{profile.display}</h5>
              <span className="profile-level">Level {profile.level}</span>
            </div>
            <p className="profile-description">{profile.description}</p>
            <button 
              onClick={() => onActivateProfile(profile.name)}
              className={`profile-btn ${stealthData.current_profile === profile.name ? 'active' : ''}`}
              disabled={stealthData.current_profile === profile.name}
            >
              {stealthData.current_profile === profile.name ? 'Active' : 'Activate'}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
};

const StealthProxies = ({ proxiesData, anonymityData, onRotateProxy, onTestProxies, onRefreshProxies }) => (
  <div className="stealth-proxies">
    <div className="proxies-header">
      <h4>Proxy Management</h4>
      <div className="proxy-actions">
        <button onClick={onRotateProxy} className="action-btn">
          🔄 Rotate Proxy
        </button>
        <button onClick={onTestProxies} className="action-btn">
          🧪 Test All Proxies
        </button>
        <button onClick={onRefreshProxies} className="action-btn refresh-btn">
          🔄 Refresh Sources
        </button>
      </div>
    </div>

    <div className="proxy-stats">
      <div className="stat-card">
        <h5>📊 Statistics</h5>
        <div className="stat-grid">
          <div className="stat-item">
            <span className="stat-label">Total Proxies:</span>
            <span className="stat-value">{proxiesData.total_proxies || 0}</span>
          </div>
          <div className="stat-item">
            <span className="stat-label">Active Proxies:</span>
            <span className="stat-value">{proxiesData.active_proxies || 0}</span>
          </div>
          <div className="stat-item">
            <span className="stat-label">Success Rate:</span>
            <span className="stat-value">{Math.round(proxiesData.success_rate || 0)}%</span>
          </div>
          <div className="stat-item">
            <span className="stat-label">Avg Response Time:</span>
            <span className="stat-value">{(proxiesData.average_response_time || 0).toFixed(2)}s</span>
          </div>
        </div>
      </div>

      <div className="stat-card">
        <h5>🔐 Current Anonymity</h5>
        <div className="anonymity-info">
          <div className="anonymity-status">
            <span className="status-indicator">
              {anonymityData.anonymous ? '🟢' : '🔴'}
            </span>
            <span className="status-text">
              {anonymityData.anonymous ? 'Anonymous' : 'Direct Connection'}
            </span>
          </div>
          <div className="ip-info">
            <span className="ip-label">Current IP:</span>
            <span className="ip-value">{anonymityData.current_ip || 'Unknown'}</span>
          </div>
          {anonymityData.proxy_used && (
            <div className="proxy-info">
              <span className="proxy-label">Via Proxy:</span>
              <span className="proxy-value">{anonymityData.proxy_used}</span>
            </div>
          )}
        </div>
      </div>
    </div>

    <div className="proxy-countries">
      <h5>🌍 Proxy Distribution</h5>
      <div className="countries-grid">
        {Object.entries(proxiesData.countries || {}).map(([country, count]) => (
          <div key={country} className="country-item">
            <span className="country-name">{country}</span>
            <span className="country-count">{count}</span>
          </div>
        ))}
      </div>
    </div>
  </div>
);

const StealthTools = ({ onRunTest, onClearAlerts, onRunCleanup }) => (
  <div className="stealth-tools">
    <div className="tools-header">
      <h4>Stealth Tools & Utilities</h4>
    </div>

    <div className="tools-grid">
      <div className="tool-card">
        <div className="tool-header">
          <h5>🧪 Stealth Test</h5>
        </div>
        <p>Test current stealth configuration against external services</p>
        <button onClick={onRunTest} className="tool-btn">
          Run Test
        </button>
      </div>

      <div className="tool-card">
        <div className="tool-header">
          <h5>🗑️ Clear Alerts</h5>
        </div>
        <p>Clear all detection alerts and reset stealth score</p>
        <button onClick={onClearAlerts} className="tool-btn">
          Clear Alerts
        </button>
      </div>

      <div className="tool-card">
        <div className="tool-header">
          <h5>🧹 Anti-Forensics</h5>
        </div>
        <p>Run comprehensive cleanup of forensic traces</p>
        <button onClick={onRunCleanup} className="tool-btn">
          Run Cleanup
        </button>
      </div>
    </div>
  </div>
);

const getScoreClass = (score) => {
  if (score >= 80) return 'excellent';
  if (score >= 60) return 'good';
  if (score >= 40) return 'fair';
  return 'poor';
};

export default StealthDashboard;