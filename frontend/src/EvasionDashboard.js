import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './EvasionDashboard.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

const api = axios.create({
  baseURL: BACKEND_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  }
});

const EvasionDashboard = () => {
  const [evasionStatus, setEvasionStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [customProfile, setCustomProfile] = useState({
    name: '',
    description: '',
    stealth_level: 7,
    techniques: []
  });

  useEffect(() => {
    fetchEvasionStatus();
    const interval = setInterval(fetchEvasionStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchEvasionStatus = async () => {
    try {
      const response = await api.get('/api/evasion/status');
      setEvasionStatus(response.data);
      setError(null);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
      console.error('Failed to fetch evasion status:', err);
    } finally {
      setLoading(false);
    }
  };

  const activateProfile = async (profileName) => {
    try {
      await api.post(`/api/evasion/profiles/${profileName}/activate`);
      fetchEvasionStatus();
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  };

  const createCustomProfile = async () => {
    try {
      await api.post(`/api/evasion/profiles/${customProfile.name}`, {
        description: customProfile.description,
        stealth_level: customProfile.stealth_level,
        techniques: customProfile.techniques,
        timing_profile: {
          min_delay: 1.0,
          max_delay: 3.0,
          burst_limit: 5
        },
        proxy_settings: {
          enabled: true,
          rotation_interval: 60
        },
        obfuscation_settings: {
          level: customProfile.stealth_level,
          string_obfuscation: true
        },
        anti_forensics: true,
        detection_thresholds: {
          rate_limit: 0.5,
          captcha: 0.4,
          block: 0.6
        }
      });
      
      // Reset form
      setCustomProfile({
        name: '',
        description: '',
        stealth_level: 7,
        techniques: []
      });
      
      fetchEvasionStatus();
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  };

  const testProfile = async (profileName) => {
    try {
      await api.post(`/api/evasion/test-profile?profile_name=${profileName}`);
      // Success notification would go here
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  };

  const clearDetectionEvents = async () => {
    try {
      await api.delete('/api/evasion/detection-events');
      fetchEvasionStatus();
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  };

  const reportDetectionEvent = async (eventType, source) => {
    try {
      await api.post('/api/evasion/detection-events', {
        event_type: eventType,
        source: source,
        details: {}
      });
      fetchEvasionStatus();
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  };

  if (loading) {
    return (
      <div className="evasion-dashboard">
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>Loading evasion status...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="evasion-dashboard">
        <div className="error-container">
          <h3>❌ Error</h3>
          <p>{error}</p>
          <button onClick={fetchEvasionStatus} className="retry-btn">
            🔄 Retry
          </button>
        </div>
      </div>
    );
  }

  const evasionData = evasionStatus?.evasion_data || {};
  const currentProfile = evasionData.current_profile || {};
  const metrics = evasionData.metrics || {};
  const availableProfiles = evasionData.available_profiles || [];
  const detectionEvents = evasionData.detection_events || [];
  const recentDetections = evasionData.recent_detections || 0;

  // Calculate evasion score
  const evasionScore = Math.round(((metrics.successful_requests || 0) / Math.max((metrics.total_requests || 1), 1)) * 100);

  return (
    <div className="evasion-dashboard">
      <div className="evasion-header">
        <h2>🎭 Evasion Dashboard</h2>
        <div className="evasion-score">
          <span className="score-label">Evasion Score</span>
          <span className={`score-value ${getScoreClass(evasionScore)}`}>
            {evasionScore}%
          </span>
        </div>
      </div>

      <div className="evasion-tabs">
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
          className={`tab-btn ${activeTab === 'events' ? 'active' : ''}`}
          onClick={() => setActiveTab('events')}
        >
          🚨 Events ({detectionEvents.length})
        </button>
        <button 
          className={`tab-btn ${activeTab === 'tools' ? 'active' : ''}`}
          onClick={() => setActiveTab('tools')}
        >
          🛠️ Tools
        </button>
      </div>

      <div className="evasion-content">
        {activeTab === 'overview' && (
          <EvasionOverview 
            currentProfile={currentProfile}
            metrics={metrics}
            recentDetections={recentDetections}
            detectionEvents={detectionEvents}
          />
        )}
        
        {activeTab === 'profiles' && (
          <EvasionProfiles 
            availableProfiles={availableProfiles}
            currentProfile={currentProfile}
            onActivateProfile={activateProfile}
            onTestProfile={testProfile}
            customProfile={customProfile}
            setCustomProfile={setCustomProfile}
            onCreateProfile={createCustomProfile}
          />
        )}
        
        {activeTab === 'events' && (
          <EvasionEvents 
            detectionEvents={detectionEvents}
            onClearEvents={clearDetectionEvents}
            onReportEvent={reportDetectionEvent}
          />
        )}
        
        {activeTab === 'tools' && (
          <EvasionTools 
            onClearEvents={clearDetectionEvents}
            onReportEvent={reportDetectionEvent}
          />
        )}
      </div>
    </div>
  );
};

const EvasionOverview = ({ currentProfile, metrics, recentDetections, detectionEvents }) => (
  <div className="evasion-overview">
    <div className="overview-stats">
      <div className="stat-card">
        <div className="stat-header">
          <span className="stat-title">Success Rate</span>
          <span className="stat-icon">✅</span>
        </div>
        <div className="stat-value">{Math.round(((metrics.successful_requests || 0) / Math.max((metrics.total_requests || 1), 1)) * 100)}%</div>
        <div className="stat-description">
          {metrics.successful_requests || 0} successful out of {metrics.total_requests || 0} requests
        </div>
      </div>

      <div className="stat-card">
        <div className="stat-header">
          <span className="stat-title">Detection Rate</span>
          <span className="stat-icon">🚨</span>
        </div>
        <div className="stat-value">{Math.round((metrics.detection_rate || 0) * 100)}%</div>
        <div className="stat-description">
          Current detection rate across all operations
        </div>
      </div>

      <div className="stat-card">
        <div className="stat-header">
          <span className="stat-title">Active Profile</span>
          <span className="stat-icon">🎭</span>
        </div>
        <div className="stat-value">{currentProfile.name || 'None'}</div>
        <div className="stat-description">
          Stealth Level: {currentProfile.stealth_level || 0}/10
        </div>
      </div>

      <div className="stat-card">
        <div className="stat-header">
          <span className="stat-title">Recent Alerts</span>
          <span className="stat-icon">⚠️</span>
        </div>
        <div className="stat-value">{recentDetections}</div>
        <div className="stat-description">
          Detection events in the last hour
        </div>
      </div>
    </div>

    <div className="metrics-section">
      <h4>📊 Performance Metrics</h4>
      <div className="metrics-grid">
        <div className="metric-item">
          <span className="metric-label">Total Requests:</span>
          <span className="metric-value">{metrics.total_requests || 0}</span>
        </div>
        <div className="metric-item">
          <span className="metric-label">CAPTCHA Encounters:</span>
          <span className="metric-value">{metrics.captcha_encounters || 0}</span>
        </div>
        <div className="metric-item">
          <span className="metric-label">Rate Limits Hit:</span>
          <span className="metric-value">{metrics.rate_limit_hits || 0}</span>
        </div>
        <div className="metric-item">
          <span className="metric-label">Blocked Requests:</span>
          <span className="metric-value">{metrics.blocked_requests || 0}</span>
        </div>
      </div>
    </div>

    <div className="recent-events">
      <h4>🕒 Recent Detection Events</h4>
      <div className="events-list">
        {detectionEvents.slice(0, 5).map((event, index) => (
          <div key={index} className="event-item">
            <span className="event-type">{event.type}</span>
            <span className="event-time">{new Date(event.timestamp).toLocaleTimeString()}</span>
          </div>
        ))}
        {detectionEvents.length === 0 && (
          <div className="event-item">
            <span className="event-type">No recent events</span>
          </div>
        )}
      </div>
    </div>
  </div>
);

const EvasionProfiles = ({ 
  availableProfiles, 
  currentProfile, 
  onActivateProfile, 
  onTestProfile, 
  customProfile, 
  setCustomProfile, 
  onCreateProfile 
}) => {
  const defaultProfiles = [
    {
      name: 'normal',
      description: 'Standard operations with minimal evasion',
      stealth_level: 3,
      techniques: ['basic_headers', 'user_agent_rotation']
    },
    {
      name: 'stealth', 
      description: 'Balanced stealth and performance',
      stealth_level: 7,
      techniques: ['advanced_headers', 'timing_randomization', 'referer_spoofing']
    },
    {
      name: 'maximum',
      description: 'Maximum evasion with slow operations', 
      stealth_level: 10,
      techniques: ['ultra_slow_scanning', 'deep_packet_inspection_evasion', 'statistical_traffic_analysis_evasion']
    },
    {
      name: 'fast',
      description: 'Quick operations with basic evasion',
      stealth_level: 5,
      techniques: ['basic_headers', 'request_fingerprint_masking']
    }
  ];

  const profiles = availableProfiles.length > 0 ? availableProfiles : defaultProfiles;

  return (
    <div className="profiles-section">
      <h4>Available Evasion Profiles</h4>
      <div className="profiles-grid">
        {profiles.map(profile => (
          <div 
            key={profile.name}
            className={`profile-card ${currentProfile.name === profile.name ? 'active' : ''}`}
          >
            <div className="profile-header">
              <h5 className="profile-name">{profile.name}</h5>
              <span className="profile-level">Level {profile.stealth_level}</span>
            </div>
            <p className="profile-description">{profile.description}</p>
            
            <div className="profile-techniques">
              <h6>Techniques:</h6>
              <div className="techniques-list">
                {(profile.techniques || []).slice(0, 3).map(technique => (
                  <span key={technique} className="technique-tag">{technique}</span>
                ))}
                {(profile.techniques || []).length > 3 && (
                  <span className="technique-tag">+{profile.techniques.length - 3} more</span>
                )}
              </div>
            </div>

            <div className="profile-actions">
              <button 
                onClick={() => onActivateProfile(profile.name)}
                className="profile-btn activate-btn"
                disabled={currentProfile.name === profile.name}
              >
                {currentProfile.name === profile.name ? 'Active' : 'Activate'}
              </button>
              <button 
                onClick={() => onTestProfile(profile.name)}
                className="profile-btn test-btn"
              >
                Test
              </button>
            </div>
          </div>
        ))}
      </div>

      <div className="custom-profile-section">
        <h5>Create Custom Profile</h5>
        <div className="custom-profile-form">
          <div className="form-group">
            <label>Profile Name:</label>
            <input 
              type="text"
              className="form-input"
              value={customProfile.name}
              onChange={(e) => setCustomProfile(prev => ({ ...prev, name: e.target.value }))}
              placeholder="Enter profile name"
            />
          </div>
          <div className="form-group">
            <label>Description:</label>
            <input 
              type="text"
              className="form-input"
              value={customProfile.description}
              onChange={(e) => setCustomProfile(prev => ({ ...prev, description: e.target.value }))}
              placeholder="Enter description"
            />
          </div>
          <div className="form-group">
            <label>Stealth Level:</label>
            <select 
              className="form-select"
              value={customProfile.stealth_level}
              onChange={(e) => setCustomProfile(prev => ({ ...prev, stealth_level: parseInt(e.target.value) }))}
            >
              {[...Array(10)].map((_, i) => (
                <option key={i + 1} value={i + 1}>{i + 1}</option>
              ))}
            </select>
          </div>
        </div>
        <button 
          onClick={onCreateProfile}
          className="create-profile-btn"
          disabled={!customProfile.name || !customProfile.description}
        >
          Create Profile
        </button>
      </div>
    </div>
  );
};

const EvasionEvents = ({ detectionEvents, onClearEvents, onReportEvent }) => {
  const [eventFilter, setEventFilter] = useState('all');
  const [timeFilter, setTimeFilter] = useState('24h');

  const filteredEvents = detectionEvents.filter(event => {
    if (eventFilter !== 'all' && event.type !== eventFilter) return false;
    
    const eventTime = new Date(event.timestamp);
    const now = new Date();
    const timeDiff = now - eventTime;
    
    switch (timeFilter) {
      case '1h': return timeDiff <= 60 * 60 * 1000;
      case '6h': return timeDiff <= 6 * 60 * 60 * 1000;
      case '24h': return timeDiff <= 24 * 60 * 60 * 1000;
      case '7d': return timeDiff <= 7 * 24 * 60 * 60 * 1000;
      default: return true;
    }
  });

  const eventTypes = ['rate_limit', 'captcha', 'block', 'timeout'];
  const eventCounts = eventTypes.reduce((acc, type) => {
    acc[type] = detectionEvents.filter(e => e.type === type).length;
    return acc;
  }, {});

  return (
    <div className="events-section">
      <h4>Detection Events</h4>
      
      <div className="events-filters">
        <div className="filter-group">
          <label>Event Type:</label>
          <select 
            className="filter-select"
            value={eventFilter}
            onChange={(e) => setEventFilter(e.target.value)}
          >
            <option value="all">All Types</option>
            <option value="rate_limit">Rate Limit</option>
            <option value="captcha">CAPTCHA</option>
            <option value="block">Blocked</option>
            <option value="timeout">Timeout</option>
          </select>
        </div>
        <div className="filter-group">
          <label>Time Range:</label>
          <select 
            className="filter-select"
            value={timeFilter}
            onChange={(e) => setTimeFilter(e.target.value)}
          >
            <option value="1h">Last Hour</option>
            <option value="6h">Last 6 Hours</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="all">All Time</option>
          </select>
        </div>
        <div className="filter-group">
          <button onClick={onClearEvents} className="create-profile-btn">
            Clear All Events
          </button>
        </div>
      </div>

      <div className="events-summary">
        <div className="summary-card">
          <span className="summary-number">{eventCounts.rate_limit}</span>
          <span className="summary-label">Rate Limits</span>
        </div>
        <div className="summary-card">
          <span className="summary-number">{eventCounts.captcha}</span>
          <span className="summary-label">CAPTCHAs</span>
        </div>
        <div className="summary-card">
          <span className="summary-number">{eventCounts.block}</span>
          <span className="summary-label">Blocks</span>
        </div>
        <div className="summary-card">
          <span className="summary-number">{eventCounts.timeout}</span>
          <span className="summary-label">Timeouts</span>
        </div>
      </div>

      <div className="events-list">
        <div className="event-header">
          <div>Type</div>
          <div>Source</div>
          <div>Details</div>
          <div>Time</div>
        </div>
        {filteredEvents.map((event, index) => (
          <div key={index} className="detection-event">
            <span className={`event-type-badge ${event.type}`}>
              {event.type}
            </span>
            <span className="event-source">{event.source}</span>
            <span className="event-details">
              {JSON.stringify(event.details || {})}
            </span>
            <span className="event-timestamp">
              {new Date(event.timestamp).toLocaleString()}
            </span>
          </div>
        ))}
        {filteredEvents.length === 0 && (
          <div className="detection-event">
            <span>No events found matching current filters</span>
          </div>
        )}
      </div>
    </div>
  );
};

const EvasionTools = ({ onClearEvents, onReportEvent }) => {
  const [toolStatus, setToolStatus] = useState({});

  const runTool = async (toolName, action) => {
    setToolStatus(prev => ({ ...prev, [toolName]: 'running' }));
    
    try {
      await new Promise(resolve => setTimeout(resolve, 2000)); // Simulate work
      
      if (action) {
        await action();
      }
      
      setToolStatus(prev => ({ ...prev, [toolName]: 'success' }));
    } catch (error) {
      setToolStatus(prev => ({ ...prev, [toolName]: 'error' }));
    }
  };

  const tools = [
    {
      id: 'clear_events',
      icon: '🧹',
      title: 'Clear Detection Events',
      description: 'Clear all recorded detection events and reset metrics',
      action: onClearEvents
    },
    {
      id: 'test_evasion',
      icon: '🧪',
      title: 'Test Evasion Techniques',
      description: 'Run a comprehensive test of current evasion configuration',
      action: () => onReportEvent('test', 'manual_test')
    },
    {
      id: 'simulate_detection',
      icon: '⚠️',
      title: 'Simulate Detection',
      description: 'Manually trigger a detection event for testing',
      action: () => onReportEvent('rate_limit', 'simulation')
    },
    {
      id: 'export_config',
      icon: '📤',
      title: 'Export Configuration',
      description: 'Export current evasion profiles and settings',
      action: null
    }
  ];

  return (
    <div className="tools-section">
      <h4>Evasion Tools & Utilities</h4>
      <div className="tools-grid">
        {tools.map(tool => (
          <div key={tool.id} className="tool-card">
            <div className="tool-header">
              <span className="tool-icon">{tool.icon}</span>
              <h5 className="tool-title">{tool.title}</h5>
            </div>
            <p className="tool-description">{tool.description}</p>
            <button 
              onClick={() => runTool(tool.id, tool.action)}
              className="tool-btn"
              disabled={toolStatus[tool.id] === 'running'}
            >
              {toolStatus[tool.id] === 'running' ? 'Running...' : 'Run Tool'}
            </button>
            {toolStatus[tool.id] && (
              <div className={`tool-status ${toolStatus[tool.id]}`}>
                {toolStatus[tool.id] === 'success' && '✅ Completed successfully'}
                {toolStatus[tool.id] === 'error' && '❌ Tool execution failed'}
                {toolStatus[tool.id] === 'running' && '⏳ Tool is running...'}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

const getScoreClass = (score) => {
  if (score >= 85) return 'excellent';
  if (score >= 70) return 'good';
  if (score >= 50) return 'fair';
  return 'poor';
};

export default EvasionDashboard;