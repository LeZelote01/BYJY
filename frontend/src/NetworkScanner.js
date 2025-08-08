import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './NetworkScanner.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

const api = axios.create({
  baseURL: BACKEND_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  }
});

const NetworkScanner = () => {
  const [activeTab, setActiveTab] = useState('scanner');
  const [scanConfig, setScanConfig] = useState({
    target: '',
    ports: '1-1000',
    scan_type: 'syn',
    stealth_level: 7
  });
  const [activeScans, setActiveScans] = useState([]);
  const [scanResults, setScanResults] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [scanProfiles, setScanProfiles] = useState({});
  const [scanStatistics, setScanStatistics] = useState({});

  useEffect(() => {
    fetchScanProfiles();
    fetchActiveScans();
    fetchStatistics();
    
    // Auto-refresh active scans every 3 seconds
    const interval = setInterval(() => {
      fetchActiveScans();
      fetchStatistics();
    }, 3000);
    
    return () => clearInterval(interval);
  }, []);

  const fetchScanProfiles = async () => {
    try {
      const response = await api.get('/api/reconnaissance/profiles');
      setScanProfiles(response.data.profiles);
    } catch (err) {
      console.error('Failed to fetch scan profiles:', err);
    }
  };

  const fetchActiveScans = async () => {
    try {
      const response = await api.get('/api/reconnaissance/network/scans');
      const scans = response.data.active_scans || [];
      setActiveScans(scans);
      
      // Monitor running scans for status updates
      scans.forEach(scan => {
        if (scan && scan.status === 'running') {
          monitorScan(scan.scan_id);
        }
      });
    } catch (err) {
      console.error('Failed to fetch active scans:', err);
    }
  };

  const fetchStatistics = async () => {
    try {
      const response = await api.get('/api/reconnaissance/statistics');
      setScanStatistics(response.data);
    } catch (err) {
      console.error('Failed to fetch statistics:', err);
    }
  };

  const validateTarget = async (target) => {
    try {
      const response = await api.get(`/api/reconnaissance/targets/validate/${encodeURIComponent(target)}`);
      return response.data;
    } catch (err) {
      throw new Error(err.response?.data?.detail || 'Target validation failed');
    }
  };

  const startScan = async () => {
    if (!scanConfig.target.trim()) {
      setError('Please enter a target to scan');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // Validate target first
      const validation = await validateTarget(scanConfig.target);
      if (!validation.valid) {
        throw new Error(validation.error || 'Invalid target');
      }

      // Start the scan
      const response = await api.post('/api/reconnaissance/network/scan', scanConfig);
      
      console.log('✅ Scan started:', response.data);
      
      // Refresh active scans immediately
      fetchActiveScans();
      
      // Switch to active scans tab
      setActiveTab('active');

    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to start scan');
    } finally {
      setLoading(false);
    }
  };

  const startProfileScan = async (profileName) => {
    if (!scanConfig.target.trim()) {
      setError('Please enter a target to scan');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await api.post('/api/reconnaissance/profiles/scan', null, {
        params: {
          profile: profileName,
          target: scanConfig.target
        }
      });
      
      console.log('✅ Profile scan started:', response.data);
      
      // Refresh active scans
      fetchActiveScans();
      
      // Switch to active scans tab
      setActiveTab('active');

    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to start profile scan');
    } finally {
      setLoading(false);
    }
  };

  const monitorScan = async (scanId) => {
    try {
      const response = await api.get(`/api/reconnaissance/network/scan/${scanId}/status`);
      const scanStatus = response.data;

      // Update active scans with new status
      setActiveScans(prev => prev.map(scan => 
        scan && scan.scan_id === scanId 
          ? { ...scan, ...scanStatus }
          : scan
      ).filter(Boolean));

      // If scan is completed, fetch results automatically
      if (scanStatus.status === 'completed') {
        const resultsResponse = await api.get(`/api/reconnaissance/network/scan/${scanId}/results`);
        setScanResults(prev => ({
          ...prev,
          [scanId]: resultsResponse.data
        }));
      }
    } catch (err) {
      console.error('Error monitoring scan:', err);
    }
  };

  const cancelScan = async (scanId) => {
    try {
      await api.delete(`/api/reconnaissance/network/scan/${scanId}`);
      setActiveScans(prev => prev.filter(scan => scan && scan.scan_id !== scanId));
      setError(null);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to cancel scan');
    }
  };

  const getScanResults = async (scanId) => {
    try {
      const response = await api.get(`/api/reconnaissance/network/scan/${scanId}/results`);
      setScanResults(prev => ({
        ...prev,
        [scanId]: response.data
      }));
      
      // Switch to results tab after fetching
      setActiveTab('results');
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to fetch scan results');
    }
  };

  return (
    <div className="network-scanner">
      <div className="scanner-header">
        <h2>🔍 Network Scanner</h2>
        <div className="scanner-stats">
          <div className="stat-item">
            <span className="stat-value">{scanStatistics.network_scanner?.total_scans || 0}</span>
            <span className="stat-label">Total Scans</span>
          </div>
          <div className="stealth-indicator">
            <span className="stealth-label">Stealth Level:</span>
            <span className="stealth-value">{scanConfig.stealth_level}/10</span>
          </div>
        </div>
      </div>

      <div className="scanner-tabs">
        <button 
          className={`tab-btn ${activeTab === 'scanner' ? 'active' : ''}`}
          onClick={() => setActiveTab('scanner')}
        >
          🎯 Scanner
        </button>
        <button 
          className={`tab-btn ${activeTab === 'profiles' ? 'active' : ''}`}
          onClick={() => setActiveTab('profiles')}
        >
          📋 Profiles
        </button>
        <button 
          className={`tab-btn ${activeTab === 'active' ? 'active' : ''}`}
          onClick={() => setActiveTab('active')}
        >
          🔄 Active Scans ({activeScans.length})
        </button>
        <button 
          className={`tab-btn ${activeTab === 'results' ? 'active' : ''}`}
          onClick={() => setActiveTab('results')}
        >
          📊 Results ({Object.keys(scanResults).length})
        </button>
      </div>

      {error && (
        <div className="error-message">
          <span className="error-icon">⚠️</span>
          <span>{error}</span>
          <button onClick={() => setError(null)} className="close-btn">×</button>
        </div>
      )}

      <div className="scanner-content">
        {activeTab === 'scanner' && (
          <ScannerTab 
            config={scanConfig}
            setConfig={setScanConfig}
            onStartScan={startScan}
            loading={loading}
          />
        )}
        
        {activeTab === 'profiles' && (
          <ProfilesTab 
            profiles={scanProfiles}
            target={scanConfig.target}
            setTarget={(target) => setScanConfig(prev => ({ ...prev, target }))}
            onStartProfileScan={startProfileScan}
            loading={loading}
          />
        )}
        
        {activeTab === 'active' && (
          <ActiveScansTab 
            scans={activeScans}
            onCancelScan={cancelScan}
            onGetResults={getScanResults}
            onRefresh={fetchActiveScans}
          />
        )}
        
        {activeTab === 'results' && (
          <ResultsTab 
            results={scanResults}
            scans={activeScans}
            onClearResults={() => setScanResults({})}
          />
        )}
      </div>
    </div>
  );
};

const ScannerTab = ({ config, setConfig, onStartScan, loading }) => (
  <div className="scanner-tab">
    <div className="scan-config">
      <h3>📡 Scan Configuration</h3>
      
      <div className="config-group">
        <label>Target Host/IP:</label>
        <input
          type="text"
          value={config.target}
          onChange={(e) => setConfig(prev => ({ ...prev, target: e.target.value }))}
          placeholder="192.168.1.1 or example.com"
          className="target-input"
        />
        <div className="input-help">
          Enter IP address or hostname to scan
        </div>
      </div>

      <div className="config-group">
        <label>Port Range:</label>
        <input
          type="text"
          value={config.ports}
          onChange={(e) => setConfig(prev => ({ ...prev, ports: e.target.value }))}
          placeholder="1-1000, 80,443,8080"
          className="ports-input"
        />
        <div className="input-help">
          Examples: 1-1000, 80,443,8080, 1-65535
        </div>
      </div>

      <div className="config-group">
        <label>Scan Type:</label>
        <select
          value={config.scan_type}
          onChange={(e) => setConfig(prev => ({ ...prev, scan_type: e.target.value }))}
          className="scan-type-select"
        >
          <option value="syn">SYN Scan (Fast, Stealth)</option>
          <option value="connect">Connect Scan (Reliable)</option>
          <option value="fin">FIN Scan (Very Stealth)</option>
          <option value="null">NULL Scan (Very Stealth)</option>
          <option value="xmas">XMAS Scan (Very Stealth)</option>
        </select>
      </div>

      <div className="config-group">
        <label>Stealth Level: {config.stealth_level}</label>
        <div className="stealth-slider">
          <input
            type="range"
            min="1"
            max="10"
            value={config.stealth_level}
            onChange={(e) => setConfig(prev => ({ ...prev, stealth_level: parseInt(e.target.value) }))}
            className="stealth-range"
          />
          <div className="stealth-labels">
            <span>Fast (1-3)</span>
            <span>Balanced (4-7)</span>
            <span>Maximum Stealth (8-10)</span>
          </div>
        </div>
      </div>

      <button 
        onClick={onStartScan}
        disabled={loading || !config.target.trim()}
        className="start-scan-btn"
      >
        {loading ? '🔄 Starting Scan...' : '🚀 Start Stealth Scan'}
      </button>
    </div>

    <div className="scan-info">
      <h4>ℹ️ Scan Information</h4>
      <div className="info-grid">
        <div className="info-item">
          <span className="info-label">Stealth Features:</span>
          <span className="info-value">
            {config.stealth_level >= 8 ? 'Decoy Scanning, Fragmentation, Max Delays' : 
             config.stealth_level >= 6 ? 'Decoy Scanning, Source Port Spoofing' :
             config.stealth_level >= 4 ? 'Timing Delays, Random Headers' : 
             'Basic Speed Optimization'}
          </span>
        </div>
        <div className="info-item">
          <span className="info-label">Estimated Duration:</span>
          <span className="info-value">
            {config.stealth_level >= 8 ? '15-45 minutes' : 
             config.stealth_level >= 6 ? '8-20 minutes' :
             config.stealth_level >= 4 ? '3-10 minutes' : 
             '1-5 minutes'}
          </span>
        </div>
        <div className="info-item">
          <span className="info-label">Detection Risk:</span>
          <span className={`info-value ${config.stealth_level >= 7 ? 'low' : config.stealth_level >= 5 ? 'medium' : 'high'}`}>
            {config.stealth_level >= 7 ? 'Very Low' : config.stealth_level >= 5 ? 'Medium' : 'High'}
          </span>
        </div>
        <div className="info-item">
          <span className="info-label">Nmap Available:</span>
          <span className="info-value">Auto-detected</span>
        </div>
      </div>
      
      <div className="stealth-features">
        <h5>🛡️ Active Stealth Techniques:</h5>
        <div className="features-grid">
          {config.stealth_level >= 6 && <span className="feature-tag">🎭 Decoy Scanning</span>}
          {config.stealth_level >= 7 && <span className="feature-tag">🔧 Packet Fragmentation</span>}
          {config.stealth_level >= 5 && <span className="feature-tag">🔀 Source Port Spoofing</span>}
          {config.stealth_level >= 8 && <span className="feature-tag">⏱️ Paranoid Timing</span>}
          {config.stealth_level >= 4 && <span className="feature-tag">🌐 Anti-Fingerprinting</span>}
        </div>
      </div>
    </div>
  </div>
);

const ProfilesTab = ({ profiles, target, setTarget, onStartProfileScan, loading }) => (
  <div className="profiles-tab">
    <h3>📋 Predefined Scan Profiles</h3>
    
    <div className="profile-target">
      <label>Target:</label>
      <input
        type="text"
        value={target}
        onChange={(e) => setTarget(e.target.value)}
        placeholder="Enter target host/IP"
        className="target-input"
      />
    </div>

    <div className="profiles-grid">
      {Object.entries(profiles).map(([profileName, profile]) => (
        <div key={profileName} className="profile-card">
          <div className="profile-header">
            <h4>{profile.name}</h4>
            <span className={`profile-level level-${profile.stealth_level}`}>
              Level {profile.stealth_level}
            </span>
          </div>
          <p className="profile-description">{profile.description}</p>
          <div className="profile-details">
            <div className="detail-item">
              <span className="detail-label">Ports:</span>
              <span className="detail-value ports-preview">
                {profile.ports.length > 30 ? `${profile.ports.slice(0, 30)}...` : profile.ports}
              </span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Stealth Level:</span>
              <span className="detail-value">{profile.stealth_level}/10</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Type:</span>
              <span className="detail-value">{profileName.replace('_', ' ')}</span>
            </div>
          </div>
          <button
            onClick={() => onStartProfileScan(profileName)}
            disabled={loading || !target.trim()}
            className="profile-btn"
          >
            {loading ? '🔄 Starting...' : '🚀 Start Profile Scan'}
          </button>
        </div>
      ))}
    </div>
    
    <div className="profiles-info">
      <h4>📝 Profile Information</h4>
      <div className="profiles-help">
        <p><strong>Quick Scan:</strong> Fast scan of common ports - ideal for initial reconnaissance</p>
        <p><strong>Comprehensive:</strong> Full port range with high stealth - thorough but slow</p>
        <p><strong>Maximum Stealth:</strong> Ultra-stealthy scan with all evasion techniques</p>
        <p><strong>Web Services:</strong> Focused on web-related ports and services</p>
        <p><strong>Database Services:</strong> Targeted scan for database servers</p>
      </div>
    </div>
  </div>
);

const ActiveScansTab = ({ scans, onCancelScan, onGetResults, onRefresh }) => (
  <div className="active-scans-tab">
    <div className="scans-header">
      <h3>🔄 Active Network Scans</h3>
      <button onClick={onRefresh} className="refresh-btn">
        🔄 Refresh
      </button>
    </div>
    
    {scans.length === 0 ? (
      <div className="no-scans">
        <div className="no-scans-content">
          <div className="no-scans-icon">📡</div>
          <h4>No Active Scans</h4>
          <p>Start a new scan to see it here</p>
        </div>
      </div>
    ) : (
      <div className="scans-list">
        {scans.filter(Boolean).map((scan) => (
          <div key={scan.scan_id} className="scan-item">
            <div className="scan-header">
              <div className="scan-info">
                <div className="scan-target">{scan.target}</div>
                <div className="scan-meta">
                  <span className="scan-id">ID: {scan.scan_id}</span>
                  <span className="scan-time">
                    Started: {new Date(scan.start_time).toLocaleString()}
                  </span>
                </div>
              </div>
              <div className="scan-actions">
                {scan.status === 'completed' && (
                  <button 
                    onClick={() => onGetResults(scan.scan_id)}
                    className="results-btn"
                  >
                    📊 View Results
                  </button>
                )}
                {scan.status === 'running' && (
                  <button 
                    onClick={() => onCancelScan(scan.scan_id)}
                    className="cancel-btn"
                  >
                    ❌ Cancel
                  </button>
                )}
              </div>
            </div>
            
            <div className="scan-progress">
              <div className="progress-info">
                <span className={`scan-status status-${scan.status}`}>
                  {scan.status === 'running' ? '🔄 Running' : 
                   scan.status === 'completed' ? '✅ Completed' : 
                   scan.status === 'failed' ? '❌ Failed' : scan.status}
                </span>
                <span className="scan-progress-text">{scan.progress || 0}%</span>
              </div>
              <div className="progress-bar">
                <div 
                  className={`progress-fill ${scan.status}`}
                  style={{ width: `${scan.progress || 0}%` }}
                ></div>
              </div>
            </div>
            
            <div className="scan-details">
              <div className="detail-item">
                <span className="detail-label">Open Ports:</span>
                <span className="detail-value">{scan.open_ports_count || 0}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Services:</span>
                <span className="detail-value">{scan.services_count || 0}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Vulnerabilities:</span>
                <span className="detail-value">{scan.vulnerabilities_count || 0}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Stealth Score:</span>
                <span className="detail-value stealth-score">
                  {Math.round(scan.stealth_score || 0)}%
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>
    )}
  </div>
);

const ResultsTab = ({ results, scans, onClearResults }) => (
  <div className="results-tab">
    <div className="results-header">
      <h3>📊 Scan Results</h3>
      <div className="results-actions">
        {Object.keys(results).length > 0 && (
          <button onClick={onClearResults} className="clear-results-btn">
            🗑️ Clear All
          </button>
        )}
      </div>
    </div>
    
    {Object.keys(results).length === 0 ? (
      <div className="no-results">
        <div className="no-results-content">
          <div className="no-results-icon">📊</div>
          <h4>No Scan Results</h4>
          <p>Complete a scan to see results here</p>
        </div>
      </div>
    ) : (
      <div className="results-list">
        {Object.entries(results).map(([scanId, result]) => (
          <div key={scanId} className="result-item">
            <div className="result-header">
              <h4>🎯 {result.target}</h4>
              <div className="result-meta">
                <span className="scan-id">ID: {scanId}</span>
                <span className="scan-time">
                  Completed: {result.end_time ? new Date(result.end_time).toLocaleString() : 'N/A'}
                </span>
              </div>
            </div>
            
            <div className="result-summary">
              <div className="summary-item">
                <span className="summary-value">{result.open_ports?.length || 0}</span>
                <span className="summary-label">Open Ports</span>
              </div>
              <div className="summary-item">
                <span className="summary-value">{result.services?.length || 0}</span>
                <span className="summary-label">Services</span>
              </div>
              <div className="summary-item">
                <span className="summary-value">{result.vulnerabilities?.length || 0}</span>
                <span className="summary-label">Vulnerabilities</span>
              </div>
              <div className="summary-item">
                <span className="summary-value stealth-score">
                  {Math.round(result.stealth_score || 0)}%
                </span>
                <span className="summary-label">Stealth Score</span>
              </div>
            </div>
            
            {result.open_ports && result.open_ports.length > 0 && (
              <div className="ports-section">
                <h5>🔓 Open Ports</h5>
                <div className="ports-grid">
                  {result.open_ports.map((port, index) => (
                    <div key={index} className="port-item">
                      <div className="port-number">{port.port}/{port.protocol}</div>
                      <div className="port-service">{port.service || 'unknown'}</div>
                      {port.version && <div className="port-version">{port.version}</div>}
                      {port.product && <div className="port-product">{port.product}</div>}
                    </div>
                  ))}
                </div>
              </div>
            )}
            
            {result.vulnerabilities && result.vulnerabilities.length > 0 && (
              <div className="vulnerabilities-section">
                <h5>🛡️ Potential Vulnerabilities</h5>
                <div className="vulnerabilities-list">
                  {result.vulnerabilities.map((vuln, index) => (
                    <div key={index} className={`vulnerability-item ${vuln.severity}`}>
                      <div className="vuln-info">
                        <span className="vuln-name">{vuln.name}</span>
                        <span className="vuln-port">Port {vuln.port}</span>
                      </div>
                      <span className={`vuln-severity severity-${vuln.severity}`}>
                        {vuln.severity.toUpperCase()}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            
            {result.os_detection && result.os_detection.name && (
              <div className="os-section">
                <h5>💻 OS Detection</h5>
                <div className="os-info">
                  <span className="os-name">{result.os_detection.name}</span>
                  <span className="os-accuracy">
                    ({result.os_detection.accuracy}% confidence)
                  </span>
                </div>
              </div>
            )}

            {result.raw_output && (
              <div className="raw-output-section">
                <h5>📄 Raw Output</h5>
                <div className="raw-output">
                  <pre>{result.raw_output.slice(0, 1000)}{result.raw_output.length > 1000 ? '...' : ''}</pre>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    )}
  </div>
);

export default NetworkScanner;