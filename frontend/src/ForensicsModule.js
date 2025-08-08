import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';

// Backend URL configuration
const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

// API client
const api = axios.create({
  baseURL: BACKEND_URL,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' }
});

const ForensicsModule = () => {
  const [activeTab, setActiveTab] = useState('overview');
  const [dashboardData, setDashboardData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [analyses, setAnalyses] = useState({
    logs: [],
    files: [],
    network: [],
    memory: []
  });

  // States for different forensics modules
  const [logAnalysisState, setLogAnalysisState] = useState({
    uploading: false,
    results: null,
    error: null
  });

  const [fileAnalysisState, setFileAnalysisState] = useState({
    uploading: false,
    results: null,
    error: null
  });

  const [memoryAnalysisState, setMemoryAnalysisState] = useState({
    analyzing: false,
    results: null,
    error: null
  });

  const [networkAnalysisState, setNetworkAnalysisState] = useState({
    uploading: false,
    results: null,
    error: null
  });

  useEffect(() => {
    fetchDashboardData();
    fetchAllAnalyses();
  }, []);

  const fetchDashboardData = async () => {
    try {
      const response = await api.get('/api/forensics/dashboard/overview');
      setDashboardData(response.data);
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchAllAnalyses = async () => {
    try {
      const [logsResp, filesResp, networkResp, memoryResp] = await Promise.allSettled([
        api.get('/api/forensics/logs/analyses'),
        api.get('/api/forensics/files/analyses'),
        api.get('/api/forensics/network/analyses'),
        api.get('/api/forensics/memory/analyses')
      ]);

      setAnalyses({
        logs: logsResp.status === 'fulfilled' ? logsResp.value.data.analyses || [] : [],
        files: filesResp.status === 'fulfilled' ? filesResp.value.data.analyses || [] : [],
        network: networkResp.status === 'fulfilled' ? networkResp.value.data.analyses || [] : [],
        memory: memoryResp.status === 'fulfilled' ? memoryResp.value.data.analyses || [] : []
      });
    } catch (error) {
      console.error('Failed to fetch analyses:', error);
    }
  };

  // Overview Dashboard Component
  const OverviewDashboard = () => (
    <div className="forensics-overview">
      <div className="dashboard-header">
        <h2>🔬 Digital Forensics Suite</h2>
        <p>Advanced forensic analysis tools with stealth capabilities</p>
      </div>

      {loading ? (
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>Loading forensics dashboard...</p>
        </div>
      ) : (
        <>
          {/* Overview Stats */}
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-icon">📊</div>
              <div className="stat-content">
                <div className="stat-value">{dashboardData?.overview?.total_analyses || 0}</div>
                <div className="stat-label">Total Analyses</div>
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-icon">🚨</div>
              <div className="stat-content">
                <div className="stat-value">{dashboardData?.overview?.recent_analyses_24h || 0}</div>
                <div className="stat-label">Recent (24h)</div>
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-icon">⚠️</div>
              <div className="stat-content">
                <div className="stat-value">{(dashboardData?.overview?.average_threat_score * 100 || 0).toFixed(1)}%</div>
                <div className="stat-label">Avg Threat Score</div>
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-icon">🛡️</div>
              <div className="stat-content">
                <div className="stat-value">{dashboardData?.overview?.modules_active || 0}</div>
                <div className="stat-label">Active Modules</div>
              </div>
            </div>
          </div>

          {/* Modules Status */}
          <div className="modules-status">
            <h3>Forensics Modules Status</h3>
            <div className="modules-grid">
              {Object.entries(dashboardData?.modules || {}).map(([key, module]) => (
                <div key={key} className={`module-card ${module.status}`}>
                  <div className="module-header">
                    <span className="module-icon">
                      {key === 'log_forensics' && '📋'}
                      {key === 'file_forensics' && '📁'}
                      {key === 'network_forensics' && '🌐'}
                      {key === 'memory_forensics' && '🧠'}
                    </span>
                    <span className="module-name">
                      {key.replace('_', ' ').replace('forensics', '').trim()}
                    </span>
                  </div>
                  <div className="module-stats">
                    <div className="module-analyses">{module.total_analyses} analyses</div>
                    <div className={`module-status ${module.status}`}>
                      {module.status === 'active' ? '✅ Active' : '❌ Inactive'}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Recent Activities */}
          {dashboardData?.recent_activities?.length > 0 && (
            <div className="recent-activities">
              <h3>Recent Activities</h3>
              <div className="activities-list">
                {dashboardData.recent_activities.map((activity, index) => (
                  <div key={index} className="activity-item">
                    <span className="activity-type">{activity.type}</span>
                    <span className="activity-id">{activity.id}</span>
                    <span className="activity-time">{new Date(activity.created_at).toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );

  // Log Analysis Component
  const LogAnalysis = () => {
    const fileInputRef = useRef(null);

    const handleLogUpload = async (event) => {
      const files = event.target.files;
      if (!files || files.length === 0) return;

      setLogAnalysisState({ ...logAnalysisState, uploading: true, error: null });

      try {
        const formData = new FormData();
        for (let i = 0; i < files.length; i++) {
          formData.append('log_files', files[i]);
        }
        formData.append('case_id', `case_${Date.now()}`);
        formData.append('analysis_name', 'Web Interface Log Analysis');

        const response = await api.post('/api/forensics/logs/analyze', formData, {
          headers: { 'Content-Type': 'multipart/form-data' },
          timeout: 60000
        });

        setLogAnalysisState({
          uploading: false,
          results: response.data.results,
          error: null
        });

        // Refresh analyses list
        fetchAllAnalyses();
      } catch (error) {
        setLogAnalysisState({
          uploading: false,
          results: null,
          error: error.response?.data?.detail || error.message
        });
      }
    };

    return (
      <div className="log-analysis">
        <div className="analysis-header">
          <h3>📋 Log Forensic Analysis</h3>
          <p>Analyze log files with anomaly detection and timeline reconstruction</p>
        </div>

        <div className="upload-section">
          <div className="upload-area" onClick={() => fileInputRef.current?.click()}>
            <div className="upload-icon">📁</div>
            <div className="upload-text">
              <h4>Upload Log Files</h4>
              <p>Support: syslog, Apache, Nginx, IIS, Windows Event logs</p>
              <p>Click to select files or drag and drop</p>
            </div>
            <input
              ref={fileInputRef}
              type="file"
              multiple
              accept=".log,.txt,.evtx"
              onChange={handleLogUpload}
              style={{ display: 'none' }}
            />
          </div>
        </div>

        {logAnalysisState.uploading && (
          <div className="analysis-progress">
            <div className="progress-spinner"></div>
            <p>Analyzing log files... This may take a few minutes.</p>
          </div>
        )}

        {logAnalysisState.error && (
          <div className="error-message">
            <span className="error-icon">❌</span>
            <span>Error: {logAnalysisState.error}</span>
          </div>
        )}

        {logAnalysisState.results && (
          <div className="analysis-results">
            <div className="results-header">
              <h4>Analysis Results</h4>
              <span className="analysis-id">ID: {logAnalysisState.results.analysis_id}</span>
            </div>
            
            <div className="results-summary">
              <div className="summary-item">
                <span className="label">Total Entries:</span>
                <span className="value">{logAnalysisState.results.total_entries}</span>
              </div>
              <div className="summary-item">
                <span className="label">Anomalies Found:</span>
                <span className="value">{logAnalysisState.results.anomalies?.length || 0}</span>
              </div>
              <div className="summary-item">
                <span className="label">Stealth Score:</span>
                <span className="value">{(logAnalysisState.results.stealth_score * 100).toFixed(1)}%</span>
              </div>
            </div>

            {logAnalysisState.results.anomalies?.length > 0 && (
              <div className="anomalies-section">
                <h5>🚨 Detected Anomalies</h5>
                <div className="anomalies-list">
                  {logAnalysisState.results.anomalies.map((anomaly, index) => (
                    <div key={index} className={`anomaly-item severity-${anomaly.severity}`}>
                      <div className="anomaly-header">
                        <span className="anomaly-type">{anomaly.pattern_type}</span>
                        <span className={`severity severity-${anomaly.severity}`}>{anomaly.severity}</span>
                      </div>
                      <div className="anomaly-description">{anomaly.description}</div>
                      <div className="anomaly-details">
                        <span>Count: {anomaly.count}</span>
                        <span>Confidence: {(anomaly.confidence_score * 100).toFixed(1)}%</span>
                        <span>First: {new Date(anomaly.first_seen).toLocaleString()}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Previous Analyses */}
        <div className="previous-analyses">
          <h4>Previous Log Analyses</h4>
          {analyses.logs.length === 0 ? (
            <p className="no-analyses">No previous analyses found</p>
          ) : (
            <div className="analyses-list">
              {analyses.logs.map((analysis, index) => (
                <div key={index} className="analysis-item">
                  <div className="analysis-info">
                    <span className="analysis-name">{analysis.name || 'Log Analysis'}</span>
                    <span className="analysis-date">{new Date(analysis.created_at).toLocaleString()}</span>
                  </div>
                  <div className="analysis-stats">
                    <span>Entries: {analysis.total_entries}</span>
                    <span>Anomalies: {analysis.anomalies_found}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    );
  };

  // File Analysis Component
  const FileAnalysis = () => {
    const fileInputRef = useRef(null);

    const handleFileUpload = async (event) => {
      const file = event.target.files[0];
      if (!file) return;

      setFileAnalysisState({ ...fileAnalysisState, uploading: true, error: null });

      try {
        const formData = new FormData();
        formData.append('file', file);

        const response = await api.post('/api/forensics/files/analyze', formData, {
          headers: { 'Content-Type': 'multipart/form-data' },
          timeout: 60000
        });

        setFileAnalysisState({
          uploading: false,
          results: response.data.results,
          error: null
        });

        fetchAllAnalyses();
      } catch (error) {
        setFileAnalysisState({
          uploading: false,
          results: null,
          error: error.response?.data?.detail || error.message
        });
      }
    };

    return (
      <div className="file-analysis">
        <div className="analysis-header">
          <h3>📁 File Forensic Analysis</h3>
          <p>Analyze files for metadata, malware, and steganography</p>
        </div>

        <div className="upload-section">
          <div className="upload-area" onClick={() => fileInputRef.current?.click()}>
            <div className="upload-icon">📄</div>
            <div className="upload-text">
              <h4>Upload File for Analysis</h4>
              <p>Supports all file types - binary analysis included</p>
              <p>Click to select a file</p>
            </div>
            <input
              ref={fileInputRef}
              type="file"
              onChange={handleFileUpload}
              style={{ display: 'none' }}
            />
          </div>
        </div>

        {fileAnalysisState.uploading && (
          <div className="analysis-progress">
            <div className="progress-spinner"></div>
            <p>Analyzing file... Checking for malware and extracting metadata.</p>
          </div>
        )}

        {fileAnalysisState.error && (
          <div className="error-message">
            <span className="error-icon">❌</span>
            <span>Error: {fileAnalysisState.error}</span>
          </div>
        )}

        {fileAnalysisState.results && (
          <div className="analysis-results">
            <div className="results-header">
              <h4>File Analysis Results</h4>
              <span className="analysis-id">ID: {fileAnalysisState.results.analysis_id}</span>
            </div>
            
            <div className="results-summary">
              <div className="summary-item">
                <span className="label">Risk Score:</span>
                <span className={`value risk-${fileAnalysisState.results.risk_score > 0.7 ? 'high' : fileAnalysisState.results.risk_score > 0.4 ? 'medium' : 'low'}`}>
                  {(fileAnalysisState.results.risk_score * 100).toFixed(1)}%
                </span>
              </div>
              <div className="summary-item">
                <span className="label">File Type:</span>
                <span className="value">{fileAnalysisState.results.file_info?.mime_type || 'Unknown'}</span>
              </div>
              <div className="summary-item">
                <span className="label">File Size:</span>
                <span className="value">{fileAnalysisState.results.file_info?.size_bytes || 0} bytes</span>
              </div>
            </div>

            {fileAnalysisState.results.malware_analysis && (
              <div className="malware-section">
                <h5>🦠 Malware Analysis</h5>
                <div className="malware-indicators">
                  <div className="indicator-item">
                    <span className="label">Entropy:</span>
                    <span className="value">{fileAnalysisState.results.malware_analysis.entropy?.toFixed(2) || 'N/A'}</span>
                  </div>
                  <div className="indicator-item">
                    <span className="label">Suspicious Strings:</span>
                    <span className="value">{fileAnalysisState.results.malware_analysis.suspicious_strings?.length || 0}</span>
                  </div>
                  <div className="indicator-item">
                    <span className="label">Packed:</span>
                    <span className="value">{fileAnalysisState.results.malware_analysis.is_packed ? 'Yes' : 'No'}</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    );
  };

  // Memory Analysis Component
  const MemoryAnalysis = () => {
    const [analysisOptions, setAnalysisOptions] = useState({
      processes: true,
      rootkits: true,
      dumps: false,
      artifacts: true
    });

    const handleMemoryAnalysis = async () => {
      setMemoryAnalysisState({ ...memoryAnalysisState, analyzing: true, error: null });

      try {
        const params = new URLSearchParams(analysisOptions);
        const response = await api.post(`/api/forensics/memory/analyze?${params}`, null, {
          timeout: 120000 // 2 minutes
        });

        setMemoryAnalysisState({
          analyzing: false,
          results: response.data.results,
          error: null
        });

        fetchAllAnalyses();
      } catch (error) {
        setMemoryAnalysisState({
          analyzing: false,
          results: null,
          error: error.response?.data?.detail || error.message
        });
      }
    };

    return (
      <div className="memory-analysis">
        <div className="analysis-header">
          <h3>🧠 Memory Forensic Analysis</h3>
          <p>Analyze system memory for processes, rootkits, and artifacts</p>
        </div>

        <div className="analysis-options">
          <h4>Analysis Options</h4>
          <div className="options-grid">
            {Object.entries(analysisOptions).map(([key, value]) => (
              <label key={key} className="option-item">
                <input
                  type="checkbox"
                  checked={value}
                  onChange={(e) => setAnalysisOptions({
                    ...analysisOptions,
                    [key]: e.target.checked
                  })}
                />
                <span className="option-label">
                  {key.charAt(0).toUpperCase() + key.slice(1).replace('_', ' ')}
                </span>
              </label>
            ))}
          </div>
        </div>

        <div className="analysis-controls">
          <button
            className="analyze-btn"
            onClick={handleMemoryAnalysis}
            disabled={memoryAnalysisState.analyzing}
          >
            {memoryAnalysisState.analyzing ? (
              <>
                <span className="spinner"></span>
                Analyzing Memory...
              </>
            ) : (
              <>
                🧠 Start Memory Analysis
              </>
            )}
          </button>
        </div>

        {memoryAnalysisState.error && (
          <div className="error-message">
            <span className="error-icon">❌</span>
            <span>Error: {memoryAnalysisState.error}</span>
          </div>
        )}

        {memoryAnalysisState.results && (
          <div className="analysis-results">
            <div className="results-header">
              <h4>Memory Analysis Results</h4>
              <span className="analysis-id">ID: {memoryAnalysisState.results.analysis_id}</span>
            </div>
            
            <div className="results-summary">
              <div className="summary-item">
                <span className="label">Threat Score:</span>
                <span className={`value risk-${memoryAnalysisState.results.threat_score > 0.7 ? 'high' : memoryAnalysisState.results.threat_score > 0.4 ? 'medium' : 'low'}`}>
                  {(memoryAnalysisState.results.threat_score * 100).toFixed(1)}%
                </span>
              </div>
              <div className="summary-item">
                <span className="label">Processes Analyzed:</span>
                <span className="value">{memoryAnalysisState.results.total_processes || 0}</span>
              </div>
              <div className="summary-item">
                <span className="label">Suspicious Processes:</span>
                <span className="value">{memoryAnalysisState.results.suspicious_processes || 0}</span>
              </div>
              <div className="summary-item">
                <span className="label">Rootkit Indicators:</span>
                <span className="value">{memoryAnalysisState.results.rootkit_indicators || 0}</span>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  };

  // Network Analysis Component (placeholder for PCAP upload)
  const NetworkAnalysis = () => (
    <div className="network-analysis">
      <div className="analysis-header">
        <h3>🌐 Network Forensic Analysis</h3>
        <p>Analyze network traffic from PCAP files</p>
      </div>
      
      <div className="feature-coming-soon">
        <div className="coming-soon-icon">🚧</div>
        <h4>PCAP Analysis Coming Soon</h4>
        <p>Network traffic analysis and session reconstruction will be available in the next update.</p>
      </div>
    </div>
  );

  const tabs = [
    { id: 'overview', name: 'Overview', icon: '📊', component: OverviewDashboard },
    { id: 'logs', name: 'Log Analysis', icon: '📋', component: LogAnalysis },
    { id: 'files', name: 'File Analysis', icon: '📁', component: FileAnalysis },
    { id: 'memory', name: 'Memory Analysis', icon: '🧠', component: MemoryAnalysis },
    { id: 'network', name: 'Network Analysis', icon: '🌐', component: NetworkAnalysis }
  ];

  const ActiveComponent = tabs.find(tab => tab.id === activeTab)?.component || OverviewDashboard;

  return (
    <div className="forensics-module">
      <div className="forensics-nav">
        {tabs.map(tab => (
          <button
            key={tab.id}
            className={`nav-tab ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            <span className="nav-icon">{tab.icon}</span>
            <span className="nav-text">{tab.name}</span>
          </button>
        ))}
      </div>

      <div className="forensics-content">
        <ActiveComponent />
      </div>
    </div>
  );
};

export default ForensicsModule;