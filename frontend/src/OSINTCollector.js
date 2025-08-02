import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './OSINTCollector.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

const api = axios.create({
  baseURL: BACKEND_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  }
});

const OSINTCollector = () => {
  const [activeTab, setActiveTab] = useState('collector');
  const [collectionConfig, setCollectionConfig] = useState({
    target: '',
    collect_subdomains: true,
    collect_emails: true,
    collect_social_media: false,
    collect_certificates: true,
    stealth_level: 8
  });
  const [activeCollections, setActiveCollections] = useState([]);
  const [collectionResults, setCollectionResults] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [collectionStatistics, setCollectionStatistics] = useState({});

  useEffect(() => {
    fetchStatistics();
    
    // Auto-refresh collections every 4 seconds
    const interval = setInterval(() => {
      monitorActiveCollections();
      fetchStatistics();
    }, 4000);
    
    return () => clearInterval(interval);
  }, []);

  const fetchStatistics = async () => {
    try {
      const response = await api.get('/api/reconnaissance/statistics');
      setCollectionStatistics(response.data);
    } catch (err) {
      console.error('Failed to fetch statistics:', err);
    }
  };

  const monitorActiveCollections = () => {
    activeCollections.forEach(collection => {
      if (collection.status === 'running') {
        checkCollectionStatus(collection.collection_id);
      }
    });
  };

  const validateTarget = async (target) => {
    try {
      const response = await api.get(`/api/reconnaissance/targets/validate/${encodeURIComponent(target)}`);
      return response.data;
    } catch (err) {
      throw new Error(err.response?.data?.detail || 'Target validation failed');
    }
  };

  const startCollection = async () => {
    if (!collectionConfig.target.trim()) {
      setError('Please enter a target domain or company name');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // Start OSINT collection
      const response = await api.post('/api/reconnaissance/osint/collect', collectionConfig);
      
      console.log('✅ OSINT collection started:', response.data);
      
      // Add to active collections with initial status
      const newCollection = {
        collection_id: response.data.collection_id,
        target: collectionConfig.target,
        status: 'running',
        progress: 0,
        start_time: new Date().toISOString(),
        stealth_level: collectionConfig.stealth_level,
        modules: {
          subdomains: collectionConfig.collect_subdomains,
          emails: collectionConfig.collect_emails,
          social_media: collectionConfig.collect_social_media,
          certificates: collectionConfig.collect_certificates
        },
        subdomains_count: 0,
        emails_count: 0,
        certificates_count: 0,
        stealth_score: 100
      };

      setActiveCollections(prev => [...prev, newCollection]);

      // Switch to active collections tab
      setActiveTab('collections');
      
      // Start monitoring this collection
      setTimeout(() => checkCollectionStatus(response.data.collection_id), 2000);

    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  const checkCollectionStatus = async (collectionId) => {
    try {
      const response = await api.get(`/api/reconnaissance/osint/collection/${collectionId}/status`);
      const status = response.data;

      // Update collection status
      setActiveCollections(prev => prev.map(collection => 
        collection.collection_id === collectionId 
          ? { ...collection, ...status }
          : collection
      ));

      // If completed, fetch results automatically
      if (status.status === 'completed') {
        const resultsResponse = await api.get(`/api/reconnaissance/osint/collection/${collectionId}/results`);
        setCollectionResults(prev => ({
          ...prev,
          [collectionId]: resultsResponse.data
        }));
      }
    } catch (err) {
      console.error('Error checking collection status:', err);
    }
  };

  const getCollectionResults = async (collectionId) => {
    try {
      const response = await api.get(`/api/reconnaissance/osint/collection/${collectionId}/results`);
      setCollectionResults(prev => ({
        ...prev,
        [collectionId]: response.data
      }));
      
      // Switch to results tab
      setActiveTab('results');
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to get collection results');
    }
  };

  const cancelCollection = async (collectionId) => {
    try {
      // Remove from active collections (backend doesn't have cancel endpoint yet)
      setActiveCollections(prev => prev.filter(c => c.collection_id !== collectionId));
      setError(null);
    } catch (err) {
      setError('Failed to cancel collection');
    }
  };

  return (
    <div className="osint-collector">
      <div className="osint-header">
        <h2>🕵️‍♀️ OSINT Collector</h2>
        <div className="collector-stats">
          <div className="stat-item">
            <span className="stat-value">{collectionStatistics.osint_collector?.total_collections || 0}</span>
            <span className="stat-label">Total Collections</span>
          </div>
          <div className="stealth-info">
            <span className="stealth-label">Stealth Level:</span>
            <span className="stealth-value">{collectionConfig.stealth_level}/10</span>
          </div>
        </div>
      </div>

      <div className="osint-tabs">
        <button 
          className={`tab-btn ${activeTab === 'collector' ? 'active' : ''}`}
          onClick={() => setActiveTab('collector')}
        >
          🎯 OSINT Collector
        </button>
        <button 
          className={`tab-btn ${activeTab === 'collections' ? 'active' : ''}`}
          onClick={() => setActiveTab('collections')}
        >
          🔄 Active Collections ({activeCollections.length})
        </button>
        <button 
          className={`tab-btn ${activeTab === 'results' ? 'active' : ''}`}
          onClick={() => setActiveTab('results')}
        >
          📊 Results ({Object.keys(collectionResults).length})
        </button>
      </div>

      {error && (
        <div className="error-message">
          <span className="error-icon">⚠️</span>
          <span>{error}</span>
          <button onClick={() => setError(null)} className="close-btn">×</button>
        </div>
      )}

      <div className="osint-content">
        {activeTab === 'collector' && (
          <CollectorTab
            config={collectionConfig}
            setConfig={setCollectionConfig}
            onStartCollection={startCollection}
            loading={loading}
            error={error}
          />
        )}
        
        {activeTab === 'collections' && (
          <ActiveCollectionsTab
            collections={activeCollections}
            onCancelCollection={cancelCollection}
            onGetResults={getCollectionResults}
            onRefresh={monitorActiveCollections}
          />
        )}
        
        {activeTab === 'results' && (
          <ResultsTab
            results={collectionResults}
            collections={activeCollections}
            onClearResults={() => setCollectionResults({})}
          />
        )}
      </div>
    </div>
  );
};

const CollectorTab = ({ config, setConfig, onStartCollection, loading, error }) => (
  <div className="collector-tab">
    <div className="collector-grid">
      <div className="collector-config">
        <h3>🎯 OSINT Collection Configuration</h3>
        
        <div className="config-section">
          <label className="config-label">Target Domain/Organization:</label>
          <input
            type="text"
            value={config.target}
            onChange={(e) => setConfig(prev => ({ ...prev, target: e.target.value }))}
            placeholder="example.com or Acme Corp"
            className="target-input"
          />
          <div className="input-help">
            Enter domain name (example.com) or organization name
          </div>
        </div>

        <div className="config-section">
          <label className="config-label">Collection Modules:</label>
          <div className="modules-grid">
            <label className="module-checkbox">
              <input
                type="checkbox"
                checked={config.collect_subdomains}
                onChange={(e) => setConfig(prev => ({ ...prev, collect_subdomains: e.target.checked }))}
              />
              <span>🌐 Subdomain Enumeration</span>
              <div className="module-help">Find all subdomains using DNS, CT logs, brute force</div>
            </label>
            <label className="module-checkbox">
              <input
                type="checkbox"
                checked={config.collect_emails}
                onChange={(e) => setConfig(prev => ({ ...prev, collect_emails: e.target.checked }))}
              />
              <span>📧 Email Harvesting</span>
              <div className="module-help">Extract email addresses from web content</div>
            </label>
            <label className="module-checkbox">
              <input
                type="checkbox"
                checked={config.collect_certificates}
                onChange={(e) => setConfig(prev => ({ ...prev, collect_certificates: e.target.checked }))}
              />
              <span>🔐 SSL Certificate Analysis</span>
              <div className="module-help">Analyze SSL/TLS certificates for domain info</div>
            </label>
            <label className="module-checkbox">
              <input
                type="checkbox"
                checked={config.collect_social_media}
                onChange={(e) => setConfig(prev => ({ ...prev, collect_social_media: e.target.checked }))}
              />
              <span>📱 Social Media Intelligence</span>
              <div className="module-help">Search for social media profiles (higher detection risk)</div>
            </label>
          </div>
        </div>

        <div className="config-section">
          <label className="config-label">Stealth Level: {config.stealth_level}</label>
          <input
            type="range"
            min="1"
            max="10"
            value={config.stealth_level}
            onChange={(e) => setConfig(prev => ({ ...prev, stealth_level: parseInt(e.target.value) }))}
            className="stealth-slider"
          />
          <div className="stealth-indicators">
            <span>Fast (1-3)</span>
            <span>Balanced (4-7)</span>
            <span>Maximum Stealth (8-10)</span>
          </div>
          <div className="stealth-info-detail">
            <span className="stealth-description">
              {config.stealth_level >= 8 ? 'Maximum delays, minimal footprint, very slow' :
               config.stealth_level >= 6 ? 'Balanced speed vs stealth, recommended' :
               config.stealth_level >= 4 ? 'Moderate delays, faster collection' :
               'Minimal delays, higher detection risk'}
            </span>
          </div>
        </div>

        <button 
          onClick={onStartCollection}
          disabled={loading || !config.target.trim()}
          className="start-collection-btn"
        >
          {loading ? '🔄 Starting OSINT Collection...' : '🚀 Start Intelligence Collection'}
        </button>
      </div>

      <div className="collection-info">
        <h3>📋 OSINT Collection Information</h3>
        
        <div className="info-section">
          <h4>🔍 Intelligence Sources:</h4>
          <ul className="sources-list">
            <li>Certificate Transparency logs (crt.sh, certspotter)</li>
            <li>DNS enumeration and zone transfers</li>
            <li>Passive DNS databases (BufferOver, etc.)</li>
            <li>Search engine reconnaissance</li>
            <li>WHOIS and domain registration data</li>
            <li>Technology fingerprinting</li>
            <li>Social media profiles (optional)</li>
          </ul>
        </div>

        <div className="info-section">
          <h4>🛡️ Stealth & Evasion Features:</h4>
          <ul className="features-list">
            <li>Intelligent rate limiting and delays</li>
            <li>User-Agent rotation and randomization</li>
            <li>Request timing and spacing control</li>
            <li>Proxy rotation (when available)</li>
            <li>Anti-detection headers and cookies</li>
            <li>Forensic trace cleanup</li>
            <li>Search engine query obfuscation</li>
          </ul>
        </div>

        <div className="info-section">
          <h4>⏱️ Estimated Collection Time:</h4>
          <div className="duration-estimate">
            <span className="duration-value">
              {config.stealth_level >= 8 ? '20-45 minutes' : 
               config.stealth_level >= 6 ? '10-25 minutes' : 
               config.stealth_level >= 4 ? '5-15 minutes' :
               '2-8 minutes'}
            </span>
            <span className="duration-note">
              Time varies based on target size, stealth level, and active modules
            </span>
          </div>
        </div>

        <div className="info-section">
          <h4>⚖️ Legal Notice:</h4>
          <div className="legal-notice">
            <p>This tool is for authorized testing and legitimate research only. 
            Always ensure you have explicit permission before collecting intelligence 
            on any organization or domain.</p>
          </div>
        </div>
      </div>
    </div>
  </div>
);

const ActiveCollectionsTab = ({ collections, onCancelCollection, onGetResults, onRefresh }) => (
  <div className="active-collections-tab">
    <div className="collections-header">
      <h3>🔄 Active OSINT Collections</h3>
      <button onClick={onRefresh} className="refresh-btn">
        🔄 Refresh Status
      </button>
    </div>
    
    {collections.length === 0 ? (
      <div className="no-collections">
        <div className="no-collections-content">
          <div className="no-collections-icon">🕵️‍♀️</div>
          <h4>No Active Collections</h4>
          <p>Start a new OSINT collection to see progress here</p>
        </div>
      </div>
    ) : (
      <div className="collections-list">
        {collections.map((collection) => (
          <div key={collection.collection_id} className="collection-item">
            <div className="collection-header">
              <div className="collection-target">
                <h4>🎯 {collection.target}</h4>
                <div className="collection-meta">
                  <span className="collection-id">ID: {collection.collection_id}</span>
                  <span className="collection-time">
                    Started: {new Date(collection.start_time).toLocaleString()}
                  </span>
                </div>
              </div>
              
              <div className="collection-actions">
                <button 
                  onClick={() => onGetResults(collection.collection_id)}
                  className="results-btn"
                  disabled={collection.status !== 'completed'}
                >
                  📊 View Results
                </button>
                {collection.status === 'running' && (
                  <button 
                    onClick={() => onCancelCollection(collection.collection_id)}
                    className="cancel-btn"
                  >
                    ❌ Cancel
                  </button>
                )}
              </div>
            </div>
            
            <div className="collection-progress">
              <div className="progress-info">
                <span className={`collection-status status-${collection.status}`}>
                  {collection.status === 'running' ? '🔄 Collecting Intelligence' : 
                   collection.status === 'completed' ? '✅ Collection Complete' : 
                   collection.status === 'failed' ? '❌ Collection Failed' : collection.status}
                </span>
                <span className="collection-progress-text">{collection.progress || 0}%</span>
              </div>
              <div className="progress-bar">
                <div 
                  className={`progress-fill ${collection.status}`}
                  style={{ width: `${collection.progress || 0}%` }}
                ></div>
              </div>
            </div>
            
            <div className="collection-modules">
              <span className="modules-label">Active Modules:</span>
              <div className="modules-tags">
                {collection.modules?.subdomains && <span className="module-tag">🌐 Subdomains</span>}
                {collection.modules?.emails && <span className="module-tag">📧 Emails</span>}
                {collection.modules?.certificates && <span className="module-tag">🔐 Certificates</span>}
                {collection.modules?.social_media && <span className="module-tag">📱 Social Media</span>}
              </div>
            </div>
            
            <div className="collection-details">
              <div className="detail-item">
                <span className="detail-label">Subdomains Found:</span>
                <span className="detail-value">{collection.subdomains_count || 0}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Emails Found:</span>
                <span className="detail-value">{collection.emails_count || 0}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Certificates:</span>
                <span className="detail-value">{collection.certificates_count || 0}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Stealth Score:</span>
                <span className="detail-value stealth-score">
                  {Math.round(collection.stealth_score || 100)}%
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>
    )}
  </div>
);

const ResultsTab = ({ results, collections, onClearResults }) => (
  <div className="results-tab">
    <div className="results-header">
      <h3>📊 OSINT Collection Results</h3>
      <div className="results-actions">
        {Object.keys(results).length > 0 && (
          <button onClick={onClearResults} className="clear-results-btn">
            🗑️ Clear All Results
          </button>
        )}
      </div>
    </div>
    
    {Object.keys(results).length === 0 ? (
      <div className="no-results">
        <div className="no-results-content">
          <div className="no-results-icon">📋</div>
          <h4>No Collection Results</h4>
          <p>Complete an OSINT collection to see intelligence results here</p>
        </div>
      </div>
    ) : (
      <div className="results-list">
        {Object.entries(results).map(([collectionId, result]) => {
          const collection = collections.find(c => c.collection_id === collectionId);
          return (
            <div key={collectionId} className="result-item">
              <div className="result-header">
                <h4>🎯 {result.target}</h4>
                <div className="result-meta">
                  <span className="result-id">Collection ID: {collectionId}</span>
                  <span className="result-time">
                    Completed: {result.end_time ? new Date(result.end_time).toLocaleString() : 'In Progress'}
                  </span>
                </div>
              </div>
              
              <div className="result-summary">
                <div className="summary-grid">
                  <div className="summary-item">
                    <span className="summary-value">{result.summary?.total_subdomains || 0}</span>
                    <span className="summary-label">Subdomains</span>
                  </div>
                  <div className="summary-item">
                    <span className="summary-value">{result.summary?.total_emails || 0}</span>
                    <span className="summary-label">Email Addresses</span>
                  </div>
                  <div className="summary-item">
                    <span className="summary-value">{result.summary?.total_certificates || 0}</span>
                    <span className="summary-label">SSL Certificates</span>
                  </div>
                  <div className="summary-item">
                    <span className="summary-value">{result.summary?.technologies_detected || 0}</span>
                    <span className="summary-label">Technologies</span>
                  </div>
                </div>
              </div>
              
              {result.subdomains && result.subdomains.length > 0 && (
                <div className="result-section">
                  <h5>🌐 Discovered Subdomains ({result.subdomains.length})</h5>
                  <div className="subdomains-grid">
                    {result.subdomains.slice(0, 12).map((subdomain, index) => (
                      <div key={index} className="subdomain-item">
                        <span className="subdomain-name">{subdomain}</span>
                      </div>
                    ))}
                    {result.subdomains.length > 12 && (
                      <div className="more-items">
                        +{result.subdomains.length - 12} more subdomains...
                      </div>
                    )}
                  </div>
                </div>
              )}
              
              {result.emails && result.emails.length > 0 && (
                <div className="result-section">
                  <h5>📧 Email Addresses ({result.emails.length})</h5>
                  <div className="emails-list">
                    {result.emails.slice(0, 8).map((email, index) => (
                      <div key={index} className="email-item">
                        <span className="email-address">{email}</span>
                      </div>
                    ))}
                    {result.emails.length > 8 && (
                      <div className="more-items">
                        +{result.emails.length - 8} more email addresses...
                      </div>
                    )}
                  </div>
                </div>
              )}

              {result.certificates && result.certificates.length > 0 && (
                <div className="result-section">
                  <h5>🔐 SSL Certificates ({result.certificates.length})</h5>
                  <div className="certificates-list">
                    {result.certificates.slice(0, 5).map((cert, index) => (
                      <div key={index} className="certificate-item">
                        <div className="cert-info">
                          <span className="cert-hostname">{cert.hostname}</span>
                          <span className="cert-issuer">{cert.issuer?.organizationName || 'Unknown Issuer'}</span>
                        </div>
                        <div className="cert-validity">
                          <span className="cert-dates">
                            Valid: {cert.not_before} - {cert.not_after}
                          </span>
                        </div>
                      </div>
                    ))}
                    {result.certificates.length > 5 && (
                      <div className="more-items">
                        +{result.certificates.length - 5} more certificates...
                      </div>
                    )}
                  </div>
                </div>
              )}

              {result.technologies && Object.keys(result.technologies).length > 0 && (
                <div className="result-section">
                  <h5>🔧 Technology Stack</h5>
                  <div className="technologies-grid">
                    {result.technologies.server && (
                      <div className="tech-item">
                        <span className="tech-label">Web Server:</span>
                        <span className="tech-value">{result.technologies.server}</span>
                      </div>
                    )}
                    {result.technologies.framework && result.technologies.framework !== 'Unknown' && (
                      <div className="tech-item">
                        <span className="tech-label">Framework:</span>
                        <span className="tech-value">{result.technologies.framework}</span>
                      </div>
                    )}
                    {result.technologies.cms && result.technologies.cms !== 'Unknown' && (
                      <div className="tech-item">
                        <span className="tech-label">CMS:</span>
                        <span className="tech-value">{result.technologies.cms}</span>
                      </div>
                    )}
                    {result.technologies.javascript_libraries && result.technologies.javascript_libraries.length > 0 && (
                      <div className="tech-item">
                        <span className="tech-label">JS Libraries:</span>
                        <span className="tech-value">{result.technologies.javascript_libraries.join(', ')}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {result.dns_records && Object.keys(result.dns_records).length > 0 && (
                <div className="result-section">
                  <h5>🌐 DNS Records</h5>
                  <div className="dns-records">
                    {Object.entries(result.dns_records).map(([recordType, records]) => (
                      records.length > 0 && (
                        <div key={recordType} className="dns-record-type">
                          <span className="dns-type">{recordType}:</span>
                          <div className="dns-values">
                            {records.slice(0, 3).map((record, index) => (
                              <span key={index} className="dns-value">{record}</span>
                            ))}
                            {records.length > 3 && <span className="dns-more">+{records.length - 3} more</span>}
                          </div>
                        </div>
                      )
                    ))}
                  </div>
                </div>
              )}

              <div className="collection-summary">
                <div className="summary-stats">
                  <span className="stealth-score">
                    Stealth Score: {Math.round(result.stealth_score || 100)}%
                  </span>
                  <span className="collection-duration">
                    Duration: {result.start_time && result.end_time ? 
                      Math.round((new Date(result.end_time) - new Date(result.start_time)) / 1000 / 60) + ' minutes' : 
                      'Unknown'}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    )}
  </div>
);

export default OSINTCollector;