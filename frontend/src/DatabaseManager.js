import React, { useState, useEffect } from 'react';
import axios from 'axios';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

const DatabaseManager = () => {
  const [databaseStats, setDatabaseStats] = useState(null);
  const [backups, setBackups] = useState([]);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const [integrity, setIntegrity] = useState(null);

  useEffect(() => {
    fetchDatabaseStats();
    fetchBackups();
    checkIntegrity();
  }, []);

  const fetchDatabaseStats = async () => {
    try {
      const response = await axios.get(`${BACKEND_URL}/api/database/status`);
      setDatabaseStats(response.data);
    } catch (error) {
      console.error('Failed to fetch database stats:', error);
    }
  };

  const fetchBackups = async () => {
    try {
      const response = await axios.get(`${BACKEND_URL}/api/database/backups`);
      setBackups(response.data.backups || []);
    } catch (error) {
      console.error('Failed to fetch backups:', error);
    }
  };

  const checkIntegrity = async () => {
    try {
      const response = await axios.get(`${BACKEND_URL}/api/database/integrity-check`);
      setIntegrity(response.data);
    } catch (error) {
      console.error('Failed to check integrity:', error);
    }
  };

  const createBackup = async () => {
    setLoading(true);
    try {
      const response = await axios.post(`${BACKEND_URL}/api/database/backup`, {
        backup_name: `manual_backup_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.db`
      });
      
      if (response.data.message) {
        alert(`✅ ${response.data.message}`);
        fetchBackups(); // Refresh backup list
      }
    } catch (error) {
      alert(`❌ Backup failed: ${error.response?.data?.detail || error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const exportData = async (modules = null) => {
    setLoading(true);
    try {
      const response = await axios.post(`${BACKEND_URL}/api/database/export`, {
        modules: modules,
        include_encrypted: false
      });
      
      if (response.data.download_url) {
        // Download the exported file
        window.open(`${BACKEND_URL}${response.data.download_url}`, '_blank');
        alert(`✅ ${response.data.message}`);
      }
    } catch (error) {
      alert(`❌ Export failed: ${error.response?.data?.detail || error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const vacuumDatabase = async () => {
    setLoading(true);
    try {
      const response = await axios.post(`${BACKEND_URL}/api/database/vacuum`);
      alert(`✅ ${response.data.message}\nSpace saved: ${formatBytes(response.data.size_saved)}`);
      fetchDatabaseStats(); // Refresh stats
    } catch (error) {
      alert(`❌ Vacuum failed: ${error.response?.data?.detail || error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const deleteBackup = async (backupName) => {
    if (!confirm(`Are you sure you want to delete backup: ${backupName}?`)) return;
    
    try {
      await axios.delete(`${BACKEND_URL}/api/database/backups/${backupName}`);
      alert('✅ Backup deleted successfully');
      fetchBackups(); // Refresh backup list
    } catch (error) {
      alert(`❌ Delete failed: ${error.response?.data?.detail || error.message}`);
    }
  };

  const formatBytes = (bytes) => {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString();
  };

  if (!databaseStats) {
    return (
      <div className="database-loading">
        <div className="loading-spinner"></div>
        <p>Loading database information...</p>
      </div>
    );
  }

  return (
    <div className="database-manager">
      {/* Header */}
      <div className="database-header">
        <h2>🗃️ Database Management</h2>
        <div className="database-controls">
          <button 
            className="btn-primary" 
            onClick={createBackup} 
            disabled={loading}
          >
            {loading ? '⏳' : '💾'} Create Backup
          </button>
          <button 
            className="btn-secondary" 
            onClick={() => exportData()} 
            disabled={loading}
          >
            {loading ? '⏳' : '📤'} Export All Data
          </button>
          <button 
            className="btn-warning" 
            onClick={vacuumDatabase} 
            disabled={loading}
          >
            {loading ? '⏳' : '🔧'} Optimize DB
          </button>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="tab-navigation">
        <button 
          className={`tab ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          📊 Overview
        </button>
        <button 
          className={`tab ${activeTab === 'backups' ? 'active' : ''}`}
          onClick={() => setActiveTab('backups')}
        >
          💾 Backups ({backups.length})
        </button>
        <button 
          className={`tab ${activeTab === 'schema' ? 'active' : ''}`}
          onClick={() => setActiveTab('schema')}
        >
          🏗️ Schema
        </button>
        <button 
          className={`tab ${activeTab === 'integrity' ? 'active' : ''}`}
          onClick={() => setActiveTab('integrity')}
        >
          ✅ Integrity
        </button>
      </div>

      {/* Tab Content */}
      <div className="tab-content">
        {activeTab === 'overview' && (
          <div className="overview-tab">
            {/* Database Status Cards */}
            <div className="stats-grid">
              <div className="stat-card database-size">
                <div className="stat-icon">💾</div>
                <div className="stat-content">
                  <div className="stat-value">{formatBytes(databaseStats.statistics?.database_size)}</div>
                  <div className="stat-label">Database Size</div>
                </div>
              </div>
              
              <div className="stat-card total-records">
                <div className="stat-icon">📊</div>
                <div className="stat-content">
                  <div className="stat-value">{databaseStats.statistics?.total_records?.toLocaleString() || 0}</div>
                  <div className="stat-label">Total Records</div>
                </div>
              </div>
              
              <div className="stat-card table-count">
                <div className="stat-icon">🗂️</div>
                <div className="stat-content">
                  <div className="stat-value">{Object.keys(databaseStats.statistics?.tables || {}).length}</div>
                  <div className="stat-label">Tables</div>
                </div>
              </div>
              
              <div className="stat-card backup-count">
                <div className="stat-icon">🔄</div>
                <div className="stat-content">
                  <div className="stat-value">{databaseStats.statistics?.backups?.count || 0}</div>
                  <div className="stat-label">Backups</div>
                </div>
              </div>
            </div>

            {/* Configuration Status */}
            <div className="config-section">
              <h3>🔧 Configuration</h3>
              <div className="config-grid">
                <div className="config-item">
                  <span className="config-label">Auto Backup:</span>
                  <span className={`config-value ${databaseStats.statistics?.config?.auto_backup_enabled ? 'enabled' : 'disabled'}`}>
                    {databaseStats.statistics?.config?.auto_backup_enabled ? '✅ Enabled' : '❌ Disabled'}
                  </span>
                </div>
                <div className="config-item">
                  <span className="config-label">Encryption:</span>
                  <span className={`config-value ${databaseStats.statistics?.config?.encryption_enabled ? 'enabled' : 'disabled'}`}>
                    {databaseStats.statistics?.config?.encryption_enabled ? '🔒 Enabled' : '🔓 Disabled'}
                  </span>
                </div>
                <div className="config-item">
                  <span className="config-label">Backup Interval:</span>
                  <span className="config-value">{databaseStats.statistics?.config?.backup_interval_hours || 24} hours</span>
                </div>
                <div className="config-item">
                  <span className="config-label">Max Backups:</span>
                  <span className="config-value">{databaseStats.statistics?.config?.max_backups || 30}</span>
                </div>
              </div>
            </div>

            {/* Tables Overview */}
            <div className="tables-section">
              <h3>📋 Tables Overview</h3>
              <div className="tables-grid">
                {Object.entries(databaseStats.statistics?.tables || {})
                  .filter(([_, data]) => data.records > 0)
                  .sort(([,a], [,b]) => b.records - a.records)
                  .map(([tableName, data]) => (
                    <div key={tableName} className="table-card">
                      <div className="table-name">{tableName}</div>
                      <div className="table-records">{data.records.toLocaleString()} records</div>
                    </div>
                  ))
                }
              </div>
            </div>
          </div>
        )}

        {activeTab === 'backups' && (
          <div className="backups-tab">
            <div className="backups-header">
              <h3>💾 Database Backups</h3>
              <div className="backups-summary">
                Total: {backups.length} | Size: {formatBytes(backups.reduce((sum, b) => sum + b.size, 0))}
              </div>
            </div>

            <div className="backups-list">
              {backups.length === 0 ? (
                <div className="no-backups">
                  <p>No backups found. Create your first backup!</p>
                </div>
              ) : (
                backups.map((backup, index) => (
                  <div key={index} className="backup-item">
                    <div className="backup-info">
                      <div className="backup-name">📦 {backup.name}</div>
                      <div className="backup-details">
                        <span>Size: {formatBytes(backup.size)}</span>
                        <span>Created: {formatDate(backup.created_at)}</span>
                      </div>
                    </div>
                    <div className="backup-actions">
                      <a 
                        href={`${BACKEND_URL}${backup.download_url}`} 
                        className="btn-download"
                        download
                      >
                        ⬇️ Download
                      </a>
                      <button 
                        className="btn-delete"
                        onClick={() => deleteBackup(backup.name)}
                      >
                        🗑️ Delete
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {activeTab === 'schema' && (
          <div className="schema-tab">
            <h3>🏗️ Database Schema</h3>
            <div className="schema-modules">
              {[
                { name: 'Core System', tables: ['system_config', 'user_sessions', 'activity_log'] },
                { name: 'Network Scanning', tables: ['port_scans', 'network_discovery', 'service_enumeration'] },
                { name: 'Brute Force', tables: ['auth_attacks', 'hash_cracking', 'wordlists'] },
                { name: 'WiFi Security', tables: ['wifi_networks', 'wifi_handshakes', 'wifi_clients'] },
                { name: 'MITM Attacks', tables: ['mitm_sessions', 'intercepted_credentials', 'traffic_analysis'] },
                { name: 'Digital Forensics', tables: ['file_analysis', 'log_analysis', 'evidence_chain'] },
                { name: 'Reports', tables: ['reports', 'report_templates'] },
                { name: 'OSINT', tables: ['osint_results', 'threat_intelligence'] },
                { name: 'Vulnerabilities', tables: ['vulnerabilities', 'cve_database'] },
                { name: 'Tools', tables: ['tools_status', 'tool_executions'] }
              ].map((module, index) => (
                <div key={index} className="schema-module">
                  <div className="module-header">
                    <h4>{module.name}</h4>
                    <button 
                      className="export-module-btn"
                      onClick={() => exportData([module.name.toLowerCase().replace(' ', '')])}
                    >
                      📤 Export Module
                    </button>
                  </div>
                  <div className="module-tables">
                    {module.tables.map(tableName => {
                      const tableData = databaseStats.statistics?.tables?.[tableName];
                      return (
                        <div key={tableName} className="schema-table">
                          <span className="table-name">{tableName}</span>
                          <span className="table-records">
                            {tableData ? `${tableData.records} records` : '0 records'}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'integrity' && (
          <div className="integrity-tab">
            <h3>✅ Database Integrity</h3>
            
            <div className="integrity-status">
              <div className={`integrity-card ${integrity?.healthy ? 'healthy' : 'unhealthy'}`}>
                <div className="integrity-icon">
                  {integrity?.healthy ? '✅' : '❌'}
                </div>
                <div className="integrity-content">
                  <div className="integrity-title">
                    {integrity?.healthy ? 'Database Healthy' : 'Issues Found'}
                  </div>
                  <div className="integrity-subtitle">
                    Last checked: {integrity ? formatDate(integrity.checked_at) : 'Never'}
                  </div>
                </div>
                <button 
                  className="btn-check"
                  onClick={checkIntegrity}
                >
                  🔍 Check Again
                </button>
              </div>
            </div>

            {integrity?.integrity_check && (
              <div className="integrity-details">
                <h4>Integrity Check Results:</h4>
                <div className="integrity-results">
                  {integrity.integrity_check.map((result, index) => (
                    <div key={index} className="integrity-result">
                      {result === 'ok' ? '✅' : '❌'} {result}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {integrity?.foreign_key_violations && integrity.foreign_key_violations.length > 0 && (
              <div className="fk-violations">
                <h4>Foreign Key Violations:</h4>
                <div className="violations-list">
                  {integrity.foreign_key_violations.map((violation, index) => (
                    <div key={index} className="violation-item">
                      ❌ Table: {violation.table}, Row: {violation.rowid}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default DatabaseManager;