import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import DatabaseManager from './DatabaseManager';
import StealthDashboard from './StealthDashboard';
import StealthControl from './StealthControl';
import EvasionDashboard from './EvasionDashboard';
import NetworkScanner from './NetworkScanner';
import OSINTCollector from './OSINTCollector';
import BruteForceModule from './BruteForceModule';
import VulnerabilityScanner from './VulnerabilityScanner';
import ForensicsModule from './ForensicsModule';
import ExploitationModule from './ExploitationModule';
import ProxyConfigManager from './ProxyConfigManager';
import './App.css';
import './EvasionDashboard.css';
import './ForensicsModule.css';
import './ExploitationModule.css';

// Backend URL - Auto-detect portable environment
const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

// For local testing, use localhost if external URL fails
const getBackendURL = () => {
  // Try to detect if we're in local development
  if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
    return 'http://localhost:8001';
  }
  return BACKEND_URL;
};

// API client configuration
const api = axios.create({
  baseURL: getBackendURL(),
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  }
});

// WebSocket connections
let wsTerminal = null;
let wsMonitoring = null;

// Terminal Component
const TerminalComponent = () => {
  const [commands, setCommands] = useState([]);
  const [currentCommand, setCurrentCommand] = useState('');
  const [isExecuting, setIsExecuting] = useState(false);
  const [history, setHistory] = useState([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const terminalRef = useRef(null);

  useEffect(() => {
    loadTerminalHistory();
    setupWebSocket();
    return () => {
      if (wsTerminal) wsTerminal.close();
    };
  }, []);

  const loadTerminalHistory = async () => {
    try {
      const response = await api.get('/api/terminal/history?limit=20');
      setHistory(response.data.history.map(h => h.command));
    } catch (error) {
      console.error('Failed to load terminal history:', error);
    }
  };

  const setupWebSocket = () => {
    const wsUrl = BACKEND_URL.replace('http', 'ws') + '/ws/terminal';
    wsTerminal = new WebSocket(wsUrl);
    
    wsTerminal.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'command_result') {
        setCommands(prev => [...prev, {
          id: Date.now(),
          command: data.command,
          output: data.stdout + data.stderr,
          exitCode: data.exit_code,
          timestamp: data.timestamp,
          type: data.exit_code === 0 ? 'success' : 'error'
        }]);
      }
      setIsExecuting(false);
    };

    wsTerminal.onerror = () => {
      console.error('WebSocket connection failed, falling back to HTTP');
    };
  };

  const executeCommand = async () => {
    if (!currentCommand.trim() || isExecuting) return;

    const command = currentCommand.trim();
    setIsExecuting(true);
    
    // Add command to history
    if (!history.includes(command)) {
      setHistory(prev => [...prev, command]);
    }
    setHistoryIndex(-1);

    // Add command to display
    setCommands(prev => [...prev, {
      id: Date.now(),
      command: command,
      output: 'Executing...',
      type: 'executing',
      timestamp: new Date().toISOString()
    }]);

    try {
      if (wsTerminal && wsTerminal.readyState === WebSocket.OPEN) {
        // Use WebSocket for real-time execution
        wsTerminal.send(JSON.stringify({ command }));
      } else {
        // Fallback to HTTP API
        const response = await api.post('/api/terminal/execute', {
          command: command,
          working_directory: null
        });

        setCommands(prev => prev.map(cmd => 
          cmd.command === command && cmd.type === 'executing' 
            ? {
                ...cmd,
                output: response.data.stdout + response.data.stderr,
                exitCode: response.data.exit_code,
                type: response.data.exit_code === 0 ? 'success' : 'error'
              }
            : cmd
        ));
        setIsExecuting(false);
      }
    } catch (error) {
      setCommands(prev => prev.map(cmd => 
        cmd.command === command && cmd.type === 'executing' 
          ? {
              ...cmd,
              output: `Error: ${error.response?.data?.detail || error.message}`,
              type: 'error'
            }
          : cmd
      ));
      setIsExecuting(false);
    }

    setCurrentCommand('');
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      executeCommand();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (historyIndex < history.length - 1) {
        const newIndex = historyIndex + 1;
        setHistoryIndex(newIndex);
        setCurrentCommand(history[history.length - 1 - newIndex]);
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex > 0) {
        const newIndex = historyIndex - 1;
        setHistoryIndex(newIndex);
        setCurrentCommand(history[history.length - 1 - newIndex]);
      } else if (historyIndex === 0) {
        setHistoryIndex(-1);
        setCurrentCommand('');
      }
    }
  };

  const clearTerminal = () => {
    setCommands([]);
  };

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [commands]);

  return (
    <div className="terminal-container">
      <div className="terminal-header">
        <div className="terminal-title">
          <span className="terminal-icon">⚡</span>
          <span>Integrated Terminal</span>
        </div>
        <div className="terminal-controls">
          <button className="terminal-btn" onClick={clearTerminal} title="Clear">
            🗑️
          </button>
          <button className="terminal-btn" onClick={loadTerminalHistory} title="Refresh">
            🔄
          </button>
        </div>
      </div>
      
      <div className="terminal-body" ref={terminalRef}>
        {commands.map((cmd) => (
          <div key={cmd.id} className={`terminal-entry ${cmd.type}`}>
            <div className="terminal-command">
              <span className="terminal-prompt">cyber@portable $</span>
              <span className="command-text">{cmd.command}</span>
            </div>
            <div className="terminal-output">
              <pre>{cmd.output}</pre>
            </div>
          </div>
        ))}
      </div>

      <div className="terminal-input">
        <span className="terminal-prompt">cyber@portable $</span>
        <input
          type="text"
          value={currentCommand}
          onChange={(e) => setCurrentCommand(e.target.value)}
          onKeyDown={handleKeyPress}
          placeholder="Enter command..."
          disabled={isExecuting}
          className="command-input"
          autoFocus
        />
        {isExecuting && <span className="executing-indicator">⚡</span>}
      </div>
    </div>
  );
};

// System Monitoring Component
const SystemMonitoring = () => {
  const [metrics, setMetrics] = useState(null);
  const [processes, setProcesses] = useState([]);
  const [autoRefresh, setAutoRefresh] = useState(true);

  useEffect(() => {
    fetchSystemMetrics();
    setupMonitoringWebSocket();
    
    const interval = setInterval(() => {
      if (autoRefresh) {
        fetchSystemMetrics();
      }
    }, 5000);

    return () => {
      clearInterval(interval);
      if (wsMonitoring) wsMonitoring.close();
    };
  }, [autoRefresh]);

  const fetchSystemMetrics = async () => {
    try {
      const [metricsResponse, processesResponse] = await Promise.all([
        api.get('/api/system/metrics'),
        api.get('/api/system/processes')
      ]);
      
      setMetrics(metricsResponse.data.metrics);
      setProcesses(processesResponse.data.processes.slice(0, 10)); // Top 10
    } catch (error) {
      console.error('Failed to fetch system metrics:', error);
    }
  };

  const setupMonitoringWebSocket = () => {
    const wsUrl = BACKEND_URL.replace('http', 'ws') + '/ws/monitoring';
    wsMonitoring = new WebSocket(wsUrl);
    
    wsMonitoring.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'system_update') {
        setMetrics(data.metrics);
        if (data.processes) {
          setProcesses(data.processes);
        }
      }
    };

    wsMonitoring.onerror = () => {
      console.error('Monitoring WebSocket connection failed');
    };
  };

  const formatBytes = (bytes) => {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatUptime = (seconds) => {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    return `${days}d ${hours}h ${minutes}m`;
  };

  if (!metrics) {
    return (
      <div className="monitoring-loading">
        <div className="loading-spinner"></div>
        <p>Loading system metrics...</p>
      </div>
    );
  }

  return (
    <div className="monitoring-container">
      <div className="monitoring-header">
        <h3>🖥️ System Monitoring</h3>
        <div className="monitoring-controls">
          <label className="auto-refresh-toggle">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            <span>Auto Refresh</span>
          </label>
          <button className="refresh-btn" onClick={fetchSystemMetrics}>
            🔄 Refresh
          </button>
        </div>
      </div>

      <div className="metrics-grid">
        {/* CPU Metrics */}
        <div className="metric-card">
          <div className="metric-header">
            <span className="metric-icon">⚡</span>
            <span className="metric-title">CPU Usage</span>
          </div>
          <div className="metric-value">{metrics.cpu?.percent?.toFixed(1) || 0}%</div>
          <div className="metric-details">
            <div>Cores: {metrics.cpu?.count || 'N/A'}</div>
            {metrics.cpu?.freq && (
              <div>Frequency: {(metrics.cpu.freq.current / 1000).toFixed(2)} GHz</div>
            )}
          </div>
          <div className="progress-bar">
            <div 
              className="progress-fill cpu" 
              style={{ width: `${metrics.cpu?.percent || 0}%` }}
            ></div>
          </div>
        </div>

        {/* Memory Metrics */}
        <div className="metric-card">
          <div className="metric-header">
            <span className="metric-icon">🧠</span>
            <span className="metric-title">Memory Usage</span>
          </div>
          <div className="metric-value">{metrics.memory?.percent?.toFixed(1) || 0}%</div>
          <div className="metric-details">
            <div>Used: {formatBytes(metrics.memory?.used)}</div>
            <div>Total: {formatBytes(metrics.memory?.total)}</div>
          </div>
          <div className="progress-bar">
            <div 
              className="progress-fill memory" 
              style={{ width: `${metrics.memory?.percent || 0}%` }}
            ></div>
          </div>
        </div>

        {/* Disk Metrics */}
        <div className="metric-card">
          <div className="metric-header">
            <span className="metric-icon">💾</span>
            <span className="metric-title">Disk Usage</span>
          </div>
          <div className="metric-value">{metrics.disk?.percent?.toFixed(1) || 0}%</div>
          <div className="metric-details">
            <div>Used: {formatBytes(metrics.disk?.used)}</div>
            <div>Free: {formatBytes(metrics.disk?.free)}</div>
          </div>
          <div className="progress-bar">
            <div 
              className="progress-fill disk" 
              style={{ width: `${metrics.disk?.percent || 0}%` }}
            ></div>
          </div>
        </div>

        {/* System Info */}
        <div className="metric-card">
          <div className="metric-header">
            <span className="metric-icon">📊</span>
            <span className="metric-title">System Info</span>
          </div>
          <div className="metric-details system-info">
            <div>Uptime: {formatUptime(metrics.uptime || 0)}</div>
            <div>Boot: {new Date((metrics.boot_time || 0) * 1000).toLocaleString()}</div>
            {metrics.network && (
              <>
                <div>↗️ Sent: {formatBytes(metrics.network.bytes_sent)}</div>
                <div>↙️ Recv: {formatBytes(metrics.network.bytes_recv)}</div>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Process List */}
      <div className="processes-section">
        <h4>🔄 Top Processes</h4>
        <div className="processes-table">
          <div className="process-header">
            <div>PID</div>
            <div>Name</div>
            <div>CPU%</div>
            <div>Memory%</div>
            <div>Status</div>
          </div>
          {processes.map((proc, index) => (
            <div key={proc.pid || index} className="process-row">
              <div>{proc.pid}</div>
              <div className="process-name">{proc.name}</div>
              <div className="cpu-usage">{proc.cpu_percent?.toFixed(1) || 0}%</div>
              <div className="memory-usage">{proc.memory_percent?.toFixed(1) || 0}%</div>
              <div className={`process-status ${proc.status?.toLowerCase()}`}>
                {proc.status || 'unknown'}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

// Advanced Logs Viewer Component
const LogsViewer = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [filters, setFilters] = useState({
    level: '',
    search: '',
    lines: 100
  });
  const [autoRefresh, setAutoRefresh] = useState(false);
  const logsRef = useRef(null);

  useEffect(() => {
    fetchLogs();
  }, []);

  useEffect(() => {
    let interval;
    if (autoRefresh) {
      interval = setInterval(fetchLogs, 3000);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [autoRefresh, filters]);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (filters.lines) params.append('lines', filters.lines);
      if (filters.level) params.append('level', filters.level);
      if (filters.search) params.append('search', filters.search);

      const response = await api.get(`/api/logs?${params}`);
      setLogs(response.data.logs);
    } catch (error) {
      console.error('Failed to fetch logs:', error);
    } finally {
      setLoading(false);
    }
  };

  const scrollToBottom = () => {
    if (logsRef.current) {
      logsRef.current.scrollTop = logsRef.current.scrollHeight;
    }
  };

  const clearLogs = () => {
    setLogs([]);
  };

  const downloadLogs = () => {
    const logsText = logs.map(log => log.raw).join('\n');
    const blob = new Blob([logsText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cybersec-logs-${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getLogLevelClass = (level) => {
    const levelLower = level?.toLowerCase();
    if (levelLower?.includes('error')) return 'log-error';
    if (levelLower?.includes('warn')) return 'log-warning';
    if (levelLower?.includes('info')) return 'log-info';
    if (levelLower?.includes('debug')) return 'log-debug';
    return 'log-default';
  };

  return (
    <div className="logs-container">
      <div className="logs-header">
        <h3>📋 System Logs</h3>
        <div className="logs-controls">
          <div className="logs-filters">
            <select
              value={filters.level}
              onChange={(e) => setFilters(prev => ({ ...prev, level: e.target.value }))}
            >
              <option value="">All Levels</option>
              <option value="ERROR">Error</option>
              <option value="WARNING">Warning</option>
              <option value="INFO">Info</option>
              <option value="DEBUG">Debug</option>
            </select>
            
            <input
              type="text"
              placeholder="Search logs..."
              value={filters.search}
              onChange={(e) => setFilters(prev => ({ ...prev, search: e.target.value }))}
              className="search-input"
            />
            
            <select
              value={filters.lines}
              onChange={(e) => setFilters(prev => ({ ...prev, lines: parseInt(e.target.value) }))}
            >
              <option value={50}>50 lines</option>
              <option value={100}>100 lines</option>
              <option value={500}>500 lines</option>
              <option value={1000}>1000 lines</option>
            </select>
          </div>

          <div className="logs-actions">
            <label className="auto-refresh-toggle">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
              />
              <span>Auto</span>
            </label>
            <button onClick={fetchLogs} disabled={loading} title="Refresh">
              🔄
            </button>
            <button onClick={scrollToBottom} title="Scroll to bottom">
              ⬇️
            </button>
            <button onClick={downloadLogs} title="Download logs">
              💾
            </button>
            <button onClick={clearLogs} title="Clear display">
              🗑️
            </button>
          </div>
        </div>
      </div>

      <div className="logs-stats">
        <span>Total lines: {logs.length}</span>
        {loading && <span className="loading-indicator">Loading...</span>}
      </div>

      <div className="logs-body" ref={logsRef}>
        {logs.length === 0 ? (
          <div className="no-logs">
            <p>No logs found matching current filters</p>
          </div>
        ) : (
          logs.map((log, index) => (
            <div key={index} className={`log-entry ${getLogLevelClass(log.level)}`}>
              <span className="log-timestamp">{log.timestamp}</span>
              <span className="log-level">{log.level}</span>
              <span className="log-message">{log.message}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

// Main Dashboard Component (Updated)
const Dashboard = ({ systemInfo, onRefresh }) => {
  const [activeModule, setActiveModule] = useState('overview');
  
  const modules = [
    { id: 'overview', name: 'Overview', icon: '🏠' },
    { id: 'terminal', name: 'Terminal', icon: '⚡' },
    { id: 'monitoring', name: 'System Monitor', icon: '📊' },
    { id: 'logs', name: 'Logs Viewer', icon: '📋' },
    { id: 'database', name: 'Database Manager', icon: '🗃️' },
    { id: 'network_scanner', name: 'Network Scanner', icon: '🔍' },
    { id: 'osint-collector', name: 'OSINT Collector', icon: '🕵️‍♀️' },
    { id: 'vulnerability-scanner', name: 'Vulnerability Scanner', icon: '🛡️' },
    { id: 'exploitation', name: 'Exploitation Framework', icon: '⚔️' },
    { id: 'scanning', name: 'Legacy Scanner', icon: '🔍' },
    { id: 'bruteforce', name: 'Brute Force', icon: '🔨' },
    { id: 'wifi', name: 'WiFi Security', icon: '📡' },
    { id: 'mitm', name: 'MITM Attacks', icon: '🕷️' },
    { id: 'forensics', name: 'Digital Forensics', icon: '🔬' },
    { id: 'reports', name: 'Reports', icon: '📊' },
    { id: 'stealth', name: 'Stealth Dashboard', icon: '🕵️' },
    { id: 'stealth-control', name: 'Stealth Control', icon: '🛡️' },
    { id: 'evasion', name: 'Evasion Dashboard', icon: '🎭' },
    { id: 'proxy-config', name: 'Proxy Configuration', icon: '🌐' },
    { id: 'settings', name: 'Settings', icon: '⚙️' }
  ];

  return (
    <div className="dashboard-container">
      {/* Sidebar Navigation */}
      <div className="sidebar">
        <div className="logo">
          <span className="logo-icon">🛡️</span>
          <span className="logo-text">CyberSec Assistant</span>
          <span className="portable-badge">PORTABLE V1.3</span>
        </div>
        
        <nav className="nav-menu">
          {modules.map(module => (
            <button
              key={module.id}
              className={`nav-item ${activeModule === module.id ? 'active' : ''}`}
              onClick={() => setActiveModule(module.id)}
            >
              <span className="nav-icon">{module.icon}</span>
              <span className="nav-text">{module.name}</span>
            </button>
          ))}
        </nav>
        
        {/* System Status */}
        <div className="system-status">
          <div className="status-header">
            <span className="status-icon">💻</span>
            <span>System Status</span>
          </div>
          <div className="status-info">
            <div className="status-item">
              <span className="status-label">Platform:</span>
              <span className="status-value">{systemInfo?.platform || 'Unknown'}</span>
            </div>
            <div className="status-item">
              <span className="status-label">Version:</span>
              <span className="status-value">v1.2.0</span>
            </div>
            <div className="status-item">
              <span className="status-label">Features:</span>
              <span className="status-value">Terminal, Monitor, Logs</span>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="main-content">
        <div className="content-header">
          <h1 className="module-title">
            {modules.find(m => m.id === activeModule)?.icon} {modules.find(m => m.id === activeModule)?.name}
          </h1>
          <div className="header-actions">
            <button className="refresh-btn" onClick={onRefresh} title="Refresh">
              🔄
            </button>
            <div className="connection-status online">
              <span className="status-dot"></span>
              <span>Connected</span>
            </div>
          </div>
        </div>

        <div className="content-body">
          {activeModule === 'overview' && <OverviewModule systemInfo={systemInfo} />}
          {activeModule === 'terminal' && <TerminalComponent />}
          {activeModule === 'monitoring' && <SystemMonitoring />}
          {activeModule === 'logs' && <LogsViewer />}
          {activeModule === 'database' && <DatabaseManager />}
          {activeModule === 'network_scanner' && <NetworkScanner />}
          {activeModule === 'osint-collector' && <OSINTCollector />}
          {activeModule === 'vulnerability-scanner' && <VulnerabilityScanner />}
          {activeModule === 'exploitation' && <ExploitationModule />}
          {activeModule === 'scanning' && <ScanningModule />}
          {activeModule === 'bruteforce' && <BruteForceModule />}
          {activeModule === 'wifi' && <WiFiModule />}
          {activeModule === 'mitm' && <MITMModule />}
          {activeModule === 'forensics' && <ForensicsModule />}
          {activeModule === 'reports' && <ReportsModule />}
          {activeModule === 'stealth' && <StealthDashboard />}
          {activeModule === 'stealth-control' && <StealthControl />}
          {activeModule === 'evasion' && <EvasionDashboard />}
          {activeModule === 'proxy-config' && <ProxyConfigManager />}
          {activeModule === 'settings' && <SettingsModule systemInfo={systemInfo} />}
        </div>
      </div>
    </div>
  );
};

// Overview Module (Updated with new features)
const OverviewModule = ({ systemInfo }) => {
  const [stats, setStats] = useState({
    totalScans: 0,
    activeTools: 0,
    successRate: 0,
    lastActivity: 'Never'
  });

  useEffect(() => {
    fetchStats();
  }, []);

  const fetchStats = async () => {
    try {
      const response = await api.get('/api/scans');
      const scans = response.data.scans || [];
      setStats({
        totalScans: scans.length,
        activeTools: 4, // TODO: Get from tools status
        successRate: scans.length > 0 ? Math.round((scans.filter(s => s.status === 'completed').length / scans.length) * 100) : 0,
        lastActivity: scans.length > 0 ? new Date(scans[0].created_at).toLocaleString() : 'Never'
      });
    } catch (error) {
      console.error('Failed to fetch stats:', error);
    }
  };

  return (
    <div className="overview-module">
      {/* Quick Stats */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon">📊</div>
          <div className="stat-content">
            <div className="stat-value">{stats.totalScans}</div>
            <div className="stat-label">Total Scans</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">🛠️</div>
          <div className="stat-content">
            <div className="stat-value">{stats.activeTools}</div>
            <div className="stat-label">Active Tools</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">✅</div>
          <div className="stat-content">
            <div className="stat-value">{stats.successRate}%</div>
            <div className="stat-label">Success Rate</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">🚀</div>
          <div className="stat-content">
            <div className="stat-value">V1.2</div>
            <div className="stat-label">Version</div>
          </div>
        </div>
      </div>

      {/* New Features Highlight */}
      <div className="features-highlight">
        <h3>🌟 New Features in v1.2</h3>
        <div className="features-grid">
          <div className="feature-card">
            <div className="feature-icon">⚡</div>
            <div className="feature-content">
              <h4>Integrated Terminal</h4>
              <p>Execute commands directly in the interface with real-time WebSocket support</p>
            </div>
          </div>
          <div className="feature-card">
            <div className="feature-icon">📊</div>
            <div className="feature-content">
              <h4>System Monitoring</h4>
              <p>Real-time CPU, memory, disk usage and process monitoring</p>
            </div>
          </div>
          <div className="feature-card">
            <div className="feature-icon">📋</div>
            <div className="feature-content">
              <h4>Advanced Logs</h4>
              <p>Filter, search, and analyze application logs with auto-refresh</p>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="quick-actions">
        <h3>Quick Actions</h3>
        <div className="actions-grid">
          <button className="action-btn">
            <span className="action-icon">⚡</span>
            <span className="action-text">Open Terminal</span>
          </button>
          <button className="action-btn">
            <span className="action-icon">📊</span>
            <span className="action-text">System Monitor</span>
          </button>
          <button className="action-btn">
            <span className="action-icon">📋</span>
            <span className="action-text">View Logs</span>
          </button>
          <button className="action-btn">
            <span className="action-icon">🔍</span>
            <span className="action-text">Port Scan</span>
          </button>
        </div>
      </div>

      {/* System Information */}
      <div className="system-info-card">
        <h3>System Information</h3>
        <div className="info-grid">
          <div className="info-item">
            <span className="info-label">Platform:</span>
            <span className="info-value">{systemInfo?.platform || 'Unknown'}</span>
          </div>
          <div className="info-item">
            <span className="info-label">Python Version:</span>
            <span className="info-value">{systemInfo?.python_version?.split(' ')[0] || 'Unknown'}</span>
          </div>
          <div className="info-item">
            <span className="info-label">Portable Directory:</span>
            <span className="info-value portable-path">{systemInfo?.portable_dir || 'Unknown'}</span>
          </div>
          <div className="info-item">
            <span className="info-label">Database:</span>
            <span className="info-value">{systemInfo?.database_path ? 'Connected' : 'Disconnected'}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

// Placeholder modules (to be implemented)
const ScanningModule = () => (
  <div className="module-placeholder">
    <div className="placeholder-content">
      <div className="placeholder-icon">🔍</div>
      <h3>Network Scanning Module</h3>
      <p>Port scanning, service detection, and network discovery tools</p>
      <div className="coming-soon">Coming Soon</div>
    </div>
  </div>
);

const WiFiModule = () => (
  <div className="module-placeholder">
    <div className="placeholder-content">
      <div className="placeholder-icon">📡</div>
      <h3>WiFi Security Module</h3>
      <p>WPA/WPA2/WPA3 attacks, evil twin, and wireless reconnaissance</p>
      <div className="coming-soon">Coming Soon</div>
    </div>
  </div>
);

const MITMModule = () => (
  <div className="module-placeholder">
    <div className="placeholder-content">
      <div className="placeholder-icon">🕷️</div>
      <h3>MITM Attacks Module</h3>
      <p>ARP poisoning, SSL stripping, and traffic interception</p>
      <div className="coming-soon">Coming Soon</div>
    </div>
  </div>
);



const ReportsModule = () => (
  <div className="module-placeholder">
    <div className="placeholder-content">
      <div className="placeholder-icon">📊</div>
      <h3>Reports Module</h3>
      <p>Professional security reports and documentation generation</p>
      <div className="coming-soon">Coming Soon</div>
    </div>
  </div>
);

const SettingsModule = ({ systemInfo }) => (
  <div className="settings-module">
    <div className="settings-section">
      <h3>Application Settings</h3>
      <div className="settings-grid">
        <div className="setting-item">
          <label>Theme</label>
          <select defaultValue="dark">
            <option value="dark">Dark (Cybersec)</option>
            <option value="light">Light</option>
          </select>
        </div>
        <div className="setting-item">
          <label>Auto-save Results</label>
          <input type="checkbox" defaultChecked />
        </div>
        <div className="setting-item">
          <label>Log Level</label>
          <select defaultValue="info">
            <option value="debug">Debug</option>
            <option value="info">Info</option>
            <option value="warning">Warning</option>
            <option value="error">Error</option>
          </select>
        </div>
        <div className="setting-item">
          <label>Terminal Auto-scroll</label>
          <input type="checkbox" defaultChecked />
        </div>
        <div className="setting-item">
          <label>Monitoring Auto-refresh</label>
          <input type="checkbox" defaultChecked />
        </div>
        <div className="setting-item">
          <label>WebSocket Enabled</label>
          <input type="checkbox" defaultChecked />
        </div>
      </div>
    </div>
    
    <div className="settings-section">
      <h3>System Information</h3>
      <div className="system-details">
        <pre>{JSON.stringify(systemInfo, null, 2)}</pre>
      </div>
    </div>
  </div>
);

// Main App Component (same as before)
const App = () => {
  const [systemInfo, setSystemInfo] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    checkConnection();
    const interval = setInterval(checkConnection, 120000); // Check every 2 minutes instead of 30s
    return () => clearInterval(interval);
  }, []);

  const checkConnection = async () => {
    try {
      setLoading(true);
      
      // Test backend connection
      const healthResponse = await api.get('/api/health');
      const systemResponse = await api.get('/api/system/info');
      
      setSystemInfo(systemResponse.data);
      setIsConnected(true);
      setError(null);
      
    } catch (err) {
      console.error('Backend connection failed:', err);
      setIsConnected(false);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (loading && !systemInfo) {
    return (
      <div className="loading-screen">
        <div className="loading-content">
          <div className="loading-spinner"></div>
          <h2>🛡️ CyberSec Assistant v1.2</h2>
          <p>Initializing portable cybersecurity toolkit...</p>
          <div className="loading-steps">
            <div className="step active">Connecting to backend</div>
            <div className="step">Loading system information</div>
            <div className="step">Initializing terminal & monitoring</div>
          </div>
        </div>
      </div>
    );
  }

  if (error && !isConnected) {
    return (
      <div className="error-screen">
        <div className="error-content">
          <div className="error-icon">❌</div>
          <h2>Connection Failed</h2>
          <p>Unable to connect to the backend server.</p>
          <div className="error-details">
            <strong>Error:</strong> {error}
          </div>
          <div className="error-help">
            <h4>Troubleshooting:</h4>
            <ul>
              <li>Ensure the backend server is running (python server.py)</li>
              <li>Check if port 8001 is available</li>
              <li>Verify the portable directory structure</li>
              <li>Try running: pip install psutil websockets</li>
            </ul>
          </div>
          <button className="retry-btn" onClick={checkConnection}>
            🔄 Retry Connection
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="App">
      <Dashboard 
        systemInfo={systemInfo} 
        onRefresh={checkConnection}
      />
    </div>
  );
};

export default App;