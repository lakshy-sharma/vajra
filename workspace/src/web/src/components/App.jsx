import React, { useState, useEffect } from 'react';
import { AlertTriangle, Shield, Activity, FileText, Cpu, Clock, Search, ChevronLeft, ChevronRight } from 'lucide-react';

const API_BASE = '/api';

export default function VajraDashboard() {
  const [stats, setStats] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [fileScans, setFileScans] = useState({ data: [], page: 1, total_pages: 1 });
  const [processScans, setProcessScans] = useState({ data: [], page: 1, total_pages: 1 });
  const [recentFiles, setRecentFiles] = useState([]);
  const [recentProcesses, setRecentProcesses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [showOnlyMatches, setShowOnlyMatches] = useState(false);

  useEffect(() => {
    fetchStats();
    fetchRecentActivity();
    const interval = setInterval(() => {
      fetchStats();
      fetchRecentActivity();
    }, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (activeTab === 'files') {
      fetchFileScans(1);
    } else if (activeTab === 'processes') {
      fetchProcessScans(1);
    }
  }, [activeTab, showOnlyMatches]);

  const fetchStats = async () => {
    try {
      const response = await fetch(`${API_BASE}/stats`);
      const data = await response.json();
      setStats(data);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch stats:', error);
      setLoading(false);
    }
  };

  const fetchRecentActivity = async () => {
    try {
      const [filesRes, procsRes] = await Promise.all([
        fetch(`${API_BASE}/recent/files?limit=5`),
        fetch(`${API_BASE}/recent/processes?limit=5`)
      ]);
      setRecentFiles(await filesRes.json());
      setRecentProcesses(await procsRes.json());
    } catch (error) {
      console.error('Failed to fetch recent activity:', error);
    }
  };

  const fetchFileScans = async (page) => {
    try {
      const endpoint = showOnlyMatches ? 'files/matches' : 'files';
      const response = await fetch(`${API_BASE}/${endpoint}?page=${page}&page_size=20`);
      const data = await response.json();
      setFileScans(data);
    } catch (error) {
      console.error('Failed to fetch file scans:', error);
    }
  };

  const fetchProcessScans = async (page) => {
    try {
      const endpoint = showOnlyMatches ? 'processes/matches' : 'processes';
      const response = await fetch(`${API_BASE}/${endpoint}?page=${page}&page_size=20`);
      const data = await response.json();
      setProcessScans(data);
    } catch (error) {
      console.error('Failed to fetch process scans:', error);
    }
  };

  const formatTimestamp = (timestamp) => {
    if (!timestamp) return 'Never';
    return new Date(timestamp * 1000).toLocaleString();
  };

  const parseYaraResults = (yaraResults) => {
    try {
      const results = JSON.parse(yaraResults);
      return Array.isArray(results) ? results : [];
    } catch {
      return [];
    }
  };

  const filteredFileScans = fileScans.data.filter(scan =>
    scan.filepath.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredProcessScans = processScans.data.filter(scan =>
    scan.process_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    scan.cmdline.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-white text-xl">Loading Vajra Dashboard...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700 shadow-lg">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Shield className="w-8 h-8 text-blue-400" />
              <h1 className="text-2xl font-bold text-white">Vajra Security Monitor</h1>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2 text-sm text-gray-400">
                <Activity className="w-4 h-4" />
                <span>Live Monitoring Active</span>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="bg-gray-800 border-b border-gray-700">
        <div className="container mx-auto px-6">
          <div className="flex space-x-1">
            {[
              { id: 'overview', label: 'Overview', icon: Activity },
              { id: 'files', label: 'File Scans', icon: FileText },
              { id: 'processes', label: 'Process Scans', icon: Cpu }
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-2 px-6 py-3 border-b-2 transition-colors ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-400'
                    : 'border-transparent text-gray-400 hover:text-gray-300'
                }`}
              >
                <tab.icon className="w-4 h-4" />
                <span>{tab.label}</span>
              </button>
            ))}
          </div>
        </div>
      </nav>

      <div className="container mx-auto px-6 py-8">
        {/* Overview Tab */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              <StatCard
                title="Total File Scans"
                value={stats?.total_file_scans || 0}
                icon={FileText}
                color="blue"
              />
              <StatCard
                title="Files with Threats"
                value={stats?.files_with_matches || 0}
                icon={AlertTriangle}
                color="red"
              />
              <StatCard
                title="Total Process Scans"
                value={stats?.total_process_scans || 0}
                icon={Cpu}
                color="green"
              />
              <StatCard
                title="Processes with Threats"
                value={stats?.processes_with_matches || 0}
                icon={AlertTriangle}
                color="red"
              />
              <StatCard
                title="Last File Scan"
                value={formatTimestamp(stats?.last_file_scan)}
                icon={Clock}
                color="purple"
                isTime
              />
              <StatCard
                title="Last Process Scan"
                value={formatTimestamp(stats?.last_process_scan)}
                icon={Clock}
                color="purple"
                isTime
              />
            </div>

            {/* Recent Activity */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <RecentActivity
                title="Recent File Scans"
                items={recentFiles}
                type="file"
                formatTimestamp={formatTimestamp}
                parseYaraResults={parseYaraResults}
              />
              <RecentActivity
                title="Recent Process Scans"
                items={recentProcesses}
                type="process"
                formatTimestamp={formatTimestamp}
                parseYaraResults={parseYaraResults}
              />
            </div>
          </div>
        )}

        {/* File Scans Tab */}
        {activeTab === 'files' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold text-white">File Scan Results</h2>
              <div className="flex items-center space-x-4">
                <label className="flex items-center space-x-2 text-sm cursor-pointer">
                  <input
                    type="checkbox"
                    checked={showOnlyMatches}
                    onChange={(e) => setShowOnlyMatches(e.target.checked)}
                    className="rounded bg-gray-700 border-gray-600"
                  />
                  <span>Show only threats</span>
                </label>
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                  <input
                    type="text"
                    placeholder="Search files..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>
            </div>

            <div className="bg-gray-800 rounded-lg shadow-lg overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-gray-700">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                        File Path
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                        Scan Time
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                        Matches
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-700">
                    {filteredFileScans.map((scan) => {
                      const matches = parseYaraResults(scan.yara_results);
                      return (
                        <tr key={scan.id} className="hover:bg-gray-750 transition-colors">
                          <td className="px-6 py-4">
                            <div className="text-sm text-gray-300 font-mono break-all">
                              {scan.filepath}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm text-gray-400">
                              {formatTimestamp(scan.lastscan_time)}
                            </div>
                          </td>
                          <td className="px-6 py-4">
                            {matches.length > 0 ? (
                              <div className="space-y-1">
                                {matches.map((match, idx) => (
                                  <div
                                    key={idx}
                                    className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-red-900 text-red-200 mr-2"
                                  >
                                    <AlertTriangle className="w-3 h-3 mr-1" />
                                    {match.Rule}
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <span className="text-sm text-green-400">Clean</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              <Pagination
                currentPage={fileScans.page}
                totalPages={fileScans.total_pages}
                onPageChange={(page) => fetchFileScans(page)}
              />
            </div>
          </div>
        )}

        {/* Process Scans Tab */}
        {activeTab === 'processes' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold text-white">Process Scan Results</h2>
              <div className="flex items-center space-x-4">
                <label className="flex items-center space-x-2 text-sm cursor-pointer">
                  <input
                    type="checkbox"
                    checked={showOnlyMatches}
                    onChange={(e) => setShowOnlyMatches(e.target.checked)}
                    className="rounded bg-gray-700 border-gray-600"
                  />
                  <span>Show only threats</span>
                </label>
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                  <input
                    type="text"
                    placeholder="Search processes..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>
            </div>

            <div className="bg-gray-800 rounded-lg shadow-lg overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-gray-700">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                        PID
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                        Process Name
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                        Command Line
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                        Scan Time
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                        Matches
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-700">
                    {filteredProcessScans.map((scan) => {
                      const matches = parseYaraResults(scan.yara_results);
                      return (
                        <tr key={scan.id} className="hover:bg-gray-750 transition-colors">
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm font-mono text-gray-300">{scan.pid}</div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm font-medium text-gray-300">
                              {scan.process_name}
                            </div>
                          </td>
                          <td className="px-6 py-4">
                            <div className="text-sm text-gray-400 font-mono truncate max-w-md">
                              {scan.cmdline || 'N/A'}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm text-gray-400">
                              {formatTimestamp(scan.lastscan_time)}
                            </div>
                          </td>
                          <td className="px-6 py-4">
                            {matches.length > 0 ? (
                              <div className="space-y-1">
                                {matches.map((match, idx) => (
                                  <div
                                    key={idx}
                                    className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-red-900 text-red-200 mr-2"
                                  >
                                    <AlertTriangle className="w-3 h-3 mr-1" />
                                    {match.Rule}
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <span className="text-sm text-green-400">Clean</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              <Pagination
                currentPage={processScans.page}
                totalPages={processScans.total_pages}
                onPageChange={(page) => fetchProcessScans(page)}
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({ title, value, icon: Icon, color, isTime = false }) {
  const colors = {
    blue: 'bg-blue-900 text-blue-300',
    red: 'bg-red-900 text-red-300',
    green: 'bg-green-900 text-green-300',
    purple: 'bg-purple-900 text-purple-300'
  };

  return (
    <div className="bg-gray-800 rounded-lg shadow-lg p-6 border border-gray-700">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-400">{title}</p>
          <p className={`text-2xl font-bold mt-2 ${isTime ? 'text-base' : ''}`}>
            {value}
          </p>
        </div>
        <div className={`p-3 rounded-lg ${colors[color]}`}>
          <Icon className="w-6 h-6" />
        </div>
      </div>
    </div>
  );
}

function RecentActivity({ title, items, type, formatTimestamp, parseYaraResults }) {
  return (
    <div className="bg-gray-800 rounded-lg shadow-lg p-6 border border-gray-700">
      <h3 className="text-lg font-semibold text-white mb-4">{title}</h3>
      <div className="space-y-3">
        {items.length === 0 ? (
          <p className="text-gray-400 text-sm">No recent activity</p>
        ) : (
          items.map((item) => {
            const matches = parseYaraResults(item.yara_results);
            const hasMatches = matches.length > 0;

            return (
              <div
                key={item.id}
                className={`p-3 rounded-lg border ${
                  hasMatches
                    ? 'bg-red-900 bg-opacity-20 border-red-700'
                    : 'bg-gray-750 border-gray-700'
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-200 truncate font-mono">
                      {type === 'file' ? item.filepath : item.process_name}
                    </p>
                    {type === 'process' && item.cmdline && (
                      <p className="text-xs text-gray-400 truncate font-mono mt-1">
                        {item.cmdline}
                      </p>
                    )}
                    <p className="text-xs text-gray-500 mt-1">
                      {formatTimestamp(item.lastscan_time)}
                    </p>
                  </div>
                  {hasMatches && (
                    <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 ml-2" />
                  )}
                </div>
                {hasMatches && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {matches.map((match, idx) => (
                      <span
                        key={idx}
                        className="inline-block px-2 py-1 text-xs rounded bg-red-800 text-red-200"
                      >
                        {match.Rule}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

function Pagination({ currentPage, totalPages, onPageChange }) {
  if (totalPages <= 1) return null;

  return (
    <div className="bg-gray-750 px-6 py-4 flex items-center justify-between border-t border-gray-700">
      <div className="text-sm text-gray-400">
        Page {currentPage} of {totalPages}
      </div>
      <div className="flex space-x-2">
        <button
          onClick={() => onPageChange(currentPage - 1)}
          disabled={currentPage === 1}
          className="px-3 py-2 rounded bg-gray-700 text-gray-300 hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <ChevronLeft className="w-4 h-4" />
        </button>
        <button
          onClick={() => onPageChange(currentPage + 1)}
          disabled={currentPage === totalPages}
          className="px-3 py-2 rounded bg-gray-700 text-gray-300 hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <ChevronRight className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}