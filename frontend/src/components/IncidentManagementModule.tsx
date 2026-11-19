import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  Search,
  Filter,
  RefreshCw,
  Eye,
  CheckCircle,
  AlertOctagon,
  Clock,
  ShieldAlert,
} from 'lucide-react';
import { Incident, Severity, IncidentStatus } from '../types';
import { getIncidents } from '../api/client';
import { IncidentDetailModal } from './IncidentDetailModal';

interface IncidentManagementModuleProps {
  selectedIncident: Incident | null;
  onSelectIncident: (inc: Incident | null) => void;
}

export const IncidentManagementModule: React.FC<IncidentManagementModuleProps> = ({
  selectedIncident,
  onSelectIncident,
}) => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const fetchIncidentsData = async () => {
    try {
      setLoading(true);
      const res = await getIncidents({
        limit: 100,
        severity: severityFilter !== 'ALL' ? severityFilter : undefined,
        status: statusFilter !== 'ALL' ? statusFilter : undefined,
      });
      if (res && res.items) {
        setIncidents(res.items);
      }
    } catch (err) {
      console.error('Failed to load incidents:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidentsData();
  }, [severityFilter, statusFilter]);

  const handleIncidentUpdated = (updated: Incident) => {
    setIncidents((prev) =>
      prev.map((inc) => (inc.incident_id === updated.incident_id ? updated : inc))
    );
    if (selectedIncident?.incident_id === updated.incident_id) {
      onSelectIncident(updated);
    }
  };

  const filteredIncidents = incidents.filter((inc) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      inc.title.toLowerCase().includes(q) ||
      inc.rule_id.toLowerCase().includes(q) ||
      inc.service_identity.toLowerCase().includes(q) ||
      inc.source_ip.toLowerCase().includes(q) ||
      inc.explanation.toLowerCase().includes(q)
    );
  });

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-sentinel-danger text-white border-sentinel-danger';
      case 'HIGH':
        return 'bg-amber-500 text-slate-900 border-amber-500';
      case 'MEDIUM':
        return 'bg-orange-500 text-white border-orange-500';
      default:
        return 'bg-emerald-500 text-white border-emerald-500';
    }
  };

  const getStatusBadge = (st: string) => {
    switch (st) {
      case 'OPEN':
        return 'bg-red-500/20 text-red-400 border-red-500/40';
      case 'INVESTIGATING':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
      case 'RESOLVED':
        return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40';
      case 'FALSE_POSITIVE':
        return 'bg-slate-500/20 text-slate-400 border-slate-500/40';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/40';
    }
  };

  return (
    <div className="space-y-4">
      {/* Top Header Card */}
      <div className="bg-sentinel-navy border border-sentinel-border rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-md">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-sentinel-danger/10 border border-sentinel-danger/30 text-sentinel-danger rounded-lg">
            <AlertOctagon className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-sentinel-textBright font-mono">
              SECURITY INCIDENT & THREAT TRIAGE
            </h2>
            <p className="text-[11px] text-sentinel-textMuted">
              Deterministic violations, Isolation Forest deviations, and Sequential LSTM anomalies
            </p>
          </div>
        </div>

        <button
          onClick={fetchIncidentsData}
          disabled={loading}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-sentinel-card hover:bg-sentinel-hover border border-sentinel-border text-xs text-sentinel-cyan transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Filter Tabs and Search */}
      <div className="flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
        {/* Severity Tabs */}
        <div className="flex flex-wrap items-center gap-1.5 bg-sentinel-card p-1 rounded-xl border border-sentinel-border text-xs font-mono">
          <span className="px-2 text-sentinel-textMuted text-[10px] uppercase font-bold">Severity:</span>
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-2.5 py-1 rounded-lg transition-colors ${
                severityFilter === sev
                  ? 'bg-sentinel-navy text-sentinel-accent font-bold border border-sentinel-accent/40 shadow'
                  : 'text-sentinel-textMuted hover:text-sentinel-textBright'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        {/* Status Tabs */}
        <div className="flex flex-wrap items-center gap-1.5 bg-sentinel-card p-1 rounded-xl border border-sentinel-border text-xs font-mono">
          <span className="px-2 text-sentinel-textMuted text-[10px] uppercase font-bold">Status:</span>
          {['ALL', 'OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'].map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-2.5 py-1 rounded-lg transition-colors ${
                statusFilter === st
                  ? 'bg-sentinel-navy text-sentinel-cyan font-bold border border-sentinel-cyan/40 shadow'
                  : 'text-sentinel-textMuted hover:text-sentinel-textBright'
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* Search Input */}
      <div className="relative">
        <Search className="w-4 h-4 text-sentinel-textMuted absolute left-3 top-2.5" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Filter incidents by title, rule ID, service, or forensic detail..."
          className="w-full bg-sentinel-card border border-sentinel-border rounded-xl pl-9 pr-4 py-2 text-xs font-mono text-sentinel-textBright placeholder-sentinel-textMuted focus:outline-none focus:border-sentinel-cyan transition-colors"
        />
      </div>

      {/* Incidents Table */}
      <div className="bg-sentinel-card border border-sentinel-border rounded-xl shadow-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-sentinel-navy text-sentinel-textMuted uppercase border-b border-sentinel-border/70">
              <tr>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Rule / Title</th>
                <th className="px-4 py-3">Service & System</th>
                <th className="px-4 py-3">Source IP</th>
                <th className="px-4 py-3">Risk Score</th>
                <th className="px-4 py-3">Created</th>
                <th className="px-4 py-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-sentinel-border/40">
              {filteredIncidents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-sentinel-textMuted">
                    {loading ? 'Loading incidents...' : 'No security incidents match the selected filters.'}
                  </td>
                </tr>
              ) : (
                filteredIncidents.map((incident) => (
                  <tr
                    key={incident.incident_id}
                    onClick={() => onSelectIncident(incident)}
                    className="hover:bg-sentinel-hover/60 transition-colors cursor-pointer"
                  >
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(incident.severity)}`}>
                        {incident.severity}
                      </span>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getStatusBadge(incident.status)}`}>
                        {incident.status}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="font-semibold text-sentinel-textBright truncate max-w-sm">
                        {incident.title}
                      </div>
                      <div className="text-[10px] text-sentinel-textMuted">
                        {incident.rule_id} • {incident.incident_id.substring(0, 8)}
                      </div>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <div className="text-sentinel-cyan">{incident.service_identity}</div>
                      <div className="text-[10px] text-sentinel-textMuted">{incident.source_system}</div>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-amber-400">
                      {incident.source_ip}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className="font-bold text-amber-400">{incident.risk_score}</span>
                      <span className="text-[10px] text-sentinel-textMuted">/100</span>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-sentinel-textMuted">
                      {new Date(incident.created_at).toLocaleTimeString()}
                    </td>
                    <td className="px-4 py-3 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectIncident(incident);
                        }}
                        className="px-2.5 py-1 bg-sentinel-navy hover:bg-sentinel-hover border border-sentinel-border rounded text-[11px] text-sentinel-cyan transition-colors"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detail Modal */}
      <IncidentDetailModal
        incident={selectedIncident}
        onClose={() => onSelectIncident(null)}
        onStatusUpdated={handleIncidentUpdated}
      />
    </div>
  );
};
