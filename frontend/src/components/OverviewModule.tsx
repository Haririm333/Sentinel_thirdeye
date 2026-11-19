import React, { useEffect, useState } from 'react';
import {
  Activity,
  AlertOctagon,
  ShieldAlert,
  Cpu,
  Clock,
  ArrowUpRight,
  TrendingUp,
  AlertTriangle,
  RefreshCw,
  ExternalLink,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
  PieChart,
  Pie,
} from 'recharts';
import { AssessmentSummary, Incident, ApiEvent } from '../types';
import { getAssessmentSummary, getIncidents, getEvents } from '../api/client';
import { ActiveTab } from './Sidebar';

interface OverviewModuleProps {
  onNavigate: (tab: ActiveTab) => void;
  onSelectIncident: (incident: Incident) => void;
}

export const OverviewModule: React.FC<OverviewModuleProps> = ({
  onNavigate,
  onSelectIncident,
}) => {
  const [summary, setSummary] = useState<AssessmentSummary | null>(null);
  const [recentIncidents, setRecentIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [lastRefreshed, setLastRefreshed] = useState<Date>(new Date());

  const loadData = async () => {
    try {
      setLoading(true);
      const [sumData, incData] = await Promise.all([
        getAssessmentSummary().catch(() => null),
        getIncidents({ limit: 5 }).catch(() => ({ items: [] })),
      ]);

      if (sumData) setSummary(sumData);
      if (incData && incData.items) setRecentIncidents(incData.items);
      setLastRefreshed(new Date());
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, []);

  // Compute breakdown data for Recharts
  const severityData = [
    { name: 'Low', count: summary?.severity_distribution?.LOW || 0, color: '#10B981' },
    { name: 'Medium', count: summary?.severity_distribution?.MEDIUM || 0, color: '#F59E0B' },
    { name: 'High', count: summary?.severity_distribution?.HIGH || 0, color: '#F97316' },
    { name: 'Critical', count: summary?.severity_distribution?.CRITICAL || 0, color: '#EF4444' },
  ];

  const componentData = [
    {
      name: 'Deterministic Rules',
      triggers: summary?.component_trigger_counts?.DETERMINISTIC_RULES || 0,
      fill: '#5BC0BE',
    },
    {
      name: 'Isolation Forest',
      triggers: summary?.component_trigger_counts?.ISOLATION_FOREST || 0,
      fill: '#3B82F6',
    },
    {
      name: 'LSTM Autoencoder',
      triggers: summary?.component_trigger_counts?.LSTM_AUTOENCODER || 0,
      fill: '#A855F7',
    },
    {
      name: 'Correlated (Multi-Tier)',
      triggers: summary?.component_trigger_counts?.MULTI_TIER_CORRELATED || 0,
      fill: '#48E5C2',
    },
  ];

  const criticalAndHighCount =
    (summary?.severity_distribution?.CRITICAL || 0) + (summary?.severity_distribution?.HIGH || 0);

  const totalAnomalies =
    (summary?.component_trigger_counts?.ISOLATION_FOREST || 0) +
    (summary?.component_trigger_counts?.LSTM_AUTOENCODER || 0);

  return (
    <div className="space-y-6">
      {/* Top Banner & Refresh */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-sentinel-navy p-5 rounded-xl border border-sentinel-border shadow-lg">
        <div>
          <h1 className="text-xl font-bold text-sentinel-textBright flex items-center space-x-2">
            <span>Enterprise Security Posture & Activity Overview</span>
          </h1>
          <p className="text-xs text-sentinel-textMuted mt-1">
            Real-time multi-tier threat correlation across LedgerOne, HelpDeskr, and TallyBridge API streams.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <div className="text-[11px] font-mono text-sentinel-textMuted text-right">
            <span>Last Sync: {lastRefreshed.toLocaleTimeString()}</span>
          </div>
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-sentinel-card hover:bg-sentinel-hover border border-sentinel-border text-xs text-sentinel-cyan transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Metric Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Total Assessed Events */}
        <div className="bg-sentinel-card border border-sentinel-border rounded-xl p-4 shadow-md relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-sentinel-textMuted">
              Total Ingested Events
            </span>
            <div className="p-2 bg-sentinel-navy rounded-lg text-sentinel-cyan border border-sentinel-border/50">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-bold font-mono text-sentinel-textBright">
              {summary?.total_assessed_events ?? '--'}
            </div>
            <div className="flex items-center space-x-1 text-[11px] text-sentinel-cyan mt-1">
              <TrendingUp className="w-3 h-3" />
              <span>Full cryptographic validation active</span>
            </div>
          </div>
        </div>

        {/* Card 2: Open Incidents */}
        <div
          onClick={() => onNavigate('incidents')}
          className="bg-sentinel-card hover:border-sentinel-danger/60 border border-sentinel-border rounded-xl p-4 shadow-md relative cursor-pointer transition-all"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-sentinel-textMuted">
              Security Incidents
            </span>
            <div className="p-2 bg-sentinel-danger/10 rounded-lg text-sentinel-danger border border-sentinel-danger/30">
              <AlertOctagon className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-bold font-mono text-sentinel-textBright">
              {summary?.total_incidents ?? '--'}
            </div>
            <div className="flex items-center space-x-1 text-[11px] text-sentinel-danger mt-1">
              <span>{criticalAndHighCount} Critical or High priority</span>
            </div>
          </div>
        </div>

        {/* Card 3: AI Anomalies */}
        <div
          onClick={() => onNavigate('ai-detection')}
          className="bg-sentinel-card hover:border-sentinel-accent/60 border border-sentinel-border rounded-xl p-4 shadow-md relative cursor-pointer transition-all"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-sentinel-textMuted">
              AI Anomalies Triggered
            </span>
            <div className="p-2 bg-sentinel-accent/10 rounded-lg text-sentinel-accent border border-sentinel-accent/30">
              <Cpu className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-bold font-mono text-sentinel-textBright">
              {totalAnomalies}
            </div>
            <div className="text-[11px] text-sentinel-accent mt-1">
              <span>IF: {summary?.component_trigger_counts?.ISOLATION_FOREST || 0} | LSTM: {summary?.component_trigger_counts?.LSTM_AUTOENCODER || 0}</span>
            </div>
          </div>
        </div>

        {/* Card 4: Average Risk Score */}
        <div className="bg-sentinel-card border border-sentinel-border rounded-xl p-4 shadow-md relative">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-sentinel-textMuted">
              Average Risk Score
            </span>
            <div className="p-2 bg-amber-500/10 rounded-lg text-amber-400 border border-amber-500/30">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-bold font-mono text-amber-400">
              {summary?.average_risk_score !== undefined ? `${summary.average_risk_score.toFixed(1)}/100` : '--'}
            </div>
            <div className="text-[11px] text-sentinel-textMuted mt-1">
              Multi-tiered aggregated risk index
            </div>
          </div>
        </div>
      </div>

      {/* Visual Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Chart 1: Threat Severity Distribution */}
        <div className="bg-sentinel-card border border-sentinel-border rounded-xl p-5 shadow-lg">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-sentinel-textBright font-mono">
              INCIDENT SEVERITY BREAKDOWN
            </h3>
            <span className="text-xs text-sentinel-textMuted">Current active triage</span>
          </div>

          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#64748B" fontSize={12} tickLine={false} />
                <YAxis stroke="#64748B" fontSize={12} tickLine={false} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0B132B',
                    borderColor: '#3A506B',
                    borderRadius: '8px',
                    fontSize: '12px',
                    color: '#F8FAFC',
                  }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="grid grid-cols-4 gap-2 pt-3 border-t border-sentinel-border/50 text-center">
            {severityData.map((s) => (
              <div key={s.name} className="px-2 py-1 bg-sentinel-navy rounded">
                <span className="text-[10px] text-sentinel-textMuted font-mono block">{s.name}</span>
                <span className="text-xs font-bold font-mono" style={{ color: s.color }}>
                  {s.count}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Chart 2: Multi-Tier Detection Engine Breakdown */}
        <div className="bg-sentinel-card border border-sentinel-border rounded-xl p-5 shadow-lg">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-sentinel-textBright font-mono">
              DETECTION COMPONENT TRIGGERS
            </h3>
            <span className="text-xs text-sentinel-textMuted">Multi-tier contribution</span>
          </div>

          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={componentData}
                layout="vertical"
                margin={{ top: 10, right: 20, left: 40, bottom: 0 }}
              >
                <XAxis type="number" stroke="#64748B" fontSize={11} tickLine={false} allowDecimals={false} />
                <YAxis
                  type="category"
                  dataKey="name"
                  stroke="#94A3B8"
                  fontSize={11}
                  tickLine={false}
                  width={120}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0B132B',
                    borderColor: '#3A506B',
                    borderRadius: '8px',
                    fontSize: '12px',
                    color: '#F8FAFC',
                  }}
                />
                <Bar dataKey="triggers" radius={[0, 4, 4, 0]}>
                  {componentData.map((entry, index) => (
                    <Cell key={`cell-comp-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="pt-3 border-t border-sentinel-border/50 text-[11px] text-sentinel-textMuted flex items-center justify-between">
            <span>6 Deterministic Security Rules Active</span>
            <span className="text-sentinel-cyan font-mono">Isolation Forest + LSTM Models Synced</span>
          </div>
        </div>
      </div>

      {/* Recent Suspicious Incidents Table */}
      <div className="bg-sentinel-card border border-sentinel-border rounded-xl shadow-lg overflow-hidden">
        <div className="p-4 border-b border-sentinel-border flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 text-sentinel-warning" />
            <h3 className="text-sm font-semibold text-sentinel-textBright font-mono">
              RECENT SUSPICIOUS INCIDENTS & THREATS
            </h3>
          </div>
          <button
            onClick={() => onNavigate('incidents')}
            className="text-xs font-mono text-sentinel-cyan hover:underline flex items-center space-x-1"
          >
            <span>View All Incidents</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-sentinel-navy text-sentinel-textMuted uppercase border-b border-sentinel-border/70">
              <tr>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Rule / Title</th>
                <th className="px-4 py-3">Service</th>
                <th className="px-4 py-3">Risk Score</th>
                <th className="px-4 py-3">Detected At</th>
                <th className="px-4 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-sentinel-border/40">
              {recentIncidents.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-sentinel-textMuted">
                    No active security incidents recorded. System normal.
                  </td>
                </tr>
              ) : (
                recentIncidents.map((incident) => {
                  const severityBadge =
                    incident.severity === 'CRITICAL'
                      ? 'bg-sentinel-danger/20 text-sentinel-danger border-sentinel-danger/40'
                      : incident.severity === 'HIGH'
                      ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                      : incident.severity === 'MEDIUM'
                      ? 'bg-orange-500/20 text-orange-400 border-orange-500/40'
                      : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40';

                  return (
                    <tr
                      key={incident.incident_id}
                      className="hover:bg-sentinel-hover/60 transition-colors cursor-pointer"
                      onClick={() => onSelectIncident(incident)}
                    >
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${severityBadge}`}>
                          {incident.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-semibold text-sentinel-textBright">
                        <div>{incident.title}</div>
                        <div className="text-[10px] text-sentinel-textMuted">{incident.rule_id}</div>
                      </td>
                      <td className="px-4 py-3 text-sentinel-cyan">{incident.service_identity}</td>
                      <td className="px-4 py-3 font-bold text-amber-400">{incident.risk_score}</td>
                      <td className="px-4 py-3 text-sentinel-textMuted">
                        {new Date(incident.created_at).toLocaleTimeString()}
                      </td>
                      <td className="px-4 py-3 text-right">
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
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
