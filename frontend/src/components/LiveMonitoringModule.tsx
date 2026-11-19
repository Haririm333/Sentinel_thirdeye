import React, { useState, useEffect } from 'react';
import {
  Radio,
  Search,
  RefreshCw,
  Play,
  Pause,
  Filter,
  CheckCircle,
  AlertTriangle,
  FileCode,
  ArrowRight,
  ShieldCheck,
  Cpu,
  ChevronRight,
  X,
} from 'lucide-react';
import { ApiEvent, UnifiedAssessment } from '../types';
import { getEvents, evaluateEventRiskOnDemand, getEventAssessment } from '../api/client';

export const LiveMonitoringModule: React.FC = () => {
  const [events, setEvents] = useState<ApiEvent[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);
  const [refreshInterval, setRefreshInterval] = useState<number>(3000);
  const [systemFilter, setSystemFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedEvent, setSelectedEvent] = useState<ApiEvent | null>(null);
  const [evaluating, setEvaluating] = useState<boolean>(false);
  const [assessmentResult, setAssessmentResult] = useState<UnifiedAssessment | null>(null);

  const fetchEventsData = async () => {
    try {
      const res = await getEvents({
        limit: 50,
        source_system: systemFilter !== 'ALL' ? systemFilter : undefined,
      });
      if (res && res.items) {
        setEvents(res.items);
      }
    } catch (err) {
      console.error('Failed to fetch events:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEventsData();
  }, [systemFilter]);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(fetchEventsData, refreshInterval);
    return () => clearInterval(interval);
  }, [autoRefresh, refreshInterval, systemFilter]);

  const handleSelectEvent = async (event: ApiEvent) => {
    setSelectedEvent(event);
    setAssessmentResult(null);
    try {
      // Check if assessment already exists
      const assessment = await getEventAssessment(event.event_id).catch(() => null);
      if (assessment) {
        setAssessmentResult(assessment);
      }
    } catch {
      // not assessed yet
    }
  };

  const handleRunEvaluation = async (eventId: string) => {
    try {
      setEvaluating(true);
      const res = await evaluateEventRiskOnDemand(eventId);
      setAssessmentResult(res);
    } catch (err) {
      console.error('Evaluation failed:', err);
    } finally {
      setEvaluating(false);
    }
  };

  // Filter events by query
  const filteredEvents = events.filter((ev) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      ev.endpoint.toLowerCase().includes(q) ||
      ev.service_identity.toLowerCase().includes(q) ||
      ev.source_ip.toLowerCase().includes(q) ||
      ev.auth_identity.toLowerCase().includes(q) ||
      ev.action.toLowerCase().includes(q)
    );
  });

  const getMethodBadge = (method: string) => {
    switch (method.toUpperCase()) {
      case 'GET':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
      case 'POST':
        return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40';
      case 'PUT':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
      case 'PATCH':
        return 'bg-purple-500/20 text-purple-400 border-purple-500/40';
      case 'DELETE':
        return 'bg-red-500/20 text-red-400 border-red-500/40';
      default:
        return 'bg-slate-500/20 text-slate-300 border-slate-500/40';
    }
  };

  return (
    <div className="space-y-4">
      {/* Top Controls Bar */}
      <div className="bg-sentinel-navy border border-sentinel-border rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-md">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-sentinel-card border border-sentinel-cyan/30 text-sentinel-cyan rounded-lg">
            <Radio className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-sentinel-textBright font-mono">
              REAL-TIME API EVENT INGESTION STREAM
            </h2>
            <p className="text-[11px] text-sentinel-textMuted">
              Live cryptographic verification, payload sanitization, and sequential tracking
            </p>
          </div>
        </div>

        {/* Polling & Interval Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* System Filter Dropdown */}
          <div className="flex items-center space-x-1.5 bg-sentinel-card px-2.5 py-1.5 rounded-lg border border-sentinel-border text-xs font-mono">
            <Filter className="w-3.5 h-3.5 text-sentinel-textMuted" />
            <select
              value={systemFilter}
              onChange={(e) => setSystemFilter(e.target.value)}
              className="bg-transparent text-sentinel-textBright focus:outline-none cursor-pointer"
            >
              <option value="ALL" className="bg-sentinel-navy">All Systems</option>
              <option value="LedgerOne" className="bg-sentinel-navy">LedgerOne</option>
              <option value="HelpDeskr" className="bg-sentinel-navy">HelpDeskr</option>
              <option value="TallyBridge" className="bg-sentinel-navy">TallyBridge</option>
            </select>
          </div>

          {/* Auto Refresh Toggle */}
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-colors border ${
              autoRefresh
                ? 'bg-sentinel-accent/10 border-sentinel-accent/40 text-sentinel-accent'
                : 'bg-sentinel-card border-sentinel-border text-sentinel-textMuted'
            }`}
          >
            {autoRefresh ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            <span>{autoRefresh ? 'Streaming (Active)' : 'Stream Paused'}</span>
          </button>

          {/* Manual Refresh */}
          <button
            onClick={fetchEventsData}
            disabled={loading}
            className="p-1.5 bg-sentinel-card hover:bg-sentinel-hover border border-sentinel-border rounded-lg text-sentinel-cyan transition-colors"
            title="Manual Poll"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Search Input */}
      <div className="relative">
        <Search className="w-4 h-4 text-sentinel-textMuted absolute left-3 top-2.5" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Filter by endpoint, service identity, source IP, or action..."
          className="w-full bg-sentinel-card border border-sentinel-border rounded-xl pl-9 pr-4 py-2 text-xs font-mono text-sentinel-textBright placeholder-sentinel-textMuted focus:outline-none focus:border-sentinel-cyan transition-colors"
        />
      </div>

      {/* Events Table */}
      <div className="bg-sentinel-card border border-sentinel-border rounded-xl shadow-lg overflow-hidden">
        <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-sentinel-navy text-sentinel-textMuted uppercase border-b border-sentinel-border/70 sticky top-0 z-10">
              <tr>
                <th className="px-3.5 py-3">Timestamp (UTC)</th>
                <th className="px-3.5 py-3">System</th>
                <th className="px-3.5 py-3">Service Identity</th>
                <th className="px-3.5 py-3">Method & Endpoint</th>
                <th className="px-3.5 py-3">Source IP</th>
                <th className="px-3.5 py-3">Status</th>
                <th className="px-3.5 py-3">Payload Hash</th>
                <th className="px-3.5 py-3 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-sentinel-border/40">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-sentinel-textMuted">
                    {loading ? 'Polling event buffer...' : 'No matching events found.'}
                  </td>
                </tr>
              ) : (
                filteredEvents.map((ev) => {
                  const isSelected = selectedEvent?.event_id === ev.event_id;
                  const isExternalIp = !ev.source_ip.startsWith('10.0.') && !ev.source_ip.startsWith('127.0.');
                  return (
                    <tr
                      key={ev.event_id}
                      onClick={() => handleSelectEvent(ev)}
                      className={`hover:bg-sentinel-hover/60 transition-colors cursor-pointer ${
                        isSelected ? 'bg-sentinel-hover/80 border-l-4 border-sentinel-accent' : ''
                      }`}
                    >
                      <td className="px-3.5 py-2.5 text-sentinel-textMuted whitespace-nowrap">
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="px-3.5 py-2.5 font-semibold text-sentinel-textBright whitespace-nowrap">
                        {ev.source_system}
                      </td>
                      <td className="px-3.5 py-2.5 text-sentinel-cyan whitespace-nowrap">
                        {ev.service_identity}
                      </td>
                      <td className="px-3.5 py-2.5">
                        <div className="flex items-center space-x-2">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${getMethodBadge(
                              ev.http_method
                            )}`}
                          >
                            {ev.http_method}
                          </span>
                          <span className="text-sentinel-textBright truncate max-w-xs">{ev.endpoint}</span>
                        </div>
                      </td>
                      <td className="px-3.5 py-2.5 whitespace-nowrap">
                        <span
                          className={`font-mono ${
                            isExternalIp
                              ? 'text-sentinel-danger font-bold bg-sentinel-danger/10 px-1 py-0.5 rounded'
                              : 'text-sentinel-textMuted'
                          }`}
                        >
                          {ev.source_ip}
                        </span>
                      </td>
                      <td className="px-3.5 py-2.5 whitespace-nowrap">
                        <span
                          className={`font-bold ${
                            ev.http_status_code >= 200 && ev.http_status_code < 300
                              ? 'text-emerald-400'
                              : 'text-amber-400'
                          }`}
                        >
                          {ev.http_status_code}
                        </span>
                      </td>
                      <td className="px-3.5 py-2.5 text-sentinel-textMuted font-mono text-[10px] whitespace-nowrap">
                        {ev.payload_hash ? `${ev.payload_hash.substring(0, 10)}...` : '--'}
                      </td>
                      <td className="px-3.5 py-2.5 text-right whitespace-nowrap">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleSelectEvent(ev);
                          }}
                          className="px-2 py-0.5 bg-sentinel-navy hover:bg-sentinel-hover border border-sentinel-border rounded text-[10px] text-sentinel-cyan transition-colors"
                        >
                          Details
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

      {/* Slide-over Event Detail Drawer */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-xl bg-sentinel-card border-l border-sentinel-border h-full overflow-y-auto p-6 shadow-2xl space-y-6">
            {/* Drawer Header */}
            <div className="flex items-center justify-between border-b border-sentinel-border/80 pb-4">
              <div>
                <span className="text-[10px] font-mono uppercase tracking-wider text-sentinel-textMuted">
                  API Event Telemetry
                </span>
                <h3 className="text-sm font-bold font-mono text-sentinel-textBright truncate">
                  {selectedEvent.event_id}
                </h3>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="p-1 rounded-lg text-sentinel-textMuted hover:text-white hover:bg-sentinel-navy"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Quick Metadata Grid */}
            <div className="grid grid-cols-2 gap-3 text-xs font-mono bg-sentinel-navy p-3 rounded-lg border border-sentinel-border/60">
              <div>
                <span className="text-sentinel-textMuted block text-[10px]">SOURCE SYSTEM</span>
                <span className="text-sentinel-textBright font-semibold">{selectedEvent.source_system}</span>
              </div>
              <div>
                <span className="text-sentinel-textMuted block text-[10px]">SERVICE IDENTITY</span>
                <span className="text-sentinel-cyan font-semibold">{selectedEvent.service_identity}</span>
              </div>
              <div>
                <span className="text-sentinel-textMuted block text-[10px]">HTTP METHOD & STATUS</span>
                <span className="text-sentinel-textBright">
                  {selectedEvent.http_method} • {selectedEvent.http_status_code}
                </span>
              </div>
              <div>
                <span className="text-sentinel-textMuted block text-[10px]">SOURCE IP</span>
                <span className="text-amber-400">{selectedEvent.source_ip}</span>
              </div>
              <div>
                <span className="text-sentinel-textMuted block text-[10px]">AUTH IDENTITY</span>
                <span className="text-sentinel-textBright">{selectedEvent.auth_identity}</span>
              </div>
              <div>
                <span className="text-sentinel-textMuted block text-[10px]">TIMESTAMP</span>
                <span className="text-sentinel-textMuted">{selectedEvent.timestamp}</span>
              </div>
              <div>
                <span className="text-sentinel-textMuted block text-[10px]">ACTION</span>
                <span className="text-sentinel-accent">{selectedEvent.action}</span>
              </div>
              <div>
                <span className="text-sentinel-textMuted block text-[10px]">RESOURCE</span>
                <span className="text-sentinel-textBright">{selectedEvent.resource_type}: {selectedEvent.resource_id}</span>
              </div>
            </div>

            {/* Cryptographic Hash */}
            <div className="bg-sentinel-darkest p-3 rounded-lg border border-sentinel-border/40 text-[11px] font-mono">
              <span className="text-sentinel-textMuted block text-[10px]">SHA-256 PAYLOAD HASH</span>
              <span className="text-sentinel-accent break-all">{selectedEvent.payload_hash}</span>
            </div>

            {/* Unified AI & Deterministic Assessment Trigger */}
            <div className="border border-sentinel-border rounded-xl p-4 bg-sentinel-navy space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Cpu className="w-4 h-4 text-sentinel-accent" />
                  <span className="text-xs font-bold font-mono text-sentinel-textBright">
                    MULTI-TIER RISK EVALUATION
                  </span>
                </div>
                <button
                  onClick={() => handleRunEvaluation(selectedEvent.event_id)}
                  disabled={evaluating}
                  className="px-3 py-1 bg-sentinel-accent hover:bg-sentinel-accent/80 text-sentinel-darkest font-bold text-xs rounded transition-colors flex items-center space-x-1"
                >
                  {evaluating ? <RefreshCw className="w-3 h-3 animate-spin" /> : null}
                  <span>{assessmentResult ? 'Re-Evaluate' : 'Evaluate Threat'}</span>
                </button>
              </div>

              {assessmentResult && (
                <div className="space-y-3 pt-3 border-t border-sentinel-border/60">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-sentinel-textMuted font-mono">RISK LEVEL:</span>
                    <span
                      className={`px-2 py-0.5 rounded text-xs font-bold font-mono ${
                        assessmentResult.overall_risk_level === 'CRITICAL'
                          ? 'bg-sentinel-danger text-white'
                          : assessmentResult.overall_risk_level === 'HIGH'
                          ? 'bg-amber-500 text-slate-900'
                          : assessmentResult.overall_risk_level === 'MEDIUM'
                          ? 'bg-orange-500 text-white'
                          : 'bg-emerald-500 text-white'
                      }`}
                    >
                      {assessmentResult.overall_risk_level} ({assessmentResult.overall_risk_score}/100)
                    </span>
                  </div>

                  <p className="text-xs text-sentinel-textBright bg-sentinel-card p-2.5 rounded border border-sentinel-border/80">
                    {assessmentResult.findings_summary}
                  </p>

                  {/* Components Breakdown */}
                  <div className="space-y-1.5 text-xs font-mono">
                    <div className="text-[10px] text-sentinel-textMuted uppercase">Subsystem Evaluation:</div>
                    <div className="p-2 bg-sentinel-darkest rounded border border-sentinel-border/50 text-[11px] space-y-1">
                      <div className="flex justify-between">
                        <span className="text-sentinel-cyan">Deterministic Rules:</span>
                        <span className={assessmentResult.deterministic_rule_findings.some(f => f.triggered) ? 'text-sentinel-danger font-bold' : 'text-emerald-400'}>
                          {assessmentResult.deterministic_rule_findings.filter(f => f.triggered).length} Triggered
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sentinel-cyan">Isolation Forest:</span>
                        <span className={assessmentResult.isolation_forest_result.is_anomaly ? 'text-sentinel-danger font-bold' : 'text-emerald-400'}>
                          {assessmentResult.isolation_forest_result.is_anomaly ? 'ANOMALOUS' : 'NORMAL'}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sentinel-cyan">LSTM Autoencoder:</span>
                        <span className={assessmentResult.lstm_autoencoder_result.is_anomaly ? 'text-sentinel-danger font-bold' : 'text-emerald-400'}>
                          {assessmentResult.lstm_autoencoder_result.is_anomaly ? 'ANOMALOUS' : 'NORMAL'}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Raw JSON viewer */}
            <div>
              <span className="text-xs font-mono text-sentinel-textMuted block mb-1">
                SANITIZED EVENT RAW PAYLOAD
              </span>
              <pre className="bg-sentinel-darkest border border-sentinel-border/50 rounded-lg p-3 text-[11px] font-mono text-sentinel-cyan overflow-x-auto max-h-60">
                {JSON.stringify(selectedEvent, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
