import React, { useState, useEffect } from 'react';
import {
  X,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Cpu,
  Shield,
  FileText,
  User,
  ArrowRight,
  ExternalLink,
  RefreshCw,
} from 'lucide-react';
import { Incident, IncidentStatus, UnifiedAssessment } from '../types';
import { updateIncidentStatus, getIncidentAssessment } from '../api/client';

interface IncidentDetailModalProps {
  incident: Incident | null;
  onClose: () => void;
  onStatusUpdated: (updatedIncident: Incident) => void;
}

export const IncidentDetailModal: React.FC<IncidentDetailModalProps> = ({
  incident,
  onClose,
  onStatusUpdated,
}) => {
  const [updating, setUpdating] = useState<boolean>(false);
  const [assessment, setAssessment] = useState<UnifiedAssessment | null>(null);
  const [loadingAssessment, setLoadingAssessment] = useState<boolean>(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!incident) return;
    setStatusMessage(null);
    setLoadingAssessment(true);
    getIncidentAssessment(incident.incident_id)
      .then(setAssessment)
      .catch(() => setAssessment(null))
      .finally(() => setLoadingAssessment(false));
  }, [incident]);

  if (!incident) return null;

  const handleUpdateStatus = async (newStatus: IncidentStatus) => {
    try {
      setUpdating(true);
      const updated = await updateIncidentStatus(incident.incident_id, newStatus as any);
      setStatusMessage(`Incident successfully marked as ${newStatus}`);
      onStatusUpdated(updated);
    } catch (err: any) {
      setStatusMessage(`Error: ${err?.response?.data?.message || err.message}`);
    } finally {
      setUpdating(false);
    }
  };

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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="bg-sentinel-card border border-sentinel-border rounded-2xl w-full max-w-3xl max-h-[90vh] overflow-y-auto shadow-2xl flex flex-col">
        {/* Header */}
        <div className="p-5 border-b border-sentinel-border flex items-start justify-between bg-sentinel-navy sticky top-0 z-10">
          <div>
            <div className="flex items-center space-x-2">
              <span className={`px-2 py-0.5 rounded text-[11px] font-bold font-mono border ${getSeverityBadge(incident.severity)}`}>
                {incident.severity}
              </span>
              <span className={`px-2 py-0.5 rounded text-[11px] font-bold font-mono border ${getStatusBadge(incident.status)}`}>
                {incident.status}
              </span>
              <span className="text-xs text-sentinel-textMuted font-mono">
                Risk Score: <strong className="text-amber-400 font-bold">{incident.risk_score}</strong>/100
              </span>
            </div>
            <h2 className="text-base font-bold text-sentinel-textBright mt-2">
              {incident.title}
            </h2>
            <div className="flex items-center space-x-3 text-xs text-sentinel-textMuted font-mono mt-1">
              <span>Rule ID: {incident.rule_id}</span>
              <span>•</span>
              <span>Incident: {incident.incident_id.substring(0, 8)}</span>
              <span>•</span>
              <span>Detected: {new Date(incident.created_at).toLocaleString()}</span>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-sentinel-textMuted hover:text-white hover:bg-sentinel-card"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-6 flex-1">
          {/* Status Message Notification */}
          {statusMessage && (
            <div className="p-3 bg-sentinel-navy border border-sentinel-cyan/40 rounded-lg text-xs font-mono text-sentinel-cyan flex items-center space-x-2">
              <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
              <span>{statusMessage}</span>
            </div>
          )}

          {/* Explanation Section */}
          <div className="bg-sentinel-navy p-4 rounded-xl border border-sentinel-border">
            <h4 className="text-xs font-bold text-sentinel-cyan font-mono uppercase tracking-wider mb-2">
              SECURITY ANALYST EXPLANATION
            </h4>
            <p className="text-xs text-sentinel-textBright leading-relaxed font-sans">
              {incident.explanation}
            </p>
          </div>

          {/* Context Telemetry Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
            <div className="bg-sentinel-navy p-3 rounded-lg border border-sentinel-border/50">
              <span className="text-[10px] text-sentinel-textMuted block">SOURCE SYSTEM</span>
              <span className="font-semibold text-sentinel-textBright">{incident.source_system}</span>
            </div>
            <div className="bg-sentinel-navy p-3 rounded-lg border border-sentinel-border/50">
              <span className="text-[10px] text-sentinel-textMuted block">SERVICE IDENTITY</span>
              <span className="font-semibold text-sentinel-cyan">{incident.service_identity}</span>
            </div>
            <div className="bg-sentinel-navy p-3 rounded-lg border border-sentinel-border/50">
              <span className="text-[10px] text-sentinel-textMuted block">SOURCE IP</span>
              <span className="font-semibold text-amber-400">{incident.source_ip}</span>
            </div>
            <div className="bg-sentinel-navy p-3 rounded-lg border border-sentinel-border/50">
              <span className="text-[10px] text-sentinel-textMuted block">AUTH USER</span>
              <span className="font-semibold text-sentinel-textBright">{incident.auth_identity}</span>
            </div>
          </div>

          {/* Contributing Detection Components */}
          {incident.contributing_components && incident.contributing_components.length > 0 && (
            <div className="space-y-2">
              <h4 className="text-xs font-bold text-sentinel-textMuted font-mono uppercase">
                CONTRIBUTING DETECTION SUBSYSTEMS
              </h4>
              <div className="flex flex-wrap gap-2">
                {incident.contributing_components.map((comp) => (
                  <span
                    key={comp}
                    className="px-2.5 py-1 rounded bg-sentinel-accent/10 border border-sentinel-accent/40 text-sentinel-accent text-xs font-mono font-medium"
                  >
                    {comp}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Supporting Evidence Inspector */}
          <div className="space-y-2">
            <h4 className="text-xs font-bold text-sentinel-textMuted font-mono uppercase flex items-center justify-between">
              <span>SUPPORTING FORENSIC EVIDENCE</span>
              <span className="text-[11px] text-sentinel-cyan lowercase font-normal">
                {Object.keys(incident.evidence || {}).length} forensic parameters captured
              </span>
            </h4>
            <div className="bg-sentinel-darkest border border-sentinel-border/60 rounded-xl p-4 max-h-56 overflow-y-auto">
              <pre className="text-[11px] font-mono text-sentinel-cyan whitespace-pre-wrap">
                {JSON.stringify(incident.evidence, null, 2)}
              </pre>
            </div>
          </div>

          {/* Multi-Tier Correlated Assessment View */}
          {assessment && (
            <div className="border border-sentinel-border/80 rounded-xl p-4 bg-sentinel-navy/80 space-y-3">
              <div className="flex items-center space-x-2 text-xs font-bold font-mono text-sentinel-accent">
                <Cpu className="w-4 h-4" />
                <span>UNIFIED RISK ASSESSMENT CORRELATION</span>
              </div>
              <p className="text-xs text-sentinel-textBright">
                {assessment.findings_summary}
              </p>
              <div className="grid grid-cols-2 gap-2 text-[11px] font-mono pt-2 border-t border-sentinel-border/50">
                <div className="text-sentinel-textMuted">
                  Primary Detector: <span className="text-sentinel-cyan">{assessment.primary_detector}</span>
                </div>
                <div className="text-sentinel-textMuted">
                  Overall Risk: <span className="text-amber-400 font-bold">{assessment.overall_risk_score}/100</span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Action Controls Footer */}
        <div className="p-4 border-t border-sentinel-border bg-sentinel-navy flex flex-wrap items-center justify-between gap-3 sticky bottom-0 z-10">
          <div className="text-xs text-sentinel-textMuted font-mono">
            <span>TRIAGE WORKFLOW:</span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => handleUpdateStatus('INVESTIGATING')}
              disabled={updating || incident.status === 'INVESTIGATING'}
              className="px-3 py-1.5 rounded-lg bg-blue-600/20 hover:bg-blue-600/30 border border-blue-500/40 text-blue-400 text-xs font-mono font-medium disabled:opacity-40 transition-colors"
            >
              Mark Investigating
            </button>
            <button
              onClick={() => handleUpdateStatus('FALSE_POSITIVE')}
              disabled={updating || incident.status === 'FALSE_POSITIVE'}
              className="px-3 py-1.5 rounded-lg bg-slate-700/40 hover:bg-slate-700/60 border border-slate-600/50 text-slate-300 text-xs font-mono font-medium disabled:opacity-40 transition-colors"
            >
              False Positive
            </button>
            <button
              onClick={() => handleUpdateStatus('RESOLVED')}
              disabled={updating || incident.status === 'RESOLVED'}
              className="px-3 py-1.5 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 border border-emerald-500/40 text-emerald-400 text-xs font-mono font-medium disabled:opacity-40 transition-colors"
            >
              Resolve Incident
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
