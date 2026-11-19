import React, { useState, useEffect } from 'react';
import {
  FileText,
  Search,
  Filter,
  RefreshCw,
  ShieldCheck,
  Clock,
  User,
  ArrowRight,
  Database,
  ExternalLink,
  X,
} from 'lucide-react';
import { AuditRecord, BankChangeRequest } from '../types';
import { getBankChanges, getBankChangeAudit } from '../api/client';

export const AuditTrailModule: React.FC = () => {
  const [auditLogs, setAuditLogs] = useState<AuditRecord[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [actionFilter, setActionFilter] = useState<string>('ALL');
  const [selectedRecord, setSelectedRecord] = useState<AuditRecord | null>(null);

  const fetchAllAuditRecords = async () => {
    try {
      setLoading(true);
      // Fetch all bank change requests, then fetch audit trail for each
      const changesRes = await getBankChanges({ limit: 50 });
      if (changesRes && changesRes.items) {
        const auditPromises = changesRes.items.map((req) =>
          getBankChangeAudit(req.request_id).catch(() => ({ audit_trail: [] }))
        );
        const results = await Promise.all(auditPromises);
        const combined = results.flatMap((r) => r.audit_trail || []);
        // Sort descending by performed_at
        combined.sort(
          (a, b) => new Date(b.performed_at).getTime() - new Date(a.performed_at).getTime()
        );
        setAuditLogs(combined);
      }
    } catch (err) {
      console.error('Failed to load audit records:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAllAuditRecords();
  }, []);

  const filteredLogs = auditLogs.filter((log) => {
    if (actionFilter !== 'ALL' && log.action !== actionFilter) return false;
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      log.actor_id.toLowerCase().includes(q) ||
      log.action.toLowerCase().includes(q) ||
      log.request_id.toLowerCase().includes(q) ||
      JSON.stringify(log.details).toLowerCase().includes(q)
    );
  });

  const getActionBadge = (action: string) => {
    switch (action) {
      case 'CREATED':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
      case 'FIRST_APPROVAL':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
      case 'SECOND_APPROVAL':
        return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40';
      case 'REJECTED':
        return 'bg-red-500/20 text-red-400 border-red-500/40';
      case 'CANCELLED':
        return 'bg-slate-500/20 text-slate-400 border-slate-500/40';
      default:
        return 'bg-purple-500/20 text-purple-400 border-purple-500/40';
    }
  };

  return (
    <div className="space-y-4">
      {/* Top Header Card */}
      <div className="bg-sentinel-navy border border-sentinel-border rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-md">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-sentinel-cyan/10 border border-sentinel-cyan/30 text-sentinel-cyan rounded-lg">
            <FileText className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-sentinel-textBright font-mono">
              IMMUTABLE SOC FORENSIC AUDIT TRAIL
            </h2>
            <p className="text-[11px] text-sentinel-textMuted">
              Chronological, non-repudiable audit logs of all privileged authorizations and state modifications
            </p>
          </div>
        </div>

        <button
          onClick={fetchAllAuditRecords}
          disabled={loading}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-sentinel-card hover:bg-sentinel-hover border border-sentinel-border text-xs text-sentinel-cyan transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Audit</span>
        </button>
      </div>

      {/* Filter and Search */}
      <div className="flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
        {/* Action Tabs */}
        <div className="flex flex-wrap items-center gap-1 bg-sentinel-card p-1 rounded-xl border border-sentinel-border text-xs font-mono">
          <span className="px-2 text-sentinel-textMuted text-[10px] uppercase font-bold">Action:</span>
          {['ALL', 'CREATED', 'FIRST_APPROVAL', 'SECOND_APPROVAL', 'REJECTED', 'CANCELLED'].map((act) => (
            <button
              key={act}
              onClick={() => setActionFilter(act)}
              className={`px-2 py-1 rounded-lg transition-colors text-[11px] ${
                actionFilter === act
                  ? 'bg-sentinel-navy text-sentinel-cyan font-bold border border-sentinel-cyan/40 shadow'
                  : 'text-sentinel-textMuted hover:text-sentinel-textBright'
              }`}
            >
              {act}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-sentinel-textMuted absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by actor, request ID, or action..."
            className="w-full bg-sentinel-card border border-sentinel-border rounded-xl pl-9 pr-4 py-2 text-xs font-mono text-sentinel-textBright placeholder-sentinel-textMuted focus:outline-none focus:border-sentinel-cyan transition-colors"
          />
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="bg-sentinel-card border border-sentinel-border rounded-xl shadow-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-sentinel-navy text-sentinel-textMuted uppercase border-b border-sentinel-border/70">
              <tr>
                <th className="px-4 py-3">Timestamp (UTC)</th>
                <th className="px-4 py-3">Action</th>
                <th className="px-4 py-3">Actor Identity</th>
                <th className="px-4 py-3">Role</th>
                <th className="px-4 py-3">Target Request ID</th>
                <th className="px-4 py-3">Client IP</th>
                <th className="px-4 py-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-sentinel-border/40">
              {filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-sentinel-textMuted">
                    {loading ? 'Aggregating forensic audit trails...' : 'No audit records found.'}
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log) => (
                  <tr
                    key={log.audit_id}
                    onClick={() => setSelectedRecord(log)}
                    className="hover:bg-sentinel-hover/60 transition-colors cursor-pointer"
                  >
                    <td className="px-4 py-3 whitespace-nowrap text-sentinel-textMuted">
                      {new Date(log.performed_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getActionBadge(log.action)}`}>
                        {log.action}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-semibold text-sentinel-textBright whitespace-nowrap">
                      {log.actor_id}
                    </td>
                    <td className="px-4 py-3 text-sentinel-cyan whitespace-nowrap">
                      {log.actor_role}
                    </td>
                    <td className="px-4 py-3 text-sentinel-textMuted whitespace-nowrap">
                      {log.request_id.substring(0, 13)}...
                    </td>
                    <td className="px-4 py-3 text-amber-400 whitespace-nowrap">
                      {log.client_ip || '127.0.0.1'}
                    </td>
                    <td className="px-4 py-3 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedRecord(log);
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

      {/* Audit Detail Modal */}
      {selectedRecord && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="bg-sentinel-card border border-sentinel-border rounded-2xl w-full max-w-2xl max-h-[85vh] overflow-y-auto shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-sentinel-border pb-3">
              <div>
                <span className="text-[10px] font-mono uppercase tracking-wider text-sentinel-textMuted">
                  Audit Entry Details
                </span>
                <h3 className="text-sm font-bold font-mono text-sentinel-textBright">
                  {selectedRecord.action} by {selectedRecord.actor_id}
                </h3>
              </div>
              <button
                onClick={() => setSelectedRecord(null)}
                className="p-1 rounded-lg text-sentinel-textMuted hover:text-white hover:bg-sentinel-navy"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs font-mono bg-sentinel-navy p-3 rounded-lg border border-sentinel-border/60">
              <div>
                <span className="text-sentinel-textMuted block text-[10px]">RECORD ID</span>
                <span className="text-sentinel-textBright">{selectedRecord.audit_id}</span>
              </div>
              <div>
                <span className="text-sentinel-textMuted block text-[10px]">TIMESTAMP</span>
                <span className="text-sentinel-textBright">{selectedRecord.performed_at}</span>
              </div>
              <div>
                <span className="text-sentinel-textMuted block text-[10px]">REQUEST ID</span>
                <span className="text-sentinel-cyan">{selectedRecord.request_id}</span>
              </div>
              <div>
                <span className="text-sentinel-textMuted block text-[10px]">CLIENT IP</span>
                <span className="text-amber-400">{selectedRecord.client_ip || '127.0.0.1'}</span>
              </div>
            </div>

            <div>
              <span className="text-xs font-mono text-sentinel-textMuted block mb-1">
                STRUCTURED FORENSIC SNAPSHOT & EVIDENCE
              </span>
              <pre className="bg-sentinel-darkest border border-sentinel-border/50 rounded-lg p-3 text-[11px] font-mono text-sentinel-cyan overflow-x-auto max-h-72">
                {JSON.stringify(selectedRecord.details, null, 2)}
              </pre>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedRecord(null)}
                className="px-4 py-1.5 rounded-lg bg-sentinel-navy hover:bg-sentinel-hover border border-sentinel-border text-xs font-mono text-sentinel-textMuted"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
