import React, { useState, useEffect } from 'react';
import {
  CheckCheck,
  Plus,
  RefreshCw,
  AlertTriangle,
  ShieldAlert,
  Clock,
  User,
  CheckCircle2,
  XCircle,
  FileText,
  Ban,
  ArrowRight,
  ShieldCheck,
  Fingerprint,
} from 'lucide-react';
import { BankChangeRequest, AuditRecord } from '../types';
import {
  getBankChanges,
  approveBankChange,
  rejectBankChange,
  cancelBankChange,
  getBankChangeAudit,
} from '../api/client';
import { useAuth } from '../context/AuthContext';
import { NewBankChangeModal } from './NewBankChangeModal';

export const BankApprovalModule: React.FC = () => {
  const { activePersona } = useAuth();
  const [requests, setRequests] = useState<BankChangeRequest[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedRequest, setSelectedRequest] = useState<BankChangeRequest | null>(null);
  const [isNewModalOpen, setIsNewModalOpen] = useState<boolean>(false);
  const [actionInProgress, setActionInProgress] = useState<boolean>(false);
  const [actionMessage, setActionMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [auditRecords, setAuditRecords] = useState<AuditRecord[] | null>(null);
  const [rejectionReasonInput, setRejectionReasonInput] = useState<string>('');
  const [showRejectPrompt, setShowRejectPrompt] = useState<boolean>(false);
  const [approvalNotes, setApprovalNotes] = useState<string>('');

  const fetchRequests = async () => {
    try {
      setLoading(true);
      const res = await getBankChanges({ limit: 50 });
      if (res && res.items) {
        setRequests(res.items);
        if (selectedRequest) {
          const updated = res.items.find((r) => r.request_id === selectedRequest.request_id);
          if (updated) setSelectedRequest(updated);
        }
      }
    } catch (err) {
      console.error('Failed to fetch bank changes:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRequests();
  }, []);

  const handleSelectRequest = async (req: BankChangeRequest) => {
    setSelectedRequest(req);
    setActionMessage(null);
    setShowRejectPrompt(false);
    setAuditRecords(null);
    try {
      const audit = await getBankChangeAudit(req.request_id);
      setAuditRecords(audit.audit_trail);
    } catch {
      // audit load fallback
    }
  };

  const handleApprove = async () => {
    if (!selectedRequest) return;
    try {
      setActionInProgress(true);
      setActionMessage(null);
      const updated = await approveBankChange(selectedRequest.request_id, approvalNotes);
      setActionMessage({ type: 'success', text: `Approval successfully recorded by ${activePersona.name}!` });
      setSelectedRequest(updated);
      setApprovalNotes('');
      fetchRequests();
    } catch (err: any) {
      const msg = err?.response?.data?.message || err?.response?.data?.detail?.message || err.message;
      setActionMessage({ type: 'error', text: msg });
    } finally {
      setActionInProgress(false);
    }
  };

  const handleReject = async () => {
    if (!selectedRequest || !rejectionReasonInput.trim()) return;
    try {
      setActionInProgress(true);
      setActionMessage(null);
      const updated = await rejectBankChange(selectedRequest.request_id, rejectionReasonInput);
      setActionMessage({ type: 'success', text: `Request rejected by ${activePersona.name}.` });
      setSelectedRequest(updated);
      setShowRejectPrompt(false);
      setRejectionReasonInput('');
      fetchRequests();
    } catch (err: any) {
      const msg = err?.response?.data?.message || err?.response?.data?.detail?.message || err.message;
      setActionMessage({ type: 'error', text: msg });
    } finally {
      setActionInProgress(false);
    }
  };

  const handleCancel = async () => {
    if (!selectedRequest) return;
    try {
      setActionInProgress(true);
      setActionMessage(null);
      const updated = await cancelBankChange(selectedRequest.request_id);
      setActionMessage({ type: 'success', text: `Request cancelled.` });
      setSelectedRequest(updated);
      fetchRequests();
    } catch (err: any) {
      const msg = err?.response?.data?.message || err?.response?.data?.detail?.message || err.message;
      setActionMessage({ type: 'error', text: msg });
    } finally {
      setActionInProgress(false);
    }
  };

  // Anti-Self-Approval and Anti-Duplicate-Approver UI Guards
  const isRequester = selectedRequest?.requester_id === activePersona.id;
  const hasAlreadyApproved = selectedRequest?.approvals?.some(
    (appr) => appr.approver_id === activePersona.id
  );
  const isPendingState =
    selectedRequest?.status === 'PENDING_APPROVAL' ||
    selectedRequest?.status === 'PARTIALLY_APPROVED';

  let approvalDisabledReason: string | null = null;
  if (!isPendingState) {
    approvalDisabledReason = `Request is ${selectedRequest?.status}; no further approvals can be recorded.`;
  } else if (isRequester) {
    approvalDisabledReason = `ANTI-SELF-APPROVAL ENFORCED: Requesters (${activePersona.id}) cannot approve their own bank change requests. Switch persona to an authorized Approver in the top header.`;
  } else if (hasAlreadyApproved) {
    approvalDisabledReason = `ANTI-DUPLICATE APPROVER ENFORCED: You (${activePersona.id}) already provided approval step 1. Two distinct human approvers are strictly required. Switch persona to Approver 2.`;
  }

  const getStatusBadge = (st: string) => {
    switch (st) {
      case 'PENDING_APPROVAL':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
      case 'PARTIALLY_APPROVED':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
      case 'APPROVED':
        return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40';
      case 'REJECTED':
        return 'bg-red-500/20 text-red-400 border-red-500/40';
      case 'CANCELLED':
        return 'bg-slate-500/20 text-slate-400 border-slate-500/40';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/40';
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header Card */}
      <div className="bg-sentinel-navy border border-sentinel-border rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-md">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-amber-500/10 border border-amber-500/30 text-amber-400 rounded-lg">
            <CheckCheck className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-sentinel-textBright font-mono">
              TWO-PERSON BANK CHANGE APPROVAL & LEDGER ENFORCEMENT
            </h2>
            <p className="text-[11px] text-sentinel-textMuted">
              Deterministic separation of duties: 2 distinct human sign-offs required before vendor routing changes
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => setIsNewModalOpen(true)}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-sentinel-accent hover:bg-sentinel-accent/80 text-sentinel-darkest font-bold text-xs font-mono transition-colors shadow"
          >
            <Plus className="w-4 h-4" />
            <span>New Change Request</span>
          </button>
          <button
            onClick={fetchRequests}
            disabled={loading}
            className="p-1.5 bg-sentinel-card hover:bg-sentinel-hover border border-sentinel-border rounded-lg text-sentinel-cyan transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Main Grid: Requests List & Details Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Requests List */}
        <div className="lg:col-span-1 bg-sentinel-card border border-sentinel-border rounded-xl shadow-lg overflow-hidden flex flex-col h-[700px]">
          <div className="p-3.5 border-b border-sentinel-border bg-sentinel-navy flex items-center justify-between">
            <span className="text-xs font-mono uppercase font-bold text-sentinel-textBright">
              Requests ({requests.length})
            </span>
            <span className="text-[10px] text-sentinel-textMuted font-mono">
              Pending: {requests.filter((r) => r.status.includes('PENDING') || r.status.includes('PARTIAL')).length}
            </span>
          </div>

          <div className="divide-y divide-sentinel-border/50 overflow-y-auto flex-1">
            {requests.length === 0 ? (
              <div className="p-6 text-center text-xs text-sentinel-textMuted font-mono">
                No bank change requests found.
              </div>
            ) : (
              requests.map((req) => {
                const isSelected = selectedRequest?.request_id === req.request_id;
                const hasWarnings = req.security_warnings && req.security_warnings.length > 0;
                return (
                  <div
                    key={req.request_id}
                    onClick={() => handleSelectRequest(req)}
                    className={`p-3.5 hover:bg-sentinel-hover/60 transition-colors cursor-pointer ${
                      isSelected ? 'bg-sentinel-hover/80 border-l-4 border-sentinel-accent' : ''
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-sentinel-textBright">
                        {req.vendor_id}
                      </span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getStatusBadge(req.status)}`}>
                        {req.status}
                      </span>
                    </div>

                    <div className="text-[11px] font-mono text-sentinel-cyan mt-1 truncate">
                      {req.proposed_bank_name}
                    </div>

                    <div className="flex items-center justify-between text-[10px] font-mono text-sentinel-textMuted mt-2">
                      <span>By: {req.requester_id}</span>
                      <span>Approvals: {req.approval_count}/2</span>
                    </div>

                    {hasWarnings && (
                      <div className="mt-2 flex items-center space-x-1 text-[10px] text-sentinel-danger font-mono bg-sentinel-danger/10 px-1.5 py-0.5 rounded border border-sentinel-danger/30">
                        <AlertTriangle className="w-3 h-3 flex-shrink-0" />
                        <span className="truncate">{req.security_warnings.length} Security Incident(s) Linked</span>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Request Details & Action Panel */}
        <div className="lg:col-span-2 bg-sentinel-card border border-sentinel-border rounded-xl shadow-lg p-6 flex flex-col h-[700px] overflow-y-auto space-y-6">
          {!selectedRequest ? (
            <div className="h-full flex flex-col items-center justify-center text-sentinel-textMuted text-xs font-mono">
              <CheckCheck className="w-12 h-12 text-sentinel-border mb-3" />
              <span>Select a bank change request from the left column to review.</span>
            </div>
          ) : (
            <>
              {/* Header Info */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-sentinel-border gap-2">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="text-base font-bold font-mono text-sentinel-textBright">
                      Vendor: {selectedRequest.vendor_id}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getStatusBadge(selectedRequest.status)}`}>
                      {selectedRequest.status}
                    </span>
                  </div>
                  <span className="text-[10px] text-sentinel-textMuted font-mono">
                    Request ID: {selectedRequest.request_id}
                  </span>
                </div>

                <div className="text-right text-xs font-mono text-sentinel-textMuted">
                  <div>Created: {new Date(selectedRequest.created_at).toLocaleString()}</div>
                  <div className="text-amber-400">Expires: {new Date(selectedRequest.expires_at).toLocaleDateString()}</div>
                </div>
              </div>

              {/* Action Response Banner */}
              {actionMessage && (
                <div
                  className={`p-3 rounded-lg border text-xs font-mono flex items-center space-x-2 ${
                    actionMessage.type === 'success'
                      ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-400'
                      : 'bg-sentinel-danger/10 border-sentinel-danger/40 text-sentinel-danger'
                  }`}
                >
                  {actionMessage.type === 'success' ? (
                    <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                  )}
                  <span>{actionMessage.text}</span>
                </div>
              )}

              {/* Linked Security Warnings Banner */}
              {selectedRequest.security_warnings && selectedRequest.security_warnings.length > 0 && (
                <div className="p-4 bg-sentinel-danger/10 border border-sentinel-danger/40 rounded-xl space-y-2">
                  <div className="flex items-center space-x-2 text-xs font-bold font-mono text-sentinel-danger">
                    <ShieldAlert className="w-4 h-4" />
                    <span>LINKED SECURITY INCIDENT WARNINGS (HIGH-RISK VENDOR ACTIVITY)</span>
                  </div>
                  <ul className="space-y-1.5 text-xs text-sentinel-textBright font-mono">
                    {selectedRequest.security_warnings.map((warn, idx) => (
                      <li key={idx} className="bg-sentinel-navy/80 p-2 rounded border border-sentinel-danger/30 text-[11px]">
                        {warn}
                      </li>
                    ))}
                  </ul>
                  <p className="text-[10px] text-sentinel-textMuted font-mono">
                    AI anomaly detection signals caution. Two independent authorized human approvers are strictly required.
                  </p>
                </div>
              )}

              {/* Two-Person Approval Chain Visual Progression */}
              <div className="bg-sentinel-navy p-4 rounded-xl border border-sentinel-border space-y-3">
                <span className="text-xs font-mono uppercase font-bold text-sentinel-cyan block">
                  TWO-PERSON SEPARATION OF DUTIES WORKFLOW
                </span>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
                  {/* Step 1: Requester */}
                  <div className="p-3 rounded-lg bg-sentinel-card border border-sentinel-border/70 flex flex-col justify-between">
                    <div>
                      <span className="text-[10px] text-sentinel-textMuted block">STEP 1: SUBMITTED</span>
                      <span className="text-sentinel-textBright font-semibold truncate block">
                        {selectedRequest.requester_id}
                      </span>
                    </div>
                    <div className="mt-2 text-emerald-400 flex items-center space-x-1 text-[10px]">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Initiated</span>
                    </div>
                  </div>

                  {/* Step 2: Approver 1 */}
                  <div className={`p-3 rounded-lg border flex flex-col justify-between ${
                    selectedRequest.approvals?.[0]
                      ? 'bg-sentinel-card border-emerald-500/50'
                      : 'bg-sentinel-card/40 border-sentinel-border/50'
                  }`}>
                    <div>
                      <span className="text-[10px] text-sentinel-textMuted block">STEP 2: APPROVER 1</span>
                      <span className="text-sentinel-textBright font-semibold truncate block">
                        {selectedRequest.approvals?.[0]?.approver_id || 'Pending Controller Review'}
                      </span>
                    </div>
                    <div className="mt-2 text-[10px]">
                      {selectedRequest.approvals?.[0] ? (
                        <span className="text-emerald-400 flex items-center space-x-1">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Approved</span>
                        </span>
                      ) : (
                        <span className="text-amber-400 flex items-center space-x-1">
                          <Clock className="w-3.5 h-3.5" />
                          <span>Awaiting Sign-off</span>
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Step 3: Approver 2 */}
                  <div className={`p-3 rounded-lg border flex flex-col justify-between ${
                    selectedRequest.approvals?.[1]
                      ? 'bg-sentinel-card border-emerald-500/50'
                      : 'bg-sentinel-card/40 border-sentinel-border/50'
                  }`}>
                    <div>
                      <span className="text-[10px] text-sentinel-textMuted block">STEP 3: APPROVER 2</span>
                      <span className="text-sentinel-textBright font-semibold truncate block">
                        {selectedRequest.approvals?.[1]?.approver_id || 'Pending VP Sign-off'}
                      </span>
                    </div>
                    <div className="mt-2 text-[10px]">
                      {selectedRequest.approvals?.[1] ? (
                        <span className="text-emerald-400 flex items-center space-x-1">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Approved & Committed</span>
                        </span>
                      ) : (
                        <span className="text-sentinel-textMuted flex items-center space-x-1">
                          <Clock className="w-3.5 h-3.5" />
                          <span>Awaiting Step 2</span>
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              {/* Financial Account Coordinates (Strictly Masked) */}
              <div className="grid grid-cols-2 gap-4 text-xs font-mono bg-sentinel-navy p-4 rounded-xl border border-sentinel-border">
                <div className="space-y-1">
                  <span className="text-sentinel-textMuted text-[10px] block">CURRENT ACTIVE ACCOUNT (MASKED)</span>
                  <span className="text-sentinel-textBright font-bold text-sm block">
                    {selectedRequest.old_bank_account_ref || 'None on file'}
                  </span>
                  <span className="text-[10px] text-sentinel-cyan">Active in Ledger until dual approvals commit</span>
                </div>

                <div className="space-y-1">
                  <span className="text-sentinel-textMuted text-[10px] block">PROPOSED TARGET ACCOUNT (MASKED)</span>
                  <span className="text-sentinel-accent font-bold text-sm block">
                    {selectedRequest.proposed_bank_account_ref}
                  </span>
                  <span className="text-[10px] text-sentinel-textBright">
                    {selectedRequest.proposed_bank_name} • {selectedRequest.proposed_routing_masked}
                  </span>
                </div>
              </div>

              {/* Justification & Fingerprint */}
              <div className="space-y-2 text-xs font-mono">
                <div className="bg-sentinel-navy p-3 rounded-lg border border-sentinel-border/60">
                  <span className="text-sentinel-textMuted block text-[10px] uppercase">Business Purpose</span>
                  <span className="text-sentinel-textBright">{selectedRequest.request_reason}</span>
                </div>

                <div className="bg-sentinel-darkest p-3 rounded-lg border border-sentinel-border/40 text-[10px] flex items-center justify-between">
                  <span className="text-sentinel-textMuted flex items-center space-x-1">
                    <Fingerprint className="w-3.5 h-3.5 text-sentinel-cyan" />
                    <span>Cryptographic Tamper-Proof Fingerprint (SHA-256):</span>
                  </span>
                  <span className="text-sentinel-cyan font-mono truncate max-w-xs">
                    {selectedRequest.fingerprint}
                  </span>
                </div>
              </div>

              {/* Rejection / Cancellation Info if Applicable */}
              {selectedRequest.rejection_reason && (
                <div className="p-3 bg-sentinel-danger/10 border border-sentinel-danger/40 rounded-lg text-xs font-mono text-sentinel-danger">
                  <strong>REJECTION REASON:</strong> {selectedRequest.rejection_reason}
                </div>
              )}

              {/* Approval Controls Section */}
              <div className="border border-sentinel-border rounded-xl p-4 bg-sentinel-navy space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono uppercase font-bold text-sentinel-textBright">
                    APPROVER ACTION CONTROLS
                  </span>
                  <span className="text-xs font-mono text-sentinel-cyan">
                    Logged in: <strong>{activePersona.name}</strong> ({activePersona.systemRole})
                  </span>
                </div>

                {/* Enforcement Warning Banner if Action is Prohibited */}
                {approvalDisabledReason && (
                  <div className="p-3 bg-sentinel-danger/10 border border-sentinel-danger/40 rounded-lg text-xs font-mono text-sentinel-danger flex items-start space-x-2">
                    <Ban className="w-4 h-4 flex-shrink-0 mt-0.5" />
                    <span>{approvalDisabledReason}</span>
                  </div>
                )}

                {/* Optional Approval Notes */}
                {isPendingState && !approvalDisabledReason && (
                  <div>
                    <label className="text-[11px] font-mono text-sentinel-textMuted block mb-1">
                      APPROVAL AUDIT NOTES (OPTIONAL):
                    </label>
                    <input
                      type="text"
                      value={approvalNotes}
                      onChange={(e) => setApprovalNotes(e.target.value)}
                      placeholder="e.g. Verified vendor tax ID and verified voice confirmation"
                      className="w-full bg-sentinel-card border border-sentinel-border rounded-lg px-3 py-1.5 text-xs font-mono text-sentinel-textBright focus:outline-none focus:border-sentinel-cyan"
                    />
                  </div>
                )}

                {/* Rejection Reason Input Box */}
                {showRejectPrompt && (
                  <div className="space-y-2 p-3 bg-sentinel-darkest rounded-lg border border-sentinel-danger/40">
                    <label className="text-xs font-mono text-sentinel-danger block font-bold">
                      REJECTION JUSTIFICATION (MANDATORY):
                    </label>
                    <textarea
                      rows={2}
                      value={rejectionReasonInput}
                      onChange={(e) => setRejectionReasonInput(e.target.value)}
                      placeholder="State exact security or operational reason for rejecting this change..."
                      className="w-full bg-sentinel-navy border border-sentinel-border rounded-lg px-3 py-1.5 text-xs font-mono text-sentinel-textBright focus:outline-none focus:border-sentinel-danger"
                    />
                    <div className="flex items-center justify-end space-x-2">
                      <button
                        onClick={() => setShowRejectPrompt(false)}
                        className="px-3 py-1 rounded bg-sentinel-card text-sentinel-textMuted text-xs font-mono"
                      >
                        Cancel
                      </button>
                      <button
                        onClick={handleReject}
                        disabled={actionInProgress || !rejectionReasonInput.trim()}
                        className="px-3 py-1 rounded bg-sentinel-danger text-white font-bold text-xs font-mono disabled:opacity-50"
                      >
                        Confirm Rejection
                      </button>
                    </div>
                  </div>
                )}

                {/* Primary Action Buttons */}
                <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                  <div className="flex items-center space-x-2">
                    {/* Reject Button */}
                    {isPendingState && !showRejectPrompt && (
                      <button
                        onClick={() => setShowRejectPrompt(true)}
                        disabled={actionInProgress}
                        className="px-3 py-1.5 rounded-lg bg-sentinel-danger/20 hover:bg-sentinel-danger/30 border border-sentinel-danger/40 text-sentinel-danger text-xs font-mono font-bold transition-colors"
                      >
                        Reject Change
                      </button>
                    )}

                    {/* Cancel Button (For requester or admin) */}
                    {isPendingState && (isRequester || activePersona.systemRole === 'FINANCE_ADMIN') && (
                      <button
                        onClick={handleCancel}
                        disabled={actionInProgress}
                        className="px-3 py-1.5 rounded-lg bg-slate-700/30 hover:bg-slate-700/50 border border-slate-600/50 text-slate-300 text-xs font-mono transition-colors"
                      >
                        Cancel Request
                      </button>
                    )}
                  </div>

                  {/* Approve Button */}
                  <button
                    onClick={handleApprove}
                    disabled={actionInProgress || !!approvalDisabledReason}
                    className="px-5 py-2 rounded-lg bg-sentinel-accent hover:bg-sentinel-accent/80 text-sentinel-darkest font-bold text-xs font-mono transition-colors disabled:opacity-40 disabled:cursor-not-allowed flex items-center space-x-1.5 shadow"
                  >
                    <CheckCheck className="w-4 h-4" />
                    <span>
                      {selectedRequest.approval_count === 0 ? 'Provide Approval Step 1' : 'Provide Final Approval Step 2'}
                    </span>
                  </button>
                </div>
              </div>

              {/* Audit Records Sub-table */}
              {auditRecords && auditRecords.length > 0 && (
                <div className="space-y-2">
                  <span className="text-xs font-mono uppercase font-bold text-sentinel-textMuted block">
                    FORENSIC AUDIT LOG FOR THIS REQUEST ({auditRecords.length} ENTRIES)
                  </span>
                  <div className="bg-sentinel-navy rounded-xl border border-sentinel-border/70 overflow-hidden">
                    <table className="w-full text-left text-[11px] font-mono">
                      <thead className="bg-sentinel-darkest text-sentinel-textMuted uppercase border-b border-sentinel-border/50">
                        <tr>
                          <th className="px-3 py-2">Timestamp</th>
                          <th className="px-3 py-2">Actor</th>
                          <th className="px-3 py-2">Action</th>
                          <th className="px-3 py-2">Details</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-sentinel-border/40">
                        {auditRecords.map((rec) => (
                          <tr key={rec.audit_id}>
                            <td className="px-3 py-2 text-sentinel-textMuted">
                              {new Date(rec.performed_at).toLocaleTimeString()}
                            </td>
                            <td className="px-3 py-2 font-semibold text-sentinel-cyan">
                              {rec.actor_id} ({rec.actor_role})
                            </td>
                            <td className="px-3 py-2 font-bold text-sentinel-textBright">
                              {rec.action}
                            </td>
                            <td className="px-3 py-2 text-sentinel-textMuted truncate max-w-xs">
                              {JSON.stringify(rec.details)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>

      {/* New Request Modal */}
      <NewBankChangeModal
        isOpen={isNewModalOpen}
        onClose={() => setIsNewModalOpen(false)}
        onCreated={(req) => {
          fetchRequests();
          setSelectedRequest(req);
        }}
      />
    </div>
  );
};
