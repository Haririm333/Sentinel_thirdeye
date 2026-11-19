import React, { useState } from 'react';
import { X, ShieldAlert, CheckCircle, AlertTriangle, Send } from 'lucide-react';
import { createBankChangeRequest } from '../api/client';
import { BankChangeRequest } from '../types';
import { useAuth } from '../context/AuthContext';

interface NewBankChangeModalProps {
  isOpen: boolean;
  onClose: () => void;
  onCreated: (request: BankChangeRequest) => void;
}

export const NewBankChangeModal: React.FC<NewBankChangeModalProps> = ({
  isOpen,
  onClose,
  onCreated,
}) => {
  const { activePersona } = useAuth();
  const [vendorId, setVendorId] = useState('vnd_10482');
  const [proposedAccount, setProposedAccount] = useState('ACC-4499220011');
  const [bankName, setBankName] = useState('Barclays Bank UK');
  const [routingNumber, setRoutingNumber] = useState('ROUT-021000021');
  const [reason, setReason] = useState('Annual contract renewal payment routing update');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      setSubmitting(true);
      const res = await createBankChangeRequest({
        vendor_id: vendorId,
        proposed_bank_account: proposedAccount,
        proposed_bank_name: bankName,
        proposed_routing_number: routingNumber,
        request_reason: reason,
      });
      onCreated(res);
      onClose();
    } catch (err: any) {
      setError(err?.response?.data?.message || err?.response?.data?.detail?.message || err.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
      <div className="bg-sentinel-card border border-sentinel-border rounded-2xl w-full max-w-lg shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="p-5 border-b border-sentinel-border flex items-center justify-between bg-sentinel-navy">
          <div>
            <span className="text-[10px] font-mono uppercase tracking-wider text-sentinel-cyan">
              FINANCIAL GOVERNANCE WORKFLOW
            </span>
            <h3 className="text-sm font-bold text-sentinel-textBright">
              Submit Sensitive Vendor Bank Change
            </h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-sentinel-textMuted hover:text-white hover:bg-sentinel-card"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {error && (
            <div className="p-3 bg-sentinel-danger/10 border border-sentinel-danger/40 rounded-lg text-xs font-mono text-sentinel-danger flex items-start space-x-2">
              <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {/* Active Persona Banner */}
          <div className="p-3 bg-sentinel-navy rounded-lg border border-sentinel-border/60 flex items-center justify-between text-xs font-mono">
            <div>
              <span className="text-sentinel-textMuted block text-[10px]">SUBMITTING AS:</span>
              <span className="font-semibold text-sentinel-textBright">{activePersona.name}</span>
            </div>
            <span className="px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-400 border border-indigo-500/40 text-[10px] font-bold">
              {activePersona.systemRole}
            </span>
          </div>

          {/* Vendor ID */}
          <div>
            <label className="text-xs font-mono text-sentinel-textMuted block mb-1">
              VENDOR IDENTIFIER:
            </label>
            <input
              type="text"
              required
              value={vendorId}
              onChange={(e) => setVendorId(e.target.value)}
              placeholder="e.g. vnd_10482"
              className="w-full bg-sentinel-navy border border-sentinel-border rounded-lg px-3 py-2 text-xs font-mono text-sentinel-textBright focus:outline-none focus:border-sentinel-cyan"
            />
          </div>

          {/* Proposed Bank Name */}
          <div>
            <label className="text-xs font-mono text-sentinel-textMuted block mb-1">
              PROPOSED BANK NAME:
            </label>
            <input
              type="text"
              required
              value={bankName}
              onChange={(e) => setBankName(e.target.value)}
              placeholder="e.g. Barclays Bank UK"
              className="w-full bg-sentinel-navy border border-sentinel-border rounded-lg px-3 py-2 text-xs font-mono text-sentinel-textBright focus:outline-none focus:border-sentinel-cyan"
            />
          </div>

          {/* Proposed Bank Account */}
          <div>
            <label className="text-xs font-mono text-sentinel-textMuted block mb-1">
              PROPOSED ACCOUNT NUMBER:
            </label>
            <input
              type="text"
              required
              value={proposedAccount}
              onChange={(e) => setProposedAccount(e.target.value)}
              placeholder="e.g. ACC-4499220011"
              className="w-full bg-sentinel-navy border border-sentinel-border rounded-lg px-3 py-2 text-xs font-mono text-sentinel-textBright focus:outline-none focus:border-sentinel-cyan"
            />
            <p className="text-[10px] text-sentinel-cyan mt-1 font-mono">
              Masking preview: ACC-***masked***{proposedAccount.slice(-4) || 'XXXX'} (Never logged in plaintext)
            </p>
          </div>

          {/* Proposed Routing Number */}
          <div>
            <label className="text-xs font-mono text-sentinel-textMuted block mb-1">
              PROPOSED ROUTING NUMBER / SORT CODE:
            </label>
            <input
              type="text"
              required
              value={routingNumber}
              onChange={(e) => setRoutingNumber(e.target.value)}
              placeholder="e.g. ROUT-021000021"
              className="w-full bg-sentinel-navy border border-sentinel-border rounded-lg px-3 py-2 text-xs font-mono text-sentinel-textBright focus:outline-none focus:border-sentinel-cyan"
            />
          </div>

          {/* Reason */}
          <div>
            <label className="text-xs font-mono text-sentinel-textMuted block mb-1">
              BUSINESS JUSTIFICATION & PURPOSE:
            </label>
            <textarea
              required
              rows={3}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="State the verifiable reason for changing vendor payment coordinates..."
              className="w-full bg-sentinel-navy border border-sentinel-border rounded-lg px-3 py-2 text-xs font-mono text-sentinel-textBright focus:outline-none focus:border-sentinel-cyan resize-none"
            />
          </div>

          {/* Security Notice */}
          <div className="p-3 bg-sentinel-darkest rounded-lg border border-sentinel-border/50 text-[11px] text-sentinel-textMuted flex items-start space-x-2">
            <ShieldAlert className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
            <span>
              Request will enter <strong>PENDING_APPROVAL</strong> state. It strictly requires two distinct
              authorized approvals before changing active payment routing.
            </span>
          </div>

          {/* Action buttons */}
          <div className="flex items-center justify-end space-x-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-sentinel-navy hover:bg-sentinel-hover border border-sentinel-border text-xs font-mono text-sentinel-textMuted"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-4 py-2 rounded-lg bg-sentinel-accent hover:bg-sentinel-accent/80 text-sentinel-darkest font-bold text-xs font-mono flex items-center space-x-1.5 transition-colors disabled:opacity-50"
            >
              <Send className="w-3.5 h-3.5" />
              <span>{submitting ? 'Submitting...' : 'Submit Request'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
