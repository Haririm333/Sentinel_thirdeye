import React from 'react';
import {
  LayoutDashboard,
  Radio,
  AlertTriangle,
  Cpu,
  CheckCheck,
  FileText,
  ShieldCheck,
} from 'lucide-react';

export type ActiveTab = 'overview' | 'live-events' | 'incidents' | 'ai-detection' | 'bank-approvals' | 'audit-trail';

interface SidebarProps {
  activeTab: ActiveTab;
  onTabChange: (tab: ActiveTab) => void;
  incidentCount: number;
  pendingApprovalCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onTabChange,
  incidentCount,
  pendingApprovalCount,
}) => {
  const navItems = [
    {
      id: 'overview' as ActiveTab,
      label: 'Security Overview',
      icon: LayoutDashboard,
      description: 'System posture & key metrics',
    },
    {
      id: 'live-events' as ActiveTab,
      label: 'Live API Monitoring',
      icon: Radio,
      description: 'Streamed activity ingestion',
    },
    {
      id: 'incidents' as ActiveTab,
      label: 'Incident Management',
      icon: AlertTriangle,
      badge: incidentCount > 0 ? incidentCount : undefined,
      badgeColor: 'bg-sentinel-danger text-white',
      description: 'Threats & rule triggers',
    },
    {
      id: 'ai-detection' as ActiveTab,
      label: 'AI Detection Models',
      icon: Cpu,
      description: 'IsoForest & PyTorch LSTM',
    },
    {
      id: 'bank-approvals' as ActiveTab,
      label: 'Bank Change Approvals',
      icon: CheckCheck,
      badge: pendingApprovalCount > 0 ? pendingApprovalCount : undefined,
      badgeColor: 'bg-amber-500 text-slate-900',
      description: 'Two-person approval chain',
    },
    {
      id: 'audit-trail' as ActiveTab,
      label: 'SOC Audit Trail',
      icon: FileText,
      description: 'Immutable ledger records',
    },
  ];

  return (
    <aside className="w-64 bg-sentinel-navy border-r border-sentinel-border flex flex-col justify-between h-[calc(100vh-61px)] flex-shrink-0">
      <div className="p-4 space-y-1 overflow-y-auto">
        <div className="px-3 pb-3 pt-1">
          <p className="text-[11px] font-mono tracking-wider uppercase text-sentinel-textMuted font-semibold">
            SOC Navigation
          </p>
        </div>

        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-left transition-all ${
                isActive
                  ? 'bg-sentinel-card text-sentinel-accent border border-sentinel-accent/30 shadow-md font-medium'
                  : 'text-sentinel-textMuted hover:text-sentinel-textBright hover:bg-sentinel-card/60'
              }`}
            >
              <div className="flex items-center space-x-3 truncate">
                <Icon className={`w-4 h-4 flex-shrink-0 ${isActive ? 'text-sentinel-accent' : 'text-sentinel-textMuted'}`} />
                <div className="truncate">
                  <div className="text-xs font-medium leading-none">{item.label}</div>
                  <div className="text-[10px] text-sentinel-textMuted mt-1 truncate">{item.description}</div>
                </div>
              </div>

              {item.badge !== undefined && (
                <span
                  className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold flex-shrink-0 ${item.badgeColor}`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Footer SOC Status */}
      <div className="p-4 border-t border-sentinel-border/70 bg-sentinel-darkest/60">
        <div className="flex items-center space-x-2 text-xs text-sentinel-textMuted">
          <ShieldCheck className="w-4 h-4 text-sentinel-accent flex-shrink-0" />
          <div className="font-mono text-[11px] leading-tight">
            <span className="text-sentinel-textBright font-semibold block">SENTINEL SOC v1.0</span>
            <span className="text-sentinel-cyan">Deterministic + AI Pipeline</span>
          </div>
        </div>
      </div>
    </aside>
  );
};
