import React, { useState, useEffect } from 'react';
import { Shield, Activity, User, ChevronDown, CheckCircle2 } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { getHealth } from '../api/client';

export const Header: React.FC = () => {
  const { activePersona, setActivePersona, availablePersonas } = useAuth();
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [health, setHealth] = useState<{ status: string; version: string; database?: { latency_ms: number } } | null>(null);

  useEffect(() => {
    getHealth()
      .then(setHealth)
      .catch(() => setHealth({ status: 'degraded', version: '1.0.0' }));
    
    const interval = setInterval(() => {
      getHealth()
        .then(setHealth)
        .catch(() => setHealth({ status: 'degraded', version: '1.0.0' }));
    }, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="bg-sentinel-navy border-b border-sentinel-border px-6 py-3 flex items-center justify-between shadow-md">
      {/* Brand & SOC Health Status */}
      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-sentinel-darkest border border-sentinel-accent/40 rounded-lg text-sentinel-accent glow-accent">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-mono font-bold text-lg tracking-wider text-sentinel-textBright">SENTINEL</span>
              <span className="text-xs px-2 py-0.5 rounded bg-sentinel-accent/10 border border-sentinel-accent/30 text-sentinel-accent font-mono font-medium">
                SOC ACTIVE
              </span>
            </div>
            <p className="text-xs text-sentinel-textMuted font-mono">
              API Behaviour Monitoring & Threat Detection Engine
            </p>
          </div>
        </div>

        {/* Backend & DB Health pill */}
        <div className="hidden lg:flex items-center space-x-3 pl-6 border-l border-sentinel-border/60">
          <div className="flex items-center space-x-2 text-xs font-mono text-sentinel-textMuted bg-sentinel-card px-3 py-1.5 rounded border border-sentinel-border">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span>API v{health?.version || '1.0.0'}</span>
            <span className="text-sentinel-border">|</span>
            <span className="text-sentinel-cyan">
              PostgreSQL: {health?.database?.latency_ms ? `${health.database.latency_ms.toFixed(1)}ms` : 'Connected'}
            </span>
          </div>
        </div>
      </div>

      {/* Role / Persona Switcher */}
      <div className="relative">
        <div className="flex items-center space-x-3">
          <span className="hidden sm:inline text-xs font-mono text-sentinel-textMuted">SIMULATED IDENTITY:</span>
          <button
            onClick={() => setDropdownOpen(!dropdownOpen)}
            className="flex items-center space-x-3 bg-sentinel-card hover:bg-sentinel-hover border border-sentinel-border px-3 py-1.5 rounded-lg transition-colors focus:outline-none focus:ring-1 focus:ring-sentinel-accent"
          >
            <div className={`w-7 h-7 rounded-full flex items-center justify-center text-white text-xs font-bold ${activePersona.avatarColor}`}>
              {activePersona.name.split(' ').map(n => n[0]).join('')}
            </div>
            <div className="text-left">
              <div className="text-xs font-semibold text-sentinel-textBright">{activePersona.name}</div>
              <div className="text-[10px] text-sentinel-textMuted font-mono leading-none">
                {activePersona.role} ({activePersona.systemRole})
              </div>
            </div>
            <ChevronDown className="w-4 h-4 text-sentinel-textMuted" />
          </button>
        </div>

        {/* Dropdown Menu */}
        {dropdownOpen && (
          <>
            <div className="fixed inset-0 z-40" onClick={() => setDropdownOpen(false)} />
            <div className="absolute right-0 mt-2 w-80 bg-sentinel-card border border-sentinel-border rounded-xl shadow-2xl py-2 z-50">
              <div className="px-4 py-2 border-b border-sentinel-border/60">
                <p className="text-xs font-semibold text-sentinel-cyan uppercase tracking-wider font-mono">
                  Role-Based Identity Switcher
                </p>
                <p className="text-[11px] text-sentinel-textMuted mt-0.5">
                  Simulates user header for two-person approvals & RBAC enforcement.
                </p>
              </div>

              <div className="max-h-72 overflow-y-auto py-1">
                {availablePersonas.map((persona) => {
                  const isSelected = persona.id === activePersona.id;
                  return (
                    <button
                      key={persona.id}
                      onClick={() => {
                        setActivePersona(persona);
                        setDropdownOpen(false);
                      }}
                      className={`w-full px-4 py-2.5 text-left flex items-start space-x-3 hover:bg-sentinel-hover transition-colors ${
                        isSelected ? 'bg-sentinel-hover/80 border-l-4 border-sentinel-accent' : ''
                      }`}
                    >
                      <div className={`w-8 h-8 rounded-full flex-shrink-0 flex items-center justify-center text-white text-xs font-bold ${persona.avatarColor}`}>
                        {persona.name.split(' ').map(n => n[0]).join('')}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-semibold text-sentinel-textBright truncate">
                            {persona.name}
                          </span>
                          {isSelected && <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-accent" />}
                        </div>
                        <p className="text-[11px] text-sentinel-cyan font-mono">{persona.role} • {persona.systemRole}</p>
                        <p className="text-[10px] text-sentinel-textMuted truncate mt-0.5">{persona.description}</p>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          </>
        )}
      </div>
    </header>
  );
};
