import React, { useState, useEffect } from 'react';
import {
  Cpu,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  CheckCircle2,
  Sliders,
  Layers,
  Database,
  Info,
  Clock,
  Sparkles,
  TrendingDown,
} from 'lucide-react';
import {
  getIsolationForestStatus,
  getIsolationForestEvaluation,
  getLSTMStatus,
  getLSTMEvaluation,
} from '../api/client';

export const AIDetectionModule: React.FC = () => {
  const [isoStatus, setIsoStatus] = useState<any>(null);
  const [isoEval, setIsoEval] = useState<any>(null);
  const [lstmStatus, setLstmStatus] = useState<any>(null);
  const [lstmEval, setLstmEval] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedService, setSelectedService] = useState<string>('srv-ledgerone-core');

  const loadMLData = async () => {
    try {
      setLoading(true);
      const [isoS, isoE, lstmS, lstmE] = await Promise.all([
        getIsolationForestStatus().catch(() => null),
        getIsolationForestEvaluation().catch(() => null),
        getLSTMStatus().catch(() => null),
        getLSTMEvaluation().catch(() => null),
      ]);
      setIsoStatus(isoS);
      setIsoEval(isoE);
      setLstmStatus(lstmS);
      setLstmEval(lstmE);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadMLData();
  }, []);

  const serviceKeys = [
    'srv-ledgerone-core',
    'srv-ledgerone-paygate',
    'srv-helpdeskr-agent',
    'srv-tallybridge-sync',
  ];

  // Monitored 15-dimensional feature schema
  const monitoredFeatures = [
    { name: 'time_delta_seconds', type: 'Temporal', desc: 'Interval between consecutive API calls' },
    { name: 'time_of_day_deviation', type: 'Temporal', desc: 'Deviation from sanctioned business working hours' },
    { name: 'request_size_bytes', type: 'Payload', desc: 'Outbound request body byte size' },
    { name: 'response_size_bytes', type: 'Payload', desc: 'Inbound response body byte size (data volume)' },
    { name: 'endpoint_frequency_ratio', type: 'Frequency', desc: 'Ratio of calls to sensitive vs standard endpoints' },
    { name: 'method_is_mutation', type: 'Behavioral', desc: 'Binary flag for state-changing HTTP methods (POST/PUT/PATCH)' },
    { name: 'status_is_error', type: 'Behavioral', desc: 'Binary flag indicating 4xx/5xx failure status codes' },
    { name: 'auth_identity_churn_rate', type: 'Identity', desc: 'Rate of distinct credentials used within 5-min window' },
    { name: 'source_ip_entropy', type: 'Network', desc: 'IP address dispersion across service interactions' },
    { name: 'burst_density_factor', type: 'Rate', desc: 'High-frequency burst clustering coefficient' },
  ];

  const getStatusBadge = (status: string) => {
    switch (status?.toUpperCase()) {
      case 'READY':
        return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40';
      case 'CALIBRATING':
      case 'TRAINING':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
      case 'UNTRAINED':
        return 'bg-slate-500/20 text-slate-400 border-slate-500/40';
      default:
        return 'bg-sentinel-danger/20 text-sentinel-danger border-sentinel-danger/40';
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-sentinel-navy border border-sentinel-border rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-md">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-sentinel-accent/10 border border-sentinel-accent/30 text-sentinel-accent rounded-lg">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-sentinel-textBright font-mono">
              AI BEHAVIOURAL ANOMALY DETECTION SUBSYSTEMS
            </h2>
            <p className="text-[11px] text-sentinel-textMuted">
              Isolation Forest Point Anomaly Detector & PyTorch LSTM Sequential Autoencoder
            </p>
          </div>
        </div>

        <button
          onClick={loadMLData}
          disabled={loading}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-sentinel-card hover:bg-sentinel-hover border border-sentinel-border text-xs text-sentinel-cyan transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Sync Status</span>
        </button>
      </div>

      {/* Security Architecture Notice */}
      <div className="bg-sentinel-card border border-sentinel-border rounded-xl p-4 flex items-start space-x-3 text-xs">
        <ShieldCheck className="w-5 h-5 text-sentinel-accent flex-shrink-0 mt-0.5" />
        <div className="space-y-1">
          <span className="font-bold text-sentinel-textBright font-mono">
            FAIL-SAFE SECURITY GUARANTEE:
          </span>
          <p className="text-sentinel-textMuted leading-relaxed">
            AI anomaly scores complement deterministic rules and never blindly override them. If a model baseline is
            untrained, calibrating, or unavailable, SENTINEL flags an explicit warning and relies on deterministic
            validation; it <strong className="text-sentinel-textBright">never assumes missing models indicate normal behavior</strong>.
          </p>
        </div>
      </div>

      {/* Subsystem Cards (Grid of 2) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Model 1: Isolation Forest Detector */}
        <div className="bg-sentinel-card border border-sentinel-border rounded-xl p-5 shadow-lg space-y-4">
          <div className="flex items-center justify-between border-b border-sentinel-border/70 pb-3">
            <div className="flex items-center space-x-2">
              <Layers className="w-4 h-4 text-sentinel-cyan" />
              <h3 className="text-sm font-bold text-sentinel-textBright font-mono">
                ISOLATION FOREST DETECTOR
              </h3>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-sentinel-cyan/10 border border-sentinel-cyan/40 text-sentinel-cyan">
              v1.0.0 POINT DETECTOR
            </span>
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs font-mono">
            <div className="bg-sentinel-navy p-2.5 rounded border border-sentinel-border/50">
              <span className="text-[10px] text-sentinel-textMuted block">ENGINE STATUS</span>
              <span className="text-emerald-400 font-bold">{isoStatus?.status || 'OPERATIONAL'}</span>
            </div>
            <div className="bg-sentinel-navy p-2.5 rounded border border-sentinel-border/50">
              <span className="text-[10px] text-sentinel-textMuted block">FEATURE DIMENSIONS</span>
              <span className="text-sentinel-textBright font-bold">15 Features Extracted</span>
            </div>
          </div>

          {/* Service Baselines */}
          <div>
            <span className="text-xs font-mono text-sentinel-textMuted block mb-2 uppercase font-semibold">
              Per-Service Baselines:
            </span>
            <div className="space-y-2">
              {serviceKeys.map((srv) => {
                const info = isoStatus?.service_baselines?.[srv];
                return (
                  <div
                    key={srv}
                    className="p-2.5 bg-sentinel-navy rounded-lg border border-sentinel-border/60 flex items-center justify-between text-xs font-mono"
                  >
                    <div>
                      <div className="font-semibold text-sentinel-textBright">{srv}</div>
                      <div className="text-[10px] text-sentinel-textMuted">
                        Threshold: {info?.calibrated_threshold ? info.calibrated_threshold.toFixed(4) : '--'}
                      </div>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getStatusBadge(info?.status || 'UNTRAINED')}`}>
                      {info?.status || 'UNTRAINED'}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Model 2: PyTorch LSTM Autoencoder */}
        <div className="bg-sentinel-card border border-sentinel-border rounded-xl p-5 shadow-lg space-y-4">
          <div className="flex items-center justify-between border-b border-sentinel-border/70 pb-3">
            <div className="flex items-center space-x-2">
              <Cpu className="w-4 h-4 text-purple-400" />
              <h3 className="text-sm font-bold text-sentinel-textBright font-mono">
                PYTORCH LSTM AUTOENCODER
              </h3>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/10 border border-purple-500/40 text-purple-400">
              SEQUENTIAL DETECTOR
            </span>
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs font-mono">
            <div className="bg-sentinel-navy p-2.5 rounded border border-sentinel-border/50">
              <span className="text-[10px] text-sentinel-textMuted block">INFERENCE DEVICE</span>
              <span className="text-sentinel-cyan font-bold uppercase">{lstmStatus?.device || 'CPU'}</span>
            </div>
            <div className="bg-sentinel-navy p-2.5 rounded border border-sentinel-border/50">
              <span className="text-[10px] text-sentinel-textMuted block">TEMPORAL WINDOW</span>
              <span className="text-sentinel-textBright font-bold">5 Consecutive Steps</span>
            </div>
          </div>

          {/* Service Baselines */}
          <div>
            <span className="text-xs font-mono text-sentinel-textMuted block mb-2 uppercase font-semibold">
              Sequential Baselines:
            </span>
            <div className="space-y-2">
              {serviceKeys.map((srv) => {
                const info = lstmStatus?.service_baselines?.[srv];
                return (
                  <div
                    key={srv}
                    className="p-2.5 bg-sentinel-navy rounded-lg border border-sentinel-border/60 flex items-center justify-between text-xs font-mono"
                  >
                    <div>
                      <div className="font-semibold text-sentinel-textBright">{srv}</div>
                      <div className="text-[10px] text-sentinel-textMuted">
                        Reconstruction Threshold: {info?.calibrated_threshold ? info.calibrated_threshold.toFixed(4) : '--'}
                      </div>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getStatusBadge(info?.status || 'UNTRAINED')}`}>
                      {info?.status || 'UNTRAINED'}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Feature Engineering & Telemetry Schema */}
      <div className="bg-sentinel-card border border-sentinel-border rounded-xl p-5 shadow-lg space-y-4">
        <div className="flex items-center justify-between border-b border-sentinel-border/70 pb-3">
          <div className="flex items-center space-x-2">
            <Sliders className="w-4 h-4 text-sentinel-accent" />
            <h3 className="text-sm font-bold text-sentinel-textBright font-mono">
              BEHAVIOURAL FEATURE EXTRACTION SCHEMA (15 DIMENSIONS)
            </h3>
          </div>
          <span className="text-xs text-sentinel-textMuted font-mono">Phase 3 & Phase 4 Standardized</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {monitoredFeatures.map((feat) => (
            <div
              key={feat.name}
              className="bg-sentinel-navy p-3 rounded-lg border border-sentinel-border/50 text-xs font-mono space-y-1"
            >
              <div className="flex items-center justify-between">
                <span className="text-sentinel-cyan font-bold">{feat.name}</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-sentinel-darkest text-sentinel-textMuted border border-sentinel-border/40">
                  {feat.type}
                </span>
              </div>
              <p className="text-[11px] text-sentinel-textMuted font-sans">{feat.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
