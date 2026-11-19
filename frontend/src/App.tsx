import React, { useState, useEffect } from 'react';
import { AuthProvider } from './context/AuthContext';
import { Header } from './components/Header';
import { Sidebar, ActiveTab } from './components/Sidebar';
import { OverviewModule } from './components/OverviewModule';
import { LiveMonitoringModule } from './components/LiveMonitoringModule';
import { IncidentManagementModule } from './components/IncidentManagementModule';
import { AIDetectionModule } from './components/AIDetectionModule';
import { BankApprovalModule } from './components/BankApprovalModule';
import { AuditTrailModule } from './components/AuditTrailModule';
import { Incident } from './types';
import { getIncidents, getBankChanges } from './api/client';

const DashboardContent: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ActiveTab>('overview');
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [incidentCount, setIncidentCount] = useState<number>(0);
  const [pendingApprovalCount, setPendingApprovalCount] = useState<number>(0);

  // Poll badge counts periodically
  useEffect(() => {
    const fetchCounts = async () => {
      try {
        const [incRes, bankRes] = await Promise.all([
          getIncidents({ status: 'OPEN', limit: 1 }),
          getBankChanges({ status: 'PENDING_APPROVAL', limit: 1 }),
        ]);
        if (incRes) setIncidentCount(incRes.total || 0);
        if (bankRes) setPendingApprovalCount(bankRes.total || 0);
      } catch {
        // quiet fallback
      }
    };

    fetchCounts();
    const interval = setInterval(fetchCounts, 15000);
    return () => clearInterval(interval);
  }, []);

  const handleSelectIncidentFromOverview = (incident: Incident) => {
    setSelectedIncident(incident);
    setActiveTab('incidents');
  };

  return (
    <div className="min-h-screen bg-sentinel-darkest text-sentinel-textBright flex flex-col font-sans">
      <Header />

      <div className="flex-1 flex overflow-hidden">
        <Sidebar
          activeTab={activeTab}
          onTabChange={setActiveTab}
          incidentCount={incidentCount}
          pendingApprovalCount={pendingApprovalCount}
        />

        <main className="flex-1 overflow-y-auto p-6 bg-sentinel-darkest">
          <div className="max-w-7xl mx-auto">
            {activeTab === 'overview' && (
              <OverviewModule
                onNavigate={setActiveTab}
                onSelectIncident={handleSelectIncidentFromOverview}
              />
            )}

            {activeTab === 'live-events' && <LiveMonitoringModule />}

            {activeTab === 'incidents' && (
              <IncidentManagementModule
                selectedIncident={selectedIncident}
                onSelectIncident={setSelectedIncident}
              />
            )}

            {activeTab === 'ai-detection' && <AIDetectionModule />}

            {activeTab === 'bank-approvals' && <BankApprovalModule />}

            {activeTab === 'audit-trail' && <AuditTrailModule />}
          </div>
        </main>
      </div>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <DashboardContent />
    </AuthProvider>
  );
};

export default App;
