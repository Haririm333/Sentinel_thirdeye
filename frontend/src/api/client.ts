import axios from 'axios';
import {
  ApiEvent,
  Incident,
  IncidentStatus,
  AssessmentSummary,
  UnifiedAssessment,
  BankChangeRequest,
  AuditRecord,
} from '../types';

const API_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

export const apiClient = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 10000,
});

// Inject current authenticated persona identity on every outbound request
apiClient.interceptors.request.use((config) => {
  const personaId = localStorage.getItem('sentinel_active_persona') || 'usr_appr_elena';
  config.headers['X-User-Id'] = personaId;
  return config;
});

// Health & System
export const getHealth = async () => {
  const res = await apiClient.get('/health');
  return res.data;
};

// Unified Assessment Summary
export const getAssessmentSummary = async (): Promise<AssessmentSummary> => {
  const res = await apiClient.get('/api/v1/assessment/summary');
  return res.data;
};

// Events Ingestion Stream
export const getEvents = async (params: {
  page?: number;
  limit?: number;
  source_system?: string;
  service_identity?: string;
} = {}): Promise<{ total: number; page: number; limit: number; pages: number; items: ApiEvent[] }> => {
  const res = await apiClient.get('/api/v1/events', { params });
  return res.data;
};

export const getEventById = async (eventId: string): Promise<ApiEvent> => {
  const res = await apiClient.get(`/api/v1/events/${eventId}`);
  return res.data;
};

// Incidents
export const getIncidents = async (params: {
  page?: number;
  limit?: number;
  status?: string;
  severity?: string;
} = {}): Promise<{ total: number; page: number; limit: number; pages: number; items: Incident[] }> => {
  const res = await apiClient.get('/api/v1/incidents', { params });
  return res.data;
};

export const getIncidentById = async (incidentId: string): Promise<Incident> => {
  const res = await apiClient.get(`/api/v1/incidents/${incidentId}`);
  return res.data;
};

export const updateIncidentStatus = async (
  incidentId: string,
  status: IncidentStatus,
  notes?: string
): Promise<Incident> => {
  const res = await apiClient.patch(`/api/v1/incidents/${incidentId}/status`, {
    status,
    notes: notes || `Status updated to ${status} via SOC dashboard`,
  });
  return res.data;
};

export const getIncidentAssessment = async (incidentId: string): Promise<UnifiedAssessment> => {
  const res = await apiClient.get(`/api/v1/incidents/${incidentId}/assessment`);
  return res.data;
};

export const getEventAssessment = async (eventId: string): Promise<UnifiedAssessment> => {
  const res = await apiClient.get(`/api/v1/assessment/events/${eventId}`);
  return res.data;
};

export const evaluateEventRiskOnDemand = async (eventId: string): Promise<UnifiedAssessment> => {
  const res = await apiClient.post(`/api/v1/assessment/evaluate/${eventId}`);
  return res.data;
};

// AI Models Status & Evaluation
export const getIsolationForestStatus = async () => {
  const res = await apiClient.get('/api/v1/ml/status');
  return res.data;
};

export const getIsolationForestEvaluation = async () => {
  const res = await apiClient.get('/api/v1/ml/evaluation');
  return res.data;
};

export const getLSTMStatus = async () => {
  const res = await apiClient.get('/api/v1/ml/lstm/status');
  return res.data;
};

export const getLSTMEvaluation = async () => {
  const res = await apiClient.get('/api/v1/ml/lstm/evaluation');
  return res.data;
};

// Bank Change Approvals & Enforcement
export const getBankChanges = async (params: {
  status?: string;
  vendor_id?: string;
  page?: number;
  limit?: number;
} = {}): Promise<{ total: number; page: number; limit: number; pages: number; items: BankChangeRequest[] }> => {
  const res = await apiClient.get('/api/v1/bank-changes', { params });
  return res.data;
};

export const getBankChangeById = async (requestId: string): Promise<BankChangeRequest> => {
  const res = await apiClient.get(`/api/v1/bank-changes/${requestId}`);
  return res.data;
};

export const getBankChangeAudit = async (requestId: string): Promise<{ request_id: string; total_records: number; audit_trail: AuditRecord[] }> => {
  const res = await apiClient.get(`/api/v1/bank-changes/${requestId}/audit`);
  if (Array.isArray(res.data)) {
    return {
      request_id: requestId,
      total_records: res.data.length,
      audit_trail: res.data
    };
  }
  return res.data;
};

export const getBankChangeRiskSnapshot = async (requestId: string) => {
  const res = await apiClient.get(`/api/v1/bank-changes/${requestId}/risk-assessment`);
  return res.data;
};

export const createBankChangeRequest = async (payload: {
  vendor_id: string;
  proposed_bank_account: string;
  proposed_bank_name: string;
  proposed_routing_number: string;
  request_reason: string;
}): Promise<BankChangeRequest> => {
  const body = {
    ...payload,
    proposed_account_number: payload.proposed_bank_account
  };
  const res = await apiClient.post('/api/v1/bank-changes', body);
  return res.data;
};

export const approveBankChange = async (requestId: string, notes?: string): Promise<BankChangeRequest> => {
  const res = await apiClient.post(`/api/v1/bank-changes/${requestId}/approve`, {
    comment: notes || '',
    notes: notes || ''
  });
  return res.data;
};

export const rejectBankChange = async (requestId: string, reason: string): Promise<BankChangeRequest> => {
  const res = await apiClient.post(`/api/v1/bank-changes/${requestId}/reject`, { reason });
  return res.data;
};

export const cancelBankChange = async (requestId: string, reason?: string): Promise<BankChangeRequest> => {
  const res = await apiClient.post(`/api/v1/bank-changes/${requestId}/cancel`, {
    reason: reason || 'Cancelled by user'
  });
  return res.data;
};
