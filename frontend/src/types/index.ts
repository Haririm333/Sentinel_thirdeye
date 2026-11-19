export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
export type BankChangeStatus = 'PENDING_APPROVAL' | 'PARTIALLY_APPROVED' | 'APPROVED' | 'REJECTED' | 'CANCELLED';

export interface ApiEvent {
  id: number;
  event_id: string;
  timestamp: string;
  received_at: string;
  source_system: 'LedgerOne' | 'HelpDeskr' | 'TallyBridge' | string;
  service_identity: string;
  endpoint: string;
  http_method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | string;
  http_status_code: number;
  request_size_bytes: number;
  response_size_bytes: number;
  source_ip: string;
  auth_identity: string;
  action: string;
  resource_type: string;
  resource_id: string;
  approval_reference?: string | null;
  payload_hash: string;
}

export interface Incident {
  incident_id: string;
  title: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  status: IncidentStatus;
  risk_score: number;
  event_id: string;
  source_system: string;
  service_identity: string;
  endpoint: string;
  http_method: string;
  source_ip: string;
  auth_identity: string;
  explanation: string;
  evidence: Record<string, any>;
  contributing_components?: string[];
  correlated_incident_ids?: string[];
  created_at: string;
  updated_at: string;
}

export interface UnifiedAssessment {
  assessment_id: string;
  event_id: string;
  service_identity: string;
  source_system: string;
  overall_risk_score: number;
  overall_risk_level: Severity;
  primary_detector: string;
  contributing_components: string[];
  findings_summary: string;
  deterministic_rule_findings: Array<{
    rule_id: string;
    rule_name: string;
    triggered: boolean;
    severity?: Severity;
    score?: number;
    explanation?: string;
  }>;
  isolation_forest_result: {
    service_identity?: string;
    is_anomaly: boolean;
    raw_anomaly_score?: number;
    normalized_risk_score?: number;
    calibrated_threshold?: number;
    model_status: string;
    explanation?: string;
    top_deviations?: Array<{
      feature: string;
      deviation_score: number;
      value: number;
    }>;
  };
  lstm_autoencoder_result: {
    service_identity?: string;
    is_anomaly: boolean;
    reconstruction_error?: number;
    calibrated_threshold?: number;
    normalized_risk_score?: number;
    sequence_length?: number;
    model_status: string;
    explanation?: string;
    top_feature_reconstruction_errors?: Array<{
      feature: string;
      error: number;
      ratio_to_normal?: number;
    }>;
  };
  evidence_snapshot: Record<string, any>;
  assessed_at: string;
}

export interface AssessmentSummary {
  total_assessed_events: number;
  total_incidents: number;
  component_trigger_counts: {
    DETERMINISTIC_RULES?: number;
    ISOLATION_FOREST?: number;
    LSTM_AUTOENCODER?: number;
    MULTI_TIER_CORRELATED?: number;
    [key: string]: number | undefined;
  };
  severity_distribution: {
    LOW?: number;
    MEDIUM?: number;
    HIGH?: number;
    CRITICAL?: number;
    [key: string]: number | undefined;
  };
  average_risk_score: number;
  model_status: {
    deterministic_engine: {
      rules_active: number;
      status: string;
    };
    isolation_forest: Record<string, {
      status: string;
      model_id: string;
      calibrated_threshold: number;
      trained_at: string;
    }>;
    lstm_autoencoder: Record<string, {
      status: string;
      model_id: string;
      calibrated_threshold: number;
      trained_at: string;
    }>;
  };
}

export interface BankApprovalStep {
  approver_id: string;
  approver_role: string;
  approval_step: number;
  approved_at: string;
  notes?: string;
}

export interface BankChangeRequest {
  request_id: string;
  vendor_id: string;
  requester_id: string;
  old_bank_account_ref: string;
  proposed_bank_account_ref: string;
  proposed_bank_name: string;
  proposed_routing_masked: string;
  request_reason: string;
  status: BankChangeStatus;
  fingerprint: string;
  version: number;
  approval_count: number;
  approvals: BankApprovalStep[];
  created_at: string;
  updated_at: string;
  expires_at: string;
  rejection_reason?: string | null;
  cancelled_by?: string | null;
  linked_incident_ids: string[];
  security_warnings: string[];
  risk_assessment_snapshot?: {
    vendor_id?: string;
    requester_id?: string;
    associated_incidents_count?: number;
    max_incident_severity?: Severity;
    max_incident_risk_score?: number;
    security_warnings?: string[];
    two_person_rule_status?: string;
    ai_authorization_override_permitted?: boolean;
    snapshot_timestamp?: string;
    linked_incidents?: Array<{
      incident_id: string;
      rule_id: string;
      rule_name: string;
      severity: Severity;
      risk_score: number;
      explanation: string;
      status: string;
    }>;
  };
}

export interface AuditRecord {
  audit_id: string;
  request_id: string;
  actor_id: string;
  actor_role: string;
  action: 'CREATED' | 'FIRST_APPROVAL' | 'SECOND_APPROVAL' | 'REJECTED' | 'CANCELLED' | string;
  details: Record<string, any>;
  client_ip?: string;
  performed_at: string;
}

export interface UserPersona {
  id: string;
  name: string;
  role: string;
  systemRole: 'REQUESTER' | 'FINANCE_APPROVER' | 'FINANCE_ADMIN' | 'AUDITOR';
  description: string;
  avatarColor: string;
}
