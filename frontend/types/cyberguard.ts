export interface Alert {
  incident_id?: string;
  category?: string;
  incident_type?: string;
  title?: string;
  affected_system?: string;
  description?: string;
  severity?: string;
  [key: string]: unknown;
}

export type IncidentAlert = Alert;

export interface HistoricalMatch {
  incident_id: string;
  similarity: number;
  resolution: string;
  outcome?: string;
}

export interface Recommendation {
  resolution_id: string;
  resolution: string;
  response_domain?: string;
  priority?: string;
  rationale?: string;
  response_steps?: string[];
  confidence: number;
  success_rate: number;
  times_used: number;
  successful_resolutions: number;
  alternate_resolution_id?: string;
  alternate_playbook?: string;
  alternate_steps?: string[];
  escalation_tier?: string;
}

export interface InvestigationResult {
  is_cold_start?: boolean;
  historical_matches: HistoricalMatch[];
  recommendation: Recommendation;
  source?: string;
  user_input_preview?: string;
}

export interface FeedbackSubmission {
  incident_id: string;
  resolution_id: string;
  outcome: 'success' | 'failed';
  escalation_count?: number;
}

export interface FeedbackJsonPayload {
  event_type: 'SOC_ANALYST_FEEDBACK';
  timestamp: string;
  incident_id: string;
  resolution_id: string;
  feedback_outcome: 'success' | 'failed';
  escalation_count?: number;
  segment_writeback_target: 'Hindsight_Memory_Worker';
}

export interface FeedbackResponse {
  memory_updated: boolean;
  metrics: Pick<Recommendation, 'times_used' | 'success_rate' | 'successful_resolutions'>;
  historical_matches?: HistoricalMatch[];
  alternate_playbook?: string;
  alternate_steps?: string[];
  escalation_tier?: string;
  is_exhausted?: boolean;
  deep_investigation_memo?: string;
  emergency_actions?: string[];
}