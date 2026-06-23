// Shared TypeScript types for matthunder frontend

export interface User {
  id: string
  username: string
  email: string
  is_active: boolean
  is_superuser: boolean
  created_at: string
  updated_at?: string
}

export interface Target {
  id: string
  domain: string
  notes?: string
  scope?: Record<string, any>
  created_by?: string
  created_at: string
  updated_at: string
}

export interface Scan {
  id: string
  target_id: string
  scan_type: string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  speed: 'low' | 'standard' | 'fast'
  celery_task_id?: string
  started_at?: string
  completed_at?: string
  created_by?: string
  metadata?: Record<string, any>
  created_at: string
  progress_pct?: number
  current_stage?: string
}

export interface Finding {
  id: string
  scan_id: string
  scanner: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  category?: string
  title?: string
  description?: string
  url?: string
  source_url?: string
  evidence?: string
  http_code?: number
  status: 'new' | 'confirmed' | 'false_positive' | 'fixed'
  cve_id?: string
  cvss_score?: number
  remediation?: string
  metadata?: Record<string, any>
  created_at: string
}

export interface ScanLog {
  id: number
  scan_id: string
  level: 'info' | 'warn' | 'error' | 'success'
  message: string
  timestamp: string
}

export interface Report {
  id: string
  scan_id: string
  report_type: string
  file_path: string
  file_size?: number
  generated_at: string
  created_by?: string
}

export interface Scanner {
  name: string
  display_name: string
  description: string
  category: string
  is_active: boolean
}

export interface AIProvider {
  name: string
  configured: boolean
  default_model: string
  available_models: string[]
}

export interface ApprovalRequest {
  id: string
  request_type: string
  requestor_id: string
  reviewer_id?: string
  target_id?: string
  scan_id?: string
  payload: Record<string, any>
  reason?: string
  status: 'pending' | 'approved' | 'rejected' | 'expired'
  review_comment?: string
  requested_at: string
  reviewed_at?: string
  expires_at?: string
}

export interface AuditLog {
  id: string
  user_id?: string
  action: string
  resource_type?: string
  resource_id?: string
  details?: Record<string, any>
  ip_address?: string
  status: string
  created_at: string
}

export interface APIKey {
  id: string
  name: string
  scopes?: string[]
  expires_at?: string
  last_used_at?: string
  is_active: boolean
  created_at: string
}

export interface LoginResponse {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
  user_id: string
}

export interface WSMessage {
  type: 'log' | 'status' | 'error' | 'complete'
  data: Record<string, any>
  timestamp?: string
}
