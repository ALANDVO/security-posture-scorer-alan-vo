export interface Finding {
  id: string
  title: string
  category: 'authentication' | 'cryptography' | 'configuration' | 'dependencies'
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  description: string
  file_path?: string
  line_number?: number
  evidence?: string
  deduction_points: number
  remediation: string
}

export interface Deduction {
  category: string
  points: number
  reason: string
  finding_id: string
}

export interface RemediationFix {
  priority: number
  action: string
  effort: string
  impact: string
  roi_score: number
  suggested_patch?: string
}

export interface LLMAdvisory {
  advisory_enabled: boolean
  provider: string
  model: string
  executive_summary: string
  threat_analysis: string
  prioritized_guidance: string[]
  is_fallback: boolean
  error?: string | null
}

export interface ScanResponse {
  id: string
  target_name: string
  target_type: string
  overall_score: number
  grade: string
  category_scores: Record<string, number>
  findings: Finding[]
  deductions: Deduction[]
  fixes: RemediationFix[]
  summary: string
  llm_advisory?: LLMAdvisory | null
  created_at: string
  created_by: string
  status: string
}

export interface ScanListResponse {
  items: ScanResponse[]
  total: number
  skip: number
  limit: number
}

export interface ScanSubmission {
  target_name: string
  target_type: 'codebase' | 'config' | 'headers' | 'manifest'
  content?: string
  file_tree?: Record<string, string>
}

export interface ScanDiffRequest {
  before_scan_id: string
  after_scan_id: string
}

export interface ScanDiffResponse {
  before_id: string
  after_id: string
  score_before: number
  score_after: number
  score_delta: number
  resolved_findings: Finding[]
  new_regressions: Finding[]
  summary: string
  trend: 'IMPROVED' | 'REGRESSED' | 'UNCHANGED'
}

export interface BenchmarkResult {
  id: string
  benchmark_name: string
  sample_count: number
  precision_score: number
  recall_score: number
  f1_score: number
  mean_absolute_error: number
  details: {
    true_positives: number
    false_positives: number
    false_negatives: number
    samples: Array<{
      sample_id: string
      name: string
      expected_vulns: number
      detected_vulns: number
      ground_truth_score: number
      predicted_score: number
      score_delta: number
      grade: string
      findings: string[]
    }>
    evaluation_timestamp: string
  }
  created_at: string
}

export interface AuditLogEntry {
  id: number
  event_type: string
  actor: string
  resource_id: string
  details: Record<string, unknown>
  created_at: string
}

export interface UserProfile {
  sub: string
  email: string
  name: string
  roles: string[]
}

export interface TokenResponse {
  access_token: string
  token_type: string
  expires_in: number
  user: UserProfile
}
