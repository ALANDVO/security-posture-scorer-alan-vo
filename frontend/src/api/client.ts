import {
  ScanResponse,
  ScanListResponse,
  ScanSubmission,
  ScanDiffResponse,
  BenchmarkResult,
  AuditLogEntry,
  TokenResponse,
  UserProfile
} from '../types/api'

// In-memory token storage (never persisted in localStorage as per security contract)
let inMemoryAccessToken: string | null = null

export function setAccessToken(token: string | null): void {
  inMemoryAccessToken = token
}

export function getAccessToken(): string | null {
  return inMemoryAccessToken
}

// PKCE utility functions for OIDC flow
export async function generatePKCE(): Promise<{ verifier: string; challenge: string }> {
  const array = new Uint8Array(32)
  crypto.getRandomValues(array)
  const verifier = Array.from(array, dec => dec.toString(16).padStart(2, '0')).join('')

  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  const hash = await crypto.subtle.digest('SHA-256', data)
  const challenge = btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')

  return { verifier, challenge }
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers || {})
  headers.set('Content-Type', 'application/json')

  if (inMemoryAccessToken) {
    headers.set('Authorization', `Bearer ${inMemoryAccessToken}`)
  }

  const response = await fetch(endpoint, {
    ...options,
    headers
  })

  if (!response.ok) {
    let errorDetail = `Request failed: ${response.status} ${response.statusText}`
    try {
      const errJson = await response.json()
      if (errJson.detail) {
        errorDetail = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail)
      }
    } catch {
      // ignore json parse error
    }
    throw new Error(errorDetail)
  }

  return response.json() as Promise<T>
}

export const api = {
  async loginDemo(role: 'viewer' | 'analyst' | 'admin' = 'analyst'): Promise<TokenResponse> {
    const username = `${role}@demo.local`
    const res = await request<TokenResponse>('/api/auth/token', {
      method: 'POST',
      body: JSON.stringify({
        grant_type: 'password',
        username,
        password: 'demo-password'
      })
    })
    setAccessToken(res.access_token)
    return res
  },

  async exchangeOidcCode(code: string, codeVerifier: string): Promise<TokenResponse> {
    const res = await request<TokenResponse>('/api/auth/token', {
      method: 'POST',
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code,
        code_verifier: codeVerifier
      })
    })
    setAccessToken(res.access_token)
    return res
  },

  async getMe(): Promise<UserProfile> {
    return request<UserProfile>('/api/auth/me')
  },

  async getHealth(): Promise<{ status: string; service: string; version: string; demo_mode: boolean }> {
    return request('/api/health')
  },

  async createScan(submission: ScanSubmission): Promise<ScanResponse> {
    return request<ScanResponse>('/api/scans', {
      method: 'POST',
      body: JSON.stringify(submission)
    })
  },

  async listScans(params?: { skip?: number; limit?: number; target?: string }): Promise<ScanListResponse> {
    const q = new URLSearchParams()
    if (params?.skip !== undefined) q.set('skip', params.skip.toString())
    if (params?.limit !== undefined) q.set('limit', params.limit.toString())
    if (params?.target) q.set('target', params.target)
    const qs = q.toString()
    return request<ScanListResponse>(`/api/scans${qs ? '?' + qs : ''}`)
  },

  async getScan(id: string): Promise<ScanResponse> {
    return request<ScanResponse>(`/api/scans/${id}`)
  },

  async deleteScan(id: string): Promise<{ message: string; scan_id: string }> {
    return request(`/api/scans/${id}`, {
      method: 'DELETE'
    })
  },

  async requestAdvisory(scanId: string): Promise<ScanResponse> {
    return request<ScanResponse>(`/api/scans/${scanId}/advise`, {
      method: 'POST'
    })
  },

  async diffScans(beforeScanId: string, afterScanId: string): Promise<ScanDiffResponse> {
    return request<ScanDiffResponse>('/api/scans/diff', {
      method: 'POST',
      body: JSON.stringify({
        before_scan_id: beforeScanId,
        after_scan_id: afterScanId
      })
    })
  },

  async runBenchmark(): Promise<BenchmarkResult> {
    return request<BenchmarkResult>('/api/eval/benchmark')
  },

  async getAuditLogs(limit: number = 25): Promise<AuditLogEntry[]> {
    return request<AuditLogEntry[]>(`/api/audit-logs?limit=${limit}`)
  }
}
