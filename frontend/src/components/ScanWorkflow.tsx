import React, { useState, useEffect } from 'react'
import { ScanResponse, ScanSubmission } from '../types/api'
import { api } from '../api/client'
import { ScoreGauge } from './ScoreGauge'
import { FindingsTable } from './FindingsTable'
import { FixesList } from './FixesList'
import { useAuth } from '../context/AuthContext'

const SAMPLE_TEMPLATES: Record<string, { type: ScanSubmission['target_type']; name: string; content: string }> = {
  insecure_config: {
    type: 'config',
    name: 'Insecure CORS & Debug',
    content: '{\n  "debug": true,\n  "allow_origins": ["*"],\n  "ssl": false\n}'
  },
  weak_crypto: {
    type: 'codebase',
    name: 'Weak MD5 & DES',
    content: 'import hashlib\nfrom Crypto.Cipher import DES\nh = hashlib.md5(b"x").digest()\nc = DES.new(k, DES.MODE_ECB)\nimport random\nauth_token = random.random()'
  },
  missing_headers: {
    type: 'headers',
    name: 'Missing HTTP Headers',
    content: 'HTTP/1.1 200 OK\nContent-Type: text/html\nSet-Cookie: session=xyz'
  },
  vulnerable_deps: {
    type: 'manifest',
    name: 'Vulnerable Dependencies',
    content: 'requests==2.28.0\nurllib3==1.26.5\nflask=*'
  },
  hardened: {
    type: 'config',
    name: 'Hardened Config',
    content: '{\n  "debug": false,\n  "allow_origins": ["https://app.alanvo.dev"],\n  "ssl": true\n}'
  }
}

export const ScanWorkflow: React.FC = () => {
  const { user } = useAuth()
  const [targetName, setTargetName] = useState('My Application Audit')
  const [targetType, setTargetType] = useState<ScanSubmission['target_type']>('config')
  const [content, setContent] = useState(SAMPLE_TEMPLATES.insecure_config.content)
  const [activeScan, setActiveScan] = useState<ScanResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [advisoryLoading, setAdvisoryLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [history, setHistory] = useState<ScanResponse[]>([])

  const loadHistory = async () => {
    try {
      const res = await api.listScans({ limit: 10 })
      setHistory(res.items)
      if (!activeScan && res.items.length > 0) {
        setActiveScan(res.items[0])
      }
    } catch {
      // ignore
    }
  }

  useEffect(() => {
    loadHistory()
  }, [])

  const handleTemplateSelect = (key: string) => {
    const tmpl = SAMPLE_TEMPLATES[key]
    if (tmpl) {
      setTargetName(tmpl.name)
      setTargetType(tmpl.type)
      setContent(tmpl.content)
    }
  }

  const handleRunScan = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    try {
      const res = await api.createScan({
        target_name: targetName,
        target_type: targetType,
        content: content
      })
      setActiveScan(res)
      loadHistory()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Scan execution failed'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  const handleRequestAdvisory = async () => {
    if (!activeScan) return
    setAdvisoryLoading(true)
    setError(null)
    try {
      const res = await api.requestAdvisory(activeScan.id)
      setActiveScan(res)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Advisory request failed'
      setError(msg)
    } finally {
      setAdvisoryLoading(false)
    }
  }

  const handleExportJson = () => {
    if (!activeScan) return
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(activeScan, null, 2))
    const downloadAnchor = document.createElement('a')
    downloadAnchor.setAttribute('href', dataStr)
    downloadAnchor.setAttribute('download', `security-posture-${activeScan.id.substring(0, 8)}.json`)
    document.body.appendChild(downloadAnchor)
    downloadAnchor.click()
    downloadAnchor.remove()
  }

  return (
    <div className="scan-workflow-layout">
      <div className="scan-controls-card">
        <h2>Initiate Security Posture Audit</h2>
        <p className="controls-desc">
          Audit configuration files, source code, HTTP response headers, or dependency manifests.
        </p>

        <div className="template-picker">
          <span className="picker-label">Quick Sample Scenarios:</span>
          <div className="template-buttons">
            <button
              type="button"
              className="btn-chip"
              onClick={() => handleTemplateSelect('insecure_config')}
            >
              Insecure Config &amp; CORS
            </button>
            <button
              type="button"
              className="btn-chip"
              onClick={() => handleTemplateSelect('weak_crypto')}
            >
              Weak MD5 &amp; DES
            </button>
            <button
              type="button"
              className="btn-chip"
              onClick={() => handleTemplateSelect('missing_headers')}
            >
              Missing HTTP Headers
            </button>
            <button
              type="button"
              className="btn-chip"
              onClick={() => handleTemplateSelect('vulnerable_deps')}
            >
              Vulnerable Dependencies
            </button>
            <button
              type="button"
              className="btn-chip"
              onClick={() => handleTemplateSelect('hardened')}
            >
              Hardened Baseline
            </button>
          </div>
        </div>

        <form onSubmit={handleRunScan} className="scan-form">
          <div className="form-row">
            <div className="form-group flex-2">
              <label htmlFor="target-name">Audit Target Name</label>
              <input
                id="target-name"
                type="text"
                className="input-text"
                value={targetName}
                onChange={(e) => setTargetName(e.target.value)}
                required
              />
            </div>
            <div className="form-group flex-1">
              <label htmlFor="target-type">Target Format</label>
              <select
                id="target-type"
                className="select-field"
                value={targetType}
                onChange={(e) => setTargetType(e.target.value as ScanSubmission['target_type'])}
              >
                <option value="config">Configuration (JSON/YAML)</option>
                <option value="codebase">Codebase Source (.py/.js)</option>
                <option value="headers">HTTP Headers</option>
                <option value="manifest">Dependency Manifest</option>
              </select>
            </div>
          </div>

          <div className="form-group">
            <label htmlFor="target-content">Target Source or Content to Audit</label>
            <textarea
              id="target-content"
              rows={8}
              className="textarea-code"
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder="Paste config, headers, requirements.txt, or source code here..."
              required
            />
          </div>

          <div className="form-actions">
            <button
              type="submit"
              className="btn btn-primary"
              disabled={loading}
            >
              {loading ? 'Executing Deterministic Audit...' : 'Audit Security Posture'}
            </button>
          </div>
        </form>

        {history.length > 0 && (
          <div className="recent-history">
            <span className="history-label">Recent Audits:</span>
            <div className="history-chips">
              {history.map(h => (
                <button
                  key={h.id}
                  className={`chip-history ${activeScan?.id === h.id ? 'active' : ''}`}
                  onClick={() => setActiveScan(h)}
                >
                  <span className="chip-score">{h.overall_score}/100</span>
                  <span className="chip-name">{h.target_name}</span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {error && (
        <div className="alert-error">
          <p><strong>Error:</strong> {error}</p>
        </div>
      )}

      {activeScan && (
        <div className="scan-results-container">
          <div className="results-header">
            <div>
              <h3>Audit Results: {activeScan.target_name}</h3>
              <p className="results-sub">
                Target Format: <code>{activeScan.target_type}</code> | Audited by {activeScan.created_by} at {new Date(activeScan.created_at).toLocaleString()}
              </p>
            </div>
            <div className="header-actions">
              <button
                className="btn btn-secondary"
                onClick={handleRequestAdvisory}
                disabled={advisoryLoading || !['analyst', 'admin'].includes(user?.roles[0] || '')}
                title={['analyst', 'admin'].includes(user?.roles[0] || '') ? 'Request grounded advisory' : 'Analyst role required'}
              >
                {advisoryLoading ? 'Querying Advisory...' : 'Opt-in Threat Advisory'}
              </button>
              <button className="btn btn-outline" onClick={handleExportJson}>
                Export Report (.json)
              </button>
            </div>
          </div>

          <ScoreGauge
            score={activeScan.overall_score}
            grade={activeScan.grade}
            categoryScores={activeScan.category_scores}
          />

          <div className="summary-box">
            <h4>Executive Synthesis</h4>
            <p>{activeScan.summary}</p>
          </div>

          {activeScan.llm_advisory && (
            <div className="advisory-card">
              <div className="advisory-badge">
                Opt-in Advisory Analysis ({activeScan.llm_advisory.provider})
              </div>
              <h4>{activeScan.llm_advisory.executive_summary}</h4>
              <p className="threat-text">{activeScan.llm_advisory.threat_analysis}</p>
              {activeScan.llm_advisory.prioritized_guidance.length > 0 && (
                <div className="advisory-guidance">
                  <strong>Strategic Guidance:</strong>
                  <ul>
                    {activeScan.llm_advisory.prioritized_guidance.map((g, i) => (
                      <li key={i}>{g}</li>
                    ))}
                  </ul>
                </div>
              )}
              {activeScan.llm_advisory.error && (
                <div className="advisory-notice">
                  <em>Note: {activeScan.llm_advisory.error}</em>
                </div>
              )}
            </div>
          )}

          <FindingsTable findings={activeScan.findings} />
          <FixesList fixes={activeScan.fixes} />
        </div>
      )}
    </div>
  )
}
