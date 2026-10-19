import React, { useState, useEffect } from 'react'
import { ScanResponse, ScanDiffResponse } from '../types/api'
import { api } from '../api/client'

export const DiffWorkflow: React.FC = () => {
  const [scans, setScans] = useState<ScanResponse[]>([])
  const [beforeId, setBeforeId] = useState<string>('')
  const [afterId, setAfterId] = useState<string>('')
  const [diff, setDiff] = useState<ScanDiffResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api.listScans({ limit: 20 })
      .then(res => {
        setScans(res.items)
        if (res.items.length >= 2) {
          setBeforeId(res.items[1].id)
          setAfterId(res.items[0].id)
        }
      })
      .catch(() => {
        // ignore
      })
  }, [])

  const handleRunDiff = async () => {
    if (!beforeId || !afterId) return
    setLoading(true)
    setError(null)
    try {
      const res = await api.diffScans(beforeId, afterId)
      setDiff(res)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to compare scans'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="diff-workflow">
      <div className="page-header">
        <div>
          <h2>Posture Differential &amp; Regression Tracker</h2>
          <p className="page-subtitle">
            Compare security posture delta between any two historical scans to verify remediation progress or catch regressions.
          </p>
        </div>
      </div>

      {scans.length < 2 ? (
        <div className="empty-state">
          <p>At least two scans are required to compute a posture delta. Run audits on different targets or revisions first.</p>
        </div>
      ) : (
        <div className="diff-form-card">
          <div className="diff-selectors">
            <div className="form-group flex-1">
              <label>Baseline (Before) Scan</label>
              <select
                className="select-field"
                value={beforeId}
                onChange={(e) => setBeforeId(e.target.value)}
              >
                {scans.map(s => (
                  <option key={s.id} value={s.id}>
                    [{s.overall_score}/100] {s.target_name} ({new Date(s.created_at).toLocaleTimeString()})
                  </option>
                ))}
              </select>
            </div>

            <div className="diff-arrow">➡️</div>

            <div className="form-group flex-1">
              <label>Comparison (After) Scan</label>
              <select
                className="select-field"
                value={afterId}
                onChange={(e) => setAfterId(e.target.value)}
              >
                {scans.map(s => (
                  <option key={s.id} value={s.id}>
                    [{s.overall_score}/100] {s.target_name} ({new Date(s.created_at).toLocaleTimeString()})
                  </option>
                ))}
              </select>
            </div>

            <div className="form-group action-align">
              <button
                className="btn btn-primary"
                onClick={handleRunDiff}
                disabled={loading || beforeId === afterId}
              >
                {loading ? 'Comparing...' : 'Calculate Delta'}
              </button>
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="alert-error">
          <p><strong>Error:</strong> {error}</p>
        </div>
      )}

      {diff && (
        <div className="diff-results-card">
          <div className="diff-summary-header">
            <div className="diff-delta-box">
              <span className="delta-label">Posture Delta</span>
              <span className={`delta-number ${diff.score_delta > 0 ? 'text-emerald' : diff.score_delta < 0 ? 'text-red' : 'text-blue'}`}>
                {diff.score_delta > 0 ? `+${diff.score_delta}` : diff.score_delta} pts
              </span>
              <span className={`trend-badge trend-${diff.trend.toLowerCase()}`}>
                {diff.trend}
              </span>
            </div>

            <div className="score-progression">
              <div className="progression-item">
                <span className="prog-label">Baseline Score</span>
                <span className="prog-val">{diff.score_before}/100</span>
              </div>
              <span className="prog-arrow">➔</span>
              <div className="progression-item">
                <span className="prog-label">New Score</span>
                <span className="prog-val">{diff.score_after}/100</span>
              </div>
            </div>
          </div>

          <p className="diff-narrative">{diff.summary}</p>

          <div className="diff-columns">
            <div className="diff-col resolved-col">
              <h4>✅ Resolved Findings ({diff.resolved_findings.length})</h4>
              {diff.resolved_findings.length === 0 ? (
                <p className="no-items">No findings were resolved between these checkpoints.</p>
              ) : (
                <ul className="finding-change-list">
                  {diff.resolved_findings.map(f => (
                    <li key={f.id} className="resolved-item">
                      <span className="change-title">{f.title}</span>
                      <span className="change-pts">+{f.deduction_points} pts recovered</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div className="diff-col regression-col">
              <h4>⚠️ New Regressions ({diff.new_regressions.length})</h4>
              {diff.new_regressions.length === 0 ? (
                <p className="no-items">Zero new security regressions introduced!</p>
              ) : (
                <ul className="finding-change-list">
                  {diff.new_regressions.map(f => (
                    <li key={f.id} className="regression-item">
                      <span className="change-title">{f.title}</span>
                      <span className="change-pts text-red">-{f.deduction_points} pts penalty</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
