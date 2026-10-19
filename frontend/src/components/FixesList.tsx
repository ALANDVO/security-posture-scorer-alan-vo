import React, { useState } from 'react'
import { RemediationFix } from '../types/api'

interface FixesListProps {
  fixes: RemediationFix[]
}

export const FixesList: React.FC<FixesListProps> = ({ fixes }) => {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null)

  const handleCopy = (text: string, index: number) => {
    navigator.clipboard.writeText(text)
    setCopiedIndex(index)
    setTimeout(() => setCopiedIndex(null), 2000)
  }

  return (
    <div className="fixes-section">
      <div className="section-header">
        <h2>Prioritized Remediation Roadmap ({fixes.length} Fixes)</h2>
        <p className="section-subtitle">
          Ranked deterministically by Return on Investment: ROI = Impact Weight / Remediation Effort Cost.
        </p>
      </div>

      {fixes.length === 0 ? (
        <div className="empty-state">
          <p>No remediation items required. The codebase meets the security hardening baseline.</p>
        </div>
      ) : (
        <div className="fixes-grid">
          {fixes.map((fix, idx) => (
            <div key={fix.priority} className="fix-card">
              <div className="fix-card-header">
                <div className="priority-badge">#{fix.priority}</div>
                <div className="fix-meta">
                  <span className={`effort-tag effort-${fix.effort}`}>
                    Effort: {fix.effort.toUpperCase()}
                  </span>
                  <span className={`impact-tag impact-${fix.impact}`}>
                    Impact: {fix.impact.toUpperCase()}
                  </span>
                  <span className="roi-tag">
                    ROI: <strong>{fix.roi_score}</strong>
                  </span>
                </div>
              </div>

              <div className="fix-body">
                <h4 className="fix-action">{fix.action}</h4>
                {fix.suggested_patch && (
                  <div className="patch-container">
                    <div className="patch-header">
                      <span>Suggested Remediation Patch</span>
                      <button
                        className="btn-copy"
                        onClick={() => handleCopy(fix.suggested_patch!, idx)}
                      >
                        {copiedIndex === idx ? 'Copied!' : 'Copy Patch'}
                      </button>
                    </div>
                    <pre className="patch-snippet"><code>{fix.suggested_patch}</code></pre>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
