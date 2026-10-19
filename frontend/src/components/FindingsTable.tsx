import React, { useState } from 'react'
import { Finding } from '../types/api'

interface FindingsTableProps {
  findings: Finding[]
}

export const FindingsTable: React.FC<FindingsTableProps> = ({ findings }) => {
  const [search, setSearch] = useState('')
  const [selectedCategory, setSelectedCategory] = useState<string>('all')
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all')
  const [expandedId, setExpandedId] = useState<string | null>(null)

  const filtered = findings.filter(f => {
    const matchesSearch =
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      f.description.toLowerCase().includes(search.toLowerCase()) ||
      (f.file_path && f.file_path.toLowerCase().includes(search.toLowerCase()))
    const matchesCategory = selectedCategory === 'all' || f.category === selectedCategory
    const matchesSeverity = selectedSeverity === 'all' || f.severity === selectedSeverity
    return matchesSearch && matchesCategory && matchesSeverity
  })

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev.toUpperCase()) {
      case 'CRITICAL': return 'badge-critical'
      case 'HIGH': return 'badge-high'
      case 'MEDIUM': return 'badge-medium'
      case 'LOW': return 'badge-low'
      default: return 'badge-info'
    }
  }

  return (
    <div className="findings-section">
      <div className="section-toolbar">
        <h2>Deterministic Findings ({filtered.length} / {findings.length})</h2>
        <div className="filters-group">
          <input
            type="text"
            className="input-search"
            placeholder="Search findings or files..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <select
            className="select-filter"
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
          >
            <option value="all">All Categories</option>
            <option value="authentication">Authentication</option>
            <option value="cryptography">Cryptography</option>
            <option value="configuration">Configuration</option>
            <option value="dependencies">Dependencies</option>
          </select>
          <select
            className="select-filter"
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
          >
            <option value="all">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="empty-state">
          <p>No security findings match your active search or filters.</p>
        </div>
      ) : (
        <div className="table-responsive">
          <table className="findings-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Title &amp; File</th>
                <th>Category</th>
                <th>Deduction</th>
                <th>Remediation</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(f => {
                const isExpanded = expandedId === f.id
                return (
                  <React.Fragment key={f.id}>
                    <tr className={isExpanded ? 'row-expanded' : ''}>
                      <td>
                        <span className={`badge ${getSeverityBadgeClass(f.severity)}`}>
                          {f.severity}
                        </span>
                      </td>
                      <td>
                        <div className="finding-title">{f.title}</div>
                        {f.file_path && (
                          <span className="file-tag">
                            {f.file_path}{f.line_number ? `:${f.line_number}` : ''}
                          </span>
                        )}
                      </td>
                      <td>
                        <span className="cat-chip">{f.category}</span>
                      </td>
                      <td className="deduction-val">
                        -{f.deduction_points} pts
                      </td>
                      <td className="remediation-cell">{f.remediation}</td>
                      <td>
                        <button
                          className="btn-details"
                          onClick={() => setExpandedId(isExpanded ? null : f.id)}
                        >
                          {isExpanded ? 'Hide' : 'Inspect'}
                        </button>
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr className="expansion-row">
                        <td colSpan={6}>
                          <div className="finding-detail-box">
                            <p className="detail-desc"><strong>Description:</strong> {f.description}</p>
                            {f.evidence && (
                              <div className="evidence-block">
                                <strong>Code / Header Evidence:</strong>
                                <pre className="code-snippet"><code>{f.evidence}</code></pre>
                              </div>
                            )}
                            <div className="remediation-recommendation">
                              <strong>Recommended Fix:</strong>
                              <p>{f.remediation}</p>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
