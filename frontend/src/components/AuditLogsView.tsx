import React, { useState, useEffect } from 'react'
import { AuditLogEntry } from '../types/api'
import { api } from '../api/client'
import { useAuth } from '../context/AuthContext'

export const AuditLogsView: React.FC = () => {
  const { user } = useAuth()
  const [logs, setLogs] = useState<AuditLogEntry[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadLogs = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.getAuditLogs(50)
      setLogs(res)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to retrieve audit trail'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadLogs()
  }, [])

  const isAuthorized = user && ['analyst', 'admin'].includes(user.roles[0] || '')

  return (
    <div className="audit-page">
      <div className="page-header">
        <div>
          <h2>Security Audit Trail</h2>
          <p className="page-subtitle">
            Immutable log of all posture scans, advisory queries, benchmark runs, and administrative actions.
          </p>
        </div>
        <button
          className="btn btn-secondary"
          onClick={loadLogs}
          disabled={loading || !isAuthorized}
        >
          {loading ? 'Refreshing...' : 'Refresh Logs'}
        </button>
      </div>

      {!isAuthorized ? (
        <div className="alert-error">
          <p>
            <strong>Access Denied:</strong> Viewing audit logs requires <code>analyst</code> or <code>admin</code> role. Switch your role using the demo menu in the navbar.
          </p>
        </div>
      ) : error ? (
        <div className="alert-error">
          <p><strong>Error:</strong> {error}</p>
        </div>
      ) : logs.length === 0 ? (
        <div className="empty-state">
          <p>No audit events recorded yet.</p>
        </div>
      ) : (
        <div className="table-responsive">
          <table className="audit-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Timestamp (UTC)</th>
                <th>Event Type</th>
                <th>Actor</th>
                <th>Resource ID</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {logs.map(log => (
                <tr key={log.id}>
                  <td><code>#{log.id}</code></td>
                  <td>{new Date(log.created_at).toLocaleString()}</td>
                  <td>
                    <span className="badge badge-info">{log.event_type}</span>
                  </td>
                  <td><code>{log.actor}</code></td>
                  <td><code className="text-muted">{log.resource_id}</code></td>
                  <td>
                    <pre className="json-details">
                      <code>{JSON.stringify(log.details)}</code>
                    </pre>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
