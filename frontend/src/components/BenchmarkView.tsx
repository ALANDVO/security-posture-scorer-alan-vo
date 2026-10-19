import React, { useState, useEffect } from 'react'
import { BenchmarkResult } from '../types/api'
import { api } from '../api/client'

export const BenchmarkView: React.FC = () => {
  const [benchmark, setBenchmark] = useState<BenchmarkResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadBenchmark = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.runBenchmark()
      setBenchmark(res)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Benchmark execution failed'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadBenchmark()
  }, [])

  return (
    <div className="benchmark-page">
      <div className="page-header">
        <div>
          <h2>AI/ML Security Posture Scorer Benchmark</h2>
          <p className="page-subtitle">
            Curated evaluation suite of 10 test environments measuring model vulnerability detection precision, recall, F1, and score calibration error.
          </p>
        </div>
        <button
          className="btn btn-primary"
          onClick={loadBenchmark}
          disabled={loading}
        >
          {loading ? 'Evaluating...' : 'Re-run Evaluation Suite'}
        </button>
      </div>

      {error && (
        <div className="alert-error">
          <p><strong>Evaluation Error:</strong> {error}</p>
        </div>
      )}

      {loading && !benchmark && (
        <div className="loading-state">
          <div className="spinner"></div>
          <p>Executing security posture benchmark against 10 ground-truth environments...</p>
        </div>
      )}

      {benchmark && (
        <div className="benchmark-content">
          <div className="metrics-grid">
            <div className="metric-card">
              <span className="metric-title">Precision</span>
              <span className="metric-val text-emerald">
                {(benchmark.precision_score * 100).toFixed(1)}%
              </span>
              <span className="metric-sub">
                TP: {benchmark.details.true_positives} / (TP+FP: {benchmark.details.true_positives + benchmark.details.false_positives})
              </span>
            </div>

            <div className="metric-card">
              <span className="metric-title">Recall</span>
              <span className="metric-val text-blue">
                {(benchmark.recall_score * 100).toFixed(1)}%
              </span>
              <span className="metric-sub">
                TP: {benchmark.details.true_positives} / (TP+FN: {benchmark.details.true_positives + benchmark.details.false_negatives})
              </span>
            </div>

            <div className="metric-card">
              <span className="metric-title">F1 Score</span>
              <span className="metric-val text-purple">
                {benchmark.f1_score.toFixed(4)}
              </span>
              <span className="metric-sub">Harmonic mean of detection</span>
            </div>

            <div className="metric-card">
              <span className="metric-title">Score MAE</span>
              <span className="metric-val text-amber">
                {benchmark.mean_absolute_error.toFixed(2)} pts
              </span>
              <span className="metric-sub">Mean absolute delta vs ground truth</span>
            </div>
          </div>

          <div className="benchmark-table-card">
            <h3>Sample Calibration Matrix ({benchmark.sample_count} Scenarios)</h3>
            <div className="table-responsive">
              <table className="benchmark-table">
                <thead>
                  <tr>
                    <th>Scenario</th>
                    <th>Expected Vulns</th>
                    <th>Detected Vulns</th>
                    <th>Ground Truth Score</th>
                    <th>Predicted Score</th>
                    <th>Delta</th>
                    <th>Grade</th>
                  </tr>
                </thead>
                <tbody>
                  {benchmark.details.samples.map(s => {
                    const deltaPositive = s.score_delta > 0
                    const isPerfect = s.score_delta === 0
                    return (
                      <tr key={s.sample_id}>
                        <td>
                          <div className="sample-name">{s.name}</div>
                          <span className="sample-id">{s.sample_id}</span>
                        </td>
                        <td>{s.expected_vulns}</td>
                        <td>
                          <span className={s.detected_vulns === s.expected_vulns ? 'text-emerald' : 'text-amber'}>
                            {s.detected_vulns}
                          </span>
                        </td>
                        <td>{s.ground_truth_score}</td>
                        <td><strong>{s.predicted_score}</strong></td>
                        <td>
                          <span className={isPerfect ? 'text-emerald' : deltaPositive ? 'text-blue' : 'text-orange'}>
                            {deltaPositive ? `+${s.score_delta}` : s.score_delta} pts
                          </span>
                        </td>
                        <td>
                          <span className="badge badge-info">{s.grade}</span>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>

          <div className="benchmark-methodology-card">
            <h3>Methodology &amp; Evaluation Limitations</h3>
            <ul>
              <li>
                <strong>Data Provenance:</strong> The benchmark test suite comprises 10 synthetic yet representative micro-environments ranging from hardened production FastAPI services to legacy cryptographic setups and unpinned dependency manifests.
              </li>
              <li>
                <strong>Ground Truth:</strong> Scored against OWASP Top 10 2021 and CWE security guidelines with manually verified vulnerability counts and calibrated deduction boundaries.
              </li>
              <li>
                <strong>Limitations:</strong> Static heuristic scanning without dynamic execution may miss multi-step taint tracking vulnerabilities. Adversarial token obfuscation requires opt-in semantic LLM analysis.
              </li>
            </ul>
          </div>
        </div>
      )}
    </div>
  )
}
