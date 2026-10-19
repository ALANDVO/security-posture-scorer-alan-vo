import React from 'react'

interface ScoreGaugeProps {
  score: number
  grade: string
  categoryScores: Record<string, number>
}

export const ScoreGauge: React.FC<ScoreGaugeProps> = ({ score, grade, categoryScores }) => {
  const getGradeColor = (g: string) => {
    switch (g.toUpperCase()) {
      case 'A': return '#10b981' // emerald
      case 'B': return '#3b82f6' // blue
      case 'C': return '#f59e0b' // amber
      case 'D': return '#f97316' // orange
      default: return '#ef4444' // red
    }
  }

  const strokeDashoffset = 283 - (283 * Math.min(100, Math.max(0, score))) / 100
  const color = getGradeColor(grade)

  const categories = [
    { key: 'authentication', label: 'Authentication', max: 25 },
    { key: 'cryptography', label: 'Cryptography', max: 25 },
    { key: 'configuration', label: 'Configuration', max: 25 },
    { key: 'dependencies', label: 'Dependencies', max: 25 },
  ]

  return (
    <div className="score-gauge-card">
      <div className="gauge-visual">
        <svg viewBox="0 0 100 100" className="gauge-svg">
          <circle
            cx="50"
            cy="50"
            r="45"
            className="gauge-track"
          />
          <circle
            cx="50"
            cy="50"
            r="45"
            className="gauge-progress"
            style={{
              strokeDasharray: 283,
              strokeDashoffset,
              stroke: color
            }}
          />
        </svg>
        <div className="gauge-label">
          <span className="gauge-score" style={{ color }}>{score}</span>
          <span className="gauge-max">/100</span>
          <div className="gauge-grade" style={{ backgroundColor: color }}>
            Grade {grade}
          </div>
        </div>
      </div>

      <div className="category-breakdown">
        <h3>Category Allocation</h3>
        <div className="category-bars">
          {categories.map(cat => {
            const val = categoryScores[cat.key] ?? 0
            const pct = (val / cat.max) * 100
            return (
              <div key={cat.key} className="category-row">
                <div className="cat-header">
                  <span className="cat-name">{cat.label}</span>
                  <span className="cat-val">{val} / {cat.max} pts</span>
                </div>
                <div className="cat-track">
                  <div
                    className="cat-fill"
                    style={{
                      width: `${pct}%`,
                      backgroundColor: pct >= 80 ? '#10b981' : pct >= 50 ? '#f59e0b' : '#ef4444'
                    }}
                  />
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
