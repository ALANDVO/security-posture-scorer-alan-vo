import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ScoreGauge } from '../components/ScoreGauge'

describe('ScoreGauge Component', () => {
  it('displays calculated score and letter grade', () => {
    const categoryScores = {
      authentication: 20,
      cryptography: 15,
      configuration: 22,
      dependencies: 18
    }

    render(
      <ScoreGauge
        score={75}
        grade="B"
        categoryScores={categoryScores}
      />
    )

    expect(screen.getByText('75')).toBeInTheDocument()
    expect(screen.getByText('/100')).toBeInTheDocument()
    expect(screen.getByText('Grade B')).toBeInTheDocument()
  })

  it('renders all category allocation metrics', () => {
    const categoryScores = {
      authentication: 25,
      cryptography: 10,
      configuration: 15,
      dependencies: 20
    }

    render(
      <ScoreGauge
        score={70}
        grade="C"
        categoryScores={categoryScores}
      />
    )

    expect(screen.getByText('Authentication')).toBeInTheDocument()
    expect(screen.getByText('25 / 25 pts')).toBeInTheDocument()
    expect(screen.getByText('Cryptography')).toBeInTheDocument()
    expect(screen.getByText('10 / 25 pts')).toBeInTheDocument()
    expect(screen.getByText('Configuration')).toBeInTheDocument()
    expect(screen.getByText('15 / 25 pts')).toBeInTheDocument()
    expect(screen.getByText('Dependencies')).toBeInTheDocument()
    expect(screen.getByText('20 / 25 pts')).toBeInTheDocument()
  })
})
