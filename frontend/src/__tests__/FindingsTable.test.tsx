import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { FindingsTable } from '../components/FindingsTable'
import { Finding } from '../types/api'

describe('FindingsTable Component', () => {
  const mockFindings: Finding[] = [
    {
      id: 'f1',
      title: 'Insecure DES Cipher',
      category: 'cryptography',
      severity: 'CRITICAL',
      description: 'DES ECB mode detected',
      deduction_points: 15,
      remediation: 'Upgrade to AES-GCM',
      evidence: 'DES.new(key, DES.MODE_ECB)'
    },
    {
      id: 'f2',
      title: 'Missing Content-Security-Policy',
      category: 'configuration',
      severity: 'HIGH',
      description: 'CSP header missing',
      deduction_points: 10,
      remediation: 'Set CSP header'
    }
  ]

  it('renders table headers and findings items', () => {
    render(<FindingsTable findings={mockFindings} />)
    expect(screen.getByText(/Deterministic Findings \(2 \/ 2\)/i)).toBeInTheDocument()
    expect(screen.getByText('Insecure DES Cipher')).toBeInTheDocument()
    expect(screen.getByText('Missing Content-Security-Policy')).toBeInTheDocument()
    expect(screen.getByText('-15 pts')).toBeInTheDocument()
    expect(screen.getByText('-10 pts')).toBeInTheDocument()
  })

  it('filters findings by search keyword', () => {
    render(<FindingsTable findings={mockFindings} />)
    const searchInput = screen.getByPlaceholderText(/Search findings or files/i)
    fireEvent.change(searchInput, { target: { value: 'DES' } })

    expect(screen.getByText('Insecure DES Cipher')).toBeInTheDocument()
    expect(screen.queryByText('Missing Content-Security-Policy')).not.toBeInTheDocument()
  })

  it('allows expanding details to view evidence', () => {
    render(<FindingsTable findings={mockFindings} />)
    const inspectBtn = screen.getAllByRole('button', { name: /Inspect/i })[0]
    fireEvent.click(inspectBtn)

    expect(screen.getByText(/DES ECB mode detected/i)).toBeInTheDocument()
    expect(screen.getByText('DES.new(key, DES.MODE_ECB)')).toBeInTheDocument()
  })
})
