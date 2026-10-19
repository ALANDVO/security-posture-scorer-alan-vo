import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import App from '../App'

describe('App Layout and Branding', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/auth/token')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            access_token: 'fake-demo-token',
            token_type: 'Bearer',
            expires_in: 3600,
            user: { sub: '123', email: 'analyst@demo.local', name: 'Demo Analyst', roles: ['analyst'] }
          })
        })
      }
      if (url.includes('/api/scans')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: [], total: 0, skip: 0, limit: 10 })
        })
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({})
      })
    }))
  })

  it('renders author branding and title', async () => {
    render(<App />)
    expect(screen.getByRole('heading', { level: 1, name: /Security Posture Scorer/i })).toBeInTheDocument()
    expect(screen.getByText(/Alan Vo \| AI & Machine Learning/i)).toBeInTheDocument()
    expect(screen.getByText(/Designed and built by/i)).toBeInTheDocument()
  })

  it('displays the main workflow navigation buttons', () => {
    render(<App />)
    expect(screen.getByRole('button', { name: /Audit & Score/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Posture Delta/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /AI\/ML Benchmark/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Audit Trail/i })).toBeInTheDocument()
  })
})
