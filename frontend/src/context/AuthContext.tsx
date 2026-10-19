import React, { createContext, useContext, useState, useEffect } from 'react'
import { UserProfile } from '../types/api'
import { api, setAccessToken } from '../api/client'

interface AuthContextType {
  user: UserProfile | null
  loading: boolean
  error: string | null
  loginAs: (role: 'viewer' | 'analyst' | 'admin') => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserProfile | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    // Attempt automatic local demo analyst login on initial mount
    api.loginDemo('analyst')
      .then(res => {
        setUser(res.user)
        setError(null)
      })
      .catch(err => {
        setError(err.message || 'Failed to authenticate')
      })
      .finally(() => {
        setLoading(false)
      })
  }, [])

  const loginAs = async (role: 'viewer' | 'analyst' | 'admin') => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.loginDemo(role)
      setUser(res.user)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Login failed'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  const logout = () => {
    setAccessToken(null)
    setUser(null)
  }

  return (
    <AuthContext.Provider value={{ user, loading, error, loginAs, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
