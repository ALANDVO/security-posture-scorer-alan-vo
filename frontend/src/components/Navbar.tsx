import React from 'react'
import { useAuth } from '../context/AuthContext'

interface NavbarProps {
  activeTab: string
  setActiveTab: (tab: string) => void
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, setActiveTab }) => {
  const { user, loginAs, logout } = useAuth()

  return (
    <header className="navbar">
      <div className="navbar-brand">
        <span className="logo-shield">🛡️</span>
        <div className="brand-text">
          <h1>Security Posture Scorer</h1>
          <span className="author-tag">Alan Vo | AI &amp; Machine Learning</span>
        </div>
      </div>

      <nav className="nav-links">
        <button
          className={`nav-btn ${activeTab === 'scan' ? 'active' : ''}`}
          onClick={() => setActiveTab('scan')}
        >
          Audit &amp; Score
        </button>
        <button
          className={`nav-btn ${activeTab === 'diff' ? 'active' : ''}`}
          onClick={() => setActiveTab('diff')}
        >
          Posture Delta
        </button>
        <button
          className={`nav-btn ${activeTab === 'benchmark' ? 'active' : ''}`}
          onClick={() => setActiveTab('benchmark')}
        >
          AI/ML Benchmark
        </button>
        <button
          className={`nav-btn ${activeTab === 'audit' ? 'active' : ''}`}
          onClick={() => setActiveTab('audit')}
        >
          Audit Trail
        </button>
      </nav>

      <div className="navbar-user">
        {user ? (
          <div className="user-info">
            <span className="user-email">{user.email}</span>
            <span className={`role-badge role-${user.roles[0] || 'viewer'}`}>
              {user.roles[0] || 'viewer'}
            </span>
            <div className="role-switch">
              <select
                value={user.roles[0] || 'analyst'}
                onChange={(e) => loginAs(e.target.value as 'viewer' | 'analyst' | 'admin')}
                title="Switch demo role"
              >
                <option value="viewer">Viewer</option>
                <option value="analyst">Analyst</option>
                <option value="admin">Admin</option>
              </select>
            </div>
            <button className="logout-btn" onClick={logout}>Sign out</button>
          </div>
        ) : (
          <div className="login-actions">
            <button className="btn btn-primary" onClick={() => loginAs('analyst')}>
              Demo Login
            </button>
          </div>
        )}
      </div>
    </header>
  )
}
