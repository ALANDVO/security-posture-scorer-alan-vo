import React, { useState } from 'react'
import { AuthProvider } from './context/AuthContext'
import { Navbar } from './components/Navbar'
import { ScanWorkflow } from './components/ScanWorkflow'
import { DiffWorkflow } from './components/DiffWorkflow'
import { BenchmarkView } from './components/BenchmarkView'
import { AuditLogsView } from './components/AuditLogsView'

export const AppContent: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'scan' | 'diff' | 'benchmark' | 'audit'>('scan')

  return (
    <div className="app-container">
      <Navbar activeTab={activeTab} setActiveTab={(t) => setActiveTab(t as typeof activeTab)} />

      <main className="main-content">
        {activeTab === 'scan' && <ScanWorkflow />}
        {activeTab === 'diff' && <DiffWorkflow />}
        {activeTab === 'benchmark' && <BenchmarkView />}
        {activeTab === 'audit' && <AuditLogsView />}
      </main>

      <footer className="app-footer">
        <div className="footer-content">
          <p>
            <strong>Security Posture Scorer</strong> &mdash; Designed and built by{' '}
            <a href="mailto:alanvo@gmail.com">Alan Vo</a> &lt;alanvo@gmail.com&gt;
          </p>
          <p className="license-tag">Released under the MIT License &bull; Provider-neutral advisory architecture</p>
        </div>
      </footer>
    </div>
  )
}

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  )
}

export default App
