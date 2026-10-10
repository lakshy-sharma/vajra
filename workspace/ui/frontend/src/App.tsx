import { Routes, Route, Navigate } from 'react-router-dom'
import { useEffect } from 'react'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import Detections from './pages/Detections'
import Events from './pages/Events'
import Autoruns from './pages/Autoruns'
import Settings from './pages/Settings'

export default function App() {
  // Keep theme in sync with OS preference changes at runtime.
  useEffect(() => {
    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const onChange = (e: MediaQueryListEvent) => {
      // Only apply OS preference if the user hasn't set a manual override.
      try {
        if (!localStorage.getItem('vajra-theme')) {
          document.documentElement.setAttribute('data-theme', e.matches ? 'dark' : 'light')
        }
      } catch (_) {}
    }
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [])

  return (
    <div className="flex h-full" style={{ background: 'rgb(var(--bg))' }}>
      <Sidebar />
      <main className="flex-1 overflow-auto">
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/detections" element={<Detections />} />
          <Route path="/events/*" element={<Events />} />
          <Route path="/autoruns" element={<Autoruns />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </main>
    </div>
  )
}
