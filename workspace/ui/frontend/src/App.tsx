import { Routes, Route, Navigate } from 'react-router-dom'
import { useEffect, useState } from 'react'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import Detections from './pages/Detections'
import Events from './pages/Events'
import Autoruns from './pages/Autoruns'
import Settings from './pages/Settings'

type Theme = 'dark' | 'light'

function getInitialTheme(): Theme {
  try {
    const stored = localStorage.getItem('vajra-theme')
    if (stored === 'dark' || stored === 'light') return stored
  } catch (_) {}
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

// UI8: theme state lives here — single source of truth.
// Previously it was split between App (OS listener) and Sidebar (toggle state),
// which caused the toggle to invert after an OS preference change because the
// two pieces of state diverged.
export default function App() {
  const [theme, setTheme] = useState<Theme>(getInitialTheme)

  // Apply the theme to the DOM whenever it changes.
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
  }, [theme])

  // Persist a user-initiated toggle and update state.
  function handleThemeChange(next: Theme) {
    try { localStorage.setItem('vajra-theme', next) } catch (_) {}
    setTheme(next)
  }

  // Sync with OS preference changes — only when no manual override is stored.
  useEffect(() => {
    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const onChange = (e: MediaQueryListEvent) => {
      try {
        if (!localStorage.getItem('vajra-theme')) {
          setTheme(e.matches ? 'dark' : 'light')
        }
      } catch (_) {}
    }
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [])

  return (
    <div className="flex h-full" style={{ background: 'rgb(var(--bg))' }}>
      <Sidebar theme={theme} onThemeChange={handleThemeChange} />
      <main className="flex-1 overflow-auto" style={{ color: 'rgb(var(--fg))' }}>
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
