import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  ShieldAlert,
  Activity,
  ListChecks,
  Settings,
  Moon,
  Sun,
} from 'lucide-react'
import { useState, useEffect } from 'react'

const nav = [
  { to: '/dashboard',  icon: LayoutDashboard, label: 'Dashboard'  },
  { to: '/detections', icon: ShieldAlert,      label: 'Detections' },
  { to: '/events',     icon: Activity,         label: 'Events'     },
  { to: '/autoruns',   icon: ListChecks,       label: 'Autoruns'   },
  { to: '/settings',   icon: Settings,         label: 'Settings'   },
]

function getTheme(): 'dark' | 'light' {
  try {
    const stored = localStorage.getItem('vajra-theme')
    if (stored === 'dark' || stored === 'light') return stored
  } catch (_) {}
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

export default function Sidebar() {
  const [theme, setTheme] = useState<'dark' | 'light'>(getTheme)

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    try { localStorage.setItem('vajra-theme', theme) } catch (_) {}
  }, [theme])

  return (
    <aside
      className="flex flex-col w-56 h-full border-r shrink-0"
      style={{
        background: 'rgb(var(--surface))',
        borderColor: 'rgb(var(--border))',
      }}
    >
      {/* Logo */}
      <div className="flex items-center gap-2 px-4 py-5 border-b"
           style={{ borderColor: 'rgb(var(--border))' }}>
        <ShieldAlert className="w-6 h-6" style={{ color: 'rgb(var(--accent))' }} />
        <span className="font-semibold tracking-wide text-sm">Vajra EDR</span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-2 py-3 space-y-0.5 overflow-y-auto">
        {nav.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              [
                'flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors',
                isActive
                  ? 'bg-[rgb(var(--accent)/0.15)] text-[rgb(var(--accent))] font-medium'
                  : 'text-[rgb(var(--muted))] hover:bg-[rgb(var(--surface-2))] hover:text-[rgb(var(--fg))]',
              ].join(' ')
            }
          >
            <Icon className="w-4 h-4 shrink-0" />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Theme toggle */}
      <div className="px-4 py-3 border-t" style={{ borderColor: 'rgb(var(--border))' }}>
        <button
          onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
          className="flex items-center gap-2 text-xs w-full rounded-md px-3 py-2 transition-colors"
          style={{ color: 'rgb(var(--muted))' }}
          title="Toggle dark / light mode"
        >
          {theme === 'dark'
            ? <><Sun className="w-4 h-4" /> Light mode</>
            : <><Moon className="w-4 h-4" /> Dark mode</>
          }
        </button>
      </div>
    </aside>
  )
}
