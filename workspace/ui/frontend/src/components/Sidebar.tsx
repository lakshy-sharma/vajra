// ui/frontend/src/components/Sidebar.tsx
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

const nav = [
  { to: '/dashboard',  icon: LayoutDashboard, label: 'Dashboard'  },
  { to: '/detections', icon: ShieldAlert,      label: 'Detections' },
  { to: '/events',     icon: Activity,         label: 'Events'     },
  { to: '/autoruns',   icon: ListChecks,       label: 'Autoruns'   },
  { to: '/settings',   icon: Settings,         label: 'Settings'   },
]

interface Props {
  // UI8: theme and toggle handler come from App — no local state here.
  // This prevents the toggle from inverting after an OS preference change
  // that updated the DOM directly without updating Sidebar's state.
  theme: 'dark' | 'light'
  onThemeChange: (theme: 'dark' | 'light') => void
}

export default function Sidebar({ theme, onThemeChange }: Props) {
  return (
    <aside
      className="flex flex-col w-56 h-full border-r shrink-0"
      style={{ background: 'rgb(var(--surface))', borderColor: 'rgb(var(--border))' }}
    >
      {/* Logo */}
      <div
        className="flex items-center gap-2 px-4 py-5 border-b"
        style={{ borderColor: 'rgb(var(--border))' }}
      >
        <ShieldAlert className="w-6 h-6" style={{ color: 'rgb(var(--accent))' }} />
        <span className="font-semibold tracking-wide text-sm" style={{ color: 'rgb(var(--fg))' }}>
          Vajra EDR
        </span>
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
                  ? 'font-medium'
                  : 'hover:bg-[rgb(var(--surface-2))]',
              ].join(' ')
            }
            style={({ isActive }) => ({
              color: isActive ? 'rgb(var(--accent))' : 'rgb(var(--muted))',
              background: isActive ? 'rgb(var(--accent) / 0.12)' : undefined,
            })}
          >
            <Icon className="w-4 h-4 shrink-0" />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Theme toggle */}
      <div className="px-4 py-3 border-t" style={{ borderColor: 'rgb(var(--border))' }}>
        <button
          onClick={() => onThemeChange(theme === 'dark' ? 'light' : 'dark')}
          className="flex items-center gap-2 text-xs w-full rounded-md px-3 py-2 transition-colors hover:bg-[rgb(var(--surface-2))]"
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
