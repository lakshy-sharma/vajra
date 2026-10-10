import { useEffect, useState } from 'react'
import { Routes, Route, NavLink, Navigate } from 'react-router-dom'
import { GetSecurityEvents, GetNetworkEvents, GetMemoryEvents } from '../wails'
import Pagination from '../components/Pagination'
import SeverityBadge from '../components/SeverityBadge'

const PER_PAGE = 50

function fmtTime(unix: number) {
  if (!unix) return '—'
  return new Date(unix * 1000).toLocaleString()
}

// ── Security events tab ───────────────────────────────────────────────────────

function SecurityTab() {
  const [page, setPage] = useState(1)
  const [data, setData] = useState<{ items: unknown[]; totalCount: number; page: number; perPage: number } | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setLoading(true)
    GetSecurityEvents(page, PER_PAGE)
      .then(setData)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, [page])

  type Row = {
    id: number; eventTime: number; eventName: string; pid: number; uid: number
    processName: string; targetPath: string; details: string; severity: string; status: string
  }

  return (
    <div className="flex flex-col flex-1 overflow-hidden">
      <div className="flex-1 overflow-auto">
        <table className="w-full text-xs border-collapse">
          <thead>
            <tr className="sticky top-0 text-left" style={{ background: 'rgb(var(--surface-2))', color: 'rgb(var(--muted))' }}>
              {['Time', 'Event', 'PID / UID', 'Process', 'Target', 'Severity'].map(h => (
                <th key={h} className="px-4 py-2 font-medium border-b whitespace-nowrap" style={{ borderColor: 'rgb(var(--border))' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading && <tr><td colSpan={6} className="px-4 py-8 text-center" style={{ color: 'rgb(var(--muted))' }}>Loading…</td></tr>}
            {!loading && (data?.items as Row[] | undefined)?.map(row => (
              <tr key={row.id} className="border-b hover:bg-[rgb(var(--surface-2)/0.5)] transition-colors" style={{ borderColor: 'rgb(var(--border))' }}>
                <td className="px-4 py-2 whitespace-nowrap tabular-nums">{fmtTime(row.eventTime)}</td>
                <td className="px-4 py-2 whitespace-nowrap">{row.eventName}</td>
                <td className="px-4 py-2 tabular-nums whitespace-nowrap" style={{ color: 'rgb(var(--muted))' }}>{row.pid} / {row.uid}</td>
                <td className="px-4 py-2">{row.processName}</td>
                <td className="px-4 py-2 max-w-[200px] truncate" title={row.targetPath}>{row.targetPath || '—'}</td>
                <td className="px-4 py-2"><SeverityBadge severity={row.severity} /></td>
              </tr>
            ))}
            {!loading && !data?.items?.length && <tr><td colSpan={6} className="px-4 py-8 text-center" style={{ color: 'rgb(var(--muted))' }}>No events.</td></tr>}
          </tbody>
        </table>
      </div>
      {data && <Pagination page={data.page} perPage={data.perPage} totalCount={data.totalCount} onPageChange={setPage} />}
      {error && <div className="px-4 py-2 text-xs text-red-400">{error}</div>}
    </div>
  )
}

// ── Network events tab ────────────────────────────────────────────────────────

function NetworkTab() {
  const [page, setPage] = useState(1)
  const [data, setData] = useState<{ items: unknown[]; totalCount: number; page: number; perPage: number } | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setLoading(true)
    GetNetworkEvents(page, PER_PAGE)
      .then(setData)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, [page])

  type Row = {
    id: number; eventTime: number; pid: number; uid: number; processName: string
    srcAddr: string; dstAddr: string; srcPort: number; dstPort: number; protocol: string; severity: string
  }

  return (
    <div className="flex flex-col flex-1 overflow-hidden">
      <div className="flex-1 overflow-auto">
        <table className="w-full text-xs border-collapse">
          <thead>
            <tr className="sticky top-0 text-left" style={{ background: 'rgb(var(--surface-2))', color: 'rgb(var(--muted))' }}>
              {['Time', 'Process', 'PID', 'Source', 'Destination', 'Proto', 'Severity'].map(h => (
                <th key={h} className="px-4 py-2 font-medium border-b whitespace-nowrap" style={{ borderColor: 'rgb(var(--border))' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading && <tr><td colSpan={7} className="px-4 py-8 text-center" style={{ color: 'rgb(var(--muted))' }}>Loading…</td></tr>}
            {!loading && (data?.items as Row[] | undefined)?.map(row => (
              <tr key={row.id} className="border-b hover:bg-[rgb(var(--surface-2)/0.5)] transition-colors" style={{ borderColor: 'rgb(var(--border))' }}>
                <td className="px-4 py-2 whitespace-nowrap tabular-nums">{fmtTime(row.eventTime)}</td>
                <td className="px-4 py-2">{row.processName}</td>
                <td className="px-4 py-2 tabular-nums" style={{ color: 'rgb(var(--muted))' }}>{row.pid}</td>
                <td className="px-4 py-2 tabular-nums whitespace-nowrap">{row.srcAddr}:{row.srcPort}</td>
                <td className="px-4 py-2 tabular-nums whitespace-nowrap">{row.dstAddr}:{row.dstPort}</td>
                <td className="px-4 py-2 uppercase">{row.protocol}</td>
                <td className="px-4 py-2"><SeverityBadge severity={row.severity} /></td>
              </tr>
            ))}
            {!loading && !data?.items?.length && <tr><td colSpan={7} className="px-4 py-8 text-center" style={{ color: 'rgb(var(--muted))' }}>No events.</td></tr>}
          </tbody>
        </table>
      </div>
      {data && <Pagination page={data.page} perPage={data.perPage} totalCount={data.totalCount} onPageChange={setPage} />}
      {error && <div className="px-4 py-2 text-xs text-red-400">{error}</div>}
    </div>
  )
}

// ── Memory events tab ─────────────────────────────────────────────────────────

function MemoryTab() {
  const [page, setPage] = useState(1)
  const [data, setData] = useState<{ items: unknown[]; totalCount: number; page: number; perPage: number } | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setLoading(true)
    GetMemoryEvents(page, PER_PAGE)
      .then(setData)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, [page])

  type Row = {
    id: number; eventTime: number; pid: number; uid: number; processName: string
    address: number; length: number; protection: number; filePath: string; severity: string
  }

  return (
    <div className="flex flex-col flex-1 overflow-hidden">
      <div className="flex-1 overflow-auto">
        <table className="w-full text-xs border-collapse">
          <thead>
            <tr className="sticky top-0 text-left" style={{ background: 'rgb(var(--surface-2))', color: 'rgb(var(--muted))' }}>
              {['Time', 'Process', 'PID', 'Address', 'Length', 'Prot', 'File', 'Severity'].map(h => (
                <th key={h} className="px-4 py-2 font-medium border-b whitespace-nowrap" style={{ borderColor: 'rgb(var(--border))' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading && <tr><td colSpan={8} className="px-4 py-8 text-center" style={{ color: 'rgb(var(--muted))' }}>Loading…</td></tr>}
            {!loading && (data?.items as Row[] | undefined)?.map(row => (
              <tr key={row.id} className="border-b hover:bg-[rgb(var(--surface-2)/0.5)] transition-colors" style={{ borderColor: 'rgb(var(--border))' }}>
                <td className="px-4 py-2 whitespace-nowrap tabular-nums">{fmtTime(row.eventTime)}</td>
                <td className="px-4 py-2">{row.processName}</td>
                <td className="px-4 py-2 tabular-nums" style={{ color: 'rgb(var(--muted))' }}>{row.pid}</td>
                <td className="px-4 py-2 tabular-nums font-mono">0x{row.address.toString(16)}</td>
                <td className="px-4 py-2 tabular-nums">{row.length}</td>
                <td className="px-4 py-2 tabular-nums">{row.protection}</td>
                <td className="px-4 py-2 max-w-[180px] truncate" title={row.filePath}>{row.filePath || '—'}</td>
                <td className="px-4 py-2"><SeverityBadge severity={row.severity} /></td>
              </tr>
            ))}
            {!loading && !data?.items?.length && <tr><td colSpan={8} className="px-4 py-8 text-center" style={{ color: 'rgb(var(--muted))' }}>No events.</td></tr>}
          </tbody>
        </table>
      </div>
      {data && <Pagination page={data.page} perPage={data.perPage} totalCount={data.totalCount} onPageChange={setPage} />}
      {error && <div className="px-4 py-2 text-xs text-red-400">{error}</div>}
    </div>
  )
}

// ── Events page with tab bar ──────────────────────────────────────────────────

const tabs = [
  { label: 'Security', path: '/events/security' },
  { label: 'Network',  path: '/events/network'  },
  { label: 'Memory',   path: '/events/memory'   },
]

export default function Events() {
  return (
    <div className="flex flex-col h-full">
      {/* Tab bar */}
      <div
        className="flex items-center gap-1 px-6 pt-4 border-b shrink-0"
        style={{ borderColor: 'rgb(var(--border))' }}
      >
        <h1 className="text-base font-semibold mr-4">Events</h1>
        {tabs.map(({ label, path }) => (
          <NavLink
            key={path}
            to={path}
            className={({ isActive }) =>
              [
                'px-4 py-2 text-sm -mb-px border-b-2 transition-colors',
                isActive
                  ? 'border-[rgb(var(--accent))] text-[rgb(var(--accent))]'
                  : 'border-transparent hover:text-[rgb(var(--fg))]',
              ].join(' ')
            }
            style={{ color: 'rgb(var(--muted))' }}
          >
            {label}
          </NavLink>
        ))}
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-hidden flex flex-col">
        <Routes>
          <Route index element={<Navigate to="security" replace />} />
          <Route path="security" element={<SecurityTab />} />
          <Route path="network"  element={<NetworkTab />} />
          <Route path="memory"   element={<MemoryTab />} />
        </Routes>
      </div>
    </div>
  )
}
