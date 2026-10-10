import { useEffect, useState } from 'react'
import { GetDetections } from '../wails'
import Pagination from '../components/Pagination'
import SeverityBadge from '../components/SeverityBadge'

interface DetectionRow {
  id: number
  detectionTime: number
  source: string
  severity: string
  status: string
  processName: string
  exePath: string
  cmdLine: string
  targetPath: string
  ruleId: string
  mitreTechnique: string
  dedupCount: number
  notes: string
}

interface Page {
  items: DetectionRow[]
  totalCount: number
  page: number
  perPage: number
}

interface Filters {
  severity: string
  status: string
  source: string
}

const SEVERITIES = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'CLEAN']
const STATUSES   = ['', 'NEW', 'IN_PROGRESS', 'RESOLVED', 'IGNORED']
const SOURCES    = ['', 'yara', 'secrets', 'network', 'memory']
const PER_PAGE   = 50

function fmtTime(unix: number) {
  if (!unix) return '—'
  return new Date(unix * 1000).toLocaleString()
}

export default function Detections() {
  const [page, setPage] = useState(1)
  const [data, setData] = useState<Page | null>(null)
  const [filters, setFilters] = useState<Filters>({ severity: '', status: '', source: '' })
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    setLoading(true)
    setError(null)
    GetDetections(page, PER_PAGE, filters)
      .then(setData)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, [page, filters])

  function setFilter(key: keyof Filters, value: string) {
    setFilters(f => ({ ...f, [key]: value }))
    setPage(1)
  }

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div
        className="flex items-center gap-3 px-6 py-3 border-b shrink-0"
        style={{ borderColor: 'rgb(var(--border))' }}
      >
        <h1 className="text-base font-semibold mr-auto">Detections</h1>

        {/* Filters */}
        {([
          ['severity', SEVERITIES],
          ['status',   STATUSES],
          ['source',   SOURCES],
        ] as [keyof Filters, string[]][]).map(([key, opts]) => (
          <select
            key={key}
            value={filters[key]}
            onChange={e => setFilter(key, e.target.value)}
            className="text-xs rounded-md px-2 py-1.5 border outline-none"
            style={{
              background: 'rgb(var(--surface))',
              borderColor: 'rgb(var(--border))',
              color: filters[key] ? 'rgb(var(--fg))' : 'rgb(var(--muted))',
            }}
          >
            {opts.map(o => (
              <option key={o} value={o}>{o || `All ${key}s`}</option>
            ))}
          </select>
        ))}
      </div>

      {error && (
        <div className="mx-6 mt-4 rounded-md px-4 py-3 text-sm bg-red-500/10 text-red-400 ring-1 ring-red-500/20">
          {error}
        </div>
      )}

      {/* Table */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-xs border-collapse">
          <thead>
            <tr
              className="sticky top-0 text-left"
              style={{ background: 'rgb(var(--surface-2))', color: 'rgb(var(--muted))' }}
            >
              {['Time', 'Severity', 'Status', 'Source', 'Process', 'Target / Rule', 'Count'].map(h => (
                <th key={h} className="px-4 py-2 font-medium border-b whitespace-nowrap"
                    style={{ borderColor: 'rgb(var(--border))' }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center" style={{ color: 'rgb(var(--muted))' }}>
                  Loading…
                </td>
              </tr>
            )}
            {!loading && data?.items.map(row => (
              <tr
                key={row.id}
                className="border-b transition-colors hover:bg-[rgb(var(--surface-2)/0.5)]"
                style={{ borderColor: 'rgb(var(--border))' }}
              >
                <td className="px-4 py-2 whitespace-nowrap tabular-nums">{fmtTime(row.detectionTime)}</td>
                <td className="px-4 py-2"><SeverityBadge severity={row.severity} /></td>
                <td className="px-4 py-2 whitespace-nowrap" style={{ color: 'rgb(var(--muted))' }}>
                  {row.status}
                </td>
                <td className="px-4 py-2 whitespace-nowrap">{row.source}</td>
                <td className="px-4 py-2">
                  <div className="font-medium">{row.processName || '—'}</div>
                  <div className="truncate max-w-[200px]" style={{ color: 'rgb(var(--muted))' }} title={row.exePath}>
                    {row.exePath}
                  </div>
                </td>
                <td className="px-4 py-2">
                  <div className="truncate max-w-[220px]" title={row.targetPath}>{row.targetPath || '—'}</div>
                  {row.ruleId && (
                    <div className="text-[10px]" style={{ color: 'rgb(var(--muted))' }}>{row.ruleId}</div>
                  )}
                </td>
                <td className="px-4 py-2 tabular-nums text-right">{row.dedupCount || 1}</td>
              </tr>
            ))}
            {!loading && !data?.items?.length && (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center" style={{ color: 'rgb(var(--muted))' }}>
                  No detections found.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {data && (
        <Pagination
          page={data.page}
          perPage={data.perPage}
          totalCount={data.totalCount}
          onPageChange={setPage}
        />
      )}
    </div>
  )
}
