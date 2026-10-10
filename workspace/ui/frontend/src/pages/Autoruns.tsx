import { useEffect, useState } from 'react'
import { GetAutoruns } from '../wails'

interface AutorunRow {
  id: number
  category: string
  location: string
  imagePath: string
  imageName: string
  arguments: string
  sha256: string
  isActive: boolean
  firstSeen: number
  lastSeen: number
}

function fmtTime(unix: number) {
  if (!unix) return '—'
  return new Date(unix * 1000).toLocaleDateString()
}

function categoryLabel(cat: string) {
  return cat.replace(/_/g, ' ')
}

export default function Autoruns() {
  const [rows, setRows] = useState<AutorunRow[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [filter, setFilter] = useState('')

  useEffect(() => {
    setLoading(true)
    GetAutoruns()
      .then(setRows)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  const visible = filter
    ? rows.filter(r =>
        r.imageName.toLowerCase().includes(filter) ||
        r.imagePath.toLowerCase().includes(filter) ||
        r.category.toLowerCase().includes(filter)
      )
    : rows

  // Group by category for display
  const groups = visible.reduce<Record<string, AutorunRow[]>>((acc, r) => {
    ;(acc[r.category] ??= []).push(r)
    return acc
  }, {})

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div
        className="flex items-center gap-3 px-6 py-3 border-b shrink-0"
        style={{ borderColor: 'rgb(var(--border))' }}
      >
        <h1 className="text-base font-semibold mr-auto">Autoruns</h1>
        <input
          type="search"
          placeholder="Filter…"
          value={filter}
          onChange={e => setFilter(e.target.value.toLowerCase())}
          className="text-xs rounded-md px-3 py-1.5 border w-48 outline-none"
          style={{
            background: 'rgb(var(--surface))',
            borderColor: 'rgb(var(--border))',
            color: 'rgb(var(--fg))',
          }}
        />
        <span className="text-xs" style={{ color: 'rgb(var(--muted))' }}>
          {visible.length} entries
        </span>
      </div>

      {error && (
        <div className="mx-6 mt-4 rounded-md px-4 py-3 text-sm bg-red-500/10 text-red-400 ring-1 ring-red-500/20">
          {error}
        </div>
      )}

      <div className="flex-1 overflow-auto px-6 py-4 space-y-6">
        {loading && (
          <p className="text-sm text-center py-8" style={{ color: 'rgb(var(--muted))' }}>Loading…</p>
        )}
        {!loading && Object.entries(groups).map(([cat, entries]) => (
          <section key={cat}>
            <h2
              className="text-xs font-semibold uppercase tracking-wider mb-2"
              style={{ color: 'rgb(var(--muted))' }}
            >
              {categoryLabel(cat)} ({entries.length})
            </h2>
            <div
              className="rounded-lg border overflow-hidden"
              style={{ borderColor: 'rgb(var(--border))' }}
            >
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr style={{ background: 'rgb(var(--surface-2))', color: 'rgb(var(--muted))' }}>
                    {['Name', 'Path', 'Location', 'SHA256', 'Active', 'First seen', 'Last seen'].map(h => (
                      <th key={h} className="px-4 py-2 font-medium text-left whitespace-nowrap border-b"
                          style={{ borderColor: 'rgb(var(--border))' }}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {entries.map(row => (
                    <tr
                      key={row.id}
                      className="border-b hover:bg-[rgb(var(--surface-2)/0.5)] transition-colors"
                      style={{ borderColor: 'rgb(var(--border))' }}
                    >
                      <td className="px-4 py-2 font-medium">{row.imageName}</td>
                      <td
                        className="px-4 py-2 max-w-[220px] truncate font-mono"
                        style={{ color: 'rgb(var(--muted))' }}
                        title={row.imagePath}
                      >
                        {row.imagePath}
                      </td>
                      <td className="px-4 py-2 max-w-[160px] truncate" title={row.location}>
                        {row.location}
                      </td>
                      <td
                        className="px-4 py-2 font-mono max-w-[120px] truncate"
                        style={{ color: 'rgb(var(--muted))' }}
                        title={row.sha256}
                      >
                        {row.sha256 ? row.sha256.slice(0, 12) + '…' : '—'}
                      </td>
                      <td className="px-4 py-2">
                        <span className={row.isActive
                          ? 'text-green-500'
                          : 'text-zinc-500'
                        }>
                          {row.isActive ? 'Yes' : 'No'}
                        </span>
                      </td>
                      <td className="px-4 py-2 whitespace-nowrap tabular-nums">{fmtTime(row.firstSeen)}</td>
                      <td className="px-4 py-2 whitespace-nowrap tabular-nums">{fmtTime(row.lastSeen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        ))}
        {!loading && visible.length === 0 && (
          <p className="text-sm text-center py-8" style={{ color: 'rgb(var(--muted))' }}>
            No autorun entries found.
          </p>
        )}
      </div>
    </div>
  )
}
