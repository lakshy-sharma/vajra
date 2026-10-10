// ui/frontend/src/pages/Dashboard.tsx
import { useEffect, useState } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from 'recharts'
import { GetTotals, GetStatsByDateRange } from '../wails'

interface StatRow {
  date: number       // Unix epoch (int64) — was incorrectly typed as string
  eventType: number
  eventName: string
  totalCount: number
  maliciousCount: number
  cleanCount: number
}

const COLORS = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#22c55e', '#a855f7', '#06b6d4']

// Returns [startUnix, endUnix] for the last 30 days as Unix epoch seconds.
// GetStatsByDateRange now takes int64 epochs, not date strings.
function last30Days(): [number, number] {
  const end = Math.floor(Date.now() / 1000)
  const start = end - 29 * 24 * 60 * 60
  return [start, end]
}

function fmtEpochShort(unix: number): string {
  const d = new Date(unix * 1000)
  return `${d.getMonth() + 1}/${d.getDate()}`
}

export default function Dashboard() {
  const [totals, setTotals] = useState<StatRow[]>([])
  const [trend, setTrend]   = useState<StatRow[]>([])
  const [error, setError]   = useState<string | null>(null)

  useEffect(() => {
    GetTotals()
      .then(setTotals)
      .catch((e: Error) => setError(e.message))

    const [start, end] = last30Days()
    GetStatsByDateRange(start, end)
      .then(setTrend)
      .catch((e: Error) => setError(e.message))
  }, [])

  // Roll up trend rows by date (epoch) for the stacked bar chart.
  const byDate = trend.reduce<Record<number, { date: number; malicious: number; clean: number }>>((acc, r) => {
    if (!acc[r.date]) acc[r.date] = { date: r.date, malicious: 0, clean: 0 }
    acc[r.date].malicious += r.maliciousCount
    acc[r.date].clean     += r.cleanCount
    return acc
  }, {})
  const trendData = Object.values(byDate).sort((a, b) => a.date - b.date)

  const totalAll       = totals.reduce((s, r) => s + r.totalCount,     0)
  const totalMalicious = totals.reduce((s, r) => s + r.maliciousCount, 0)
  const totalClean     = totals.reduce((s, r) => s + r.cleanCount,     0)

  const tooltipStyle = {
    background: 'rgb(var(--surface-2))',
    border: '1px solid rgb(var(--border))',
    borderRadius: 6,
    fontSize: 12,
    color: 'rgb(var(--fg))',
  }

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-xl font-semibold" style={{ color: 'rgb(var(--fg))' }}>Dashboard</h1>

      {error && (
        <div className="rounded-md px-4 py-3 text-sm bg-red-500/10 text-red-400 ring-1 ring-red-500/20">
          {error}
        </div>
      )}

      {/* Summary cards */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'Total events', value: totalAll.toLocaleString(),       color: 'rgb(var(--fg))' },
          { label: 'Malicious',    value: totalMalicious.toLocaleString(), color: '#ef4444' },
          { label: 'Clean',        value: totalClean.toLocaleString(),     color: '#22c55e' },
        ].map(({ label, value, color }) => (
          <div
            key={label}
            className="rounded-lg p-5 border"
            style={{ background: 'rgb(var(--surface))', borderColor: 'rgb(var(--border))' }}
          >
            <p className="text-xs mb-1" style={{ color: 'rgb(var(--muted))' }}>{label}</p>
            <p className="text-3xl font-bold" style={{ color }}>{value}</p>
          </div>
        ))}
      </div>

      {/* Events by type */}
      <div
        className="rounded-lg border p-5"
        style={{ background: 'rgb(var(--surface))', borderColor: 'rgb(var(--border))' }}
      >
        <h2 className="text-sm font-medium mb-4" style={{ color: 'rgb(var(--fg))' }}>
          Events by type (all-time)
        </h2>
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={totals} layout="vertical" margin={{ left: 8, right: 16 }}>
            <XAxis type="number" tick={{ fontSize: 11, fill: 'rgb(var(--muted))' }} />
            <YAxis
              type="category"
              dataKey="eventName"
              tick={{ fontSize: 11, fill: 'rgb(var(--muted))' }}
              width={130}
            />
            <Tooltip contentStyle={tooltipStyle} cursor={{ fill: 'rgb(var(--surface-2))' }} />
            <Bar dataKey="totalCount" name="Total" radius={[0, 4, 4, 0]}>
              {totals.map((_, i) => (
                <Cell key={i} fill={COLORS[i % COLORS.length]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* 30-day trend */}
      <div
        className="rounded-lg border p-5"
        style={{ background: 'rgb(var(--surface))', borderColor: 'rgb(var(--border))' }}
      >
        <h2 className="text-sm font-medium mb-4" style={{ color: 'rgb(var(--fg))' }}>
          Event trend — last 30 days
        </h2>
        <ResponsiveContainer width="100%" height={180}>
          <BarChart data={trendData} margin={{ left: 0, right: 16 }}>
            <XAxis
              dataKey="date"
              tick={{ fontSize: 10, fill: 'rgb(var(--muted))' }}
              tickFormatter={fmtEpochShort}
            />
            <YAxis tick={{ fontSize: 11, fill: 'rgb(var(--muted))' }} />
            <Tooltip
              contentStyle={tooltipStyle}
              labelFormatter={v => `Date: ${fmtEpochShort(Number(v))}`}
              cursor={{ fill: 'rgb(var(--surface-2))' }}
            />
            <Bar dataKey="malicious" name="Malicious" stackId="a" fill="#ef4444" />
            <Bar dataKey="clean"     name="Clean"     stackId="a" fill="#22c55e" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
