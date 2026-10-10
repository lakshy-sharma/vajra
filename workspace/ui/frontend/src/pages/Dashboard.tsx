import { useEffect, useState } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from 'recharts'
import { GetTotals, GetStatsByDateRange } from '../wails'

interface StatRow {
  date: string
  eventType: number
  eventName: string
  totalCount: number
  maliciousCount: number
  cleanCount: number
}

const SEVERITY_COLORS = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#22c55e']

// Default: last 30 days
function last30Days(): [string, string] {
  const end = new Date()
  const start = new Date(end)
  start.setDate(end.getDate() - 29)
  const fmt = (d: Date) => d.toISOString().split('T')[0]
  return [fmt(start), fmt(end)]
}

export default function Dashboard() {
  const [totals, setTotals] = useState<StatRow[]>([])
  const [trend, setTrend] = useState<StatRow[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    GetTotals()
      .then(setTotals)
      .catch((e: Error) => setError(e.message))

    const [start, end] = last30Days()
    GetStatsByDateRange(start, end)
      .then(setTrend)
      .catch((e: Error) => setError(e.message))
  }, [])

  // Roll up trend by date for the stacked bar chart
  const byDate = trend.reduce<Record<string, { date: string; malicious: number; clean: number }>>((acc, r) => {
    if (!acc[r.date]) acc[r.date] = { date: r.date, malicious: 0, clean: 0 }
    acc[r.date].malicious += r.maliciousCount
    acc[r.date].clean += r.cleanCount
    return acc
  }, {})
  const trendData = Object.values(byDate).sort((a, b) => a.date.localeCompare(b.date))

  const totalMalicious = totals.reduce((s, r) => s + r.maliciousCount, 0)
  const totalClean     = totals.reduce((s, r) => s + r.cleanCount, 0)
  const totalAll       = totals.reduce((s, r) => s + r.totalCount, 0)

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-xl font-semibold">Dashboard</h1>

      {error && (
        <div className="rounded-md px-4 py-3 text-sm bg-red-500/10 text-red-400 ring-1 ring-red-500/20">
          {error}
        </div>
      )}

      {/* Summary cards */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'Total events',    value: totalAll.toLocaleString(),       color: 'text-[rgb(var(--fg))]' },
          { label: 'Malicious',       value: totalMalicious.toLocaleString(), color: 'text-red-500' },
          { label: 'Clean',           value: totalClean.toLocaleString(),     color: 'text-green-500' },
        ].map(({ label, value, color }) => (
          <div
            key={label}
            className="rounded-lg p-5 border"
            style={{ background: 'rgb(var(--surface))', borderColor: 'rgb(var(--border))' }}
          >
            <p className="text-xs mb-1" style={{ color: 'rgb(var(--muted))' }}>{label}</p>
            <p className={`text-3xl font-bold ${color}`}>{value}</p>
          </div>
        ))}
      </div>

      {/* Events by type */}
      <div
        className="rounded-lg border p-5"
        style={{ background: 'rgb(var(--surface))', borderColor: 'rgb(var(--border))' }}
      >
        <h2 className="text-sm font-medium mb-4">Events by type (all-time)</h2>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={totals} layout="vertical" margin={{ left: 16, right: 16 }}>
            <XAxis type="number" tick={{ fontSize: 11 }} />
            <YAxis
              type="category"
              dataKey="eventName"
              tick={{ fontSize: 11 }}
              width={130}
            />
            <Tooltip
              contentStyle={{
                background: 'rgb(var(--surface-2))',
                border: '1px solid rgb(var(--border))',
                borderRadius: 6,
                fontSize: 12,
              }}
            />
            <Bar dataKey="totalCount" name="Total" radius={[0, 4, 4, 0]}>
              {totals.map((_, i) => (
                <Cell key={i} fill={SEVERITY_COLORS[i % SEVERITY_COLORS.length]} />
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
        <h2 className="text-sm font-medium mb-4">Event trend — last 30 days</h2>
        <ResponsiveContainer width="100%" height={180}>
          <BarChart data={trendData} margin={{ left: 0, right: 16 }}>
            <XAxis
              dataKey="date"
              tick={{ fontSize: 10 }}
              tickFormatter={d => d.slice(5)} // MM-DD
            />
            <YAxis tick={{ fontSize: 11 }} />
            <Tooltip
              contentStyle={{
                background: 'rgb(var(--surface-2))',
                border: '1px solid rgb(var(--border))',
                borderRadius: 6,
                fontSize: 12,
              }}
            />
            <Bar dataKey="malicious" name="Malicious" stackId="a" fill="#ef4444" />
            <Bar dataKey="clean"     name="Clean"     stackId="a" fill="#22c55e" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
