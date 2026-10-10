const palette: Record<string, string> = {
  CRITICAL: 'bg-red-500/10 text-red-500 ring-1 ring-red-500/30',
  HIGH:     'bg-orange-500/10 text-orange-500 ring-1 ring-orange-500/30',
  MEDIUM:   'bg-yellow-500/10 text-yellow-500 ring-1 ring-yellow-500/30',
  LOW:      'bg-blue-500/10 text-blue-500 ring-1 ring-blue-500/30',
  CLEAN:    'bg-green-500/10 text-green-500 ring-1 ring-green-500/30',
}

export default function SeverityBadge({ severity }: { severity: string }) {
  const cls = palette[severity?.toUpperCase()] ?? 'bg-zinc-500/10 text-zinc-400 ring-1 ring-zinc-500/30'
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium ${cls}`}>
      {severity}
    </span>
  )
}
