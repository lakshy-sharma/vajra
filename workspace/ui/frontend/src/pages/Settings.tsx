// ui/frontend/src/pages/Settings.tsx
import { useEffect, useState, ReactNode } from 'react'
import { GetConfig, WriteConfig } from '../wails'

// ── Primitive field components ────────────────────────────────────────────────

function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <label className="text-xs font-medium" style={{ color: 'rgb(var(--fg))' }}>{label}</label>
      {children}
      {hint && <p className="text-[11px]" style={{ color: 'rgb(var(--muted))' }}>{hint}</p>}
    </div>
  )
}

function TextInput({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <input
      type="text"
      value={value}
      onChange={e => onChange(e.target.value)}
      className="text-xs rounded-md px-3 py-1.5 border outline-none w-full"
      style={{
        background: 'rgb(var(--surface))',
        borderColor: 'rgb(var(--border))',
        color: 'rgb(var(--fg))',
      }}
    />
  )
}

function NumberInput({
  value, onChange, min, max,
}: { value: number; onChange: (v: number) => void; min?: number; max?: number }) {
  return (
    <input
      type="number"
      value={value}
      min={min}
      max={max}
      onChange={e => onChange(Number(e.target.value))}
      className="text-xs rounded-md px-3 py-1.5 border outline-none w-32"
      style={{
        background: 'rgb(var(--surface))',
        borderColor: 'rgb(var(--border))',
        color: 'rgb(var(--fg))',
      }}
    />
  )
}

function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <label className="flex items-center gap-2 cursor-pointer select-none text-xs" style={{ color: 'rgb(var(--fg))' }}>
      <input
        type="checkbox"
        checked={checked}
        onChange={e => onChange(e.target.checked)}
        className="w-3.5 h-3.5 rounded"
        style={{ accentColor: 'rgb(var(--accent))' }}
      />
      {label}
    </label>
  )
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section
      className="rounded-lg border p-6 space-y-5"
      style={{ background: 'rgb(var(--surface))', borderColor: 'rgb(var(--border))' }}
    >
      <h2 className="text-sm font-semibold" style={{ color: 'rgb(var(--fg))' }}>{title}</h2>
      <div className="grid grid-cols-2 gap-x-8 gap-y-4">
        {children}
      </div>
    </section>
  )
}

// ── Settings page ─────────────────────────────────────────────────────────────

// Mirror the UIConfig shape produced by app.go — explicit typing avoids
// relying on Wails-generated classes which may not be available in dev.
interface UIConfig {
  genericSettings:     { operationMode: string; workDirectory: string }
  threatIntelSettings: { bloomFilterPath: string }
  timing: {
    dedupWindowMin: number; autorunScanIntervalMin: number
    secretsScanIntervalMin: number; singleTargetSecretsTimeoutMin: number
    statsSyncIntervalMin: number; cleanupIntervalHour: number
    eventRetentionDays: number; hashSyncIntervalHour: number
    rulesSyncIntervalHour: number
  }
  performance: {
    defaultThreads: number; maxAllowedThreads: number
    scanQueueSize: number; resultCacheSize: number; autorunConcurrency: number
  }
  scan: { targetDirectory: string; maxFileSizeBytes: number; yaraSnapshotBytes: number }
  rules: { rulesFilepath: string; rulesRemoteURL: string; rulesArchiveCount: number; rulesSyncIntervalHour: number }
  log: { directory: string; level: string; maxSizeMB: number; maxBackups: number; maxAgeDays: number; compress: boolean }
  window: { defaultTheme: string; windowWidth: number; windowHeight: number; minWindowWidth: number; minWindowHeight: number; pageSize: number }
  alertPolicy: { highValueInboundPorts: number[]; highValueOutboundPorts: number[] }
}

const MODES   = ['monitor', 'enforce', 'diagnose']
const THEMES  = ['system', 'dark', 'light']
const LEVELS  = ['debug', 'info', 'warn', 'error']

export default function Settings() {
  const [cfg, setCfg]       = useState<UIConfig | null>(null)
  const [saving, setSaving] = useState(false)
  const [error, setError]   = useState<string | null>(null)
  const [success, setSuccess] = useState(false)

  useEffect(() => {
    GetConfig()
      .then(c => setCfg(c as unknown as UIConfig))
      .catch((e: Error) => setError(e.message))
  }, [])

  function patch<K extends keyof UIConfig>(section: K, partial: Partial<UIConfig[K]>) {
    setCfg(c => c ? { ...c, [section]: { ...c[section], ...partial } } : c)
  }

  async function handleSave() {
    if (!cfg) return
    setSaving(true)
    setError(null)
    setSuccess(false)
    try {
      await WriteConfig(JSON.stringify(cfg))
      setSuccess(true)
      setTimeout(() => setSuccess(false), 3000)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setSaving(false)
    }
  }

  if (!cfg) {
    return (
      <div className="flex items-center justify-center h-full">
        <p className="text-sm" style={{ color: error ? '#ef4444' : 'rgb(var(--muted))' }}>
          {error ? `Error: ${error}` : 'Loading configuration…'}
        </p>
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div
        className="flex items-center gap-4 px-6 py-3 border-b shrink-0"
        style={{ borderColor: 'rgb(var(--border))' }}
      >
        <h1 className="text-base font-semibold mr-auto" style={{ color: 'rgb(var(--fg))' }}>Settings</h1>
        {success && <span className="text-xs text-green-500">Saved — restart daemon to apply.</span>}
        {error && <span className="text-xs text-red-400 max-w-xs truncate" title={error}>{error}</span>}
        <button
          onClick={handleSave}
          disabled={saving}
          className="px-4 py-1.5 text-xs rounded-md font-medium disabled:opacity-50 transition-opacity"
          style={{ background: 'rgb(var(--accent))', color: '#fff' }}
        >
          {saving ? 'Saving…' : 'Save changes'}
        </button>
      </div>

      <div className="flex-1 overflow-auto px-6 py-6 space-y-6 max-w-3xl">

        {/* General */}
        <Section title="General">
          <Field label="Operation mode" hint="monitor: observe only · enforce: block · diagnose: verbose">
            <select
              value={cfg.genericSettings.operationMode}
              onChange={e => patch('genericSettings', { operationMode: e.target.value })}
              className="text-xs rounded-md px-3 py-1.5 border outline-none w-40"
              style={{ background: 'rgb(var(--surface))', borderColor: 'rgb(var(--border))', color: 'rgb(var(--fg))' }}
            >
              {MODES.map(m => <option key={m} value={m}>{m}</option>)}
            </select>
          </Field>
          <Field label="Work directory">
            <TextInput value={cfg.genericSettings.workDirectory} onChange={v => patch('genericSettings', { workDirectory: v })} />
          </Field>
        </Section>

        {/* Scan */}
        <Section title="Scanning">
          <Field label="Target directory" hint="Root path for full filesystem scans">
            <TextInput value={cfg.scan.targetDirectory} onChange={v => patch('scan', { targetDirectory: v })} />
          </Field>
          <Field label="Max file size (bytes)" hint="Files larger than this are hashed but not YARA-scanned">
            <NumberInput value={cfg.scan.maxFileSizeBytes} onChange={v => patch('scan', { maxFileSizeBytes: v })} min={1} />
          </Field>
          <Field label="YARA snapshot bytes" hint="Bytes of matched content stored per YARA string match">
            <NumberInput value={cfg.scan.yaraSnapshotBytes} onChange={v => patch('scan', { yaraSnapshotBytes: v })} min={1} max={4096} />
          </Field>
        </Section>

        {/* Performance */}
        <Section title="Performance">
          <Field label="Default scan threads">
            <NumberInput value={cfg.performance.defaultThreads} onChange={v => patch('performance', { defaultThreads: v })} min={1} />
          </Field>
          <Field label="Max scan threads">
            <NumberInput value={cfg.performance.maxAllowedThreads} onChange={v => patch('performance', { maxAllowedThreads: v })} min={1} />
          </Field>
          <Field label="Scan queue size">
            <NumberInput value={cfg.performance.scanQueueSize} onChange={v => patch('performance', { scanQueueSize: v })} min={1} />
          </Field>
          <Field label="Result cache size" hint="SHA256 → YARA result LRU entries">
            <NumberInput value={cfg.performance.resultCacheSize} onChange={v => patch('performance', { resultCacheSize: v })} min={100} />
          </Field>
          <Field label="Autorun concurrency" hint="Parallel sources per scan pass">
            <NumberInput value={cfg.performance.autorunConcurrency} onChange={v => patch('performance', { autorunConcurrency: v })} min={1} max={12} />
          </Field>
        </Section>

        {/* Timing */}
        <Section title="Timing">
          <Field label="Dedup window (min)" hint="Suppress duplicate detections within this window">
            <NumberInput value={cfg.timing.dedupWindowMin} onChange={v => patch('timing', { dedupWindowMin: v })} min={1} />
          </Field>
          <Field label="Autorun scan interval (min)">
            <NumberInput value={cfg.timing.autorunScanIntervalMin} onChange={v => patch('timing', { autorunScanIntervalMin: v })} min={1} />
          </Field>
          <Field label="Secrets scan interval (min)">
            <NumberInput value={cfg.timing.secretsScanIntervalMin} onChange={v => patch('timing', { secretsScanIntervalMin: v })} min={1} />
          </Field>
          <Field label="Per-target secrets timeout (min)">
            <NumberInput value={cfg.timing.singleTargetSecretsTimeoutMin} onChange={v => patch('timing', { singleTargetSecretsTimeoutMin: v })} min={1} />
          </Field>
          <Field label="Stats sync interval (min)">
            <NumberInput value={cfg.timing.statsSyncIntervalMin} onChange={v => patch('timing', { statsSyncIntervalMin: v })} min={1} />
          </Field>
          <Field label="Cleanup interval (hours)">
            <NumberInput value={cfg.timing.cleanupIntervalHour} onChange={v => patch('timing', { cleanupIntervalHour: v })} min={1} />
          </Field>
          <Field label="Event retention (days)">
            <NumberInput value={cfg.timing.eventRetentionDays} onChange={v => patch('timing', { eventRetentionDays: v })} min={1} />
          </Field>
          <Field label="Hash sync interval (hours)">
            <NumberInput value={cfg.timing.hashSyncIntervalHour} onChange={v => patch('timing', { hashSyncIntervalHour: v })} min={1} />
          </Field>
          <Field label="Rules sync interval (hours)">
            <NumberInput value={cfg.timing.rulesSyncIntervalHour} onChange={v => patch('timing', { rulesSyncIntervalHour: v })} min={1} />
          </Field>
        </Section>

        {/* Rules */}
        <Section title="YARA Rules">
          <Field label="Rules file path">
            <TextInput value={cfg.rules.rulesFilepath} onChange={v => patch('rules', { rulesFilepath: v })} />
          </Field>
          <Field label="Rules remote URL" hint="YARA Forge bundle download URL">
            <TextInput value={cfg.rules.rulesRemoteURL} onChange={v => patch('rules', { rulesRemoteURL: v })} />
          </Field>
          <Field label="Archive count" hint="Old bundles to keep for rollback">
            <NumberInput value={cfg.rules.rulesArchiveCount} onChange={v => patch('rules', { rulesArchiveCount: v })} min={0} />
          </Field>
        </Section>

        {/* Threat Intel */}
        <Section title="Threat Intel">
          <Field label="Bloom filter path">
            <TextInput value={cfg.threatIntelSettings.bloomFilterPath} onChange={v => patch('threatIntelSettings', { bloomFilterPath: v })} />
          </Field>
        </Section>

        {/* Logging */}
        <Section title="Logging">
          <Field label="Log level">
            <select
              value={cfg.log.level}
              onChange={e => patch('log', { level: e.target.value })}
              className="text-xs rounded-md px-3 py-1.5 border outline-none w-28"
              style={{ background: 'rgb(var(--surface))', borderColor: 'rgb(var(--border))', color: 'rgb(var(--fg))' }}
            >
              {LEVELS.map(l => <option key={l} value={l}>{l}</option>)}
            </select>
          </Field>
          <Field label="Log directory">
            <TextInput value={cfg.log.directory} onChange={v => patch('log', { directory: v })} />
          </Field>
          <Field label="Max size (MB)">
            <NumberInput value={cfg.log.maxSizeMB} onChange={v => patch('log', { maxSizeMB: v })} min={1} />
          </Field>
          <Field label="Max backups">
            <NumberInput value={cfg.log.maxBackups} onChange={v => patch('log', { maxBackups: v })} min={0} />
          </Field>
          <Field label="Max age (days)">
            <NumberInput value={cfg.log.maxAgeDays} onChange={v => patch('log', { maxAgeDays: v })} min={1} />
          </Field>
          <Field label="Compress rotated logs">
            <Toggle checked={cfg.log.compress} onChange={v => patch('log', { compress: v })} label="Enabled" />
          </Field>
        </Section>

        {/* Window */}
        <Section title="UI">
          <Field label="Default theme" hint="Requires restart to change the window background colour">
            <select
              value={cfg.window.defaultTheme}
              onChange={e => patch('window', { defaultTheme: e.target.value })}
              className="text-xs rounded-md px-3 py-1.5 border outline-none w-28"
              style={{ background: 'rgb(var(--surface))', borderColor: 'rgb(var(--border))', color: 'rgb(var(--fg))' }}
            >
              {THEMES.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
          </Field>
          <Field label="Default page size">
            <NumberInput value={cfg.window.pageSize} onChange={v => patch('window', { pageSize: v })} min={10} max={200} />
          </Field>
          <Field label="Window size (px)">
            <div className="flex gap-2">
              <NumberInput value={cfg.window.windowWidth}  onChange={v => patch('window', { windowWidth: v })}  min={800} />
              <span className="self-center text-xs" style={{ color: 'rgb(var(--muted))' }}>×</span>
              <NumberInput value={cfg.window.windowHeight} onChange={v => patch('window', { windowHeight: v })} min={600} />
            </div>
          </Field>
          <Field label="Minimum size (px)">
            <div className="flex gap-2">
              <NumberInput value={cfg.window.minWindowWidth}  onChange={v => patch('window', { minWindowWidth: v })}  min={400} />
              <span className="self-center text-xs" style={{ color: 'rgb(var(--muted))' }}>×</span>
              <NumberInput value={cfg.window.minWindowHeight} onChange={v => patch('window', { minWindowHeight: v })} min={300} />
            </div>
          </Field>
        </Section>

      </div>
    </div>
  )
}
