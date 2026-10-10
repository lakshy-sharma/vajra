import { useEffect, useState } from 'react'
import { GetConfig, WriteConfig } from '../wails'
// UIConfig and sub-types come from the Wails-generated bindings.
// The import path is resolved after `wails dev` generates wailsjs/.
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore — generated at build time
import type { main as WailsMain } from '../../wailsjs/go/models'
type UIConfig = WailsMain.UIConfig

function Field({
  label, children, hint,
}: { label: string; children: React.ReactNode; hint?: string }) {
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
      style={{ background: 'rgb(var(--surface))', borderColor: 'rgb(var(--border))', color: 'rgb(var(--fg))' }}
    />
  )
}

function NumberInput({ value, onChange, min, max }: {
  value: number; onChange: (v: number) => void; min?: number; max?: number
}) {
  return (
    <input
      type="number"
      value={value}
      min={min}
      max={max}
      onChange={e => onChange(Number(e.target.value))}
      className="text-xs rounded-md px-3 py-1.5 border outline-none w-32"
      style={{ background: 'rgb(var(--surface))', borderColor: 'rgb(var(--border))', color: 'rgb(var(--fg))' }}
    />
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section
      className="rounded-lg border p-6 space-y-4"
      style={{ background: 'rgb(var(--surface))', borderColor: 'rgb(var(--border))' }}
    >
      <h2 className="text-sm font-semibold">{title}</h2>
      <div className="grid grid-cols-2 gap-x-8 gap-y-4">
        {children}
      </div>
    </section>
  )
}

export default function Settings() {
  const [cfg, setCfg] = useState<UIConfig | null>(null)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)

  useEffect(() => {
    GetConfig()
      .then(c => setCfg(c))
      .catch((e: Error) => setError(e.message))
  }, [])

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

  // Wails generates classes (with a convertValues method) rather than plain
  // interfaces, so we cast the spread result back to UIConfig.
  function update<K extends keyof UIConfig>(section: K, partial: Partial<UIConfig[K]>) {
    setCfg(c => c ? { ...c, [section]: { ...c[section], ...partial } } as unknown as UIConfig : c)
  }

  if (!cfg) {
    return (
      <div className="flex items-center justify-center h-full">
        <p style={{ color: 'rgb(var(--muted))' }} className="text-sm">
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
        <h1 className="text-base font-semibold mr-auto">Settings</h1>
        {success && (
          <span className="text-xs text-green-500">Saved successfully.</span>
        )}
        {error && (
          <span className="text-xs text-red-400">{error}</span>
        )}
        <button
          onClick={handleSave}
          disabled={saving}
          className="px-4 py-1.5 text-xs rounded-md font-medium disabled:opacity-50 transition-colors"
          style={{ background: 'rgb(var(--accent))', color: '#fff' }}
        >
          {saving ? 'Saving…' : 'Save changes'}
        </button>
      </div>

      <div className="flex-1 overflow-auto px-6 py-6 space-y-6 max-w-3xl">
        {/* API server */}
        <Section title="API server">
          <Field label="Host">
            <TextInput
              value={cfg.apiServerSettings.host}
              onChange={v => update('apiServerSettings', { host: v })}
            />
          </Field>
          <Field label="Port">
            <NumberInput
              value={cfg.apiServerSettings.port}
              onChange={v => update('apiServerSettings', { port: v })}
              min={1} max={65535}
            />
          </Field>
        </Section>

        {/* Timing — field names are snake_case from the Go json tags */}
        <Section title="Timing">
          <Field label="Autorun scan interval (min)">
            <NumberInput value={cfg.timingSettings.autorun_scan_time_min} onChange={v => update('timingSettings', { autorun_scan_time_min: v })} min={1} />
          </Field>
          <Field label="DB cleanup interval (hours)">
            <NumberInput value={cfg.timingSettings.database_cleanup_time_hour} onChange={v => update('timingSettings', { database_cleanup_time_hour: v })} min={1} />
          </Field>
          <Field label="DB retention (days)">
            <NumberInput value={cfg.timingSettings.database_retention_days} onChange={v => update('timingSettings', { database_retention_days: v })} min={1} />
          </Field>
          <Field label="Dedup window (min)">
            <NumberInput value={cfg.timingSettings.dedup_window_min} onChange={v => update('timingSettings', { dedup_window_min: v })} min={1} />
          </Field>
          <Field label="Stats sync interval (min)">
            <NumberInput value={cfg.timingSettings.stats_sync_interval_min} onChange={v => update('timingSettings', { stats_sync_interval_min: v })} min={1} />
          </Field>
          <Field label="Shutdown timeout (sec)">
            <NumberInput value={cfg.timingSettings.shutdown_timeout_sec} onChange={v => update('timingSettings', { shutdown_timeout_sec: v })} min={1} />
          </Field>
        </Section>

        {/* Performance */}
        <Section title="Performance">
          <Field label="Default scan threads">
            <NumberInput value={cfg.performanceSettings.default_threads} onChange={v => update('performanceSettings', { default_threads: v })} min={1} />
          </Field>
          <Field label="Max allowed threads">
            <NumberInput value={cfg.performanceSettings.max_allowed_threads} onChange={v => update('performanceSettings', { max_allowed_threads: v })} min={1} />
          </Field>
          <Field label="Scan queue size">
            <NumberInput value={cfg.performanceSettings.scan_queue_size} onChange={v => update('performanceSettings', { scan_queue_size: v })} min={1} />
          </Field>
        </Section>

        {/* Rules */}
        <Section title="YARA rules">
          <Field label="Rules file path">
            <TextInput value={cfg.rulesSettings.rules_filepath} onChange={v => update('rulesSettings', { rules_filepath: v })} />
          </Field>
          <Field label="Sync interval (hours)">
            <NumberInput value={cfg.rulesSettings.rules_sync_interval_hour} onChange={v => update('rulesSettings', { rules_sync_interval_hour: v })} min={1} />
          </Field>
          <Field label="Archive count" hint="How many old rule archives to keep">
            <NumberInput value={cfg.rulesSettings.rules_archive_count} onChange={v => update('rulesSettings', { rules_archive_count: v })} min={1} />
          </Field>
        </Section>

        {/* Threat intel */}
        <Section title="Threat intelligence">
          <Field label="Bloom filter path">
            <TextInput value={cfg.threatIntelSettings.bloom_filter_path} onChange={v => update('threatIntelSettings', { bloom_filter_path: v })} />
          </Field>
          <Field label="Hash sync interval (hours)">
            <NumberInput value={cfg.threatIntelSettings.hash_sync_interval_hour} onChange={v => update('threatIntelSettings', { hash_sync_interval_hour: v })} min={1} />
          </Field>
        </Section>

        {/* Logging — Directory has json tag "log_directory", LogLevel is "log_level" */}
        <Section title="Logging">
          <Field label="Log level">
            <select
              value={cfg.logging.log_level}
              onChange={e => update('logging', { log_level: e.target.value })}
              className="text-xs rounded-md px-3 py-1.5 border outline-none"
              style={{ background: 'rgb(var(--surface))', borderColor: 'rgb(var(--border))', color: 'rgb(var(--fg))' }}
            >
              {['trace','debug','info','warn','error'].map(l => (
                <option key={l} value={l}>{l}</option>
              ))}
            </select>
          </Field>
          <Field label="Log directory">
            <TextInput value={cfg.logging.log_directory} onChange={v => update('logging', { log_directory: v })} />
          </Field>
          <Field label="Max file size (MB)">
            <NumberInput value={cfg.logging.max_size_mb} onChange={v => update('logging', { max_size_mb: v })} min={1} />
          </Field>
          <Field label="Max age (days)">
            <NumberInput value={cfg.logging.max_age_days} onChange={v => update('logging', { max_age_days: v })} min={1} />
          </Field>
        </Section>

        <p className="text-[11px] pb-4" style={{ color: 'rgb(var(--muted))' }}>
          Saving will prompt for your password via polkit. The daemon must be
          restarted for changes to take effect (systemctl restart vajra).
          DB path settings are controlled by the YAML file and cannot be changed here.
        </p>
      </div>
    </div>
  )
}
