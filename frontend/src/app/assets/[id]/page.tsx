'use client'

import { useState, useRef, useEffect } from 'react'
import { AppShell } from '@/components/layout/AppShell'
import { useCurrentUser } from '@/hooks/useAuth'
import { useAddAssetNote, useAddAssetTag, useAsset, useAssetFindings, useConfigBackupTarget, useConfigBackups, useDiffConfigBackup, useDownloadConfigBackup, useRefreshAssetAiAnalysis, useRemoveAssetTag, useRestoreAssist, useRunAssetPortScan, useTriggerConfigBackup, useUpdateAsset, useUpsertConfigBackupTarget, useWirelessClients } from '@/hooks/useAssets'
import { useTriggerScan } from '@/hooks/useScans'
import { StatusBadge, DeviceClassBadge, ConfidenceBadge } from '@/components/ui/Badge'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'
import { severityColor, formatDate, timeAgo } from '@/lib/utils'
import { Bot, Shield, Info, Network, ChevronLeft, Tag, Save, Plus, X, Router, Play, ServerCog, Wifi, ShieldAlert, Microscope, ChevronDown, ChevronUp, Workflow, Loader2, MessageSquareText, Download, FileJson2, Sheet } from 'lucide-react'
import { isAxiosError } from 'axios'
import Link from 'next/link'
import { useParams, useRouter } from 'next/navigation'
import type { Asset, AssetAutopsyStage, ConfigBackupTarget } from '@/types'
import { cn } from '@/lib/utils'
import { exportAssetJson, exportAssetCsv } from '@/lib/exportUtils'

const DEVICE_TYPE_OPTIONS = [
  'router',
  'switch',
  'access_point',
  'firewall',
  'server',
  'workstation',
  'nas',
  'printer',
  'ip_camera',
  'smart_tv',
  'iot_device',
  'voip',
  'unknown',
] as const

function getErrorDetail(error: Error): string | undefined {
  if (!isAxiosError(error)) {
    return undefined
  }
  const detail = error.response?.data?.detail
  return typeof detail === 'string' ? detail : undefined
}

function AssetMetadataEditor({ asset }: Readonly<{ asset: Asset }>) {
  const { mutate: updateAsset, isPending: isSaving } = useUpdateAsset()
  const { mutate: addTag, isPending: isAddingTag } = useAddAssetTag()
  const { mutate: removeTag } = useRemoveAssetTag()
  const [notes, setNotes] = useState(asset.notes ?? '')
  const [deviceType, setDeviceType] = useState(asset.device_type ?? '')
  const [customFieldsText, setCustomFieldsText] = useState(
    JSON.stringify(asset.custom_fields ?? {}, null, 2),
  )
  const [tagInput, setTagInput] = useState('')
  const [editorError, setEditorError] = useState<string | null>(null)

  function handleSaveMetadata() {
    try {
      const customFields = JSON.parse(customFieldsText || '{}')
      setEditorError(null)
      updateAsset({
        id: asset.id,
        payload: {
          notes,
          device_type: deviceType || null,
          custom_fields: customFields,
        },
      })
    } catch {
      setEditorError('Custom fields must be valid JSON.')
    }
  }

  function handleAddTag() {
    const normalized = tagInput.trim().toLowerCase()
    if (!normalized) return
    addTag(
      { id: asset.id, tag: normalized },
      {
        onSuccess: () => setTagInput(''),
      },
    )
  }

  return (
    <Card>
      <CardHeader><CardTitle>Tags & Metadata</CardTitle></CardHeader>
      <CardBody className="space-y-4">
        <div>
          <p className="text-xs text-zinc-500 mb-1.5">Tags</p>
          <div className="flex flex-wrap gap-1.5 mb-2">
            {asset.tags.map((tag) => (
              <span key={tag.tag} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300">
                {tag.tag}
                <button
                  onClick={() => removeTag({ id: asset.id, tag: tag.tag })}
                  aria-label={`Remove tag ${tag.tag}`}
                >
                  <X className="w-3 h-3" />
                </button>
              </span>
            ))}
          </div>
          <div className="flex gap-2">
            <input
              value={tagInput}
              onChange={(e) => setTagInput(e.target.value)}
              placeholder="Add tag"
              className="flex-1 px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
            />
            <button
              onClick={handleAddTag}
              disabled={isAddingTag}
              className="inline-flex items-center gap-1 px-3 py-2 rounded-lg text-sm bg-sky-500 text-white"
            >
              <Plus className="w-3.5 h-3.5" /> Add
            </button>
          </div>
        </div>

        <div>
          <p className="text-xs text-zinc-500 mb-1.5">Device type</p>
          <select
            value={deviceType}
            onChange={(e) => setDeviceType(e.target.value)}
            className="w-full px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
          >
            <option value="">Auto-detect</option>
            {DEVICE_TYPE_OPTIONS.map((option) => (
              <option key={option} value={option}>
                {option.replaceAll('_', ' ')}
              </option>
            ))}
          </select>
          <p className="text-xs text-zinc-400 mt-1">
            Current source: {asset.device_type_source}
          </p>
        </div>

        <div>
          <p className="text-xs text-zinc-500 mb-1.5">Asset summary notes</p>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            rows={4}
            className="w-full px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
          />
          <p className="text-xs text-zinc-400 mt-1">
            Use this for the durable asset summary. Day-to-day comments belong in the notes timeline.
          </p>
        </div>

        <div>
          <p className="text-xs text-zinc-500 mb-1.5">Custom fields (JSON)</p>
          <textarea
            value={customFieldsText}
            onChange={(e) => setCustomFieldsText(e.target.value)}
            rows={8}
            className="w-full px-3 py-2 rounded-lg text-sm font-mono bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
          />
          {editorError && <p className="text-xs text-red-500 mt-1">{editorError}</p>}
        </div>

        <button
          onClick={handleSaveMetadata}
          disabled={isSaving}
          className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm bg-sky-500 text-white"
        >
          <Save className="w-3.5 h-3.5" /> {isSaving ? 'Saving…' : 'Save'}
        </button>
      </CardBody>
    </Card>
  )
}

function AssetNotesCard({ asset }: Readonly<{ asset: Asset }>) {
  const { data: currentUser } = useCurrentUser()
  const { mutate: addNote, isPending } = useAddAssetNote()
  const [content, setContent] = useState('')
  const [error, setError] = useState<string | null>(null)

  function handleAddNote() {
    const normalized = content.trim()
    if (!normalized) {
      setError('Enter a note before saving.')
      return
    }
    setError(null)
    addNote(
      { id: asset.id, content: normalized },
      {
        onSuccess: () => setContent(''),
        onError: (err: Error) => {
          const detail = getErrorDetail(err)
          setError(typeof detail === 'string' ? detail : 'Unable to save note right now.')
        },
      },
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle><MessageSquareText className="w-4 h-4 inline mr-1.5 text-emerald-500" />Notes</CardTitle>
      </CardHeader>
      <CardBody className="space-y-4">
        <div className="rounded-xl border border-gray-200 dark:border-zinc-800 p-3">
          <p className="text-xs text-zinc-500 mb-2">
            Add operational context, handoff notes, or remediation history. Notes are stored with the asset and attributed to the user who added them.
          </p>
          <textarea
            value={content}
            onChange={(event) => setContent(event.target.value)}
            rows={4}
            placeholder={currentUser ? `Add a note as ${currentUser.username}` : 'Add a note'}
            className="w-full px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
          />
          {error && <p className="text-xs text-red-500 mt-2">{error}</p>}
          <div className="mt-3 flex items-center justify-between gap-3">
            <p className="text-xs text-zinc-400">
              Summary notes remain editable in Tags & Metadata.
            </p>
            <button
              type="button"
              onClick={handleAddNote}
              disabled={isPending}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs bg-emerald-500 text-white"
            >
              <Plus className="w-3.5 h-3.5" />
              {isPending ? 'Saving…' : 'Add Note'}
            </button>
          </div>
        </div>

        {asset.note_entries.length === 0 ? (
          <p className="text-sm text-zinc-500">No note entries have been recorded for this asset yet.</p>
        ) : (
          <div className="space-y-3">
            {asset.note_entries.map((note) => (
              <div key={note.id} className="rounded-xl border border-gray-200 dark:border-zinc-800 p-4">
                <div className="flex items-center justify-between gap-3">
                  <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">
                    {note.user?.username ?? 'Unknown user'}
                  </p>
                  <p className="text-xs text-zinc-500">
                    {formatDate(note.created_at)}
                    {note.updated_at !== note.created_at ? ` · edited ${timeAgo(note.updated_at)}` : ''}
                  </p>
                </div>
                <p className="mt-2 whitespace-pre-wrap text-sm text-zinc-600 dark:text-zinc-300">
                  {note.content}
                </p>
              </div>
            ))}
          </div>
        )}
      </CardBody>
    </Card>
  )
}

function ConfigBackupForm({ asset, target }: Readonly<{ asset: Asset; target: ConfigBackupTarget | null | undefined }>) {
  const { mutate: saveTarget, isPending: isSaving } = useUpsertConfigBackupTarget()
  const { mutate: triggerBackup, isPending: isRunning } = useTriggerConfigBackup()
  const [driver, setDriver] = useState(target?.driver ?? 'openwrt')
  const [username, setUsername] = useState(target?.username ?? 'root')
  const [passwordEnvVar, setPasswordEnvVar] = useState(target?.password_env_var ?? '')
  const [port, setPort] = useState(target?.port ?? 22)
  const [hostOverride, setHostOverride] = useState(target?.host_override ?? '')
  const [enabled, setEnabled] = useState(target?.enabled ?? true)

  function handleSave() {
    saveTarget({
      id: asset.id,
      payload: {
        driver,
        username,
        password_env_var: passwordEnvVar || null,
        port,
        host_override: hostOverride || null,
        enabled,
      },
    })
  }

  return (
    <>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <select value={driver} onChange={(event) => setDriver(event.target.value)} className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
          <option value="cisco_ios">Cisco IOS</option>
          <option value="juniper_junos">Juniper Junos</option>
          <option value="mikrotik_routeros">MikroTik RouterOS</option>
          <option value="openwrt">OpenWRT</option>
        </select>
        <input value={username} onChange={(event) => setUsername(event.target.value)} placeholder="SSH username" className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700" />
        <input value={passwordEnvVar} onChange={(event) => setPasswordEnvVar(event.target.value)} placeholder="Password env var, e.g. ARGUS_BACKUP_PASSWORD" className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700" />
        <input value={hostOverride} onChange={(event) => setHostOverride(event.target.value)} placeholder="Optional host override" className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700" />
        <input value={port} type="number" onChange={(event) => setPort(Number(event.target.value) || 22)} placeholder="22" className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700" />
        <label className="inline-flex items-center gap-2 text-sm text-zinc-600 dark:text-zinc-300">
          <input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />
          <span>Enabled</span>
        </label>
      </div>

      <div className="flex flex-wrap gap-3">
        <button onClick={handleSave} disabled={isSaving} className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm bg-sky-500 text-white">
          <ServerCog className="w-4 h-4" /> {isSaving ? 'Saving…' : 'Save backup target'}
        </button>
        <button onClick={() => triggerBackup(asset.id)} disabled={isRunning || !target} className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm border border-gray-200 dark:border-zinc-700">
          <Play className="w-4 h-4" /> {isRunning ? 'Running…' : 'Run backup now'}
        </button>
      </div>
    </>
  )
}

function ConfigBackupCard({ asset }: Readonly<{ asset: Asset }>) {
  const { data: target } = useConfigBackupTarget(asset.id)
  const { data: backups = [] } = useConfigBackups(asset.id)
  const { mutateAsync: downloadBackup } = useDownloadConfigBackup()
  const { mutateAsync: diffBackup } = useDiffConfigBackup()
  const { mutateAsync: restoreAssist } = useRestoreAssist()
  const [diffText, setDiffText] = useState<string | null>(null)
  const [restoreText, setRestoreText] = useState<string | null>(null)

  async function handleDownload(snapshotId: number) {
    const data = await downloadBackup({ id: asset.id, snapshotId })
    const url = URL.createObjectURL(data)
    const link = document.createElement('a')
    link.href = url
    link.download = `argus-backup-${snapshotId}.txt`
    link.click()
    URL.revokeObjectURL(url)
  }

  return (
    <Card>
      <CardHeader><CardTitle><Router className="w-4 h-4 inline mr-1.5" />Config Backups</CardTitle></CardHeader>
      <CardBody className="space-y-4">
        <p className="text-sm text-zinc-500">
          Configure SSH-based backups for network devices. Secrets stay in container environment variables; this form stores only the env var name.
        </p>

        <ConfigBackupForm asset={asset} target={target} key={`${asset.id}:${target?.updated_at ?? 'new'}`} />

        <div className="space-y-3">
          {backups.map((backup) => (
            <div key={backup.id} className="rounded-xl border border-gray-200 dark:border-zinc-800 p-4">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">{backup.driver}</p>
                  <p className="text-xs text-zinc-500">{new Date(backup.captured_at).toLocaleString()}</p>
                </div>
                <span className="text-xs px-2 py-0.5 rounded-full bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-300">
                  {backup.status}
                </span>
              </div>
              {backup.error && <p className="text-xs text-red-500 mt-2">{backup.error}</p>}
              {backup.content && (
                <pre className="mt-3 max-h-64 overflow-auto rounded-lg bg-zinc-950 text-zinc-200 p-3 text-xs">
                  {backup.content}
                </pre>
              )}
              <div className="mt-3 flex flex-wrap gap-3">
                <button onClick={() => handleDownload(backup.id)} className="text-sm text-sky-500 hover:text-sky-600">Download</button>
                <button onClick={async () => setDiffText(await diffBackup({ id: asset.id, snapshotId: backup.id }))} className="text-sm text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-200">Show diff</button>
                <button onClick={async () => {
                  const assist = await restoreAssist({ id: asset.id, snapshotId: backup.id })
                  setRestoreText(`${assist.driver} restore guidance\n\n${assist.warnings.join('\n')}\n\n${assist.commands.join('\n')}`)
                }} className="text-sm text-emerald-600 hover:text-emerald-700">Restore assist</button>
              </div>
            </div>
          ))}
          {backups.length === 0 && (
            <p className="text-sm text-zinc-500">No config backups captured for this asset yet.</p>
          )}
          {diffText && (
            <div>
              <p className="text-xs text-zinc-500 mb-2">Snapshot diff</p>
              <pre className="max-h-64 overflow-auto rounded-lg bg-zinc-950 text-zinc-200 p-3 text-xs">{diffText}</pre>
            </div>
          )}
          {restoreText && (
            <div>
              <p className="text-xs text-zinc-500 mb-2">Restore assist</p>
              <pre className="max-h-64 overflow-auto rounded-lg bg-zinc-950 text-zinc-200 p-3 text-xs">{restoreText}</pre>
            </div>
          )}
        </div>
      </CardBody>
    </Card>
  )
}

function WirelessAssociationsCard({ asset }: Readonly<{ asset: Asset }>) {
  const { data: associations = [] } = useWirelessClients(asset.id)

  return (
    <Card>
      <CardHeader><CardTitle><Wifi className="w-4 h-4 inline mr-1.5" />Wireless Associations</CardTitle></CardHeader>
      <CardBody className="space-y-3">
        <p className="text-sm text-zinc-500">
          SNMP-capable access points can report connected clients here. TP-Link Deco app-managed mesh hardware typically does not expose these tables, so this section may stay empty in your environment.
        </p>
        {associations.length === 0 ? (
          <p className="text-sm text-zinc-500">No wireless client associations recorded for this asset.</p>
        ) : associations.map((association) => (
          <div key={association.id} className="rounded-xl border border-gray-200 dark:border-zinc-800 p-4">
            <div className="flex items-center justify-between gap-3">
              <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">
                {association.client_ip || association.client_mac || 'Unknown client'}
              </p>
              <span className="text-xs text-zinc-500">{new Date(association.last_seen).toLocaleString()}</span>
            </div>
            <p className="text-xs text-zinc-500 mt-1">
              {association.ssid || 'SSID unknown'} · {association.band || 'band unknown'} · signal {association.signal_dbm ?? 'n/a'} dBm
            </p>
          </div>
        ))}
      </CardBody>
    </Card>
  )
}

function AssetFindingsCard({ asset }: Readonly<{ asset: Asset }>) {
  const { data: findings = [] } = useAssetFindings(asset.id)

  return (
    <Card>
      <CardHeader><CardTitle><ShieldAlert className="w-4 h-4 inline mr-1.5" />Assessment Findings</CardTitle></CardHeader>
      <CardBody className="space-y-3">
        {findings.length === 0 ? (
          <p className="text-sm text-zinc-500">No findings linked to this asset.</p>
        ) : findings.map((finding) => (
          <div key={finding.id} className="rounded-xl border border-gray-200 dark:border-zinc-800 p-4">
            <div className="flex items-center justify-between gap-3">
              <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">{finding.title}</p>
              <span className="text-xs px-2 py-0.5 rounded-full bg-red-500/10 text-red-600 dark:text-red-400">{finding.severity}</span>
            </div>
            <p className="text-xs text-zinc-500 mt-1">
              {finding.source_tool} · {finding.status}
              {finding.port_number ? ` · ${finding.port_number}/${finding.protocol || 'tcp'}` : ''}
              {finding.cve ? ` · ${finding.cve}` : ''}
            </p>
            {finding.description && <p className="text-sm text-zinc-600 dark:text-zinc-300 mt-2">{finding.description}</p>}
          </div>
        ))}
      </CardBody>
    </Card>
  )
}

function FingerprintEvidenceCard({ asset }: Readonly<{ asset: Asset }>) {
  const evidence = [...(asset.evidence ?? [])].sort((a, b) => {
    if (b.confidence !== a.confidence) return b.confidence - a.confidence
    return a.category.localeCompare(b.category)
  })
  const topEvidence = evidence.slice(0, 10)
  const confidence = topEvidence.length > 0
    ? topEvidence.reduce((sum, item) => sum + item.confidence, 0) / topEvidence.length
    : 0

  return (
    <Card>
      <CardHeader>
        <CardTitle><Info className="w-4 h-4 inline mr-1.5" />Fingerprint Evidence</CardTitle>
      </CardHeader>
      <CardBody className="space-y-4">
        <div>
          <p className="text-xs text-zinc-500 mb-1">Evidence confidence</p>
          <div className="flex items-center gap-2">
            <div className="flex-1 h-1.5 rounded-full bg-zinc-200 dark:bg-zinc-800">
              <div className="h-1.5 rounded-full bg-emerald-500" style={{ width: `${Math.min(confidence, 1) * 100}%` }} />
            </div>
            <ConfidenceBadge confidence={confidence} />
          </div>
        </div>
        {topEvidence.length === 0 ? (
          <p className="text-sm text-zinc-500">No normalized fingerprint evidence has been recorded for this asset yet.</p>
        ) : (
          <div className="space-y-2">
            {topEvidence.map((item) => (
              <div key={item.id} className="rounded-xl border border-gray-200 dark:border-zinc-800 p-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100 break-words">{item.value}</p>
                    <p className="text-xs text-zinc-500 mt-1">
                      {item.category} · {item.key} · {item.source}
                    </p>
                  </div>
                  <ConfidenceBadge confidence={item.confidence} />
                </div>
              </div>
            ))}
          </div>
        )}
        {(asset.probe_runs?.length ?? 0) > 0 && (
          <div>
            <p className="text-xs text-zinc-500 mb-2">Latest probes</p>
            <div className="space-y-2">
              {asset.probe_runs.slice(0, 6).map((probe) => (
                <div key={probe.id} className="rounded-lg bg-zinc-50 dark:bg-zinc-900/70 px-3 py-2">
                  <div className="flex items-center justify-between gap-3">
                    <p className="text-xs font-medium text-zinc-700 dark:text-zinc-200">
                      {probe.probe_type}{probe.target_port ? `:${probe.target_port}` : ''}
                    </p>
                    <span className="text-[11px] text-zinc-500">{probe.success ? 'ok' : 'failed'}</span>
                  </div>
                  {probe.summary && (
                    <p className="text-xs text-zinc-500 mt-1 break-words">{probe.summary}</p>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </CardBody>
    </Card>
  )
}

function PassiveTimelineCard({ asset }: Readonly<{ asset: Asset }>) {
  const observations = asset.observations ?? []

  return (
    <Card>
      <CardHeader>
        <CardTitle><Wifi className="w-4 h-4 inline mr-1.5" />Passive Timeline</CardTitle>
      </CardHeader>
      <CardBody className="space-y-3">
        {observations.length === 0 ? (
          <p className="text-sm text-zinc-500">No passive observations have been recorded for this asset yet.</p>
        ) : observations.slice(0, 10).map((item) => (
          <div key={item.id} className="rounded-xl border border-gray-200 dark:border-zinc-800 p-3">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">{item.summary}</p>
                <p className="text-xs text-zinc-500 mt-1">{item.source} · {item.event_type}</p>
              </div>
              <span className="text-xs text-zinc-500 whitespace-nowrap">{timeAgo(item.observed_at)}</span>
            </div>
          </div>
        ))}
      </CardBody>
    </Card>
  )
}

function FingerprintHypothesesCard({ asset }: Readonly<{ asset: Asset }>) {
  const hypotheses = asset.fingerprint_hypotheses ?? []

  return (
    <Card>
      <CardHeader>
        <CardTitle><Bot className="w-4 h-4 inline mr-1.5 text-sky-500" />Fingerprint Hypotheses</CardTitle>
      </CardHeader>
      <CardBody className="space-y-3">
        {hypotheses.length === 0 ? (
          <p className="text-sm text-zinc-500">No Ollama-generated fingerprint hypotheses are stored for this asset yet.</p>
        ) : hypotheses.slice(0, 3).map((item) => (
          <div key={item.id} className="rounded-xl border border-gray-200 dark:border-zinc-800 p-3">
            <div className="flex items-start justify-between gap-3">
              <div className="space-y-1">
                <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">
                  {item.device_type || 'unknown'}{item.vendor ? ` · ${item.vendor}` : ''}{item.model ? ` ${item.model}` : ''}
                </p>
                <p className="text-xs text-zinc-500">{item.model_used || item.source} · {timeAgo(item.created_at)}</p>
              </div>
              <ConfidenceBadge confidence={item.confidence} />
            </div>
            <p className="text-sm text-zinc-600 dark:text-zinc-300 mt-2 whitespace-pre-wrap">{item.summary}</p>
            {item.supporting_evidence.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1.5">
                {item.supporting_evidence.map((value) => (
                  <span key={value} className="px-2 py-0.5 rounded-full text-xs bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400">
                    {value}
                  </span>
                ))}
              </div>
            )}
          </div>
        ))}
      </CardBody>
    </Card>
  )
}

function LookupProvenanceCard({ asset }: Readonly<{ asset: Asset }>) {
  const results = asset.internet_lookup_results ?? []

  return (
    <Card>
      <CardHeader>
        <CardTitle><Info className="w-4 h-4 inline mr-1.5" />Lookup Provenance</CardTitle>
      </CardHeader>
      <CardBody className="space-y-3">
        {results.length === 0 ? (
          <p className="text-sm text-zinc-500">No external lookup results are cached for this asset.</p>
        ) : results.slice(0, 5).map((item) => (
          <a
            key={item.id}
            href={item.url}
            target="_blank"
            rel="noreferrer"
            className="block rounded-xl border border-gray-200 dark:border-zinc-800 p-3 hover:bg-zinc-50 dark:hover:bg-zinc-900/60"
          >
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">{item.title}</p>
                <p className="text-xs text-zinc-500 mt-1">{item.domain} · {timeAgo(item.looked_up_at)}</p>
              </div>
              <ConfidenceBadge confidence={item.confidence} />
            </div>
            {item.snippet && <p className="text-sm text-zinc-600 dark:text-zinc-300 mt-2">{item.snippet}</p>}
          </a>
        ))}
      </CardBody>
    </Card>
  )
}

function LifecycleCard({ asset }: Readonly<{ asset: Asset }>) {
  const records = asset.lifecycle_records ?? []

  return (
    <Card>
      <CardHeader>
        <CardTitle><Shield className="w-4 h-4 inline mr-1.5 text-yellow-500" />Lifecycle Status</CardTitle>
      </CardHeader>
      <CardBody className="space-y-3">
        {records.length === 0 ? (
          <p className="text-sm text-zinc-500">No lifecycle catalog matches are recorded for this asset.</p>
        ) : records.map((item) => (
          <div key={item.id} className="rounded-xl border border-gray-200 dark:border-zinc-800 p-3">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">
                  {item.product}{item.version ? ` ${item.version}` : ''}
                </p>
                <p className="text-xs text-zinc-500 mt-1">
                  {item.support_status}{item.eol_date ? ` · EOL ${item.eol_date}` : ''}{item.reference ? ` · ${item.reference}` : ''}
                </p>
              </div>
            </div>
          </div>
        ))}
      </CardBody>
    </Card>
  )
}

function AutopsyCard({ asset }: Readonly<{ asset: Asset }>) {
  const autopsy = asset.autopsy
  if (!autopsy) {
    return (
      <Card>
        <CardHeader>
          <CardTitle><Microscope className="w-4 h-4 inline mr-1.5 text-rose-500" />Discovery Autopsy</CardTitle>
        </CardHeader>
        <CardBody>
          <p className="text-sm text-zinc-500">
            No discovery autopsy has been captured for this asset yet. Run a fresh scan or targeted port scan to generate one.
          </p>
        </CardBody>
      </Card>
    )
  }

  const stages = autopsy.trace.pipeline ?? []
  const weakPoints = autopsy.trace.weak_points ?? []

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between gap-3">
          <CardTitle><Microscope className="w-4 h-4 inline mr-1.5 text-rose-500" />Discovery Autopsy</CardTitle>
          <span className="text-xs text-zinc-400">Updated {timeAgo(autopsy.updated_at)}</span>
        </div>
      </CardHeader>
      <CardBody className="space-y-4">
        {weakPoints.length > 0 && (
          <div className="rounded-xl border border-amber-200/70 bg-amber-50/60 p-3 dark:border-amber-900/60 dark:bg-amber-950/20">
            <p className="text-xs font-medium uppercase tracking-wider text-amber-700 dark:text-amber-300">Weak Points</p>
            <ul className="mt-2 space-y-1 text-sm text-amber-900 dark:text-amber-100">
              {weakPoints.map((item) => (
                <li key={item}>• {item}</li>
              ))}
            </ul>
          </div>
        )}
        <div className="space-y-3">
          {stages.map((stage) => (
            <div key={`${stage.stage}:${stage.status}:${stage.summary}`} className="rounded-xl border border-gray-200 dark:border-zinc-800 p-3">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-sm font-medium capitalize text-zinc-900 dark:text-zinc-100">
                    <Workflow className="w-4 h-4 inline mr-1.5 text-rose-500" />
                    {stage.stage.replaceAll('_', ' ')}
                  </p>
                  <p className="mt-1 text-xs text-zinc-500">{stage.summary}</p>
                </div>
                <span className="rounded-full border border-gray-200 px-2 py-0.5 text-[11px] uppercase tracking-wider text-zinc-500 dark:border-zinc-700">
                  {stage.status}
                </span>
              </div>
              <AutopsyOutputs stage={stage} />
            </div>
          ))}
        </div>
      </CardBody>
    </Card>
  )
}

function AutopsyOutputs({ stage }: Readonly<{ stage: AssetAutopsyStage }>) {
  const outputs = Object.entries(stage.outputs ?? {})
  if (outputs.length === 0) return null

  return (
    <div className="mt-3 grid grid-cols-1 lg:grid-cols-2 gap-3">
      {outputs.map(([key, value]) => (
        <div key={key} className="rounded-lg bg-gray-50 px-3 py-2 dark:bg-zinc-900/60">
          <p className="text-[11px] uppercase tracking-wider text-zinc-500">{key.replaceAll('_', ' ')}</p>
          <pre className="mt-1 whitespace-pre-wrap break-words text-xs text-zinc-700 dark:text-zinc-300">
            {typeof value === 'string' ? value : JSON.stringify(value, null, 2)}
          </pre>
        </div>
      ))}
    </div>
  )
}

export default function AssetDetailPage() {
  const params = useParams<{ id: string }>()
  const router = useRouter()
  const assetId = Array.isArray(params.id) ? params.id[0] : params.id
  const { data: asset, isLoading, isError } = useAsset(assetId)
  const { data: currentUser } = useCurrentUser()
  const { mutate: runPortScan, isPending: isPortScanPending } = useRunAssetPortScan()
  const { mutate: refreshAiAnalysis, isPending: isAiLookupPending } = useRefreshAssetAiAnalysis()
  const { mutate: triggerEnrichment, isPending: isEnrichmentPending } = useTriggerScan()
  const [showAutopsy, setShowAutopsy] = useState(false)
  const [showExport, setShowExport] = useState(false)
  const [enrichmentStatus, setEnrichmentStatus] = useState<string | null>(null)
  const [portScanStatus, setPortScanStatus] = useState<string | null>(null)
  const exportRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!showExport) return
    function handleOutsideClick(event: MouseEvent) {
      if (exportRef.current && !exportRef.current.contains(event.target as Node)) {
        setShowExport(false)
      }
    }
    function handleEscape(event: KeyboardEvent) {
      if (event.key === 'Escape') setShowExport(false)
    }
    document.addEventListener('mousedown', handleOutsideClick)
    document.addEventListener('keydown', handleEscape)
    return () => {
      document.removeEventListener('mousedown', handleOutsideClick)
      document.removeEventListener('keydown', handleEscape)
    }
  }, [showExport])

  if (isLoading) return (
    <AppShell>
      <div className="max-w-5xl mx-auto space-y-4">
        {Array.from({ length: 4 }, (_, index) => (
          <div key={`asset-detail-skeleton-${index}`} className="h-40 rounded-xl bg-zinc-200 dark:bg-zinc-900 animate-pulse" />
        ))}
      </div>
    </AppShell>
  )

  if (isError || !asset) return (
    <AppShell>
      <div className="max-w-5xl mx-auto text-center py-20">
        <p className="text-zinc-400">Asset not found.</p>
        <Link href="/assets" className="text-sky-500 text-sm mt-2 inline-block">← Back to inventory</Link>
      </div>
    </AppShell>
  )

  const ai = asset.ai_analysis ?? null
  const securityFindings = ai?.security_findings ?? []
  const openPorts = (asset.ports ?? []).filter((port) => port.state === 'open')

  return (
    <AppShell>
      <div className="max-w-7xl mx-auto space-y-5">
        {/* Back + header */}
        <div>
          <button
            type="button"
            onClick={() => router.back()}
            className="inline-flex items-center gap-1 text-sm text-zinc-500 hover:text-zinc-900 dark:hover:text-white mb-3"
          >
            <ChevronLeft className="w-4 h-4" /> Asset Inventory
          </button>
          <div className="flex items-start justify-between flex-wrap gap-3">
            <div>
              <h2 className="text-xl font-bold text-zinc-900 dark:text-white font-mono">
                {asset.ip_address}
              </h2>
              {asset.hostname && (
                <p className="text-zinc-500 mt-0.5">{asset.hostname}</p>
              )}
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              {currentUser?.role === 'admin' && (
                <>
                  <button
                    type="button"
                    onClick={() => {
                      setEnrichmentStatus(null)
                      triggerEnrichment(
                        { targets: asset.ip_address, scan_type: 'deep_enrichment' },
                        {
                          onSuccess: (response) => {
                            const jobId = response?.data?.job_id
                            const status = response?.data?.status ?? 'queued'
                            setEnrichmentStatus(
                              jobId
                                ? `Deep enrichment ${status} as job ${jobId.slice(0, 8)}. Check Scans for progress.`
                                : `Deep enrichment ${status}. Check Scans for progress.`,
                            )
                          },
                          onError: (error: Error) => {
                            const detail = getErrorDetail(error)
                            setEnrichmentStatus(
                              typeof detail === 'string'
                                ? `Unable to queue deep enrichment: ${detail}`
                                : 'Unable to queue deep enrichment right now.',
                            )
                          },
                        },
                      )
                    }}
                    disabled={isEnrichmentPending}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border border-gray-200 dark:border-zinc-700"
                  >
                    {isEnrichmentPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Microscope className="w-3.5 h-3.5" />}
                    {isEnrichmentPending ? 'Queueing enrichment…' : 'Run Deep Enrichment'}
                  </button>
                  {enrichmentStatus && (
                    <p className="text-xs text-zinc-500 dark:text-zinc-400 max-w-xs">
                      {enrichmentStatus}
                    </p>
                  )}
                </>
              )}
              <button
                type="button"
                onClick={() => setShowAutopsy((current) => !current)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border border-gray-200 dark:border-zinc-700"
              >
                <Microscope className="w-3.5 h-3.5" />
                Autopsy
                {showAutopsy ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              </button>
              <div className="relative" ref={exportRef}>
                <button
                  type="button"
                  onClick={() => setShowExport((o) => !o)}
                  aria-haspopup="true"
                  aria-expanded={showExport}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border border-gray-200 dark:border-zinc-700 hover:bg-gray-50 dark:hover:bg-zinc-800 transition-colors"
                >
                  <Download className="w-3.5 h-3.5" />
                  Export
                  <ChevronDown className={cn('w-3.5 h-3.5 transition-transform', showExport && 'rotate-180')} />
                </button>
                {showExport && (
                  <div className="absolute right-0 top-full z-10 mt-1 min-w-[9rem] rounded-lg border border-gray-200 bg-white py-1 shadow-md dark:border-zinc-700 dark:bg-zinc-900">
                    {([
                      { label: 'JSON', icon: FileJson2, action: () => exportAssetJson(asset) },
                      { label: 'CSV',  icon: Sheet,     action: () => exportAssetCsv(asset) },
                    ] as const).map(({ label, icon: Icon, action }) => (
                      <button
                        key={label}
                        type="button"
                        onClick={() => { action(); setShowExport(false) }}
                        className="flex w-full items-center gap-2 px-3 py-2 text-sm text-zinc-600 hover:bg-gray-50 dark:text-zinc-300 dark:hover:bg-zinc-800"
                      >
                        <Icon className="w-3.5 h-3.5 shrink-0" />
                        {label}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <DeviceClassBadge deviceClass={ai?.device_class ?? asset.device_type} />
              <StatusBadge status={asset.status} />
            </div>
          </div>
        </div>

        {showAutopsy && <AutopsyCard asset={asset} />}

        <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
          <div className="xl:col-span-4 space-y-5">

            {/* Overview */}
            <Card>
              <CardHeader><CardTitle><Info className="w-4 h-4 inline mr-1.5" />Overview</CardTitle></CardHeader>
              <CardBody>
                <dl className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-4 text-sm">
                  {[
                    { label: 'IP Address',  value: <span className="font-mono">{asset.ip_address}</span> },
                    { label: 'MAC Address', value: asset.mac_address || '—' },
                    { label: 'Vendor',      value: ai?.vendor ?? asset.vendor ?? '—' },
                    { label: 'OS',          value: ai?.os_guess ?? asset.os_name ?? '—' },
                    { label: 'Type Source', value: asset.device_type_source ?? 'unknown' },
                    { label: 'Device Role', value: ai?.device_role ?? '—' },
                    { label: 'First Seen',  value: formatDate(asset.first_seen) },
                    { label: 'Last Seen',   value: timeAgo(asset.last_seen) },
                    { label: 'Open Ports',  value: openPorts.length },
                  ].map(({ label, value }) => (
                    <div key={label}>
                      <dt className="text-xs text-zinc-500 mb-0.5">{label}</dt>
                      <dd className="text-zinc-900 dark:text-zinc-100">{value}</dd>
                    </div>
                  ))}
                </dl>
                {/* Tags */}
                {asset.tags && asset.tags.length > 0 && (
                  <div className="mt-4 flex flex-wrap gap-1.5">
                    {asset.tags.map((t) => (
                      <span key={t.tag} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs bg-sky-500/10 text-sky-600 dark:text-sky-400 border border-sky-500/20">
                        <Tag className="w-3 h-3" />{t.tag}
                      </span>
                    ))}
                  </div>
                )}
              </CardBody>
            </Card>

            <AssetNotesCard asset={asset} />

            {/* Open Ports */}
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between gap-3">
                  <CardTitle><Network className="w-4 h-4 inline mr-1.5" />Open Ports ({openPorts.length})</CardTitle>
                  {currentUser?.role === 'admin' && (
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => {
                          setPortScanStatus(null)
                          runPortScan(asset.id, {
                            onSuccess: (response) => {
                              const jobId = response?.data?.job_id
                              const status = response?.data?.status ?? 'queued'
                              setPortScanStatus(
                                jobId
                                  ? `Targeted port scan ${status} as job ${jobId.slice(0, 8)}.`
                                  : `Targeted port scan ${status}.`,
                              )
                            },
                            onError: (error: Error) => {
                              const detail = getErrorDetail(error)
                              setPortScanStatus(
                                typeof detail === 'string'
                                  ? `Unable to queue port scan: ${detail}`
                                  : 'Unable to queue port scan right now.',
                              )
                            },
                          })
                        }}
                        disabled={isPortScanPending}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border border-gray-200 dark:border-zinc-700"
                      >
                        <Play className="w-3.5 h-3.5" />
                        {isPortScanPending ? 'Queueing…' : 'Port Scan'}
                      </button>
                      {portScanStatus && (
                        <p className="text-xs text-zinc-500 dark:text-zinc-400 max-w-xs">
                          {portScanStatus}
                        </p>
                      )}
                    </div>
                  )}
                </div>
              </CardHeader>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-100 dark:border-zinc-800">
                      {['Port', 'Protocol', 'Service', 'Version / Product'].map(h => (
                        <th key={h} className="text-left px-5 py-2.5 text-xs text-zinc-500 uppercase tracking-wider font-medium">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100 dark:divide-zinc-800">
                    {openPorts.length === 0 ? (
                      <tr><td colSpan={4} className="px-5 py-6 text-center text-zinc-400 text-xs">No open ports found</td></tr>
                    ) : openPorts.map((p) => (
                      <tr key={`${p.port_number}-${p.protocol}`} className="hover:bg-gray-50 dark:hover:bg-zinc-800/50">
                        <td className="px-5 py-2.5 font-mono font-medium text-sky-600 dark:text-sky-400 tabular">{p.port_number}</td>
                        <td className="px-5 py-2.5 text-zinc-500">{p.protocol}</td>
                        <td className="px-5 py-2.5 text-zinc-700 dark:text-zinc-300">{p.service || '—'}</td>
                        <td className="px-5 py-2.5 text-zinc-500 text-xs max-w-xs truncate">{p.version || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
            <AssetFindingsCard asset={asset} />
          </div>

          <div className="xl:col-span-4 space-y-5">
            {ai && (
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between gap-3">
                    <CardTitle><Bot className="w-4 h-4 inline mr-1.5 text-sky-500" />AI Classification</CardTitle>
                    {currentUser?.role === 'admin' && (
                      <button
                        type="button"
                        onClick={() => refreshAiAnalysis(asset.id)}
                        disabled={isAiLookupPending}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border border-gray-200 dark:border-zinc-700"
                      >
                        <Bot className="w-3.5 h-3.5" />
                        {isAiLookupPending ? 'Looking up…' : 'Lookup'}
                      </button>
                    )}
                  </div>
                </CardHeader>
                <CardBody className="space-y-3">
                  <div>
                    <p className="text-xs text-zinc-500 mb-1">Device class</p>
                    <DeviceClassBadge deviceClass={ai.device_class} />
                  </div>
                  <div>
                    <p className="text-xs text-zinc-500 mb-1">Confidence</p>
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-1.5 rounded-full bg-zinc-200 dark:bg-zinc-800">
                        <div
                          className="h-1.5 rounded-full bg-sky-500 transition-all"
                          style={{ width: `${ai.confidence * 100}%` }}
                        />
                      </div>
                      <ConfidenceBadge confidence={ai.confidence} />
                    </div>
                  </div>
                  {ai.vendor && <div><p className="text-xs text-zinc-500">Vendor</p><p className="text-sm">{ai.vendor}</p></div>}
                  {ai.model  && <div><p className="text-xs text-zinc-500">Model</p><p className="text-sm">{ai.model}</p></div>}
                  {ai.device_role && <div><p className="text-xs text-zinc-500">Role</p><p className="text-sm">{ai.device_role}</p></div>}
                  {ai.suggested_tags?.length > 0 && (
                    <div>
                      <p className="text-xs text-zinc-500 mb-1.5">Suggested tags</p>
                      <div className="flex flex-wrap gap-1">
                        {ai.suggested_tags.map((t: string) => (
                          <span key={t} className="px-2 py-0.5 rounded-full text-xs bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400">{t}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </CardBody>
              </Card>
            )}

            {ai?.investigation_notes && (
              <Card>
                <CardHeader>
                  <CardTitle><Bot className="w-4 h-4 inline mr-1.5 text-sky-500" />AI Investigation Notes</CardTitle>
                  <span className="text-xs text-zinc-400">{ai.ai_backend} · {ai.agent_steps} steps · <ConfidenceBadge confidence={ai.confidence} /> confidence</span>
                </CardHeader>
                <CardBody>
                  <p className="text-sm text-zinc-700 dark:text-zinc-300 leading-relaxed whitespace-pre-wrap">
                    {ai.investigation_notes}
                  </p>
                  {ai.open_services_summary?.length > 0 && (
                    <div className="mt-4">
                      <p className="text-xs text-zinc-500 mb-2 font-medium">Services identified:</p>
                      <div className="flex flex-wrap gap-1.5">
                        {ai.open_services_summary.map((service: string) => (
                          <span key={service} className="px-2 py-0.5 rounded bg-zinc-100 dark:bg-zinc-800 text-xs font-mono text-zinc-700 dark:text-zinc-300">
                            {service}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </CardBody>
              </Card>
            )}

            <FingerprintEvidenceCard asset={asset} />

            {currentUser?.role === 'admin' ? (
              <div className="space-y-5">
                <PassiveTimelineCard asset={asset} />
                <WirelessAssociationsCard asset={asset} />
              </div>
            ) : (
              <div className="space-y-5">
                <PassiveTimelineCard asset={asset} />
                <Card>
                  <CardHeader><CardTitle>Tags & Metadata</CardTitle></CardHeader>
                  <CardBody>
                    <p className="text-sm text-zinc-500">
                      Viewer accounts can inspect asset details, but editing tags and metadata requires an admin account.
                    </p>
                  </CardBody>
                </Card>
              </div>
            )}
          </div>

          <div className="xl:col-span-4 space-y-5">
            <FingerprintHypothesesCard asset={asset} />
            <LookupProvenanceCard asset={asset} />
            {securityFindings.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle><Shield className="w-4 h-4 inline mr-1.5 text-yellow-500" />Security Findings</CardTitle>
                  <span className="text-xs text-zinc-400">{securityFindings.length}</span>
                </CardHeader>
                <CardBody className="space-y-3 p-0">
                  {securityFindings.map((finding) => (
                    <div key={`${finding.severity}:${finding.title}`} className="px-5 py-3 border-b last:border-0 border-gray-100 dark:border-zinc-800">
                      <div className="flex items-start gap-2">
                        <span className={`mt-0.5 inline-flex px-1.5 py-0.5 rounded text-xs font-medium border ${severityColor(finding.severity)}`}>
                          {finding.severity}
                        </span>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium text-zinc-900 dark:text-white">{finding.title}</p>
                          <p className="text-xs text-zinc-500 mt-0.5">{finding.detail}</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </CardBody>
              </Card>
            )}

            {!ai && (
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between gap-3">
                    <CardTitle><Bot className="w-4 h-4 inline mr-1.5 text-sky-500" />AI Analysis</CardTitle>
                    {currentUser?.role === 'admin' && (
                      <button
                        type="button"
                        onClick={() => refreshAiAnalysis(asset.id)}
                        disabled={isAiLookupPending}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border border-gray-200 dark:border-zinc-700"
                      >
                        <Bot className="w-3.5 h-3.5" />
                        {isAiLookupPending ? 'Looking up…' : 'Lookup'}
                      </button>
                    )}
                  </div>
                </CardHeader>
                <CardBody>
                  <p className="text-sm text-zinc-500">
                    No persisted AI analysis is attached to this asset record yet.
                  </p>
                </CardBody>
              </Card>
            )}

            <LifecycleCard asset={asset} />
            {currentUser?.role === 'admin' ? (
              <>
                <ConfigBackupCard asset={asset} />
                <AssetMetadataEditor key={asset.id} asset={asset} />
              </>
            ) : (
              <Card>
                <CardHeader><CardTitle>Tags & Metadata</CardTitle></CardHeader>
                <CardBody>
                  <p className="text-sm text-zinc-500">
                    Viewer accounts can inspect asset details, but editing tags and metadata requires an admin account.
                  </p>
                </CardBody>
              </Card>
            )}
          </div>
        </div>
      </div>
    </AppShell>
  )
}
