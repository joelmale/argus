'use client'

import { useState, type ComponentProps, type ReactNode } from 'react'
import axios from 'axios'
import { AppShell } from '@/components/layout/AppShell'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'
import { ScanLine, Bell, Wifi, Database, Construction, Shield, UserPlus, KeyRound, Trash2, History, FileText, PlugZap, ActivitySquare, HouseWifi, RefreshCw, LibraryBig } from 'lucide-react'
import { assetsApi } from '@/lib/api'
import { useAlertRules, useApiKeys, useAuditLogs, useBackupDrivers, useBackupPolicy, useCreateApiKey, useCreateUser, useCurrentUser, useDeleteApiKey, useFingerprintDatasets, useHomeAssistantEntities, useIntegrationEvents, usePlugins, useRefreshFingerprintDataset, useResetInventory, useScannerConfig, useSyncTplinkDecoModule, useTestTplinkDecoModule, useTplinkDecoModule, useUpdateAlertRule, useUpdateBackupPolicy, useUpdateScannerConfig, useUpdateTplinkDecoModule, useUpdateUser, useUsers } from '@/hooks/useAuth'
import type { FingerprintDataset, TplinkDecoConfig, TplinkDecoSyncRun } from '@/types'
import { SETTINGS_SECTIONS } from '@/lib/settings-nav'

type BackupPolicyFormProps = Readonly<{
  backupPolicy?: {
    enabled: boolean
    interval_minutes: number
    tag_filter: string
    retention_count: number
    last_run_at: string | null
  }
  isUpdatingBackupPolicy: boolean
  onSave: (payload: {
    enabled: boolean
    interval_minutes: number
    tag_filter: string
    retention_count: number
  }) => void
}>

type ScannerConfigCardProps = Readonly<{
  scannerConfig?: {
    enabled: boolean
    default_targets: string | null
    auto_detect_targets: boolean
    detected_targets: string | null
    effective_targets: string | null
    default_profile: string
    interval_minutes: number
    concurrent_hosts: number
    host_chunk_size: number
    top_ports_count: number
    deep_probe_timeout_seconds: number
    ai_after_scan_enabled: boolean
    fingerprint_ai_enabled: boolean
    fingerprint_ai_model: string
    fingerprint_ai_min_confidence: number
    fingerprint_ai_prompt_suffix: string | null
    internet_lookup_enabled: boolean
    internet_lookup_allowed_domains: string | null
    internet_lookup_budget: number
    internet_lookup_timeout_seconds: number
    last_scheduled_scan_at: string | null
    updated_at: string
  }
  isUpdatingScannerConfig: boolean
  onSave: (payload: {
    enabled: boolean
    default_targets: string | null
    auto_detect_targets: boolean
    default_profile: string
    interval_minutes: number
    concurrent_hosts: number
    host_chunk_size: number
    top_ports_count: number
    deep_probe_timeout_seconds: number
    ai_after_scan_enabled: boolean
    fingerprint_ai_enabled: boolean
    fingerprint_ai_model: string
    fingerprint_ai_min_confidence: number
    fingerprint_ai_prompt_suffix: string | null
    internet_lookup_enabled: boolean
    internet_lookup_allowed_domains: string | null
    internet_lookup_budget: number
    internet_lookup_timeout_seconds: number
  }) => void
}>

type TplinkModulePayload = Omit<TplinkDecoConfig, 'id' | 'effective_owner_username' | 'last_tested_at' | 'last_sync_at' | 'last_status' | 'last_error' | 'last_client_count' | 'created_at' | 'updated_at'>
type FormSubmitHandler = NonNullable<ComponentProps<'form'>['onSubmit']>
type TplinkDecoModuleCardProps = Readonly<{
  moduleConfig?: TplinkDecoConfig
  recentRuns: TplinkDecoSyncRun[]
  isSaving: boolean
  isTesting: boolean
  isSyncing: boolean
  onSave: (payload: TplinkModulePayload) => Promise<unknown>
  onTest: () => Promise<unknown>
  onSync: () => Promise<unknown>
}>
type FingerprintDatasetsCardProps = Readonly<{
  datasets: FingerprintDataset[]
  onRefresh: (key: string) => void
  refreshingKey: string | null
}>
type SettingsSectionProps = Readonly<{
  id: string
  title: string
  description?: string
  children: ReactNode
}>

function describeTplinkActionError(error: unknown) {
  if (!axios.isAxiosError(error)) {
    return 'The Deco action failed before Argus returned a usable response.'
  }
  if (!error.response) {
    return 'Argus could not reach the backend while running the Deco action.'
  }
  let detail: unknown
  if (error.response.data && typeof error.response.data === 'object') {
    detail = (error.response.data as { detail?: unknown }).detail
  }
  if (typeof detail === 'string' && detail.trim()) {
    return detail
  }
  return `The Deco action failed with HTTP ${error.response.status}.`
}

function buildTplinkTestMessage(
  result: { client_count?: number; device_count?: number; status?: string; auth_username?: string } | undefined,
  saved: { last_client_count?: number } | undefined,
) {
  const clientCount = result?.client_count ?? saved?.last_client_count
  const deviceSummary = typeof result?.device_count === 'number' ? `, ${result.device_count} Deco nodes detected` : ''
  let clientSummary = ''
  if (typeof clientCount === 'number') {
    const connector = typeof result?.device_count === 'number' ? ' and' : ','
    clientSummary = `${connector} ${clientCount} clients detected`
  }
  const authSummary = result?.auth_username ? ` using hidden username ${result.auth_username}` : ''
  return `Connection test ${result?.status ?? 'completed'}${deviceSummary}${clientSummary}${authSummary}.`
}

function buildTplinkSyncMessage(result: { ingested_assets?: number; client_count?: number; device_count?: number } | undefined) {
  const assetSummary = typeof result?.ingested_assets === 'number' ? `, ${result.ingested_assets} assets updated` : ''
  const nodeSummary = typeof result?.device_count === 'number' ? ` from ${result.device_count} Deco nodes` : ''
  let clientSummary = ''
  if (typeof result?.client_count === 'number') {
    const clientPrefix = typeof result?.device_count === 'number' ? ' and' : ' from'
    clientSummary = `${clientPrefix} ${result.client_count} Deco clients`
  }
  return `Sync completed${assetSummary}${nodeSummary}${clientSummary}.`
}

function getEnvVarLineClass(line: string) {
  if (line.startsWith('#')) {
    return 'text-zinc-500'
  }
  if (line === '') {
    return ''
  }
  return 'text-emerald-400'
}

function BackupPolicyCard({ backupPolicy, isUpdatingBackupPolicy, onSave }: BackupPolicyFormProps) {
  const [backupEnabled, setBackupEnabled] = useState(backupPolicy?.enabled ?? false)
  const [backupInterval, setBackupInterval] = useState(backupPolicy?.interval_minutes ?? 720)
  const [backupTag, setBackupTag] = useState(backupPolicy?.tag_filter ?? 'infrastructure')
  const [backupRetention, setBackupRetention] = useState(backupPolicy?.retention_count ?? 5)

  return (
    <Card>
      <CardHeader>
        <CardTitle><Database className="w-4 h-4 inline mr-1.5" />Scheduled Backups</CardTitle>
      </CardHeader>
      <CardBody className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <label className="inline-flex items-center gap-2 text-sm text-zinc-600 dark:text-zinc-300">
            <input type="checkbox" checked={backupEnabled} onChange={(event) => setBackupEnabled(event.target.checked)} />
            <span>Enable scheduled backups</span>
          </label>
          <input value={backupTag} onChange={(event) => setBackupTag(event.target.value)} placeholder="Tag filter" className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700" />
          <input value={backupInterval} type="number" onChange={(event) => setBackupInterval(Number(event.target.value) || 720)} placeholder="Interval minutes" className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700" />
          <input value={backupRetention} type="number" onChange={(event) => setBackupRetention(Number(event.target.value) || 5)} placeholder="Retention count" className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700" />
        </div>
        <p className="text-xs text-zinc-500">
          Last scheduled run: {backupPolicy?.last_run_at ? new Date(backupPolicy.last_run_at).toLocaleString() : 'never'}
        </p>
        <button
          type="button"
          disabled={isUpdatingBackupPolicy}
          onClick={() => onSave({
            enabled: backupEnabled,
            interval_minutes: backupInterval,
            tag_filter: backupTag,
            retention_count: backupRetention,
          })}
          className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm bg-sky-500 text-white"
        >
          Save backup policy
        </button>
      </CardBody>
    </Card>
  )
}

function ScannerConfigCard({ scannerConfig, isUpdatingScannerConfig, onSave }: ScannerConfigCardProps) {
  const [scannerEnabled, setScannerEnabled] = useState(scannerConfig?.enabled ?? true)
  const [autoDetectTargets, setAutoDetectTargets] = useState(scannerConfig?.auto_detect_targets ?? true)
  const [defaultTargets, setDefaultTargets] = useState(scannerConfig?.default_targets ?? '')
  const [defaultProfile, setDefaultProfile] = useState(scannerConfig?.default_profile ?? 'balanced')
  const [scanInterval, setScanInterval] = useState(scannerConfig?.interval_minutes ?? 60)
  const [concurrentHosts, setConcurrentHosts] = useState(scannerConfig?.concurrent_hosts ?? 10)
  const [hostChunkSize, setHostChunkSize] = useState(scannerConfig?.host_chunk_size ?? 64)
  const [topPortsCount, setTopPortsCount] = useState(scannerConfig?.top_ports_count ?? 1000)
  const [deepProbeTimeoutSeconds, setDeepProbeTimeoutSeconds] = useState(scannerConfig?.deep_probe_timeout_seconds ?? 6)
  const [aiAfterScanEnabled, setAiAfterScanEnabled] = useState(scannerConfig?.ai_after_scan_enabled ?? true)
  const [fingerprintAiEnabled, setFingerprintAiEnabled] = useState(scannerConfig?.fingerprint_ai_enabled ?? false)
  const [fingerprintAiModel, setFingerprintAiModel] = useState(scannerConfig?.fingerprint_ai_model ?? 'qwen2.5:7b')
  const [fingerprintAiMinConfidence, setFingerprintAiMinConfidence] = useState(scannerConfig?.fingerprint_ai_min_confidence ?? 0.75)
  const [fingerprintAiPromptSuffix, setFingerprintAiPromptSuffix] = useState(scannerConfig?.fingerprint_ai_prompt_suffix ?? '')
  const [internetLookupEnabled, setInternetLookupEnabled] = useState(scannerConfig?.internet_lookup_enabled ?? false)
  const [internetLookupAllowedDomains, setInternetLookupAllowedDomains] = useState(scannerConfig?.internet_lookup_allowed_domains ?? 'docs.tp-link.com,ui.com,synology.com,qnap.com,netgate.com,proxmox.com')
  const [internetLookupBudget, setInternetLookupBudget] = useState(scannerConfig?.internet_lookup_budget ?? 3)
  const [internetLookupTimeoutSeconds, setInternetLookupTimeoutSeconds] = useState(scannerConfig?.internet_lookup_timeout_seconds ?? 5)

  return (
    <Card>
      <CardHeader>
        <CardTitle><ScanLine className="w-4 h-4 inline mr-1.5" />Scanner Configuration</CardTitle>
      </CardHeader>
      <CardBody className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <label className="inline-flex items-center gap-2 text-sm text-zinc-600 dark:text-zinc-300">
            <input type="checkbox" checked={scannerEnabled} onChange={(event) => setScannerEnabled(event.target.checked)} />
            <span>Enable scheduled scans</span>
          </label>
          <label className="inline-flex items-center gap-2 text-sm text-zinc-600 dark:text-zinc-300">
            <input type="checkbox" checked={autoDetectTargets} onChange={(event) => setAutoDetectTargets(event.target.checked)} />
            <span>Auto-detect local subnet when no explicit target is set</span>
          </label>
          <input
            value={defaultTargets}
            onChange={(event) => setDefaultTargets(event.target.value)}
            placeholder={autoDetectTargets ? 'Optional override, e.g. 192.168.96.0/20' : 'Required, e.g. 192.168.96.0/20'}
            className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
          />
          <select
            value={defaultProfile}
            onChange={(event) => setDefaultProfile(event.target.value)}
            className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
          >
            <option value="quick">Quick</option>
            <option value="balanced">Balanced</option>
            <option value="deep_enrichment">Deep Enrichment</option>
          </select>
          <input
            value={scanInterval}
            type="number"
            min={1}
            onChange={(event) => setScanInterval(Number(event.target.value) || 60)}
            placeholder="Scan interval minutes"
            className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
          />
          <input
            value={concurrentHosts}
            type="number"
            min={1}
            max={128}
            onChange={(event) => setConcurrentHosts(Number(event.target.value) || 10)}
            placeholder="Concurrent hosts"
            className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
          />
          <input
            value={hostChunkSize}
            type="number"
            min={1}
            max={256}
            onChange={(event) => setHostChunkSize(Number(event.target.value) || 64)}
            placeholder="Host chunk size"
            className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
          />
          <input
            value={topPortsCount}
            type="number"
            min={10}
            max={65535}
            onChange={(event) => setTopPortsCount(Number(event.target.value) || 1000)}
            placeholder="Top ports count"
            className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
          />
          <input
            value={deepProbeTimeoutSeconds}
            type="number"
            min={1}
            max={30}
            onChange={(event) => setDeepProbeTimeoutSeconds(Number(event.target.value) || 6)}
            placeholder="Deep probe timeout seconds"
            className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
          />
          <label className="inline-flex items-center gap-2 text-sm text-zinc-600 dark:text-zinc-300">
            <input type="checkbox" checked={aiAfterScanEnabled} onChange={(event) => setAiAfterScanEnabled(event.target.checked)} />
            <span>Enable AI after-scan investigation</span>
          </label>
          <label className="inline-flex items-center gap-2 text-sm text-zinc-600 dark:text-zinc-300">
            <input type="checkbox" checked={fingerprintAiEnabled} onChange={(event) => setFingerprintAiEnabled(event.target.checked)} />
            <span>Enable Ollama fingerprint synthesis</span>
          </label>
          <input
            value={fingerprintAiModel}
            onChange={(event) => setFingerprintAiModel(event.target.value)}
            placeholder="Ollama model"
            className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
          />
          <input
            value={fingerprintAiMinConfidence}
            type="number"
            min={0}
            max={1}
            step={0.05}
            onChange={(event) => setFingerprintAiMinConfidence(Number(event.target.value) || 0.75)}
            placeholder="Fingerprint AI minimum confidence"
            className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
          />
          <label className="inline-flex items-center gap-2 text-sm text-zinc-600 dark:text-zinc-300">
            <input type="checkbox" checked={internetLookupEnabled} onChange={(event) => setInternetLookupEnabled(event.target.checked)} />
            <span>Enable internet lookup for unresolved assets</span>
          </label>
          <input
            value={internetLookupBudget}
            type="number"
            min={1}
            max={10}
            onChange={(event) => setInternetLookupBudget(Number(event.target.value) || 3)}
            placeholder="Lookup budget"
            className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
          />
          <input
            value={internetLookupTimeoutSeconds}
            type="number"
            min={1}
            max={30}
            onChange={(event) => setInternetLookupTimeoutSeconds(Number(event.target.value) || 5)}
            placeholder="Lookup timeout seconds"
            className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
          />
        </div>
        <textarea
          value={fingerprintAiPromptSuffix}
          onChange={(event) => setFingerprintAiPromptSuffix(event.target.value)}
          rows={3}
          placeholder="Optional extra instructions for fingerprint synthesis"
          className="w-full px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
        />
        <input
          value={internetLookupAllowedDomains}
          onChange={(event) => setInternetLookupAllowedDomains(event.target.value)}
          placeholder="Allowed domains, comma separated"
          className="w-full px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
        />
        <div className="rounded-xl border border-gray-200 dark:border-zinc-800 p-4 space-y-1">
          <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">Effective target</p>
          <p className="text-xs text-zinc-500">
            {scannerConfig?.effective_targets ?? 'No target resolved yet. Save settings or enter an explicit range.'}
          </p>
          {scannerConfig?.detected_targets && (
            <p className="text-xs text-zinc-500">Auto-detected subnet: {scannerConfig.detected_targets}</p>
          )}
          <p className="text-xs text-zinc-500">
            Last scheduled run: {scannerConfig?.last_scheduled_scan_at ? new Date(scannerConfig.last_scheduled_scan_at).toLocaleString() : 'never'}
          </p>
        </div>
        <div className="rounded-xl border border-gray-200 dark:border-zinc-800 p-4 space-y-1 text-xs text-zinc-500">
          <p>Host concurrency controls how many devices Argus investigates at once.</p>
          <p>Chunk size controls how many discovered hosts go into each nmap batch before the next chunk starts.</p>
          <p>Top ports count applies to quick and balanced scans; deep enrichment still scans the full port range.</p>
          <p>Deep probe timeout is applied per protocol probe and is clamped between 1 and 30 seconds.</p>
          <p>AI after-scan investigation lets you disable the post-probe analyst pass without turning off fingerprint AI settings.</p>
        </div>
        <button
          type="button"
          disabled={isUpdatingScannerConfig}
          onClick={() => onSave({
            enabled: scannerEnabled,
            default_targets: defaultTargets.trim() || null,
            auto_detect_targets: autoDetectTargets,
            default_profile: defaultProfile,
            interval_minutes: scanInterval,
            concurrent_hosts: concurrentHosts,
            host_chunk_size: hostChunkSize,
            top_ports_count: topPortsCount,
            deep_probe_timeout_seconds: deepProbeTimeoutSeconds,
            ai_after_scan_enabled: aiAfterScanEnabled,
            fingerprint_ai_enabled: fingerprintAiEnabled,
            fingerprint_ai_model: fingerprintAiModel,
            fingerprint_ai_min_confidence: fingerprintAiMinConfidence,
            fingerprint_ai_prompt_suffix: fingerprintAiPromptSuffix.trim() || null,
            internet_lookup_enabled: internetLookupEnabled,
            internet_lookup_allowed_domains: internetLookupAllowedDomains.trim() || null,
            internet_lookup_budget: internetLookupBudget,
            internet_lookup_timeout_seconds: internetLookupTimeoutSeconds,
          })}
          className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm bg-sky-500 text-white disabled:bg-zinc-300 disabled:text-zinc-500 dark:disabled:bg-zinc-800"
        >
          Save scanner settings
        </button>
      </CardBody>
    </Card>
  )
}

function FingerprintDatasetsCard({
  datasets,
  onRefresh,
  refreshingKey,
}: FingerprintDatasetsCardProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle><LibraryBig className="w-4 h-4 inline mr-1.5" />Fingerprint Datasets</CardTitle>
      </CardHeader>
      <CardBody className="space-y-3">
        <p className="text-sm text-zinc-500">
          These datasets feed vendor and fingerprint enrichment. MAC vendor and SNMP enterprise lookups use the local cached copies directly.
        </p>
        <div className="space-y-3">
          {datasets.map((dataset) => (
            <div key={dataset.key} className="rounded-xl border border-gray-200 dark:border-zinc-800 p-3">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">{dataset.name}</p>
                  <p className="mt-1 text-xs text-zinc-500">{dataset.description}</p>
                  <div className="mt-2 flex flex-wrap gap-2 text-[11px] text-zinc-500">
                    <span className="rounded-full border border-gray-200 px-2 py-0.5 dark:border-zinc-700">{dataset.category}</span>
                    <span className="rounded-full border border-gray-200 px-2 py-0.5 dark:border-zinc-700">{dataset.status}</span>
                    <span>records: {dataset.record_count ?? '—'}</span>
                    <span>updated: {dataset.last_updated_at ? new Date(dataset.last_updated_at).toLocaleString() : 'never'}</span>
                  </div>
                  {dataset.upstream_last_modified && (
                    <p className="mt-1 text-[11px] text-zinc-500">Upstream last modified: {dataset.upstream_last_modified}</p>
                  )}
                  {dataset.error && (
                    <p className="mt-1 text-[11px] text-rose-500">{dataset.error}</p>
                  )}
                  <a href={dataset.upstream_url} target="_blank" rel="noreferrer" className="mt-2 inline-block text-xs text-sky-500 hover:text-sky-400">
                    Source
                  </a>
                </div>
                <button
                  type="button"
                  onClick={() => onRefresh(dataset.key)}
                  disabled={refreshingKey === dataset.key}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border border-gray-200 dark:border-zinc-700"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${refreshingKey === dataset.key ? 'animate-spin' : ''}`} />
                  {refreshingKey === dataset.key ? 'Refreshing…' : 'Pull update'}
                </button>
              </div>
            </div>
          ))}
        </div>
      </CardBody>
    </Card>
  )
}

function TplinkDecoModuleCard({
  moduleConfig,
  recentRuns,
  isSaving,
  isTesting,
  isSyncing,
  onSave,
  onTest,
  onSync,
}: TplinkDecoModuleCardProps) {
  const [enabled, setEnabled] = useState(moduleConfig?.enabled ?? false)
  const [baseUrl, setBaseUrl] = useState(moduleConfig?.base_url ?? 'http://tplinkdeco.net')
  const [ownerPassword, setOwnerPassword] = useState(moduleConfig?.owner_password ?? '')
  const [fetchConnectedClients, setFetchConnectedClients] = useState(moduleConfig?.fetch_connected_clients ?? true)
  const [fetchPortalLogs, setFetchPortalLogs] = useState(moduleConfig?.fetch_portal_logs ?? true)
  const [requestTimeoutSeconds, setRequestTimeoutSeconds] = useState(moduleConfig?.request_timeout_seconds ?? 10)
  const [verifyTls, setVerifyTls] = useState(moduleConfig?.verify_tls ?? false)
  const [actionMessage, setActionMessage] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)

  function buildPayload() {
    return {
      enabled,
      base_url: baseUrl.trim() || 'http://tplinkdeco.net',
      owner_username: null,
      owner_password: ownerPassword.trim() || null,
      fetch_connected_clients: fetchConnectedClients,
      fetch_portal_logs: fetchPortalLogs,
      request_timeout_seconds: requestTimeoutSeconds,
      verify_tls: verifyTls,
    }
  }

  async function handleSave() {
    setActionMessage(null)
    setActionError(null)
    await onSave(buildPayload())
    setActionMessage('Deco module settings saved.')
  }

  async function handleTest() {
    setActionMessage(null)
    setActionError(null)
    try {
      // Save the current form first so test runs against what the user can see,
      // not an older persisted password or portal URL.
      const saved = await onSave(buildPayload()) as { last_client_count?: number } | undefined
      const result = await onTest() as { client_count?: number; device_count?: number; status?: string; auth_username?: string } | undefined
      setActionMessage(buildTplinkTestMessage(result, saved))
    } catch (error) {
      setActionError(describeTplinkActionError(error))
    }
  }

  async function handleSync() {
    setActionMessage(null)
    setActionError(null)
    try {
      await onSave(buildPayload())
      const result = await onSync() as { ingested_assets?: number; client_count?: number; device_count?: number } | undefined
      setActionMessage(buildTplinkSyncMessage(result))
    } catch (error) {
      setActionError(describeTplinkActionError(error))
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle><Wifi className="w-4 h-4 inline mr-1.5" />TP-Link Deco Module</CardTitle>
      </CardHeader>
      <CardBody className="space-y-4">
        <p className="text-sm text-zinc-500">
          Pull connected-client data and portal details directly from the local Deco portal using the owner password shown on the password-only local login screen. Deco still signs requests with a hidden <span className="font-mono">admin</span> username even though the UI does not display it.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <label className="inline-flex items-center gap-2 text-sm text-zinc-600 dark:text-zinc-300">
            <input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />
            <span>Enable Deco module</span>
          </label>
          <label className="inline-flex items-center gap-2 text-sm text-zinc-600 dark:text-zinc-300">
            <input type="checkbox" checked={fetchConnectedClients} onChange={(event) => setFetchConnectedClients(event.target.checked)} />
            <span>Pull connected clients</span>
          </label>
          <label className="inline-flex items-center gap-2 text-sm text-zinc-600 dark:text-zinc-300">
            <input type="checkbox" checked={fetchPortalLogs} onChange={(event) => setFetchPortalLogs(event.target.checked)} />
            <span>Pull portal logs</span>
          </label>
          <label className="inline-flex items-center gap-2 text-sm text-zinc-600 dark:text-zinc-300">
            <input type="checkbox" checked={verifyTls} onChange={(event) => setVerifyTls(event.target.checked)} />
            <span>Verify TLS</span>
          </label>
          <input
            value={baseUrl}
            onChange={(event) => setBaseUrl(event.target.value)}
            placeholder="http://tplinkdeco.net"
            className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
          />
          <input
            type="password"
            value={ownerPassword}
            onChange={(event) => setOwnerPassword(event.target.value)}
            placeholder="Owner password from tplinkdeco.net"
            className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
          />
          <input
            type="number"
            min={3}
            max={60}
            value={requestTimeoutSeconds}
            onChange={(event) => setRequestTimeoutSeconds(Number(event.target.value) || 10)}
            placeholder="Timeout seconds"
            className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
          />
        </div>

        <div className="rounded-xl border border-gray-200 dark:border-zinc-800 p-4 space-y-1">
          <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">Module health</p>
          <p className="text-xs text-zinc-500">Status: {moduleConfig?.last_status ?? 'idle'}</p>
          <p className="text-xs text-zinc-500">Last tested: {moduleConfig?.last_tested_at ? new Date(moduleConfig.last_tested_at).toLocaleString() : 'never'}</p>
          <p className="text-xs text-zinc-500">Last sync: {moduleConfig?.last_sync_at ? new Date(moduleConfig.last_sync_at).toLocaleString() : 'never'}</p>
          <p className="text-xs text-zinc-500">Auth username: {moduleConfig?.effective_owner_username ?? 'admin'}</p>
          <p className="text-xs text-zinc-500">Last client count: {moduleConfig?.last_client_count ?? '—'}</p>
          {moduleConfig?.last_error && <p className="text-xs text-rose-500">{moduleConfig.last_error}</p>}
        </div>

        <div className="flex flex-wrap gap-3">
          <button
            type="button"
            disabled={isSaving || isTesting || isSyncing}
            onClick={handleSave}
            className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm bg-sky-500 text-white disabled:bg-zinc-300 disabled:text-zinc-500 dark:disabled:bg-zinc-800"
          >
            Save module settings
          </button>
          <button
            type="button"
            disabled={isSaving || isTesting || isSyncing}
            onClick={handleTest}
            className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm border border-gray-200 dark:border-zinc-700"
          >
            {isTesting ? 'Testing…' : 'Test connection'}
          </button>
          <button
            type="button"
            disabled={isSaving || isTesting || isSyncing || !enabled}
            onClick={handleSync}
            className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm border border-gray-200 dark:border-zinc-700 disabled:opacity-50"
          >
            {isSyncing ? 'Syncing…' : 'Sync now'}
          </button>
        </div>

        {actionMessage && (
          <div className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-300">
            {actionMessage}
          </div>
        )}
        {actionError && (
          <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-950 dark:bg-red-950/40 dark:text-red-300">
            {actionError}
          </div>
        )}

        <div className="space-y-3">
          <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">Recent sync runs</p>
          {recentRuns.length === 0 ? (
            <p className="text-sm text-zinc-500">No Deco sync runs recorded yet.</p>
          ) : recentRuns.map((run) => (
            <div key={run.id} className="rounded-xl border border-gray-200 dark:border-zinc-800 p-4 space-y-2">
              <div className="flex items-center justify-between gap-3">
                <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">Run #{run.id}</p>
                <span className="text-xs text-zinc-500">{run.status}</span>
              </div>
              <p className="text-xs text-zinc-500">
                Started {new Date(run.started_at).toLocaleString()}
                {run.finished_at ? ` · finished ${new Date(run.finished_at).toLocaleString()}` : ''}
                {run.client_count !== null ? ` · clients ${run.client_count}` : ''}
              </p>
              {run.error && <p className="text-xs text-rose-500">{run.error}</p>}
              {run.log_analysis && (
                <div className="rounded-lg border border-gray-200 dark:border-zinc-800 p-3 space-y-3 bg-gray-50/70 dark:bg-zinc-900/40">
                  <div className="flex flex-wrap items-center gap-3 text-xs text-zinc-500">
                    <span>Health score: <span className="font-medium text-zinc-900 dark:text-zinc-100">{run.log_analysis.health_score}</span></span>
                    <span>Events parsed: <span className="font-medium text-zinc-900 dark:text-zinc-100">{run.log_analysis.event_count}</span></span>
                    <span>Unique MACs: <span className="font-medium text-zinc-900 dark:text-zinc-100">{run.log_analysis.observed_macs.length}</span></span>
                  </div>

                  {run.log_analysis.issues.length > 0 && (
                    <div className="space-y-2">
                      <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">Detected issues</p>
                      {run.log_analysis.issues.slice(0, 6).map((issue) => (
                        <div key={issue.key} className="rounded-lg border border-gray-200 dark:border-zinc-800 p-3 space-y-1 bg-white dark:bg-zinc-950/40">
                          <div className="flex flex-wrap items-center gap-2">
                            <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">{issue.title}</p>
                            <span className="rounded-full px-2 py-0.5 text-[11px] uppercase tracking-wide bg-gray-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-300">{issue.severity}</span>
                            <span className="text-[11px] text-zinc-500">{issue.count} matches</span>
                          </div>
                          <p className="text-xs text-zinc-500">{issue.issue}</p>
                          <p className="text-xs text-zinc-700 dark:text-zinc-300">Recommendation: {issue.recommendation}</p>
                          {issue.affected_macs.length > 0 && (
                            <p className="text-[11px] text-zinc-500">Affected MACs: {issue.affected_macs.join(', ')}</p>
                          )}
                          {issue.sample_lines.length > 0 && (
                            <pre className="rounded bg-zinc-950 text-zinc-200 p-2 text-[10px] whitespace-pre-wrap overflow-x-auto max-h-24 overflow-y-auto">
                              {issue.sample_lines.join('\n')}
                            </pre>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  {run.log_analysis.recommendations.length > 0 && (
                    <div className="space-y-2">
                      <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">Recommendations</p>
                      {run.log_analysis.recommendations.map((item) => (
                        <div key={`${item.title}:${item.recommendation}`} className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs text-amber-800 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-200">
                          <p className="font-medium">{item.title}</p>
                          <p className="mt-1">{item.recommendation}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
              {run.logs_excerpt && (
                <div className="flex justify-end">
                  <button
                    type="button"
                    onClick={() => downloadTextFile(`tplink-deco-log-run-${run.id}.log`, run.logs_excerpt ?? '')}
                    className="inline-flex items-center justify-center gap-2 px-3 py-1.5 rounded-lg text-xs border border-gray-200 dark:border-zinc-700"
                  >
                    Download log copy
                  </button>
                </div>
              )}
              {run.logs_excerpt && (
                <pre className="rounded-lg bg-zinc-950 text-zinc-200 p-3 text-[11px] overflow-x-auto whitespace-pre-wrap max-h-40 overflow-y-auto">
                  {run.logs_excerpt}
                </pre>
              )}
            </div>
          ))}
        </div>
      </CardBody>
    </Card>
  )
}

function SettingsSection({
  id,
  title,
  description,
  children,
}: SettingsSectionProps) {
  return (
    <section id={id} className="space-y-4 scroll-mt-24">
      <div>
        <h3 className="text-lg font-semibold text-zinc-900 dark:text-zinc-100">{title}</h3>
        {description && <p className="mt-1 text-sm text-zinc-500">{description}</p>}
      </div>
      {children}
    </section>
  )
}

function downloadTextFile(filename: string, content: string) {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  URL.revokeObjectURL(url)
}


async function openHtmlReport() {
  const response = await assetsApi.exportHtmlReport()
  const blob = new Blob([response.data], { type: 'text/html;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  globalThis.window.open(url, '_blank', 'noopener,noreferrer')
}

export default function SettingsPage() {
  const { data: currentUser } = useCurrentUser()
  const { data: users = [] } = useUsers(currentUser?.role === 'admin')
  const { data: apiKeys = [] } = useApiKeys(currentUser?.role === 'admin')
  const { data: auditLogs = [] } = useAuditLogs(currentUser?.role === 'admin')
  const { data: alertRules = [] } = useAlertRules(currentUser?.role === 'admin')
  const { data: backupDrivers = [] } = useBackupDrivers(currentUser?.role === 'admin')
  const { data: backupPolicy } = useBackupPolicy(currentUser?.role === 'admin')
  const { data: scannerConfig } = useScannerConfig(currentUser?.role === 'admin')
  const { data: tplinkDecoModule } = useTplinkDecoModule(currentUser?.role === 'admin')
  const { data: fingerprintDatasets = [] } = useFingerprintDatasets(currentUser?.role === 'admin')
  const { data: plugins = [] } = usePlugins(currentUser?.role === 'admin')
  const { data: integrationEvents = [] } = useIntegrationEvents(currentUser?.role === 'admin')
  const { data: homeAssistantExport } = useHomeAssistantEntities(currentUser?.role === 'admin')
  const { mutate: createUser, isPending: isCreatingUser } = useCreateUser()
  const { mutate: updateUser, isPending: isUpdatingUser } = useUpdateUser()
  const { mutate: createApiKey, isPending: isCreatingApiKey } = useCreateApiKey()
  const { mutate: deleteApiKey, isPending: isDeletingApiKey } = useDeleteApiKey()
  const { mutate: updateAlertRule, isPending: isUpdatingAlertRule } = useUpdateAlertRule()
  const { mutate: updateBackupPolicy, isPending: isUpdatingBackupPolicy } = useUpdateBackupPolicy()
  const { mutate: updateScannerConfig, isPending: isUpdatingScannerConfig } = useUpdateScannerConfig()
  const { mutateAsync: updateTplinkDecoModule, isPending: isUpdatingTplinkDecoModule } = useUpdateTplinkDecoModule()
  const { mutateAsync: testTplinkDecoModule, isPending: isTestingTplinkDecoModule } = useTestTplinkDecoModule()
  const { mutateAsync: syncTplinkDecoModule, isPending: isSyncingTplinkDecoModule } = useSyncTplinkDecoModule()
  const { mutate: refreshFingerprintDataset, isPending: isRefreshingFingerprintDataset } = useRefreshFingerprintDataset()
  const [refreshingDatasetKey, setRefreshingDatasetKey] = useState<string | null>(null)
  const { mutate: resetInventory, isPending: isResettingInventory } = useResetInventory()
  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newRole, setNewRole] = useState<'admin' | 'viewer'>('viewer')
  const [userError, setUserError] = useState<string | null>(null)
  const [apiKeyName, setApiKeyName] = useState('')
  const [generatedApiKey, setGeneratedApiKey] = useState<string | null>(null)
  const [inventoryConfirm, setInventoryConfirm] = useState('')
  const [includeScanHistory, setIncludeScanHistory] = useState(false)

  const handleCreateUser: FormSubmitHandler = (event) => {
    event.preventDefault()
    setUserError(null)
    createUser(
      { username: newUsername.trim(), password: newPassword, role: newRole },
      {
        onSuccess: () => {
          setNewUsername('')
          setNewPassword('')
          setNewRole('viewer')
        },
        onError: () => setUserError('Unable to create user. Check for duplicate usernames or emails.'),
      },
    )
  }

  const handleCreateApiKey: FormSubmitHandler = (event) => {
    event.preventDefault()
    createApiKey(
      { name: apiKeyName.trim() || 'CLI key' },
      {
        onSuccess: (created) => {
          setGeneratedApiKey(created.token)
          setApiKeyName('')
        },
      },
    )
  }

  return (
    <AppShell>
      <div className="max-w-7xl mx-auto space-y-6">
        <div>
          <h2 className="text-xl font-bold text-zinc-900 dark:text-white">Settings</h2>
          <p className="text-sm text-zinc-500 mt-0.5">Grouped controls for discovery, automation, access, and retention.</p>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-[240px_minmax(0,1fr)] gap-6">
          <aside className="hidden xl:block">
            <div className="sticky top-6 rounded-2xl border border-gray-200 bg-white/80 p-4 dark:border-zinc-800 dark:bg-zinc-950/70">
              <p className="text-xs font-medium uppercase tracking-wider text-zinc-400">Settings</p>
              <div className="mt-4 space-y-4">
                {SETTINGS_SECTIONS.map((section) => (
                  <div key={section.heading} className="space-y-1.5">
                    <p className="text-[11px] font-medium uppercase tracking-wider text-zinc-400">{section.heading}</p>
                    {section.items.map((item) => (
                      <a
                        key={item.id}
                        href={`#${item.id}`}
                        className="flex items-center gap-2 rounded-lg px-2 py-1.5 text-sm text-zinc-600 hover:bg-gray-100 hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-zinc-900 dark:hover:text-zinc-100"
                      >
                        <item.icon className="w-4 h-4 flex-shrink-0" />
                        <span>{item.label}</span>
                      </a>
                    ))}
                  </div>
                ))}
              </div>
            </div>
          </aside>

          <div className="space-y-8">
            {currentUser?.role === 'viewer' && (
              <div className="flex items-start gap-3 p-4 rounded-xl bg-red-500/10 border border-red-500/20">
                <Construction className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm font-medium text-red-700 dark:text-red-400">Admin access required</p>
                  <p className="text-xs text-red-600/80 dark:text-red-400/70 mt-0.5">
                    Viewer accounts can inspect Argus data, but settings are limited to admins.
                  </p>
                </div>
              </div>
            )}

            {currentUser?.role === 'admin' && (
              <>
                <SettingsSection
                  id="scan-configuration"
                  title="Scan Configuration"
                  description="Default targets, profile, interval, concurrency, and dataset-backed fingerprinting inputs."
                >
                  <ScannerConfigCard
                    key={scannerConfig?.updated_at ?? 'scanner-config'}
                    scannerConfig={scannerConfig}
                    isUpdatingScannerConfig={isUpdatingScannerConfig}
                    onSave={(payload) => updateScannerConfig(payload)}
                  />
                </SettingsSection>

                <SettingsSection
                  id="ai-agent"
                  title="AI Agent"
                  description="Current AI controls for fingerprint synthesis and unresolved asset lookup behavior."
                >
                  <Card>
                    <CardBody className="space-y-3">
                      <p className="text-sm text-zinc-500">
                        AI settings currently live inside the scanner configuration card. The implemented controls are Ollama fingerprint synthesis, confidence threshold, prompt suffix, and internet lookup policy.
                      </p>
                      <p className="text-sm text-zinc-500">
                        Missing from a true AI control plane today: backend/provider selection, Anthropic/OpenAI credential management, and per-workflow model routing.
                      </p>
                    </CardBody>
                  </Card>
                </SettingsSection>

                <SettingsSection
                  id="network-snmp"
                  title="Network & SNMP"
                  description="Passive discovery, SNMP, and local controller integrations."
                >
                  <div className="space-y-4">
                    <Card>
                      <CardBody className="space-y-3">
                        <p className="text-sm text-zinc-500">
                          Scanner-level SNMP and passive listener controls now live in the scanner configuration model, but the dedicated form surface still needs to be split out cleanly from general scan settings.
                        </p>
                        <p className="text-sm text-zinc-500">
                          The Deco module below is a separate local-portal integration that can enrich transient client inventory beyond what SNMP exposes on consumer AP hardware.
                        </p>
                      </CardBody>
                    </Card>
                    <TplinkDecoModuleCard
                      key={tplinkDecoModule?.config.updated_at ?? 'tplink-deco-module'}
                      moduleConfig={tplinkDecoModule?.config}
                      recentRuns={tplinkDecoModule?.recent_runs ?? []}
                      isSaving={isUpdatingTplinkDecoModule}
                      isTesting={isTestingTplinkDecoModule}
                      isSyncing={isSyncingTplinkDecoModule}
                      onSave={(payload) => updateTplinkDecoModule(payload)}
                      onTest={() => testTplinkDecoModule()}
                      onSync={() => syncTplinkDecoModule()}
                    />
                  </div>
                </SettingsSection>

                <SettingsSection
                  id="fingerprint-datasets"
                  title="Fingerprint Datasets"
                  description="Local dataset cache and update status for MAC, SNMP, banner, and OS fingerprint sources."
                >
                  <FingerprintDatasetsCard
                    datasets={fingerprintDatasets}
                    onRefresh={(key) => {
                      setRefreshingDatasetKey(key)
                      refreshFingerprintDataset(key, {
                        onSettled: () => setRefreshingDatasetKey(null),
                      })
                    }}
                    refreshingKey={isRefreshingFingerprintDataset ? refreshingDatasetKey : null}
                  />
                </SettingsSection>

                <SettingsSection
                  id="notifications"
                  title="Notifications"
                  description="Current alert rule toggles exist, but delivery destinations still need first-class settings."
                >
                  <Card>
                    <CardHeader>
                      <CardTitle><Bell className="w-4 h-4 inline mr-1.5" />Alert Rules</CardTitle>
                    </CardHeader>
                    <CardBody className="space-y-3">
                      {alertRules.map((rule) => (
                        <div key={rule.id} className="rounded-xl border border-gray-200 dark:border-zinc-800 p-4 space-y-3">
                          <div>
                            <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">{rule.event_type}</p>
                            <p className="text-xs text-zinc-500">{rule.description}</p>
                          </div>
                          <div className="flex flex-wrap gap-4 text-sm text-zinc-600 dark:text-zinc-300">
                            <label className="inline-flex items-center gap-2">
                              <input
                                type="checkbox"
                                checked={rule.enabled}
                                disabled={isUpdatingAlertRule}
                                onChange={(event) => updateAlertRule({ id: rule.id, payload: { enabled: event.target.checked } })}
                              />
                              <span>Enabled</span>
                            </label>
                            <label className="inline-flex items-center gap-2">
                              <input
                                type="checkbox"
                                checked={rule.notify_email}
                                disabled={isUpdatingAlertRule}
                                onChange={(event) => updateAlertRule({ id: rule.id, payload: { notify_email: event.target.checked } })}
                              />
                              <span>Email</span>
                            </label>
                            <label className="inline-flex items-center gap-2">
                              <input
                                type="checkbox"
                                checked={rule.notify_webhook}
                                disabled={isUpdatingAlertRule}
                                onChange={(event) => updateAlertRule({ id: rule.id, payload: { notify_webhook: event.target.checked } })}
                              />
                              <span>Webhook</span>
                            </label>
                          </div>
                        </div>
                      ))}
                    </CardBody>
                  </Card>
                </SettingsSection>

                <SettingsSection
                  id="integrations"
                  title="Integrations"
                  description="Exports and webhook event catalog for downstream tools."
                >
                  <Card>
                    <CardHeader>
                      <CardTitle><PlugZap className="w-4 h-4 inline mr-1.5" />Integrations</CardTitle>
                    </CardHeader>
                    <CardBody className="space-y-4">
                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                        <div className="rounded-xl border border-gray-200 dark:border-zinc-800 p-4 space-y-2">
                          <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100"><HouseWifi className="w-4 h-4 inline mr-1.5" />Home Assistant export</p>
                          <p className="text-xs text-zinc-500">
                            {homeAssistantExport ? `${homeAssistantExport.entities.length} entities available` : 'Loading entity export…'}
                          </p>
                          <a
                            href="http://localhost:8000/api/v1/system/integrations/home-assistant/entities"
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-2 text-xs text-sky-500 hover:text-sky-600"
                          >
                            Open entity export
                          </a>
                        </div>
                        <div className="rounded-xl border border-gray-200 dark:border-zinc-800 p-4 space-y-2">
                          <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100"><ActivitySquare className="w-4 h-4 inline mr-1.5" />Inventory sync export</p>
                          <p className="text-xs text-zinc-500">
                            Read-only normalized JSON snapshot for external systems.
                          </p>
                          <a
                            href="http://localhost:8000/api/v1/system/integrations/inventory-sync"
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-2 text-xs text-sky-500 hover:text-sky-600"
                          >
                            Open sync snapshot
                          </a>
                        </div>
                      </div>

                      <div className="space-y-3">
                        <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">Webhook event catalog</p>
                        {integrationEvents.map((item) => (
                          <div key={item.event} className="rounded-xl border border-gray-200 dark:border-zinc-800 p-4">
                            <div className="flex items-center justify-between gap-3">
                              <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">{item.event}</p>
                              <span className="text-xs text-zinc-500">{item.source}</span>
                            </div>
                            <p className="text-xs text-zinc-500 mt-1">{item.description}</p>
                            <pre className="mt-3 rounded-lg bg-zinc-950 text-zinc-200 p-3 text-[11px] overflow-x-auto">{JSON.stringify(item.example, null, 2)}</pre>
                          </div>
                        ))}
                      </div>
                    </CardBody>
                  </Card>
                </SettingsSection>

                <SettingsSection
                  id="reports-metrics"
                  title="Reports & Metrics"
                  description="Operational exports and observability entry points."
                >
                  <Card>
                    <CardHeader>
                      <CardTitle><FileText className="w-4 h-4 inline mr-1.5" />Reports & Metrics</CardTitle>
                    </CardHeader>
                    <CardBody className="flex flex-col md:flex-row gap-3">
                      <button
                        type="button"
                        onClick={openHtmlReport}
                        className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm bg-sky-500 text-white"
                      >
                        <FileText className="w-4 h-4" /> Open HTML inventory report
                      </button>
                      <a
                        href="http://localhost:8000/metrics"
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm border border-gray-200 dark:border-zinc-800"
                      >
                        <Database className="w-4 h-4" /> View metrics endpoint
                      </a>
                    </CardBody>
                  </Card>
                </SettingsSection>

                <SettingsSection
                  id="data-retention"
                  title="Data Retention"
                  description="Only backup retention is configurable today. Broader cleanup policies still need implementation."
                >
                  <BackupPolicyCard
                    key={backupPolicy?.updated_at ?? 'backup-policy'}
                    backupPolicy={backupPolicy}
                    isUpdatingBackupPolicy={isUpdatingBackupPolicy}
                    onSave={(payload) => updateBackupPolicy(payload)}
                  />
                </SettingsSection>

                <SettingsSection
                  id="user-management"
                  title="User Management"
                  description="Manage admin and viewer accounts."
                >
                  <Card>
              <CardHeader>
                <CardTitle><Shield className="w-4 h-4 inline mr-1.5" />User Management</CardTitle>
              </CardHeader>
              <CardBody className="space-y-5">
                <form onSubmit={handleCreateUser} className="grid grid-cols-1 md:grid-cols-[1fr_1fr_140px_auto] gap-3">
                  <input
                    value={newUsername}
                    onChange={(event) => setNewUsername(event.target.value)}
                    placeholder="Username"
                    className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
                  />
                  <input
                    type="password"
                    value={newPassword}
                    onChange={(event) => setNewPassword(event.target.value)}
                    placeholder="Temporary password"
                    className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
                  />
                  <select
                    value={newRole}
                    onChange={(event) => setNewRole(event.target.value as 'admin' | 'viewer')}
                    className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
                  >
                    <option value="viewer">Viewer</option>
                    <option value="admin">Admin</option>
                  </select>
                  <button
                    type="submit"
                    disabled={isCreatingUser || !newUsername.trim() || !newPassword}
                    className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm bg-sky-500 text-white disabled:bg-zinc-300 disabled:text-zinc-500 dark:disabled:bg-zinc-800"
                  >
                    <UserPlus className="w-4 h-4" /> Create
                  </button>
                </form>
                {userError && <p className="text-xs text-red-500">{userError}</p>}

                <div className="space-y-3">
                  {users.map((user) => (
                    <div key={user.id} className="flex flex-col md:flex-row md:items-center gap-3 rounded-xl border border-gray-200 dark:border-zinc-800 p-4">
                      <div className="flex-1">
                        <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">{user.username}</p>
                        <p className="text-xs text-zinc-500">
                          {user.email || 'No email'} · created {new Date(user.created_at).toLocaleDateString()}
                        </p>
                      </div>
                      <select
                        value={user.role}
                        disabled={isUpdatingUser}
                        onChange={(event) => updateUser({ id: user.id, payload: { role: event.target.value as 'admin' | 'viewer' } })}
                        className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
                      >
                        <option value="viewer">Viewer</option>
                        <option value="admin">Admin</option>
                      </select>
                      <label className="inline-flex items-center gap-2 text-sm text-zinc-600 dark:text-zinc-300">
                        <input
                          type="checkbox"
                          checked={user.is_active}
                          disabled={isUpdatingUser}
                          onChange={(event) => updateUser({ id: user.id, payload: { is_active: event.target.checked } })}
                        />
                        <span>Active</span>
                      </label>
                    </div>
                  ))}
                </div>
              </CardBody>
                  </Card>
                </SettingsSection>

                <SettingsSection
                  id="api-keys"
                  title="API Keys"
                  description="Create and revoke tokens for automation and CLI access."
                >
                  <Card>
              <CardHeader>
                <CardTitle><KeyRound className="w-4 h-4 inline mr-1.5" />API Keys</CardTitle>
              </CardHeader>
              <CardBody className="space-y-4">
                <form onSubmit={handleCreateApiKey} className="flex flex-col md:flex-row gap-3">
                  <input
                    value={apiKeyName}
                    onChange={(event) => setApiKeyName(event.target.value)}
                    placeholder="CLI key"
                    className="flex-1 px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
                  />
                  <button
                    type="submit"
                    disabled={isCreatingApiKey}
                    className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-900 disabled:bg-zinc-300 dark:disabled:bg-zinc-800"
                  >
                    <KeyRound className="w-4 h-4" /> Create key
                  </button>
                </form>

                {generatedApiKey && (
                  <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-4 dark:border-emerald-900 dark:bg-emerald-950/30">
                    <p className="text-sm font-medium text-emerald-700 dark:text-emerald-300">Copy this API key now</p>
                    <p className="text-xs text-emerald-600 dark:text-emerald-400 mt-1 mb-2">
                      This is the only time the full token will be shown.
                    </p>
                    <code className="block rounded-lg bg-white/80 dark:bg-zinc-950 px-3 py-2 text-xs break-all">{generatedApiKey}</code>
                  </div>
                )}

                <div className="space-y-3">
                  {apiKeys.map((apiKey) => (
                    <div key={apiKey.id} className="flex flex-col md:flex-row md:items-center gap-3 rounded-xl border border-gray-200 dark:border-zinc-800 p-4">
                      <div className="flex-1">
                        <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">{apiKey.name}</p>
                        <p className="text-xs text-zinc-500">
                          {apiKey.key_prefix} · last used {apiKey.last_used_at ? new Date(apiKey.last_used_at).toLocaleString() : 'never'}
                        </p>
                      </div>
                      <button
                        type="button"
                        disabled={isDeletingApiKey}
                        onClick={() => deleteApiKey(apiKey.id)}
                        className="inline-flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-sm text-red-600 hover:bg-red-50 dark:hover:bg-red-950/30"
                      >
                        <Trash2 className="w-4 h-4" /> Revoke
                      </button>
                    </div>
                  ))}
                </div>
              </CardBody>
                  </Card>
                </SettingsSection>

                <SettingsSection
                  id="audit-activity"
                  title="Audit Activity"
                  description="Recent administrative changes and system actions."
                >
                  <Card>
              <CardHeader>
                <CardTitle><History className="w-4 h-4 inline mr-1.5" />Recent Audit Activity</CardTitle>
              </CardHeader>
              <CardBody className="space-y-3">
                {auditLogs.map((entry) => (
                  <div key={entry.id} className="rounded-xl border border-gray-200 dark:border-zinc-800 p-4">
                    <div className="flex items-center justify-between gap-3">
                      <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">{entry.action}</p>
                      <p className="text-xs text-zinc-500">{new Date(entry.created_at).toLocaleString()}</p>
                    </div>
                    <p className="text-xs text-zinc-500 mt-1">
                      {entry.user?.username || 'system'} {entry.target_type ? `· ${entry.target_type}` : ''}
                      {entry.target_id ? ` · ${entry.target_id}` : ''}
                    </p>
                  </div>
                ))}
                {auditLogs.length === 0 && (
                  <p className="text-sm text-zinc-500">No audit events recorded yet.</p>
                )}
              </CardBody>
                  </Card>
                </SettingsSection>

                <SettingsSection
                  id="plugins-drivers"
                  title="Plugins & Drivers"
                  description="Inventory of loaded plugins and available config-backup drivers."
                >
                  <Card>
              <CardHeader>
                <CardTitle><Wifi className="w-4 h-4 inline mr-1.5" />Backup Drivers & Plugins</CardTitle>
              </CardHeader>
              <CardBody className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="space-y-3">
                  <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">Supported config backup drivers</p>
                  {backupDrivers.map((driver) => (
                    <div key={driver.name} className="rounded-xl border border-gray-200 dark:border-zinc-800 p-4">
                      <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">{driver.label}</p>
                      <p className="text-xs text-zinc-500 mt-1 font-mono">{driver.name}</p>
                      <p className="text-xs text-zinc-500 mt-2">{driver.description}</p>
                    </div>
                  ))}
                  {backupDrivers.length === 0 && (
                    <p className="text-sm text-zinc-500">No backup drivers available.</p>
                  )}
                </div>
                <div className="space-y-3">
                  <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">Loaded plugins</p>
                  {plugins.length === 0 ? (
                    <p className="text-sm text-zinc-500">No external plugins loaded yet. Phase 4 plugin hooks are ready for custom discovery modules.</p>
                  ) : plugins.map((plugin) => (
                    <div key={plugin.name} className="rounded-xl border border-gray-200 dark:border-zinc-800 p-4">
                      <div className="flex items-center justify-between gap-3 flex-wrap">
                        <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">{plugin.name}</p>
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-zinc-500">{plugin.version}</span>
                          <span className="text-[11px] px-2 py-0.5 rounded-full bg-zinc-100 dark:bg-zinc-800 text-zinc-500">{plugin.health}</span>
                        </div>
                      </div>
                      {plugin.description && <p className="text-xs text-zinc-500 mt-2">{plugin.description}</p>}
                      <p className="text-xs text-zinc-500 mt-2">
                        Capabilities: {plugin.capabilities.length > 0 ? plugin.capabilities.join(', ') : 'none declared'}
                      </p>
                    </div>
                  ))}
                </div>
              </CardBody>
                  </Card>
                </SettingsSection>

                <SettingsSection
                  id="danger-zone"
                  title="Danger Zone"
                  description="High-impact destructive actions."
                >
                  <Card>
                    <CardHeader>
                      <CardTitle><Trash2 className="w-4 h-4 inline mr-1.5 text-red-500" />Danger Zone</CardTitle>
                    </CardHeader>
                    <CardBody className="space-y-4">
                      <p className="text-sm text-zinc-500">
                        Clear the discovered asset inventory if a bad scan polluted the database. This removes assets, ports, history, topology, findings, and config backup records.
                      </p>
                      <label className="inline-flex items-center gap-2 text-sm text-zinc-600 dark:text-zinc-300">
                        <input type="checkbox" checked={includeScanHistory} onChange={(event) => setIncludeScanHistory(event.target.checked)} />
                        <span>Also delete scan job history</span>
                      </label>
                      <input
                        value={inventoryConfirm}
                        onChange={(event) => setInventoryConfirm(event.target.value)}
                        placeholder="Type: reset inventory"
                        className="w-full px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-red-200 dark:border-red-900"
                      />
                      <button
                        type="button"
                        disabled={isResettingInventory || inventoryConfirm.trim().toLowerCase() !== 'reset inventory'}
                        onClick={() => resetInventory(
                          { confirm: inventoryConfirm, include_scan_history: includeScanHistory },
                          { onSuccess: () => { setInventoryConfirm(''); setIncludeScanHistory(false) } },
                        )}
                        className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm bg-red-500 text-white disabled:bg-zinc-300 disabled:text-zinc-500 dark:disabled:bg-zinc-800"
                      >
                        Clear inventory
                      </button>
                    </CardBody>
                  </Card>
                </SettingsSection>
              </>
            )}

            <Card>
          <CardHeader>
            <CardTitle><Database className="w-4 h-4 inline mr-1.5" />Environment Variables</CardTitle>
          </CardHeader>
          <CardBody>
            <p className="text-xs text-zinc-500 mb-3">
              Environment variables still bootstrap Argus at container start, but scanner defaults can now be updated live here without editing <span className="font-mono">.env</span>.
            </p>
            <div className="rounded-lg bg-zinc-900 text-zinc-300 p-4 text-xs font-mono space-y-1 overflow-x-auto">
              {[
                '# Scanner',
                'SCANNER_DEFAULT_TARGETS=192.168.1.0/24',
                'SCANNER_INTERVAL_MINUTES=60',
                'SCANNER_DEFAULT_PROFILE=balanced',
                'SCANNER_CONCURRENT_HOSTS=10',
                '',
                '# AI Agent',
                'AI_BACKEND=ollama',
                'OLLAMA_BASE_URL=http://ollama:11434/v1',
                'OLLAMA_MODEL=qwen2.5:7b',
                '# ANTHROPIC_API_KEY=sk-ant-...',
              ].map((line) => (
                <div key={line || 'blank-line'}>
                  <span className={getEnvVarLineClass(line)}>
                    {line || '\u00a0'}
                  </span>
                </div>
              ))}
            </div>
          </CardBody>
            </Card>
          </div>
        </div>
      </div>
    </AppShell>
  )
}
