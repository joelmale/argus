'use client'

import { useState } from 'react'
import { AppShell } from '@/components/layout/AppShell'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'
import { ScanLine, Bell, Wifi, Brain, Database, Construction, Shield, UserPlus, KeyRound, Trash2, History, FileText, PlugZap, ActivitySquare, HouseWifi } from 'lucide-react'
import { assetsApi } from '@/lib/api'
import { useAlertRules, useApiKeys, useAuditLogs, useBackupDrivers, useBackupPolicy, useCreateApiKey, useCreateUser, useCurrentUser, useDeleteApiKey, useHomeAssistantEntities, useIntegrationEvents, usePlugins, useResetInventory, useScannerConfig, useUpdateAlertRule, useUpdateBackupPolicy, useUpdateScannerConfig, useUpdateUser, useUsers } from '@/hooks/useAuth'

const SECTIONS = [
  {
    icon: ScanLine,
    title: 'Scan Configuration',
    desc: 'Default targets, scan intervals, concurrent host limits, port ranges.',
  },
  {
    icon: Brain,
    title: 'AI Agent',
    desc: 'AI backend selection (Ollama / Anthropic), model, confidence thresholds.',
  },
  {
    icon: Wifi,
    title: 'Network & SNMP',
    desc: 'SNMP community strings, mDNS interfaces, passive ARP listener settings.',
  },
  {
    icon: Bell,
    title: 'Notifications',
    desc: 'Webhook endpoints, alert rules for new devices, offline hosts, findings.',
  },
  {
    icon: Database,
    title: 'Data Retention',
    desc: 'Asset history TTL, scan job cleanup, topology snapshot frequency.',
  },
]

type BackupPolicyFormProps = {
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
}

type ScannerConfigCardProps = {
  scannerConfig?: {
    enabled: boolean
    default_targets: string | null
    auto_detect_targets: boolean
    detected_targets: string | null
    effective_targets: string | null
    default_profile: string
    interval_minutes: number
    concurrent_hosts: number
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
    fingerprint_ai_enabled: boolean
    fingerprint_ai_model: string
    fingerprint_ai_min_confidence: number
    fingerprint_ai_prompt_suffix: string | null
    internet_lookup_enabled: boolean
    internet_lookup_allowed_domains: string | null
    internet_lookup_budget: number
    internet_lookup_timeout_seconds: number
  }) => void
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
            Enable scheduled backups
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
            Enable scheduled scans
          </label>
          <label className="inline-flex items-center gap-2 text-sm text-zinc-600 dark:text-zinc-300">
            <input type="checkbox" checked={autoDetectTargets} onChange={(event) => setAutoDetectTargets(event.target.checked)} />
            Auto-detect local subnet when no explicit target is set
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
            <option value="balanced">Balanced</option>
            <option value="polite">Polite</option>
            <option value="aggressive">Aggressive</option>
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
          <label className="inline-flex items-center gap-2 text-sm text-zinc-600 dark:text-zinc-300">
            <input type="checkbox" checked={fingerprintAiEnabled} onChange={(event) => setFingerprintAiEnabled(event.target.checked)} />
            Enable Ollama fingerprint synthesis
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
            Enable internet lookup for unresolved assets
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

export default function SettingsPage() {
  const { data: currentUser } = useCurrentUser()
  const { data: users = [] } = useUsers(currentUser?.role === 'admin')
  const { data: apiKeys = [] } = useApiKeys(currentUser?.role === 'admin')
  const { data: auditLogs = [] } = useAuditLogs(currentUser?.role === 'admin')
  const { data: alertRules = [] } = useAlertRules(currentUser?.role === 'admin')
  const { data: backupDrivers = [] } = useBackupDrivers(currentUser?.role === 'admin')
  const { data: backupPolicy } = useBackupPolicy(currentUser?.role === 'admin')
  const { data: scannerConfig } = useScannerConfig(currentUser?.role === 'admin')
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
  const { mutate: resetInventory, isPending: isResettingInventory } = useResetInventory()
  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newRole, setNewRole] = useState<'admin' | 'viewer'>('viewer')
  const [userError, setUserError] = useState<string | null>(null)
  const [apiKeyName, setApiKeyName] = useState('')
  const [generatedApiKey, setGeneratedApiKey] = useState<string | null>(null)
  const [inventoryConfirm, setInventoryConfirm] = useState('')
  const [includeScanHistory, setIncludeScanHistory] = useState(false)

  function handleCreateUser(event: React.FormEvent) {
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

  function handleCreateApiKey(event: React.FormEvent) {
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

  async function handleOpenReport() {
    const response = await assetsApi.exportHtmlReport()
    const reportWindow = window.open('', '_blank')
    reportWindow?.document.write(response.data)
    reportWindow?.document.close()
  }

  return (
    <AppShell>
      <div className="max-w-3xl mx-auto space-y-6">
        <div>
          <h2 className="text-xl font-bold text-zinc-900 dark:text-white">Settings</h2>
          <p className="text-sm text-zinc-500 mt-0.5">Configuration for Argus scans, AI, and notifications.</p>
        </div>

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
                        Active
                      </label>
                    </div>
                  ))}
                </div>
              </CardBody>
            </Card>

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

            <BackupPolicyCard
              key={backupPolicy?.updated_at ?? 'backup-policy'}
              backupPolicy={backupPolicy}
              isUpdatingBackupPolicy={isUpdatingBackupPolicy}
              onSave={(payload) => updateBackupPolicy(payload)}
            />

            <ScannerConfigCard
              key={scannerConfig?.updated_at ?? 'scanner-config'}
              scannerConfig={scannerConfig}
              isUpdatingScannerConfig={isUpdatingScannerConfig}
              onSave={(payload) => updateScannerConfig(payload)}
            />

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
                        Enabled
                      </label>
                      <label className="inline-flex items-center gap-2">
                        <input
                          type="checkbox"
                          checked={rule.notify_email}
                          disabled={isUpdatingAlertRule}
                          onChange={(event) => updateAlertRule({ id: rule.id, payload: { notify_email: event.target.checked } })}
                        />
                        Email
                      </label>
                      <label className="inline-flex items-center gap-2">
                        <input
                          type="checkbox"
                          checked={rule.notify_webhook}
                          disabled={isUpdatingAlertRule}
                          onChange={(event) => updateAlertRule({ id: rule.id, payload: { notify_webhook: event.target.checked } })}
                        />
                        Webhook
                      </label>
                    </div>
                  </div>
                ))}
              </CardBody>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle><FileText className="w-4 h-4 inline mr-1.5" />Reports & Metrics</CardTitle>
              </CardHeader>
              <CardBody className="flex flex-col md:flex-row gap-3">
                <button
                  type="button"
                  onClick={handleOpenReport}
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
                  Also delete scan job history
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
          </>
        )}

        {/* Upcoming sections preview */}
        <div className={currentUser?.role === 'viewer' ? 'space-y-3 opacity-50 pointer-events-none' : 'space-y-3'}>
          {SECTIONS.map(({ icon: Icon, title, desc }) => (
            <Card key={title} className="opacity-60 pointer-events-none select-none">
              <CardBody>
                <div className="flex items-start gap-3">
                  <div className="w-9 h-9 rounded-lg bg-zinc-100 dark:bg-zinc-800 flex items-center justify-center flex-shrink-0">
                    <Icon className="w-4 h-4 text-zinc-500" />
                  </div>
                  <div>
                    <p className="text-sm font-medium text-zinc-800 dark:text-zinc-200">{title}</p>
                    <p className="text-xs text-zinc-500 mt-0.5">{desc}</p>
                  </div>
                  <span className="ml-auto text-xs px-2 py-0.5 rounded-full bg-zinc-100 dark:bg-zinc-800 text-zinc-500">
                    Planned
                  </span>
                </div>
              </CardBody>
            </Card>
          ))}
        </div>

        {/* .env reference */}
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
              ].map((line, i) => (
                <div key={i}>
                  <span className={line.startsWith('#') ? 'text-zinc-500' : line === '' ? '' : 'text-emerald-400'}>
                    {line || '\u00a0'}
                  </span>
                </div>
              ))}
            </div>
          </CardBody>
        </Card>
      </div>
    </AppShell>
  )
}
