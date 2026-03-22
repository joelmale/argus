'use client'

import Link from 'next/link'
import { useState, type ComponentProps } from 'react'
import { AppShell } from '@/components/layout/AppShell'
import { useCurrentUser } from '@/hooks/useAuth'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'
import { ScanHistory } from '@/components/scans/ScanHistory'
import { useScans, useTriggerScan } from '@/hooks/useScans'
import { useAppStore } from '@/store'
import { cn } from '@/lib/utils'
import {
  ScanLine, CheckCircle, XCircle,
  Cpu, Loader2, Radio, Target, Layers,
} from 'lucide-react'

const PROFILES = [
  {
    value: 'quick',
    label: 'Quick',
    desc: 'Fast first-pass inventory. Limited ports, no AI, no deep probes.',
    color: 'emerald',
  },
  {
    value: 'balanced',
    label: 'Balanced',
    desc: 'Inventory plus OS fingerprinting, deep probes, and AI analysis.',
    color: 'sky',
  },
  {
    value: 'deep_enrichment',
    label: 'Deep Enrichment',
    desc: 'Full-port, deeper service inspection for deliberate follow-up work.',
    color: 'red',
  },
]

export default function ScansPage() {
  const [targets, setTargets] = useState('')
  const [profile, setProfile]   = useState('balanced')
  const [error, setError]        = useState<string | null>(null)
  const [lastResult, setLastResult] = useState<'success' | 'error' | null>(null)

  const { data: scans = [], isLoading } = useScans()
  const { mutate: trigger, isPending } = useTriggerScan()
  const { activeScan } = useAppStore()
  const { data: currentUser } = useCurrentUser()
  const isViewer = currentUser?.role === 'viewer'

  const targetInputId = 'new-scan-target'

  const handleScan: NonNullable<ComponentProps<'form'>['onSubmit']> = (e) => {
    e.preventDefault()
    setError(null)
    setLastResult(null)
    trigger(
      { targets: targets.trim() || undefined, scan_type: profile },
      {
        onSuccess: () => { setLastResult('success'); setTargets('') },
        onError:   () => { setLastResult('error') },
      },
    )
  }

  const runningScans = scans.filter((s) => s.status === 'running' || s.status === 'pending')
  const followUpScan = scans.find((scan) =>
    scan.status === 'done'
    && (scan.scan_type === 'quick' || scan.scan_type === 'balanced')
  )
  const stageLabel = activeScan?.stage ? formatScanStage(activeScan.stage) : null
  const inputBorderClass = error ? 'border-red-400' : 'border-gray-200 dark:border-zinc-700'
  const queuedScanLabel = runningScans.length === 1 ? 'scan' : 'scans'
  const followUpButtonClass = isPending || activeScan
    ? 'bg-zinc-200 text-zinc-400 dark:bg-zinc-800'
    : 'bg-red-500 text-white hover:bg-red-600'

  const buttonStateClass = isViewer || isPending || !!activeScan
    ? 'bg-zinc-200 dark:bg-zinc-800 text-zinc-400 cursor-not-allowed'
    : 'bg-sky-500 hover:bg-sky-600 text-white shadow-sm hover:shadow-md hover:shadow-sky-500/20'

  function getProfileClass(profileValue: string) {
    if (profile !== profileValue) {
      return 'border-gray-200 dark:border-zinc-700 text-zinc-700 dark:text-zinc-300 hover:border-zinc-400 dark:hover:border-zinc-500'
    }
    if (profileValue === 'balanced') {
      return 'border-sky-500 bg-sky-500/10 text-sky-700 dark:text-sky-300'
    }
    if (profileValue === 'quick') {
      return 'border-emerald-500 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
    }
    return 'border-red-500 bg-red-500/10 text-red-700 dark:text-red-300'
  }

  function renderSubmitLabel() {
    if (isPending) {
      return <><Loader2 className="w-4 h-4 animate-spin" /> Queuing…</>
    }
    return <><ScanLine className="w-4 h-4" /> Start Scan</>
  }

  return (
    <AppShell>
      <div className="max-w-6xl mx-auto space-y-6">

        {/* Page header */}
        <div>
          <h2 className="text-xl font-bold text-zinc-900 dark:text-white">Scans</h2>
          <p className="text-sm text-zinc-500 mt-0.5">Trigger network scans and review historical job results.</p>
        </div>

        {/* Top row: trigger form + active progress */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">

          {/* Trigger form — spans 2 cols */}
          <div className="lg:col-span-2">
            <Card>
              <CardHeader>
                <CardTitle><Target className="w-4 h-4 inline mr-1.5" />New Scan</CardTitle>
              </CardHeader>
              <CardBody>
                {isViewer && (
                  <div className="mb-4 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-700 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-300">
                    Viewer accounts can review scan history but cannot trigger new scans.
                  </div>
                )}
                <form onSubmit={handleScan} className="space-y-4">
                  {/* Targets */}
                  <div>
                    <label htmlFor={targetInputId} className="text-xs font-medium text-zinc-500 mb-1.5 block">
                      Target — IP address or CIDR range
                    </label>
                    <input
                      id={targetInputId}
                      type="text"
                      value={targets}
                      onChange={(e) => { setTargets(e.target.value); setError(null) }}
                      placeholder="Leave blank to use the saved default target"
                      className={cn(
                        'w-full px-3 py-2.5 rounded-lg text-sm font-mono',
                        'bg-gray-50 dark:bg-zinc-800',
                        'border placeholder:text-zinc-400',
                        'text-zinc-900 dark:text-white',
                        'focus:outline-none focus:ring-2 focus:ring-sky-500/50 focus:border-sky-500',
                        inputBorderClass,
                      )}
                    />
                    {error && <p className="text-xs text-red-500 mt-1">{error}</p>}
                  </div>

                  {/* Profile selector */}
                  <div>
                    <p className="text-xs font-medium text-zinc-500 mb-1.5 flex items-center gap-1">
                      <Layers className="w-3.5 h-3.5" /> Scan profile
                    </p>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                      {PROFILES.map((p) => (
                        <button
                          key={p.value}
                          type="button"
                          onClick={() => setProfile(p.value)}
                          className={cn(
                            'text-left px-3 py-2.5 rounded-lg border text-sm transition-all',
                            getProfileClass(p.value),
                          )}
                        >
                          <p className="font-medium text-xs capitalize">{p.label}</p>
                          <p className="text-xs opacity-70 mt-0.5 leading-relaxed">{p.desc}</p>
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Submit */}
                  <div className="flex items-center gap-3">
                    <button
                      type="submit"
                      disabled={isViewer || isPending || !!activeScan}
                      className={cn(
                        'flex items-center gap-2 py-2.5 px-5 rounded-lg text-sm font-medium',
                        'transition-all duration-150',
                        buttonStateClass,
                      )}
                    >
                      {renderSubmitLabel()}
                    </button>

                    {lastResult === 'success' && (
                      <span className="flex items-center gap-1 text-xs text-emerald-600 dark:text-emerald-400">
                        <CheckCircle className="w-4 h-4" /> Scan enqueued
                      </span>
                    )}
                    {lastResult === 'error' && (
                      <span className="flex items-center gap-1 text-xs text-red-500">
                        <XCircle className="w-4 h-4" /> Failed to enqueue
                      </span>
                    )}
                  </div>
                </form>
              </CardBody>
            </Card>
          </div>

          {/* Right: active scan status */}
          <div>
            <Card className="h-full">
              <CardHeader>
                <CardTitle><Radio className="w-4 h-4 inline mr-1.5 text-sky-500" />Live Status</CardTitle>
              </CardHeader>
              <CardBody>
                {activeScan ? (
                  <div className="space-y-3">
                    <div className="flex items-center gap-2">
                      <span className="w-2.5 h-2.5 rounded-full bg-yellow-500 animate-pulse flex-shrink-0" />
                      <span className="text-sm font-medium text-yellow-600 dark:text-yellow-400">
                        {stageLabel ? `Stage: ${stageLabel}` : 'Scanning…'}
                      </span>
                    </div>
                    {activeScan.current_host && (
                      <div>
                        <p className="text-xs text-zinc-500 mb-0.5">Current host</p>
                        <p className="text-sm font-mono text-zinc-800 dark:text-zinc-200">{activeScan.current_host}</p>
                      </div>
                    )}
                    {activeScan.progress !== undefined && (
                      <div>
                        <div className="flex justify-between text-xs text-zinc-500 mb-1">
                          <span>Progress</span>
                          <span>{Math.round(activeScan.progress * 100)}%</span>
                        </div>
                        <div className="h-1.5 rounded-full bg-zinc-200 dark:bg-zinc-800">
                          <div
                            className="h-1.5 rounded-full bg-sky-500 transition-all duration-500"
                            style={{ width: `${activeScan.progress * 100}%` }}
                          />
                        </div>
                      </div>
                    )}
                    {activeScan.hosts_found !== undefined && (
                      <div className="grid grid-cols-2 gap-2 text-xs text-zinc-500">
                        <p><span className="font-medium text-zinc-900 dark:text-zinc-100">{activeScan.hosts_found}</span> hosts discovered</p>
                        <p><span className="font-medium text-zinc-900 dark:text-zinc-100">{activeScan.hosts_port_scanned ?? 0}</span> port scanned</p>
                        <p><span className="font-medium text-zinc-900 dark:text-zinc-100">{activeScan.hosts_fingerprinted ?? 0}</span> fingerprinted</p>
                        <p><span className="font-medium text-zinc-900 dark:text-zinc-100">{activeScan.hosts_deep_probed ?? 0}</span> deep probed</p>
                        <p><span className="font-medium text-zinc-900 dark:text-zinc-100">{activeScan.assets_created ?? 0}</span> assets created</p>
                        <p><span className="font-medium text-zinc-900 dark:text-zinc-100">{activeScan.assets_updated ?? 0}</span> assets updated</p>
                      </div>
                    )}
                    <Link
                      href="/assets"
                      className="inline-flex items-center justify-center rounded-lg border border-sky-200 px-3 py-2 text-xs font-medium text-sky-600 hover:bg-sky-50 dark:border-sky-900 dark:text-sky-300 dark:hover:bg-sky-950/30"
                    >
                      View Inventory So Far
                    </Link>
                  </div>
                ) : runningScans.length > 0 ? (
                  <div className="flex items-center gap-2">
                    <Cpu className="w-4 h-4 text-sky-500 animate-pulse" />
                    <span className="text-sm text-zinc-600 dark:text-zinc-300">
                      {runningScans.length} {queuedScanLabel} in queue
                    </span>
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center py-6 text-center">
                    <Radio className="w-8 h-8 text-zinc-300 dark:text-zinc-700 mb-2" />
                    <p className="text-sm text-zinc-400">No active scans</p>
                    <p className="text-xs text-zinc-400 mt-0.5">Trigger a scan to see live progress here.</p>
                  </div>
                )}
              </CardBody>
            </Card>
          </div>
        </div>

        {followUpScan && !isViewer && (
          <Card>
            <CardHeader>
              <CardTitle><Layers className="w-4 h-4 inline mr-1.5" />Follow-Up Enrichment</CardTitle>
            </CardHeader>
            <CardBody className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-sm text-zinc-700 dark:text-zinc-300">
                  Deepen the latest {followUpScan.scan_type.replaceAll('_', ' ')} scan without retyping targets.
                </p>
                <p className="mt-1 text-xs text-zinc-500 font-mono">{followUpScan.targets}</p>
              </div>
              <button
                type="button"
                disabled={isPending || !!activeScan}
                onClick={() => {
                  setError(null)
                  setLastResult(null)
                  trigger(
                    { targets: followUpScan.targets, scan_type: 'deep_enrichment' },
                    {
                      onSuccess: () => setLastResult('success'),
                      onError: () => setLastResult('error'),
                    },
                  )
                }}
                className={cn(
                  'inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium',
                  followUpButtonClass,
                )}
              >
                <Layers className="w-4 h-4" />
                Run Deep Enrichment
              </button>
            </CardBody>
          </Card>
        )}

        {/* Scan history */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-zinc-700 dark:text-zinc-300">
              Scan History
              {scans.length > 0 && (
                <span className="ml-2 text-xs text-zinc-400 font-normal">{scans.length} jobs</span>
              )}
            </h3>
          </div>
          <ScanHistory scans={scans} isLoading={isLoading} />
        </div>

      </div>
    </AppShell>
  )
}

function formatScanStage(stage: string) {
  const labels: Record<string, string> = {
    discovery: 'Discovery',
    port_scan: 'Port Scan',
    investigation: 'Fingerprint + Probes',
    persist: 'Finalize Inventory',
    queued: 'Queued',
  }
  return labels[stage] ?? stage.replaceAll('_', ' ')
}
