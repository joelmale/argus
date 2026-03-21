'use client'

import { useState } from 'react'
import { ScanLine, ChevronDown } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'
import { useTriggerScan } from '@/hooks/useScans'
import { useAppStore } from '@/store'
import { cn } from '@/lib/utils'

const PROFILES = [
  { value: 'quick', label: 'Quick', desc: 'Fast first-pass inventory' },
  { value: 'balanced', label: 'Balanced', desc: 'Ports + OS + AI analysis' },
  { value: 'deep_enrichment', label: 'Deep Enrichment', desc: 'Follow-up full-port investigation' },
]

export function QuickScan() {
  const [targets, setTargets] = useState('')
  const [profile, setProfile] = useState('quick')
  const { mutate: trigger, isPending } = useTriggerScan()
  const { activeScan } = useAppStore()

  function handleScan(e: React.FormEvent) {
    e.preventDefault()
    trigger({ targets: targets.trim() || undefined, scan_type: profile })
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Quick Scan</CardTitle>
        {activeScan && (
          <span className="flex items-center gap-1.5 text-xs text-yellow-500">
            <span className="w-2 h-2 rounded-full bg-yellow-500 animate-pulse" />
            {activeScan.stage ? `Stage: ${formatScanStage(activeScan.stage)}` : 'Scanning…'}
          </span>
        )}
      </CardHeader>
      <CardBody>
        <form onSubmit={handleScan} className="space-y-3">
          <div>
            <label className="text-xs text-zinc-500 mb-1 block">Target (CIDR or IP)</label>
            <input
              type="text"
              value={targets}
              onChange={(e) => setTargets(e.target.value)}
              placeholder="Leave blank to use saved scanner default"
              className={cn(
                'w-full px-3 py-2 rounded-lg text-sm',
                'bg-gray-50 dark:bg-zinc-800',
                'border border-gray-200 dark:border-zinc-700',
                'text-zinc-900 dark:text-white placeholder:text-zinc-400',
                'focus:outline-none focus:ring-2 focus:ring-sky-500/50 focus:border-sky-500',
              )}
            />
          </div>

          <div>
            <label className="text-xs text-zinc-500 mb-1 block">Profile</label>
            <div className="relative">
              <select
                value={profile}
                onChange={(e) => setProfile(e.target.value)}
                className={cn(
                  'w-full px-3 py-2 rounded-lg text-sm appearance-none',
                  'bg-gray-50 dark:bg-zinc-800',
                  'border border-gray-200 dark:border-zinc-700',
                  'text-zinc-900 dark:text-white',
                  'focus:outline-none focus:ring-2 focus:ring-sky-500/50',
                )}
              >
                {PROFILES.map((p) => (
                  <option key={p.value} value={p.value}>{p.label} — {p.desc}</option>
                ))}
              </select>
              <ChevronDown className="absolute right-3 top-2.5 w-4 h-4 text-zinc-400 pointer-events-none" />
            </div>
          </div>

          <button
            type="submit"
            disabled={isPending || !!activeScan}
            className={cn(
              'w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg text-sm font-medium',
              'transition-all duration-150',
              isPending || activeScan
                ? 'bg-zinc-200 dark:bg-zinc-800 text-zinc-400 cursor-not-allowed'
                : 'bg-sky-500 hover:bg-sky-600 text-white shadow-sm hover:shadow-sky-500/25',
            )}
          >
            <ScanLine className="w-4 h-4" />
            {isPending ? 'Queuing…' : activeScan ? 'Scan in progress…' : 'Start Scan'}
          </button>
        </form>

        {/* Active scan progress */}
        {activeScan && (
          <div className="mt-4 p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
            <p className="text-xs font-medium text-yellow-600 dark:text-yellow-400 mb-1">
              {activeScan.stage ? `Stage: ${activeScan.stage}` : 'Scanning…'}
            </p>
            {activeScan.current_host && (
              <p className="text-xs text-zinc-500 font-mono">{activeScan.current_host}</p>
            )}
            {activeScan.hosts_found !== undefined && (
              <p className="text-xs text-zinc-500 mt-0.5">{activeScan.hosts_found} hosts discovered</p>
            )}
            {activeScan.assets_created !== undefined && (
              <p className="text-xs text-zinc-500 mt-0.5">{activeScan.assets_created} created · {activeScan.assets_updated ?? 0} updated</p>
            )}
          </div>
        )}
      </CardBody>
    </Card>
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
