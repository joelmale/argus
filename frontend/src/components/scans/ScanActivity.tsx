'use client'

import { cn } from '@/lib/utils'

export function formatScanStage(stage: string) {
  const labels: Record<string, string> = {
    discovery: 'Discovery',
    port_scan: 'Port Scan',
    investigation: 'Fingerprint + Probes',
    persist: 'Finalize Inventory',
    queued: 'Queued',
  }
  return labels[stage] ?? stage.replaceAll('_', ' ')
}

export function ScanPulseDots({ className }: Readonly<{ className?: string }>) {
  return (
    <span aria-hidden className={cn('inline-flex items-center gap-0.5 align-middle', className)}>
      <span
        className="inline-block h-1 w-1 rounded-full bg-current animate-pulse-slow motion-reduce:animate-none"
        style={{ animationDelay: '0ms' }}
      />
      <span
        className="inline-block h-1 w-1 rounded-full bg-current animate-pulse-slow motion-reduce:animate-none"
        style={{ animationDelay: '180ms' }}
      />
      <span
        className="inline-block h-1 w-1 rounded-full bg-current animate-pulse-slow motion-reduce:animate-none"
        style={{ animationDelay: '360ms' }}
      />
    </span>
  )
}

export function ScanActivityBar({ className }: Readonly<{ className?: string }>) {
  return (
    <div className={cn('relative h-1 overflow-hidden rounded-full bg-zinc-200 dark:bg-zinc-800', className)}>
      <div className="absolute inset-y-0 left-0 w-1/3 rounded-full bg-gradient-to-r from-transparent via-sky-500/80 to-transparent animate-scan-glide motion-reduce:animate-none" />
    </div>
  )
}
