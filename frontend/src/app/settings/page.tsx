'use client'

import dynamic from 'next/dynamic'
import { AppShell } from '@/components/layout/AppShell'

const SettingsContent = dynamic(() => import('./SettingsContent'), {
  ssr: false,
  loading: () => (
    <AppShell>
      <div className="max-w-7xl mx-auto space-y-6 animate-pulse">
        <div className="h-7 w-24 rounded bg-zinc-200 dark:bg-zinc-800" />
        <div className="h-4 w-64 rounded bg-zinc-100 dark:bg-zinc-800/60" />
        <div className="grid grid-cols-1 xl:grid-cols-[240px_minmax(0,1fr)] gap-6">
          <div className="hidden xl:block h-96 rounded-2xl bg-zinc-100 dark:bg-zinc-800/60" />
          <div className="space-y-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="h-48 rounded-2xl bg-zinc-100 dark:bg-zinc-800/60" />
            ))}
          </div>
        </div>
      </div>
    </AppShell>
  ),
})

export default function SettingsPage() {
  return <SettingsContent />
}
