'use client'

import { useSyncExternalStore } from 'react'
import { usePathname } from 'next/navigation'
import { Sun, Moon, Monitor, RefreshCw } from 'lucide-react'
import { useTheme } from 'next-themes'
import { useAppStore } from '@/store'
import { cn } from '@/lib/utils'
import { useQueryClient } from '@tanstack/react-query'

const PAGE_TITLES: Record<string, string> = {
  '/dashboard': 'Dashboard',
  '/assets':    'Asset Inventory',
  '/topology':  'Topology Map',
  '/scans':     'Scan Management',
  '/settings':  'Settings',
}

export function Header() {
  const pathname = usePathname()
  const { resolvedTheme, setTheme, theme } = useTheme()
  const { activeScan } = useAppStore()
  const queryClient = useQueryClient()
  const mounted = useSyncExternalStore(
    () => () => {},
    () => true,
    () => false,
  )

  // Resolve page title (handles /assets/[id])
  const title = PAGE_TITLES[pathname]
    ?? (pathname.startsWith('/assets/') ? 'Asset Detail' : 'Argus')

  const themes: { value: string; icon: React.ElementType }[] = [
    { value: 'light',  icon: Sun     },
    { value: 'system', icon: Monitor },
    { value: 'dark',   icon: Moon    },
  ]

  const activeTheme = mounted ? theme : null
  const systemTheme = mounted ? resolvedTheme : null

  return (
    <header className="h-16 flex items-center justify-between px-6 border-b border-gray-200 dark:border-zinc-800 bg-white dark:bg-zinc-950 sticky top-0 z-30">
      {/* Left: page title + active scan indicator */}
      <div className="flex items-center gap-4">
        <h1 className="text-lg font-semibold">{title}</h1>
        {activeScan && (
          <div className="flex items-center gap-2 text-xs text-sky-500 bg-sky-500/10 px-3 py-1 rounded-full">
            <span className="w-2 h-2 rounded-full bg-sky-500 animate-pulse" />
            <span>Scanning — {activeScan.current_host || activeScan.stage || 'in progress'}</span>
          </div>
        )}
      </div>

      {/* Right: refresh + theme toggle */}
      <div className="flex items-center gap-2">
        {/* Refresh all queries */}
        <button
          onClick={() => queryClient.invalidateQueries()}
          className="p-2 rounded-lg text-zinc-500 hover:text-zinc-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-zinc-800 transition-colors"
          title="Refresh all data"
        >
          <RefreshCw className="w-4 h-4" />
        </button>

        {/* Theme toggle — three-way */}
        <div className="flex items-center bg-gray-100 dark:bg-zinc-800 rounded-lg p-1 gap-0.5">
          {themes.map(({ value, icon: Icon }) => (
            <button
              key={value}
              onClick={() => setTheme(value)}
              className={cn(
                'p-1.5 rounded-md transition-colors',
                activeTheme === value
                  || (value === 'system' && activeTheme === 'system' && systemTheme !== null)
                  ? 'bg-white dark:bg-zinc-700 text-zinc-900 dark:text-white shadow-sm'
                  : 'text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300',
              )}
              title={`${value} mode`}
            >
              <Icon className="w-3.5 h-3.5" />
            </button>
          ))}
        </div>
      </div>
    </header>
  )
}
