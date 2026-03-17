'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import {
  Eye, LayoutDashboard, Server, Network, ScanLine,
  Settings, ChevronLeft, ChevronRight, Wifi, WifiOff,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useAppStore } from '@/store'
import { useCurrentUser } from '@/hooks/useAuth'

const NAV_ITEMS = [
  { href: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { href: '/assets',    icon: Server,          label: 'Assets'    },
  { href: '/topology',  icon: Network,         label: 'Topology'  },
  { href: '/scans',     icon: ScanLine,        label: 'Scans'     },
  { href: '/settings',  icon: Settings,        label: 'Settings'  },
]

export function Sidebar() {
  const pathname = usePathname()
  const { sidebarCollapsed, toggleSidebar, wsConnected } = useAppStore()
  const { data: currentUser } = useCurrentUser()

  const navItems = currentUser?.role === 'viewer'
    ? NAV_ITEMS.filter((item) => item.href !== '/settings')
    : NAV_ITEMS

  return (
    <aside
      className={cn(
        'fixed inset-y-0 left-0 z-40 flex flex-col',
        'bg-white dark:bg-sidebar border-r border-gray-200 dark:border-sidebar-border',
        'transition-all duration-200 ease-in-out',
        sidebarCollapsed ? 'w-16' : 'w-56',
      )}
    >
      {/* Logo */}
      <div className={cn(
        'flex items-center h-16 px-4 border-b border-gray-200 dark:border-sidebar-border',
        sidebarCollapsed ? 'justify-center' : 'gap-3',
      )}>
        <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-sky-500 flex items-center justify-center">
          <Eye className="w-5 h-5 text-white" />
        </div>
        {!sidebarCollapsed && (
          <span className="text-lg font-semibold tracking-tight text-zinc-900 dark:text-white">
            Argus
          </span>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-2 py-4 space-y-1 overflow-y-auto">
        {navItems.map(({ href, icon: Icon, label }) => {
          const active = pathname === href || (href !== '/dashboard' && pathname.startsWith(href))
          return (
            <Link
              key={href}
              href={href}
              title={sidebarCollapsed ? label : undefined}
              className={cn(
                'flex items-center gap-3 px-2 py-2 rounded-lg text-sm font-medium transition-colors',
                'group relative',
                active
                  ? 'bg-sky-50 dark:bg-sky-500/10 text-sky-600 dark:text-sky-400'
                  : 'text-zinc-600 dark:text-zinc-400 hover:bg-gray-100 dark:hover:bg-sidebar-hover hover:text-zinc-900 dark:hover:text-white',
                sidebarCollapsed && 'justify-center px-0',
              )}
            >
              <Icon className={cn('w-5 h-5 flex-shrink-0', active ? 'text-sky-500' : '')} />
              {!sidebarCollapsed && <span>{label}</span>}
              {/* Active indicator */}
              {active && (
                <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 bg-sky-500 rounded-r" />
              )}
            </Link>
          )
        })}
      </nav>

      {/* Bottom: WS status + collapse toggle */}
      <div className={cn(
        'px-2 py-3 border-t border-gray-200 dark:border-sidebar-border space-y-1',
      )}>
        {/* Connection status */}
        <div className={cn(
          'flex items-center gap-2 px-2 py-1.5 rounded-lg text-xs',
          wsConnected
            ? 'text-emerald-600 dark:text-emerald-400'
            : 'text-zinc-500 dark:text-zinc-500',
          sidebarCollapsed && 'justify-center px-0',
        )}>
          {wsConnected
            ? <Wifi className="w-4 h-4 flex-shrink-0" />
            : <WifiOff className="w-4 h-4 flex-shrink-0" />}
          {!sidebarCollapsed && (
            <span>{wsConnected ? 'Live' : 'Disconnected'}</span>
          )}
          {wsConnected && !sidebarCollapsed && (
            <span className="ml-auto w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          )}
        </div>

        {/* Collapse toggle */}
        <button
          onClick={toggleSidebar}
          className={cn(
            'flex items-center w-full px-2 py-1.5 rounded-lg text-sm',
            'text-zinc-500 hover:text-zinc-900 dark:hover:text-white',
            'hover:bg-gray-100 dark:hover:bg-sidebar-hover transition-colors',
            sidebarCollapsed && 'justify-center px-0',
          )}
        >
          {sidebarCollapsed
            ? <ChevronRight className="w-4 h-4" />
            : <><ChevronLeft className="w-4 h-4" /><span className="ml-2 text-xs">Collapse</span></>
          }
        </button>
      </div>
    </aside>
  )
}
