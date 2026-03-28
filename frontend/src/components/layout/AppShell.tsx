'use client'

import { useEffect } from 'react'
import { Loader2, RefreshCw } from 'lucide-react'
import { usePathname, useRouter } from 'next/navigation'
import { Sidebar } from './Sidebar'
import { Header } from './Header'
import { useAppStore } from '@/store'
import { useWebSocket } from '@/hooks/useWebSocket'
import { clearAuthToken, isUnauthorizedError, useCurrentUser } from '@/hooks/useAuth'
import { cn } from '@/lib/utils'

interface AppShellProps {
  children: React.ReactNode
}

export function AppShell({ children }: Readonly<AppShellProps>) {
  const router = useRouter()
  const pathname = usePathname()
  const { sidebarCollapsed } = useAppStore()
  const { data: currentUser, error, isError, isFetching, isLoading, refetch } = useCurrentUser()
  const authExpired = isUnauthorizedError(error)
  useWebSocket(!!currentUser)  // Establish & maintain WS connection

  useEffect(() => {
    if (!isLoading && !currentUser && authExpired) {
      clearAuthToken()
      router.replace(`/login?next=${encodeURIComponent(pathname)}`)
    }
  }, [authExpired, currentUser, isLoading, pathname, router])

  if (currentUser) {
    return (
      <div className="min-h-screen flex">
        <Sidebar />
        <div className={cn(
          'flex-1 flex flex-col min-h-screen transition-all duration-200',
          sidebarCollapsed ? 'ml-16' : 'ml-56',
        )}>
          <Header />
          <main className="flex-1 p-6 overflow-auto">
            {children}
          </main>
        </div>
      </div>
    )
  }

  if (isLoading || isFetching || (!currentUser && !isError)) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-zinc-950">
        <div className="inline-flex items-center gap-2 text-sm text-zinc-500">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading session…
        </div>
      </div>
    )
  }

  if (authExpired) {
    return null
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-zinc-950 px-6">
      <div className="max-w-md rounded-2xl border border-gray-200 dark:border-zinc-800 bg-white dark:bg-zinc-950 p-6 text-center shadow-sm">
        <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">Session check failed</p>
        <p className="mt-2 text-sm text-zinc-500">
          Argus could not verify your login yet. Your local session token was kept, so this is usually a temporary API or container startup issue.
        </p>
        <button
          type="button"
          onClick={() => {
            void refetch()
          }}
          className="mt-4 inline-flex items-center gap-2 rounded-lg bg-sky-500 px-4 py-2 text-sm font-medium text-white hover:bg-sky-600"
        >
          <RefreshCw className="h-4 w-4" />
          Retry session check
        </button>
      </div>
    </div>
  )
}
