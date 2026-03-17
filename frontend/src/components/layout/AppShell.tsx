'use client'

import { useEffect } from 'react'
import { Loader2 } from 'lucide-react'
import { usePathname, useRouter } from 'next/navigation'
import { Sidebar } from './Sidebar'
import { Header } from './Header'
import { useAppStore } from '@/store'
import { useWebSocket } from '@/hooks/useWebSocket'
import { clearAuthToken, useCurrentUser } from '@/hooks/useAuth'
import { cn } from '@/lib/utils'

export function AppShell({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const pathname = usePathname()
  const { sidebarCollapsed } = useAppStore()
  const { data: currentUser, isLoading, isError } = useCurrentUser()
  useWebSocket(!!currentUser)  // Establish & maintain WS connection

  useEffect(() => {
    if (!isLoading && (isError || !currentUser)) {
      clearAuthToken()
      router.replace(`/login?next=${encodeURIComponent(pathname)}`)
    }
  }, [currentUser, isError, isLoading, pathname, router])

  if (isLoading || (!currentUser && !isError)) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-zinc-950">
        <div className="inline-flex items-center gap-2 text-sm text-zinc-500">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading session…
        </div>
      </div>
    )
  }

  if (!currentUser) {
    return null
  }

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
