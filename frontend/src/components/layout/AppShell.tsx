'use client'

import { useEffect } from 'react'
import { Sidebar } from './Sidebar'
import { Header } from './Header'
import { useAppStore } from '@/store'
import { useWebSocket } from '@/hooks/useWebSocket'
import { cn } from '@/lib/utils'

export function AppShell({ children }: { children: React.ReactNode }) {
  const { sidebarCollapsed } = useAppStore()
  useWebSocket()  // Establish & maintain WS connection

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
