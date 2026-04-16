'use client'

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ThemeProvider } from 'next-themes'
import { useState, type ReactNode } from 'react'
import { ErrorBoundary } from '@/components/layout/ErrorBoundary'

interface ProvidersProps {
  children: ReactNode
}

export function Providers({ children }: Readonly<ProvidersProps>) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 30_000,      // Data fresh for 30s before background refetch
            retry: 2,
            refetchOnWindowFocus: true,
          },
        },
      }),
  )

  return (
    <ThemeProvider attribute="class" defaultTheme="system" enableSystem>
      <QueryClientProvider client={queryClient}>
        <ErrorBoundary>
          {children}
        </ErrorBoundary>
      </QueryClientProvider>
    </ThemeProvider>
  )
}
