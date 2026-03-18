import type { Metadata } from 'next'
import { Providers } from './providers'
import './globals.css'

export const metadata: Metadata = {
  title: 'Argus — Network Asset Intelligence',
  description: 'Network asset discovery, inventory, and topology mapping for home labs',
  icons: { icon: '/favicon.ico' },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="bg-gray-50 dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100 antialiased">
        <Providers>{children}</Providers>
      </body>
    </html>
  )
}
