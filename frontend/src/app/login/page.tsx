'use client'

import { useEffect, useState } from 'react'
import axios from 'axios'
import { Eye, Loader2, ShieldCheck } from 'lucide-react'
import { useRouter } from 'next/navigation'
import { useCurrentUser, useLogin } from '@/hooks/useAuth'

function getLoginErrorMessage(error: unknown) {
  const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000'

  if (!axios.isAxiosError(error)) {
    return 'Sign-in failed before the server returned a usable response. Try again and check the browser console if it repeats.'
  }

  if (!error.response) {
    return `Cannot reach the Argus API at ${apiUrl}. Check that the backend container is running and that the browser can reach that address.`
  }

  if (error.response.status === 401) {
    return 'Argus rejected the login with HTTP 401. Check the username and password, and confirm the admin account was bootstrapped with the credentials you expect.'
  }

  if (error.response.status >= 500) {
    return `The Argus API returned HTTP ${error.response.status}. Check backend logs for the login request and verify the database connection is healthy.`
  }

  const detail = error.response.data && typeof error.response.data === 'object' ? (error.response.data as { detail?: unknown }).detail : undefined
  if (typeof detail === 'string' && detail.trim()) {
    return detail
  }

  return `Sign-in failed with HTTP ${error.response.status}.`
}

export default function LoginPage() {
  const router = useRouter()
  const { data: currentUser, isLoading: isLoadingUser } = useCurrentUser()
  const { mutate: login, isPending } = useLogin()
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (currentUser) {
      router.replace('/dashboard')
    }
  }, [currentUser, router])

  function handleSubmit(event: React.FormEvent) {
    event.preventDefault()
    setError(null)

    login(
      { username, password },
      {
        onSuccess: () => router.replace('/dashboard'),
        onError: (error) => setError(getLoginErrorMessage(error)),
      },
    )
  }

  return (
    <main className="min-h-screen bg-[radial-gradient(circle_at_top,_rgba(14,165,233,0.18),_transparent_35%),linear-gradient(180deg,_#f8fafc,_#e2e8f0)] dark:bg-[radial-gradient(circle_at_top,_rgba(14,165,233,0.24),_transparent_35%),linear-gradient(180deg,_#09090b,_#18181b)] flex items-center justify-center px-6">
      <div className="w-full max-w-md rounded-3xl border border-white/60 dark:border-zinc-800 bg-white/90 dark:bg-zinc-950/90 backdrop-blur-xl shadow-2xl shadow-sky-500/10 p-8">
        <div className="flex items-center gap-3 mb-8">
          <div className="w-11 h-11 rounded-2xl bg-sky-500 flex items-center justify-center shadow-lg shadow-sky-500/30">
            <Eye className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-zinc-950 dark:text-white">Argus</h1>
            <p className="text-sm text-zinc-500">Sign in to access your network inventory.</p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-zinc-700 dark:text-zinc-200 mb-1.5">
              Username
            </label>
            <input
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              className="w-full rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 px-4 py-3 text-sm outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20"
              autoComplete="username"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-zinc-700 dark:text-zinc-200 mb-1.5">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="w-full rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 px-4 py-3 text-sm outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20"
              autoComplete="current-password"
            />
          </div>

          {error && (
            <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-600 dark:border-red-950 dark:bg-red-950/40 dark:text-red-300">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={isPending || isLoadingUser}
            className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-sky-500 px-4 py-3 text-sm font-medium text-white transition-colors hover:bg-sky-600 disabled:bg-zinc-300 disabled:text-zinc-500 dark:disabled:bg-zinc-800"
          >
            {isPending || isLoadingUser ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" /> Signing in
              </>
            ) : (
              <>
                <ShieldCheck className="w-4 h-4" /> Sign In
              </>
            )}
          </button>
        </form>
      </div>
    </main>
  )
}
