'use client'

import { useEffect, useState, type ComponentProps } from 'react'
import axios from 'axios'
import { Eye, Loader2 } from 'lucide-react'
import { useRouter } from 'next/navigation'
import { SAVED_USERNAME_KEY, useCurrentUser, useInitializeFirstAdmin, useLogin, useSetupStatus } from '@/hooks/useAuth'

type FormSubmitHandler = NonNullable<ComponentProps<'form'>['onSubmit']>
const APP_VERSION = process.env.NEXT_PUBLIC_APP_VERSION ?? 'v1.5-dev'

function getLoginErrorMessage(error: unknown) {
  const apiUrl = process.env.NEXT_PUBLIC_API_URL
    ?? (typeof globalThis.window === 'object' ? `${globalThis.location.origin}/api` : '/api')

  if (!axios.isAxiosError(error)) {
    return 'Sign-in failed before the server returned a usable response. Try again and check the browser console if it repeats.'
  }

  if (!error.response) {
    return `Cannot reach the Argus API at ${apiUrl}. Check that the backend container is running and that the browser can reach that address.`
  }

  if (error.response.status === 401) {
    return 'Argus rejected the login with HTTP 401. Check the username and password.'
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

function getSetupErrorMessage(error: unknown) {
  if (!axios.isAxiosError(error)) {
    return 'Initial setup failed before the server returned a usable response.'
  }

  const detail = error.response?.data && typeof error.response.data === 'object'
    ? (error.response.data as { detail?: unknown }).detail
    : undefined

  if (typeof detail === 'string' && detail.trim()) {
    return detail
  }

  if (!error.response) {
    return 'Cannot reach the Argus API to complete setup.'
  }

  return `Initial setup failed with HTTP ${error.response.status}.`
}

interface LoginPageClientProps {
  initialNextPath: string
}

export function LoginPageClient({ initialNextPath }: Readonly<LoginPageClientProps>) {
  const router = useRouter()
  const { data: currentUser, isLoading: isLoadingUser } = useCurrentUser()
  const { data: setupStatus, isLoading: isLoadingSetup } = useSetupStatus()
  const { mutate: login, isPending: isPendingLogin } = useLogin()
  const { mutate: initializeFirstAdmin, isPending: isPendingSetup } = useInitializeFirstAdmin()
  const nextPath = initialNextPath
  const [username, setUsername] = useState(() => {
    if (typeof globalThis.window === 'object') {
      return globalThis.window.localStorage.getItem(SAVED_USERNAME_KEY) ?? ''
    }
    return ''
  })
  const [password, setPassword] = useState('')
  const [rememberMe, setRememberMe] = useState(false)
  const [setupUsername, setSetupUsername] = useState('admin')
  const [setupEmail, setSetupEmail] = useState('')
  const [setupPassword, setSetupPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (currentUser) {
      router.replace(nextPath)
    }
  }, [currentUser, nextPath, router])

  const handleLoginSubmit: FormSubmitHandler = (event) => {
    event.preventDefault()
    setError(null)

    login(
      { username, password, rememberMe },
      {
        onSuccess: () => router.replace(nextPath),
        onError: (submitError) => setError(getLoginErrorMessage(submitError)),
      },
    )
  }

  const handleSetupSubmit: FormSubmitHandler = (event) => {
    event.preventDefault()
    setError(null)

    if (setupPassword !== confirmPassword) {
      setError('Password confirmation does not match.')
      return
    }

    initializeFirstAdmin(
      {
        username: setupUsername.trim(),
        password: setupPassword,
        email: setupEmail.trim() || undefined,
      },
      {
        onSuccess: () => router.replace(nextPath),
        onError: (submitError) => setError(getSetupErrorMessage(submitError)),
      },
    )
  }

  const needsSetup = setupStatus?.needs_setup ?? false
  const isBusy = isLoadingUser || isLoadingSetup || isPendingLogin || isPendingSetup

  return (
    <main className="relative min-h-screen bg-[radial-gradient(circle_at_top,_rgba(14,165,233,0.18),_transparent_35%),linear-gradient(180deg,_#f8fafc,_#e2e8f0)] dark:bg-[radial-gradient(circle_at_top,_rgba(14,165,233,0.24),_transparent_35%),linear-gradient(180deg,_#09090b,_#18181b)] flex items-center justify-center px-6">
      <div className="w-full max-w-md rounded-3xl border border-white/60 dark:border-zinc-800 bg-white/90 dark:bg-zinc-950/90 backdrop-blur-xl shadow-2xl shadow-sky-500/10 p-8">
        <div className="flex items-center gap-3 mb-8">
          <div className="w-11 h-11 rounded-2xl bg-sky-500 flex items-center justify-center shadow-lg shadow-sky-500/30">
            <Eye className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-zinc-950 dark:text-white">Argus</h1>
            <p className="text-sm text-zinc-500">
              {needsSetup ? 'Create the first administrator account to finish setup.' : 'Sign in to access your network inventory.'}
            </p>
          </div>
        </div>

        {needsSetup ? (
          <form onSubmit={handleSetupSubmit} className="space-y-4">
            <div className="rounded-xl border border-sky-200 bg-sky-50 px-4 py-3 text-sm text-sky-700 dark:border-sky-900 dark:bg-sky-950/30 dark:text-sky-200">
              No user accounts exist yet. Argus will create the first account as an administrator.
            </div>

            <div>
              <label htmlFor="setup-username" className="block text-sm font-medium text-zinc-700 dark:text-zinc-200 mb-1.5">
                Admin username
              </label>
              <input
                id="setup-username"
                value={setupUsername}
                onChange={(event) => setSetupUsername(event.target.value)}
                className="w-full rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 px-4 py-3 text-sm outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20"
                autoComplete="username"
              />
            </div>

            <div>
              <label htmlFor="setup-email" className="block text-sm font-medium text-zinc-700 dark:text-zinc-200 mb-1.5">
                Email
              </label>
              <input
                id="setup-email"
                type="email"
                value={setupEmail}
                onChange={(event) => setSetupEmail(event.target.value)}
                className="w-full rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 px-4 py-3 text-sm outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20"
                autoComplete="email"
              />
            </div>

            <div>
              <label htmlFor="setup-password" className="block text-sm font-medium text-zinc-700 dark:text-zinc-200 mb-1.5">
                Password
              </label>
              <input
                id="setup-password"
                type="password"
                value={setupPassword}
                onChange={(event) => setSetupPassword(event.target.value)}
                className="w-full rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 px-4 py-3 text-sm outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20"
                autoComplete="new-password"
              />
              <p className="mt-1 text-[11px] text-zinc-500">Use at least 10 characters.</p>
            </div>

            <div>
              <label htmlFor="confirm-password" className="block text-sm font-medium text-zinc-700 dark:text-zinc-200 mb-1.5">
                Confirm password
              </label>
              <input
                id="confirm-password"
                type="password"
                value={confirmPassword}
                onChange={(event) => setConfirmPassword(event.target.value)}
                className="w-full rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 px-4 py-3 text-sm outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20"
                autoComplete="new-password"
              />
            </div>

            {error && (
              <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-600 dark:border-red-950 dark:bg-red-950/40 dark:text-red-300">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={isBusy}
              className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-sky-500 px-4 py-3 text-sm font-medium text-white shadow-lg shadow-sky-500/25 transition hover:bg-sky-600 disabled:cursor-not-allowed disabled:opacity-70"
            >
              {isPendingSetup && <Loader2 className="h-4 w-4 animate-spin" />}
              Create admin account
            </button>
          </form>
        ) : (
          <form onSubmit={handleLoginSubmit} className="space-y-4">
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-zinc-700 dark:text-zinc-200 mb-1.5">
                Username
              </label>
              <input
                id="username"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                className="w-full rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 px-4 py-3 text-sm outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20"
                autoComplete="username"
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-zinc-700 dark:text-zinc-200 mb-1.5">
                Password
              </label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                className="w-full rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 px-4 py-3 text-sm outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20"
                autoComplete="current-password"
              />
            </div>

            <label className="flex items-center gap-2 text-sm text-zinc-600 dark:text-zinc-300">
              <input
                type="checkbox"
                checked={rememberMe}
                onChange={(event) => setRememberMe(event.target.checked)}
                className="h-4 w-4 rounded border-zinc-300 text-sky-500 focus:ring-sky-500"
              />
              Remember me on this device
            </label>

            {error && (
              <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-600 dark:border-red-950 dark:bg-red-950/40 dark:text-red-300">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={isBusy}
              className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-sky-500 px-4 py-3 text-sm font-medium text-white shadow-lg shadow-sky-500/25 transition hover:bg-sky-600 disabled:cursor-not-allowed disabled:opacity-70"
            >
              {isPendingLogin && <Loader2 className="h-4 w-4 animate-spin" />}
              Sign in
            </button>
          </form>
        )}

        <div className="mt-8 flex items-center justify-between text-[11px] uppercase tracking-[0.2em] text-zinc-400">
          <span>Argus</span>
          <span>{APP_VERSION}</span>
        </div>
      </div>
    </main>
  )
}
