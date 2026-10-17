'use client'

import { useState, type ComponentProps } from 'react'
import axios from 'axios'
import Link from 'next/link'
import { Eye, Loader2 } from 'lucide-react'
import { useResetPassword } from '@/hooks/useAuth'

type FormSubmitHandler = NonNullable<ComponentProps<'form'>['onSubmit']>

function getErrorMessage(error: unknown) {
  if (axios.isAxiosError(error)) {
    const detail = (error.response?.data as { detail?: unknown } | undefined)?.detail
    if (typeof detail === 'string' && detail.trim()) {
      return detail
    }
  }
  return 'Could not reset the password. Request a new link and try again.'
}

export function ResetPasswordClient({ token }: Readonly<{ token: string }>) {
  const { mutate: resetPassword, isPending, isSuccess, error } = useResetPassword()
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [localError, setLocalError] = useState<string | null>(null)

  const handleSubmit: FormSubmitHandler = (event) => {
    event.preventDefault()
    setLocalError(null)
    if (password !== confirmPassword) {
      setLocalError('Password confirmation does not match.')
      return
    }
    resetPassword({ token, password })
  }

  const message = localError ?? (error ? getErrorMessage(error) : null)

  return (
    <main className="min-h-screen bg-gray-50 dark:bg-zinc-950 flex items-center justify-center px-6">
      <div className="w-full max-w-md rounded-3xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950 shadow-xl p-8">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-11 h-11 rounded-2xl bg-sky-500 flex items-center justify-center">
            <Eye className="w-6 h-6 text-white" />
          </div>
          <h1 className="text-xl font-semibold text-zinc-950 dark:text-white">Choose a new password</h1>
        </div>

        {!token ? (
          <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-600 dark:border-red-950 dark:bg-red-950/40 dark:text-red-300">
            This reset link is missing its token. Request a new one.
          </div>
        ) : isSuccess ? (
          <div className="rounded-xl border border-sky-200 bg-sky-50 px-4 py-3 text-sm text-sky-700 dark:border-sky-900 dark:bg-sky-950/30 dark:text-sky-200">
            Password updated. You can sign in now.
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="new-password" className="block text-sm font-medium text-zinc-700 dark:text-zinc-200 mb-1.5">
                New password
              </label>
              <input
                id="new-password"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                className="w-full rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 px-4 py-3 text-sm outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20"
                autoComplete="new-password"
              />
            </div>
            <div>
              <label htmlFor="confirm-new-password" className="block text-sm font-medium text-zinc-700 dark:text-zinc-200 mb-1.5">
                Confirm password
              </label>
              <input
                id="confirm-new-password"
                type="password"
                value={confirmPassword}
                onChange={(event) => setConfirmPassword(event.target.value)}
                className="w-full rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 px-4 py-3 text-sm outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20"
                autoComplete="new-password"
              />
            </div>
            {message && (
              <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-600 dark:border-red-950 dark:bg-red-950/40 dark:text-red-300">
                {message}
              </div>
            )}
            <button
              type="submit"
              disabled={isPending || !password}
              className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-sky-500 px-4 py-3 text-sm font-medium text-white transition hover:bg-sky-600 disabled:cursor-not-allowed disabled:opacity-70"
            >
              {isPending && <Loader2 className="h-4 w-4 animate-spin" />}
              Update password
            </button>
          </form>
        )}

        <div className="mt-6 text-center">
          <Link href="/login" className="text-sm text-sky-600 hover:underline dark:text-sky-400">Back to sign in</Link>
        </div>
      </div>
    </main>
  )
}
