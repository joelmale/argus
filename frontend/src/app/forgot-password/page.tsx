'use client'

import { useState, type ComponentProps } from 'react'
import Link from 'next/link'
import { Eye, Loader2 } from 'lucide-react'
import { useForgotPassword } from '@/hooks/useAuth'

type FormSubmitHandler = NonNullable<ComponentProps<'form'>['onSubmit']>

export default function ForgotPasswordPage() {
  const { mutate: requestReset, isPending, isSuccess, isError } = useForgotPassword()
  const [identifier, setIdentifier] = useState('')

  const handleSubmit: FormSubmitHandler = (event) => {
    event.preventDefault()
    requestReset(identifier.trim())
  }

  return (
    <main className="min-h-screen bg-gray-50 dark:bg-zinc-950 flex items-center justify-center px-6">
      <div className="w-full max-w-md rounded-3xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950 shadow-xl p-8">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-11 h-11 rounded-2xl bg-sky-500 flex items-center justify-center">
            <Eye className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-zinc-950 dark:text-white">Reset password</h1>
            <p className="text-sm text-zinc-500">We&apos;ll email you a reset link.</p>
          </div>
        </div>

        {isSuccess ? (
          <div className="rounded-xl border border-sky-200 bg-sky-50 px-4 py-3 text-sm text-sky-700 dark:border-sky-900 dark:bg-sky-950/30 dark:text-sky-200">
            If that account exists and has an email address, a reset link has been sent. The link expires shortly.
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="identifier" className="block text-sm font-medium text-zinc-700 dark:text-zinc-200 mb-1.5">
                Username or email
              </label>
              <input
                id="identifier"
                value={identifier}
                onChange={(event) => setIdentifier(event.target.value)}
                className="w-full rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 px-4 py-3 text-sm outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20"
                autoComplete="username"
              />
            </div>
            {isError && (
              <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-600 dark:border-red-950 dark:bg-red-950/40 dark:text-red-300">
                Could not send the request. Try again in a minute.
              </div>
            )}
            <button
              type="submit"
              disabled={isPending || !identifier.trim()}
              className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-sky-500 px-4 py-3 text-sm font-medium text-white transition hover:bg-sky-600 disabled:cursor-not-allowed disabled:opacity-70"
            >
              {isPending && <Loader2 className="h-4 w-4 animate-spin" />}
              Send reset link
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
