'use client'

import { Component, type ReactNode } from 'react'

interface Props {
  children: ReactNode
}

interface State {
  hasError: boolean
  message: string
}

/**
 * App-shell error boundary. Catches component-level render errors and shows
 * a fallback with navigation links so the user can reach another page without
 * a full reload.
 */
export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, message: '' }
  }

  static getDerivedStateFromError(error: unknown): State {
    const message = error instanceof Error ? error.message : String(error)
    return { hasError: true, message }
  }

  override componentDidCatch(error: unknown, info: { componentStack?: string | null }) {
    // Log to console for developer visibility; swap for an error reporting service if desired.
    console.error('[ErrorBoundary]', error, info.componentStack)
  }

  override render() {
    if (!this.state.hasError) return this.props.children

    return (
      <div className="min-h-screen bg-gray-50 dark:bg-zinc-950 flex items-center justify-center p-6">
        <div className="w-full max-w-md rounded-xl border border-gray-200 bg-white p-8 shadow-sm dark:border-zinc-800 dark:bg-zinc-900 text-center space-y-4">
          <div className="text-4xl">⚠</div>
          <h1 className="text-lg font-semibold text-zinc-900 dark:text-zinc-100">
            Something went wrong
          </h1>
          <p className="text-sm text-zinc-500">
            An unexpected error occurred in this page. You can navigate to another
            section — the rest of the app is unaffected.
          </p>
          {this.state.message && (
            <pre className="mt-2 max-h-28 overflow-auto rounded-lg bg-gray-100 dark:bg-zinc-800 p-3 text-left text-xs text-red-600 dark:text-red-400">
              {this.state.message}
            </pre>
          )}
          <div className="flex justify-center gap-3 pt-2">
            <a
              href="/dashboard"
              className="rounded-lg border border-gray-200 px-4 py-2 text-sm text-zinc-600 hover:bg-gray-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800"
            >
              Go to Dashboard
            </a>
            <button
              type="button"
              onClick={() => this.setState({ hasError: false, message: '' })}
              className="rounded-lg bg-sky-600 px-4 py-2 text-sm text-white hover:bg-sky-700"
            >
              Try again
            </button>
          </div>
        </div>
      </div>
    )
  }
}
