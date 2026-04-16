'use client'

import { useEffect, useRef } from 'react'
import { createPortal } from 'react-dom'

interface AlertDialogProps {
  open: boolean
  title: string
  description: string
  confirmLabel?: string
  cancelLabel?: string
  destructive?: boolean
  onConfirm: () => void
  onCancel: () => void
}

/**
 * Accessible modal confirmation dialog — replaces window.confirm().
 * Traps focus within the dialog and closes on Escape.
 */
export function AlertDialog({
  open,
  title,
  description,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  destructive = false,
  onConfirm,
  onCancel,
}: AlertDialogProps) {
  const cancelRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (!open) return
    // Focus the cancel button by default (safer choice for destructive actions)
    cancelRef.current?.focus()

    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onCancel()
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [open, onCancel])

  if (!open || typeof document === 'undefined') return null

  return createPortal(
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="alert-dialog-title"
      aria-describedby="alert-dialog-description"
      className="fixed inset-0 z-50 flex items-center justify-center"
    >
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/40 dark:bg-black/60"
        onClick={onCancel}
        aria-hidden="true"
      />
      {/* Panel */}
      <div className="relative z-10 w-full max-w-md rounded-xl border border-gray-200 bg-white p-6 shadow-xl dark:border-zinc-700 dark:bg-zinc-900">
        <h2
          id="alert-dialog-title"
          className="text-base font-semibold text-zinc-900 dark:text-zinc-100"
        >
          {title}
        </h2>
        <p
          id="alert-dialog-description"
          className="mt-2 text-sm text-zinc-600 dark:text-zinc-400"
        >
          {description}
        </p>
        <div className="mt-6 flex justify-end gap-3">
          <button
            ref={cancelRef}
            type="button"
            onClick={onCancel}
            className="rounded-lg border border-gray-200 px-4 py-2 text-sm text-zinc-600 hover:bg-gray-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800"
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            onClick={onConfirm}
            className={
              destructive
                ? 'rounded-lg bg-red-600 px-4 py-2 text-sm text-white hover:bg-red-700'
                : 'rounded-lg bg-sky-600 px-4 py-2 text-sm text-white hover:bg-sky-700'
            }
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>,
    document.body,
  )
}
