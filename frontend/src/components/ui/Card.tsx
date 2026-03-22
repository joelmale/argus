import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

type CardProps = Readonly<{ className?: string; children: ReactNode }>
type CardTitleProps = Readonly<{ children: ReactNode }>

export function Card({ className, children }: CardProps) {
  return (
    <div className={cn(
      'rounded-xl border border-gray-200 dark:border-zinc-800',
      'bg-white dark:bg-zinc-900',
      'shadow-sm',
      className,
    )}>
      {children}
    </div>
  )
}

export function CardHeader({ className, children }: CardProps) {
  return (
    <div className={cn('flex items-center justify-between px-5 py-4 border-b border-gray-100 dark:border-zinc-800', className)}>
      {children}
    </div>
  )
}

export function CardTitle({ children }: CardTitleProps) {
  return <h3 className="text-sm font-semibold text-zinc-900 dark:text-white">{children}</h3>
}

export function CardBody({ className, children }: CardProps) {
  return <div className={cn('px-5 py-4', className)}>{children}</div>
}
