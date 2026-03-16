import { cn } from '@/lib/utils'

export function Card({ className, children }: { className?: string; children: React.ReactNode }) {
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

export function CardHeader({ className, children }: { className?: string; children: React.ReactNode }) {
  return (
    <div className={cn('flex items-center justify-between px-5 py-4 border-b border-gray-100 dark:border-zinc-800', className)}>
      {children}
    </div>
  )
}

export function CardTitle({ children }: { children: React.ReactNode }) {
  return <h3 className="text-sm font-semibold text-zinc-900 dark:text-white">{children}</h3>
}

export function CardBody({ className, children }: { className?: string; children: React.ReactNode }) {
  return <div className={cn('px-5 py-4', className)}>{children}</div>
}
