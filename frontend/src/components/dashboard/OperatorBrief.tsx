'use client'

import Link from 'next/link'
import type { ElementType } from 'react'
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  HelpCircle,
  Loader2,
  RadioTower,
  ShieldAlert,
  Sparkles,
} from 'lucide-react'
import { Card, CardBody, CardHeader, CardTitle } from '@/components/ui/Card'
import { useCurrentUser } from '@/hooks/useAuth'
import { useOperatorBrief } from '@/hooks/useOperatorBrief'
import { cn, severityColor, timeAgo } from '@/lib/utils'
import type { OperatorBriefItem, OperatorBriefSection } from '@/types'

const SECTION_META = {
  changed: { icon: Sparkles, color: 'text-sky-500', empty: 'No material changes in the current window.' },
  attention: { icon: AlertTriangle, color: 'text-amber-500', empty: 'No urgent operational items.' },
  unknowns: { icon: HelpCircle, color: 'text-violet-500', empty: 'No unresolved inventory items.' },
  risk: { icon: ShieldAlert, color: 'text-red-500', empty: 'No high-risk items currently open.' },
  recommendations: { icon: CheckCircle2, color: 'text-emerald-500', empty: 'No recommended actions right now.' },
} satisfies Record<string, { icon: ElementType; color: string; empty: string }>

function sectionMeta(key: string) {
  return SECTION_META[key as keyof typeof SECTION_META] ?? {
    icon: RadioTower,
    color: 'text-zinc-500',
    empty: 'No items.',
  }
}

function BriefItemRow({
  item,
  isViewer,
}: Readonly<{
  item: OperatorBriefItem
  isViewer: boolean
}>) {
  const route = item.action?.route || item.route
  const disabled = Boolean(item.action?.requires_admin && isViewer)
  return (
    <div className="rounded-lg border border-gray-100 bg-zinc-50 px-3 py-2.5 dark:border-zinc-800 dark:bg-zinc-950">
      <div className="flex items-start gap-2">
        <span className={cn('mt-0.5 rounded-full border px-2 py-0.5 text-[11px] capitalize', severityColor(item.severity))}>
          {item.severity}
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">{item.title}</p>
          <p className="mt-0.5 text-xs text-zinc-500">{item.reason}</p>
          {item.occurred_at && (
            <p className="mt-1 text-[11px] text-zinc-400">{timeAgo(item.occurred_at)}</p>
          )}
        </div>
      </div>
      {route && (
        <div className="mt-2">
          {disabled ? (
            <span className="inline-flex items-center gap-1.5 rounded-md border border-gray-200 px-2.5 py-1 text-xs text-zinc-400 dark:border-zinc-800">
              Admin action
            </span>
          ) : (
            <Link
              href={route}
              className="inline-flex items-center gap-1.5 rounded-md border border-sky-200 px-2.5 py-1 text-xs font-medium text-sky-600 hover:bg-sky-50 dark:border-sky-900 dark:text-sky-300 dark:hover:bg-sky-950/30"
            >
              {item.action?.label || 'Open'}
              <ArrowRight className="h-3 w-3" />
            </Link>
          )}
        </div>
      )}
    </div>
  )
}

function BriefSectionCard({
  section,
  isViewer,
}: Readonly<{
  section: OperatorBriefSection
  isViewer: boolean
}>) {
  const meta = sectionMeta(section.key)
  const Icon = meta.icon
  return (
    <div className="rounded-xl border border-gray-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-900">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Icon className={cn('h-4 w-4', meta.color)} />
            <h4 className="text-sm font-semibold text-zinc-900 dark:text-white">{section.title}</h4>
          </div>
          <p className="mt-1 text-xs text-zinc-500">{section.question}</p>
        </div>
        <span className="rounded-full bg-zinc-100 px-2 py-0.5 text-xs text-zinc-500 dark:bg-zinc-800">
          {section.total}
        </span>
      </div>
      <div className="mt-3 space-y-2">
        {section.items.length === 0 ? (
          <p className="rounded-lg border border-dashed border-gray-200 px-3 py-3 text-xs text-zinc-400 dark:border-zinc-800">
            {meta.empty}
          </p>
        ) : (
          section.items.slice(0, 3).map((item) => (
            <BriefItemRow key={item.key} item={item} isViewer={isViewer} />
          ))
        )}
      </div>
    </div>
  )
}

export function OperatorBrief() {
  const { data: brief, isLoading, isError } = useOperatorBrief()
  const { data: currentUser } = useCurrentUser()
  const isViewer = currentUser?.role === 'viewer'

  if (isLoading) {
    return (
      <Card>
        <CardBody className="flex items-center gap-3 text-sm text-zinc-500">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading operator brief...
        </CardBody>
      </Card>
    )
  }

  if (isError || !brief) {
    return (
      <Card>
        <CardBody className="text-sm text-red-500">
          Failed to load operator brief.
        </CardBody>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader className="items-start gap-3">
        <div>
          <CardTitle>Operator Brief</CardTitle>
          <p className="mt-1 text-xs text-zinc-500">
            {brief.summary.attention} attention | {brief.summary.unknowns} unknown | {brief.summary.risk} risk
          </p>
        </div>
        <p className="text-xs text-zinc-400">{timeAgo(brief.generated_at)}</p>
      </CardHeader>
      <CardBody>
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
          {brief.sections.map((section) => (
            <BriefSectionCard key={section.key} section={section} isViewer={isViewer} />
          ))}
        </div>
      </CardBody>
    </Card>
  )
}
