'use client'

import Link from 'next/link'
import { ArrowRight, ShieldAlert } from 'lucide-react'
import { Card, CardBody, CardHeader, CardTitle } from '@/components/ui/Card'
import { useFindingsSummary } from '@/hooks/useFindings'

export function FindingsSummary() {
  const { data, isLoading } = useFindingsSummary()

  return (
    <Card>
      <CardHeader>
        <CardTitle>Findings</CardTitle>
        <Link href="/findings" className="text-xs text-sky-500 hover:text-sky-600 flex items-center gap-1">
          View all <ArrowRight className="w-3 h-3" />
        </Link>
      </CardHeader>
      <CardBody className="space-y-3">
        {isLoading ? (
          <div className="h-24 rounded-xl bg-zinc-100 dark:bg-zinc-800 animate-pulse" />
        ) : (
          <>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center">
                <ShieldAlert className="w-5 h-5 text-red-500" />
              </div>
              <div>
                <p className="text-2xl font-bold text-zinc-900 dark:text-white">{data?.open ?? 0}</p>
                <p className="text-xs text-zinc-500">Open findings</p>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2 text-sm">
              {Object.entries(data?.severity_counts ?? {}).map(([severity, count]) => (
                <div key={severity} className="rounded-lg border border-gray-200 dark:border-zinc-800 px-3 py-2">
                  <p className="text-xs uppercase tracking-wide text-zinc-500">{severity}</p>
                  <p className="font-semibold text-zinc-900 dark:text-white">{count}</p>
                </div>
              ))}
            </div>
          </>
        )}
      </CardBody>
    </Card>
  )
}
