'use client'

import { AppShell } from '@/components/layout/AppShell'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'
import { ScanLine, Bell, Wifi, Brain, Database, Construction } from 'lucide-react'

const SECTIONS = [
  {
    icon: ScanLine,
    title: 'Scan Configuration',
    desc: 'Default targets, scan intervals, concurrent host limits, port ranges.',
  },
  {
    icon: Brain,
    title: 'AI Agent',
    desc: 'AI backend selection (Ollama / Anthropic), model, confidence thresholds.',
  },
  {
    icon: Wifi,
    title: 'Network & SNMP',
    desc: 'SNMP community strings, mDNS interfaces, passive ARP listener settings.',
  },
  {
    icon: Bell,
    title: 'Notifications',
    desc: 'Webhook endpoints, alert rules for new devices, offline hosts, findings.',
  },
  {
    icon: Database,
    title: 'Data Retention',
    desc: 'Asset history TTL, scan job cleanup, topology snapshot frequency.',
  },
]

export default function SettingsPage() {
  return (
    <AppShell>
      <div className="max-w-3xl mx-auto space-y-6">
        <div>
          <h2 className="text-xl font-bold text-zinc-900 dark:text-white">Settings</h2>
          <p className="text-sm text-zinc-500 mt-0.5">Configuration for Argus scans, AI, and notifications.</p>
        </div>

        {/* Coming soon banner */}
        <div className="flex items-start gap-3 p-4 rounded-xl bg-yellow-500/10 border border-yellow-500/20">
          <Construction className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-medium text-yellow-700 dark:text-yellow-400">Settings UI coming soon</p>
            <p className="text-xs text-yellow-600/80 dark:text-yellow-400/70 mt-0.5">
              Configure Argus via <span className="font-mono">.env</span> for now.
              A full settings UI is planned for a future release.
            </p>
          </div>
        </div>

        {/* Upcoming sections preview */}
        <div className="space-y-3">
          {SECTIONS.map(({ icon: Icon, title, desc }) => (
            <Card key={title} className="opacity-60 pointer-events-none select-none">
              <CardBody>
                <div className="flex items-start gap-3">
                  <div className="w-9 h-9 rounded-lg bg-zinc-100 dark:bg-zinc-800 flex items-center justify-center flex-shrink-0">
                    <Icon className="w-4 h-4 text-zinc-500" />
                  </div>
                  <div>
                    <p className="text-sm font-medium text-zinc-800 dark:text-zinc-200">{title}</p>
                    <p className="text-xs text-zinc-500 mt-0.5">{desc}</p>
                  </div>
                  <span className="ml-auto text-xs px-2 py-0.5 rounded-full bg-zinc-100 dark:bg-zinc-800 text-zinc-500">
                    Planned
                  </span>
                </div>
              </CardBody>
            </Card>
          ))}
        </div>

        {/* .env reference */}
        <Card>
          <CardHeader>
            <CardTitle><Database className="w-4 h-4 inline mr-1.5" />Environment Variables</CardTitle>
          </CardHeader>
          <CardBody>
            <p className="text-xs text-zinc-500 mb-3">
              All Argus settings are currently configured via environment variables in <span className="font-mono">.env</span>.
              See <span className="font-mono">.env.example</span> in the project root for all available options.
            </p>
            <div className="rounded-lg bg-zinc-900 text-zinc-300 p-4 text-xs font-mono space-y-1 overflow-x-auto">
              {[
                '# Scanner',
                'SCANNER_DEFAULT_TARGETS=192.168.1.0/24',
                'SCANNER_INTERVAL_MINUTES=60',
                'SCANNER_DEFAULT_PROFILE=balanced',
                'SCANNER_CONCURRENT_HOSTS=10',
                '',
                '# AI Agent',
                'AI_BACKEND=ollama',
                'OLLAMA_BASE_URL=http://ollama:11434/v1',
                'OLLAMA_MODEL=qwen2.5:7b',
                '# ANTHROPIC_API_KEY=sk-ant-...',
              ].map((line, i) => (
                <div key={i}>
                  <span className={line.startsWith('#') ? 'text-zinc-500' : line === '' ? '' : 'text-emerald-400'}>
                    {line || '\u00a0'}
                  </span>
                </div>
              ))}
            </div>
          </CardBody>
        </Card>
      </div>
    </AppShell>
  )
}
