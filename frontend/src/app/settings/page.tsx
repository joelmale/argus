'use client'

import { useState } from 'react'
import { AppShell } from '@/components/layout/AppShell'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'
import { ScanLine, Bell, Wifi, Brain, Database, Construction, Shield, UserPlus } from 'lucide-react'
import { useCreateUser, useCurrentUser, useUpdateUser, useUsers } from '@/hooks/useAuth'

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
  const { data: currentUser } = useCurrentUser()
  const { data: users = [] } = useUsers(currentUser?.role === 'admin')
  const { mutate: createUser, isPending: isCreatingUser } = useCreateUser()
  const { mutate: updateUser, isPending: isUpdatingUser } = useUpdateUser()
  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newRole, setNewRole] = useState<'admin' | 'viewer'>('viewer')
  const [userError, setUserError] = useState<string | null>(null)

  function handleCreateUser(event: React.FormEvent) {
    event.preventDefault()
    setUserError(null)
    createUser(
      { username: newUsername.trim(), password: newPassword, role: newRole },
      {
        onSuccess: () => {
          setNewUsername('')
          setNewPassword('')
          setNewRole('viewer')
        },
        onError: () => setUserError('Unable to create user. Check for duplicate usernames or emails.'),
      },
    )
  }

  return (
    <AppShell>
      <div className="max-w-3xl mx-auto space-y-6">
        <div>
          <h2 className="text-xl font-bold text-zinc-900 dark:text-white">Settings</h2>
          <p className="text-sm text-zinc-500 mt-0.5">Configuration for Argus scans, AI, and notifications.</p>
        </div>

        {currentUser?.role === 'viewer' && (
          <div className="flex items-start gap-3 p-4 rounded-xl bg-red-500/10 border border-red-500/20">
            <Construction className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-red-700 dark:text-red-400">Admin access required</p>
              <p className="text-xs text-red-600/80 dark:text-red-400/70 mt-0.5">
                Viewer accounts can inspect Argus data, but settings are limited to admins.
              </p>
            </div>
          </div>
        )}

        {currentUser?.role === 'admin' && (
          <Card>
            <CardHeader>
              <CardTitle><Shield className="w-4 h-4 inline mr-1.5" />User Management</CardTitle>
            </CardHeader>
            <CardBody className="space-y-5">
              <form onSubmit={handleCreateUser} className="grid grid-cols-1 md:grid-cols-[1fr_1fr_140px_auto] gap-3">
                <input
                  value={newUsername}
                  onChange={(event) => setNewUsername(event.target.value)}
                  placeholder="Username"
                  className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
                />
                <input
                  type="password"
                  value={newPassword}
                  onChange={(event) => setNewPassword(event.target.value)}
                  placeholder="Temporary password"
                  className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
                />
                <select
                  value={newRole}
                  onChange={(event) => setNewRole(event.target.value as 'admin' | 'viewer')}
                  className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
                >
                  <option value="viewer">Viewer</option>
                  <option value="admin">Admin</option>
                </select>
                <button
                  type="submit"
                  disabled={isCreatingUser || !newUsername.trim() || !newPassword}
                  className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm bg-sky-500 text-white disabled:bg-zinc-300 disabled:text-zinc-500 dark:disabled:bg-zinc-800"
                >
                  <UserPlus className="w-4 h-4" /> Create
                </button>
              </form>
              {userError && <p className="text-xs text-red-500">{userError}</p>}

              <div className="space-y-3">
                {users.map((user) => (
                  <div key={user.id} className="flex flex-col md:flex-row md:items-center gap-3 rounded-xl border border-gray-200 dark:border-zinc-800 p-4">
                    <div className="flex-1">
                      <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">{user.username}</p>
                      <p className="text-xs text-zinc-500">
                        {user.email || 'No email'} · created {new Date(user.created_at).toLocaleDateString()}
                      </p>
                    </div>
                    <select
                      value={user.role}
                      disabled={isUpdatingUser}
                      onChange={(event) => updateUser({ id: user.id, payload: { role: event.target.value as 'admin' | 'viewer' } })}
                      className="px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
                    >
                      <option value="viewer">Viewer</option>
                      <option value="admin">Admin</option>
                    </select>
                    <label className="inline-flex items-center gap-2 text-sm text-zinc-600 dark:text-zinc-300">
                      <input
                        type="checkbox"
                        checked={user.is_active}
                        disabled={isUpdatingUser}
                        onChange={(event) => updateUser({ id: user.id, payload: { is_active: event.target.checked } })}
                      />
                      Active
                    </label>
                  </div>
                ))}
              </div>
            </CardBody>
          </Card>
        )}

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
        <div className={currentUser?.role === 'viewer' ? 'space-y-3 opacity-50 pointer-events-none' : 'space-y-3'}>
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
