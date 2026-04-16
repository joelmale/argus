import type { Metadata } from 'next'
import { LoginPageClient } from './page.client'

export const metadata: Metadata = {
  title: 'Argus | Sign in',
}

function sanitizeNextPath(nextPath: string | string[] | undefined): string {
  const value = Array.isArray(nextPath) ? nextPath[0] : nextPath
  if (!value || !value.trim()) {
    return '/dashboard'
  }
  if (!value.startsWith('/') || value.startsWith('//')) {
    return '/dashboard'
  }
  return value
}

interface LoginPageProps {
  searchParams?: Promise<Record<string, string | string[] | undefined>>
}

export default async function LoginPage({ searchParams }: Readonly<LoginPageProps>) {
  const resolvedSearchParams = await searchParams
  return <LoginPageClient initialNextPath={sanitizeNextPath(resolvedSearchParams?.next)} />
}
