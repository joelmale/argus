import type { Metadata } from 'next'
import { ResetPasswordClient } from './page.client'

export const metadata: Metadata = {
  title: 'Argus | Reset password',
}

interface ResetPasswordPageProps {
  searchParams?: Promise<Record<string, string | string[] | undefined>>
}

export default async function ResetPasswordPage({ searchParams }: Readonly<ResetPasswordPageProps>) {
  const resolved = await searchParams
  const token = resolved?.token
  return <ResetPasswordClient token={(Array.isArray(token) ? token[0] : token) ?? ''} />
}
