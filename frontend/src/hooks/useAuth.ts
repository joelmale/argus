'use client'

import { useSyncExternalStore } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { authApi, TOKEN_STORAGE_KEY } from '@/lib/api'
import type { CurrentUser } from '@/types'

const AUTH_EVENT = 'argus-auth-changed'

function emitAuthChange() {
  window.dispatchEvent(new Event(AUTH_EVENT))
}

function getStoredToken() {
  return typeof window === 'undefined' ? null : localStorage.getItem(TOKEN_STORAGE_KEY)
}

export function setAuthToken(token: string) {
  localStorage.setItem(TOKEN_STORAGE_KEY, token)
  emitAuthChange()
}

export function clearAuthToken() {
  localStorage.removeItem(TOKEN_STORAGE_KEY)
  emitAuthChange()
}

export function useAuthToken() {
  return useSyncExternalStore(
    (onStoreChange) => {
      window.addEventListener(AUTH_EVENT, onStoreChange)
      window.addEventListener('storage', onStoreChange)
      return () => {
        window.removeEventListener(AUTH_EVENT, onStoreChange)
        window.removeEventListener('storage', onStoreChange)
      }
    },
    getStoredToken,
    () => null,
  )
}

export function useCurrentUser() {
  const token = useAuthToken()

  return useQuery<CurrentUser>({
    queryKey: ['auth', 'me', token],
    queryFn: async () => {
      const { data } = await authApi.me()
      return data
    },
    enabled: !!token,
    retry: false,
  })
}

export function useLogin() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async ({ username, password }: { username: string; password: string }) => {
      const { data } = await authApi.login(username, password)
      return data as { access_token: string; token_type: string }
    },
    onSuccess: async (data) => {
      setAuthToken(data.access_token)
      await queryClient.invalidateQueries({ queryKey: ['auth', 'me'] })
    },
  })
}

export function useLogout() {
  const queryClient = useQueryClient()

  return () => {
    clearAuthToken()
    queryClient.removeQueries({ queryKey: ['auth'] })
  }
}
