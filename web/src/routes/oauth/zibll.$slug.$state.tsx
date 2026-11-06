/*
Copyright (C) 2023-2026 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please contact support@quantumnous.com
*/
import {
  createFileRoute,
  useNavigate,
  useParams,
} from '@tanstack/react-router'
import i18next from 'i18next'
import { useEffect, useRef } from 'react'
import { toast } from 'sonner'

import { OAuthCallbackScreen } from '@/features/auth/components/oauth-callback-screen'
import {
  OAUTH_POPUP_CALLBACK_MESSAGE,
  OAUTH_POPUP_RESULT_MESSAGE,
} from '@/features/auth/constants'
import { useAuthRedirect } from '@/features/auth/hooks/use-auth-redirect'
import {
  getOAuthSessionStorage,
  consumeOAuthLoginRedirect,
  resolveOAuthCallbackMode,
} from '@/features/auth/lib/oauth-callback-mode'
import { startOAuthBindResponseDeadline } from '@/features/auth/lib/oauth-bind-window'
import type { LoginResponse } from '@/features/auth/types'
import { api } from '@/lib/api'
import { handleServerError } from '@/lib/handle-server-error'
import { AuthOperationError } from '@/lib/secure-verification'
import { getServerErrorMessageKey } from '@/lib/server-error-message'

// The Zibll master site redirects here carrying the signed identity in the
// query string. The console forwards those parameters verbatim (order
// preserved — the signature is order sensitive) to the API callback endpoint.

type OAuthPopupResult = {
  intent: 'bind' | 'verify'
  type: typeof OAUTH_POPUP_RESULT_MESSAGE
  provider: string
  state: string
  success: boolean
  message?: string
}

function ZibllOAuthCallback() {
  const navigate = useNavigate()
  const { handleLoginResult } = useAuthRedirect()
  const completedLogin = useRef<string | null>(null)
  const { slug, state } = useParams({ from: '/oauth/zibll/$slug/$state' }) as {
    slug: string
    state: string
  }

  let mode: 'login' | 'bind' | 'verify' = 'login'
  if (typeof window !== 'undefined') {
    mode = resolveOAuthCallbackMode(slug, state, {
      opener: window.opener,
      storage: getOAuthSessionStorage(window),
    })
  }

  useEffect(() => {
    if (typeof window === 'undefined') return

    const rawQuery = window.location.search.replace(/^\?/, '')

    if (mode === 'bind' || mode === 'verify') {
      const opener = window.opener
      if (!opener || opener.closed) {
        toast.error(i18next.t('OAuth window is no longer available.'))
        return
      }

      let cancelResultTimeout: () => void = () => undefined
      let delayedClose: number | undefined
      const handleBindingResult = (event: MessageEvent<unknown>) => {
        if (
          event.origin !== window.location.origin ||
          event.source !== opener
        ) {
          return
        }
        const result = event.data as Partial<OAuthPopupResult> | null
        if (
          !result ||
          result.type !== OAUTH_POPUP_RESULT_MESSAGE ||
          result.intent !== mode ||
          result.provider !== slug ||
          result.state !== state
        ) {
          return
        }
        cancelResultTimeout()
        if (result.success) {
          if (mode === 'bind') toast.success(i18next.t('Binding successful!'))
          window.close()
          return
        }
        handleServerError(result, i18next.t('OAuth failed'))
        delayedClose = window.setTimeout(() => window.close(), 1500)
      }

      window.addEventListener('message', handleBindingResult)
      cancelResultTimeout = startOAuthBindResponseDeadline(() => {
        toast.error(
          i18next.t('OAuth authorization timed out. Please try again.')
        )
        delayedClose = window.setTimeout(() => window.close(), 1500)
      })
      opener.postMessage(
        {
          type: OAUTH_POPUP_CALLBACK_MESSAGE,
          intent: mode,
          provider: slug,
          state,
          zibllQuery: rawQuery,
          error: undefined,
          errorDescription: undefined,
        },
        window.location.origin
      )
      return () => {
        window.removeEventListener('message', handleBindingResult)
        cancelResultTimeout()
        if (delayedClose !== undefined) window.clearTimeout(delayedClose)
      }
    }

    const loginKey = `${slug}:${state}`
    if (completedLogin.current === loginKey) return
    let active = true
    void (async () => {
      try {
        // Append the flow state after the master site's parameters so the
        // signed parameter order stays byte-identical to the redirect.
        const query = rawQuery
          ? `${rawQuery}&state=${encodeURIComponent(state)}`
          : `state=${encodeURIComponent(state)}`
        const response = await api.get<LoginResponse>(
          `/api/oauth/zibll/callback/${encodeURIComponent(slug)}?${query}`,
          {
            skipBusinessError: true,
            skipAuthRefresh: true,
          }
        )
        if (!active) return
        if (response.data?.success) {
          completedLogin.current = loginKey
          if (
            await handleLoginResult(
              response.data.data,
              consumeOAuthLoginRedirect(state) ?? undefined
            )
          ) {
            toast.success(i18next.t('Signed in successfully!'))
          }
          return
        }
        const messageKey = getServerErrorMessageKey(response.data)
        handleServerError(
          response.data,
          messageKey
            ? i18next.t(messageKey)
            : response.data?.message || i18next.t('OAuth failed')
        )
      } catch (error: unknown) {
        if (!active) return
        handleServerError(
          AuthOperationError.from(error, i18next.t('OAuth failed'))
        )
      }
      void navigate({ href: '/sign-in', replace: true })
    })()
    return () => {
      active = false
    }
  }, [mode, navigate, handleLoginResult, slug, state])

  return <OAuthCallbackScreen provider={slug} mode={mode} />
}

export const Route = createFileRoute('/oauth/zibll/$slug/$state')({
  component: ZibllOAuthCallback,
})
