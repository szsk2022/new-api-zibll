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
import { Loader2 } from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { api } from '@/lib/api'
import { handleServerError } from '@/lib/handle-server-error'
import { AuthOperationError } from '@/lib/secure-verification'

import { Dialog } from '@/components/dialog'

type ZibllGzhDialogProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
  state: string
}

type GzhCheckResponse = {
  success: boolean
  message?: string
  data?: {
    status?: 'waiting' | 'done'
    goto?: string
    qr_url?: string
  }
}

const POLL_INTERVAL_MS = 2500

/**
 * Zibll weixingzh (WeChat official account) login dialog: shows the official
 * account QR code from the master site and polls for the scan result, with a
 * verification-code fallback for accounts that cannot scan.
 */
export function ZibllGzhDialog({
  open,
  onOpenChange,
  state,
}: ZibllGzhDialogProps) {
  const { t } = useTranslation()
  const [qrUrl, setQrUrl] = useState('')
  const [qrError, setQrError] = useState('')
  const [code, setCode] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [followingGoto, setFollowingGoto] = useState(false)
  const timerRef = useRef<number | null>(null)
  const gotoRef = useRef('')

  const stopPolling = useCallback(() => {
    if (timerRef.current !== null) {
      window.clearInterval(timerRef.current)
      timerRef.current = null
    }
  }, [])

  const followGoto = useCallback(
    (goto: string) => {
      if (gotoRef.current) return
      gotoRef.current = goto
      stopPolling()
      setFollowingGoto(true)
      window.location.replace(goto)
    },
    [stopPolling]
  )

  useEffect(() => {
    if (!open || !state) return
    let active = true

    const poll = async () => {
      try {
        const res = await api.get<GzhCheckResponse>(
          `/api/oauth/zibll/weixingzh/check/${encodeURIComponent(state)}`,
          { skipBusinessError: true, skipErrorHandler: true }
        )
        if (!active) return
        const goto = res.data?.data?.goto
        if (res.data?.success && goto) {
          followGoto(goto)
        }
      } catch {
        // transient polling errors are ignored; the deadline handles hangs
      }
    }

    const start = async () => {
      setQrError('')
      setQrUrl('')
      gotoRef.current = ''
      try {
        const res = await api.post<GzhCheckResponse>(
          '/api/oauth/zibll/weixingzh/qr',
          null,
          { params: { state }, skipBusinessError: true, skipErrorHandler: true }
        )
        if (!active) return
        const qr = res.data?.data?.qr_url
        if (res.data?.success && qr) {
          setQrUrl(qr)
          timerRef.current = window.setInterval(poll, POLL_INTERVAL_MS)
        } else {
          setQrError(
            res.data?.message || t('Failed to load the QR code, please retry.')
          )
        }
      } catch (error) {
        if (!active) return
        setQrError(t('Failed to load the QR code, please retry.'))
        handleServerError(
          AuthOperationError.from(error, t('Failed to load the QR code.'))
        )
      }
    }
    void start()

    return () => {
      active = false
      stopPolling()
    }
  }, [open, state, followGoto, stopPolling, t])

  const handleCodeLogin = async () => {
    if (!code.trim()) {
      toast.error(t('Please enter the verification code'))
      return
    }
    setSubmitting(true)
    try {
      const res = await api.post<GzhCheckResponse>(
        '/api/oauth/zibll/weixingzh/code',
        null,
        {
          params: { state, code: code.trim() },
          skipBusinessError: true,
          skipErrorHandler: true,
        }
      )
      const goto = res.data?.data?.goto
      if (res.data?.success && goto) {
        followGoto(goto)
        return
      }
      handleServerError(
        res.data,
        res.data?.message || t('The verification code is incorrect or has expired.')
      )
    } catch (error) {
      handleServerError(
        AuthOperationError.from(
          error,
          t('The verification code is incorrect or has expired.')
        )
      )
    } finally {
      setSubmitting(false)
    }
  }

  const reset = (next: boolean) => {
    onOpenChange(next)
    if (!next) {
      stopPolling()
      setQrUrl('')
      setQrError('')
      setCode('')
      setFollowingGoto(false)
      gotoRef.current = ''
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={reset}
      title={t('WeChat sign in')}
      description={t(
        'Scan the QR code to follow the official account and reply with “验证码” to receive your verification code.'
      )}
      contentClassName='max-w-sm'
      headerClassName='text-left'
      contentHeight='auto'
      bodyClassName='space-y-4'
      footer={
        <>
          <Button
            type='button'
            variant='outline'
            onClick={() => reset(false)}
            disabled={submitting || followingGoto}
          >
            {t('Cancel')}
          </Button>
          <Button
            type='button'
            onClick={handleCodeLogin}
            disabled={
              submitting ||
              followingGoto ||
              !code.trim()
            }
            className='gap-2'
          >
            {submitting || followingGoto ? (
              <Loader2 className='h-4 w-4 animate-spin' />
            ) : null}
            {followingGoto ? t('Returning…') : t('Confirm')}
          </Button>
        </>
      }
    >
      {qrUrl ? (
        <div className='flex flex-col items-center gap-2'>
          <img
            src={qrUrl}
            alt={t('WeChat login QR code')}
            className='h-44 w-44 rounded-md border object-contain'
          />
          {followingGoto ? (
            <p className='text-muted-foreground flex items-center gap-2 text-sm'>
              <Loader2 className='h-4 w-4 animate-spin' />
              {t('Scan confirmed, signing you in…')}
            </p>
          ) : (
            <p className='text-muted-foreground text-sm'>
              {t('Scan with WeChat to confirm, or enter the verification code below.')}
            </p>
          )}
        </div>
      ) : (
        <div className='flex flex-col items-center gap-2 py-4'>
          {!qrError ? (
            <Loader2 className='text-muted-foreground h-8 w-8 animate-spin' />
          ) : (
            <p className='text-destructive text-sm'>{qrError}</p>
          )}
        </div>
      )}
      <div className='grid gap-2'>
        <Label htmlFor='zibll-gzh-code'>{t('Verification code')}</Label>
        <Input
          id='zibll-gzh-code'
          placeholder={t('Enter the verification code')}
          value={code}
          onChange={(event) => setCode(event.target.value)}
          autoComplete='one-time-code'
        />
      </div>
    </Dialog>
  )
}
