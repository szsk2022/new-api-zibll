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
import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

import { ZibllBrandIcon } from '@/features/auth/components/zibll-brand-icon'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

import { SettingsSection } from '../../components/settings-section'
import {
  getZibllAgentSettings,
  updateZibllAgentSettings,
  type ZibllAgentSettings,
} from './api'

export function ZibllAgentSection() {
  const { t } = useTranslation()
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [serverAddress, setServerAddress] = useState('')
  const [key, setKey] = useState('')
  const [keyConfigured, setKeyConfigured] = useState(false)
  const [types, setTypes] = useState<ZibllAgentSettings['types']>([])
  const [selected, setSelected] = useState<Set<string>>(new Set())

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await getZibllAgentSettings()
      if (res.success && res.data) {
        setServerAddress(res.data.server_address ?? '')
        setKeyConfigured(Boolean(res.data.key_configured))
        setTypes(res.data.types ?? [])
        setSelected(
          new Set(
            (res.data.types ?? [])
              .filter((t) => t.enabled)
              .map((t) => t.type)
          )
        )
      }
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const toggleType = (type: string) => {
    setSelected((current) => {
      const next = new Set(current)
      if (next.has(type)) {
        next.delete(type)
      } else {
        next.add(type)
      }
      return next
    })
  }

  const handleSave = async () => {
    if (!serverAddress.trim()) {
      toast.error(t('The Zibll agent server address is required'))
      return
    }
    if (!keyConfigured && !key.trim()) {
      toast.error(t('The Zibll agent shared key is required'))
      return
    }
    setSaving(true)
    try {
      const res = await updateZibllAgentSettings({
        server_address: serverAddress.trim(),
        key: key.trim() || undefined,
        types: Array.from(selected),
      })
      if (res.success && res.data) {
        setKeyConfigured(Boolean(res.data.key_configured))
        setTypes(res.data.types ?? [])
        setKey('')
        toast.success(t('Zibll agent login settings saved'))
      } else {
        toast.error(res.message || t('Failed to save settings'))
      }
    } catch {
      toast.error(t('Failed to save settings'))
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return (
      <SettingsSection title={t('Zibll Agent Login')}>
        <div className='text-muted-foreground py-8 text-center text-sm'>
          {t('Loading...')}
        </div>
      </SettingsSection>
    )
  }

  return (
    <SettingsSection title={t('Zibll Agent Login')}>
      <Alert>
        <AlertTitle>{t('Zibll proxy social login')}</AlertTitle>
        <AlertDescription className='space-y-2 text-sm'>
          <p>
            {t(
              'Connect this site to a Zibll master site running in “代理登录服务端” (agent server) mode. The master site completes the real WeChat/QQ/GitHub OAuth and returns a signed identity — users log in here without their own OAuth apps.'
            )}
          </p>
          <p>
            {t(
              'Copy the 接口地址 (server URL) and 通讯密钥 (shared key) from the master site. Users bound to a disabled login type keep their binding and can sign in again once it is re-enabled.'
            )}
          </p>
        </AlertDescription>
      </Alert>

      <div className='grid gap-3'>
        <div className='grid gap-2'>
          <Label htmlFor='zibll-server-address'>
            {t('Master site URL (接口地址)')}
          </Label>
          <Input
            id='zibll-server-address'
            placeholder='https://your-zibll-site.com/'
            value={serverAddress}
            onChange={(event) => setServerAddress(event.target.value)}
          />
        </div>
        <div className='grid gap-2'>
          <Label htmlFor='zibll-agent-key'>
            {t('Shared key (通讯密钥)')}
          </Label>
          <Input
            id='zibll-agent-key'
            type='password'
            placeholder={
              keyConfigured
                ? t('Configured — leave blank to keep the current key')
                : t('Enter the shared key from the master site')
            }
            value={key}
            onChange={(event) => setKey(event.target.value)}
            autoComplete='new-password'
          />
        </div>
      </div>

      <div className='grid gap-2'>
        <Label>{t('Enabled login methods (multi-select)')}</Label>
        <div className='grid gap-2 sm:grid-cols-2'>
          {types.map((loginType) => (
            <label
              key={loginType.type}
              className='hover:bg-muted/50 flex cursor-pointer items-center gap-3 rounded-lg border px-3 py-2'
            >
              <Checkbox
                checked={selected.has(loginType.type)}
                onCheckedChange={() => toggleType(loginType.type)}
              />
              <ZibllBrandIcon
                slug={loginType.icon}
                className='h-4 w-4 shrink-0'
              />
              <span className='min-w-0 flex-1 truncate text-sm'>
                {loginType.name}
                <span className='text-muted-foreground ml-1.5 text-xs'>
                  {loginType.type}
                  {loginType.qrcode ? ' · QR' : ''}
                </span>
              </span>
            </label>
          ))}
        </div>
      </div>

      <div className='flex justify-end'>
        <Button type='button' onClick={handleSave} disabled={saving}>
          {saving ? <Loader2 className='h-4 w-4 animate-spin' /> : null}
          {t('Save')}
        </Button>
      </div>
    </SettingsSection>
  )
}
