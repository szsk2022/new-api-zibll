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
  IconAlipay,
  IconFacebook,
  IconGithub,
  IconWeChat,
  IconZibllApple,
  IconZibllBaidu,
  IconZibllDouyin,
  IconZibllGitee,
  IconZibllGoogle,
  IconZibllMicrosoft,
  IconZibllQQ,
  IconZibllTwitter,
  IconZibllWeibo,
} from '@/assets/brand-icons'

const zibllIconMap = {
  'zibll-weixin': IconWeChat,
  'zibll-weixingzh': IconWeChat,
  'zibll-qq': IconZibllQQ,
  'zibll-weibo': IconZibllWeibo,
  'zibll-douyin': IconZibllDouyin,
  'zibll-github': IconGithub,
  'zibll-gitee': IconZibllGitee,
  'zibll-baidu': IconZibllBaidu,
  'zibll-alipay': IconAlipay,
  'zibll-google': IconZibllGoogle,
  'zibll-microsoft': IconZibllMicrosoft,
  'zibll-facebook': IconFacebook,
  'zibll-twitter': IconZibllTwitter,
  'zibll-apple': IconZibllApple,
} as const

type ZibllBrandIconProps = {
  slug: string
  className?: string
}

/** Renders the brand logo of a Zibll agent login type by its icon slug. */
export function ZibllBrandIcon({ slug, className }: ZibllBrandIconProps) {
  const Icon = zibllIconMap[slug as keyof typeof zibllIconMap]
  if (!Icon) return null
  return <Icon className={className} focusable='false' />
}

/** True when the provider slug belongs to a Zibll agent login. */
export function isZibllProviderSlug(slug?: string | null): boolean {
  return typeof slug === 'string' && slug.startsWith('zibll-')
}

export const zibllGZHSlug = 'zibll-weixingzh'
