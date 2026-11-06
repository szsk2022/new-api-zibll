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
import { api } from '@/lib/api'

export interface ZibllAgentTypeStatus {
  type: string
  name: string
  icon: string
  enabled: boolean
  qrcode: boolean
}

export interface ZibllAgentSettings {
  server_address: string
  key_configured: boolean
  types: ZibllAgentTypeStatus[]
}

export interface ZibllAgentSettingsUpdate {
  server_address: string
  key?: string
  types: string[]
}

interface ApiResponse<T = unknown> {
  success: boolean
  message?: string
  data?: T
}

export async function getZibllAgentSettings(): Promise<
  ApiResponse<ZibllAgentSettings>
> {
  const res = await api.get('/api/zibll_agent/settings')
  return res.data
}

export async function updateZibllAgentSettings(
  data: ZibllAgentSettingsUpdate
): Promise<ApiResponse<ZibllAgentSettings>> {
  const res = await api.put('/api/zibll_agent/settings', data)
  return res.data
}
