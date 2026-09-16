import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import {
  AndroidAppLinkPanel,
  androidAppLinkUnchanged,
  parseFingerprints,
  syncOwnedAndroidAppLink,
  validateAndroidAppLink,
} from './android-app-link-panel'

const { apiFetchMock } = vi.hoisted(() => ({
  apiFetchMock: vi.fn((_path: string, _init?: RequestInit): Promise<unknown> => Promise.resolve({})),
}))

vi.mock('../../api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../api')>()),
  apiFetch: apiFetchMock,
}))

beforeEach(() => {
  apiFetchMock.mockReset()
  apiFetchMock.mockResolvedValue({})
  vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({
    ok: true,
    json: async () => ({ issuer: 'https://issuer.example' }),
  })))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const FINGERPRINT = '14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5'

describe('parseFingerprints / validateAndroidAppLink', () => {
  it('按换行和逗号拆分指纹', () => {
    expect(parseFingerprints(` ${FINGERPRINT} \n aabb , \n`)).toEqual([FINGERPRINT, 'aabb'])
  })

  it('只填包名或只填指纹时互相要求补全', () => {
    expect(validateAndroidAppLink({ packageName: 'com.example.app', fingerprints: '' }).fingerprints).toBeTruthy()
    expect(validateAndroidAppLink({ packageName: '', fingerprints: FINGERPRINT }).packageName).toBeTruthy()
    expect(validateAndroidAppLink({ packageName: '', fingerprints: '' })).toEqual({})
    expect(validateAndroidAppLink({ packageName: 'com.example.app', fingerprints: FINGERPRINT })).toEqual({})
  })
})

describe('androidAppLinkUnchanged', () => {
  it('空表单对未登记声明视为未改', () => {
    expect(androidAppLinkUnchanged(null, { packageName: '', fingerprints: '' })).toBe(true)
  })

  it('包名或指纹变化视为已改', () => {
    const original = { package_name: 'com.example.app', sha256_cert_fingerprints: [FINGERPRINT] }
    expect(androidAppLinkUnchanged(original, { packageName: 'com.example.app', fingerprints: FINGERPRINT })).toBe(true)
    expect(androidAppLinkUnchanged(original, { packageName: 'com.other.app', fingerprints: FINGERPRINT })).toBe(false)
  })
})

describe('syncOwnedAndroidAppLink', () => {
  it('未改动不发请求', async () => {
    await syncOwnedAndroidAppLink('cx-1', null, { packageName: '', fingerprints: '' })
    expect(apiFetchMock).not.toHaveBeenCalled()
  })

  it('有包名和指纹时 PUT', async () => {
    await syncOwnedAndroidAppLink('cx-1', null, { packageName: 'com.example.app', fingerprints: FINGERPRINT })
    expect(apiFetchMock).toHaveBeenCalledWith('/api/v1/auth/oauth-clients/cx-1/app-link', {
      method: 'PUT',
      body: JSON.stringify({ package_name: 'com.example.app', sha256_cert_fingerprints: [FINGERPRINT] }),
    })
  })

  it('清空已有声明时 DELETE', async () => {
    await syncOwnedAndroidAppLink(
      'cx-1',
      { package_name: 'com.example.app', sha256_cert_fingerprints: [FINGERPRINT] },
      { packageName: '', fingerprints: '' },
    )
    expect(apiFetchMock).toHaveBeenCalledWith('/api/v1/auth/oauth-clients/cx-1/app-link', { method: 'DELETE' })
  })
})

describe('AndroidAppLinkPanel', () => {
  it('展示数字 App ID、官方路径和 Discovery 里的 Issuer URL，不含 Vite origin', async () => {
    render(
      <AndroidAppLinkPanel
        numericAppId={7}
        value={{ packageName: '', fingerprints: '' }}
        errors={{}}
        onChange={() => {}}
      />,
    )
    expect(screen.getByText('7')).toBeTruthy()
    expect(screen.getByText('/app/7/oauth/callback')).toBeTruthy()
    expect(await screen.findByText('https://issuer.example/app/7/oauth/callback')).toBeTruthy()
    expect(screen.getByText(/不会把本认证域名交给这个 App/)).toBeTruthy()
    expect(screen.queryByText(/5175/)).toBeNull()
  })

  it('Discovery 失败时只显示路径，并说明完整地址来自配置中的 Issuer', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('offline'))))
    render(
      <AndroidAppLinkPanel
        numericAppId={7}
        value={{ packageName: '', fingerprints: '' }}
        errors={{}}
        onChange={() => {}}
      />,
    )
    expect(screen.getByText('/app/7/oauth/callback')).toBeTruthy()
    await waitFor(() => {
      expect(screen.getByText(/完整地址是配置中的 Issuer 加上这条路径/)).toBeTruthy()
    })
    expect(screen.queryByText(/5175/)).toBeNull()
  })
})
