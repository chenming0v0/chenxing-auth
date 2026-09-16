import { useEffect, useState } from 'react'
import { apiFetch, type AppLinkResponse } from '../../api'
import { CopyValue, Field, HudPanel, TextAreaField } from '@chenxing/ui'

export type AndroidAppLinkValue = {
  packageName: string
  fingerprints: string
}

export type AndroidAppLinkErrors = {
  packageName?: string
  fingerprints?: string
}

export const ANDROID_APP_LINK_FIELD_ID = {
  packageName: 'android-app-link-package-name',
  fingerprints: 'android-app-link-fingerprints',
} as const

type DeclaredAppLink = {
  package_name: string
  sha256_cert_fingerprints: string[]
}

export function parseFingerprints(raw: string): string[] {
  return raw
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean)
}

export function formFromAndroidAppLink(link: DeclaredAppLink | null | undefined): AndroidAppLinkValue {
  if (!link) return { packageName: '', fingerprints: '' }
  return {
    packageName: link.package_name,
    fingerprints: link.sha256_cert_fingerprints.join('\n'),
  }
}

export function validateAndroidAppLink(value: AndroidAppLinkValue): AndroidAppLinkErrors {
  const packageName = value.packageName.trim()
  const fingerprints = parseFingerprints(value.fingerprints)
  const errors: AndroidAppLinkErrors = {}
  if (packageName && fingerprints.length === 0) errors.fingerprints = '填了包名就必须填写签名指纹。'
  if (!packageName && fingerprints.length > 0) errors.packageName = '填了签名指纹就必须填写包名。'
  return errors
}

function sameFingerprints(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((item, index) => item === right[index])
}

export function androidAppLinkUnchanged(
  original: DeclaredAppLink | null | undefined,
  value: AndroidAppLinkValue,
): boolean {
  const packageName = value.packageName.trim()
  const fingerprints = parseFingerprints(value.fingerprints)
  if (!original) return !packageName && fingerprints.length === 0
  return original.package_name === packageName && sameFingerprints(original.sha256_cert_fingerprints, fingerprints)
}

export async function syncOwnedAndroidAppLink(
  clientId: string,
  original: DeclaredAppLink | null | undefined,
  value: AndroidAppLinkValue,
): Promise<void> {
  if (androidAppLinkUnchanged(original, value)) return
  const packageName = value.packageName.trim()
  const fingerprints = parseFingerprints(value.fingerprints)
  const path = `/api/v1/auth/oauth-clients/${encodeURIComponent(clientId)}/app-link`
  if (packageName && fingerprints.length > 0) {
    await apiFetch<AppLinkResponse>(path, {
      method: 'PUT',
      body: JSON.stringify({ package_name: packageName, sha256_cert_fingerprints: fingerprints }),
    })
    return
  }
  if (!packageName && fingerprints.length === 0 && original) {
    await apiFetch<void>(path, { method: 'DELETE' })
  }
}

function issuerFromDiscovery(body: unknown): string | null {
  if (!body || typeof body !== 'object' || !('issuer' in body)) return null
  const issuer = body.issuer
  if (typeof issuer !== 'string') return null
  const trimmed = issuer.trim().replace(/\/+$/, '')
  if (!/^https:\/\//i.test(trimmed)) return null
  return trimmed
}

export function AndroidAppLinkPanel({
  numericAppId,
  value,
  errors,
  disabled,
  onChange,
}: {
  numericAppId: number
  value: AndroidAppLinkValue
  errors: AndroidAppLinkErrors
  disabled?: boolean
  onChange: (value: AndroidAppLinkValue) => void
}) {
  const callbackPath = `/app/${numericAppId}/oauth/callback`
  const [issuer, setIssuer] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    void fetch('/.well-known/openid-configuration')
      .then((response) => (response.ok ? response.json() : null))
      .then((body) => {
        if (active) setIssuer(issuerFromDiscovery(body))
      })
      .catch(() => {
        if (active) setIssuer(null)
      })
    return () => {
      active = false
    }
  }, [])

  const officialCallback = issuer ? `${issuer}${callbackPath}` : null

  function update<K extends keyof AndroidAppLinkValue>(key: K, next: AndroidAppLinkValue[K]) {
    onChange({ ...value, [key]: next })
  }

  return (
    <HudPanel className="space-y-4 !p-5">
      <p className="chenxing-label !mb-0">软件链接</p>
      <p className="chenxing-caption">
        第三方原生应用把 Redirect URI 填成你自己的 HTTPS 地址，并在那个域名发布 assetlinks.json。
        这里保存的包名和指纹只是档案，不会把本认证域名交给这个 App。留空并保存会清掉档案。
      </p>
      <div className="grid gap-3 sm:grid-cols-2">
        <div>
          <p className="chenxing-label">数字 App ID</p>
          <p className="chenxing-mono text-sm">{numericAppId}</p>
        </div>
        <div className="min-w-0">
          <p className="chenxing-label">官方回调路径（仅第一方）</p>
          <CopyValue value={callbackPath} ariaLabel="复制官方回调路径" />
        </div>
      </div>
      {officialCallback ? (
        <div className="min-w-0">
          <p className="chenxing-label">官方完整回调 URL（仅第一方）</p>
          <CopyValue value={officialCallback} ariaLabel="复制官方完整回调 URL" />
        </div>
      ) : (
        <p className="chenxing-caption">完整地址是配置中的 Issuer 加上这条路径，不使用当前页面的域名。</p>
      )}
      <Field
        label="Android 包名"
        id={ANDROID_APP_LINK_FIELD_ID.packageName}
        icon="box"
        placeholder="com.example.app"
        autoComplete="off"
        spellCheck={false}
        autoCapitalize="none"
        value={value.packageName}
        onChange={(event) => update('packageName', event.target.value)}
        errorText={errors.packageName}
        disabled={disabled}
      />
      <TextAreaField
        label="SHA-256 签名指纹"
        id={ANDROID_APP_LINK_FIELD_ID.fingerprints}
        placeholder="每行一条，支持 AA:BB 或 aabb 写法"
        spellCheck={false}
        value={value.fingerprints}
        onChange={(event) => update('fingerprints', event.target.value)}
        errorText={errors.fingerprints}
        disabled={disabled}
        hint="同包名可填多条：调试、发布、上传密钥轮换。"
      />
    </HudPanel>
  )
}
