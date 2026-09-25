import { afterEach, describe, expect, it, vi } from 'vitest'
import { androidAppLinkIntent, appLaunchTarget, isAndroidBrowser } from './android-intent'

const HTTPS = 'https://issuer.example.test/app/7/oauth/callback?code=secret-code&state=xyz'
const PACKAGE = 'com.example.app'
const ANDROID_UA = 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile'
const DESKTOP_UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'

function intentFor(httpsUrl: string, packageName = PACKAGE): string {
  const url = new URL(httpsUrl)
  return `intent://${url.host}${url.pathname}${url.search}#Intent;scheme=https;package=${packageName};S.browser_fallback_url=${encodeURIComponent(httpsUrl)};end`
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('isAndroidBrowser', () => {
  it('匹配 Android，忽略大小写', () => {
    expect(isAndroidBrowser(ANDROID_UA)).toBe(true)
    expect(isAndroidBrowser('Mozilla/5.0 (Linux; android 10; K)')).toBe(true)
  })

  it('桌面和 iOS 不是 Android', () => {
    expect(isAndroidBrowser(DESKTOP_UA)).toBe(false)
    expect(isAndroidBrowser('Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)')).toBe(false)
    expect(isAndroidBrowser('')).toBe(false)
  })

  it('不传参时读取 navigator.userAgent', () => {
    vi.spyOn(navigator, 'userAgent', 'get').mockReturnValue(ANDROID_UA)
    expect(isAndroidBrowser()).toBe(true)
  })
})

describe('androidAppLinkIntent', () => {
  it('拼出带显式 package 和编码 fallback 的 intent URL', () => {
    expect(androidAppLinkIntent(HTTPS, PACKAGE)).toBe(intentFor(HTTPS))
  })

  it('非默认端口留在 host 里', () => {
    const raw = 'https://issuer.example.test:8443/cb?code=1'
    expect(androidAppLinkIntent(raw, PACKAGE)).toBe(
      `intent://issuer.example.test:8443/cb?code=1#Intent;scheme=https;package=${PACKAGE};S.browser_fallback_url=${encodeURIComponent(raw)};end`,
    )
  })

  it('丢掉分层部分的 hash，原文 hash 只留在 fallback 里', () => {
    const raw = 'https://issuer.example.test/app/7/oauth/callback?code=1#section'
    const intent = androidAppLinkIntent(raw, PACKAGE)
    expect(intent).toBe(
      `intent://issuer.example.test/app/7/oauth/callback?code=1#Intent;scheme=https;package=${PACKAGE};S.browser_fallback_url=${encodeURIComponent(raw)};end`,
    )
    expect(intent).not.toContain('#section')
  })

  it('host 按 URL 解析结果，fallback 保留调用方原文', () => {
    const raw = 'https://Example.COM/App'
    expect(androidAppLinkIntent(raw, PACKAGE)).toBe(
      `intent://example.com/App#Intent;scheme=https;package=${PACKAGE};S.browser_fallback_url=${encodeURIComponent(raw)};end`,
    )
  })

  it('默认端口不出现在 intent host 里', () => {
    const raw = 'https://example.com:443/cb'
    expect(androidAppLinkIntent(raw, PACKAGE)).toBe(
      `intent://example.com/cb#Intent;scheme=https;package=${PACKAGE};S.browser_fallback_url=${encodeURIComponent(raw)};end`,
    )
  })

  it.each([
    'http://issuer.example.test/cb',
    'HTTP://issuer.example.test/cb',
    'javascript:alert(1)',
    'https://',
    '/app/7/oauth/callback',
    '',
    'not a url',
  ])('拒绝 %j', (raw) => {
    expect(androidAppLinkIntent(raw, PACKAGE)).toBeNull()
  })

  it.each([
    'com.example.app',
    'a.b',
    'Com.Example_1.App2',
  ])('接受包名 %s', (packageName) => {
    expect(androidAppLinkIntent(HTTPS, packageName)).toBe(intentFor(HTTPS, packageName))
  })

  it.each([
    'com',
    'com.example.',
    'com..example',
    '.com.example',
    '1com.example',
    'com.1example',
    'com.example.app;S.extra=1',
    'com.example.my-app',
    '',
    'com.example app',
  ])('拒绝包名 %j', (packageName) => {
    expect(androidAppLinkIntent(HTTPS, packageName)).toBeNull()
  })
})

describe('appLaunchTarget', () => {
  it('Android 加合法包名时返回 intent', () => {
    expect(appLaunchTarget(HTTPS, PACKAGE, ANDROID_UA)).toBe(intentFor(HTTPS))
  })

  it('非 Android 即使有包名也保持 https', () => {
    expect(appLaunchTarget(HTTPS, PACKAGE, DESKTOP_UA)).toBe(HTTPS)
  })

  it.each([null, undefined])('包名为 %s 时保持 https', (packageName) => {
    expect(appLaunchTarget(HTTPS, packageName, ANDROID_UA)).toBe(HTTPS)
  })

  it('包名或目标不合法时退回原来的地址', () => {
    expect(appLaunchTarget(HTTPS, 'not a package', ANDROID_UA)).toBe(HTTPS)
    expect(appLaunchTarget('http://issuer.example.test/cb', PACKAGE, ANDROID_UA)).toBe('http://issuer.example.test/cb')
  })

  it('不传 userAgent 时跟随 navigator，显式参数可以覆盖', () => {
    vi.spyOn(navigator, 'userAgent', 'get').mockReturnValue(ANDROID_UA)
    expect(appLaunchTarget(HTTPS, PACKAGE)).toBe(intentFor(HTTPS))
    expect(appLaunchTarget(HTTPS, PACKAGE, DESKTOP_UA)).toBe(HTTPS)
  })
})
