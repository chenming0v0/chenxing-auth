/**
 * Chrome Android 对「导航目标与当前页同一 host」有一条硬规则
 * （ExternalNavigationHandler.shouldStayWithinHost）：App Link 回调就挂在发行者自己的
 * host 上时，`location.assign(https://<issuer>/...)` 会被留在浏览器里，应用收不到授权码。
 * 带显式 package 的 `intent://` 不走这条规则。
 *
 * 确认页的 assign 发生在用户点击之后，仍在 Chrome 约 5 秒的用户激活窗口内，所以拉起是静默的，
 * 不再弹「要打开应用吗」。`S.browser_fallback_url` 指回原来的 https 地址：应用没安装时
 * 还能打开兜底页，而不是把用户丢进打不开的 intent。
 *
 * intent 的分层部分不能带原来的 hash——`#Intent` 才是参数分隔符——所以 fragment 被丢掉；
 * 原文（含 hash）只出现在编码后的 fallback 里。host 用 `url.host`，非默认端口会留在里面。
 */

/** 至少两段、每段以字母开头。挡掉 `;` / `#` 之类，避免把 extras 注入 intent。 */
const ANDROID_PACKAGE_NAME = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/

export function isAndroidBrowser(userAgent = navigator.userAgent): boolean {
  return /Android/i.test(userAgent)
}

export function androidAppLinkIntent(httpsUrl: string, packageName: string): string | null {
  if (!ANDROID_PACKAGE_NAME.test(packageName)) return null
  let url: URL
  try {
    url = new URL(httpsUrl)
  } catch {
    return null
  }
  // 只接受带 host 的 https。http、javascript: 以及解析失败都不能编进 intent。
  if (url.protocol !== 'https:' || !url.host) return null
  const fallback = encodeURIComponent(httpsUrl)
  return `intent://${url.host}${url.pathname}${url.search}#Intent;scheme=https;package=${packageName};S.browser_fallback_url=${fallback};end`
}

/** Android 且包名能编成 intent 时返回 intent URL，否则原样返回 https 目标。 */
export function appLaunchTarget(
  httpsTarget: string,
  packageName: string | null | undefined,
  userAgent?: string,
): string {
  if (packageName === null || packageName === undefined) return httpsTarget
  if (!isAndroidBrowser(userAgent)) return httpsTarget
  return androidAppLinkIntent(httpsTarget, packageName) ?? httpsTarget
}
