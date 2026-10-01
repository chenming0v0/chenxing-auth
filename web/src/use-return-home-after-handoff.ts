import { useEffect } from 'react'
import { navigate } from './router'

const HOME = '/console'

/**
 * 浏览器把授权结果交给应用之后，这个标签页上的交接页/回调页就过期了：授权码
 * 已经用掉，再点「打开应用」只会把一个死回调重新发给应用。所以用户切回浏览器时
 * 直接换成控制台（replace，不在历史里留下过期页）。
 *
 * 只在「确实离开过」之后才跳：页面隐藏过一次再变回可见，或者从 bfcache 恢复。
 * 用户一直停在这页没走，就保持原样。
 */
export function useReturnHomeAfterHandoff(enabled = true) {
  useEffect(() => {
    if (!enabled) return
    let left = false
    const goHome = () => navigate(HOME, { replace: true })
    const onVisibility = () => {
      if (document.visibilityState === 'hidden') {
        left = true
        return
      }
      if (left) goHome()
    }
    const onPageShow = (event: PageTransitionEvent) => {
      if (event.persisted) goHome()
    }
    document.addEventListener('visibilitychange', onVisibility)
    window.addEventListener('pageshow', onPageShow)
    return () => {
      document.removeEventListener('visibilitychange', onVisibility)
      window.removeEventListener('pageshow', onPageShow)
    }
  }, [enabled])
}
