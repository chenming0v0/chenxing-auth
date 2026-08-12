/**
 * 全局测试环境初始化（vitest setupFiles）。
 *
 * 这里刻意不注入任何 Cookie：CSRF Cookie 只对走 apiFetch 的状态变更请求有意义，
 * 全局注入会让所有测试隐式携带有效 token —— api.ts 的「无 cookie → csrf_required」
 * 分支永远测不到，且所有测试都固化在 chenxing_csrf 回退名上，从不验证生产用的
 * __Host-chenxing_csrf 优先路径。需要 CSRF 的测试文件在自身文件顶层显式调用
 * ./csrf-cookie 的 installCsrfCookie()，其余文件不带任何 CSRF Cookie 运行。
 */
