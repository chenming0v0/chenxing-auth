// 全局 setup 不再注入 CSRF cookie（#374）：
// 无条件写入 chenxing_csrf 会让「缺 cookie → missingCsrfError」和
// 「优先读 __Host-chenxing_csrf」两条路径在整个套件里测不到。
// 需要 cookie 的用例自己在 beforeEach 里写，并在 afterEach 里清掉。
