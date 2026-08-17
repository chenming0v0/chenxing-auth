# 密钥目录安全边界

`KEY_DIRECTORY`（默认 `data/keys`）保存签名私钥、active `kid` 和 OAuth Provider / SMTP 主密钥。目录必须保持在 Git 忽略范围内；生产环境应按下面的平台边界保护，而不是依赖默认 umask 或资源管理器继承来的 ACL。

错误路径只返回通用权限/路径错误，不包含文件内容、密钥材料或 SID 字符串。

## Unix

叶子目录必须属于当前有效 uid，权限 `0700`；密钥文件 `0600`。祖先必须属于本进程或 root，且不可被他人改写（root + sticky 如 `/tmp` 除外）。关键操作绑定目录 fd，经 `openat2` / `openat` + `O_NOFOLLOW` 拒绝符号链接，打开后 `fstat` 同一 inode。

已有叶子若只是 mode 过宽，打开时会收紧为 `0700` / `0600`。异 uid 或符号链接 fail-closed。

## Windows

Windows 没有 POSIX uid / `O_NOFOLLOW`。实现同时校验对象 Owner SID 与受保护 DACL，并用 `NtCreateFile(..., FILE_OPEN_REPARSE_POINT)` 相对已打开的目录句柄前进，避免路径级 check-then-open 和 junction 替换。

### 服务帐户

生产应使用专用服务帐户或 `NT AUTHORITY\\SYSTEM`（LocalSystem）运行进程。DACL 只授给：

- 当前进程令牌的用户 SID（服务帐户或 LocalSystem）
- `NT AUTHORITY\\SYSTEM`（`S-1-5-18`），便于操作系统备份与服务控制

不授予 `Everyone`、`Authenticated Users`、`Users`、其它交互用户或任意外来 SID。也不把 `Administrators` 写进默认 DACL：管理员仍可取得所有权做灾难恢复，但不能靠组成员身份直接读私钥。

### 创建与已有目录

- **由本进程创建**：`Create` 时写入带 `SE_DACL_PROTECTED` 的 DACL，禁用从父目录继承。
- **已有目录 / 已有密钥文件**：只校验，不静默改写。Owner 必须是当前服务帐户或 LocalSystem；有效 DACL 必须存在、非 NULL、受保护，且每个 Allow ACE 只授给上面两个主体并具有 Windows 映射后的 full-control mask。即使 DACL 看似只允许服务帐户/SYSTEM，外来 Owner 仍可重写它，因此必须 fail-closed。默认 `mkdir` 继承来的 Users/Everyone ACE、非规范 Allow mask 或外来 Owner 都会让启动失败。

因此 Windows 上应让服务自己创建 `KEY_DIRECTORY`，或事先用同等 DACL 建好。不要先用资源管理器建一个继承默认 ACL 的空目录再启动。

### 重解析点

叶子、密钥文件和走查中的每一级都必须是普通目录或普通文件。符号链接、junction、挂载点以及其它 `FILE_ATTRIBUTE_REPARSE_POINT` 对象一律拒绝。原子写入在同一目录句柄下独占创建临时文件、写入并 `FlushFileBuffers`，再用 `SetFileInformationByHandle(FileRenameInfo)` 以父目录句柄 + 基名替换，避免目标路径被重解析点调包。`replace_existing = false` 时目标已存在则失败，不覆盖。

### 运维

- 备份：以 SYSTEM 或该服务帐户读取 `KEY_DIRECTORY`。普通管理员备份需先取得所有权或用同一服务帐户启动备份任务。
- 恢复：还原备份的私钥和 `kid`；不要用“新建一个空目录再启动”来绕过缺失材料。active `kid` 存在但私钥不在时服务 fail-closed，详见 README。
- 多实例：共享同一 NTFS 目录时，每个实例的进程身份必须是同一个服务帐户，否则后启动的实例会把对方 SID 看成外来主体并拒绝打开。

### 多实例锁与时钟

Windows 上 `.chenxing-key.lock` 是长期保留的普通文件。实例用 `share_mode(0)` 打开它并持有内核独占句柄：进程崩溃时句柄由内核关闭，进程暂停时句柄仍然有效；PID、文件内容和 mtime 都不参与归属判断。释放只关闭句柄，绝不删除锁文件，因此旧实例没有机会删除后继实例的锁代次。若升级前遗留的是旧版目录租约 `.chenxing-key.lock/`，必须在确认所有旧实例都已停止后删除该目录；新版本会对目录形态 fail-closed，不做竞态不安全的自动回收。

共享目录的轮换时间由 `KEY_ROTATION_SKEW_ALLOWANCE_SECONDS` 统一吸收允许的实例时钟偏差：新公钥的激活截止是发布时刻加 `KEY_ACTIVATION_DELAY_SECONDS` 再加该偏差围栏，避免慢钟实例写入的截止被快钟实例提前判定；旧公钥的删除边界仍是 `retired_at + KEY_ROTATION_GRACE_SECONDS + allowance`。偏差围栏只会延后激活或回收，不会缩短 JWKS 传播窗口和旧公钥验证窗口。

## 其它目标

非 Unix、非 Windows 的构建没有等价安全文件原语。安全文件操作返回 `std::io::ErrorKind::Unsupported`，不会退回未校验的路径级读写。锁模块仍保留 portable 目录租约供目标兼容与测试：owner 记录包含 host、PID、process-start 与随机 nonce，acquire、heartbeat、陈旧回收和 release 都校验完整 token；release 只写入同代 `released` 标记，不按路径删除目录，避免暂停后恢复的旧 owner 删除 successor。
