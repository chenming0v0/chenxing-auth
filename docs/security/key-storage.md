# 密钥目录安全边界

`KEY_DIRECTORY`（默认 `data/keys`）保存签名私钥、active `kid` 和 OAuth Provider / SMTP 主密钥。目录必须保持在 Git 忽略范围内；生产环境应按下面的平台边界保护，而不是依赖默认 umask 或资源管理器继承来的 ACL。

错误路径只返回通用权限/路径错误，不包含文件内容、密钥材料或 SID 字符串。

## Unix

叶子目录必须属于当前有效 uid，权限 `0700`；密钥文件 `0600`。祖先必须属于本进程或 root，且不可被他人改写（root + sticky 如 `/tmp` 除外）。关键操作绑定目录 fd，经 `openat2` / `openat` + `O_NOFOLLOW` 拒绝符号链接，打开后 `fstat` 同一 inode。

已有叶子若只是 mode 过宽，打开时会收紧为 `0700` / `0600`。异 uid 或符号链接 fail-closed。

## Windows

Windows 没有 POSIX owner / `O_NOFOLLOW`。实现用受保护 DACL 和 `NtCreateFile(..., FILE_OPEN_REPARSE_POINT)` 相对已打开的目录句柄前进，避免路径级 check-then-open 和 junction 替换。

### 服务帐户

生产应使用专用服务帐户或 `NT AUTHORITY\\SYSTEM`（LocalSystem）运行进程。DACL 只授给：

- 当前进程令牌的用户 SID（服务帐户或 LocalSystem）
- `NT AUTHORITY\\SYSTEM`（`S-1-5-18`），便于操作系统备份与服务控制

不授予 `Everyone`、`Authenticated Users`、`Users`、其它交互用户或任意外来 SID。也不把 `Administrators` 写进默认 DACL：管理员仍可取得所有权做灾难恢复，但不能靠组成员身份直接读私钥。

### 创建与已有目录

- **由本进程创建**：`Create` 时写入带 `SE_DACL_PROTECTED` 的 DACL，禁用从父目录继承。
- **已有目录 / 已有密钥文件**：只校验，不静默改写。有效 DACL 必须存在、非 NULL、受保护，且每个 Allow ACE 只授给上面两个主体。默认 `mkdir` 继承来的 Users/Everyone ACE 会让启动 fail-closed。

因此 Windows 上应让服务自己创建 `KEY_DIRECTORY`，或事先用同等 DACL 建好。不要先用资源管理器建一个继承默认 ACL 的空目录再启动。

### 重解析点

叶子、密钥文件和走查中的每一级都必须是普通目录或普通文件。符号链接、junction、挂载点以及其它 `FILE_ATTRIBUTE_REPARSE_POINT` 对象一律拒绝。原子写入在同一目录句柄下独占创建临时文件、写入并 `FlushFileBuffers`，再用 `SetFileInformationByHandle(FileRenameInfo)` 以父目录句柄 + 基名替换，避免目标路径被重解析点调包。`replace_existing = false` 时目标已存在则失败，不覆盖。

### 运维

- 备份：以 SYSTEM 或该服务帐户读取 `KEY_DIRECTORY`。普通管理员备份需先取得所有权或用同一服务帐户启动备份任务。
- 恢复：还原备份的私钥和 `kid`；不要用“新建一个空目录再启动”来绕过缺失材料。active `kid` 存在但私钥不在时服务 fail-closed，详见 README。
- 多实例：共享同一 NTFS 目录时，每个实例的进程身份必须是同一个服务帐户，否则后启动的实例会把对方 SID 看成外来主体并拒绝打开。

## 其它目标

非 Unix、非 Windows 的构建没有等价安全原语。安全文件操作返回 `std::io::ErrorKind::Unsupported`，不会退回未校验的路径级读写。
