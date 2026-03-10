# MailMaster 逆向分析整理

本文档整理 `mailmaster` 当前仍然依赖、且对后续维护仍然有意义的逆向结论。

目标是回答四个问题：

1. MailMaster 的本地数据存在哪里
2. 当前 CLI 依赖了哪些稳定的逆向结论
3. 历史上探索过哪些路线，以及为什么被移除
4. 如果未来版本变动，应该从哪里开始排查

---

## 1. 本地数据位置

当前确认的关键路径如下：

- 启动器：`C:\Program Files (x86)\NetEase\MailMaster\Application\mailmaster.exe`
- 应用级数据库：`%LOCALAPPDATA%\NetEase\MailMaster\data\app.db`
- 每账号邮件库：`C:\MailMasterData\<account>_<id>\mail.db`
- 每账号正文库：`C:\MailMasterData\<account>_<id>\content.db`

其中：

- `app.db -> Account` 保存账号列表、账号 ID、邮箱地址、数据目录
- `mail.db -> Mailbox` 保存文件夹定义
- `mail.db -> MailMeta` 保存邮件元信息
- `mail.db -> MailAttachment` 保存附件元信息
- `mail.db -> AccountConfig` 保存协议配置与部分账号配置
- `content.db -> MailContent` 保存正文内容；压缩正文可按 `CompressType` 处理

---

## 2. 当前 CLI 依赖的逆向结论

当前代码库已经收敛为两条主线：

- 本地 SQLite 读信
- 动态解密 SMTP 配置后直连发送

因此，真正重要的逆向结论集中在 `AccountConfig` 的解密链路上。

### 2.1 `AccountConfig` 中的协议配置

在每个账号的 `mail.db -> AccountConfig` 中，常见键包括：

- `IMAPServerConfig`
- `SMTPServerConfig`
- `WmsvrServerConfig`

这些值不是明文 JSON，而是加密后的二进制 blob。

解密后，典型字段包括：

- `host`
- `port`
- `user`
- `pass`
- `sslType`
- `verifyMethod`
- `refreshToken`

其中：

- 外层 blob 解密后得到的是 JSON 配置
- JSON 中的 `pass` 字段本身还经过了第二层保护

### 2.2 外层配置解密

通过对 `mastercore.dll` 的静态分析确认：

- 使用 `PBKDF2-HMAC-SHA1`
- 迭代次数：`256`
- 派生长度：`32` 字节
- 对称算法：`AES-256-CBC`

当前实现不会只依赖源码里写死的常量，而是：

1. 优先从本机安装目录中的 `mastercore.dll` 提取安全常量
2. 提取失败时再回退到默认值

当前代码位置：`src/mailmaster/protocol_config.py`

### 2.3 内层 `pass` 解密

`pass` 不是直接明文，也不是简单 base64。

当前确认的逻辑是：

- 仍然使用 `PBKDF2-HMAC-SHA1(256)` + `AES-256-CBC`
- 但密码不是固定字符串，而是由 **当前 Windows 用户 SID** 派生得到

也就是说：

- 外层配置参数更像“按版本固定”
- 内层密码更像“按当前 Windows 用户环境动态生成”

这也是为什么当前 CLI 的发送逻辑设计为：

- 每次发送时动态解密
- 不把解密后的 SMTP 密码额外落盘到本地文件

### 2.4 为什么当前发送路径不走 DLL 直接调用

虽然 `mastercore.dll` 中存在大量内部逻辑，但当前没有把“直接调用 DLL 完成发信”作为产品路径，原因包括：

- `mastercore.dll` 仅导出极少数符号，缺少稳定公开 API
- 内部大量逻辑依赖 C++ 对象图与运行时上下文
- 该路径稳定性和可移植性都明显差于“解密后直接使用标准 SMTP”

因此当前实现选择：

- 从 MailMaster 本地配置中动态解密账号 SMTP 参数
- 通过 Python 标准 SMTP 客户端完成发送

这是目前最稳、最可维护的方案。

---

## 3. 已验证的配置样例特征

在本机样本中，已经解出过多类服务器配置，例如：

- Gmail：`imap.gmail.com` / `smtp.gmail.com`
- 飞书邮箱：`imap.feishu.cn` / `smtp.feishu.cn`
- QQ 企业邮：`hwimap.exmail.qq.com` / `hwsmtp.exmail.qq.com`
- 网易企业邮：`imap.ym.163.com` / `smtp.ym.163.com`

这说明当前逆向结论不仅能解结构，还能恢复实际可用的协议配置与密码。

---

## 4. 历史探索：曾经走过但已移除的路线

历史上项目探索过更多外部控制手段，但它们已经不属于当前 CLI 的主路径。

### 4.1 `mailto:` / 自定义 URL 协议

历史上曾通过：

- `mailto:`
- `mailmaster://?payload=<...>`

来拉起写信或打开邮件窗口。

这条路的问题是：

- 依赖桌面客户端交互
- 自动化可控性较弱
- 不适合作为 AI Agent 的稳定后端接口

因此已从当前 CLI 中移除。

### 4.2 Chromium DevTools / MasterBridge

历史上曾确认：

- MailMaster 可在特定调试参数下暴露 DevTools 端口
- 页面上下文里存在 `MasterBridge.dispatch(...)`
- 能调用部分内部命令，如账号列表、文件夹列表、邮件查询等

更具体地说，旧研究中已确认过：

- `COMMON.GET_ACCOUNT_LIST`
- `GET_MAIL_FOLDER_LIST`
- `GET_CURRENT_MAIL_FOLDER`
- `MAIL.QUERY_MAILS`
- `MAIL.GET_MAIL_INFO`

以及这些关键结论：

- `nativeId == localId` 在真实读取链路中成立
- `MAIL.QUERY_MAILS` 在许多页面上下文中可用
- 正文可从真实读信页 iframe 提取

但这条路的问题是：

- 需要特殊启动参数
- 依赖 GUI 客户端运行状态与页面上下文
- 对 AI Agent 来说环境前提重、稳定性差

因此已从当前产品能力中移除。

### 4.3 Workbench / Advanced Search 等页面级探索

旧研究中还分析过：

- workbench 页面上下文
- 页面内 Redux store
- `behaviorX` 事件总线
- advanced search 页面暴露的 `window.jmail`

这些内容对理解 MailMaster 内部架构很有帮助，但对当前 CLI 的核心能力并不构成必需依赖，因此没有保留在产品路径中。

---

## 5. 稳定性与边界

当前实现的稳定性判断如下：

### 5.1 较稳定部分

- `app.db` / `mail.db` / `content.db` 的整体角色划分
- `Account` / `Mailbox` / `MailMeta` / `MailAttachment` / `MailContent` 的用途
- 当前版本系下 `AccountConfig` 的两层解密思路

### 5.2 可能变化部分

- `mastercore.dll` 中安全常量的布局位置
- 是否仍然保留可提取的 ASCII 常量
- 内层密码派生时 SID 的具体拼接规则
- 个别账号类型是否只有 `WmsvrServerConfig` 而没有独立 `SMTPServerConfig`

### 5.3 失效时的排查顺序

若未来某版 MailMaster 升级后发送链路失效，建议按以下顺序排查：

1. 确认 `mail.db -> AccountConfig` 中目标键是否仍存在
2. 确认外层 blob 是否仍能解出 JSON
3. 确认 `pass` 是否仍是第二层加密而非改为其他机制
4. 确认本机 SID 推导出的运行时密码是否仍然匹配
5. 再考虑是否需要重新分析 `mastercore.dll`

---

## 6. 对当前代码的映射

逆向分析对应的核心实现位于：

- 配置解密：`src/mailmaster/protocol_config.py`
- SMTP profile 构造：`src/mailmaster/smtp.py`
- 账号与邮件读取：`src/mailmaster/store.py`
- CLI 入口：`src/mailmaster/cli/`

如果未来要维护当前“读信 + 动态发信”能力，优先看这几个文件即可。

