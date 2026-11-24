# mailmaster

[English](README_EN.md)

在 Windows 命令行或 Python 中直接读取、搜索、发送和管理**网易邮箱大师（MailMaster）**里的邮件。支持普通 IMAP/SMTP 账号和 163/126/yeah.net 等网易系账号，支持 Markdown、LaTeX 公式、附件、草稿与结构化 JSON 输出，无需打开邮箱大师客户端。

## 安装

推荐使用 [`uv`](https://docs.astral.sh/uv/) 一键安装为全局命令行工具：

```powershell
# 推荐：一键安装全局命令行工具
uv tool install mailmaster

# 可选：支持将 LaTeX 数学公式渲染为内联图片
uv tool install "mailmaster[latex-image]"

# 检查或一键更新到 GitHub Releases 最新版本
mailmaster update --check
mailmaster update
```

作为 Python 库安装到项目中：

```powershell
uv add mailmaster
# 或
pip install mailmaster
```

从本地源码安装或参与开发：

```powershell
git clone https://github.com/AndersonBY/mailmaster-cli.git
cd mailmaster-cli

# 安装本地版本为全局 CLI
uv tool install .

# 或创建本地开发环境
uv sync
```

## 给 AI Agent 使用

`mailmaster` 内置了完整的 Agent Skill，并在所有命令上提供稳定的 JSON 输出，方便 Claude Code、Codex、Gemini、Cursor 等 AI Agent 直接接管邮件工作流。

### 方式一：通过 CLI 一键加载或安装 Skill

```powershell
# 直接输出完整 Skill 使用指南（供 Agent 当场读取上下文）
mailmaster activate-skill

# 一键安装到当前项目或常用 Agent 的全局技能目录
mailmaster activate-skill --install project   # .agents/skills/mailmaster/SKILL.md
mailmaster activate-skill --install claude    # ~/.claude/skills/mailmaster/SKILL.md
mailmaster activate-skill --install codex     # ~/.codex/skills/mailmaster/SKILL.md
mailmaster activate-skill --install gemini    # ~/.gemini/config/skills/mailmaster/SKILL.md
mailmaster activate-skill --install cursor    # .cursor/skills/mailmaster/SKILL.md

# 或安装到自定义目录 / 查看内置 SKILL.md 路径
mailmaster activate-skill --dest C:\path\to\skills
mailmaster activate-skill --path
```

### 方式二：从仓库 `skill/` 目录安装

仓库根目录提供了标准格式的 [`skill/SKILL.md`](skill/SKILL.md)，可以直接复制整个 `skill/` 目录到你的 Agent 技能路径，或通过通用技能工具安装：

```powershell
npx skills add AndersonBY/mailmaster-cli
```

### 结构化 JSON 输出

在任意命令的**前面或后面**加上 `--json`（或 `--format json`），即可获得统一的结构化输出：

```powershell
mailmaster accounts --json
mailmaster list --account sender@example.com --unread --limit 10 --json
```

成功时返回：

```json
{"ok": true, "command": "list", "data": {}}
```

失败时（本地查无此项、参数错误或服务端拒绝）退出码为 `2`，不打印 Python traceback，返回带错误码和建议的 JSON：

```json
{
  "ok": false,
  "command": "read",
  "error": {"code": "mail_not_found", "message": "...", "details": {}}
}
```

## 常用命令

### 查看状态与账号

```powershell
# 检查本地邮箱大师数据路径与账号数量
mailmaster doctor

# 列出所有已配置的账号（后续命令均可用邮箱地址、账号名或数字 ID 指定账号）
mailmaster accounts

# 查看每个账号支持的能力与推荐通道（适合脚本与 Agent 分支判断）
mailmaster capabilities --json
mailmaster capabilities --sendable --mutable --json
mailmaster capabilities --query 163 --json
```

### 本地查信与搜信

读取与搜索直接访问本地数据库快照，离线可用、响应极快：

```powershell
# 查看文件夹列表
mailmaster mailboxes --account sender@example.com

# 列出邮件（支持按文件夹、未读状态和条数过滤）
mailmaster list --account sender@example.com --mailbox 收件箱 --limit 10
mailmaster list --account sender@example.com --unread --limit 20

# 阅读邮件正文（可传 LocalId 或 RemoteId；加 --html 输出 HTML）
mailmaster read --account sender@example.com --mail-id 40073

# 按主题/发件人搜索，加 --body 同时搜索正文
mailmaster search --account sender@example.com github --body --limit 5
```

### 发信（纯文本、HTML、Markdown 与附件）

`send-mail` 会根据账号能力自动选择 SMTP 或 163/Wmsvr 私有通道发送，也支持用 `--transport smtp|wmsvr-private` 手动指定：

```powershell
# 发送纯文本邮件
mailmaster send-mail --account sender@example.com `
  --to user@example.com --subject "周报" --body "本周进展如下..."

# 发送 HTML 邮件
mailmaster send-mail --account sender@example.com `
  --to user@example.com --subject "通知" --html-body "<p>你好</p>"

# 发送 Markdown + LaTeX 公式（支持 --markdown-body 或 --markdown-file）
mailmaster send-mail --account sender@example.com `
  --to user@example.com --subject "实验记录" `
  --markdown-body "# 摘要`n`n结果：`$E = mc^2$`" --latex-mode auto

# 携带一个或多个附件（SMTP 与 163 私有通道均支持）
mailmaster send-mail --account sender@example.com `
  --to user@example.com --subject "附件请查收" --body "详见附件。" `
  --attach C:\path\report.pdf --attach C:\path\data.xlsx
```

如果需要显式通过 SMTP 并自定义 `--from` 发件地址，可使用 `mailmaster smtp-send`。

### 草稿管理

支持在 163/Wmsvr 账号上直接创建、更新和发送服务端草稿（支持 Markdown 与附件）：

```powershell
# 新建服务端草稿（返回 draft_id 与 compose_id）
mailmaster save-draft --account user@163.com `
  --to colleague@example.com --subject "方案草稿" `
  --body "初稿内容" --attach C:\path\spec.pdf

# 更新同一份草稿（传入上次返回的 compose_id）
mailmaster save-draft --account user@163.com `
  --subject "方案草稿 v2" --body "补充了第二部分" --compose-id <compose_id>

# 发送已保存的草稿（按草稿 ID 或最新匹配主题，已有附件会自动随信发出）
mailmaster send-draft --account user@163.com --draft-id <draft_id>
mailmaster send-draft --account user@163.com --subject "方案草稿 v2"
```

### 标记、移动、删除与拉取原文

所有操作均支持通过重复 `--mail-id` 批量处理，IMAP 账号走直接 IMAP，163/Wmsvr 账号走私有通道并在同一会话内校验服务端结果：

```powershell
# 标记已读 / 未读
mailmaster mark-read --account sender@example.com --mail-id 40073
mailmaster mark-unread --account sender@example.com --mail-id 40073 --mail-id 40074

# 移动到指定文件夹（支持文件夹名或文件夹 ID）
mailmaster move-mail --account sender@example.com --mail-id 40073 --target-mailbox Archive

# 删除邮件
mailmaster delete-mail --account sender@example.com --mail-id 40073

# 拉取完整 RFC822 原文并导出为 .eml（支持直接传本地数字 ID 或远端 ID）
mailmaster fetch-mail --account user@163.com --mail-id 40073 --out message.eml
```

## Python 库

```python
from mailmaster import MailMaster

mm = MailMaster()

# 列出账号；支持邮箱地址、账号名或整数 account.id
for account in mm.get_accounts():
    print(account.id, account.email)

acc = mm.open_account("sender@example.com")

# 本地读取与搜索
for mail in acc.list_mail(limit=5):
    print(mail.local_id, mail.subject)

details = acc.get_details("40073")
print(details.content.text_body)

# 统一发信（自动选择 SMTP 或 163 私有通道，支持 Markdown、LaTeX 与附件）
result = acc.send_mail(
    to=["colleague@example.com"],
    subject="Hello",
    markdown_text="# 标题\n\n通过 `mailmaster` 发送。",
    attachments=[r"C:\path\report.pdf"],
)
print(result["transport"], result["status"])

# 标记已读与移动
acc.mark_read("40073")
acc.move_mail("40073", target_mailbox="Archive")
```

更多接口（草稿、批量操作、原文拉取、异常处理与底层协议会话）见 [`docs/library-api.md`](docs/library-api.md)。

## 使用须知

- 需要在 Windows 上安装并登录过网易邮箱大师（工具直接复用其本地数据库与已保存账号配置，无需开启客户端进程）。
- 账号口令仅在运行时内存中解密使用，不会另存到磁盘。
- 163/Wmsvr 账号执行 `delete-mail` 为服务端彻底删除（不进“已删除”文件夹），操作前请确认目标邮件。

## 文档

- [Agent Skill 指南](skill/SKILL.md)
- [Python SDK 与 CLI 参考](docs/library-api.md)
- [架构说明](docs/architecture.md)
- [更新记录](CHANGELOG.md)
- [贡献指南](CONTRIBUTING.md)
- [安全策略](SECURITY.md)
- [协议研究笔记](docs/reverse-engineering.md)

## 开发

```powershell
python -m pytest -q
python -m ruff check .
python -m ty check
```

## 许可

MIT，见 [`LICENSE`](LICENSE)。
