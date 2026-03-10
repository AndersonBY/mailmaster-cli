# mailmaster

`mailmaster` 是一个面向已安装网易邮箱大师的 Windows 命令行工具，用于读取本地 MailMaster 数据，并通过动态解密得到的 SMTP 配置直接发送邮件。

它既适合人类直接使用，也适合 AI Agent / 脚本自动调用。

## 安装

### 使用 `uv tool install`

```powershell
uv tool install mailmaster
```

安装后直接使用：

```powershell
mailmaster doctor
```

### 不安装，直接通过 `uvx` 运行

```powershell
uvx mailmaster doctor
```

如果你需要可选的 LaTeX 图片渲染支持：

```powershell
uv tool install "mailmaster[latex-image]"

# 或者一次性运行
uvx --with "mailmaster[latex-image]" mailmaster doctor
```

## 核心功能

- 读取账号列表、文件夹、邮件列表、邮件详情
- 搜索本地邮件数据
- 动态解密当前账号 SMTP 配置并直接发送邮件
- 支持纯文本、HTML、Markdown、本地内联图片、普通附件、LaTeX 渲染模式
- 支持结构化 JSON 输出，便于 Agent / 脚本组合使用

## 输出格式

所有命令都支持全局 `--format` 参数：

```powershell
# 默认文本输出
mailmaster accounts

# 结构化 JSON 输出
mailmaster --format json accounts
mailmaster --format json smtp-send --from sender@example.com --to user@example.com --subject "Test" --body "Hello"
```

JSON 输出统一使用如下包装结构：

```json
{
  "ok": true,
  "command": "accounts",
  "data": {}
}
```

## 快速开始

### 作为 Python 库使用

```python
from mailmaster import MailMaster

mm = MailMaster()

for account in mm.get_accounts():
    print(account.email)

acc = mm.open_account("sender@example.com")

for mail in acc.list_mail(limit=5):
    print(mail.subject)

details = acc.get_details("40073")
print(details.content.text_body)

acc.send_markdown_email(
    to=["user@example.com"],
    subject="Hello",
    markdown_text="# Title\n\nHello from the library API.",
)
```

### 查看本地邮件数据

```powershell
mailmaster doctor
mailmaster accounts
mailmaster mailboxes --account sender@example.com
mailmaster list --account sender@example.com --mailbox 收件箱 --limit 10
mailmaster read --account sender@example.com --mail-id 40073
mailmaster search --account sender@example.com github --body --limit 5
```

### 通过 IMAP 修改邮件状态

```powershell
# 标记已读
mailmaster mark-read --account sender@example.com --mail-id 40073

# 标记未读
mailmaster mark-unread --account sender@example.com --mail-id 40073

# 移动到其他文件夹
mailmaster move-mail --account sender@example.com --mail-id 40073 --target-mailbox Archive

# 删除邮件
mailmaster delete-mail --account sender@example.com --mail-id 40073
```

### 发送邮件

`smtp-send` 会在发送时动态解析并解密当前账号的 SMTP 配置，不会把解密后的敏感凭据额外保存到本地配置文件。

#### 纯文本

```powershell
mailmaster smtp-send \
    --from sender@example.com \
    --to user@example.com \
    --subject "Test" \
    --body "Hello from mailmaster"
```

#### HTML

```powershell
mailmaster smtp-send \
    --from sender@example.com \
    --to user@example.com \
    --subject "HTML 邮件" \
    --html-body "<h1>Hello</h1><p>This is an HTML email.</p>"
```

#### Markdown

```powershell
mailmaster smtp-send \
    --from sender@example.com \
    --to user@example.com \
    --subject "Markdown 邮件" \
    --markdown-body "# Title\n\n- item 1\n- item 2\n\n**bold**"
```

#### 从 Markdown 文件读取

```powershell
mailmaster smtp-send \
    --from sender@example.com \
    --to user@example.com \
    --subject "Markdown file" \
    --markdown-file .\mail.md
```

#### 从标准输入读取 Markdown

```powershell
Get-Content .\mail.md | mailmaster smtp-send \
    --from sender@example.com \
    --to user@example.com \
    --subject "Markdown stdin" \
    --markdown-file -
```

#### Markdown 中的本地图片

如果 Markdown 文件里引用了本地图片，发送时会自动以内联图片方式嵌入邮件正文。

示例 Markdown：

```markdown
![Screenshot](C:/path/to/image.png)
```

#### 普通附件

```powershell
mailmaster smtp-send \
    --from sender@example.com \
    --to user@example.com \
    --subject "With attachment" \
    --body "See attachment." \
    --attach C:\path\to\attachment.png
```

可重复传入 `--attach` 以添加多个附件。

### LaTeX 渲染模式

Markdown 正文中的 LaTeX 支持以下模式：

- `auto`（默认）：如果安装了可选图片依赖，则优先使用图片模式；否则回退到 `raw`
- `mathml`：轻量依赖路径，但不同邮件客户端效果可能不稳定
- `image`：显示效果最好，需要安装 `mailmaster[latex-image]`
- `raw`：直接按原始公式文本展示

#### 默认 auto 模式

```powershell
mailmaster smtp-send \
    --from sender@example.com \
    --to user@example.com \
    --subject "LaTeX auto" \
    --markdown-body "Inline formula $E=mc^2$"
```

#### 强制使用 MathML 模式

```powershell
mailmaster smtp-send \
    --from sender@example.com \
    --to user@example.com \
    --subject "LaTeX MathML" \
    --markdown-body "Formula $E=mc^2$" \
    --latex-mode mathml
```

#### 强制使用图片模式

```powershell
mailmaster smtp-send \
    --from sender@example.com \
    --to user@example.com \
    --subject "LaTeX image" \
    --markdown-body "Formula $\\alpha + \\beta$" \
    --latex-mode image
```

## 发布与调用方式

本项目已按 PyPI 发布场景配置，可支持：

- `uv tool install mailmaster`
- `uvx mailmaster ...`

安装后会同时暴露两个命令入口：

- `mailmaster`
- `mailmaster`

## 逆向分析文档

当前逆向分析整理位于：

- `docs/reverse-engineering.md`

面向 Python 库使用的接口说明位于：

- `docs/library-api.md`
