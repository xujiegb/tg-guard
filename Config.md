## 单群模版
```congig
# =========================
# tg-guard config.yaml
# =========================

bot:
  # Telegram Bot Token
  token: "123456:ABCDEF_your_bot_token_here"

  # Long polling timeout (seconds)
  # 建议 20~30
  polling_timeout_secs: 25

  # tracing 日志级别
  # trace | debug | info | warn | error
  log_level: "info"

# =========================
# runtime settings
# =========================
runtime:
  # 数据目录（持久化 verify / warn / snapshot）
  data_dir: "./data"

  # 是否合并新成员提示（防刷屏）
  merge_group_notice: true

  # 合并提示时间窗口（秒）
  merge_group_notice_interval_secs: 8

  # 合并时最多显示多少个用户名
  merge_group_notice_max_names: 6

  # snapshot 自动清理
  snapshots:
    enable_daily_cleanup: true

    # 保留多少天的 snapshot
    retention_days: 7

    # 每天 UTC 时间点清理（HH:MM）
    daily_cleanup_at: "03:30"

    # 磁盘水位保护
    enable_disk_guard: true

    # 剩余空间低于该百分比触发清理
    disk_free_percent_low: 10

    # 触发时删除最老的比例
    delete_oldest_fraction: 0.35

    # 文件名前后缀（一般不用改）
    filename_prefix: "group_"
    filename_suffix: ".json"

# =========================
# group list
# =========================
groups:
  - name: "Example Group"
    chat_id: -1001234567890   # ⚠️ 必须是群的真实 chat_id

    # 是否忽略管理员（true = 管理员不触发规则）
    ignore_admins: true

    # -------------------------
    # 入群验证
    # -------------------------
    join_verification:
      enabled: true

      # 新人入群先限制的权限
      restrict:
        can_send_messages: false
        can_send_media_messages: false
        can_send_polls: false
        can_send_other_messages: false
        can_add_web_page_previews: false
        can_change_info: false
        can_invite_users: false
        can_pin_messages: false

      # 题库（按钮验证）
      questions:
        - id: "q1"
          prompt: "Linux 的创始人是谁？"
          options:
            - "Linus Torvalds"
            - "Richard Stallman"
            - "Bill Gates"
            - "Steve Jobs"
          # ⚠️ answer 必须等于 options 中某一项（文本精确匹配）
          answer: "Linus Torvalds"

        - id: "q2"
          prompt: "以下哪个不是 Linux 发行版？"
          options:
            - "Ubuntu"
            - "Debian"
            - "Fedora"
            - "Windows"
          answer: "Windows"

      # 验证超时时间（秒）
      timeout_secs: 300

      # 最大重试次数
      # 0 = 一次答错直接失败
      max_attempts: 2

      # 群内合并提示模板
      # 可用变量：
      # {names} {group_name} {bot_username} {slowest}
      group_notice_template: |
        👋 欢迎 {names} 加入 {group_name}
        请私聊 {bot_username} 完成入群验证

      # 私聊题目开头说明
      dm_intro: |
        你正在加入 {group_name}
        请在 {timeout_secs} 秒内完成验证：

      # 验证失败处理
      on_fail:
        # kick | ban
        action: kick

        # ban 时才生效
        # <=0 或不写 = 永久
        ban_minutes: 0

        # 失败原因（可选）
        reason: "未通过入群验证"

      # 验证通过
      on_pass:
        welcome_dm: "✅ 验证通过，欢迎加入群组！"

    # -------------------------
    # 自动回复规则
    # -------------------------
    auto_replies:
      - name: "hello_reply"
        match:
          any_keywords:
            - "hello"
            - "你好"
        reply: "你好 👋 有问题可以直接问"

    # -------------------------
    # 警告规则（累计）
    # -------------------------
    warnings:
      - name: "spam_warning"
        match:
          any_keywords:
            - "http://"
            - "https://"
        warn_message: "⚠️ 请勿发送链接（{count}/{limit}）"
        window_minutes: 10
        limit: 3
        on_limit:
          action: kick
          reason: "多次发送链接"

    # -------------------------
    # 直接踢 / 封规则
    # -------------------------
    kicks:
      - name: "ads"
        match:
          regex:
            - "(?i)免费机场"
            - "(?i)vpn"
        action: kick
        delete_message: true
        reason: "广告"

    # -------------------------
    # 群命令
    # -------------------------
    commands:
      enabled: true
      admin_only: true
      prefix: "/"
```
## 多群模版
```config
# =========================
# tg-guard multi-group config
# =========================

bot:
  token: "123456:ABCDEF_your_bot_token_here"
  polling_timeout_secs: 25
  log_level: "info"

runtime:
  data_dir: "./data"

  merge_group_notice: true
  merge_group_notice_interval_secs: 8
  merge_group_notice_max_names: 6

  snapshots:
    enable_daily_cleanup: true
    retention_days: 7
    daily_cleanup_at: "03:30"
    enable_disk_guard: true
    disk_free_percent_low: 10
    delete_oldest_fraction: 0.35
    filename_prefix: "group_"
    filename_suffix: ".json"

# =========================
# group definitions
# =========================
groups:

  # =====================
  # 群 1：技术交流群
  # =====================
  - name: "Linux Tech Group"
    chat_id: -1001111111111
    ignore_admins: true

    join_verification:
      enabled: true
      restrict:
        can_send_messages: false
        can_send_media_messages: false
        can_send_polls: false
        can_send_other_messages: false
        can_add_web_page_previews: false
        can_change_info: false
        can_invite_users: false
        can_pin_messages: false

      questions:
        - id: "linux_q1"
          prompt: "Linux 内核的作者是谁？"
          options:
            - "Linus Torvalds"
            - "Richard Stallman"
            - "Ken Thompson"
          answer: "Linus Torvalds"

      timeout_secs: 300
      max_attempts: 2

      group_notice_template: |
        👋 欢迎 {names} 加入 Linux 技术群
        请私聊 {bot_username} 完成验证

      dm_intro: |
        欢迎加入 Linux 技术群
        请在 {timeout_secs} 秒内完成验证：

      on_fail:
        action: kick
        reason: "未通过入群验证"

      on_pass:
        welcome_dm: "✅ 验证通过，欢迎来到 Linux 技术群！"

    auto_replies:
      - name: "hello"
        match:
          any_keywords: ["hello", "你好"]
        reply: "你好 👋 有问题可以直接提"

    warnings:
      - name: "link_warn"
        match:
          any_keywords: ["http://", "https://"]
        warn_message: "⚠️ 请勿发链接（{count}/{limit}）"
        window_minutes: 10
        limit: 3
        on_limit:
          action: kick
          reason: "多次发送链接"

    kicks:
      - name: "ads"
        match:
          regex:
            - "(?i)vpn"
            - "(?i)机场"
        action: kick
        delete_message: true
        reason: "广告"

    commands:
      enabled: true
      admin_only: true
      prefix: "/"

  # =====================
  # 群 2：水群（宽松）
  # =====================
  - name: "Water Chat"
    chat_id: -1002222222222
    ignore_admins: true

    join_verification:
      enabled: false   # ❗不启用入群验证

      restrict:
        can_send_messages: true
        can_send_media_messages: true
        can_send_polls: true
        can_send_other_messages: true
        can_add_web_page_previews: true
        can_change_info: false
        can_invite_users: true
        can_pin_messages: false

      questions: []    # 未启用可留空
      timeout_secs: 0
      max_attempts: 0
      group_notice_template: ""
      dm_intro: ""

      on_fail:
        action: kick

      on_pass: {}

    auto_replies:
      - name: "bot_ping"
        match:
          any_keywords: ["bot", "机器人"]
        reply: "🤖 在的，在的"

    warnings: []

    kicks: []

    commands:
      enabled: false

  # =====================
  # 群 3：公告 / 广播群
  # =====================
  - name: "Announcement Channel"
    chat_id: -1003333333333
    ignore_admins: true

    join_verification:
      enabled: false
      restrict:
        can_send_messages: false
        can_send_media_messages: false
        can_send_polls: false
        can_send_other_messages: false
        can_add_web_page_previews: false
        can_change_info: false
        can_invite_users: false
        can_pin_messages: false
      questions: []
      timeout_secs: 0
      max_attempts: 0
      group_notice_template: ""
      dm_intro: ""
      on_fail:
        action: kick
      on_pass: {}

    auto_replies: []
    warnings: []
    kicks: []

    commands:
      enabled: false
```
