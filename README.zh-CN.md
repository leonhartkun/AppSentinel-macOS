# AppSentinel for macOS

简体中文 | [English](README.md)

AppSentinel 是一款由用户控制的 macOS 安全工具，用于监控 Mac 所有者不完全信任的应用。用户选择一个应用，确认其预期权限，然后在明确的安全策略下运行它。

项目使用 Apple Endpoint Security 框架，在敏感操作完成前进行观察和授权。设计重点是范围明确、可以解释的策略，而不是采集整台电脑的活动。

## 计划能力

- 跟踪用户指定的应用及其完整子进程树。
- 阻止意外启动的可执行文件、脚本和提权行为。
- 保护持久化位置、用户凭据、浏览器数据、SSH 配置和其他敏感路径。
- 检测系统代理、DNS、路由、证书、登录项、LaunchAgent、LaunchDaemon 和系统扩展的变化。
- 为安装本地代理证书等预期操作提供明确、限时的登记窗口。
- 违反策略时停止受监控进程树，并在本地保存证据日志。

## 隐私

Endpoint Security 事件全部在本机判断。AppSentinel 不上传事件数据、文件内容、凭据、浏览数据或个人信息。监控范围只包括 Mac 所有者选定的应用和明确配置的受保护位置。

## 状态

AppSentinel 目前处于早期开发阶段。授权模式需要 Apple 批准 `com.apple.developer.endpoint-security.client` 权限，才能在正常启用系统安全保护的 Mac 上运行 Endpoint Security 系统扩展。

## 许可证

项目使用 MIT License，详见 [LICENSE](LICENSE)。
