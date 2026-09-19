# AppSentinel for macOS

简体中文 | [English](README.md)

AppSentinel 是一款由用户控制的 macOS 安全工具，用于监控 Mac 所有者不完全信任的应用。用户选择一个应用，确认其预期权限，然后在明确的安全策略下运行它。

完整方案计划使用 Apple Endpoint Security 框架，在敏感操作完成前进行观察和授权，这需要 Apple 批准 `com.apple.developer.endpoint-security.client` 权限，而本项目目前尚未获得该权限。**本仓库目前提供的是在权限批准前可用的轻量监控版本**，完全基于 macOS 自带工具实现。具体能做到什么、做不到什么，请见下方[已知限制](#已知限制)。

任何 `.app` 都可以作为监控目标。项目第一个实际测试对象是一款网络代理应用（"猫熊网络"），但代码中的任何规则、路径或 Bundle ID 都不绑定该应用——AppSentinel 设计上可以指向所有者想要监控的任意应用。

## 状态

轻量监控版本：已实现、已测试、可直接运行，无需关闭系统完整性保护（SIP），也不依赖任何第三方库。

完整的 Endpoint Security 系统扩展：尚未实现，需要等待 Apple 批准权限。代码结构（见 `AppSentinelSystem` 中的适配器协议）已经为未来替换观察层做好准备，替换时无需改动策略判断逻辑。

## 轻量监控版本的能力

- 启动指定的 `.app` 并跟踪其完整子进程树，无论嵌套多少层。
- 在 `eslogger`（macOS 自带的 Endpoint Security 事件记录工具）可用时（需要 root 权限和完全磁盘访问权限）使用它进行近实时检测；不可用时自动降级为轮询模式，并在终端和会话日志中明确提示保护能力降低。
- 无论 `eslogger` 是否可用，都会始终并行运行一条独立的轮询检测路径（进程列表、证书、网络状态、受监控目录），作为不依赖特殊权限的二次验证。
- 检测并在触发严重违规时终止：
  - 未授权的 shell/AppleScript/解释器执行，或在临时目录新释放的可执行文件；
  - 对 SSH 私钥、浏览器凭据数据库、钥匙串文件、LaunchAgents/LaunchDaemons、登录项、系统扩展位置的读取或修改；
  - 策略之外的系统代理、DNS 或默认路由变化；
  - 登记窗口之外的证书新增/删除/信任变化。
- 触发严重违规时：先终止子进程，再终止根进程；将事件、进程祖先链（含可执行文件 SHA-256）、相关状态差异写入本地会话目录；并尝试恢复启动时记录的代理设置。证书、启动项、用户文件绝不会被自动删除——只报告，不自动撤销。
- 不上传任何数据。证据日志绝不包含文件内容或凭据，只包含路径、哈希值和判断结果。

## 构建

需要安装 Xcode 命令行工具（Swift 5.9+ / macOS 13+ SDK）。不依赖任何第三方包。

```bash
swift build
```

CLI 可执行文件位于 `.build/debug/appsentinel`（使用 `swift build -c release` 则在 `.build/release/appsentinel`）。

## 运行

```bash
appsentinel run /Applications/Example.app
```

参数说明：

| 参数 | 说明 |
|---|---|
| `--policy <文件>` | 加载 JSON 策略文件（见下方[策略文件](#策略文件)） |
| `--certificate-enrollment <时长>` | 开启证书登记窗口，例如 `5m`、`30s`、`1h`，窗口内最多允许一张新增证书 |
| `--allow-shell <路径>` | 允许目标运行指定 shell/解释器（可重复） |
| `--allow-script <路径>` | 允许目标运行指定脚本（可重复） |
| `--allow-path <路径>` | 声明受保护路径的例外（可重复） |
| `--log-dir <目录>` | 覆盖证据日志目录（主要用于测试） |
| `--no-eslogger` | 强制使用纯轮询模式 |

示例，对应设计文档中五分钟证书登记窗口的场景：

```bash
appsentinel run /Applications/Example.app \
  --certificate-enrollment 5m \
  --allow-shell /bin/zsh
```

证据日志保存在 `~/Library/Logs/AppSentinel/<会话ID>/` 下：`session.json`（会话摘要）、`events.ndjson`（所有已评估事件，每行一个紧凑 JSON 对象），以及仅在发生严重违规时生成的 `violation.json`（触发原因、含哈希的进程祖先链、状态差异）。

## 权限说明

- 轮询模式不需要任何特殊权限，这也是当前普通（非提权）运行时实际使用的模式。
- `eslogger` 需要以 root 身份运行，实际使用中还需要终端/宿主进程获得完全磁盘访问权限，因为它包装的正是完整系统扩展会用到的同一套 Endpoint Security 子系统。缺少任一条件时，AppSentinel 会在启动时自动检测并降级为轮询模式，不会卡死或静默失效。
- 轻量模式下，AppSentinel 完全不需要、也不会申请 Endpoint Security 的 `com.apple.developer.endpoint-security.client` 权限。

## 策略文件

策略文件是与 `SecurityPolicy` 字段直接对应的 JSON，参见 [`policies/example-policy.json`](policies/example-policy.json)：

```json
{
  "allowedShellExecutables": ["/bin/zsh"],
  "allowedScriptPaths": ["/Applications/Example.app/Contents/Resources/helper.sh"],
  "protectedPathExceptions": [],
  "allowedNetworkChanges": [
    { "field": "httpProxy", "allowedValue": "127.0.0.1:8080" },
    { "field": "httpsProxy", "allowedValue": "127.0.0.1:8080" }
  ],
  "certificateEnrollmentWindow": 300
}
```

`allowedNetworkChanges[].field` 取值为 `httpProxy`、`httpsProxy`、`dns`、`defaultRoute` 之一。不填 `allowedValue` 表示允许该字段任意变化；填写具体值则只允许变为该值。命令行参数（`--allow-shell`、`--allow-script`、`--allow-path`、`--certificate-enrollment`）会叠加在 `--policy` 文件声明的基础之上。

策略默认拒绝一切：凡未被明确声明允许的行为都被视为严重违规。

## 已知限制

这不是一款完整的杀毒软件，轻量模式的保护能力也确实弱于未来获批权限后的正式系统扩展：

- **无法做到动作发生前的真正拦截。** 没有 Endpoint Security 权限时，AppSentinel 只能在 `eslogger` 报告事件或轮询发现变化之后才作出响应，无法保证在每个操作完成之前进行拦截。速度极快的单次恶意动作可能在响应触发之前就已经完成。
- **轮询模式无法感知"读取"行为。** 单纯的文件读取不会改变文件的修改时间，因此轮询适配器——也就是在缺少 root/完全磁盘访问权限（这是最常见的情况）导致 `eslogger` 不可用时唯一在运行的检测手段——只能发现对受保护路径的写入（创建/修改/删除），无法发现读取。如果只读取 SSH 密钥而不做任何写入，轮询模式是看不到的。
- **轮询模式无法把受保护位置的变化精确归因到某个具体子进程。** 与 `eslogger` 不同，轮询只能知道某个受监控目录在会话期间发生了变化，无法确定是哪个进程做的。这类变化仍会被记录并仍会终止会话，只是证据中的进程祖先链无法精确定位到具体子进程。
- **证书/代理恢复是尽力而为。** AppSentinel 只恢复启动时记录的 HTTP/HTTPS 代理字段，且只针对恢复时默认路由所在网络接口对应的那个网络服务生效。它不会直接改动证书、DNS 或路由，也绝不会删除证书、启动项或文件——这些只会被报告，交由用户手动处理。
- **`eslogger` 的确切事件格式未经过本项目自身真实抓包验证**，因为运行它需要 root 权限，而本开发环境没有可交互的 `sudo` 权限。其 JSON 解析是依据 Apple 公开文档/典型字段结构进行防御性编写，并使用符合该结构的合成事件做了单元测试；如果实际字段名与预期确实不同，对应的那一条事件会被静默跳过（自动回退到始终在运行的轮询路径），而不会导致会话崩溃。

## 开发

```bash
swift build            # 构建全部目标
swift test              # 单元测试 + 集成测试（见下）
```

测试覆盖包括：进程树归属（只归属根进程及其子进程、多层子进程）、证书登记窗口规则（首张证书允许、窗口内第二张立即违规、窗口外新增违规）、受保护路径读写策略、允许与未授权的 shell 执行、网络状态策略、`eslogger` 不可用时的降级模式、子进程优先于根进程的终止顺序、证据日志绝不包含文件内容/凭据、目标正常退出时监控器同步退出。

集成验收测试（`Tests/appsentinelIntegrationTests`）在临时目录中针对无害的 shell 脚本 `.app` fixture，真实运行编译产物：其中一个测试端到端运行真实编译出的 `appsentinel run` 命令，验证正常启动/跟踪/退出流程（期间只调用真实但只读的系统命令）；另一个测试用注入的伪造证书/网络适配器驱动真实的 `Session`，验证严重违规的完整响应流程——包括真正终止一个（fixture）长期休眠的孙进程、以及"恢复"网络代理状态——全程不会调用真实的 `security`/`networksetup` 命令。

## 隐私

所有判断均在本机完成。AppSentinel 不上传事件数据、文件内容、凭据、浏览数据或个人信息。监控范围只包括 Mac 所有者选定的应用（及其子进程）和明确配置的受保护位置。

## 许可证

项目使用 MIT License，详见 [LICENSE](LICENSE)。
