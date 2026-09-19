import Foundation

enum CLIEntryPoint {
    static let helpText = """
    AppSentinel —— macOS 轻量应用监控器

    用法：
      appsentinel run <应用路径> [选项]

    选项：
      --policy <文件>                 加载 JSON 策略文件
      --certificate-enrollment <时长>  开启证书登记窗口，例如 5m、30s
      --allow-shell <路径>             允许目标运行指定 shell/解释器（可重复）
      --allow-script <路径>            允许目标运行指定脚本（可重复）
      --allow-path <路径>              声明受保护路径的例外（可重复）
      --log-dir <目录>                 覆盖默认证据日志目录（用于测试）
      --no-eslogger                    强制使用轮询降级模式

    示例：
      appsentinel run /Applications/Example.app \\
        --certificate-enrollment 5m \\
        --allow-shell /bin/zsh
    """

    static func run(arguments: [String]) -> Never {
        let output = TerminalOutput()

        guard let subcommand = arguments.first else {
            output.critical(ArgumentParsingError.missingSubcommand.description)
            output.line(helpText)
            exit(64)
        }

        if subcommand == "--help" || subcommand == "-h" {
            output.line(helpText)
            exit(0)
        }

        guard subcommand == "run" else {
            output.critical(ArgumentParsingError.unknownSubcommand(subcommand).description)
            output.line(helpText)
            exit(64)
        }

        do {
            let options = try ArgumentParser.parseRun(Array(arguments.dropFirst()))
            let session = Session(options: options)
            let code = session.run()
            exit(code)
        } catch {
            output.critical("\(error)")
            exit(64)
        }
    }
}
