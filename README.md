# AppSentinel for macOS

[简体中文](README.zh-CN.md) | English

AppSentinel is a user-controlled macOS security utility for monitoring applications that the Mac owner does not fully trust. A user selects an application, reviews the permissions it is expected to need, and runs it under an explicit security policy.

The project uses Apple's Endpoint Security framework to observe and authorize security-sensitive operations before they complete. It is designed for narrow, explainable policies rather than system-wide collection.

## Intended capabilities

- Track a selected application and its complete descendant process tree.
- Block unexpected executables, scripts, and privilege-escalation attempts.
- Protect persistence locations, user credentials, browser data, SSH configuration, and other sensitive paths.
- Detect changes to system proxy, DNS, routes, certificates, login items, launch agents, daemons, and system extensions.
- Support explicit, time-limited enrollment for expected actions such as installing a required local proxy certificate.
- Stop the monitored process tree and preserve a local evidence log when a policy violation occurs.

## Privacy

Endpoint Security events are evaluated locally. AppSentinel does not upload event data, file contents, credentials, browsing data, or personal information. Monitoring is limited to applications selected by the Mac owner and explicitly protected locations.

## Status

AppSentinel is in early development. The Endpoint Security system extension requires the `com.apple.developer.endpoint-security.client` entitlement from Apple before authorization-mode builds can run on a normally secured Mac.

## License

MIT License. See [LICENSE](LICENSE).
