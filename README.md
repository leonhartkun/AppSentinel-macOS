# AppSentinel for macOS

[简体中文](README.zh-CN.md) | English

AppSentinel is a user-controlled macOS security utility for monitoring applications that the Mac owner does not fully trust. A user selects an application, reviews the permissions it is expected to need, and runs it under an explicit security policy.

The full design intends to use Apple's Endpoint Security framework to observe and authorize security-sensitive operations before they complete. That requires Apple's `com.apple.developer.endpoint-security.client` entitlement, which this project does not yet have. **This repository currently ships the lightweight monitor**, built entirely from tools already on macOS, that runs while the entitlement request is pending. See [Limitations](#limitations) below for exactly what that does and does not guarantee.

Any `.app` can be a target. The project's first real-world test subject is a network proxy application ("猫熊网络"), but no rule, path, or bundle identifier in the code is specific to it — AppSentinel is meant to be pointed at any application the owner wants watched.

## Status

Lightweight monitor: implemented, tested, and runnable today without disabling System Integrity Protection or installing any third-party dependency.

Full Endpoint Security system extension: not implemented. It requires Apple's entitlement approval; the codebase is structured (see `AppSentinelSystem`'s adapter protocols) so that layer can be swapped in later without changing policy logic.

## What the lightweight monitor does

- Launches a `.app` you specify and tracks its full descendant process tree, at any depth.
- Uses `eslogger` (macOS's built-in Endpoint Security event logger) for near-real-time detection when it is available (requires root + Full Disk Access); otherwise falls back to polling and makes that degradation explicit in the terminal and in the session log.
- Always runs an independent polling pass (process list, certificates, network state, watched directories) alongside `eslogger`, as a second, privilege-free verification path.
- Flags and, on a critical violation, terminates the monitored tree for:
  - unauthorized shell/AppleScript/interpreter execution, or a newly dropped executable in a temp location;
  - reads or writes to SSH private keys, browser credential databases, keychain files, LaunchAgents/LaunchDaemons, login items, and system extension locations;
  - system proxy, DNS, or default-route changes outside the declared policy;
  - certificate additions/removals/trust changes outside an explicit enrollment window.
- On a critical violation: terminates descendants before the root process, writes evidence (event, process ancestry with executable SHA-256 hashes, and any relevant state diff) to a local session directory, and attempts to restore the proxy configuration captured at launch. It never auto-deletes certificates, launch items, or user files — those are reported, not reversed.
- Writes nothing off the Mac. Evidence logs never contain file contents or credential material — only paths, hashes, and decisions.

## Building

Requires Xcode's command line tools (Swift 5.9+ / macOS 13+ SDK). No third-party package dependencies are used.

```bash
swift build
```

The CLI binary is produced at `.build/debug/appsentinel` (or `.build/release/appsentinel` with `swift build -c release`).

## Running

```bash
appsentinel run /Applications/Example.app
```

Options:

| Flag | Meaning |
|---|---|
| `--policy <file>` | Load a JSON policy file (see [Policy files](#policy-files)) |
| `--certificate-enrollment <duration>` | Open a certificate enrollment window, e.g. `5m`, `30s`, `1h`. At most one new certificate is permitted inside it. |
| `--allow-shell <path>` | Allow the target to run a specific shell/interpreter (repeatable) |
| `--allow-script <path>` | Allow the target to run a specific script (repeatable) |
| `--allow-path <path>` | Declare an exception to the default protected-path block (repeatable) |
| `--log-dir <dir>` | Override the evidence log directory (mainly for testing) |
| `--no-eslogger` | Force polling-only mode |

Example, matching the design's five-minute certificate-enrollment scenario:

```bash
appsentinel run /Applications/Example.app \
  --certificate-enrollment 5m \
  --allow-shell /bin/zsh
```

Evidence logs land under `~/Library/Logs/AppSentinel/<session-id>/`: `session.json` (summary), `events.ndjson` (every evaluated event, one compact JSON object per line), and — only if a critical violation occurred — `violation.json` (triggering reason, process ancestry with hashes, and state diff).

## Permissions

- No permission is required to run in polling mode. This is what a normal, non-elevated run uses today.
- `eslogger` requires the process to run as root and (in practice) the terminal/host process to have Full Disk Access, since it wraps the same Endpoint Security subsystem the full system extension would use. Without both, AppSentinel detects this automatically at startup and falls back to polling — it does not hang or silently do nothing.
- AppSentinel never asks for or needs Endpoint Security's `com.apple.developer.endpoint-security.client` entitlement in this lightweight mode.

## Policy files

A policy file is JSON matching `SecurityPolicy`'s fields directly; see [`policies/example-policy.json`](policies/example-policy.json):

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

`allowedNetworkChanges[].field` is one of `httpProxy`, `httpsProxy`, `dns`, `defaultRoute`. Omitting `allowedValue` allows any change to that field; setting it restricts the allowance to that exact value. CLI flags (`--allow-shell`, `--allow-script`, `--allow-path`, `--certificate-enrollment`) are additive on top of whatever a `--policy` file declares.

The policy is deliberately deny-by-default: anything not explicitly declared allowed is a critical violation.

## Limitations

This is not a full antivirus product, and the lightweight mode is honestly weaker than the entitled system extension it is meant to be replaced by once approved:

- **No true pre-action blocking.** Without the Endpoint Security entitlement, AppSentinel reacts *after* an event is reported by `eslogger` or discovered by polling — it cannot guarantee interception before every operation completes. A fast, single-shot malicious action can complete before the response fires.
- **Polling mode cannot see reads.** A plain file read never changes a file's modification time, so the polling adapter — the *only* detector active when `eslogger` is unavailable, which is the common case without root/Full Disk Access — can detect protected-path *writes* (create/modify/delete) but not reads. Reading an SSH key without also writing anywhere is invisible to polling.
- **Polling attributes protected-location changes to the session, not to a specific descendant process.** Unlike `eslogger`, polling cannot tell *which* process wrote a watched file — only that it changed during the session. This is still logged and still stops the session; the ancestry evidence just won't pinpoint the exact child.
- **Certificate/proxy recovery is best-effort.** AppSentinel restores only the HTTP/HTTPS proxy fields it captured at launch, and only for the network service matching the default route's interface at the time of recovery. It never touches certificates, DNS, or routing directly, and never deletes a certificate, launch item, or file — those are reported for manual review.
- **eslogger's exact event schema was not empirically verified against this project's own captured output**, since running it requires root and this development environment does not have interactive `sudo` access. Its JSON parsing was written defensively against Apple's documented/typical field layout and unit-tested against synthetic events of that shape; a genuinely different real-world field name would cause that specific event to be silently skipped (falling through to the always-on polling path) rather than crash the session.

## Development

```bash
swift build            # build everything
swift test              # unit + integration tests (see below)
```

Test coverage includes: process-tree attribution (root + descendants only, multi-level), certificate enrollment window rules (first certificate allowed, second immediately critical, outside-window critical), protected-path read/write policy, allowed vs. unauthorized shell execution, network-state policy, `eslogger`-unavailable degraded mode, descendants-before-root termination ordering, evidence logs never containing file contents/credentials, and the monitor exiting when the target exits normally.

Integration acceptance tests (`Tests/appsentinelIntegrationTests`) run the real, compiled CLI binary and a real `Session` against harmless shell-script `.app` fixtures in temporary directories: one drives the actual `appsentinel run` command end-to-end for the normal-launch/track/exit path (touching only real, read-only system calls); the other drives `Session` with synthetic certificate/network adapters injected, to prove a real critical-violation response — including killing a real (fixture) grandchild process and restoring "proxy" state — without ever calling the real `security`/`networksetup` tools.

## Privacy

Events are evaluated locally. AppSentinel does not upload event data, file contents, credentials, browsing data, or personal information. Monitoring is limited to the application selected by the Mac owner (and its descendants) plus explicitly protected locations.

## License

MIT License. See [LICENSE](LICENSE).
