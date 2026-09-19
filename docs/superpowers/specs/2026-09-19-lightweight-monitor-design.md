# AppSentinel Lightweight Monitor Design

[简体中文](2026-09-19-lightweight-monitor-design.zh-CN.md) | English

## Goal

AppSentinel launches and monitors any macOS application selected by the Mac owner. The lightweight version provides useful protection while the Endpoint Security entitlement is pending. It uses only built-in macOS facilities and does not require disabling System Integrity Protection.

The first real-world target is a network proxy application, but no rule or component is tied to a specific vendor or bundle identifier.

## User flow

1. The user runs `appsentinel run /Applications/Example.app`.
2. AppSentinel records the target's identity and a baseline of protected system state.
3. AppSentinel launches the target and watches its full descendant process tree.
4. The monitor exits when the target and its descendants exit.
5. On a critical policy violation, AppSentinel records evidence, terminates the monitored process tree, and restores proxy settings captured at launch when possible.

The CLI is the first interface. A native graphical launcher can use the same monitor core later without changing policy behavior.

## Monitoring model

The monitor combines three sources:

- `eslogger` for near-real-time process and file-system events on supported macOS versions. AppSentinel starts it only for the duration of a monitored session.
- Periodic process-tree and network-state inspection as a fallback and as independent verification.
- Before/after snapshots for certificates, launch items, system extensions, proxy settings, and protected user paths.

If `eslogger` is unavailable or lacks permission, AppSentinel continues in degraded mode and makes that state prominent in both terminal output and the session log.

## Policy

Policies are scoped to the selected application and its descendants. AppSentinel does not collect unrelated system activity in its evidence log.

Critical events terminate the monitored process tree:

- creating or changing a LaunchAgent, LaunchDaemon, login item, or system extension;
- reading or changing SSH private keys, browser credential databases, password stores, or unrelated keychain material;
- executing an unapproved shell, AppleScript, or newly dropped executable;
- changing system proxy, DNS, or routing state outside the target's declared session policy;
- adding, deleting, replacing, or changing trust for certificates outside an active enrollment window.

Certificate enrollment is explicit. A session can allow a five-minute enrollment window, during which at most one newly added certificate is recorded. The certificate is not silently trusted by AppSentinel; macOS still controls trust authorization. Any additional certificate change is critical.

The initial policy is deliberately conservative. Expected executables, scripts, network changes, and certificate enrollment must be granted through command-line options or a policy file before launch.

## Response and recovery

On a critical event AppSentinel:

1. freezes or terminates descendants before terminating the root process;
2. writes the triggering event, process ancestry, executable hashes, and relevant before/after state to a local session directory;
3. restores the launch-time system proxy configuration when the monitor can do so without changing unrelated interfaces;
4. reports actions it could not safely reverse.

The lightweight version never automatically deletes certificates, launch items, or user files. It preserves evidence and reports exact remediation commands for user review.

## Privacy and storage

Logs remain under `~/Library/Logs/AppSentinel/`. They contain only events attributed to the monitored process tree plus state changes in explicitly protected locations. File contents, credentials, and browser data are never copied into logs. No data leaves the Mac.

## Implementation structure

- `AppSentinelCore`: process identity, ancestry tracking, policy evaluation, baselines, evidence records, and response decisions.
- `AppSentinelSystem`: adapters for `eslogger`, process inspection, certificates, protected paths, network state, and termination.
- `appsentinel`: CLI for selecting the target, declaring expected behavior, launching, monitoring, and presenting results.

Policy evaluation is pure Swift and tested with synthetic events. System adapters expose narrow protocols so tests can exercise response logic without modifying the real Mac.

## Verification

Automated tests cover process-tree attribution, certificate enrollment limits, protected-path rules, allowed shell execution, network-state policy, degraded mode, and critical-event response ordering.

Integration checks use harmless fixture processes and temporary directories. They verify launch/exit coupling, descendant tracking, local evidence creation, and termination of a deliberately violating fixture. Tests do not change real certificates, system proxy settings, or production launch-item directories.

## Limitations

Without the Endpoint Security entitlement, the lightweight monitor observes and reacts after an event is reported. It cannot guarantee prevention before every operation completes. Polling fallback has a larger detection window. These limits are always shown to the user and are removed only when the authorized Endpoint Security system extension replaces the observation layer.
