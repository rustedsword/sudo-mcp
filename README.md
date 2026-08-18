# sudo-mcp

A local stdio MCP server that runs a command through `sudo` and, when authentication is required, asks the connected MCP client to collect the password.

> [!CAUTION]
> This form-based password prompt is an intentional, stdio-only deviation and is **not MCP-compliant**. The specification says servers must not request passwords or other credentials with form-mode elicitation and must use URL mode instead. This binary only implements stdio and is designed for a trusted client connected through a direct local pipe. See [Protocol and security warning](#protocol-and-security-warning).

> [!WARNING]
> `sudo-mcp` has no command denylist. Any command accepted by the tool is eligible to run as root. Use a restrictive `sudoers` rule, a wrapper, or another sandbox if you do not intend to grant arbitrary root execution.

## How it works

The agent calls `sudo_run` with an argument vector and a reason. The server then:

1. Starts the exact requested command once with `sudo -A -k` and a private askpass bridge. Command-mode `-k` makes sudo ignore existing cached credentials and prevents successful authentication from updating the credential cache.
2. If a command-specific `NOPASSWD` rule applies, sudo never starts the bridge helper. The command runs immediately and no password prompt appears.
3. Otherwise the helper connects to the server, proves possession of a fresh one-use bridge capability, and blocks before the requested command can start. The server then sends an MCP form elicitation request containing one string field named `password`.
4. After acceptance, the server passes the password to that helper over its private socket. The helper writes it to the same sudo process's dedicated askpass channel, and sudo authenticates and starts the already-authorized command. This does not depend on a reusable timestamp credential.
5. The command receives `/dev/null` as stdin. Its exit code, stdout, and combined sudo/PAM/command stderr are returned without any password-dependent transformation.

On Linux and macOS, the server and helper communicate over a temporary Unix-domain socket inside a mode-`0700` directory. Before requesting or sending a password, the server checks the socket peer's kernel-reported UID and PID, verifies that it descends from the exact spawned sudo process, verifies the executable's file identity, and requires a fresh random 256-bit capability. That capability is supplied under an unpredictable per-call environment variable name, removed by the helper before it connects, and compared without an early-exit byte comparison. A same-user sibling cannot win the socket race using the public protocol marker, and a target-command descendant cannot impersonate askpass merely by launching the genuine binary. Passwords are limited to the 255-byte conversation reply boundary shared by supported sudo 1.8 and 1.9 releases; embedded NUL and line-break bytes are rejected so sudo consumes the complete value supplied through the bridge. The password never becomes command stdin, and the server drops its working copy after sending it to the authenticated helper. No returned output is inspected or changed based on the password. Cleanup is only best effort; the MCP client, protocol implementation, allocator, crash dumps, and other process memory may retain copies.

If a client does not declare form-elicitation support, `sudo-mcp` falls back to its original native `SUDO_ASKPASS` dialog. The exact authorization text is stored in a mode-`0600` file inside a private temporary directory. The helper verifies the bytes it reads against a server-provided SHA-256 digest and refuses to display modified content. Only the short path and fixed-size digest are placed in the helper environment:

![sudo-mcp native fallback dialog](docs/dialog.png)

Declining or cancelling an MCP prompt stops the call. It does not trigger a second native prompt.

## Protocol and security warning

The [MCP elicitation specification](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation) explicitly requires URL mode for passwords and other sensitive credentials. This implementation deliberately makes a narrower tradeoff that the protocol does not recognize: it assumes both the client and this server are trusted local processes connected directly over stdio. The server has no HTTP or TCP transport and opens no network listener. Its temporary Unix-domain bridge does carry the password between two processes of this local server.

That tradeoff has concrete consequences:

- The password crosses the local MCP JSON-RPC transport and the private Unix-domain askpass bridge. It is visible to the MCP client. It is not a `sudo_run` argument and is never intentionally included in the tool result sent to the model, but the project cannot guarantee that a client will not log, persist, inspect, or expose it.
- The complete stderr stream is returned unchanged because filtering it based on the submitted password would create a candidate-testing oracle. This project trusts the local sudo/PAM authentication stack not to echo credentials; a broken backend that does so can expose the password in the tool result.
- Standard MCP form schemas have no secret/password field type. The current Codex TUI renders standard string fields as non-secret text, so the value is visible while it is typed; other clients may do the same.
- A compromised client, server binary, debugger, or same-user process with sufficient inspection privileges can obtain the password.
- The bridge capability relies on sudo's normal separation between its inherited authentication environment and the environment constructed for the requested command. Do not disable `env_reset` or wildcard-preserve the complete caller environment for commands exposed through this server; either can deliberately pass the capability to the requested command. A root command able to inspect another process's protected environment is already within the preceding inspection-privilege limitation.
- Stdio can still be relayed by an external wrapper such as `ssh` or an MCP bridge. Doing that would send the password through the relay and falls outside this project's direct-local-pipe assumption.
- Every command is run with sudo's command-mode `-k`: existing cached credentials are ignored, and successful authentication does not update the timestamp cache. Each command governed by a `PASSWD` rule therefore requires independent authentication. An explicit `NOPASSWD` rule, `exempt_group`, or another policy-level authentication exemption still takes precedence.

For a standards-compliant secret flow, use URL-mode elicitation with an out-of-band local web UI, or keep using the native askpass fallback. Both introduce a UI outside the model harness, which is precisely the tradeoff this experiment is exploring.

## Install

The server requires `sudo`. Building from source requires a stable Rust toolchain. The native fallback works out of the box on macOS; on Linux it needs at least one of `ssh-askpass`, `ksshaskpass`, `zenity`, or `kdialog`.

### From source

```sh
cargo install --locked --path .
```

The binary lands in Cargo's bin directory, typically `~/.cargo/bin/sudo-mcp`. Use an absolute path when registering it so the MCP client does not depend on shell PATH setup.

### Prebuilt binary

Download the archive for your OS and architecture from the [latest release](https://github.com/0xMH/sudo-mcp/releases/latest), then verify its SHA-256 against `checksums.txt` from the same release before running it. Version 0.1.0 predates MCP form elicitation and uses only the native askpass dialog; build 0.2.0 from source until a matching prebuilt release is available.

## Configure Codex

Build the release binary and register it as a local stdio server:

```sh
cargo build --release --locked
codex mcp add sudo-mcp -- /absolute/path/to/sudo-mcp/target/release/sudo-mcp
codex mcp list
```

Codex must also be configured to surface MCP elicitations. If your current policy is `approval_policy = "never"` and you want every other prompt category to remain auto-rejected, use this narrow granular policy in `~/.codex/config.toml`:

```toml
approval_policy = { granular = { sandbox_approval = false, rules = false, mcp_elicitations = true, request_permissions = false, skill_approval = false } }
```

Restart Codex after changing the MCP list or approval policy. `sudo-mcp` ignores cached credentials itself, so every command governed by a `PASSWD` rule prompts independently; commands governed by `NOPASSWD` do not. Never put the password in chat or in the tool arguments.

## Configure Claude Code

Register the server at user scope:

```sh
claude mcp add sudo-mcp --scope user -- ~/.cargo/bin/sudo-mcp
claude mcp list
```

To make Claude prefer `sudo_run` over invoking `sudo` through Bash, deny direct sudo calls in `~/.claude/settings.json`:

```json
{
  "permissions": {
    "deny": ["Bash(sudo *)", "Bash(sudo)"],
    "allow": ["mcp__sudo-mcp__sudo_run"]
  }
}
```

## Tool reference

`sudo_run` accepts:

- `argv` (string array, required): the command and arguments, such as `["apt", "install", "-y", "htop"]`. The server executes this list directly without a shell.
- `reason` (string, required): a short justification shown alongside the exact argument vector before the user provides a password.
- `timeout_seconds` (integer, optional, default 120, max 3600): the command timeout. On Unix, the server starts `sudo` in its own process group and attempts to terminate that group on timeout.
- `cwd` (string, optional): the command's working directory.

The result is a text block containing the exit code, stdout, and combined sudo/PAM/command stderr. At most 256 KiB from each output stream is rendered as text, with invalid UTF-8 replaced. Output is never filtered based on the submitted password, so a command or defective local authentication backend can expose secrets through its output.

## Additional security properties and limits

- `argv` is a list rather than a shell string; `sudo-mcp` does not interpolate it through `bash -c`.
- The server resolves a root-owned, executable `sudo` binary that is not writable by group or others.
- Authorization values are rendered losslessly as inert ASCII: controls, Unicode layout/bidirectional characters, non-ASCII lookalikes, and literal backslashes are escaped rather than normalized or trimmed.
- Cached credentials are deliberately ignored and not refreshed, so each `PASSWD` command authenticates independently. Command-specific `NOPASSWD` rules remain passwordless as required by sudoers policy, without probing or retrying a command that may already have run.
- MCP bridge connectors must match the expected UID, sudo-process ancestry, executable identity, and fresh one-use capability before elicitation begins. Invalid or stale connectors receive no password bytes.
- Output rendering never depends on the submitted password, avoiding a candidate-testing oracle. Stdout and the combined sudo/PAM/command stderr stream receive only content-independent size bounds and text conversion. This deliberately relies on the trusted local authentication stack not to echo the password.
- The native fallback rejects rendered authorization text larger than 32 KiB before starting sudo and independently caps the complete GUI prompt at 60 KiB. Accepted text is stored in a bounded private context file; only its short path and fixed-size SHA-256 digest cross the environment, and the helper rejects replacement or modification before displaying it.
- The native askpass fallback keeps the password out of MCP, but its security still depends on the selected OS prompt helper.
- Timeout cleanup is not a sandbox. A command that daemonizes, changes its process group or session, or is protected by restrictive sudo policy may survive the MCP call.
- Restricting direct `sudo` use in an agent's shell configuration is recommended; otherwise the MCP tool is not an exclusive privilege boundary. `sudo-mcp` cannot force `-k` onto sudo processes started elsewhere. For a policy-level no-cache guarantee, an administrator can additionally set `Defaults:username timestamp_timeout=0` in sudoers.

## License

MIT. See [LICENSE](LICENSE).
