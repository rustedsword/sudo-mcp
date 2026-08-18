use std::fmt::Write as _;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, Result};
use rmcp::{Peer, RoleServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::process::Command;
use tokio::time::timeout;
use zeroize::{Zeroize, Zeroizing};

use crate::mcp_prompt::{self, PasswordPrompt};
use crate::{
    SudoRunInput, ASKPASS_CONTEXT_DIGEST_ENV, ASKPASS_CONTEXT_ENV, BRIDGE_CAPABILITY_HEX_BYTES,
    BRIDGE_CAPABILITY_VALUE_PREFIX, BRIDGE_MARKER, BRIDGE_PASSWORD, BRIDGE_SOCKET_ENV, ROLE_ENV,
};

const DEFAULT_TIMEOUT_SECONDS: u64 = 120;
const MAX_TIMEOUT_SECONDS: u64 = 3600;
const MAX_OUTPUT_BYTES: usize = 256 * 1024;
#[cfg(unix)]
const BRIDGE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const TIMEOUT_CLEANUP_GRACE: Duration = Duration::from_secs(5);
#[cfg(unix)]
const BRIDGE_CAPABILITY_RANDOM_BYTES: usize = BRIDGE_CAPABILITY_HEX_BYTES / 2;
#[cfg(unix)]
const BRIDGE_CAPABILITY_NAME_RANDOM_BYTES: usize = 16;

#[cfg(unix)]
struct BridgeCapability {
    environment_name: String,
    environment_value: Zeroizing<String>,
}

#[cfg(unix)]
impl BridgeCapability {
    fn generate() -> Result<Self> {
        let mut secret = Zeroizing::new([0_u8; BRIDGE_CAPABILITY_RANDOM_BYTES]);
        getrandom::fill(&mut *secret)
            .map_err(|error| anyhow!("cannot generate bridge capability: {error}"))?;
        let mut environment_value = Zeroizing::new(String::with_capacity(
            BRIDGE_CAPABILITY_VALUE_PREFIX.len() + BRIDGE_CAPABILITY_HEX_BYTES,
        ));
        environment_value.push_str(BRIDGE_CAPABILITY_VALUE_PREFIX);
        for byte in secret.iter() {
            write!(&mut *environment_value, "{byte:02x}").expect("writing to a String cannot fail");
        }

        let mut name_random = Zeroizing::new([0_u8; BRIDGE_CAPABILITY_NAME_RANDOM_BYTES]);
        getrandom::fill(&mut *name_random)
            .map_err(|error| anyhow!("cannot generate bridge capability name: {error}"))?;
        // A random name prevents a targeted sudoers env_keep entry from
        // preserving this one-use value in the requested command.
        let environment_name = format!("M{}", hex_encode(&name_random[..]));

        Ok(Self {
            environment_name,
            environment_value,
        })
    }

    fn expected(&self) -> &[u8] {
        &self.environment_value.as_bytes()[BRIDGE_CAPABILITY_VALUE_PREFIX.len()..]
    }

    fn install(&self, command: &mut Command) {
        // Do not let a caller-provided lookalike create an ambiguous helper
        // environment. The fresh variable name also avoids a targeted
        // env_keep entry for a reusable, predictable capability name.
        for (name, value) in std::env::vars_os() {
            if value
                .to_str()
                .is_some_and(|value| value.starts_with(BRIDGE_CAPABILITY_VALUE_PREFIX))
            {
                command.env_remove(name);
            }
        }
        command.env(&self.environment_name, self.environment_value.as_str());
    }
}

#[cfg(unix)]
fn hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

pub async fn run_sudo(
    input: SudoRunInput,
    self_path: &str,
    peer: &Peer<RoleServer>,
) -> Result<String> {
    validate_input(&input)?;

    let sudo_bin = sudo_executable().ok_or_else(|| {
        anyhow!("trusted sudo executable not found (it must be root-owned and not writable by group or others)")
    })?;
    let timeout_secs = command_timeout_seconds(&input);

    if mcp_prompt::supports_form(peer) {
        #[cfg(unix)]
        return run_mcp_command(&input, &sudo_bin, self_path, peer, timeout_secs).await;

        #[cfg(not(unix))]
        return Err(anyhow!(
            "MCP password elicitation requires a Unix-domain askpass bridge"
        ));
    }

    run_native_command(&input, &sudo_bin, self_path, timeout_secs).await
}

fn validate_input(input: &SudoRunInput) -> Result<()> {
    if input.argv.is_empty() {
        return Err(anyhow!("argv must be a non-empty list"));
    }
    if input.reason.trim().is_empty() {
        return Err(anyhow!(
            "reason is required so the user knows what they are authorizing"
        ));
    }
    Ok(())
}

fn command_timeout_seconds(input: &SudoRunInput) -> u64 {
    match input.timeout_seconds {
        Some(0) | None => DEFAULT_TIMEOUT_SECONDS,
        Some(value) => value.min(MAX_TIMEOUT_SECONDS),
    }
}

async fn run_native_command(
    input: &SudoRunInput,
    sudo_bin: &Path,
    self_path: &str,
    timeout_secs: u64,
) -> Result<String> {
    use std::io::Write as _;

    let authorization_summary = mcp_prompt::authorization_summary(input);
    crate::prompt::validate_native_authorization(&authorization_summary)?;

    let context_dir = tempfile::Builder::new()
        .prefix("sudo-mcp-context-")
        .tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(context_dir.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let context_path = context_dir.path().join("authorization.txt");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let context_digest = crate::integrity::sha256_hex(authorization_summary.as_bytes());
    let mut context_file = options.open(&context_path)?;
    context_file.write_all(authorization_summary.as_bytes())?;
    context_file.sync_all()?;
    drop(context_file);

    // Keep the containing directory alive until sudo and any askpass helper
    // have exited. Only the short path and fixed-size expected digest are
    // duplicated into the environment.
    let result = run_command(
        input,
        sudo_bin,
        self_path,
        &context_path,
        &context_digest,
        timeout_secs,
    )
    .await;
    drop(context_dir);
    result
}

#[cfg(unix)]
async fn run_mcp_command(
    input: &SudoRunInput,
    sudo_bin: &Path,
    self_path: &str,
    peer: &Peer<RoleServer>,
    timeout_secs: u64,
) -> Result<String> {
    run_bridged_command(
        input,
        sudo_bin,
        self_path,
        Path::new(self_path),
        timeout_secs,
        || mcp_prompt::request_password(peer, input, Duration::from_secs(timeout_secs)),
    )
    .await
}

#[cfg(unix)]
async fn run_bridged_command<F, Fut>(
    input: &SudoRunInput,
    sudo_bin: &Path,
    askpass_path: &str,
    expected_bridge_executable: &Path,
    timeout_secs: u64,
    request_password: F,
) -> Result<String>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<PasswordPrompt>>,
{
    use std::os::unix::fs::PermissionsExt;

    ensure_bridge_peer_authentication_supported()?;
    let expected_bridge_executable = executable_identity(expected_bridge_executable)?;
    let bridge_dir = tempfile::Builder::new().prefix("sudo-mcp-").tempdir()?;
    std::fs::set_permissions(bridge_dir.path(), std::fs::Permissions::from_mode(0o700))?;
    let socket_path = bridge_dir.path().join("bridge.sock");
    let listener = UnixListener::bind(&socket_path)?;
    let capability = BridgeCapability::generate()?;

    let mut cmd = Command::new(sudo_bin);
    // Ignore any existing timestamp and do not create a reusable one. Sudo's
    // `-k` command mode keeps authentication and execution in this one process
    // while ensuring the next PASSWD command must authenticate independently.
    cmd.args(["-A", "-k"]);
    cmd.env("SUDO_ASKPASS", askpass_path);
    cmd.env(ROLE_ENV, "bridge");
    cmd.env(BRIDGE_SOCKET_ENV, &socket_path);
    capability.install(&mut cmd);
    configure_command(&mut cmd, input);

    let mut child = cmd.spawn()?;
    drop(cmd);
    let pid = child.id();
    let sudo_pid = pid.ok_or_else(|| anyhow!("sudo did not report a process ID"))?;
    let (stdout_task, stderr_task) = capture_child_output(&mut child);

    enum InitialEvent {
        Authentication(Result<UnixStream>),
        Exited(std::io::Result<std::process::ExitStatus>),
        TimedOut,
    }

    let event = tokio::select! {
        biased;
        stream = accept_bridge(
            &listener,
            sudo_pid,
            expected_bridge_executable,
            capability.expected(),
        ) => InitialEvent::Authentication(stream),
        status = child.wait() => InitialEvent::Exited(status),
        _ = tokio::time::sleep(Duration::from_secs(timeout_secs)) => InitialEvent::TimedOut,
    };

    match event {
        InitialEvent::Exited(status) => {
            let status = status?;
            let stdout = collect_task_output(stdout_task).await;
            let stderr = collect_task_output(stderr_task).await;
            Ok(format_command_output(
                Some(status),
                false,
                timeout_secs,
                &stdout,
                &stderr,
            ))
        }
        InitialEvent::TimedOut => {
            let status = terminate_timed_out_child(&mut child, pid, sudo_bin).await;
            let stdout = collect_task_output(stdout_task).await;
            let stderr = collect_task_output(stderr_task).await;
            Ok(format_command_output(
                status,
                true,
                timeout_secs,
                &stdout,
                &stderr,
            ))
        }
        InitialEvent::Authentication(stream) => {
            let mut stream = match stream {
                Ok(stream) => stream,
                Err(error) => {
                    abort_waiting_child(&mut child, stdout_task, stderr_task).await;
                    return Err(error);
                }
            };
            // Permit exactly one form response. If authentication fails and
            // sudo retries askpass, subsequent helpers fail closed.
            drop(listener);

            let password = match request_password().await {
                Ok(PasswordPrompt::Password(password)) => password,
                Ok(PasswordPrompt::Unsupported) => {
                    reject_bridge(&mut stream).await;
                    abort_waiting_child(&mut child, stdout_task, stderr_task).await;
                    return Err(anyhow!(
                        "the MCP client stopped supporting form elicitation"
                    ));
                }
                Err(error) => {
                    reject_bridge(&mut stream).await;
                    abort_waiting_child(&mut child, stdout_task, stderr_task).await;
                    return Err(error);
                }
            };

            if let Err(error) = send_bridge_password(&mut stream, &password).await {
                abort_waiting_child(&mut child, stdout_task, stderr_task).await;
                return Err(error);
            }
            drop(stream);
            // Returned output must never be transformed based on the password.
            // Trust the local sudo/PAM stack not to echo credentials and return
            // its mixed diagnostics/target-stderr stream unchanged.
            drop(password);

            let (status, timed_out) =
                match wait_for_child(&mut child, pid, sudo_bin, timeout_secs).await {
                    Ok(result) => result,
                    Err(error) => {
                        abort_waiting_child(&mut child, stdout_task, stderr_task).await;
                        return Err(error);
                    }
                };
            let stdout = collect_task_output(stdout_task).await;
            let stderr = collect_task_output(stderr_task).await;
            Ok(format_command_output(
                status,
                timed_out,
                timeout_secs,
                &stdout,
                &stderr,
            ))
        }
    }
}

#[cfg(unix)]
async fn accept_bridge(
    listener: &UnixListener,
    sudo_pid: u32,
    expected_executable: ExecutableIdentity,
    expected_capability: &[u8],
) -> Result<UnixStream> {
    loop {
        let (mut stream, _) = listener.accept().await?;

        // Socket permissions only separate Unix users. Process identity rejects
        // unrelated siblings; the fresh capability distinguishes the actual
        // askpass environment from a target-command descendant that launches
        // the same executable.
        if !bridge_peer_is_expected(&stream, sudo_pid, expected_executable) {
            continue;
        }

        let mut handshake = Zeroizing::new(vec![
            0_u8;
            BRIDGE_MARKER.len() + BRIDGE_CAPABILITY_HEX_BYTES
        ]);
        if !matches!(
            timeout(BRIDGE_HANDSHAKE_TIMEOUT, stream.read_exact(&mut handshake)).await,
            Ok(Ok(_))
        ) {
            continue;
        }
        let (marker, presented_capability) = handshake.split_at(BRIDGE_MARKER.len());
        if marker != BRIDGE_MARKER
            || !crate::integrity::constant_time_eq(presented_capability, expected_capability)
        {
            continue;
        }
        return Ok(stream);
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecutableIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
fn executable_identity(path: &Path) -> Result<ExecutableIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata(path).map_err(|error| {
        anyhow!(
            "cannot identify askpass bridge executable {}: {error}",
            path.display()
        )
    })?;
    if !metadata.is_file() {
        return Err(anyhow!(
            "askpass bridge executable is not a file: {}",
            path.display()
        ));
    }
    Ok(ExecutableIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(unix)]
fn bridge_peer_is_expected(
    stream: &UnixStream,
    sudo_pid: u32,
    expected_executable: ExecutableIdentity,
) -> bool {
    let Ok(credentials) = stream.peer_cred() else {
        return false;
    };
    let Some(raw_peer_pid) = credentials.pid() else {
        return false;
    };
    let Ok(peer_pid) = u32::try_from(raw_peer_pid) else {
        return false;
    };
    let expected_uid = unsafe { libc::geteuid() };
    if credentials.uid() != expected_uid {
        return false;
    }

    process_is_descendant_of(peer_pid, sudo_pid)
        && process_executable_identity(peer_pid).is_ok_and(|actual| actual == expected_executable)
}

#[cfg(unix)]
fn process_is_descendant_of(mut process_pid: u32, ancestor_pid: u32) -> bool {
    const MAX_ANCESTRY_DEPTH: usize = 256;

    for _ in 0..MAX_ANCESTRY_DEPTH {
        if process_pid == ancestor_pid {
            return true;
        }
        let Ok(parent_pid) = process_parent_pid(process_pid) else {
            return false;
        };
        if parent_pid == 0 || parent_pid == process_pid {
            return false;
        }
        process_pid = parent_pid;
    }
    false
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn process_parent_pid(pid: u32) -> std::io::Result<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let command_end = stat.rfind(')').ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid process stat data")
    })?;
    stat[command_end + 1..]
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "missing parent process ID")
        })?
        .parse()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn process_executable_identity(pid: u32) -> Result<ExecutableIdentity> {
    executable_identity(Path::new(&format!("/proc/{pid}/exe")))
}

#[cfg(target_os = "macos")]
fn process_parent_pid(pid: u32) -> std::io::Result<u32> {
    Ok(macos_process_info(pid)?.pbi_ppid)
}

#[cfg(target_os = "macos")]
fn process_executable_identity(pid: u32) -> Result<ExecutableIdentity> {
    use std::os::unix::ffi::OsStrExt;

    let mut path = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let path_length = unsafe {
        libc::proc_pidpath(
            pid as libc::c_int,
            path.as_mut_ptr().cast(),
            path.len() as u32,
        )
    };
    if path_length <= 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    path.truncate(path_length as usize);
    if path.last() == Some(&0) {
        path.pop();
    }
    executable_identity(Path::new(std::ffi::OsStr::from_bytes(&path)))
}

#[cfg(target_os = "macos")]
fn macos_process_info(pid: u32) -> std::io::Result<libc::proc_bsdinfo> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let info_size = std::mem::size_of::<libc::proc_bsdinfo>();
    let bytes_written = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            info_size as libc::c_int,
        )
    };
    if bytes_written != info_size as libc::c_int {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { info.assume_init() })
}

#[cfg(all(
    unix,
    any(target_os = "linux", target_os = "android", target_os = "macos")
))]
fn ensure_bridge_peer_authentication_supported() -> Result<()> {
    Ok(())
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_os = "macos"))
))]
fn ensure_bridge_peer_authentication_supported() -> Result<()> {
    Err(anyhow!(
        "secure MCP askpass peer authentication is not supported on this operating system"
    ))
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_os = "macos"))
))]
fn process_parent_pid(_pid: u32) -> std::io::Result<u32> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "process ancestry is unavailable",
    ))
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_os = "macos"))
))]
fn process_executable_identity(_pid: u32) -> Result<ExecutableIdentity> {
    Err(anyhow!("process executable identity is unavailable"))
}

#[cfg(unix)]
async fn send_bridge_password(stream: &mut UnixStream, password: &str) -> Result<()> {
    let password_len = password.len();
    crate::validate_sudo_password(password.as_bytes()).map_err(anyhow::Error::msg)?;
    let encoded_len = u32::try_from(password_len)
        .map_err(|_| anyhow!("the sudo password is too long"))?
        .to_be_bytes();
    stream.write_all(&[BRIDGE_PASSWORD]).await?;
    stream.write_all(&encoded_len).await?;
    stream.write_all(password.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

#[cfg(unix)]
async fn reject_bridge(stream: &mut UnixStream) {
    let _ = stream.write_all(&[0]).await;
    let _ = stream.shutdown().await;
}

async fn collect_task_output(task: tokio::task::JoinHandle<Vec<u8>>) -> Vec<u8> {
    timeout(TIMEOUT_CLEANUP_GRACE, task)
        .await
        .ok()
        .and_then(|result| result.ok())
        .unwrap_or_default()
}

async fn zeroize_task_output(task: tokio::task::JoinHandle<Vec<u8>>) {
    if let Ok(Ok(mut output)) = timeout(TIMEOUT_CLEANUP_GRACE, task).await {
        output.zeroize();
    }
}

async fn abort_waiting_child(
    child: &mut tokio::process::Child,
    stdout_task: tokio::task::JoinHandle<Vec<u8>>,
    stderr_task: tokio::task::JoinHandle<Vec<u8>>,
) {
    let _ = child.start_kill();
    let _ = child.wait().await;
    zeroize_task_output(stdout_task).await;
    zeroize_task_output(stderr_task).await;
}

async fn run_command(
    input: &SudoRunInput,
    sudo_bin: &Path,
    self_path: &str,
    context_path: &Path,
    context_digest: &str,
    timeout_secs: u64,
) -> Result<String> {
    let mut cmd = Command::new(sudo_bin);
    // Match the MCP path's per-command authentication semantics. In command
    // mode `-k` both ignores an existing timestamp and prevents this successful
    // authentication from updating the timestamp cache.
    cmd.args(["-A", "-k"]);
    cmd.env("SUDO_ASKPASS", self_path);
    cmd.env(ROLE_ENV, "askpass");
    cmd.env(ASKPASS_CONTEXT_ENV, context_path);
    cmd.env(ASKPASS_CONTEXT_DIGEST_ENV, context_digest);
    configure_command(&mut cmd, input);

    let mut child = cmd.spawn()?;
    let pid = child.id();
    let (stdout_task, stderr_task) = capture_child_output(&mut child);
    let (status, timed_out) = match wait_for_child(&mut child, pid, sudo_bin, timeout_secs).await {
        Ok(result) => result,
        Err(error) => {
            abort_waiting_child(&mut child, stdout_task, stderr_task).await;
            return Err(error);
        }
    };
    let stdout_bytes = collect_task_output(stdout_task).await;
    let stderr_bytes = collect_task_output(stderr_task).await;

    Ok(format_command_output(
        status,
        timed_out,
        timeout_secs,
        &stdout_bytes,
        &stderr_bytes,
    ))
}

fn configure_command(cmd: &mut Command, input: &SudoRunInput) {
    cmd.arg("--").args(&input.argv);
    if let Some(dir) = &input.cwd {
        cmd.current_dir(dir);
    }
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.kill_on_drop(true);

    #[cfg(unix)]
    cmd.process_group(0);
}

fn capture_child_output(
    child: &mut tokio::process::Child,
) -> (
    tokio::task::JoinHandle<Vec<u8>>,
    tokio::task::JoinHandle<Vec<u8>>,
) {
    let stdout_task = capture_child_stdout(child);
    let stderr_task = capture_stream(child.stderr.take().expect("piped stderr"));
    (stdout_task, stderr_task)
}

fn capture_child_stdout(child: &mut tokio::process::Child) -> tokio::task::JoinHandle<Vec<u8>> {
    capture_stream(child.stdout.take().expect("piped stdout"))
}

fn capture_stream<R>(mut stream: R) -> tokio::task::JoinHandle<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buffer = Vec::new();
        let _ = stream.read_to_end(&mut buffer).await;
        buffer
    })
}

async fn wait_for_child(
    child: &mut tokio::process::Child,
    pid: Option<u32>,
    sudo_bin: &Path,
    timeout_secs: u64,
) -> Result<(Option<std::process::ExitStatus>, bool)> {
    tokio::select! {
        status = child.wait() => Ok((Some(status?), false)),
        _ = tokio::time::sleep(Duration::from_secs(timeout_secs)) => {
            Ok((terminate_timed_out_child(child, pid, sudo_bin).await, true))
        }
    }
}

async fn terminate_timed_out_child(
    child: &mut tokio::process::Child,
    pid: Option<u32>,
    sudo_bin: &Path,
) -> Option<std::process::ExitStatus> {
    #[cfg(unix)]
    if let Some(pid) = pid {
        crate::process::kill_process_group(pid as i32, sudo_bin).await;
    }
    #[cfg(not(unix))]
    let _ = (pid, sudo_bin);

    match timeout(TIMEOUT_CLEANUP_GRACE, child.wait()).await {
        Ok(Ok(status)) => Some(status),
        _ => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            None
        }
    }
}

fn format_command_output(
    status: Option<std::process::ExitStatus>,
    timed_out: bool,
    timeout_secs: u64,
    stdout: &[u8],
    stderr: &[u8],
) -> String {
    if timed_out {
        return format!("sudo-mcp: command timed out after {timeout_secs}s");
    }

    let exit_code = status.and_then(|value| value.code()).unwrap_or(-1);
    format!(
        "exit_code: {exit_code}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        truncate(stdout),
        truncate(stderr),
    )
}

fn truncate(bytes: &[u8]) -> String {
    if bytes.len() <= MAX_OUTPUT_BYTES {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let head = String::from_utf8_lossy(&bytes[..MAX_OUTPUT_BYTES]).into_owned();
    let omitted = bytes.len() - MAX_OUTPUT_BYTES;
    format!("{head}\n... [truncated, {omitted} bytes omitted]")
}

fn sudo_executable() -> Option<PathBuf> {
    let mut candidates = vec![PathBuf::from("/usr/bin/sudo"), PathBuf::from("/bin/sudo")];
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(std::env::split_paths(&path).map(|dir| dir.join("sudo")));
    }
    candidates
        .into_iter()
        .find(|candidate| is_trusted_executable(candidate))
}

fn is_trusted_executable(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = metadata.permissions().mode();
        metadata.uid() == 0 && mode & 0o111 != 0 && mode & 0o022 == 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Some Linux security/filesystem combinations transiently reject parallel
    // execution of freshly-created scripts with ETXTBSY. Keep these fixture
    // executions serial; production always executes an installed sudo binary.
    #[cfg(unix)]
    static EXECUTABLE_SCRIPT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[cfg(unix)]
    fn executable_script(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, body).expect("write test script");
        let mut permissions = std::fs::metadata(path)
            .expect("script metadata")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions).expect("make script executable");
    }

    #[cfg(unix)]
    fn shell_quote(path: &Path) -> String {
        format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
    }

    #[cfg(unix)]
    fn test_input() -> SudoRunInput {
        SudoRunInput {
            argv: vec!["target-command".to_string()],
            reason: "test command policy".to_string(),
            timeout_seconds: Some(2),
            cwd: None,
        }
    }

    #[cfg(unix)]
    fn bridge_helper(dir: &Path) -> PathBuf {
        let helper = dir.join("bridge-helper");
        let test_binary = std::env::current_exe().expect("test binary");
        executable_script(
            &helper,
            &format!(
                "#!/bin/sh\npassword_file=${{SUDO_MCP_BRIDGE_SOCKET%/*}}/bridge-password\nrm -f \"$password_file\"\n{binary} --exact sudo::tests::bridge_askpass_test_helper --ignored --nocapture >/dev/null 2>&1 || exit 1\ncat \"$password_file\"\nprintf '\\n'\nrm -f \"$password_file\"\n",
                binary = shell_quote(&test_binary),
            ),
        );
        helper
    }

    // Invoked through the test harness by `bridge_helper`, allowing the real
    // bridge client protocol to run without an external Unix-socket utility.
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn bridge_askpass_test_helper() {
        if std::env::var(ROLE_ENV).as_deref() != Ok("bridge") {
            return;
        }
        let password = crate::receive_bridge_password().expect("receive bridged password");
        let socket_path = std::env::var_os(BRIDGE_SOCKET_ENV).expect("bridge socket path");
        let password_path = Path::new(&socket_path)
            .parent()
            .expect("bridge directory")
            .join("bridge-password");
        std::fs::write(password_path, &*password).expect("write helper password");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exact_nopasswd_command_runs_once_without_elicitation() {
        let _fixture_guard = EXECUTABLE_SCRIPT_LOCK.lock().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("fake-sudo");
        let expected_bridge = std::env::current_exe().expect("test binary");
        let executions = dir.path().join("executions");
        executable_script(
            &script,
            &format!(
                "#!/bin/sh\nprintf x >> {}\nprintf 'nopasswd command ran'\nprintf 'nopasswd command stderr' >&2\nexit 23\n",
                shell_quote(&executions),
            ),
        );

        let output = run_bridged_command(
            &test_input(),
            &script,
            "/unused-askpass-helper",
            &expected_bridge,
            2,
            || async { Err(anyhow!("unexpected password request")) },
        )
        .await
        .expect("NOPASSWD command completes");

        assert!(output.contains("exit_code: 23"), "{output}");
        assert!(output.contains("nopasswd command ran"), "{output}");
        assert!(output.contains("nopasswd command stderr"), "{output}");
        assert_eq!(
            std::fs::read_to_string(executions).expect("execution count"),
            "x"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn target_descendant_cannot_impersonate_askpass_without_capability() {
        let _fixture_guard = EXECUTABLE_SCRIPT_LOCK.lock().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("fake-sudo");
        let helper = bridge_helper(dir.path());
        let expected_bridge = std::env::current_exe().expect("test binary");
        let capability_name = "ATTACK_CAPABILITY";
        let guessed_capability = "00".repeat(BRIDGE_CAPABILITY_RANDOM_BYTES);
        let guessed_capability = format!("{BRIDGE_CAPABILITY_VALUE_PREFIX}{guessed_capability}");
        executable_script(
            &script,
            &format!(
                "#!/bin/sh\nstolen=$(/usr/bin/env -i PATH=/usr/bin:/bin {role}=\"${role}\" {socket}=\"${socket}\" {capability_name}={guessed_capability} \"$SUDO_ASKPASS\" 'Password:' 2>/dev/null)\n[ -z \"$stolen\" ] || {{ printf 'password leaked:%s' \"$stolen\"; exit 97; }}\nprintf 'target command completed without a password'\n",
                role = ROLE_ENV,
                socket = BRIDGE_SOCKET_ENV,
            ),
        );

        let output = run_bridged_command(
            &test_input(),
            &script,
            helper.to_str().unwrap(),
            &expected_bridge,
            2,
            || async { Err(anyhow!("descendant spoof triggered elicitation")) },
        )
        .await
        .expect("spoof is rejected while the target completes");

        assert!(output.contains("exit_code: 0"), "{output}");
        assert!(
            output.contains("target command completed without a password"),
            "{output}"
        );
        assert!(!output.contains("password leaked"), "{output}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn password_and_command_use_the_same_sudo_process() {
        let _fixture_guard = EXECUTABLE_SCRIPT_LOCK.lock().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("fake-sudo");
        let helper = bridge_helper(dir.path());
        let expected_bridge = std::env::current_exe().expect("test binary");
        let executions = dir.path().join("executions");
        let args = dir.path().join("args");
        executable_script(
            &script,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > {args}\npassword=$(\"$SUDO_ASKPASS\" 'Password:') || exit 1\n[ \"$password\" = 'correct horse' ] || exit 1\nprintf x >> {executions}\nprintf 'authenticated command ran'\n",
                args = shell_quote(&args),
                executions = shell_quote(&executions),
            ),
        );

        let output = run_bridged_command(
            &test_input(),
            &script,
            helper.to_str().unwrap(),
            &expected_bridge,
            2,
            || async {
                Ok(PasswordPrompt::Password(Zeroizing::new(
                    "correct horse".to_string(),
                )))
            },
        )
        .await
        .expect("authenticated command completes");

        assert!(output.contains("exit_code: 0"), "{output}");
        assert!(output.contains("authenticated command ran"), "{output}");
        assert_eq!(
            std::fs::read_to_string(executions).expect("execution count"),
            "x"
        );
        assert_eq!(
            std::fs::read_to_string(args).expect("sudo arguments"),
            "-A\n-k\n--\ntarget-command\n"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn authenticated_output_is_unfiltered_and_password_independent() {
        let _fixture_guard = EXECUTABLE_SCRIPT_LOCK.lock().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("fake-sudo");
        let helper = bridge_helper(dir.path());
        let expected_bridge = std::env::current_exe().expect("test binary");
        executable_script(
            &script,
            "#!/bin/sh\npassword=$(\"$SUDO_ASKPASS\" 'Password:') || exit 1\ncase \"$password\" in one|two) ;; *) exit 1 ;; esac\nprintf 'stdout-candidate:one\\nstdout-candidate:two\\n'\nprintf 'stderr-candidate:one\\nstderr-candidate:two\\nsudo diagnostic\\ncommand stderr\\n' >&2\n",
        );

        let first = run_bridged_command(
            &test_input(),
            &script,
            helper.to_str().unwrap(),
            &expected_bridge,
            2,
            || async { Ok(PasswordPrompt::Password(Zeroizing::new("one".to_string()))) },
        )
        .await
        .expect("first authenticated command completes");
        let second = run_bridged_command(
            &test_input(),
            &script,
            helper.to_str().unwrap(),
            &expected_bridge,
            2,
            || async { Ok(PasswordPrompt::Password(Zeroizing::new("two".to_string()))) },
        )
        .await
        .expect("second authenticated command completes");

        assert_eq!(first, second, "output varied with the submitted password");
        assert!(first.contains("stdout-candidate:one"), "{first}");
        assert!(first.contains("stdout-candidate:two"), "{first}");
        assert!(first.contains("stderr-candidate:one"), "{first}");
        assert!(first.contains("stderr-candidate:two"), "{first}");
        assert!(first.contains("sudo diagnostic"), "{first}");
        assert!(first.contains("command stderr"), "{first}");
        assert!(!first.contains("[redacted]"), "{first}");
    }

    #[test]
    fn output_truncation_is_content_independent() {
        let raw = vec![b'x'; MAX_OUTPUT_BYTES + 7];
        let rendered = truncate(&raw);

        assert!(rendered.starts_with(&"x".repeat(64)), "{rendered}");
        assert!(rendered.ends_with("... [truncated, 7 bytes omitted]"));
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    #[tokio::test]
    async fn first_same_uid_connector_cannot_steal_bridge_password() {
        let _fixture_guard = EXECUTABLE_SCRIPT_LOCK.lock().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("bridge.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind bridge socket");

        // Queue a connector from this process before the expected helper even
        // exists. It has the same UID, executable identity, and public marker.
        let mut thief = UnixStream::connect(&socket_path)
            .await
            .expect("connect first client");
        thief
            .write_all(BRIDGE_MARKER)
            .await
            .expect("write public bridge marker");

        let helper = bridge_helper(dir.path());
        let capability = "11".repeat(BRIDGE_CAPABILITY_RANDOM_BYTES);
        let capability_name = "TEST_CAPABILITY";
        let capability_environment_value = format!("{BRIDGE_CAPABILITY_VALUE_PREFIX}{capability}");
        let mut command = Command::new(&helper);
        command
            .env(ROLE_ENV, "bridge")
            .env(BRIDGE_SOCKET_ENV, &socket_path)
            .env(capability_name, capability_environment_value)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let sudo_child = command.spawn().expect("spawn stand-in sudo child");
        let sudo_pid = sudo_child.id().expect("child process ID");
        let expected_executable =
            executable_identity(&std::env::current_exe().expect("test executable path"))
                .expect("test executable identity");

        let mut authenticated = timeout(
            Duration::from_secs(2),
            accept_bridge(
                &listener,
                sudo_pid,
                expected_executable,
                capability.as_bytes(),
            ),
        )
        .await
        .expect("bridge acceptance timeout")
        .expect("accept descendant helper");
        send_bridge_password(&mut authenticated, "protected password")
            .await
            .expect("send password to authenticated helper");

        let mut stolen = Vec::new();
        let _ = timeout(Duration::from_secs(1), thief.read_to_end(&mut stolen))
            .await
            .expect("unauthenticated connector was not closed");
        assert!(stolen.is_empty(), "thief received bridge bytes: {stolen:?}");

        let output = timeout(Duration::from_secs(2), sudo_child.wait_with_output())
            .await
            .expect("helper exit timeout")
            .expect("wait for helper");
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, b"protected password\n");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn native_context_is_file_backed_and_integrity_bound() {
        let _fixture_guard = EXECUTABLE_SCRIPT_LOCK.lock().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("fake-sudo");
        let copied_context = dir.path().join("copied-context");
        let context_path = dir.path().join("context-path");
        let context_digest_path = dir.path().join("context-digest");
        let args_path = dir.path().join("args");
        executable_script(
            &script,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > {args}\nprintf '%s' \"$SUDO_MCP_ASKPASS_CONTEXT\" > {path}\nprintf '%s' \"$SUDO_MCP_ASKPASS_CONTEXT_SHA256\" > {digest}\ncp \"$SUDO_MCP_ASKPASS_CONTEXT\" {context}\nprintf native\nprintf 'native command stderr' >&2\n",
                args = shell_quote(&args_path),
                path = shell_quote(&context_path),
                digest = shell_quote(&context_digest_path),
                context = shell_quote(&copied_context),
            ),
        );
        let mut input = test_input();
        input.argv = (0..16).map(|_| "x".repeat(1000)).collect();

        let output = run_native_command(&input, &script, "/unused-askpass-helper", 2)
            .await
            .expect("bounded authorization context remains executable");

        assert!(output.contains("native"), "{output}");
        assert!(output.contains("native command stderr"), "{output}");
        assert!(
            std::fs::metadata(&copied_context)
                .expect("copied context")
                .len()
                > 8 * 1024
        );
        assert!(
            std::fs::read_to_string(context_path)
                .expect("context path")
                .len()
                < 1024
        );
        let context_digest = std::fs::read_to_string(context_digest_path).expect("context digest");
        assert_eq!(context_digest.len(), 64);
        let args = std::fs::read_to_string(args_path).expect("native sudo arguments");
        let mut args = args.lines();
        assert_eq!(args.next(), Some("-A"));
        assert_eq!(args.next(), Some("-k"));
        assert_eq!(args.next(), Some("--"));
        assert_eq!(args.count(), 16);
        assert!(crate::integrity::matches_sha256(
            &std::fs::read(copied_context).expect("copied context"),
            &context_digest,
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn oversized_native_context_is_rejected_before_sudo_starts() {
        let _fixture_guard = EXECUTABLE_SCRIPT_LOCK.lock().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("fake-sudo");
        let executions = dir.path().join("executions");
        executable_script(
            &script,
            &format!("#!/bin/sh\nprintf x > {}\n", shell_quote(&executions)),
        );
        let mut input = test_input();
        input.argv = (0..160).map(|_| "x".repeat(1000)).collect();

        let error = run_native_command(&input, &script, "/unused-askpass-helper", 2)
            .await
            .expect_err("oversized native prompt must be rejected");

        assert!(
            error
                .to_string()
                .contains("native authorization text is too large"),
            "{error:#}"
        );
        assert!(
            !executions.exists(),
            "sudo stand-in ran despite failed prompt preflight"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn privileged_command_receives_eof_on_stdin() {
        let _fixture_guard = EXECUTABLE_SCRIPT_LOCK.lock().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("fake-sudo");
        executable_script(
            &script,
            "#!/bin/sh\nif IFS= read -r value; then printf 'stdin:%s' \"$value\"; else printf 'stdin:eof'; fi\n",
        );

        let output = run_native_command(&test_input(), &script, "/unused-askpass-helper", 2)
            .await
            .expect("command succeeds");

        assert!(output.contains("stdin:eof"));
    }
}
