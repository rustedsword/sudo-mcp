// sudo-mcp is an MCP server that runs sudo commands after asking the connected
// MCP client to collect the password. Clients without form elicitation fall
// back to a native SUDO_ASKPASS dialog. The password is never a tool argument,
// and the server never intentionally adds it to the tool result.

use std::env;
#[cfg(unix)]
use std::io::Read;
use std::io::Write;
use std::process::ExitCode;

use anyhow::Result;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, Implementation, ServerCapabilities, ServerInfo};
use rmcp::service::ServiceExt;
use rmcp::transport::stdio;
use rmcp::{schemars, tool, tool_handler, tool_router, ErrorData, Peer, RoleServer, ServerHandler};
use serde::Deserialize;
use zeroize::Zeroizing;

mod integrity;
mod mcp_prompt;
mod prompt;
mod sudo;

#[cfg(unix)]
mod process;

const ROLE_ENV: &str = "SUDO_MCP_ROLE";
const ASKPASS_CONTEXT_ENV: &str = "SUDO_MCP_ASKPASS_CONTEXT";
const ASKPASS_CONTEXT_DIGEST_ENV: &str = "SUDO_MCP_ASKPASS_CONTEXT_SHA256";
const BRIDGE_SOCKET_ENV: &str = "SUDO_MCP_BRIDGE_SOCKET";
const BRIDGE_CAPABILITY_VALUE_PREFIX: &str = "sudo-mcp-bridge-capability-v1/";
const BRIDGE_CAPABILITY_HEX_BYTES: usize = 64;
const BRIDGE_MARKER: &[u8] = b"sudo-mcp-password-bridge-v2";
const BRIDGE_PASSWORD: u8 = 1;
// sudo_plugin.h defines SUDO_CONV_REPL_MAX as 255 bytes in sudo 1.8 and 1023
// bytes in sudo 1.9, excluding the trailing C NUL. Use the lowest supported
// boundary so every supported sudo consumes the complete value supplied here.
const MAX_SUDO_PASSWORD_BYTES: usize = 255;

fn validate_sudo_password(password: &[u8]) -> std::result::Result<(), &'static str> {
    if password.is_empty() {
        return Err("the sudo password cannot be empty");
    }
    if password.len() > MAX_SUDO_PASSWORD_BYTES {
        return Err("the sudo password exceeds the portable 255-byte sudo reply limit");
    }
    if password.contains(&0) {
        return Err("sudo passwords containing NUL bytes are not supported");
    }
    if password.iter().any(|byte| matches!(byte, b'\n' | b'\r')) {
        return Err("sudo passwords containing line breaks are not supported");
    }
    Ok(())
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SudoRunInput {
    /// command and arguments. Example: ["apt","install","-y","htop"]
    pub argv: Vec<String>,
    /// one-line justification shown in the password dialog. Example: "Install htop system-wide"
    pub reason: String,
    /// timeout in seconds (default 120, max 3600)
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    /// working directory (optional)
    #[serde(default)]
    pub cwd: Option<String>,
}

#[derive(Clone)]
pub struct SudoServer {
    self_path: String,
    #[allow(dead_code)]
    tool_router: ToolRouter<SudoServer>,
}

#[tool_router]
impl SudoServer {
    fn new(self_path: String) -> Self {
        Self {
            self_path,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "Run a single command as root. When authentication is needed, sudo-mcp asks the user for the password through MCP elicitation; the password is not a tool argument and is never intentionally added to the result. Clients without form elicitation use a native OS dialog. Results include the exit code, stdout, and combined sudo/PAM/command stderr, with at most 256 KiB from each stream rendered as text. Pass argv as a list, not a shell string, and include a short `reason` describing what the user is authorizing."
    )]
    async fn sudo_run(
        &self,
        Parameters(input): Parameters<SudoRunInput>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let text = sudo::run_sudo(input, &self.self_path, &peer)
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }
}

#[tool_handler]
impl ServerHandler for SudoServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("sudo-mcp", env!("CARGO_PKG_VERSION")))
    }
}

fn main() -> ExitCode {
    match env::var(ROLE_ENV).as_deref() {
        Ok("askpass") => return run_askpass(),
        #[cfg(unix)]
        Ok("bridge") => return run_bridge_askpass(),
        _ => {}
    }
    match run_server() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sudo-mcp: {e:#}");
            ExitCode::FAILURE
        }
    }
}

// The bridge helper is invoked by the same sudo process that will execute the
// requested command. It obtains one password over a private Unix-domain socket
// and writes it to sudo's dedicated askpass stdout, never to command stdin.
#[cfg(unix)]
fn run_bridge_askpass() -> ExitCode {
    let Ok(password) = receive_bridge_password() else {
        return ExitCode::FAILURE;
    };
    let mut stdout = std::io::stdout().lock();
    if stdout.write_all(&password).is_err() || stdout.write_all(b"\n").is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[cfg(unix)]
fn receive_bridge_password() -> std::io::Result<Zeroizing<Vec<u8>>> {
    use std::os::unix::net::UnixStream;

    let capability = take_bridge_capability()?;
    let Some(socket_path) = env::var_os(BRIDGE_SOCKET_ENV) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "missing bridge socket",
        ));
    };
    let mut stream = UnixStream::connect(socket_path)?;
    stream.write_all(BRIDGE_MARKER)?;
    stream.write_all(
        capability
            .as_bytes()
            .strip_prefix(BRIDGE_CAPABILITY_VALUE_PREFIX.as_bytes())
            .expect("validated bridge capability prefix"),
    )?;

    let mut response = [0_u8; 1];
    stream.read_exact(&mut response)?;
    if response[0] != BRIDGE_PASSWORD {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "password request rejected",
        ));
    }

    let mut encoded_len = [0_u8; 4];
    stream.read_exact(&mut encoded_len)?;
    let password_len = u32::from_be_bytes(encoded_len) as usize;
    if password_len == 0 || password_len > MAX_SUDO_PASSWORD_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid password length",
        ));
    }

    let mut password = Zeroizing::new(vec![0_u8; password_len]);
    stream.read_exact(&mut password)?;
    validate_sudo_password(&password)
        .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidData, message))?;
    Ok(password)
}

#[cfg(unix)]
fn take_bridge_capability() -> std::io::Result<Zeroizing<String>> {
    let mut found = None;
    for (name, value) in env::vars_os() {
        if !value
            .to_str()
            .is_some_and(|value| value.starts_with(BRIDGE_CAPABILITY_VALUE_PREFIX))
        {
            continue;
        }
        if found.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "multiple bridge capabilities",
            ));
        }
        found = Some((name, value));
    }

    let Some((name, encoded)) = found else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "missing bridge capability",
        ));
    };
    // The askpass helper is a short-lived, single-threaded process at this
    // point. Remove the secret before connecting so it is not retained for
    // any subprocess or later role dispatch.
    env::remove_var(name);

    let encoded = encoded.into_string().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bridge capability is not valid UTF-8",
        )
    })?;
    let Some(capability) = encoded.strip_prefix(BRIDGE_CAPABILITY_VALUE_PREFIX) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid bridge capability prefix",
        ));
    };
    if capability.len() != BRIDGE_CAPABILITY_HEX_BYTES
        || !capability.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid bridge capability",
        ));
    }
    Ok(Zeroizing::new(encoded))
}

fn run_server() -> Result<()> {
    let self_path = env::current_exe()?.to_string_lossy().into_owned();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        let service = SudoServer::new(self_path).serve(stdio()).await?;
        service.waiting().await?;
        Ok::<_, anyhow::Error>(())
    })
}

// run_askpass is dispatched when the binary is exec'd by sudo as the
// SUDO_ASKPASS program. It receives sudo's prompt as argv[1], shows a
// native dialog, and writes the password to stdout. Failures (no GUI,
// user cancels) exit non-zero so sudo treats it as a failed auth.
fn run_askpass() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let mut prompt = args
        .get(1)
        .filter(|s| !s.is_empty())
        .cloned()
        .unwrap_or_else(|| "Sudo password required".to_string());

    if let Some(context_path) = env::var_os(ASKPASS_CONTEXT_ENV) {
        let Ok(expected_digest) = env::var(ASKPASS_CONTEXT_DIGEST_ENV) else {
            return ExitCode::FAILURE;
        };
        let Ok(prompt_context) =
            read_verified_askpass_context(std::path::Path::new(&context_path), &expected_digest)
        else {
            return ExitCode::FAILURE;
        };
        if !prompt_context.is_empty() {
            prompt.push_str("\n\n");
            prompt.push_str(&prompt_context);
        }
    } else if env::var_os(ASKPASS_CONTEXT_DIGEST_ENV).is_some() {
        return ExitCode::FAILURE;
    }

    match prompt::prompt_password(&prompt) {
        Ok(pw) => {
            let pw = match normalize_native_askpass_output(pw) {
                Ok(password) => password,
                Err(message) => {
                    eprintln!("sudo-mcp askpass: {message}");
                    return ExitCode::FAILURE;
                }
            };
            let mut stdout = std::io::stdout().lock();
            if stdout.write_all(&pw).is_err() || stdout.write_all(b"\n").is_err() {
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("sudo-mcp askpass: {e}");
            ExitCode::FAILURE
        }
    }
}

fn normalize_native_askpass_output(
    password: Vec<u8>,
) -> std::result::Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut password = Zeroizing::new(password);
    // Native helpers conventionally terminate their stdout with LF (or CRLF).
    // Strip exactly one terminator, then reject any line break in the actual
    // password so sudo and this helper agree on the complete byte sequence.
    if password.last() == Some(&b'\n') {
        password.pop();
        if password.last() == Some(&b'\r') {
            password.pop();
        }
    }
    validate_sudo_password(&password)?;
    Ok(password)
}

fn read_verified_askpass_context(
    path: &std::path::Path,
    expected_digest: &str,
) -> std::io::Result<String> {
    use std::io::Read as _;

    let mut bytes = Vec::with_capacity(prompt::MAX_NATIVE_AUTHORIZATION_BYTES);
    std::fs::File::open(path)?
        .take((prompt::MAX_NATIVE_AUTHORIZATION_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > prompt::MAX_NATIVE_AUTHORIZATION_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "askpass authorization context exceeds the native prompt limit",
        ));
    }
    if !integrity::matches_sha256(&bytes, expected_digest) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "askpass authorization context failed integrity verification",
        ));
    }
    String::from_utf8(bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sudo_password_validation_matches_the_conversation_boundary() {
        assert!(validate_sudo_password(&vec![b'x'; MAX_SUDO_PASSWORD_BYTES]).is_ok());
        assert!(validate_sudo_password(&vec![b'x'; MAX_SUDO_PASSWORD_BYTES + 1]).is_err());
        assert!(validate_sudo_password(b"prefix\0suffix").is_err());

        assert_eq!(
            &*normalize_native_askpass_output(b"secret\n".to_vec())
                .expect("LF terminator is removed"),
            b"secret"
        );
        assert_eq!(
            &*normalize_native_askpass_output(b"secret\r\n".to_vec())
                .expect("CRLF terminator is removed"),
            b"secret"
        );
        assert!(normalize_native_askpass_output(b"prefix\0suffix\n".to_vec()).is_err());
        assert!(normalize_native_askpass_output(b"embedded\nnewline\n".to_vec()).is_err());
    }

    #[test]
    fn modified_askpass_context_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("authorization.txt");
        let original = b"Reason: original\nCommand: original";
        let expected_digest = integrity::sha256_hex(original);
        std::fs::write(&path, original).expect("write original context");

        assert_eq!(
            read_verified_askpass_context(&path, &expected_digest)
                .expect("original context verifies"),
            String::from_utf8_lossy(original)
        );

        std::fs::write(&path, b"Reason: benign\nCommand: benign").expect("replace context");
        let error = read_verified_askpass_context(&path, &expected_digest)
            .expect_err("modified context must not verify");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn oversized_askpass_context_is_bounded_before_verification() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("authorization.txt");
        let context = vec![b'x'; prompt::MAX_NATIVE_AUTHORIZATION_BYTES + 1];
        let expected_digest = integrity::sha256_hex(&context);
        std::fs::write(&path, context).expect("write oversized context");

        let error = read_verified_askpass_context(&path, &expected_digest)
            .expect_err("oversized context must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
