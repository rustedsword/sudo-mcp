// MCP requires passwords to use URL-mode elicitation. This module knowingly
// uses form mode for a trusted client connected directly to this binary's only
// transport: local stdio. The client therefore sees the credential. Keep the
// limitation prominent in README.md and never add a network transport without
// replacing this flow.

use std::time::Duration;

use anyhow::{anyhow, Result};
use rmcp::model::{
    CreateElicitationRequestParams, ElicitationAction, ElicitationSchema, StringSchema,
};
use rmcp::service::ElicitationMode;
use rmcp::{Peer, RoleServer};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::{SudoRunInput, MAX_SUDO_PASSWORD_BYTES};

pub enum PasswordPrompt {
    Password(Zeroizing<String>),
    Unsupported,
}

pub fn supports_form(peer: &Peer<RoleServer>) -> bool {
    peer.supported_elicitation_modes()
        .contains(&ElicitationMode::Form)
}

pub async fn request_password(
    peer: &Peer<RoleServer>,
    input: &SudoRunInput,
    timeout: Duration,
) -> Result<PasswordPrompt> {
    if !supports_form(peer) {
        return Ok(PasswordPrompt::Unsupported);
    }

    let response = peer
        .create_elicitation_with_timeout(
            CreateElicitationRequestParams::FormElicitationParams {
                meta: None,
                message: password_prompt_message(input),
                requested_schema: password_schema(),
            },
            Some(timeout),
        )
        .await
        // Service errors can contain protocol response data. Never interpolate
        // them into a tool error because a buggy client could include the
        // password in that data.
        .map_err(|_| anyhow!("the MCP client could not complete the sudo password prompt"))?;

    match response.action {
        ElicitationAction::Accept => extract_password(response.content),
        ElicitationAction::Decline => Err(anyhow!("user declined the sudo password prompt")),
        ElicitationAction::Cancel => Err(anyhow!("user cancelled the sudo password prompt")),
    }
}

fn password_schema() -> ElicitationSchema {
    ElicitationSchema::builder()
        .required_string_property("password", |schema: StringSchema| {
            schema
                .title("Password:")
                .min_length(1)
                .max_length(MAX_SUDO_PASSWORD_BYTES as u32)
        })
        .build()
        .expect("the static password elicitation schema is valid")
}

fn extract_password(content: Option<Value>) -> Result<PasswordPrompt> {
    let Some(value) = content else {
        return Err(no_usable_password());
    };
    let mut fields = match value {
        Value::Object(fields) => fields,
        other => {
            zeroize_json(other);
            return Err(no_usable_password());
        }
    };

    if fields.len() != 1 || !fields.contains_key("password") {
        zeroize_json(Value::Object(fields));
        return Err(no_usable_password());
    }

    let value = fields
        .remove("password")
        .expect("presence checked immediately above");
    let password = match value {
        Value::String(password) => Zeroizing::new(password),
        other => {
            zeroize_json(other);
            return Err(no_usable_password());
        }
    };

    crate::validate_sudo_password(password.as_bytes()).map_err(anyhow::Error::msg)?;

    Ok(PasswordPrompt::Password(password))
}

fn no_usable_password() -> anyhow::Error {
    anyhow!("the MCP client returned no usable sudo password; ensure MCP elicitations are allowed")
}

// Best-effort cleanup for malformed or unexpected client content. This cannot
// erase copies retained by the MCP client, JSON parser buffers, allocators, or
// operating system, but it avoids leaving owned strings live in this process.
fn zeroize_json(value: Value) {
    match value {
        Value::String(mut string) => string.zeroize(),
        Value::Array(values) => values.into_iter().for_each(zeroize_json),
        Value::Object(fields) => {
            for (mut key, value) in fields {
                key.zeroize();
                zeroize_json(value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn password_prompt_message(input: &SudoRunInput) -> String {
    format!(
        "sudo password required.\n\n{}",
        authorization_summary(input)
    )
}

pub(crate) fn authorization_summary(input: &SudoRunInput) -> String {
    let reason = quoted(&input.reason);
    let command = quoted(&display_command(&input.argv));
    let cwd = input
        .cwd
        .as_deref()
        .map(|value| format!("\nWorking directory: {}", quoted(value)))
        .unwrap_or_default();

    // Do not truncate these fields: hiding a command suffix would make the
    // authorization prompt misleading.
    format!("Reason: {reason}\nCommand: {command}{cwd}")
}

fn display_command(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| {
            if !arg.is_empty()
                && arg
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&byte))
            {
                arg.clone()
            } else {
                // Keep the raw value here and escape the completed display
                // string in `quoted`. This preserves argument boundaries while
                // ensuring controls, bidi markers, layout characters, and
                // non-ASCII lookalikes are rendered as inert ASCII escapes.
                format!("'{}'", arg.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn quoted(value: &str) -> String {
    let mut rendered = String::with_capacity(value.len() + 2);
    rendered.push('"');
    for character in value.chars() {
        match character {
            ' '..='~' if !matches!(character, '"' | '\\') => rendered.push(character),
            _ => rendered.extend(character.escape_default()),
        }
    }
    rendered.push('"');
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn password_schema_is_one_required_string() {
        let schema = serde_json::to_value(password_schema()).expect("serialize elicitation schema");
        assert_eq!(schema.get("type"), Some(&json!("object")));
        assert_eq!(schema["properties"]["password"]["type"], "string");
        assert_eq!(schema["properties"]["password"]["title"], "Password:");
        assert_eq!(
            schema["properties"]["password"]["maxLength"],
            MAX_SUDO_PASSWORD_BYTES
        );
        assert!(schema["properties"]["password"]
            .get("description")
            .is_none());
        assert_eq!(schema["required"], json!(["password"]));
    }

    #[test]
    fn accepted_content_must_contain_only_a_string_password() {
        let accepted = extract_password(Some(json!({ "password": "secret" })))
            .expect("valid password is accepted");
        match accepted {
            PasswordPrompt::Password(password) => assert_eq!(&*password, "secret"),
            PasswordPrompt::Unsupported => panic!("content parsing cannot be unsupported"),
        }

        for content in [
            json!(null),
            json!({}),
            json!({ "password": 123 }),
            json!({ "password": "secret", "extra": "unexpected" }),
        ] {
            assert!(extract_password(Some(content)).is_err());
        }
    }

    #[test]
    fn passwords_must_fit_sudos_c_conversation_reply() {
        let boundary = "x".repeat(MAX_SUDO_PASSWORD_BYTES);
        let accepted = extract_password(Some(json!({ "password": boundary })))
            .expect("255-byte password is accepted");
        assert!(matches!(accepted, PasswordPrompt::Password(_)));

        for password in [
            "x".repeat(MAX_SUDO_PASSWORD_BYTES + 1),
            "prefix\0suffix".to_string(),
            "x\ny".to_string(),
            "x\ry".to_string(),
        ] {
            assert!(
                extract_password(Some(json!({ "password": password }))).is_err(),
                "invalid password was accepted"
            );
        }

        // JSON Schema counts characters, while sudo's boundary is bytes. The
        // runtime check must therefore reject a multibyte string that fits the
        // schema's character count but not sudo's byte buffer.
        let multibyte = "é".repeat((MAX_SUDO_PASSWORD_BYTES / 2) + 1);
        assert!(extract_password(Some(json!({ "password": multibyte }))).is_err());
    }

    #[test]
    fn prompt_escapes_injected_lines_without_changing_values() {
        let input = SudoRunInput {
            argv: vec!["install".to_string(), "file with spaces".to_string()],
            reason: "first line\nspoofed line".to_string(),
            timeout_seconds: None,
            cwd: Some("/tmp/work\nnext".to_string()),
        };

        let prompt = password_prompt_message(&input);
        assert!(prompt.starts_with("sudo password required.\n\n"));
        assert!(prompt.contains("Reason: \"first line\\nspoofed line\"\nCommand:"));
        assert!(prompt.contains("Command: \"install 'file with spaces'\""));
        assert!(prompt.contains("Working directory: \"/tmp/work\\nnext\""));
    }

    #[test]
    fn authorization_rendering_is_lossless_ascii_and_layout_inert() {
        let input = SudoRunInput {
            argv: vec!["tool".to_string(), "a\u{2028}\u{202e}b".to_string()],
            reason: " approve\n\u{202e} ".to_string(),
            timeout_seconds: None,
            cwd: Some("/tmp/work ".to_string()),
        };
        let summary = authorization_summary(&input);

        assert!(summary.is_ascii(), "{summary:?}");
        assert!(summary.contains("Reason: \" approve\\n\\u{202e} \""));
        assert!(summary.contains("\\u{2028}\\u{202e}"));
        assert!(summary.contains("Working directory: \"/tmp/work \""));

        let mut distinct = input;
        distinct.cwd = Some("/tmp/work".to_string());
        assert_ne!(summary, authorization_summary(&distinct));
    }

    #[test]
    fn escaped_controls_and_layout_text_remain_distinct_from_literals() {
        assert_ne!(quoted("a\nb"), quoted("a b"));
        assert_ne!(quoted("\u{202e}"), quoted(r"\u{202e}"));
        assert_ne!(
            quoted(&display_command(&["tool".into(), "a\u{2028}b".into()])),
            quoted(&display_command(&["tool".into(), r"a\u{2028}b".into()])),
        );
    }

    #[test]
    fn simple_prompt_is_concise() {
        let input = SudoRunInput {
            argv: vec!["touch".to_string(), "/lol".to_string()],
            reason: "I hate you".to_string(),
            timeout_seconds: None,
            cwd: None,
        };

        assert_eq!(
            password_prompt_message(&input),
            "sudo password required.\n\nReason: \"I hate you\"\nCommand: \"touch /lol\""
        );
    }
}
