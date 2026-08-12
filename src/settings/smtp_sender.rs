use crate::users::email::EmailAddress;

/// 解析设置页支持的单一 SMTP 发件人格式。
///
/// 这里只接受裸邮箱或 `Display Name <email>`。显示名按 RFC phrase 的安全子集逐字符
/// 解析，避免用正则猜测嵌套引号和转义；邮箱本身仍由 [`EmailAddress`] 做唯一校验。
pub(super) fn parse_smtp_sender(value: &str) -> Option<EmailAddress> {
    // 必须在 trim 之前拒绝控制字符，否则首尾 CR/LF 会被悄悄裁掉并绕过邮件头边界。
    if value.chars().any(char::is_control) {
        return None;
    }
    let value = value.trim();

    // 尖括号属于 mailbox 结构，不允许被宽松的邮箱本地部分规则当成普通字符吞掉。
    if !value.contains('<')
        && !value.contains('>')
        && let Ok(email) = EmailAddress::parse(value)
    {
        return Some(email);
    }

    let without_closing_bracket = value.strip_suffix('>')?;
    let (display_name, email) = without_closing_bracket.rsplit_once('<')?;
    if !display_name.ends_with(' ') {
        return None;
    }
    let display_name = display_name.trim_end_matches(' ');
    if !is_valid_display_name(display_name)
        || email.is_empty()
        || email != email.trim()
        || email.contains('<')
        || email.contains('>')
    {
        return None;
    }

    EmailAddress::parse(email).ok()
}

#[derive(Clone, Copy)]
enum DisplayNameState {
    Start,
    Atom,
    BetweenWords,
    Quoted,
    QuotedEscape,
    AfterQuoted,
}

/// 接受由 atom / quoted-string 组成的 phrase，但拒绝组、地址列表、注释和裸 header
/// 分隔符。冒号、逗号等字符需要放进引号，才能明确属于显示文本而不是邮件头语法。
fn is_valid_display_name(value: &str) -> bool {
    let mut state = DisplayNameState::Start;
    let mut quoted_has_visible_character = false;

    for character in value.chars() {
        state = match state {
            DisplayNameState::Start => match character {
                '"' => DisplayNameState::Quoted,
                _ if is_atom_character(character) => DisplayNameState::Atom,
                _ => return false,
            },
            DisplayNameState::Atom => match character {
                ' ' => DisplayNameState::BetweenWords,
                _ if is_atom_character(character) => DisplayNameState::Atom,
                _ => return false,
            },
            DisplayNameState::BetweenWords => match character {
                ' ' => DisplayNameState::BetweenWords,
                '"' => {
                    quoted_has_visible_character = false;
                    DisplayNameState::Quoted
                }
                _ if is_atom_character(character) => DisplayNameState::Atom,
                _ => return false,
            },
            DisplayNameState::Quoted => match character {
                '\\' => DisplayNameState::QuotedEscape,
                '"' if quoted_has_visible_character => DisplayNameState::AfterQuoted,
                '"' => return false,
                _ if is_quoted_character(character) => {
                    quoted_has_visible_character |= character != ' ';
                    DisplayNameState::Quoted
                }
                _ => return false,
            },
            DisplayNameState::QuotedEscape => {
                if !is_quoted_character(character) {
                    return false;
                }
                quoted_has_visible_character |= character != ' ';
                DisplayNameState::Quoted
            }
            DisplayNameState::AfterQuoted => match character {
                ' ' => DisplayNameState::BetweenWords,
                _ => return false,
            },
        };
    }

    matches!(
        state,
        DisplayNameState::Atom | DisplayNameState::AfterQuoted
    )
}

fn is_atom_character(character: char) -> bool {
    if !character.is_ascii() {
        return !character.is_control() && !character.is_whitespace();
    }
    character.is_ascii_alphanumeric()
        || matches!(
            character,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '.'
                | '/'
                | '='
                | '?'
                | '^'
                | '_'
                | '`'
                | '{'
                | '|'
                | '}'
                | '~'
        )
}

fn is_quoted_character(character: char) -> bool {
    character == ' ' || (!character.is_control() && !character.is_whitespace())
}

#[cfg(test)]
mod tests {
    use super::parse_smtp_sender;
    use crate::settings::domain::{SettingsValidationError, SmtpSettingUpdate};

    fn validate_sender(value: &str) -> Result<String, SettingsValidationError> {
        SmtpSettingUpdate {
            host: "smtp.example.com".to_owned(),
            port: 587,
            username: "sender@example.com".to_owned(),
            from_address: value.to_owned(),
            ssl_enabled: true,
            force_auth_login: false,
            password: None,
        }
        .validate()
        .map(|(setting, _)| setting.from_address)
    }

    #[test]
    fn accepts_supported_single_mailbox_forms() {
        for (value, stored) in [
            ("sender@example.com", "sender@example.com"),
            ("  Sender@Example.COM  ", "Sender@Example.COM"),
            (
                "辰星认证中枢 <sender@example.com>",
                "辰星认证中枢 <sender@example.com>",
            ),
            (
                "Acme & Co. <sender@example.com>",
                "Acme & Co. <sender@example.com>",
            ),
            (
                "\"Doe, Jane\" <sender@example.com>",
                "\"Doe, Jane\" <sender@example.com>",
            ),
            (
                "Chenxing \"Auth, East\" <sender@example.com>",
                "Chenxing \"Auth, East\" <sender@example.com>",
            ),
        ] {
            assert_eq!(validate_sender(value), Ok(stored.to_owned()), "{value:?}");
        }

        assert_eq!(
            parse_smtp_sender("辰星认证中枢 <Sender@ÉXAMPLE.COM>")
                .expect("valid display-name mailbox")
                .display(),
            "Sender@xn--xample-9ua.com"
        );
    }

    #[test]
    fn rejects_crlf_and_other_control_characters_even_at_trim_boundaries() {
        for value in [
            "\rTrusted <sender@example.com>",
            "Trusted <sender@example.com>\n",
            "Trusted\r\nBcc: victim@example.com <sender@example.com>",
            "Trusted\0 <sender@example.com>",
            "Trusted\u{007f} <sender@example.com>",
            "Trusted\t<sender@example.com>",
        ] {
            assert_eq!(
                validate_sender(value),
                Err(SettingsValidationError::InvalidSmtpFrom),
                "{value:?}"
            );
        }
    }

    #[test]
    fn rejects_malicious_or_ambiguous_display_name_prefixes() {
        for value in [
            "Bcc: victim@example.com <sender@example.com>",
            "attacker@example.com, Trusted <sender@example.com>",
            "<script> <sender@example.com>",
            "Trusted<sender@example.com>",
            "prefix<sender@example.com",
            "Trusted <sender@example.com> ignored",
            "Trusted <sender@example.com><attacker@example.com>",
            "Trusted <<sender@example.com>",
            "Trusted <sender@example.com>>",
            "\"unterminated <sender@example.com>",
        ] {
            assert_eq!(
                validate_sender(value),
                Err(SettingsValidationError::InvalidSmtpFrom),
                "{value:?}"
            );
        }
    }
}
