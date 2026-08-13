mod inputs;
mod passkey;
mod responses;
mod ticket_proof;
mod totp;

pub use inputs::{
    PasskeyAuthenticationInput, PasskeyRegistrationInput, PasskeyTicketInput, TotpConfirmInput,
    TotpLoginInput, TotpSetupInput,
};
pub use passkey::{
    finish_passkey_authentication, finish_passkey_registration, start_passkey_authentication,
    start_passkey_registration,
};
pub use totp::{confirm_totp_setup, login_totp, start_totp_setup};

/// 密码登录路径（`users::handlers`）也要区分「码错」和「密钥退役」，因此这条
/// 响应映射对 crate 内公开，避免两处各写一份不一致的错误语义。
pub(crate) use responses::factor_key_unavailable_response;
