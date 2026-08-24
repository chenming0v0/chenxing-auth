use std::fmt;

use serde::Deserialize;

#[derive(Deserialize)]
pub struct RegistrationInput {
    pub username: String,
    pub email: String,
    pub password: String,
    pub display_name: Option<String>,
    #[serde(default)]
    pub invitation_code: Option<String>,
}

impl fmt::Debug for RegistrationInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegistrationInput")
            .field("username", &self.username)
            .field("email", &self.email)
            .field("password", &"<redacted>")
            .field("display_name", &self.display_name)
            .field(
                "invitation_code",
                &self.invitation_code.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}
