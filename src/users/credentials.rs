use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use std::sync::OnceLock;

const DUMMY_PASSWORD: &str = "chenxing-auth-dummy-password";
static DUMMY_PASSWORD_HASH: OnceLock<String> = OnceLock::new();

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
}

pub fn verify_password(password: &str, encoded_hash: &str) -> bool {
    let Ok(hash) = PasswordHash::new(encoded_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &hash)
        .is_ok()
}

pub fn prepare_dummy_password_hash() {
    let _ = dummy_password_hash();
}

pub fn verify_login_password(password: &str, encoded_hash: Option<&str>) -> bool {
    match encoded_hash {
        Some(hash) => verify_password(password, hash),
        None => {
            let dummy_hash = dummy_password_hash();
            let _ = verify_password(password, dummy_hash);
            false
        }
    }
}

fn dummy_password_hash() -> &'static str {
    DUMMY_PASSWORD_HASH.get_or_init(|| match hash_password(DUMMY_PASSWORD) {
        Ok(hash) => hash,
        Err(error) => {
            tracing::error!(error = %error, "failed to prepare dummy password hash");
            String::new()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{DUMMY_PASSWORD, dummy_password_hash, verify_login_password};

    #[test]
    fn dummy_password_path_uses_a_reusable_argon2_hash() {
        let hash = dummy_password_hash();
        assert!(hash.starts_with("$argon2"));
        assert!(!verify_login_password(DUMMY_PASSWORD, None));
        assert!(!verify_login_password("wrong dummy password", None));
    }
}
