use subtle::ConstantTimeEq;

pub mod auth_handlers;
pub mod authorization;
pub mod domain;
pub mod handlers;
pub mod key_handlers;
pub mod management_handlers;
pub mod repository;
pub mod service;
pub mod session;
pub mod web_handlers;

#[derive(Clone)]
pub struct AdminAuthenticator {
    token: String,
}

impl AdminAuthenticator {
    pub fn new(token: String) -> Self {
        Self { token }
    }

    pub fn is_valid(&self, candidate: &str) -> bool {
        !self.token.is_empty()
            && self.token.len() == candidate.len()
            && self.token.as_bytes().ct_eq(candidate.as_bytes()).into()
    }

    pub fn is_authorization_header_valid(&self, value: &str) -> bool {
        let Some((scheme, token)) = value.split_once(' ') else {
            return false;
        };
        scheme.eq_ignore_ascii_case("Bearer") && self.is_valid(token)
    }
}
