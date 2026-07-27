use subtle::ConstantTimeEq;

pub mod handlers;

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
}
