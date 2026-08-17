//! Password-login application decision, independent of Axum extractors and responses.

use crate::{
    auth_factors::{
        domain::FactorMethod,
        service::{AuthFactorService, AuthFactorServiceError, FactorVerification},
    },
    settings::IssuerRuntime,
    users::{
        domain::{AuthenticatedUser, LoginInput, UserId},
        service::{UserService, UserServiceError},
    },
};

pub(crate) trait LoginUserPort {
    async fn authenticate(
        &self,
        input: LoginInput,
        source_ip: Option<&str>,
    ) -> Result<AuthenticatedUser, UserServiceError>;
}

impl LoginUserPort for UserService {
    async fn authenticate(
        &self,
        input: LoginInput,
        source_ip: Option<&str>,
    ) -> Result<AuthenticatedUser, UserServiceError> {
        UserService::authenticate(self, input, source_ip).await
    }
}

pub(crate) trait LoginFactorPort {
    async fn available_methods(
        &self,
        user_id: UserId,
    ) -> Result<Vec<FactorMethod>, AuthFactorServiceError>;

    async fn verify_totp(
        &self,
        user_id: UserId,
        account_key: &str,
        source_ip: Option<&str>,
        code: &str,
    ) -> Result<FactorVerification, AuthFactorServiceError>;

    async fn is_passkey_recovery_required(
        &self,
        user_id: UserId,
    ) -> Result<bool, AuthFactorServiceError>;
}

impl LoginFactorPort for AuthFactorService {
    async fn available_methods(
        &self,
        user_id: UserId,
    ) -> Result<Vec<FactorMethod>, AuthFactorServiceError> {
        AuthFactorService::available_methods(self, user_id).await
    }

    async fn verify_totp(
        &self,
        user_id: UserId,
        account_key: &str,
        source_ip: Option<&str>,
        code: &str,
    ) -> Result<FactorVerification, AuthFactorServiceError> {
        AuthFactorService::verify_totp(self, user_id, account_key, source_ip, code).await
    }

    async fn is_passkey_recovery_required(
        &self,
        user_id: UserId,
    ) -> Result<bool, AuthFactorServiceError> {
        AuthFactorService::is_passkey_recovery_required(self, user_id).await
    }
}

pub(crate) trait LoginIssuerPort {
    fn local_login_allowed(&self, user_id: UserId) -> bool;
}

impl LoginIssuerPort for IssuerRuntime {
    fn local_login_allowed(&self, user_id: UserId) -> bool {
        IssuerRuntime::local_login_allowed(self, user_id)
    }
}

#[derive(Debug)]
pub enum LoginDecision {
    PasswordOnly {
        authenticated: AuthenticatedUser,
        passkey_recovery_required: bool,
    },
    TotpAccepted(AuthenticatedUser),
    TotpRejected(UserId),
    TotpRateLimited(UserId),
    TotpKeyUnavailable(UserId),
    FactorRequired {
        authenticated: AuthenticatedUser,
        methods: Vec<FactorMethod>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum LoginUseCaseError {
    #[error(transparent)]
    User(#[from] UserServiceError),
    #[error(transparent)]
    Factor(#[from] AuthFactorServiceError),
    #[error("local login is not allowed while the issuer runtime is unavailable")]
    IssuerRestricted(UserId),
}

pub(crate) async fn decide_login<U, F, I>(
    users: &U,
    factors: &F,
    issuer: &I,
    input: LoginInput,
    account_key: &str,
    source_ip: Option<&str>,
) -> Result<LoginDecision, LoginUseCaseError>
where
    U: LoginUserPort + ?Sized,
    F: LoginFactorPort + ?Sized,
    I: LoginIssuerPort + ?Sized,
{
    let totp_code = input.totp_code.clone();
    let authenticated = users.authenticate(input, source_ip).await?;
    if !issuer.local_login_allowed(authenticated.id) {
        return Err(LoginUseCaseError::IssuerRestricted(authenticated.id));
    }
    let methods = factors.available_methods(authenticated.id).await?;
    if methods.contains(&FactorMethod::Totp) && totp_code.is_some() {
        return Ok(
            match factors
                .verify_totp(
                    authenticated.id,
                    account_key,
                    source_ip,
                    totp_code.as_deref().unwrap_or_default(),
                )
                .await
            {
                Ok(FactorVerification::Accepted) => LoginDecision::TotpAccepted(authenticated),
                Ok(FactorVerification::Rejected) => LoginDecision::TotpRejected(authenticated.id),
                Ok(FactorVerification::KeyUnavailable) => {
                    LoginDecision::TotpKeyUnavailable(authenticated.id)
                }
                Err(AuthFactorServiceError::RateLimited) => {
                    LoginDecision::TotpRateLimited(authenticated.id)
                }
                Err(error) => return Err(error.into()),
            },
        );
    }
    if methods.is_empty() {
        return Ok(LoginDecision::PasswordOnly {
            passkey_recovery_required: factors
                .is_passkey_recovery_required(authenticated.id)
                .await?,
            authenticated,
        });
    }
    Ok(LoginDecision::FactorRequired {
        authenticated,
        methods,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    enum TotpOutcome {
        Accepted,
        Rejected,
        KeyUnavailable,
        RateLimited,
    }

    struct FakeUsers {
        authenticated: AuthenticatedUser,
    }

    impl LoginUserPort for FakeUsers {
        async fn authenticate(
            &self,
            _input: LoginInput,
            _source_ip: Option<&str>,
        ) -> Result<AuthenticatedUser, UserServiceError> {
            Ok(self.authenticated)
        }
    }

    struct FakeFactors {
        methods: Vec<FactorMethod>,
        recovery_required: bool,
        totp: TotpOutcome,
    }

    impl LoginFactorPort for FakeFactors {
        async fn available_methods(
            &self,
            _user_id: UserId,
        ) -> Result<Vec<FactorMethod>, AuthFactorServiceError> {
            Ok(self.methods.clone())
        }

        async fn verify_totp(
            &self,
            _user_id: UserId,
            _account_key: &str,
            _source_ip: Option<&str>,
            _code: &str,
        ) -> Result<FactorVerification, AuthFactorServiceError> {
            match self.totp {
                TotpOutcome::Accepted => Ok(FactorVerification::Accepted),
                TotpOutcome::Rejected => Ok(FactorVerification::Rejected),
                TotpOutcome::KeyUnavailable => Ok(FactorVerification::KeyUnavailable),
                TotpOutcome::RateLimited => Err(AuthFactorServiceError::RateLimited),
            }
        }

        async fn is_passkey_recovery_required(
            &self,
            _user_id: UserId,
        ) -> Result<bool, AuthFactorServiceError> {
            Ok(self.recovery_required)
        }
    }

    struct FakeIssuer(bool);

    impl LoginIssuerPort for FakeIssuer {
        fn local_login_allowed(&self, _user_id: UserId) -> bool {
            self.0
        }
    }

    fn input(totp_code: Option<&str>) -> LoginInput {
        LoginInput {
            identifier: "user@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
            totp_code: totp_code.map(str::to_owned),
        }
    }

    fn factors(methods: Vec<FactorMethod>, totp: TotpOutcome) -> FakeFactors {
        FakeFactors {
            methods,
            recovery_required: false,
            totp,
        }
    }

    #[tokio::test]
    async fn password_only_decision_carries_recovery_policy() {
        let users = FakeUsers {
            authenticated: AuthenticatedUser::new(42, 7),
        };
        let mut factors = factors(Vec::new(), TotpOutcome::Accepted);
        factors.recovery_required = true;

        let decision = decide_login(
            &users,
            &factors,
            &FakeIssuer(true),
            input(None),
            "user@example.com",
            Some("192.0.2.1"),
        )
        .await
        .expect("password-only login should be decided");

        assert!(matches!(
            decision,
            LoginDecision::PasswordOnly {
                authenticated: AuthenticatedUser {
                    id: 42,
                    session_epoch: 7
                },
                passkey_recovery_required: true,
            }
        ));
    }

    #[tokio::test]
    async fn totp_outcomes_remain_distinct_application_results() {
        let users = FakeUsers {
            authenticated: AuthenticatedUser::new(42, 7),
        };
        let cases = [
            (TotpOutcome::Accepted, "accepted"),
            (TotpOutcome::Rejected, "rejected"),
            (TotpOutcome::KeyUnavailable, "key_unavailable"),
            (TotpOutcome::RateLimited, "rate_limited"),
        ];

        for (outcome, expected) in cases {
            let decision = decide_login(
                &users,
                &factors(vec![FactorMethod::Totp], outcome),
                &FakeIssuer(true),
                input(Some("123456")),
                "user@example.com",
                None,
            )
            .await
            .expect("TOTP outcome should be represented without HTTP mapping");
            let actual = match decision {
                LoginDecision::TotpAccepted(_) => "accepted",
                LoginDecision::TotpRejected(42) => "rejected",
                LoginDecision::TotpKeyUnavailable(42) => "key_unavailable",
                LoginDecision::TotpRateLimited(42) => "rate_limited",
                other => panic!("unexpected login decision: {other:?}"),
            };
            assert_eq!(actual, expected);
        }
    }

    #[tokio::test]
    async fn issuer_restriction_is_not_an_http_response() {
        let users = FakeUsers {
            authenticated: AuthenticatedUser::new(42, 7),
        };

        let error = decide_login(
            &users,
            &factors(Vec::new(), TotpOutcome::Accepted),
            &FakeIssuer(false),
            input(None),
            "user@example.com",
            None,
        )
        .await
        .expect_err("issuer policy should reject the application decision");

        assert!(matches!(error, LoginUseCaseError::IssuerRestricted(42)));
    }
}
