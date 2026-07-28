use redis::Client;

use crate::{
    admin::AdminAuthenticator,
    admin::{service::AdminService, session::AdminSessionStore},
    audit::AuditService,
    clients::service::ClientService,
    config::Config,
    consents::ConsentService,
    db::Database,
    keys::{KeyManager, KeyManagerError},
    oauth::quota::OAuthQuotaStore,
    oauth::refresh_store::RefreshTokenStore,
    oauth::request_store::AuthorizationRequestStore,
    oauth::revocation::TokenRevocationStore,
    oauth::store::AuthorizationCodeStore,
    sessions::store::SessionStore,
    users::service::UserService,
};

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub database: Database,
    pub redis: Client,
    pub sessions: SessionStore,
    pub users: UserService,
    pub clients: ClientService,
    pub keys: KeyManager,
    pub authorization_codes: AuthorizationCodeStore,
    pub refresh_tokens: RefreshTokenStore,
    pub authorization_requests: AuthorizationRequestStore,
    pub consents: ConsentService,
    pub revocations: TokenRevocationStore,
    pub oauth_quotas: OAuthQuotaStore,
    pub admin: AdminAuthenticator,
    pub admins: AdminService,
    pub admin_sessions: AdminSessionStore,
    pub audit: AuditService,
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("database configuration is invalid: {0}")]
    Database(#[from] crate::sqlx::Error),
    #[error("redis configuration is invalid: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("key manager initialization failed: {0}")]
    Keys(#[from] KeyManagerError),
}

impl AppState {
    pub fn new(config: Config) -> Result<Self, StateError> {
        let database = crate::db::connect(&config)?;
        let redis = redis::Client::open(config.redis_url.as_str())?;
        let sessions = SessionStore::with_metadata(redis.clone(), database.clone());
        let users = UserService::new(database.clone());
        let clients = ClientService::new(database.clone());
        let keys = KeyManager::load_or_generate(&config.key_directory)?;
        let authorization_codes = AuthorizationCodeStore::new(redis.clone());
        let refresh_tokens = RefreshTokenStore::new(redis.clone());
        let authorization_requests = AuthorizationRequestStore::new(redis.clone());
        let consents = ConsentService::new(database.clone());
        let revocations = TokenRevocationStore::new(redis.clone());
        let oauth_quotas = OAuthQuotaStore::new(redis.clone());
        let admin = AdminAuthenticator::new(config.admin_token.clone());
        let admins = AdminService::new(database.clone());
        let admin_sessions = AdminSessionStore::new(redis.clone());
        let audit = AuditService::new(database.clone());

        Ok(Self {
            config,
            database,
            redis,
            sessions,
            users,
            clients,
            keys,
            authorization_codes,
            refresh_tokens,
            authorization_requests,
            consents,
            revocations,
            oauth_quotas,
            admin,
            admins,
            admin_sessions,
            audit,
        })
    }

    pub fn for_test() -> Self {
        let config = Config::from_values(
            "127.0.0.1".to_owned(),
            3000,
            "postgres://localhost/chenxing_auth".to_owned(),
            "redis://localhost".to_owned(),
            3600,
        )
        .expect("test configuration");

        Self::new(config).expect("test state")
    }
}
