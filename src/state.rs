use redis::Client;

use crate::{
    admin::AdminAuthenticator,
    audit::AuditService,
    clients::service::ClientService,
    config::Config,
    db::Database,
    keys::{KeyManager, KeyManagerError},
    oauth::refresh_store::RefreshTokenStore,
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
    pub revocations: TokenRevocationStore,
    pub admin: AdminAuthenticator,
    pub audit: AuditService,
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("database configuration is invalid: {0}")]
    Database(#[from] sqlx::Error),
    #[error("redis configuration is invalid: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("key manager initialization failed: {0}")]
    Keys(#[from] KeyManagerError),
}

impl AppState {
    pub fn new(config: Config) -> Result<Self, StateError> {
        let database = crate::db::connect(&config)?;
        let redis = redis::Client::open(config.redis_url.as_str())?;
        let sessions = SessionStore::new(redis.clone());
        let users = UserService::new(database.clone());
        let clients = ClientService::new(database.clone());
        let keys = KeyManager::load_or_generate(&config.key_directory)?;
        let authorization_codes = AuthorizationCodeStore::new(redis.clone());
        let refresh_tokens = RefreshTokenStore::new(redis.clone());
        let revocations = TokenRevocationStore::new(redis.clone());
        let admin = AdminAuthenticator::new(config.admin_token.clone());
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
            revocations,
            admin,
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
