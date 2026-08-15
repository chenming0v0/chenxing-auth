use std::sync::{Arc, Mutex};

use serde::Serialize;
use time::OffsetDateTime;
use tokio::sync::watch;

use crate::config::{
    Config, ConfigError, IssuerUrl, parse_root_http_url, validate_cookie_security,
};

use super::issuer::{IssuerRecord, RawIssuerRecord};

pub const ISSUER_SYNC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemPhase {
    AwaitingIssuer,
    IssuerLoaded,
    IssuerInvalid,
}

#[derive(Debug, Clone)]
pub struct IssuerSnapshot {
    issuer: IssuerUrl,
    generation: i64,
    updated_at: OffsetDateTime,
    webauthn_rp_id: String,
    webauthn_origin: String,
}

impl IssuerSnapshot {
    pub fn issuer(&self) -> &IssuerUrl {
        &self.issuer
    }

    pub fn generation(&self) -> i64 {
        self.generation
    }

    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    pub fn webauthn_rp_id(&self) -> &str {
        &self.webauthn_rp_id
    }

    pub fn webauthn_origin(&self) -> &str {
        &self.webauthn_origin
    }
}

#[derive(Debug, Clone)]
pub enum IssuerRuntimeState {
    AwaitingIssuer,
    Pending {
        persisted_generation: i64,
    },
    Ready(Arc<IssuerSnapshot>),
    Invalid {
        persisted_generation: i64,
        loaded_generation: Option<i64>,
    },
}

impl IssuerRuntimeState {
    pub fn phase(&self) -> SystemPhase {
        match self {
            Self::AwaitingIssuer => SystemPhase::AwaitingIssuer,
            Self::Pending { .. } => SystemPhase::IssuerInvalid,
            Self::Ready(_) => SystemPhase::IssuerLoaded,
            Self::Invalid { .. } => SystemPhase::IssuerInvalid,
        }
    }

    pub fn loaded(&self) -> Option<Arc<IssuerSnapshot>> {
        match self {
            Self::Ready(snapshot) => Some(snapshot.clone()),
            _ => None,
        }
    }

    pub fn loaded_generation(&self) -> Option<i64> {
        match self {
            Self::Ready(snapshot) => Some(snapshot.generation()),
            Self::Invalid {
                loaded_generation, ..
            } => *loaded_generation,
            Self::AwaitingIssuer | Self::Pending { .. } => None,
        }
    }
}

#[derive(Debug, Clone)]
struct IssuerPolicy {
    cookie_secure: bool,
    webauthn_rp_id_override: Option<String>,
    webauthn_origin_override: Option<String>,
}

impl IssuerPolicy {
    fn from_config(config: &Config) -> Self {
        Self {
            cookie_secure: config.cookie_secure,
            webauthn_rp_id_override: config
                .webauthn_rp_id_explicit
                .then(|| config.webauthn_rp_id.clone()),
            webauthn_origin_override: config
                .webauthn_origin_explicit
                .then(|| config.webauthn_origin.clone()),
        }
    }

    fn snapshot(&self, record: &IssuerRecord) -> Result<IssuerSnapshot, ConfigError> {
        let issuer = IssuerUrl::parse(&record.value)?;
        validate_cookie_security(issuer.parsed(), self.cookie_secure)?;
        let webauthn_rp_id = self
            .webauthn_rp_id_override
            .clone()
            .unwrap_or_else(|| issuer.host_str().to_owned());
        if webauthn_rp_id.trim().is_empty() {
            return Err(ConfigError::InvalidValue("WEBAUTHN_RP_ID"));
        }
        let webauthn_origin = self
            .webauthn_origin_override
            .clone()
            .unwrap_or_else(|| issuer.as_str().to_owned());
        parse_root_http_url(&webauthn_origin, "WEBAUTHN_ORIGIN")?;
        Ok(IssuerSnapshot {
            issuer,
            generation: record.generation,
            updated_at: record.updated_at,
            webauthn_rp_id,
            webauthn_origin,
        })
    }
}

#[derive(Clone)]
pub struct IssuerRuntime {
    sender: Arc<watch::Sender<Arc<IssuerRuntimeState>>>,
    policy: Arc<IssuerPolicy>,
    transition_lock: Arc<Mutex<()>>,
}

impl IssuerRuntime {
    pub fn new(config: &Config, record: Option<&IssuerRecord>) -> Result<Self, ConfigError> {
        let policy = Arc::new(IssuerPolicy::from_config(config));
        let initial = match record {
            Some(record) => IssuerRuntimeState::Ready(Arc::new(policy.snapshot(record)?)),
            None => IssuerRuntimeState::AwaitingIssuer,
        };
        Ok(Self::with_state(policy, initial))
    }

    pub(crate) fn new_from_raw(config: &Config, record: Option<&RawIssuerRecord>) -> Self {
        let policy = Arc::new(IssuerPolicy::from_config(config));
        let initial = match record {
            None => IssuerRuntimeState::AwaitingIssuer,
            Some(record) => {
                let Some(value) = record
                    .value
                    .as_deref()
                    .filter(|value| !value.trim().is_empty())
                else {
                    return Self::with_state(
                        policy,
                        IssuerRuntimeState::Pending {
                            persisted_generation: record.generation,
                        },
                    );
                };
                let normalized = IssuerRecord {
                    value: value.to_owned(),
                    generation: record.generation,
                    updated_at: record.updated_at,
                };
                match policy.snapshot(&normalized) {
                    Ok(snapshot) => IssuerRuntimeState::Ready(Arc::new(snapshot)),
                    Err(_) => IssuerRuntimeState::Invalid {
                        persisted_generation: record.generation,
                        loaded_generation: None,
                    },
                }
            }
        };
        Self::with_state(policy, initial)
    }

    fn with_state(policy: Arc<IssuerPolicy>, state: IssuerRuntimeState) -> Self {
        let (sender, _) = watch::channel(Arc::new(state));
        Self {
            sender: Arc::new(sender),
            policy,
            transition_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn new_invalid(config: &Config, generation: i64) -> Self {
        Self::with_state(
            Arc::new(IssuerPolicy::from_config(config)),
            IssuerRuntimeState::Invalid {
                persisted_generation: generation,
                loaded_generation: None,
            },
        )
    }

    pub fn state(&self) -> Arc<IssuerRuntimeState> {
        self.sender.borrow().clone()
    }

    pub fn is_awaiting_configuration(&self) -> bool {
        matches!(self.state().as_ref(), IssuerRuntimeState::AwaitingIssuer)
    }

    pub fn is_ready(&self) -> bool {
        matches!(self.state().as_ref(), IssuerRuntimeState::Ready(_))
    }

    pub fn local_login_allowed(&self, user_id: i64) -> bool {
        match self.state().as_ref() {
            IssuerRuntimeState::Ready(_) => true,
            IssuerRuntimeState::AwaitingIssuer
                if user_id == crate::users::domain::INITIAL_OWNER_ID =>
            {
                true
            }
            IssuerRuntimeState::AwaitingIssuer
            | IssuerRuntimeState::Pending { .. }
            | IssuerRuntimeState::Invalid { .. } => false,
        }
    }

    pub fn subscribe(&self) -> watch::Receiver<Arc<IssuerRuntimeState>> {
        self.sender.subscribe()
    }

    pub fn validate_value(&self, value: &IssuerUrl) -> Result<(), ConfigError> {
        validate_cookie_security(value.parsed(), self.policy.cookie_secure)?;
        let record = IssuerRecord {
            value: value.as_str().to_owned(),
            generation: 1,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        self.policy.snapshot(&record).map(|_| ())
    }

    pub fn webauthn_defaults_for(
        &self,
        value: &IssuerUrl,
    ) -> Result<(String, String), ConfigError> {
        let record = IssuerRecord {
            value: value.as_str().to_owned(),
            generation: 1,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        let snapshot = self.policy.snapshot(&record)?;
        Ok((
            snapshot.webauthn_rp_id().to_owned(),
            snapshot.webauthn_origin().to_owned(),
        ))
    }

    pub fn current(&self) -> Option<Arc<IssuerSnapshot>> {
        self.state().loaded()
    }

    pub fn apply(&self, record: &IssuerRecord) -> Result<Option<Arc<IssuerSnapshot>>, ConfigError> {
        let raw = RawIssuerRecord {
            value: Some(record.value.clone()),
            generation: record.generation,
            updated_at: record.updated_at,
        };
        self.apply_raw(Some(&raw))
    }

    pub(crate) fn apply_raw(
        &self,
        record: Option<&RawIssuerRecord>,
    ) -> Result<Option<Arc<IssuerSnapshot>>, ConfigError> {
        let _guard = self
            .transition_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.apply_raw_locked(record)
    }

    pub(crate) fn apply_raw_if_unchanged(
        &self,
        expected: &Arc<IssuerRuntimeState>,
        record: Option<&RawIssuerRecord>,
    ) -> Result<Option<Arc<IssuerSnapshot>>, ConfigError> {
        let _guard = self
            .transition_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let current = self.sender.borrow().clone();
        if !Arc::ptr_eq(expected, &current) {
            return Ok(None);
        }
        self.apply_raw_locked(record)
    }

    fn apply_raw_locked(
        &self,
        record: Option<&RawIssuerRecord>,
    ) -> Result<Option<Arc<IssuerSnapshot>>, ConfigError> {
        let Some(record) = record else {
            if matches!(
                self.sender.borrow().as_ref(),
                IssuerRuntimeState::AwaitingIssuer
            ) {
                return Ok(None);
            }
            self.sender
                .send_replace(Arc::new(IssuerRuntimeState::AwaitingIssuer));
            return Ok(None);
        };
        let current = self.sender.borrow().clone();
        let current_generation = match current.as_ref() {
            IssuerRuntimeState::Ready(snapshot) => Some(snapshot.generation()),
            IssuerRuntimeState::Pending {
                persisted_generation,
            }
            | IssuerRuntimeState::Invalid {
                persisted_generation,
                ..
            } => Some(*persisted_generation),
            IssuerRuntimeState::AwaitingIssuer => None,
        };
        if current_generation.is_some_and(|generation| record.generation < generation) {
            return Ok(None);
        }
        let Some(value) = record
            .value
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        else {
            if matches!(
                current.as_ref(),
                IssuerRuntimeState::Pending {
                    persisted_generation
                } if *persisted_generation == record.generation
            ) {
                return Ok(None);
            }
            self.sender
                .send_replace(Arc::new(IssuerRuntimeState::Pending {
                    persisted_generation: record.generation,
                }));
            return Ok(None);
        };
        if let IssuerRuntimeState::Ready(snapshot) = current.as_ref()
            && record.generation == snapshot.generation()
        {
            if value == snapshot.issuer().as_str() {
                return Ok(None);
            }
            self.sender
                .send_replace(Arc::new(IssuerRuntimeState::Invalid {
                    persisted_generation: record.generation,
                    loaded_generation: Some(snapshot.generation()),
                }));
            return Err(ConfigError::InvalidValue("APP_ISSUER_GENERATION"));
        }

        let previous_generation = current.loaded_generation();
        let normalized = IssuerRecord {
            value: value.to_owned(),
            generation: record.generation,
            updated_at: record.updated_at,
        };
        let snapshot = match self.policy.snapshot(&normalized) {
            Ok(snapshot) => Arc::new(snapshot),
            Err(error) => {
                self.sender
                    .send_replace(Arc::new(IssuerRuntimeState::Invalid {
                        persisted_generation: record.generation,
                        loaded_generation: previous_generation,
                    }));
                return Err(error);
            }
        };
        self.sender
            .send_replace(Arc::new(IssuerRuntimeState::Ready(snapshot.clone())));
        Ok(Some(snapshot))
    }
}
