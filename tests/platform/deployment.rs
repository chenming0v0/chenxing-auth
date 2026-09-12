//! Deployment / installation / CI contract tests, split by concern.
//!
//! The embedded source literals live here once so every child module
//! asserts against the same bytes; the tests live in the child modules.

const BUILD_WORKFLOW: &str = include_str!("../../.github/workflows/build.yml");
const CI_WORKFLOW: &str = include_str!("../../.github/workflows/ci.yml");
const INSTALL_SCRIPT: &str = include_str!("../../deploy/install.sh");
const MANAGE_SCRIPT: &str = include_str!("../../manage.sh");
const REMOTE_INSTALL_SCRIPT: &str = include_str!("../../install.sh");
const REMOTE_UPDATE_SCRIPT: &str = include_str!("../../update.sh");
const REMOTE_COMPOSE: &str = include_str!("../../deploy/compose.yml");
const PRODUCTION_COMPOSE: &str = include_str!("../../docker-compose.prod.yml");
const REDIS_CRASH_RECOVERY_SCRIPT: &str = include_str!("../../test_sh/redis_crash_recovery.sh");
const TEST_RUNNER_CONTRACT_SCRIPT: &str = include_str!("../../test_sh/test_runner_contract.sh");
const DB_MODULE: &str = include_str!("../../src/db/mod.rs");
const DB_POOL_MODULE: &str = include_str!("../../src/db/pool.rs");
const DB_AUDIT_BOUNDARY_MODULE: &str = include_str!("../../src/db/audit_boundary.rs");
const DB_ROLES_MODULE: &str = include_str!("../../src/db/roles.rs");
const DB_MIGRATE_MODULE: &str = include_str!("../../src/db/migrate.rs");
const DB_MIGRATION_COMPAT_MODULE: &str = include_str!("../../src/db/migration_compat.rs");
const DB_MIGRATION_COMPAT_DESCRIPTION_MODULE: &str =
    include_str!("../../src/db/migration_compat_description.rs");
const DB_MIGRATION_PREFLIGHT_MODULE: &str = include_str!("../../src/db/migration_preflight.rs");
const ENV_EXAMPLE: &str = include_str!("../../.env.example");
const DOCKERFILE: &str = include_str!("../../Dockerfile");
const RUNTIME_DOCKERFILE: &str = include_str!("../../Dockerfile.runtime");
const DOCKERIGNORE: &str = include_str!("../../.dockerignore");
const STATIC_FILES_MODULE: &str = include_str!("../../src/api/static_files.rs");
const HEALTH_MODULE: &str = include_str!("../../src/api/health.rs");
const OAUTH_RESPONSE_MODULE: &str = include_str!("../../src/oauth/response.rs");
const OAUTH_TOKEN_SUPPORT_MODULE: &str = include_str!("../../src/oauth/token_use_case_support.rs");
const OAUTH_ERROR_MODULE: &str = include_str!("../../src/error.rs");
const WEB_DIST_MODULE: &str = include_str!("../../src/web_dist.rs");
const CONFIG_CONSTRUCTION_MODULE: &str = include_str!("../../src/config/construction.rs");
const STATE_MODULE: &str = include_str!("../../src/state.rs");
const DATABASE_BASELINE: &str = include_str!("../../migrations/0001_initial.sql");
const PUBLISHED_MIGRATION_CHECKSUMS: &str =
    include_str!("../../migrations/published-checksums.sha256");

/// Where both production images place the built frontend bundle.
const WEB_DIST_IMAGE_PATH: &str = "/usr/local/share/chenxing-auth/web/dist";

mod compose;
mod images;
mod installer;
mod migration_invariants;
mod migrations;
mod release;
mod runtime;
