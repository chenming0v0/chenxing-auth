//! 请求鉴权提取器：把「浏览器写操作必须校验 CSRF」从人工约定变成类型约束。
//!
//! # 为什么需要这一层
//!
//! CSRF 防御的对象是「浏览器自动附带用户已有凭据」这一行为，所以它是
//! **认证方式的属性，而不是 HTTP 方法的属性**：
//!
//! - 用 Session Cookie 认证的写操作必须校验 CSRF —— 浏览器会跨站自动带上 Cookie。
//! - 登录前的公开端点无从校验 —— 此时用户还没有任何凭据可被借用。
//! - `Authorization: Bearer` 认证的端点不需要 —— 浏览器不会自动附带该头部。
//!
//! 这一层把上述判断收敛成四个类型。handler 签名里写哪个类型，就获得哪一档保证；
//! 想拿到身份只能通过这些提取器，因此漏掉 CSRF 校验会变成**编译错误**，
//! 而不是静默降级的安全漏洞。
//!
//! | 提取器 | 校验内容 | 适用场景 |
//! |---|---|---|
//! | [`SessionRead`] | Session Cookie | 普通用户读端点 |
//! | [`SessionWrite`] | Session Cookie + CSRF Cookie + `X-CSRF-Token` 三者绑定 | 普通用户写端点 |
//! | [`AdminRead`] | Session Cookie 或系统 Token，随后 `authorize()` 校验权限 | 管理读端点 |
//! | [`AdminWrite`] | 同上，且 `authorize()` 额外无条件校验 CSRF | 管理写端点 |
//!
//! 管理提取器是「管理面开关」的执行点：`ADMIN_TOKEN` 为空时（AGENTS.md，Issue #348）
//! [`AdminCaller::resolve`] 拒绝所有请求，两条管理通道一并关闭，唯一例外是
//! 不存在 Owner 时公开的首个 Owner 引导端点（它不使用本层提取器）。
//!
//! # 两种拒绝时机
//!
//! [`SessionWrite`] 在提取阶段就拒绝，因此 CSRF 校验发生在请求体解析之前 ——
//! 攻击者构造的 body 在鉴权通过前不会被反序列化。
//!
//! [`AdminWrite`] 把拒绝推迟到 [`AdminWrite::authorize`]，因为管理端的授权失败
//! 审计需要记录「尝试的是哪个权限」，而权限由 handler 在运行时给出。
//! 不变量仍然成立 —— 拿到 [`AdminActor`] 的唯一途径是 `authorize()`，而它无条件校验 CSRF。
//!
//! 需要按目标资源抬高门槛的端点（禁用 Owner、改写 Owner 的套餐）**不得**把
//! 「查资源决定权限」放在第一次 `authorize()` 之前：那会让权限门槛成为资源状态的
//! 函数，403 的措辞变成资源存在性预言机（Issue #280）。正确顺序是先按与目标无关的
//! 基线授权，再由写事务锁住目标并按实际角色消费授权档位。目标角色不得在事务外
//! 预读，否则会在预读与写入之间产生 Owner 晋升竞态（Issue #323）。
//!
//! 类型让人难以写错，`tests/csrf_route_coverage.rs` 的路由级测试让写错的跑不过。

use axum::{
    Json,
    extract::{FromRef, FromRequest, FromRequestParts, OptionalFromRequestParts},
    http::{Request, StatusCode, request::Parts},
    response::Response,
};
use serde::de::DeserializeOwned;
use std::ops::Deref;
use std::sync::Arc;

use crate::{
    admin::{
        authorization::{AdminActor, record_authz_denial},
        domain::AdminPermission,
        handlers::is_admin_request,
    },
    error,
    settings::IssuerSnapshot,
    state::AppState,
    users::{
        domain::OwnerTargetAccess,
        ui_auth::{UserContext, current_user, user_csrf_valid},
    },
};

/// 由全局 Issuer gate 注入的请求级快照。
///
/// handler 不能重新读取 runtime：更新可能恰好落在 gate 与 handler 之间，二次读取会
/// 让同一请求混用两个 generation。提取器缺失即表示路由没有经过协议门禁，直接拒绝。
#[derive(Debug, Clone)]
pub struct RequestIssuer(Arc<IssuerSnapshot>);

impl RequestIssuer {
    pub fn snapshot(&self) -> &Arc<IssuerSnapshot> {
        &self.0
    }
}

impl Deref for RequestIssuer {
    type Target = IssuerSnapshot;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for RequestIssuer
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Arc<IssuerSnapshot>>()
            .cloned()
            .map(Self)
            .ok_or_else(|| {
                tracing::error!("issuer-gated handler was invoked without a request snapshot");
                error::service_unavailable(
                    "issuer_not_loaded",
                    "the application issuer is not loaded",
                )
            })
    }
}

/// 已认证的浏览器会话，未校验 CSRF。用于读端点。
///
/// 读操作不改变状态，跨站发起也拿不到响应内容（同源策略），因此不需要 CSRF 校验。
#[derive(Debug)]
pub struct SessionRead(UserContext);

/// 已认证且已校验 CSRF 的浏览器会话。用于普通用户写端点。
///
/// 校验在提取阶段完成，因此请求体尚未被解析 —— 鉴权先行，减少攻击面。
#[derive(Debug)]
pub struct SessionWrite(UserContext);

/// JSON request extractor with the service error envelope.
///
/// Axum's rejection includes serde's field/type diagnostics and uses a plain-text
/// body. API callers get one stable code instead, without parser details.
#[derive(Debug)]
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = Response;

    async fn from_request(request: Request<axum::body::Body>, state: &S) -> Result<Self, Response> {
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|rejection| error::json_rejection(rejection.status()))
    }
}

impl Deref for SessionRead {
    type Target = UserContext;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for SessionWrite {
    type Target = UserContext;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for SessionRead
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = AppState::from_ref(state);
        Ok(Self(current_user(&state, &parts.headers).await?))
    }
}

/// `Option<SessionRead>` 用于「探测登录状态」而非「要求登录」的读端点。
///
/// `auth_status` 要如实回答「当前浏览器是否已登录」，未登录是一个正常答案而不是错误，
/// 只有明确的未登录/失效会话收敛成 `None`。数据库、Redis 或响应构造故障必须保留
/// 为拒绝响应，否则依赖故障会被伪装成正常的 `authenticated: false`。
impl<S> OptionalFromRequestParts<S> for SessionRead
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        let state = AppState::from_ref(state);
        match current_user(&state, &parts.headers).await {
            Ok(context) => Ok(Some(SessionRead(context))),
            Err(response) if response.status() == StatusCode::UNAUTHORIZED => Ok(None),
            Err(response) => Err(response),
        }
    }
}

#[cfg(test)]
#[path = "extract_tests.rs"]
mod tests;

impl<S> FromRequestParts<S> for SessionWrite
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = AppState::from_ref(state);
        let context = current_user(&state, &parts.headers).await?;
        if !user_csrf_valid(&parts.headers, &context.session, state.config.cookie_secure) {
            return Err(error::bad_request("csrf_invalid", "CSRF token is invalid"));
        }
        Ok(Self(context))
    }
}

/// 管理端调用者身份，权限尚未校验。
///
/// 两条独立通道，任一成立即可继续到权限校验（Issue #305）：
///
/// - [`Self::Session`]：浏览器 HttpOnly Session Cookie，写操作另需 CSRF 双 Cookie
///   与 `X-CSRF-Token` 绑定，权限由用户角色决定。
/// - [`Self::SystemToken`]：配置的系统 `ADMIN_TOKEN`，非浏览器自动附带的凭据，
///   因此豁免 CSRF，权限等价于 Owner。
///
/// `ADMIN_TOKEN` 为空时整个管理面关闭（AGENTS.md，Issue #348）：`is_valid` 恒假
/// 关掉 Bearer 通道，[`AdminCaller::resolve`] 顶部的 fail-closed 检查同时拒绝
/// Session 通道——空 Token 是「管理面关闭」的开关，而不是「只关自动化通道」。
/// 唯一例外是不存在 Owner 时公开的首个 Owner 引导端点，它不经过本提取器。
#[derive(Debug)]
enum AdminCaller {
    Session(Box<UserContext>),
    SystemToken,
}

impl AdminCaller {
    async fn resolve(state: &AppState, parts: &Parts) -> Result<Self, Response> {
        // AGENTS.md：ADMIN_TOKEN 为空时必须拒绝所有已初始化的管理 API（Issue #348）。
        // 两条通道统一拒绝，响应不区分调用者，避免把配置状态变成探测预言机。
        if state.config.admin_token.is_empty() {
            return Err(error::admin_disabled());
        }
        if is_admin_request(state, &parts.headers) {
            return Ok(Self::SystemToken);
        }
        Ok(Self::Session(Box::new(
            current_user(state, &parts.headers).await?,
        )))
    }

    /// 校验角色权限，失败时留痕。系统 Token 拥有全部权限，无需角色检查。
    async fn check_permission(
        &self,
        state: &AppState,
        permission: AdminPermission,
    ) -> Result<AdminActor, Response> {
        match self {
            Self::SystemToken => Ok(AdminActor::SystemToken),
            Self::Session(context) => {
                if !context.role.allows(permission) {
                    // 已认证但权限不足：留痕以便发现低权限账号的探测行为。
                    record_authz_denial(state, context.user_id, permission, "insufficient_role")
                        .await;
                    return Err(error::forbidden(
                        "admin_forbidden",
                        "administrator permission is insufficient",
                    ));
                }
                Ok(AdminActor::User(context.user_id))
            }
        }
    }
}

/// 管理端读端点入口。调用 [`AdminRead::authorize`] 完成权限校验。
#[derive(Debug)]
pub struct AdminRead(AdminCaller);

/// 管理端写端点入口。调用 [`AdminWrite::authorize`] 完成 CSRF 与权限校验。
///
/// CSRF 结果在提取阶段计算但不立即拒绝，因为审计事件需要记录被拒的权限名，
/// 而权限由 handler 在运行时给出。详见模块文档。
#[derive(Debug)]
pub struct AdminWrite {
    caller: AdminCaller,
    csrf_valid: bool,
}

impl AdminRead {
    /// 校验调用者是否具备 `permission`。
    pub async fn authorize(
        &self,
        state: &AppState,
        permission: AdminPermission,
    ) -> Result<AdminActor, Response> {
        self.0.check_permission(state, permission).await
    }
}

impl AdminWrite {
    /// 校验 CSRF 与 `permission`，两者都通过才返回调用者身份。
    ///
    /// CSRF 先于权限检查：无论权限是否充足，伪造请求都必须被拒，
    /// 且拒绝原因要如实反映是 CSRF 失败而不是权限不足。
    pub async fn authorize(
        &self,
        state: &AppState,
        permission: AdminPermission,
    ) -> Result<AdminActor, Response> {
        if !self.csrf_valid {
            if let AdminCaller::Session(context) = &self.caller {
                // CSRF 失败可能是跨站伪造或会话重放，必须可检索。
                record_authz_denial(state, context.user_id, permission, "csrf_invalid").await;
            }
            return Err(error::bad_request("csrf_invalid", "CSRF token is invalid"));
        }
        self.caller.check_permission(state, permission).await
    }

    /// 调用者在完成基线授权后可携带到目标用户写事务的最高档位。
    ///
    /// 该方法只描述调用者，不读取目标；目标角色必须由写事务持行锁后判定（#323）。
    pub(crate) fn owner_target_access(&self) -> OwnerTargetAccess {
        match &self.caller {
            AdminCaller::SystemToken => OwnerTargetAccess::ManageRoles,
            AdminCaller::Session(context) if context.role.allows(AdminPermission::ManageRoles) => {
                OwnerTargetAccess::ManageRoles
            }
            AdminCaller::Session(_) => OwnerTargetAccess::ManageUsers,
        }
    }
}

impl<S> FromRequestParts<S> for AdminRead
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = AppState::from_ref(state);
        Ok(Self(AdminCaller::resolve(&state, parts).await?))
    }
}

impl<S> FromRequestParts<S> for AdminWrite
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = AppState::from_ref(state);
        let caller = AdminCaller::resolve(&state, parts).await?;
        // 系统 Token 不是浏览器自动附带的凭据，跨站请求无法伪造它，因此豁免 CSRF。
        let csrf_valid = match &caller {
            AdminCaller::SystemToken => true,
            AdminCaller::Session(context) => {
                user_csrf_valid(&parts.headers, &context.session, state.config.cookie_secure)
            }
        };
        Ok(Self { caller, csrf_valid })
    }
}
