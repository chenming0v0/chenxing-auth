use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::error;

use super::LinkedAccountView;

#[derive(Debug, Serialize)]
pub(crate) struct AccountList {
    pub(crate) items: Vec<LinkedAccountView>,
    pub(crate) next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LinkedAccountListQuery {
    pub(crate) limit: Option<String>,
    pub(crate) cursor: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct AccountCursor {
    linked_at: i64,
    id: String,
}

pub(crate) fn invalid_pagination() -> Response {
    error::bad_request(
        "invalid_pagination",
        "limit must be between 1 and 100 and cursor must be valid",
    )
}

pub(crate) fn limit(query: &LinkedAccountListQuery) -> Result<usize, ()> {
    match query.limit.as_deref() {
        None => Ok(50),
        Some(value) => match value.parse::<usize>() {
            Ok(value) if (1..=100).contains(&value) => Ok(value),
            _ => Err(()),
        },
    }
}

pub(crate) fn cursor(query: &LinkedAccountListQuery) -> Result<Option<AccountCursor>, ()> {
    let cursor = match query.cursor.as_deref() {
        None => None,
        Some(value) if value.len() <= 512 => decode_cursor(value),
        Some(_) => None,
    };
    if query.cursor.is_some() && cursor.is_none() {
        return Err(());
    }
    Ok(cursor)
}

pub(crate) fn page(
    items: Vec<LinkedAccountView>,
    limit: usize,
    cursor: Option<&AccountCursor>,
) -> Response {
    let mut items = items
        .into_iter()
        .filter(|item| cursor.is_none_or(|cursor| after_cursor(item, cursor)))
        .take(limit + 1)
        .collect::<Vec<_>>();
    let next_cursor = (items.len() > limit).then(|| {
        let extra = items.pop().expect("limit + 1 contains an extra item");
        encode_cursor(&extra)
    });
    (StatusCode::OK, Json(AccountList { items, next_cursor })).into_response()
}

fn encode_cursor(item: &LinkedAccountView) -> String {
    let cursor = AccountCursor {
        linked_at: item.linked_at.unix_timestamp(),
        id: item.id.clone(),
    };
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&cursor).expect("cursor is serializable"))
}

fn decode_cursor(value: &str) -> Option<AccountCursor> {
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    let cursor = serde_json::from_slice::<AccountCursor>(&bytes).ok()?;
    (!cursor.id.is_empty() && cursor.id.len() <= 128).then_some(cursor)
}

fn after_cursor(item: &LinkedAccountView, cursor: &AccountCursor) -> bool {
    let linked_at = item.linked_at.unix_timestamp();
    linked_at < cursor.linked_at || (linked_at == cursor.linked_at && item.id < cursor.id)
}
