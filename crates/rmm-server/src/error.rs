use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not authenticated")]
    Unauthorized,
    #[error("insufficient permissions")]
    Forbidden,
    /// Forbidden, with the reason (a policy turned the feature off).
    #[error("{0}")]
    Denied(String),
    /// Password was right; a TOTP or recovery code is needed (or was wrong).
    #[error("{0}")]
    MfaRequired(&'static str),
    /// Password was right; a second factor is needed (or was wrong), and these are the ones the
    /// account has.
    #[error("{msg}")]
    MfaMethods { msg: &'static str, totp: bool, passkey: bool },
    /// Signed in, but the account must set up 2FA before using anything else.
    #[error("set up two-factor authentication to continue")]
    MfaSetupRequired,
    #[error("{0} not found")]
    NotFound(&'static str),
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Conflict(String),
    /// An upload over its limit; the message names the limit.
    #[error("{0}")]
    TooLarge(String),
    #[error("too many failed attempts; try again in {} seconds", .0.as_secs())]
    TooManyRequests(std::time::Duration),
    /// A limit on every use, not on failures (vault reveals).
    #[error("too many requests; try again in {} seconds", .0.as_secs())]
    Throttled(std::time::Duration),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

pub type ApiResult<T> = Result<T, ApiError>;

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden | ApiError::Denied(_) | ApiError::MfaSetupRequired => StatusCode::FORBIDDEN,
            ApiError::MfaRequired(_) | ApiError::MfaMethods { .. } => StatusCode::UNAUTHORIZED,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::TooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            ApiError::TooManyRequests(_) | ApiError::Throttled(_) => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Db(sqlx::Error::RowNotFound) => StatusCode::NOT_FOUND,
            ApiError::Db(sqlx::Error::Database(e)) if e.is_unique_violation() => StatusCode::CONFLICT,
            ApiError::Db(_) | ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        if matches!(self, ApiError::Db(sqlx::Error::PoolTimedOut)) {
            crate::metrics::inc(&crate::metrics::M.db_acquire_timeouts);
        }
        let msg = if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!("internal error: {self:#}");
            "internal server error".to_string()
        } else if status == StatusCode::CONFLICT && matches!(self, ApiError::Db(_)) {
            "already exists".to_string()
        } else {
            self.to_string()
        };
        let mut body = json!({ "error": msg });
        match self {
            ApiError::MfaRequired(_) => body["mfa_required"] = true.into(),
            ApiError::MfaMethods { totp, passkey, .. } => {
                body["mfa_required"] = true.into();
                body["methods"] = json!({ "totp": totp, "passkey": passkey });
            }
            ApiError::MfaSetupRequired => body["mfa_setup_required"] = true.into(),
            ApiError::TooManyRequests(wait) | ApiError::Throttled(wait) => {
                return (status, [(axum::http::header::RETRY_AFTER, wait.as_secs().to_string())], Json(body)).into_response();
            }
            _ => {}
        }
        (status, Json(body)).into_response()
    }
}
