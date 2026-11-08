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
    /// Password was right; a TOTP or recovery code is needed (or was wrong).
    #[error("{0}")]
    MfaRequired(&'static str),
    /// Signed in, but the account must set up 2FA before using anything else.
    #[error("set up two-factor authentication to continue")]
    MfaSetupRequired,
    #[error("{0} not found")]
    NotFound(&'static str),
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Conflict(String),
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
            ApiError::Forbidden | ApiError::MfaSetupRequired => StatusCode::FORBIDDEN,
            ApiError::MfaRequired(_) => StatusCode::UNAUTHORIZED,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::Db(sqlx::Error::RowNotFound) => StatusCode::NOT_FOUND,
            ApiError::Db(sqlx::Error::Database(e)) if e.is_unique_violation() => StatusCode::CONFLICT,
            ApiError::Db(_) | ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
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
            ApiError::MfaSetupRequired => body["mfa_setup_required"] = true.into(),
            _ => {}
        }
        (status, Json(body)).into_response()
    }
}
