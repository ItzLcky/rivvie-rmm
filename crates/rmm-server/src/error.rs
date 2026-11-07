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
            ApiError::Forbidden => StatusCode::FORBIDDEN,
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
        (status, Json(json!({ "error": msg }))).into_response()
    }
}
