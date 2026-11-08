//! Per-client access checks for single-object endpoints. List endpoints filter in SQL with
//! [`User::scope`] instead.
//!
//! Anything outside the user's clients is reported as not found, not forbidden, so ids from
//! other clients can't be probed.

use uuid::Uuid;

use crate::auth::User;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// The agent's client, if the agent exists and `u` may see it.
pub async fn agent(st: &AppState, u: &User, agent_id: Uuid) -> ApiResult<Uuid> {
    let client: Option<Uuid> =
        sqlx::query_scalar("SELECT s.client_id FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = $1")
            .bind(agent_id)
            .fetch_optional(&st.db)
            .await?;
    client.filter(|c| u.can_see_client(*c)).ok_or(ApiError::NotFound("agent"))
}

/// The site's client, if the site exists and `u` may see it.
pub async fn site(st: &AppState, u: &User, site_id: Uuid) -> ApiResult<Uuid> {
    let client: Option<Uuid> =
        sqlx::query_scalar("SELECT client_id FROM sites WHERE id = $1").bind(site_id).fetch_optional(&st.db).await?;
    client.filter(|c| u.can_see_client(*c)).ok_or(ApiError::NotFound("site"))
}

pub fn client(u: &User, client_id: Uuid) -> ApiResult<()> {
    if u.can_see_client(client_id) { Ok(()) } else { Err(ApiError::NotFound("client")) }
}
