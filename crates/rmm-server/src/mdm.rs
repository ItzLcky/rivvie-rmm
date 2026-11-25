//! Intune managed devices, read-only, through a client's Entra connection
//! (docs/design/mdm.md). Read by [`crate::identity`]'s sync when the source has
//! `sync_devices`; nothing is ever sent to Intune.
//!
//! Each device is matched to the client's agent on the same machine. Agents don't report a
//! serial number yet, so the match is by host name (the part before the first dot, ignoring
//! case); see the design record.

use sqlx::PgPool;

use crate::entra::MdmDevice;
use crate::identity::Source;

/// Replaces the source's devices with `devices` and matches them to agents.
pub async fn store(db: &PgPool, s: &Source, devices: &[MdmDevice]) -> sqlx::Result<()> {
    let mut tx = db.begin().await?;
    let clip = |v: &str, n: usize| v.chars().take(n).collect::<String>();
    for d in devices {
        sqlx::query(
            "INSERT INTO mdm_devices (id, source_id, external_id, name, user_upn, os, os_version, compliance, encrypted, ownership,
                                      serial, model, manufacturer, enrolled_at, last_sync_at)
             VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
             ON CONFLICT (source_id, external_id) DO UPDATE SET name = $3, user_upn = $4, os = $5, os_version = $6, compliance = $7,
                    encrypted = $8, ownership = $9, serial = $10, model = $11, manufacturer = $12, enrolled_at = $13, last_sync_at = $14,
                    synced_at = now()",
        )
        .bind(s.id)
        .bind(&d.id)
        .bind(clip(&d.name, 256))
        .bind(clip(&d.user_upn, 256))
        .bind(clip(&d.os, 100))
        .bind(clip(&d.os_version, 100))
        .bind(&d.compliance)
        .bind(d.encrypted)
        .bind(&d.ownership)
        .bind(clip(&d.serial, 100))
        .bind(clip(&d.model, 200))
        .bind(clip(&d.manufacturer, 200))
        .bind(d.enrolled_at)
        .bind(d.last_sync_at)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("DELETE FROM mdm_devices WHERE source_id = $1 AND NOT (external_id = ANY($2))")
        .bind(s.id)
        .bind(devices.iter().map(|d| d.id.clone()).collect::<Vec<_>>())
        .execute(&mut *tx)
        .await?;
    match_agents(&mut tx, s).await?;
    tx.commit().await
}

/// Links each device to the client's agent with the same short host name (the most recently
/// seen one if several).
async fn match_agents(db: &mut sqlx::PgConnection, s: &Source) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE mdm_devices d SET agent_id = (
                SELECT a.id FROM agents a JOIN sites si ON si.id = a.site_id
                 WHERE si.client_id = $2 AND d.name <> ''
                   AND lower(split_part(a.hostname, '.', 1)) = lower(split_part(d.name, '.', 1))
                 ORDER BY a.last_seen_at DESC NULLS LAST, a.id LIMIT 1)
          WHERE d.source_id = $1",
    )
    .bind(s.id)
    .bind(s.client_id)
    .execute(db)
    .await?;
    Ok(())
}
