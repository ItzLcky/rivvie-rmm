//! SLA engine: response, update and resolution deadlines in business time.
//!
//! A ticket's policy is its client's (or the default one); the policy's targets for the
//! ticket's priority are minutes of business time on the policy's calendar (opening hours in a
//! time zone, minus holidays; no calendar means around the clock). Deadlines are stored on the
//! ticket so lists can sort and filter on them, and [`refresh`] recomputes them whenever an
//! input changes (priority, client, a pause ending, a public reply).
//!
//! The clock pauses while a ticket waits on the client or sits resolved: the business time spent
//! paused (`sla_paused_secs`) pushes every deadline back. [`sweep`] warns at 75% of a target and
//! again on a breach, on the policy's notification channels and to the assignee.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{DateTime, Datelike, Duration, NaiveDate, TimeZone, Utc};
use chrono_tz::Tz;
use serde_json::{Value, json};
use sqlx::PgConnection;
use tracing::warn;
use uuid::Uuid;

use crate::state::AppState;
use crate::tickets::{self, Author};

/// Status categories that stop the clock.
pub const PAUSED: &[&str] = &["waiting_client", "resolved", "closed"];
/// The three targets, in the order they're reported.
pub const TARGETS: &[&str] = &["respond", "update", "resolve"];

/// Opening hours: per weekday (Monday first), `[start, end)` in minutes from local midnight.
pub type Hours = [Vec<(u32, u32)>; 7];

#[derive(Clone, Debug)]
pub struct Calendar {
    tz: Tz,
    hours: Hours,
    holidays: HashSet<NaiveDate>,
}

impl Calendar {
    pub fn new(tz: Tz, hours: Hours, holidays: HashSet<NaiveDate>) -> Self {
        Calendar { tz, hours, holidays }
    }

    /// Around the clock, every day.
    pub fn always() -> Self {
        Calendar { tz: Tz::UTC, hours: std::array::from_fn(|_| vec![(0, 1440)]), holidays: HashSet::new() }
    }

    /// Checks and normalises the stored form: 7 lists of `[start, end]` minute pairs.
    pub fn parse_hours(v: &Value) -> Result<Hours, String> {
        let days = v.as_array().filter(|d| d.len() == 7).ok_or("hours must list the 7 weekdays, Monday first")?;
        let mut out: Hours = Default::default();
        let mut total = 0;
        for (i, day) in days.iter().enumerate() {
            let ranges = day.as_array().ok_or("each weekday is a list of [start, end] minute pairs")?;
            let mut list: Vec<(u32, u32)> = vec![];
            for r in ranges {
                let pair = r.as_array().filter(|p| p.len() == 2).ok_or("each range is [start, end] in minutes")?;
                let (Some(s), Some(e)) = (pair[0].as_u64(), pair[1].as_u64()) else { return Err("minutes must be whole numbers".into()) };
                if s >= e || e > 1440 {
                    return Err("each range must start before it ends, within the day (0-1440)".into());
                }
                list.push((s as u32, e as u32));
            }
            list.sort_unstable();
            if list.windows(2).any(|w| w[1].0 < w[0].1) {
                return Err("opening hours on a day must not overlap".into());
            }
            total += list.len();
            out[i] = list;
        }
        if total == 0 {
            return Err("open at least one day".into());
        }
        Ok(out)
    }

    pub fn hours_json(hours: &Hours) -> Value {
        Value::Array(hours.iter().map(|d| Value::Array(d.iter().map(|(s, e)| json!([s, e])).collect())).collect())
    }

    /// Local `minute` on `day` as an instant. A time that doesn't exist (spring forward) moves
    /// to the first one that does; one that exists twice (fall back) is the earlier.
    fn at(&self, day: NaiveDate, minute: u32) -> DateTime<Utc> {
        let naive = if minute >= 1440 {
            day.succ_opt().unwrap_or(day).and_hms_opt(0, 0, 0)
        } else {
            day.and_hms_opt(minute / 60, minute % 60, 0)
        }
        .expect("valid time");
        let mut probe = naive;
        for _ in 0..8 {
            if let Some(t) = self.tz.from_local_datetime(&probe).earliest() {
                return t.with_timezone(&Utc);
            }
            probe += Duration::minutes(30);
        }
        Utc.from_utc_datetime(&naive)
    }

    /// The day's open windows as instants (none on a holiday).
    fn windows(&self, day: NaiveDate) -> Vec<(DateTime<Utc>, DateTime<Utc>)> {
        if self.holidays.contains(&day) {
            return vec![];
        }
        self.hours[day.weekday().num_days_from_monday() as usize].iter().map(|(s, e)| (self.at(day, *s), self.at(day, *e))).collect()
    }

    /// The instant `secs` of business time after `start`.
    pub fn add(&self, start: DateTime<Utc>, secs: i64) -> DateTime<Utc> {
        if secs <= 0 {
            return start;
        }
        let mut left = secs;
        // From the day before, in case a window that started yesterday (local) is still open.
        let mut day = start.with_timezone(&self.tz).date_naive().pred_opt().unwrap_or(NaiveDate::MIN);
        for _ in 0..(366 * 5) {
            for (a, b) in self.windows(day) {
                let a = a.max(start);
                if b <= a {
                    continue;
                }
                let len = (b - a).num_seconds();
                if left <= len {
                    return a + Duration::seconds(left);
                }
                left -= len;
            }
            day = match day.succ_opt() {
                Some(d) => d,
                None => break,
            };
        }
        // Holidays every day for five years: count wall-clock time rather than never.
        start + Duration::seconds(secs)
    }

    /// When the opening hours `at` falls in end (across back-to-back windows), or `None` when
    /// closed at `at`.
    pub fn open_until(&self, at: DateTime<Utc>) -> Option<DateTime<Utc>> {
        let mut t = at;
        let mut open = false;
        for _ in 0..400 {
            let day = t.with_timezone(&self.tz).date_naive();
            let mut moved = false;
            for d in [day.pred_opt().unwrap_or(day), day] {
                for (a, b) in self.windows(d) {
                    if a <= t && t < b {
                        t = b;
                        open = true;
                        moved = true;
                    }
                }
            }
            if !moved {
                break;
            }
        }
        open.then_some(t)
    }

    /// Business seconds in `[a, b)`.
    pub fn between(&self, a: DateTime<Utc>, b: DateTime<Utc>) -> i64 {
        if b <= a {
            return 0;
        }
        let mut total = 0;
        let mut day = a.with_timezone(&self.tz).date_naive().pred_opt().unwrap_or(NaiveDate::MIN);
        let last = b.with_timezone(&self.tz).date_naive();
        let mut n = 0;
        while day <= last && n < 366 * 20 {
            for (s, e) in self.windows(day) {
                let (s, e) = (s.max(a), e.min(b));
                if e > s {
                    total += (e - s).num_seconds();
                }
            }
            day = match day.succ_opt() {
                Some(d) => d,
                None => break,
            };
            n += 1;
        }
        total
    }
}

/// The policy that applies to a client's tickets: an active contract's, else the client's own,
/// else the default.
pub async fn policy_for(db: &mut PgConnection, client_id: Option<Uuid>) -> sqlx::Result<Option<Uuid>> {
    sqlx::query_scalar(
        "SELECT coalesce(
            (SELECT ct.sla_policy_id FROM contracts ct WHERE ct.client_id = $1 AND ct.sla_policy_id IS NOT NULL
                AND ct.start_date <= current_date AND (ct.end_date IS NULL OR ct.end_date >= current_date)
              ORDER BY ct.start_date DESC LIMIT 1),
            (SELECT c.sla_policy_id FROM clients c WHERE c.id = $1),
            (SELECT id FROM sla_policies WHERE is_default))",
    )
    .bind(client_id)
    .fetch_one(&mut *db)
    .await
}

pub async fn calendar_of(db: &mut PgConnection, policy_id: Uuid) -> sqlx::Result<Calendar> {
    let row: Option<(Uuid, String, Value)> = sqlx::query_as(
        "SELECT c.id, c.timezone, c.hours FROM sla_policies p JOIN business_calendars c ON c.id = p.calendar_id WHERE p.id = $1",
    )
    .bind(policy_id)
    .fetch_optional(&mut *db)
    .await?;
    let Some((cal_id, tz, hours)) = row else { return Ok(Calendar::always()) };
    let holidays: Vec<NaiveDate> =
        sqlx::query_scalar("SELECT day FROM holidays WHERE calendar_id = $1").bind(cal_id).fetch_all(&mut *db).await?;
    let tz: Tz = tz.parse().unwrap_or(Tz::UTC);
    let hours = Calendar::parse_hours(&hours).unwrap_or_else(|_| Calendar::always().hours);
    Ok(Calendar::new(tz, hours, holidays.into_iter().collect()))
}

#[derive(sqlx::FromRow)]
struct Clock {
    created_at: DateTime<Utc>,
    priority: i16,
    client_id: Option<Uuid>,
    first_response_at: Option<DateTime<Utc>>,
    resolved_at: Option<DateTime<Utc>>,
    sla_paused_secs: i64,
    sla_update_from: Option<DateTime<Utc>>,
    sla_update_paused_base: i64,
    sla_warned: Vec<String>,
    sla_breached: Vec<String>,
    respond_by: Option<DateTime<Utc>>,
    respond_warn_at: Option<DateTime<Utc>>,
    update_by: Option<DateTime<Utc>>,
    update_warn_at: Option<DateTime<Utc>>,
    resolve_by: Option<DateTime<Utc>>,
    resolve_warn_at: Option<DateTime<Utc>>,
}

/// Deadline and 75% point for `mins` of business time from `from`, after `paused` seconds of pause.
fn deadline(cal: &Calendar, from: DateTime<Utc>, mins: Option<i32>, paused: i64) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
    match mins {
        Some(m) if m > 0 => {
            let secs = m as i64 * 60;
            (Some(cal.add(from, secs + paused)), Some(cal.add(from, secs * 3 / 4 + paused)))
        }
        _ => (None, None),
    }
}

/// Recomputes the ticket's policy and deadlines from its current state. A deadline whose clock
/// has stopped (responded, resolved) keeps its value, for attainment reporting.
pub async fn refresh(db: &mut PgConnection, ticket_id: Uuid) -> sqlx::Result<()> {
    let Some(t): Option<Clock> = sqlx::query_as(
        "SELECT created_at, priority, client_id, first_response_at, resolved_at, sla_paused_secs, sla_update_from,
                sla_update_paused_base, sla_warned, sla_breached, respond_by, respond_warn_at, update_by, update_warn_at,
                resolve_by, resolve_warn_at
           FROM tickets WHERE id = $1",
    )
    .bind(ticket_id)
    .fetch_optional(&mut *db)
    .await?
    else {
        return Ok(());
    };
    let policy = policy_for(db, t.client_id).await?;
    let targets: Option<(Option<i32>, Option<i32>, Option<i32>)> = match policy {
        Some(p) => sqlx::query_as("SELECT respond_mins, update_mins, resolve_mins FROM sla_targets WHERE policy_id = $1 AND priority = $2")
            .bind(p)
            .bind(t.priority)
            .fetch_optional(&mut *db)
            .await?,
        None => None,
    };
    let Some((respond, update, resolve)) = targets else {
        sqlx::query(
            "UPDATE tickets SET sla_policy_id = $2, respond_by = NULL, respond_warn_at = NULL, update_by = NULL, update_warn_at = NULL,
                    resolve_by = NULL, resolve_warn_at = NULL, sla_warned = '{}', sla_breached = '{}'
              WHERE id = $1",
        )
        .bind(ticket_id)
        .bind(policy)
        .execute(&mut *db)
        .await?;
        return Ok(());
    };
    let cal = calendar_of(db, policy.expect("targets imply a policy")).await?;
    let paused = t.sla_paused_secs;
    let (respond_by, respond_warn) =
        if t.first_response_at.is_none() { deadline(&cal, t.created_at, respond, paused) } else { (t.respond_by, t.respond_warn_at) };
    let (update_by, update_warn) = match (t.first_response_at, t.resolved_at) {
        (Some(first), None) => deadline(&cal, t.sla_update_from.unwrap_or(first), update, paused - t.sla_update_paused_base),
        (Some(_), Some(_)) => (t.update_by, t.update_warn_at),
        (None, _) => (None, None),
    };
    let (resolve_by, resolve_warn) =
        if t.resolved_at.is_none() { deadline(&cal, t.created_at, resolve, paused) } else { (t.resolve_by, t.resolve_warn_at) };

    // A deadline that moved into the future (a later priority, a pause, a new reply) can be
    // warned about and breached again.
    let now = Utc::now();
    let future = |kind: &str| -> (bool, bool) {
        let (by, warn) = match kind {
            "respond" => (respond_by, respond_warn),
            "update" => (update_by, update_warn),
            _ => (resolve_by, resolve_warn),
        };
        (by.is_none_or(|d| d > now), warn.is_none_or(|d| d > now))
    };
    let breached: Vec<String> = t.sla_breached.iter().filter(|k| !future(k).0).cloned().collect();
    let warned: Vec<String> = t.sla_warned.iter().filter(|k| !future(k).1).cloned().collect();
    sqlx::query(
        "UPDATE tickets SET sla_policy_id = $2, respond_by = $3, respond_warn_at = $4, update_by = $5, update_warn_at = $6,
                resolve_by = $7, resolve_warn_at = $8, sla_warned = $9, sla_breached = $10
          WHERE id = $1",
    )
    .bind(ticket_id)
    .bind(policy)
    .bind(respond_by)
    .bind(respond_warn)
    .bind(update_by)
    .bind(update_warn)
    .bind(resolve_by)
    .bind(resolve_warn)
    .bind(&warned)
    .bind(&breached)
    .execute(&mut *db)
    .await?;
    Ok(())
}

/// A status change: start or end a pause.
pub async fn status_changed(db: &mut PgConnection, ticket_id: Uuid, from: &str, to: &str) -> sqlx::Result<()> {
    let (was, is) = (PAUSED.contains(&from), PAUSED.contains(&to));
    if !was && is {
        sqlx::query("UPDATE tickets SET sla_paused_at = coalesce(sla_paused_at, now()) WHERE id = $1").bind(ticket_id).execute(&mut *db).await?;
    } else if was && !is {
        let (paused_at, policy): (Option<DateTime<Utc>>, Option<Uuid>) =
            sqlx::query_as("SELECT sla_paused_at, sla_policy_id FROM tickets WHERE id = $1").bind(ticket_id).fetch_one(&mut *db).await?;
        if let Some(at) = paused_at {
            let cal = match policy {
                Some(p) => calendar_of(db, p).await?,
                None => Calendar::always(),
            };
            let secs = cal.between(at, Utc::now());
            sqlx::query("UPDATE tickets SET sla_paused_secs = sla_paused_secs + $2, sla_paused_at = NULL WHERE id = $1")
                .bind(ticket_id)
                .bind(secs)
                .execute(&mut *db)
                .await?;
        }
        refresh(db, ticket_id).await?;
    }
    Ok(())
}

/// A technician's public reply: the first response, and a restart of the update clock.
pub async fn replied(db: &mut PgConnection, ticket_id: Uuid) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE tickets SET first_response_at = coalesce(first_response_at, now()), sla_update_from = now(),
                sla_update_paused_base = sla_paused_secs
          WHERE id = $1",
    )
    .bind(ticket_id)
    .execute(&mut *db)
    .await?;
    refresh(db, ticket_id).await
}

// ---------------------------------------------------------------------------
// Warnings and breaches
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct Due {
    id: Uuid,
    sla_policy_id: Uuid,
    first_response_at: Option<DateTime<Utc>>,
    respond_by: Option<DateTime<Utc>>,
    update_by: Option<DateTime<Utc>>,
    resolve_by: Option<DateTime<Utc>>,
    respond_warn_at: Option<DateTime<Utc>>,
    update_warn_at: Option<DateTime<Utc>>,
    resolve_warn_at: Option<DateTime<Utc>>,
    sla_warned: Vec<String>,
    sla_breached: Vec<String>,
    assignee_id: Option<Uuid>,
}

pub fn target_label(kind: &str) -> &'static str {
    match kind {
        "respond" => "First response",
        "update" => "Next update",
        _ => "Resolution",
    }
}

/// What's newly due on a ticket: `(target, breached)` pairs.
fn due_events(d: &Due, now: DateTime<Utc>) -> Vec<(&'static str, bool)> {
    let mut out = vec![];
    for kind in TARGETS {
        let running = match *kind {
            "respond" => d.first_response_at.is_none(),
            "update" => d.first_response_at.is_some(),
            _ => true,
        };
        if !running {
            continue;
        }
        let (by, warn) = match *kind {
            "respond" => (d.respond_by, d.respond_warn_at),
            "update" => (d.update_by, d.update_warn_at),
            _ => (d.resolve_by, d.resolve_warn_at),
        };
        let has = |list: &[String]| list.iter().any(|k| k == kind);
        if by.is_some_and(|b| b <= now) && !has(&d.sla_breached) {
            out.push((*kind, true));
        } else if warn.is_some_and(|w| w <= now) && !has(&d.sla_warned) && !has(&d.sla_breached) {
            out.push((*kind, false));
        }
    }
    out
}

/// Sends what's due. Returns how many warnings and breaches it recorded.
pub async fn sweep(st: &AppState) -> anyhow::Result<usize> {
    let rows: Vec<Due> = sqlx::query_as(
        "SELECT t.id, t.sla_policy_id, t.first_response_at, t.respond_by, t.update_by, t.resolve_by, t.respond_warn_at,
                t.update_warn_at, t.resolve_warn_at, t.sla_warned, t.sla_breached, t.assignee_id
           FROM tickets t JOIN board_statuses s ON s.id = t.status_id
          WHERE t.sla_policy_id IS NOT NULL AND t.sla_paused_at IS NULL AND t.merged_into IS NULL
            AND s.category NOT IN ('resolved', 'closed', 'waiting_client')
            AND ((t.first_response_at IS NULL AND (t.respond_warn_at <= now() AND NOT 'respond' = ANY(t.sla_warned)
                                                   OR t.respond_by <= now() AND NOT 'respond' = ANY(t.sla_breached)))
              OR (t.first_response_at IS NOT NULL AND (t.update_warn_at <= now() AND NOT 'update' = ANY(t.sla_warned)
                                                   OR t.update_by <= now() AND NOT 'update' = ANY(t.sla_breached)))
              OR t.resolve_warn_at <= now() AND NOT 'resolve' = ANY(t.sla_warned)
              OR t.resolve_by <= now() AND NOT 'resolve' = ANY(t.sla_breached))
          LIMIT 200",
    )
    .fetch_all(&st.db)
    .await?;
    let now = Utc::now();
    let mut sent = 0;
    for d in rows {
        let events = due_events(&d, now);
        if events.is_empty() {
            continue;
        }
        let mut tx = st.db.begin().await?;
        let author = Author::system("SLA");
        for (kind, breached) in &events {
            let by = match *kind {
                "respond" => d.respond_by,
                "update" => d.update_by,
                _ => d.resolve_by,
            };
            let due = by.map(|b| b.format("%Y-%m-%d %H:%M UTC").to_string()).unwrap_or_default();
            let body = if *breached {
                format!("{} target missed (was due {due}).", target_label(kind))
            } else {
                format!("{} target 75% used: due {due}.", target_label(kind))
            };
            // A breach counts as warned too, so it never warns afterwards.
            let sql = if *breached {
                "UPDATE tickets SET sla_breached = array_append(sla_breached, $2),
                        sla_warned = CASE WHEN $2 = ANY(sla_warned) THEN sla_warned ELSE array_append(sla_warned, $2) END,
                        sla_breached_at = coalesce(sla_breached_at, now())
                  WHERE id = $1 AND NOT $2 = ANY(sla_breached)"
            } else {
                "UPDATE tickets SET sla_warned = array_append(sla_warned, $2) WHERE id = $1 AND NOT $2 = ANY(sla_warned)"
            };
            let n = sqlx::query(sql).bind(d.id).bind(*kind).execute(&mut *tx).await?.rows_affected();
            if n == 0 {
                continue;
            }
            let event = if *breached { "sla_breach" } else { "sla_warning" };
            tickets::add_event(&mut tx, d.id, "sla", false, &author, &body, json!({ "target": kind, "event": event, "due": by })).await?;
            sqlx::query(
                "INSERT INTO notifications (channel_id, ticket_id, event, data)
                 SELECT c.id, $1, $2, $3 FROM notification_channels c JOIN sla_policies p ON c.id = ANY(p.channel_ids)
                  WHERE c.enabled AND p.id = $4",
            )
            .bind(d.id)
            .bind(event)
            .bind(json!({ "target": kind, "due": by }))
            .bind(d.sla_policy_id)
            .execute(&mut *tx)
            .await?;
            sent += 1;
        }
        tx.commit().await?;
        st.notify_wake.notify_one();
        let tell_assignee: bool = sqlx::query_scalar("SELECT notify_assignee FROM sla_policies WHERE id = $1")
            .bind(d.sla_policy_id)
            .fetch_optional(&st.db)
            .await?
            .unwrap_or(false);
        if let Some(a) = d.assignee_id.filter(|_| tell_assignee)
            && let Err(e) = crate::email::queue_sla(st, d.id, a, &events).await
        {
            warn!(ticket = %d.id, "emailing the assignee about the SLA: {e:#}");
        }
        tickets::announce(st, d.id).await;
    }
    Ok(sent)
}

/// Every 30 seconds: SLA warnings and breaches, then satisfaction surveys that are due.
pub async fn run(st: Arc<AppState>) {
    // RMM_SLA_SWEEP_SECS is for tests.
    let secs = std::env::var("RMM_SLA_SWEEP_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(30u64).max(1);
    let mut tick = tokio::time::interval(StdDuration::from_secs(secs));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if let Err(e) = sweep(&st).await {
            warn!("SLA sweep: {e:#}");
        }
        if let Err(e) = crate::csat::send_due(&st).await {
            warn!("satisfaction surveys: {e:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn office(tz: Tz) -> Calendar {
        // Monday to Friday, 09:00-17:00.
        let mut hours: Hours = Default::default();
        for d in hours.iter_mut().take(5) {
            *d = vec![(540, 1020)];
        }
        Calendar::new(tz, hours, HashSet::new())
    }

    #[test]
    fn around_the_clock() {
        let c = Calendar::always();
        let t = utc("2026-11-13T23:30:00Z");
        assert_eq!(c.add(t, 3600), utc("2026-11-14T00:30:00Z"));
        assert_eq!(c.between(t, utc("2026-11-15T23:30:00Z")), 2 * 86400);
    }

    #[test]
    fn open_until_the_hours_end() {
        let c = office(Tz::UTC);
        assert_eq!(c.open_until(utc("2026-11-13T10:00:00Z")), Some(utc("2026-11-13T17:00:00Z")));
        assert_eq!(c.open_until(utc("2026-11-13T17:00:00Z")), None, "closed at closing time");
        assert_eq!(c.open_until(utc("2026-11-14T10:00:00Z")), None, "Saturday");
        assert_eq!(Calendar::always().open_until(utc("2026-11-13T10:00:00Z")).map(|t| t > utc("2027-01-01T00:00:00Z")), Some(true));
    }

    #[test]
    fn office_hours() {
        let c = office(Tz::UTC);
        // Friday 16:00 + 2 h of business time = Monday 10:00.
        let fri = utc("2026-11-13T16:00:00Z");
        assert_eq!(c.add(fri, 7200), utc("2026-11-16T10:00:00Z"));
        // Saturday morning starts counting Monday 09:00.
        assert_eq!(c.add(utc("2026-11-14T08:00:00Z"), 60), utc("2026-11-16T09:01:00Z"));
        // Exactly at closing: the next opening.
        assert_eq!(c.add(utc("2026-11-16T17:00:00Z"), 1), utc("2026-11-17T09:00:01Z"));
        assert_eq!(c.between(fri, utc("2026-11-16T10:00:00Z")), 7200);
        assert_eq!(c.between(utc("2026-11-14T00:00:00Z"), utc("2026-11-15T23:00:00Z")), 0);
    }

    #[test]
    fn holidays_and_time_zones() {
        let mut c = office(chrono_tz::America::New_York);
        c.holidays.insert(NaiveDate::from_ymd_opt(2026, 11, 26).unwrap()); // Thanksgiving, a Thursday
        // Wednesday 16:00 New York (21:00 UTC) + 2 h → Friday 10:00 New York (15:00 UTC).
        assert_eq!(c.add(utc("2026-11-25T21:00:00Z"), 7200), utc("2026-11-27T15:00:00Z"));
        // Across the end of daylight saving time (1 November 2026): Friday 16:00 EDT + 2 h is
        // Monday 10:00 EST.
        assert_eq!(c.add(utc("2026-10-30T20:00:00Z"), 7200), utc("2026-11-02T15:00:00Z"));
    }

    #[test]
    fn parses_and_checks_hours() {
        let ok = json!([[[540, 720], [780, 1020]], [], [], [], [], [], []]);
        assert_eq!(Calendar::parse_hours(&ok).unwrap()[0], vec![(540, 720), (780, 1020)]);
        for bad in [json!([[], [], [], [], [], [], []]), json!([[[600, 500]], [], [], [], [], [], []]), json!([[[0, 600], [500, 700]], [], [], [], [], [], []]), json!([[]])] {
            assert!(Calendar::parse_hours(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn what_is_due() {
        let now = utc("2026-11-12T12:00:00Z");
        let past = Some(utc("2026-11-12T11:00:00Z"));
        let future = Some(utc("2026-11-12T13:00:00Z"));
        let d = Due {
            id: Uuid::nil(),
            sla_policy_id: Uuid::nil(),
            first_response_at: None,
            respond_by: future,
            respond_warn_at: past,
            update_by: past,
            update_warn_at: past,
            resolve_by: past,
            resolve_warn_at: past,
            sla_warned: vec![],
            sla_breached: vec![],
            assignee_id: None,
        };
        // Not responded yet: the update clock isn't running.
        assert_eq!(due_events(&d, now), vec![("respond", false), ("resolve", true)]);
        let d = Due { sla_warned: vec!["respond".into()], sla_breached: vec!["resolve".into()], ..d };
        assert!(due_events(&d, now).is_empty());
    }
}
