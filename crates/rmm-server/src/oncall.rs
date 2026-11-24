//! On-call schedules, escalation and paging (docs/design/oncall.md).
//!
//! Paging is a notification channel kind: an alert item whose channels include an `oncall`
//! channel opens a *page* when the outbox delivers to it ([`trigger_alert`]). A page walks its
//! escalation policy one step at a time; each step notifies whoever its targets resolve to
//! (the person on call on a schedule, a named user, or another channel) by the methods they
//! chose, and the next step follows after the step's delay unless someone acknowledges.
//!
//! [`run`] ticks every 15 seconds (sooner with `RMM_ONCALL_MINUTE_SECS`, which also sets how
//! long a "minute" of delay is, for tests): it starts held pages, escalates due ones, follows
//! the alerts and tickets pages belong to, pages new P1 tickets when Company settings name a
//! policy for them, and sends due deliveries with [`crate::notify::backoff`] on failure.

use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use chrono::{DateTime, Datelike, Duration as Dur, NaiveDate, TimeZone, Timelike, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{info, warn};
use uuid::Uuid;

use crate::hub::Event;
use crate::state::AppState;

const BATCH: i64 = 20;
const MAX_ATTEMPTS: i32 = 5;
/// The longest text message we send; Twilio splits anything over 160 GSM characters anyway.
pub const SMS_MAX: usize = 300;

static WAKE: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// Wakes the worker (something was paged or acknowledged).
pub fn wake() {
    WAKE.notify_one();
}

/// Seconds in a "minute" of escalation and contact-rule delay: 60, or `RMM_ONCALL_MINUTE_SECS`.
pub fn minute_secs() -> i64 {
    static V: OnceLock<i64> = OnceLock::new();
    *V.get_or_init(|| std::env::var("RMM_ONCALL_MINUTE_SECS").ok().and_then(|v| v.trim().parse().ok()).filter(|v| *v > 0).unwrap_or(60))
}

fn minutes(m: i64) -> Dur {
    Dur::seconds(m * minute_secs())
}

// ---------------------------------------------------------------------------
// Rotation maths (pure)
// ---------------------------------------------------------------------------

/// A time window a layer is restricted to, in the schedule's zone. `days` are weekdays,
/// Monday = 0; `start`/`end` minutes from midnight. `end <= start` runs past midnight into
/// the next day (the day listed is the one it starts on).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Window {
    pub days: Vec<u8>,
    pub start: u32,
    pub end: u32,
}

impl Window {
    pub fn validate(&self) -> Result<(), String> {
        if self.days.is_empty() || self.days.iter().any(|d| *d > 6) {
            return Err("each restriction needs one or more weekdays (0 = Monday … 6 = Sunday)".into());
        }
        if self.start >= 1440 || self.end > 1440 || self.start == self.end {
            return Err("a restriction runs from a start to a different end minute, within the day".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Layer {
    pub id: Uuid,
    pub position: i32,
    pub name: String,
    pub user_ids: Vec<Uuid>,
    pub start_at: DateTime<Utc>,
    pub shift_hours: i32,
    pub restrict: Vec<Window>,
}

#[derive(Clone, Debug)]
pub struct Override {
    pub id: Uuid,
    pub user_id: Uuid,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
}

/// A local wall-clock time as an instant. A time that doesn't exist (spring forward) moves to
/// the first one that does; one that exists twice (fall back) is the earlier.
fn local(tz: Tz, day: NaiveDate, minute: u32) -> DateTime<Utc> {
    let naive = if minute >= 1440 { day.succ_opt().unwrap_or(day).and_hms_opt(0, 0, 0) } else { day.and_hms_opt(minute / 60, minute % 60, 0) }
        .expect("valid time");
    let mut probe = naive;
    for _ in 0..8 {
        if let Some(t) = tz.from_local_datetime(&probe).earliest() {
            return t.with_timezone(&Utc);
        }
        probe += Dur::minutes(30);
    }
    Utc.from_utc_datetime(&naive)
}

impl Layer {
    /// Shift `n` starts here. Whole-day shifts hand over at the start's local time each time,
    /// whatever the UTC offset does in between; other lengths are exact hours.
    fn shift_start(&self, tz: Tz, n: i64) -> DateTime<Utc> {
        if self.shift_hours % 24 == 0 {
            let l = self.start_at.with_timezone(&tz);
            let minute = l.hour() * 60 + l.minute();
            let day = l.date_naive() + Dur::days(n * i64::from(self.shift_hours / 24));
            local(tz, day, minute)
        } else {
            self.start_at + Dur::hours(n * i64::from(self.shift_hours))
        }
    }

    /// The shift covering `at`: its number and bounds. `None` before the rotation starts.
    pub fn shift_at(&self, tz: Tz, at: DateTime<Utc>) -> Option<(i64, DateTime<Utc>, DateTime<Utc>)> {
        if at < self.start_at || self.shift_hours <= 0 {
            return None;
        }
        // An estimate from elapsed hours, corrected for DST drift.
        let mut n = (at - self.start_at).num_seconds() / (i64::from(self.shift_hours) * 3600);
        while n > 0 && self.shift_start(tz, n) > at {
            n -= 1;
        }
        while self.shift_start(tz, n + 1) <= at {
            n += 1;
        }
        Some((n, self.shift_start(tz, n), self.shift_start(tz, n + 1)))
    }

    /// Whether `at` falls in one of the restriction windows (always, without any).
    pub fn allows(&self, tz: Tz, at: DateTime<Utc>) -> bool {
        if self.restrict.is_empty() {
            return true;
        }
        let l = at.with_timezone(&tz);
        let minute = l.hour() * 60 + l.minute();
        let wd = l.weekday().num_days_from_monday() as u8;
        let prev = (wd + 6) % 7;
        self.restrict.iter().any(|w| {
            if w.start < w.end {
                w.days.contains(&wd) && (w.start..w.end).contains(&minute)
            } else {
                (w.days.contains(&wd) && minute >= w.start) || (w.days.contains(&prev) && minute < w.end)
            }
        })
    }

    /// Who this layer puts on at `at`.
    pub fn on_call(&self, tz: Tz, at: DateTime<Utc>) -> Option<Uuid> {
        if self.user_ids.is_empty() || !self.allows(tz, at) {
            return None;
        }
        let (n, _, _) = self.shift_at(tz, at)?;
        Some(self.user_ids[n.rem_euclid(self.user_ids.len() as i64) as usize])
    }
}

/// Where the person on call comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum Source {
    Override(Uuid),
    Layer(Uuid),
}

/// Who is on call at `at`: an override covering it (the last one listed wins), else the
/// highest-positioned layer that has someone on.
pub fn who_is_on_call(tz: Tz, layers: &[Layer], overrides: &[Override], at: DateTime<Utc>) -> Option<(Uuid, Source)> {
    if let Some(o) = overrides.iter().rev().find(|o| o.starts_at <= at && at < o.ends_at) {
        return Some((o.user_id, Source::Override(o.id)));
    }
    let mut sorted: Vec<&Layer> = layers.iter().collect();
    sorted.sort_by_key(|l| std::cmp::Reverse(l.position));
    sorted.into_iter().find_map(|l| l.on_call(tz, at).map(|u| (u, Source::Layer(l.id))))
}

/// A stretch of time with one person on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Segment {
    pub user_id: Uuid,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// Every instant in `[from, to)` where who is on could change.
fn boundaries(tz: Tz, layers: &[Layer], overrides: &[Override], from: DateTime<Utc>, to: DateTime<Utc>) -> Vec<DateTime<Utc>> {
    let mut out = BTreeSet::new();
    out.insert(from);
    for l in layers {
        let first = l.shift_at(tz, from).map(|(n, _, _)| n).unwrap_or(0);
        let mut n = first;
        for _ in 0..5000 {
            let s = l.shift_start(tz, n);
            if s >= to {
                break;
            }
            out.insert(s);
            n += 1;
        }
        let mut day = from.with_timezone(&tz).date_naive() - Dur::days(1);
        let last = to.with_timezone(&tz).date_naive();
        while day <= last {
            let wd = day.weekday().num_days_from_monday() as u8;
            for w in l.restrict.iter().filter(|w| w.days.contains(&wd)) {
                out.insert(local(tz, day, w.start));
                let end_day = if w.end <= w.start { day + Dur::days(1) } else { day };
                out.insert(local(tz, end_day, w.end));
            }
            day += Dur::days(1);
        }
    }
    for o in overrides {
        out.insert(o.starts_at);
        out.insert(o.ends_at);
    }
    out.into_iter().filter(|t| *t >= from && *t < to).collect()
}

/// Splits `[from, to)` into segments by `who`, merging neighbours with the same person and
/// leaving out the gaps where nobody is on.
fn segments(points: &[DateTime<Utc>], to: DateTime<Utc>, who: impl Fn(DateTime<Utc>) -> Option<Uuid>) -> Vec<Segment> {
    let mut out: Vec<Segment> = Vec::new();
    for (i, start) in points.iter().enumerate() {
        let end = points.get(i + 1).copied().unwrap_or(to);
        let Some(user_id) = who(*start) else { continue };
        match out.last_mut() {
            Some(last) if last.user_id == user_id && last.end == *start => last.end = end,
            _ => out.push(Segment { user_id, start: *start, end }),
        }
    }
    out
}

/// The final schedule over `[from, to)`.
pub fn final_shifts(tz: Tz, layers: &[Layer], overrides: &[Override], from: DateTime<Utc>, to: DateTime<Utc>) -> Vec<Segment> {
    let points = boundaries(tz, layers, overrides, from, to);
    segments(&points, to, |t| who_is_on_call(tz, layers, overrides, t).map(|w| w.0))
}

/// One layer's own rotation over `[from, to)` (before overrides and higher layers).
pub fn layer_shifts(tz: Tz, layer: &Layer, from: DateTime<Utc>, to: DateTime<Utc>) -> Vec<Segment> {
    let points = boundaries(tz, std::slice::from_ref(layer), &[], from, to);
    segments(&points, to, |t| layer.on_call(tz, t))
}

// ---------------------------------------------------------------------------
// Escalation state machine (pure)
// ---------------------------------------------------------------------------

/// After step `step` of round `round` went unacknowledged: the next `(step, round)`, or `None`
/// when the policy (and its repeats) are used up.
pub fn next_step(step: i32, round: i32, steps: i32, repeat: i32) -> Option<(i32, i32)> {
    if step + 1 < steps {
        Some((step + 1, round))
    } else if round < repeat && steps > 0 {
        Some((0, round + 1))
    } else {
        None
    }
}

/// A target of an escalation step.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    Schedule(Uuid),
    User(Uuid),
    Channel(Uuid),
}

impl Target {
    /// `{"schedule": id}`, `{"user": id}` or `{"channel": id}`.
    pub fn parse(v: &Value) -> Result<Target, String> {
        let o = v.as_object().filter(|o| o.len() == 1).ok_or("each target is {schedule}, {user} or {channel}")?;
        let (k, id) = o.iter().next().expect("one entry");
        let id: Uuid = id.as_str().and_then(|s| s.parse().ok()).ok_or_else(|| format!("{k}: not an id"))?;
        match k.as_str() {
            "schedule" => Ok(Target::Schedule(id)),
            "user" => Ok(Target::User(id)),
            "channel" => Ok(Target::Channel(id)),
            other => Err(format!("unknown target {other}")),
        }
    }

    pub fn to_json(&self) -> Value {
        match self {
            Target::Schedule(id) => json!({ "schedule": id }),
            Target::User(id) => json!({ "user": id }),
            Target::Channel(id) => json!({ "channel": id }),
        }
    }
}

// ---------------------------------------------------------------------------
// Text messages
// ---------------------------------------------------------------------------

/// The text of a page: `[Brand] CRITICAL: <title>` cut to fit, then the link. At most
/// [`SMS_MAX`] characters.
pub fn sms_text(brand: &str, severity: &str, headline: &str, link: &str) -> String {
    let lead = format!("[{brand}] {}: ", severity.to_uppercase());
    let tail = format!(" {link}");
    let room = SMS_MAX.saturating_sub(lead.chars().count() + tail.chars().count());
    let mut head: String = headline.split_whitespace().collect::<Vec<_>>().join(" ");
    if head.chars().count() > room {
        head = head.chars().take(room.saturating_sub(1)).collect::<String>() + "…";
    }
    let text = format!("{lead}{head}{tail}");
    text.chars().take(SMS_MAX).collect()
}

/// An E.164 number: `+` and 7-15 digits, no leading zero.
pub fn valid_e164(s: &str) -> bool {
    let Some(d) = s.strip_prefix('+') else { return false };
    (7..=15).contains(&d.len()) && d.bytes().all(|b| b.is_ascii_digit()) && !d.starts_with('0')
}

/// Sends one text message through the configured provider (Twilio's Messages API). Returns
/// the provider's message id.
pub async fn send_sms(st: &AppState, to: &str, body: &str) -> Result<String, String> {
    let c = st.company();
    if c.sms_account_sid.trim().is_empty() || c.sms_from.trim().is_empty() {
        return Err("no SMS provider: set one up under Company settings → Notifications".into());
    }
    let token = match c.sms_token_enc.as_deref() {
        Some(stored) => crate::crypto::load(st.cfg.data_key.as_ref(), stored, c.sms_token_sealed)
            .map(|p| String::from_utf8_lossy(&p).into_owned())
            .ok_or("the SMS auth token can't be read: RMM_DATA_KEY is missing or changed")?,
        None => return Err("the SMS auth token is not set".into()),
    };
    let url = format!("{}/2010-04-01/Accounts/{}/Messages.json", c.sms_base_url.trim_end_matches('/'), c.sms_account_sid.trim());
    let res = st
        .http
        .post(url)
        .basic_auth(c.sms_account_sid.trim(), Some(token))
        .form(&[("To", to), ("From", c.sms_from.trim()), ("Body", body)])
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    let status = res.status();
    let v: Value = res.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let msg = v["message"].as_str().unwrap_or("");
        return Err(format!("HTTP {status}: {}", msg.chars().take(300).collect::<String>()));
    }
    Ok(v["sid"].as_str().unwrap_or_default().to_string())
}

// ---------------------------------------------------------------------------
// Loading schedules
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct LayerRow {
    id: Uuid,
    position: i32,
    name: String,
    user_ids: Vec<Uuid>,
    start_at: DateTime<Utc>,
    shift_hours: i32,
    restrict: Value,
}

pub struct Schedule {
    pub id: Uuid,
    pub name: String,
    pub tz: Tz,
    pub layers: Vec<Layer>,
    pub overrides: Vec<Override>,
}

impl Schedule {
    pub fn on_call(&self, at: DateTime<Utc>) -> Option<(Uuid, Source)> {
        who_is_on_call(self.tz, &self.layers, &self.overrides, at)
    }
}

/// A schedule with its layers and the overrides that end after `since`.
pub async fn load_schedule(db: &sqlx::PgPool, id: Uuid, since: DateTime<Utc>) -> sqlx::Result<Option<Schedule>> {
    let Some((name, tz)): Option<(String, String)> =
        sqlx::query_as("SELECT name, timezone FROM oncall_schedules WHERE id = $1").bind(id).fetch_optional(db).await?
    else {
        return Ok(None);
    };
    let rows: Vec<LayerRow> = sqlx::query_as(
        "SELECT id, position, name, user_ids, start_at, shift_hours, restrict FROM oncall_layers WHERE schedule_id = $1 ORDER BY position",
    )
    .bind(id)
    .fetch_all(db)
    .await?;
    let layers = rows
        .into_iter()
        .map(|r| Layer {
            id: r.id,
            position: r.position,
            name: r.name,
            user_ids: r.user_ids,
            start_at: r.start_at,
            shift_hours: r.shift_hours,
            restrict: serde_json::from_value(r.restrict).unwrap_or_default(),
        })
        .collect();
    let overrides: Vec<(Uuid, Uuid, DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, user_id, starts_at, ends_at FROM oncall_overrides WHERE schedule_id = $1 AND ends_at > $2 ORDER BY created_at, id",
    )
    .bind(id)
    .bind(since)
    .fetch_all(db)
    .await?;
    let overrides = overrides.into_iter().map(|(id, user_id, starts_at, ends_at)| Override { id, user_id, starts_at, ends_at }).collect();
    Ok(Some(Schedule { id, name, tz: tz.parse().unwrap_or(Tz::UTC), layers, overrides }))
}

// ---------------------------------------------------------------------------
// Triggering
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct OncallConfig {
    escalation_policy_id: Option<Uuid>,
    #[serde(default)]
    when: String,
    calendar_id: Option<Uuid>,
}

/// A business calendar by id (the SLA feature's), or `None` when it was deleted.
async fn calendar(db: &sqlx::PgPool, id: Uuid) -> sqlx::Result<Option<crate::sla::Calendar>> {
    let row: Option<(String, Value)> = sqlx::query_as("SELECT timezone, hours FROM business_calendars WHERE id = $1").bind(id).fetch_optional(db).await?;
    let Some((tz, hours)) = row else { return Ok(None) };
    let holidays: Vec<NaiveDate> = sqlx::query_scalar("SELECT day FROM holidays WHERE calendar_id = $1").bind(id).fetch_all(db).await?;
    let Ok(hours) = crate::sla::Calendar::parse_hours(&hours) else { return Ok(None) };
    Ok(Some(crate::sla::Calendar::new(tz.parse().unwrap_or(Tz::UTC), hours, holidays.into_iter().collect())))
}

/// The outbox delivered an alert event to an `oncall` channel. "opened" starts a page (unless
/// the alert was dealt with meanwhile); other events need nothing here (the alert's own
/// acknowledge and resolve hooks follow it).
pub async fn trigger_alert(st: &AppState, channel_config: &Value, alert_id: Uuid, event: &str) -> Result<(), String> {
    if event != "opened" {
        return Ok(());
    }
    let cfg: OncallConfig = serde_json::from_value(channel_config.clone()).unwrap_or_default();
    let policy = cfg.escalation_policy_id.ok_or("the channel has no escalation policy")?;
    let row: Option<(String, String, Option<String>, bool)> = sqlx::query_as(
        "SELECT al.title, al.severity, a.hostname, al.resolved_at IS NULL AND al.acknowledged_at IS NULL
           FROM alerts al LEFT JOIN agents a ON a.id = al.agent_id WHERE al.id = $1",
    )
    .bind(alert_id)
    .fetch_optional(&st.db)
    .await
    .map_err(|e| e.to_string())?;
    let Some((title, severity, host, open)) = row else { return Err("alert was deleted".into()) };
    if !open {
        return Ok(());
    }
    let title = match host {
        Some(h) => format!("{title} on {h}"),
        None => title,
    };
    start(st, Some(alert_id), None, policy, &title, &severity, &cfg).await.map_err(|e| e.to_string())
}

/// Starts a page for a ticket through `policy` (new P1 tickets, or a ticket event on an
/// `oncall` channel).
pub async fn trigger_ticket(st: &AppState, ticket_id: Uuid, policy: Uuid, channel_config: Option<&Value>) -> anyhow::Result<()> {
    let (number, subject, priority): (i64, String, i16) =
        sqlx::query_as("SELECT number, subject, priority FROM tickets WHERE id = $1").bind(ticket_id).fetch_one(&st.db).await?;
    let cfg: OncallConfig = channel_config.and_then(|c| serde_json::from_value(c.clone()).ok()).unwrap_or_default();
    let severity = if priority <= 1 { "critical" } else { "warning" };
    start(st, None, Some(ticket_id), policy, &format!("T-{number} {subject}"), severity, &cfg).await
}

async fn start(
    st: &AppState,
    alert_id: Option<Uuid>,
    ticket_id: Option<Uuid>,
    policy: Uuid,
    title: &str,
    severity: &str,
    cfg: &OncallConfig,
) -> anyhow::Result<()> {
    let now = Utc::now();
    // Inside business hours an `outside_hours` page waits for them to end.
    let mut held_until = None;
    if cfg.when == "outside_hours"
        && let Some(cal_id) = cfg.calendar_id
        && let Some(cal) = calendar(&st.db, cal_id).await?
    {
        held_until = cal.open_until(now);
    }
    let (status, next) = match held_until {
        Some(t) => ("held", t),
        None => ("triggered", now),
    };
    let id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO pages (id, alert_id, ticket_id, policy_id, title, severity, status, next_escalation_at)
         SELECT $1, $2, $3, $4, $5, $6, $7, $8 WHERE EXISTS (SELECT 1 FROM escalation_policies WHERE id = $4)
         ON CONFLICT DO NOTHING RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(alert_id)
    .bind(ticket_id)
    .bind(policy)
    .bind(title.chars().take(300).collect::<String>())
    .bind(severity)
    .bind(status)
    .bind(next)
    .fetch_optional(&st.db)
    .await?;
    match id {
        Some(id) => {
            info!(page = %id, ?alert_id, ?ticket_id, status, "page opened");
            // A "triggered" page is due now: the worker notifies step one at once.
            wake();
        }
        None => {
            let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM escalation_policies WHERE id = $1)").bind(policy).fetch_one(&st.db).await?;
            if !exists {
                anyhow::bail!("the escalation policy was deleted");
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Acknowledging and resolving
// ---------------------------------------------------------------------------

/// Someone acknowledged a page: it stops, and its alert is acknowledged too. Returns false when
/// the page was already acknowledged or resolved.
pub async fn ack(st: &AppState, page_id: Uuid, user_id: Uuid) -> sqlx::Result<bool> {
    let row: Option<Option<Uuid>> = sqlx::query_scalar(
        "UPDATE pages SET status = 'acknowledged', acked_by = $2, acked_at = now(), next_escalation_at = NULL
          WHERE id = $1 AND status IN ('held', 'triggered') RETURNING alert_id",
    )
    .bind(page_id)
    .bind(user_id)
    .fetch_optional(&st.db)
    .await?;
    let Some(alert_id) = row else { return Ok(false) };
    cancel_pending(st).await?;
    if let Some(alert_id) = alert_id {
        let acked: Option<(Uuid, Uuid)> = sqlx::query_as(
            "UPDATE alerts al SET acknowledged_at = now(), acknowledged_by = $2
               FROM agents a JOIN sites s ON s.id = a.site_id
              WHERE a.id = al.agent_id AND al.id = $1 AND al.resolved_at IS NULL AND al.acknowledged_at IS NULL
              RETURNING al.agent_id, s.client_id",
        )
        .bind(alert_id)
        .bind(user_id)
        .fetch_optional(&st.db)
        .await?;
        if let Some((agent_id, client_id)) = acked {
            st.hub.publish(Event::Alert { id: alert_id, agent_id, client_id, state: "acknowledged".into() });
            crate::webhooks::alert_event(st, alert_id, "alert.acknowledged").await;
        }
        // Other pages of the same alert (several on-call channels) stop too.
        sync(st, Some(alert_id)).await?;
    }
    Ok(true)
}

/// Pages follow their alert or ticket: acknowledged or resolved there means done here. `alert`
/// narrows it to one alert (the acknowledge and resolve hooks).
pub async fn sync(st: &AppState, alert: Option<Uuid>) -> sqlx::Result<u64> {
    let resolved = sqlx::query(
        "UPDATE pages p SET status = 'resolved', resolved_at = now(), next_escalation_at = NULL
           FROM alerts a WHERE a.id = p.alert_id AND ($1::uuid IS NULL OR a.id = $1)
            AND p.status IN ('held', 'triggered', 'acknowledged') AND a.resolved_at IS NOT NULL",
    )
    .bind(alert)
    .execute(&st.db)
    .await?
    .rows_affected();
    let acked = sqlx::query(
        "UPDATE pages p SET status = 'acknowledged', acked_at = a.acknowledged_at, acked_by = a.acknowledged_by, next_escalation_at = NULL
           FROM alerts a WHERE a.id = p.alert_id AND ($1::uuid IS NULL OR a.id = $1)
            AND p.status IN ('held', 'triggered') AND a.acknowledged_at IS NOT NULL",
    )
    .bind(alert)
    .execute(&st.db)
    .await?
    .rows_affected();
    let tickets = if alert.is_none() {
        sqlx::query(
            "UPDATE pages p SET status = 'resolved', resolved_at = now(), next_escalation_at = NULL
               FROM tickets t WHERE t.id = p.ticket_id AND p.status IN ('held', 'triggered', 'acknowledged') AND t.resolved_at IS NOT NULL",
        )
        .execute(&st.db)
        .await?
        .rows_affected()
    } else {
        0
    };
    if resolved + acked + tickets > 0 {
        cancel_pending(st).await?;
    }
    Ok(resolved + acked + tickets)
}

async fn cancel_pending(st: &AppState) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE page_deliveries d SET status = 'cancelled' FROM pages p
          WHERE p.id = d.page_id AND d.status = 'pending' AND p.status IN ('acknowledged', 'resolved')",
    )
    .execute(&st.db)
    .await?;
    Ok(())
}

/// The alert was acknowledged or resolved (API, policy or condition): its pages follow.
pub async fn alert_changed(st: &AppState, alert_id: Uuid) {
    if let Err(e) = sync(st, Some(alert_id)).await {
        warn!(%alert_id, "following the alert's pages: {e}");
    }
}

// ---------------------------------------------------------------------------
// The worker
// ---------------------------------------------------------------------------

pub async fn run(st: Arc<AppState>) {
    let tick = Duration::from_secs(minute_secs().clamp(1, 15) as u64);
    loop {
        if let Err(e) = tick_once(&st).await {
            warn!("on-call worker: {e:#}");
        }
        tokio::select! {
            _ = WAKE.notified() => {}
            _ = tokio::time::sleep(tick) => {}
        }
    }
}

async fn tick_once(st: &AppState) -> anyhow::Result<()> {
    sync(st, None).await?;
    p1_tickets(st).await?;
    while escalate(st).await? == BATCH as usize {}
    while deliver_due(st).await? == BATCH as usize {}
    // Links in old text messages.
    sqlx::query("DELETE FROM page_links WHERE expires_at < now() - interval '7 days'").execute(&st.db).await?;
    Ok(())
}

/// New P1 tickets, when Company settings name a policy for them.
async fn p1_tickets(st: &AppState) -> anyhow::Result<()> {
    let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT t.id, c.p1_escalation_policy_id FROM tickets t, company_settings c
          WHERE c.p1_escalation_policy_id IS NOT NULL AND t.priority = 1 AND t.resolved_at IS NULL
            AND t.created_at > now() - interval '15 minutes' AND t.created_at > c.updated_at - interval '1 minute'
            AND NOT EXISTS (SELECT 1 FROM pages p WHERE p.ticket_id = t.id)
          LIMIT 20",
    )
    .fetch_all(&st.db)
    .await?;
    for (ticket, policy) in rows {
        trigger_ticket(st, ticket, policy, None).await?;
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
struct DuePage {
    id: Uuid,
    alert_id: Option<Uuid>,
    ticket_id: Option<Uuid>,
    policy_id: Option<Uuid>,
    step: i32,
    round: i32,
    last_step_at: Option<DateTime<Utc>>,
}

/// Starts held pages and moves triggered ones on to their next step.
async fn escalate(st: &AppState) -> anyhow::Result<usize> {
    let mut tx = st.db.begin().await?;
    let due: Vec<DuePage> = sqlx::query_as(
        "SELECT id, alert_id, ticket_id, policy_id, step, round, last_step_at FROM pages
          WHERE status IN ('held', 'triggered') AND next_escalation_at <= now()
          ORDER BY next_escalation_at LIMIT $1 FOR UPDATE SKIP LOCKED",
    )
    .bind(BATCH)
    .fetch_all(&mut *tx)
    .await?;
    let n = due.len();
    let mut channels: Vec<(Uuid, Option<Uuid>, Option<Uuid>)> = Vec::new();
    for p in due {
        let steps: Vec<(i32, Value)> = match p.policy_id {
            Some(pid) => {
                sqlx::query_as("SELECT delay_minutes, targets FROM escalation_steps WHERE policy_id = $1 ORDER BY position")
                    .bind(pid)
                    .fetch_all(&mut *tx)
                    .await?
            }
            None => vec![],
        };
        let repeat: i32 = match p.policy_id {
            Some(pid) => sqlx::query_scalar("SELECT repeat FROM escalation_policies WHERE id = $1").bind(pid).fetch_optional(&mut *tx).await?.unwrap_or(0),
            None => 0,
        };
        // A page that hasn't notified anyone yet (just opened, or held until now) starts at step
        // one; otherwise the current step timed out.
        let next = match p.last_step_at {
            None => (!steps.is_empty()).then_some((0, 0)),
            Some(_) => next_step(p.step, p.round, steps.len() as i32, repeat),
        };
        let Some((step, round)) = next else {
            sqlx::query("UPDATE pages SET status = 'triggered', next_escalation_at = NULL WHERE id = $1").bind(p.id).execute(&mut *tx).await?;
            continue;
        };
        let (delay, targets) = &steps[step as usize];
        let now = Utc::now();
        let mut users: Vec<Uuid> = Vec::new();
        for t in targets.as_array().into_iter().flatten().filter_map(|t| Target::parse(t).ok()) {
            match t {
                Target::User(u) => users.push(u),
                Target::Schedule(s) => {
                    if let Some(sched) = load_schedule(&st.db, s, now).await?
                        && let Some((u, _)) = sched.on_call(now)
                    {
                        users.push(u);
                    }
                }
                Target::Channel(c) => {
                    sqlx::query("INSERT INTO page_deliveries (id, page_id, channel_id, method, step, round, status, sent_at) VALUES ($1, $2, $3, 'channel', $4, $5, 'sent', now())")
                        .bind(Uuid::new_v4())
                        .bind(p.id)
                        .bind(c)
                        .bind(step)
                        .bind(round)
                        .execute(&mut *tx)
                        .await?;
                    channels.push((c, p.alert_id, p.ticket_id));
                }
            }
        }
        users.sort_unstable();
        users.dedup();
        for u in users {
            let rules: Vec<(String, i32)> = sqlx::query_as(
                "SELECT r.method, r.delay_minutes FROM user_contact_rules r JOIN users x ON x.id = r.user_id WHERE r.user_id = $1 AND NOT x.disabled",
            )
            .bind(u)
            .fetch_all(&mut *tx)
            .await?;
            let rules = if rules.is_empty() { default_rules(&mut tx, u).await? } else { rules };
            for (method, delay) in rules {
                sqlx::query(
                    "INSERT INTO page_deliveries (id, page_id, user_id, method, step, round, next_attempt_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                )
                .bind(Uuid::new_v4())
                .bind(p.id)
                .bind(u)
                .bind(&method)
                .bind(step)
                .bind(round)
                .bind(now + minutes(i64::from(delay)))
                .execute(&mut *tx)
                .await?;
            }
        }
        sqlx::query("UPDATE pages SET status = 'triggered', step = $2, round = $3, next_escalation_at = $4, last_step_at = now() WHERE id = $1")
            .bind(p.id)
            .bind(step)
            .bind(round)
            .bind(now + minutes(i64::from(*delay)))
            .execute(&mut *tx)
            .await?;
        info!(page = %p.id, step, round, "page escalated");
    }
    tx.commit().await?;
    // Another channel as a target: the outbox sends the alert (or ticket) there as usual.
    let mut woke = false;
    for (channel, alert, ticket) in channels {
        let kind: Option<String> = sqlx::query_scalar("SELECT kind FROM notification_channels WHERE id = $1 AND enabled").bind(channel).fetch_optional(&st.db).await?;
        // Never another on-call channel: that could page in a loop.
        if kind.is_none_or(|k| k == "oncall") {
            continue;
        }
        match (alert, ticket) {
            (Some(a), _) => crate::notify::enqueue(st, a, "opened", &[channel]).await,
            (None, Some(t)) => {
                sqlx::query("INSERT INTO notifications (channel_id, ticket_id, event) VALUES ($1, $2, 'page')").bind(channel).bind(t).execute(&st.db).await?;
            }
            _ => continue,
        }
        woke = true;
    }
    if woke {
        st.notify_wake.notify_one();
    }
    Ok(n)
}

/// Without contact rules: email and push at once, and a text when the phone is verified.
async fn default_rules(tx: &mut sqlx::PgConnection, user: Uuid) -> sqlx::Result<Vec<(String, i32)>> {
    let verified: Option<bool> = sqlx::query_scalar("SELECT phone IS NOT NULL AND phone_verified_at IS NOT NULL FROM users WHERE id = $1 AND NOT disabled")
        .bind(user)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(verified) = verified else { return Ok(vec![]) };
    let mut out = vec![("email".to_string(), 0), ("push".to_string(), 0)];
    if verified {
        out.push(("sms".into(), 0));
    }
    Ok(out)
}

#[derive(sqlx::FromRow)]
struct DueDelivery {
    id: Uuid,
    page_id: Uuid,
    user_id: Option<Uuid>,
    method: String,
    attempts: i32,
}

#[derive(sqlx::FromRow)]
struct PageCtx {
    title: String,
    severity: String,
    alert_id: Option<Uuid>,
    ticket_id: Option<Uuid>,
}

async fn deliver_due(st: &AppState) -> anyhow::Result<usize> {
    let due: Vec<DueDelivery> = sqlx::query_as(
        "UPDATE page_deliveries SET attempts = attempts + 1, next_attempt_at = now() + interval '10 minutes'
          WHERE id IN (SELECT d.id FROM page_deliveries d JOIN pages p ON p.id = d.page_id
                        WHERE d.status = 'pending' AND d.next_attempt_at <= now() AND p.status = 'triggered'
                        ORDER BY d.next_attempt_at LIMIT $1 FOR UPDATE OF d SKIP LOCKED)
          RETURNING id, page_id, user_id, method, attempts",
    )
    .bind(BATCH)
    .fetch_all(&st.db)
    .await?;
    let n = due.len();
    for d in due {
        let result = send_delivery(st, &d).await;
        match result {
            Ok(provider_ref) => {
                sqlx::query("UPDATE page_deliveries SET status = 'sent', sent_at = now(), error = NULL, provider_ref = $2 WHERE id = $1")
                    .bind(d.id)
                    .bind(provider_ref)
                    .execute(&st.db)
                    .await?;
            }
            Err(err) => {
                let give_up = d.attempts >= MAX_ATTEMPTS;
                warn!(delivery = %d.id, method = %d.method, attempts = d.attempts, give_up, "page delivery failed: {err}");
                let wait = crate::notify::backoff(d.attempts).num_minutes() * minute_secs();
                sqlx::query(
                    "UPDATE page_deliveries SET status = CASE WHEN $3 THEN 'failed' ELSE 'pending' END, error = $2,
                            next_attempt_at = now() + make_interval(secs => $4)
                      WHERE id = $1",
                )
                .bind(d.id)
                .bind(err.chars().take(1000).collect::<String>())
                .bind(give_up)
                .bind(wait as f64)
                .execute(&st.db)
                .await?;
            }
        }
    }
    Ok(n)
}

/// Sends one delivery. Returns the provider's reference, if it gives one.
async fn send_delivery(st: &AppState, d: &DueDelivery) -> Result<Option<String>, String> {
    let user = d.user_id.ok_or("nobody to send to")?;
    let p: PageCtx = sqlx::query_as("SELECT title, severity, alert_id, ticket_id FROM pages WHERE id = $1")
        .bind(d.page_id)
        .fetch_one(&st.db)
        .await
        .map_err(|e| e.to_string())?;
    let path = match (p.alert_id, p.ticket_id) {
        (Some(a), _) => format!("/alerts/{a}"),
        (None, Some(t)) => format!("/tickets/{t}"),
        _ => "/alerts".to_string(),
    };
    let brand = brand(st);
    match d.method.as_str() {
        "sms" => {
            let phone: Option<String> = sqlx::query_scalar("SELECT phone FROM users WHERE id = $1 AND phone_verified_at IS NOT NULL AND NOT disabled")
                .bind(user)
                .fetch_optional(&st.db)
                .await
                .map_err(|e| e.to_string())?
                .flatten();
            let phone = phone.ok_or("no verified mobile number")?;
            let token = crate::auth::random_token()[..32].to_string();
            sqlx::query("INSERT INTO page_links (token_hash, page_id, user_id, expires_at) VALUES ($1, $2, $3, now() + interval '24 hours')")
                .bind(crate::auth::token_hash(&token))
                .bind(d.page_id)
                .bind(user)
                .execute(&st.db)
                .await
                .map_err(|e| e.to_string())?;
            let link = format!("{}/a/{token}", st.cfg.public_url);
            send_sms(st, &phone, &sms_text(&brand, &p.severity, &p.title, &link)).await.map(Some)
        }
        "email" => {
            crate::notify::mailer(st)?;
            let subject = format!("Paged: {}", p.title);
            let body = format!(
                "You are paged for:\n\n{}\n\nAcknowledge it here (this stops the escalation):\n{}{path}\n",
                p.title, st.cfg.public_url
            );
            crate::email::queue_staff_note(st, user, &subject, &body).await.map_err(|e| format!("{e:#}"))?;
            Ok(None)
        }
        "push" => {
            let payload = json!({
                "title": format!("Paged: {}", p.severity.to_uppercase()),
                "body": p.title,
                "url": path,
                "alert_id": p.alert_id,
                "tag": format!("page-{}", d.page_id),
                "kind": "page",
            });
            match crate::push::send_to_user(st, user, &payload, true).await? {
                0 => Err("no device of theirs accepts notifications".into()),
                n => Ok(Some(format!("{n} device(s)"))),
            }
        }
        other => Err(format!("unknown method {other}")),
    }
}

fn brand(st: &AppState) -> String {
    // COORDINATOR: once branding lands, take the product name from `branding::resolve(None)`.
    let name = st.company().company_name;
    if name.trim().is_empty() { "RMM".into() } else { name }
}

// ---------------------------------------------------------------------------
// The short link in text messages
// ---------------------------------------------------------------------------

/// `GET /a/<token>`: opens the page's alert (or ticket) in the dashboard, once, within 24
/// hours. Acting on it still needs a session; the link only saves typing.
pub async fn short_link(
    axum::extract::State(st): axum::extract::State<Arc<AppState>>,
    axum::extract::Path(token): axum::extract::Path<String>,
) -> axum::response::Response {
    use axum::response::{IntoResponse, Redirect};
    let gone = || {
        (
            axum::http::StatusCode::GONE,
            [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "This link has expired or was already used. Open the alerts page instead.",
        )
            .into_response()
    };
    if token.len() > 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return gone();
    }
    let row: Option<(Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
        "UPDATE page_links l SET used_at = now() FROM pages p
          WHERE l.token_hash = $1 AND l.used_at IS NULL AND l.expires_at > now() AND p.id = l.page_id
          RETURNING p.alert_id, p.ticket_id",
    )
    .bind(crate::auth::token_hash(&token))
    .fetch_optional(&st.db)
    .await
    .unwrap_or(None);
    match row {
        Some((Some(a), _)) => Redirect::to(&format!("/alerts/{a}")).into_response(),
        Some((None, Some(t))) => Redirect::to(&format!("/tickets/{t}")).into_response(),
        _ => gone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn ids(n: usize) -> Vec<Uuid> {
        (0..n).map(|i| Uuid::from_u128(i as u128 + 1)).collect()
    }

    fn layer(position: i32, users: Vec<Uuid>, start: &str, hours: i32, restrict: Vec<Window>) -> Layer {
        Layer { id: Uuid::from_u128(1000 + position as u128), position, name: String::new(), user_ids: users, start_at: t(start), shift_hours: hours, restrict }
    }

    #[test]
    fn weekly_rotation_keeps_local_handover_across_dst() {
        let tz: Tz = "Europe/London".parse().unwrap();
        let u = ids(2);
        // Monday 09:00 BST, 2026-10-19; clocks go back on Sunday 25 October.
        let l = layer(0, u.clone(), "2026-10-19T08:00:00Z", 168, vec![]);
        assert_eq!(l.on_call(tz, t("2026-10-19T08:00:00Z")), Some(u[0]));
        assert_eq!(l.on_call(tz, t("2026-10-26T08:59:00Z")), Some(u[0]), "08:59 GMT is still before the 09:00 local handover");
        assert_eq!(l.on_call(tz, t("2026-10-26T09:00:00Z")), Some(u[1]), "09:00 GMT is 09:00 local after the change");
        let (n, s, e) = l.shift_at(tz, t("2026-10-27T00:00:00Z")).unwrap();
        assert_eq!((n, s, e), (1, t("2026-10-26T09:00:00Z"), t("2026-11-02T09:00:00Z")));
        // Spring forward: 30 March 2026 is the first Monday after; 09:00 BST is 08:00 UTC.
        let spring = layer(0, u.clone(), "2026-03-23T09:00:00Z", 168, vec![]);
        assert_eq!(spring.shift_at(tz, t("2026-03-31T00:00:00Z")).unwrap().1, t("2026-03-30T08:00:00Z"));
        assert_eq!(l.on_call(tz, t("2026-10-18T00:00:00Z")), None, "nobody before the rotation starts");
    }

    #[test]
    fn hourly_rotation_is_exact_hours() {
        let tz: Tz = "America/New_York".parse().unwrap();
        let u = ids(3);
        let l = layer(0, u.clone(), "2026-03-07T12:00:00Z", 12, vec![]);
        // 12-hour shifts straight through the 8 March DST change: exact elapsed hours.
        assert_eq!(l.on_call(tz, t("2026-03-08T11:59:00Z")), Some(u[1]));
        assert_eq!(l.on_call(tz, t("2026-03-08T12:00:00Z")), Some(u[2]));
        assert_eq!(l.on_call(tz, t("2026-03-09T00:00:00Z")), Some(u[0]), "wraps round the list");
    }

    #[test]
    fn restrictions_and_overnight_windows() {
        let tz: Tz = "UTC".parse().unwrap();
        let u = ids(1);
        // Weeknights 18:00-08:00 (Monday night to Friday night).
        let l = layer(0, u.clone(), "2026-01-05T00:00:00Z", 24, vec![Window { days: vec![0, 1, 2, 3, 4], start: 18 * 60, end: 8 * 60 }]);
        assert_eq!(l.on_call(tz, t("2026-01-05T19:00:00Z")), Some(u[0]), "Monday evening");
        assert_eq!(l.on_call(tz, t("2026-01-06T07:59:00Z")), Some(u[0]), "Tuesday early morning, from Monday's window");
        assert_eq!(l.on_call(tz, t("2026-01-06T12:00:00Z")), None, "Tuesday midday");
        assert_eq!(l.on_call(tz, t("2026-01-10T07:00:00Z")), Some(u[0]), "Saturday morning, from Friday night");
        assert_eq!(l.on_call(tz, t("2026-01-11T07:00:00Z")), None, "Sunday morning: Saturday has no window");
        assert!(Window { days: vec![7], start: 0, end: 60 }.validate().is_err());
        assert!(Window { days: vec![1], start: 60, end: 60 }.validate().is_err());
    }

    #[test]
    fn layers_by_position_and_overrides_win() {
        let tz: Tz = "UTC".parse().unwrap();
        let u = ids(4);
        let base = layer(0, vec![u[0]], "2026-01-01T00:00:00Z", 24, vec![]);
        // Higher layer, weekdays 09:00-17:00 only.
        let day = layer(1, vec![u[1]], "2026-01-01T00:00:00Z", 24, vec![Window { days: vec![0, 1, 2, 3, 4], start: 540, end: 1020 }]);
        let layers = [base.clone(), day.clone()];
        assert_eq!(who_is_on_call(tz, &layers, &[], t("2026-01-05T10:00:00Z")).unwrap().0, u[1]);
        assert_eq!(who_is_on_call(tz, &layers, &[], t("2026-01-05T20:00:00Z")).unwrap().0, u[0], "falls through to the lower layer");
        let o = [
            Override { id: Uuid::from_u128(77), user_id: u[2], starts_at: t("2026-01-05T09:30:00Z"), ends_at: t("2026-01-05T12:00:00Z") },
            Override { id: Uuid::from_u128(78), user_id: u[3], starts_at: t("2026-01-05T11:00:00Z"), ends_at: t("2026-01-05T11:30:00Z") },
        ];
        assert_eq!(who_is_on_call(tz, &layers, &o, t("2026-01-05T10:00:00Z")), Some((u[2], Source::Override(Uuid::from_u128(77)))));
        assert_eq!(who_is_on_call(tz, &layers, &o, t("2026-01-05T11:10:00Z")).unwrap().0, u[3], "the later override wins");
        assert_eq!(who_is_on_call(tz, &layers, &o, t("2026-01-05T12:00:00Z")).unwrap().0, u[1], "an override ends at its end");

        let shifts = final_shifts(tz, &layers, &o, t("2026-01-05T00:00:00Z"), t("2026-01-06T00:00:00Z"));
        let got: Vec<(Uuid, String, String)> = shifts.iter().map(|s| (s.user_id, s.start.format("%H:%M").to_string(), s.end.format("%H:%M").to_string())).collect();
        let want = [(u[0], "00:00", "09:00"), (u[1], "09:00", "09:30"), (u[2], "09:30", "11:00"), (u[3], "11:00", "11:30"), (u[2], "11:30", "12:00"), (u[1], "12:00", "17:00"), (u[0], "17:00", "00:00")];
        assert_eq!(got, want.map(|(a, b, c)| (a, b.to_string(), c.to_string())));
        let own = layer_shifts(tz, &day, t("2026-01-05T00:00:00Z"), t("2026-01-07T00:00:00Z"));
        assert_eq!(own.len(), 2, "one 09:00-17:00 block per weekday: {own:?}");
    }

    #[test]
    fn escalation_steps_then_repeats_then_stops() {
        assert_eq!(next_step(0, 0, 3, 1), Some((1, 0)));
        assert_eq!(next_step(2, 0, 3, 1), Some((0, 1)), "repeat from the first step");
        assert_eq!(next_step(2, 1, 3, 1), None, "repeats used up");
        assert_eq!(next_step(0, 0, 1, 0), None);
        assert_eq!(next_step(0, 0, 0, 3), None, "no steps");
    }

    #[test]
    fn targets_parse() {
        let id = Uuid::from_u128(5);
        assert_eq!(Target::parse(&json!({ "schedule": id })).unwrap(), Target::Schedule(id));
        assert_eq!(Target::parse(&Target::User(id).to_json()).unwrap(), Target::User(id));
        assert!(Target::parse(&json!({ "team": id })).is_err());
        assert!(Target::parse(&json!({ "user": "x" })).is_err());
        assert!(Target::parse(&json!({ "user": id, "channel": id })).is_err());
    }

    #[test]
    fn sms_is_at_most_300_characters_and_keeps_the_link() {
        let link = "https://rmm.example.com/a/0123456789abcdef0123456789abcdef";
        let short = sms_text("Northwind", "critical", "Disk nearly full on acme-fs01", link);
        assert_eq!(short, format!("[Northwind] CRITICAL: Disk nearly full on acme-fs01 {link}"));
        let long = sms_text("Northwind", "warning", &"Very long title ".repeat(40), link);
        assert_eq!(long.chars().count(), SMS_MAX);
        assert!(long.ends_with(link) && long.contains("…"), "{long}");
        assert!(valid_e164("+447700900123") && !valid_e164("07700900123") && !valid_e164("+0123456789") && !valid_e164("+12"));
    }
}
