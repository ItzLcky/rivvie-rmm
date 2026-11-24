//! Scheduled and emailed reports (docs/design/scheduled-reports.md).
//!
//! A `report_schedules` row names one of the four reports ([`Kind`]), a range preset, a cron
//! timetable in a time zone, and who gets it. Every [`TICK`] the due rows are claimed
//! (`FOR UPDATE SKIP LOCKED`, moved to their next time as in [`crate::scheduler`]) and run:
//! the report is built **with the owner's access as it is now** (a lost permission or client
//! fails the run with the reason instead of leaking figures), rendered to a PDF, kept in object
//! storage, and mailed through the outbox to each recipient on their own.
//!
//! Who may receive what ([`recipient_rule`]): users who could open the report themselves;
//! contacts only a QBR or a service desk report about their own client; other addresses only on
//! an admin's schedule.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Datelike, Days, Months, NaiveDate, Utc};
use serde_json::{Value, json};
use tracing::{info, warn};
use uuid::Uuid;

pub(crate) use crate::api::reports::Kind;
use crate::auth::{self, Perm, Role, User};
use crate::error::ApiError;
use crate::state::AppState;

const TICK: Duration = Duration::from_secs(30);
/// Runs (and their PDFs) are kept this long.
pub const KEEP_DAYS: i32 = 400;

/// The period a report covers, worked out when it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    /// Monday to Sunday of the week before this one.
    LastWeek,
    /// The calendar month before this one.
    LastMonth,
    /// The calendar quarter before this one.
    LastQuarter,
    /// The 30 days up to yesterday.
    Last30Days,
}

impl Preset {
    pub fn parse(s: &str) -> Option<Preset> {
        Some(match s {
            "last_week" => Preset::LastWeek,
            "last_month" => Preset::LastMonth,
            "last_quarter" => Preset::LastQuarter,
            "last_30_days" => Preset::Last30Days,
            _ => return None,
        })
    }

    /// The default for a report: a quarter for the QBR, a month for the others.
    pub fn default_for(kind: Kind) -> Preset {
        if kind == Kind::Qbr { Preset::LastQuarter } else { Preset::LastMonth }
    }

    /// `(from, to)`, both inclusive, for a run at `now` in the time zone `tz`.
    pub fn resolve(self, now: DateTime<Utc>, tz: chrono_tz::Tz) -> (NaiveDate, NaiveDate) {
        let today = now.with_timezone(&tz).date_naive();
        match self {
            Preset::LastWeek => {
                let monday = today - Days::new(u64::from(today.weekday().num_days_from_monday()));
                (monday - Days::new(7), monday - Days::new(1))
            }
            Preset::LastMonth => {
                let first = today.with_day(1).expect("day 1 exists");
                (first - Months::new(1), first - Days::new(1))
            }
            Preset::LastQuarter => crate::api::reports::last_quarter(today),
            Preset::Last30Days => (today - Days::new(30), today - Days::new(1)),
        }
    }
}

/// The range preset of a schedule's `params`.
pub fn preset_of(kind: Kind, params: &Value) -> Result<Preset, String> {
    match params.get("range").and_then(Value::as_str) {
        None => Ok(Preset::default_for(kind)),
        Some(r) => Preset::parse(r).ok_or_else(|| format!("unknown range {r:?}: use last_week, last_month, last_quarter or last_30_days")),
    }
}

/// Whether a contact of `contact_client` may receive this report.
pub fn recipient_rule(kind: Kind, client: Option<Uuid>, contact_client: Uuid) -> Result<(), String> {
    match kind {
        Kind::Utilisation | Kind::Profitability => Err(format!("a {} report never goes to client contacts", kind.as_str())),
        Kind::Qbr | Kind::ServiceDesk => match client {
            Some(c) if c == contact_client => Ok(()),
            Some(_) => Err("a contact only receives reports about their own client".into()),
            None => Err("a service desk report for every client can't go to client contacts: pick the client".into()),
        },
    }
}

/// Whether `a` sees at least every client `b` sees.
fn covers(a: &User, b: &User) -> bool {
    match (a.scope(), b.scope()) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(a), Some(b)) => b.iter().all(|c| a.contains(c)),
    }
}

/// Why `u` can't open this report itself (`None`: it can).
pub fn cannot_view(u: &User, kind: Kind, client: Option<Uuid>) -> Option<String> {
    if client.is_some_and(|c| !u.can_see_client(c)) {
        return Some("can't see this client".into());
    }
    match kind {
        Kind::Profitability if !u.has(Perm::BillingRead) => Some("lacks the billing.read permission".into()),
        Kind::Utilisation if !u.has(Perm::TimeApprove) && !u.has(Perm::BillingRead) => {
            Some("lacks the billing.read or time.approve permission".into())
        }
        _ => None,
    }
}

/// Why user `r` can't receive the owner's report (`None`: they can). Besides opening it, they
/// must see every client the owner sees when the report covers more than one.
pub fn cannot_receive(r: &User, owner: &User, kind: Kind, client: Option<Uuid>) -> Option<String> {
    if let Some(why) = cannot_view(r, kind, client) {
        return Some(why);
    }
    let many = matches!(kind, Kind::Profitability) || (kind == Kind::ServiceDesk && client.is_none());
    (many && !covers(r, owner)).then(|| "can't see every client the report covers".into())
}

/// A user as they are now (any session; disabled accounts are `None`).
pub async fn load_user(st: &AppState, id: Uuid) -> sqlx::Result<Option<User>> {
    sqlx::query_as(concat!("SELECT ", auth::user_columns!("$2", "$3::uuid", "false"), " FROM users u WHERE u.id = $1 AND NOT u.disabled"))
        .bind(id)
        .bind(st.company().require_2fa_all)
        .bind(Uuid::nil())
        .fetch_optional(&st.db)
        .await
}

pub fn valid_email(s: &str) -> bool {
    let s = s.trim();
    let Some((local, domain)) = s.split_once('@') else { return false };
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.') && s.len() <= 254 && !s.contains(char::is_whitespace) && !s.contains(['<', '>', ',', ';'])
}

#[derive(sqlx::FromRow)]
struct Schedule {
    id: Uuid,
    name: String,
    report: String,
    client_id: Option<Uuid>,
    params: Value,
    timezone: String,
    user_ids: Vec<Uuid>,
    contact_ids: Vec<Uuid>,
    extra_emails: Vec<String>,
    subject: String,
    message: String,
    owner_id: Uuid,
}

pub async fn run(st: Arc<AppState>) {
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut n: u64 = 0;
    loop {
        tick.tick().await;
        match claim_due(&st).await {
            Ok(due) => {
                for id in due {
                    if let Err(e) = run_schedule(&st, id, None).await {
                        warn!(schedule = %id, "scheduled report: {e:#}");
                    }
                }
            }
            Err(e) => warn!("report scheduler: {e}"),
        }
        if n.is_multiple_of(120)
            && let Err(e) = prune(&st).await
        {
            warn!("pruning report runs: {e:#}");
        }
        n += 1;
    }
}

/// Moves every due schedule to its next run and returns their ids.
async fn claim_due(st: &AppState) -> sqlx::Result<Vec<Uuid>> {
    let mut tx = st.db.begin().await?;
    let due: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT id, cron, timezone FROM report_schedules WHERE enabled AND next_run_at <= now()
          ORDER BY next_run_at LIMIT 50 FOR UPDATE SKIP LOCKED",
    )
    .fetch_all(&mut *tx)
    .await?;
    let now = Utc::now();
    for (id, cron, tz) in &due {
        let next = crate::scheduler::next_run(cron, tz, now).ok();
        sqlx::query("UPDATE report_schedules SET next_run_at = $2 WHERE id = $1").bind(id).bind(next).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(due.into_iter().map(|d| d.0).collect())
}

/// The next time a schedule runs, or `None` when it is off.
pub fn next_run_at(enabled: bool, cron: &str, tz: &str) -> Result<Option<DateTime<Utc>>, String> {
    let next = crate::scheduler::next_run(cron, tz, Utc::now())?;
    Ok(enabled.then_some(next))
}

/// Runs a schedule now: `by` is the user who pressed "send now" (`None`: its timetable).
/// Returns the run's id; the run records whether it was sent or why it failed.
pub async fn run_schedule(st: &AppState, schedule_id: Uuid, by: Option<Uuid>) -> anyhow::Result<Uuid> {
    let s: Schedule = sqlx::query_as(
        "SELECT id, name, report, client_id, params, timezone, user_ids, contact_ids, extra_emails, subject, message, owner_id
           FROM report_schedules WHERE id = $1",
    )
    .bind(schedule_id)
    .fetch_one(&st.db)
    .await?;
    let run_id = Uuid::new_v4();
    sqlx::query("INSERT INTO report_runs (id, schedule_id, trigger, started_by) VALUES ($1, $2, $3, $4)")
        .bind(run_id)
        .bind(s.id)
        .bind(if by.is_some() { "manual" } else { "schedule" })
        .bind(by)
        .execute(&st.db)
        .await?;
    let outcome = deliver(st, &s, run_id).await;
    let (status, error) = match &outcome {
        Ok(()) => ("sent", None),
        Err(e) => ("failed", Some(e.clone())),
    };
    sqlx::query("UPDATE report_runs SET status = $2, error = $3, finished_at = now() WHERE id = $1")
        .bind(run_id)
        .bind(status)
        .bind(&error)
        .execute(&st.db)
        .await?;
    sqlx::query("UPDATE report_schedules SET last_run_at = now(), last_status = $2, last_error = $3 WHERE id = $1")
        .bind(s.id)
        .bind(status)
        .bind(&error)
        .execute(&st.db)
        .await?;
    match &error {
        None => {
            info!(schedule = %s.id, run = %run_id, "report sent");
            auth::audit(&st.db, by, "report.sent", Some(("report_schedule", s.id)), json!({ "run_id": run_id, "report": s.report })).await;
        }
        Some(e) => warn!(schedule = %s.id, run = %run_id, "report not sent: {e}"),
    }
    Ok(run_id)
}

/// Builds, stores and mails one run. `Err` is the reason it failed, for the people reading the
/// history.
async fn deliver(st: &AppState, s: &Schedule, run_id: Uuid) -> Result<(), String> {
    let kind = Kind::parse(&s.report).ok_or("unknown report")?;
    let tz = chrono_tz::Tz::from_str(&s.timezone).map_err(|_| format!("unknown time zone {}", s.timezone))?;
    let (from, to) = preset_of(kind, &s.params)?.resolve(Utc::now(), tz);
    let db = |e: sqlx::Error| e.to_string();
    sqlx::query("UPDATE report_runs SET from_date = $2, to_date = $3 WHERE id = $1")
        .bind(run_id)
        .bind(from)
        .bind(to)
        .execute(&st.db)
        .await
        .map_err(db)?;

    // The owner's access, now.
    let owner = load_user(st, s.owner_id).await.map_err(db)?.ok_or("the owner's account is disabled")?;
    if owner.role() < Role::Technician {
        return Err("the owner is no longer a technician or admin".into());
    }
    if let Some(why) = cannot_view(&owner, kind, s.client_id) {
        return Err(format!("the owner {why}"));
    }
    let rendered = crate::api::reports::render(st, &owner, kind, s.client_id, from, to).await.map_err(|e| match e {
        ApiError::Forbidden => "the owner no longer has permission for this report".to_string(),
        ApiError::NotFound(what) => format!("the {what} no longer exists or the owner can't see it"),
        e => e.to_string(),
    })?;

    // Who it goes to.
    let mut recipients: Vec<Value> = Vec::new();
    let mut to_addrs: Vec<String> = Vec::new();
    let mut add = |recipients: &mut Vec<Value>, kind: &str, id: Option<Uuid>, email: &str, skip: Option<String>| {
        let email = email.trim().to_string();
        let skip = skip.or_else(|| (!valid_email(&email)).then(|| "no usable email address".into()));
        let dup = skip.is_none() && to_addrs.iter().any(|a| a.eq_ignore_ascii_case(&email));
        match (&skip, dup) {
            (Some(why), _) => recipients.push(json!({ "kind": kind, "id": id, "email": email, "status": "skipped", "reason": why })),
            (None, true) => {}
            (None, false) => {
                recipients.push(json!({ "kind": kind, "id": id, "email": email, "status": "queued" }));
                to_addrs.push(email);
            }
        }
    };
    for uid in &s.user_ids {
        match load_user(st, *uid).await.map_err(db)? {
            None => add(&mut recipients, "user", Some(*uid), "", Some("not an active user any more".into())),
            Some(r) => {
                let why = cannot_receive(&r, &owner, kind, s.client_id);
                add(&mut recipients, "user", Some(*uid), &r.email, why);
            }
        }
    }
    let contacts: Vec<(Uuid, Uuid, String)> = sqlx::query_as("SELECT id, client_id, email FROM contacts WHERE id = ANY($1)")
        .bind(&s.contact_ids)
        .fetch_all(&st.db)
        .await
        .map_err(db)?;
    for cid in &s.contact_ids {
        match contacts.iter().find(|c| c.0 == *cid) {
            None => add(&mut recipients, "contact", Some(*cid), "", Some("the contact was deleted".into())),
            Some((_, client, email)) => add(&mut recipients, "contact", Some(*cid), email, recipient_rule(kind, s.client_id, *client).err()),
        }
    }
    for e in &s.extra_emails {
        let why = (owner.role() != Role::Admin).then(|| "only an admin's schedule mails other addresses".to_string());
        add(&mut recipients, "email", None, e, why);
    }
    let save_recipients = |recipients: Vec<Value>| async move {
        sqlx::query("UPDATE report_runs SET recipients = $2 WHERE id = $1").bind(run_id).bind(Value::Array(recipients)).execute(&st.db).await
    };
    if to_addrs.is_empty() {
        save_recipients(recipients).await.map_err(db)?;
        return Err("nobody left to send it to".into());
    }

    // The PDF, kept for the history and attached from storage.
    let pdf = rendered.pdf(st);
    let key = format!("reports/{run_id}.pdf");
    let bytes = pdf.len() as i64;
    st.storage.put(&key, pdf, "application/pdf").await.map_err(|e| format!("storing the PDF: {e}"))?;
    sqlx::query("UPDATE report_runs SET storage_key = $2, bytes = $3, file_name = $4 WHERE id = $1")
        .bind(run_id)
        .bind(&key)
        .bind(bytes)
        .bind(&rendered.file)
        .execute(&st.db)
        .await
        .map_err(db)?;

    let brand = crate::email::brand(st);
    let subject = if s.subject.trim().is_empty() { format!("{}: {}", rendered.title, rendered.subtitle) } else { s.subject.trim().to_string() };
    let body = email_body(&s.message, &rendered.title, &rendered.subtitle, &s.name, &brand);
    let mut failed = None;
    for addr in &to_addrs {
        match crate::email::queue_report(st, addr.clone(), subject.clone(), body.clone(), (format!("{}.pdf", rendered.file), key.clone())).await {
            Ok((_, true)) => {}
            Ok((_, false)) => failed = Some("no mail server: set one up under Company settings → Notifications".to_string()),
            Err(e) => failed = Some(format!("queueing the email: {e}")),
        }
    }
    save_recipients(recipients).await.map_err(db)?;
    failed.map_or(Ok(()), Err)
}

/// The text of a report email: the schedule's own message, what is attached, and why it came.
pub fn email_body(message: &str, title: &str, subtitle: &str, schedule: &str, brand: &str) -> String {
    let mut out = String::from("Hello,\n\n");
    if !message.trim().is_empty() {
        out.push_str(message.trim());
        out.push_str("\n\n");
    }
    out.push_str(&format!("Attached: {title}, {subtitle} (PDF).\n\nYou receive this report from the schedule \"{schedule}\".\n\n{brand}\n"));
    out
}

/// Forgets runs older than [`KEEP_DAYS`], and their PDFs.
pub async fn prune(st: &AppState) -> anyhow::Result<()> {
    let old: Vec<(Uuid, Option<String>)> =
        sqlx::query_as("SELECT id, storage_key FROM report_runs WHERE started_at < now() - make_interval(days => $1) LIMIT 1000")
            .bind(KEEP_DAYS)
            .fetch_all(&st.db)
            .await?;
    for (id, key) in old {
        if let Some(k) = key
            && let Err(e) = st.storage.delete(&k).await
        {
            warn!(run = %id, "deleting an old report PDF: {e:#}");
        }
        sqlx::query("DELETE FROM report_runs WHERE id = $1").bind(id).execute(&st.db).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    #[test]
    fn ranges_follow_the_schedules_time_zone() {
        let auckland: chrono_tz::Tz = "Pacific/Auckland".parse().unwrap();
        let utc = chrono_tz::UTC;
        // 31 Dec 2026 20:00 UTC is already 1 January 2027 in Auckland.
        let at = Utc.with_ymd_and_hms(2026, 12, 31, 20, 0, 0).unwrap();
        assert_eq!(Preset::LastMonth.resolve(at, utc), (d("2026-11-01"), d("2026-11-30")));
        assert_eq!(Preset::LastMonth.resolve(at, auckland), (d("2026-12-01"), d("2026-12-31")));
        assert_eq!(Preset::LastQuarter.resolve(at, utc), (d("2026-07-01"), d("2026-09-30")));
        assert_eq!(Preset::LastQuarter.resolve(at, auckland), (d("2026-10-01"), d("2026-12-31")));
        // 1 March in a leap year and not.
        assert_eq!(Preset::LastMonth.resolve(Utc.with_ymd_and_hms(2028, 3, 1, 9, 0, 0).unwrap(), utc), (d("2028-02-01"), d("2028-02-29")));
        assert_eq!(Preset::LastMonth.resolve(Utc.with_ymd_and_hms(2027, 3, 1, 9, 0, 0).unwrap(), utc), (d("2027-02-01"), d("2027-02-28")));
        // January: last quarter is the previous year's fourth.
        assert_eq!(Preset::LastQuarter.resolve(Utc.with_ymd_and_hms(2027, 1, 15, 9, 0, 0).unwrap(), utc), (d("2026-10-01"), d("2026-12-31")));
        // Weeks run Monday to Sunday; on a Monday, last week is the one that just ended.
        let monday = Utc.with_ymd_and_hms(2026, 11, 23, 7, 0, 0).unwrap();
        assert_eq!(Preset::LastWeek.resolve(monday, utc), (d("2026-11-16"), d("2026-11-22")));
        assert_eq!(Preset::LastWeek.resolve(Utc.with_ymd_and_hms(2026, 11, 29, 23, 0, 0).unwrap(), utc), (d("2026-11-16"), d("2026-11-22")));
        assert_eq!(Preset::Last30Days.resolve(monday, utc), (d("2026-10-24"), d("2026-11-22")));
    }

    #[test]
    fn presets_parse_with_defaults() {
        assert_eq!(preset_of(Kind::Qbr, &json!({})), Ok(Preset::LastQuarter));
        assert_eq!(preset_of(Kind::ServiceDesk, &json!({})), Ok(Preset::LastMonth));
        assert_eq!(preset_of(Kind::Utilisation, &json!({ "range": "last_week" })), Ok(Preset::LastWeek));
        assert!(preset_of(Kind::Utilisation, &json!({ "range": "yesterday" })).is_err());
    }

    fn user(role: &str, clients: Option<Vec<Uuid>>, perms: Option<Vec<&str>>) -> User {
        User {
            id: Uuid::new_v4(),
            email: "u@example.com".into(),
            name: "U".into(),
            role: role.into(),
            totp_enabled: false,
            mfa_enabled: false,
            mfa_setup_required: false,
            sso_session: false,
            sso_only: false,
            client_ids: clients,
            permissions: perms.map(|p| p.into_iter().map(String::from).collect()),
            session_id: Uuid::nil(),
            api_key: None,
        }
    }

    #[test]
    fn contacts_get_only_their_own_clients_reports() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        assert!(recipient_rule(Kind::Qbr, Some(a), a).is_ok());
        assert!(recipient_rule(Kind::ServiceDesk, Some(a), a).is_ok());
        assert!(recipient_rule(Kind::Qbr, Some(a), b).is_err());
        assert!(recipient_rule(Kind::ServiceDesk, None, a).is_err());
        assert!(recipient_rule(Kind::Profitability, None, a).is_err());
        assert!(recipient_rule(Kind::Utilisation, Some(a), a).is_err());
    }

    #[test]
    fn users_get_what_they_could_open() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let admin = user("admin", None, None);
        let tech = user("technician", None, None);
        let narrow = user("technician", Some(vec![a]), None);
        let billing = user("technician", None, Some(vec!["billing.read"]));
        assert!(cannot_view(&tech, Kind::Profitability, None).unwrap().contains("billing.read"));
        assert!(cannot_view(&billing, Kind::Profitability, None).is_none());
        assert!(cannot_view(&billing, Kind::Utilisation, None).is_none());
        assert!(cannot_view(&narrow, Kind::Qbr, Some(b)).is_some());
        assert!(cannot_view(&narrow, Kind::Qbr, Some(a)).is_none());
        // A narrower recipient doesn't get an all-clients report, but does get one client's.
        assert!(cannot_receive(&narrow, &admin, Kind::ServiceDesk, None).is_some());
        assert!(cannot_receive(&narrow, &admin, Kind::ServiceDesk, Some(a)).is_none());
        assert!(cannot_receive(&admin, &narrow, Kind::ServiceDesk, None).is_none());
        assert!(cannot_receive(&tech, &admin, Kind::Utilisation, None).is_some());
    }

    #[test]
    fn emails_and_bodies() {
        assert!(valid_email("ops@example.com") && !valid_email("nope") && !valid_email("a@b") && !valid_email("a b@example.com") && !valid_email("<a@x.com>"));
        let body = email_body("  Here it is.  ", "Client profitability", "1 – 31 October 2026", "Monthly", "Acme IT");
        assert_eq!(body, "Hello,\n\nHere it is.\n\nAttached: Client profitability, 1 – 31 October 2026 (PDF).\n\nYou receive this report from the schedule \"Monthly\".\n\nAcme IT\n");
        assert!(!email_body("", "T", "S", "N", "B").contains("\n\n\n"));
    }
}
