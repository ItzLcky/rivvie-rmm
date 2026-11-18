//! Billing core: rates, contract coverage, the block-hours bank, billing cycles and the invoice
//! run. HTTP handlers live in `api::billing` and `api::time`.
//!
//! Money is `i64` minor units with a currency code; quantities are thousandths (`1500` = 1.5),
//! so amounts are exact integers and only ever rounded once, when a quantity meets a price.

use chrono::{Datelike, Duration, NaiveDate, Utc};
use serde_json::json;
use sqlx::PgConnection;
use uuid::Uuid;

/// Digits after the decimal point for a currency (ISO 4217's minor unit).
pub fn minor_digits(currency: &str) -> u32 {
    match currency {
        "JPY" | "KRW" | "ISK" | "CLP" | "VND" | "UGX" | "PYG" | "XAF" | "XOF" => 0,
        "BHD" | "KWD" | "OMR" | "JOD" | "TND" | "LYD" | "IQD" => 3,
        _ => 2,
    }
}

/// `123456, "USD"` → `"USD 1,234.56"`; negatives keep their sign in front.
pub fn money(amount: i64, currency: &str) -> String {
    let digits = minor_digits(currency);
    let scale = 10i64.pow(digits);
    let (sign, abs) = if amount < 0 { ("-", amount.unsigned_abs()) } else { ("", amount as u64) };
    let whole = abs / scale as u64;
    let frac = abs % scale as u64;
    let mut grouped = String::new();
    for (i, c) in whole.to_string().chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(c);
    }
    let whole: String = grouped.chars().rev().collect();
    if digits == 0 { format!("{sign}{currency} {whole}") } else { format!("{sign}{currency} {whole}.{frac:0width$}", width = digits as usize) }
}

/// `1500` → `"1.5"`, `2000` → `"2"`, `1250` → `"1.25"`.
pub fn qty(milli: i64) -> String {
    let s = format!("{}.{:03}", milli / 1000, (milli % 1000).abs());
    let s = s.trim_end_matches('0').trim_end_matches('.').to_string();
    if milli < 0 && !s.starts_with('-') { format!("-{s}") } else { s }
}

/// `quantity × unit price`, rounded half away from zero to a whole minor unit.
pub fn line_amount(quantity_milli: i64, unit_price: i64) -> i64 {
    let p = quantity_milli as i128 * unit_price as i128;
    let r = if p >= 0 { (p + 500) / 1000 } else { (p - 500) / 1000 };
    r as i64
}

/// Minutes at an hourly rate.
pub fn time_amount(minutes: i64, hourly: i64) -> i64 {
    let p = minutes as i128 * hourly as i128;
    ((p + 30) / 60) as i64
}

/// Hours as thousandths: 90 minutes → 1500.
pub fn minutes_milli(minutes: i64) -> i64 {
    (minutes * 1000 + 30) / 60
}

// ---------------------------------------------------------------------------
// Cycles
// ---------------------------------------------------------------------------

pub fn cycle_months(cycle: &str) -> u32 {
    match cycle {
        "quarterly" => 3,
        "annual" => 12,
        _ => 1,
    }
}

fn add_months(d: NaiveDate, months: u32) -> NaiveDate {
    shift_months(d, months as i32)
}

/// The first of the month `months` after (or before) `d`'s month.
fn shift_months(d: NaiveDate, months: i32) -> NaiveDate {
    let total = d.year() * 12 + d.month0() as i32 + months;
    NaiveDate::from_ymd_opt(total.div_euclid(12), total.rem_euclid(12) as u32 + 1, 1).expect("first of a month")
}

/// The calendar-aligned cycle (month, quarter or year) containing `day`: `[start, end]`.
pub fn cycle_of(day: NaiveDate, cycle: &str) -> (NaiveDate, NaiveDate) {
    let m = cycle_months(cycle);
    let first_month = (day.month0() / m) * m;
    let start = NaiveDate::from_ymd_opt(day.year(), first_month + 1, 1).expect("valid");
    (start, add_months(start, m) - Duration::days(1))
}

/// Of the cycle `[start, end]`, the share the contract was active (thousandths), so a contract
/// starting or ending mid-cycle is prorated by days.
pub fn active_fraction(cycle: (NaiveDate, NaiveDate), from: NaiveDate, until: Option<NaiveDate>) -> i64 {
    let (cs, ce) = cycle;
    let s = cs.max(from);
    let e = until.map_or(ce, |u| ce.min(u));
    if e < s {
        return 0;
    }
    let active = (e - s).num_days() + 1;
    let total = (ce - cs).num_days() + 1;
    (active * 1000 + total / 2) / total
}

/// The cycles to bill in a run for `[period_start, period_end]`: those starting in the period,
/// plus the contract's first (partial) cycle if it started in the cycle just before the period
/// and so missed the last run. Excludes cycles outside the contract's dates.
pub fn cycles_due(
    cycle: &str,
    contract_start: NaiveDate,
    contract_end: Option<NaiveDate>,
    period_start: NaiveDate,
    period_end: NaiveDate,
) -> Vec<(NaiveDate, NaiveDate)> {
    let mut out = vec![];
    let first = cycle_of(contract_start, cycle);
    let previous = shift_months(cycle_of(period_start, cycle).0, -(cycle_months(cycle) as i32));
    if first.0 < period_start && first.0 >= previous && first.0 <= period_end {
        out.push(first);
    }
    let mut c = cycle_of(period_start, cycle);
    if c.0 < period_start {
        c = (add_months(c.0, cycle_months(cycle)), add_months(c.1 + Duration::days(1), cycle_months(cycle)) - Duration::days(1));
    }
    while c.0 <= period_end {
        let overlaps = c.1 >= contract_start && contract_end.is_none_or(|e| c.0 <= e);
        if overlaps && !out.contains(&c) {
            out.push(c);
        }
        c = (add_months(c.0, cycle_months(cycle)), add_months(c.1 + Duration::days(1), cycle_months(cycle)) - Duration::days(1));
    }
    out
}

// ---------------------------------------------------------------------------
// Rates and coverage
// ---------------------------------------------------------------------------

/// The hourly rate for a technician's time of a work type on a contract, first match wins:
/// the contract's override for the work type, the technician's work role, the work type's
/// default, the technician's own rate, the company default.
pub async fn rate_for(db: &mut PgConnection, user: Uuid, work_type: Uuid, contract: Option<Uuid>) -> sqlx::Result<i64> {
    sqlx::query_scalar(
        "SELECT coalesce(
            (SELECT rate FROM contract_rate_overrides WHERE contract_id = $3 AND work_type_id = $2),
            (SELECT r.rate FROM users u JOIN work_roles r ON r.id = u.work_role_id WHERE u.id = $1 AND r.rate > 0),
            (SELECT rate FROM work_types WHERE id = $2),
            (SELECT default_rate FROM users WHERE id = $1),
            (SELECT default_rate FROM company_settings))",
    )
    .bind(user)
    .bind(work_type)
    .bind(contract)
    .fetch_one(&mut *db)
    .await
}

#[derive(sqlx::FromRow)]
struct EntryCtx {
    user_id: Uuid,
    client_id: Option<Uuid>,
    work_type_id: Uuid,
    started_at: chrono::DateTime<Utc>,
    minutes: Option<i32>,
    billable: bool,
    type_billable: bool,
}

#[derive(sqlx::FromRow)]
struct ContractCtx {
    id: Uuid,
    kind: String,
    covered_work_type_ids: Vec<Uuid>,
    overage_rate: Option<i64>,
}

/// Works out an approved entry's coverage, rate and amount, and draws block hours from the
/// bank. Undoes an earlier resolution first, so it can run again after a rejection.
pub async fn resolve_entry(db: &mut PgConnection, entry: Uuid) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM contract_bank WHERE time_entry_id = $1").bind(entry).execute(&mut *db).await?;
    let e: EntryCtx = sqlx::query_as(
        "SELECT e.user_id, e.client_id, e.work_type_id, e.started_at, e.minutes, e.billable, w.billable AS type_billable
           FROM time_entries e JOIN work_types w ON w.id = e.work_type_id WHERE e.id = $1",
    )
    .bind(entry)
    .fetch_one(&mut *db)
    .await?;
    let minutes = e.minutes.unwrap_or(0) as i64;
    let set = |coverage: &'static str, contract: Option<Uuid>, rate: Option<i64>, amount: i64| {
        sqlx::query("UPDATE time_entries SET coverage = $2, contract_id = $3, rate = $4, amount = $5, updated_at = now() WHERE id = $1")
            .bind(entry)
            .bind(coverage)
            .bind(contract)
            .bind(rate)
            .bind(amount)
    };
    let Some(client) = e.client_id.filter(|_| e.billable && e.type_billable) else {
        set("non_billable", None, None, 0).execute(&mut *db).await?;
        return Ok(());
    };
    let day = e.started_at.date_naive();
    let contracts: Vec<ContractCtx> = sqlx::query_as(
        "SELECT id, kind, covered_work_type_ids, overage_rate FROM contracts
          WHERE client_id = $1 AND start_date <= $2 AND (end_date IS NULL OR end_date >= $2)
          ORDER BY CASE kind WHEN 'block_hours' THEN 1 WHEN 'time_materials' THEN 2 ELSE 0 END, start_date",
    )
    .bind(client)
    .bind(day)
    .fetch_all(&mut *db)
    .await?;
    // Managed contracts cover their work types outright.
    if let Some(c) = contracts.iter().find(|c| matches!(c.kind.as_str(), "per_device" | "per_user" | "recurring") && c.covered_work_type_ids.contains(&e.work_type_id)) {
        set("covered", Some(c.id), None, 0).execute(&mut *db).await?;
        return Ok(());
    }
    // Block hours: draw from the bank, bill what it can't cover at the overage rate.
    if let Some(c) = contracts
        .iter()
        .find(|c| c.kind == "block_hours" && (c.covered_work_type_ids.is_empty() || c.covered_work_type_ids.contains(&e.work_type_id)))
    {
        let balance: i64 = sqlx::query_scalar("SELECT coalesce(sum(minutes), 0)::bigint FROM contract_bank WHERE contract_id = $1")
            .bind(c.id)
            .fetch_one(&mut *db)
            .await?;
        let drawn = minutes.min(balance.max(0));
        if drawn > 0 {
            sqlx::query("INSERT INTO contract_bank (contract_id, minutes, reason, time_entry_id) VALUES ($1, $2, 'usage', $3)")
                .bind(c.id)
                .bind(-(drawn as i32))
                .bind(entry)
                .execute(&mut *db)
                .await?;
        }
        let over = minutes - drawn;
        let rate = match c.overage_rate {
            Some(r) => r,
            None => rate_for(db, e.user_id, e.work_type_id, Some(c.id)).await?,
        };
        set("block", Some(c.id), Some(rate), time_amount(over, rate)).execute(&mut *db).await?;
        return Ok(());
    }
    // Everything else is billable, at the contract's rates if one applies.
    let contract = contracts.iter().find(|c| c.kind == "time_materials").or(contracts.first()).map(|c| c.id);
    let rate = rate_for(db, e.user_id, e.work_type_id, contract).await?;
    set("billable", contract, Some(rate), time_amount(minutes, rate)).execute(&mut *db).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Invoice run
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct RunContract {
    id: Uuid,
    name: String,
    kind: String,
    start_date: NaiveDate,
    end_date: Option<NaiveDate>,
    billing_cycle: String,
    unit_price: i64,
    device_filter: String,
    user_count: i32,
    block_minutes: i32,
}

struct Line {
    kind: &'static str,
    description: String,
    quantity_milli: i64,
    unit_price: i64,
    amount: i64,
    contract_id: Option<Uuid>,
    product_id: Option<Uuid>,
    details: serde_json::Value,
}

impl Line {
    fn priced(kind: &'static str, description: String, quantity_milli: i64, unit_price: i64, contract_id: Option<Uuid>) -> Self {
        Line { kind, description, quantity_milli, unit_price, amount: line_amount(quantity_milli, unit_price), contract_id, product_id: None, details: json!({}) }
    }
}

fn period_label(c: (NaiveDate, NaiveDate)) -> String {
    format!("{} – {}", c.0.format("%-d %b %Y"), c.1.format("%-d %b %Y"))
}

/// The client's currency, else the company's.
pub async fn currency_of(db: &mut PgConnection, client: Uuid) -> sqlx::Result<String> {
    sqlx::query_scalar("SELECT coalesce((SELECT currency FROM clients WHERE id = $1), (SELECT currency FROM company_settings))")
        .bind(client)
        .fetch_one(&mut *db)
        .await
}

/// Builds a draft invoice for one client for `[from, to]`: contract cycles due (prorated),
/// device and user counts (snapshotted), approved billable time and products not billed yet.
/// Returns `None` when there's nothing to bill.
pub async fn draft_for_client(db: &mut PgConnection, client: Uuid, from: NaiveDate, to: NaiveDate, by: Uuid) -> sqlx::Result<Option<Uuid>> {
    let invoice = Uuid::new_v4();
    let mut lines: Vec<Line> = vec![];
    let mut cycles: Vec<(Uuid, NaiveDate)> = vec![];
    let mut purchases: Vec<(Uuid, i32, String)> = vec![];

    let contracts: Vec<RunContract> = sqlx::query_as(
        "SELECT id, name, kind, start_date, end_date, billing_cycle, unit_price, device_filter, user_count, block_minutes
           FROM contracts WHERE client_id = $1 AND start_date <= $3 AND (end_date IS NULL OR end_date >= $2) AND kind <> 'time_materials'
          ORDER BY start_date, name",
    )
    .bind(client)
    .bind(from)
    .bind(to)
    .fetch_all(&mut *db)
    .await?;
    // Devices are counted once per run: enrolled agents under the client now, servers and
    // workstations by the platform the agent reports (or the server's guess for older builds).
    let agents: Vec<String> =
        sqlx::query_scalar("SELECT a.platform FROM agents a JOIN sites s ON s.id = a.site_id WHERE s.client_id = $1")
            .bind(client)
            .fetch_all(&mut *db)
            .await?;
    for c in &contracts {
        for cyc in cycles_due(&c.billing_cycle, c.start_date, c.end_date, from, to) {
            let billed: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM contract_cycles WHERE contract_id = $1 AND period_start = $2)")
                .bind(c.id)
                .bind(cyc.0)
                .fetch_one(&mut *db)
                .await?;
            let fraction = active_fraction(cyc, c.start_date, c.end_date);
            if billed || fraction == 0 {
                continue;
            }
            cycles.push((c.id, cyc.0));
            let label = period_label(cyc);
            let prorated = if fraction < 1000 { format!(", prorated {}%", (fraction + 5) / 10) } else { String::new() };
            match c.kind.as_str() {
                "per_device" => {
                    let servers = agents.iter().filter(|p| *p == "server").count() as i64;
                    let workstations = agents.len() as i64 - servers;
                    let count = match c.device_filter.as_str() {
                        "servers" => servers,
                        "workstations" => workstations,
                        _ => agents.len() as i64,
                    };
                    let what = match c.device_filter.as_str() {
                        "servers" => "servers",
                        "workstations" => "workstations",
                        _ => "devices",
                    };
                    let mut l = Line::priced("devices", format!("{}: {count} {what}, {label}{prorated}", c.name), count * fraction, c.unit_price, Some(c.id));
                    l.details = json!({ "devices": count, "servers": servers, "workstations": workstations, "filter": c.device_filter,
                                        "fraction_milli": fraction, "period": [cyc.0, cyc.1] });
                    lines.push(l);
                }
                "per_user" => {
                    let mut l = Line::priced("users", format!("{}: {} users, {label}{prorated}", c.name, c.user_count), c.user_count as i64 * fraction, c.unit_price, Some(c.id));
                    l.details = json!({ "users": c.user_count, "fraction_milli": fraction, "period": [cyc.0, cyc.1] });
                    lines.push(l);
                }
                "block_hours" => {
                    let minutes = (c.block_minutes as i64 * fraction / 1000) as i32;
                    let mut l = Line::priced("block", format!("{}: {} hours, {label}{prorated}", c.name, qty(minutes_milli(minutes as i64))), fraction, c.unit_price, Some(c.id));
                    l.details = json!({ "minutes": minutes, "fraction_milli": fraction, "period": [cyc.0, cyc.1] });
                    lines.push(l);
                    purchases.push((c.id, minutes, label.clone()));
                }
                _ => {
                    if c.unit_price > 0 {
                        let mut l = Line::priced("recurring", format!("{}, {label}{prorated}", c.name), fraction, c.unit_price, Some(c.id));
                        l.details = json!({ "fraction_milli": fraction, "period": [cyc.0, cyc.1] });
                        lines.push(l);
                    }
                }
            }
            let items: Vec<(Option<Uuid>, String, i64, i64)> = sqlx::query_as(
                "SELECT product_id, description, quantity_milli, unit_price FROM contract_items WHERE contract_id = $1 ORDER BY position",
            )
            .bind(c.id)
            .fetch_all(&mut *db)
            .await?;
            for (product, description, q, price) in items {
                let q = q * fraction / 1000;
                let mut l = Line::priced("recurring", format!("{description}, {label}{prorated}"), q, price, Some(c.id));
                l.product_id = product;
                lines.push(l);
            }
        }
    }

    // Approved time with something to bill, grouped by work type, rate and coverage.
    #[allow(clippy::type_complexity)]
    let time: Vec<(Uuid, String, i64, String, Option<Uuid>, i64, i64, Vec<Uuid>)> = sqlx::query_as(
        "SELECT e.work_type_id, w.name, e.rate, e.coverage, e.contract_id, sum(e.minutes)::bigint, sum(e.amount)::bigint, array_agg(e.id)
           FROM time_entries e JOIN work_types w ON w.id = e.work_type_id
           JOIN timesheets ts ON ts.user_id = e.user_id AND ts.week_start = (date_trunc('week', e.started_at AT TIME ZONE 'UTC'))::date
          WHERE e.client_id = $1 AND e.invoice_line_id IS NULL AND ts.status = 'approved' AND e.amount > 0
            AND e.coverage IN ('billable', 'block') AND (e.started_at AT TIME ZONE 'UTC')::date <= $2
          GROUP BY 1, 2, 3, 4, 5 ORDER BY 2, 3",
    )
    .bind(client)
    .bind(to)
    .fetch_all(&mut *db)
    .await?;
    let mut time_lines: Vec<(usize, Vec<Uuid>)> = vec![];
    for (wt, name, rate, coverage, contract, minutes, amount, ids) in time {
        let (kind, label) = if coverage == "block" { ("overage", format!("{name}: hours beyond the block")) } else { ("time", name) };
        // Overage lines bill only the minutes the bank didn't cover.
        let billed_minutes = if coverage == "block" { (amount * 60 + rate / 2) / rate.max(1) } else { minutes };
        time_lines.push((lines.len(), ids.clone()));
        lines.push(Line {
            kind,
            description: format!("{label} ({} h)", qty(minutes_milli(billed_minutes))),
            quantity_milli: minutes_milli(billed_minutes),
            unit_price: rate,
            amount,
            contract_id: contract,
            product_id: None,
            details: json!({ "work_type_id": wt, "minutes": minutes, "entries": ids.len() }),
        });
    }

    // Products sold.
    #[allow(clippy::type_complexity)]
    let charges: Vec<(Uuid, Option<Uuid>, String, i64, i64)> = sqlx::query_as(
        "SELECT id, product_id, description, quantity_milli, unit_price FROM charges
          WHERE client_id = $1 AND invoice_line_id IS NULL AND day <= $2 ORDER BY day, created_at",
    )
    .bind(client)
    .bind(to)
    .fetch_all(&mut *db)
    .await?;
    let mut charge_lines: Vec<(usize, Uuid)> = vec![];
    for (id, product, description, q, price) in charges {
        charge_lines.push((lines.len(), id));
        let mut l = Line::priced("product", description, q, price, None);
        l.product_id = product;
        lines.push(l);
    }

    if lines.is_empty() {
        return Ok(None);
    }
    let currency = currency_of(db, client).await?;
    let total: i64 = lines.iter().map(|l| l.amount).sum();
    sqlx::query(
        "INSERT INTO invoices (id, client_id, currency, issue_date, due_date, period_start, period_end, total, created_by)
         VALUES ($1, $2, $3, current_date, current_date + (SELECT invoice_terms_days FROM company_settings), $4, $5, $6, $7)",
    )
    .bind(invoice)
    .bind(client)
    .bind(&currency)
    .bind(from)
    .bind(to)
    .bind(total)
    .bind(by)
    .execute(&mut *db)
    .await?;
    let mut ids = vec![];
    for (pos, l) in lines.iter().enumerate() {
        let id = Uuid::new_v4();
        ids.push(id);
        sqlx::query(
            "INSERT INTO invoice_lines (id, invoice_id, position, kind, description, quantity_milli, unit_price, amount, contract_id, product_id, details)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(id)
        .bind(invoice)
        .bind(pos as i32)
        .bind(l.kind)
        .bind(&l.description)
        .bind(l.quantity_milli)
        .bind(l.unit_price)
        .bind(l.amount)
        .bind(l.contract_id)
        .bind(l.product_id)
        .bind(&l.details)
        .execute(&mut *db)
        .await?;
    }
    for (i, entries) in time_lines {
        sqlx::query("UPDATE time_entries SET invoice_line_id = $2 WHERE id = ANY($1)").bind(&entries).bind(ids[i]).execute(&mut *db).await?;
    }
    for (i, charge) in charge_lines {
        sqlx::query("UPDATE charges SET invoice_line_id = $2 WHERE id = $1").bind(charge).bind(ids[i]).execute(&mut *db).await?;
    }
    for (contract, start) in cycles {
        sqlx::query("INSERT INTO contract_cycles (contract_id, period_start, invoice_id) VALUES ($1, $2, $3)")
            .bind(contract)
            .bind(start)
            .bind(invoice)
            .execute(&mut *db)
            .await?;
    }
    for (contract, minutes, label) in purchases {
        sqlx::query("INSERT INTO contract_bank (contract_id, minutes, reason, invoice_id, note, created_by) VALUES ($1, $2, 'purchase', $3, $4, $5)")
            .bind(contract)
            .bind(minutes)
            .bind(invoice)
            .bind(label)
            .bind(by)
            .execute(&mut *db)
            .await?;
        sqlx::query("UPDATE contracts SET low_balance_warned_at = NULL WHERE id = $1").bind(contract).execute(&mut *db).await?;
    }
    Ok(Some(invoice))
}

/// Recomputes a draft's total from its lines.
pub async fn retotal(db: &mut PgConnection, invoice: Uuid) -> sqlx::Result<i64> {
    sqlx::query_scalar(
        "UPDATE invoices SET total = coalesce((SELECT sum(amount) FROM invoice_lines WHERE invoice_id = $1), 0), updated_at = now()
          WHERE id = $1 RETURNING total",
    )
    .bind(invoice)
    .fetch_one(&mut *db)
    .await
}

/// The next invoice number, taken under a lock so numbers have no gaps.
pub async fn next_number(db: &mut PgConnection) -> sqlx::Result<String> {
    let (n, prefix): (i64, String) = sqlx::query_as(
        "UPDATE invoice_counter SET next = next + 1 WHERE id = 1 RETURNING next - 1, (SELECT invoice_prefix FROM company_settings)",
    )
    .fetch_one(&mut *db)
    .await?;
    Ok(format!("{prefix}{n}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    #[test]
    fn money_and_quantities() {
        assert_eq!(money(123456, "USD"), "USD 1,234.56");
        assert_eq!(money(-5, "EUR"), "-EUR 0.05");
        assert_eq!(money(1500, "JPY"), "JPY 1,500");
        assert_eq!(money(1234, "KWD"), "KWD 1.234");
        assert_eq!(money(100000000, "GBP"), "GBP 1,000,000.00");
        assert_eq!(qty(1500), "1.5");
        assert_eq!(qty(2000), "2");
        assert_eq!(qty(1250), "1.25");
        assert_eq!(qty(-500), "-0.5");
        assert_eq!(line_amount(1500, 1999), 2999); // 29.985 → 29.99
        assert_eq!(line_amount(-1500, 1999), -2999);
        assert_eq!(time_amount(90, 12000), 18000);
        assert_eq!(time_amount(7, 10000), 1167);
        assert_eq!(minutes_milli(90), 1500);
        assert_eq!(minutes_milli(20), 333);
    }

    #[test]
    fn cycles_and_proration() {
        assert_eq!(cycle_of(d("2026-11-12"), "monthly"), (d("2026-11-01"), d("2026-11-30")));
        assert_eq!(cycle_of(d("2026-11-12"), "quarterly"), (d("2026-10-01"), d("2026-12-31")));
        assert_eq!(cycle_of(d("2026-02-12"), "annual"), (d("2026-01-01"), d("2026-12-31")));
        // Started on the 16th of a 30-day month: 15 days.
        assert_eq!(active_fraction((d("2026-11-01"), d("2026-11-30")), d("2026-11-16"), None), 500);
        assert_eq!(active_fraction((d("2026-11-01"), d("2026-11-30")), d("2026-01-01"), Some(d("2026-11-10"))), 333);
        assert_eq!(active_fraction((d("2026-11-01"), d("2026-11-30")), d("2026-12-01"), None), 0);
        // A December run for a monthly contract that started mid-November and wasn't billed yet.
        let due = cycles_due("monthly", d("2026-11-16"), None, d("2026-12-01"), d("2026-12-31"));
        assert_eq!(due, vec![(d("2026-11-01"), d("2026-11-30")), (d("2026-12-01"), d("2026-12-31"))]);
        // A quarterly contract bills in the quarter's first month only.
        assert!(cycles_due("quarterly", d("2026-01-01"), None, d("2026-11-01"), d("2026-11-30")).is_empty());
        assert_eq!(cycles_due("quarterly", d("2026-01-01"), None, d("2026-10-01"), d("2026-10-31")), vec![(d("2026-10-01"), d("2026-12-31"))]);
        // A back-dated contract doesn't bill cycles long gone.
        assert_eq!(cycles_due("monthly", d("2025-03-10"), None, d("2026-12-01"), d("2026-12-31")), vec![(d("2026-12-01"), d("2026-12-31"))]);
        // Ended before the period: nothing.
        assert!(cycles_due("monthly", d("2026-01-01"), Some(d("2026-10-31")), d("2026-11-01"), d("2026-11-30")).is_empty());
        // Starts after the period: nothing.
        assert!(cycles_due("monthly", d("2027-01-05"), None, d("2026-11-01"), d("2026-11-30")).is_empty());
    }
}
