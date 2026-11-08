//! Server-side sorting and keyset pagination for list endpoints.
//!
//! A page is addressed by an opaque cursor holding the sort key and id of the row it starts
//! after (`after`) or ends before (`before`), so pages stay stable while rows are added and
//! no `OFFSET` scan is needed. Every sort expression must be non-null (wrap it in
//! `coalesce`), because the keyset comparison is a row comparison `(key, id) > (k, i)`.
//!
//! Query parameters: `sort`, `dir` (`asc`/`desc`), `after` or `before`, `limit`.

use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ApiResult};

/// One sortable column: the name the API accepts, a non-null SQL expression, and its type.
pub struct SortKey {
    pub name: &'static str,
    pub expr: &'static str,
    pub ty: &'static str,
}

#[derive(Deserialize, Default)]
pub struct PageQuery {
    pub sort: Option<String>,
    pub dir: Option<String>,
    pub after: Option<String>,
    pub before: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    /// Cursor for the next page (`?after=`), if there is one.
    pub next: Option<String>,
    /// Cursor for the previous page (`?before=`), if this isn't the first.
    pub prev: Option<String>,
    /// Rows matching the filters, counted up to [`COUNT_CAP`].
    pub total: i64,
    /// False when there are more than [`COUNT_CAP`] rows.
    pub total_exact: bool,
}

/// Counting stops here, so a huge job table doesn't cost a full scan per page view.
pub const COUNT_CAP: i64 = 10_000;
pub const MAX_LIMIT: i64 = 500;

/// A resolved sort and page: SQL fragments to splice in, plus the cursor values to bind.
pub struct Plan {
    /// `expr::text AS sort_key`, for the select list.
    pub key_select: String,
    /// `AND (expr, id) > ($n::text::ty, $m::text::idty)`, or empty on the first page.
    pub keyset: String,
    pub order: String,
    /// Fetch one more than this to learn whether another page follows.
    pub limit: i64,
    /// Bind these two (as text) at `first_param` and `first_param + 1` when `keyset` is set.
    pub cursor: Option<(String, String)>,
    backwards: bool,
    had_cursor: bool,
}

#[derive(Serialize, Deserialize)]
struct Cursor(String, String);

fn encode(key: &str, id: &str) -> String {
    BASE64URL_NOPAD.encode(serde_json::to_string(&Cursor(key.into(), id.into())).unwrap_or_default().as_bytes())
}

fn decode(s: &str) -> ApiResult<Cursor> {
    let bad = || ApiError::BadRequest("invalid page cursor".into());
    let bytes = BASE64URL_NOPAD.decode(s.as_bytes()).map_err(|_| bad())?;
    serde_json::from_slice(&bytes).map_err(|_| bad())
}

impl Plan {
    /// `id_expr`/`id_ty` break ties so the order is total. `first_param` is the next free
    /// `$n` in the caller's query.
    pub fn new(
        keys: &[SortKey],
        default: (&str, bool),
        q: &PageQuery,
        id_expr: &str,
        id_ty: &str,
        first_param: usize,
    ) -> ApiResult<Plan> {
        let name = q.sort.as_deref().filter(|s| !s.is_empty()).unwrap_or(default.0);
        let key = keys.iter().find(|k| k.name == name).ok_or_else(|| ApiError::BadRequest(format!("cannot sort by {name}")))?;
        let desc = match q.dir.as_deref() {
            Some("asc") => false,
            Some("desc") => true,
            None | Some("") => if name == default.0 { default.1 } else { false },
            Some(d) => return Err(ApiError::BadRequest(format!("dir must be asc or desc, not {d}"))),
        };
        let (cursor, backwards) = match (&q.after, &q.before) {
            (Some(_), Some(_)) => return Err(ApiError::BadRequest("pass after or before, not both".into())),
            (Some(a), None) if !a.is_empty() => (Some(decode(a)?), false),
            (None, Some(b)) if !b.is_empty() => (Some(decode(b)?), true),
            _ => (None, false),
        };
        // Walking backwards flips both the comparison and the order; rows are reversed after.
        let ascending = desc == backwards;
        let (cmp, ord) = if ascending { (">", "ASC") } else { ("<", "DESC") };
        let keyset = if cursor.is_some() {
            format!(
                "AND ({expr}, {id_expr}) {cmp} (${a}::text::{ty}, ${b}::text::{id_ty})",
                expr = key.expr,
                ty = key.ty,
                a = first_param,
                b = first_param + 1
            )
        } else {
            String::new()
        };
        Ok(Plan {
            key_select: format!("({})::text AS sort_key", key.expr),
            keyset,
            order: format!("ORDER BY {} {ord}, {id_expr} {ord}", key.expr),
            limit: q.limit.unwrap_or(50).clamp(1, MAX_LIMIT),
            had_cursor: cursor.is_some(),
            cursor: cursor.map(|c| (c.0, c.1)),
            backwards,
        })
    }

    /// `LIMIT n` with the extra look-ahead row.
    pub fn limit_sql(&self) -> String {
        format!("LIMIT {}", self.limit + 1)
    }

    /// Trims the look-ahead row, restores display order and builds the cursors.
    pub fn finish<T>(&self, mut rows: Vec<T>, key: impl Fn(&T) -> (String, String), total: i64) -> Page<T> {
        let more = rows.len() as i64 > self.limit;
        rows.truncate(self.limit as usize);
        if self.backwards {
            rows.reverse();
        }
        let cursor = |r: Option<&T>| r.map(|r| {
            let (k, id) = key(r);
            encode(&k, &id)
        });
        // Forwards: a next page exists if we saw the look-ahead row; a previous one if we
        // started from a cursor. Backwards it's the other way round.
        let (has_next, has_prev) = if self.backwards { (true, more) } else { (more, self.had_cursor) };
        Page {
            next: if has_next { cursor(rows.last()) } else { None },
            prev: if has_prev { cursor(rows.first()) } else { None },
            items: rows,
            total: total.min(COUNT_CAP),
            total_exact: total <= COUNT_CAP,
        }
    }
}

/// Wraps a `FROM ... WHERE ...` body in a capped count.
pub fn count_sql(from_where: &str) -> String {
    format!("SELECT count(*) FROM (SELECT 1 {from_where} LIMIT {}) t", COUNT_CAP + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEYS: &[SortKey] = &[
        SortKey { name: "name", expr: "lower(x.name)", ty: "text" },
        SortKey { name: "ts", expr: "x.ts", ty: "timestamptz" },
    ];

    fn q(sort: &str, dir: &str, after: Option<String>, before: Option<String>) -> PageQuery {
        PageQuery { sort: Some(sort.into()), dir: Some(dir.into()), after, before, limit: Some(2) }
    }

    #[test]
    fn cursor_roundtrip() {
        let c = decode(&encode("2026-01-01 00:00:00+00", "abc")).unwrap();
        assert_eq!((c.0.as_str(), c.1.as_str()), ("2026-01-01 00:00:00+00", "abc"));
        assert!(decode("not-a-cursor!").is_err());
    }

    #[test]
    fn rejects_unknown_sort_and_dir() {
        assert!(Plan::new(KEYS, ("name", false), &q("password", "asc", None, None), "x.id", "uuid", 1).is_err());
        assert!(Plan::new(KEYS, ("name", false), &q("name", "sideways", None, None), "x.id", "uuid", 1).is_err());
    }

    #[test]
    fn default_direction_applies_to_default_key_only() {
        let p = Plan::new(KEYS, ("ts", true), &PageQuery::default(), "x.id", "uuid", 1).unwrap();
        assert!(p.order.contains("DESC"));
        let p = Plan::new(KEYS, ("ts", true), &PageQuery { sort: Some("name".into()), ..Default::default() }, "x.id", "uuid", 1).unwrap();
        assert!(p.order.contains("ASC"));
    }

    #[test]
    fn forward_and_backward_pages() {
        let key = |r: &(&str, &str)| (r.0.to_string(), r.1.to_string());
        // First page: three rows fetched for limit 2, so there's a next page and no previous.
        let p = Plan::new(KEYS, ("name", false), &q("name", "asc", None, None), "x.id", "uuid", 3).unwrap();
        assert!(p.keyset.is_empty());
        let page = p.finish(vec![("a", "1"), ("b", "2"), ("c", "3")], key, 3);
        assert_eq!(page.items, vec![("a", "1"), ("b", "2")]);
        assert!(page.prev.is_none());
        let next = page.next.unwrap();

        let p = Plan::new(KEYS, ("name", false), &q("name", "asc", Some(next), None), "x.id", "uuid", 3).unwrap();
        assert_eq!(p.keyset, "AND (lower(x.name), x.id) > ($3::text::text, $4::text::uuid)");
        assert_eq!(p.cursor.as_ref().unwrap().0, "b");
        let page = p.finish(vec![("c", "3")], key, 3);
        assert!(page.next.is_none() && page.prev.is_some());

        // Back from "c": descending query, rows come back reversed.
        let p = Plan::new(KEYS, ("name", false), &q("name", "asc", None, page.prev), "x.id", "uuid", 3).unwrap();
        assert!(p.keyset.contains(" < ") && p.order.contains("DESC"));
        let page = p.finish(vec![("b", "2"), ("a", "1")], key, 3);
        assert_eq!(page.items, vec![("a", "1"), ("b", "2")]);
        assert!(page.prev.is_none() && page.next.is_some());
    }
}
