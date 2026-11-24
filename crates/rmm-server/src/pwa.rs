//! The web app manifest that makes the dashboard installable (docs/design/pwa.md).
//!
//! Served by the server rather than as a static file so the name and colours follow the
//! instance's branding. The icons are the dashboard's own (`web/static/icons`).

use std::sync::Arc;

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use serde_json::json;

use crate::state::AppState;

/// What the manifest shows.
pub struct ManifestBrand {
    pub name: String,
    pub short_name: String,
    pub theme_color: String,
    pub background_color: String,
    /// (path, size, purpose)
    pub icons: Vec<(String, &'static str, &'static str)>,
}

/// The single place the manifest takes its branding from.
///
/// COORDINATOR: when the branding track merges, build this from `branding::resolve(None)`
/// (product name, accent colour, and icons resized from the branding icon) instead of the
/// company name and the built-in colours and icons.
pub fn manifest_branding(st: &AppState) -> ManifestBrand {
    let company = st.company().company_name;
    let company = company.trim();
    let name = if company.is_empty() { "RMM".to_string() } else { format!("{company} RMM") };
    let short_name = if company.is_empty() { "RMM".to_string() } else { company.chars().take(12).collect() };
    ManifestBrand {
        name,
        short_name,
        // The navigation rail's colour, and the dark page background.
        theme_color: "#0c1b21".into(),
        background_color: "#0c1b21".into(),
        icons: vec![
            ("/icons/icon-192.png".into(), "192x192", "any"),
            ("/icons/icon-512.png".into(), "512x512", "any"),
            ("/icons/maskable-512.png".into(), "512x512", "maskable"),
        ],
    }
}

pub fn manifest(b: &ManifestBrand) -> serde_json::Value {
    json!({
        "id": "/",
        "name": b.name,
        "short_name": b.short_name,
        "description": "Alerts, pages, tickets and time on the go.",
        "start_url": "/alerts?source=pwa",
        "scope": "/",
        "display": "standalone",
        "orientation": "any",
        "theme_color": b.theme_color,
        "background_color": b.background_color,
        "icons": b.icons.iter().map(|(src, sizes, purpose)| json!({ "src": src, "sizes": sizes, "type": "image/png", "purpose": purpose })).collect::<Vec<_>>(),
    })
}

/// `GET /manifest.webmanifest`
pub async fn handler(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let body = manifest(&manifest_branding(&st));
    ([(header::CONTENT_TYPE, "application/manifest+json"), (header::CACHE_CONTROL, "no-cache")], body.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_is_installable() {
        let b = ManifestBrand {
            name: "Northwind RMM".into(),
            short_name: "Northwind".into(),
            theme_color: "#0c1b21".into(),
            background_color: "#0c1b21".into(),
            icons: vec![("/icons/icon-192.png".into(), "192x192", "any"), ("/icons/icon-512.png".into(), "512x512", "any")],
        };
        let m = manifest(&b);
        // What Chrome's installability check needs.
        assert_eq!(m["display"], "standalone");
        assert!(m["start_url"].as_str().unwrap().starts_with('/'));
        let sizes: Vec<&str> = m["icons"].as_array().unwrap().iter().map(|i| i["sizes"].as_str().unwrap()).collect();
        assert!(sizes.contains(&"192x192") && sizes.contains(&"512x512"));
        assert_eq!(m["name"], "Northwind RMM");
    }
}
