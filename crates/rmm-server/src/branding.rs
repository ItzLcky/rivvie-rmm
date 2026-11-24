//! White-labelling (docs/design/branding.md).
//!
//! The `branding` table has one row for the instance (`client_id` NULL) and at most one per
//! client. [`resolve`] merges them field by field: the client's value, else the instance's,
//! else the built-in default. Every row is cached in [`AppState::branding`] (there are only a
//! handful), so resolving never touches the database; the API reloads the cache after a write.
//!
//! Other modules use [`resolve`] and the [`Branding`] it returns: the product name, the support
//! card, the accent palette, and [`image`] for the uploaded logos and icon (the PWA manifest,
//! reports and the MSI icon read them that way).
//!
//! The licence (AGPL-3.0-or-later, §13) needs a source offer to network users whatever the
//! branding says: [`Branding::source_url`] is always set, and the console and portal always
//! show a "Licence and source" link to it.

use std::collections::HashMap;
use std::io::Write as _;
use std::sync::RwLock;

use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::state::AppState;

/// What the product is called when nothing is branded.
pub const BUILT_IN_NAME: &str = "RMM";
/// Uploaded images: PNG or JPEG, at most this many bytes.
pub const IMAGE_MAX_BYTES: usize = 512 * 1024;
/// Where the source of the running server is offered (RMM_SOURCE_URL overrides it).
pub const DEFAULT_SOURCE_URL: &str = "https://github.com/ItzLcky/rivvie-rmm";

/// A stored `branding` row. Every field but the scope is optional.
#[derive(Debug, Clone, Default, sqlx::FromRow, Serialize)]
pub struct Row {
    pub client_id: Option<Uuid>,
    pub product_name: Option<String>,
    #[serde(skip)]
    pub logo_light: Option<String>,
    #[serde(skip)]
    pub logo_dark: Option<String>,
    #[serde(skip)]
    pub icon: Option<String>,
    pub accent: Option<String>,
    pub support_email: Option<String>,
    pub support_phone: Option<String>,
    pub support_url: Option<String>,
    pub support_hours: Option<String>,
    pub email_from_name: Option<String>,
    pub email_footer: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub const COLUMNS: &str = "client_id, product_name, logo_light, logo_dark, icon, accent, support_email, support_phone, support_url,
    support_hours, email_from_name, email_footer, updated_at";

/// Every branding row, by client (None = the instance).
#[derive(Default)]
pub struct Cache(RwLock<HashMap<Option<Uuid>, Row>>);

impl Cache {
    pub async fn load(db: &PgPool) -> sqlx::Result<Self> {
        let c = Cache::default();
        c.reload(db).await?;
        Ok(c)
    }

    pub async fn reload(&self, db: &PgPool) -> sqlx::Result<()> {
        let rows: Vec<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {COLUMNS} FROM branding"))).fetch_all(db).await?;
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = rows.into_iter().map(|r| (r.client_id, r)).collect();
        Ok(())
    }

    pub fn row(&self, client_id: Option<Uuid>) -> Option<Row> {
        self.0.read().unwrap_or_else(|e| e.into_inner()).get(&client_id).cloned()
    }
}

/// The three uploadable images.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    LogoLight,
    LogoDark,
    Icon,
}

impl Variant {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "logo_light" => Variant::LogoLight,
            "logo_dark" => Variant::LogoDark,
            "icon" => Variant::Icon,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Variant::LogoLight => "logo_light",
            Variant::LogoDark => "logo_dark",
            Variant::Icon => "icon",
        }
    }

    fn key(self, r: &Row) -> Option<&str> {
        match self {
            Variant::LogoLight => r.logo_light.as_deref(),
            Variant::LogoDark => r.logo_dark.as_deref(),
            Variant::Icon => r.icon.as_deref(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Support {
    pub email: Option<String>,
    pub phone: Option<String>,
    pub url: Option<String>,
    pub hours: Option<String>,
}

/// The branding in effect for one audience: an instance's staff and its sign-in pages
/// (`resolve(st, None)`), or one client's people (`resolve(st, Some(client))`).
#[derive(Debug, Clone, Serialize)]
pub struct Branding {
    /// The configured product name, if any.
    pub product_name: Option<String>,
    /// What to call the product: the configured name, else "<company> RMM", else "RMM".
    pub name: String,
    /// Image URLs (with a version so a new upload isn't cached over), if uploaded.
    pub logo_light: Option<String>,
    pub logo_dark: Option<String>,
    pub icon: Option<String>,
    /// `#rrggbb`, and the palette the web app derives from it.
    pub accent: Option<String>,
    pub theme: Option<Theme>,
    pub support: Support,
    /// The AGPL source offer; always shown.
    pub source_url: String,
    /// Sender name on outgoing mail: the configured one, else the company name, else "Support".
    #[serde(skip)]
    pub email_from_name: String,
    #[serde(skip)]
    pub email_footer: Option<String>,
    /// Storage keys of the images, and whose row each came from.
    #[serde(skip)]
    keys: [Option<(String, Option<Uuid>)>; 3],
}

impl Branding {
    /// The Windows service and installer name: "Acme Remote Agent", or "RMM Agent".
    pub fn agent_name(&self) -> String {
        format!("{} Agent", self.product_name.as_deref().unwrap_or(BUILT_IN_NAME))
    }

    /// For file names: "acme-remote", or "rmm".
    pub fn slug(&self) -> String {
        slug(self.product_name.as_deref().unwrap_or(BUILT_IN_NAME))
    }

    /// The storage key of an image, if one applies.
    pub fn image_key(&self, v: Variant) -> Option<&str> {
        self.keys[v as usize].as_ref().map(|(k, _)| k.as_str())
    }
}

fn pick(client: Option<&Row>, instance: Option<&Row>, f: impl Fn(&Row) -> Option<&String>) -> Option<String> {
    client.and_then(&f).or_else(|| instance.and_then(&f)).filter(|s| !s.trim().is_empty()).cloned()
}

/// The branding a client's people see (`Some`), or the instance's (`None`).
pub fn resolve(st: &AppState, client_id: Option<Uuid>) -> Branding {
    let instance = st.branding.row(None);
    let client = client_id.and_then(|c| st.branding.row(Some(c)));
    resolve_rows(client.as_ref(), instance.as_ref(), &st.company().company_name, &st.cfg.source_url)
}

pub fn resolve_rows(client: Option<&Row>, instance: Option<&Row>, company: &str, source_url: &str) -> Branding {
    let company = company.trim();
    let product_name = pick(client, instance, |r| r.product_name.as_ref());
    let name = match &product_name {
        Some(p) => p.clone(),
        None if company.is_empty() => BUILT_IN_NAME.into(),
        None => format!("{company} {BUILT_IN_NAME}"),
    };
    let key = |v: Variant| {
        client
            .and_then(|r| v.key(r).map(|k| (k.to_string(), r.client_id)))
            .or_else(|| instance.and_then(|r| v.key(r).map(|k| (k.to_string(), None))))
    };
    let keys = [key(Variant::LogoLight), key(Variant::LogoDark), key(Variant::Icon)];
    let url = |v: Variant| {
        keys[v as usize].as_ref().map(|(k, owner)| {
            let base = if owner.is_some() { "/api/portal/branding" } else { "/api/branding" };
            format!("{base}/{}?v={}", v.as_str(), etag(k))
        })
    };
    let accent = pick(client, instance, |r| r.accent.as_ref());
    let theme = accent.as_deref().and_then(|a| parse_hex(a).ok()).and_then(|c| theme(c).ok());
    let email_from_name = pick(client, instance, |r| r.email_from_name.as_ref())
        .unwrap_or_else(|| if company.is_empty() { "Support".into() } else { company.to_string() });
    Branding {
        product_name,
        name,
        logo_light: url(Variant::LogoLight),
        logo_dark: url(Variant::LogoDark),
        icon: url(Variant::Icon),
        accent,
        theme,
        support: Support {
            email: pick(client, instance, |r| r.support_email.as_ref()),
            phone: pick(client, instance, |r| r.support_phone.as_ref()),
            url: pick(client, instance, |r| r.support_url.as_ref()),
            hours: pick(client, instance, |r| r.support_hours.as_ref()),
        },
        source_url: source_url.to_string(),
        email_from_name,
        email_footer: pick(client, instance, |r| r.email_footer.as_ref()),
        keys,
    }
}

/// An uploaded image's bytes and content type, for the branding in effect.
pub async fn image(st: &AppState, client_id: Option<Uuid>, v: Variant) -> anyhow::Result<Option<(Vec<u8>, &'static str, String)>> {
    let b = resolve(st, client_id);
    let Some(key) = b.image_key(v) else { return Ok(None) };
    let bytes = st.storage.get(key).await?;
    let ct = match sniff(&bytes) {
        Some(Format::Png) => "image/png",
        Some(Format::Jpeg) => "image/jpeg",
        None => return Ok(None),
    };
    Ok(Some((bytes, ct, etag(key))))
}

/// The PDF form of the light logo in effect, for report and invoice headers.
pub async fn pdf_logo(st: &AppState, client_id: Option<Uuid>) -> Option<crate::pdf::Image> {
    match image(st, client_id, Variant::LogoLight).await {
        Ok(Some((bytes, _, _))) => pdf_image(&bytes).ok(),
        Ok(None) => None,
        Err(e) => {
            tracing::warn!("branding logo for a PDF: {e:#}");
            None
        }
    }
}

/// A short, stable tag for a storage key (keys are unique per upload).
pub fn etag(key: &str) -> String {
    use sha2::Digest;
    hex::encode(&sha2::Sha256::digest(key.as_bytes())[..8])
}

/// Lowercase ASCII letters and digits, words joined by `-`, at most 40 characters.
pub fn slug(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars().flat_map(|c| c.to_lowercase()) {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
        if out.len() >= 40 {
            break;
        }
    }
    let s = out.trim_end_matches('-').to_string();
    if s.is_empty() { "rmm".into() } else { s }
}

// ---------------------------------------------------------------------------
// Colour
// ---------------------------------------------------------------------------

pub type Rgb = (u8, u8, u8);

const WHITE: Rgb = (0xff, 0xff, 0xff);
/// The ink of the design tokens (`--nav-bg`, `--on-cta`).
const INK: Rgb = (0x0c, 0x1b, 0x21);
/// Light theme surfaces: the page and cards.
const LIGHT_SURFACE: Rgb = (0xf3, 0xf5, 0xf4);
/// Dark theme cards (`--raised`); the page is darker still.
const DARK_RAISED: Rgb = (0x13, 0x27, 0x2f);
/// WCAG AA for normal text.
pub const MIN_CONTRAST: f64 = 4.5;

/// `#rrggbb` (either case) to a colour.
pub fn parse_hex(s: &str) -> Result<Rgb, String> {
    let h = s.trim().strip_prefix('#').ok_or("a colour is written #rrggbb")?;
    if h.len() != 6 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("a colour is written #rrggbb".into());
    }
    let byte = |i: usize| u8::from_str_radix(&h[i..i + 2], 16).map_err(|e| e.to_string());
    Ok((byte(0)?, byte(2)?, byte(4)?))
}

pub fn hex((r, g, b): Rgb) -> String {
    format!("#{r:02x}{g:02x}{b:02x}")
}

/// WCAG relative luminance.
pub fn luminance((r, g, b): Rgb) -> f64 {
    let ch = |c: u8| {
        let c = f64::from(c) / 255.0;
        if c <= 0.03928 { c / 12.92 } else { ((c + 0.055) / 1.055).powf(2.4) }
    };
    0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b)
}

pub fn contrast(a: Rgb, b: Rgb) -> f64 {
    let (la, lb) = (luminance(a), luminance(b));
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
}

/// `a` moved `t` (0..1) of the way to `b`.
fn mix(a: Rgb, b: Rgb, t: f64) -> Rgb {
    let m = |x: u8, y: u8| (f64::from(x) + (f64::from(y) - f64::from(x)) * t).round().clamp(0.0, 255.0) as u8;
    (m(a.0, b.0), m(a.1, b.1), m(a.2, b.2))
}

/// `c` moved toward `toward` just far enough to reach [`MIN_CONTRAST`] against `bg`.
fn until_readable(c: Rgb, toward: Rgb, bg: Rgb) -> Rgb {
    (0..=20).map(|i| mix(c, toward, f64::from(i) / 20.0)).find(|&x| contrast(x, bg) >= MIN_CONTRAST).unwrap_or(toward)
}

/// White or ink, whichever reads better on `c`.
fn on(c: Rgb) -> Rgb {
    if contrast(WHITE, c) >= contrast(INK, c) { WHITE } else { INK }
}

/// The accent tokens of one theme (the names of the CSS variables in `layout.css`).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Palette {
    pub accent: String,
    pub accent_hover: String,
    pub accent_soft: String,
    pub on_accent: String,
    pub accent_ink: String,
    pub cta: String,
    pub cta_hover: String,
    pub on_cta: String,
    pub focus: String,
    pub nav_indicator: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Theme {
    pub light: Palette,
    pub dark: Palette,
}

/// The palette both themes use for an accent. The accent itself fills the main buttons, with
/// white or ink text on it, so it must reach 4.5:1 against one of them; links and other text
/// use a shade of it moved toward ink (light theme) or white (dark theme) until they read on
/// that theme's surfaces.
pub fn theme(accent: Rgb) -> Result<Theme, String> {
    let on_cta = on(accent);
    if contrast(on_cta, accent) < MIN_CONTRAST {
        return Err(format!(
            "{} is too close to mid-grey: neither white nor dark text on it reaches {MIN_CONTRAST}:1 (best {:.1}:1). Pick a darker or a lighter colour",
            hex(accent),
            contrast(on_cta, accent)
        ));
    }
    // The hover fill stays readable with the same text colour.
    let cta_hover = [0.12, 0.06, 0.0]
        .iter()
        .map(|&t| mix(accent, if on_cta == INK { WHITE } else { INK }, t))
        .find(|&c| contrast(on_cta, c) >= MIN_CONTRAST)
        .unwrap_or(accent);
    let nav_indicator = until_readable(accent, WHITE, INK);
    let palette = |text: Rgb, toward: Rgb, soft_base: Rgb, soft_t: f64| {
        let hover = mix(text, toward, 0.3);
        let soft = mix(accent, soft_base, soft_t);
        let ink = until_readable(text, toward, soft);
        Palette {
            accent: hex(text),
            accent_hover: hex(hover),
            accent_soft: hex(soft),
            on_accent: hex(on(text)),
            accent_ink: hex(ink),
            cta: hex(accent),
            cta_hover: hex(cta_hover),
            on_cta: hex(on_cta),
            focus: hex(text),
            nav_indicator: hex(nav_indicator),
        }
    };
    let light_text = until_readable(accent, INK, LIGHT_SURFACE);
    let dark_text = until_readable(accent, WHITE, DARK_RAISED);
    Ok(Theme { light: palette(light_text, INK, WHITE, 0.88), dark: palette(dark_text, WHITE, INK, 0.78) })
}

/// The accent as stored: lowercase `#rrggbb`, after checking it can be used.
pub fn validate_accent(s: &str) -> Result<String, String> {
    let c = parse_hex(s)?;
    theme(c)?;
    Ok(hex(c))
}

// ---------------------------------------------------------------------------
// Images
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Png,
    Jpeg,
}

pub fn sniff(b: &[u8]) -> Option<Format> {
    if b.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some(Format::Png)
    } else if b.starts_with(&[0xff, 0xd8, 0xff]) {
        Some(Format::Jpeg)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageInfo {
    pub format: Format,
    pub width: u32,
    pub height: u32,
}

/// Checks an upload: PNG or JPEG (no SVG), at most 512 KiB, and a sensible size. The icon is
/// a square PNG (it becomes the `.ico` and the app icons), 64 to 1024 pixels; logos are 16 to
/// 2048 pixels each way.
pub fn check_image(v: Variant, bytes: &[u8]) -> Result<ImageInfo, String> {
    if bytes.len() > IMAGE_MAX_BYTES {
        return Err(format!("images are limited to {} KiB", IMAGE_MAX_BYTES / 1024));
    }
    let info = match sniff(bytes) {
        Some(Format::Png) => {
            let (w, h, _, _) = decode_png(bytes)?;
            ImageInfo { format: Format::Png, width: w, height: h }
        }
        Some(Format::Jpeg) => {
            let (w, h, _) = jpeg_info(bytes)?;
            ImageInfo { format: Format::Jpeg, width: w, height: h }
        }
        None => return Err("upload a PNG or JPEG image".into()),
    };
    if v == Variant::Icon {
        if info.format != Format::Png {
            return Err("the icon must be a PNG".into());
        }
        if info.width != info.height || !(64..=1024).contains(&info.width) {
            return Err(format!("the icon must be square, 64 to 1024 pixels (this one is {}x{})", info.width, info.height));
        }
    } else if !(16..=2048).contains(&info.width) || !(16..=2048).contains(&info.height) {
        return Err(format!("logos must be 16 to 2048 pixels each way (this one is {}x{})", info.width, info.height));
    }
    Ok(info)
}

/// Width, height, 8-bit RGB samples, and the 8-bit alpha channel when there is one.
type Decoded = (u32, u32, Vec<u8>, Option<Vec<u8>>);

/// Decodes a PNG to 8-bit RGB and, when it has one, an 8-bit alpha channel.
fn decode_png(bytes: &[u8]) -> Result<Decoded, String> {
    let mut dec = png::Decoder::new(std::io::Cursor::new(bytes));
    dec.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    // A tiny file can claim a huge image: check the header before allocating for it.
    let mut reader = dec.read_info().map_err(|e| format!("not a readable PNG: {e}"))?;
    let (w, h) = (reader.info().width, reader.info().height);
    if w > 4096 || h > 4096 {
        return Err(format!("the image is too large ({w}x{h})"));
    }
    let mut buf = vec![0; reader.output_buffer_size().ok_or("the image is too large")?];
    let frame = reader.next_frame(&mut buf).map_err(|e| format!("not a readable PNG: {e}"))?;
    let data = &buf[..frame.buffer_size()];
    let px = (w as usize) * (h as usize);
    let (mut rgb, mut alpha) = (Vec::with_capacity(px * 3), Vec::with_capacity(px));
    match frame.color_type {
        png::ColorType::Rgb => rgb.extend_from_slice(data),
        png::ColorType::Rgba => data.as_chunks::<4>().0.iter().for_each(|p| {
            rgb.extend_from_slice(&p[..3]);
            alpha.push(p[3]);
        }),
        png::ColorType::Grayscale => data.iter().for_each(|&g| rgb.extend_from_slice(&[g, g, g])),
        png::ColorType::GrayscaleAlpha => data.as_chunks::<2>().0.iter().for_each(|p| {
            rgb.extend_from_slice(&[p[0], p[0], p[0]]);
            alpha.push(p[1]);
        }),
        png::ColorType::Indexed => return Err("unsupported PNG colour type".into()),
    }
    if rgb.len() != px * 3 {
        return Err("not a readable PNG".into());
    }
    let alpha = (!alpha.is_empty() && alpha.iter().any(|&a| a != 255)).then_some(alpha);
    Ok((w, h, rgb, alpha))
}

/// Width, height and colour components from a JPEG's start-of-frame marker.
fn jpeg_info(b: &[u8]) -> Result<(u32, u32, u8), String> {
    let bad = || "not a readable JPEG".to_string();
    let mut i = 2;
    while i + 4 <= b.len() {
        if b[i] != 0xff {
            return Err(bad());
        }
        let marker = b[i + 1];
        if marker == 0xff {
            i += 1;
            continue;
        }
        if matches!(marker, 0xd8 | 0x01 | 0xd0..=0xd7) {
            i += 2;
            continue;
        }
        let len = usize::from(u16::from_be_bytes([b[i + 2], b[i + 3]]));
        // SOF0..SOF15, except DHT (C4), JPG (C8) and DAC (CC).
        if matches!(marker, 0xc0..=0xcf) && !matches!(marker, 0xc4 | 0xc8 | 0xcc) {
            let s = b.get(i + 4..i + 2 + len).filter(|s| s.len() >= 6).ok_or_else(bad)?;
            let h = u32::from(u16::from_be_bytes([s[1], s[2]]));
            let w = u32::from(u16::from_be_bytes([s[3], s[4]]));
            let comps = s[5];
            if !matches!(comps, 1 | 3) {
                return Err("CMYK JPEGs aren't supported: save it as RGB".into());
            }
            return Ok((w, h, comps));
        }
        if marker == 0xda || len < 2 {
            break;
        }
        i += 2 + len;
    }
    Err(bad())
}

/// The image as a PDF image XObject: JPEGs as they are (DCTDecode), PNGs as Flate-compressed
/// RGB with the alpha channel as a soft mask.
pub fn pdf_image(bytes: &[u8]) -> Result<crate::pdf::Image, String> {
    match sniff(bytes) {
        Some(Format::Jpeg) => {
            let (w, h, comps) = jpeg_info(bytes)?;
            Ok(crate::pdf::Image { width: w, height: h, data: bytes.to_vec(), dct: true, gray: comps == 1, smask: None })
        }
        Some(Format::Png) => {
            let (w, h, rgb, alpha) = decode_png(bytes)?;
            let z = |d: &[u8]| -> Result<Vec<u8>, String> {
                let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                e.write_all(d).map_err(|e| e.to_string())?;
                e.finish().map_err(|e| e.to_string())
            };
            Ok(crate::pdf::Image { width: w, height: h, data: z(&rgb)?, dct: false, gray: false, smask: alpha.as_deref().map(z).transpose()? })
        }
        None => Err("not a PNG or JPEG".into()),
    }
}

/// A one-image `.ico` that wraps the PNG as it is (Windows Vista and later read those).
pub fn ico(png: &[u8], width: u32, height: u32) -> Vec<u8> {
    let dim = |d: u32| if d >= 256 { 0 } else { d as u8 };
    let mut out = Vec::with_capacity(22 + png.len());
    out.extend_from_slice(&[0, 0, 1, 0, 1, 0]); // reserved, type 1 (icon), one image
    out.extend_from_slice(&[dim(width), dim(height), 0, 0]); // size, no palette, reserved
    out.extend_from_slice(&1u16.to_le_bytes()); // colour planes
    out.extend_from_slice(&32u16.to_le_bytes()); // bits per pixel
    out.extend_from_slice(&(png.len() as u32).to_le_bytes());
    out.extend_from_slice(&22u32.to_le_bytes()); // offset of the image
    out.extend_from_slice(png);
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A small RGBA PNG (`w`x`h`, half transparent), for tests.
    pub fn sample_png(w: u32, h: u32) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut out, w, h);
            enc.set_color(png::ColorType::Rgba);
            enc.set_depth(png::BitDepth::Eight);
            let mut wr = enc.write_header().unwrap();
            let data: Vec<u8> = (0..w * h).flat_map(|i| [20, 120, 200, if i % 2 == 0 { 255 } else { 128 }]).collect();
            wr.write_image_data(&data).unwrap();
        }
        out
    }

    /// The header of a baseline JPEG (enough for [`jpeg_info`]).
    fn sample_jpeg(w: u16, h: u16, comps: u8) -> Vec<u8> {
        let mut b = vec![0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10];
        b.extend_from_slice(b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0");
        b.extend_from_slice(&[0xff, 0xc0, 0x00, 8 + 3 * comps, 8]);
        b.extend_from_slice(&h.to_be_bytes());
        b.extend_from_slice(&w.to_be_bytes());
        b.push(comps);
        for c in 0..comps {
            b.extend_from_slice(&[c + 1, 0x11, 0]);
        }
        b.extend_from_slice(&[0xff, 0xd9]);
        b
    }

    #[test]
    fn hex_parsing() {
        assert_eq!(parse_hex("#0F766e"), Ok((0x0f, 0x76, 0x6e)));
        assert_eq!(hex((0x0f, 0x76, 0x6e)), "#0f766e");
        for bad in ["0f766e", "#0f766", "#0f766eff", "#0g766e", "", "#"] {
            assert!(parse_hex(bad).is_err(), "{bad}");
        }
        assert_eq!(validate_accent("#1D4ED8"), Ok("#1d4ed8".into()));
    }

    #[test]
    fn contrast_matches_wcag() {
        assert!((contrast(WHITE, (0, 0, 0)) - 21.0).abs() < 1e-9);
        assert!((contrast((0x77, 0x77, 0x77), WHITE) - 4.48).abs() < 0.01);
        assert_eq!(contrast(INK, WHITE), contrast(WHITE, INK));
    }

    #[test]
    fn mid_tones_are_refused() {
        // About 0.2 luminance: neither white nor ink reaches 4.5:1 on it.
        let err = validate_accent("#808080").unwrap_err();
        assert!(err.contains("Pick a darker or a lighter colour"), "{err}");
        assert!(validate_accent("#14b8a6").is_ok(), "the built-in teal is fine");
        assert!(validate_accent("#ffeb3b").is_ok(), "yellow takes ink text");
        assert!(validate_accent("#000000").is_ok() && validate_accent("#ffffff").is_ok());
    }

    #[test]
    fn every_derived_pair_is_readable_in_both_themes() {
        // A sweep over the colour cube: whatever is accepted gives a readable palette.
        let mut accepted = 0;
        for r in (0..=255).step_by(51) {
            for g in (0..=255).step_by(51) {
                for b in (0..=255).step_by(51) {
                    let Ok(t) = theme((r as u8, g as u8, b as u8)) else { continue };
                    accepted += 1;
                    let c = |s: &str| parse_hex(s).unwrap();
                    for (p, surface) in [(&t.light, LIGHT_SURFACE), (&t.light, WHITE), (&t.dark, DARK_RAISED), (&t.dark, INK)] {
                        let at = format!("{r},{g},{b}: {p:?}");
                        assert!(contrast(c(&p.accent), surface) >= MIN_CONTRAST, "accent text on the surface, {at}");
                        assert!(contrast(c(&p.on_accent), c(&p.accent)) >= MIN_CONTRAST, "text on an accent fill, {at}");
                        assert!(contrast(c(&p.on_cta), c(&p.cta)) >= MIN_CONTRAST, "button text, {at}");
                        assert!(contrast(c(&p.on_cta), c(&p.cta_hover)) >= MIN_CONTRAST, "hovered button text, {at}");
                        assert!(contrast(c(&p.accent_ink), c(&p.accent_soft)) >= MIN_CONTRAST, "text on the soft tint, {at}");
                        assert!(contrast(c(&p.nav_indicator), INK) >= MIN_CONTRAST, "the rail indicator, {at}");
                    }
                }
            }
        }
        assert!(accepted > 150, "most colours are usable ({accepted} of 216)");
    }

    #[test]
    fn slugs() {
        assert_eq!(slug("Acme Remote"), "acme-remote");
        assert_eq!(slug("  Ünïcode & Co.  "), "n-code-co");
        assert_eq!(slug("!!!"), "rmm");
        assert_eq!(slug(&"x".repeat(100)).len(), 40);
    }

    #[test]
    fn image_checks() {
        let png = sample_png(64, 64);
        assert_eq!(check_image(Variant::Icon, &png), Ok(ImageInfo { format: Format::Png, width: 64, height: 64 }));
        assert!(check_image(Variant::Icon, &sample_png(64, 32)).unwrap_err().contains("square"));
        assert!(check_image(Variant::Icon, &sample_png(32, 32)).is_err(), "too small for an icon");
        assert!(check_image(Variant::LogoLight, &sample_png(200, 40)).is_ok());
        assert!(check_image(Variant::LogoLight, &sample_png(8, 8)).is_err());
        let jpeg = sample_jpeg(300, 80, 3);
        assert_eq!(check_image(Variant::LogoDark, &jpeg), Ok(ImageInfo { format: Format::Jpeg, width: 300, height: 80 }));
        assert!(check_image(Variant::Icon, &sample_jpeg(64, 64, 3)).unwrap_err().contains("PNG"));
        assert!(check_image(Variant::LogoDark, &sample_jpeg(300, 80, 4)).unwrap_err().contains("CMYK"));
        assert!(check_image(Variant::LogoLight, b"<svg xmlns='http://www.w3.org/2000/svg'/>").is_err(), "no SVG");
        let mut truncated = png.clone();
        truncated.truncate(40);
        assert!(check_image(Variant::LogoLight, &truncated).is_err());
        let mut big = png.clone();
        big.resize(IMAGE_MAX_BYTES + 1, 0);
        assert!(check_image(Variant::LogoLight, &big).unwrap_err().contains("512 KiB"));
    }

    #[test]
    fn pdf_and_ico_forms() {
        let png = sample_png(10, 4);
        let img = pdf_image(&png).unwrap();
        assert_eq!((img.width, img.height, img.dct), (10, 4, false));
        let mut rgb = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::ZlibDecoder::new(&img.data[..]), &mut rgb).unwrap();
        assert_eq!(rgb.len(), 10 * 4 * 3);
        assert_eq!(&rgb[..3], &[20, 120, 200]);
        assert!(img.smask.is_some(), "the alpha channel becomes a soft mask");
        let j = pdf_image(&sample_jpeg(30, 20, 1)).unwrap();
        assert!(j.dct && j.gray && j.smask.is_none());
        let ico = ico(&png, 10, 4);
        assert_eq!(&ico[..6], &[0, 0, 1, 0, 1, 0]);
        assert_eq!((ico[6], ico[7]), (10, 4));
        assert_eq!(u32::from_le_bytes(ico[18..22].try_into().unwrap()), 22);
        assert_eq!(&ico[22..], &png[..]);
        assert_eq!(super::ico(&png, 256, 256)[6], 0, "256 is written as 0");
    }

    #[test]
    fn resolution_order() {
        let instance = Row {
            product_name: Some("Acme Remote".into()),
            accent: Some("#1d4ed8".into()),
            support_email: Some("help@acme.example".into()),
            logo_light: Some("branding/instance/logo_light-1".into()),
            email_footer: Some("Acme IT, 1 Main St".into()),
            ..Default::default()
        };
        let client = Row {
            client_id: Some(Uuid::nil()),
            support_email: Some("vip@acme.example".into()),
            support_phone: Some("  ".into()),
            logo_dark: Some("branding/client/logo_dark-1".into()),
            email_from_name: Some("Acme for Globex".into()),
            ..Default::default()
        };
        let b = resolve_rows(Some(&client), Some(&instance), "Acme IT", DEFAULT_SOURCE_URL);
        assert_eq!(b.name, "Acme Remote");
        assert_eq!(b.support.email.as_deref(), Some("vip@acme.example"), "the client's value wins");
        assert_eq!(b.support.phone, None, "blank is unset");
        assert_eq!(b.email_from_name, "Acme for Globex");
        assert_eq!(b.email_footer.as_deref(), Some("Acme IT, 1 Main St"), "the instance's when the client has none");
        assert!(b.logo_light.as_deref().unwrap().starts_with("/api/branding/logo_light?v="));
        assert!(b.logo_dark.as_deref().unwrap().starts_with("/api/portal/branding/logo_dark?v="), "a client's own image is served to its contacts");
        assert!(b.theme.is_some());
        assert_eq!(b.agent_name(), "Acme Remote Agent");
        assert_eq!(b.slug(), "acme-remote");

        let plain = resolve_rows(None, None, "Acme IT", DEFAULT_SOURCE_URL);
        assert_eq!((plain.name.as_str(), plain.agent_name().as_str(), plain.slug().as_str()), ("Acme IT RMM", "RMM Agent", "rmm"));
        assert_eq!(plain.email_from_name, "Acme IT");
        assert!(plain.theme.is_none() && plain.logo_light.is_none());
        assert_eq!(resolve_rows(None, None, "", DEFAULT_SOURCE_URL).email_from_name, "Support");
        assert!(!plain.source_url.is_empty(), "the source offer is always there");
    }
}
