//! Design tokens. Colours are semantic (`Theme::text()`, `Theme::line()`) and
//! come in a light and a dark set.

// Taken whole from Wisp Paper: the parts this app does not use yet are kept, so the two stay alike.
#![allow(dead_code)]

use gpui::{BoxShadow, Font, FontFallbacks, Hsla, Pixels, SharedString, hsla, point, px, rgb};
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use wisp_ops_core::settings::{self, DEFAULT_FONT_SIZE};

pub const UI_FONT: &str = if cfg!(target_os = "linux") { "Noto Sans" } else { ".SystemUIFont" };
/// For code in an answer.
pub const MONO_FONT: &str = if cfg!(target_os = "macos") { "Menlo" } else if cfg!(target_os = "windows") { "Consolas" } else { "DejaVu Sans Mono" };

thread_local! {
    static TYPOGRAPHY: RefCell<(Font, f32)> = RefCell::new((gpui::font(UI_FONT), 1.));
}

/// Applied on the UI thread before refreshing the whole window, including cached child views.
/// `family` draws Latin letters, digits and symbols; `cjk` is its fallback, so it draws what
/// `family` has no glyph for (Chinese). Empty is the platform's own choice for either.
pub fn set_typography(family: &str, cjk: &str, size: f32) {
    let mut font = gpui::font(if family.is_empty() { SharedString::from(UI_FONT) } else { family.to_string().into() });
    if !cjk.is_empty() { font.fallbacks = Some(FontFallbacks::from_fonts(vec![cjk.to_string()])) }
    TYPOGRAPHY.with(|value| *value.borrow_mut() = (font, settings::font_size(size) / DEFAULT_FONT_SIZE));
}

/// The interface font with its Chinese fallback; set with `.font(…)` on a root element.
pub fn ui_font() -> Font {
    TYPOGRAPHY.with(|value| value.borrow().0.clone())
}

/// Text sizes, line heights and text controls share a scale.
pub fn text_px(value: f32) -> Pixels {
    TYPOGRAPHY.with(|typography| px(value * typography.borrow().1))
}

/// Long-form text (an answer): the line height follows the interface size.
pub fn body_line(value: f32) -> Pixels {
    text_px(value)
}

pub fn paragraph_factor() -> f32 {
    1.
}

pub fn paragraph_gap(value: f32) -> Pixels {
    text_px(value)
}

static HIGH_CONTRAST: AtomicBool = AtomicBool::new(false);

pub fn set_high_contrast(enabled: bool) {
    HIGH_CONTRAST.store(enabled, Ordering::Relaxed);
}

fn contrast() -> bool {
    HIGH_CONTRAST.load(Ordering::Relaxed)
}

pub fn c(hex: u32) -> Hsla {
    rgb(hex).into()
}

static DARK: AtomicBool = AtomicBool::new(false);

/// Whether the dark set is in use (设置 › 外观, or the system's choice).
pub fn dark() -> bool {
    DARK.load(Ordering::Relaxed)
}

pub fn set_dark(dark: bool) {
    DARK.store(dark, Ordering::Relaxed);
}

/// The light or the dark value of a token.
fn pick(light: u32, dark_hex: u32) -> Hsla {
    c(if dark() { dark_hex } else { light })
}

/// An accent colour: the strong tone for marks and buttons, the soft one for
/// fills, and the brighter tone that stands in for `strong` on dark surfaces.
#[derive(Clone, Copy)]
pub struct Accent {
    pub key: &'static str,
    strong: u32,
    soft: u32,
    bright: u32,
}

impl Accent {
    pub fn strong(&self) -> Hsla {
        pick(self.strong, self.bright)
    }

    pub fn soft(&self) -> Hsla {
        if dark() { c(self.bright).opacity(0.18) } else { c(self.soft) }
    }
}

pub const ACCENTS: [Accent; 7] = [
    Accent { key: "blue", strong: 0x2F6BDE, soft: 0xE8F0FE, bright: 0x6C9BF2 },
    Accent { key: "green", strong: 0x2E8B57, soft: 0xE4F4EA, bright: 0x57BA85 },
    Accent { key: "amber", strong: 0xB7791F, soft: 0xFBF1DC, bright: 0xDDA94B },
    Accent { key: "rose", strong: 0xC8456B, soft: 0xFCE8EE, bright: 0xE87C9B },
    Accent { key: "violet", strong: 0x7052C8, soft: 0xEEE9FB, bright: 0x9F8AEA },
    Accent { key: "teal", strong: 0x1F8A8A, soft: 0xDFF3F2, bright: 0x4DBCBC },
    Accent { key: "slate", strong: 0x4A5568, soft: 0xE9ECF0, bright: 0x9BA7BA },
];

static ACCENT: AtomicUsize = AtomicUsize::new(0);

pub fn accent_of(key: &str) -> Accent {
    ACCENTS.iter().copied().find(|a| a.key == key).unwrap_or(ACCENTS[0])
}

/// Choose the accent the window is drawn in.
pub fn set_accent(key: &str) {
    ACCENT.store(ACCENTS.iter().position(|a| a.key == key).unwrap_or(0), Ordering::Relaxed);
}

pub struct Theme;

impl Theme {
    /// The window surface the sidebar sits on.
    pub fn bg_window() -> Hsla { pick(0xF5F4F1, 0x1A1B1D) }
    /// The working plane: tables, panels, dialogs.
    pub fn bg_body() -> Hsla { pick(0xFFFFFF, 0x222326) }
    /// Insets on the working plane: inputs at rest, table header, code.
    pub fn bg_sunken() -> Hsla { pick(0xF7F7F5, 0x2A2B2F) }
    pub fn hover() -> Hsla { if dark() { hsla(0., 0., 1., 0.06) } else { hsla(0., 0., 0., 0.045) } }
    pub fn pressed() -> Hsla { if dark() { hsla(0., 0., 1., 0.11) } else { hsla(0., 0., 0., 0.08) } }
    pub fn text() -> Hsla { pick(0x1F2329, 0xE6E7EA) }
    pub fn text_secondary() -> Hsla { if contrast() { pick(0x333942, 0xD8DBE0) } else { pick(0x5C636E, 0xABAFB7) } }
    pub fn text_tertiary() -> Hsla { if contrast() { pick(0x535B66, 0xBBC0C8) } else { pick(0x8F959E, 0x80858E) } }
    pub fn text_placeholder() -> Hsla { if contrast() { pick(0x626B77, 0xA3ABB7) } else { pick(0xB0B5BD, 0x5E636C) } }
    pub fn line() -> Hsla { if contrast() { pick(0x969C95, 0x747A83) } else { pick(0xE7E7E3, 0x333539) } }
    pub fn line_strong() -> Hsla { if contrast() { pick(0x737B74, 0x979EA8) } else { pick(0xD5D6D2, 0x47494F) } }
    pub fn scrim() -> Hsla { hsla(0., 0., 0., if dark() { 0.5 } else { 0.28 }) }
    pub fn danger() -> Hsla { pick(0xD4483B, 0xEB7468) }
    pub fn danger_soft() -> Hsla { pick(0xFDECEA, 0x3B2523) }
    pub fn success() -> Hsla { pick(0x2E8B57, 0x57BA85) }
    /// Something that still wants the reader's attention, short of an error.
    pub fn warning() -> Hsla { pick(0x9A6410, 0xE0B25A) }
    pub fn star() -> Hsla { pick(0xE0A100, 0xE8B92E) }
    pub fn accent() -> Hsla { ACCENTS[ACCENT.load(Ordering::Relaxed)].strong() }
    pub fn accent_soft() -> Hsla { ACCENTS[ACCENT.load(Ordering::Relaxed)].soft() }
    /// Text and icons on an accent or danger fill: the dark set's fills are
    /// bright, so they carry dark text.
    pub fn on_accent() -> Hsla { pick(0xFFFFFF, 0x141518) }
    pub fn selection() -> Hsla { Self::accent().opacity(if dark() { 0.36 } else { 0.22 }) }
    /// The off state of a switch and the groove of a segmented control.
    pub fn groove() -> Hsla { if dark() { hsla(0., 0., 1., 0.12) } else { hsla(0., 0., 0., 0.07) } }
    /// The chosen segment of a segmented control, lighter than its groove.
    // ---- the terminal: its ground, its text, its cursor and the 256 colours programs ask for
    pub fn term_bg() -> Hsla { pick(0xFBFBFA, 0x18191B) }
    pub fn term_fg() -> Hsla { pick(0x24292F, 0xD9DBE0) }
    pub fn term_cursor() -> Hsla { Self::accent().opacity(0.75) }
    /// An indexed colour: the sixteen of the palette (a light and a dark set), the 6×6×6 cube, the greys.
    pub fn term_ansi(index: u8) -> Hsla {
        const LIGHT: [u32; 16] = [0x24292F, 0xCF222E, 0x116329, 0x7D4E00, 0x0969DA, 0x8250DF, 0x1B7C83, 0x6E7781, 0x57606A, 0xA40E26, 0x1A7F37, 0x633C01, 0x218BFF, 0xA475F9, 0x3192AA, 0x8C959F];
        const DARK: [u32; 16] = [0x484F58, 0xFF7B72, 0x3FB950, 0xD29922, 0x58A6FF, 0xBC8CFF, 0x39C5CF, 0xB1BAC4, 0x6E7681, 0xFFA198, 0x56D364, 0xE3B341, 0x79C0FF, 0xD2A8FF, 0x56D4DD, 0xF0F3F6];
        match index {
            0..16 => c(if dark() { DARK } else { LIGHT }[usize::from(index)]),
            16..232 => {
                let n = u32::from(index - 16);
                let level = |v: u32| if v == 0 { 0 } else { 55 + v * 40 };
                c(level(n / 36) << 16 | level(n / 6 % 6) << 8 | level(n % 6))
            }
            _ => {
                let grey = 8 + u32::from(index - 232) * 10;
                c(grey << 16 | grey << 8 | grey)
            }
        }
    }
    pub fn segment() -> Hsla { pick(0xFFFFFF, 0x5A5C63) }
}

/// The tile a model provider's mark is drawn on (设置 › 模型): the service's
/// own colour, from the top of the tile to its bottom, the same in both sets.
pub fn provider_tile(preset: &str) -> (Hsla, Hsla) {
    let (top, bottom) = match preset {
        "deepseek" => (0x6A86FF, 0x3D5AF1),
        "kimi" => (0x3A3D45, 0x111216),
        "glm" => (0x7B6BFF, 0x4338E0),
        "claude" => (0xE69477, 0xC9603E),
        "openai" => (0x19B48E, 0x0B7A5F),
        "gemini" => (0x5B9BFF, 0x7A5CF0),
        "ark" => (0x2FC4D8, 0x1677E0),
        _ => (0x9AA0AA, 0x6E737D),
    };
    (c(top), c(bottom))
}

/// The (text, fill) of a status chip: a server's state, a risk level, a permission.
pub fn status_colors(value: &str) -> (Hsla, Hsla) {
    let (light, fill, bright) = match value {
        "ok" | "allow" | "read" | "verified" => (0x23764A, 0xE4F4EA, 0x63C48F),
        "info" | "grant" | "policy" => (0x2A5FC4, 0xE8F0FE, 0x7CA8F5),
        "warn" | "ask" | "change" | "sudo" => (0x9A6410, 0xFBF1DC, 0xE0B25A),
        "crit" | "deny" | "destructive" | "failed" | "full" => (0xB23B30, 0xFDECEA, 0xEE877C),
        _ => (0x5C636E, 0xEFEFEC, 0xABAFB7),
    };
    if dark() { (c(bright), c(bright).opacity(0.16)) } else { (c(light), c(fill)) }
}

/// The hues of a space map's blocks, one per directory of the open level; nested blocks keep
/// their parent's. Drawn as a faint fill, a stronger border and the text, all of the one hue.
const MAP_HUES: [(u32, u32); 10] = [(0x7858D2, 0xAA96F5), (0x1978B4, 0x6EBEF0), (0x1E875F, 0x6ECDA0), (0xC45A22, 0xF09B69), (0x4E5CCE, 0x8C9BF5), (0xBE3C78, 0xEB82B4), (0x0F8085, 0x5FC8CD), (0x9C6A0A, 0xE1B95F), (0x587828, 0xA5C869), (0x925ABE, 0xC396EB)];

/// The hue of the `index`-th block of a space map.
pub fn map_hue(index: usize) -> Hsla {
    let (light, dark) = MAP_HUES[index % MAP_HUES.len()];
    pick(light, dark)
}

/// What a space map draws without a hue of its own: files, the directories too small to list, free space.
pub fn map_neutral() -> Hsla {
    pick(0x707A8C, 0x96A0B2)
}

pub fn shadow_panel() -> Vec<BoxShadow> {
    let strength = if dark() { 3. } else { 1. };
    vec![
        BoxShadow { color: hsla(0., 0., 0., 0.10 * strength), offset: point(px(0.), px(8.)), blur_radius: px(28.), spread_radius: px(0.) },
        BoxShadow { color: hsla(0., 0., 0., 0.06 * strength), offset: point(px(0.), px(1.)), blur_radius: px(3.), spread_radius: px(0.) },
    ]
}

pub fn shadow_card() -> Vec<BoxShadow> {
    vec![BoxShadow { color: hsla(0., 0., 0., if dark() { 0.2 } else { 0.05 }), offset: point(px(0.), px(1.)), blur_radius: px(3.), spread_radius: px(0.) }]
}
