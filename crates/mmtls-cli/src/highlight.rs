use std::io::IsTerminal;
use std::sync::OnceLock;

use syntect::easy::HighlightLines;
use syntect::highlighting::{Theme, ThemeSet, Style};
use syntect::parsing::{SyntaxReference, SyntaxSet};
use syntect::util::LinesWithEndings;

fn syntax_set() -> &'static SyntaxSet {
    static SS: OnceLock<SyntaxSet> = OnceLock::new();
    SS.get_or_init(|| SyntaxSet::load_defaults_newlines())
}

fn theme() -> &'static Theme {
    static THEME: OnceLock<Theme> = OnceLock::new();
    THEME.get_or_init(|| {
        let ts = ThemeSet::load_defaults();
        ts.themes["base16-ocean.dark"].clone()
    })
}

fn pick_syntax(content_type: &str) -> &'static SyntaxReference {
    let ct = content_type.to_lowercase();
    let token = if ct.contains("xml") || ct.contains("html") {
        "xml"
    } else if ct.contains("json") {
        "json"
    } else {
        return syntax_set().find_syntax_plain_text();
    };
    syntax_set()
        .find_syntax_by_token(token)
        .unwrap_or_else(|| syntax_set().find_syntax_plain_text())
}

/// Apply syntax highlighting based on content-type, if enabled.
pub fn by_content_type(text: &str, content_type: &str, pretty: bool) -> String {
    if !pretty {
        return text.to_string();
    }
    if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        return text.to_string();
    }
    if !std::io::stdout().is_terminal() {
        return text.to_string();
    }

    let syntax = pick_syntax(content_type);
    let mut highlighter = HighlightLines::new(syntax, theme());
    let mut out = String::new();

    for line in LinesWithEndings::from(text) {
        match highlighter.highlight_line(line, syntax_set()) {
            Ok(ranges) => {
                for (style, segment) in &ranges {
                    push_colored(&mut out, *style, segment);
                }
            }
            Err(_) => out.push_str(line),
        }
    }
    out
}

fn push_colored(out: &mut String, style: Style, text: &str) {
    let fg = style.foreground;
    // Skip default foreground (color 0x00000001 used by syntect for unknown)
    if fg.r == 0 && fg.g == 0 && fg.b == 0 && fg.a == 0 {
        out.push_str(text);
        return;
    }
    use std::fmt::Write;
    write!(
        out,
        "\x1b[38;2;{};{};{}m{text}\x1b[0m",
        fg.r, fg.g, fg.b
    )
    .ok();
}
