pub mod consent;
pub mod handlers;
pub mod helpers;
pub mod login;

pub fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{title}</title><style>body{{font-family:system-ui,sans-serif;max-width:42rem;margin:4rem auto;padding:0 1rem;line-height:1.6}}form{{display:grid;gap:.75rem}}input,button{{font:inherit;padding:.65rem}}button{{cursor:pointer}}</style></head><body>{body}</body></html>",
        title = escape_html(title),
    )
}
