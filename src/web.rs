pub mod helpers;

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
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{title}</title><style>body{{font-family:system-ui,sans-serif;max-width:42rem;margin:4rem auto;padding:0 1rem;line-height:1.6}}form{{display:grid;gap:.75rem}}input,button{{font:inherit;padding:.65rem}}button{{cursor:pointer}}.totp-qr{{display:flex;justify-content:center;margin:1rem 0;padding:1rem;background:#fff;border-radius:.5rem}}.totp-qr svg{{width:min(100%,18rem);height:auto}}.totp-secret{{display:flex;align-items:center;gap:.5rem;margin-top:.75rem}}.totp-secret code{{flex:1;overflow-wrap:anywhere;padding:.65rem;background:#f4f4f4;border-radius:.35rem;font-size:.85rem}}.totp-secret button{{white-space:nowrap}}</style></head><body>{body}</body></html>",
        title = escape_html(title),
    )
}

