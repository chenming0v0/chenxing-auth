use chenxing_auth::web::escape_html;

#[test]
fn browser_html_escapes_untrusted_values() {
    assert_eq!(
        escape_html("<script>alert(\"x\")</script>"),
        "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;"
    );
}
