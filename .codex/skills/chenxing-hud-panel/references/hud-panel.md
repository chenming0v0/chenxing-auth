# HUD Panel Reference

## Source of truth

- CSS: `design-auth-chengming/colors_and_type.css` -> `.chenxing-hud-panel`
- Shared fragment: `design-auth-chengming/partials/hud-panel.html`
- Design requirements: `design-auth-chengming/DESIGN.md`

## CSS contract

`.chenxing-hud-panel` provides:

- Strong glass background and 28px backdrop blur with saturation boost.
- 1px translucent blue border and 16px border radius.
- Top-left and bottom-right 18px cyan corner brackets via `::before` and `::after`.
- Default `2rem` padding. Do not make it narrow or fixed-width in the public class.

## HTML fragment

```html
<!-- Shared HUD glass panel: strong glass surface with top-left / bottom-right cyan corner brackets. -->
<div class="chenxing-hud-panel">
  <!-- SLOT: hudPanelContent -->
</div>
```

## Existing pages using it

- `design-auth-chengming/pages/login.html`
- `design-auth-chengming/pages/register.html`
- `design-auth-chengming/pages/bootstrap.html`
- `design-auth-chengming/pages/oauth-account.html`
- `design-auth-chengming/pages/oauth-consent.html`
- `design-auth-chengming/pages/oauth-redirect.html`

## Width behavior

- The panel is fluid and does not set its own width.
- Use `w-full`, `max-w-*`, grid columns, or parent layout to size it.
- Keep the same element for the panel class and layout utilities.

## Solo-design workflow

1. Add or update `.chenxing-hud-panel` in `colors_and_type.css`.
2. Create or update `partials/hud-panel.html` with the shared fragment.
3. Update pages to use `chenxing-hud-panel`.
4. Re-apply heads:

```powershell
node C:/Users/HEI/.claude/skills/solo-design/script/fill-html-head.mjs <css-path> <page.html...> --replace-head
```

5. Validate:

```powershell
node C:/Users/HEI/.claude/skills/solo-design/script/scan-design-directory.mjs <design-project-path> --report-json=<design-project-path>/validation-report.json
```
