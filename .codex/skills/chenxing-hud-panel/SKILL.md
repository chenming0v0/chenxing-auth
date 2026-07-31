---
name: chenxing-hud-panel
description: Enforce the shared Chenxing HUD glass panel (.chenxing-hud-panel) for every UI card, glass container, form panel, dialog, or design-draft surface in this repository. Use when creating or modifying design drafts, HTML pages, web UI, cards, auth screens, or any UI that needs a strong glass surface with cyan corner highlights. Do not let agents invent alternative glass card styles.
---

# Chenxing HUD Panel

## Mandatory container

Every card or glass container in this project must use the public class `chenxing-hud-panel`. The CSS source of truth is `design-auth-chengming/colors_and_type.css`; the shared fragment is `design-auth-chengming/partials/hud-panel.html`; the full design requirements live in `design-auth-chengming/DESIGN.md`.

```html
<div class="chenxing-hud-panel">
  <!-- content -->
</div>
```

For width control, add layout utilities to the same element:

```html
<div class="chenxing-hud-panel w-full max-w-lg">
  <!-- content -->
</div>
```

## Rules

- Never write cards with one-off glass styles or the old `chenxing-glass-strong chenxing-hud-frame p-8` combination.
- Keep the panel CSS in `colors_and_type.css`; do not duplicate it into page-level styles.
- When creating a new page, copy the shared partial and fill only `<!-- SLOT: hudPanelContent -->`.
- After changing `colors_and_type.css`, re-run `fill-html-head.mjs --replace-head` on affected pages.
- Run `scan-design-directory.mjs` before finishing design work.

See `references/hud-panel.md` for the exact CSS contract, existing page examples, and solo-design workflow commands.
