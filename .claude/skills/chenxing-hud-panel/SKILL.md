---
name: chenxing-hud-panel
description: Enforce the shared Chenxing HUD glass panel (.chenxing-hud-panel) for every UI card, glass container, form panel, or dialog in this repository. Use when creating or modifying web UI, cards, auth screens, or any surface that needs a strong glass surface with cyan corner highlights. Do not invent alternative glass card styles.
---

# Chenxing HUD Panel

## Mandatory container

Every card or glass container in this project must use the public class `chenxing-hud-panel`. The CSS source of truth is the `@chenxing/ui` package (`node_modules/@chenxing/ui/src/styles/components.css`, imported via `web/src/index.css`); in React always go through the shared `HudPanel` component exported by `@chenxing/ui`.

```tsx
import { HudPanel } from '@chenxing/ui'

<HudPanel>{/* content */}</HudPanel>
```

For width control, pass layout utilities through `className`:

```tsx
<HudPanel className="w-full max-w-lg">{/* content */}</HudPanel>
```

## Rules

- Never write cards with one-off glass styles or the old `chenxing-glass-strong chenxing-hud-frame p-8` combination.
- Keep the panel CSS in the `@chenxing/ui` library (edit it in the chenxing-ui repo, then update the dependency); do not duplicate it into app-level styles or new CSS files.
- Do not apply the raw `chenxing-hud-panel` class in pages; render `HudPanel` so the contract stays in one place.
- After changing the panel CSS, rebuild `web/dist` so the embedded assets stay in sync.
- The prototype drafts that originally defined this panel live on the `design` branch (`design-auth-chengming/`); they are not part of `dev` and must not be re-added here.

See `references/hud-panel.md` for the exact CSS contract and existing usage.
