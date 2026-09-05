---
name: chenxing-hud-panel
description: Enforce the shared Chenxing HUD glass panel (.chenxing-hud-panel) for formal UI cards, glass containers, form panels, and dialogs in this repository. Use when creating or modifying web UI, cards, auth screens, or any surface that needs a strong glass surface with cyan corner highlights. When @chenxing/ui lacks a needed component, allow a temporary app-local fallback and track the missing component in issues for both repositories.
---

# Chenxing HUD Panel

## Mandatory container

Every formal card or glass container in this project must use the public class `chenxing-hud-panel`. The CSS source of truth is the `@chenxing/ui` package (`node_modules/@chenxing/ui/src/styles/components.css`, imported via `web/src/index.css`); in React always go through the shared `HudPanel` component exported by `@chenxing/ui`. A missing library component may temporarily use an app-local fallback card/UI so work can continue.

```tsx
import { HudPanel } from '@chenxing/ui'

<HudPanel>{/* content */}</HudPanel>
```

For width control, pass layout utilities through `className`:

```tsx
<HudPanel className="w-full max-w-lg">{/* content */}</HudPanel>
```

## Rules

- Do not create a competing long-lived glass system or use the old `chenxing-glass-strong chenxing-hud-frame p-8` combination. A temporary fallback for a missing component may use local card/component styles, but it must remain clearly temporary.
- Keep the formal panel CSS in the `@chenxing/ui` library (edit it in the chenxing-ui repo, then update the dependency); do not duplicate the `HudPanel` CSS recipe into app-level styles or new CSS files. Fallback-specific layout and component styles may live in the app and should be removed when the shared component lands.
- Do not apply the raw `chenxing-hud-panel` class in pages; render `HudPanel` so the contract stays in one place.
- When using a temporary fallback, check for an existing issue first; otherwise open a tracking issue in this repository and a corresponding issue in `chenming0v0/chenxing-ui`, cross-link them, and record both issue numbers in the task or PR.
- After changing the panel CSS, rebuild `web/dist` so the embedded assets stay in sync.
- The prototype drafts that originally defined this panel live on the `design` branch (`design-auth-chengming/`); they are not part of `dev` and must not be re-added here.

See `references/hud-panel.md` for the exact CSS contract and existing usage.
