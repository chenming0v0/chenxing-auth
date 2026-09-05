# HUD Panel Reference

## Source of truth

- CSS: `@chenxing/ui` -> `src/styles/components.css` -> `.chenxing-hud-panel`（库仓库 https://github.com/chenming0v0/chenxing-ui ）
- React component: `@chenxing/ui` -> `HudPanel`
- Prototype drafts (design branch only): `design-auth-chengming/DESIGN.md`

## CSS contract

`.chenxing-hud-panel` provides:

- Strong glass background and 24px backdrop blur with saturation boost.
- 1px translucent white border and `--chenxing-radius-lg` border radius.
- Top-left and bottom-right 18px cyan corner brackets via `::before` and `::after`.
- Default `2rem` padding. Do not make it narrow or fixed-width in the public class.

## React component

```tsx
export function HudPanel({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`chenxing-hud-panel ${className}`}>{children}</div>
}
```

## Width behavior

- The panel is fluid and does not set its own width.
- Use `w-full`, `max-w-*`, grid columns, or parent layout to size it.
- Pass those utilities via `className` so they land on the panel element.

## Missing component fallback

If `@chenxing/ui` does not yet provide a needed component, implement a temporary fallback in the app so the current feature can proceed. Use the project's existing card/panel visual language and keep the fallback-specific styles local to that component. Before or alongside the change, check for an existing issue; otherwise open and cross-link one issue in this repository and one in `chenming0v0/chenxing-ui`, recording the missing component, use case, and proposed shared API. Replace the fallback when the shared component becomes available.

## Workflow

1. For formal panel changes, add or update `.chenxing-hud-panel` in the chenxing-ui repo (`src/styles/components.css`), then update the locked dependency in `web/package-lock.json`.
2. Use `HudPanel` from `@chenxing/ui` for formal panel surfaces; never hand-roll the public class.
3. Rebuild the frontend so `web/dist` matches the source:

```bash
cd web && npm run build
```

4. Verify no page reintroduced a one-off glass card:

```bash
grep -rn "chenxing-glass-strong\|chenxing-hud-frame" web/src/pages web/src/components
```
