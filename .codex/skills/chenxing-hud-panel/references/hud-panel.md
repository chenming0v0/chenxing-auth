# HUD Panel Reference

## Source of truth

- CSS: `web/src/chenxing-design.css` -> `.chenxing-hud-panel`
- React component: `web/src/components/ui.tsx` -> `HudPanel`
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

## Workflow

1. Add or update `.chenxing-hud-panel` in `web/src/chenxing-design.css`.
2. Use `HudPanel` from `web/src/components/ui.tsx` in pages; never hand-roll the class.
3. Rebuild the frontend so `web/dist` matches the source:

```bash
cd web && npm run build
```

4. Verify no page reintroduced a one-off glass card:

```bash
grep -rn "chenxing-glass-strong\|chenxing-hud-frame" web/src/pages web/src/components
```
