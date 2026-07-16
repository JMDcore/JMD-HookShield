# HookShield design system

HookShield is an operations product, so its interface optimises for evidence density, decision clarity, and calm repeat use. The first screen is the application itself; there is no marketing landing page in front of the console.

## Tooling provenance

The project brief requested Impeccable for the visual renewal. No Impeccable skill or plugin was available in the implementation session or installed in the local Codex skill directory. It was therefore **not used and is not claimed**. The functional baseline is preserved at Git tag `pre-interface-redesign-v0.2`; the system below was refined manually and verified through repeated browser critique, responsive inspection, keyboard operation, Playwright flows, and axe WCAG rules.

## Design principles

1. **Decision before decoration.** Status, event, endpoint, and time lead each row.
2. **Evidence remains adjacent.** The inbox and inspector share a workbench instead of forcing route changes.
3. **Colour has a job.** Forest green means primary control, green admission, red rejection, and ochre replay/duplicate/freshness concern.
4. **Density is deliberate.** Operational evidence stays compact without falling into microtype; section boundaries preserve scanability.
5. **No security theatre.** No neon, fake terminals, glass, decorative gradients, hacker motifs, or arbitrary warning copy.

## Foundations

### Colour tokens

| Token | Value | Use |
| --- | --- | --- |
| `canvas` | `#f3f3ef` | Warm application background |
| `surface` | `#fdfdfb` | Primary work surfaces |
| `surface-subtle` | `#f6f6f2` | Toolbars and evidence metadata |
| `ink` | `#20231f` | Main text |
| `muted` | `#596159` | Secondary information with AA contrast |
| `faint` | `#60675f` | Compact metadata with AA contrast |
| `sidebar` | `#ecece7` | Quiet endpoint navigation |
| `accent` | `#245b49` | Primary actions and selection |
| `green` | `#2d7052` | Accepted / passed |
| `amber` | `#8a631d` | Duplicate / expired / warning |
| `red` | `#98464b` | Rejected / failed |

Status colour is never the only signal: every state includes text and an icon or decision label.

### Typography

The UI uses the operating system's modern sans stack for fast local startup and consistent rendering without a remote font request. Hierarchy comes from restrained weight, spacing, and case:

- 15–21px for page facts, metrics, and inspector titles.
- 10–13px for dense operational text.
- 9–10px uppercase only for short structural labels.
- Monospace only for delivery identifiers, headers, hashes, and JSON.

### Spacing and shape

Spacing uses 4px multiples with 8, 12, 16, and 24px as the common steps. Corners stay between 3px and 4px. Shadows appear only where a modal must detach from its source context.

## Layout

Desktop uses three functional regions: a quiet endpoint sidebar, a scroll-bounded delivery list, and an evidence inspector. Summary metrics form a horizontal ledger rather than four floating cards. At 900px, the sidebar becomes a drawer and list/inspector stack. At 560px, facts become a 2×2 grid, endpoint tools wrap to a dedicated row, and dialogs dock near the bottom.

## Components and states

- **Delivery row:** restrained state dot, event type, endpoint/delivery ID, explicit decision, relative time.
- **Security check:** unboxed result mark, named control, concrete evidence statement, textual outcome.
- **Decision banner:** admitted/stopped plus the machine-readable rejection code.
- **Inspector tabs:** checks, formatted payload, redacted headers, processing timeline.
- **Simulator:** endpoint choice plus mutually exclusive, described attack scenarios.
- **Dialogs:** purposeful title, short consequence copy, labelled fields, clear primary action.
- **System states:** startup skeleton, fatal retry, empty inbox, success/error toast, disabled unsupported scenarios.

## Accessibility and interaction

- Visible focus uses a 2px green outline independent of status colour.
- The delivery list supports Up/Down arrow navigation.
- Dialogs and controls expose semantic names; native radio/select controls are retained.
- Reduced-motion preferences collapse animations and transitions.
- Automated browser tests run axe against WCAG 2 A/AA and 2.1 A/AA tags.
- Secondary tokens were darkened after the first audit found insufficient compact-text contrast.

## Visual audit checklist

- [x] Real application is the entry screen.
- [x] No gradients, neon, glassmorphism, terminal decoration, emojis, or giant marketing copy.
- [x] Metrics, list rows, checks, and headers use continuous surfaces instead of ornamental cards.
- [x] Border, shadow, and radius hierarchy are constrained.
- [x] Provider, status, and security copy is specific rather than generic.
- [x] Desktop and 390px mobile screenshots verified.
- [x] Serious and critical axe violations: zero.
- [x] GitHub freshness limitation is visible instead of implied away.
