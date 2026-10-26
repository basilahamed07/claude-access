# Design notes (frontend-design review pass)

Implements `docs/superpowers/specs/2026-10-26-agentshield-frontend-design.md`. The `frontend-design` skill was not
installed in this environment, so its review step was applied by hand from the spec's §3 table:

- **Rejected the default** of a dark "SOC console" with one acid accent. The surface is a light "hangar" grey-blue; dark
  mode is an equal theme. Orange (`--recorder`) is bound to one meaning: *stopped / malicious* (and the focus ring).
- **No card kit, gradients or multiple shadows.** Tables and lanes; the only shadow is the drawer that floats over a list.
- **Mono only for literal values** (arguments, payloads, keys, hashes). Labels are Atkinson Hyperlegible Next, sentence case.
- **Radius follows hierarchy:** 6 px panels, 4 px inputs/buttons, 999 px status dots only.
- **Decision words** Cleared / Holding / Blocked always carry an icon and a word; the API value is on hover.
- **One motion moment:** a live mark drawing in on the tape (200 ms). Drawers slide for 150 ms. Both off under
  `prefers-reduced-motion`.

Deviations from the plan: plain CSS with the spec's tokens instead of CSS Modules (one global stylesheet, class names
prefixed by component); Radix `Dialog` only (drawer and confirm); the Overview chart is hand-written SVG/HTML (three status
colours, no library).
