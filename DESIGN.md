---
name: LogPit
description: A homelab's logs read like a live match centre, night-stadium dark by default and pitch-side white by day.
colors:
  night-ground: "#0e1015"
  floodlit-surface: "#171a21"
  floodlit-surface-raised: "#1e222b"
  rail-band: "#13161c"
  night-ink: "#e8eaf0"
  terrace-muted: "#9aa0ae"
  night-hairline: "#252933"
  night-field-line: "#343946"
  focus-violet: "#8b7cff"
  live-red: "#ff4d4f"
  error-red: "#ff5c5e"
  warning-amber: "#fbbf24"
  notice-blue: "#60a5fa"
  healthy-green: "#34d399"
  new-sky: "#38bdf8"
  chart-info-slate: "#4b5568"
  chart-debug-slate: "#363c4a"
  pitch-white: "#ffffff"
  day-surface: "#f6f7f9"
  day-surface-raised: "#eef0f3"
  day-ink: "#0f1115"
  day-muted: "#5b6070"
  day-hairline: "#e4e6eb"
  day-field-line: "#cfd3da"
  focus-violet-day: "#6d5df5"
  live-red-day: "#e5383b"
  error-red-day: "#d92d2f"
  warning-amber-day: "#b45309"
  notice-blue-day: "#2563eb"
  healthy-green-day: "#0f9f6e"
  new-sky-day: "#0284c7"
  chart-info-day: "#94a3b8"
  chart-debug-day: "#cbd5e1"
typography:
  headline:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica Neue, sans-serif"
    fontSize: "20px"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "-0.02em"
    fontFeature: "tnum"
  title:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica Neue, sans-serif"
    fontSize: "15px"
    fontWeight: 650
    lineHeight: 1.5
    letterSpacing: "-0.01em"
  body:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica Neue, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "tnum"
  body-dense:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica Neue, sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "tnum"
  label:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica Neue, sans-serif"
    fontSize: "12px"
    fontWeight: 500
    lineHeight: 1.5
    fontFeature: "tnum"
  pill:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica Neue, sans-serif"
    fontSize: "11px"
    fontWeight: 600
    lineHeight: "19px"
    letterSpacing: "0.02em"
  message:
    fontFamily: "ui-monospace, SF Mono, Cascadia Mono, Menlo, Consolas, monospace"
    fontSize: "12.5px"
    fontWeight: 400
    lineHeight: 1.55
rounded:
  hair: "2px"
  sm: "4px"
  control: "6px"
  md: "8px"
  lg: "12px"
  pill: "999px"
spacing:
  hair: "2px"
  xs: "4px"
  sm: "6px"
  md: "8px"
  lg: "10px"
  xl: "14px"
  gutter: "16px"
components:
  button:
    backgroundColor: "{colors.floodlit-surface}"
    textColor: "{colors.night-ink}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "32px"
  button-hover:
    backgroundColor: "{colors.floodlit-surface-raised}"
  button-primary:
    backgroundColor: "{colors.night-ink}"
    textColor: "{colors.night-ground}"
    rounded: "{rounded.md}"
    padding: "0 16px"
    height: "36px"
  button-primary-hover:
    backgroundColor: "{colors.pitch-white}"
  button-small:
    rounded: "{rounded.control}"
    padding: "0 9px"
    height: "26px"
  input:
    backgroundColor: "{colors.floodlit-surface}"
    textColor: "{colors.night-ink}"
    rounded: "{rounded.control}"
    padding: "0 10px"
    height: "32px"
  command-search:
    backgroundColor: "{colors.floodlit-surface}"
    textColor: "{colors.night-ink}"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    padding: "0 34px"
    height: "36px"
  live-badge:
    backgroundColor: "{colors.floodlit-surface}"
    textColor: "{colors.night-ink}"
    rounded: "{rounded.pill}"
    padding: "0 12px 0 10px"
    height: "36px"
  live-badge-on:
    textColor: "{colors.live-red}"
  filter-chip:
    textColor: "{colors.night-ink}"
    rounded: "{rounded.pill}"
    padding: "0 8px 0 10px"
    height: "26px"
  level-pill:
    typography: "{typography.pill}"
    rounded: "{rounded.pill}"
    padding: "0 7px"
    width: "44px"
  popover:
    backgroundColor: "{colors.floodlit-surface}"
    textColor: "{colors.night-ink}"
    rounded: "{rounded.lg}"
    padding: "14px"
  tooltip:
    backgroundColor: "{colors.floodlit-surface}"
    textColor: "{colors.night-ink}"
    rounded: "{rounded.md}"
    padding: "6px 9px"
  form-pip:
    rounded: "{rounded.hair}"
    width: "6px"
    height: "14px"
  incident-mark:
    backgroundColor: "{colors.notice-blue}"
    rounded: "{rounded.sm}"
    width: "8px"
    height: "14px"
---

# Design System: LogPit

## Overview

**Creative North Star: "Match en direct"**

The web UI reads a homelab the way a live match centre reads a game. A momentum curve shows who is pushing right now; every incident lands on a timeline at its minute; each host carries its recent form in the rail. The page is never a static grey histogram over undifferentiated rows: data moves in place, lines arrive while you watch, and the state of each host shows without opening anything. Night-stadium dark is the default (a near-black ground under floodlit surfaces); daytime is pitch-side white with the same state hues deepened for contrast.

Density is that of a working tool: 14px body, 32-36px controls, 16px gutters, hairline rules between rows rather than cards around them. Colour is semantic and scarce: red, amber, green and blue encode state, a ten-hue series palette encodes hosts or apps, and one violet belongs to the viewer alone. Motion is part of the material, authored and short, and steps aside under `prefers-reduced-motion`.

The world is a match centre in structure, never in costume: no football words, cards or goals in the labels, no green-on-black hacker theme, no KPI tiles or decorative gradients. Everything ships inline under a strict CSP, so type is the system stack and every icon is inline SVG.

Scope: the search page (`src/web/index.html`) is the redesigned surface and the reference for this system, with tokens in `src/web/theme.css`. `src/web/pages.html` (board, host, admin, compare) inherits these tokens but still carries the retired world's component styling (navy header band, timetable rows); it is scheduled for redesign and is not a source for this document. New work on those views follows this file, not their current markup.

**Key Characteristics:**
- Night-stadium dark by default, pitch-side white by day; theme auto/light/dark via `data-theme`.
- Violet marks the viewer's focus and nothing else.
- Signature: the momentum curve, volume above a baseline, errors mirrored below, incidents on a timeline beneath, a live "now" edge.
- The host rail: pulse dot, five calibrated form pips, proportional volume bar.
- Figures roll to new values; segments morph in height; live lines slide in lit and fade.
- System sans with tabular figures everywhere; monospace for message bodies and code only.

## Colors

A cool, near-neutral night palette where hue only appears to say something: state, series, or the viewer's focus.

### Primary
- **Focus Violet** (dark `focus-violet`, day `focus-violet-day`): the viewer's attention. Focus rings, text selection, caret, active filter chips (tinted at 12-14%, 22-28% on hover), the brush range and its count on the curve, the keyboard-current stream line and context line, the hovered axis label, the "new since you left" divider, the new-lines pill, sort and link hovers. It never encodes a datum.

### Secondary (state)
- **Live Red** (`live-red` / `live-red-day`): liveness only. The Live badge when on, its pulsing dot, the curve's "now" edge and pulse.
- **Error Red** (`error-red` / `error-red-day`): errors and above. The mirrored lower half of the curve, error level pills (on a 10-14% tint), error timestamps, error counts, failing incident marks, the alert badge, the "hot" host pulse, error form pips.
- **Warning Amber** (`warning-amber` / `warning-amber-day`): warnings, warning counts and pips, maintenance shading (diagonal hatch on a tint with a 2px top rule).
- **Healthy Green** (`healthy-green` / `healthy-green-day`): a host that is talking normally (pulse dot), healthy form pips (at 70%), recovered incident marks, falling pattern trends.
- **Notice Blue** (`notice-blue` / `notice-blue-day`): notice level, neutral incident marks, top-value bars, trace links.
- **New Sky** (`new-sky` / `new-sky-day`): a pattern that is new in the window.

### Tertiary (series)
- **Series palette** (`--c0` to `--c9`, plus `--other`): ten distinct hues (blue, orange, green, pink, cyan, yellow, rose, brown, teal, lime) for stacking the curve by host or app; violet is deliberately absent. Info and debug volume use the quiet slates (`chart-info-slate`, `chart-debug-slate`, and their day pairs) so state colours stand out.

### Neutral
- **Night Ground** / **Pitch White** (`night-ground` / `pitch-white`): page ground and the header shell (88% opaque with a 12px blur).
- **Floodlit Surface** (`floodlit-surface` / `day-surface`): fields, buttons, popovers, tooltips, the line toolbar.
- **Floodlit Surface Raised** (`floodlit-surface-raised` / `day-surface-raised`): button hover, `kbd` keys, the host-page shortcut.
- **Rail Band** (`rail-band`; day uses `day-surface`): the host rail and the opened context block.
- **Night Ink** / **Day Ink** (`night-ink` / `day-ink`): text, primary button fill, hour-band numerals.
- **Terrace Muted** / **Day Muted** (`terrace-muted` / `day-muted`): secondary text, headers, host and app columns, axis labels.
- **Hairline** (`night-hairline` / `day-hairline`): every rule and resting border; stream row dividers at 65%.
- **Field Line** (`night-field-line` / `day-field-line`): hover borders, unchecked pulse rings, scrollbar.
- Translucent tints: `--tint` (ink at 3.5%) for hover rows, `--quiet-tint` (5-6%) for neutral pills, `--mark` (yellow at 26-32%) for search-term highlights.

### Named Rules
**The Viewer's Violet Rule.** Violet means "you are looking here": selection, active filter, brush, zoomed range, current line. If an element would still be violet with nobody using the page, it is wrong.

**The Two Reds Rule.** Live red says "this is happening now"; error red says "this failed". The Live badge and the now edge never borrow error red, and errors never pulse in live red.

**The State-Only Hue Rule.** Red, amber, green and blue carry severity and health; series hues carry identity. Neither is used for decoration, and series never reuse violet.

## Typography

**Display Font:** none. The system sans (`system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", sans-serif`) carries every role; the strict CSP forbids web fonts.
**Body Font:** the same system sans, with `font-variant-numeric: tabular-nums` set on the body.
**Label/Mono Font:** `ui-monospace, "SF Mono", "Cascadia Mono", Menlo, Consolas, monospace`, for message bodies, context lines, patterns, top values, syntax help and code.

**Character:** a quiet, native sans at a real scale, with figures that never jitter as they roll; mono appears only where the text is the machine's own.

### Hierarchy
- **Headline** (700, 20px, -0.02em): the hour-band numeral of the stream (15px in compact density); the empty-state welcome heading goes to 22px. The largest type on the page.
- **Title** (650, 15px, -0.01em): rail section headers. The brand wordmark is 17px / 700 / -0.02em.
- **Body** (400, 14px/1.5): default text, the search field, legend figures (14px / 650).
- **Body Dense** (13px): secondary filter row, host and app columns, stream timestamps (600).
- **Label** (500-600, 11.5-12.5px): chart bar, table headers, counts, "seen" ages, tooltips, help.
- **Pill** (600, 11px/19px, 0.02em): level pills, badges (10.5px), tags.
- **Message** (mono 12.5px/1.55, 11.5px/1.35 compact): log message bodies, wrapped `pre-wrap` by default.

### Named Rules
**The Tabular Figures Rule.** Every number on the page uses tabular figures, so counts can roll in place without shifting their neighbours.

**The Mono Is Evidence Rule.** Monospace is reserved for what the machine wrote (messages, patterns, values, queries). Interface text is never mono.

## Layout

A sticky command bar spans the top: brand, a flexible search field (basis 320px), help, level, range, the Live badge and Search, then the status, right-aligned. A second row holds secondary filters, page links, saved views and settings; active filters appear as removable chips below it. From 1000px the work area is a two-column grid: the host rail (330px, 360px from 1280px) sticky on the left with its own scroll, the chart bar, momentum curve, incident timeline, axis and stream on the right. Below 1000px the rail drops under the stream; below 760px the header stops sticking, filters collapse behind a toggle and stream rows reflow to a grid. Desktop is the target; the narrow layout is a fallback only.

Rhythm: 16px outer gutter everywhere; 6-8px gaps between controls; 10-14px panel padding; stream cells 6px x 10px (2px vertical in compact). Separation comes from hairline rules and the rail band, never from card boxes.

**The Hairline Not Box Rule.** Rows, rail sections and the stream are separated by 1px rules; containers with borders and shadows are reserved for floating things (popovers, palette, tooltip, toolbar).

## Elevation & Depth

Flat at rest, tonal in structure, lifted only when floating. Structure uses the ground / rail band / surface steps and hairlines. Two shadows exist, both soft and ambient, and only for elements above the page; the header and hour bands use translucency and backdrop blur instead.

### Shadow Vocabulary
- **Raise** (`--raise`; dark `0 1px 2px rgb(0 0 0 / .4), 0 10px 28px -8px rgb(0 0 0 / .6)`): chart tooltip, line toolbar, new-lines pill.
- **Pop** (`--pop`; dark `0 2px 8px rgb(0 0 0 / .45), 0 28px 56px -12px rgb(0 0 0 / .7)`): range picker, help and settings panels, command palette (over a 45% black backdrop).
- **Focus halo** (`0 0 0 3px` focus tint): focused inputs, with the border turning violet. Elsewhere, a 2px violet outline offset 2px.

### Named Rules
**The Float-Only Shadow Rule.** A shadow means the element floats above the page and will go away. Nothing anchored in the layout carries one.

## Shapes

Gently rounded and consistent, on a six-step scale: 2px for hairline marks (form pips, volume and top-value bars, legend swatches), 4px for small marks (curve columns and segment caps, incident marks, `kbd`, highlights, context lines), 6px for controls (`--radius-s`), 8px for the command bar's fields and buttons, tooltips and the line toolbar (`--radius`), 12px for popovers and the palette, and full pills (999px) for everything that is a status or a token: Live badge, filter chips, level pills, badges, tags, band counts, the new-lines pill. Dots (pulse, now edge) are circles. The curve's upper stack rounds its top corners, the mirrored error stack its bottom ones, so the baseline reads as one seam.

## Components

### Buttons
Calm and solid, pressed rather than glowing.
- **Shape:** 6px corners (8px and 36px tall in the command bar), 32px tall, 600 weight.
- **Default:** surface fill, hairline border; hover raises to the raised surface with a field-line border; active presses down 1px and scales to 0.98.
- **Primary (Search):** ink fill with ground text (inverts per theme), hover goes to full white in dark, `#2a2e37` in day.
- **Small:** 26px, 12px text. **Link:** bare text, violet on hover.
- **Transitions:** 160ms on the shared ease.

### Chips
- **Filter chips:** pills, 26px, focus tint background (stronger on hover), the key in violet, the value in mono, a close glyph in SVG. They enter with the `rise` animation. "Clear all" is a muted text button.
- **Level pills:** fixed 44px minimum, state text on a state tint; info and debug have no tint.
- **Band counts:** quiet pills in each hour band, with errors and warnings on their tints.

### Cards / Containers
There are no cards. Floating panels (range picker, help, settings) use the surface, a hairline border, 12px corners, the Pop shadow, 14px padding, and open with `rise` (180ms) from their anchor corner.

### Inputs / Fields
- **Style:** surface fill, hairline border, 6px corners (8px in the command bar), 32px tall (30px in the filter row, 36px for search).
- **Hover / Focus:** border to field line on hover; on focus the border turns violet with a 3px violet halo; no outline.
- **Search:** inline SVG magnifier on the left, a `/` key hint on the right that hides on focus.

### Navigation
The command bar is the navigation: a translucent sticky header (88% shell, 12px blur, hairline bottom). Board, Compare and Admin sit in a segmented group on the surface, muted text that inks on hover. `Ctrl/Cmd+K` opens a command palette (620px, 12px corners, 54px input, violet-tinted current option).

### Live Badge
A pill with a dot. Off: field-grey dot on the shell field. On: error-tint fill, a 45% live-red border, live-red text, and the dot pulsing (`pulse`, 1.6s) as an expanding ring.

### Momentum Curve (signature component)
The page's one big gesture. Per time bucket, a column of stacked segments: non-error volume rises above a hairline baseline (134px), errors mirror below it (56px) in error red; grouping by host or app stacks everything upward in the series palette. Columns are kept between renders and their segments morph in height (320ms). A live "now" edge (a 1px live-red line, a "now" label and a dot that pulses while the window ends now) marks where the next lines will land. Maintenance windows shade the curve with an amber hatch. Under it, the **incident timeline**: a hairline track with 8 x 14px marks at each alert's minute (blue neutral, red failing, green recovered; resolved alerts stay, marked recovered), each a button into its moment, scaling to 1.25 on hover or focus. Below, an axis of clickable time labels. Dragging brushes a violet range (focus tint with a 1px violet inset), dims stream lines outside it and counts what it holds live; releasing zooms every panel. The legend above shows rolling totals per series.

### Host Rail
One row per host, sortable by column: a **pulse dot** (8px; green and pulsing every 2.4s when talking, red and pulsing when hot, a hollow field-line ring when silent, a one-shot `ping` when a line arrives), the name, five **form pips** (6 x 14px, 2px gap; calibrated against the host's own error and warning rate so a host that always logs a few errors stays green and one that starts failing shows it), entries, errors and warnings in state colour, and the age since last seen. Under the name, a 3px **volume bar** (ink at 40%) proportional to the host's share, animating its width over 500ms. The active host gets a violet-tinted row and violet name. Collapsible rail sections (hosts, top values, patterns, alerts) open with `reveal`.

### Stream
Rows separated by 65% hairlines, sticky translucent hour bands (20px numeral, date, count pills). Timestamps 600 weight, error timestamps in red; host in ink 600, app muted, message in mono with fields trailing on the same line (a violet "+N" opens the rest). A single floating toolbar follows the hovered or keyboard-current line. A line that arrives live slides in (`arrive`, 420ms) lit by a faint wash that fades over 2.4s. Opened context sits on the rail band, prefetched on hover, the current line violet-tinted. A violet pill announces unseen new lines.

### Motion
One ease, `cubic-bezier(.22, 1, .36, 1)` (`--ease`), a fast-settling ease-out. Durations: 120-160ms for hover and state colour, 180-240ms for panels, chips and reveals, 320ms for segment morphs, 420ms for arrivals, 500ms for bar widths, 700ms (quartic ease-out) for rolling numbers. Loops are limited to liveness: the Live dot and now edge (1.6s) and host pulses (2.4s). `prefers-reduced-motion: reduce` collapses every animation and transition to near zero in CSS, and rolling numbers jump straight to their value in script.

## Do's and Don'ts

### Do:
- **Do** keep violet for the viewer's focus: selection, active filters, brush, zoomed range, current line.
- **Do** encode severity and health with the state hues only, each paired with its tint for fills.
- **Do** let figures roll to their new value (700ms) and segments morph (320ms) instead of re-rendering.
- **Do** use the one `--ease` curve and keep state transitions in the 120-240ms band.
- **Do** honour `prefers-reduced-motion` for every new animation, in CSS and in script.
- **Do** separate rows with hairlines and keep shadows for floating elements.
- **Do** use pills (999px) for status and tokens, and the 2/4/6/8/12 scale for everything else.
- **Do** set every number in tabular figures and every machine-written string in mono.
- **Do** draw icons as inline SVG in `currentColor`.

### Don't:
- **Don't** use violet for a datum, a series or a severity.
- **Don't** use live red for errors or error red for liveness.
- **Don't** pulse anything that is not live; a static state does not loop.
- **Don't** add web fonts, external images or any external resource; the CSP forbids them.
- **Don't** add KPI tiles, decorative gradients or cards around content.
- **Don't** dress the match-centre world as a sports app: no football words, cards or goals in labels.
- **Don't** fall into the hacker costume: no green-on-black, CRT or neon.
- **Don't** copy component styling from `pages.html` until it has been redesigned.
