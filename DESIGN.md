---
name: LogPit
description: A log stream set like a railway timetable, on paper by day and on the departure board by night.
colors:
  timetable-paper: "#ffffff"
  ink: "#111111"
  pencil-grey: "#5e5e5e"
  hairline: "#d6d6d6"
  field-grey: "#8a8a8a"
  band-grey: "#f2f2f2"
  platform-navy: "#2d327d"
  platform-lavender: "#c3c6ea"
  platform-rule: "#8f94c8"
  notice-tint: "#eceef8"
  notice-tint-strong: "#d9dcf1"
  selection-lavender: "#c9cbe8"
  signal-red: "#d30000"
  signal-red-deep: "#b00000"
  warning-amber: "#9a5300"
  clear-green: "#1b7a34"
  first-purple: "#6b3fa0"
  chart-info-grey: "#868686"
  chart-debug-grey: "#949494"
  live-highlight: "#fff1b8"
  board-navy: "#141a46"
  board-band: "#1b2257"
  board-shell: "#0b0f2e"
  board-white: "#f3f4fa"
  board-muted: "#a7acd4"
  board-rule: "#2b3170"
  board-field: "#6f76b3"
  board-yellow: "#ffd23f"
  board-tint: "#1f275f"
  board-tint-strong: "#2c3680"
  board-selection: "#3a438f"
  board-red: "#c40000"
  board-red-deep: "#a30000"
  board-error: "#ff6b6b"
  board-amber: "#ffb54d"
  board-notice: "#9cb0ff"
  board-green: "#5fd38a"
  board-purple: "#c7a6ff"
  board-chart-info: "#6f76b3"
  board-chart-debug: "#5f67a8"
  board-live-highlight: "#33303f"
  series-0: "#4e79a7"
  series-1: "#f28e2b"
  series-2: "#59a14f"
  series-3: "#b07aa1"
  series-4: "#76b7b2"
  series-5: "#d4a92a"
  series-6: "#ff9da7"
  series-7: "#9c755f"
  series-8: "#7b5fb5"
  series-9: "#86bc86"
  board-series-0: "#8fb3e0"
  board-series-1: "#ffa64d"
  board-series-2: "#7fcf6f"
  board-series-3: "#d6a3c9"
  board-series-4: "#9ad9d3"
  board-series-5: "#f5d76e"
  board-series-6: "#ffb3bb"
  board-series-7: "#c9a084"
  board-series-8: "#c59fd9"
  board-series-9: "#a8d8a8"
typography:
  wordmark:
    fontFamily: "\"Helvetica Neue\", Helvetica, Arial, system-ui, sans-serif"
    fontSize: "20px"
    fontWeight: 700
    lineHeight: "32px"
    letterSpacing: "-0.01em"
  hour:
    fontFamily: "\"Helvetica Neue\", Helvetica, Arial, system-ui, sans-serif"
    fontSize: "20px"
    fontWeight: 700
    lineHeight: 1
    fontFeature: "\"tnum\""
  body:
    fontFamily: "\"Helvetica Neue\", Helvetica, Arial, system-ui, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.45
    fontFeature: "\"tnum\""
  time:
    fontFamily: "\"Helvetica Neue\", Helvetica, Arial, system-ui, sans-serif"
    fontSize: "14px"
    fontWeight: 700
    lineHeight: 1.45
    fontFeature: "\"tnum\""
  rail-title:
    fontFamily: "\"Helvetica Neue\", Helvetica, Arial, system-ui, sans-serif"
    fontSize: "13px"
    fontWeight: 700
    lineHeight: 1.45
  rail-body:
    fontFamily: "\"Helvetica Neue\", Helvetica, Arial, system-ui, sans-serif"
    fontSize: "12.5px"
    fontWeight: 400
    lineHeight: 1.45
    fontFeature: "\"tnum\""
  label:
    fontFamily: "\"Helvetica Neue\", Helvetica, Arial, system-ui, sans-serif"
    fontSize: "12px"
    fontWeight: 700
    lineHeight: 1.45
  micro:
    fontFamily: "\"Helvetica Neue\", Helvetica, Arial, system-ui, sans-serif"
    fontSize: "11px"
    fontWeight: 700
    lineHeight: "16px"
  message:
    fontFamily: "ui-monospace, \"SF Mono\", Menlo, Consolas, monospace"
    fontSize: "12.5px"
    fontWeight: 400
    lineHeight: 1.45
  message-compact:
    fontFamily: "ui-monospace, \"SF Mono\", Menlo, Consolas, monospace"
    fontSize: "11.5px"
    fontWeight: 400
    lineHeight: 1.3
  fields:
    fontFamily: "\"Helvetica Neue\", Helvetica, Arial, system-ui, sans-serif"
    fontSize: "11.5px"
    fontWeight: 400
    lineHeight: 1.45
rounded:
  none: "0px"
  sm: "2px"
spacing:
  xs: "4px"
  sm: "6px"
  md: "8px"
  cell: "10px"
  lg: "12px"
  gutter: "16px"
  xl: "32px"
components:
  button:
    backgroundColor: "{colors.timetable-paper}"
    textColor: "{colors.ink}"
    rounded: "{rounded.sm}"
    padding: "0 12px"
    height: "32px"
  button-hover:
    backgroundColor: "{colors.band-grey}"
  button-primary:
    backgroundColor: "{colors.signal-red}"
    textColor: "{colors.timetable-paper}"
    rounded: "{rounded.sm}"
    padding: "0 12px"
    height: "32px"
  button-primary-hover:
    backgroundColor: "{colors.signal-red-deep}"
  button-small:
    typography: "{typography.label}"
    rounded: "{rounded.sm}"
    padding: "0 8px"
    height: "24px"
  input:
    backgroundColor: "{colors.timetable-paper}"
    textColor: "{colors.ink}"
    rounded: "{rounded.sm}"
    padding: "0 8px"
    height: "32px"
  header-band:
    backgroundColor: "{colors.platform-navy}"
    textColor: "{colors.timetable-paper}"
    padding: "10px 16px"
  header-field:
    backgroundColor: "{colors.timetable-paper}"
    textColor: "{colors.ink}"
    rounded: "{rounded.sm}"
    height: "32px"
  filter-row:
    backgroundColor: "{colors.band-grey}"
    textColor: "{colors.ink}"
    padding: "8px 16px"
  hour-band:
    backgroundColor: "{colors.band-grey}"
    textColor: "{colors.ink}"
    typography: "{typography.hour}"
    padding: "8px 10px 6px 16px"
  stream-row:
    backgroundColor: "{colors.timetable-paper}"
    textColor: "{colors.ink}"
    typography: "{typography.body}"
    padding: "4px 10px"
  stream-row-error:
    textColor: "{colors.signal-red}"
  context-panel:
    backgroundColor: "{colors.notice-tint}"
    typography: "{typography.message}"
    padding: "8px 16px 12px 32px"
  badge-silent:
    backgroundColor: "{colors.signal-red}"
    textColor: "{colors.timetable-paper}"
    typography: "{typography.micro}"
    rounded: "{rounded.sm}"
    padding: "0 5px"
  tag:
    backgroundColor: "{colors.timetable-paper}"
    textColor: "{colors.pencil-grey}"
    rounded: "{rounded.sm}"
    padding: "0 5px"
  popover-panel:
    backgroundColor: "{colors.timetable-paper}"
    textColor: "{colors.ink}"
    rounded: "{rounded.sm}"
    padding: "12px"
---

# Design System: LogPit

## Overview

**Creative North Star: "The Timetable"**

LogPit sets the log stream the way Swiss railway timetable books set departures. The hour is stated once, on a band; every line under it leads with its minutes and seconds in bold tabular figures while the hour recedes in grey; disruptions read in red. Read top to bottom, the stream has the calm, regular cadence of a printed timetable, and an incident shows up the way a cancelled train does: as a red line in an otherwise black column.

The world has two faces. In light, it is timetable paper: a white ground, near-black ink, hairline rules and a platform-navy band across the top. In dark, it is the station departure board: a deep navy ground, white type and board yellow as the accent. Both are flat, printed surfaces. Nothing floats, nothing glows, nothing eases in; state changes snap like a split-flap board turning over.

The system is dense but not cramped, and built for long reading during an incident. It rejects the category default (a dark observability console with a grey histogram over undifferentiated rows), the SaaS dashboard (cards, giant KPIs, gradients) and the hacker costume (green on black, CRT, neon). Because the page ships inside the binary under a `default-src 'none'` policy, everything is system type, inline CSS and inline SVG; lightness is part of the look.

**Key Characteristics:**
- The pinned hour band: the hour stated once in large bold figures, the band sticking under the header while its hour scrolls past.
- Bold tabular minutes:seconds leading each line, the hour prefix in grey.
- Helvetica-family system stack for everything, monospace reserved for message text.
- Colour only for meaning: red for errors and the one primary action, amber for warnings, navy for notices and structure, purple for first-ever patterns, yellow as the board accent at night.
- Flat surfaces, hairline rules, radii of 2px at most, no shadows, no easing.

## Colors

Two printed palettes sharing one grammar: neutral ink and rules carry the structure, and a few signal colours carry meaning.

### Primary
- **Signal Red** (light `signal-red`, dark `board-red` for the button and `board-error` for text): errors (severity 0–3), error counts, the timestamp of an error line, the "silent" host badge, rising patterns, failed alerts, and the single primary action (Search). The deeper variants (`signal-red-deep`, `board-red-deep`) are the primary button's hover.

### Secondary
- **Platform Navy** (`platform-navy`): the header band in light, notices (severity 5), the light theme's accent and focus ring, and the bars of top values. Its paler companions `platform-lavender` (secondary text on the band) and `platform-rule` (field borders on the band) exist only inside the header.
- **Board Yellow** (`board-yellow`): the dark theme's accent: focus ring, caret, hovered links, active host, chart selection, trace links, and the hour figures on the hour bands. It never appears in light.

### Tertiary
- **Warning Amber** (`warning-amber` / `board-amber`): warnings (severity 4) and warning counts.
- **First Purple** (`first-purple` / `board-purple`): a pattern seen for the first time ("new"). Nothing else.
- **Clear Green** (`clear-green` / `board-green`): a host recovered, a pattern falling. Status of good news only, never decoration.

### Neutral
- **Timetable Paper** (`timetable-paper`): the light ground, field and button fill.
- **Ink** (`ink`): text, the rule under the chart and under each hour band.
- **Pencil Grey** (`pencil-grey`): secondary text, the receding hour prefix, info and debug severities, counts.
- **Hairline** (`hairline`): every row and section rule.
- **Field Grey** (`field-grey`): borders of inputs, buttons, tags and the preferences panel.
- **Band Grey** (`band-grey`): the hour band, the filter row, button hover.
- **Notice Tint** (`notice-tint`, `notice-tint-strong`): the open context panel and its current line. **Selection Lavender** (`selection-lavender`) for text selection.
- **Board Navy** (`board-navy`): the dark ground; `board-band` for bands and the filter row, `board-shell` (darker still) for the header band, `board-white` for text, `board-muted` for secondary text, `board-rule` for rules, `board-field` for field borders, `board-tint`/`board-tint-strong` for the context panel, `board-selection` for selection.
- **Chart greys** (`chart-info-grey`, `chart-debug-grey`; dark `board-chart-info`, `board-chart-debug`): info and debug volume in the severity-stacked chart, recessive so errors and warnings dominate the silhouette, yet at 3:1 or more against the ground so the bars stay perceivable.
- **Live highlight** (`live-highlight`; dark `board-live-highlight`): the ground of a line that just arrived through the live tail, for three seconds. Light is a pale timetable yellow; dark stays close to the board ground (error red keeps 4.6:1 on it), so the line's time also turns board yellow there.
- **Series palette** (`series-0`…`series-9`, dark `board-series-0`…`board-series-9`, "other" in field grey or board muted): identity colours for hosts or apps only when the chart is stacked by host or app.

### Named Rules
**The Meaning Rule.** Colour says something or it is ink. Red is an error or the primary action, amber a warning, navy a notice or structure, purple a first sighting, green a recovery. A coloured element with no such meaning is a defect.

**The One Red Button Rule.** Exactly one filled red control per screen: Search. Every other button is outlined in field grey on the ground.

**The Two Boards Rule.** The light theme accent is navy; the dark theme accent is yellow. Never carry yellow into light, never carry navy accents into dark (the dark board is already navy).

## Typography

**Display Font:** Helvetica Neue (with Helvetica, Arial, system-ui, sans-serif)
**Body Font:** the same stack
**Label/Mono Font:** ui-monospace (with SF Mono, Menlo, Consolas, monospace), for message text only

**Character:** One grotesque in two weights, set with tabular figures everywhere, like a timetable book; the monospace is the voice of the machine and appears only where the machine speaks.

### Hierarchy
- **Wordmark** (700, 20px, 32px line, −0.01em): "LogPit" on the header band.
- **Hour** (700, 20px, line-height 1; 14px in compact density): the hour on each hour band, "14:00".
- **Time** (700, 14px, tabular): minutes:seconds leading each line; the hour prefix beside it is 400 in pencil grey.
- **Body** (400, 14px, 1.45, tabular figures on the whole page): hosts, apps, controls.
- **Rail title** (700, 13px): section heads in the rail; their counts in 400 muted.
- **Rail body** (400, 12.5px): rail content, chart bar, band counts.
- **Label** (700 or 600, 12px): severity column, table headers, small buttons.
- **Micro** (700, 11px, 16px line): badge, chart axis hours; tags use it at 400.
- **Message** (400 mono, 12.5px, 1.45; compact 11.5px/1.3): message bodies, patterns, context lines.
- **Fields** (400, 11.5px, keys 600): structured fields under a message.

### Named Rules
**The Tabular Rule.** All figures are tabular (`font-variant-numeric: tabular-nums` on the body). Times, counts and hours must line up in columns like a printed timetable.

**The Receding Hour Rule.** On a line, the hour is grey and regular, minutes:seconds black and bold. On an error line the whole timestamp turns red, hour included.

## Layout

A full-bleed working surface, no centred container. The header is sticky (static on phones): a navy band row with the wordmark, a flexible search (`flex: 1 1 280px`), level, range, Live, the red Search button and a right-aligned status; under it a band-grey row of secondary filters, saved views and the Settings popover (access token, display preferences, keyboard keys); under that, only when filters are active, a ground-coloured row of filter chips. Below 760px the second row folds behind a Filters toggle that shows the active filter count.

From 1100px the page is a two-column grid: a 340px rail on the left (sticky under the header, scrolling on its own) holding Hosts, Top values, Message patterns and Alerts as collapsible sections, and the main column holding the legend and export bar, a 72px volume chart with its hour axis, then the stream. Below 1100px the rail stacks above the stream.

The stream is a table set to the page edge with a 16px gutter on the left. Each hour opens with a band that sticks under the header (`top: var(--hdr)`, measured at runtime; 0 on phones). Below 760px each entry becomes a small grid: time, level, host, app on one line, message across the full width under it.

Spacing is tight and regular: 4px vertical cell padding, 10px horizontal cell padding, 8px gaps between controls, 16px gutters, 32px only around the empty state. Compact density cuts row padding to 1px and message type to 11.5px. On coarse pointers every control grows to a 44px minimum height (36px for small buttons). A skip link, shown on keyboard focus, jumps to the results; rail section titles are `h2` headings inside their summaries.

## Elevation & Depth

None. The system is flat: no shadows anywhere, including the preferences popover, which is a bordered sheet in field grey. Depth is conveyed only by tone and rules: the navy header band above the band-grey filter row, band-grey hour bands ruled in ink, the tinted context panel opening under a line. Stacking order is handled by z-index alone (header 10, popover 20, hour band 1).

### Named Rules
**The Printed Sheet Rule.** Every surface lies on the same sheet of paper (or the same board). If something needs to stand out, give it a rule, a tint or a band, never a shadow or a blur.

**The Hard Step Rule.** State changes are immediate: hover fills, open sections, chevrons, selections, the live highlight going on and off. No transitions, no animations, no easing.

## Shapes

Rectangles with a barely softened corner. Controls, badges, tags and the popover take 2px (`rounded.sm`); rows, bands, the chart and the header take none. Borders are 1px: field grey around interactive things, hairline between rows, ink under the hour band, the chart baseline and axis ticks. Small marks are geometry, not glyphs: square 10px legend swatches, CSS-drawn chevrons (two border sides rotated) on rail sections, CSS triangles for sort direction, and one inline SVG for the Display control.

## Components

### Buttons
Plain, outlined, bold-labelled, like the controls on a ticket machine.
- **Shape:** 2px corners, 32px tall (24px small), 1px field-grey border.
- **Default:** ground fill, ink text, 600 weight, 12px horizontal padding.
- **Primary:** signal red fill and border, white text; deeper red on hover. One per screen (Search).
- **Hover / Focus:** hover fills with band grey instantly; focus is a 2px outline in the accent (navy / yellow) with a 2px offset; on the header band the focus outline is white.
- **On the header band:** transparent fill, white text, platform-rule border.
- **Link button:** no border or padding; turns to the accent on hover. Used for the timestamp that opens context.

### Chips
- **Silent badge:** signal red fill, ground-coloured text, micro type, 2px corners, after a host name.
- **Tag:** outlined in field grey, pencil-grey micro text at 400; clickable to filter.

### Cards / Containers
There are no cards. Containers are bands and sheets:
- **Rail sections:** collapsible `details` separated by hairlines, 16px padding, bold title with a grey count.
- **Context panel:** notice tint, indented 32px, monospace lines in a grid (time, level, host, message); the current line in the stronger tint and bold.
- **Preferences popover:** ground fill, 1px field-grey border, 2px corners, 12px padding, no shadow.

### Inputs / Fields
- **Style:** 32px tall, 8px horizontal padding, 1px field-grey border, 2px corners, ground fill; placeholder in muted at full opacity. On the header band fields are white (light) or board navy (dark) with platform-rule borders.
- **Focus:** the global 2px accent outline.
- **Checkboxes:** 16px (22px on coarse pointers, where the Live label also grows to 44px), tinted with the primary red.

### Filter Chips
- **Style:** one per active filter of the last search, as a small button: 26px tall, 1px field-grey border, 2px corners, the filter name in muted, the value in bold monospace, a drawn 10px cross. Clicking removes the filter and searches again; *Clear all* (muted text button) appears from two chips.
- **Keys:** `kbd` labels in the Settings popover use bold 11px monospace in a 1px field-grey frame, 2px corners.
- **Current line:** J/K or a click marks the current stream line with the tint ground; a line focused without a time button gets the 2px focus outline inset.

### Hour Scale and New-Lines Pill
- **Hour scale:** the graduation under the chart is a row of borderless buttons (bold 11px tabular, a 1px ink tick on the left); hover turns them accent. A click scrolls the stream to that hour's band or zooms to it.
- **New-lines pill:** while reading below the top in Live mode, a fixed pill under the pinned band, in the header navy with header ink ("8 new lines above"); notice-coloured on hover. It appears and disappears in one step.

### Syntax Help, Line Actions and Empty State
- **Syntax help:** a 32px square `?` toggle beside the search on the header band (white on navy, inverted when open) opening a ground-coloured popover: muted intro, bold 12px section titles, a two-column list of examples as small monospace buttons and muted explanations.
- **Line actions:** one toolbar of three small buttons (*copy*, *JSON*, *link*) moved to the hovered or current line, top-right of its message cell; hidden on other lines. Feedback is the label itself ("copied", "copy failed") for 1.5s, switched in one step.
- **Empty state:** muted sentence, then the ways out as standard buttons (wider range, leave the zoom, remove or clear filters).

### Navigation
There is no navigation in the site sense; the header band is the control strip. Wordmark left, search taking the remaining width, filters inline, status pushed right in lavender. Rail sections act as the secondary navigation, each opened or closed with a hard-turning chevron.

### Hour Band (signature component)
A full-width band at the top of each hour of the stream: band-grey fill, 1px ink rule beneath, the hour in Hour type (ink in light, board yellow in dark), the date in muted beside it, and right-floated counts ("32 entries · 4 errors · 3 warnings") with errors in red and warnings in amber. It sticks under the header while its hour scrolls. Lines beneath it carry only grey `HH:` and bold `MM:SS`.

### Stream Row
Columns: time, level, host (600, ink), app (muted), message (monospace, pre-wrapped; one-line ellipsis when wrapping is off) with clickable `key=value` fields beneath. Hairline between rows. Level names are coloured by severity; error lines also turn their timestamp red. Every column but the message can be hidden from the Display preferences. A line that arrives through the live tail is lit on the live highlight for three seconds, then put out in one step, like a changed row on a departure board; error lines keep their red time.

### Volume Chart
A 72px SVG histogram with an ink baseline and bold hour ticks on an axis beneath. Stacked by severity by default (red, amber, navy, then the two greys), or by host or app with the series palette. Hovering a bucket tints it with the accent at 18%; dragging selects a range at 30% with an accent stroke and zooms to it.

## Do's and Don'ts

### Do:
- **Do** state the hour once, on a sticky hour band, and lead every line with bold tabular minutes:seconds with the hour prefix in grey.
- **Do** keep every figure tabular so times and counts align in columns.
- **Do** reserve red for errors and the single primary action; amber for warnings; navy for notices and structure; purple for first-seen patterns; green for recoveries.
- **Do** use board yellow as the only accent in dark, and platform navy as the accent in light.
- **Do** separate things with 1px rules (hairline between rows, ink under bands and the chart) and tints, not with boxes.
- **Do** keep corners at 2px or square, and keep everything system type, inline CSS and inline SVG.
- **Do** keep monospace for message text (messages, patterns, context lines).

### Don't:
- **Don't** add shadows, blurs, gradients or glows; the world is a printed sheet or a departure board.
- **Don't** add transitions or easing; state changes are hard steps.
- **Don't** introduce cards, KPI tiles or dashboard chrome.
- **Don't** use green-on-black terminal styling, CRT effects or neon.
- **Don't** use colour decoratively or to "brighten" a section; if it does not mean something it is ink, grey or rule.
- **Don't** add a second filled red button, or radii above 2px.
- **Don't** load web fonts, icon fonts or any external resource; the CSP forbids it and lightness is the point.
