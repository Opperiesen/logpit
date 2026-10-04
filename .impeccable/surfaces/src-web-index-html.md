---
version: 1
slug: "src-web-index-html"
primary_target: "src/web/index.html"
related_targets: ["src/web/pages.html","src/web/theme.css"]
---

# Surface: LogPit web UI (src/web/index.html)

Scope: replacement of the visual world of the search screen, then board, host, admin and compare in the same system. Mode: operate.
Audience and job: homelab admins triaging an incident or a doubt: see at once which hosts are active, noisy or silent, find the hours that carry trouble, narrow with filters, read lines, open context and traces.
Owner's brief (2026-10-05): the current UI lacks modernity, has no visual system feel, is static and dull. References for craft and feel: Better Stack and Raycast. "Alive" means, in order: data that moves (live lines arriving smoothly, chart updating, counters animating), micro-interactions (hover, panels, chips, view transitions), system state visible without opening a panel (active hosts pulse, a host going silent or noisy is signalled).
Success: faster triage, an interface that feels current and alive, comfortable long reading.
Must stay: every existing feature, element id and API call; URL parameters; display preferences (theme auto/light/dark, time format, density, wrapping, columns); keyboard paths and accessible names; one inline file under the existing CSP (no external resource); vanilla, no build step.
Must not feel like: a generic SaaS dashboard (KPI tiles, gradients for decoration), a hacker costume (green on black, CRT, neon), or a sports app costume (no goals, cards or football words in the labels).
Build path: code-led (no image generation available).

## Direction contract

THESIS: The homelab reads like a live match centre: a momentum curve shows who is pushing right now, every incident lands on the timeline at its minute, and each host carries its recent form. It refuses the category default: a static grey histogram over undifferentiated rows that only change when you press Search.

OWN-WORLD: Night-stadium dark by default: ground #0e1015, raised surfaces #171a21 with soft 1px inner borders and 8px radii, ink #e8eaf0. LIVE red #ff4d4f for errors and the live badge, green #34d399 for healthy, amber #fbbf24 for warnings, violet #8b7cff reserved for the viewer's focus only. Light mode is daytime pitch-side: white ground, the same state hues deepened for contrast. System sans at a real scale, tabular figures everywhere, monospace for message bodies only. Motion is material: easing 160-240ms, springs on panels, rolling numbers.

STORY: The admin opens the page and sees at once which hosts are talking (pulsing dots) and how each has been doing (form pips); the momentum curve shows where errors pushed; dragging across it dims the lines outside the range and counts what it holds as it moves, and releasing zooms every panel to it; lines slide in as they arrive; one click opens context, already loaded.

FIRST VIEWPORT: Top: a Raycast-style command bar (search, level, range, Live badge pulsing red when on, Search), secondary filters as chips under it. Left rail: the host squad, one row per host with name, a live pulse dot, five form pips (ok/warn/err per recent interval), a proportional volume bar, error and warning counts. Main: the momentum curve (volume above a baseline, errors mirrored below in red, alerts as markers on an incident timeline under it), then the stream with sticky hour bands and rows that slide in. Signature move: the momentum curve with its incident timeline, brushed live.

Raises (named for their donors): Orienteering map: violet is reserved for the viewer's focus (selection, active filter, zoomed range) and never encodes data. Metro tiles: figures change in place by rolling to their new value. Type specimen: one gesture drives the page continuously (brushing the curve dims the stream outside the range and counts it as it moves; releasing zooms stream, hosts, patterns and chart to it). Ticket wallet: nothing disappears, it cancels (a resolved alert stays on the timeline, marked recovered). Manual tab rail: the rail shows extent (each host row carries a bar proportional to its volume). Vertical feed: the next thing is already loaded (a line's context is prefetched on hover).

FORM: Live sports match centre (momentum graph, minute-by-minute feed, team form guide), position 7 of the ordered list, seed key 8ed949e7.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
