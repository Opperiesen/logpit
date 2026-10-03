---
version: 1
slug: "src-web-index-html"
primary_target: "src/web/index.html"
related_targets: []
---

# Surface: LogPit web UI (src/web/index.html)

Scope: full redesign of the single-page web UI. Mode: operate.
Audience and job: homelab admins triaging an incident or a doubt: find which hours and hosts carry trouble, narrow with filters, read lines, open context and traces.
Success (owner): faster triage, an identity of its own (no Primer clone), comfortable long reading.
Must stay: every existing feature, element id and API call; URL parameters; display preferences; one inline file under the existing CSP (no external resource).
Must not feel like: a SaaS dashboard (cards, giant KPIs, gradients) or a hacker costume (green on black, CRT, neon).
Build path: code-led (no image generation available).

## Direction contract

THESIS: The log stream is set like a railway timetable: the hour is stated once on a band, each line leads with its minutes and seconds in bold tabular figures, its hour receding in grey, disruptions read in red. It refuses the category default, a dark observability console with a grey histogram over undifferentiated rows.

OWN-WORLD: Light is timetable paper: white ground, ink #111, signal red #d30000 for errors and the primary action, platform navy #2d327d for the header band and notices, hairline rules. Dark is the station departure board: navy #141a46 ground, white type, board yellow #ffd23f as accent. Helvetica-family system stack, bold tabular figures, monospace only for message bodies. Flat: no shadows, radii of 2px at most.

STORY: The admin sees at once which hours and hosts carry disruptions, narrows with filters, reads the lines in a calm rhythm, and opens context or a trace in place.

FIRST VIEWPORT: Navy header band with the wordmark, a wide search, range, level, Live and the red Search button; a second row of secondary filters, views and preferences, folded behind a Filters toggle on phones. Desktop left rail: Hosts as lines (errors, warnings, silent marker), then Top values, Patterns and Alerts. Main area: legend and export bar, the volume chart, then the stream in hour bands whose band header stays pinned while scrolling. Signature move: the pinned hour band. Motion: hard steps, never easing.

Decision record: concept-seed key bfb1a9b7 (scope direction, mode operate, assigned index 7 = Pit Wall); decision page key c7def2e0 answered {"optionId":"model-pick","steer":"","buildPath":"code","buildPathFlipped":false}; choice ping sent with --kind pick.

FORM: Timetable (Swiss railway timetable books and station departure boards), position 1 of the ordered list, chosen as the pick card; seed key bfb1a9b7.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
