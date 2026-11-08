# Phase 3 UI review (November 2026)

A review of the redesigned dashboard against the Playwright baselines in `web/tests/visual/__screenshots__/` (1440 px desktop, 375 px phone, light and dark). The foundation is sound: role-based tokens, a real component library, keyboard-first shell, light/dark parity, 0 svelte-check errors. The issues below are mostly consistency and signal-to-noise, not structure.

## Cross-cutting

1. **Two status columns compete.** Agent tables show Status (dot + text) and Health (tinted pill) side by side, so most rows carry two coloured signals. Health pills with icon + tint on *every* row (including "Healthy") make the problems harder to spot. Quiet the normal state (no fill for Healthy/Online), and spend colour only on exceptions.
2. **Badge text is smaller than the row text and sits off-baseline.** Pills are ~11 px inside 14 px rows; Status text renders lower than neighbouring cells (visible in the Agents and Client tables). Badges and status should share the cell's font size or one step down, vertically centred on the text baseline.
3. **KPI tiles are inconsistent.** The dashboard tiles have tinted icon chips and coloured numbers; the client page tiles have no icons, smaller numbers, and a non-metric ("Client since"). Pick one KPI component. Numbers should be neutral when the count is 0 and only take warning/danger colour when non-zero. Decorative tinted icon squares are a template tell.
4. **Usage bars everywhere.** Every CPU/Memory/Disk cell has a bar plus a percentage. Bars duplicate the number and add noise across 3 columns × N rows. Prefer the number (tabular, right-aligned) with colour only past a threshold, or a bar only for the one metric being sorted on / over threshold.
5. **Filter "views" look like a different component from tabs.** Agents/Jobs use a segmented control for built-in views (All / Online / Offline / Needs attention / New); detail pages use underline tabs. Counts appear only on "All". Views should show counts for each (they're the point of the "every count links to a filtered list" health model) and should not truncate on phone without a scroll affordance ("New (7 days" is clipped at 375 px).
6. **Live indicator is an unlabeled amber dot** in the top bar. Amber reads as a warning. Use a labelled state (tooltip + visually hidden text at minimum) and green/neutral for "connected".
7. **Underlined small links** ("All offline", "All failed", "Sort agents by disk", "Open in Agents for filters and bulk actions") look like 2010-era web links inside an app. Use quiet text buttons/links with arrow affordance, underline on hover.

## Dashboard

8. **Duplicate metrics.** "Offline 2/7" (tile) and "Agents online 5/7" (Fleet card) say the same thing; "Need attention 3" vs "Healthy 3". The Fleet card nests four tinted tiles inside a card (card-in-card).
9. **Column imbalance.** The left column ends ~100 px above the right; the bottom-left is empty. Consider a single prioritised feed of problems (offline, failed jobs, full disks) and moving fleet composition into a slimmer side rail or a strip under the KPIs.
10. **Clients by health** mixes pills, plain text ("1 offline") and a mini bar with its own "3/4 online" label in tiny type. Simplify to counts in fixed columns so clients compare vertically.

## Agents list

11. **Table overflows at 1440 px**: "Last seen" is clipped at the right edge with no horizontal-scroll cue. Default visible columns need to fit a 1440 viewport with the sidebar open, or the table needs a sticky first column + scroll shadow.
12. OS cell repeats "Windows Server 2022" in full weight; it can be muted, and the OS icon alone conveys family.

## Agent detail

13. **Header row mixes four styles** (bold name, green text status, amber pill, icon + OS text). Group the metadata as one muted line under the name.
14. **Charts have no axes.** No time labels or y-scale; three charts use three unrelated hues (blue, purple, teal), implying different meanings. Use one series colour with a 0–100 % scale, a time axis, and a hover crosshair.
15. **Mock data contradicts itself**: the meter row says CPU 71 % / memory 83 % while the charts say "now 22 %" / "now 45 %". Fix the mock in `tests/visual/mock.ts` so screenshots don't normalise a real-looking bug.
16. System card values mix mono (kernel, agent version, ID) and sans at different sizes; mono is fine for IDs, but match the size.

## Jobs

17. **Repeated "Rerun" text buttons** on every row are noise; show on row hover/focus or use an icon button with tooltip, and keep them in a fixed actions column.
18. Empty Exit cells for running/queued/timed-out jobs should show an em dash like other tables.

## Phone

19. Search and OS filter stack awkwardly; the column-picker button floats beside them. On phone, collapse filters behind a single "Filters" button.
