# Design practices for dense B2B admin dashboards

Research done in November 2026 to support a review of the web UI. It looks beyond RMMs, at the design systems and product write-ups of Linear, Vercel (Geist and the Web Interface Guidelines), Stripe, GitHub Primer, Atlassian, IBM Carbon, Radix, Grafana and Datadog, plus Nielsen Norman Group (NN/g) research. The RMM-specific competitor survey is in [rmm-ui-survey.md](rmm-ui-survey.md), and this doc doesn't repeat it.

Where a source gives no number, this doc says so rather than guessing. A few points come only from secondary sources, and those are marked.

## 1. Information density

**Row heights**
- Carbon's data table has five row sizes: xs 24 px, sm 32 px, md 40 px (the default), lg 48 px and xl 64 px. Use xl only for two-line rows. [Carbon](https://carbondesignsystem.com/components/data-table/usage/)
- The header row, toolbar, batch action bar and pagination should all match the row height: "Don't mix row heights for the table and header rows." [Carbon](https://carbondesignsystem.com/components/data-table/usage/)
- Material-derived grids use 52 px rows with a 56 px header ([MUI](https://mui.com/x/react-data-grid/row-height/), [Flutter](https://api.flutter.dev/flutter/material/DataTable/headingRowHeight.html)). Vuetify's dense rows are 32 px ([Vuetify](https://rubik.20cube.com/qiify/vuetify-data-table-row-height.html), secondary source).
- Primer's DataTable has three densities (condensed, normal and spacious), but its docs give no pixel values. [Primer](https://primer.style/product/components/data-table/)
- In practice, a dense admin UI uses 32 px rows as compact and 40 px as default.

**Font sizes**
- Primer's body sizes are 16, 14 and 12 px. Body medium is 14 px with a 1.5 line height, captions are 12 px, and titles are 16, 20 and 32 px at weight 600. [Primer](https://primer.style/product/primitives/typography/)
- Geist has 13 px label and copy styles, and its default button text is 14 px. `text-label-13` is meant for secondary lines and uses tabular numbers. [Geist](https://vercel.com/geist/typography)
- Atlassian's smallest token is 12 px, and headings should be no more than twice the body size. [Atlassian](https://atlassian.design/foundations/typography-beta/applying-typography)
- The common range for data UIs is 13 to 14 px body text and 12 px for metadata. Tailwind's `text-sm` is 14 px and `text-xs` is 12 px. A 13 px size needs a custom token.

**Tabular numerals**
- Use `font-variant-numeric: tabular-nums`, or a monospace font, wherever figures are compared. [Vercel guidelines](https://vercel.com/design/guidelines)
- On macOS the default San Francisco font draws proportional digits, so tabular figures have to be set explicitly. [CSS-Tricks](https://css-tricks.com/?p=262294)

**Line length and spacing**
- Primer keeps prose lines around 80 characters or less, left-aligned with a ragged right edge. It treats centred or justified text as atypical. [Primer](https://primer.style/foundations/typography)
- Spacing and line heights sit on a 4 px grid ([Primer](https://primer.style/foundations/typography)). Atlassian's type scale is a 1.2 ratio, rounded to multiples of 4 ([Atlassian](https://atlassian.design/foundations/typography/product-typefaces-and-scale)).
- Tailwind v4 derives all spacing from `--spacing: 0.25rem`, which is 4 px. [Tailwind](https://tailwindcss.com/docs/theme)

**Density without overload**
- Linear's 2026 refresh aimed to "keep information density without letting the interface feel overwhelming." It got there by reducing chrome rather than adding whitespace. [Linear](https://linear.app/now/behind-the-latest-design-refresh)

## 2. Color

**Perceptual colour spaces**
- Linear moved its theme generation from HSL to LCH. Each theme is now defined by three inputs (base, accent and contrast) instead of 98 variables. [Linear 2024](https://linear.app/now/how-we-redesigned-the-linear-ui)
- Stripe built its palette in CIELAB, because in HSL "yellow appears lighter than blue" at the same lightness. [Stripe](https://stripe.com/blog/accessible-color-systems)

**Contrast rules**
- In Stripe's palette, any two shades at least five steps apart pass 4.5:1 for small text. Four steps apart is enough for icons and large text. [Stripe](https://stripe.com/blog/accessible-color-systems)
- For badges, Stripe shifted both the background and the text up one step together, which kept contrast across all hues without tuning each pair. [Stripe](https://stripe.com/blog/accessible-color-systems)

**Step roles**
- Radix's 12-step scale assigns each step a job:
  - 1–2 for app backgrounds;
  - 3–5 for component backgrounds (normal, hover, pressed);
  - 6–8 for borders (8 is also the focus ring);
  - 9–10 for solid fills (10 is hover);
  - 11–12 for text.
- Steps 11 and 12 are guaranteed APCA Lc 60 and Lc 90 on step 2. [Radix](https://www.radix-ui.com/colors/docs/palette-composition/understanding-the-scale)
- Geist uses 100–300 for backgrounds, 400–600 for borders, 700–800 for high-contrast fills and 900–1000 for text. It has two background values, and the second should be used "sparingly". [Geist](https://vercel.com/geist/colors)

**APCA thresholds**
- Lc 90 is preferred for body text: 14 px at weight 400 or above.
- Lc 75 is the minimum for body text.
- Lc 60 is for other content text, such as 16 px bold or 24 px regular.
- Lc 45 is for headlines and fine icons.
- Lc 30 is the floor for placeholder and disabled text.
- Lc 15 is the floor for dividers. Anything below it should be treated as invisible.
- [APCA](https://git.apcacontrast.com/documentation/APCA_in_a_Nutshell)
- Vercel prefers APCA to WCAG 2. Its guidelines also say hover, active and focus states should have more contrast than the rest state. [Vercel guidelines](https://vercel.com/design/guidelines)

**Accent restraint**
- Linear's 2024 redesign cut back on blue in its chrome for "a more neutral, timeless look" ([Linear 2024](https://linear.app/now/how-we-redesigned-the-linear-ui)).
- Linear's 2026 refresh moved its grays from a cool blue tint to a warmer gray that is "crisp, but less saturated", and warned that going too warm looks "muddy" ([Linear 2026](https://linear.app/now/behind-the-latest-design-refresh)).

**Status colours**
- Carbon's mapping:
  - red for danger or error;
  - orange for a serious warning;
  - yellow for a regular warning;
  - green for success;
  - blue for passive information;
  - gray for drafts or not started;
  - purple for outliers.
- For a group, show the colour of its highest-attention member. [Carbon](https://carbondesignsystem.com/patterns/status-indicator-pattern/)

**Dark mode**
- Shadows are hard to see in dark mode, so higher elevations use lighter surfaces: "the higher the elevation, the lighter the surface looks." Atlassian keeps surfaces and shadows paired in dark mode. [Atlassian](https://atlassian.design/foundations/elevation)
- Material's dark base surface is #121212, and elevation adds a white overlay. Third-party summaries put the overlay at about 5% at 1dp and 9% at 4dp. [Material](https://m2.material.io/design/color/dark-theme)
- Base colours in real products: GitHub #0d1117, Spotify #121212, Material 3 #1C1B1F. Apple uses pure #000000. (secondary source, [UI/UX Atlas](https://uiux-atlas.pages.dev/lessons/color/dark-mode-design))
- "Don't assume that because UI is accessible in light mode, it will be in dark mode." [Atlassian](https://atlassian.design/foundations/elevation)
- Native controls need extra settings in dark mode. [Vercel guidelines](https://vercel.com/design/guidelines)
  - Set `color-scheme: dark` on `<html>` so scrollbars and native controls follow the theme.
  - Set explicit colours on `<select>` to avoid a Windows dark-mode bug.
  - Make `<meta name="theme-color">` match the background.

## 3. Typography hierarchy

- Primer's whole product scale is eight styles: one display, three titles, three body sizes and a caption. Titles get weight 600 and body text 400. [Primer](https://primer.style/product/primitives/typography/)
- Don't use colour as the main way to show emphasis. [Primer](https://primer.style/foundations/typography)
- Keep heading levels in semantic order and style them to fit; don't reorder heading tags to get a look. [Primer](https://primer.style/foundations/typography)
- Linear uses Inter Display for headings and regular Inter for everything else, so hierarchy comes from one family. [Linear 2024](https://linear.app/now/how-we-redesigned-the-linear-ui)
- A Primer table gets a title and an optional subtitle, with table-level actions beside the title. [Primer DataTable](https://primer.style/product/components/data-table/)
- Atlassian caps headings at twice the body size, so a 14 px body means page titles of 28 px at most. [Atlassian](https://atlassian.design/foundations/typography-beta/applying-typography)
- A "flat type hierarchy", "crushed letter spacing" and "all-caps body text" appear on impeccable.style's list of tells of generated design. [impeccable](https://impeccable.style/anti-patterns)

## 4. Tables

**Structure**
- Freeze header rows, and header columns too, when the table is larger than the screen. [NN/g](https://www.nngroup.com/articles/data-tables/)
- The first column should be a human-readable identifier, not an auto-generated ID. [NN/g](https://www.nngroup.com/articles/data-tables/)
- Put the most important columns first and keep related columns next to each other. [NN/g](https://www.nngroup.com/articles/data-tables/)
- Hiding and reordering columns should be cheap, and the table should show clearly when columns are hidden. [NN/g](https://www.nngroup.com/articles/data-tables/)

**Alignment**
- Columns are left-aligned by default. Right-align numeric columns so they can be scanned and compared. [Primer](https://primer.style/product/components/data-table/)
- Pair right alignment with tabular numerals. [Vercel guidelines](https://vercel.com/design/guidelines)

**Truncation**
- Wrap long column titles to two lines, then truncate, with the full text in a tooltip. [Carbon](https://carbondesignsystem.com/components/data-table/usage/)
- Better still, give the table enough room that it doesn't need to truncate. [Carbon](https://carbondesignsystem.com/components/data-table/usage/)
- Test layouts with short, average and very long user content. [Vercel guidelines](https://vercel.com/design/guidelines)

**Hover and striping**
- Borders, zebra striping and hover highlighting help people keep their place. [NN/g](https://www.nngroup.com/articles/data-tables/)
- Don't make hover the only way to reveal row actions. [NN/g](https://www.nngroup.com/articles/data-tables/)

**Row actions**
- Put row actions in a last column with a visually hidden "Actions" header. Each action is an icon button whose `aria-label` names the row. [Primer](https://primer.style/product/components/data-table/)
- Group several actions in a menu, and pull at most one out of it. [Primer](https://primer.style/product/components/data-table/)

**Selection and bulk actions**
- The header checkbox has three states: checked, unchecked and indeterminate. [Carbon](https://carbondesignsystem.com/components/data-table/usage/)
- Once a row is selected, a batch action bar appears at the top of the table, with a cancel button at its far right. [Carbon](https://carbondesignsystem.com/components/data-table/usage/)
- While batch mode is on, per-row actions are disabled. [Carbon](https://carbondesignsystem.com/components/data-table/usage/)
- Offer "Select all" when the same action is often applied to the whole dataset. [NN/g](https://www.nngroup.com/articles/data-tables/)

**Toolbar**
- Allow at most five toolbar actions, with the rest in an overflow menu. [Carbon](https://carbondesignsystem.com/components/data-table/usage/)
- Search sits at the left under the title. [Carbon](https://carbondesignsystem.com/components/data-table/usage/)
- Pagination always goes at the bottom. [Carbon](https://carbondesignsystem.com/components/data-table/usage/)

**Sorting**
- One column is always sorted by default. Only the sorted column shows an icon; unsorted columns show one on hover. [Primer](https://primer.style/product/components/data-table/), [Carbon](https://carbondesignsystem.com/components/data-table/usage/)

**Filter chips**
- Stripe gives each filterable attribute one chip. An empty chip shows a + and opens a menu, and an active chip shows its value and an × to clear it. [Stripe](https://docs.stripe.com/stripe-apps/patterns/filter-controls)
- Chip labels match the column headers. [Stripe](https://docs.stripe.com/stripe-apps/patterns/filter-controls)
- "Clear filters" appears at the end of the filter row, and only when a filter is active. [Stripe](https://docs.stripe.com/stripe-apps/patterns/filter-controls)
- Active filters need a clear visual indication. [NN/g](https://www.nngroup.com/articles/data-tables/)

**URL state**
- Persist filters, tabs, pagination and expanded panels in the URL. [Vercel guidelines](https://vercel.com/design/guidelines)
- Restore the scroll position on Back. [Vercel guidelines](https://vercel.com/design/guidelines)
- Use real links, so Cmd/Ctrl-click and middle-click work. [Vercel guidelines](https://vercel.com/design/guidelines)

**Empty, loading and error states**
- Never show "No records" while data is still loading. [NN/g](https://www.nngroup.com/articles/empty-state-interface-design/)
- An empty state says why the area is empty and offers the action that fills it. [NN/g](https://www.nngroup.com/articles/empty-state-interface-design/)
- Error messages say how to fix the problem, and every screen has a next step. [Vercel guidelines](https://vercel.com/design/guidelines)
- Use skeletons, not spinners, where loading will take a while. [Carbon](https://carbondesignsystem.com/components/data-table/usage/)

## 5. Navigation

**Sidebar**
- Linear's 2026 refresh made the sidebar "a few notches dimmer" so the work area leads: "Don't compete for attention you haven't earned." [Linear 2026](https://linear.app/now/behind-the-latest-design-refresh)
- The same refresh reduced and shrank icons, and removed the coloured backgrounds from team icons. [Linear 2026](https://linear.app/now/behind-the-latest-design-refresh)
- Vercel's January 2026 navigation replaced horizontal tabs with a resizable sidebar that can be hidden. [Vercel](https://vercel.com/changelog/new-dashboard-navigation-available)
  - Sidebar links are the same at team and project level.
  - "Projects as filters" switches between the team and project versions of a page in one click.
  - On mobile, a floating bottom bar replaces the sidebar.
- Cloudflare's November 2025 nav relabelled menu items by task rather than product name. Search matches both the old and new names. [Cloudflare](https://developers.cloudflare.com/changelog/post/new-cloudflare-one-navigation-and-product-experience/)

**Command palette** ([Superhuman](https://blog.superhuman.com/how-to-build-a-remarkable-command-palette/))
- One shortcut (Cmd/Ctrl+K) opens it from every screen.
- It is the one place where every command can be found.
- Each result shows its keyboard shortcut, so people learn it.
- Matching is fuzzy and covers synonyms.
- Results are ranked by the current context and by recent use.

**Breadcrumbs** ([NN/g](https://www.nngroup.com/articles/breadcrumbs/))
- Show the place in the hierarchy, not the click history.
- The last item, the current page, is not a link.
- Breadcrumbs are only needed on deep hierarchies. On mobile, show the last level or two.

**Keyboard** ([Vercel guidelines](https://vercel.com/design/guidelines))
- All flows are keyboard-operable, following WAI-ARIA patterns.
- Focus rings are visible, using `:focus-visible`.
- Sticky headers never cover the focused element.
- Hit targets are at least 24 px, or 44 px on mobile.

## 6. Status and health indicators

**Never colour alone** ([Carbon](https://carbondesignsystem.com/patterns/status-indicator-pattern/))
- Each indicator uses at least two of colour, shape and symbol: "Relying solely on color to convey status is insufficient."
- Status colours need 3:1 contrast against each other and against the background.
- Light orange and yellow shapes also need outlines.

**Which indicator** ([Carbon](https://carbondesignsystem.com/patterns/status-indicator-pattern/))
- Icon indicators (icon, shape, colour and inline label) are for system-wide feedback that needs attention.
- Shape indicators (shape, colour and label) are for small spaces and for scanning large datasets, such as a table status column. Put the shape before the label.
- Dot badges are for "something new" in the header; numbered badges are for counts.
- Change indicators need a +/− sign, a caret or an arrow.
- "Avoid using status indicators when no user action is required."
- Icons alone are acceptable at 3:1 non-text contrast, but Carbon recommends a label.

**Restraint**
- Indicators are passive and need no action. Reserve intrusive treatment for things that need a response. [NN/g](https://www.nngroup.com/articles/indicators-validations-notifications/)
- Keep colour meanings fixed across the app, for example green for good and red for bad through thresholds. [Grafana](https://grafana.com/docs/grafana/latest/visualizations/dashboards/build-dashboards/best-practices/)

## 7. Dashboards and overview pages

**Purpose**
- A dashboard communicates critical information "with a minimum of interaction or cognitive processing". It isn't a portal or a place to explore. [NN/g](https://www.nngroup.com/articles/dashboards-preattentive/)
- An operational dashboard should "impart critical information quickly". [NN/g](https://www.nngroup.com/articles/dashboards-preattentive/)
- "A dashboard with just a couple of widgets is perfectly valid, if it has a clear goal." Datadog also asks for a clear description and for related widgets to be grouped. [Datadog](https://github.com/DataDog/effective-dashboards/blob/master/guidelines.md)

**What to show** ([Grafana](https://grafana.com/docs/grafana/latest/visualizations/dashboards/build-dashboards/best-practices/))
- Show symptoms that affect users (RED) ahead of machine resources (USE).
- For a "which servers are unhealthy" question, show only the servers in trouble.
- Normalise units, for example CPU as a percentage rather than a core count.

**Linking**
- Build dashboards as a hierarchy that drills down a level at a time, and link to them from alerts. [Grafana](https://grafana.com/docs/grafana/latest/visualizations/dashboards/build-dashboards/best-practices/)

**KPI tiles**
- Datadog's "query value" widget (one big number) is for KPIs. It works better with a timeseries background than left blank. [Datadog docs](https://docs.datadoghq.com/extend/integrations/create-an-integration-dashboard/)
- "Hero metric layout" appears on impeccable.style's list of tells of generated design, so only use big numbers when the number matters. [impeccable](https://impeccable.style/anti-patterns)

**Charts**
- Length and 2D position are read accurately, so bar charts (sorted), line charts and scatter plots work well. [NN/g](https://www.nngroup.com/articles/dashboards-preattentive/)
- Avoid pie and donut charts, gauges and 3D. Don't use colour to encode magnitude. [NN/g](https://www.nngroup.com/articles/dashboards-preattentive/)
- Turn stacking off in most cases, because stacked graphs can mislead. [Grafana](https://grafana.com/docs/grafana/latest/visualizations/dashboards/build-dashboards/best-practices/)
- Timeseries need a minimum width: Datadog sets 4 of 12 columns. [Datadog](https://github.com/DataDog/effective-dashboards/blob/master/guidelines.md)

**Refresh**
- Don't refresh more often than the data changes. [Grafana](https://grafana.com/docs/grafana/latest/visualizations/dashboards/build-dashboards/best-practices/)

## 8. Forms, overlays, confirmations and toasts

**Modals**
- Keep modals for short, direct exchanges: warnings that prevent irreversible errors, or input a user-started task needs to continue. [NN/g](https://www.nngroup.com/articles/modal-nonmodal-dialog/)
- Don't put complex tasks in a modal. [NN/g](https://www.nngroup.com/articles/modal-nonmodal-dialog/)
- Overused modals train people to dismiss them. [NN/g](https://www.nngroup.com/articles/modal-nonmodal-dialog/)

**Drawers**
- Atlassian has marked its drawer component for deprecation in favour of modals. [Atlassian](https://atlassian.design/components/drawer)
- There is no consensus on drawers. A rough rule: a modal holds a single task, a drawer extends the current one while keeping context, and a full page is for anything long or that needs a URL.

**Destructive confirmations** ([NN/g](https://www.nngroup.com/articles/confirmation-dialog/))
- Confirm only serious or irreversible actions; confirming routine ones "cries wolf".
- Say exactly what will happen.
- Label buttons with the outcome ("Delete file" / "Keep file"), not Yes/No.
- Don't pre-select the confirm button.
- For rare, severe actions, require a non-standard step such as typing a name.
- "Do go to great lengths to provide undo."
- Vercel: require confirmation or offer Undo, and warn before leaving with unsaved data. [Vercel guidelines](https://vercel.com/design/guidelines)

**Notifications** ([Carbon](https://carbondesignsystem.com/components/notification/usage/))
- Inline notifications never auto-dismiss, and are capped at two lines.
- Toasts sit top right, newest on top, at most two lines. They auto-dismiss after 5 s if configured to.
- A notification has at most one action, and an actionable notification doesn't auto-dismiss.

**Toasts and errors**
- Toasts are "a bad way to implement an error message". In NN/g's example, a user missed an error toast and then waited five minutes. [NN/g](https://www.nngroup.com/articles/indicators-validations-notifications/)
- Announce toasts and validation messages through a polite `aria-live` region. [Vercel guidelines](https://vercel.com/design/guidelines)

**Submits** ([Vercel guidelines](https://vercel.com/design/guidelines))
- While a submit is in flight, disable the control and show a spinner, but keep the button's label.
- Send an idempotency key.
- Label loading states with an ellipsis, such as "Saving…".

## 9. Motion and feedback

**Durations** ([Carbon](https://carbondesignsystem.com/elements/motion/overview/))
- 70 ms for button and toggle feedback.
- 110 ms for fades.
- 150 ms for small expansions.
- 240 ms for larger expansions and toasts.
- 400 ms for large expansions.
- 700 ms for background dimming.
- Longer moves take longer.
- Use "productive" easing, `cubic-bezier(0.2, 0, 0.38, 0.9)`, for tables, dropdowns and buttons. Keep "expressive" motion for rare, important moments.
- A Vercel-published animation skill keeps UI animation under 300 ms, and modals and drawers at 200–300 ms. (secondary source, [mirror](https://mcpservers.org/agent-skills/vercel/web-animation-design))

**Animation rules** ([Vercel guidelines](https://vercel.com/design/guidelines))
- Animate only `transform` and `opacity`, and never use `transition: all`.
- Honour `prefers-reduced-motion`.
- Let user input interrupt animations.

**Loading** ([Vercel guidelines](https://vercel.com/design/guidelines))
- Wait about 150–300 ms before showing a spinner or skeleton, then keep it visible for at least 300–500 ms so it doesn't flicker.
- Skeletons match the final layout's dimensions, so nothing shifts.

**Skeletons, spinners and progress bars** ([NN/g](https://www.nngroup.com/articles/skeleton-screens/), [NN/g](https://www.nngroup.com/articles/progress-indicators/))
- Under 1 s, show no indicator.
- Use skeletons for full-page loads of up to about 10 s.
- Use a spinner for a single module at about 2–10 s.
- Over 10 s, use a percent-done bar with an estimate.
- Content skeletons that mirror the layout are better than frame-only ones.
- For batches, show counts, such as "Updating 3 of 50".

**Optimistic UI**
- Update immediately when success is likely, and reconcile with the server's reply. On failure, roll back or offer Undo. [Vercel guidelines](https://vercel.com/design/guidelines)
- Aim to complete writes in under 500 ms. [Vercel guidelines](https://vercel.com/design/guidelines)

## 10. Anti-patterns that read as "template" or "generated"

**Overused cards** ([NN/g](https://www.nngroup.com/articles/cards-component/))
- Cards are poor for searching, scanning and comparing, and show fewer items per screen.
- Cards suit mixed content, not as "a modern-looking replacement for a list."
- For homogeneous records, use a list or table.

**impeccable.style's catalogue** ([impeccable](https://impeccable.style/anti-patterns))
- "Cardocalypse" and nested cards.
- Grids of identical cards.
- "Side-tab accent border".
- A hairline border with a wide shadow.
- Glassmorphism.
- Gradient text and radial glow halos.
- "Dark mode with glowing accents" and "Neon on dark".
- "Extreme border-radius on cards".
- "Massive icons" and an icon tile stacked above a heading.
- A badge or label above every heading.
- "Monotonous spacing".
- "Inter everywhere" and a flat type hierarchy.
- Gray text on coloured backgrounds.

**Generated-dashboard defaults**
- Developer write-ups name the same defaults: an indigo or purple gradient, Inter, rounded cards with drop shadows everywhere, and a centred hero followed by three feature cards. They trace this to models reproducing Tailwind and shadcn defaults. (secondary sources, [DEV](https://dev.to/alanwest/why-every-ai-built-website-looks-the-same-blame-tailwinds-indigo-500-3h2p), [DEV](https://dev.to/alanwest/how-to-fix-the-ai-generated-look-in-your-frontend-1ahh))

**Signs from the design systems**
- Linear's 2026 refresh removed separators that had "quietly proliferated" and softened border contrast so structure is "felt not seen". [Linear 2026](https://linear.app/now/behind-the-latest-design-refresh)
- Linear also cut icon use where it had "grown excessive". [Linear 2026](https://linear.app/now/behind-the-latest-design-refresh)
- Carbon warns against status indicators where no action is needed. [Carbon](https://carbondesignsystem.com/patterns/status-indicator-pattern/)
- A child element's corner radius should not exceed its parent's, and the two should be concentric. [Vercel guidelines](https://vercel.com/design/guidelines)
- Primer treats centred text as atypical for product UI. [Primer](https://primer.style/foundations/typography)

## Checklist for reviewing our UI

Each item should be checkable by looking at the page or the code.

**Density and type**
1. Compact rows are 32 px and default rows 40 px. The header, toolbar and pagination match the row height.
2. Body text is 13–14 px and metadata 12 px. The app uses no more than about 6 distinct font sizes.
3. Page titles are at most twice the body size. Hierarchy comes mostly from weight (400/500/600), not size or colour.
4. Every numeric column and live counter uses `tabular-nums` and is right-aligned, header included.
5. Spacing values come from the 4 px scale, with no arbitrary `[13px]`-style values.

**Colour and themes**
6. Body text passes APCA Lc 75 (or WCAG 4.5:1) and secondary text passes Lc 60, in both themes. Placeholder and disabled text pass at least Lc 30.
7. The accent colour appears only on primary actions, links, focus and selection, not as decoration.
8. The dark background isn't pure black. Raised surfaces (popovers, dialogs) are lighter than the page, not only shadowed.
9. Dark mode sets `color-scheme: dark`, a matching `theme-color` and explicit `<select>` colours.
10. Status colours have one fixed meaning each across the app and pass 3:1 against the background.

**Status**
11. Every status uses at least two of colour, shape and icon, plus a text label (or `aria-label`) wherever space allows.

**Tables**
12. Table headers stay sticky when scrolling, and the first column is the human-readable name.
13. Truncated cells show the full value in a tooltip or `title`, and work with long hostnames.
14. Row actions are reachable without hover, and each has an `aria-label` naming the row.
15. Selecting rows shows a batch bar with a count, its actions and Cancel. The header checkbox has an indeterminate state.
16. Active filters show as chips with their values. "Clear filters" appears only when a filter is active, and filters, sort, page and tab all live in the URL.
17. Each list has a distinct loading state (a skeleton matching the rows), an empty state (why it's empty, plus the action that fills it) and an error state (what failed, plus retry). "No results" never shows while loading.

**Dashboard**
18. Dashboard counts are links to the filtered list. The page answers "what needs attention now" above the fold.
19. Charts are lines or bars only, with no pies, gauges or 3D. Units are normalised, and stacking is off.

**Navigation and keyboard**
20. The command palette opens with Ctrl/Cmd+K on every page and shows shortcuts beside its commands.
21. The sidebar is visually quieter than the content. The current page is clearly marked, and the last breadcrumb is not a link.
22. Every interactive element has a visible `:focus-visible` ring, nothing sticky hides the focused element, and hit targets are at least 24 px.

**Feedback and motion**
23. Destructive confirmations name the object and use outcome labels ("Delete agent" / "Cancel"). Nothing is pre-selected. Rare, severe actions (deleting a client) require typing the name, and Undo is offered where possible.
24. Errors are never shown only in an auto-dismissing toast. Toasts are announced through `aria-live`.
25. Transitions are 100–250 ms and animate only `transform` and `opacity`, with no `transition: all`. `prefers-reduced-motion` is respected, and spinners are delayed about 150–300 ms to avoid flicker.
26. Card count audit: no nested cards, no identical card grids standing in for a table, and no gradients or glow. Corner radius is at most about 8 px on containers, with children no rounder than their parents.
27. There is no emoji in UI chrome, no badge or label above every heading, and no icon on every button and heading.
