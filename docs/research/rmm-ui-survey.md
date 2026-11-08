# How other RMMs lay out their dashboards

Survey done for Phase 3 (November 2026) from vendor docs, review sites and Tactical RMM's source. It covers NinjaOne, Datto RMM, N-able N-sight/N-central, Level, Syncro, Tactical RMM, MeshCentral, Action1, and partially Atera and Kaseya VSA 10. ConnectWise Automate has no public docs on its layout, so it's not covered.

## What each one does

**NinjaOne**
- **Navigation:** left sidebar. There's no global client switcher: you drill down from the system dashboard to an organization dashboard. [docs](https://www.ninjaone.com/docs/new-to-ninjaone/dashboards-navigation/system-organization-dashboard-navigation/)
- **Device list:**
  - Device and Health Status columns are always shown, and Organization, Location and Policy can be stacked into the Device cell.
  - Up to 20 columns; pages hold 150 rows.
  - "Save group" stores a filter.
  - Bulk actions are grouped Run / Create / Edit.
  - [docs](https://www.ninjaone.com/docs/new-to-ninjaone/search-tools/devices-search-page/)
- **Device detail:** tabs Overview, Details, Patching, Software, Activities. The header has a favourite star, an Action menu and remote buttons.
- **Health:** four states (Healthy, Needs attention, Unhealthy, Unknown), mapped from configurable conditions. Every count links to the filtered device grid. [docs](https://www.ninjaone.com/docs/endpoint-management/customize-device-health-statuses/)
- **Style:** dark mode only arrived in 2026, and was one of the most requested features.

**Datto RMM** (new UI)
- **Navigation:** a collapsible left nav plus a top bar with global search (`F`), Create and Recent history. Below 600 px the two menus merge.
- **Search:** quick results show the online state, hostname, description and site; Enter opens a full list.
- **Device summary:** cards. Chart colours change with the theme.
- **Reviews:** "too many clicks", and "the new UI is less friendly than the old one". [docs](https://rmm.datto.com/help/en/Content/3NEWUI/NEWUI.htm)

**N-able N-sight / N-central**
- N-sight shows a client/site tree, a device list, then a device pane with tabs underneath. Clients with problems sort to the top in red.
- N-central's quick search indexes nav destinations only, and lists not scoping it to the current customer as a known limitation.

**Level**
- **Device list:**
  - Default columns: Device, Status, Group, Tags, Security score, Reachability.
  - Built-in views All, New (first check-in in the last 7 days) and Ungrouped.
  - Saved views store filters, columns, widths and sort. They are personal or shared, and only admins edit shared ones.
  - Search is fuzzy across all columns.
- **Device page:** sections run down a left sub-nav: Overview, System, Manage, Users, Applications, Updates, Alerts, Automations, Monitors…
- [docs](https://docs.level.io/en/articles/9926476-device-listing)

**Syncro**
- **Asset header:** name, status, and Wake-on-LAN when the device is offline. An Actions menu holds New ticket, Reboot, Merge, Delete…
- **Tabs:** Overview, System Info, Monitoring, Antivirus, Scripts, System Checks, Installed Apps, Patches.
- **Overview:** facts in the left column; activity and the ticket log in the main column.
- [docs](https://docs.syncrosecure.com/assets-rmm/about-the-asset-details-page)

**Tactical RMM** ([source](https://github.com/amidaware/tacticalrmm-web))
- **Layout:** client tree, agent table, and subtabs below.
- **Columns:** icon columns for alert flags, platform, checks, pending patches, reboot and status; then Client, Site, Hostname, Description, User, Last response, Boot time.
- **Theme:** a dark-mode toggle stored per user on the server.
- **Gap:** columns can't be chosen, which users have asked for ([issue #2557](https://github.com/amidaware/tacticalrmm/issues/2557)).

**MeshCentral**
- Device tabs: General, Desktop, Terminal, Files, Events, Details, Console.
- A `viewmode` URL parameter deep-links straight to a tab.

**Action1**
- An "Entire Enterprise" option in the organization selector adds an Organization column.
- A 2026 release reduced spacing for dense views.
- A reviewer found dark mode's blue on black uncomfortable.

**Atera**
- Editable columns, and saved views (private or public).
- The Actions and Remote columns can't be hidden.
- Users disliked loading 20 devices at a time.
- The mobile app is rated 1.7/5.

**Kaseya VSA 10**
- Clicking a device opens a details pane on the right, which can be pinned.
- Reviewers complain that screens don't refresh, and that device details are spread across tabs and modules.

## What we took for Phase 3

| Finding | What we did |
|---|---|
| Health separate from online/offline (NinjaOne) | Server-computed health: healthy, needs attention, unhealthy, no data |
| Counts link to filtered lists (NinjaOne) | Every dashboard tile and client health count is a link; all filters live in the URL |
| Problem clients first (NinjaOne, N-sight) | Dashboard client health is sorted worst first |
| Built-in views (Level) | Agents: All, Online, Offline, Needs attention, New (7 days) |
| Organization column only for "all" (Action1) | The Client column becomes Site when the switcher selects a client |
| Search scoped, with recents (Datto, N-central) | The palette follows the client switcher, offers "search all", and shows recent agents |
| Deep-linkable tabs (MeshCentral) | `?tab=` on agent and client pages |
| An activity tab everywhere | Agent Activity tab from the audit log |
| Facts left, activity right (Syncro) | Agent overview: System column, then performance, recent jobs and volumes |
| Dark mode demanded; blue on black hard to read | Both themes from the start, default follows the OS; the dark accent is lighter and less saturated, and contrast is checked by axe in CI |
| Density and page size (Action1, NinjaOne, Atera) | Compact by default, per-user density, 25/50/100/200 rows per page |
| Screens that don't refresh (Kaseya) | Live updates over one SSE stream |
| Weak mobile apps (Atera, NinjaOne) | Triage on the web at 375 px instead of a native app |

Deferred:

- favourites and tags (NinjaOne);
- a peek drawer from the list (Kaseya);
- grouped bulk-action menus (NinjaOne), until there are more bulk actions;
- a vertical sub-nav for agent tabs (Level), until there are more than about eight.
