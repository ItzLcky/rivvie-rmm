# Vulnerabilities

Known vulnerabilities in the software installed on each device: Linux packages against their distribution's own advisories (which account for backported fixes), Arch packages against the Arch security tracker, and Windows applications against NVD through a curated product map. CISA's Known Exploited Vulnerabilities catalogue and EPSS scores rank them. Built as phase E of the [parity plan](parity-plan.md).

Out of scope: language ecosystems (npm, PyPI) and container images, Windows OS CVEs (missing KBs are already patch management), macOS, configuration checks (CIS), a network scanner, Ubuntu Pro/ESM entitlements.

## Inventory

The agent's software inventory gained, all `#[serde(default)]` (old agents and old servers keep working; covered by unit round-trips in `rmm-proto`):

- `Software.source_name`: the source package when it differs from the name: dpkg `${source:Package}`, rpm from `%{SOURCERPM}`, apk's origin. Debian and Ubuntu publish by source package.
- rpm versions carry the epoch when there is one (`1:3.0.7-24.el9`, as `rpm -q` prints it; the plan's `%{EPOCHNUM}:` always would have written `0:`, which compares the same).
- `SystemInfo.os_id` and `os_version_id` from `/etc/os-release` (`ID`, `VERSION_ID`).
- dpkg packages in the `rc` state (removed, configuration left) are no longer listed: they would have looked installed at an old version.
- Alpine packages (`apk list --installed`) are listed now; there was no Alpine inventory before.

No new agent messages.

## Ecosystems

`vuln::ecosystem` derives what a device is matched against:

| os-release / packages | Ecosystem | Feed | Versions |
|---|---|---|---|
| `debian` 12 | `Debian:12` | `osv:Debian` | dpkg |
| `ubuntu` 24.04 | `Ubuntu:24.04` (OSV's `:LTS` dropped, `Ubuntu:Pro:*` ignored) | `osv:Ubuntu` | dpkg |
| `almalinux`, `rocky`, `rhel` 9.x | `AlmaLinux:9`, `Rocky Linux:9`, `Red Hat:9` (from `Red Hat:enterprise_linux:9::*`; EUS streams ignored) | `osv:…` | rpm |
| `sles` 15.5, `opensuse-leap` 15.5, `opensuse-tumbleweed` | `SUSE:Linux Enterprise Server 15 SP5`, `openSUSE:Leap 15.5`, `openSUSE:Tumbleweed` | `osv:SUSE`, `osv:openSUSE` | rpm |
| `alpine` 3.19.1 | `Alpine:v3.19` | `osv:Alpine` | apk |
| any device with pacman packages (Arch, Manjaro, CachyOS, …) | `Arch` | `arch` | pacman |
| Windows | `Windows` (ranges in `NVD`) | `nvd` | dotted |

A Linux agent without `os_id` is "not assessed: update the agent"; other distributions (and macOS) are "operating system not covered". Derivatives other than Arch's (Mint, Pop!_OS) aren't mapped to their parent: their `VERSION_ID` isn't the parent's.

## Version comparison

`vuln/version.rs` has one comparer per scheme, each following its package manager's code: dpkg (`verrevcmp`, `~` before everything), rpm (`rpmvercmp` with `~` and `^`, plus epoch, and the release only when both sides have one), pacman (libalpm's older rpmvercmp that weighs separators and never lets a trailing alpha segment win), apk (digits, letter, `_alpha`…`_p` suffixes, `-rN`), and a dotted-numeric one for Windows `DisplayVersion`s and NVD ranges (missing components are 0). The unit tests use vectors from dpkg's, rpm's, pacman's and apk-tools' own test suites. A range is `introduced` (inclusive, or exclusive for NVD's `versionStartExcluding`) up to `fixed` (exclusive) or `last_affected` (inclusive).

## Feeds

Mirrored into Postgres, never looked up live: no inventory leaves the instance, there are no per-request rate limits at fleet size, and tests are deterministic. `vuln/feeds.rs`:

| Feed | Source (override) | |
|---|---|---|
| `osv:<Ecosystem>` | `RMM_VULN_OSV_URL/<Ecosystem>/all.zip` (`https://osv-vulnerabilities.storage.googleapis.com`) | streamed to a temporary file, read entry by entry in a blocking thread (`vuln/zip.rs`, zip64 aware, no new dependency), stored in batches of 500 with progress |
| `arch` | `RMM_VULN_ARCH_URL` (`https://security.archlinux.org/issues/all.json`) | one AVG per group; `Not affected` skipped; `Vulnerable` without a fix affects every version |
| `nvd` | `RMM_VULN_NVD_URL` (`https://services.nvd.nist.gov/rest/json/cves/2.0`), `RMM_NVD_API_KEY` | per mapped product that some Windows device has installed (`virtualMatchString=cpe:2.3:a:<vendor>:<product>`), in full the first time and by `lastModStartDate` (within NVD's 120-day window) after that; 6.5 s between requests without a key, 0.7 s with one |
| `kev` | `RMM_VULN_KEV_URL` (CISA's JSON) | |
| `epss` | `RMM_VULN_EPSS_URL` (`https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`) | gzipped or plain; only CVEs an advisory names are kept |

Only feeds the fleet needs are synced (an ecosystem some device is in; KEV and EPSS once any is). The worker looks every hour, first an hour after start (a fresh install gets its inventory in first, and restarts don't hammer the feeds), and syncs feeds older than `RMM_VULN_SYNC_HOURS` (24; 0 turns the automatic sync off). Downloads are conditional (ETag, Last-Modified). After a full dump, the feed's advisories that weren't in it are deleted (unless more than a tenth of its records failed to parse). One sync runs at a time. `POST /vulnerabilities/sync` starts one in the background.

OSV records are parsed into one `Advisory` type (`vuln/osv.rs`), which the Arch and NVD parsers also produce: severity from the best CVSS v3 vector (base score computed here, per the specification), else the vendor's word (Ubuntu priority, Debian urgency, Red Hat or SUSE rating). Bare `CVE-…` ids (Alpine's) are namespaced (`ALPINE-CVE-…`) so they don't collide with NVD's records of the same CVE.

`rmm-server vuln-import <dir>` loads the same files from a directory for air-gapped installs: `*.zip` OSV dumps named after their ecosystem (`Debian/all.zip` or `Debian.zip`), and `*.json` and `*.csv[.gz]` files told apart by shape (Arch array, KEV catalogue, saved NVD API pages, single OSV records, EPSS). A running server picks the result up within ten seconds (the evaluation queue is in the database).

## Data

Migration `0048_vulnerabilities.sql`: `vuln_feeds`, `vulns`, `vuln_ranges` (indexed by `(ecosystem, package)`), `vuln_products`, `vuln_findings` (primary key `(agent_id, vuln_id, package)`), `vuln_acceptances`, and on `agents` `vuln_evaluated_at`, `vuln_inventory_hash`, `vuln_ecosystem`, `vuln_unassessed`, `vuln_critical`, `vuln_high`. Additions to the plan:

- `vuln_cve_scores (cve, epss, epss_percentile, kev, kev_added, kev_due)`: KEV and EPSS by CVE, copied onto `vulns.epss`/`kev` after every sync, so an advisory imported after them still gets them.
- `vuln_ranges.introduced_exclusive` (NVD's `versionStartExcluding`).
- `vuln_products.builtin`, `hidden` (removing a built-in mapping hides it, so the seed doesn't bring it back) and `nvd_synced_at` (the per-product NVD cursor).
- `vuln_findings.software_name` (the installed package or title the finding came through) and `product_id`.
- `vuln_accepted(agent, vuln, cve)`, a SQL function used by every count.

**Storage rule:** a finding is stored only when a fix exists, or the severity is high or critical, or the CVE is known exploited. Resolved findings keep `resolved_at`; one that comes back starts a new `first_seen`.

## Matching

`vuln/matcher.rs`. When an inventory arrives, its hash (OS ids and the software list) is compared with `vuln_inventory_hash`; if it changed, `vuln_evaluated_at` is cleared, which queues the device. The worker evaluates the queue 50 at a time; after a sync every device is queued again. No `agent_software` table: the inventory JSON is read.

Linux: one lookup by `(ecosystem, package = ANY(names))`, by source package on Debian and Ubuntu and by binary and source name elsewhere; a package installed more than once (kernels) counts at its newest version. Windows: each title goes through the product map (case-insensitive `*` globs on the title, and on the publisher when the mapping has one; the longest matching pattern wins, so `Mozilla Firefox ESR*` beats `Mozilla Firefox*`), every installed version counting. Titles are never fuzzy-matched to CPEs: a wrong match would destroy trust in the list. `content/vuln/products.json` seeds about 150 common applications (applications whose registry version isn't comparable with NVD's, such as Python's `3.12.1150.0` and Java's `8.0.3910.13`, are left out). The CPE names were written from memory of the NVD dictionary; a wrong one only means no data for that product, never a false finding, but they should be checked against the dictionary.

## Alert

Kind `vulnerability` (in `policy::ALERT_KINDS`, so also an automation trigger), params `{min_severity: "critical", kev_only: false, fix_available_only: true, older_than_days: 14, min_epss: null}`, all conditions together. **One alert per device** (key `""`), titled "3 vulnerabilities to fix (1 critical, 2 high)", with the counts and the top five CVEs in `details` (worst severity, then KEV, EPSS, CVSS). Accepted findings don't count. It is re-checked after every evaluation, an acceptance or its removal, a policy change (`alerts::recheck_item`/`recheck_agent`), and on the clock (every `RMM_ALERT_EVAL_SECS`, at most a minute) for acceptances that expired and findings that just became older than an item's `older_than_days`. Health follows from open alerts as for every kind.

## Accepting risk

`vuln_acceptances`: a CVE (or advisory id) for one device, or every device of a client, with a note and an optional expiry. Accepted findings stay listed, marked, but leave the counts, the alert and the default lists (`?accepted=true` shows them). `vuln.accept` and `vuln.unaccept` are audited.

## Remediation

Each finding carries a `remediation`: the device's pending update for the package (Linux: a `patches` row whose id is the package, or `name.arch` on dnf) with Approve & install through `POST /patches/install`; for a Windows product mapped to a global catalog package, "Upgrade with <package>" through `POST /software/deploy {op: "upgrade"}`; a mapped product without one links to the catalog; otherwise the fixed version. A `latest` software policy item is the standing fix.

## API

`api/vulns.rs`. Reads need `security.read`, accepting `security.respond`, products, feeds and sync `security.manage`.

| | |
|---|---|
| `GET /vulnerabilities` | paged, one row per CVE (advisories without one stand alone), device counts; filters `client_id`, `severity`, `kev`, `fix`, `accepted`, `q`; sorts `severity` (default), `devices`, `cvss`, `epss`, `published`, `first_seen`, `cve` |
| `GET /vulnerabilities/summary` | counts for the dashboard and a client's overview (from the stored per-device counts) |
| `GET /vulnerabilities/{id}` | the advisories about a CVE, their ranges, KEV and EPSS, acceptances |
| `GET /vulnerabilities/{id}/devices` | with each finding's remediation |
| `GET /agents/{id}/vulnerabilities` | the device's findings and whether (and why not) it is assessed |
| `GET /vulnerabilities/agents` | by device (an addition: the "By device" tab needs it) |
| `GET /vulnerabilities/software` | by package or product |
| `GET /vulnerabilities/unassessed` | devices not assessed and why, and Windows titles the map doesn't cover |
| `POST /vulnerabilities/acceptances`, `DELETE /vulnerabilities/acceptances/{id}` | |
| `GET /vulnerabilities/feeds`, `PUT /vulnerabilities/feeds/{name}` (`enabled`), `POST /vulnerabilities/sync` | status, progress and attribution |
| `GET|POST /vulnerabilities/products`, `PUT|DELETE /vulnerabilities/products/{id}` | the product map; vendor and product are CPE names (lowercase, no spaces or colons); a changed map re-evaluates Windows devices and asks NVD about new products |

Audit: `vuln.accept`, `vuln.unaccept`, `vuln.product.create|update|delete`, `vuln.feed.update`, `vuln.sync` (also from `vuln-import`). Public API (group `security`): `listVulnerabilities`, `listVulnerabilityDevices`, `listAgentVulnerabilities`, `listVulnerableSoftware`.

## UI

`/vulnerabilities` (Monitoring in the sidebar after Security, `g z`) with tabs By CVE, By device, By software, Not assessed (with "Map" for unmapped titles) and, for `security.manage`, Feeds & products (sync status and progress, enable switches, the attribution texts NVD and OSV ask for, and the product map editor). The plan put the feeds under Settings → Security; there is no such page (the Security page's Settings tab is endpoint protection, and another track is adding to that page), so they live here. `/vulnerabilities/[id]`: scores, KEV, EPSS, the affected devices with their fix and accept-risk, acceptances, advisories and ranges. A Vulnerabilities tab on the agent (`AgentVulnerabilities.svelte`). A one-line summary on the dashboard and a client's overview (`VulnStrip.svelte`). The `Vulnerabilities` kind in the alert form. A "Vulnerabilities" block in the QBR (devices assessed and affected, open critical and high, found and fixed in the period, the ten worst open CVEs), for users with `security.read`.

## Tests

- Unit: the comparers (`version.rs`); OSV (Debian, Ubuntu, Rocky, Alpine), Arch and NVD parsing against `tests/fixtures/vuln/`; CVSS v3 scores; ecosystem derivation; the zip reader; the matcher on synthetic inventories and the storage rule; the rule's validation; the agent's dpkg, rpm, apk and pacman parsers and os-release; proto round-trips without the new fields.
- e2e `vulnerabilities` (`tests/e2e_parts/vulnerabilities.rs`, `RMM_E2E_ONLY=vulnerabilities`): a mock feed server serves a record for a real package of the host's own inventory (pacman on an Arch box, dpkg by source package on Ubuntu CI) that affects exactly its installed version, one fixed at that version (nothing), and a low unfixed KEV one (kept); KEV and EPSS applied; the alert opens and the agent turns unhealthy; client scoping; accepting closes the alert, and it reopens when the acceptance expires; the fix arriving upstream resolves the finding and clears the alert, and a full dump drops what it no longer has; a seeded Windows inventory goes through the built-in Chrome mapping to the mock NVD (with the API key, only for products in the fleet); mapping an unmapped title; `vuln-import`.
- Visual: the list's tabs, CVE pages, the agent tab (Linux, Windows, not assessed), the alert form.

## Limits

- Full-size real feeds haven't been synced here: run one manual sync before release and time the first Debian and Ubuntu imports (the dumps are hundreds of MB; memory stays bounded, but the time and the database size should be measured).
- Red Hat's OSV coverage and package naming need checking against a real RHEL host.
- Windows coverage is whatever the product map covers; the Not assessed tab says so and lists what isn't mapped.
- The dpkg inventory uses the binary package's version, which can differ from its source package's (binNMUs, `+b1`): such versions compare as newer, so no false finding comes from it.
