# Tags, custom fields, agent notes and saved views

Four small features that let an MSP record what it knows about its machines, and find them again. Migration `0029_tags_fields_notes_views.sql`; handlers in `crates/rmm-server/src/api/{tags,fields,notes,views}.rs`, value rules and script output in `src/fields.rs`; dashboard in `web/src/lib/components/{tags,fields,SavedViews.svelte,agent/AgentNotes.svelte}` and Company settings → Fields & tags.

## Tags

A tag is a name (1-40 characters, unique ignoring case) and one of nine palette colours. Tags belong to the MSP, not to a client, so "VIP" or "Pilot ring" means the same on every client's machines. They go on **agents** only.

| Action | Who |
|---|---|
| list tags | everyone signed in; `agents` counts only the agents they can see |
| create a tag, put tags on agents the user can see, bulk add and remove | technicians and admins |
| rename, recolour, delete a tag | admins (a tag is shared by everyone) |

Tag names are visible to every signed-in user whatever clients they can see: a tag is not the place for something confidential. What is scoped is which agents carry it. `PUT /agents/{id}/tags` replaces an agent's tags; `POST /agents/tags` adds and removes on up to 5,000 agents at once, and does nothing at all (404) if one of them is out of reach. The agents list filters with `?tag=<id>[,<id>…]` (agents that have all of them) and returns each row's `tags`. Changes are audited (`agent.tags`, `agent.tags_bulk`, `tag.*`) and show in an agent's Activity.

## Custom fields

An admin defines a field for **agents, clients or sites**: a stable `name` (lowercase letters, digits, underscores: what scripts and the API use), a `label`, an optional description, and a type: `text` (up to 2,000 characters), `number`, `bool`, `date` (`YYYY-MM-DD`) or `select` (one of up to 50 listed choices). The name, type and entity can't change after creation, because values are stored by type and integrations address the field by name; label, description, choices, position and the script flag can. At most 100 fields per entity kind.

A field can be limited to **one client**: it then exists only for that client's agents and sites, and only people who can see that client see the definition. Client fields can't be limited (they are already per client).

Values are JSON of the field's kind in `custom_field_values` (exactly one of agent, client or site per row, so deleting the entity or the field takes its values with it) with who or what set them: `user`, `api` (a key) or `script`. People, API keys and scripts all pass through the same check (`fields::coerce`): strings are accepted for every type because a script only has strings (`"42"`, `"yes"`, a choice ignoring case), an empty string or `null` clears, and **one bad value refuses the whole request** (400, nothing stored). Editing needs a technician who can see the entity; reading follows the entity's own scoping. Changes are audited with the old and new value (`agent.fields`, `client.fields`, `site.fields`).

The agents list filters on one agent field: `?cf=<field id>` (agents with a value) and `&cfv=<value>` (exact for typed fields, case-insensitive substring for text).

### Script output → field

An admin marks an **agent** field *script-writable*. A script run on an agent can then set it by printing, on **stdout**, from the first column:

```
RMM-FIELD warranty_end=2027-03-01
```

When the job finishes `succeeded`, the server reads the stored output and applies each marker (`fields::apply_job_output`, called from the agent socket's result handler):

* the field must exist for agents, be script-writable, and apply to the agent's client; anything else is refused;
* the value is checked like any other (a select must be one of its choices); what doesn't fit is skipped, never stored;
* an empty value clears; when a name is printed twice the last line wins; at most 64 markers are read;
* the audit log gets one `agent.field_script` entry with the job, what was set and what was refused with the reason.

Trust: a marker is a *request*. It can only reach fields an admin flagged, only on the agent the script ran on, and failed jobs set nothing. Because it is plain text, a script that echoes untrusted content (a log, a web page) could be made to print one, so flag only fields where that is acceptable. Only the first part of a job's output is stored (`JOB_OUTPUT_CAP`), so print markers early in a chatty script.

## Agent notes

Timestamped, authored notes on an agent (up to 10,000 characters, 500 per agent), shown newest first. Technicians write them; everyone who can see the agent reads them. The text is plain: the dashboard shows it as text, never markup. The **author or an admin** edits or deletes the text; any technician may pin and unpin. At most one note per agent is pinned (enforced by a partial unique index; pinning another moves it), and the pinned note appears under the agent's header and in `GET /agents/{id}` as `pinned_note`. The author's name is stored with the note, so it stays readable after the account is disabled.

## Saved views

A saved view names the state of a list page: the query string the page keeps in its URL, plus the columns it hides. Only the agents page has them so far (`page = 'agents'`).

* **Personal or shared.** Anyone keeps personal views (100 each); sharing needs a technician. A shared view is listed to everyone who can see its client; its owner, or an admin, changes or deletes it. Names are unique per person, ignoring case.
* **The query is validated on the way in:** only keys the page understands (`client, site, view, q, os, health, category, set, tag, cf, cfv, sort, dir`), no paging cursors, values without control characters, and a `client` the saver can see. It is stored re-encoded from the parsed pairs, so the dashboard's link is always plain `key=value` data. A view naming a client is bound to it (`client_id`) and listed only to people who can see that client.
* **Applying a view is navigation:** the dashboard sets the hidden columns (a user preference, `columns.agents`) and goes to `/agents?<query>`, so a view is nothing but a URL with a name.
* Views are a dashboard feature and are not in the public API.

## Public API

Tags, custom fields (definitions read-only, values read and write for agents, clients and sites) and notes (list, add) are in the OpenAPI document (`listTags`, `createTag`, `setAgentTags`, `tagAgents`, `listCustomFields`, `listAgentFields`, `setAgentFields`, `listClientFields`, …, `listAgentNotes`, `addAgentNote`). A key sees and changes what its owner and client limit allow, and its writes are recorded with source `api`.

## Not built

Tags on clients, sites, tickets or scripts; field definitions through the API; filtering lists by more than one custom field; saved views on pages other than agents; custom-field values in reports and webhooks payloads.
