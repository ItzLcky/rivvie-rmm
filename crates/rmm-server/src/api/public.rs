//! The public REST API: which routes API keys may call, and its OpenAPI 3.1 description.
//!
//! [`OPS`] is the one list both come from. A route that isn't in it is unreachable with a
//! key (see [`crate::apikeys`]), however the handler is written, so adding a route to the
//! dashboard API doesn't publish it. Each entry names the resource group a key must hold,
//! and `GET` entries need only read access; anything else needs a `write` key.
//!
//! The same router answers on `/api` (the dashboard's own, cookie-authenticated) and
//! `/api/v1`, the versioned path integrations should use and the one the document's `servers`
//! entry names. `GET /api/v1/openapi.json` needs no credentials.

use std::sync::OnceLock;

use axum::Json;
use serde_json::{Map, Value, json};

/// One public operation.
pub struct Op {
    /// `operationId`.
    pub id: &'static str,
    pub method: &'static str,
    /// The route pattern as registered in `api::router`, relative to `/api`.
    pub path: &'static str,
    /// Resource group the key needs (see `apikeys::GROUPS`).
    pub group: &'static str,
    pub summary: &'static str,
    /// Extra requirements and behaviour that don't fit the summary.
    pub note: &'static str,
    /// Query parameters: (name, type, description). `type` is a JSON Schema type, or `uuid`.
    pub query: &'static [(&'static str, &'static str, &'static str)],
    /// Takes the keyset paging parameters (`sort`, `dir`, `after`, `before`, `limit`).
    pub paged: bool,
    /// Schema name of the JSON request body.
    pub body: Option<&'static str>,
    pub response: Resp,
}

#[derive(Clone, Copy)]
pub enum Resp {
    One(&'static str),
    List(&'static str),
    Paged(&'static str),
    /// A small ad-hoc object (documented in the summary or note).
    Object,
    /// A file download (CSV or JSON Lines).
    Download,
}

impl Op {
    pub fn writes(&self) -> bool {
        self.method != "GET"
    }
}

const NONE: &[(&str, &str, &str)] = &[];
const CLIENT_Q: (&str, &str, &str) = ("client_id", "uuid", "Only this client.");

pub static OPS: &[Op] = &[
    // ---- clients and sites -------------------------------------------------------------
    Op {
        id: "listClients", method: "GET", path: "/clients", group: "clients", summary: "List clients with their sites",
        note: "Only the clients the key can see.", query: NONE, paged: false, body: None, response: Resp::List("Client"),
    },
    Op {
        id: "getClient", method: "GET", path: "/clients/{id}", group: "clients", summary: "Get a client",
        note: "", query: NONE, paged: false, body: None, response: Resp::One("Client"),
    },
    Op {
        id: "listSites", method: "GET", path: "/sites", group: "clients", summary: "List sites",
        note: "", query: &[CLIENT_Q], paged: false, body: None, response: Resp::List("Site"),
    },
    Op {
        id: "getSite", method: "GET", path: "/sites/{id}", group: "clients", summary: "Get a site",
        note: "", query: NONE, paged: false, body: None, response: Resp::One("Site"),
    },
    Op {
        id: "listClientFields", method: "GET", path: "/clients/{id}/fields", group: "clients", summary: "A client's custom fields and their values",
        note: "", query: NONE, paged: false, body: None, response: Resp::List("FieldValue"),
    },
    Op {
        id: "setClientFields", method: "PUT", path: "/clients/{id}/fields", group: "clients", summary: "Set a client's custom fields",
        note: "As `setAgentFields`.", query: NONE, paged: false, body: Some("SetFieldValues"), response: Resp::List("FieldValue"),
    },
    Op {
        id: "listSiteFields", method: "GET", path: "/sites/{id}/fields", group: "clients", summary: "A site's custom fields and their values",
        note: "", query: NONE, paged: false, body: None, response: Resp::List("FieldValue"),
    },
    Op {
        id: "setSiteFields", method: "PUT", path: "/sites/{id}/fields", group: "clients", summary: "Set a site's custom fields",
        note: "As `setAgentFields`.", query: NONE, paged: false, body: Some("SetFieldValues"), response: Resp::List("FieldValue"),
    },
    // ---- agents ------------------------------------------------------------------------
    Op {
        id: "listAgents", method: "GET", path: "/agents", group: "agents", summary: "List agents (devices)",
        note: "Search matches hostname, OS, IP address prefix and logged-in user.",
        query: &[
            CLIENT_Q,
            ("site_id", "uuid", "Only this site."),
            ("q", "string", "Search text."),
            ("online", "boolean", "Only online or only offline agents."),
            ("os", "string", "`linux`, `windows` or `macos`."),
            ("health", "string", "Comma-separated: healthy, attention, unhealthy, unknown."),
            ("tag", "string", "Comma-separated tag ids: agents that have all of them."),
            ("cf", "uuid", "An agent custom field (its id): agents with a value for it."),
            ("cfv", "string", "With `cf`: the value. Matched exactly, or as a case-insensitive substring for a text field."),
        ],
        paged: true, body: None, response: Resp::Paged("Agent"),
    },
    Op {
        id: "getAgent", method: "GET", path: "/agents/{id}", group: "agents", summary: "Get an agent with its hardware and software inventory",
        note: "`inventory` is what the agent last reported: hardware, network interfaces, installed software, logged-in users.",
        query: NONE, paged: false, body: None, response: Resp::One("AgentDetail"),
    },
    Op {
        id: "getAgentMetrics", method: "GET", path: "/agents/{id}/metrics", group: "agents", summary: "CPU, memory, disk and network history",
        note: "About 500 points whatever the range; beyond 48 hours from hourly rollups.",
        query: &[("hours", "integer", "How far back, 1-8784. Default 24.")], paged: false, body: None, response: Resp::List("Metric"),
    },
    Op {
        id: "refreshAgentInventory", method: "POST", path: "/agents/{id}/inventory/refresh", group: "agents",
        summary: "Ask an online agent to report its inventory now",
        note: "409 when the agent is offline.", query: NONE, paged: false, body: None, response: Resp::Object,
    },
    // ---- tags, custom fields and notes ---------------------------------------------------
    Op {
        id: "listTags", method: "GET", path: "/tags", group: "agents", summary: "List tags",
        note: "Tags are shared by the whole MSP; `agents` counts the agents the key can see.", query: NONE, paged: false, body: None, response: Resp::List("Tag"),
    },
    Op {
        id: "createTag", method: "POST", path: "/tags", group: "agents", summary: "Create a tag",
        note: "Needs a write key whose owner is a technician or admin. 409 if the name is taken (ignoring case).", query: NONE, paged: false, body: Some("NewTag"), response: Resp::One("Tag"),
    },
    Op {
        id: "setAgentTags", method: "PUT", path: "/agents/{id}/tags", group: "agents", summary: "Set an agent's tags",
        note: "Replaces the agent's tags with exactly `tag_ids`.", query: NONE, paged: false, body: Some("SetTags"), response: Resp::Object,
    },
    Op {
        id: "tagAgents", method: "POST", path: "/agents/tags", group: "agents", summary: "Add and remove tags on many agents",
        note: "Up to 5000 agents; every one must be visible to the key or nothing changes (404).", query: NONE, paged: false, body: Some("BulkTags"), response: Resp::Object,
    },
    Op {
        id: "listCustomFields", method: "GET", path: "/custom-fields", group: "agents", summary: "List custom field definitions",
        note: "For agents, clients and sites. Fields limited to a client are listed only if the key can see that client. A field's `name` is what the values are set by.",
        query: &[("entity", "string", "`agent`, `client` or `site`.")], paged: false, body: None, response: Resp::List("CustomField"),
    },
    Op {
        id: "listAgentFields", method: "GET", path: "/agents/{id}/fields", group: "agents", summary: "An agent's custom fields and their values",
        note: "Every field that applies to the agent, with `value` null where none is set.", query: NONE, paged: false, body: None, response: Resp::List("FieldValue"),
    },
    Op {
        id: "setAgentFields", method: "PUT", path: "/agents/{id}/fields", group: "agents", summary: "Set an agent's custom fields",
        note: "Only the fields named change; `null` or an empty string clears one. Every value is checked first and nothing is stored if one is wrong (400). Returns the fields as `listAgentFields` does.",
        query: NONE, paged: false, body: Some("SetFieldValues"), response: Resp::List("FieldValue"),
    },
    Op {
        id: "listAgentNotes", method: "GET", path: "/agents/{id}/notes", group: "agents", summary: "An agent's notes",
        note: "The pinned note first, then newest first.", query: NONE, paged: false, body: None, response: Resp::List("Note"),
    },
    Op {
        id: "addAgentNote", method: "POST", path: "/agents/{id}/notes", group: "agents", summary: "Add a note to an agent",
        note: "Needs a write key whose owner is a technician or admin; the note is authored by the key's owner. `pinned` replaces the agent's pinned note.",
        query: NONE, paged: false, body: Some("NewNote"), response: Resp::One("Note"),
    },
    // ---- jobs and scripts ----------------------------------------------------------------
    Op {
        id: "listJobs", method: "GET", path: "/jobs", group: "jobs", summary: "List jobs, newest first",
        note: "", query: &[
            ("status", "string", "Comma-separated; `failed` also matches error, timed_out and lost."),
            ("script_id", "uuid", "Only runs of this script."),
            CLIENT_Q,
            ("agent_id", "uuid", "Only this agent."),
            ("q", "string", "Hostname or script name."),
        ],
        paged: true, body: None, response: Resp::Paged("Job"),
    },
    Op {
        id: "getJob", method: "GET", path: "/jobs/{id}", group: "jobs", summary: "Get a job with its output",
        note: "Output is the whole of stdout and stderr; pass `since_stdout` and `since_stderr` (the lengths already read) to fetch only what's new.",
        query: &[("since_stdout", "integer", "Skip this many characters of stdout."), ("since_stderr", "integer", "Skip this many characters of stderr.")],
        paged: false, body: None, response: Resp::One("JobDetail"),
    },
    Op {
        id: "listAgentJobs", method: "GET", path: "/agents/{id}/jobs", group: "jobs", summary: "The agent's 100 latest jobs",
        note: "", query: NONE, paged: false, body: None, response: Resp::List("Job"),
    },
    Op {
        id: "listAgentAutomations", method: "GET", path: "/agents/{id}/automations", group: "jobs",
        summary: "What automation policies did on the agent: its 200 latest runs",
        note: "Each run says what fired it (`trigger`), whether it ran, waited or was skipped (`status`, `reason`), and its job.",
        query: NONE, paged: false, body: None, response: Resp::List("AutomationRun"),
    },
    Op {
        id: "createJobs", method: "POST", path: "/jobs", group: "jobs", summary: "Run a saved script on agents",
        note: "Keys run saved scripts only (`script_id`): ad-hoc code is refused. Agents that are offline get the job when they reconnect. Needs a write key whose owner is a technician or admin.",
        query: NONE, paged: false, body: Some("NewJob"), response: Resp::Object,
    },
    Op {
        id: "listScripts", method: "GET", path: "/scripts", group: "scripts", summary: "List scripts",
        note: "The MSP-wide scripts and the ones belonging to clients the key can see.", query: NONE, paged: false, body: None, response: Resp::List("Script"),
    },
    Op {
        id: "getScript", method: "GET", path: "/scripts/{id}", group: "scripts", summary: "Get a script",
        note: "", query: NONE, paged: false, body: None, response: Resp::One("Script"),
    },
    // ---- alerts --------------------------------------------------------------------------
    Op {
        id: "listAlerts", method: "GET", path: "/alerts", group: "alerts", summary: "List alerts",
        note: "", query: &[
            ("state", "string", "`active` (open and acknowledged, the default), `open`, `acknowledged`, `resolved` or `all`."),
            ("severity", "string", "Comma-separated: critical, warning, info."),
            CLIENT_Q,
            ("agent_id", "uuid", "Only this agent."),
            ("kind", "string", "Alert kind, e.g. `offline`, `cpu`, `disk`."),
            ("q", "string", "Hostname or title."),
        ],
        paged: true, body: None, response: Resp::Paged("Alert"),
    },
    Op {
        id: "alertSummary", method: "GET", path: "/alerts/summary", group: "alerts", summary: "Open alert counts by severity",
        note: "", query: &[CLIENT_Q], paged: false, body: None, response: Resp::Object,
    },
    Op {
        id: "getAlert", method: "GET", path: "/alerts/{id}", group: "alerts", summary: "Get an alert with its notifications and linked ticket",
        note: "", query: NONE, paged: false, body: None, response: Resp::One("Alert"),
    },
    Op {
        id: "acknowledgeAlert", method: "POST", path: "/alerts/{id}/acknowledge", group: "alerts", summary: "Acknowledge an alert",
        note: "", query: NONE, paged: false, body: None, response: Resp::One("Alert"),
    },
    Op {
        id: "resolveAlert", method: "POST", path: "/alerts/{id}/resolve", group: "alerts", summary: "Resolve an alert",
        note: "Resolved by hand; if its condition is still true it opens again.", query: NONE, paged: false, body: None, response: Resp::One("Alert"),
    },
    // ---- tickets -------------------------------------------------------------------------
    Op {
        id: "listTickets", method: "GET", path: "/tickets", group: "tickets", summary: "List tickets",
        note: "", query: &[
            ("view", "string", "`open` (default), `mine`, `unassigned`, `waiting`, `triage`, `done` or `all`."),
            ("board_id", "uuid", "Only this board."),
            ("status_id", "uuid", "Only this status."),
            ("priority", "string", "Comma-separated, 1-4."),
            ("assignee", "string", "A user id, or `none`."),
            CLIENT_Q,
            ("agent_id", "uuid", "Tickets this agent is linked to."),
            ("q", "string", "A ticket number (`T-10423`) or words from the subject, timeline and contact."),
        ],
        paged: true, body: None, response: Resp::Paged("Ticket"),
    },
    Op {
        id: "ticketMeta", method: "GET", path: "/tickets/meta", group: "tickets", summary: "Boards with their statuses, ticket types, technicians and teams",
        note: "The ids to use in `board_id`, `status_id`, `type_id`, `assignee_id` and `team_id`.", query: NONE, paged: false, body: None, response: Resp::Object,
    },
    Op {
        id: "ticketSummary", method: "GET", path: "/tickets/summary", group: "tickets", summary: "Open ticket counts",
        note: "", query: &[CLIENT_Q], paged: false, body: None, response: Resp::Object,
    },
    Op {
        id: "getTicket", method: "GET", path: "/tickets/{id}", group: "tickets", summary: "Get a ticket with its timeline",
        note: "The timeline includes internal notes.", query: NONE, paged: false, body: None, response: Resp::One("TicketDetail"),
    },
    Op {
        id: "createTicket", method: "POST", path: "/tickets", group: "tickets", summary: "Open a ticket",
        note: "Needs a write key whose owner is a technician or admin.", query: NONE, paged: false, body: Some("NewTicket"), response: Resp::One("Ticket"),
    },
    Op {
        id: "updateTicket", method: "PATCH", path: "/tickets/{id}", group: "tickets", summary: "Change a ticket's status, priority, assignee and other fields",
        note: "Only the fields sent change. Send `null` to clear `assignee_id`, `contact_id`, `type_id` and the like.",
        query: NONE, paged: false, body: Some("TicketPatch"), response: Resp::One("Ticket"),
    },
    Op {
        id: "addTicketEvent", method: "POST", path: "/tickets/{id}/events", group: "tickets", summary: "Reply to the client or add an internal note",
        note: "A `reply` is public and emailed to the contact.", query: NONE, paged: false, body: Some("NewTicketEvent"), response: Resp::Object,
    },
    // ---- software ------------------------------------------------------------------------
    Op {
        id: "listSoftwarePackages", method: "GET", path: "/software/packages", group: "software", summary: "List the software catalog",
        note: "MSP-wide packages and those of the clients the key can see. Each says how it's installed (winget, Chocolatey, apt, dnf, uploaded installer) and on how many devices it was last seen.",
        query: &[CLIENT_Q, ("q", "string", "Name, publisher or package id."), ("platform", "string", "`windows` or `linux`: only packages deployable there.")],
        paged: false, body: None, response: Resp::List("SoftwarePackage"),
    },
    Op {
        id: "getSoftwarePackage", method: "GET", path: "/software/packages/{id}", group: "software", summary: "Get a catalog package",
        note: "", query: NONE, paged: false, body: None, response: Resp::One("SoftwarePackage"),
    },
    Op {
        id: "getAgentSoftware", method: "GET", path: "/agents/{id}/software", group: "software", summary: "What a device has of the catalog, what its policies ask, and its recent runs",
        note: "`items[].compliant` is true or false when a policy asks for the package and the device has been scanned, else null.",
        query: &[("all", "boolean", "Every package the device could use, not only those installed or required.")], paged: false, body: None, response: Resp::Object,
    },
    Op {
        id: "listSoftwareRuns", method: "GET", path: "/software/runs", group: "software", summary: "List software installs, upgrades and removals, newest first",
        note: "At most 500.", query: &[
            ("agent_id", "uuid", "Only this device."),
            ("package_id", "uuid", "Only this package."),
            CLIENT_Q,
            ("status", "string", "Comma-separated: queued, sent, succeeded, failed, lost, expired, cancelled."),
            ("limit", "integer", "1-500, default 200."),
        ],
        paged: false, body: None, response: Resp::List("SoftwareRun"),
    },
    Op {
        id: "listSoftwareUpdates", method: "GET", path: "/software/updates", group: "software", summary: "Installed catalog packages with a newer version on offer",
        note: "One row per device and package.", query: &[CLIENT_Q, ("package_id", "uuid", "Only this package."), ("q", "string", "Hostname or package name."), ("ignored", "boolean", "Include versions someone chose to skip.")],
        paged: false, body: None, response: Resp::Object,
    },
    Op {
        id: "deploySoftware", method: "POST", path: "/software/deploy", group: "software", summary: "Install, upgrade or remove a catalog package on devices",
        note: "Only catalog packages can be deployed, never arbitrary commands. Offline devices run it when they reconnect. Devices that can't take it (another client's package, an agent without software support, a run already in progress) are listed under `skipped`. Needs a write key whose owner is a technician or admin.",
        query: NONE, paged: false, body: Some("SoftwareDeploy"), response: Resp::Object,
    },
    // ---- network discovery and SNMP devices (read) ------------------------------------------
    Op {
        id: "listNetworkDevices", method: "GET", path: "/network/devices", group: "network", summary: "List SNMP-monitored network devices",
        note: "Switches, routers, firewalls, printers and the like read through a site's designated agent. Credentials are never returned.",
        query: &[
            CLIENT_Q,
            ("site_id", "uuid", "Only this site."),
            ("state", "string", "`up`, `down` or `unknown`."),
            ("kind", "string", "`switch`, `router`, `firewall`, `ap`, `printer`, `ups`, `nas`, `server`, `windows`, `linux` or `other`."),
            ("q", "string", "Name, address, description or vendor."),
        ],
        paged: false, body: None, response: Resp::List("NetworkDevice"),
    },
    Op {
        id: "getNetworkDevice", method: "GET", path: "/network/devices/{id}", group: "network", summary: "Get a network device with its interfaces and open alerts",
        note: "", query: NONE, paged: false, body: None, response: Resp::One("NetworkDeviceDetail"),
    },
    Op {
        id: "getNetworkDeviceMetrics", method: "GET", path: "/network/devices/{id}/metrics", group: "network", summary: "Reachability, latency, CPU and memory history of a device",
        note: "About 500 points whatever the range; beyond 48 hours from hourly rollups.",
        query: &[("hours", "integer", "How far back, 1-8784. Default 24.")], paged: false, body: None, response: Resp::List("NetworkDevicePoint"),
    },
    Op {
        id: "listDiscoveredDevices", method: "GET", path: "/network/discovered", group: "network", summary: "List the hosts that network scans found",
        note: "`state` says whether a host is managed (an agent runs on it), monitored (read over SNMP), ignored, known or still unmanaged.",
        query: &[
            CLIENT_Q,
            ("site_id", "uuid", "Only this site."),
            ("state", "string", "`unmanaged` (default), `managed`, `monitored`, `ignored`, `known` or `all`."),
            ("online", "boolean", "Seen (or not) by the latest scan."),
            ("q", "string", "Name, address, MAC, vendor or note."),
            ("limit", "integer", "At most this many, 1-2000. Default 500."),
        ],
        paged: false, body: None, response: Resp::List("DiscoveredDevice"),
    },
    // ---- endpoint protection (read) -------------------------------------------------------
    Op {
        id: "securitySummary", method: "GET", path: "/security/summary", group: "security", summary: "Protection state of the fleet",
        note: "Needs the `security.read` permission on the key.", query: &[CLIENT_Q], paged: false, body: None, response: Resp::Object,
    },
    Op {
        id: "listDetections", method: "GET", path: "/security/detections", group: "security", summary: "List detections",
        note: "Needs the `security.read` permission on the key.", query: &[
            ("view", "string", "`active` (default) or `all`."),
            ("severity", "string", "Comma-separated."),
            CLIENT_Q,
            ("q", "string", "Search text."),
        ],
        paged: true, body: None, response: Resp::Paged("Detection"),
    },
    // ---- audit log (admins, or whoever holds audit.read) ----------------------------------
    Op {
        id: "listAudit", method: "GET", path: "/audit", group: "audit", summary: "List audit log events, newest first",
        note: "Needs the `audit.read` permission on the key, which only a key of an admin (or of a user an admin gave it) can hold.",
        query: AUDIT_Q, paged: true, body: None, response: Resp::Paged("AuditEvent"),
    },
    Op {
        id: "exportAudit", method: "GET", path: "/audit/export", group: "audit", summary: "Download the audit log as CSV or JSON Lines",
        note: "Needs the `audit.read` permission on the key. Oldest first, streamed: the whole log can be fetched in one request. \
               The export is itself audited (`audit.export`). Fields: id, time, user_id, user_email, user_name, action, target_type, target_id, details.",
        query: &[
            ("format", "string", "`csv` (default) or `jsonl` (one JSON object per line)."),
            ("action", "string", "An action, or a prefix ending in `.` (`user.`)."),
            ("user_id", "uuid", "Only this user's actions."),
            ("target_type", "string", "Only this kind of target."),
            ("target_id", "uuid", "Only this target."),
            ("from", "datetime", "Events at or after this time."),
            ("to", "datetime", "Events at or before this time."),
        ],
        paged: false, body: None, response: Resp::Download,
    },
];

const AUDIT_Q: &[(&str, &str, &str)] = &[
    ("action", "string", "An action, or a prefix ending in `.` (`user.`)."),
    ("user_id", "uuid", "Only this user's actions."),
    ("target_type", "string", "Only this kind of target."),
    ("target_id", "uuid", "Only this target."),
    ("from", "datetime", "Events at or after this time."),
    ("to", "datetime", "Events at or before this time."),
];

/// The operation for a request: HTTP method and route pattern relative to `/api`.
pub fn find(method: &str, path: &str) -> Option<&'static Op> {
    OPS.iter().find(|o| o.method == method && o.path == path)
}

// ---------------------------------------------------------------------------
// OpenAPI
// ---------------------------------------------------------------------------

fn prop(ty: &str) -> Value {
    match ty {
        "uuid" => json!({ "type": "string", "format": "uuid" }),
        "datetime" => json!({ "type": "string", "format": "date-time" }),
        t => json!({ "type": t }),
    }
}

/// An object schema from `(name, type)` pairs; a type ending in `?` is nullable.
fn object(description: &str, fields: &[(&str, &str)]) -> Value {
    let mut props = Map::new();
    for (name, ty) in fields {
        let (ty, nullable) = ty.strip_suffix('?').map_or((*ty, false), |t| (t, true));
        let mut p = prop(ty);
        if nullable {
            let base = p["type"].take();
            p["type"] = json!([base, "null"]);
        }
        props.insert((*name).into(), p);
    }
    json!({ "type": "object", "description": description, "properties": props })
}

fn reference(name: &str) -> Value {
    json!({ "$ref": format!("#/components/schemas/{name}") })
}

/// Tags, custom fields and notes (a second `json!`, which would otherwise pass the macro's recursion limit).
fn field_schemas() -> Value {
    json!({
        "Tag": object("A label on agents, shared by the whole MSP.", &[
            ("id", "uuid"), ("name", "string"), ("color", "string"), ("agents", "integer"), ("created_at", "datetime"),
        ]),
        "NewTag": {
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string", "maxLength": 40 },
                "color": { "type": "string", "enum": ["slate", "red", "orange", "amber", "green", "teal", "blue", "violet", "pink"] },
            },
        },
        "SetTags": {
            "type": "object",
            "required": ["tag_ids"],
            "properties": { "tag_ids": { "type": "array", "items": { "type": "string", "format": "uuid" }, "maxItems": 50 } },
        },
        "BulkTags": {
            "type": "object",
            "required": ["agent_ids"],
            "properties": {
                "agent_ids": { "type": "array", "items": { "type": "string", "format": "uuid" }, "minItems": 1, "maxItems": 5000 },
                "add": { "type": "array", "items": { "type": "string", "format": "uuid" } },
                "remove": { "type": "array", "items": { "type": "string", "format": "uuid" } },
            },
        },
        "CustomField": object("The definition of a custom field.", &[
            ("id", "uuid"), ("entity", "string"), ("name", "string"), ("label", "string"), ("description", "string"),
            ("kind", "string"), ("options", "array"), ("client_id", "uuid?"), ("client_name", "string?"),
            ("script_writable", "boolean"), ("position", "integer"), ("in_use", "integer"),
        ]),
        "FieldValue": object("A custom field with the value of one agent, client or site. `kind` is text, number, bool, date (`YYYY-MM-DD`) or select (one of `options`).", &[
            ("field_id", "uuid"), ("name", "string"), ("label", "string"), ("description", "string"), ("kind", "string"), ("options", "array"),
            ("script_writable", "boolean"), ("client_id", "uuid?"), ("value", "object?"), ("source", "string?"), ("updated_at", "datetime?"),
            ("updated_by_name", "string?"),
        ]),
        "SetFieldValues": {
            "type": "object",
            "required": ["values"],
            "properties": {
                "values": {
                    "type": "object",
                    "description": "Field name to value. A string, number, boolean or `YYYY-MM-DD` date as the field's type needs (strings are accepted for numbers and booleans); `null` or an empty string clears.",
                    "additionalProperties": true,
                },
            },
        },
        "Note": object("A note on an agent.", &[
            ("id", "uuid"), ("agent_id", "uuid"), ("body", "string"), ("author_id", "uuid?"), ("author_name", "string"), ("pinned", "boolean"),
            ("created_at", "datetime"), ("updated_at", "datetime"), ("can_edit", "boolean"),
        ]),
        "NewNote": {
            "type": "object",
            "required": ["body"],
            "properties": { "body": { "type": "string", "maxLength": 10000 }, "pinned": { "type": "boolean" } },
        },
    })
}

fn schemas() -> Value {
    let mut all = base_schemas();
    if let (Some(all), Value::Object(more)) = (all.as_object_mut(), field_schemas()) {
        all.extend(more);
    }
    all
}

fn base_schemas() -> Value {
    json!({
        "Error": { "type": "object", "properties": { "error": { "type": "string" } }, "required": ["error"] },
        "Client": object("A customer of the MSP, with its sites.", &[
            ("id", "uuid"), ("name", "string"), ("created_at", "datetime"), ("email_domains", "array"), ("security_canary", "boolean"),
            ("sla_policy_id", "uuid?"), ("portal_devices", "boolean"), ("sites", "array"),
        ]),
        "Site": object("A location of a client; agents enroll into a site.", &[
            ("id", "uuid"), ("client_id", "uuid"), ("name", "string"), ("agent_count", "integer"), ("online_count", "integer"),
        ]),
        "Agent": object("A managed device.", &[
            ("id", "uuid"), ("hostname", "string"), ("os_family", "string"), ("os_name", "string"), ("os_version", "string"), ("arch", "string"),
            ("agent_version", "string"), ("online", "boolean"), ("last_seen_at", "datetime?"), ("enrolled_at", "datetime"),
            ("site_id", "uuid"), ("site_name", "string"), ("client_id", "uuid"), ("client_name", "string"), ("last_metrics", "object?"),
            ("health", "string"), ("open_alerts", "integer"), ("failed_jobs_24h", "integer"), ("reboot_pending", "boolean"),
            ("platform", "string"), ("category_name", "string"), ("policy_set_name", "string"), ("tags", "array"),
        ]),
        "AgentDetail": {
            "allOf": [reference("Agent"), object("The agent's inventory.", &[
                ("kernel_version", "string"), ("machine_id", "string?"), ("inventory", "object?"), ("inventory_at", "datetime?"), ("capabilities", "array"),
                ("pinned_note", "object?"),
            ])],
        },
        "Metric": object("One point of an agent's history.", &[
            ("ts", "datetime"), ("cpu_percent", "number"), ("mem_used", "integer"), ("mem_total", "integer"), ("disk_max_pct", "number"),
            ("net_rx_bytes", "integer"), ("net_tx_bytes", "integer"),
        ]),
        "Job": object("A script run on one agent.", &[
            ("id", "uuid"), ("agent_id", "uuid"), ("hostname", "string"), ("script_id", "uuid?"), ("script_name", "string?"), ("interpreter", "string"),
            ("status", "string"), ("exit_code", "integer?"), ("created_by_name", "string?"), ("created_at", "datetime"), ("sent_at", "datetime?"),
            ("finished_at", "datetime?"), ("duration_ms", "integer?"),
        ]),
        "AutomationRun": object("One run of an automation policy on an agent: a saved script started by an event (enrollment, agent_online, alert_opened, patch_reboot_pending) or once per device (run_once).", &[
            ("id", "uuid"), ("item_id", "uuid"), ("item_name", "string"), ("agent_id", "uuid"), ("hostname", "string"), ("trigger", "string"),
            ("status", "string"), ("reason", "string?"), ("context", "object"), ("job_id", "uuid?"), ("script_id", "uuid?"), ("script_name", "string?"),
            ("exit_code", "integer?"), ("attempts", "integer"), ("created_at", "datetime"), ("started_at", "datetime?"), ("finished_at", "datetime?"),
        ]),
        "JobDetail": {
            "allOf": [reference("Job"), object("The job's script and output.", &[
                ("body", "string"), ("args", "array"), ("timeout_secs", "integer"), ("stdout", "string"), ("stderr", "string"),
                ("stdout_len", "integer"), ("stderr_len", "integer"),
            ])],
        },
        "NewJob": {
            "type": "object",
            "required": ["agent_ids", "script_id"],
            "properties": {
                "agent_ids": { "type": "array", "items": { "type": "string", "format": "uuid" }, "minItems": 1, "maxItems": 5000 },
                "script_id": { "type": "string", "format": "uuid", "description": "A saved script. API keys can't run ad-hoc code." },
                "args": { "type": "array", "items": { "type": "string" } },
                "timeout_secs": { "type": "integer", "description": "Default: the script's own." },
                "ticket_id": { "type": "string", "format": "uuid", "description": "Run from this ticket: the result is added to its timeline." },
            },
        },
        "Script": object("A saved script.", &[
            ("id", "uuid"), ("name", "string"), ("description", "string"), ("interpreter", "string"), ("body", "string"),
            ("timeout_secs", "integer"), ("client_id", "uuid?"), ("client_name", "string?"), ("created_at", "datetime"), ("updated_at", "datetime"),
        ]),
        "Alert": object("An alert: something that needs attention on an agent.", &[
            ("id", "uuid"), ("policy_id", "uuid?"), ("policy_name", "string?"), ("agent_id", "uuid"), ("hostname", "string"),
            ("client_id", "uuid"), ("client_name", "string"), ("site_name", "string"), ("kind", "string"), ("severity", "string"),
            ("title", "string"), ("details", "object"), ("occurrences", "integer"), ("state", "string"), ("opened_at", "datetime"),
            ("last_seen_at", "datetime"), ("acknowledged_at", "datetime?"), ("acknowledged_by_name", "string?"), ("resolved_at", "datetime?"),
            ("resolved_by_name", "string?"), ("resolution", "string?"), ("suppressed", "boolean"),
        ]),
        "Ticket": object("A service desk ticket.", &[
            ("id", "uuid"), ("number", "integer"), ("subject", "string"), ("client_id", "uuid?"), ("client_name", "string?"), ("site_id", "uuid?"),
            ("contact_id", "uuid?"), ("contact_name", "string?"), ("board_id", "uuid"), ("board_name", "string"), ("status_id", "uuid"),
            ("status_name", "string"), ("status_category", "string"), ("type_id", "uuid?"), ("priority", "integer"), ("impact", "integer?"),
            ("urgency", "integer?"), ("source", "string"), ("assignee_id", "uuid?"), ("assignee_name", "string?"), ("requester_name", "string"),
            ("requester_email", "string"), ("created_at", "datetime"), ("updated_at", "datetime"), ("first_response_at", "datetime?"),
            ("resolved_at", "datetime?"), ("closed_at", "datetime?"), ("sla_due", "datetime?"),
        ]),
        "TicketDetail": {
            "allOf": [reference("Ticket"), object("The timeline and links.", &[
                ("events", "array"), ("attachments", "array"), ("agents", "array"), ("docs", "array"), ("statuses", "array"),
            ])],
        },
        "NewTicket": {
            "type": "object",
            "required": ["subject"],
            "properties": {
                "subject": { "type": "string", "maxLength": 300 },
                "description": { "type": "string" },
                "client_id": { "type": "string", "format": "uuid" },
                "site_id": { "type": "string", "format": "uuid" },
                "contact_id": { "type": "string", "format": "uuid" },
                "board_id": { "type": "string", "format": "uuid", "description": "Default: the default board." },
                "type_id": { "type": "string", "format": "uuid" },
                "priority": { "type": "integer", "minimum": 1, "maximum": 4 },
                "impact": { "type": "integer", "minimum": 1, "maximum": 3 },
                "urgency": { "type": "integer", "minimum": 1, "maximum": 3 },
                "assignee_id": { "type": "string", "format": "uuid" },
                "team_id": { "type": "string", "format": "uuid" },
                "agent_ids": { "type": "array", "items": { "type": "string", "format": "uuid" } },
            },
        },
        "TicketPatch": {
            "type": "object",
            "properties": {
                "subject": { "type": "string" },
                "board_id": { "type": "string", "format": "uuid" },
                "status_id": { "type": "string", "format": "uuid" },
                "priority": { "type": "integer", "minimum": 1, "maximum": 4 },
                "impact": { "type": ["integer", "null"] },
                "urgency": { "type": ["integer", "null"] },
                "type_id": { "type": ["string", "null"], "format": "uuid" },
                "assignee_id": { "type": ["string", "null"], "format": "uuid" },
                "client_id": { "type": ["string", "null"], "format": "uuid" },
                "site_id": { "type": ["string", "null"], "format": "uuid" },
                "contact_id": { "type": ["string", "null"], "format": "uuid" },
                "team_id": { "type": ["string", "null"], "format": "uuid" },
            },
        },
        "NewTicketEvent": {
            "type": "object",
            "required": ["kind", "body"],
            "properties": {
                "kind": { "type": "string", "enum": ["reply", "note"], "description": "`reply` is public and emailed; `note` is internal." },
                "body": { "type": "string" },
                "status_id": { "type": "string", "format": "uuid", "description": "Change the status in the same step." },
            },
        },
        "SoftwarePackage": object("A package in the software catalog.", &[
            ("id", "uuid"), ("client_id", "uuid?"), ("client_name", "string?"), ("name", "string"), ("description", "string"), ("publisher", "string?"),
            ("winget_id", "string?"), ("choco_id", "string?"), ("apt_name", "string?"), ("dnf_name", "string?"), ("version", "string?"),
            ("installer", "object?"), ("platforms", "array"), ("installed_on", "integer"), ("updates", "integer"), ("policies", "integer"),
            ("created_at", "datetime"), ("updated_at", "datetime"),
        ]),
        "SoftwareRun": object("One install, upgrade or removal of a package on a device.", &[
            ("id", "uuid"), ("agent_id", "uuid"), ("hostname", "string"), ("client_id", "uuid"), ("client_name", "string"), ("package_id", "uuid?"),
            ("package_name", "string"), ("op", "string"), ("trigger", "string"), ("policy_item_id", "uuid?"), ("created_by_name", "string?"),
            ("status", "string"), ("error", "string?"), ("provider", "string?"), ("from_version", "string?"), ("to_version", "string?"),
            ("reboot_required", "boolean"), ("created_at", "datetime"), ("sent_at", "datetime?"), ("finished_at", "datetime?"), ("duration_ms", "integer?"),
        ]),
        "SoftwareDeploy": {
            "type": "object",
            "required": ["package_id", "op", "agent_ids"],
            "properties": {
                "package_id": { "type": "string", "format": "uuid" },
                "op": { "type": "string", "enum": ["install", "upgrade", "uninstall"] },
                "agent_ids": { "type": "array", "items": { "type": "string", "format": "uuid" }, "minItems": 1, "maxItems": 5000 },
                "bootstrap_choco": { "type": "boolean", "description": "Allow installing Chocolatey first if the package needs it and the device lacks it." },
            },
        },
        "Detection": object("A detection from the endpoint protection.", &[
            ("id", "uuid"), ("agent_id", "uuid"), ("hostname", "string"), ("client_id", "uuid"), ("client_name", "string"), ("product", "string"),
            ("name", "string"), ("severity", "string"), ("status", "string"), ("resources", "array"), ("first_seen_at", "datetime"),
            ("last_seen_at", "datetime"), ("resolved_at", "datetime?"), ("source", "string"), ("sha256", "string?"),
        ]),
        "AuditEvent": object("One entry of the audit log.", &[
            ("id", "integer"), ("ts", "datetime"), ("user_name", "string?"), ("action", "string"), ("target_type", "string?"),
            ("target_id", "uuid?"), ("details", "object"),
        ]),
        "NetworkDevice": object("A device read over SNMP.", &[
            ("id", "uuid"), ("site_id", "uuid"), ("site_name", "string"), ("client_id", "uuid"), ("client_name", "string"), ("name", "string"),
            ("host", "string"), ("port", "integer"), ("kind", "string"), ("enabled", "boolean"), ("sys_descr", "string?"), ("sys_name", "string?"),
            ("sys_object_id", "string?"), ("sys_location", "string?"), ("vendor", "string?"), ("mac", "string?"), ("state", "string"),
            ("state_since", "datetime"), ("last_poll_at", "datetime?"), ("last_ok_at", "datetime?"), ("last_error", "string?"), ("rtt_ms", "integer?"),
            ("uptime_secs", "integer?"), ("cpu_percent", "number?"), ("mem_used", "integer?"), ("mem_total", "integer?"), ("storage", "array"),
            ("supplies", "array"), ("agent_id", "uuid?"), ("agent_hostname", "string?"), ("agent_online", "boolean"), ("open_alerts", "integer"),
            ("interfaces", "integer"), ("interfaces_up", "integer"),
        ]),
        "NetworkDeviceDetail": {
            "allOf": [reference("NetworkDevice"), object("Interfaces and open alerts.", &[("interfaces", "array"), ("alerts", "array")])],
        },
        "NetworkDevicePoint": object("One point of a device's history.", &[
            ("ts", "datetime"), ("reachable_pct", "number"), ("rtt_ms", "number?"), ("cpu_percent", "number?"), ("mem_used", "integer?"), ("mem_total", "integer?"),
        ]),
        "DiscoveredDevice": object("A host a network scan found.", &[
            ("id", "uuid"), ("site_id", "uuid"), ("site_name", "string"), ("client_id", "uuid"), ("client_name", "string"), ("ip", "string"),
            ("mac", "string?"), ("hostname", "string?"), ("mdns_name", "string?"), ("vendor", "string?"), ("sys_name", "string?"), ("sys_descr", "string?"),
            ("kind", "string"), ("open_ports", "array"), ("methods", "array"), ("state", "string"), ("note", "string"), ("agent_id", "uuid?"),
            ("agent_hostname", "string?"), ("net_device_id", "uuid?"), ("online", "boolean"), ("first_seen_at", "datetime"), ("last_seen_at", "datetime"),
            ("name", "string"),
        ]),
        "Webhook": object("The body of every webhook delivery. `data` depends on the event.", &[
            ("id", "uuid"), ("event", "string"), ("created_at", "datetime"), ("data", "object"),
        ]),
    })
}

fn response_schema(r: Resp) -> Option<Value> {
    match r {
        Resp::One(n) => Some(reference(n)),
        Resp::List(n) => Some(json!({ "type": "array", "items": reference(n) })),
        Resp::Paged(n) => Some(json!({
            "type": "object",
            "properties": {
                "items": { "type": "array", "items": reference(n) },
                "next": { "type": ["string", "null"], "description": "Pass as `after` for the next page." },
                "prev": { "type": ["string", "null"], "description": "Pass as `before` for the previous page." },
                "total": { "type": "integer" },
            },
        })),
        Resp::Object | Resp::Download => None,
    }
}

fn operation(op: &Op) -> Value {
    let mut params: Vec<Value> = Vec::new();
    let mut rest = op.path;
    while let Some(start) = rest.find('{') {
        let end = rest[start..].find('}').map_or(rest.len(), |e| start + e);
        params.push(json!({ "name": &rest[start + 1..end], "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }));
        rest = &rest[(end + 1).min(rest.len())..];
    }
    for (name, ty, description) in op.query {
        params.push(json!({ "name": name, "in": "query", "description": description, "schema": prop(ty) }));
    }
    if op.paged {
        params.extend([
            json!({ "name": "sort", "in": "query", "description": "Sort key; the allowed ones depend on the list.", "schema": { "type": "string" } }),
            json!({ "name": "dir", "in": "query", "schema": { "type": "string", "enum": ["asc", "desc"] } }),
            json!({ "name": "after", "in": "query", "description": "`next` of the previous page.", "schema": { "type": "string" } }),
            json!({ "name": "before", "in": "query", "description": "`prev` of the next page.", "schema": { "type": "string" } }),
            json!({ "name": "limit", "in": "query", "schema": { "type": "integer", "minimum": 1, "maximum": 200 } }),
        ]);
    }
    let access = if op.writes() { "A key with `write` access" } else { "Any key" };
    let mut description = format!("{access} that holds the `{}` scope. {}", op.group, op.note);
    description = description.trim().to_string();
    let ok = match response_schema(op.response) {
        Some(s) => json!({ "description": "Success.", "content": { "application/json": { "schema": s } } }),
        None if matches!(op.response, Resp::Download) => json!({
            "description": "Success: a download, streamed.",
            "content": { "text/csv": { "schema": { "type": "string" } }, "application/x-ndjson": { "schema": { "type": "string" } } },
        }),
        None => json!({ "description": "Success.", "content": { "application/json": { "schema": { "type": "object" } } } }),
    };
    let err = |d: &str| json!({ "description": d, "content": { "application/json": { "schema": reference("Error") } } });
    let mut responses = json!({
        "200": ok,
        "401": err("No key, or the key is unknown, revoked or expired."),
        "403": err("The key's scope, access level or the owner's rights don't allow this."),
        "429": err("The key's rate limit is used up; wait `Retry-After` seconds."),
    });
    if op.path.contains('{') {
        responses["404"] = err("Not found, or not one of the clients the key can see.");
    }
    if op.body.is_some() {
        responses["400"] = err("The request was invalid.");
    }
    let mut out = json!({
        "operationId": op.id,
        "summary": op.summary,
        "description": description,
        "tags": [op.group],
        "parameters": params,
        "responses": responses,
        "x-rmm-scope": op.group,
        "x-rmm-access": if op.writes() { "write" } else { "read" },
    });
    if let Some(body) = op.body {
        out["requestBody"] = json!({ "required": true, "content": { "application/json": { "schema": reference(body) } } });
    }
    out
}

fn build() -> Value {
    let mut paths = Map::new();
    for op in OPS {
        paths.entry(op.path.to_string()).or_insert_with(|| json!({}))[op.method.to_lowercase()] = operation(op);
    }
    let tags: Vec<Value> = crate::apikeys::GROUPS.iter().map(|(id, label)| json!({ "name": id, "description": label })).collect();
    let events: Vec<&str> = crate::webhooks::EVENTS.to_vec();
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "RMM API",
            "version": "1.0.0",
            "description": format!(
                "Authenticate with an API key: `Authorization: Bearer rmm_k_…`. Create keys under Account → API keys; \
                 admins create keys for service accounts under Company settings → API. A key acts as its owner and never \
                 with more: it is limited to the scopes (resource groups) and clients it was given, and read-only keys can \
                 only `GET`. Lists page with keyset cursors (`next`/`prev`). Errors are `{{\"error\": \"…\"}}`. Each key has its \
                 own request budget (HTTP 429 with `Retry-After` when it is used up).\n\n\
                 **Webhooks.** Admins subscribe a URL to ticket and alert events ({}). Each delivery is a `POST` of the `Webhook` \
                 schema, signed like the webhook notification channel: `X-RMM-Signature: sha256=<hex HMAC-SHA256 of the raw body \
                 with the subscription's secret>`, with `X-RMM-Event` and `X-RMM-Delivery` (the delivery id; the same on retries). \
                 Any 2xx counts as delivered; anything else is retried after 1, 5, 30 minutes and 2 hours.",
                events.join(", ")
            ),
        },
        "servers": [{ "url": "/api/v1", "description": "This server" }],
        "security": [{ "bearer": [] }],
        "tags": tags,
        "paths": paths,
        "components": {
            "securitySchemes": { "bearer": { "type": "http", "scheme": "bearer", "description": "An API key: rmm_k_…" } },
            "schemas": schemas(),
        },
    })
}

/// `GET /api/openapi.json`: the description of the public API. No credentials needed.
pub async fn openapi() -> Json<&'static Value> {
    static SPEC: OnceLock<Value> = OnceLock::new();
    Json(SPEC.get_or_init(build))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_operation_is_a_real_route() {
        let router = include_str!("mod.rs");
        for op in OPS {
            assert!(router.contains(&format!("\"{}\"", op.path)), "{} isn't routed", op.path);
            assert!(crate::apikeys::valid_group(op.group), "{}: unknown group {}", op.id, op.group);
        }
    }

    #[test]
    fn operations_are_unique() {
        for (i, a) in OPS.iter().enumerate() {
            for b in &OPS[i + 1..] {
                assert!(a.id != b.id && !(a.method == b.method && a.path == b.path), "{} duplicated", a.id);
            }
        }
    }

    #[test]
    fn nothing_dangerous_is_public() {
        for op in OPS {
            for bad in ["/shell", "/desktop", "/vault", "/processes", "/files", "/services/control"] {
                assert!(!op.path.contains(bad), "{} must not be reachable with a key", op.path);
            }
            for bad in ["/auth", "/users", "/settings", "/agent/", "/events", "/billing", "/invoices", "/api-keys", "/service-accounts", "/webhook"] {
                assert!(!op.path.starts_with(bad), "{} must not be reachable with a key", op.path);
            }
        }
    }

    #[test]
    fn the_document_is_openapi_3_1_and_resolves_its_references() {
        let doc = build();
        assert_eq!(doc["openapi"], "3.1.0");
        let text = doc.to_string();
        let schemas = doc["components"]["schemas"].as_object().unwrap();
        for part in text.split("#/components/schemas/").skip(1) {
            let name: String = part.chars().take_while(|c| c.is_alphanumeric()).collect();
            assert!(schemas.contains_key(&name), "dangling reference {name}");
        }
        assert_eq!(doc["paths"]["/agents/{id}"]["get"]["parameters"][0]["name"], "id");
        assert_eq!(doc["paths"]["/tickets"]["post"]["x-rmm-access"], "write");
        assert!(doc["paths"]["/tickets/{id}"]["patch"]["requestBody"].is_object());
    }
}
