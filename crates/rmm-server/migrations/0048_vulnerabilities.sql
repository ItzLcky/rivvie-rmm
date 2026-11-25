-- Vulnerabilities (docs/design/vulnerabilities.md): a local mirror of the distributions' and
-- NVD's advisories, matched against each device's software inventory. Nothing about the fleet
-- leaves the server: feeds are downloaded whole (or by product, for NVD) and matched here.

-- One row per feed: OSV per ecosystem (`osv:Debian`, ...), the Arch tracker, NVD, CISA KEV, EPSS.
CREATE TABLE vuln_feeds (
    name            text PRIMARY KEY,
    enabled         boolean NOT NULL DEFAULT true,
    last_sync_at    timestamptz,
    -- The last attempt, successful or not, and what it is doing while it runs.
    last_attempt_at timestamptz,
    progress        text,
    -- HTTP Last-Modified of the last download, or NVD's lastModStartDate cursor.
    last_modified   text,
    etag            text,
    records         integer NOT NULL DEFAULT 0,
    error           text
);
INSERT INTO vuln_feeds (name) VALUES
    ('osv:Debian'), ('osv:Ubuntu'), ('osv:AlmaLinux'), ('osv:Rocky Linux'), ('osv:Red Hat'),
    ('osv:SUSE'), ('osv:openSUSE'), ('osv:Alpine'), ('arch'), ('nvd'), ('kev'), ('epss');

-- An advisory as its feed names it (DEBIAN-CVE-..., UBUNTU-CVE-..., ALSA-..., AVG-..., CVE-...).
CREATE TABLE vulns (
    id          text PRIMARY KEY,
    aliases     text[] NOT NULL DEFAULT '{}',
    -- The CVE it is about, when there is one: what the lists group by.
    cve         text,
    summary     text NOT NULL DEFAULT '',
    details     text NOT NULL DEFAULT '',
    severity    text NOT NULL DEFAULT 'unknown' CHECK (severity IN ('critical', 'high', 'medium', 'low', 'none', 'unknown')),
    cvss        real,
    cvss_vector text,
    -- Copied from vuln_cve_scores after every sync (filters and stored counts read them here).
    epss        real,
    kev         boolean NOT NULL DEFAULT false,
    published   timestamptz,
    modified    timestamptz,
    source      text NOT NULL,
    url         text
);
CREATE INDEX vulns_cve ON vulns (cve);

-- KEV and EPSS, by CVE: kept apart so an advisory imported after them still gets them.
CREATE TABLE vuln_cve_scores (
    cve             text PRIMARY KEY,
    epss            real,
    epss_percentile real,
    kev             boolean NOT NULL DEFAULT false,
    kev_added       date,
    kev_due         date
);

-- What an advisory affects: a package of an ecosystem (`Debian:12` + source package, `Arch` +
-- package, `NVD` + `vendor:product`) between `introduced` and `fixed` (or `last_affected`).
CREATE TABLE vuln_ranges (
    vuln_id              text NOT NULL REFERENCES vulns(id) ON DELETE CASCADE,
    ecosystem            text NOT NULL,
    package              text NOT NULL,
    introduced           text,
    introduced_exclusive boolean NOT NULL DEFAULT false,
    fixed                text,
    last_affected        text
);
CREATE INDEX vuln_ranges_package ON vuln_ranges (ecosystem, package);
CREATE INDEX vuln_ranges_vuln ON vuln_ranges (vuln_id);

-- Windows applications: a curated map from installed titles to NVD products, never fuzzy CPE
-- matching. Seeded from content/vuln/products.json (`builtin`); admins add, edit and hide.
CREATE TABLE vuln_products (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor            text NOT NULL,
    product           text NOT NULL,
    name              text NOT NULL,
    -- Case-insensitive globs (`*`) on the installed DisplayName.
    name_patterns     text[] NOT NULL,
    publisher_pattern text,
    package_id        uuid REFERENCES software_packages(id) ON DELETE SET NULL,
    builtin           boolean NOT NULL DEFAULT false,
    -- A built-in product someone removed: kept so the seed doesn't bring it back.
    hidden            boolean NOT NULL DEFAULT false,
    -- NVD is fetched per product: in full the first time, by lastModStartDate after that.
    nvd_synced_at     timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (vendor, product)
);

-- A vulnerable package on a device. Stored only when a fix exists, the severity is high or
-- critical, or the CVE is known exploited (distributions list many minor unfixed issues).
CREATE TABLE vuln_findings (
    agent_id          uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    vuln_id           text NOT NULL REFERENCES vulns(id) ON DELETE CASCADE,
    -- The package as the feed names it (the source package on Debian and Ubuntu, the product
    -- for Windows), and the installed software it was found through.
    package           text NOT NULL,
    software_name     text NOT NULL,
    installed_version text NOT NULL,
    fixed_version     text,
    fix_available     boolean NOT NULL,
    product_id        uuid REFERENCES vuln_products(id) ON DELETE SET NULL,
    first_seen        timestamptz NOT NULL DEFAULT now(),
    last_seen         timestamptz NOT NULL DEFAULT now(),
    resolved_at       timestamptz,
    PRIMARY KEY (agent_id, vuln_id, package)
);
CREATE INDEX vuln_findings_open ON vuln_findings (vuln_id) WHERE resolved_at IS NULL;
CREATE INDEX vuln_findings_package ON vuln_findings (package) WHERE resolved_at IS NULL;
CREATE INDEX vuln_findings_first_seen ON vuln_findings (first_seen) WHERE resolved_at IS NULL;

-- Accepted risk: a CVE (or advisory id) for a client's devices, or one device, until it expires.
CREATE TABLE vuln_acceptances (
    id         uuid PRIMARY KEY,
    vuln_id    text NOT NULL,
    client_id  uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    agent_id   uuid REFERENCES agents(id) ON DELETE CASCADE,
    note       text NOT NULL DEFAULT '',
    expires_at timestamptz,
    by         uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX vuln_acceptances_vuln ON vuln_acceptances (vuln_id);

-- Whether a finding (advisory `vuln`, about `cve`) on this agent is accepted right now.
CREATE FUNCTION vuln_accepted(agent uuid, vuln text, cve text) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM vuln_acceptances va JOIN agents a ON a.id = agent JOIN sites s ON s.id = a.site_id
         WHERE va.client_id = s.client_id AND (va.agent_id IS NULL OR va.agent_id = agent)
           AND (va.vuln_id = vuln OR va.vuln_id = cve) AND (va.expires_at IS NULL OR va.expires_at > now()))
$$;

ALTER TABLE agents
    ADD COLUMN vuln_evaluated_at   timestamptz,
    ADD COLUMN vuln_inventory_hash text,
    -- The ecosystem its packages are matched in (`Debian:12`, `Arch`, `Windows`), or why the
    -- device isn't assessed (`vuln_unassessed`: old_agent, unsupported_os, no_inventory).
    ADD COLUMN vuln_ecosystem      text,
    ADD COLUMN vuln_unassessed     text,
    -- Open findings nobody accepted, for lists and the dashboard.
    ADD COLUMN vuln_critical       integer NOT NULL DEFAULT 0,
    ADD COLUMN vuln_high           integer NOT NULL DEFAULT 0;
