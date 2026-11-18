-- Antivirus milestones 3 and 5 (docs/design/antivirus.md): on-access protection and the
-- reputation lookup.

-- Real-time protection: off, audit (decide but never deny or act) or block; scanning files as
-- they're written; how deep archives are opened.
ALTER TABLE security_policies ADD COLUMN realtime      text    NOT NULL DEFAULT 'off' CHECK (realtime IN ('off', 'audit', 'block'));
ALTER TABLE security_policies ADD COLUMN scan_on_write boolean NOT NULL DEFAULT true;
ALTER TABLE security_policies ADD COLUMN archive_depth integer NOT NULL DEFAULT 5 CHECK (archive_depth BETWEEN 1 AND 20);

-- How a file detection was found (on_exec, on_write, scan, reputation) and whether the program
-- was refused before it ran.
ALTER TABLE security_detections ADD COLUMN found_by text;
ALTER TABLE security_detections ADD COLUMN denied   boolean NOT NULL DEFAULT false;

-- The server's full set of known-bad SHA-256 hashes, for agents' lookups: the newest database
-- that isn't rolled back ('db:<version>') plus hash lists uploaded for reputation only
-- ('list:<name>'), which agents never download.
CREATE TABLE reputation_hashes (
    sha256    bytea NOT NULL CHECK (length(sha256) = 32),
    source    text  NOT NULL,
    name      text  NOT NULL,
    severity  text  NOT NULL,
    added_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (sha256, source)
);
CREATE INDEX ON reputation_hashes (source);

-- Each program hash an agent asked about, once: first seen, and so prevalence across the fleet.
CREATE TABLE hash_sightings (
    sha256      bytea NOT NULL CHECK (length(sha256) = 32),
    agent_id    uuid  NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    path        text,
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (sha256, agent_id)
);
CREATE INDEX ON hash_sightings (agent_id);
CREATE INDEX ON hash_sightings (first_seen);
