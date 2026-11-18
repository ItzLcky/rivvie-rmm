-- Signature databases (docs/design/antivirus.md, milestone 2): binary files of hash signatures
-- and YARA rules, signed offline like content bundles and rolled out through the same stages.
-- The file itself is in storage (disk or S3), not in a row; agents fetch it over HTTPS.

CREATE TABLE signature_databases (
    id               uuid PRIMARY KEY,
    version          text NOT NULL UNIQUE,
    -- Of the whole file, signature included: what agents check the download against.
    sha256           text NOT NULL,
    size             bigint NOT NULL,
    -- NULL once pruned from storage (the row stays, for history).
    storage_key      text,
    description      text NOT NULL DEFAULT '',
    -- Same shape as content_versions.rules (id, name, kind, severity, confidence, mode, mitre,
    -- digest, plus source and licence): the rules view and the canary rollout read it.
    rules            jsonb NOT NULL DEFAULT '[]',
    sources          jsonb NOT NULL DEFAULT '[]',
    hashes           bigint NOT NULL DEFAULT 0,
    yara_rules       integer NOT NULL DEFAULT 0,
    -- When it was built (from the file).
    built_at         timestamptz NOT NULL,
    stage            text NOT NULL DEFAULT 'canary' CHECK (stage IN ('canary', 'general', 'rolled_back', 'retired')),
    stage_reason     text,
    uploaded_by      uuid REFERENCES users(id) ON DELETE SET NULL,
    uploaded_at      timestamptz NOT NULL DEFAULT now(),
    stage_changed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON signature_databases (stage, uploaded_at);

ALTER TABLE agents ADD COLUMN database_version text;

-- Which database a detection came from, and where in the file (archive member, macro).
ALTER TABLE security_detections ADD COLUMN database_version text, ADD COLUMN part text;
