-- Antivirus milestone 4 (docs/design/antivirus.md): how old our signature database may be
-- before the agent counts as at risk and the security alert policy's "database out of date"
-- check fires. 0 = never. 72 hours matches the age at which other products' signatures
-- already count as stale.
ALTER TABLE security_policies ADD COLUMN database_max_age_hours integer NOT NULL DEFAULT 72
    CHECK (database_max_age_hours BETWEEN 0 AND 8760);
