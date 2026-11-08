-- Agent self-update progress, as last reported by the agent (or 'offered' by the server).
ALTER TABLE agents ADD COLUMN update_version text;
ALTER TABLE agents ADD COLUMN update_state   text;
ALTER TABLE agents ADD COLUMN update_detail  text;
ALTER TABLE agents ADD COLUMN update_at      timestamptz;

-- Offer the newest signed agent build to every agent when it connects.
ALTER TABLE company_settings ADD COLUMN auto_update_agents boolean NOT NULL DEFAULT false;
