-- Phase 6: remote desktop.

-- Ask the person at the machine before a remote desktop session starts.
ALTER TABLE clients ADD COLUMN desktop_consent boolean NOT NULL DEFAULT false;
