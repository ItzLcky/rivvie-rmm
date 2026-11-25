-- Wake-on-LAN (docs/design/wake-on-lan.md). When the server last asked another agent of the
-- site to wake this one, by hand or before a patch window: the patch scheduler wakes a device
-- at most once in 12 hours, so a machine that never wakes isn't sent packets every minute.
ALTER TABLE agents ADD COLUMN wol_sent_at timestamptz;
