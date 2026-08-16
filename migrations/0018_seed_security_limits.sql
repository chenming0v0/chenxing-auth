-- The v1.0.6 release added this seed directly to migration 0009. Move the
-- behavior into a new migration so the published 0009 bytes stay immutable.
INSERT INTO app_settings (setting_key, setting_value, updated_at)
VALUES ('security_limits', NULL, NOW())
ON CONFLICT (setting_key) DO NOTHING;
