-- Nonsecret metadata and authenticated ciphertext share the settings transaction.
-- NULL allows a one-time import from a legacy deployment; an empty JSON array
-- is an explicitly configured empty registry and must never resurrect env values.
INSERT INTO app_settings (setting_key, setting_value, updated_at)
VALUES ('account_providers', NULL, NOW())
ON CONFLICT (setting_key) DO NOTHING;
