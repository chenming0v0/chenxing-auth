-- System settings seeds for admin-configurable auth, mail, and SMTP policy.
-- Existing registration_email_from remains for compatibility; SMTP from can mirror it.

INSERT INTO app_settings (setting_key, setting_value, updated_at)
VALUES
  ('passkey', NULL, NOW()),
  ('email_policy', NULL, NOW()),
  ('smtp', NULL, NOW()),
  ('security_limits', NULL, NOW())
ON CONFLICT (setting_key) DO NOTHING;
