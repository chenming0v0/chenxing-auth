CREATE TABLE app_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value TEXT,
    updated_at TIMESTAMPTZ NOT NULL
);

INSERT INTO app_settings (setting_key, setting_value, updated_at)
VALUES ('registration_email_from', NULL, NOW());
