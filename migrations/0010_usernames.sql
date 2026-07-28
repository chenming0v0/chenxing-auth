ALTER TABLE users
    ADD COLUMN username TEXT;

UPDATE users
SET username = 'user_' || id
WHERE username IS NULL;

ALTER TABLE users
    ALTER COLUMN username SET NOT NULL;

ALTER TABLE users
    ADD CONSTRAINT users_username_key UNIQUE (username);
