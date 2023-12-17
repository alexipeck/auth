CREATE TABLE IF NOT EXISTS user (
    id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    email TEXT NOT NULL,
    hashed_and_salted_password TEXT NOT NULL,
    two_fa_client_secret TEXT NOT NULL,
    PRIMARY KEY(id)
);