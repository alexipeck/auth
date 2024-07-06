CREATE TABLE user_new (
    id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    email TEXT NOT NULL,
    hashed_and_salted_password TEXT NOT NULL,
    two_fa_client_secret TEXT NOT NULL,
    PRIMARY KEY(id)
);
INSERT INTO user_new (id, display_name, email, hashed_and_salted_password, two_fa_client_secret)
SELECT id, display_name, email, hashed_and_salted_password, two_fa_client_secret FROM user;
DROP TABLE user;
ALTER TABLE user_new RENAME TO user;
