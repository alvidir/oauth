CREATE TYPE IF NOT EXISTS SECRET AS ENUM ('otp', 'salt');

CREATE TABLE IF NOT EXISTS Secrets (
    id SERIAL PRIMARY KEY,
    kind SECRET NOT NULL,
    owner VARCHAR(128) NOT NULL,
    data TEXT NOT NULL,

    UNIQUE (kind, owner),

    CONSTRAINT fk_user_uuid
        FOREIGN KEY (owner)
        REFERENCES Users(uuid)
        ON DELETE CASCADE,
);

CREATE OR REPLACE FUNCTION fn_prevent_update_secrets_data()
    RETURNS trigger AS
$BODY$
    BEGIN
        RAISE EXCEPTION 'cannot update secret fields';
    END;
$BODY$
    LANGUAGE plpgsql VOLATILE
    COST 100;

CREATE TRIGGER trg_prevent_update_secrets_data
    BEFORE UPDATE OF *
    ON Secrets
    FOR EACH ROW
    EXECUTE PROCEDURE fn_prevent_update_secrets_data;
