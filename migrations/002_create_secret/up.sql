-- Your SQL goes here
CREATE TYPE SECRET AS ENUM ('totp');

CREATE TABLE Secrets (
    id SERIAL PRIMARY KEY,
    kind SECRET NOT NULL,
    owner INTEGER NOT NULL,
    data TEXT NOT NULL,

    UNIQUE (kind, owner),

    FOREIGN KEY (owner)
        REFERENCES Users(id),
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
