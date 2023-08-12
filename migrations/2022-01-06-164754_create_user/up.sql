-- Your SQL goes here
CREATE TABLE Users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(64) NOT NULL UNIQUE,
    email VARCHAR(64) NOT NULL UNIQUE,
    actual_email VARCHAR(64) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    meta_id INTEGER NOT NULL UNIQUE,

    FOREIGN KEY (meta_id)
        REFERENCES Metadata(id)
);

CREATE TRIGGER trg_update_metadata_once_user_updated
    AFTER UPDATE OF *
    ON Users
    FOR EACH ROW
    EXECUTE PROCEDURE fn_update_metadata;