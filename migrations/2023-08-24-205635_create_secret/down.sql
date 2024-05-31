DROP TRIGGER IF EXISTS trg_prevent_update_secrets_data ON TABLE Secrets;
DROP FUNCTION IF EXISTS fn_prevent_update_secrets_data;
DROP TABLE IF EXISTS Secrets;
DROP TYPE IF EXISTS SECRET;