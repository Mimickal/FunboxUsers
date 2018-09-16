CREATE TABLE IF NOT EXISTS Users (
	id          INTEGER PRIMARY KEY,
	name        TEXT    UNIQUE NOT NULL,
	pass_hash   TEXT    NOT NULL,
	pass_salt   TEXT    NOT NULL,
	email       TEXT,
	created_at  TIMESTAMP,
	updated_at  TIMESTAMP,
	accessed_at TIMESTAMP
);

CREATE TRIGGER IF NOT EXISTS trig_created_at
AFTER INSERT ON Users
BEGIN
	UPDATE Users
	SET created_at = datetime(CURRENT_TIMESTAMP, 'localtime')
	WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trig_updated_at
AFTER UPDATE ON Users
BEGIN
	UPDATE Users
	SET updated_at = datetime(CURRENT_TIMESTAMP, 'localtime')
	WHERE id = NEW.id;
END;

