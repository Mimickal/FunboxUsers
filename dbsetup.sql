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

CREATE TABLE IF NOT EXISTS Codes (
	code       TEXT       UNIQUE NOT NULL,
	user_id    INTEGER    REFERENCES Users(id),
	email      TEXT       NOT NULL,
	created_at TIMESTAMP,
	used_at    TIMESTAMP
);

CREATE TRIGGER IF NOT EXISTS trig_user_created_at
AFTER INSERT ON Users
BEGIN
	UPDATE Users
	SET created_at = DATETIME('now', 'localtime')
	WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trig_user_updated_at
AFTER UPDATE ON Users
BEGIN
	UPDATE Users
	SET updated_at = DATETIME('now', 'localtime')
	WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trig_code_created_at
AFTER INSERT ON Codes
BEGIN
	UPDATE Codes
	SET created_at = DATETIME('now', 'localtime')
	WHERE code = NEW.code
	AND created_at IS NULL;
END;

