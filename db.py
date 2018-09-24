import sqlite3

# Connect to DB and setup tables, if necessary
DB_NAME = 'fbusers.db'
DB_CONN = sqlite3.connect(DB_NAME, detect_types=sqlite3.PARSE_COLNAMES)

SETUP_SCRIPT = open('dbsetup.sql').read()
DB_CONN.executescript(SETUP_SCRIPT)


def getUser(name):
	'''Gets a user by their name.'''
	global DB_CONN
	cursor = DB_CONN.execute('SELECT * FROM Users WHERE name = ?', [name])
	row = cursor.fetchone()

	if row is None:
		return None

	# Convert row to map with named fields
	data = {}
	desc = cursor.description
	for x in range(len(desc)):
		data[desc[x][0]] = row[x];

	return data

def addUser(user):
	'''Creates a new user.'''
	global DB_CONN
	cursor = DB_CONN.execute('''
		INSERT INTO Users (
			name, pass_hash, pass_salt, email
		) VALUES (?, ?, ?, ?);
	''', [
		user.get('name'),
		user.get('pass_hash'),
		user.get('pass_salt'),
		user.get('email')
	])
	DB_CONN.commit()
	return cursor.lastrowid

def updateUser(user):
	'''Updates a user. Not-present or null values are unset.'''
	global DB_CONN
	cursor = DB_CONN.execute('''
		UPDATE Users SET
			name = ?,
			pass_hash = ?,
			pass_salt = ?,
			email = ?
		WHERE id = ?;
	''', [
		user.get('name'),
		user.get('pass_hash'),
		user.get('pass_salt'),
		user.get('email'),
		user.get('id')
	])
	DB_CONN.commit()
	return cursor.rowcount

def addCode(code, user_id):
	'''Adds a new verification code.'''
	global DB_CONN
	DB_CONN.execute('''
		INSERT INTO Codes (
			code, user_id
		) VALUES (?, ?);
	''', [code, user_id])
	DB_CONN.commit()

def getCode(code):
	'''Gets a code if it hasn't been used'''
	global DB_CONN
	cursor = DB_CONN.execute('''
		SELECT * FROM Codes
		WHERE code = ?
		AND used_at IS NULL;
	''', [code])
	row = cursor.fetchone()

	if row is None:
		return None

	data = {}
	desc = cursor.description
	for x in range(len(desc)):
		data[desc[x][0]] = row[x];

	return data

def useCode(code):
	'''Sets a code's used_at field, effectively marking it as used.'''
	global DB_CONN
	cursor = DB_CONN.execute('''
		UPDATE Codes
		SET used_at = DATETIME('now')
		WHERE code = ?;
	''', [code])
	DB_CONN.commit()
	return cursor.rowcount

