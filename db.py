import sqlite3

CODE_TYPE_PASS = 'pass'
CODE_TYPE_EMAIL = 'email'

# Connect to DB and setup tables, if necessary
DB_NAME = 'fbusers.db'
DB_CONN = sqlite3.connect(DB_NAME,
	detect_types=sqlite3.PARSE_COLNAMES,
	check_same_thread=False #TODO this might be a terrible idea
)

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

def getUserById(uid):
	'''Gets a user by their DB assigned ID'''
	global DB_CONN
	cursor = DB_CONN.execute('SELECT * FROM Users WHERE id = ?', [uid])
	row = cursor.fetchone()

	if row is None:
		return None

	data = {}
	desc = cursor.description
	for x in range(len(desc)):
		data[desc[x][0]] = row[x]

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

def addEmailCode(code, user_id, email):
	'''Adds a new email verification code.'''
	global DB_CONN
	global CODE_TYPE_EMAIL

	if email is None:
		raise sqlite3.IntegrityError('Email codes must define an email')

	DB_CONN.execute('''
		INSERT INTO Codes (
			type, code, user_id, email
		) VALUES (?, ?, ?, ?);
	''', [CODE_TYPE_EMAIL, code, user_id, email])
	DB_CONN.commit()

def addPasswordCode(code, user_id):
	'''Adds a new password reset code.'''
	global DB_CONN
	global CODE_TYPE_PASS
	DB_CONN.execute('''
		INSERT INTO Codes (
			type, code, user_id
		) VALUES (?, ?, ?);
	''', [CODE_TYPE_PASS, code, user_id])
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
		SET used_at = DATETIME('now', 'localtime')
		WHERE code = ?;
	''', [code])
	DB_CONN.commit()
	return cursor.rowcount

def cullOldCodes():
	'''Deletes all old, unused codes.'''
	global DB_CONN
	cursor = DB_CONN.execute('''
		DELETE FROM Codes
		WHERE used_at IS NULL
		AND created_at < DATETIME('now', '-2 days');
	''')
	DB_CONN.commit()
	return cursor.rowcount

