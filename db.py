import sqlite3
from flask import g

CODE_TYPE_PASS = 'pass'
CODE_TYPE_EMAIL = 'email'

# Connect to DB and setup tables, if necessary
DB_NAME = 'fbusers.db'

# TODO This needs a new place
'''
SETUP_SCRIPT = open('dbsetup.sql').read()
DB_CONN.executescript(SETUP_SCRIPT)
'''

def getDb():
	'''Gets the DB connection for this context.
	   Will make a connection if there is none.'''
	db = getattr(g, '_database', None)
	if db is None:
		db = g._database = sqlite3.connect(DB_NAME,
		                       detect_types=sqlite3.PARSE_COLNAMES,
		                   )
	return db

def closeDb():
	db = getattr(g, '_database', None)
	if db is not None:
		db.close()

def FetchOneAsMap(cursor):
	row = cursor.fetchone()

	if row is None:
		return None

	# Convert row to map with named fields
	data = {}
	desc = cursor.description
	for x in range(len(desc)):
		data[desc[x][0]] = row[x];

	return data

def getUser(name):
	'''Gets a user by their name.'''
	cursor = getDb().execute('SELECT * FROM Users WHERE name = ?', [name])

	return FetchOneAsMap(cursor)

def getUserById(uid):
	'''Gets a user by their DB assigned ID'''
	cursor = getDb().execute('SELECT * FROM Users WHERE id = ?', [uid])

	return FetchOneAsMap(cursor)

def addUser(user):
	'''Creates a new user.'''
	db_conn = getDb()
	cursor = db_conn.execute('''
		INSERT INTO Users (
			name, pass_hash, pass_salt, email
		) VALUES (?, ?, ?, ?);
	''', [
		user.get('name'),
		user.get('pass_hash'),
		user.get('pass_salt'),
		user.get('email')
	])
	db_conn.commit()
	return cursor.lastrowid

def updateUser(user):
	'''Updates a user. Not-present or null values are unset.'''
	db_conn = getDb()
	cursor = db_conn.execute('''
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
	db_conn.commit()
	return cursor.rowcount

def addEmailCode(code, user_id, email):
	'''Adds a new email verification code.'''
	db_conn = getDb()
	global CODE_TYPE_EMAIL

	if email is None:
		raise sqlite3.IntegrityError('Email codes must define an email')

	db_conn.execute('''
		INSERT INTO Codes (
			type, code, user_id, email
		) VALUES (?, ?, ?, ?);
	''', [CODE_TYPE_EMAIL, code, user_id, email])
	db_conn.commit()

def addPasswordCode(code, user_id):
	'''Adds a new password reset code.'''
	db_conn = getDb()
	global CODE_TYPE_PASS
	db_conn.execute('''
		INSERT INTO Codes (
			type, code, user_id
		) VALUES (?, ?, ?);
	''', [CODE_TYPE_PASS, code, user_id])
	db_conn.commit()

def getCode(code):
	'''Gets a code if it hasn't been used'''
	db_conn = getDb()
	cursor = db_conn.execute('''
		SELECT * FROM Codes
		WHERE code = ?
		AND used_at IS NULL;
	''', [code])

	return FetchOneAsMap(cursor)

def useCode(code):
	'''Sets a code's used_at field, effectively marking it as used.'''
	db_conn = getDb()
	cursor = db_conn.execute('''
		UPDATE Codes
		SET used_at = DATETIME('now', 'localtime')
		WHERE code = ?;
	''', [code])
	db_conn.commit()
	return cursor.rowcount

def cullOldCodes():
	'''Deletes all old, unused codes.'''
	db_conn = getDb()
	cursor = db_conn.execute('''
		DELETE FROM Codes
		WHERE used_at IS NULL
		AND created_at < DATETIME('now', '-2 days');
	''')
	db_conn.commit()
	return cursor.rowcount

