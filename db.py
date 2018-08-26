import sqlite3

from user import User

# Connect to DB and setup tables, if necessary
DB_NAME = 'fbusers.db'
DB_CONN = sqlite3.connect(DB_NAME, detect_types=sqlite3.PARSE_COLNAMES)

SETUP_SCRIPT = open('dbsetup.sql').read()
DB_CONN.executescript(SETUP_SCRIPT)


def getUser(name):
	'''Gets a user by their name.'''
	global DB_CONN
	cursor = DB_CONN.execute('SELECT * FROM Users WHERE name = ?', name)
	row = cursor.fetchone()

	# Convert row to map with named fields
	data = {}
	desc = cursor.description
	for x in range(len(desc)):
		data[desc[x][0]] = row[x];

	return User(
		id = data['id'],
		name = data['name'],
		pass_hash = data['pass_hash'],
		pass_salt = data['pass_salt'],
		email = data['email'],
		created_at = data['created_at'],
		updated_at = data['updated_at'],
		accessed_at = data['accessed_at']
	)


