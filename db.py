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

	cursor = DB_CONN.cursor()
	cursor.execute('SELECT * FROM Users WHERE name = ?', name)
	data = cursor.fetchone()

	return User(*data)

