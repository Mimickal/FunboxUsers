from random import choice
from string import ascii_letters, digits, printable
import scrypt
from sqlite3 import IntegrityError

from user import User
import db


def randomStr(characters, length):
	return ''.join(choice(characters) for _ in range(length))

def createUser(username):
	temp_pass = randomStr(ascii_letters + digits, 12)
	pw_salt = randomStr(printable, 10)
	pw_hash = memoryview(scrypt.hash(temp_pass, pw_salt))

	user = User(
		name=username,
		pass_hash=pw_hash,
		pass_salt=pw_salt
	)

	db.addUser(user)
	return temp_pass


if __name__ == '__main__':
	from argparse import ArgumentParser
	from sys import stderr

	parser = ArgumentParser(description='Funbox add-user-account utility')
	parser.add_argument('username')
	args = parser.parse_args()

	try:
		new_pass = createUser(args.username)
		print(new_pass)
	except IntegrityError:
		print('Username already exists: ' + args.username, file=stderr)

