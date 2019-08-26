from argparse import ArgumentParser
from sys import stderr

from peewee import IntegrityError

from db import User
import util

if __name__ == '__main__':
	from argparse import ArgumentParser
	from sys import stderr

	parser = ArgumentParser(description='Funbox add-user-account utility')
	parser.add_argument('username')
	args = parser.parse_args()

	name = args.username
	pw = util.makeCode(12)
	pw_salt = util.makeCode(8)
	pw_hash = memoryview(util.hashPassword(pw, pw_salt))

	try:
		User.create(
			name      = name,
			pass_hash = pw_hash,
			pass_salt = pw_salt
		)
		print('User [%s] created with temp password [%s]' % (name, pw))
	except IntegrityError as e:
		print('Error adding user [%s]: %s' % (name, e), file=stderr)
else:
	raise Exception('This is not a module, do not import this')

