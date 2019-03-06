from pocha import describe, it, after_each, before
from sqlite3 import IntegrityError

from add_user import createUser
import db

@describe('add_user')
def add_user_test():

	test_name = "AddUserTest"

	# We need to also do this before in case of our database already
	# containing a user named AddUserTest.
	@before
	@after_each
	def cleanup():
		db.DB_CONN.execute(
		'DELETE FROM Users WHERE name = ?', [test_name]
	)
	db.DB_CONN.commit()

	@it('can create a new user')
	def test_createUser():
		new_pass = createUser(test_name)
		assert new_pass != None

	@it('can detect it when we are trying to create a user that already exists')
	def test_createDuplicateUser():
		passed = False
		new_pass_1 = createUser(test_name)
		try:
			createUser(test_name)
		except IntegrityError:
			passed = True
		assert passed
