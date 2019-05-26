from pocha import describe, it, afterEach, before
from hamcrest import *
from sqlite3 import IntegrityError

from add_user import createUser
import db

@describe('Add User')
def add_user_test():

	test_name = "AddUserTest"

	# We need to also do this before in case of our database already
	# containing a user named AddUserTest.
	@before
	@afterEach
	def cleanup():
		db.DB_CONN.execute(
			'DELETE FROM Users WHERE name = ?', [test_name]
		)
		db.DB_CONN.commit()

	@it('can create a new user')
	def test_createUser():
		new_pass = createUser(test_name)
		assert_that(new_pass, not_none())

	@it('can detect it when we are trying to create a user that already exists')
	def test_createDuplicateUser():
		createUser(test_name)
		assert_that(
			calling(createUser).with_args(test_name),
			raises(IntegrityError, 'UNIQUE constraint failed: Users.name')
		)

