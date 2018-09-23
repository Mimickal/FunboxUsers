import unittest
from sqlite3 import IntegrityError

from add_user import createUser
import db

class AddUserTest(unittest.TestCase):

	test_name = 'AddUserTest'

	def tearDown(self):
		db.DB_CONN.execute(
			'DELETE FROM Users WHERE name = ?', [self.test_name]
		)
		db.DB_CONN.commit()

	def test_createUser(self):
		new_pass = createUser(self.test_name)
		self.assertIsNotNone(new_pass)

	def test_createDuplicateUser(self):
		new_pass_1 = createUser(self.test_name)
		with self.assertRaises(IntegrityError):
			createUser(self.test_name)


if __name__ == '__main__':
	unittest.main()

