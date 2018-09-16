import unittest
import sqlite3
import scrypt
from time import mktime, sleep, time as now
from datetime import datetime

from server import AccountException
import db
from user import User

class DBTest(unittest.TestCase):

	test_name = 'TestUser'
	test_salt = 'testsalt'
	test_hash = scrypt.hash('testpass', test_salt)
	test_email = 'test@email.com'

	def tearDown(self):
		'''Removes the test user from the database'''
		db.DB_CONN.execute(
			'DELETE FROM Users WHERE name = ?', [self.test_name]
		)
		db.DB_CONN.commit()


class GetUserTest(DBTest):

	def setUp(self):
		'''Create a test user'''
		db.DB_CONN.execute('''
			INSERT INTO Users (
				name, pass_hash, pass_salt, email
			) VALUES (?, ?, ?, ?);
		''', (self.test_name, self.test_hash, self.test_salt, self.test_email))

	def test_fieldsPreserved(self):
		user = db.getUser(self.test_name)
		with self.subTest():
			self.assertEqual(user.name, self.test_name)
			self.assertEqual(user.pass_hash, self.test_hash)
			self.assertEqual(user.pass_salt, self.test_salt)
			self.assertEqual(user.email, self.test_email)

	def test_noUserFound(self):
		user = db.getUser('badname')
		with self.subTest():
			self.assertIsNone(user)


class AddUserTest(DBTest):

	def setUp(self):
		super().setUp()
		self.test_user = User(
			name=self.test_name,
			pass_hash=self.test_hash,
			pass_salt=self.test_salt,
			email=self.test_email
		)

	def test_fieldsPreserved(self):
		db.addUser(self.test_user)
		row = db.DB_CONN.execute('''
			SELECT name, pass_hash, pass_salt, email
			FROM Users WHERE name = ?
		''', [self.test_name]).fetchone()

		with self.subTest():
			self.assertEqual(row[0], self.test_name)
			self.assertEqual(row[1], self.test_hash)
			self.assertEqual(row[2], self.test_salt)
			self.assertEqual(row[3], self.test_email)

	def test_datesPopulated(self):
		db.addUser(self.test_user)
		row = db.DB_CONN.execute('''
			SELECT created_at, updated_at, accessed_at
			FROM Users WHERE name = ?
		''', [self.test_name]).fetchone()

		with self.subTest():
			self.assertTrue(dateNearNow(row[0]))
			self.assertTrue(dateNearNow(row[1]))
			#self.assertTrue(dateNearNow(row[2]))

	def test_duplicateName(self):
		db.addUser(self.test_user)
		with self.assertRaises(sqlite3.IntegrityError):
			db.addUser(self.test_user)

	def test_hashAndSaltRequired(self):
		with self.assertRaises(sqlite3.IntegrityError):
			db.addUser(User(
				name=self.test_name,
				pass_hash=self.test_hash,
				pass_salt=None
			))
			db.addUser(User(
				name=self.test_name,
				pass_hash=None,
				pass_salt=self.test_salt
			))


class UpdateUserTest(DBTest):

	def setUp(self):
		'''Create a test user'''
		self.test_user = User(
			name=self.test_name,
			pass_hash=self.test_hash,
			pass_salt=self.test_salt,
			email=self.test_email
		)
		db.DB_CONN.execute('''
			INSERT INTO Users (
				name, pass_hash, pass_salt, email
			) VALUES (?, ?, ?, ?);
		''', (self.test_name, self.test_hash, self.test_salt, self.test_email))

		cursor = db.DB_CONN.execute(
			'SELECT * FROM Users WHERE name = ?', [self.test_name]
		)
		row = cursor.fetchone()
		self.test_user = User(
			id=row[0],
			name=row[1],
			pass_hash=row[2],
			pass_salt=row[3],
			email=row[4],
			created_at=row[5],
			updated_at=row[6],
			accessed_at=row[7]
		)

	def test_updatedUser(self):
		update_email = 'new@email.com'
		self.test_user.email = update_email
		res = db.updateUser(self.test_user)
		update_user = db.getUser(self.test_name)

		with self.subTest():
			self.assertEqual(update_user.name, self.test_name)
			self.assertEqual(update_user.pass_hash, self.test_hash)
			self.assertEqual(update_user.pass_salt, self.test_salt)
			self.assertEqual(update_user.email, update_email)

	def test_modifiedUpdated(self):
		sleep(1) # Delay to ensure modified time is different
		db.updateUser(self.test_user)
		update_user = db.getUser(self.test_name)

		self.assertNotEqual(update_user.updated_at, self.test_user.updated_at)

	def test_createdNotUpdated(self):
		sleep(1) # Same here
		db.updateUser(self.test_user)
		update_user = db.getUser(self.test_name)

		self.assertEqual(update_user.created_at, self.test_user.created_at)


def dateNearNow(date):
	'''Check that the given time is within a few seconds of now.'''
	utime = mktime(datetime.strptime(date, "%Y-%m-%d %H:%M:%S").timetuple())
	return utime + 5 > now()


if __name__ == '__main__':
	unittest.main()

