import unittest
import sqlite3
import scrypt
from time import mktime, sleep, time as now
from datetime import datetime

import db

class DBTest(unittest.TestCase):

	test_name = 'TestUser'
	test_salt = 'testsalt'
	test_hash = scrypt.hash('testpass', test_salt)
	test_email = 'test@email.com'
	test_code1 = 'abcd'
	test_code2 = '1234'
	test_code3 = 'wxyz'

	def tearDown(self):
		'''Removes the test user from the database'''
		db.DB_CONN.execute(
			'DELETE FROM Users WHERE name = ?', [self.test_name]
		)
		db.DB_CONN.commit()
		db.DB_CONN.execute(
			'DELETE FROM Codes WHERE code IN (?,?,?)',
			[self.test_code1, self.test_code2, self.test_code3]
		)
		db.DB_CONN.commit()


class GetUserTest(DBTest):

	def setUp(self):
		'''Create a test user'''
		addTestUser(self)

	def test_fieldsPreserved(self):
		user = db.getUser(self.test_name)
		with self.subTest():
			self.assertEqual(user.get('name'), self.test_name)
			self.assertEqual(user.get('pass_hash'), self.test_hash)
			self.assertEqual(user.get('pass_salt'), self.test_salt)
			self.assertEqual(user.get('email'), self.test_email)

	def test_noUserFound(self):
		user = db.getUser('badname')
		with self.subTest():
			self.assertIsNone(user)


class AddUserTest(DBTest):

	def setUp(self):
		super().setUp()
		self.test_user = {
			'name': self.test_name,
			'pass_hash': self.test_hash,
			'pass_salt': self.test_salt,
			'email': self.test_email
		}

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
			db.addUser({
				'name': self.test_name,
				'pass_hash': self.test_hash,
				'pass_salt': None
			})
			db.addUser({
				'name': self.test_name,
				'pass_hash': None,
				'pass_salt': self.test_salt
			})


class UpdateUserTest(DBTest):

	def setUp(self):
		'''Create a test user'''
		self.test_user = {
			'name': self.test_name,
			'pass_hash': self.test_hash,
			'pass_salt': self.test_salt,
			'email': self.test_email
		}
		row = addTestUser(self)
		self.test_user = {
			'id': row[0],
			'name': row[1],
			'pass_hash': row[2],
			'pass_salt': row[3],
			'email': row[4],
			'created_at': row[5],
			'updated_at': row[6],
			'accessed_at': row[7]
		}

	def test_updatedUser(self):
		update_email = 'new@email.com'
		self.test_user['email'] = update_email
		res = db.updateUser(self.test_user)
		update_user = db.getUser(self.test_name)

		with self.subTest():
			self.assertEqual(update_user.get('name'), self.test_name)
			self.assertEqual(update_user.get('pass_hash'), self.test_hash)
			self.assertEqual(update_user.get('pass_salt'), self.test_salt)
			self.assertEqual(update_user.get('email'), update_email)

	def test_modifiedUpdated(self):
		sleep(1) # Delay to ensure modified time is different
		db.updateUser(self.test_user)
		update_user = db.getUser(self.test_name)

		self.assertNotEqual(
			update_user.get('updated_at'), self.test_user.get('updated_at')
		)

	def test_createdNotUpdated(self):
		sleep(1) # Same here
		db.updateUser(self.test_user)
		update_user = db.getUser(self.test_name)

		self.assertEqual(
			update_user.get('created_at'), self.test_user.get('created_at')
		)


class AddCodeTest(DBTest):

	def setUp(self):
		self.test_id = addTestUser(self)[0]

	def test_none(self):
		with self.assertRaises(sqlite3.IntegrityError):
			db.addCode(None, self.test_id)

	def test_duplicate(self):
		db.addCode(self.test_code1, self.test_id)
		with self.assertRaises(sqlite3.IntegrityError):
			db.addCode(self.test_code1, self.test_id)

	def test_codeAdded(self):
		db.addCode(self.test_code1, self.test_id)
		db.addCode(self.test_code2, self.test_id)
		row = db.DB_CONN.execute(
			'SELECT * FROM Codes WHERE code = ?', [self.test_code1]
		).fetchone()

		code = {
			'code': row[0],
			'user_id': row[1],
			'created_at': row[2],
			'used_at': row[3]
		}

		with self.subTest():
			self.assertEqual(code.get('code'), self.test_code1)
			self.assertEqual(code.get('user_id'), self.test_id)
			self.assertTrue(dateNearNow(code.get('created_at')))
			self.assertIsNone(code.get('used_at'))


class GetCodeTest(DBTest):

	def setUp(self):
		self.test_id = addTestUser(self)[0]
		addTestCode(self)

	def test_nonExisting(self):
		code = db.getCode('badcode')
		self.assertIsNone(code)

	def test_codeRetrieved(self):
		code = db.getCode(self.test_code1)
		with self.subTest():
			self.assertIsNotNone(code)
			self.assertEqual(code.get('code'), self.test_code1)
			self.assertEqual(code.get('user_id'), self.test_id)


class UseCodeTest(DBTest):

	def setUp(self):
		self.test_id = addTestUser(self)[0]
		addTestCode(self)

	def test_nonExisting(self):
		db.useCode('badcode')
		row = getTestCode('badcode')
		self.assertIsNone(row)

	def test_used(self):
		row = getTestCode(self.test_code1)
		self.assertIsNone(row[3]) # used_at

		db.useCode(self.test_code1)

		row = getTestCode(self.test_code1)
		self.assertTrue(dateNearNow(row[3]))


class CullOldCodeTest(DBTest):

	def setUp(self):
		self.test_id = addTestUser(self)[0]

	def test_oldCulled(self):
		db.DB_CONN.execute('''
			INSERT INTO Codes (code, user_id, created_at)
			VALUES
				(?, ?, DATETIME('now')),
				(?, ?, DATETIME('now', '-1 days')),
				(?, ?, DATETIME('now', '-3 days'));
		''', [
			self.test_code1, self.test_id,
			self.test_code2, self.test_id,
			self.test_code3, self.test_id
		])
		with self.subTest():
			self.assertIsNotNone(db.getCode(self.test_code1))
			self.assertIsNotNone(db.getCode(self.test_code2))
			self.assertIsNotNone(db.getCode(self.test_code3))

			count = db.cullOldCodes()

			self.assertEqual(count, 1)
			self.assertIsNotNone(db.getCode(self.test_code1))
			self.assertIsNotNone(db.getCode(self.test_code2))
			self.assertIsNone(db.getCode(self.test_code3))


def addTestUser(self):
	db.DB_CONN.execute('''
		INSERT INTO Users (
			name, pass_hash, pass_salt, email
		) VALUES (?, ?, ?, ?);
	''', (self.test_name, self.test_hash, self.test_salt, self.test_email))
	cursor = db.DB_CONN.execute(
		'SELECT * FROM Users WHERE name = ?', [self.test_name]
	)
	return cursor.fetchone()

def addTestCode(self):
	db.DB_CONN.execute('''
		INSERT INTO Codes (code, user_id)
		VALUES (?, ?)
	''', [self.test_code1, self.test_id])

def getTestCode(code):
	return db.DB_CONN.execute(
		'SELECT * FROM Codes WHERE code = ?', [code]
	).fetchone()

def dateNearNow(date):
	'''Check that the given time is within a few seconds of now.'''
	utime = mktime(datetime.strptime(date, "%Y-%m-%d %H:%M:%S").timetuple())
	return utime + 5 > now()


if __name__ == '__main__':
	unittest.main()

