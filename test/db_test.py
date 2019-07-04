from pocha import describe, it, before, beforeEach, after
from hamcrest import *
from sqlite3 import IntegrityError
import scrypt
from time import mktime, sleep, time as now
from datetime import datetime

import db

from server import app

@describe('Database Tests')
def databaseTests():

	test_name = 'TestUser'
	test_salt = 'testsalt'
	test_hash = scrypt.hash('testpass', test_salt)
	test_email = 'test@email.com'
	test_code1 = 'abcd'
	test_code2 = '1234'
	test_code3 = 'wxyz'

	test_user = {
		'name': test_name,
		'pass_hash': test_hash,
		'pass_salt': test_salt,
		'email': test_email
	}

	test_id = None

	def cleanup():
		'''Removes the test data from the database'''
		db.getDb().execute('DELETE FROM Users WHERE name = ?', [test_name])
		db.getDb().execute(
			'DELETE FROM Codes WHERE code IN (?,?,?)',
			[test_code1, test_code2, test_code3]
		)
		db.getDb().commit()

	def addTestUser(whole_row=False):
		db.getDb().execute('''
			INSERT INTO Users (
				name, pass_hash, pass_salt, email
			) VALUES (?, ?, ?, ?);
		''', (test_name, test_hash, test_salt, test_email))
		cursor = db.getDb().execute(
			'SELECT * FROM Users WHERE name = ?', [test_name]
		)
		row = cursor.fetchone()
		db.getDb().commit()
		if whole_row:
			return row
		else:
			# Only return ID of newly added user
			return row[0]

	def addTestCode():
		nonlocal test_id
		db.getDb().execute('''
			INSERT INTO Codes (type, code, user_id, email)
			VALUES (?, ?, ?, ?)
		''', [db.CODE_TYPE_EMAIL, test_code1, test_id, test_email])
		db.getDb().commit()

	def getTestCode(code):
		with app.app_context():
			return db.getDb().execute(
				'SELECT * FROM Codes WHERE code = ?', [code]
			).fetchone()

	def assertDateNearNow(date):
		'''Check that the given time is within a few seconds of now.'''
		utime = mktime(datetime.strptime(date, "%Y-%m-%d %H:%M:%S").timetuple())
		assert_that(utime, close_to(now(), 5))

	@before
	def beforeAll():
		with app.app_context():
			cleanup()

	@after
	def afterAll():
		with app.app_context():
			cleanup()

	@describe('Get User')
	def getUser():
		with app.app_context():
			@beforeEach
			def _beforeEach():
				with app.app_context():
					cleanup()
					addTestUser()

			@it('User fields persisted')
			def fieldsPreserved():
				with app.app_context():
					user = db.getUser(test_name)
					assert_that(user.get('name'), equal_to(test_name))
					assert_that(user.get('pass_hash'), equal_to(test_hash))
					assert_that(user.get('pass_salt'), equal_to(test_salt))
					assert_that(user.get('email'), equal_to(test_email))

			@it('None returned for non-existing user')
			def noUserFound():
				with app.app_context():
					user = db.getUser('badname')
					assert_that(user, none())

	@describe('Add User')
	def addUser():

		@beforeEach
		def _beforeEach():
			with app.app_context():
				cleanup()

		@it('Fields preserved')
		def fieldsPreserved():
			with app.app_context():
				db.addUser(test_user)
				row = db.getDb().execute('''
					SELECT name, pass_hash, pass_salt, email
					FROM Users WHERE name = ?
				''', [test_name]).fetchone()

				assert_that(row[0], equal_to(test_name))
				assert_that(row[1], equal_to(test_hash))
				assert_that(row[2], equal_to(test_salt))
				assert_that(row[3], equal_to(test_email))

		@it('Dates auto-populated')
		def datesPopulated():
			with app.app_context():
				db.addUser(test_user)
				row = db.getDb().execute('''
					SELECT created_at, updated_at, accessed_at
					FROM Users WHERE name = ?
				''', [test_name]).fetchone()

				assertDateNearNow(row[0])
				assertDateNearNow(row[1])
				#assertDateNearNow(row[2])

		@it('Cannot have multiple users with the same name')
		def duplicateName():
			with app.app_context():
				db.addUser(test_user)
				assert_that(
					calling(db.addUser).with_args(test_user),
					raises(IntegrityError, 'UNIQUE constraint failed: Users.name')
				)

		@it('Password hash and salt required')
		def hashAndSaltRequired():
			with app.app_context():
				assert_that(
					calling(db.addUser).with_args({
						'name': test_name,
						'pass_hash': test_hash,
						'pass_salt': None
					}),
					raises(IntegrityError, 'NOT NULL constraint failed: Users.pass_salt')
				)
				assert_that(
					calling(db.addUser).with_args({
						'name': test_name,
						'pass_hash': None,
						'pass_salt': test_salt
					}),
					raises(IntegrityError, 'NOT NULL constraint failed: Users.pass_hash')
				)

	@describe('Update User')
	def updateUser():

		added_user = None

		@beforeEach
		def _beforeEach():
			nonlocal added_user
			with app.app_context():
				cleanup()
				row = addTestUser(whole_row=True)
				added_user = {
					'id': row[0],
					'name': row[1],
					'pass_hash': row[2],
					'pass_salt': row[3],
					'email': row[4],
					'created_at': row[5],
					'updated_at': row[6],
					'accessed_at': row[7]
				}

		@it('Update user email preserves other fields')
		def updatedUser():
			nonlocal added_user
			with app.app_context():
				update_email = 'new@email.com'
				added_user['email'] = update_email
				res = db.updateUser(added_user)
				updated_user = db.getUser(test_name)

				assert_that(updated_user.get('name'), equal_to(test_name))
				assert_that(updated_user.get('pass_hash'), equal_to(test_hash))
				assert_that(updated_user.get('pass_salt'), equal_to(test_salt))
				assert_that(updated_user.get('email'), equal_to(update_email))

		@it('Date modified changed on update')
		def modifiedUpdated():
			nonlocal added_user
			sleep(1) # Delay to ensure modified time is different
			with app.app_context():
				db.updateUser(added_user)

				update_user = db.getUser(test_name)
				assert_that(
					update_user.get('updated_at'),
					not_(equal_to(added_user.get('updated_at')))
				)

		@it('Date created not changed on update')
		def createdNotUpdated():
			nonlocal added_user
			sleep(1) # Same here
			with app.app_context():
				db.updateUser(added_user)

				update_user = db.getUser(test_name)
				assert_that(
					update_user.get('created_at'),
					equal_to(added_user.get('created_at'))
				)

	@describe('Add Code')
	def addCode():

		@beforeEach
		def _beforeEach():
			nonlocal test_id
			with app.app_context():
				cleanup()
				test_id = addTestUser()

		@it('None not allowed for code')
		def codeNone():
			nonlocal test_id
			with app.app_context():
				assert_that(
					calling(db.addEmailCode).with_args(None, test_id, test_email),
					raises(IntegrityError, 'NOT NULL constraint failed: Codes.code')
				)

		@it('Empty string not allowed for code')
		def codeEmpty():
			nonlocal test_id
			with app.app_context():
				assert_that(
					calling(db.addEmailCode).with_args('', test_id, test_email),
					raises(IntegrityError, 'CHECK constraint failed: Codes')
				)

		@it('Duplicate codes not allowed')
		def duplicate():
			nonlocal test_id
			with app.app_context():
				db.addPasswordCode(test_code1, test_id)
				assert_that(
					calling(db.addEmailCode).with_args(test_code1, test_id, test_email),
					raises(IntegrityError, 'UNIQUE constraint failed: Codes.code')
				)

		@it('Email codes require email')
		def emailNone():
			nonlocal test_id
			with app.app_context():
				assert_that(
					calling(db.addEmailCode).with_args(test_code1, test_id, None),
					raises(IntegrityError, 'Email codes must define an email')
				)

		@it('Successfully added codes')
		def codeAdded():
			nonlocal test_id
			with app.app_context():
				db.addEmailCode(test_code1, test_id, test_email)
				db.addPasswordCode(test_code2, test_id)
				row = db.getDb().execute(
					'SELECT * FROM Codes WHERE code = ?', [test_code1]
				).fetchone()

				assert_that(row[0], equal_to(test_code1))
				assert_that(row[1], equal_to(test_id))
				# Ignore row[2]
				assert_that(row[3], equal_to(test_email))
				assertDateNearNow(row[4]) # created_at
				assert_that(row[5], none()) # used_at

	@describe('Get Code')
	def getCode():

		@beforeEach
		def _beforeEach():
			nonlocal test_id
			with app.app_context():
				cleanup()
				test_id = addTestUser()
				addTestCode()

		@it('None returned for non-existing code')
		def nonExisting():
			with app.app_context():
				code = db.getCode('badcode')
				assert_that(code, none())

		@it('Code successfully retrieved')
		def codeRetrieved():
			nonlocal test_id
			with app.app_context():
				code = db.getCode(test_code1)
				assert_that(code, not_none())
				assert_that(code.get('code'), equal_to(test_code1))
				assert_that(code.get('user_id'), equal_to(test_id))
				assert_that(code.get('email'), equal_to(test_email))

	@describe('Use Code')
	def useCode():

		@beforeEach
		def _beforeEach():
			nonlocal test_id
			with app.app_context():
				cleanup()
				test_id = addTestUser()
				addTestCode()

		@it('None returned for using non-existing code')
		def nonExisting():
			with app.app_context():
				db.useCode('badcode')
			row = getTestCode('badcode')
			assert_that(row, none())

		@it('Code successfully used')
		def usedCode():
			row = getTestCode(test_code1)
			assert_that(row[5], none()) # used_at

			with app.app_context():
				db.useCode(test_code1)

			row = getTestCode(test_code1)
			assertDateNearNow(row[5])

	@describe('Cull Old Codes')
	def cullOldCodes():

		@beforeEach
		def _beforeEach():
			nonlocal test_id
			with app.app_context():
				cleanup()
				test_id = addTestUser()

		@it('Old codes culled')
		def oldCulled():
			nonlocal test_id
			with app.app_context():
				codetype = db.CODE_TYPE_EMAIL
				db.getDb().execute('''
					INSERT INTO Codes (type, code, user_id, email, created_at)
					VALUES
						(?, ?, ?, ?, DATETIME('now')),
						(?, ?, ?, ?, DATETIME('now', '-1 days')),
						(?, ?, ?, ?, DATETIME('now', '-3 days'));
				''', [
					codetype, test_code1, test_id, 'email1',
					codetype, test_code2, test_id, 'email2',
					codetype, test_code3, test_id, 'email3'
				])

				# Verify codes all exist
				assert_that(db.getCode(test_code1), not_none())
				assert_that(db.getCode(test_code2), not_none())
				assert_that(db.getCode(test_code3), not_none())

				count = db.cullOldCodes()

				# Code #3 should be removed now
				assert_that(count, equal_to(1))
				assert_that(db.getCode(test_code1), not_none())
				assert_that(db.getCode(test_code2), not_none())
				assert_that(db.getCode(test_code3), none())
