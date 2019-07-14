from pocha import describe, it, before, beforeEach, after
from hamcrest import *
import scrypt
from time import mktime, sleep, time as now
from peewee import IntegrityError

import db
from db import User, Code


@describe('Database Tests')
def databaseTests():

	test_name = 'TestUser'
	test_salt = 'testsalt'
	test_hash = scrypt.hash('testpass', test_salt)
	test_email = 'test@email.com'
	test_code1 = 'abcd'
	test_code2 = '1234'
	test_code3 = 'wxyz'

	test_user = None
	test_id = None

	def cleanup():
		'''Removes the test data from the database'''
		Code.delete().where(Code.code.in_(
			[test_code1, test_code2, test_code3]
		)).execute()
		User.delete().where(User.name == test_name).execute()

	def addTestUser():
		nonlocal test_user
		test_user = User.create(
			name      = test_name,
			pass_hash = test_hash,
			pass_salt = test_salt,
			email     = test_email
		)
		return test_user

#
#	def addTestCode():
#		nonlocal test_id
#		db.getDb().execute('''
#			INSERT INTO Codes (type, code, user_id, email)
#			VALUES (?, ?, ?, ?)
#		''', [db.CODE_TYPE_EMAIL, test_code1, test_id, test_email])
#		db.getDb().commit()
#
#	def getTestCode(code):
#		with app.app_context():
#			return db.getDb().execute(
#				'SELECT * FROM Codes WHERE code = ?', [code]
#			).fetchone()
#
	def assertDateNearNow(date):
		assert_that(date.timestamp(), close_to(now(), 5))

	@before
	def beforeAll():
		cleanup()

	@after
	def afterAll():
		cleanup()

	@describe('Get User')
	def getUser():

		@beforeEach
		def _beforeEach():
			cleanup()
			addTestUser()

		@it('User fields persisted')
		def fieldsPreserved():
			user = User.get_by_name(test_name)
			assert_that(user.name,      equal_to(test_name))
			assert_that(user.pass_hash, equal_to(test_hash))
			assert_that(user.pass_salt, equal_to(test_salt))
			assert_that(user.email,     equal_to(test_email))

		@it('None returned for non-existing user')
		def noUserFound():
			user = User.get_by_name('badname')
			assert_that(user, is_(none()))

	@describe('Add User')
	def addUser():

		@beforeEach
		def _beforeEach():
			cleanup()

		@it('Fields preserved')
		def fieldsPreserved():
			user = addTestUser()
			assert_that(user.name, equal_to(test_name))
			assert_that(user.pass_hash, equal_to(test_hash))
			assert_that(user.pass_salt, equal_to(test_salt))
			assert_that(user.email, equal_to(test_email))

		@it('Dates auto-populated')
		def datesPopulated():
			user = addTestUser()
			assertDateNearNow(user.created_at)
			assertDateNearNow(user.updated_at)
			assertDateNearNow(user.accessed_at)

		@it('Cannot have multiple users with the same name')
		def duplicateName():
			user = addTestUser()
			assert_that(
				calling(addTestUser),
				raises(IntegrityError, 'UNIQUE constraint failed: user.name')
			)

		@it('Password hash and salt required')
		def hashAndSaltRequired():
			assert_that(
				calling(User.create).with_args(
					name      = test_name,
					pass_hash = test_hash,
					pass_salt = None
				),
				raises(IntegrityError, 'NOT NULL constraint failed: user.pass_salt')
			)
			assert_that(
				calling(User.create).with_args(
					name      = test_name,
					pass_hash = None,
					pass_salt = test_salt
				),
				raises(IntegrityError, 'NOT NULL constraint failed: user.pass_hash')
			)

	@describe('Update User')
	def updateUser():

		@beforeEach
		def _beforeEach():
			nonlocal test_user
			cleanup()
			test_user = addTestUser()

		@it('Update user email preserves other fields')
		def updatedUser():
			nonlocal test_user
			update_email = 'new@email.com'
			test_user.email = update_email
			test_user.save()

			updated_user = User.get_by_id(test_user.id)
			assert_that(updated_user.name,      equal_to(test_name))
			assert_that(updated_user.pass_hash, equal_to(test_hash))
			assert_that(updated_user.pass_salt, equal_to(test_salt))
			assert_that(updated_user.email,     equal_to(update_email))

		@it('Date modified changed on update')
		def modifiedUpdated():
			nonlocal test_user
			sleep(1) # Delay to ensure modified time is different
			test_user.email = 'updated'
			test_user.save()

			updated_user = User.get_by_id(test_user.id)
			assert_that(
				updated_user.updated_at,
				not_(equal_to(test_user.created_at))
			)
			assert_that(
				updated_user.accessed_at,
				equal_to(test_user.updated_at)
			)

		@it('Date created not changed on update')
		def createdNotUpdated():
			nonlocal test_user
			sleep(1) # Same here
			test_user.email = 'updated'
			test_user.save()

			updated_user = User.get_by_id(test_user.id)
			assert_that(
				updated_user.created_at,
				equal_to(test_user.created_at)
			)

	@describe('Add Code')
	def addCode():

		@beforeEach
		def _beforeEach():
			cleanup()
			addTestUser()

		@it('None not allowed for code')
		def codeNone():
			nonlocal test_user
			assert_that(
				calling(Code.create_email).with_args(
					user    = test_user,
					email   = test_email,
					code    = None
				),
				raises(IntegrityError, 'NOT NULL constraint failed: code.code')
			)

		@it('Empty string not allowed for code')
		def codeEmpty():
			nonlocal test_user
			assert_that(
				calling(Code.create_email).with_args(
					user    = test_user,
					email   = test_email,
					code    = ''
				),
				raises(IntegrityError, 'CHECK constraint failed: code')
			)

		@it('Duplicate codes not allowed')
		def duplicate():
			nonlocal test_user
			Code.create_password(
				user    = test_user,
				email   = test_email,
				code    = test_code1
			)
			assert_that(
				calling(Code.create_password).with_args(
					user    = test_user,
					email   = test_email,
					code    = test_code1
				),
				raises(IntegrityError, 'UNIQUE constraint failed: code.code')
			)

		@it('Email codes require email')
		def emailNone():
			nonlocal test_user
			assert_that(
				calling(Code.create_email).with_args(
					user    = test_user,
					email   = None,
					code    = test_code1
				),
				raises(IntegrityError, 'Email codes must define an email')
			)

		@it('Successfully added codes')
		def codeAdded():
			nonlocal test_user
			Code.create_email(
				user    = test_user,
				email   = test_email,
				code    = test_code1
			)
			Code.create_password(
				user    = test_user,
				email   = None,
				code    = test_code2
			)

			code = Code.get_by_code(test_code1)
			assert_that(code.code,    equal_to(test_code1))
			assert_that(code.email,   equal_to(test_email))
			assert_that(code.used_at, is_(none()))
			assertDateNearNow(code.created_at)
			# Peewee gets the entire related model for foreign keys
			assert_that(code.user, equal_to(test_user))

#	@describe('Get Code')
#	def getCode():
#
#		@beforeEach
#		def _beforeEach():
#			nonlocal test_id
#			with app.app_context():
#				cleanup()
#				test_id = addTestUser()
#				addTestCode()
#
#		@it('None returned for non-existing code')
#		def nonExisting():
#			with app.app_context():
#				code = db.getCode('badcode')
#				assert_that(code, none())
#
#		@it('Code successfully retrieved')
#		def codeRetrieved():
#			nonlocal test_id
#			with app.app_context():
#				code = db.getCode(test_code1)
#				assert_that(code, not_none())
#				assert_that(code.get('code'), equal_to(test_code1))
#				assert_that(code.get('user_id'), equal_to(test_id))
#				assert_that(code.get('email'), equal_to(test_email))
#
#	@describe('Use Code')
#	def useCode():
#
#		@beforeEach
#		def _beforeEach():
#			nonlocal test_id
#			with app.app_context():
#				cleanup()
#				test_id = addTestUser()
#				addTestCode()
#
#		@it('None returned for using non-existing code')
#		def nonExisting():
#			with app.app_context():
#				db.useCode('badcode')
#			row = getTestCode('badcode')
#			assert_that(row, none())
#
#		@it('Code successfully used')
#		def usedCode():
#			row = getTestCode(test_code1)
#			assert_that(row[5], none()) # used_at
#
#			with app.app_context():
#				db.useCode(test_code1)
#
#			row = getTestCode(test_code1)
#			assertDateNearNow(row[5])
#
#	@describe('Cull Old Codes')
#	def cullOldCodes():
#
#		@beforeEach
#		def _beforeEach():
#			nonlocal test_id
#			with app.app_context():
#				cleanup()
#				test_id = addTestUser()
#
#		@it('Old codes culled')
#		def oldCulled():
#			nonlocal test_id
#			with app.app_context():
#				codetype = db.CODE_TYPE_EMAIL
#				db.getDb().execute('''
#					INSERT INTO Codes (type, code, user_id, email, created_at)
#					VALUES
#						(?, ?, ?, ?, DATETIME('now')),
#						(?, ?, ?, ?, DATETIME('now', '-1 days')),
#						(?, ?, ?, ?, DATETIME('now', '-3 days'));
#				''', [
#					codetype, test_code1, test_id, 'email1',
#					codetype, test_code2, test_id, 'email2',
#					codetype, test_code3, test_id, 'email3'
#				])
#
#				# Verify codes all exist
#				assert_that(db.getCode(test_code1), not_none())
#				assert_that(db.getCode(test_code2), not_none())
#				assert_that(db.getCode(test_code3), not_none())
#
#				count = db.cullOldCodes()
#
#				# Code #3 should be removed now
#				assert_that(count, equal_to(1))
#				assert_that(db.getCode(test_code1), not_none())
#				assert_that(db.getCode(test_code2), not_none())
#				assert_that(db.getCode(test_code3), none())
