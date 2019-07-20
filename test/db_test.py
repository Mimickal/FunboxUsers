from pocha import describe, it, before, beforeEach
from hamcrest import *
import scrypt
from time import sleep
from datetime import datetime, timedelta
from peewee import IntegrityError

import testutil
from db import User, Code, PendingEmail


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

	def addTestUser():
		nonlocal test_user
		test_user = User.create(
			name      = test_name,
			pass_hash = test_hash,
			pass_salt = test_salt,
			email     = test_email
		)
		return test_user

	def assertDateNearNow(date):
		assert_that(date.timestamp(), close_to(datetime.now().timestamp(), 5))

	@before
	def beforeAll():
		testutil.clearDatabase()

	@describe('Get User')
	def getUser():

		@beforeEach
		def _beforeEach():
			testutil.clearDatabase()
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
			testutil.clearDatabase()

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
			testutil.clearDatabase()
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
			testutil.clearDatabase()
			addTestUser()

		@it('None not allowed for code')
		def codeNone():
			nonlocal test_user
			assert_that(
				calling(Code.create).with_args(code=None),
				raises(IntegrityError, 'NOT NULL constraint failed: code.code')
			)

		@it('Empty string not allowed for code')
		def codeEmpty():
			nonlocal test_user
			assert_that(
				calling(Code.create).with_args(code=''),
				raises(IntegrityError, 'CHECK constraint failed: code')
			)

		@it('Duplicate codes not allowed')
		def duplicate():
			nonlocal test_user
			Code.create(code=test_code1)
			assert_that(
				calling(Code.create).with_args(code=test_code1),
				raises(IntegrityError, 'UNIQUE constraint failed: code.code')
			)

		@it('Successfully added codes')
		def codeAdded():
			nonlocal test_user
			Code.create(code=test_code1)
			Code.create(code=test_code2)

			code = Code.get_by_code(test_code1)
			assert_that(code.code, equal_to(test_code1))
			assert_that(code.used_at, none())
			assertDateNearNow(code.created_at)

	@describe('Get Code')
	def getCode():

		@beforeEach
		def _beforeEach():
			testutil.clearDatabase()
			Code.create(code=test_code1)

		@it('None returned for non-existing code')
		def nonExisting():
			code = Code.get_by_code('badcode')
			assert_that(code, none())

		@it('Code successfully retrieved')
		def codeRetrieved():
			code = Code.get_by_code(test_code1)
			assert_that(code, not_none())
			assert_that(code.code, equal_to(test_code1))

		@it('Getting used code')
		def gettingUsedCode():
			Code.use_code(test_code1)
			assert_that(Code.get_by_code(test_code1), none())
			assert_that(Code.get_by_code(test_code1, include_used=True), not_none())

	@describe('Use Code')
	def useCode():

		@beforeEach
		def _beforeEach():
			testutil.clearDatabase()
			Code.create(code=test_code1)

		@it('None returned for using non-existing code')
		def nonExisting():
			Code.use_code('badcode')
			code = Code.get_by_code('badcode')
			assert_that(code, none())

		@it('Code successfully used')
		def usedCode():
			code = Code.get_by_code(test_code1)
			assert_that(code.used_at, none())

			Code.use_code(test_code1)

			code = Code.get_by_code(test_code1, include_used=True)
			assertDateNearNow(code.used_at)

	@describe('Cull Old Codes')
	def cullOldCodes():

		@beforeEach
		def _beforeEach():
			testutil.clearDatabase()

		@it('Old codes culled')
		def oldCulled():
			now = datetime.now()
			three_days = timedelta(days=3)
			Code.insert_many(
				[
					(test_code1, None, now),
					(test_code2, now,  now - three_days),
					(test_code3, None, now - three_days),
				],
				fields=[Code.code, Code.used_at, Code.created_at]
			).execute()

			# Verify codes all exist
			assert_that(Code.get_by_code(test_code1, include_used=True), not_none())
			assert_that(Code.get_by_code(test_code2, include_used=True), not_none())
			assert_that(Code.get_by_code(test_code3, include_used=True), not_none())

			num_removed = Code.cull_old_codes()

			# Code #3 should be removed now
			assert_that(num_removed, equal_to(1))
			assert_that(Code.get_by_code(test_code1, include_used=True), not_none())
			assert_that(Code.get_by_code(test_code2, include_used=True), not_none())
			assert_that(Code.get_by_code(test_code3, include_used=True), none())

		#@it('Unused PendingEmail rows also removed')
		#def pendingCulled():
		#	nonlocal test_user
		#	Code.create(code=test_code1

	@describe('Pending email codes')
	def pendingEmail():

		added_code = None

		@beforeEach
		def _beforeEach():
			nonlocal added_code
			testutil.clearDatabase()
			addTestUser()
			Code.create(code=test_code1)
			added_code = Code.get_by_code(test_code1)

		@it('Code ref must be unique')
		def codeRefUnique():
			other_test_user = User.create(
				name = 'newuser2',
				pass_hash = test_hash,
				pass_salt = test_salt,
			)
			PendingEmail.create(
				code = added_code,
				user = test_user,
				email = 'a@email.com'
			)
			assert_that(
				calling(PendingEmail.create).with_args(
					code = added_code,
					user = other_test_user,
					email = 'a@email.com'
				),
				raises(IntegrityError, 'UNIQUE constraint failed: pendingemail.code')
			)

		@it('Code ref must exist')
		def codeRefExists():
			assert_that(
				calling(PendingEmail.create).with_args(
					code = None,
					user = test_user,
					email = 'a@email.com'
				),
				raises(IntegrityError, 'NOT NULL constraint failed: pendingemail.code')
			)

		@it('User ref must be unique')
		def codeRefUnique():
			other_added_code = Code.create(code=test_code2)
			PendingEmail.create(
				code = added_code,
				user = test_user,
				email = 'a@email.com'
			)
			assert_that(
				calling(PendingEmail.create).with_args(
					code = other_added_code,
					user = test_user,
					email = 'a@email.com'
				),
				raises(IntegrityError, 'UNIQUE constraint failed: pendingemail.user')
			)

		@it('User ref must exist')
		def userRefExists():
			assert_that(
				calling(PendingEmail.create).with_args(
					code = added_code,
					user = None,
					email = 'a@email.com'
				),
				raises(IntegrityError, 'NOT NULL constraint failed: pendingemail.user')
			)

		@it('Get by code')
		def getByCode():
			PendingEmail.create(code=added_code, user=test_user, email='aaa')
			pending = PendingEmail.get_by_code(added_code.code)
			assert_that(pending, not_none())
			assert_that(pending.code.code, equal_to(added_code.code))

		@it('None returned for non-existing code')
		def noneCode():
			assert_that(PendingEmail.get_by_code('bad'), none())

