from datetime import datetime, timedelta
from time import sleep

from hamcrest import *
from peewee import IntegrityError
from playhouse.shortcuts import model_to_dict
from pocha import before, beforeEach, describe, it

import testutil
from db import Code, LoginCode, PendingEmail, User
import util


@describe('Database Tests')
def databaseTests():

	test_name = 'TestUser'
	test_salt = 'testsalt'
	test_hash = util.hashPassword('testpass', test_salt)
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

		@it('User accessed_at field updates (And nothing else)')
		def userAccessedAt():
			before = User.get_by_name(test_name)
			after = User.get_by_name(test_name)

			#This works because the date is stored in nanoseconds.
			assert_that(
				before.accessed_at,
				not_(equal_to(after.accessed_at))
			)

			before = model_to_dict(before)
			after = model_to_dict(after)

			before.pop('accessed_at')
			after.pop('accessed_at')

			#Make sure no other data was edited.
			assert_that(before, equal_to(after))


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

		@it('None not allowed for code')
		def codeNone():
			assert_that(
				calling(Code.create).with_args(code=None),
				raises(IntegrityError, 'NOT NULL constraint failed: code.code')
			)

		@it('Empty string not allowed for code')
		def codeEmpty():
			assert_that(
				calling(Code.create).with_args(code=''),
				raises(IntegrityError, 'CHECK constraint failed: code')
			)

		@it('Duplicate codes not allowed')
		def duplicate():
			Code.create(code=test_code1)
			assert_that(
				calling(Code.create).with_args(code=test_code1),
				raises(IntegrityError, 'UNIQUE constraint failed: code.code')
			)

		@it('Successfully added codes')
		def codeAdded():
			Code.create(code=test_code1)
			Code.create(code=test_code2)

			code = Code.get_by_code(test_code1)
			assert_that(code, equal_to(test_code1))
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

	@describe('Code association')
	def codeAssociation():

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

		@it('Get by user PendingEmail')
		def getByUserPendingEmail():
			PendingEmail.create(code=added_code, user=test_user, email='aaa')
			pending = PendingEmail.get_by_user(test_user)
			assert_that(pending, not_none())
			assert_that(pending.user, equal_to(test_user))

		@it('Get by user LoginCode')
		def getByUserLogin():
			LoginCode.create(code=added_code, user=test_user)
			login = LoginCode.get_by_user(test_user)
			assert_that(login, not_none())
			assert_that(login.user, equal_to(test_user))

		@it('Get by code PendingEmail')
		def getByCodePendingEmail():
			PendingEmail.create(code=added_code, user=test_user, email='aaa')
			pending = PendingEmail.get_by_code(added_code)
			assert_that(pending, not_none())
			assert_that(pending.code, equal_to(added_code))

		@it('Get by code LoginCode')
		def getByCodeLogin():
			LoginCode.create(code=added_code, user=test_user)
			login = LoginCode.get_by_code(added_code)
			assert_that(login, not_none())
			assert_that(login.code, equal_to(added_code))

		@it('Upsert PendingEmail')
		def upsertPending():
			PendingEmail.create(code=added_code, user=test_user, email='aaa')
			PendingEmail.upsert(code=added_code, user=test_user, email='bbb')
			updated = PendingEmail.get_by_code(added_code)
			assert_that(updated.email, equal_to('bbb'))

		@it('Upsert LoginCode')
		def upsertLogin():
			LoginCode.upsert(code=added_code, user=test_user)
			added = LoginCode.get_by_code(added_code)
			assert_that(added.code, equal_to(added_code))

		@it('None returned for non-existing code')
		def noneCode():
			assert_that(PendingEmail.get_by_code('bad'), none())

	@describe('Code class')
	def classCode():

		@beforeEach
		def _beforeEach():
			testutil.clearDatabase()
			Code.create(code=test_code1)
			Code.create(code=test_code2)

		@it('Can convert to a string')
		def strConv():
			code = Code.get_by_code(test_code1)
			assert_that(str(code), equal_to(test_code1))
			assert_that(str(code), equal_to(code.code))

		@it('Handles string concat')
		def strConcat():
			code = Code.get_by_code(test_code1)

			prefix = "somestuff"

			assert_that(prefix + code, equal_to(prefix + test_code1))
			assert_that(code + prefix, equal_to(test_code1 + prefix))
			assert_that(code + code, equal_to(test_code1 + test_code1))

		@it('Handles comparisons against strings')
		def strCmp():
			assert_that(Code.get_by_code(test_code1), equal_to(test_code1))

		@it('Does not give false positive when comparing two different Code objects')
		def codeCmp():
			code1 = Code.get_by_code(test_code1)
			code2 = Code.get_by_code(test_code2)

			#Two different codes should not equal each other.
			assert_that(code1, not_(equal_to(code2)))

			#Two codes with the same code (which I'm sure violates a constraint)
			#should still not equal if any properties other than the code
			#don't equate.
			#
			#If these equate there is something fundamentally wrong with the
			# __eq__ override.
			code2.code = code1.code
			code2.used_at = datetime.now
			assert_that(code1, not_(equal_to(code2)))

	#TODO: In the future when PendingEmail is ready for tests,
	#copy the Code Class test patterns into PendingEmail tests.
