from pocha import describe, it, beforeEach, afterEach
from hamcrest import *
import os
import shutil
from peewee import fn

import util
from db import User, Code
import testutil

@describe('Util Tests')
def utilTests():

	@describe('getSecretKey')
	def test_getSecretKey():
		test_key_file = '/tmp/fbusers_test_key'
		test_nested_path = '/tmp/fbusers/nested/test/directory/key'

		@beforeEach
		@afterEach
		def cleanupKey():
			try: os.remove(test_key_file)
			except FileNotFoundError: pass

			try: shutil.rmtree('/tmp/fbusers')
			except FileNotFoundError: pass

		@it('New key created on first request')
		def newKey():
			assert_that(os.path.isfile(test_key_file), equal_to(False))
			assert_that(util.getSecretKey(test_key_file), is_(not_none()))
			assert_that(os.path.isfile(test_key_file), equal_to(True))

		@it('Existing key loaded')
		def existingKey():
			key = b'I am test key bytes'
			with open(test_key_file, 'wb+') as keyFile:
				keyFile.write(key)

			# Do it twice to ensure the key isn't being recreated
			assert_that(util.getSecretKey(test_key_file), equal_to(key))
			assert_that(util.getSecretKey(test_key_file), equal_to(key))

		@it('Exception thrown for empty path')
		def emptyPathException():
			assert_that(
				calling(util.getSecretKey).with_args(''),
				raises(Exception, 'Empty key path')
			)

		@it('Directories recursively created')
		def recursivePathCreation():
			assert_that(util.getSecretKey(test_nested_path), is_(not_none()))

	@describe('makeCode')
	def test_makeCode():

		@it('Length is respected')
		def lengthRespected():
			size = 12
			code = util.makeCode(size)
			assert_that(code, has_length(size))

		@it('0 length')
		def zeroLength():
			code = util.makeCode(0)
			assert_that(code, equal_to(''))

		@it('Negative length')
		def negativeLength():
			size = -1
			assert_that(
				calling(util.makeCode).with_args(size),
				raises(Exception, 'Tried to make a code with length %d' % size)
			)

		@it('Non-numeric length')
		def nonNumericLength():
			assert_that(
				calling(util.makeCode).with_args('not an int'),
				raises(TypeError)
			)

	@describe('makeUniqueCode')
	def test_makeUniqueCode():

		test_user = None
		added_codes = []

		@beforeEach
		def createUser():
			nonlocal test_user
			test_user = User.create(
				name='test', pass_hash='hash', pass_salt='salt'
			)

		@afterEach
		def cleanupCodes():
			nonlocal test_user
			nonlocal added_codes
			testutil.clearDatabase()
			test_user = None

		@it('Ensures unique codes')
		def codesUnique():
			nonlocal added_codes
			nonlocal test_user

			# Add a bunch of codes
			num_codes = 10
			added_codes = []
			for _ in range(num_codes):
				code = util.makeUniqueCode(8)
				Code.create_email(code=code, user=test_user, email='a@email')
				added_codes.append(code)

			# Verify that all codes were added and unique
			codes_added = Code                      \
				.select(fn.COUNT(1).alias('count')) \
				.distinct()                         \
				.where(Code.code.in_(added_codes))  \
				.get()                              \
				.count
			assert_that(codes_added, equal_to(num_codes))

		@it('Detect when there are no more unique combinations')
		def notEnoughUniqueCodes():
			nonlocal added_codes
			nonlocal test_user

			num_codes = len(util.CODE_CHARS)
			for _ in range(num_codes):
				code = util.makeUniqueCode(1)
				# TODO remove this and make makeUniqueCode add the code
				Code.create_email(code=code, user=test_user, email='a@email')
				added_codes.append(code)

			assert_that(
				calling(util.makeUniqueCode).with_args(1),
				raises(Exception, 'No remaining unique codes available of length 1')
			)

