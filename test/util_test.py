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
			assert_that(util.getSecretKey(test_key_file), not_none())
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
			assert_that(util.getSecretKey(test_nested_path), not_none())

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

		@beforeEach
		@afterEach
		def createUser():
			testutil.clearDatabase()

		@it('Ensures unique codes')
		def codesUnique():
			# Add a bunch of codes
			num_codes = 10
			for _ in range(num_codes):
				util.makeUniqueCode(8)

			# Verify that all codes were added and unique
			codes_added = Code                      \
				.select(fn.COUNT(1).alias('count')) \
				.distinct().get().count
			assert_that(codes_added, equal_to(num_codes))

		@it('Detect when there are no more unique combinations')
		def notEnoughUniqueCodes():
			num_codes = len(util.CODE_CHARS)
			for _ in range(num_codes):
				util.makeUniqueCode(1)

			assert_that(
				calling(util.makeUniqueCode).with_args(1),
				raises(Exception, 'No remaining unique codes available of length 1')
			)

	@describe('isValidPassword')
	def test_isValidPassword():

		@it('None not allowed')
		def noneNotAllowed():
			assert_that(util.isValidPassword(None), equal_to(False))

		@it('Empty string not allowed')
		def emptyNotAllowed():
			assert_that(util.isValidPassword(''), equal_to(False))

		@it('Non-string not allowed')
		def nonStringNotAllowed():
			assert_that(util.isValidPassword(['mypasshere']), equal_to(False))

		@it('Valid password accepted')
		def validPassAccepted():
			assert_that(util.isValidPassword('mypasshere'), equal_to(True))

