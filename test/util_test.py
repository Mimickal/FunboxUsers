from pocha import describe, it, beforeEach, afterEach
from hamcrest import *
import os
import shutil

import util
import db

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
			code = util.makeCode(12)
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

		added_codes = []

		@afterEach
		def cleanupCodes():
			nonlocal added_codes
			db.DB_CONN.execute('''
					DELETE FROM Codes WHERE code IN ({})
				'''.format(','.join( ['?'] * len(added_codes) )),
				added_codes
			)
			db.DB_CONN.commit()

		@it('Codes are unique')
		def codesAreUnique():
			nonlocal added_codes

			# Add a bunch of codes
			num_codes = 10
			user_id = 1 # This works even if user_id doesn't exist
			for _ in range(num_codes):
				code = util.makeUniqueCode(8)
				# FIXME remove this and make makeUniqueCode add the code
				db.addEmailCode(code, user_id, 'test@email.com')
				added_codes.append(code)

			# Verify that all codes were added and unique
			cursor = db.DB_CONN.execute('''
					SELECT DISTINCT count(1)
					FROM Codes
					WHERE code IN ({})
				'''.format(','.join(['?'] * num_codes)),
				added_codes
			) # ^^^ Yes, python actually needs this jank^^^
			codes_added = cursor.fetchone()[0]

			assert_that(codes_added, equal_to(num_codes))

		@it('Detect when there are no more unique combinations')
		def notEnoughUniqueCodes():
			nonlocal added_codes

			num_codes = len(util.CODE_CHARS)
			for _ in range(num_codes):
				code = util.makeUniqueCode(1)
				# TODO remove this and make makeUniqueCode add the code
				db.addEmailCode(code, 1, 'test@email.com')
				added_codes.append(code)

			assert_that(
				calling(util.makeUniqueCode).with_args(1),
				raises(Exception, 'No remaining unique codes available of length 1')
			)

