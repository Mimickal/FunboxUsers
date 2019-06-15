from pocha import describe, it, before, beforeEach, afterEach
from hamcrest import *
from unittest.mock import patch
import scrypt
from base64 import b64encode
import re

from server import app as server_app, makeUniqueCode
import db

def authHeader(username, password):
	return {
		'Authorization': 'Basic ' + b64encode(
			bytes(username + ':' + password, 'utf-8')
		).decode('utf-8')
	}

def assertResponse(response, code, text):
	assert_that(response.status_code, equal_to(code))
	assert_that(response.get_data(as_text=True), equal_to(text))

# TODO Pocha doesn't currently support applying afterEach to nested
# describe blocks, so we need this as a work-around for now.
def cleanupUsers(name):
	assert_that(name, not_none())
	db.DB_CONN.execute('DELETE FROM Users WHERE name = ?', [name])
	db.DB_CONN.commit()

def cleanupCodes(code):
	assert_that(code, not_none())
	db.DB_CONN.execute('DELETE FROM Codes WHERE code = ?', [code])
	db.DB_CONN.commit()

@describe('Server Tests')
def serverTests():

	server_app.config['TESTING'] = True
	app = server_app.test_client()
	test_name = 'ServerTest'
	test_pass = 'testpass'
	test_code = 'Test1234'
	test_email = 'test@email.com'
	salt = 'saltything'
	headers = authHeader(test_name, test_pass)
	test_user = {
		'name': test_name,
		'pass_salt': salt,
		'pass_hash': scrypt.hash(test_pass, salt)
	}

	test_id = None

	@before
	def _beforeAll():
		cleanupUsers(test_name)
		cleanupCodes(test_code)

	@describe('Login')
	def login():

		@beforeEach
		def _beforeEach():
			db.addUser(test_user)

		@afterEach
		def _afterEach():
			cleanupUsers(test_name)

		@it('Non-existing user')
		def noUser():
			response = app.post('/login', data={
				'username': 'Idontexist',
				'password': 'lalala'
			})
			assertResponse(response, 403, 'Forbidden')

		@it('Existing user but bad password')
		def badPassword():
			response = app.post('/login', data={
				'username': test_name,
				'password': 'badpassword'
			})
			assertResponse(response, 403, 'Forbidden')

		@it('Successful login')
		def goodLogin():
			response = app.post('/login', data={
				'username': test_name,
				'password': test_pass
			})
			assertResponse(response, 200, 'Ok')

	@describe('Verify')
	def verify():

		@beforeEach
		def _beforeEach():
			db.addUser(test_user)

		@afterEach
		def _afterEach():
			cleanupUsers(test_name)

		@it('Verifies User')
		def verifiesUser():
			response = app.get('/verify', headers=headers)
			assertResponse(response, 200, 'Ok')

		@it('User does not exist')
		def userDoesNotExist():
			response = app.get(
				'/verify', headers=authHeader('baduser', 'pass'))
			assertResponse(response, 403, 'Forbidden')

		@it('Password does not match')
		def passDoesNotMatch():
			response = app.get(
				'/verify', headers=authHeader(test_name, 'badpass'))
			assertResponse(response, 403, 'Forbidden')

	@describe('Add Email')
	def addEmail():

		@beforeEach
		def _beforeEach():
			nonlocal test_id
			test_id = db.addUser(test_user)

		@afterEach
		def _afterEach():
			cleanupUsers(test_name)

		@it('User does not exist')
		def userDoesNotExist():
			response = app.put(
				'/update/email',
				headers=authHeader('baduser', 'pass'),
				data='example@email.com')
			assertResponse(response, 403, 'Forbidden')

		@it('Password does not match')
		def passDoesNotMatch():
			response = app.put(
				'/update/email',
				headers=authHeader(test_name, 'badpass'),
				data='example@email.com')
			assertResponse(response, 403, 'Forbidden')

		@it('Invalid email')
		def emailInvalid():
			response = app.put(
				'/update/email', headers=headers, data='bademail')
			assertResponse(response, 400, 'Invalid email')

		@it('Code added')
		@patch('server.sendmail')
		def codeAdded(mock_emailer):
			email = 'new@email.com'
			response = app.put(
				'/update/email', headers=headers, data=email)
			assertResponse(response, 200, 'Ok')

			args = mock_emailer.call_args[0]
			assert_that(args[0], equal_to(email))
			assert_that(args[1], equal_to('Funbox Email Verification'))

			# Check that our confirm link contains a valid code
			match = re.search(r'email\/confirm\/(\w{8})', args[2])
			assert_that(match, not_none())
			code = match.groups()[0]
			assert_that(db.getCode(code), not_none())

			cleanupCodes(code)

		@it('Ensures unique codes')
		def codesUnique():
			nonlocal test_id

			# Add a bunch of codes
			num_codes = 10
			added_codes = []
			for _ in range(num_codes):
				code = makeUniqueCode()
				db.addEmailCode(code, test_id, 'test@email.com')
				added_codes.append(code)

			# Verify that all codes were added and unique
			cursor = db.DB_CONN.execute('''
					SELECT DISTINCT count(1)
					FROM Codes
					WHERE code IN ({})
				'''.format(','.join(['?'] * num_codes)),
				added_codes)
				# ^^^ Yes, python actually needs this jank^^^
			codes_added = cursor.fetchone()[0]

			assert_that(codes_added, equal_to(num_codes))

			# Cleanup
			db.DB_CONN.execute('''
					DELETE FROM Codes WHERE code IN ({})
				'''.format(','.join(['?'] * num_codes)),
				added_codes)

	@describe('Confirm Code')
	def confirmCode():

		@beforeEach
		def _beforeEach():
			nonlocal test_id
			test_id = db.addUser(test_user)
			db.addEmailCode(test_code, test_id, test_email)

		@afterEach
		def _afterEach():
			cleanupUsers(test_name)
			cleanupCodes(test_code)

		@it('Attempting to confirm bad code')
		def confirmBadCode():
			bad_codes = [
				'I am bad',
				'; 1 == 1',
				'code123<',
				'>code123',
				'short',
				'ThisIsTooLong'
			]
			for code in bad_codes:
				resp = app.get('/update/email/confirm/' + code)
				assertResponse(resp, 403, 'Forbidden')

		@it('Attempting to confirm a used code')
		def confirmUsedCode():
			nonlocal test_id
			db.useCode(test_code)
			response = app.get('/update/email/confirm/' + test_code)
			assertResponse(response, 403, 'Forbidden')

			user = db.getUserById(test_id)
			assert_that(user.get('email', None), none())

		@it('Attempting to confirm code for a deleted user')
		def confirmCodeDeletedUser():
			nonlocal test_id
			db.DB_CONN.execute('DELETE FROM Users WHERE id = ?', [test_id])
			db.DB_CONN.commit()

			response = app.get('/update/email/confirm/' + test_code)
			assertResponse(response, 403, 'Forbidden')
			assert_that(db.getUserById(test_id), none())

		@it('Successfully confirm email via code')
		def emailAdded():
			nonlocal test_id
			response = app.get('/update/email/confirm/' + test_code)
			assertResponse(response, 200, 'Ok')

			user = db.getUserById(test_id)
			assert_that(user.get('email'), equal_to(test_email))
			assert_that(db.getCode(test_code), none())

	@describe('Generic Error')
	def genericError():

		@it('Bad Endpoint')
		def badEndpoint():
			response = app.get('/bad/endpoint')
			assertResponse(response, 403, 'Forbidden')

